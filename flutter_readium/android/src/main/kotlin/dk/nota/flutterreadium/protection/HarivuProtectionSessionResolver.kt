package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.readium.r2.shared.util.Url
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

internal class HarivuProtectionSessionResolver(
    private val signingPublicKey: ByteArray,
    private val deviceKey: HarivuDeviceKeyAgreement,
    private val expectedDeviceId: String,
    private val expectedDeviceKeyId: String,
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
) {
    /** The software development device, for the bundled fixture and the recorded vectors. */
    constructor(
        signingPublicKey: ByteArray,
        devicePrivateKey: ByteArray,
        expectedDeviceId: String,
        expectedDeviceKeyId: String,
        nowEpochMillis: () -> Long = System::currentTimeMillis,
    ) : this(
        signingPublicKey,
        HarivuSoftwareDeviceKey(devicePrivateKey),
        expectedDeviceId,
        expectedDeviceKeyId,
        nowEpochMillis,
    )

    @OptIn(ExperimentalEncodingApi::class)
    fun resolve(
        manifest: ByteArray,
        licenseJws: String,
    ): HarivuProtectionSession {
        val licensePayload = HarivuLicenseVerifier.verifySignature(licenseJws.trim(), signingPublicKey)
        val license = parseObject(licensePayload, HarivuProtectionErrorCode.ProtectedLicenseInvalid)
        validateLicenseEnvelope(license)

        val expectedManifestHash = license.requiredString("manifestSha256")
        if (!MessageDigest.isEqual(expectedManifestHash.hexToBytes(), manifest.sha256())) {
            fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
        }
        val manifestJson =
            parseObject(
                manifest.toString(StandardCharsets.UTF_8),
                HarivuProtectionErrorCode.ProtectedPackageTampered,
            )
        validateManifestEnvelope(manifestJson, license)

        val publicationId = license.requiredString("publicationId")
        val publicationVersion = license.requiredInt("publicationVersion")
        val contentKeyWrap = license.requiredObject("contentKeyWrap")
        if (contentKeyWrap.requiredString("algorithm") != WRAP_ALGORITHM) {
            fail(HarivuProtectionErrorCode.UnsupportedProtectionVersion)
        }
        val wrapAad =
            buildJsonObject {
                put("algorithm", WRAP_ALGORITHM)
                put("deviceId", expectedDeviceId)
                put("deviceKeyId", expectedDeviceKeyId)
                put("licenseVersion", 1)
                put("publicationId", publicationId)
                put("publicationVersion", publicationVersion)
            }.toString().toByteArray(StandardCharsets.UTF_8)
        val contentKey =
            HarivuContentKeyUnwrapper.unwrap(
                deviceKey = deviceKey,
                ephemeralPublicKey = contentKeyWrap.requiredString("ephemeralPublicKey").base64UrlBytes(),
                nonce = contentKeyWrap.requiredString("nonce").base64UrlBytes(),
                wrappedContentKey = contentKeyWrap.requiredString("wrappedContentKey").base64UrlBytes(),
                tag = contentKeyWrap.requiredString("tag").base64UrlBytes(),
                aad = wrapAad,
                publicationId = publicationId,
                deviceId = expectedDeviceId,
            )
        if (contentKey.size != 32) fail(HarivuProtectionErrorCode.ProtectedDeviceMismatch)

        val resources = mutableMapOf<Url, HarivuProtectedResource>()
        for (resourceElement in manifestJson["resources"]?.jsonArray ?: invalidPackage()) {
            val resource = resourceElement.jsonObject
            val path = resource.requiredString("path")
            val url = Url(path) ?: invalidPackage()
            if (resources.containsKey(url)) invalidPackage()
            val plaintextLength = resource.requiredInt("plaintextLength")
            if (plaintextLength > MAX_PLAINTEXT_RESOURCE_SIZE) {
                fail(HarivuProtectionErrorCode.ProtectedResourceTooLarge)
            }
            val mediaType = resource.requiredString("mediaType")
            val aad =
                buildJsonObject {
                    put("algorithm", "A256GCM")
                    put("mediaType", mediaType)
                    put("packageVersion", 1)
                    put("path", path)
                    put("plaintextLength", plaintextLength)
                    put("publicationId", publicationId)
                    put("publicationVersion", publicationVersion)
                }.toString().toByteArray(StandardCharsets.UTF_8)
            resources[url] =
                HarivuProtectedResource(
                    nonce = resource.requiredString("nonce").base64UrlBytes(),
                    tag = resource.requiredString("tag").base64UrlBytes(),
                    aad = aad,
                    plaintextLength = plaintextLength,
                )
        }
        return HarivuProtectionSession(contentKey = contentKey, resources = resources)
    }

    private fun validateLicenseEnvelope(license: JsonObject) {
        if (license.requiredString("format") != "harivu-offline-license" ||
            license.requiredInt("licenseVersion") != 1
        ) {
            fail(HarivuProtectionErrorCode.UnsupportedProtectionVersion)
        }
        if (license.requiredString("deviceId") != expectedDeviceId ||
            license.requiredString("deviceKeyId") != expectedDeviceKeyId
        ) {
            fail(HarivuProtectionErrorCode.ProtectedDeviceMismatch)
        }
        val now = nowEpochMillis()
        if (parseTimestamp(license.requiredString("expiresAt")) <= now) {
            fail(HarivuProtectionErrorCode.ProtectedLicenseExpired)
        }
        if (parseTimestamp(license.requiredString("notBefore")) > now) {
            fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
        }
    }

    private fun validateManifestEnvelope(
        manifest: JsonObject,
        license: JsonObject,
    ) {
        if (manifest.requiredString("format") != "harivu-protected-epub" ||
            manifest.requiredString("algorithm") != "A256GCM" ||
            manifest.requiredInt("packageVersion") != 1 ||
            manifest.requiredInt("maxPlaintextResourceSize") != MAX_PLAINTEXT_RESOURCE_SIZE
        ) {
            fail(HarivuProtectionErrorCode.UnsupportedProtectionVersion)
        }
        if (manifest.requiredString("publicationId") != license.requiredString("publicationId") ||
            manifest.requiredInt("publicationVersion") != license.requiredInt("publicationVersion")
        ) {
            fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
        }
    }

    private fun parseTimestamp(value: String): Long =
        try {
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
                .apply {
                    isLenient = false
                    timeZone = TimeZone.getTimeZone("UTC")
                }.parse(value)
                ?.time ?: invalidLicense()
        } catch (_: IllegalArgumentException) {
            invalidLicense()
        } catch (_: java.text.ParseException) {
            invalidLicense()
        }

    private fun JsonObject.requiredString(key: String): String =
        try {
            getValue(key).jsonPrimitive.content
        } catch (_: RuntimeException) {
            invalidLicense()
        }

    private fun JsonObject.requiredInt(key: String): Int = requiredString(key).toIntOrNull() ?: invalidLicense()

    private fun JsonObject.requiredObject(key: String): JsonObject =
        try {
            getValue(key).jsonObject
        } catch (_: RuntimeException) {
            invalidLicense()
        }

    private fun parseObject(
        value: String,
        code: HarivuProtectionErrorCode,
    ): JsonObject =
        try {
            Json.parseToJsonElement(value).jsonObject
        } catch (_: RuntimeException) {
            fail(code)
        }

    @OptIn(ExperimentalEncodingApi::class)
    private fun String.base64UrlBytes(): ByteArray =
        try {
            Base64.UrlSafe.decode(padEnd(length + (4 - length % 4) % 4, '='))
        } catch (_: IllegalArgumentException) {
            invalidLicense()
        }

    private fun String.hexToBytes(): ByteArray =
        if (length == 64) {
            try {
                chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            } catch (_: NumberFormatException) {
                invalidLicense()
            }
        } else {
            invalidLicense()
        }

    private fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)

    private fun invalidLicense(): Nothing = fail(HarivuProtectionErrorCode.ProtectedLicenseInvalid)

    private fun invalidPackage(): Nothing = fail(HarivuProtectionErrorCode.ProtectedPackageTampered)

    private fun fail(code: HarivuProtectionErrorCode): Nothing = throw HarivuProtectionException(code)

    private companion object {
        const val MAX_PLAINTEXT_RESOURCE_SIZE = 2 * 1024 * 1024
        const val WRAP_ALGORITHM = "ECDH-ES+HKDF-SHA256+A256GCM"
    }
}
