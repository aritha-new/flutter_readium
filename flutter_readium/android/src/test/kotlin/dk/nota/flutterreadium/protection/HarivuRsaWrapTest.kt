package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Android devices hold an RSA key in the Keystore, so their license wraps the content key with a hybrid
 * RSA-OAEP-SHA256 + AES-256-GCM scheme. The recorded vector was produced by openssl and Node, independently of
 * the Java backend and of this code.
 */
class HarivuRsaWrapTest {
    private fun load(name: String): JsonObject =
        checkNotNull(javaClass.classLoader?.getResourceAsStream(name))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }

    private val vector = load("harivu_rsa_wrap_v1.json")
    private val keys = load("harivu_protection_v1.json")["keys"]!!.jsonObject

    private fun str(
        obj: JsonObject,
        key: String,
    ) = obj[key]!!.jsonPrimitive.content

    private fun String.b64(): ByteArray = Base64.getUrlDecoder().decode(this)

    private fun String.hex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** The recorded device key, standing in for the Keystore key. */
    private fun softwareRsaKey(pkcs8: ByteArray = str(vector, "devicePrivateKeyPkcs8").b64()): RsaTestDeviceKey {
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        return RsaTestDeviceKey { encryptedKey ->
            Cipher
                .getInstance("RSA/ECB/OAEPPadding")
                .apply {
                    init(
                        Cipher.DECRYPT_MODE,
                        key,
                        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
                    )
                }.doFinal(encryptedKey)
        }
    }

    private fun unwrap(
        decryptor: HarivuDeviceKeyDecryptor,
        deviceId: String = str(vector, "deviceId"),
        tamperTag: Boolean = false,
    ): ByteArray {
        val wrap = vector["contentKeyWrap"]!!.jsonObject
        val tag = str(wrap, "tag").b64()
        if (tamperTag) tag[0] = (tag[0].toInt() xor 1).toByte()
        return HarivuContentKeyUnwrapper.unwrapRsa(
            decryptor = decryptor,
            encryptedKey = str(wrap, "encryptedKey").b64(),
            nonce = str(wrap, "nonce").b64(),
            wrappedContentKey = str(wrap, "wrappedContentKey").b64(),
            tag = tag,
            aad = str(vector, "aad").replace(str(vector, "deviceId"), deviceId).toByteArray(StandardCharsets.UTF_8),
        )
    }

    /** A minimal manifest and an ES256-signed license (dev signing key) carrying the recorded RSA wrap. */
    private fun rsaLicense(): Pair<ByteArray, String> {
        val manifest =
            """{"algorithm":"A256GCM","format":"harivu-protected-epub","maxPlaintextResourceSize":2097152,""" +
                """"packageVersion":1,"publicationId":"harivu-phase2-fixture","publicationVersion":1,"resources":[]}"""
        val manifestBytes = manifest.toByteArray(StandardCharsets.UTF_8)
        val manifestSha = MessageDigest.getInstance("SHA-256").digest(manifestBytes).joinToString("") { "%02x".format(it) }
        val wrap = vector["contentKeyWrap"]!!.jsonObject
        val payload =
            """{"contentKeyWrap":{"algorithm":"RSA-OAEP-SHA256+A256GCM","encryptedKey":"${str(wrap, "encryptedKey")}",""" +
                """"nonce":"${str(
                    wrap,
                    "nonce",
                )}","tag":"${str(wrap, "tag")}","wrappedContentKey":"${str(wrap, "wrappedContentKey")}"},""" +
                """"deviceId":"${str(vector, "deviceId")}","deviceKeyId":"${str(vector, "deviceKeyId")}",""" +
                """"expiresAt":"2036-01-01T00:00:00Z","format":"harivu-offline-license","issuedAt":"2026-01-01T00:00:00Z",""" +
                """"licenseId":"rsa-vector-license","licenseVersion":1,"manifestSha256":"$manifestSha",""" +
                """"notBefore":"2026-01-01T00:00:00Z","publicationId":"harivu-phase2-fixture","publicationVersion":1}"""
        val header = """{"alg":"ES256","kid":"harivu-dev-signing-key-v1","typ":"harivu-license+jws"}"""
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val signingInput = encoder.encodeToString(header.toByteArray()) + "." + encoder.encodeToString(payload.toByteArray())
        val params =
            java.security.AlgorithmParameters
                .getInstance("EC")
                .apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        val signingKey =
            KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, str(keys, "signingPrivateKeyHex").hex()), params))
        val der =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(signingKey)
                update(signingInput.toByteArray())
                sign()
            }
        return manifestBytes to signingInput + "." + encoder.encodeToString(HarivuEcdsa.derToP1363(der))
    }

    private fun resolver(deviceKey: HarivuDeviceKeyAgreement) =
        HarivuProtectionSessionResolver(
            signingPublicKey = str(keys, "signingPublicKey").b64(),
            deviceKey = deviceKey,
            expectedDeviceId = str(vector, "deviceId"),
            expectedDeviceKeyId = str(vector, "deviceKeyId"),
            nowEpochMillis = { Instant.parse("2026-11-10T00:00:00Z").toEpochMilli() },
        )

    @Test
    fun `the recorded RSA wrap unwraps to the content key`() {
        assertArrayEquals(str(vector, "contentKeyHex").hex(), unwrap(softwareRsaKey()))
    }

    @Test
    fun `another device id, a tampered tag, a different key or an unavailable key fails closed as device mismatch`() {
        val otherKey =
            KeyPairGenerator
                .getInstance("RSA")
                .apply { initialize(2048) }
                .generateKeyPair()
                .private.encoded

        for (attempt in listOf<() -> ByteArray>(
            { unwrap(softwareRsaKey(), deviceId = "some-other-device") },
            { unwrap(softwareRsaKey(), tamperTag = true) },
            { unwrap(softwareRsaKey(otherKey)) },
            { unwrap(RsaTestDeviceKey { throw GeneralSecurityException("key unavailable") }) },
        )) {
            val error = assertThrows(HarivuProtectionException::class.java) { attempt() }
            assertEquals(HarivuProtectionErrorCode.ProtectedDeviceMismatch, error.code)
        }
    }

    @Test
    fun `a license with an RSA wrap resolves through the resolver for an RSA device`() {
        val (manifest, jws) = rsaLicense()

        val session = resolver(softwareRsaKey()).resolve(manifest = manifest, licenseJws = jws)

        assertArrayEquals(str(vector, "contentKeyHex").hex(), session.contentKey)
    }

    @Test
    fun `an RSA license cannot be opened by a device key that only does EC`() {
        val (manifest, jws) = rsaLicense()
        val ecOnly = HarivuSoftwareDeviceKey(str(keys, "devicePrivateKeyHex").hex())

        val error = assertThrows(HarivuProtectionException::class.java) { resolver(ecOnly).resolve(manifest = manifest, licenseJws = jws) }

        assertEquals(HarivuProtectionErrorCode.ProtectedDeviceMismatch, error.code)
    }

    /** A device key that only decrypts, like the Keystore RSA key. */
    private class RsaTestDeviceKey(
        private val decrypt: (ByteArray) -> ByteArray,
    ) : HarivuDeviceKeyAgreement,
        HarivuDeviceKeyDecryptor {
        override fun sharedSecret(ephemeralPublicKey: ByteArray): ByteArray = throw GeneralSecurityException("RSA key")

        override fun decrypt(encryptedKey: ByteArray): ByteArray = decrypt.invoke(encryptedKey)
    }
}
