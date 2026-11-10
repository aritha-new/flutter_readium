package dk.nota.flutterreadium.protection

import android.content.Context
import org.readium.r2.shared.publication.protection.ContentProtection
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.zip.ZipException
import java.util.zip.ZipFile
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

internal data class HarivuProtectedFixtureAssets(
    val epubAssetKey: String,
    val licenseAssetKey: String,
)

internal data class HarivuPreparedPublication(
    val file: File,
    val contentProtection: ContentProtection,
)

internal object HarivuProtectedFixture {
    const val OPAQUE_ID = "harivu-protected-fixture-v1"

    @OptIn(ExperimentalEncodingApi::class)
    fun prepare(
        context: Context,
        opaqueId: String,
        assets: HarivuProtectedFixtureAssets?,
    ): HarivuPreparedPublication {
        if (opaqueId != OPAQUE_ID || assets == null) {
            fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
        }
        try {
            val directory = File(context.noBackupFilesDir, "harivu-protected-publications")
            if (!directory.exists() && !directory.mkdirs()) {
                fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
            }
            val publicationFile = File(directory, "phase2-protected-reader-fixture.epub")
            context.assets.open(assets.epubAssetKey).use { input ->
                publicationFile.outputStream().use(input::copyTo)
            }
            val licenseJws =
                context.assets
                    .open(assets.licenseAssetKey)
                    .bufferedReader()
                    .use { it.readText() }
            return open(publicationFile, licenseJws)
        } catch (error: HarivuProtectionException) {
            throw error
        } catch (_: ZipException) {
            fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
        } catch (_: IOException) {
            fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
        }
    }

    /**
     * Verifies the license, unwraps the content key and builds the Readium protection for an
     * on-disk protected package. Shared by the bundled fixture and downloaded publications.
     */
    internal fun open(
        publicationFile: File,
        licenseJws: String,
        device: HarivuDeviceIdentity = HarivuDeviceIdentity.DEVELOPMENT,
    ): HarivuPreparedPublication {
        try {
            val manifest =
                ZipFile(publicationFile).use { zip ->
                    val entry =
                        zip.getEntry("META-INF/harivu-protection.json")
                            ?: fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
                    zip.getInputStream(entry).use { it.readBytes() }
                }
            val resolver =
                HarivuProtectionSessionResolver(
                    signingPublicKey = signingPublicKey(),
                    devicePrivateKey = DEVICE_PRIVATE_KEY_HEX.hexToBytes(),
                    expectedDeviceId = device.deviceId,
                    expectedDeviceKeyId = device.deviceKeyId,
                )
            val session = resolver.resolve(manifest = manifest, licenseJws = licenseJws)
            val protection =
                HarivuContentProtection { openedManifest ->
                    if (!MessageDigest.isEqual(manifest, openedManifest)) {
                        fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
                    }
                    session
                }
            return HarivuPreparedPublication(publicationFile, protection)
        } catch (error: HarivuProtectionException) {
            throw error
        } catch (_: ZipException) {
            fail(HarivuProtectionErrorCode.ProtectedPackageTampered)
        } catch (_: IOException) {
            fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
        }
    }

    // Kotlin's UrlSafe decoder requires padding; the key constant is unpadded base64url.
    @OptIn(ExperimentalEncodingApi::class)
    internal fun signingPublicKey(): ByteArray =
        Base64.UrlSafe.decode(
            SIGNING_PUBLIC_KEY_BASE64URL.padEnd(
                SIGNING_PUBLIC_KEY_BASE64URL.length + (4 - SIGNING_PUBLIC_KEY_BASE64URL.length % 4) % 4,
                '=',
            ),
        )

    internal fun devicePrivateKeyBytes(): ByteArray = DEVICE_PRIVATE_KEY_HEX.hexToBytes()

    private fun String.hexToBytes(): ByteArray =
        try {
            chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (_: NumberFormatException) {
            fail(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
        }

    private fun fail(code: HarivuProtectionErrorCode): Nothing = throw HarivuProtectionException(code)

    private const val SIGNING_PUBLIC_KEY_BASE64URL =
        "BI7VfsK49edekZIye1HlZhyHyOXbAXByEwmlF_xuEEaxVIHorjs50yN3jkUcse_rVB4TJadmft2HfGj69wUAdXU"
    private const val DEVICE_PRIVATE_KEY_HEX =
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
}
