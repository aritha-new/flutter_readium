package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class HarivuProtectionSessionResolverTest {
    @Test
    fun `recorded license and manifest resolve a decrypting session`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val packageData = fixture["package"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject
        val vector = fixture["resourceVector"]!!.jsonObject
        val resolver = resolver(keys)

        val session =
            resolver.resolve(
                manifest = packageData["manifestUtf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                licenseJws = license["jws"]!!.jsonPrimitive.content,
            )

        assertArrayEquals(
            keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
            session.contentKey,
        )
        val resource = checkNotNull(session.resources.values.single())
        assertEquals(vector["plaintextLength"]!!.jsonPrimitive.content.toInt(), resource.plaintextLength)
        assertEquals(vector["aad"]!!.jsonPrimitive.content, resource.aad.toString(StandardCharsets.UTF_8))
    }

    @Test
    fun `changed manifest fails as package tampering`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                resolver(keys).resolve(
                    manifest = "{}".toByteArray(),
                    licenseJws = license["jws"]!!.jsonPrimitive.content,
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedPackageTampered, error.code)
    }

    @Test
    fun `expired license fails closed`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val packageData = fixture["package"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                resolver(keys, nowEpochMillis = Instant.parse("2037-01-01T00:00:00Z").toEpochMilli()).resolve(
                    manifest = packageData["manifestUtf8"]!!.jsonPrimitive.content.toByteArray(),
                    licenseJws = license["jws"]!!.jsonPrimitive.content,
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedLicenseExpired, error.code)
    }

    @Test
    fun `correctly signed license with unsupported version fails closed`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val packageData = fixture["package"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                resolver(keys).resolve(
                    manifest = packageData["manifestUtf8"]!!.jsonPrimitive.content.toByteArray(),
                    licenseJws = license["unsupportedVersionJws"]!!.jsonPrimitive.content,
                )
            }

        assertEquals(HarivuProtectionErrorCode.UnsupportedProtectionVersion, error.code)
    }

    private fun resolver(
        keys: kotlinx.serialization.json.JsonObject,
        nowEpochMillis: Long = Instant.parse("2026-11-09T00:00:00Z").toEpochMilli(),
    ) = HarivuProtectionSessionResolver(
        signingPublicKey = keys["signingPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
        devicePrivateKey = keys["devicePrivateKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
        expectedDeviceId = "harivu-dev-device-v1",
        expectedDeviceKeyId = "harivu-dev-device-key-v1",
        nowEpochMillis = { nowEpochMillis },
    )

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun String.base64UrlBytes(): ByteArray = Base64.getUrlDecoder().decode(this)
