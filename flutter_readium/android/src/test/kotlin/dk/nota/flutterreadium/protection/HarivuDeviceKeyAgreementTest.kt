package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.util.Base64

/** The content key is unwrapped through a key-agreement seam, so a hardware key can replace the software one. */
class HarivuDeviceKeyAgreementTest {
    private fun fixture(): JsonObject =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }

    private fun unwrapWith(agreement: HarivuDeviceKeyAgreement): ByteArray {
        val vector = fixture()["keyWrapVector"]!!.jsonObject
        return HarivuContentKeyUnwrapper.unwrap(
            deviceKey = agreement,
            ephemeralPublicKey = vector["ephemeralPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
            nonce = vector["nonce"]!!.jsonPrimitive.content.base64UrlBytes(),
            wrappedContentKey = vector["wrappedContentKey"]!!.jsonPrimitive.content.base64UrlBytes(),
            tag = vector["tag"]!!.jsonPrimitive.content.base64UrlBytes(),
            aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
            publicationId = "harivu-phase2-fixture",
            deviceId = "harivu-dev-device-v1",
        )
    }

    @Test
    fun `the software device key agrees on the recorded secret and unwraps the content key`() {
        val keys = fixture()["keys"]!!.jsonObject
        val key = HarivuSoftwareDeviceKey(keys["devicePrivateKeyHex"]!!.jsonPrimitive.content.hexToBytes())

        assertArrayEquals(keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(), unwrapWith(key))
    }

    @Test
    fun `the unwrapper only ever hands the ephemeral public key to the device key`() {
        val keys = fixture()["keys"]!!.jsonObject
        val software = HarivuSoftwareDeviceKey(keys["devicePrivateKeyHex"]!!.jsonPrimitive.content.hexToBytes())
        val seen = mutableListOf<ByteArray>()

        unwrapWith(
            HarivuDeviceKeyAgreement { ephemeral ->
                seen += ephemeral
                software.sharedSecret(ephemeral)
            },
        )

        assertEquals(1, seen.size)
        assertEquals(65, seen.single().size)
        assertEquals(0x04.toByte(), seen.single()[0])
    }

    @Test
    fun `a device key that fails to agree fails closed as device mismatch`() {
        val error =
            assertThrows(HarivuProtectionException::class.java) {
                unwrapWith(HarivuDeviceKeyAgreement { throw GeneralSecurityException("key unavailable") })
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedDeviceMismatch, error.code)
    }

    @Test
    fun `a device key that agrees on the wrong secret fails closed as device mismatch`() {
        val error =
            assertThrows(HarivuProtectionException::class.java) {
                unwrapWith(HarivuDeviceKeyAgreement { ByteArray(32) { 7 } })
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedDeviceMismatch, error.code)
    }

    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun String.base64UrlBytes(): ByteArray = Base64.getUrlDecoder().decode(this)
}
