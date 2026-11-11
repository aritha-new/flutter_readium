package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.Base64

class HarivuContentKeyUnwrapperTest {
    @Test
    fun `recorded v1 device unwraps the expected content key`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val vector = fixture["keyWrapVector"]!!.jsonObject

        val contentKey =
            HarivuContentKeyUnwrapper.unwrap(
                devicePrivateKey = keys["devicePrivateKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
                ephemeralPublicKey = vector["ephemeralPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
                nonce = vector["nonce"]!!.jsonPrimitive.content.base64UrlBytes(),
                wrappedContentKey = vector["wrappedContentKey"]!!.jsonPrimitive.content.base64UrlBytes(),
                tag = vector["tag"]!!.jsonPrimitive.content.base64UrlBytes(),
                aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                publicationId = "harivu-phase2-fixture",
                deviceId = "harivu-dev-device-v1",
            )

        assertArrayEquals(keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(), contentKey)
    }

    @Test
    fun `different device private key fails closed as device mismatch`() {
        val fixture = fixture()
        val vector = fixture["keyWrapVector"]!!.jsonObject
        val wrongDeviceKey = ByteArray(32) { (it + 1).toByte() }

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                HarivuContentKeyUnwrapper.unwrap(
                    devicePrivateKey = wrongDeviceKey,
                    ephemeralPublicKey = vector["ephemeralPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
                    nonce = vector["nonce"]!!.jsonPrimitive.content.base64UrlBytes(),
                    wrappedContentKey = vector["wrappedContentKey"]!!.jsonPrimitive.content.base64UrlBytes(),
                    tag = vector["tag"]!!.jsonPrimitive.content.base64UrlBytes(),
                    aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                    publicationId = "harivu-phase2-fixture",
                    deviceId = "harivu-dev-device-v1",
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedDeviceMismatch, error.code)
    }

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private fun String.base64UrlBytes(): ByteArray = Base64.getUrlDecoder().decode(this)

private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
