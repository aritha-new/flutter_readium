package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets

class HarivuResourceCryptoTest {
    @Test
    fun `recorded v1 resource decrypts to the expected plaintext`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val vector = fixture["resourceVector"]!!.jsonObject

        val plaintext =
            HarivuResourceCrypto.decrypt(
                contentKey = keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
                nonce = vector["nonceHex"]!!.jsonPrimitive.content.hexToBytes(),
                ciphertext = vector["ciphertextHex"]!!.jsonPrimitive.content.hexToBytes(),
                tag = vector["tagHex"]!!.jsonPrimitive.content.hexToBytes(),
                aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                expectedPlaintextLength = vector["plaintextLength"]!!.jsonPrimitive.content.toInt(),
            )

        assertArrayEquals(
            vector["plaintextUtf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
            plaintext,
        )
    }

    @Test
    fun `changed authentication tag fails closed as package tampering`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val vector = fixture["resourceVector"]!!.jsonObject
        val changedTag = vector["tagHex"]!!.jsonPrimitive.content.hexToBytes()
        changedTag[0] = (changedTag[0].toInt() xor 1).toByte()

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                HarivuResourceCrypto.decrypt(
                    contentKey = keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
                    nonce = vector["nonceHex"]!!.jsonPrimitive.content.hexToBytes(),
                    ciphertext = vector["ciphertextHex"]!!.jsonPrimitive.content.hexToBytes(),
                    tag = changedTag,
                    aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                    expectedPlaintextLength = vector["plaintextLength"]!!.jsonPrimitive.content.toInt(),
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedPackageTampered, error.code)
    }

    @Test
    fun `declared plaintext above 2 MiB is rejected before decryption`() {
        val error =
            assertThrows(HarivuProtectionException::class.java) {
                HarivuResourceCrypto.decrypt(
                    contentKey = ByteArray(32),
                    nonce = ByteArray(12),
                    ciphertext = byteArrayOf(1),
                    tag = ByteArray(16),
                    aad = byteArrayOf(),
                    expectedPlaintextLength = 2 * 1024 * 1024 + 1,
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedResourceTooLarge, error.code)
    }

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
