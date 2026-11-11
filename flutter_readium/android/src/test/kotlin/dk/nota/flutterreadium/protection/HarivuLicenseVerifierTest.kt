package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class HarivuLicenseVerifierTest {
    @Test
    fun `recorded v1 JWS verifies to the exact license payload`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject

        val payload =
            HarivuLicenseVerifier.verifySignature(
                jws = license["jws"]!!.jsonPrimitive.content,
                signingPublicKey = keys["signingPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
            )

        assertEquals(license["payloadUtf8"]!!.jsonPrimitive.content, payload)
    }

    @Test
    fun `changed JWS signature fails closed as invalid license`() {
        val fixture = fixture()
        val keys = fixture["keys"]!!.jsonObject
        val license = fixture["license"]!!.jsonObject
        val jws = license["jws"]!!.jsonPrimitive.content
        val changedJws = jws.dropLast(1) + if (jws.last() == 'A') "B" else "A"

        val error =
            assertThrows(HarivuProtectionException::class.java) {
                HarivuLicenseVerifier.verifySignature(
                    jws = changedJws,
                    signingPublicKey = keys["signingPublicKey"]!!.jsonPrimitive.content.base64UrlBytes(),
                )
            }

        assertEquals(HarivuProtectionErrorCode.ProtectedLicenseInvalid, error.code)
    }

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private fun String.base64UrlBytes(): ByteArray = Base64.getUrlDecoder().decode(this)
