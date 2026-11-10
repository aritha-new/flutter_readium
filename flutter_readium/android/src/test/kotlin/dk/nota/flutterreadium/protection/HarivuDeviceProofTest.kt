package dk.nota.flutterreadium.protection

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
class HarivuDeviceProofTest {
    private val recordedDevicePublicKey =
        "BJhCJVhdIoXBOAM9YUDjzvi5GFlwTlPDE_i2NrpPlnZJlzQUT0b9GadnpUUofEOWuXtp3Tj6rqiYGtwaT-2bQB4"

    private fun decode(value: String): ByteArray = Base64.UrlSafe.decode(value.padEnd(value.length + (4 - value.length % 4) % 4, '='))

    private fun verify(
        publicKey: ByteArray,
        message: ByteArray,
        p1363: ByteArray,
    ): Boolean {
        val params =
            AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec("secp256r1"))
                getParameterSpec(ECParameterSpec::class.java)
            }
        val point = ECPoint(BigInteger(1, publicKey.copyOfRange(1, 33)), BigInteger(1, publicKey.copyOfRange(33, 65)))
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
        val r = BigInteger(1, p1363.copyOfRange(0, 32)).toByteArray()
        val s = BigInteger(1, p1363.copyOfRange(32, 64)).toByteArray()
        val body = 2 + r.size + 2 + s.size
        val der = byteArrayOf(0x30, body.toByte(), 0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(message)
            verify(der)
        }
    }

    @Test
    fun `the public key is the recorded development device key`() {
        assertEquals(recordedDevicePublicKey, HarivuDeviceProof.publicKeyBase64Url())
        assertEquals(65, HarivuDeviceProof.publicKey().size)
        assertEquals(4.toByte(), HarivuDeviceProof.publicKey()[0])
    }

    @Test
    fun `a proof is a 64 byte signature that verifies with the device public key only`() {
        val message = "harivu-device-registration-v1|challenge|nonce|dk-1".toByteArray()

        val signature = HarivuDeviceProof.sign(message)

        assertEquals(64, signature.size)
        assertTrue(verify(HarivuDeviceProof.publicKey(), message, signature))
        assertFalse(verify(HarivuDeviceProof.publicKey(), "other".toByteArray(), signature))
        val otherKey = decode("BI7VfsK49edekZIye1HlZhyHyOXbAXByEwmlF_xuEEaxVIHorjs50yN3jkUcse_rVB4TJadmft2HfGj69wUAdXU")
        assertFalse(verify(otherKey, message, signature))
    }

    @Test
    fun `proof signatures are not a constant`() {
        val message = "m".toByteArray()

        assertTrue(!HarivuDeviceProof.sign(message).contentEquals(HarivuDeviceProof.sign(message)))
        assertArrayEquals(HarivuDeviceProof.publicKey(), HarivuDeviceProof.publicKey())
    }
}
