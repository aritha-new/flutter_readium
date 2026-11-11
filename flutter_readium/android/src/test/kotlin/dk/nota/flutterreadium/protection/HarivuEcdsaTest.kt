package dk.nota.flutterreadium.protection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class HarivuEcdsaTest {
    private fun toDer(p1363: ByteArray): ByteArray {
        val r = BigInteger(1, p1363.copyOfRange(0, 32)).toByteArray()
        val s = BigInteger(1, p1363.copyOfRange(32, 64)).toByteArray()
        val body = 2 + r.size + 2 + s.size
        return byteArrayOf(0x30, body.toByte(), 0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
    }

    @Test
    fun `der signatures convert to a 64 byte P1363 signature that verifies, for many random keys`() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        repeat(300) { round ->
            val pair = generator.generateKeyPair()
            val message = "message-$round".toByteArray()
            val der =
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(pair.private)
                    update(message)
                    sign()
                }

            val p1363 = HarivuEcdsa.derToP1363(der)

            assertEquals(64, p1363.size)
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(pair.public as ECPublicKey)
            verifier.update(message)
            assertTrue("round $round", verifier.verify(toDer(p1363)))
        }
    }
}
