package dk.nota.flutterreadium.protection

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

internal object HarivuLicenseVerifier {
    private const val PROTECTED_HEADER =
        "{\"alg\":\"ES256\",\"kid\":\"harivu-dev-signing-key-v1\",\"typ\":\"harivu-license+jws\"}"

    @OptIn(ExperimentalEncodingApi::class)
    fun verifySignature(
        jws: String,
        signingPublicKey: ByteArray,
    ): String =
        try {
            val parts = jws.split('.')
            if (parts.size != 3) invalidLicense()
            val header = decodeBase64Url(parts[0]).toString(StandardCharsets.UTF_8)
            if (header != PROTECTED_HEADER) invalidLicense()
            val parameters =
                AlgorithmParameters
                    .getInstance("EC")
                    .apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(ECParameterSpec::class.java)
            val publicKey =
                KeyFactory
                    .getInstance("EC")
                    .generatePublic(
                        ECPublicKeySpec(signingPublicKey.toPoint(), parameters),
                    )
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update("${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII))
            if (!verifier.verify(decodeBase64Url(parts[2]).p1363ToDer())) {
                invalidLicense()
            }
            decodeBase64Url(parts[1]).toString(StandardCharsets.UTF_8)
        } catch (error: HarivuProtectionException) {
            throw error
        } catch (error: GeneralSecurityException) {
            invalidLicense()
        } catch (error: IllegalArgumentException) {
            invalidLicense()
        }

    @OptIn(ExperimentalEncodingApi::class)
    private fun decodeBase64Url(value: String): ByteArray =
        Base64.UrlSafe.decode(value.padEnd(value.length + (4 - value.length % 4) % 4, '='))

    private fun ByteArray.toPoint(): ECPoint {
        if (size != 65 || first() != 0x04.toByte()) invalidLicense()
        return ECPoint(
            BigInteger(1, copyOfRange(1, 33)),
            BigInteger(1, copyOfRange(33, 65)),
        )
    }

    private fun ByteArray.p1363ToDer(): ByteArray {
        if (size != 64) invalidLicense()
        val r = copyOfRange(0, 32).derInteger()
        val s = copyOfRange(32, 64).derInteger()
        return byteArrayOf(0x30, (r.size + s.size + 4).toByte(), 0x02, r.size.toByte()) +
            r +
            byteArrayOf(0x02, s.size.toByte()) +
            s
    }

    private fun ByteArray.derInteger(): ByteArray {
        val firstNonZero = indexOfFirst { it != 0.toByte() }.let { if (it == -1) lastIndex else it }
        val unsigned = copyOfRange(firstNonZero, size)
        return if (unsigned.first().toInt() and 0x80 != 0) byteArrayOf(0) + unsigned else unsigned
    }

    private fun invalidLicense(): Nothing = throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedLicenseInvalid)
}
