package dk.nota.flutterreadium.protection

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * The device's half of the content-key unwrap: ECDH between the device private key and the license's ephemeral
 * public key. The private key is never exposed through this interface, so it can live in hardware.
 *
 * Implementations throw [GeneralSecurityException] when they cannot agree; the unwrap then fails closed as a
 * device mismatch.
 */
internal fun interface HarivuDeviceKeyAgreement {
    @Throws(GeneralSecurityException::class)
    fun sharedSecret(ephemeralPublicKey: ByteArray): ByteArray
}

/** A software P-256 key. Used only for the bundled development device and its recorded vectors, never for real books. */
internal class HarivuSoftwareDeviceKey(
    private val devicePrivateKey: ByteArray,
) : HarivuDeviceKeyAgreement {
    override fun sharedSecret(ephemeralPublicKey: ByteArray): ByteArray {
        val parameters =
            AlgorithmParameters
                .getInstance("EC")
                .apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        val keyFactory = KeyFactory.getInstance("EC")
        val privateKey = keyFactory.generatePrivate(ECPrivateKeySpec(BigInteger(1, devicePrivateKey), parameters))
        val publicKey = keyFactory.generatePublic(ECPublicKeySpec(ephemeralPublicKey.toEcPoint(), parameters))
        return KeyAgreement
            .getInstance("ECDH")
            .apply {
                init(privateKey)
                doPhase(publicKey, true)
            }.generateSecret()
    }
}

internal fun ByteArray.toEcPoint(): ECPoint {
    if (size != 65 || first() != 0x04.toByte()) throw GeneralSecurityException("not an uncompressed P-256 point")
    return ECPoint(BigInteger(1, copyOfRange(1, 33)), BigInteger(1, copyOfRange(33, 65)))
}
