package dk.nota.flutterreadium.protection

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object HarivuContentKeyUnwrapper {
    fun unwrap(
        devicePrivateKey: ByteArray,
        ephemeralPublicKey: ByteArray,
        nonce: ByteArray,
        wrappedContentKey: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
        publicationId: String,
        deviceId: String,
    ): ByteArray =
        try {
            val parameters =
                AlgorithmParameters
                    .getInstance("EC")
                    .apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(ECParameterSpec::class.java)
            val keyFactory = KeyFactory.getInstance("EC")
            val privateKey =
                keyFactory.generatePrivate(
                    ECPrivateKeySpec(BigInteger(1, devicePrivateKey), parameters),
                )
            val publicKey =
                keyFactory.generatePublic(
                    ECPublicKeySpec(ephemeralPublicKey.toPoint(), parameters),
                )
            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(privateKey)
            agreement.doPhase(publicKey, true)
            val sharedSecret = agreement.generateSecret()
            val salt =
                MessageDigest
                    .getInstance("SHA-256")
                    .digest(
                        "harivu-license-v1|$publicationId|$deviceId"
                            .toByteArray(StandardCharsets.UTF_8),
                    )
            val wrappingKey =
                hkdfSha256(
                    inputKeyMaterial = sharedSecret,
                    salt = salt,
                    info = "harivu-content-key-wrap-v1".toByteArray(StandardCharsets.UTF_8),
                    outputLength = 32,
                )
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(wrappingKey, "AES"),
                GCMParameterSpec(tag.size * 8, nonce),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(wrappedContentKey + tag)
        } catch (error: GeneralSecurityException) {
            throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedDeviceMismatch)
        }

    private fun hkdfSha256(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = hmac.doFinal(inputKeyMaterial)
        val output = ByteArray(outputLength)
        var previous = byteArrayOf()
        var offset = 0
        var counter = 1
        while (offset < outputLength) {
            hmac.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
            hmac.update(previous)
            hmac.update(info)
            hmac.update(counter.toByte())
            previous = hmac.doFinal()
            val count = minOf(previous.size, outputLength - offset)
            previous.copyInto(output, offset, 0, count)
            offset += count
            counter += 1
        }
        return output
    }

    private fun ByteArray.toPoint(): ECPoint {
        require(size == 65 && first() == 0x04.toByte())
        return ECPoint(
            BigInteger(1, copyOfRange(1, 33)),
            BigInteger(1, copyOfRange(33, 65)),
        )
    }
}
