package dk.nota.flutterreadium.protection

import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object HarivuContentKeyUnwrapper {
    /** Convenience for the software development key and the recorded vectors. */
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
        unwrap(
            deviceKey = HarivuSoftwareDeviceKey(devicePrivateKey),
            ephemeralPublicKey = ephemeralPublicKey,
            nonce = nonce,
            wrappedContentKey = wrappedContentKey,
            tag = tag,
            aad = aad,
            publicationId = publicationId,
            deviceId = deviceId,
        )

    fun unwrap(
        deviceKey: HarivuDeviceKeyAgreement,
        ephemeralPublicKey: ByteArray,
        nonce: ByteArray,
        wrappedContentKey: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
        publicationId: String,
        deviceId: String,
    ): ByteArray =
        try {
            val sharedSecret = deviceKey.sharedSecret(ephemeralPublicKey)
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
}
