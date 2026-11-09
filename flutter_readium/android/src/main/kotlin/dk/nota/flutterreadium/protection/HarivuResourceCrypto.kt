package dk.nota.flutterreadium.protection

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object HarivuResourceCrypto {
    private const val MAX_PLAINTEXT_RESOURCE_SIZE = 2 * 1024 * 1024

    fun decrypt(
        contentKey: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
        expectedPlaintextLength: Int,
    ): ByteArray {
        if (expectedPlaintextLength > MAX_PLAINTEXT_RESOURCE_SIZE) {
            throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedResourceTooLarge)
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(contentKey, "AES"),
            GCMParameterSpec(tag.size * 8, nonce),
        )
        cipher.updateAAD(aad)
        return try {
            val plaintext = cipher.doFinal(ciphertext + tag)
            if (plaintext.size != expectedPlaintextLength) {
                throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedPackageTampered)
            }
            plaintext
        } catch (error: GeneralSecurityException) {
            throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedPackageTampered)
        }
    }
}
