package dk.nota.flutterreadium.protection

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * This device's key for the protected reader, a P-256 key that lives in the Android Keystore (StrongBox when the
 * device has it, else the trusted environment) and never leaves it. One key does both jobs: it signs the
 * registration proof and takes part in the ECDH that unwraps a license's content key.
 *
 * ECDH with a Keystore key needs Android 12 (API 31). Older devices report [isSupported] as false and cannot read
 * protected books; there is deliberately no software fallback.
 */
internal object HarivuKeystoreDeviceKey : HarivuDeviceKeyAgreement {
    private const val ALIAS = "harivu-device-key-v1"
    private const val PROVIDER = "AndroidKeyStore"

    enum class Protection(
        val wire: String,
    ) {
        Hardware("hardware"),
        Software("software"),
    }

    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    /** Whether the key is held by secure hardware. A key the system holds in software is reported as such. */
    fun protection(): Protection {
        val key = privateKey()
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        return if (info.securityLevel == KeyProperties.SECURITY_LEVEL_SOFTWARE) Protection.Software else Protection.Hardware
    }

    /** The public key as an uncompressed P-256 point (65 bytes). */
    fun publicKey(): ByteArray {
        ensureKey()
        val point = (keyStore().getCertificate(ALIAS).publicKey as ECPublicKey).w
        return byteArrayOf(0x04) + fixed32(point.affineX.toByteArray()) + fixed32(point.affineY.toByteArray())
    }

    /** ECDSA P-256 / SHA-256 over [message] as a 64-byte IEEE P1363 signature. */
    fun sign(message: ByteArray): ByteArray {
        val der =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey())
                update(message)
                sign()
            }
        return HarivuEcdsa.derToP1363(der)
    }

    override fun sharedSecret(ephemeralPublicKey: ByteArray): ByteArray {
        val parameters =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                // Only the curve parameters are needed to rebuild the peer's public key.
                (generateKeyPair().public as ECPublicKey).params
            }
        val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ephemeralPublicKey.toEcPoint(), parameters))
        return KeyAgreement
            .getInstance("ECDH")
            .apply {
                init(privateKey())
                doPhase(peer, true)
            }.generateSecret()
    }

    @Synchronized
    private fun privateKey(): PrivateKey {
        ensureKey()
        return keyStore().getKey(ALIAS, null) as? PrivateKey ?: throw GeneralSecurityException("device key missing")
    }

    @Synchronized
    private fun ensureKey() {
        if (!isSupported()) throw GeneralSecurityException("device keys need Android 12 or newer")
        if (!keyStore().containsAlias(ALIAS)) generateKey()
    }

    private fun generateKey() {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)

        fun spec(strongBox: Boolean) =
            KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()
        try {
            generator.initialize(spec(strongBox = true))
            generator.generateKeyPair()
        } catch (_: StrongBoxUnavailableException) {
            generator.initialize(spec(strongBox = false))
            generator.generateKeyPair()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun fixed32(value: ByteArray): ByteArray {
        val unsigned = if (value.size > 32) value.copyOfRange(value.size - 32, value.size) else value
        return ByteArray(32 - unsigned.size) + unsigned
    }
}
