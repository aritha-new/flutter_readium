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
import java.security.ProviderException
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * This device's key for the protected reader: an RSA-2048 key in the Android Keystore (StrongBox when the device
 * has it, else the trusted environment) that never leaves it. The same key signs the registration proof
 * (RSASSA-PKCS1-v1_5, SHA-256) and decrypts the AES key of a license's hybrid content-key wrap (RSA-OAEP,
 * SHA-256, MGF1 with SHA-1).
 *
 * RSA rather than EC on purpose: on test hardware an EC key-agreement key silently became a software key
 * (while EC signing and RSA stayed in hardware), so the key-agreement purpose cannot be trusted to be hardware
 * backed. RSA decrypt and sign are hardware backed broadly and need only API 23. There is no software fallback.
 */
internal object HarivuKeystoreDeviceKey : HarivuDeviceKeyAgreement, HarivuDeviceKeyDecryptor {
    private const val ALIAS = "harivu-device-key-v3-rsa"
    private val LEGACY_ALIASES = listOf("harivu-device-key-v1", "harivu-device-key-v2-rsa")

    /**
     * Fixed attestation challenge. The key is created before the server issues a registration challenge, so it
     * cannot carry a fresh one; freshness comes from the registration proof signed by this key. The backend
     * checks that the attestation carries this value.
     */
    private val ATTESTATION_CHALLENGE = "harivu-device-key-v1".toByteArray(Charsets.UTF_8)
    private const val PROVIDER = "AndroidKeyStore"

    enum class Protection(
        val wire: String,
    ) {
        Hardware("hardware"),
        Software("software"),
    }

    /** RSA-OAEP in the Keystore needs API 23; the plugin's minimum is 24. */
    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N

    /** Whether the key is held by secure hardware. A key the system holds in software is reported as such. */
    fun protection(): Protection {
        val key = privateKey()
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        val inHardware =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
            } else {
                @Suppress("DEPRECATION")
                info.isInsideSecureHardware
            }
        return if (inHardware) Protection.Hardware else Protection.Software
    }

    /** The public key as an X.509 SubjectPublicKeyInfo (DER). */
    fun publicKey(): ByteArray {
        ensureKey()
        return keyStore().getCertificate(ALIAS).publicKey.encoded
    }

    /**
     * The Keystore attestation chain of the key, leaf first, as DER certificates. The platform signs it up to a
     * Google root, so the backend can tell a key held in secure hardware from a claim. A key that could not be
     * attested has a chain whose leaf is self signed; the backend refuses such a chain.
     */
    fun attestationChain(): List<ByteArray> {
        ensureKey()
        return keyStore().getCertificateChain(ALIAS)?.map { it.encoded } ?: emptyList()
    }

    /** RSASSA-PKCS1-v1_5 over [message] with SHA-256. */
    fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey())
            update(message)
            sign()
        }

    override fun decrypt(encryptedKey: ByteArray): ByteArray =
        Cipher
            .getInstance("RSA/ECB/OAEPPadding")
            .apply {
                init(
                    Cipher.DECRYPT_MODE,
                    privateKey(),
                    OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
                )
            }.doFinal(encryptedKey)

    /** This key does not do ECDH; a license for it uses the RSA wrap. */
    override fun sharedSecret(ephemeralPublicKey: ByteArray): ByteArray = throw GeneralSecurityException("RSA device key")

    @Synchronized
    private fun privateKey(): PrivateKey {
        ensureKey()
        return keyStore().getKey(ALIAS, null) as? PrivateKey ?: throw GeneralSecurityException("device key missing")
    }

    @Synchronized
    private fun ensureKey() {
        if (!isSupported()) throw GeneralSecurityException("device keys need Android 7 or newer")
        val store = keyStore()
        // Earlier development builds created keys under other names (an EC key, then an RSA key without an
        // attestation); they are never used, and the device registers again with the new key.
        LEGACY_ALIASES.filter(store::containsAlias).forEach(store::deleteEntry)
        if (!store.containsAlias(ALIAS)) generateKey()
    }

    private fun generateKey() {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PROVIDER)

        fun create(
            strongBox: Boolean,
            attest: Boolean,
        ) {
            val spec =
                KeyGenParameterSpec
                    .Builder(ALIAS, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(false)
                    .apply {
                        if (attest) setAttestationChallenge(ATTESTATION_CHALLENGE)
                        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                    }.build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        try {
            create(strongBox = true, attest = true)
        } catch (_: StrongBoxUnavailableException) {
            attestedInTee(::create)
        }
    }

    /** The trusted environment, attested; a device that cannot attest still gets a key, which the backend refuses. */
    private fun attestedInTee(create: (strongBox: Boolean, attest: Boolean) -> Unit) {
        try {
            create(false, true)
        } catch (_: ProviderException) {
            create(false, false)
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
}
