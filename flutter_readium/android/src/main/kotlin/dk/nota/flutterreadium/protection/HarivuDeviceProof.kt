package dk.nota.flutterreadium.protection

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Proof of possession of the device key, used when the app registers this device with the backend.
 *
 * DEVELOPMENT ONLY: the device key is the recorded Phase 2B development key, whose private half is public
 * in the test vectors. Production replaces it with a non-exportable platform key. The private key never
 * leaves native code; only the public key and a signature are returned.
 */
@OptIn(ExperimentalEncodingApi::class)
internal object HarivuDeviceProof {
    private const val DEVICE_PUBLIC_KEY_BASE64URL =
        "BJhCJVhdIoXBOAM9YUDjzvi5GFlwTlPDE_i2NrpPlnZJlzQUT0b9GadnpUUofEOWuXtp3Tj6rqiYGtwaT-2bQB4"

    fun publicKey(): ByteArray =
        Base64.UrlSafe.decode(
            DEVICE_PUBLIC_KEY_BASE64URL.padEnd(
                DEVICE_PUBLIC_KEY_BASE64URL.length + (4 - DEVICE_PUBLIC_KEY_BASE64URL.length % 4) % 4,
                '=',
            ),
        )

    fun publicKeyBase64Url(): String = DEVICE_PUBLIC_KEY_BASE64URL

    /** ECDSA P-256 / SHA-256 over [message] as a 64-byte IEEE P1363 `R || S` signature. */
    fun sign(message: ByteArray): ByteArray {
        val params =
            AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec("secp256r1"))
                getParameterSpec(ECParameterSpec::class.java)
            }
        val scalar = BigInteger(1, HarivuProtectedFixture.devicePrivateKeyBytes())
        val key = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(scalar, params))
        val der =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(message)
                sign()
            }
        return derToP1363(der)
    }

    private fun derToP1363(der: ByteArray): ByteArray {
        var offset = 2
        if (der[1].toInt() and 0x80 != 0) offset += der[1].toInt() and 0x7f
        val rLength = der[offset + 1].toInt()
        val r = der.copyOfRange(offset + 2, offset + 2 + rLength)
        val sOffset = offset + 2 + rLength
        val sLength = der[sOffset + 1].toInt()
        val s = der.copyOfRange(sOffset + 2, sOffset + 2 + sLength)
        return fixed32(r) + fixed32(s)
    }

    private fun fixed32(value: ByteArray): ByteArray {
        val unsigned = BigInteger(1, value).toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - unsigned.size) + unsigned
    }
}
