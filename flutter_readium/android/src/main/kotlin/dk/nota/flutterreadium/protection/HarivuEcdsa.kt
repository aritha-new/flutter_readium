package dk.nota.flutterreadium.protection

import java.math.BigInteger

internal object HarivuEcdsa {
    /** Converts a DER ECDSA signature to the 64-byte IEEE P1363 `R || S` form the backend verifies. */
    fun derToP1363(der: ByteArray): ByteArray {
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
