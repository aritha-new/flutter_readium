package dk.nota.flutterreadium.protection

import org.junit.Assert.assertEquals
import org.junit.Test

class HarivuProtectedFixtureTest {
    @Test
    fun `embedded unpadded signing key decodes to an uncompressed P-256 point`() {
        val key = HarivuProtectedFixture.signingPublicKey()

        assertEquals(65, key.size)
        assertEquals(0x04, key[0].toInt())
    }
}
