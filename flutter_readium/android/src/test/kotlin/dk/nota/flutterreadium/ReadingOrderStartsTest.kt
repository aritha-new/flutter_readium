package dk.nota.flutterreadium

import org.junit.Assert.assertEquals
import org.junit.Test

internal class ReadingOrderStartsTest {
    @Test
    fun `each item starts after the positions of the items before it`() {
        assertEquals(listOf(0.0, 0.25, 0.75), readingOrderStarts(listOf(1, 2, 1)))
    }

    @Test
    fun `no positions gives no starts`() {
        assertEquals(emptyList<Double>(), readingOrderStarts(emptyList()))
        assertEquals(emptyList<Double>(), readingOrderStarts(listOf(0, 0)))
    }
}
