package dk.nota.flutterreadium.models

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.readium.r2.shared.util.Url
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [28])
internal class PageInformationTest {
    private val href = Url("text/chapter-1.xhtml")!!

    @Test
    fun `keeps the script's page in the file and page count`() {
        val info =
            PageInformation.fromJson(
                JSONObject("""{"currentPage":3,"totalPages":25,"cssSelector":"p"}"""),
                href,
            )

        assertEquals(3, info.otherLocations["currentPage"])
        assertEquals(25, info.otherLocations["totalPages"])
    }

    @Test
    fun `leaves out missing or zero page values`() {
        val info =
            PageInformation.fromJson(
                JSONObject("""{"currentPage":0,"cssSelector":"p"}"""),
                href,
            )

        assertFalse(info.otherLocations.containsKey("currentPage"))
        assertFalse(info.otherLocations.containsKey("totalPages"))
    }
}
