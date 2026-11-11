package dk.nota.flutterreadium.protection

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class HarivuDownloadedPublicationLocatorTest {
    private lateinit var root: File

    @Before
    fun setUp() {
        root = Files.createTempDirectory("harivu-locator").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun install(
        id: String,
        version: Int,
        jws: String? = "a.b.c",
        withPackage: Boolean = true,
    ) {
        val dir = File(root, "$id/v$version").apply { mkdirs() }
        if (withPackage) File(dir, "package.epub").writeText("epub-$version")
        if (jws != null) File(dir, "license.json").writeText("""{"licenseId":"l","jws":"$jws","expiresAt":"x","notBefore":"y"}""")
    }

    private fun codeOf(block: () -> Unit): HarivuProtectionErrorCode = assertThrows(HarivuProtectionException::class.java) { block() }.code

    @Test
    fun `finds the package and license of the highest complete version`() {
        install("book-1", 1, jws = "old.old.old")
        install("book-1", 2, jws = "new.new.new")

        val located = HarivuDownloadedPublicationLocator.locate(root, "book-1")

        assertEquals("epub-2", located.packageFile.readText())
        assertEquals("new.new.new", located.licenseJws)
    }

    @Test
    fun `ignores a newer version that has no license yet`() {
        install("book-1", 1)
        install("book-1", 2, jws = null)

        assertEquals("epub-1", HarivuDownloadedPublicationLocator.locate(root, "book-1").packageFile.readText())
    }

    @Test
    fun `ignores a newer version that has no package`() {
        install("book-1", 1)
        install("book-1", 2, withPackage = false)

        assertEquals("epub-1", HarivuDownloadedPublicationLocator.locate(root, "book-1").packageFile.readText())
    }

    @Test
    fun `unknown publication is unavailable`() {
        assertEquals(
            HarivuProtectionErrorCode.OfflineAuthorizationUnavailable,
            codeOf { HarivuDownloadedPublicationLocator.locate(root, "missing") },
        )
    }

    @Test
    fun `identifiers that could escape the store are rejected`() {
        File(root.parentFile, "outside").apply { mkdirs() }
        for (id in listOf("", "..", "../outside", "a/b", "a\\b", ".hidden", "x".repeat(200))) {
            assertEquals(
                "id=$id",
                HarivuProtectionErrorCode.OfflineAuthorizationUnavailable,
                codeOf { HarivuDownloadedPublicationLocator.locate(root, id) },
            )
        }
    }

    @Test
    fun `a malformed license file is an invalid license`() {
        install("book-1", 1)
        File(root, "book-1/v1/license.json").writeText("not json")

        assertEquals(
            HarivuProtectionErrorCode.ProtectedLicenseInvalid,
            codeOf { HarivuDownloadedPublicationLocator.locate(root, "book-1") },
        )
    }
}
