package dk.nota.flutterreadium.protection

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class HarivuDeviceIdentityTest {
    private lateinit var root: File

    @Before
    fun setUp() {
        root = Files.createTempDirectory("harivu-device").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun write(json: String) = File(root, "device.json").writeText(json)

    private fun codeOf(block: () -> Unit): HarivuProtectionErrorCode = assertThrows(HarivuProtectionException::class.java) { block() }.code

    @Test
    fun `no device file means the development device`() {
        assertEquals(HarivuDeviceIdentity.DEVELOPMENT, HarivuDeviceIdentity.read(root))
        assertEquals("harivu-dev-device-v1", HarivuDeviceIdentity.DEVELOPMENT.deviceId)
        assertEquals("harivu-dev-device-key-v1", HarivuDeviceIdentity.DEVELOPMENT.deviceKeyId)
    }

    @Test
    fun `reads the registered device identity`() {
        write("""{"deviceId":"3b2f0c7e-1111-4222-8333-444455556666","deviceKeyId":"dk-android-1"}""")

        val identity = HarivuDeviceIdentity.read(root)

        assertEquals("3b2f0c7e-1111-4222-8333-444455556666", identity.deviceId)
        assertEquals("dk-android-1", identity.deviceKeyId)
    }

    @Test
    fun `a malformed or incomplete device file fails closed`() {
        for (bad in listOf(
            "",
            "not json",
            "{}",
            """{"deviceId":"a"}""",
            """{"deviceKeyId":"a"}""",
            "[]",
            """{"deviceId":1,"deviceKeyId":"a"}""",
        )) {
            write(bad)
            assertEquals(bad, HarivuProtectionErrorCode.OfflineAuthorizationUnavailable, codeOf { HarivuDeviceIdentity.read(root) })
        }
    }

    @Test
    fun `identifiers that could carry anything but a plain id are rejected`() {
        for (bad in listOf("../x", "a b", "a/b", "", "x".repeat(129), "-leading")) {
            write("""{"deviceId":"$bad","deviceKeyId":"ok"}""")
            assertEquals(bad, HarivuProtectionErrorCode.OfflineAuthorizationUnavailable, codeOf { HarivuDeviceIdentity.read(root) })
            write("""{"deviceId":"ok","deviceKeyId":"$bad"}""")
            assertEquals(bad, HarivuProtectionErrorCode.OfflineAuthorizationUnavailable, codeOf { HarivuDeviceIdentity.read(root) })
        }
    }
}
