package dk.nota.flutterreadium

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ProtectedResourceExportBlockTest {
    @After
    fun resetFlag() = setProtected(false)

    @Test
    fun `getResourceUrl is blocked while a protected publication is open`() {
        setProtected(true)
        val latch = CountDownLatch(1)
        var errorCode: String? = null
        var succeeded = false

        PublicationMethodCallHandler().onMethodCall(
            MethodCall("getResourceUrl", mapOf("href" to "chapter1.xhtml")),
            object : MethodChannel.Result {
                override fun success(result: Any?) {
                    succeeded = true
                    latch.countDown()
                }

                override fun error(
                    errorCode2: String,
                    errorMessage: String?,
                    errorDetails: Any?,
                ) {
                    errorCode = errorCode2
                    latch.countDown()
                }

                override fun notImplemented() = latch.countDown()
            },
        )

        assertTrue(latch.await(10, TimeUnit.SECONDS))
        assertEquals(false, succeeded)
        assertEquals("ProtectedResourceExportBlocked", errorCode)
    }

    private fun setProtected(value: Boolean) {
        ReadiumReader::class.java
            .getDeclaredField("currentPublicationIsProtected")
            .apply { isAccessible = true }
            .setBoolean(ReadiumReader, value)
    }
}
