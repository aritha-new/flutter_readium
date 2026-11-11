package dk.nota.flutterreadium.protection

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.readium.r2.shared.util.Url
import org.readium.r2.shared.util.data.Container
import org.readium.r2.shared.util.getOrElse
import org.readium.r2.shared.util.resource.InMemoryResource
import org.readium.r2.shared.util.resource.Resource
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.charset.StandardCharsets

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class HarivuDecryptingContainerTest {
    @Test
    fun `Readium resource access decrypts only the protected entry`() =
        runBlocking {
            val fixture = fixture()
            val keys = fixture["keys"]!!.jsonObject
            val vector = fixture["resourceVector"]!!.jsonObject
            val url = checkNotNull(Url(vector["path"]!!.jsonPrimitive.content))
            val original =
                MapContainer(
                    mapOf(
                        url to
                            InMemoryResource(
                                vector["ciphertextHex"]!!.jsonPrimitive.content.hexToBytes(),
                            ),
                    ),
                )
            val container =
                HarivuDecryptingContainer(
                    container = original,
                    contentKey = keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
                    resources =
                        mapOf(
                            url to
                                HarivuProtectedResource(
                                    nonce = vector["nonceHex"]!!.jsonPrimitive.content.hexToBytes(),
                                    tag = vector["tagHex"]!!.jsonPrimitive.content.hexToBytes(),
                                    aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                                    plaintextLength = vector["plaintextLength"]!!.jsonPrimitive.content.toInt(),
                                ),
                        ),
                )

            val plaintext = checkNotNull(container[url]).read().getOrElse { throw AssertionError(it.message) }

            assertArrayEquals(
                vector["plaintextUtf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                plaintext,
            )
        }

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private class MapContainer(
    private val resources: Map<Url, Resource>,
) : Container<Resource> {
    override val entries: Set<Url> = resources.keys

    override fun get(url: Url): Resource? = resources[url]

    override fun close() = Unit
}

private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
