package dk.nota.flutterreadium.protection

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.readium.r2.shared.publication.protection.ContentProtection
import org.readium.r2.shared.util.FileExtension
import org.readium.r2.shared.util.Url
import org.readium.r2.shared.util.asset.ContainerAsset
import org.readium.r2.shared.util.data.Container
import org.readium.r2.shared.util.format.Format
import org.readium.r2.shared.util.format.FormatSpecification
import org.readium.r2.shared.util.format.Specification
import org.readium.r2.shared.util.getOrElse
import org.readium.r2.shared.util.mediatype.MediaType
import org.readium.r2.shared.util.resource.InMemoryResource
import org.readium.r2.shared.util.resource.Resource
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.charset.StandardCharsets

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class HarivuContentProtectionTest {
    @Test
    fun `ordinary EPUB without Harivu marker is not claimed`() =
        runBlocking {
            val protection =
                HarivuContentProtection(
                    resolveSession = { throw AssertionError("Resolver must not be called") },
                )
            val asset = ContainerAsset(epubFormat, TestContainer(emptyMap()))

            val result =
                protection.open(
                    asset = asset,
                    credentials = null,
                    allowUserInteraction = false,
                )

            assertTrue(result.failureOrNull() is ContentProtection.OpenError.AssetNotSupported)
        }

    @Test
    fun `Harivu marker returns an asset that decrypts protected resources`() =
        runBlocking {
            val fixture = fixture()
            val keys = fixture["keys"]!!.jsonObject
            val packageData = fixture["package"]!!.jsonObject
            val vector = fixture["resourceVector"]!!.jsonObject
            val markerBytes = packageData["manifestUtf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8)
            val markerUrl = checkNotNull(Url("META-INF/harivu-protection.json"))
            val resourceUrl = checkNotNull(Url(vector["path"]!!.jsonPrimitive.content))
            val protection =
                HarivuContentProtection(
                    resolveSession = { manifest ->
                        assertArrayEquals(markerBytes, manifest)
                        HarivuProtectionSession(
                            contentKey = keys["contentKeyHex"]!!.jsonPrimitive.content.hexToBytes(),
                            resources =
                                mapOf(
                                    resourceUrl to
                                        HarivuProtectedResource(
                                            nonce = vector["nonceHex"]!!.jsonPrimitive.content.hexToBytes(),
                                            tag = vector["tagHex"]!!.jsonPrimitive.content.hexToBytes(),
                                            aad = vector["aad"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8),
                                            plaintextLength = vector["plaintextLength"]!!.jsonPrimitive.content.toInt(),
                                        ),
                                ),
                        )
                    },
                )
            val asset =
                ContainerAsset(
                    epubFormat,
                    TestContainer(
                        mapOf(
                            markerUrl to InMemoryResource(markerBytes),
                            resourceUrl to InMemoryResource(vector["ciphertextHex"]!!.jsonPrimitive.content.hexToBytes()),
                        ),
                    ),
                )

            val opened =
                protection
                    .open(asset = asset, credentials = null, allowUserInteraction = false)
                    .getOrElse { throw AssertionError(it.message) }
                    .asset as ContainerAsset
            val plaintext = checkNotNull(opened.container[resourceUrl]).read().getOrElse { throw AssertionError(it.message) }

            assertEquals(vector["plaintextUtf8"]!!.jsonPrimitive.content, plaintext.toString(StandardCharsets.UTF_8))
        }

    private val epubFormat =
        Format(
            specification = FormatSpecification(Specification.Epub, Specification.Zip),
            mediaType = MediaType.EPUB,
            fileExtension = FileExtension("epub"),
        )

    private fun fixture() =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("harivu_protection_v1.json"))
            .bufferedReader()
            .use { Json.parseToJsonElement(it.readText()).jsonObject }
}

private class TestContainer(
    private val resources: Map<Url, Resource>,
) : Container<Resource> {
    override val entries: Set<Url> = resources.keys

    override fun get(url: Url): Resource? = resources[url]

    override fun close() = Unit
}

private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
