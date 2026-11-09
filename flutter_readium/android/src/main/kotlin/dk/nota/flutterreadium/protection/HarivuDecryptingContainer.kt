package dk.nota.flutterreadium.protection

import org.readium.r2.shared.util.Try
import org.readium.r2.shared.util.Url
import org.readium.r2.shared.util.data.Container
import org.readium.r2.shared.util.data.ReadError
import org.readium.r2.shared.util.resource.Resource
import org.readium.r2.shared.util.resource.TransformingContainer
import org.readium.r2.shared.util.resource.TransformingResource

internal data class HarivuProtectedResource(
    val nonce: ByteArray,
    val tag: ByteArray,
    val aad: ByteArray,
    val plaintextLength: Int,
)

internal class HarivuDecryptingContainer(
    container: Container<Resource>,
    contentKey: ByteArray,
    resources: Map<Url, HarivuProtectedResource>,
) : Container<Resource> by TransformingContainer(
        container,
        transformer = { url, resource ->
            val protectedResource = resources[url]
            if (protectedResource == null) {
                resource
            } else {
                TransformingResource(resource) { ciphertext ->
                    try {
                        Try.success(
                            HarivuResourceCrypto.decrypt(
                                contentKey = contentKey,
                                nonce = protectedResource.nonce,
                                ciphertext = ciphertext,
                                tag = protectedResource.tag,
                                aad = protectedResource.aad,
                                expectedPlaintextLength = protectedResource.plaintextLength,
                            ),
                        )
                    } catch (error: HarivuProtectionException) {
                        Try.failure(ReadError.Decoding("Protected resource validation failed."))
                    }
                }
            }
        },
    )
