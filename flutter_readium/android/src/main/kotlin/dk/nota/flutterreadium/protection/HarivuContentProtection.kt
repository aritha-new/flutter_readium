package dk.nota.flutterreadium.protection

import org.readium.r2.shared.publication.protection.ContentProtection
import org.readium.r2.shared.util.Try
import org.readium.r2.shared.util.Url
import org.readium.r2.shared.util.asset.Asset
import org.readium.r2.shared.util.asset.ContainerAsset
import org.readium.r2.shared.util.data.ReadError
import org.readium.r2.shared.util.getOrElse

internal data class HarivuProtectionSession(
    val contentKey: ByteArray,
    val resources: Map<Url, HarivuProtectedResource>,
)

internal class HarivuContentProtection(
    private val resolveSession: suspend (manifest: ByteArray) -> HarivuProtectionSession,
) : ContentProtection {
    override suspend fun open(
        asset: Asset,
        credentials: String?,
        allowUserInteraction: Boolean,
    ): Try<ContentProtection.OpenResult, ContentProtection.OpenError> {
        val containerAsset =
            asset as? ContainerAsset
                ?: return Try.failure(ContentProtection.OpenError.AssetNotSupported())
        val markerUrl = checkNotNull(Url("META-INF/harivu-protection.json"))
        val marker =
            containerAsset.container[markerUrl]
                ?: return Try.failure(ContentProtection.OpenError.AssetNotSupported())
        val manifest =
            marker.read().getOrElse {
                return Try.failure(ContentProtection.OpenError.Reading(it))
            }
        val session =
            try {
                resolveSession(manifest)
            } catch (error: HarivuProtectionException) {
                return Try.failure(
                    ContentProtection.OpenError.Reading(
                        ReadError.Decoding("Protected publication validation failed."),
                    ),
                )
            }
        return Try.success(
            ContentProtection.OpenResult(
                asset =
                    ContainerAsset(
                        format = containerAsset.format,
                        container =
                            HarivuDecryptingContainer(
                                container = containerAsset.container,
                                contentKey = session.contentKey,
                                resources = session.resources,
                            ),
                    ),
            ),
        )
    }
}
