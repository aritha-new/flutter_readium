package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

internal data class HarivuLocatedPublication(
    val packageFile: File,
    val licenseJws: String,
)

/**
 * Finds a downloaded protected publication from an opaque identifier.
 *
 * Layout written by the app's package store: `root/<id>/v<N>/{package.epub,license.json}`.
 * A version is usable only when both files exist (the license is written last).
 * The identifier is validated so it can never address anything outside [root].
 */
internal object HarivuDownloadedPublicationLocator {
    private val validId = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    private val versionDir = Regex("v(\\d+)")

    fun locate(
        root: File,
        opaqueId: String,
    ): HarivuLocatedPublication {
        if (!validId.matches(opaqueId) || opaqueId.contains("..")) unavailable()
        val publicationDir = File(root, opaqueId)
        val versions =
            publicationDir
                .listFiles { file -> file.isDirectory && versionDir.matches(file.name) }
                ?.sortedByDescending { versionDir.matchEntire(it.name)!!.groupValues[1].toInt() }
                ?: unavailable()
        for (dir in versions) {
            val packageFile = File(dir, "package.epub")
            val licenseFile = File(dir, "license.json")
            if (packageFile.isFile && licenseFile.isFile) {
                return HarivuLocatedPublication(packageFile, readLicenseJws(licenseFile))
            }
        }
        unavailable()
    }

    private fun readLicenseJws(file: File): String =
        try {
            Json
                .parseToJsonElement(file.readText())
                .jsonObject["jws"]!!
                .jsonPrimitive.content
        } catch (_: Exception) {
            throw HarivuProtectionException(HarivuProtectionErrorCode.ProtectedLicenseInvalid)
        }

    private fun unavailable(): Nothing = throw HarivuProtectionException(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
}
