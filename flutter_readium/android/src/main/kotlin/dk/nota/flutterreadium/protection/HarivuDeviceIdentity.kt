package dk.nota.flutterreadium.protection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

/**
 * The device id and device key id a license must be bound to. They are plain identifiers (no key material),
 * written by the Flutter app after the device is registered with the backend, to `<store root>/device.json`.
 * Without that file the bundled development device is used, which keeps the fixture and vectors working.
 */
internal data class HarivuDeviceIdentity(
    val deviceId: String,
    val deviceKeyId: String,
) {
    companion object {
        const val FILE_NAME = "device.json"
        val DEVELOPMENT = HarivuDeviceIdentity("harivu-dev-device-v1", "harivu-dev-device-key-v1")
        private val validId = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

        fun read(root: File): HarivuDeviceIdentity {
            val file = File(root, FILE_NAME)
            if (!file.exists()) return DEVELOPMENT
            return try {
                val json: JsonObject = Json.parseToJsonElement(file.readText()).jsonObject
                val identity =
                    HarivuDeviceIdentity(
                        deviceId = json.requiredId("deviceId"),
                        deviceKeyId = json.requiredId("deviceKeyId"),
                    )
                identity
            } catch (_: HarivuProtectionException) {
                throw HarivuProtectionException(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
            } catch (_: Exception) {
                throw HarivuProtectionException(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
            }
        }

        private fun JsonObject.requiredId(name: String): String {
            val primitive = this[name]?.jsonPrimitive
            val value = primitive?.takeIf { it.isString }?.content
            if (value == null || !validId.matches(value)) {
                throw HarivuProtectionException(HarivuProtectionErrorCode.OfflineAuthorizationUnavailable)
            }
            return value
        }
    }
}
