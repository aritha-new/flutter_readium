package dk.nota.flutterreadium.protection

internal enum class HarivuProtectionErrorCode {
    ProtectedLicenseInvalid,
    ProtectedLicenseExpired,
    ProtectedDeviceMismatch,
    ProtectedPackageTampered,
    UnsupportedProtectionVersion,
    OfflineAuthorizationUnavailable,
    ProtectedResourceExportBlocked,
    ProtectedResourceTooLarge,
}

internal class HarivuProtectionException(
    val code: HarivuProtectionErrorCode,
) : Exception(code.name)
