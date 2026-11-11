import Foundation

struct HarivuLocatedPublication {
  let packageURL: URL
  let licenseJWS: String
}

/// Finds a downloaded protected publication from an opaque identifier.
///
/// Layout written by the app's package store: `root/<id>/v<N>/{package.epub,license.json}`.
/// A version is usable only when both files exist (the license is written last). The identifier
/// is validated so it can never address anything outside `root`.
enum HarivuDownloadedPublicationLocator {
  private static let validID = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

  static func locate(root: URL, opaqueID: String) throws -> HarivuLocatedPublication {
    let range = NSRange(opaqueID.startIndex..., in: opaqueID)
    guard validID.firstMatch(in: opaqueID, range: range) != nil, !opaqueID.contains("..") else {
      throw HarivuProtectionError.offlineAuthorizationUnavailable
    }
    let publicationDir = root.appendingPathComponent(opaqueID, isDirectory: true)
    guard let entries = try? FileManager.default.contentsOfDirectory(
      at: publicationDir, includingPropertiesForKeys: nil
    ) else {
      throw HarivuProtectionError.offlineAuthorizationUnavailable
    }
    let versions = entries
      .compactMap { url -> (Int, URL)? in
        let name = url.lastPathComponent
        guard name.hasPrefix("v"), let number = Int(name.dropFirst()) else { return nil }
        return (number, url)
      }
      .sorted { $0.0 > $1.0 }
    for (_, dir) in versions {
      let package = dir.appendingPathComponent("package.epub")
      let license = dir.appendingPathComponent("license.json")
      guard FileManager.default.fileExists(atPath: package.path),
            FileManager.default.fileExists(atPath: license.path) else { continue }
      guard let data = try? Data(contentsOf: license),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let jws = object["jws"] as? String else {
        throw HarivuProtectionError.protectedLicenseInvalid
      }
      return HarivuLocatedPublication(packageURL: package, licenseJWS: jws)
    }
    throw HarivuProtectionError.offlineAuthorizationUnavailable
  }
}
