import CryptoKit
import Foundation

/// Proof of possession of the device key, used when the app registers this device with the backend.
///
/// DEVELOPMENT ONLY: the device key is the recorded Phase 2B development key, whose private half is
/// public in the test vectors. Production replaces it with a non-exportable platform key. The private
/// key never leaves native code; only the public key and a signature are returned.
enum HarivuDeviceProof {
  static let publicKeyBase64URL =
    "BJhCJVhdIoXBOAM9YUDjzvi5GFlwTlPDE_i2NrpPlnZJlzQUT0b9GadnpUUofEOWuXtp3Tj6rqiYGtwaT-2bQB4"

  static var publicKey: Data {
    var encoded = publicKeyBase64URL.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
    return Data(base64Encoded: encoded)!
  }

  /// ECDSA P-256 / SHA-256 over `message` as a 64-byte IEEE P1363 `R || S` signature.
  static func sign(_ message: Data) throws -> Data {
    let key = try P256.Signing.PrivateKey(
      rawRepresentation: HarivuProtectionSessionResolver.developmentDeviceKeyBytes
    )
    return try key.signature(for: message).rawRepresentation
  }
}
