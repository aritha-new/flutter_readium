import CryptoKit
import Foundation
import Security

/// The device's half of the content-key unwrap: ECDH between the device private key and the license's
/// ephemeral public key. The private key is never exposed through this protocol, so it can live in the
/// Secure Enclave.
protocol HarivuDeviceKeyAgreement {
  /// The raw ECDH shared secret for an uncompressed P-256 public key (65 bytes).
  func sharedSecret(withEphemeralPublicKey x963: Data) throws -> Data
}

/// A software P-256 key. Used only for the bundled development device and its recorded vectors, never for
/// real books.
struct HarivuSoftwareDeviceKey: HarivuDeviceKeyAgreement {
  let privateKey: P256.KeyAgreement.PrivateKey

  func sharedSecret(withEphemeralPublicKey x963: Data) throws -> Data {
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: x963)
    return try privateKey.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
  }
}

enum HarivuKeyProtection: String {
  case hardware
  case software
}

enum HarivuDeviceKeyError: Error {
  case unavailable
}

/// This device's key for the protected reader: a P-256 key created in the Secure Enclave, which signs the
/// registration proof and takes part in the ECDH that unwraps a license's content key. The private key never
/// leaves the Secure Enclave.
///
/// The simulator has no Secure Enclave, so there the key is an ordinary Keychain key and
/// [protection] reports `software`; a backend that requires hardware keys refuses such a device. A test run can
/// opt in to a `hardware` claim with HARIVU_SIMULATE_HARDWARE_KEY=1 (simulator builds only); the key itself is
/// still software, and the backend does not verify the claim.
struct HarivuSecureDeviceKey: HarivuDeviceKeyAgreement {
  private static let tag = Data("dev.harivu.reader.device-key.v1".utf8)

  func protection() -> HarivuKeyProtection {
    #if targetEnvironment(simulator)
    // Test runs only: lets a simulator, which has no Secure Enclave, claim a hardware key so the rest of the
    // protected-reader flow can be exercised against a backend that requires one. It is compiled into simulator
    // builds only, never into a device build, and stays off unless the variable is exactly "1".
    if ProcessInfo.processInfo.environment["HARIVU_SIMULATE_HARDWARE_KEY"] == "1" {
      return .hardware
    }
    #endif
    guard let key = try? privateKey(),
          let attributes = SecKeyCopyAttributes(key) as? [String: Any],
          let token = attributes[kSecAttrTokenID as String] as? String,
          token == kSecAttrTokenIDSecureEnclave as String else {
      return .software
    }
    return .hardware
  }

  /// The public key as an uncompressed P-256 point (65 bytes).
  func publicKey() throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(try privateKey()),
          let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      throw HarivuDeviceKeyError.unavailable
    }
    return data
  }

  /// ECDSA P-256 / SHA-256 over `message` as a 64-byte IEEE P1363 signature.
  func sign(_ message: Data) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCreateSignature(
      try privateKey(), .ecdsaSignatureMessageX962SHA256, message as CFData, &error
    ) as Data? else {
      throw HarivuDeviceKeyError.unavailable
    }
    return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
  }

  func sharedSecret(withEphemeralPublicKey x963: Data) throws -> Data {
    guard x963.count == 65, x963.first == 0x04 else { throw HarivuDeviceKeyError.unavailable }
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
    ]
    var error: Unmanaged<CFError>?
    guard let peer = SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, &error),
          let secret = SecKeyCopyKeyExchangeResult(
            try privateKey(), .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error
          ) as Data? else {
      throw HarivuDeviceKeyError.unavailable
    }
    return secret
  }

  private func privateKey() throws -> SecKey {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecAttrApplicationTag: Self.tag,
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef: true,
    ]
    var item: CFTypeRef?
    if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item {
      return item as! SecKey // swiftlint:disable:this force_cast
    }
    return try create()
  }

  private func create() throws -> SecKey {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
    ) else {
      throw HarivuDeviceKeyError.unavailable
    }
    var privateAttributes: [CFString: Any] = [
      kSecAttrIsPermanent: true,
      kSecAttrApplicationTag: Self.tag,
    ]
    var attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
    ]
    #if targetEnvironment(simulator)
    // No Secure Enclave on the simulator: an ordinary Keychain key, reported as software.
    #else
    attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
    privateAttributes[kSecAttrAccessControl] = access
    #endif
    attributes[kSecPrivateKeyAttrs] = privateAttributes
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw HarivuDeviceKeyError.unavailable
    }
    return key
  }
}
