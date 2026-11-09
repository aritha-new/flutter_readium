import CryptoKit
import Foundation
import ReadiumShared

enum HarivuProtectionError: String, Error {
  case protectedLicenseInvalid = "ProtectedLicenseInvalid"
  case protectedLicenseExpired = "ProtectedLicenseExpired"
  case protectedDeviceMismatch = "ProtectedDeviceMismatch"
  case protectedPackageTampered = "ProtectedPackageTampered"
  case unsupportedProtectionVersion = "UnsupportedProtectionVersion"
  case offlineAuthorizationUnavailable = "OfflineAuthorizationUnavailable"
  case protectedResourceExportBlocked = "ProtectedResourceExportBlocked"
  case protectedResourceTooLarge = "ProtectedResourceTooLarge"
}

struct HarivuProtectedResource {
  let nonce: Data
  let tag: Data
  let aad: Data
  let plaintextLength: Int
  let ciphertextSHA256: Data
  let plaintextSHA256: Data
}

struct HarivuProtectionSession {
  let contentKey: SymmetricKey
  let resources: [String: HarivuProtectedResource]
}

final class HarivuContentProtection: ContentProtection {
  private let licenseJWS: String
  private(set) var lastError: HarivuProtectionError?

  init(licenseJWS: String) {
    self.licenseJWS = licenseJWS
  }

  func open(
    asset: Asset,
    credentials _: String?,
    allowUserInteraction _: Bool,
    sender _: Any?
  ) async -> Result<ContentProtectionAsset, ContentProtectionOpenError> {
    guard case let .container(containerAsset) = asset,
          let markerURL = AnyURL(path: "META-INF/harivu-protection.json"),
          let marker = containerAsset.container[markerURL] else {
      return .failure(.assetNotSupported(nil))
    }
    do {
      let manifest = try await marker.read().get()
      let session = try HarivuProtectionSessionResolver().resolve(
        manifest: manifest,
        licenseJWS: licenseJWS
      )
      let transformed = TransformingContainer(container: containerAsset.container) { url, resource in
        guard let protected = session.resources[url.string] else { return resource }
        return TransformingResource(resource) { result in
          switch result {
          case .failure(let error):
            return .failure(error)
          case .success(let ciphertext):
            do {
              return .success(try Self.decrypt(
                ciphertext: ciphertext,
                resource: protected,
                contentKey: session.contentKey
              ))
            } catch {
              return .failure(.decoding("Protected resource validation failed."))
            }
          }
        }
      }
      return .success(ContentProtectionAsset(
        asset: .container(ContainerAsset(container: transformed, format: containerAsset.format))
      ))
    } catch let error as HarivuProtectionError {
      lastError = error
      return .failure(.reading(.decoding("Protected publication validation failed.")))
    } catch {
      lastError = .protectedPackageTampered
      return .failure(.reading(.decoding("Protected publication validation failed.")))
    }
  }

  static func decrypt(
    ciphertext: Data,
    resource: HarivuProtectedResource,
    contentKey: SymmetricKey
  ) throws -> Data {
    guard resource.plaintextLength <= 2 * 1024 * 1024 else {
      throw HarivuProtectionError.protectedResourceTooLarge
    }
    guard Data(SHA256.hash(data: ciphertext)) == resource.ciphertextSHA256 else {
      throw HarivuProtectionError.protectedPackageTampered
    }
    do {
      let sealed = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: resource.nonce),
        ciphertext: ciphertext,
        tag: resource.tag
      )
      let plaintext = try AES.GCM.open(sealed, using: contentKey, authenticating: resource.aad)
      guard plaintext.count == resource.plaintextLength,
            Data(SHA256.hash(data: plaintext)) == resource.plaintextSHA256 else {
        throw HarivuProtectionError.protectedPackageTampered
      }
      return plaintext
    } catch let error as HarivuProtectionError {
      throw error
    } catch {
      throw HarivuProtectionError.protectedPackageTampered
    }
  }
}

struct HarivuProtectionSessionResolver {
  private let signingPublicKey = try! P256.Signing.PublicKey(
    x963Representation: Data(base64URLEncoded: "BI7VfsK49edekZIye1HlZhyHyOXbAXByEwmlF_xuEEaxVIHorjs50yN3jkUcse_rVB4TJadmft2HfGj69wUAdXU")!
  )
  static let developmentDeviceKey = try! P256.KeyAgreement.PrivateKey(
    rawRepresentation: Data(hex: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")!
  )
  private let devicePrivateKey: P256.KeyAgreement.PrivateKey

  init(devicePrivateKey: P256.KeyAgreement.PrivateKey = HarivuProtectionSessionResolver.developmentDeviceKey) {
    self.devicePrivateKey = devicePrivateKey
  }

  func resolve(manifest: Data, licenseJWS: String, now: Date = Date()) throws -> HarivuProtectionSession {
    let parts = licenseJWS.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".")
    guard parts.count == 3,
          let header = Data(base64URLEncoded: String(parts[0])),
          String(data: header, encoding: .utf8) == #"{"alg":"ES256","kid":"harivu-dev-signing-key-v1","typ":"harivu-license+jws"}"#,
          let signatureData = Data(base64URLEncoded: String(parts[2])),
          let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData),
          signingPublicKey.isValidSignature(
            signature,
            for: Data("\(parts[0]).\(parts[1])".utf8)
          ),
          let payload = Data(base64URLEncoded: String(parts[1])),
          let license = try? Self.object(payload) else {
      throw HarivuProtectionError.protectedLicenseInvalid
    }
    guard Self.string(license, "format") == "harivu-offline-license",
          Self.int(license, "licenseVersion") == 1 else {
      throw HarivuProtectionError.unsupportedProtectionVersion
    }
    guard Self.string(license, "deviceId") == "harivu-dev-device-v1",
          Self.string(license, "deviceKeyId") == "harivu-dev-device-key-v1" else {
      throw HarivuProtectionError.protectedDeviceMismatch
    }
    let dateFormatter = ISO8601DateFormatter()
    guard let expiresAt = dateFormatter.date(from: Self.string(license, "expiresAt") ?? ""),
          let notBefore = dateFormatter.date(from: Self.string(license, "notBefore") ?? "") else {
      throw HarivuProtectionError.protectedLicenseInvalid
    }
    guard expiresAt > now else { throw HarivuProtectionError.protectedLicenseExpired }
    guard notBefore <= now else { throw HarivuProtectionError.offlineAuthorizationUnavailable }
    guard let expectedManifestHash = Data(hex: Self.string(license, "manifestSha256") ?? ""),
          Data(SHA256.hash(data: manifest)) == expectedManifestHash else {
      throw HarivuProtectionError.protectedPackageTampered
    }
    guard let manifestJSON = try? Self.object(manifest),
          Self.string(manifestJSON, "format") == "harivu-protected-epub",
          Self.string(manifestJSON, "algorithm") == "A256GCM",
          Self.int(manifestJSON, "packageVersion") == 1,
          Self.int(manifestJSON, "maxPlaintextResourceSize") == 2 * 1024 * 1024 else {
      throw HarivuProtectionError.unsupportedProtectionVersion
    }
    guard let publicationID = Self.string(license, "publicationId"),
          let publicationVersion = Self.int(license, "publicationVersion"),
          publicationID == Self.string(manifestJSON, "publicationId"),
          publicationVersion == Self.int(manifestJSON, "publicationVersion") else {
      throw HarivuProtectionError.protectedPackageTampered
    }
    let contentKey = try unwrapContentKey(
      license: license,
      publicationID: publicationID,
      publicationVersion: publicationVersion
    )
    guard let resourceObjects = manifestJSON["resources"] as? [[String: Any]] else {
      throw HarivuProtectionError.protectedPackageTampered
    }
    var resources: [String: HarivuProtectedResource] = [:]
    for resource in resourceObjects {
      guard let path = Self.string(resource, "path"),
            resources[path] == nil,
            let mediaType = Self.string(resource, "mediaType"),
            let plaintextLength = Self.int(resource, "plaintextLength"),
            let nonce = Data(base64URLEncoded: Self.string(resource, "nonce") ?? ""),
            let tag = Data(base64URLEncoded: Self.string(resource, "tag") ?? ""),
            let ciphertextHash = Data(hex: Self.string(resource, "ciphertextSha256") ?? ""),
            let plaintextHash = Data(hex: Self.string(resource, "plaintextSha256") ?? "") else {
        throw HarivuProtectionError.protectedPackageTampered
      }
      guard plaintextLength <= 2 * 1024 * 1024 else {
        throw HarivuProtectionError.protectedResourceTooLarge
      }
      let aad = "{\"algorithm\":\"A256GCM\",\"mediaType\":\(Self.literal(mediaType)),\"packageVersion\":1,\"path\":\(Self.literal(path)),\"plaintextLength\":\(plaintextLength),\"publicationId\":\(Self.literal(publicationID)),\"publicationVersion\":\(publicationVersion)}"
      resources[path] = HarivuProtectedResource(
        nonce: nonce,
        tag: tag,
        aad: Data(aad.utf8),
        plaintextLength: plaintextLength,
        ciphertextSHA256: ciphertextHash,
        plaintextSHA256: plaintextHash
      )
    }
    return HarivuProtectionSession(contentKey: contentKey, resources: resources)
  }

  private func unwrapContentKey(
    license: [String: Any],
    publicationID: String,
    publicationVersion: Int
  ) throws -> SymmetricKey {
    guard let wrap = license["contentKeyWrap"] as? [String: Any],
          Self.string(wrap, "algorithm") == "ECDH-ES+HKDF-SHA256+A256GCM",
          let ephemeralData = Data(base64URLEncoded: Self.string(wrap, "ephemeralPublicKey") ?? ""),
          let ephemeralKey = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralData),
          let nonceData = Data(base64URLEncoded: Self.string(wrap, "nonce") ?? ""),
          let tag = Data(base64URLEncoded: Self.string(wrap, "tag") ?? ""),
          let wrapped = Data(base64URLEncoded: Self.string(wrap, "wrappedContentKey") ?? "") else {
      throw HarivuProtectionError.protectedLicenseInvalid
    }
    do {
      let secret = try devicePrivateKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
      let salt = Data(SHA256.hash(data: Data("harivu-license-v1|\(publicationID)|harivu-dev-device-v1".utf8)))
      let wrappingKey = secret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: salt,
        sharedInfo: Data("harivu-content-key-wrap-v1".utf8),
        outputByteCount: 32
      )
      let aad = "{\"algorithm\":\"ECDH-ES+HKDF-SHA256+A256GCM\",\"deviceId\":\"harivu-dev-device-v1\",\"deviceKeyId\":\"harivu-dev-device-key-v1\",\"licenseVersion\":1,\"publicationId\":\(Self.literal(publicationID)),\"publicationVersion\":\(publicationVersion)}"
      let sealed = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: nonceData),
        ciphertext: wrapped,
        tag: tag
      )
      let raw = try AES.GCM.open(sealed, using: wrappingKey, authenticating: Data(aad.utf8))
      guard raw.count == 32 else { throw HarivuProtectionError.protectedDeviceMismatch }
      return SymmetricKey(data: raw)
    } catch let error as HarivuProtectionError {
      throw error
    } catch {
      throw HarivuProtectionError.protectedDeviceMismatch
    }
  }

  private static func object(_ data: Data) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw HarivuProtectionError.protectedLicenseInvalid
    }
    return object
  }

  private static func string(_ object: [String: Any], _ key: String) -> String? {
    object[key] as? String
  }

  private static func int(_ object: [String: Any], _ key: String) -> Int? {
    (object[key] as? NSNumber)?.intValue
  }

  private static func literal(_ value: String) -> String {
    let data = try! JSONSerialization.data(withJSONObject: [value], options: [.withoutEscapingSlashes])
    let array = String(data: data, encoding: .utf8)!
    return String(array.dropFirst().dropLast())
  }
}

private extension Data {
  init?(base64URLEncoded value: String) {
    var encoded = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
    self.init(base64Encoded: encoded)
  }

  init?(hex: String) {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self = Data(bytes)
  }
}
