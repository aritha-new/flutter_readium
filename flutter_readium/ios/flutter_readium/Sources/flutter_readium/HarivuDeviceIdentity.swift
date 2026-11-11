import Foundation

/// The device id and device key id a license must be bound to. They are plain identifiers (no key
/// material), written by the Flutter app after the device is registered with the backend, to
/// `<store root>/device.json`. Without that file the bundled development device is used, which keeps
/// the fixture and vectors working.
struct HarivuDeviceIdentity: Equatable {
  let deviceID: String
  let deviceKeyID: String

  static let fileName = "device.json"
  static let development = HarivuDeviceIdentity(
    deviceID: "harivu-dev-device-v1",
    deviceKeyID: "harivu-dev-device-key-v1"
  )
  private static let validID = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

  static func read(root: URL) throws -> HarivuDeviceIdentity {
    let file = root.appendingPathComponent(fileName)
    guard FileManager.default.fileExists(atPath: file.path) else { return development }
    guard let data = try? Data(contentsOf: file),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let deviceID = object["deviceId"] as? String, isValid(deviceID),
          let deviceKeyID = object["deviceKeyId"] as? String, isValid(deviceKeyID) else {
      throw HarivuProtectionError.offlineAuthorizationUnavailable
    }
    return HarivuDeviceIdentity(deviceID: deviceID, deviceKeyID: deviceKeyID)
  }

  private static func isValid(_ value: String) -> Bool {
    validID.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
  }
}
