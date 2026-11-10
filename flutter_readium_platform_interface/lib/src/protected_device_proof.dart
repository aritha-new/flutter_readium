import 'package:meta/meta.dart';

/// The public key of this device's protected-reader key and a signature proving
/// possession of the matching private key. Both are unpadded base64url.
///
/// The private key never leaves native code.
@immutable
class ProtectedDeviceProof {
  const ProtectedDeviceProof({
    required this.devicePublicKey,
    required this.signature,
  });

  factory ProtectedDeviceProof.fromJson(Map<String, dynamic> json) => ProtectedDeviceProof(
    devicePublicKey: json['devicePublicKey'] as String,
    signature: json['signature'] as String,
  );

  /// Uncompressed P-256 point, base64url without padding.
  final String devicePublicKey;

  /// 64-byte IEEE P1363 ECDSA P-256 / SHA-256 signature, base64url without padding.
  final String signature;

  @override
  bool operator ==(Object other) =>
      other is ProtectedDeviceProof && other.devicePublicKey == devicePublicKey && other.signature == signature;

  @override
  int get hashCode => Object.hash(devicePublicKey, signature);
}
