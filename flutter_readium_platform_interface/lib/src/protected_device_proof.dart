import 'package:meta/meta.dart';

/// The public key of this device's protected-reader key and how it is held.
///
/// [keyProtection] is `hardware` when the private key lives in platform hardware
/// (Android Keystore, iOS Secure Enclave) and `software` when it does not. The
/// private key never leaves native code.
@immutable
class ProtectedDeviceInfo {
  const ProtectedDeviceInfo({
    required this.devicePublicKey,
    required this.keyProtection,
  });

  factory ProtectedDeviceInfo.fromJson(Map<String, dynamic> json) => ProtectedDeviceInfo(
    devicePublicKey: json['devicePublicKey'] as String,
    keyProtection: json['keyProtection'] as String,
  );

  /// Uncompressed P-256 point, base64url without padding.
  final String devicePublicKey;

  /// `hardware` or `software`.
  final String keyProtection;

  @override
  bool operator ==(Object other) =>
      other is ProtectedDeviceInfo && other.devicePublicKey == devicePublicKey && other.keyProtection == keyProtection;

  @override
  int get hashCode => Object.hash(devicePublicKey, keyProtection);
}

/// A [ProtectedDeviceInfo] plus a signature proving possession of the private key.
@immutable
class ProtectedDeviceProof extends ProtectedDeviceInfo {
  const ProtectedDeviceProof({
    required super.devicePublicKey,
    required super.keyProtection,
    required this.signature,
  });

  factory ProtectedDeviceProof.fromJson(Map<String, dynamic> json) => ProtectedDeviceProof(
    devicePublicKey: json['devicePublicKey'] as String,
    keyProtection: json['keyProtection'] as String,
    signature: json['signature'] as String,
  );

  /// 64-byte IEEE P1363 ECDSA P-256 / SHA-256 signature, base64url without padding.
  final String signature;

  @override
  bool operator ==(Object other) => other is ProtectedDeviceProof && super == other && other.signature == signature;

  @override
  int get hashCode => Object.hash(super.hashCode, signature);
}
