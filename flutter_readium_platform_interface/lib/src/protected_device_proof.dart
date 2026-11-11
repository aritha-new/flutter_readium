import 'package:flutter/foundation.dart' show listEquals;
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
    this.attestationChain = const [],
  });

  factory ProtectedDeviceInfo.fromJson(Map<String, dynamic> json) => ProtectedDeviceInfo(
    devicePublicKey: json['devicePublicKey'] as String,
    keyProtection: json['keyProtection'] as String,
    attestationChain: _chain(json['attestationChain']),
  );

  /// Uncompressed P-256 point, base64url without padding.
  final String devicePublicKey;

  /// `hardware` or `software`.
  final String keyProtection;

  /// The platform's attestation of the key as X.509 certificates (standard base64 DER), leaf first, or empty
  /// when the platform has nothing to attest. Android sends the Keystore attestation chain. The backend, not the
  /// app, decides whether it is genuine.
  final List<String> attestationChain;

  @override
  bool operator ==(Object other) =>
      other is ProtectedDeviceInfo &&
      other.devicePublicKey == devicePublicKey &&
      other.keyProtection == keyProtection &&
      listEquals(other.attestationChain, attestationChain);

  @override
  int get hashCode => Object.hash(devicePublicKey, keyProtection, Object.hashAll(attestationChain));
}

List<String> _chain(Object? value) =>
    value is List ? List<String>.unmodifiable(value.whereType<String>()) : const <String>[];

/// A [ProtectedDeviceInfo] plus a signature proving possession of the private key.
@immutable
class ProtectedDeviceProof extends ProtectedDeviceInfo {
  const ProtectedDeviceProof({
    required super.devicePublicKey,
    required super.keyProtection,
    required this.signature,
    super.attestationChain,
  });

  factory ProtectedDeviceProof.fromJson(Map<String, dynamic> json) => ProtectedDeviceProof(
    devicePublicKey: json['devicePublicKey'] as String,
    keyProtection: json['keyProtection'] as String,
    attestationChain: _chain(json['attestationChain']),
    signature: json['signature'] as String,
  );

  /// 64-byte IEEE P1363 ECDSA P-256 / SHA-256 signature, base64url without padding.
  final String signature;

  @override
  bool operator ==(Object other) => other is ProtectedDeviceProof && super == other && other.signature == signature;

  @override
  int get hashCode => Object.hash(super.hashCode, signature);
}
