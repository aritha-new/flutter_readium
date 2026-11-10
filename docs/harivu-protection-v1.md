# Harivu Protection v1 — Phase 2B Contract

This contract is for the deterministic Phase 2B proof fixture. It is not a
production DRM certification, production key-custody design, or Readium LCP.
All private keys in the recorded vectors are development-only and public.

The machine-readable source of truth is
`test_vectors/harivu_protection_v1.json`.

## Scope

- EPUB 3 text-and-image publications.
- Complete encrypted packages may exceed 20 MiB and remain offline readable.
- Each encrypted EPUB resource has a maximum plaintext size of 2 MiB
  (2,097,152 bytes).
- Comics, audio, video, authenticated chunking, and range-aware decryption are
  outside Phase 2B.

## Versions and algorithms

| Purpose | Value |
| --- | --- |
| Package format | `harivu-protected-epub`, version `1` |
| License format | `harivu-offline-license`, version `1` |
| Resource encryption | AES-256-GCM (`A256GCM`) |
| Resource nonce/tag | 96-bit nonce, 128-bit tag |
| Content-key binding | P-256 ECDH, HKDF-SHA-256, AES-256-GCM |
| License envelope | JWS compact serialization |
| License signature | ES256 with 64-byte IEEE P1363 `R || S` signature |
| Digests | SHA-256 |
| Binary JSON fields | Unpadded Base64url |

## EPUB package layout

The proof package stays an EPUB ZIP. EPUB discovery metadata needed before the
protection adapter is installed remains plaintext. Protected XHTML, CSS, image,
font, and navigation resources retain their normalized EPUB paths, but their
ZIP entry bytes contain ciphertext rather than plaintext.

`META-INF/harivu-protection.json` contains the exact UTF-8 manifest bytes. Its
SHA-256 digest is bound into the signed license. A protected resource entry is
accepted only when its path occurs exactly once in the manifest.

Resource paths use `/`, are relative, contain no empty, `.` or `..` segment,
and must already be normalized. Percent-decoded or Unicode-normalized aliases
are rejected rather than rewritten.

## Canonical JSON

Phase 2B uses the exact compact UTF-8 JSON strings recorded in the vector file.
No whitespace or alternate key ordering is accepted for signed or
authenticated bytes. Producers emit object keys in the order shown by the
reference packager. Consumers verify the original bytes before parsing them;
they do not reserialize JSON to verify a signature or hash.

## Resource encryption

Every protected resource uses a unique 96-bit nonce under the publication's
256-bit content key. The ZIP entry stores ciphertext only; the manifest stores
the nonce and 128-bit authentication tag.

The AES-GCM additional authenticated data is this compact JSON object, in this
exact key order:

```json
{"algorithm":"A256GCM","mediaType":"...","packageVersion":1,"path":"...","plaintextLength":0,"publicationId":"...","publicationVersion":1}
```

The adapter rejects a declared plaintext length above 2 MiB before allocating
or decrypting. It also rejects an authenticated plaintext whose actual length
does not equal `plaintextLength`.

## Device-bound content-key wrapping

The license contains a one-time uncompressed P-256 ephemeral public key. The
device derives the ECDH shared secret using its P-256 private key. Phase 2B uses
the deterministic development device private key recorded in the vectors;
production replaces this with a non-exportable platform key.

HKDF parameters are:

- Hash: SHA-256.
- Input key material: the P-256 ECDH shared secret.
- Salt: `SHA-256(UTF8("harivu-license-v1|" + publicationId + "|" + deviceId))`.
- Info: `UTF8("harivu-content-key-wrap-v1")`.
- Output length: 32 bytes.

The derived key wraps the 32-byte content key with AES-256-GCM. Its additional
authenticated data is this compact JSON object, in this exact key order:

```json
{"algorithm":"ECDH-ES+HKDF-SHA256+A256GCM","deviceId":"...","deviceKeyId":"...","licenseVersion":1,"publicationId":"...","publicationVersion":1}
```

## RSA device-key wrap (Android hardware keys)

Android Keystore keeps RSA decrypt and sign keys in secure hardware reliably, while an EC
key-agreement key can silently become a software key. An Android device therefore registers an
RSA-2048 key (X.509 SPKI, DER) and its license uses a hybrid wrap:

- `contentKeyWrap.algorithm` is `RSA-OAEP-SHA256+A256GCM`.
- The backend draws a random AES-256 key, encrypts it with RSA-OAEP (SHA-256, MGF1 with SHA-1, empty
  label) into `encryptedKey`, and seals the content key with AES-256-GCM (`nonce`,
  `wrappedContentKey`, `tag`) using that key.
- The AAD is the same canonical JSON as the ECDH wrap, with `algorithm` set to the RSA value.
- The registration proof is RSASSA-PKCS1-v1_5 with SHA-256 over the same message; `keyProtection`
  (`hardware` or `software`) is the device's claim and is not attested.

The recorded vector is `test_vectors/harivu_rsa_wrap_v1.json`; the backend and the Android unit
tests both unwrap it. iOS keeps the P-256 ECDH wrap (Secure Enclave).

## License JWS

The compact JWS protected header is exactly:

```json
{"alg":"ES256","kid":"harivu-dev-signing-key-v1","typ":"harivu-license+jws"}
```

The payload is the exact compact UTF-8 license JSON recorded in the vectors.
The signature covers `base64url(header) + "." + base64url(payload)` and is a
64-byte IEEE P1363 P-256 signature. Verification, version, publication,
manifest digest, device binding, `notBefore`, and `expiresAt` checks all succeed
before content-key unwrapping.

## Stable errors

Native implementations expose only these non-sensitive protected-reader codes:

- `ProtectedLicenseInvalid`
- `ProtectedLicenseExpired`
- `ProtectedDeviceMismatch`
- `ProtectedPackageTampered`
- `UnsupportedProtectionVersion`
- `OfflineAuthorizationUnavailable`
- `ProtectedResourceExportBlocked`
- `ProtectedResourceTooLarge`

Every malformed, unknown, duplicated, cryptographically invalid, or
unauthorized input fails closed. No content key, device private key, plaintext
resource, or plaintext path crosses the Flutter method channel.
