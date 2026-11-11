import { createECDH, createHash } from 'node:crypto';

import {
  buildLicensePayload,
  buildManifest,
  encryptResource,
  signLicenseJws,
  wrapContentKey,
} from './reference_packager.mjs';

const contentKeyHex =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const devicePrivateKeyHex =
  '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100';
const ephemeralPrivateKeyHex =
  '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const signingPrivateKeyHex =
  '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f';
const devicePublicKeyHex = publicKeyHex(devicePrivateKeyHex);
const signingPublicKeyHex = publicKeyHex(signingPrivateKeyHex);
const plaintext = Buffer.from('<p>Harivu protected fixture.</p>\n');

const resource = encryptResource({
  contentKeyHex,
  nonceHex: '000102030405060708090a0b',
  plaintext,
  publicationId: 'harivu-phase2-fixture',
  publicationVersion: 1,
  path: 'EPUB/chapter-1.xhtml',
  mediaType: 'application/xhtml+xml',
});
const resourceManifest = {
  ciphertextSha256: sha256(Buffer.from(resource.ciphertextHex, 'hex')),
  mediaType: 'application/xhtml+xml',
  nonce: Buffer.from(resource.nonceHex, 'hex').toString('base64url'),
  path: 'EPUB/chapter-1.xhtml',
  plaintextLength: resource.plaintextLength,
  plaintextSha256: resource.plaintextSha256,
  tag: Buffer.from(resource.tagHex, 'hex').toString('base64url'),
};
const manifestUtf8 = buildManifest({
  publicationId: 'harivu-phase2-fixture',
  publicationVersion: 1,
  resources: [resourceManifest],
});
const manifestSha256 = sha256(Buffer.from(manifestUtf8));
const keyWrap = wrapContentKey({
  contentKeyHex,
  deviceId: 'harivu-dev-device-v1',
  deviceKeyId: 'harivu-dev-device-key-v1',
  devicePublicKeyHex,
  ephemeralPrivateKeyHex,
  nonceHex: '0c0d0e0f1011121314151617',
  publicationId: 'harivu-phase2-fixture',
  publicationVersion: 1,
});
const contentKeyWrap = {
  algorithm: keyWrap.algorithm,
  ephemeralPublicKey: keyWrap.ephemeralPublicKey,
  nonce: keyWrap.nonce,
  tag: keyWrap.tag,
  wrappedContentKey: keyWrap.wrappedContentKey,
};
const licensePayloadUtf8 = buildLicensePayload({
  manifestSha256,
  contentKeyWrap,
});

const vector = {
  warning: 'NON-PRODUCTION DEVELOPMENT KEYS. DO NOT REUSE.',
  errors: [
    'ProtectedLicenseInvalid',
    'ProtectedLicenseExpired',
    'ProtectedDeviceMismatch',
    'ProtectedPackageTampered',
    'UnsupportedProtectionVersion',
    'OfflineAuthorizationUnavailable',
    'ProtectedResourceExportBlocked',
    'ProtectedResourceTooLarge',
  ],
  keys: {
    contentKeyHex,
    devicePrivateKeyHex,
    devicePublicKey: Buffer.from(devicePublicKeyHex, 'hex').toString(
      'base64url',
    ),
    ephemeralPrivateKeyHex,
    signingPrivateKeyHex,
    signingPublicKey: Buffer.from(signingPublicKeyHex, 'hex').toString(
      'base64url',
    ),
  },
  package: {
    algorithm: 'A256GCM',
    format: 'harivu-protected-epub',
    manifestSha256,
    manifestUtf8,
    maxPlaintextResourceSize: 2097152,
    version: 1,
  },
  license: {
    format: 'harivu-offline-license',
    jws: signLicenseJws({
      payload: licensePayloadUtf8,
      signingPrivateKeyHex,
    }),
    payloadUtf8: licensePayloadUtf8,
    protectedHeaderUtf8:
      '{"alg":"ES256","kid":"harivu-dev-signing-key-v1","typ":"harivu-license+jws"}',
    version: 1,
  },
  resourceVector: {
    ...resource,
    mediaType: 'application/xhtml+xml',
    path: 'EPUB/chapter-1.xhtml',
    plaintextUtf8: plaintext.toString(),
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
  },
  keyWrapVector: keyWrap,
};

process.stdout.write(`${JSON.stringify(vector, null, 2)}\n`);

function publicKeyHex(privateKeyHex) {
  const key = createECDH('prime256v1');
  key.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
  return key.getPublicKey('hex', 'uncompressed');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
