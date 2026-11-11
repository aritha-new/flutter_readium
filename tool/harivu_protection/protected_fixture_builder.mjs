import { createECDH, createHash } from 'node:crypto';

import {
  buildLicensePayload,
  buildManifest,
  encryptResource,
  signLicenseJws,
  wrapContentKey,
} from './reference_packager.mjs';

const CONTENT_KEY_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const DEVICE_PRIVATE_KEY_HEX =
  '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100';
const EPHEMERAL_PRIVATE_KEY_HEX =
  '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const SIGNING_PRIVATE_KEY_HEX =
  '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f';

export function buildProtectedFixture({
  publicationId,
  publicationVersion,
  resources,
}) {
  const encryptedResources = new Map();
  const manifestResources = [];

  for (const [path, resource] of [...resources].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const nonceHex = deterministicResourceNonce({
      path,
      publicationId,
      publicationVersion,
    });
    const encrypted = encryptResource({
      contentKeyHex: CONTENT_KEY_HEX,
      mediaType: resource.mediaType,
      nonceHex,
      path,
      plaintext: resource.plaintext,
      publicationId,
      publicationVersion,
    });
    const ciphertext = Buffer.from(encrypted.ciphertextHex, 'hex');
    encryptedResources.set(path, ciphertext);
    manifestResources.push({
      ciphertextSha256: sha256(ciphertext),
      mediaType: resource.mediaType,
      nonce: Buffer.from(nonceHex, 'hex').toString('base64url'),
      path,
      plaintextLength: encrypted.plaintextLength,
      plaintextSha256: encrypted.plaintextSha256,
      tag: Buffer.from(encrypted.tagHex, 'hex').toString('base64url'),
    });
  }

  const manifestUtf8 = buildManifest({
    publicationId,
    publicationVersion,
    resources: manifestResources,
  });
  const manifestSha256 = sha256(Buffer.from(manifestUtf8));
  const keyWrap = wrapContentKey({
    contentKeyHex: CONTENT_KEY_HEX,
    deviceId: 'harivu-dev-device-v1',
    deviceKeyId: 'harivu-dev-device-key-v1',
    devicePublicKeyHex: publicKeyHex(DEVICE_PRIVATE_KEY_HEX),
    ephemeralPrivateKeyHex: EPHEMERAL_PRIVATE_KEY_HEX,
    nonceHex: '0c0d0e0f1011121314151617',
    publicationId,
    publicationVersion,
  });
  const licensePayloadUtf8 = buildLicensePayload({
    contentKeyWrap: {
      algorithm: keyWrap.algorithm,
      ephemeralPublicKey: keyWrap.ephemeralPublicKey,
      nonce: keyWrap.nonce,
      tag: keyWrap.tag,
      wrappedContentKey: keyWrap.wrappedContentKey,
    },
    manifestSha256,
  });

  return {
    encryptedResources,
    licenseJws: signLicenseJws({
      payload: licensePayloadUtf8,
      signingPrivateKeyHex: SIGNING_PRIVATE_KEY_HEX,
    }),
    manifestSha256,
    manifestUtf8,
  };
}

function deterministicResourceNonce({
  path,
  publicationId,
  publicationVersion,
}) {
  return createHash('sha256')
    .update(
      `harivu-resource-nonce-v1|${publicationId}|${publicationVersion}|${path}`,
    )
    .digest()
    .subarray(0, 12)
    .toString('hex');
}

function publicKeyHex(privateKeyHex) {
  const key = createECDH('prime256v1');
  key.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
  return key.getPublicKey('hex', 'uncompressed');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
