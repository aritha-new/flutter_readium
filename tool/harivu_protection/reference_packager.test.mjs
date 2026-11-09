import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildManifest,
  buildLicensePayload,
  encryptResource,
  signLicenseJws,
  wrapContentKey,
} from './reference_packager.mjs';

test('encrypts the recorded Harivu v1 resource vector', () => {
  const vector = encryptResource({
    contentKeyHex:
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    nonceHex: '000102030405060708090a0b',
    plaintext: Buffer.from('<p>Harivu protected fixture.</p>\n'),
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
    path: 'EPUB/chapter-1.xhtml',
    mediaType: 'application/xhtml+xml',
  });

  assert.deepEqual(vector, {
    aad:
      '{"algorithm":"A256GCM","mediaType":"application/xhtml+xml","packageVersion":1,"path":"EPUB/chapter-1.xhtml","plaintextLength":33,"publicationId":"harivu-phase2-fixture","publicationVersion":1}',
    aadSha256: '6ca183e829509c48fac018f17937a45ae8fac398a00c49cde33d5e5111d045f0',
    ciphertextHex:
      '7b72e853a497ab6df861e7f9de9d1d0ef7b3e314961227084d1580ab2146708c0b',
    nonceHex: '000102030405060708090a0b',
    plaintextLength: 33,
    plaintextSha256:
      '47dff6bbaad22345246b1bda8749fa5c8d2a16ed5e0063f1c56ec42716dee73e',
    tagHex: 'ee706c631439e486cbc471177c7f2433',
  });
});

test('rejects a plaintext resource larger than 2 MiB', () => {
  assert.throws(
    () =>
      encryptResource({
        contentKeyHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        nonceHex: '000102030405060708090a0b',
        plaintext: Buffer.alloc(2 * 1024 * 1024 + 1),
        publicationId: 'harivu-phase2-fixture',
        publicationVersion: 1,
        path: 'EPUB/oversized-image.jpg',
        mediaType: 'image/jpeg',
      }),
    (error) => error.code === 'ProtectedResourceTooLarge',
  );
});

test('builds the canonical Harivu protected EPUB v1 manifest', () => {
  const manifest = buildManifest({
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
    resources: [
      {
        ciphertextSha256:
          'a80cb620da0e4fdb4bc92fe6502d642244c2a6d9c8c9927ca29166363f51e2fa',
        mediaType: 'application/xhtml+xml',
        nonce: 'AAECAwQFBgcICQoL',
        path: 'EPUB/chapter-1.xhtml',
        plaintextLength: 33,
        plaintextSha256:
          '47dff6bbaad22345246b1bda8749fa5c8d2a16ed5e0063f1c56ec42716dee73e',
        tag: '7nBsYxQ55IbLxHEXfH8kMw',
      },
    ],
  });

  assert.equal(
    manifest,
    '{"algorithm":"A256GCM","format":"harivu-protected-epub","maxPlaintextResourceSize":2097152,"packageVersion":1,"publicationId":"harivu-phase2-fixture","publicationVersion":1,"resources":[{"ciphertextSha256":"a80cb620da0e4fdb4bc92fe6502d642244c2a6d9c8c9927ca29166363f51e2fa","mediaType":"application/xhtml+xml","nonce":"AAECAwQFBgcICQoL","path":"EPUB/chapter-1.xhtml","plaintextLength":33,"plaintextSha256":"47dff6bbaad22345246b1bda8749fa5c8d2a16ed5e0063f1c56ec42716dee73e","tag":"7nBsYxQ55IbLxHEXfH8kMw"}]}',
  );
});

test('wraps the content key for the recorded development device', () => {
  const vector = wrapContentKey({
    contentKeyHex:
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    deviceId: 'harivu-dev-device-v1',
    deviceKeyId: 'harivu-dev-device-key-v1',
    devicePublicKeyHex:
      '04984225585d2285c138033d6140e3cef8b91859704e53c313f8b636ba4f9676499734144f46fd19a767a545287c4396b97b69dd38faaea8981adc1a4fed9b401e',
    ephemeralPrivateKeyHex:
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
    nonceHex: '0c0d0e0f1011121314151617',
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
  });

  assert.deepEqual(vector, {
    aad:
      '{"algorithm":"ECDH-ES+HKDF-SHA256+A256GCM","deviceId":"harivu-dev-device-v1","deviceKeyId":"harivu-dev-device-key-v1","licenseVersion":1,"publicationId":"harivu-phase2-fixture","publicationVersion":1}',
    aadSha256: 'e830328cd5f8a380190eb9b7f0eb0ff70c513f597bafd8613f6098ccffcf8e13',
    algorithm: 'ECDH-ES+HKDF-SHA256+A256GCM',
    ephemeralPublicKey:
      'BMZVnUFt-1avcU8UbZF8JKv4GLL7EhYEEpZJhIIwotJYsqbYLcbGc0zwkv-qn8AS8Q9wCNOVKgjVeX6F_qul2Xc',
    nonce: 'DA0ODxAREhMUFRYX',
    sharedSecretHex:
      'c89ed911b74fe83058ce058e0b4693986b8458ea948e859e21d4a0f547473a4a',
    tag: 'VrDXLqqtqemWLgUIpzHTFg',
    wrappingKeyHex:
      'af66ddce360a0545ebd5406ba2d77fbd72a699fcd793fdc1f1d0b17a6e39f148',
    wrappedContentKey: 'u9vixgi9_qFl_if7aLUpAliEpq7jVYYjcgbMxlvuyR8',
  });
});

test('builds the canonical Harivu offline license v1 payload', () => {
  const payload = buildLicensePayload({
    manifestSha256:
      'fd368365c29053c9adaf91857d2b891cda52002169bd0f6e0d6b024bc486c90e',
    contentKeyWrap: {
      algorithm: 'ECDH-ES+HKDF-SHA256+A256GCM',
      ephemeralPublicKey:
        'BMZVnUFt-1avcU8UbZF8JKv4GLL7EhYEEpZJhIIwotJYsqbYLcbGc0zwkv-qn8AS8Q9wCNOVKgjVeX6F_qul2Xc',
      nonce: 'DA0ODxAREhMUFRYX',
      tag: 'VrDXLqqtqemWLgUIpzHTFg',
      wrappedContentKey: 'u9vixgi9_qFl_if7aLUpAliEpq7jVYYjcgbMxlvuyR8',
    },
  });

  assert.equal(
    payload,
    '{"contentKeyWrap":{"algorithm":"ECDH-ES+HKDF-SHA256+A256GCM","ephemeralPublicKey":"BMZVnUFt-1avcU8UbZF8JKv4GLL7EhYEEpZJhIIwotJYsqbYLcbGc0zwkv-qn8AS8Q9wCNOVKgjVeX6F_qul2Xc","nonce":"DA0ODxAREhMUFRYX","tag":"VrDXLqqtqemWLgUIpzHTFg","wrappedContentKey":"u9vixgi9_qFl_if7aLUpAliEpq7jVYYjcgbMxlvuyR8"},"deviceId":"harivu-dev-device-v1","deviceKeyId":"harivu-dev-device-key-v1","expiresAt":"2036-01-01T00:00:00Z","format":"harivu-offline-license","issuedAt":"2026-01-01T00:00:00Z","licenseId":"harivu-dev-license-v1","licenseVersion":1,"manifestSha256":"fd368365c29053c9adaf91857d2b891cda52002169bd0f6e0d6b024bc486c90e","notBefore":"2026-01-01T00:00:00Z","publicationId":"harivu-phase2-fixture","publicationVersion":1}',
  );
});

test('signs the exact license payload as JWS ES256', () => {
  const payload = '{"licenseVersion":1,"licenseId":"recorded-license"}';
  const jws = signLicenseJws({
    payload,
    signingPrivateKeyHex:
      '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
  });
  const [protectedHeader, encodedPayload, signature] = jws.split('.');

  assert.equal(
    Buffer.from(protectedHeader, 'base64url').toString(),
    '{"alg":"ES256","kid":"harivu-dev-signing-key-v1","typ":"harivu-license+jws"}',
  );
  assert.equal(Buffer.from(encodedPayload, 'base64url').toString(), payload);
  assert.equal(Buffer.from(signature, 'base64url').length, 64);

  const publicBytes = Buffer.from(
    '048ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b15481e8ae3b39d323778e451cb1efeb541e1325a7667edd877c68faf705007575',
    'hex',
  );
  const publicKey = createPublicKey({
    format: 'jwk',
    key: {
      crv: 'P-256',
      kty: 'EC',
      x: publicBytes.subarray(1, 33).toString('base64url'),
      y: publicBytes.subarray(33).toString('base64url'),
    },
  });
  assert.equal(
    verify(
      'sha256',
      Buffer.from(`${protectedHeader}.${encodedPayload}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
    true,
  );
});

test('recorded v1 fixture has a valid signature and exact payload bytes', () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL('../../test_vectors/harivu_protection_v1.json', import.meta.url),
      'utf8',
    ),
  );
  const [protectedHeader, encodedPayload, signature] =
    fixture.license.jws.split('.');
  assert.equal(
    Buffer.from(protectedHeader, 'base64url').toString(),
    fixture.license.protectedHeaderUtf8,
  );
  assert.equal(
    Buffer.from(encodedPayload, 'base64url').toString(),
    fixture.license.payloadUtf8,
  );

  const publicBytes = Buffer.from(fixture.keys.signingPublicKey, 'base64url');
  const publicKey = createPublicKey({
    format: 'jwk',
    key: {
      crv: 'P-256',
      kty: 'EC',
      x: publicBytes.subarray(1, 33).toString('base64url'),
      y: publicBytes.subarray(33).toString('base64url'),
    },
  });
  assert.equal(
    verify(
      'sha256',
      Buffer.from(`${protectedHeader}.${encodedPayload}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
    true,
  );
});
