import {
  createCipheriv,
  createECDH,
  createHash,
  createPrivateKey,
  hkdfSync,
  sign,
} from 'node:crypto';

const PACKAGE_VERSION = 1;
const MAX_PLAINTEXT_RESOURCE_SIZE = 2 * 1024 * 1024;

export function buildLicensePayload({ manifestSha256, contentKeyWrap }) {
  return JSON.stringify({
    contentKeyWrap,
    deviceId: 'harivu-dev-device-v1',
    deviceKeyId: 'harivu-dev-device-key-v1',
    expiresAt: '2036-01-01T00:00:00Z',
    format: 'harivu-offline-license',
    issuedAt: '2026-01-01T00:00:00Z',
    licenseId: 'harivu-dev-license-v1',
    licenseVersion: 1,
    manifestSha256,
    notBefore: '2026-01-01T00:00:00Z',
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
  });
}

export function signLicenseJws({ payload, signingPrivateKeyHex }) {
  const header = JSON.stringify({
    alg: 'ES256',
    kid: 'harivu-dev-signing-key-v1',
    typ: 'harivu-license+jws',
  });
  const encodedHeader = Buffer.from(header).toString('base64url');
  const encodedPayload = Buffer.from(payload).toString('base64url');
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  const privateBytes = Buffer.from(signingPrivateKeyHex, 'hex');
  const curve = createECDH('prime256v1');
  curve.setPrivateKey(privateBytes);
  const publicBytes = curve.getPublicKey(undefined, 'uncompressed');
  const privateKey = createPrivateKey({
    format: 'jwk',
    key: {
      crv: 'P-256',
      d: privateBytes.toString('base64url'),
      kty: 'EC',
      x: publicBytes.subarray(1, 33).toString('base64url'),
      y: publicBytes.subarray(33).toString('base64url'),
    },
  });
  const signature = sign('sha256', signingInput, {
    dsaEncoding: 'ieee-p1363',
    key: privateKey,
  });
  return `${encodedHeader}.${encodedPayload}.${signature.toString('base64url')}`;
}

export function buildManifest({
  publicationId,
  publicationVersion,
  resources,
}) {
  return JSON.stringify({
    algorithm: 'A256GCM',
    format: 'harivu-protected-epub',
    maxPlaintextResourceSize: MAX_PLAINTEXT_RESOURCE_SIZE,
    packageVersion: PACKAGE_VERSION,
    publicationId,
    publicationVersion,
    resources,
  });
}

export function wrapContentKey({
  contentKeyHex,
  deviceId,
  deviceKeyId,
  devicePublicKeyHex,
  ephemeralPrivateKeyHex,
  nonceHex,
  publicationId,
  publicationVersion,
}) {
  const algorithm = 'ECDH-ES+HKDF-SHA256+A256GCM';
  const aad = JSON.stringify({
    algorithm,
    deviceId,
    deviceKeyId,
    licenseVersion: 1,
    publicationId,
    publicationVersion,
  });
  const ephemeralKey = createECDH('prime256v1');
  ephemeralKey.setPrivateKey(Buffer.from(ephemeralPrivateKeyHex, 'hex'));
  const sharedSecret = ephemeralKey.computeSecret(
    Buffer.from(devicePublicKeyHex, 'hex'),
  );
  const salt = createHash('sha256')
    .update(`harivu-license-v1|${publicationId}|${deviceId}`)
    .digest();
  const wrappingKey = Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      salt,
      Buffer.from('harivu-content-key-wrap-v1'),
      32,
    ),
  );
  const cipher = createCipheriv(
    'aes-256-gcm',
    wrappingKey,
    Buffer.from(nonceHex, 'hex'),
  );
  cipher.setAAD(Buffer.from(aad));
  const wrappedContentKey = Buffer.concat([
    cipher.update(Buffer.from(contentKeyHex, 'hex')),
    cipher.final(),
  ]);

  return {
    aad,
    aadSha256: sha256(Buffer.from(aad)),
    algorithm,
    ephemeralPublicKey: ephemeralKey
      .getPublicKey(undefined, 'uncompressed')
      .toString('base64url'),
    nonce: Buffer.from(nonceHex, 'hex').toString('base64url'),
    sharedSecretHex: sharedSecret.toString('hex'),
    tag: cipher.getAuthTag().toString('base64url'),
    wrappingKeyHex: wrappingKey.toString('hex'),
    wrappedContentKey: wrappedContentKey.toString('base64url'),
  };
}

export function encryptResource({
  contentKeyHex,
  nonceHex,
  plaintext,
  publicationId,
  publicationVersion,
  path,
  mediaType,
}) {
  if (plaintext.length > MAX_PLAINTEXT_RESOURCE_SIZE) {
    const error = new Error('Protected resource exceeds 2 MiB.');
    error.code = 'ProtectedResourceTooLarge';
    throw error;
  }

  const aad = JSON.stringify({
    algorithm: 'A256GCM',
    mediaType,
    packageVersion: PACKAGE_VERSION,
    path,
    plaintextLength: plaintext.length,
    publicationId,
    publicationVersion,
  });
  const cipher = createCipheriv(
    'aes-256-gcm',
    Buffer.from(contentKeyHex, 'hex'),
    Buffer.from(nonceHex, 'hex'),
  );
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    aad,
    aadSha256: sha256(Buffer.from(aad)),
    ciphertextHex: ciphertext.toString('hex'),
    nonceHex,
    plaintextLength: plaintext.length,
    plaintextSha256: sha256(plaintext),
    tagHex: cipher.getAuthTag().toString('hex'),
  };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
