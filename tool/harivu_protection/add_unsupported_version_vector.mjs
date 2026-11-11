// Adds license.unsupportedVersionJws to the recorded vectors without regenerating
// (ECDSA signatures are randomized, so the other recorded JWS values must not change).
// The license is correctly signed but declares licenseVersion 2, which v1 clients must reject.
import { readFileSync, writeFileSync } from 'node:fs';

import { signLicenseJws } from './reference_packager.mjs';

const path = new URL('../../test_vectors/harivu_protection_v1.json', import.meta.url);
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const payload = JSON.parse(vectors.license.payloadUtf8);
payload.licenseVersion = 2;
vectors.license.unsupportedVersionJws = signLicenseJws({
  payload: JSON.stringify(payload),
  signingPrivateKeyHex: vectors.keys.signingPrivateKeyHex,
});
writeFileSync(path, `${JSON.stringify(vectors, null, 2)}\n`);
