import assert from 'node:assert/strict';
import test from 'node:test';

import { buildProtectedFixture } from './protected_fixture_builder.mjs';

test('builds encrypted publication entries and a manifest-bound license', () => {
  const fixture = buildProtectedFixture({
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
    resources: new Map([
      [
        'EPUB/chapter.xhtml',
        {
          mediaType: 'application/xhtml+xml',
          plaintext: Buffer.from('<p>secret fixture marker</p>'),
        },
      ],
    ]),
  });

  const encrypted = fixture.encryptedResources.get('EPUB/chapter.xhtml');
  assert.ok(encrypted);
  assert.equal(encrypted.includes(Buffer.from('secret fixture marker')), false);
  const manifest = JSON.parse(fixture.manifestUtf8);
  assert.equal(manifest.resources.length, 1);
  assert.equal(manifest.resources[0].path, 'EPUB/chapter.xhtml');

  const [, encodedPayload] = fixture.licenseJws.split('.');
  const license = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
  assert.equal(license.manifestSha256, fixture.manifestSha256);
  assert.equal(license.publicationId, 'harivu-phase2-fixture');
});
