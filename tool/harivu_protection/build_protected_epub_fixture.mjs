#!/usr/bin/env node

import {
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

import { buildProtectedFixture } from './protected_fixture_builder.mjs';

const [sourceRootArgument, fontArgument, outputArgument, licenseArgument] =
  process.argv.slice(2);

if (!licenseArgument) {
  process.stderr.write(
    'Usage: build_protected_epub_fixture.mjs <source-root> <font> <output.epub> <output.license.jws>\n',
  );
  process.exit(64);
}

const sourceRoot = resolve(sourceRootArgument);
const font = resolve(fontArgument);
const output = resolve(outputArgument);
const licenseOutput = resolve(licenseArgument);
const stagingRoot = mkdtempSync(join(tmpdir(), 'harivu-protected-epub-'));

try {
  cpSync(sourceRoot, stagingRoot, { recursive: true });
  mkdirSync(join(stagingRoot, 'EPUB/fonts'), { recursive: true });
  copyFileSync(font, join(stagingRoot, 'EPUB/fonts/NotoSansKannada-Regular.ttf'));
  writeFileSync(join(stagingRoot, 'mimetype'), 'application/epub+zip');

  const protectedPaths = new Map([
    ['EPUB/nav.xhtml', 'application/xhtml+xml'],
    ['EPUB/styles/reader.css', 'text/css'],
    ['EPUB/text/chapter-1.xhtml', 'application/xhtml+xml'],
    ['EPUB/text/chapter-2.xhtml', 'application/xhtml+xml'],
    ['EPUB/fonts/NotoSansKannada-Regular.ttf', 'font/ttf'],
  ]);
  const resources = new Map(
    [...protectedPaths].map(([path, mediaType]) => [
      path,
      { mediaType, plaintext: readFileSync(join(stagingRoot, path)) },
    ]),
  );
  const fixture = buildProtectedFixture({
    publicationId: 'harivu-phase2-fixture',
    publicationVersion: 1,
    resources,
  });

  for (const [path, ciphertext] of fixture.encryptedResources) {
    writeFileSync(join(stagingRoot, path), ciphertext);
  }
  mkdirSync(join(stagingRoot, 'META-INF'), { recursive: true });
  writeFileSync(
    join(stagingRoot, 'META-INF/harivu-protection.json'),
    fixture.manifestUtf8,
  );

  mkdirSync(dirname(output), { recursive: true });
  mkdirSync(dirname(licenseOutput), { recursive: true });
  const temporaryOutput = join(stagingRoot, 'protected-fixture.epub');
  runZip(['-X0', temporaryOutput, 'mimetype']);
  runZip(['-Xr9', temporaryOutput, 'META-INF', 'EPUB']);
  copyFileSync(temporaryOutput, output);
  writeFileSync(licenseOutput, `${fixture.licenseJws}\n`);

  process.stdout.write(
    `Built ${output}\nBuilt ${licenseOutput}\nManifest SHA-256: ${fixture.manifestSha256}\n`,
  );
} finally {
  rmSync(stagingRoot, { force: true, recursive: true });
}

function runZip(arguments_) {
  const result = spawnSync('zip', arguments_, {
    cwd: stagingRoot,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || 'zip failed');
  }
}
