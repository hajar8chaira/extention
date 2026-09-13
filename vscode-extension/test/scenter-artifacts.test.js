'use strict';

/**
 * Build et distribution automatiques des artefacts Security Center (A, B, C, H).
 *
 * Le vrai flux de packaging est exécuté (vsce et npm pack) sur le code courant,
 * avec une identité de commit injectée ; les règles de publication sont
 * vérifiées avec des commandes simulées.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const {
  BUILD_INFO_FILE, MANIFEST_FILE, BUILD_RECORD_FILE, BuildError,
  parseArgs, resolveIdentity, buildArtifacts, readZipEntry, readTgzEntry
} = require('../scripts/build-scenter-artifacts');
const { name: PACKAGE_NAME, version: PACKAGE_VERSION } = require('../package.json');

const EXTENSION_ROOT = path.join(__dirname, '..');
const WORKFLOW = path.join(__dirname, '..', '..', '.github', 'workflows', 'scenter-artifacts.yml');
const COMMIT = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const BASE_URL = `https://github.com/hajar8chaira/extention/releases/download/scenter-build-${COMMIT}`;
const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

function tempDir(t, prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// ------------------------------------------------------------ A / C / H

test('A / C / H — un build réussi produit VSIX, TGZ et manifeste du même commit', { timeout: 300000 }, (t) => {
  const out = tempDir(t, 'sc-artifacts-');
  const result = buildArtifacts(
    { out, baseUrl: BASE_URL, skipChecks: true },
    { identity: () => ({ commit: COMMIT, dirty: false }), log: () => {} }
  );

  // A. Les trois fichiers publiables existent.
  const vsixName = `${PACKAGE_NAME}-${PACKAGE_VERSION}.vsix`;
  const tgzName = `${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz`;
  for (const file of [vsixName, tgzName, BUILD_RECORD_FILE, MANIFEST_FILE]) {
    assert.ok(fs.existsSync(path.join(out, file)), `${file} produit`);
  }
  assert.deepEqual(fs.readdirSync(out).filter((name) => name.startsWith('.staging-')), [], 'aucun répertoire temporaire laissé');
  assert.equal(fs.existsSync(path.join(EXTENSION_ROOT, BUILD_INFO_FILE)), false, 'build-info.json retiré du dossier source');

  const manifest = JSON.parse(fs.readFileSync(path.join(out, MANIFEST_FILE), 'utf8'));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.name, PACKAGE_NAME);
  assert.equal(manifest.version, PACKAGE_VERSION);
  assert.equal(manifest.commit, COMMIT);
  assert.ok(!Number.isNaN(Date.parse(manifest.buildTimestamp)));
  assert.equal(manifest.tgz.url, `${BASE_URL}/${tgzName}`);
  assert.equal(manifest.vsix.url, `${BASE_URL}/${vsixName}`);
  assert.deepEqual(result.manifest, manifest);

  // C. Les SHA-256 du manifeste sont ceux des fichiers publiés.
  const tgz = fs.readFileSync(path.join(out, tgzName));
  const vsix = fs.readFileSync(path.join(out, vsixName));
  assert.equal(manifest.tgz.sha256, sha256(tgz));
  assert.equal(manifest.tgz.size, tgz.length);
  assert.equal(manifest.vsix.sha256, sha256(vsix));
  const record = JSON.parse(fs.readFileSync(path.join(out, BUILD_RECORD_FILE), 'utf8'));
  assert.equal(record.tgz.sha256, manifest.tgz.sha256);
  assert.equal(record.dirty, false);

  // H. Le VSIX et le TGZ embarquent la même identité de build.
  const fromVsix = JSON.parse(readZipEntry(vsix, `extension/${BUILD_INFO_FILE}`).toString('utf8'));
  const fromTgz = JSON.parse(readTgzEntry(tgz, `package/${BUILD_INFO_FILE}`).toString('utf8'));
  assert.equal(fromVsix.commit, COMMIT);
  assert.equal(fromTgz.commit, COMMIT);
  assert.equal(fromVsix.buildTimestamp, fromTgz.buildTimestamp);
  assert.equal(fromTgz.buildTimestamp, manifest.buildTimestamp);

  // Le paquet CLI reste celui du flux existant : entrée Linux, commande security-center.
  const cli = readTgzEntry(tgz, 'package/src/cli.js');
  assert.equal(cli.subarray(0, cli.indexOf(10)).toString('latin1'), '#!/usr/bin/env node');
  assert.deepEqual(JSON.parse(readTgzEntry(tgz, 'package/package.json').toString('utf8')).bin, { 'security-center': './src/cli.js' });
  assert.equal(readTgzEntry(tgz, 'package/test/ci-report.test.js'), null, 'aucun test dans le paquet');
});

// ------------------------------------------------------------ B

function recordingRun(failOn) {
  const calls = [];
  const run = (command, args) => {
    const line = `${command} ${args.join(' ')}`;
    calls.push(line);
    return failOn && line.startsWith(failOn) ? 1 : 0;
  };
  return { run, calls };
}

test('B — checks en échec : rien n’est empaqueté ni publié, l’ancien manifeste reste', (t) => {
  const out = tempDir(t, 'sc-artifacts-fail-');
  const previous = `${JSON.stringify({ schemaVersion: 1, commit: 'f'.repeat(40) })}\n`;
  fs.writeFileSync(path.join(out, MANIFEST_FILE), previous);

  const check = recordingRun('npm run check');
  assert.throws(() => buildArtifacts({ out }, { run: check.run, identity: () => ({ commit: COMMIT, dirty: false }), log: () => {} }), BuildError);
  assert.deepEqual(check.calls, ['npm run check'], 'ni tests, ni VSIX, ni npm pack après un échec');

  const tests = recordingRun('npm test');
  assert.throws(() => buildArtifacts({ out }, { run: tests.run, identity: () => ({ commit: COMMIT, dirty: false }), log: () => {} }), /npm test failed/);
  assert.deepEqual(tests.calls, ['npm run check', 'npm test']);

  const packaging = recordingRun('npm run package:vsix');
  assert.throws(() => buildArtifacts({ out }, { run: packaging.run, identity: () => ({ commit: COMMIT, dirty: false }), log: () => {} }), /VSIX packaging failed/);

  assert.equal(fs.readFileSync(path.join(out, MANIFEST_FILE), 'utf8'), previous, 'manifeste latest inchangé');
  assert.deepEqual(fs.readdirSync(out).sort(), [MANIFEST_FILE], 'aucun artefact partiel');
  assert.equal(fs.existsSync(path.join(EXTENSION_ROOT, BUILD_INFO_FILE)), false);
});

test('B — un arbre de travail modifié n’est jamais publié comme latest', () => {
  const run = recordingRun();
  assert.throws(() => buildArtifacts({ out: os.tmpdir() }, { run: run.run, identity: () => ({ commit: COMMIT, dirty: true }), log: () => {} }), /uncommitted changes/);
  assert.deepEqual(run.calls, [], 'refusé avant toute commande');
  const source = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'build-scenter-artifacts.js'), 'utf8');
  assert.match(source, /if \(dirty\) \{[\s\S]*?fs\.rmSync\(manifestPath/);
});

test('identité : commit git réel, arbre sale détecté, commit illisible refusé', () => {
  const clean = resolveIdentity({ env: {}, git: (args) => (args[0] === 'rev-parse' ? COMMIT : '') });
  assert.deepEqual(clean, { commit: COMMIT, dirty: false });
  assert.equal(resolveIdentity({ env: {}, git: (args) => (args[0] === 'rev-parse' ? COMMIT : ' M src/cli.js') }).dirty, true);
  assert.equal(resolveIdentity({ env: { GITHUB_SHA: COMMIT.toUpperCase() }, git: () => '' }).commit, COMMIT);
  assert.throws(() => resolveIdentity({ env: {}, git: () => 'not-a-sha' }), /source commit/);
  assert.throws(() => parseArgs(['--base-url', 'ftp://x']), /http\(s\) URL/);
  assert.throws(() => parseArgs(['--out']), /needs a value/);
});

// ------------------------------------------------------------ workflow

test('workflow : déclenché par push, publie seulement après succès, latest jamais régressé', () => {
  const workflow = fs.readFileSync(WORKFLOW, 'utf8');
  assert.match(workflow, /on:\s*\n\s*push:\s*\n\s*branches: \[main\]/);
  assert.match(workflow, /- 'vscode-extension\/\*\*'/);
  assert.match(workflow, /permissions:\s*\n\s*contents: write/);
  assert.match(workflow, /concurrency:\s*\n\s*group: scenter-artifacts\s*\n\s*cancel-in-progress: false/);
  // Checks et tests inclus : aucun contournement dans le build CI.
  assert.match(workflow, /node scripts\/build-scenter-artifacts\.js/);
  assert.doesNotMatch(workflow, /--skip-checks|--skip-tests|--allow-dirty/);
  assert.doesNotMatch(workflow, /if: always\(\)|continue-on-error/);
  const build = workflow.indexOf('name: Check, test and package');
  const release = workflow.indexOf('name: Publish the build release');
  const promote = workflow.indexOf('name: Promote the latest manifest');
  assert.ok(build > 0 && build < release && release < promote, 'build → release immuable → promotion');
  assert.match(workflow, /--base-url "https:\/\/github\.com\/\$\{\{ github\.repository \}\}\/releases\/download\/scenter-build-\$\{\{ github\.sha \}\}"/);
  assert.match(workflow, /TAG="scenter-build-\$\{GITHUB_SHA\}"/);
  assert.match(workflow, /if \[ "\$\(git rev-parse origin\/main\)" != "\$GITHUB_SHA" \]/);
  assert.match(workflow, /gh release upload scenter-latest dist\/security-center-latest\.json --clobber/);
  assert.doesNotMatch(workflow, /[A-Z]:\\\\|C:\/Users/, 'aucun chemin Windows local');
});
