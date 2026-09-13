'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { commandVersion, TOOLS, SNYK_CLI_BASE, snykCliAsset } = require('../src/scanner-tool-manager');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
const windowsOnly = process.platform !== 'win32' ? 'fixture cmd.exe requise' : false;

/** A launcher that answers late, like the Snyk CLI unpacking on its first run. */
async function slowVersionFixture(t, seconds = 3) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'snyk-slow-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }).catch(() => {}));
  const file = path.join(dir, 'slow-version.cmd');
  await fsp.writeFile(file, `@echo off\r\nping -n ${seconds} 127.0.0.1 >nul\r\necho 1.1307.2\r\n`);
  return file;
}

test('Snyk : le budget de détection décide seul du verdict d’installation', { skip: windowsOnly }, async (t) => {
  const launcher = await slowVersionFixture(t);
  // Un budget trop court transforme une installation saine en « rien renvoyé ».
  assert.equal(await commandVersion(launcher, 300), '', 'un budget insuffisant efface une version pourtant disponible');
  // Le même exécutable, avec le budget accordé au premier démarrage, répond.
  const started = Date.now();
  assert.equal(await commandVersion(launcher, 60000), '1.1307.2');
  assert.ok(Date.now() - started >= 1500, 'la réponse est bien arrivée après une attente réelle');
});

test('Snyk : le CLI reçoit l’allocation de premier démarrage, les autres outils gardent 30 s', () => {
  const source = src('scanner-tool-manager.js');
  // Le premier lancement du binaire Snyk fraîchement écrit (181 Mo) a été mesuré
  // à 21 s : sous 30 s, une installation réussie pouvait être déclarée en échec.
  assert.match(source, /const versionTimeout = id === 'semgrep' \|\| id === 'snyk' \? 60000 : 30000;/);
  // La détection reste la seule chose ajustée : le téléchargement partagé,
  // corrigé et validé précédemment, n’est pas retouché.
  assert.match(source, /async function download\(url, destination, onProgress = \(\) => \{\}, \{ signal, timeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS, stallTimeoutMs = DEFAULT_STALL_MS, progressIntervalMs = DEFAULT_PROGRESS_INTERVAL_MS \} = \{\}\)/);
});

test('Snyk : la carte retombe sur l’état managé quand la sonde courte n’a pas répondu', () => {
  const extension = src('extension.js');
  // `collectSnykDiagnostic` sonde le CLI avec un budget plus court que le
  // premier démarrage réel ; sans ce repli, la carte afficherait « aucune
  // version » juste après une installation réussie.
  assert.match(extension, /detectLocalSnykCli\(\{ timeoutMs: 20000 \}\)/);
  assert.match(extension, /if \(!snyk\.cliVersion && snykStatus\?\.installed\) \{[\s\S]*?snyk\.cliVersion = snykStatus\.version;[\s\S]*?snyk\.cliPath = snykStatus\.executable;/);
});

test('Snyk : la source officielle et l’artefact Windows restent inchangés', () => {
  assert.equal(SNYK_CLI_BASE, 'https://downloads.snyk.io/cli/stable');
  assert.equal(snykCliAsset('win32', 'x64'), 'snyk-win.exe');
  assert.equal(TOOLS.snyk.kind, 'snyk');
  assert.equal(TOOLS.snyk.command, 'snyk');
  const source = src('scanner-tool-manager.js');
  assert.match(source, /if \(actual !== expected\) throw new Error\('Échec de vérification SHA-256 du binaire Snyk/);
});
