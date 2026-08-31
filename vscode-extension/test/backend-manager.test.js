'use strict';

/**
 * The backend lifecycle, exercised without an editor and without a process.
 *
 * Every dependency that touches the machine — the health probe, `spawn`, the
 * lock file, the port check — is injected, so these tests describe decisions
 * rather than timing: when a backend is started, when it is reused, when it is
 * left alone, and what is reported when it never comes up.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  BackendManager, BACKEND_MODE, RESOLVED_MODE, resolveBackendMode, resolveDataDirectory,
  generateLocalApiKey
} = require('../src/backend-manager');
const { BACKEND_STATE, DEFAULT_BACKEND_URL, describeBackend } = require('../src/backend-config');
const { writeLockFile, readLockFile, writeDiscoveryFile, readDiscoveryFile, discoveryFilePath } = require('../backend/discovery');

const configuration = (values = {}) => ({ get: (key, fallback) => (key in values ? values[key] : fallback) });

const online = (url) => describeBackend({ state: BACKEND_STATE.ONLINE, url, service: 'security-center-backend', version: '1.0.0' });
const offline = (url) => describeBackend({ state: BACKEND_STATE.OFFLINE, url, message: 'connect ECONNREFUSED' });

function temporaryDirectory(prefix = 'sc-backend-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** A manager whose every side effect is observable and none of them real. */
function createManager(overrides = {}) {
  const calls = { spawns: [], discovery: [] };
  const manager = new BackendManager({
    dataDir: overrides.dataDir === undefined ? temporaryDirectory() : overrides.dataDir,
    getConfiguration: () => configuration(overrides.settings || {}),
    apiKey: 'test-key',
    readLock: overrides.readLock || (() => null),
    removeLock: overrides.removeLock || (() => {}),
    portFree: overrides.portFree || (async () => true),
    freePort: overrides.freePort || (async () => 51234),
    probe: overrides.probe || (async (url) => offline(url)),
    publishDiscovery: (record) => { calls.discovery.push(record); },
    spawnProcess: overrides.spawnProcess || ((command, args, options) => {
      calls.spawns.push({ command, args, options });
      return { pid: 4242, stdout: null, stderr: null, on() {}, unref() {} };
    }),
    startTimeoutMs: overrides.startTimeoutMs === undefined ? 400 : overrides.startTimeoutMs,
    log: () => {}
  });
  return { manager, calls };
}

// -------------------------------------------------------------------- modes

test('le mode par défaut est Auto, et une valeur inconnue y retombe', () => {
  assert.equal(resolveBackendMode(configuration()), BACKEND_MODE.AUTO);
  assert.equal(resolveBackendMode(configuration({ 'backend.mode': 'remote' })), BACKEND_MODE.REMOTE);
  assert.equal(resolveBackendMode(configuration({ 'backend.mode': 'DOCKER' })), BACKEND_MODE.DOCKER);
  // Une faute de frappe dans les réglages ne doit pas priver le produit de backend.
  assert.equal(resolveBackendMode(configuration({ 'backend.mode': 'kubernetes' })), BACKEND_MODE.AUTO);
});

// ----------------------------------------------------- 1. déjà en ligne

test('backend local déjà en ligne : il est réutilisé, aucun processus n’est démarré', async () => {
  const { manager, calls } = createManager({ probe: async (url) => online(url) });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.ONLINE);
  assert.equal(status.resolvedMode, RESOLVED_MODE.LOCAL);
  assert.equal(calls.spawns.length, 0);
});

// --------------------------------------- 2 & 3. absent → démarrage réussi

test('backend absent : il est démarré, puis considéré en ligne après un vrai /health', async () => {
  // Deux sondages précèdent le démarrage : celui de `ensureBackend`, puis celui
  // qui garde contre une autre fenêtre ayant démarré le service entre-temps.
  let probes = 0;
  const { manager, calls } = createManager({
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url))
  });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.ONLINE);
  assert.equal(calls.spawns.length, 1);
  const [spawned] = calls.spawns;
  // Le service tourne sur le Node de VS Code : ni Python, ni Docker, ni binaire téléchargé.
  assert.match(spawned.args[0], /backend[\\/]server\.js$/);
  assert.equal(spawned.options.env.ELECTRON_RUN_AS_NODE, '1');
  assert.equal(spawned.options.detached, true);
  // Le répertoire de données est transmis explicitement, jamais déduit du dossier d’extension.
  assert.ok(spawned.args.includes('--data-dir'));
});

test('la clé d’API voyage par l’environnement, jamais par la ligne de commande', async () => {
  let probes = 0;
  const { manager, calls } = createManager({ probe: async (url) => (probes++ < 2 ? offline(url) : online(url)) });
  await manager.ensureBackend();
  const [spawned] = calls.spawns;
  assert.equal(spawned.options.env.SECURITY_CENTER_API_KEY, 'test-key');
  assert.doesNotMatch(spawned.args.join(' '), /test-key/);
});

// ------------------------------------------------- 4 & 5. échec, délai

test('démarrage impossible : l’erreur du processus est rapportée, pas un ECONNREFUSED brut', async () => {
  const { manager } = createManager({
    spawnProcess: () => { throw new Error('EACCES: permission denied'); }
  });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.ERROR);
  assert.match(status.message, /EACCES/);
  assert.equal(status.online, false);
});

test('le backend démarré ne répond jamais : l’état est TIMEOUT, pas « 0 résultat »', async () => {
  const { manager } = createManager({ probe: async (url) => offline(url), startTimeoutMs: 300 });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.TIMEOUT);
  assert.equal(status.online, false);
  assert.ok(status.hint);
});

// ------------------------------------------ 6. un autre service sur le port

test('un service étranger sur le port : l’attente s’arrête au lieu de boucler', async () => {
  let probes = 0;
  const { manager } = createManager({
    probe: async (url) => {
      probes += 1;
      return probes === 1 ? offline(url) : describeBackend({ state: BACKEND_STATE.INVALID_RESPONSE, url });
    },
    startTimeoutMs: 5000
  });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.INVALID_RESPONSE);
  // Un HTTP 200 ne prouve rien : seul /health nommant le service est une preuve.
  assert.equal(status.online, false);
});

// -------------------------------------------------- 7 & 8. mode Remote

test('mode Remote : l’adresse configurée est utilisée telle quelle', async () => {
  const probed = [];
  const { manager, calls } = createManager({
    settings: { 'backend.mode': 'remote', 'backend.url': 'https://security.company.internal' },
    probe: async (url) => { probed.push(url); return online(url); }
  });
  const status = await manager.ensureBackend();
  assert.equal(status.resolvedMode, RESOLVED_MODE.REMOTE);
  assert.equal(status.url, 'https://security.company.internal');
  assert.deepEqual(probed, ['https://security.company.internal']);
  assert.equal(calls.spawns.length, 0);
});

test('mode Remote hors ligne : l’extension ne démarre rien', async () => {
  const { manager, calls } = createManager({
    settings: { 'backend.mode': 'remote', 'backend.url': 'https://security.company.internal' },
    probe: async (url) => offline(url)
  });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.OFFLINE);
  assert.equal(calls.spawns.length, 0);
  // Aucune commande à copier : démarrer le backend d’une organisation n’est pas notre rôle.
  assert.equal(status.startCommand, '');
});

test('mode Remote sans adresse : non configuré, et rien n’est démarré', async () => {
  const { manager, calls } = createManager({ settings: { 'backend.mode': 'remote' } });
  const status = await manager.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.NOT_CONFIGURED);
  assert.equal(calls.spawns.length, 0);
});

test('mode Docker : l’extension rapporte l’état et ne démarre pas le compose', async () => {
  const { manager, calls } = createManager({
    settings: { 'backend.mode': 'docker' },
    probe: async (url) => offline(url)
  });
  const status = await manager.ensureBackend();
  assert.equal(status.resolvedMode, RESOLVED_MODE.DOCKER);
  assert.equal(calls.spawns.length, 0);
});

// ------------------------------------------ 9. démarrages concurrents

test('trois pages ouvertes en même temps démarrent un seul backend', async () => {
  let probes = 0;
  const { manager, calls } = createManager({
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url))
  });
  const [first, second, third] = await Promise.all([
    manager.ensureBackend(), manager.startLocalBackend(), manager.startLocalBackend()
  ]);
  assert.equal(calls.spawns.length, 1);
  assert.equal(first.online, true);
  assert.equal(second.online, true);
  assert.equal(third.online, true);
});

// ---------------------------------------------------- 10. choix du port

test('le port par défaut est préféré quand il est libre', async () => {
  const { manager } = createManager({ portFree: async (port) => port === 8765 });
  assert.equal(await manager.choosePort(), 8765);
});

test('un port occupé par un autre service : un port libre est choisi à la place', async () => {
  const { manager } = createManager({ portFree: async () => false, freePort: async () => 51999 });
  assert.equal(await manager.choosePort(), 51999);
});

test('le port publié par un backend précédent est repris avant le port par défaut', async () => {
  const { manager } = createManager({
    readLock: () => ({ pid: 10, port: 9911, url: 'http://127.0.0.1:9911' }),
    portFree: async () => true
  });
  assert.equal(await manager.choosePort(), 9911);
});

test('l’adresse résolue est celle du verrou, pas la valeur par défaut', () => {
  const { manager } = createManager({
    readLock: () => ({ pid: 10, port: 9911, url: 'http://127.0.0.1:9911' })
  });
  assert.equal(manager.resolveBackendUrl(), 'http://127.0.0.1:9911');
});

test('sans verrou, l’adresse résolue reste l’adresse par défaut', () => {
  const { manager } = createManager();
  assert.equal(manager.resolveBackendUrl(), DEFAULT_BACKEND_URL);
});

// ------------------------------------------------------- 11. redémarrage

test('redémarrage : le processus du verrou est arrêté, puis un backend est redémarré', async () => {
  const dataDir = temporaryDirectory();
  const killed = [];
  const removed = [];
  let probes = 0;
  const { manager, calls } = createManager({
    dataDir,
    readLock: () => ({ pid: process.pid, port: 8765, url: DEFAULT_BACKEND_URL }),
    removeLock: (directory) => removed.push(directory),
    probe: async (url) => (probes++ < 1 ? offline(url) : online(url))
  });
  const originalKill = process.kill;
  process.kill = (pid, signal) => { killed.push({ pid, signal }); };
  try {
    const status = await manager.restartLocalBackend();
    assert.equal(status.online, true);
  } finally {
    process.kill = originalKill;
  }
  assert.deepEqual(killed, [{ pid: process.pid, signal: 'SIGTERM' }]);
  assert.deepEqual(removed, [dataDir]);
  assert.equal(calls.spawns.length, 1);
});

test('un backend distant n’est jamais arrêté par l’extension', async () => {
  const { manager } = createManager({ settings: { 'backend.mode': 'remote', 'backend.url': 'https://remote.internal' } });
  assert.equal(await manager.stopLocalBackend(), false);
});

test('fermer VS Code ne tue pas un backend qu’une autre fenêtre peut utiliser', async () => {
  const killed = [];
  const { manager } = createManager({ readLock: () => ({ pid: 4242, port: 8765, url: DEFAULT_BACKEND_URL }) });
  const originalKill = process.kill;
  process.kill = (pid, signal) => killed.push({ pid, signal });
  try {
    manager.dispose();
  } finally {
    process.kill = originalKill;
  }
  assert.deepEqual(killed, []);
});

// ------------------------------------------------- 12. persistance

test('les données vivent dans le stockage global, jamais dans le dossier d’extension', () => {
  const globalStorage = path.join(os.tmpdir(), 'vscode-global-storage', 'security-center');
  const dataDir = resolveDataDirectory({ globalStorageUri: { fsPath: globalStorage } });
  assert.equal(dataDir, path.join(globalStorage, 'backend-data'));
  // Une mise à jour remplace le dossier d’extension : l’historique ne doit pas y être.
  assert.doesNotMatch(dataDir, /vscode-extension/);
  assert.equal(resolveDataDirectory({}), '');
});

test('sans emplacement de données, le démarrage échoue proprement au lieu d’écrire n’importe où', async () => {
  const { manager, calls } = createManager({ dataDir: '' });
  const status = await manager.startLocalBackend();
  assert.equal(status.state, BACKEND_STATE.ERROR);
  assert.equal(calls.spawns.length, 0);
});

// ------------------------------------------- verrou et fichier de découverte

test('un verrou nommant un processus mort est traité comme absent', () => {
  const dataDir = temporaryDirectory();
  writeLockFile(dataDir, { pid: 999999, port: 8765, url: DEFAULT_BACKEND_URL });
  assert.equal(readLockFile(dataDir, { isAlive: () => false }), null);
  assert.equal(readLockFile(dataDir, { isAlive: () => true }).port, 8765);
});

test('un verrou écrit par un autre produit est ignoré', () => {
  const dataDir = temporaryDirectory();
  fs.writeFileSync(path.join(dataDir, 'backend.lock.json'), JSON.stringify({ service: 'autre-chose', pid: 1, port: 1, url: 'http://x' }));
  assert.equal(readLockFile(dataDir, { isAlive: () => true }), null);
});

// ---------------------------------------------------------- 15. Burp

test('le backend actif est publié pour Burp dès qu’il est en ligne', async () => {
  const { manager, calls } = createManager({ probe: async (url) => online(url) });
  await manager.ensureBackend();
  assert.equal(calls.discovery.length, 1);
  assert.equal(calls.discovery[0].url, DEFAULT_BACKEND_URL);
  assert.equal(calls.discovery[0].apiKey, 'test-key');
});

test('en mode Remote aussi, Burp suit le backend réellement utilisé', async () => {
  const { manager, calls } = createManager({
    settings: { 'backend.mode': 'remote', 'backend.url': 'https://security.company.internal' },
    probe: async (url) => online(url)
  });
  await manager.ensureBackend();
  assert.equal(calls.discovery[0].url, 'https://security.company.internal');
  assert.equal(calls.discovery[0].mode, BACKEND_MODE.REMOTE);
});

test('le fichier de découverte est lisible par le connecteur et n’est pas lisible par tout le monde', () => {
  const home = temporaryDirectory('sc-home-');
  const file = writeDiscoveryFile({ url: 'http://127.0.0.1:9123', mode: 'auto', version: '1.0.0', apiKey: 'k' }, { home });
  assert.equal(file, discoveryFilePath(home));
  const record = readDiscoveryFile({ home });
  assert.equal(record.url, 'http://127.0.0.1:9123');
  assert.equal(record.api_key, 'k');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test('la clé locale générée est aléatoire et suffisamment longue', () => {
  const first = generateLocalApiKey();
  const second = generateLocalApiKey();
  assert.notEqual(first, second);
  assert.ok(first.length >= 32);
});

// -------------------------------- 16. plus aucune adresse en dur ailleurs

test('l’adresse par défaut n’est déclarée que dans le module de configuration', () => {
  const sourceRoot = path.join(__dirname, '..', 'src');
  const offenders = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) { walk(target); continue; }
      if (!entry.name.endsWith('.js') || entry.name === 'backend-config.js') continue;
      if (/127\.0\.0\.1:8765/.test(fs.readFileSync(target, 'utf8'))) offenders.push(entry.name);
    }
  };
  walk(sourceRoot);
  assert.deepEqual(offenders, []);
});

test('le connecteur Burp ne code plus l’adresse du backend en dur', () => {
  const connector = path.join(
    __dirname, '..', '..', 'burp-extension', 'src', 'main', 'java', 'com', 'securitycenter', 'burp',
    'SecurityCenterExtension.java'
  );
  const source = fs.readFileSync(connector, 'utf8');
  assert.doesNotMatch(source, /127\.0\.0\.1:8765/);
  // Il lit l’adresse publiée par Security Center, quel que soit le port choisi.
  assert.match(source, /\.security-center/);
  assert.match(source, /backend\.json/);
});

// ---------------------- 13. les capacités autonomes le restent sans backend

test('scan, Live Security et correction ne dépendent pas du backend', () => {
  const sourceRoot = path.join(__dirname, '..', 'src');
  const autonomous = [
    'orchestrator.js', 'semgrep.js', 'gitleaks.js', 'trivy.js', 'osv.js', 'correlation.js',
    'autofix.js', 'fix-verification.js', 'live/liveDetector.js', 'live/liveSecurityService.js'
  ];
  for (const relative of autonomous) {
    const file = path.join(sourceRoot, relative);
    if (!fs.existsSync(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /require\('\.\.?\/?backend(-config|-manager)?'\)/, `${relative} dépend du backend`);
  }
});
