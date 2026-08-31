'use strict';

/**
 * Le cycle de vie du service local, et ce qui arrive quand il tourne mal.
 *
 * `BACKEND_STATE` répond à « qu'a dit /health ». Ces tests portent sur l'autre
 * question, celle que l'interface posait sans pouvoir y répondre : « où en est
 * le processus ». Un service jamais démarré, un service en train de démarrer, un
 * service mort en cours de route et un service qui répond mais reste inutilisable
 * sont quatre situations distinctes, avec quatre suites différentes.
 *
 * Ils couvrent aussi la règle de propriété : fermer une fenêtre ne doit jamais
 * couper l'historique d'une autre.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const {
  BackendManager, BACKEND_LIFECYCLE, lifecycleFromState, RESOLVED_MODE
} = require('../src/backend-manager');
const { BACKEND_STATE, describeBackend } = require('../src/backend-config');
const { readClients, registerClient, unregisterClient } = require('../backend/discovery');

const online = (url) => describeBackend({ state: BACKEND_STATE.ONLINE, url, service: 'security-center-backend' });
const offline = (url) => describeBackend({ state: BACKEND_STATE.OFFLINE, url });

function temporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sc-lifecycle-'));
}

/** Un processus fils observable : il peut mourir, et on voit ce qu'on lui envoie. */
function fakeChild(pid = 4242) {
  const child = new EventEmitter();
  child.pid = pid;
  child.unref = () => {};
  return child;
}

function createManager(overrides = {}) {
  const spawned = [];
  const children = [];
  const manager = new BackendManager({
    dataDir: overrides.dataDir === undefined ? temporaryDirectory() : overrides.dataDir,
    getConfiguration: () => ({ get: (key, fallback) => (overrides.settings || {})[key] ?? fallback }),
    readLock: overrides.readLock || (() => null),
    removeLock: overrides.removeLock || (() => {}),
    portFree: async () => true,
    freePort: async () => 51000,
    probe: overrides.probe || (async (url) => offline(url)),
    publishDiscovery: () => {},
    joinClients: overrides.joinClients || (() => []),
    leaveClients: overrides.leaveClients || (() => []),
    spawnProcess: overrides.spawnProcess || ((command, args, options) => {
      spawned.push({ command, args, options });
      const child = fakeChild();
      children.push(child);
      return child;
    }),
    startTimeoutMs: overrides.startTimeoutMs === undefined ? 300 : overrides.startTimeoutMs,
    log: () => {}
  });
  return { manager, spawned, children };
}

// ------------------------------------------------------- vocabulaire

test('un état sondé se traduit en une position du cycle de vie', () => {
  assert.equal(lifecycleFromState(BACKEND_STATE.ONLINE), BACKEND_LIFECYCLE.READY);
  assert.equal(lifecycleFromState(BACKEND_STATE.STARTING), BACKEND_LIFECYCLE.STARTING);
  assert.equal(lifecycleFromState(BACKEND_STATE.ERROR), BACKEND_LIFECYCLE.FAILED);
  assert.equal(lifecycleFromState(BACKEND_STATE.OFFLINE), BACKEND_LIFECYCLE.STOPPED);
  assert.equal(lifecycleFromState(BACKEND_STATE.NOT_CONFIGURED), BACKEND_LIFECYCLE.STOPPED);
  // Quelque chose répond, mais pas de façon exploitable : ce n'est pas « arrêté ».
  for (const state of [BACKEND_STATE.INVALID_RESPONSE, BACKEND_STATE.AUTH_ERROR, BACKEND_STATE.TIMEOUT]) {
    assert.equal(lifecycleFromState(state), BACKEND_LIFECYCLE.DEGRADED, state);
  }
});

test('un gestionnaire neuf est arrêté, pas « inconnu »', () => {
  const { manager } = createManager();
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.STOPPED);
});

// --------------------------------------------------- STOPPED → READY

test('démarrage réussi : STOPPED puis STARTING puis READY, dans cet ordre', async () => {
  const seen = [];
  let probes = 0;
  const { manager } = createManager({ probe: async (url) => (probes++ < 2 ? offline(url) : online(url)) });
  manager.onLifecycleChange = (next) => seen.push(next);

  const status = await manager.ensureBackend();
  assert.equal(status.online, true);
  assert.deepEqual(seen, [BACKEND_LIFECYCLE.STARTING, BACKEND_LIFECYCLE.READY]);
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.READY);
});

test('démarrage qui n’aboutit pas : le cycle de vie sort de STARTING', async () => {
  const { manager } = createManager({ probe: async (url) => offline(url), startTimeoutMs: 250 });
  await manager.ensureBackend();
  // Sans cette sortie, l'interface resterait bloquée sur « démarrage en cours ».
  assert.notEqual(manager.getLifecycle(), BACKEND_LIFECYCLE.STARTING);
  assert.ok([BACKEND_LIFECYCLE.FAILED, BACKEND_LIFECYCLE.DEGRADED].includes(manager.getLifecycle()));
});

test('spawn impossible : FAILED, et rien ne prétend démarrer', async () => {
  const { manager } = createManager({ spawnProcess: () => { throw new Error('EACCES'); } });
  await manager.ensureBackend();
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.FAILED);
  assert.equal(manager.ownsProcess, false);
});

// ------------------------------------------------------------ crash

test('le processus meurt tout seul : constaté, pas ignoré', async () => {
  let probes = 0;
  const { manager, children } = createManager({ probe: async (url) => (probes++ < 2 ? offline(url) : online(url)) });
  await manager.ensureBackend();
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.READY);
  assert.equal(manager.ownsProcess, true);

  // Le service tombe sans qu'on le lui ait demandé.
  children[0].emit('exit', 1, null);

  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.STOPPED);
  assert.equal(manager.ownsProcess, false, 'un processus mort ne nous appartient plus');
  assert.equal(manager.child, null);
});

test('après un crash, une nouvelle demande redémarre le service', async () => {
  let probes = 0;
  const { manager, spawned, children } = createManager({
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url))
  });
  await manager.ensureBackend();
  children[0].emit('exit', 1, null);
  assert.equal(spawned.length, 1);

  // Le service ne répond plus : la demande suivante en relance un.
  probes = 0;
  await manager.ensureBackend();
  assert.equal(spawned.length, 2, 'un crash doit être récupérable sans intervention');
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.READY);
});

// -------------------------------------------------- arrêt et propriété

test('arrêt explicite : STOPPING puis STOPPED', async () => {
  const seen = [];
  const dataDir = temporaryDirectory();
  let probes = 0;
  const { manager } = createManager({
    dataDir,
    readLock: () => ({ pid: process.pid, port: 8765, url: 'http://127.0.0.1:8765' }),
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url))
  });
  await manager.ensureBackend();
  manager.onLifecycleChange = (next) => seen.push(next);

  const originalKill = process.kill;
  process.kill = () => {};
  try { assert.equal(await manager.stopLocalBackend(), true); }
  finally { process.kill = originalKill; }

  assert.deepEqual(seen, [BACKEND_LIFECYCLE.STOPPING, BACKEND_LIFECYCLE.STOPPED]);
});

test('la dernière fenêtre qui part emporte le service qu’elle a démarré', async () => {
  let probes = 0;
  const killed = [];
  const { manager } = createManager({
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url)),
    leaveClients: () => []          // plus aucune autre fenêtre
  });
  await manager.ensureBackend();

  const originalKill = process.kill;
  process.kill = (pid, signal) => killed.push({ pid, signal });
  try { assert.equal(manager.dispose(), true); }
  finally { process.kill = originalKill; }

  assert.deepEqual(killed, [{ pid: 4242, signal: 'SIGTERM' }]);
  assert.equal(manager.getLifecycle(), BACKEND_LIFECYCLE.STOPPED);
});

test('une fenêtre qui part alors qu’une autre travaille ne coupe rien', async () => {
  let probes = 0;
  const killed = [];
  const { manager } = createManager({
    probe: async (url) => (probes++ < 2 ? offline(url) : online(url)),
    leaveClients: () => [9999]      // une autre fenêtre reste enregistrée
  });
  await manager.ensureBackend();

  const originalKill = process.kill;
  process.kill = (pid, signal) => killed.push({ pid, signal });
  try { assert.equal(manager.dispose(), false); }
  finally { process.kill = originalKill; }

  assert.deepEqual(killed, [], 'couper ici retirerait son historique à la fenêtre restée ouverte');
});

test('un service trouvé déjà démarré ne nous appartient pas et survit à notre départ', async () => {
  const killed = [];
  const { manager, spawned } = createManager({ probe: async (url) => online(url) });
  await manager.ensureBackend();
  assert.equal(spawned.length, 0, 'un service qui répond déjà ne doit pas être doublé');
  assert.equal(manager.ownsProcess, false);

  const originalKill = process.kill;
  process.kill = (pid, signal) => killed.push({ pid, signal });
  try { assert.equal(manager.dispose(), false); }
  finally { process.kill = originalKill; }
  assert.deepEqual(killed, []);
});

// ------------------------------------------------- registre de fenêtres

test('le registre distingue « il reste quelqu’un » de « plus personne »', () => {
  const dataDir = temporaryDirectory();
  const alive = { isAlive: () => true };
  registerClient(dataDir, 111, alive);
  registerClient(dataDir, 222, alive);
  assert.deepEqual(readClients(dataDir, () => true), [111, 222]);
  assert.deepEqual(unregisterClient(dataDir, 111, alive), [222]);
  assert.deepEqual(unregisterClient(dataDir, 222, alive), []);
  // Une fenêtre qui a planté ne doit pas bloquer l'arrêt pour toujours.
  registerClient(dataDir, 333, alive);
  assert.deepEqual(readClients(dataDir, () => false), []);
});

// --------------------------------------------------------- journal

test('le journal du service vit avec les données, jamais dans le dossier d’extension', async () => {
  let probes = 0;
  const dataDir = temporaryDirectory();
  const { manager, spawned } = createManager({
    dataDir, probe: async (url) => (probes++ < 2 ? offline(url) : online(url))
  });
  assert.equal(manager.logFilePath(), path.join(dataDir, 'backend.log'));
  await manager.ensureBackend();

  // La sortie part vers un descripteur de fichier, pas vers des tubes : un
  // processus détaché survit à la fenêtre qui l'a lancé.
  const [{ options }] = spawned;
  assert.equal(options.stdio[0], 'ignore');
  assert.notEqual(options.stdio[1], 'pipe', 'des tubes fermés tueraient le service détaché');
  assert.ok(fs.existsSync(manager.logFilePath()));
});

test('sans emplacement de données, il n’y a pas de journal à proposer', () => {
  const { manager } = createManager({ dataDir: '' });
  assert.equal(manager.logFilePath(), '');
  assert.equal(manager.readLogTail(), '');
});

// ------------------------------------------------- indépendance Docker

test('le service local ne passe ni par Docker ni par Python', async () => {
  let probes = 0;
  const { manager, spawned } = createManager({ probe: async (url) => (probes++ < 2 ? offline(url) : online(url)) });
  await manager.ensureBackend();
  const [{ command, args, options }] = spawned;

  const commandLine = `${command} ${args.join(' ')}`.toLowerCase();
  for (const forbidden of ['docker', 'compose', 'python', 'uvicorn', 'pip', 'fastapi']) {
    assert.ok(!commandLine.includes(forbidden), `le démarrage ne doit pas invoquer ${forbidden}`);
  }
  // Le binaire de l'éditeur, exécuté en Node : c'est tout le prérequis.
  assert.equal(options.env.ELECTRON_RUN_AS_NODE, '1');
  assert.match(args[0], /backend[\\/]server\.js$/);
});

test('le service embarqué est livré avec l’extension', () => {
  const backendDir = path.join(__dirname, '..', 'backend');
  for (const file of ['server.js', 'service.js', 'store.js', 'contract.js', 'discovery.js']) {
    assert.ok(fs.existsSync(path.join(backendDir, file)), `${file} doit être livré dans le paquet`);
  }
  // Aucun reliquat Python dans ce qui est distribué.
  const shipped = fs.readdirSync(backendDir);
  assert.ok(!shipped.some((name) => /\.py$|requirements|Dockerfile/i.test(name)));
});

// ----------------------------------------------------- mode distant

test('en mode Remote, rien n’est démarré et rien n’est arrêté', async () => {
  const killed = [];
  const { manager, spawned } = createManager({
    settings: { 'backend.mode': 'remote', 'backend.url': 'https://secenter.interne' },
    probe: async (url) => online(url)
  });
  const status = await manager.ensureBackend();
  assert.equal(status.resolvedMode, RESOLVED_MODE.REMOTE);
  assert.equal(spawned.length, 0);

  const originalKill = process.kill;
  process.kill = (pid, signal) => killed.push({ pid, signal });
  try { manager.dispose(); } finally { process.kill = originalKill; }
  assert.deepEqual(killed, [], 'un backend d’organisation n’est pas le nôtre à arrêter');
});
