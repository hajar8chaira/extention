'use strict';

/**
 * Burp lisait l'adresse http://127.0.0.1:8765 et la cible autorisée, mais
 * recevait « Clé API refusée ». Un backend Security Center orphelin, lancé avec
 * une autre clé, tenait le port : il répondait à /health (ouvert), l'extension le
 * croyait sien et publiait SA clé à elle dans le fichier de découverte.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { checkBackendKey } = require('../src/backend');
const { probeBackend, describeBackend, BACKEND_STATE } = require('../src/backend-config');
const { BackendManager } = require('../src/backend-manager');
const { writeDiscoveryFile, readDiscoveryFile, discoveryFilePath } = require('../backend/discovery');
const { createRequestHandler } = require('../backend/service');
const { FileStore } = require('../backend/store');

const healthy = async () => ({ service: 'security-center-backend', status: 'ok', version: '0.9.0' });
const online = (url) => describeBackend({ state: BACKEND_STATE.ONLINE, url, service: 'security-center-backend' });
const refused = (url) => describeBackend({ state: BACKEND_STATE.AUTH_ERROR, url, message: 'Backend HTTP 401' });

test('un /health valide ne suffit plus : une clé refusée donne AUTH_ERROR, jamais ONLINE', async () => {
  const status = await probeBackend('http://127.0.0.1:8765', {
    check: healthy,
    authorize: async () => { throw new Error('Backend HTTP 401: key check'); }
  });
  assert.equal(status.state, BACKEND_STATE.AUTH_ERROR);
  assert.equal(status.online, false);
  // Sans clé à vérifier, le comportement historique est inchangé.
  assert.equal((await probeBackend('http://127.0.0.1:8765', { check: healthy })).online, true);
});

test('checkBackendKey interroge une route authentifiée avec la clé exacte', async (t) => {
  const store = new FileStore(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-key-'))).initialize();
  const server = http.createServer(createRequestHandler({ store, apiKey: 'la-bonne-clé' }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await checkBackendKey(url, 'la-bonne-clé'), true);
  await assert.rejects(checkBackendKey(url, 'une-autre-clé'), /HTTP 401/);
  // Le vrai sondage : /health répond, la clé est refusée.
  const status = await probeBackend(url, { authorize: (target) => checkBackendKey(target, 'une-autre-clé') });
  assert.equal(status.state, BACKEND_STATE.AUTH_ERROR);
});

function manager({ probe, readLock = () => null, portFree = async () => false }) {
  const published = [];
  const spawned = [];
  const instance = new BackendManager({
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'sc-mgr-')),
    apiKey: 'clé-de-cette-fenêtre',
    getConfiguration: () => ({ get: (_key, fallback) => fallback }),
    probe,
    readLock,
    portFree,
    freePort: async () => 51234,
    joinClients: () => [],
    publishDiscovery: (record) => published.push(record),
    spawnProcess: (command, args) => {
      spawned.push(args);
      const { EventEmitter } = require('node:events');
      const child = new EventEmitter();
      child.pid = 4242; child.unref = () => {};
      return child;
    },
    startTimeoutMs: 500
  });
  return { instance, published, spawned };
}

test('un backend étranger sur le port par défaut : jamais publié, un backend dédié démarre ailleurs', async () => {
  const { instance, published, spawned } = manager({
    probe: async (url) => (url === 'http://127.0.0.1:8765' ? refused(url) : online(url))
  });
  const status = await instance.ensureBackend();
  assert.equal(spawned.length, 1, 'notre propre backend est lancé');
  assert.ok(spawned[0].includes('51234'), 'sur un port libre, pas sur celui de l’orphelin');
  assert.equal(status.online, true);
  assert.equal(status.url, 'http://127.0.0.1:51234');
  assert.ok(published.length >= 1);
  assert.ok(published.every((record) => record.url !== 'http://127.0.0.1:8765'), 'la clé n’est jamais publiée pour le backend qui la refuse');
});

test('notre propre backend refuse la clé : aucun second backend, aucune publication', async () => {
  const { instance, published, spawned } = manager({
    probe: async (url) => refused(url),
    readLock: () => ({ pid: process.pid, port: 8765, url: 'http://127.0.0.1:8765' })
  });
  const status = await instance.ensureBackend();
  assert.equal(status.state, BACKEND_STATE.AUTH_ERROR);
  assert.equal(spawned.length, 0);
  assert.equal(published.length, 0);
});

test('le fichier de découverte est remplacé d’un bloc, sans fichier temporaire laissé', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-home-'));
  writeDiscoveryFile({ url: 'http://127.0.0.1:8765', mode: 'auto', apiKey: 'ancienne', captureOrigins: [] }, { home });
  writeDiscoveryFile({ url: 'http://127.0.0.1:51234', mode: 'auto', apiKey: 'nouvelle', captureOrigins: ['http://192.168.222.132:3000'] }, { home });
  const record = readDiscoveryFile({ home });
  assert.equal(record.url, 'http://127.0.0.1:51234');
  assert.equal(record.api_key, 'nouvelle');
  assert.deepEqual(record.capture_origins, ['http://192.168.222.132:3000']);
  assert.deepEqual(fs.readdirSync(path.dirname(discoveryFilePath(home))).filter((name) => name.endsWith('.tmp')), []);
});
