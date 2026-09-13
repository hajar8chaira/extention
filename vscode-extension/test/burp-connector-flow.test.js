'use strict';

/**
 * Le flux Burp réel : Burp → connecteur → heartbeat → carte CONNECTÉ → trafic
 * de la cible Juice Shop distante → HTTP Traffic → détails → replay.
 *
 * Deux défauts l'empêchaient. Le connecteur jetait en silence toute requête
 * non locale — la cible autorisée http://192.168.222.132:3000 comprise. Et une
 * panne (backend arrêté, clé refusée, capture rejetée, heartbeat absent) ne
 * laissait sur la carte qu'un « déconnecté » sans raison.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { createRequestHandler } = require('../backend/service');
const { FileStore } = require('../backend/store');
const { writeDiscoveryFile, readDiscoveryFile } = require('../backend/discovery');
const { BackendManager } = require('../src/backend-manager');
const { burpConnectorProblem } = require('../src/burp-connector-state');
const { RUN_ERROR, RUN_KIND, RUN_STATUS, availability, createRun, transitionRun, dynamicRuntimeModel } = require('../src/dynamic-runtime');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const TARGET = 'http://192.168.222.132:3000';
const KEY = 'clé-de-test-burp';
const repo = path.join(__dirname, '..');
const src = (file) => fs.readFileSync(path.join(repo, file), 'utf8');
const connectorSource = () => fs.readFileSync(path.join(repo, '..', 'burp-extension', 'src', 'main', 'java', 'com', 'securitycenter', 'burp', 'SecurityCenterExtension.java'), 'utf8');

async function startBackend() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-burp-'));
  const store = new FileStore(dataDir).initialize();
  const server = http.createServer(createRequestHandler({ store, apiKey: KEY }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, route, { key = KEY, body } = {}) => {
    const response = await fetch(`${url}${route}`, {
      method, headers: { 'content-type': 'application/json', ...(key === null ? {} : { 'x-security-center-key': key }) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: response.status, body: await response.json().catch(() => null) };
  };
  return { url, call, stop: () => new Promise((resolve) => server.close(resolve)) };
}

const juiceShopScenario = {
  name: 'GET /rest/products/search',
  source: 'burp',
  request: { method: 'GET', url: `${TARGET}/rest/products/search?q=apple`, headers: { accept: 'application/json' }, body: '', sensitive_headers: [] },
  response: { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '{"status":"success"}', bodySha256: '' },
  tags: ['burp', 'automatic-capture', 'local']
};

// ------------------------------------------------------------- backend

test('le backend garde la trace d’une clé refusée, d’une capture rejetée et d’une ingestion réussie', async (t) => {
  const backend = await startBackend();
  t.after(() => backend.stop());

  const refused = await backend.call('POST', '/api/v1/integrations/burp/heartbeat', { key: 'mauvaise-clé' });
  assert.equal(refused.status, 401);
  let status = (await backend.call('GET', '/api/v1/integrations/burp/status')).body;
  assert.equal(status.connected, false);
  assert.ok(status.last_auth_rejected_at, 'le refus de clé est enregistré');

  const invalid = await backend.call('POST', '/api/v1/integrations/burp/requests', { body: { ...juiceShopScenario, request: { ...juiceShopScenario.request, url: 'pas-une-url' } } });
  assert.equal(invalid.status, 422);
  status = (await backend.call('GET', '/api/v1/integrations/burp/status')).body;
  assert.equal(status.last_ingestion_error.status, 422);
  assert.match(status.last_ingestion_error.detail, /request\.url is not a valid URL/);

  await backend.call('POST', '/api/v1/integrations/burp/heartbeat');
  const stored = await backend.call('POST', '/api/v1/integrations/burp/requests', { body: juiceShopScenario });
  assert.equal(stored.status, 201);
  status = (await backend.call('GET', '/api/v1/integrations/burp/status')).body;
  assert.equal(status.connected, true);
  assert.equal(status.received_requests, 1);
  assert.ok(Date.parse(status.last_ingested_at) >= Date.parse(status.last_ingestion_error.at));

  // La cible distante autorisée est conservée, marquée comme telle.
  const listed = (await backend.call('GET', '/api/v1/http-scenarios')).body;
  assert.equal(listed[0].source, 'burp');
  assert.equal(listed[0].scope, 'remote');
});

// ------------------------------------------------------- raison de la carte

test('la carte Burp nomme la panne : backend, clé, ingestion, heartbeat', () => {
  const at = (iso) => new Date(iso).toISOString();
  assert.equal(burpConnectorProblem({ backend_error: 'connect ECONNREFUSED 127.0.0.1:8765' }).code, RUN_ERROR.BACKEND_UNAVAILABLE);
  assert.match(burpConnectorProblem({ backend_error: 'connect ECONNREFUSED' }).reason, /Backend Security Center injoignable/);

  const rejected = burpConnectorProblem({ connected: false, last_seen: at('2026-09-13T10:00:00Z'), last_auth_rejected_at: at('2026-09-13T10:05:00Z') });
  assert.equal(rejected.code, RUN_ERROR.AUTH_REJECTED);
  assert.match(rejected.reason, /Clé API refusée/);
  // Un refus plus ancien que le dernier heartbeat réussi ne décrit plus rien.
  assert.equal(burpConnectorProblem({ connected: false, last_seen: at('2026-09-13T10:05:00Z'), last_auth_rejected_at: at('2026-09-13T10:00:00Z') }).code, RUN_ERROR.CONNECTOR_ABSENT);

  const ingestion = burpConnectorProblem({ connected: true, last_ingested_at: at('2026-09-13T10:00:00Z'), last_ingestion_error: { at: at('2026-09-13T10:01:00Z'), status: 400, detail: 'request.url is not a valid URL' } });
  assert.equal(ingestion.code, RUN_ERROR.INGESTION_REJECTED);
  assert.match(ingestion.reason, /request\.url is not a valid URL/);
  assert.equal(burpConnectorProblem({ connected: true, last_ingested_at: at('2026-09-13T10:02:00Z'), last_ingestion_error: { at: at('2026-09-13T10:01:00Z'), status: 500 } }), null);
  assert.equal(burpConnectorProblem({ connected: false, last_ingestion_error: { at: at('2026-09-13T10:01:00Z'), status: 500, detail: 'Internal backend error' } }).code, RUN_ERROR.INGESTION_FAILED);

  assert.match(burpConnectorProblem({ connected: false }).reason, /Aucun battement du connecteur Burp reçu/);
  assert.equal(burpConnectorProblem({ connected: true }), null);
});

test('la carte Burp affiche CONNECTÉ quand le connecteur bat, et la raison sinon', () => {
  const runtime = (run) => dynamicRuntimeModel({ burp: { kind: RUN_KIND.CONNECTOR, availability: availability({ installed: true }), run, lastRun: null } });
  const card = (dynamicRuntime, burpConnected) => (renderDashboardHtml(buildDashboardModel([], [], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET, dynamicRuntime, burpConnected
  }), 'n', 'dynamic').match(/<article class="dynamic-tool-card burp[\s\S]*?<\/article>/) || [''])[0];

  const connected = transitionRun(createRun({ engine: 'burp', kind: RUN_KIND.CONNECTOR }), { status: RUN_STATUS.RUNNING, requestCount: 3 });
  assert.match(card(runtime(connected), true), /<span class="tool-status running">CONNECTÉ<\/span>/);

  const problem = burpConnectorProblem({ backend_error: 'connect ECONNREFUSED 127.0.0.1:8765' });
  const waiting = transitionRun(createRun({ engine: 'burp', kind: RUN_KIND.CONNECTOR }), { status: RUN_STATUS.WAITING_EXTERNAL, errorCode: problem.code, errorReason: problem.reason });
  const html = card(runtime(waiting), false);
  assert.doesNotMatch(html, />CONNECTÉ</);
  assert.match(html, /Backend Security Center injoignable/);
});

// ----------------------------------------------- découverte et périmètre

test('le fichier de découverte publie la cible autorisée comme origine de capture', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-home-'));
  writeDiscoveryFile({ url: 'http://127.0.0.1:8765', mode: 'auto', apiKey: 'k', captureOrigins: [`${TARGET}/#/`, 'pas-une-url', 'ftp://x'] }, { home });
  assert.deepEqual(readDiscoveryFile({ home }).capture_origins, [TARGET]);
});

test('le backend actif est republié quand la cible autorisée change, et seulement alors', () => {
  const published = [];
  let origins = [TARGET];
  const manager = new BackendManager({ dataDir: os.tmpdir(), apiKey: 'k', publishDiscovery: (record) => published.push(record), captureOrigins: () => origins });
  assert.equal(manager.republishDiscovery(), false, 'rien à republier avant une première publication');
  manager.announce({ url: 'http://127.0.0.1:8765', mode: 'auto' });
  assert.deepEqual(published[0].captureOrigins, [TARGET]);
  assert.equal(manager.republishDiscovery(), false, 'cible inchangée : aucune réécriture');
  origins = [];
  assert.equal(manager.republishDiscovery(), true);
  assert.deepEqual(published[1].captureOrigins, []);
  assert.equal(published[1].url, 'http://127.0.0.1:8765');
});

test('le connecteur verse le local et la cible autorisée, relit la découverte et dit ses pannes', () => {
  const java = connectorSource();
  assert.doesNotMatch(java, /Le connecteur MVP accepte uniquement les cibles locales/);
  assert.match(java, /jsonStringArray\(content, "capture_origins"\)/);
  assert.match(java, /captureOrigins\.contains\(originOf\(uri\)\)/);
  assert.match(java, /validateCapturableUrl\(request\.url\(\)\)/);
  assert.match(java, /isCapturableUrl\(requestUrl\)/);
  assert.match(java, /private void sendHeartbeat\(\) \{\s*\/\/[^\n]*\n\s*\/\/[^\n]*\n\s*loadDiscoveredBackend\(false\);/);
  assert.match(java, /response\.statusCode\(\) == 401/);
  assert.match(java, /Backend Security Center injoignable/);
});

test('l’extension relie la raison de la carte au statut réel et publie la cible autorisée', () => {
  const extension = src('src/extension.js');
  assert.match(extension, /const problem = burpConnectorProblem\(status\);/);
  assert.match(extension, /applyBurpConnectorState\(\{ connected: false, backend_error: /);
  assert.match(extension, /captureOrigins: \(\) => \{[\s\S]{0,400}remote && cfg\.get\('zap\.remoteAuthorized', false\) !== true \? \[\] : \[origin\]/);
  assert.match(extension, /backendManager\?\.republishDiscovery\?\.\(\);/);
  // Les règles de replay ne changent pas.
  assert.match(src('src/http-scenarios.js'), /state: authorized\.includes\(origin\) \? REPLAY_STATE\.ALLOWED : REPLAY_STATE\.AUTHORIZATION_REQUIRED/);
});
