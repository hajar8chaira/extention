'use strict';

/**
 * The embedded backend, exercised over real HTTP.
 *
 * These tests start the service the extension ships and talk to it the way the
 * extension does. They exist because the contract they check is the one the
 * previous FastAPI backend published: the client was not adapted to this
 * implementation, so anything that drifts here breaks history, trends, the
 * audit journal or Burp ingestion — silently.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { start } = require('../backend/server');
const { FileStore } = require('../backend/store');
const { redactAuditMetadata, validateHttpScenario, validateStatusUpdate, clampLimit } = require('../backend/contract');
const { readLockFile } = require('../backend/discovery');

function temporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sc-service-'));
}

/** Starts a backend on a kernel-chosen port and returns a client bound to it. */
async function startService({ apiKey = '' } = {}) {
  const dataDir = temporaryDirectory();
  const running = await start({ port: 0, dataDir, apiKey, idleTimeoutSeconds: 0, version: '9.9.9' });
  const call = async (method, route, body, headers = {}) => {
    const response = await fetch(`${running.url}${route}`, {
      method,
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(apiKey ? { 'x-security-center-key': apiKey } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
    return { status: response.status, body: payload, text, headers: response.headers };
  };
  return {
    url: running.url,
    dataDir,
    call,
    stop: () => new Promise((resolve) => running.server.close(resolve))
  };
}

const SCAN = {
  workspace: 'C:/projets/demo',
  findings: [{
    id: 'f1', tool: 'Semgrep', ruleId: 'rule.a', title: 'XSS réfléchi', severity: 'error',
    rawSeverity: 'HIGH', category: 'web', file: 'src/a.js', startLine: 4, startColumn: 0, endLine: 4, endColumn: 12
  }],
  scanners: [{ tool: 'Semgrep', status: 'completed', durationMs: 120 }],
  correlations: []
};

// ------------------------------------------------------------- /health

test('/health nomme le service, sa version et le port réellement écouté', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  const { status, body } = await service.call('GET', '/health');
  assert.equal(status, 200);
  assert.equal(body.service, 'security-center-backend');
  assert.equal(body.status, 'ok');
  assert.equal(body.version, '9.9.9');
  // Un port choisi par le noyau doit être rapporté, sinon aucun client ne le connaît.
  assert.equal(`http://127.0.0.1:${body.port}`, service.url);
});

test('le service n’écoute que sur la boucle locale', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  assert.match(service.url, /^http:\/\/127\.0\.0\.1:/);
});

test('le verrou publie l’adresse réelle, pour la fenêtre suivante', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  const lock = readLockFile(service.dataDir, { isAlive: () => true });
  assert.equal(lock.url, service.url);
  assert.equal(lock.pid, process.pid);
});

// --------------------------------------------------------------- scans

test('un scan enregistré est relu, listé et exporté', async (t) => {
  const service = await startService();
  t.after(() => service.stop());

  const saved = await service.call('POST', '/api/v1/scans/results', SCAN);
  assert.equal(saved.status, 201);
  assert.equal(saved.body.scan_id, 1);
  assert.equal(saved.body.result.workspace, SCAN.workspace);

  const list = await service.call('GET', '/api/v1/scans?limit=10');
  assert.equal(list.body.length, 1);
  assert.deepEqual(
    { scan_id: list.body[0].scan_id, finding_count: list.body[0].finding_count, scanner_count: list.body[0].scanner_count },
    { scan_id: 1, finding_count: 1, scanner_count: 1 }
  );

  const stored = await service.call('GET', '/api/v1/scans/1');
  assert.equal(stored.body.result.findings[0].ruleId, 'rule.a');

  const missing = await service.call('GET', '/api/v1/scans/404');
  assert.equal(missing.status, 404);

  const html = await service.call('GET', '/api/v1/scans/1/export.html');
  assert.match(html.text, /XSS réfléchi/);
  assert.match(html.headers.get('content-disposition') || '', /security-center-scan-1\.html/);
});

test('un changement de statut écrit une entrée d’audit, et une clôture exige une justification', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  await service.call('POST', '/api/v1/scans/results', SCAN);

  const refused = await service.call('PATCH', '/api/v1/scans/1/findings/f1/status', { status: 'false_positive', actor: 'moi' });
  assert.equal(refused.status, 422);
  assert.match(refused.body.detail, /justification/i);

  const accepted = await service.call('PATCH', '/api/v1/scans/1/findings/f1/status', {
    status: 'false_positive', actor: 'moi', comment: 'Route non exposée'
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.result.findings[0].triageStatus, 'false_positive');

  const events = await service.call('GET', '/api/v1/audit-events');
  assert.equal(events.body[0].action, 'status:false_positive');
  assert.equal(events.body[0].finding_id, 'f1');

  const unknown = await service.call('PATCH', '/api/v1/scans/1/findings/inconnu/status', { status: 'triaged' });
  assert.equal(unknown.status, 404);
});

test('le tableau de bord agrège le dernier scan, et répond même sans historique', async (t) => {
  const service = await startService();
  t.after(() => service.stop());

  const empty = await service.call('GET', '/api/v1/dashboard');
  assert.equal(empty.body.total, 0);
  assert.equal(empty.body.scan_id, null);

  await service.call('POST', '/api/v1/scans/results', SCAN);
  const summary = await service.call('GET', '/api/v1/dashboard');
  assert.equal(summary.body.total, 1);
  assert.deepEqual(summary.body.by_tool, { Semgrep: 1 });
  assert.deepEqual(summary.body.by_severity, { HIGH: 1 });
});

// ---------------------------------------------------------- journal

test('un secret n’entre pas dans le journal d’audit', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  const created = await service.call('POST', '/api/v1/audit-events', {
    action: 'integration.configured',
    actor: 'Security Center',
    metadata: { host: 'localhost', token: 'valeur-secrète', nested: { 'API-Key': 'autre-secret' } }
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.metadata.token, '[REDACTED]');
  assert.equal(created.body.metadata.nested['API-Key'], '[REDACTED]');
  assert.equal(created.body.metadata.host, 'localhost');
  // Et rien de secret n’a atteint le disque.
  const journal = fs.readFileSync(path.join(service.dataDir, 'audit-events.jsonl'), 'utf8');
  assert.doesNotMatch(journal, /valeur-secrète|autre-secret/);
});

test('une autorisation sans motif est refusée', async (t) => {
  const service = await startService();
  t.after(() => service.stop());
  const refused = await service.call('POST', '/api/v1/audit-events', { action: 'scan:authorized', actor: 'moi' });
  assert.equal(refused.status, 422);
});

// -------------------------------------------------------- scénarios HTTP

test('une cible non locale est refusée, une capture Burp est stockée une seule fois', async (t) => {
  const service = await startService();
  t.after(() => service.stop());

  const remote = await service.call('POST', '/api/v1/http-scenarios', {
    name: 'externe', source: 'manual', request: { method: 'GET', url: 'https://example.com/' }
  });
  assert.equal(remote.status, 422);

  const scenario = {
    name: 'login', source: 'manual',
    request: { method: 'POST', url: 'http://127.0.0.1:3000/login', body: 'a=1' },
    response: { statusCode: 200, bodySha256: 'abc' }
  };
  const first = await service.call('POST', '/api/v1/integrations/burp/requests', scenario);
  const second = await service.call('POST', '/api/v1/integrations/burp/requests', scenario);
  assert.equal(first.body.source, 'burp');
  // Le même échange capturé deux fois reste un seul scénario.
  assert.equal(second.body.scenario_id, first.body.scenario_id);

  const listed = await service.call('GET', '/api/v1/http-scenarios');
  assert.equal(listed.body.length, 1);

  const status = await service.call('GET', '/api/v1/integrations/burp/status');
  assert.equal(status.body.connected, false);
  assert.equal(status.body.received_requests, 1);

  await service.call('POST', '/api/v1/integrations/burp/heartbeat');
  const afterHeartbeat = await service.call('GET', '/api/v1/integrations/burp/status');
  assert.equal(afterHeartbeat.body.connected, true);
});

// -------------------------------------------------------------- clé d’API

test('la clé d’API protège les routes de données, jamais le sondage /health', async (t) => {
  const service = await startService({ apiKey: 'clé-de-test' });
  t.after(() => service.stop());

  const probe = await fetch(`${service.url}/health`);
  assert.equal(probe.status, 200);

  const denied = await fetch(`${service.url}/api/v1/scans`);
  assert.equal(denied.status, 401);

  const wrongKey = await fetch(`${service.url}/api/v1/scans`, { headers: { 'x-security-center-key': 'mauvaise' } });
  assert.equal(wrongKey.status, 401);

  const allowed = await service.call('GET', '/api/v1/scans');
  assert.equal(allowed.status, 200);
});

// ------------------------------------------------------------ persistance

test('l’historique survit à un redémarrage du service', async (t) => {
  const dataDir = temporaryDirectory();
  const first = await start({ port: 0, dataDir, idleTimeoutSeconds: 0 });
  await fetch(`${first.url}/api/v1/scans/results`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(SCAN)
  });
  await new Promise((resolve) => first.server.close(resolve));

  const second = await start({ port: 0, dataDir, idleTimeoutSeconds: 0 });
  t.after(() => new Promise((resolve) => second.server.close(resolve)));
  const scans = await (await fetch(`${second.url}/api/v1/scans`)).json();
  assert.equal(scans.length, 1);
  // Et le prochain identifiant continue la série au lieu de réécrire le scan 1.
  const saved = await (await fetch(`${second.url}/api/v1/scans/results`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(SCAN)
  })).json();
  assert.equal(saved.scan_id, 2);
});

test('une ligne corrompue ne détruit pas le journal', () => {
  const dataDir = temporaryDirectory();
  const store = new FileStore(dataDir).initialize();
  store.createAuditEvent({ action: 'a', actor: 'moi' });
  fs.appendFileSync(path.join(dataDir, 'audit-events.jsonl'), '{ceci n\'est pas du JSON\n');
  store.createAuditEvent({ action: 'b', actor: 'moi' });
  const events = store.listAuditEvents(10);
  assert.deepEqual(events.map((event) => event.action), ['b', 'a']);
});

// --------------------------------------------------------- validation pure

test('les limites de requête sont bornées, jamais reprises telles quelles', () => {
  assert.equal(clampLimit('10', 50, 200), 10);
  assert.equal(clampLimit('100000', 50, 200), 200);
  assert.equal(clampLimit('0', 50, 200), 1);
  assert.equal(clampLimit(undefined, 50, 200), 50);
});

test('le vocabulaire de triage est fermé', () => {
  assert.throws(() => validateStatusUpdate({ status: 'peut-être' }), /status must be one of/);
  assert.equal(validateStatusUpdate({ status: 'triaged' }).actor, 'local-user');
});

test('seules les cibles locales sont acceptées pour un scénario', () => {
  assert.throws(() => validateHttpScenario({
    name: 'x', source: 'har', request: { method: 'GET', url: 'http://192.168.1.10/' }
  }), /local/i);
  const local = validateHttpScenario({
    name: 'x', source: 'har', request: { method: 'GET', url: 'http://localhost:3000/' }
  });
  assert.equal(local.request.url, 'http://localhost:3000/');
});

test('la rédaction des métadonnées descend dans les listes et les objets', () => {
  const redacted = redactAuditMetadata({
    items: [{ password: 'x' }, { safe: 'ok' }], Authorization: 'Bearer t', deep: { api_key: 'k' }
  });
  assert.equal(redacted.items[0].password, '[REDACTED]');
  assert.equal(redacted.items[1].safe, 'ok');
  assert.equal(redacted.Authorization, '[REDACTED]');
  assert.equal(redacted.deep.api_key, '[REDACTED]');
});

// --------------------------------------------------- bout en bout, réel

test('le gestionnaire démarre réellement le service, puis l’arrête', async (t) => {
  const { BackendManager, findFreePort } = require('../src/backend-manager');
  const { setApiKey } = require('../src/backend');
  setApiKey('');
  const dataDir = temporaryDirectory();
  const port = await findFreePort();
  const { probeBackend } = require('../src/backend-config');
  const manager = new BackendManager({
    dataDir,
    getConfiguration: () => ({ get: (key, fallback) => fallback }),
    // Le vrai binaire Node, le vrai serveur, le vrai /health : ce test verifie
    // le chemin qu'emprunte l'extension, pas une simulation de celui-ci.
    //
    // La seule contrainte posee est l'isolation : la machine qui execute ces
    // tests fait aussi tourner Security Center, donc un backend ecoute pour de
    // bon sur le port par defaut. Le sondage est restreint au port choisi pour
    // que le test decrive « rien ne repond, un service est demarre » plutot que
    // l'etat de la session VS Code de la personne qui lance la suite.
    probe: async (url) => (url === `http://127.0.0.1:${port}`
      ? probeBackend(url)
      : { state: 'offline', online: false, url, label: 'Hors ligne', hint: '', message: 'hors perimetre du test' }),
    freePort: async () => port,
    portFree: async (candidate) => candidate === port,
    startTimeoutMs: 15000
  });
  t.after(async () => { await manager.stopLocalBackend(); });

  const status = await manager.startLocalBackend();
  assert.equal(status.state, 'online', status.message || '');
  assert.equal(status.url, `http://127.0.0.1:${port}`);

  // Le verrou publie l’adresse : une autre fenêtre la résout sans rien démarrer.
  assert.equal(manager.resolveBackendUrl(), status.url);
  const health = await (await fetch(`${status.url}/health`)).json();
  assert.equal(health.service, 'security-center-backend');

  assert.equal(await manager.stopLocalBackend(), true);
});
