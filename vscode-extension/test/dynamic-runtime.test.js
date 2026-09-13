'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  RUN_KIND, RUN_STATUS, RUN_ERROR, createRun, canTransition, transitionRun,
  recordActivity, failRun, completeRun, reconcileRun, restoreRun,
  availability, unknownAvailability, engineState, dynamicRuntimeModel
} = require('../src/dynamic-runtime');
const { createRefreshCoordinator } = require('../src/dynamic-refresh');
const { FileStore } = require('../backend/store');
const { sessionSummary } = require('../src/traffic-analytics');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const clock = (iso) => () => new Date(iso).getTime();

// --------------------------------------------------------- le contrat commun

test('une analyse et une capture partagent le même contrat ; un connecteur naît en attente', () => {
  const scan = createRun({ engine: 'nuclei', kind: RUN_KIND.SCAN, target: 'http://192.168.222.132:3000' });
  for (const field of ['id', 'engine', 'kind', 'target', 'status', 'phase', 'progress',
    'startedAt', 'finishedAt', 'lastActivity', 'requestCount', 'findingCount', 'errorCode', 'errorReason']) {
    assert.ok(field in scan, `le contrat doit porter ${field}`);
  }
  assert.equal(scan.status, RUN_STATUS.STARTING);
  // Rien n'est inventé : ni progression, ni compteur, ni activité.
  assert.equal(scan.progress, null);
  assert.equal(scan.requestCount, null);
  assert.equal(scan.findingCount, null);
  assert.equal(scan.lastActivity, null);

  const capture = createRun({ engine: 'mitmproxy', kind: RUN_KIND.CAPTURE });
  assert.equal(capture.kind, RUN_KIND.CAPTURE);
  assert.equal(capture.status, RUN_STATUS.STARTING);

  // Personne ne démarre Burp : Security Center l'attend, et le dit.
  const connector = createRun({ engine: 'burp', kind: RUN_KIND.CONNECTOR });
  assert.equal(connector.status, RUN_STATUS.WAITING_EXTERNAL);

  assert.throws(() => createRun({ engine: 'zap', kind: 'quelque-chose' }), /Nature d'exécution inconnue/);
});

// ----------------------------------------------------------- les transitions

test('READY → STARTING → RUNNING → COMPLETED, et rien ne rouvre une exécution close', () => {
  assert.ok(canTransition(RUN_STATUS.READY, RUN_STATUS.STARTING));
  assert.ok(canTransition(RUN_STATUS.STARTING, RUN_STATUS.RUNNING));
  assert.ok(canTransition(RUN_STATUS.RUNNING, RUN_STATUS.COMPLETED));

  let run = createRun({ engine: 'zap', kind: RUN_KIND.SCAN, now: clock('2026-09-10T10:00:00Z') });
  run = transitionRun(run, { status: RUN_STATUS.RUNNING, phase: 'Spidering', progress: 40, now: clock('2026-09-10T10:00:05Z') });
  assert.equal(run.status, RUN_STATUS.RUNNING);
  assert.equal(run.progress, 40);
  assert.equal(run.lastActivity, '2026-09-10T10:00:05.000Z');

  run = completeRun(run, { findingCount: 207, now: clock('2026-09-10T10:00:40Z') });
  assert.equal(run.status, RUN_STATUS.COMPLETED);
  assert.equal(run.findingCount, 207);
  assert.equal(run.finishedAt, '2026-09-10T10:00:40.000Z');

  // Une exécution terminée qui se remettrait à courir est un bug, pas un état.
  assert.throws(() => transitionRun(run, { status: RUN_STATUS.RUNNING }), /Transition interdite/);
  assert.equal(completeRun(run, { findingCount: 999 }), run, 'une exécution close ne se reclôt pas');
});

test('READY → STARTING → FAILED porte toujours un code et une raison lisible', () => {
  const run = failRun(createRun({ engine: 'mitmproxy', kind: RUN_KIND.CAPTURE }), {
    errorCode: RUN_ERROR.BACKEND_UNAVAILABLE,
    errorReason: 'Le service local Security Center ne répond pas.'
  });
  assert.equal(run.status, RUN_STATUS.FAILED);
  assert.equal(run.errorCode, RUN_ERROR.BACKEND_UNAVAILABLE);
  assert.match(run.errorReason, /ne répond pas/);
  assert.ok(run.finishedAt, 'un échec est une fin');
});

test('RUNNING → STOPPING → COMPLETED est le chemin d’un arrêt demandé', () => {
  let run = transitionRun(createRun({ engine: 'mitmproxy', kind: RUN_KIND.CAPTURE }), { status: RUN_STATUS.RUNNING });
  run = transitionRun(run, { status: RUN_STATUS.STOPPING, phase: 'Arrêt du proxy' });
  assert.equal(run.status, RUN_STATUS.STOPPING);
  run = completeRun(run);
  assert.equal(run.status, RUN_STATUS.COMPLETED);
  // Un arrêt ne repart pas en course.
  assert.throws(() => transitionRun(run, { status: RUN_STATUS.RUNNING }), /Transition interdite/);
});

test('WAITING_EXTERNAL → RUNNING : c’est le trafic reçu qui promeut, pas un démarrage', () => {
  const waiting = createRun({ engine: 'burp', kind: RUN_KIND.CONNECTOR });
  assert.equal(waiting.status, RUN_STATUS.WAITING_EXTERNAL);
  // Un sondage qui ne rapporte rien de neuf n'est pas de l'activité.
  assert.equal(recordActivity(waiting, {}), waiting);
  const active = recordActivity(waiting, { requestCount: 3 });
  assert.equal(active.status, RUN_STATUS.RUNNING);
  assert.equal(active.requestCount, 3);
});

test('une progression absente reste absente : zéro n’est pas « inconnu »', () => {
  const run = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN }), { status: RUN_STATUS.RUNNING });
  assert.equal(run.progress, null);
  assert.equal(transitionRun(run, { progress: '' }).progress, null);
  assert.equal(transitionRun(run, { progress: 0 }).progress, 0);
  assert.equal(transitionRun(run, { progress: 240 }).progress, 100);
});

// ----------------------------- disponibilité et exécution sont deux questions

test('un outil installé et jamais lancé est PRÊT, jamais INDISPONIBLE', () => {
  const nuclei = engineState('nuclei', {
    kind: RUN_KIND.SCAN,
    availability: availability({ installed: true, version: '3.11.1', managed: true }),
    run: null
  });
  assert.equal(nuclei.status, RUN_STATUS.READY);
  assert.equal(nuclei.execution.neverExecuted, true);
  assert.equal(nuclei.availability.version, '3.11.1');
  assert.equal(nuclei.reason, '', 'un outil disponible n’a pas de raison à donner');
});

test('un outil réellement absent est INDISPONIBLE, avec la raison mesurée', () => {
  const zap = engineState('zap', {
    kind: RUN_KIND.SCAN,
    availability: availability({
      installed: false,
      prerequisites: [
        { name: 'ZAP local', satisfied: false, detail: 'Java introuvable' },
        { name: 'Moteur Docker', satisfied: false, detail: 'Moteur Docker indisponible' }
      ],
      reason: 'Ni ZAP local (avec Java) ni le moteur Docker ne sont disponibles.'
    })
  });
  assert.equal(zap.status, RUN_STATUS.UNAVAILABLE);
  assert.match(zap.reason, /Docker/);
  assert.equal(zap.availability.prerequisites.length, 2);

  // Un prérequis satisfait suffit : Docker seul rend ZAP utilisable.
  const viaDocker = availability({
    installed: true,
    prerequisites: [{ name: 'Moteur Docker', satisfied: true, detail: 'Docker 27.0' }]
  });
  assert.equal(viaDocker.usable, true);
  assert.equal(engineState('zap', { availability: viaDocker }).status, RUN_STATUS.READY);
});

test('un résultat passé est de l’histoire : il ne décide plus de l’état courant', () => {
  const finished = completeRun(
    transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: 'http://192.168.222.132:3000' }), { status: RUN_STATUS.RUNNING }),
    { findingCount: 207 }
  );
  const state = engineState('zap', {
    kind: RUN_KIND.SCAN,
    availability: availability({ installed: true, version: 'docker 27.0' }),
    run: finished
  });
  assert.equal(state.status, RUN_STATUS.READY, 'disponible et rien en cours : prêt');
  assert.equal(state.execution.neverExecuted, false);
  assert.equal(state.execution.lastRun.status, RUN_STATUS.COMPLETED);
  assert.equal(state.execution.lastRun.findingCount, 207);
});

test('une disponibilité non mesurée se déclare comme telle, sans prétendre à l’absence', () => {
  const unknown = unknownAvailability();
  assert.equal(unknown.installed, false);
  assert.equal(unknown.checked, false);
  assert.match(unknown.reason, /non encore vérifiée/);
});

// ---------------------------------------------- rechargement et réconciliation

test('une capture « en cours » restaurée sans processus vivant devient un échec nommé', () => {
  const running = transitionRun(createRun({ engine: 'mitmproxy', kind: RUN_KIND.CAPTURE }), { status: RUN_STATUS.RUNNING });
  const restored = restoreRun(JSON.parse(JSON.stringify(running)));
  assert.equal(restored.status, RUN_STATUS.RUNNING);
  assert.equal(restored.restored, true);

  const reconciled = reconcileRun(restored, { alive: false });
  assert.equal(reconciled.status, RUN_STATUS.FAILED);
  assert.equal(reconciled.errorCode, RUN_ERROR.STALE_PROCESS);
  assert.match(reconciled.errorReason, /n’existe plus/);

  // Un processus réellement vivant n'est pas déclaré mort.
  assert.equal(reconcileRun(restored, { alive: true }).status, RUN_STATUS.RUNNING);
});

test('un connecteur restauré « connecté » redevient une attente, pas une panne', () => {
  const connected = recordActivity(createRun({ engine: 'burp', kind: RUN_KIND.CONNECTOR }), { requestCount: 12 });
  const reconciled = reconcileRun(restoreRun(JSON.parse(JSON.stringify(connected))), { alive: false });
  assert.equal(reconciled.status, RUN_STATUS.WAITING_EXTERNAL);
  assert.equal(reconciled.errorCode, RUN_ERROR.CONNECTOR_ABSENT);
});

test('une exécution terminée survit au rechargement telle quelle', () => {
  const done = completeRun(transitionRun(createRun({ engine: 'nuclei', kind: RUN_KIND.SCAN }), { status: RUN_STATUS.RUNNING }), { findingCount: 12 });
  const restored = restoreRun(JSON.parse(JSON.stringify(done)));
  assert.equal(reconcileRun(restored, { alive: false }), restored, 'un résultat acquis ne se réconcilie pas');
  assert.equal(restored.findingCount, 12);
});

test('un cache illisible ne devient jamais une exécution à moitié construite', () => {
  for (const bad of [null, {}, { id: 'x' }, { id: 'x', engine: 'zap', kind: 'autre', status: 'RUNNING' },
    { id: 'x', engine: 'zap', kind: 'scan', status: 'PAS-UN-ÉTAT' }]) {
    assert.equal(restoreRun(bad), null);
  }
});

test('l’instantané publié porte un état par moteur, sous un seul horodatage', () => {
  const model = dynamicRuntimeModel({
    zap: { kind: RUN_KIND.SCAN, availability: availability({ installed: true, version: 'docker' }) },
    nuclei: { kind: RUN_KIND.SCAN, availability: availability({ installed: true, version: '3.11.1' }) },
    mitmproxy: { kind: RUN_KIND.CAPTURE, availability: availability({ installed: false, reason: 'Non installé.' }) },
    burp: { kind: RUN_KIND.CONNECTOR, availability: availability({ installed: true }) }
  }, { now: clock('2026-09-10T11:00:00Z') });
  assert.deepEqual(Object.keys(model.engines).sort(), ['burp', 'mitmproxy', 'nuclei', 'zap']);
  assert.equal(model.engines.nuclei.status, RUN_STATUS.READY);
  assert.equal(model.engines.mitmproxy.status, RUN_STATUS.UNAVAILABLE);
  assert.equal(model.engines.burp.status, RUN_STATUS.WAITING_EXTERNAL);
  assert.equal(model.observedAt, '2026-09-10T11:00:00.000Z');
});

// ----------------------------------------------- le coordinateur de rafraîchissement

test('deux sources qui bougent dans le même cycle ne produisent qu’une publication', async () => {
  let published = 0;
  let time = 100000;
  const coordinator = createRefreshCoordinator({
    sources: [
      { name: 'traffic', activeIntervalMs: 3000, refresh: async () => true },
      { name: 'connector', activeIntervalMs: 5000, refresh: async () => true }
    ],
    publish: () => { published += 1; },
    now: () => time,
    setTimer: () => null,
    clearTimer: () => {}
  });
  coordinator.setActive(true);
  await coordinator.tick();
  assert.equal(published, 1, 'une seule publication par cycle');
});

test('une source qui ne rapporte rien de neuf ne publie rien', async () => {
  let published = 0;
  const coordinator = createRefreshCoordinator({
    sources: [{ name: 'traffic', activeIntervalMs: 1000, refresh: async () => false }],
    publish: () => { published += 1; },
    now: () => 50000,
    setTimer: () => null,
    clearTimer: () => {}
  });
  coordinator.setActive(true);
  await coordinator.tick();
  assert.equal(published, 0);
});

test('chaque source respecte sa cadence : la plus lente n’est pas interrogée à chaque tick', async () => {
  const calls = { traffic: 0, connector: 0 };
  let time = 0;
  const coordinator = createRefreshCoordinator({
    sources: [
      { name: 'traffic', activeIntervalMs: 3000, refresh: async () => { calls.traffic += 1; return false; } },
      { name: 'connector', activeIntervalMs: 5000, refresh: async () => { calls.connector += 1; return false; } }
    ],
    publish: () => {},
    now: () => time,
    setTimer: () => null,
    clearTimer: () => {}
  });
  coordinator.setActive(true);
  for (const at of [0, 1000, 2000, 3000, 4000, 5000, 6000]) { time = at; await coordinator.tick(); }
  assert.equal(calls.traffic, 3, 'trafic à 0, 3000 et 6000 ms');
  assert.equal(calls.connector, 2, 'connecteur à 0 et 5000 ms');
});

test('page fermée : aucune source n’a de cadence, l’horloge est arrêtée et non ralentie', async () => {
  const cleared = [];
  let started = 0;
  const coordinator = createRefreshCoordinator({
    sources: [{ name: 'traffic', activeIntervalMs: 3000, idleIntervalMs: 0, refresh: async () => true }],
    publish: () => {},
    now: () => 1000,
    setTimer: () => { started += 1; return { id: started }; },
    clearTimer: (timer) => cleared.push(timer)
  });
  coordinator.setActive(true);
  assert.equal(coordinator.inspect().running, true);
  coordinator.setActive(false);
  assert.equal(coordinator.inspect().running, false, 'personne ne regarde : rien n’est interrogé');
  assert.equal(cleared.length, 1);
  // Et rien n'est interrogé même si un tick résiduel se produit.
  let refreshed = 0;
  const idle = createRefreshCoordinator({
    sources: [{ name: 'traffic', activeIntervalMs: 3000, idleIntervalMs: 0, refresh: async () => { refreshed += 1; return true; } }],
    publish: () => {}, now: () => 9999, setTimer: () => null, clearTimer: () => {}
  });
  await idle.tick();
  assert.equal(refreshed, 0);
});

test('une source qui n’a rien à surveiller n’est pas interrogée', async () => {
  let refreshed = 0;
  let needed = false;
  const coordinator = createRefreshCoordinator({
    sources: [{ name: 'capture', activeIntervalMs: 1000, needed: () => needed, refresh: async () => { refreshed += 1; return true; } }],
    publish: () => {}, now: () => 7000, setTimer: () => null, clearTimer: () => {}
  });
  coordinator.setActive(true);
  await coordinator.tick();
  assert.equal(refreshed, 0);
  needed = true;
  await coordinator.tick();
  assert.equal(refreshed, 1);
});

test('une source lente n’est pas rappelée par-dessus elle-même', async () => {
  let inFlight = 0;
  let peak = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let time = 0;
  const coordinator = createRefreshCoordinator({
    sources: [{
      name: 'traffic',
      activeIntervalMs: 1000,
      refresh: async () => { inFlight += 1; peak = Math.max(peak, inFlight); await gate; inFlight -= 1; return true; }
    }],
    publish: () => {}, now: () => time, setTimer: () => null, clearTimer: () => {}
  });
  coordinator.setActive(true);
  const first = coordinator.tick();
  time = 5000;
  await coordinator.tick();
  release();
  await first;
  assert.equal(peak, 1, 'un sondage lent ne se met pas en file derrière lui-même');
});

test('l’échec d’une source est signalé sans interrompre les autres ni l’horloge', async () => {
  const errors = [];
  let published = 0;
  const coordinator = createRefreshCoordinator({
    sources: [
      { name: 'traffic', activeIntervalMs: 1000, refresh: async () => { throw new Error('backend injoignable'); } },
      { name: 'connector', activeIntervalMs: 1000, refresh: async () => true }
    ],
    publish: () => { published += 1; },
    onError: (name, error) => errors.push(`${name}: ${error.message}`),
    now: () => 4000, setTimer: () => ({ id: 'horloge' }), clearTimer: () => {}
  });
  coordinator.setActive(true);
  await coordinator.tick();
  assert.deepEqual(errors, ['traffic: backend injoignable']);
  assert.equal(published, 1, 'la source saine publie quand même');
  assert.equal(coordinator.inspect().running, true, 'une source en panne n’arrête pas l’horloge');
});

test('arrêté, le coordinateur ne bat plus et ne se réveille plus', async () => {
  let refreshed = 0;
  const coordinator = createRefreshCoordinator({
    sources: [{ name: 'traffic', activeIntervalMs: 1000, refresh: async () => { refreshed += 1; return true; } }],
    publish: () => {}, now: () => 3000, setTimer: () => null, clearTimer: () => {}
  });
  coordinator.setActive(true);
  coordinator.stop();
  coordinator.wake();
  await coordinator.tick();
  assert.equal(await coordinator.refreshNow(), false);
  assert.equal(refreshed, 0);
  assert.equal(coordinator.inspect().running, false);
});

// --------------------------------------- la sémantique des événements de trafic

const exchange = (flowId) => ({
  name: 'GET /api/products',
  source: 'mitmproxy',
  request: { method: 'GET', url: 'http://192.168.222.132:3000/api/products', headers: {}, body: '', sensitive_headers: [] },
  response: { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '[]', bodySha256: 'b'.repeat(64) },
  ...(flowId ? { capture: { flow_id: flowId } } : {})
});

test('deux échanges identiques observés à des instants différents sont deux requêtes, un endpoint', async (t) => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-runtime-store-'));
  t.after(() => fsp.rm(dataDir, { recursive: true, force: true }));
  const store = new FileStore(dataDir).initialize();

  const first = store.saveHttpScenario({ ...exchange('flow-10h01'), timestamp: '2026-09-10T10:01:00.000Z' });
  const second = store.saveHttpScenario({ ...exchange('flow-10h02'), timestamp: '2026-09-10T10:02:00.000Z' });
  assert.notEqual(second.scenario_id, first.scenario_id);

  const stored = store.listHttpScenarios();
  assert.equal(stored.length, 2, 'requêtes capturées = 2');
  const summary = sessionSummary(stored);
  assert.equal(summary.totalRequests, 2);
  assert.equal(summary.uniqueEndpoints, 1, 'endpoints uniques = 1');
  // Le regroupement reste possible : l'empreinte n'a pas disparu, elle a changé de rôle.
  assert.equal(stored.every((entry) => !('fingerprint' in entry)), true, 'l’empreinte reste interne au stockage');
});

test('un même flux redéposé deux fois reste un seul événement', async (t) => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-runtime-store-'));
  t.after(() => fsp.rm(dataDir, { recursive: true, force: true }));
  const store = new FileStore(dataDir).initialize();
  const first = store.saveHttpScenario(exchange('flow-unique'));
  const again = store.saveHttpScenario(exchange('flow-unique'));
  assert.equal(again.scenario_id, first.scenario_id, 'une redélivraison n’est pas une observation');
  assert.equal(store.listHttpScenarios().length, 1);
});

test('sans identifiant de flux, chaque dépôt est une observation nouvelle', async (t) => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-runtime-store-'));
  t.after(() => fsp.rm(dataDir, { recursive: true, force: true }));
  const store = new FileStore(dataDir).initialize();
  store.saveHttpScenario({ ...exchange(''), source: 'burp' });
  store.saveHttpScenario({ ...exchange(''), source: 'burp' });
  assert.equal(store.listHttpScenarios().length, 2);
});

// ------------------------------------------------- le câblage minimal de la page

test('les cartes lisent l’état courant du socle commun, pas l’historique de scans', () => {
  const runtime = dynamicRuntimeModel({
    zap: { kind: RUN_KIND.SCAN, availability: availability({ installed: false, reason: 'Moteur Docker indisponible.' }) },
    nuclei: { kind: RUN_KIND.SCAN, availability: availability({ installed: true, version: '3.11.1' }) },
    mitmproxy: {
      kind: RUN_KIND.CAPTURE,
      availability: availability({ installed: true, version: '12.2.3' }),
      run: recordActivity(createRun({ engine: 'mitmproxy', kind: RUN_KIND.CAPTURE }), { requestCount: 12 })
    },
    burp: { kind: RUN_KIND.CONNECTOR, availability: availability({ installed: true }), run: null }
  });
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'juice-shop', dynamicRuntime: runtime
  }), 'nonce', 'dynamic', 'light', {}, {});

  // Nuclei installé et jamais lancé : PRÊT, et il dit qu'il n'a jamais tourné.
  assert.match(html, /class="tool-status ready">PRÊT</);
  assert.match(html, /Jamais exécuté\./);
  // ZAP réellement indisponible : la raison mesurée, pas un état muet.
  assert.match(html, /class="tool-status unavailable">INDISPONIBLE</);
  assert.match(html, /Moteur Docker indisponible\./);
  // mitmproxy en train de capturer.
  assert.match(html, /class="tool-status running">EN COURS</);
  // Burp attend un connecteur externe : une attente, pas une panne.
  assert.match(html, /class="tool-status waiting-external">EN ATTENTE</);
});

test('sans socle publié, les cartes gardent exactement leur rendu d’origine', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'juice-shop', nucleiTool: { installed: true, version: '3.11.1' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.match(html, /class="tool-status ready">PRÊT</);
  // Burp garde son vocabulaire d'origine tant qu'aucun socle n'est publié.
  assert.match(html, /class="tool-status idle">DÉCONNECTÉ</);
  assert.ok(!/class="tool-status waiting-external"/.test(html));
});

test('l’extension alimente le socle depuis des détections réelles, jamais depuis les scanners', () => {
  const extension = src('src/extension.js');
  // La disponibilité de ZAP est mesurée sur l'outillage : local + Java, ou Docker.
  assert.match(extension, /async function zapAvailability\(\)/);
  assert.match(extension, /detectLocalZap\(/);
  assert.match(extension, /ensureDockerAvailable\(/);
  // Les quatre moteurs vivent dans un registre unique.
  assert.match(extension, /const dynamicEngines = \{/);
  for (const engine of ['zap:', 'nuclei:', 'mitmproxy:', 'burp:']) {
    assert.ok(extension.includes(`    ${engine} { kind: RUN_KIND`), `${engine} doit être déclaré dans le registre`);
  }
  // Les échecs deviennent un état de produit, avec un code.
  assert.match(extension, /failEngineRun\('mitmproxy', RUN_ERROR\.BACKEND_UNAVAILABLE/);
  assert.match(extension, /failEngineRun\('mitmproxy', RUN_ERROR\.PROCESS_EXITED/);
  assert.match(extension, /failEngineRun\('mitmproxy', RUN_ERROR\.MITMDUMP_START_FAILED/);
  assert.match(extension, /failEngineRun\('mitmproxy', RUN_ERROR\.STOP_FAILED/);
  assert.match(extension, /RUN_ERROR\.INGESTION_FAILED/);
  assert.match(extension, /RUN_ERROR\.SCAN_FAILED, error\.message/);
  // Un rechargement confronte l'état restauré à la réalité.
  assert.match(extension, /function reconcileRestoredRuns\(\)/);
  assert.match(extension, /reconcileRun\(entry\.run, \{ alive \}\)/);
});
