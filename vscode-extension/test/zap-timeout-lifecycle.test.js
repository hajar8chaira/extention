'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const {
  ZAP_LOCAL_TIMEOUTS, ZAP_SCAN_TIMEOUT_MS, waitForProgress, waitForPassiveQueue, waitForZap, stopLocalZap
} = require('../src/zap-local');
const {
  ZAP_STAGE, STAGE_STATUS, STAGE_ORDER, createZapExecution, applyZapStage, applyZapLifecycle,
  skipZapStage, failZapExecution, zapExecutionSummary, restoreZapExecution
} = require('../src/zap-execution');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (name) => fs.readFileSync(path.join(__dirname, '..', 'src', name), 'utf8');
const TARGET = 'http://192.168.222.132:3000';

// ------------------------------------------------------- le budget et sa source

test('le budget ZAP est le sien, et il n’est plus celui du délai générique des scanners', () => {
  // 45 minutes : l'ordre de grandeur d'un parcours applicatif réel, pas celui
  // d'une analyse de fichiers locale.
  assert.equal(ZAP_SCAN_TIMEOUT_MS, 45 * 60 * 1000);
  assert.ok(ZAP_SCAN_TIMEOUT_MS > 300000, 'le budget ZAP doit dépasser les 300 s génériques');

  const extension = src('extension.js');
  // Le scan ZAP ne descend jamais sous son propre budget, et respecte un délai
  // global configuré plus long.
  assert.match(extension, /timeoutMs: Math\.max\(timeoutMs, ZAP_SCAN_TIMEOUT_MS\)/);
  // Le délai générique reste la source du reste des scanners : rien d'autre ne change.
  assert.match(extension, /const timeoutMs = cfg\.get\('scan\.timeoutSeconds', 300\) \* 1000;/);
  // Et le moteur ZAP ne retombe plus sur un défaut étranger.
  assert.match(src('zap.js'), /async function runZap\(\{ targetUrl, timeoutMs = ZAP_SCAN_TIMEOUT_MS,/);
  assert.match(src('zap-local.js'), /timeoutMs = ZAP_SCAN_TIMEOUT_MS, signal/);
});

test('chaque étape a son délai, aucun n’est illimité, et les 300 s ne plafonnent plus rien', () => {
  const { DAEMON_START_MS, SPIDER_MS, PASSIVE_DRAIN_MS, ACTIVE_SCAN_MS, STALL_MS, OPENAPI_IMPORT_MS } = ZAP_LOCAL_TIMEOUTS;
  for (const [name, value] of Object.entries(ZAP_LOCAL_TIMEOUTS)) {
    assert.ok(Number.isFinite(value) && value > 0, `${name} doit être un délai fini et positif`);
  }
  // Le démarrage du démon est distinct de l'exécution du scan.
  assert.equal(DAEMON_START_MS, 180000);
  assert.equal(SPIDER_MS, 900000);
  assert.equal(PASSIVE_DRAIN_MS, 600000);
  assert.equal(ACTIVE_SCAN_MS, 1800000);
  assert.equal(STALL_MS, 300000);
  assert.equal(OPENAPI_IMPORT_MS, 300000);
  // Aucune étape ne dépasse le budget total.
  for (const value of [DAEMON_START_MS, SPIDER_MS, PASSIVE_DRAIN_MS, ACTIVE_SCAN_MS]) {
    assert.ok(value <= ZAP_SCAN_TIMEOUT_MS, 'une étape ne peut pas dépasser le budget total');
  }

  const local = src('zap-local.js');
  // Les anciens plafonds littéraux ont disparu : ils étaient la cause de l'échec.
  assert.doesNotMatch(local, /Math\.min\(timeoutMs, 180000\)/);
  assert.doesNotMatch(local, /Math\.min\(timeoutMs, 120000\)/);
  assert.match(local, /Math\.min\(timeoutMs, ZAP_LOCAL_TIMEOUTS\.SPIDER_MS\)/);
  assert.match(local, /Math\.min\(timeoutMs, ZAP_LOCAL_TIMEOUTS\.PASSIVE_DRAIN_MS\)/);
  assert.match(local, /Math\.min\(timeoutMs, ZAP_LOCAL_TIMEOUTS\.ACTIVE_SCAN_MS\)/);
  assert.match(local, /timeoutMs: ZAP_LOCAL_TIMEOUTS\.DAEMON_START_MS/);
});

// --------------------------------------------- progression réelle et immobilité

/** Un ZAP de test qui répond ce qu'on lui dit de répondre, sans réseau. */
function fakeZap(statuses) {
  const queue = [...statuses];
  let last = queue[queue.length - 1];
  const originalFetch = global.fetch;
  global.fetch = async (url) => {
    const value = queue.length ? queue.shift() : last;
    last = value;
    return { ok: true, json: async () => (typeof value === 'object' ? value : { status: String(value) }) };
  };
  return () => { global.fetch = originalFetch; };
}

test('une étape qui progresse va jusqu’à 100 % et rapporte les pourcentages de ZAP', async () => {
  const restore = fakeZap([0, 35, 80, 100]);
  const seen = [];
  try {
    await waitForProgress('http://127.0.0.1:1', 'k', 'spider', '1', 60000, null, (percent) => seen.push(percent), { stallMs: 60000 });
  } finally { restore(); }
  assert.deepEqual(seen, [0, 35, 80, 100]);
});

test('une étape immobile échoue sur l’absence de progression, en nommant l’étape et le point d’arrêt', async () => {
  const restore = fakeZap([40]);
  try {
    await assert.rejects(
      waitForProgress('http://127.0.0.1:1', 'k', 'spider', '1', 60000, null, () => {}, { stallMs: 1 }),
      (error) => {
        assert.match(error.message, /L’étape spider du scan ZAP local n’a plus progressé/);
        assert.match(error.message, /bloquée à 40 %/);
        return true;
      }
    );
  } finally { restore(); }
});

test('un plafond d’étape atteint nomme l’étape et le pourcentage réellement atteint', async () => {
  const restore = fakeZap([55]);
  try {
    await assert.rejects(
      waitForProgress('http://127.0.0.1:1', 'k', 'ascan', '1', 1, null, () => {}, { stallMs: 600000 }),
      (error) => {
        assert.match(error.message, /L’étape ascan du scan ZAP local a dépassé/);
        assert.match(error.message, /arrêtée à 55 %/);
        return true;
      }
    );
  } finally { restore(); }
  // Et le message générique, qui ne disait ni l'étape ni le point d'arrêt, a disparu.
  assert.doesNotMatch(src('zap-local.js'), /Le scan ZAP local a dépassé \$\{Math\.round\(timeoutMs \/ 1000\)\} secondes/);
});

test('une progression lente mais réelle n’échoue pas : c’est l’immobilité qui décide', async () => {
  const restore = fakeZap([10, 11, 12, 100]);
  try {
    // Le plafond est large, le seuil d'immobilité aussi : chaque sondage bouge,
    // donc rien ne doit échouer.
    await waitForProgress('http://127.0.0.1:1', 'k', 'spider', '1', 60000, null, () => {}, { stallMs: 30000 });
  } finally { restore(); }
});

test('la file passive immobile est rapportée comme telle, avec son compte réel', async () => {
  const restore = fakeZap([{ recordsToScan: '12' }]);
  let result;
  try {
    result = await waitForPassiveQueue('http://127.0.0.1:1', 'k', 60000, null, () => {}, { stallMs: 1 });
  } finally { restore(); }
  assert.equal(result.available, true);
  assert.equal(result.drained, false);
  assert.equal(result.remaining, 12);
  assert.match(result.reason, /file passive immobile à 12 enregistrement\(s\)/);
});

test('une file passive qui se vide est rapportée vidée, avec son compte initial', async () => {
  const restore = fakeZap([{ recordsToScan: '4' }, { recordsToScan: '2' }, { recordsToScan: '0' }]);
  let result;
  try {
    result = await waitForPassiveQueue('http://127.0.0.1:1', 'k', 60000, null, () => {}, { stallMs: 60000 });
  } finally { restore(); }
  assert.deepEqual(result, { available: true, drained: true, records: 4 });
});

test('l’attente de l’API ZAP a son propre délai et dit combien de temps elle a attendu', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('pas encore'); };
  const waits = [];
  try {
    await assert.rejects(
      waitForZap('http://127.0.0.1:1', 'k', 1, (seconds) => waits.push(seconds)),
      /ZAP local n’a pas répondu sur http:\/\/127\.0\.0\.1:1 en 0 secondes/
    );
  } finally { global.fetch = originalFetch; }
  assert.ok(waits.length >= 1, 'l’attente doit être rapportée pendant qu’elle dure');
});

// ------------------------------------------------------------------- le nettoyage

/** Un processus de test : il sort quand on le lui demande, ou jamais. */
function fakeChild({ exitsOnShutdown = true } = {}) {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kills = [];
  child.kill = (signal) => {
    child.kills.push(signal || 'SIGTERM');
    child.exitCode = 0;
    child.emit('close', 0);
    return true;
  };
  child.exitsOnShutdown = exitsOnShutdown;
  return child;
}

test('un démon qui sort de lui-même n’est pas tué', async () => {
  const child = fakeChild();
  const originalFetch = global.fetch;
  global.fetch = async () => {
    setImmediate(() => { child.exitCode = 0; child.emit('close', 0); });
    return { ok: true, json: async () => ({ Result: 'OK' }) };
  };
  let stop;
  try { stop = await stopLocalZap(child, 'http://127.0.0.1:1', 'k'); } finally { global.fetch = originalFetch; }
  assert.deepEqual(stop, { stopped: true, forced: false });
  assert.deepEqual(child.kills, []);
});

test('un démon qui accepte l’arrêt sans sortir est tué : aucun ZAP orphelin', async () => {
  const child = fakeChild({ exitsOnShutdown: false });
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => ({ Result: 'OK' }) });
  let stop;
  try { stop = await stopLocalZap(child, 'http://127.0.0.1:1', 'k'); } finally { global.fetch = originalFetch; }
  assert.equal(stop.stopped, true);
  assert.equal(stop.forced, true);
  assert.ok(child.kills.length >= 1, 'le processus doit être tué quand il ne sort pas');
});

test('une API qui ne répond plus fait tuer le processus tout de suite', async () => {
  const child = fakeChild();
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('API morte'); };
  try { await stopLocalZap(child, 'http://127.0.0.1:1', 'k'); } finally { global.fetch = originalFetch; }
  assert.ok(child.kills.length >= 1);
});

test('l’arrêt passe dans tous les cas : terminé, échoué, annulé', () => {
  const local = src('zap-local.js');
  assert.match(local, /\} finally \{[\s\S]{0,200}await stopLocalZap\(child, baseUrl, apiKey\)/);
  // Et l'état « en cours » ne survit pas : l'étape d'arrêt est rapportée.
  assert.match(local, /report\('DAEMON_STOPPING'/);
  assert.match(local, /report\('DAEMON_STOPPED'/);
});

// --------------------------------------------------------------- le déroulé réel

test('un déroulé neuf a toutes ses étapes en attente, et n’affirme aucune progression', () => {
  const execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  assert.deepEqual(execution.stages.map((stage) => stage.id), [...STAGE_ORDER]);
  for (const stage of execution.stages) {
    assert.equal(stage.status, STAGE_STATUS.PENDING);
    assert.equal(stage.progress, null);
    assert.deepEqual(stage.metrics, {});
  }
  assert.equal(execution.lastActivity, null);
  assert.equal(execution.finishedAt, null);
});

test('les étapes réelles du moteur deviennent les étapes du déroulé', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  for (const event of [
    { state: 'DAEMON_STARTING', detail: 'port 51234' },
    { state: 'API_WAIT', detail: 'API ZAP pas encore disponible (8 s)' },
    { state: 'SPIDERING', progress: 42 },
    { state: 'PASSIVE_WAIT', progress: 50, detail: '6 enregistrement(s) en file', metrics: { recordsToScan: 6 } },
    { state: 'ACTIVE_SKIPPED', detail: 'Mode baseline passif' },
    { state: 'COLLECTING_RESULTS', progress: 100, detail: '3 alerte(s) collectée(s)', metrics: { alerts: 3 } }
  ]) execution = applyZapLifecycle(execution, event);

  const byId = Object.fromEntries(execution.stages.map((stage) => [stage.id, stage]));
  assert.equal(byId[ZAP_STAGE.DAEMON_STARTING].status, STAGE_STATUS.COMPLETED);
  assert.equal(byId[ZAP_STAGE.API_WAIT].status, STAGE_STATUS.COMPLETED);
  assert.equal(byId[ZAP_STAGE.SPIDERING].status, STAGE_STATUS.COMPLETED);
  assert.equal(byId[ZAP_STAGE.SPIDERING].progress, 42);
  assert.equal(byId[ZAP_STAGE.PASSIVE_WAIT].metrics.recordsToScan, 6);
  // Le scan actif n'a pas eu lieu : il est sauté, avec sa raison.
  assert.equal(byId[ZAP_STAGE.ACTIVE_SCANNING].status, STAGE_STATUS.SKIPPED);
  assert.equal(byId[ZAP_STAGE.ACTIVE_SCANNING].detail, 'Mode baseline passif');
  assert.equal(byId[ZAP_STAGE.COLLECTING_RESULTS].metrics.alerts, 3);
  // Et les étapes non encore atteintes restent en attente.
  assert.equal(byId[ZAP_STAGE.NORMALIZING].status, STAGE_STATUS.PENDING);
});

test('aucune étape n’invente de pourcentage, et une métrique non numérique n’entre pas', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'PASSIVE_WAIT', detail: 'file indisponible', metrics: { recordsToScan: 'beaucoup' } });
  const passive = execution.stages.find((stage) => stage.id === ZAP_STAGE.PASSIVE_WAIT);
  assert.equal(passive.progress, null);
  assert.deepEqual(passive.metrics, {});
  assert.equal(passive.status, STAGE_STATUS.RUNNING);
});

test('un état que le moteur n’a pas déclaré ne crée aucune étape', () => {
  const execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  assert.equal(applyZapLifecycle(execution, { state: 'SOMETHING_ELSE', progress: 99 }), execution);
  assert.throws(() => applyZapStage(execution, { stage: 'INVENTÉE' }), /Étape ZAP inconnue/);
});

test('l’activité distingue progression, attente, immobilité et panne', () => {
  const base = createZapExecution({ target: TARGET, mode: 'baseline', now: 1000 });
  const progressing = applyZapStage(base, { stage: ZAP_STAGE.SPIDERING, progress: 20, now: 2000 });
  assert.equal(zapExecutionSummary(progressing, { now: 3000, stallMs: 60000 }).activity, 'PROGRESSING');
  // La même observation, vue longtemps après : plus rien n'a bougé.
  assert.equal(zapExecutionSummary(progressing, { now: 2000 + 120000, stallMs: 60000 }).activity, 'STALLED');
  // Une étape sans pourcentage attend : elle ne prétend pas progresser.
  const waiting = applyZapStage(base, { stage: ZAP_STAGE.API_WAIT, detail: 'API pas encore disponible', now: 2000 });
  assert.equal(zapExecutionSummary(waiting, { now: 3000, stallMs: 60000 }).activity, 'WAITING');
  const failed = failZapExecution(progressing, { reason: 'L’étape spider n’a plus progressé.', now: 4000 });
  const summary = zapExecutionSummary(failed, { now: 5000 });
  assert.equal(summary.activity, 'FAILED');
  assert.equal(failed.stages.find((stage) => stage.id === ZAP_STAGE.SPIDERING).status, STAGE_STATUS.FAILED);
  assert.equal(failed.failureReason, 'L’étape spider n’a plus progressé.');
});

test('le temps rapporté est du temps mesuré, jamais un minuteur', () => {
  const base = createZapExecution({ target: TARGET, mode: 'baseline', now: 10000 });
  const running = applyZapStage(base, { stage: ZAP_STAGE.SPIDERING, progress: 10, now: 15000 });
  const summary = zapExecutionSummary(running, { now: 25000 });
  assert.equal(summary.elapsedMs, 15000);
  assert.equal(summary.sinceActivityMs, 10000);
  assert.equal(summary.startedAt, new Date(10000).toISOString());
  assert.equal(summary.lastActivity, new Date(15000).toISOString());
});

test('un déroulé restauré garde ses étapes et refuse ce qui n’en est pas un', () => {
  const original = applyZapStage(createZapExecution({ target: TARGET, mode: 'active' }), {
    stage: ZAP_STAGE.SPIDERING, progress: 70, detail: '12 URL découverte(s)', metrics: { urls: 12 }
  });
  const restored = restoreZapExecution(JSON.parse(JSON.stringify(original)));
  assert.equal(restored.stages.find((stage) => stage.id === ZAP_STAGE.SPIDERING).metrics.urls, 12);
  assert.equal(restored.mode, 'active');
  assert.equal(restoreZapExecution(null), null);
  assert.equal(restoreZapExecution({ stages: [{ id: 'INVENTÉE' }] }), null);
});

test('sauter une étape la nomme comme telle, jamais comme réussie', () => {
  const execution = skipZapStage(createZapExecution({ target: TARGET, mode: 'baseline' }), {
    stage: ZAP_STAGE.ACTIVE_SCANNING, reason: 'Mode baseline passif'
  });
  const active = execution.stages.find((stage) => stage.id === ZAP_STAGE.ACTIVE_SCANNING);
  assert.equal(active.status, STAGE_STATUS.SKIPPED);
  assert.notEqual(active.status, STAGE_STATUS.COMPLETED);
  assert.ok(active.finishedAt);
});

// ------------------------------------------------------- le rendu dans la carte

function executionForCard() {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline', now: 1000 });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.PREFLIGHT, status: STAGE_STATUS.COMPLETED, detail: 'Cible autorisée pour ce workspace', now: 1000 });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.ENGINE, status: STAGE_STATUS.COMPLETED, detail: 'Local', now: 1500 });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING', detail: 'Démarrage du démon ZAP local sur le port 51234' }, { now: 2000 });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT', detail: 'API ZAP disponible' }, { now: 12000 });
  execution = applyZapLifecycle(execution, { state: 'SPIDERING', progress: 64 }, { now: 30000 });
  execution = applyZapLifecycle(execution, { state: 'PASSIVE_WAIT', progress: 80, detail: '5 enregistrement(s) en file', metrics: { recordsToScan: 5 } }, { now: 40000 });
  execution = applyZapLifecycle(execution, { state: 'ACTIVE_SKIPPED', detail: 'Mode baseline passif' }, { now: 41000 });
  return execution;
}

test('la carte ZAP porte un repli « Détails d’exécution » avec les étapes réelles', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'baseline' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution: executionForCard()
  }), 'n', 'dynamic');

  // Un repli, pas une refonte de la carte.
  assert.match(html, /<details class="zap-execution-details">\s*<summary>Détails d’exécution/);
  for (const label of [
    'Preflight / autorisation de la cible', 'Moteur sélectionné', 'Démarrage du démon ZAP local',
    'Attente de l’API ZAP', 'Spidering / découverte d’URL', 'Analyse passive', 'Scan actif',
    'Collecte des alertes', 'Normalisation et persistance des findings', 'Arrêt du démon', 'Terminé'
  ]) assert.match(html, new RegExp(label.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')), `l’étape « ${label} » doit figurer`);
});

test('en baseline passif, le scan actif est explicitement SKIPPED avec sa raison', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'baseline' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution: executionForCard()
  }), 'n', 'dynamic');

  assert.match(html, /<li class="zap-stage skipped">\s*<span class="zap-stage-name">Scan actif<\/span>\s*<span class="zap-stage-state">SKIPPED<\/span>\s*<small>Mode baseline passif<\/small>/);
  // Rien ne laisse croire qu'un scan actif a eu lieu.
  assert.doesNotMatch(html, /<li class="zap-stage completed">\s*<span class="zap-stage-name">Scan actif/);
});

test('les pourcentages affichés sont ceux de ZAP, et une étape sans chiffre montre son état', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'baseline' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution: executionForCard()
  }), 'n', 'dynamic');

  assert.match(html, /Spidering \/ découverte d’URL<\/span>\s*<span class="zap-stage-state">COMPLETED · 64 %/);
  assert.match(html, /5 enregistrements en file/);
  // L'attente de l'API n'a pas de pourcentage : elle se lit par son état.
  assert.match(html, /Attente de l’API ZAP<\/span>\s*<span class="zap-stage-state">COMPLETED<\/span>/);
  // Les étapes non atteintes sont en attente, pas à 0 %.
  assert.match(html, /Arrêt du démon<\/span>\s*<span class="zap-stage-state">PENDING<\/span>/);
  assert.doesNotMatch(html, /<span class="zap-stage-state">PENDING · \d/);
});

test('la carte dit si le scan progresse, attend ou n’avance plus', () => {
  const execution = executionForCard();
  const render = (zapExecution) => renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'baseline' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution
  }), 'n', 'dynamic');

  // L'activité vient de la dernière observation réelle, pas d'une horloge d'affichage.
  assert.match(render(execution), /class="zap-activity (progressing|stalled|waiting)"/);

  // Le cas réel : l'échec survient pendant une étape, et c'est elle qui le porte.
  const spidering = applyZapLifecycle(createZapExecution({ target: TARGET, mode: 'baseline', now: 1000 }), { state: 'SPIDERING', progress: 64 }, { now: 2000 });
  const failed = failZapExecution(spidering, { reason: 'L’étape spider du scan ZAP local n’a plus progressé depuis 300 secondes (bloquée à 64 %).' });
  assert.equal(failed.stages.find((stage) => stage.id === ZAP_STAGE.SPIDERING).status, STAGE_STATUS.FAILED);
  const html = render(failed);
  assert.match(html, /class="zap-activity failed"/);
  assert.match(html, /n’a plus progressé depuis 300 secondes \(bloquée à 64 %\)/);
  assert.match(html, /<li class="zap-stage failed">/);

  // Et un échec survenu entre deux étapes ne fabrique pas d'étape fautive.
  const betweenStages = failZapExecution(execution, { reason: 'Backend injoignable.' });
  assert.equal(betweenStages.stages.filter((stage) => stage.status === STAGE_STATUS.FAILED).length, 0);
  assert.match(render(betweenStages), /Backend injoignable\./);
});

test('sans run observé, aucun déroulé n’est rendu', () => {
  const model = buildDashboardModel([], [{ tool: 'ZAP', status: 'completed', mode: 'baseline' }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET
  });
  assert.equal(model.zapExecution, null);
  // La règle de style reste dans le document ; le repli, lui, n'est pas rendu.
  assert.doesNotMatch(renderDashboardHtml(model, 'n', 'dynamic'), /<details class="zap-execution-details">/);
  assert.doesNotMatch(renderDashboardHtml(model, 'n', 'dynamic'), /class="zap-stage /);
});

test('la carte principale reste concise : le déroulé est replié, sans attribut open', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'baseline' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution: executionForCard()
  }), 'n', 'dynamic');
  assert.doesNotMatch(html, /<details class="zap-execution-details" open>/);
  assert.equal((html.match(/<details class="zap-execution-details">/g) || []).length, 1, 'un seul repli dans le document');
  // Les étapes vivent dans le repli, jamais dans le corps de la carte.
  const body = html.slice(0, html.indexOf('<details class="zap-execution-details">'));
  assert.doesNotMatch(body, /class="zap-stage /);
});

// ------------------------------------------------------------------ le cycle de vie

test('le cycle READY → STARTING → RUNNING → COMPLETED reste celui du socle commun', () => {
  const extension = src('extension.js');
  // Le déroulé s'ajoute au socle d'exécution, il ne le remplace pas.
  assert.match(extension, /updateEngineRun\('zap', \{ status: RUN_STATUS\.RUNNING, phase, progress: event\?\.progress \?\? null \}\)/);
  assert.match(extension, /setEngineRun\(dynamicEngine, completeRun\(finished/);
  assert.match(extension, /failEngineRun\(dynamicEngineOf\(scan\.tool\), RUN_ERROR\.SCAN_FAILED, error\.message\)/);
  // Et le déroulé est clos sur les trois issues, jamais laissé « en cours ».
  assert.match(extension, /failZapExecutionNow\('Analyse annulée par l’utilisateur\.', 'ZAP_RUN_CANCELLED'\)/);
  assert.match(extension, /failZapExecutionNow\(error\.message, zapStartErrorCode \|\| 'ZAP_SCAN_FAILED'\)/);
  assert.match(extension, /stage: ZAP_STAGE\.COMPLETED, status: STAGE_STATUS\.COMPLETED/);
});

test('les étapes fines du moteur ne sont pas envoyées à la campagne, qui lèverait', () => {
  const extension = src('extension.js');
  assert.match(extension, /if \(!DYNAMIC_CAMPAIGN_STATES\.has\(String\(event\?\.state \|\| ''\)\)\) return;/);
  const states = extension.slice(extension.indexOf('const DYNAMIC_CAMPAIGN_STATES'));
  const declared = states.slice(0, states.indexOf(']'));
  for (const state of ['STARTING', 'SPIDERING', 'PASSIVE_WAIT', 'ACTIVE_SCANNING', 'COLLECTING_RESULTS']) {
    assert.match(declared, new RegExp(`'${state}'`));
  }
  // Les nouveaux états n'y figurent pas : ils vont au déroulé d'exécution.
  for (const state of ['API_WAIT', 'DAEMON_STARTING', 'ACTIVE_SKIPPED', 'DAEMON_STOPPING']) {
    assert.doesNotMatch(declared, new RegExp(`'${state}'`));
  }
});
