'use strict';

/**
 * Un scan ZAP actif réel, observé sur http://192.168.222.132:3000, montrait en
 * même temps « EN COURS · Scan actif 37 % · Analysis in progress » et des
 * « Détails d'exécution » en ÉCHEC, puis perdait ces détails à la mise à jour
 * suivante, et annonçait « Authentifié » à côté d'un compte de test non vérifié.
 *
 * Ces tests tiennent les invariants qui empêchent chacune de ces contradictions.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  createZapExecution, applyZapLifecycle, applyZapStage, failZapExecution, zapExecutionSummary,
  ZAP_STAGE, STAGE_STATUS
} = require('../src/zap-execution');
const {
  createExecution, beginRefresh, updateRefresh, completeExecution, projectSnapshot
} = require('../src/security-snapshot');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const {
  RUN_KIND, RUN_STATUS, availability, createRun, transitionRun, failRun, dynamicRuntimeModel
} = require('../src/dynamic-runtime');

const TARGET = 'http://192.168.222.132:3000';
const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

function clock(start = Date.parse('2026-09-12T20:10:00Z')) {
  let at = start;
  return () => { at += 1000; return at; };
}

function stageOf(execution, id) {
  return execution.stages.find((stage) => stage.id === id);
}

/** La séquence réelle d'un scan local, jusqu'au scan actif à `percent` %. */
function activeRunUpTo(percent, now) {
  let execution = createZapExecution({ target: TARGET, mode: 'active', now });
  for (const event of [
    { state: 'MODE', detail: 'active' },
    { state: 'DAEMON_STARTING' },
    { state: 'API_WAIT' },
    { state: 'DAEMON_READY' },
    { state: 'SPIDERING', progress: 0 },
    { state: 'SPIDERING', progress: 100, metrics: { urls: 88 } },
    { state: 'PASSIVE_WAIT', progress: 100, metrics: { recordsToScan: 0 } },
    { state: 'ACTIVE_SCANNING', progress: 0 },
    { state: 'ACTIVE_SCANNING', progress: percent }
  ]) execution = applyZapLifecycle(execution, event, { now });
  return execution;
}

// ------------------------------------------------------------ déroulé ZAP

test('un scan actif en cours n’est jamais résumé en ÉCHEC', () => {
  const now = clock();
  const execution = activeRunUpTo(37, now);
  const summary = zapExecutionSummary(execution, { now });
  assert.notEqual(summary.activity, 'FAILED');
  assert.equal(summary.currentStage, ZAP_STAGE.ACTIVE_SCANNING);
  assert.equal(summary.progress, 37);
});

test('l’arrêt du démon après une panne ne fait pas passer le scan actif pour terminé', () => {
  const now = clock();
  let execution = activeRunUpTo(37, now);
  // Le `finally` du moteur passe avant que la panne n'atteigne l'extension.
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STOPPING' }, { now });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STOPPED', detail: 'Démon arrêté de force' }, { now });
  assert.equal(stageOf(execution, ZAP_STAGE.ACTIVE_SCANNING).status, STAGE_STATUS.RUNNING,
    'l’arrêt du démon ne prouve pas que le scan actif a abouti');
  assert.notEqual(zapExecutionSummary(execution, { now }).activity, 'FAILED', 'la panne n’est pas encore survenue');

  const reason = 'L’étape ascan du scan ZAP local n’a plus progressé depuis 300 secondes (bloquée à 37 %).';
  const failed = failZapExecution(execution, { reason, code: 'ZAP_SCAN_FAILED', now });
  const active = stageOf(failed, ZAP_STAGE.ACTIVE_SCANNING);
  assert.equal(active.status, STAGE_STATUS.FAILED);
  assert.equal(active.progress, 37);
  const summary = zapExecutionSummary(failed, { now });
  assert.equal(summary.activity, 'FAILED');
  assert.equal(summary.failureCode, 'ZAP_SCAN_FAILED');
  assert.equal(summary.failureReason, reason);
  assert.ok(summary.finishedAt);
});

test('régression baseline passif : le déroulé final est inchangé', () => {
  const now = clock();
  let execution = createZapExecution({ target: TARGET, mode: 'baseline', now });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.PREFLIGHT, status: STAGE_STATUS.COMPLETED, now });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.ENGINE, status: STAGE_STATUS.COMPLETED, detail: 'Local', now });
  for (const event of [
    { state: 'MODE', detail: 'baseline' },
    { state: 'DAEMON_STARTING' }, { state: 'API_WAIT' }, { state: 'DAEMON_READY' },
    { state: 'SPIDERING', progress: 100 },
    { state: 'PASSIVE_WAIT', progress: 100 },
    { state: 'ACTIVE_SKIPPED', detail: 'Mode baseline passif' },
    { state: 'COLLECTING_RESULTS' }, { state: 'COLLECTING_RESULTS', progress: 100 },
    { state: 'DAEMON_STOPPING' }, { state: 'DAEMON_STOPPED' }
  ]) execution = applyZapLifecycle(execution, event, { now });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.NORMALIZING, status: STAGE_STATUS.RUNNING, now });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.NORMALIZING, status: STAGE_STATUS.COMPLETED, now });
  execution = applyZapStage(execution, { stage: ZAP_STAGE.COMPLETED, status: STAGE_STATUS.COMPLETED, now });

  const statuses = Object.fromEntries(execution.stages.map((stage) => [stage.id, stage.status]));
  assert.deepEqual(statuses, {
    PREFLIGHT: 'COMPLETED', ENGINE: 'COMPLETED', DAEMON_STARTING: 'COMPLETED', API_WAIT: 'COMPLETED',
    SPIDERING: 'COMPLETED', PASSIVE_WAIT: 'COMPLETED', ACTIVE_SCANNING: 'SKIPPED',
    COLLECTING_RESULTS: 'COMPLETED', NORMALIZING: 'COMPLETED', DAEMON_STOPPING: 'COMPLETED', COMPLETED: 'COMPLETED'
  });
  assert.equal(zapExecutionSummary(execution, { now }).activity, 'DONE');
});

// ---------------------------------------------------- identité du run courant

function snapshotWithPassiveBaseline() {
  const previous = createExecution({ executionId: 'local-execution-15', requestedTools: ['ZAP'], allTools: ['ZAP'] });
  let snapshot = beginRefresh({ version: 1, resultSets: {} }, previous);
  const baseline = { tool: 'ZAP', mode: 'baseline', authenticated: true, engine: 'Local', status: 'completed', durationMs: 60000 };
  snapshot = updateRefresh(snapshot, 'ZAP', 'completed', { findings: [], durationMs: 60000 });
  return completeExecution(snapshot, previous, [], [baseline]);
}

test('un run actif ne reprend ni le mode ni l’authentification du baseline précédent', () => {
  const current = createExecution({ executionId: 'local-execution-16', requestedTools: ['ZAP'], allTools: ['ZAP'] });
  let snapshot = beginRefresh(snapshotWithPassiveBaseline(), current);
  const identity = { tool: 'ZAP', mode: 'active', authenticated: false, engine: 'Local' };
  snapshot = updateRefresh(snapshot, 'ZAP', 'running', { identity });

  const running = projectSnapshot(snapshot).scanners.find((scanner) => scanner.tool === 'ZAP');
  assert.equal(running.status, 'running');
  assert.equal(running.mode, 'active');
  assert.equal(running.authenticated, false);

  snapshot = updateRefresh(snapshot, 'ZAP', 'failed', { error: 'bloqué à 37 %', identity });
  snapshot = completeExecution(snapshot, current, [], [{ ...identity, status: 'failed', error: 'bloqué à 37 %' }]);
  const failed = projectSnapshot(snapshot).scanners.find((scanner) => scanner.tool === 'ZAP');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.mode, 'active', 'le run clos garde son propre mode');
  assert.equal(failed.authenticated, false, 'et sa propre authentification');
});

// ------------------------------------------------------------- carte ZAP

function zapCard(html) {
  const match = html.match(/<article class="dynamic-tool-card zap[\s\S]*?<\/article>/);
  assert.ok(match, 'la carte ZAP est rendue');
  return match[0];
}

function runtimeWith(run) {
  return dynamicRuntimeModel({
    zap: { kind: RUN_KIND.SCAN, availability: availability({ installed: true }), run, lastRun: null }
  });
}

test('pendant un run actif, la carte et les Détails d’exécution ne se contredisent pas', () => {
  const now = clock();
  const run = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET, now }), {
    status: RUN_STATUS.RUNNING, phase: 'Moteur Local · Active scanning 37 %', progress: 37, now
  });
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'active', authenticated: false }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, dynamicRuntime: runtimeWith(run),
    zapExecution: activeRunUpTo(37, now)
  }), 'n', 'dynamic');
  const card = zapCard(html);
  assert.match(card, /<summary>Détails d’exécution<span class="zap-activity (?!failed)/);
  assert.doesNotMatch(card, /zap-activity failed/);
});

test('après la panne, la carte et les Détails d’exécution disent ÉCHEC ensemble, avec la raison', () => {
  const now = clock();
  const reason = 'L’étape ascan du scan ZAP local n’a plus progressé depuis 300 secondes (bloquée à 37 %).';
  let run = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET, now }), { status: RUN_STATUS.RUNNING, now });
  run = failRun(run, { errorCode: 'SCAN_FAILED', errorReason: reason, now });
  const execution = failZapExecution(activeRunUpTo(37, now), { reason, code: 'ZAP_SCAN_FAILED', now });
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'failed', mode: 'active', authenticated: false, error: reason }], {
    scanStatus: 'partial', dynamicTargetUrl: TARGET, dynamicRuntime: runtimeWith(run), zapExecution: execution
  }), 'n', 'dynamic');
  const card = zapCard(html);
  assert.match(card, /zap-activity failed/);
  assert.match(card, /<code>ZAP_SCAN_FAILED<\/code>/);
  assert.match(card, /bloquée à 37/);
});

test('« Authentifié » exige une session vérifiée, jamais un login seulement configuré', () => {
  const policyResult = { policy: { zapActive: true, zapAuth: { login: '/rest/user/login' } } };
  const render = (scanner) => zapCard(renderDashboardHtml(buildDashboardModel([], [scanner], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, policyResult
  }), 'n', 'dynamic'));
  const configuredOnly = render({ tool: 'ZAP', status: 'running', mode: 'active' });
  assert.match(configuredOnly, /<span>Scan mode<\/span><strong>Actif<\/strong><small>Non authentifié<\/small>/);
  const unverified = render({ tool: 'ZAP', status: 'running', mode: 'active', authenticated: false });
  assert.match(unverified, /<small>Non authentifié<\/small>/);
  const verified = render({ tool: 'ZAP', status: 'running', mode: 'active', authenticated: true });
  assert.match(verified, /<span>Scan mode<\/span><strong>Actif<\/strong><small>Authentifié<\/small>/);
});

// ------------------------------------------------- câblage de l'extension

test('l’échec et l’annulation clôturent moteur et scanner avant de publier le déroulé', () => {
  const extension = src('extension.js');
  const failedAt = extension.indexOf('failZapExecutionNow(error.message, zapStartErrorCode');
  const failedEngine = extension.lastIndexOf('failEngineRun(dynamicEngineOf(scan.tool), RUN_ERROR.SCAN_FAILED', failedAt);
  const failedScanner = extension.lastIndexOf("updateRefresh(currentSecuritySnapshot, scan.tool, 'failed'", failedAt);
  assert.ok(failedEngine > 0 && failedScanner > failedEngine, 'moteur puis scanner');
  assert.ok(failedAt - failedScanner < 600, 'dans la même branche d’échec');

  const cancelledAt = extension.indexOf("failZapExecutionNow('Analyse annulée par l’utilisateur.', 'ZAP_RUN_CANCELLED')");
  const cancelledEngine = extension.lastIndexOf('failEngineRun(dynamicEngineOf(scan.tool), RUN_ERROR.CANCELLED', cancelledAt);
  const cancelledScanner = extension.lastIndexOf("updateRefresh(currentSecuritySnapshot, scan.tool, 'cancelled'", cancelledAt);
  assert.ok(cancelledEngine > 0 && cancelledScanner > cancelledEngine);
  assert.ok(cancelledAt - cancelledScanner < 600);
});

test('un nouveau run ZAP ouvre son propre déroulé avant d’être annoncé en cours', () => {
  const extension = src('extension.js');
  const running = extension.indexOf("updateRefresh(currentSecuritySnapshot, scan.tool, 'running'");
  const fresh = extension.lastIndexOf('publishZapExecution(createZapExecution(', running);
  const begin = extension.lastIndexOf('beginEngineRun(dynamicEngine,', running);
  assert.ok(begin > 0 && fresh > begin && fresh < running);
  assert.match(extension.slice(fresh - 600, fresh), /zapSessionAuthenticated = false;/);
});

test('la consolidation de fin de scan conserve Détails d’exécution et l’état dynamique', () => {
  const extension = src('extension.js');
  const final = extension.indexOf('scanStatus: finalScanStatus');
  const opening = extension.lastIndexOf('currentDashboardOptions = {', final);
  assert.match(extension.slice(opening, final), /\.\.\.currentDashboardOptions,/);
});

test('l’authentification ZAP vient de la session transmise, pas de la politique', () => {
  const extension = src('extension.js');
  assert.doesNotMatch(extension, /authenticated: Boolean\(projectPolicy\?\.zapAuth\?\.login \|\| projectPolicy\?\.zapContext/);
  assert.match(extension, /authenticated: zapSessionAuthenticated/);
  assert.match(src('zap.js'), /onAuthentication\?\.\(\{ authenticated: Boolean\(authResult\) \}\)/);
  assert.doesNotMatch(src('dashboard.js'), /zapScanner\?\.authenticated \?\? Boolean\(zapPolicy/);
});
