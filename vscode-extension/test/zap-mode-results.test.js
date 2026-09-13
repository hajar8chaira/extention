'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  zapScanMode, normalizeZapEndpoint, zapFindingFingerprint, stampZapFindings,
  recordZapRunResult, restoreZapRunResults, compareZapRuns
} = require('../src/zap-results');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderScanHistoryHtml, zapModeLabel } = require('../src/scan-history-page');

const TARGET = 'http://192.168.222.132:3000';
const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

const zap = (ruleId, endpoint, extra = {}) => ({
  tool: 'ZAP', ruleId, title: `Rule ${ruleId}`, rawSeverity: 'MEDIUM', method: 'GET', endpoint, parameter: '', ...extra
});

// ------------------------------------------------------------- modèle

test('le mode d’exécution devient un mode de résultat passif ou actif', () => {
  assert.equal(zapScanMode('baseline'), 'passive');
  assert.equal(zapScanMode('active'), 'active');
  assert.equal(zapScanMode('openapi'), 'active');
  assert.equal(zapScanMode(''), '');
});

test('chaque finding ZAP garde runId, scanMode et son empreinte ; les autres outils sont intacts', () => {
  const semgrep = { tool: 'Semgrep', id: 's1' };
  const [stamped, other] = stampZapFindings([zap('10038', `${TARGET}/`), semgrep], { runId: 'zap-run-1', scanMode: 'baseline' });
  assert.equal(stamped.runId, 'zap-run-1');
  assert.equal(stamped.scanMode, 'passive');
  assert.equal(stamped.zapFingerprint, zapFindingFingerprint(stamped));
  assert.equal(other, semgrep);
});

test('l’empreinte normalisée ignore l’ordre, les valeurs de requête, la casse de l’hôte et le / final', () => {
  assert.equal(normalizeZapEndpoint('HTTP://192.168.222.132:3000/rest/products/search?q=a&x=1'), normalizeZapEndpoint('http://192.168.222.132:3000/rest/products/search/?x=9&q=b'));
  assert.notEqual(zapFindingFingerprint(zap('40018', `${TARGET}/rest/a`)), zapFindingFingerprint(zap('40018', `${TARGET}/rest/b`)));
  assert.notEqual(zapFindingFingerprint(zap('40018', `${TARGET}/rest/a`, { parameter: 'q' })), zapFindingFingerprint(zap('40018', `${TARGET}/rest/a`)));
});

// ----------------------------------------------------------- comparaison

test('la comparaison se fait par empreinte, jamais par soustraction de compteurs', () => {
  // Même nombre de findings de chaque côté : une soustraction dirait « 0 nouveau ».
  let results = recordZapRunResult({}, {
    target: TARGET, runId: 'zap-passive', scanMode: 'baseline',
    findings: [zap('10038', `${TARGET}/`), zap('10020', `${TARGET}/`), zap('10021', `${TARGET}/ftp`)]
  });
  results = recordZapRunResult(results, {
    target: `${TARGET}/#/`, runId: 'zap-active', scanMode: 'active',
    findings: [zap('10038', `${TARGET}/`), zap('40018', `${TARGET}/rest/user/login`, { parameter: 'email' }), zap('90019', `${TARGET}/api`)]
  });
  const comparison = compareZapRuns(results, TARGET);
  assert.equal(comparison.passive.observations, 3);
  assert.equal(comparison.active.observations, 3);
  assert.deepEqual(comparison.common.map((o) => o.title), ['Rule 10038']);
  assert.deepEqual(comparison.newInActive.map((o) => o.title).sort(), ['Rule 40018', 'Rule 90019']);
  assert.deepEqual(comparison.onlyInPassive.map((o) => o.title).sort(), ['Rule 10020', 'Rule 10021']);
  assert.equal(comparison.passive.runId, 'zap-passive');
  assert.equal(comparison.active.runId, 'zap-active');
});

test('les doublons d’un même run comptent une seule observation', () => {
  const results = recordZapRunResult({}, {
    target: TARGET, runId: 'r', scanMode: 'active',
    findings: [zap('10038', `${TARGET}/?a=1`), zap('10038', `${TARGET}/?a=2`), { tool: 'Semgrep', ruleId: 'x' }]
  });
  assert.equal(restoreZapRunResults(results)['http://192.168.222.132:3000'].active.observations.length, 1);
});

test('aucune comparaison tant qu’un des deux modes manque, ou pour une autre cible', () => {
  const passiveOnly = recordZapRunResult({}, { target: TARGET, runId: 'p', scanMode: 'baseline', findings: [zap('1', `${TARGET}/`)] });
  assert.equal(compareZapRuns(passiveOnly, TARGET), null);
  const both = recordZapRunResult(passiveOnly, { target: TARGET, runId: 'a', scanMode: 'active', findings: [] });
  assert.equal(compareZapRuns(both, 'http://127.0.0.1:3000'), null);
  assert.ok(compareZapRuns(both, TARGET));
});

test('un nouveau run du même mode remplace le précédent de ce mode seulement', () => {
  let results = recordZapRunResult({}, { target: TARGET, runId: 'p1', scanMode: 'baseline', findings: [] });
  results = recordZapRunResult(results, { target: TARGET, runId: 'a1', scanMode: 'active', findings: [] });
  results = recordZapRunResult(results, { target: TARGET, runId: 'p2', scanMode: 'baseline', findings: [] });
  const entry = restoreZapRunResults(results)['http://192.168.222.132:3000'];
  assert.equal(entry.passive.runId, 'p2');
  assert.equal(entry.active.runId, 'a1');
});

// ------------------------------------------------------------------ rendu

function zapCard(html) {
  return (html.match(/<article class="dynamic-tool-card zap[\s\S]*?<\/article>/) || [''])[0];
}

test('la carte ZAP affiche la comparaison compacte quand passif et actif existent', () => {
  let zapRunResults = recordZapRunResult({}, { target: TARGET, runId: 'zap-p', scanMode: 'baseline', findings: [zap('10038', `${TARGET}/`), zap('10020', `${TARGET}/`)] });
  zapRunResults = recordZapRunResult(zapRunResults, { target: TARGET, runId: 'zap-a', scanMode: 'active', findings: [zap('10038', `${TARGET}/`), zap('40018', `${TARGET}/login`)] });
  const card = zapCard(renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'completed', mode: 'active' }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET, zapRunResults
  }), 'n', 'dynamic'));
  // Une ligne compacte, repliée par défaut ; le détail reste accessible dans le repli.
  assert.match(card, /<details class="zap-mode-comparison">\s*<summary aria-label="Comparaison des résultats passifs et actifs : Passive 2 · Active 2 · New in Active 1">/);
  assert.match(card, /<span class="zap-mode-summary">Passive 2 · Active 2 · New in Active 1<\/span>/);
  assert.doesNotMatch(card, /<details class="zap-mode-comparison" open/);
  const details = card.slice(card.indexOf('<details class="zap-mode-comparison">'), card.indexOf('</details>', card.indexOf('<details class="zap-mode-comparison">')));
  for (const [label, value] of [['Passive observations', 2], ['Active observations', 2], ['Common findings', 1], ['New in Active', 1], ['Only in Passive', 1]]) {
    assert.match(details, new RegExp(`<span>${label}</span><strong>${value}</strong>`));
  }
  assert.match(details, /Rule 40018/);
});

test('les cartes Dynamic Security gardent leur hauteur naturelle, alignées en haut', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed', dynamicTargetUrl: TARGET }), 'n', 'dynamic');
  assert.match(html, /\.dynamic-status-grid \{ display: grid; gap: 12px; align-items: start; \}/);
  assert.match(html, /\.dynamic-tool-card \{ display: grid; gap: 9px; align-content: start;/);
  assert.doesNotMatch(html, /\.dynamic-tool-card \{[^}]*height: 100%/);
});

test('sans run passif et actif pour la cible, la carte reste inchangée', () => {
  const card = zapCard(renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'completed', mode: 'active' }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET
  }), 'n', 'dynamic'));
  assert.doesNotMatch(card, /zap-mode-comparison/);
});

test('un finding ZAP dit s’il vient du passif ou de l’actif', () => {
  const findings = stampZapFindings([zap('40018', `${TARGET}/login`, { id: 'zap-1', severity: 'warning' })], { runId: 'zap-a', scanMode: 'active' });
  const html = renderDashboardHtml(buildDashboardModel(findings, [{ tool: 'ZAP', status: 'completed', mode: 'active' }], { scanStatus: 'completed' }), 'n', 'findings');
  assert.match(html, /data-scan-mode="active" data-run-id="zap-a"/);
  assert.match(html, /<span class="fact-badge zap-mode active">ZAP Actif<\/span>/);
});

test('l’historique local identifie le mode ZAP de chaque scan', () => {
  assert.equal(zapModeLabel({ scanners: [{ tool: 'ZAP', mode: 'baseline' }] }), 'ZAP Passif');
  assert.equal(zapModeLabel({ scanners: [{ tool: 'ZAP', scanMode: 'active' }] }), 'ZAP Actif');
  assert.equal(zapModeLabel({ scanners: [{ tool: 'Semgrep' }] }), '');
  const html = renderScanHistoryHtml([{ localId: 'l1', savedAt: '2026-09-12T21:17:15Z', workspace: 'juice-shop', findings: [], scanners: [{ tool: 'ZAP', mode: 'active', scanMode: 'active', runId: 'zap-a' }], dashboardOptions: {} }], [], '', 'n');
  assert.match(html, /<span class="zap-mode" data-scan-mode="active">ZAP Actif<\/span>/);
});

// --------------------------------------------------- repli d'exécution

test('« Détails d’exécution » garde son état ouvert à travers les rendus, sans toucher au sondage', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'active' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET,
    zapExecution: { target: TARGET, mode: 'active', startedAt: '2026-09-12T21:00:00Z', stages: [{ id: 'ACTIVE_SCANNING', status: 'RUNNING', progress: 37 }] }
  }), 'n', 'dynamic');
  // Rendu replié par le serveur : c'est le webview qui rouvre.
  assert.match(html, /<details class="zap-execution-details">/);
  assert.match(html, /\['details\.zap-execution-details', 'zapExecutionDetailsOpen'\], \['details\.zap-mode-comparison', 'zapModeComparisonOpen'\]/);
  assert.match(html, /document\.querySelectorAll\(selector\)/);
  assert.match(html, /readState\(\)\[key\] === true\) details\.open = true/);
  assert.match(html, /vscode\.setState\(\{ \.\.\.readState\(\), \[key\]: details\.open \}\)/);
});

test('l’extension marque runs et findings ZAP, sans changer l’exécution', () => {
  const extension = src('extension.js');
  assert.match(extension, /scanMode: zapScanMode\(scan\.mode\)/);
  assert.match(extension, /stampZapFindings\(normalizedFindings, \{ runId: dynamicEngines\.zap\?\.run\?\.id \|\| '', scanMode: scan\.mode \}\)/);
  assert.match(extension, /zapRunResults: recordZapRunResult\(currentDashboardOptions\.zapRunResults/);
});
