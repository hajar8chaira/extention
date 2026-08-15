'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { HISTORY_LIMIT, appendLocalHistory, renderScanHistoryHtml } = require('../src/scan-history-page');

test('conserve les scans locaux les plus récents avec une limite', () => {
  let history = [];
  for (let index = 0; index < HISTORY_LIMIT + 3; index += 1) history = appendLocalHistory(history, { localId: `scan-${index}` });
  assert.equal(history.length, HISTORY_LIMIT);
  assert.equal(history[0].localId, `scan-${HISTORY_LIMIT + 2}`);
});

test('affiche les historiques local et backend dans une page autonome', () => {
  const html = renderScanHistoryHtml([{ localId: 'local-1', savedAt: '2026-08-11T18:00:00Z', workspace: 'juice-shop', findings: [{}], scanners: [{}], dashboardOptions: { scanStatus: 'completed' } }], [{ scan_id: 8, finished_at: '2026-08-11T17:00:00Z', workspace: 'juice-shop', finding_count: 12, scanner_count: 5 }], '', 'nonce');
  assert.match(html, /Historique des scans/);
  assert.match(html, /LOCAL/);
  assert.match(html, /BACKEND #8/);
  assert.match(html, /Ouvrir ce scan/);
});

test('applique le thème global clair à toute la page historique', () => {
  const html = renderScanHistoryHtml([], [], '', 'nonce', 'light');
  assert.match(html, /class="theme-light"/);
  assert.match(html, /html\{background:var\(--vscode-editor-background\)\}/);
  assert.match(html, /body\{[^}]*background:var\(--vscode-editor-background\)/);
  assert.match(html, /\.scan\{[^}]*background:var\(--vscode-sideBar-background/);
  assert.doesNotMatch(html, /#24462f|#263c62/);
  assert.match(html, /← Dashboard/);
  assert.match(html, /command:'openDashboard'/);
});

test('reste utile lorsque le backend est indisponible', () => {
  const html = renderScanHistoryHtml([], [], 'ECONNREFUSED', 'nonce');
  assert.match(html, /Backend indisponible/);
  assert.match(html, /ECONNREFUSED/);
});
