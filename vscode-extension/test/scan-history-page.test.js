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
  assert.match(html, /class="theme-light[^"]*"/);
  assert.match(html, /html \{ background: var\(--sc-bg\); \}/);
  assert.match(html, /body \{[^}]*background: var\(--sc-bg\)/);
  assert.match(html, /\.scan \{[^}]*background: var\(--sc-surface\)/);
  assert.doesNotMatch(html, /#24462f|#263c62/);
  // La page vit maintenant dans le cadre applicatif : le retour au dashboard
  // passe par la navigation partagee, plus par un lien propre a la page.
  assert.match(html, /class="sc-internal-nav"/);
  assert.match(html, /data-command="securityCenter\.openDashboard"/);
  assert.doesNotMatch(html, /← Dashboard/);
  // L'ouverture d'un scan enregistre garde exactement le meme message.
  assert.match(html, /command: 'loadScan'/);
});

test('marque Scan History comme page courante dans la navigation partagée', () => {
  const html = renderScanHistoryHtml([], [], '', 'nonce', 'light');
  const active = [...html.matchAll(/<button class="sc-nav-item active"([^>]*)>/g)];
  assert.equal(active.length, 1, 'exactement un item doit porter l etat courant');
  assert.match(active[0][1], /data-command="securityCenter\.showScanHistoryPage"/);
  assert.match(active[0][1], /aria-current="page"/);
});

test('rend l historique dans les deux thèmes sans changer de structure', () => {
  const dark = renderScanHistoryHtml([], [], '', 'nonce', 'dark');
  assert.match(dark, /class="theme-dark[^"]*"/);
  assert.match(dark, /data-theme="dark"/);
  assert.match(dark, /class="sc-internal-nav"/);
});

test('reste utile lorsque le backend est indisponible', () => {
  const html = renderScanHistoryHtml([], [], 'ECONNREFUSED', 'nonce');
  assert.match(html, /Backend indisponible/);
  assert.match(html, /ECONNREFUSED/);
});
