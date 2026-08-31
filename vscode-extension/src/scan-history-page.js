'use strict';
const { renderSecurityCenterShell } = require('./security-center-shell');

const HISTORY_KEY = 'securityCenter.scanHistory.v1';
const HISTORY_LIMIT = 50;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function appendLocalHistory(existing, entry) {
  const history = Array.isArray(existing) ? existing : [];
  const normalized = { ...entry, localId: entry.localId || `local-${Date.now()}` };
  return [normalized, ...history.filter((item) => item.localId !== normalized.localId)].slice(0, HISTORY_LIMIT);
}

/** La presentation propre a l'historique. Le cadre fournit le reste. */
function historyStyles() {
  return `
    h2 { font-size: 13px; margin: 0; }
    p { margin: 0; color: var(--sc-muted); }
    .section-title { margin: 22px 0 10px; color: var(--sc-muted); font-size: 10px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; }
    .scan { display: flex; justify-content: space-between; gap: 20px; align-items: center; border: 1px solid var(--sc-border); background: var(--sc-surface); padding: 12px 14px; margin: 8px 0; border-radius: var(--sc-radius-md); }
    .scan h2 { margin: 5px 0 3px; }
    .scan p { font-size: 11px; }
    .origin { font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 999px; background: var(--sc-primary-soft); color: var(--sc-primary); }
    .state { text-transform: uppercase; font-size: 10px; margin-top: 4px; }
    button { background: var(--sc-primary); color: var(--vscode-button-foreground, #fff); border: 0; border-radius: var(--sc-radius-sm); padding: 8px 13px; cursor: pointer; white-space: nowrap; font: 600 11px var(--vscode-font-family); }
    button:hover { background: var(--sc-primary-hover); }
    .history-count { color: var(--sc-muted); font-size: 11px; font-weight: 700; }
    .empty, .warning { padding: 14px; border: 1px dashed var(--sc-border); border-radius: var(--sc-radius-md); color: var(--sc-muted); font-size: 11px; }
    .warning { border-color: var(--vscode-inputValidation-warningBorder, var(--sc-high)); }
    @media (max-width: 620px) { .scan { align-items: stretch; flex-direction: column; } }`;
}

/**
 * L'ouverture d'un scan enregistre reste exactement le meme message qu'avant
 * (`loadScan`, meme `source`, meme `id`) : seule la mise en page change.
 */
function historyScript() {
  return `
    const vscode = window.__scShellApi || acquireVsCodeApi();
    document.querySelectorAll('button[data-source]').forEach(function (button) {
      button.addEventListener('click', function () {
        vscode.postMessage({ command: 'loadScan', source: button.dataset.source, id: button.dataset.id });
      });
    });`;
}

function renderScanHistoryHtml(localScans, backendScans, backendError, nonce, selectedTheme = 'light', assets = {}) {
  const localCards = (localScans || []).map((scan) => `<article class="scan"><div><span class="origin">LOCAL</span><h2>${escapeHtml(new Date(scan.savedAt).toLocaleString('fr-FR'))}</h2><p>${escapeHtml(scan.workspace || 'Projet')} • ${Number(scan.findings?.length || 0)} résultat(s) • ${Number(scan.scanners?.length || 0)} scanner(s)</p><p class="state">${escapeHtml(scan.dashboardOptions?.scanStatus || 'terminé')}</p></div><button data-source="local" data-id="${escapeHtml(scan.localId)}">Ouvrir ce scan</button></article>`).join('');
  const backendCards = (backendScans || []).map((scan) => `<article class="scan"><div><span class="origin">BACKEND #${escapeHtml(scan.scan_id)}</span><h2>${escapeHtml(new Date(scan.finished_at).toLocaleString('fr-FR'))}</h2><p>${escapeHtml(scan.workspace)} • ${Number(scan.finding_count || 0)} résultat(s) • ${Number(scan.scanner_count || 0)} scanner(s)</p></div><button data-source="backend" data-id="${escapeHtml(scan.scan_id)}">Ouvrir ce scan</button></article>`).join('');
  const total = (localScans || []).length + (backendScans || []).length;
  const content = `
    <h2 class="section-title">Sauvegardes locales</h2>
    ${localCards || '<div class="empty">Aucun scan local enregistré. Le prochain scan apparaîtra automatiquement ici.</div>'}
    <h2 class="section-title">Historique du backend</h2>
    ${backendError
      ? `<div class="warning">Backend indisponible : ${escapeHtml(backendError)}. Les sauvegardes locales restent accessibles.</div>`
      : (backendCards || '<div class="empty">Aucun scan enregistré dans le backend.</div>')}`;
  return renderSecurityCenterShell({
    surface: 'scan-history',
    nonce,
    theme: selectedTheme,
    title: 'Historique des scans',
    subtitle: 'Tous les scans enregistrés pour ce projet',
    headerActions: `<span class="history-count">${total} scan(s)</span>`,
    content,
    styles: historyStyles(),
    script: historyScript(),
    csp: `default-src 'none'; img-src ${assets.cspSource || "'none'"}; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';`,
    brandLogoUri: assets.brandLogoUri || '',
    cspSource: assets.cspSource || '',
  });
}

/**
 * Presents a locally persisted scan under the shape the comparison already reads.
 *
 * The two histories are stored differently — the backend keeps
 * `{ scan_id, result: {...} }`, a local save keeps `{ localId, savedAt, ... }` —
 * so a local entry has to be presented in the shape `compareScans()` expects
 * rather than the comparison learning about a second format. Nothing is
 * recomputed and nothing is merged: the findings and the scanner statuses are
 * passed through exactly as they were persisted, which is what keeps the
 * comparison semantics identical whichever source supplied the scans.
 *
 * The persisted entry is never mutated — a new object is returned.
 */
function localScanAsComparable(entry) {
  if (!entry || !entry.localId) return null;
  return {
    scan_id: entry.localId,
    finished_at: entry.savedAt || '',
    workspace: entry.workspace || '',
    git_commit: entry.dashboardOptions?.gitCommit || '',
    source: 'local',
    result: {
      finished_at: entry.savedAt || '',
      workspace: entry.workspace || '',
      findings: Array.isArray(entry.findings) ? entry.findings : [],
      scanners: Array.isArray(entry.scanners) ? entry.scanners : []
    }
  };
}

/** Only saves that carry the evidence a comparison needs can be compared. */
function comparableLocalScans(history = []) {
  return (Array.isArray(history) ? history : [])
    .map(localScanAsComparable)
    .filter((scan) => scan && scan.result.scanners.length > 0);
}

module.exports = {
  HISTORY_KEY, HISTORY_LIMIT, appendLocalHistory, renderScanHistoryHtml,
  localScanAsComparable, comparableLocalScans
};
