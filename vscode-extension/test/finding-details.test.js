const test = require('node:test');
const assert = require('node:assert/strict');
const { renderFindingDetailsHtml } = require('../src/finding-details');

test('affiche les éléments exploitables d’une alerte ZAP', () => {
  const html = renderFindingDetailsHtml({
    tool: 'ZAP', title: 'Missing CSP', rawSeverity: 'MEDIUM', confidence: 'high',
    method: 'GET', endpoint: 'http://127.0.0.1:3000/login', parameter: 'q',
    evidence: 'unsafe-inline', description: 'Header absent', solution: 'Ajouter CSP',
    ruleId: '10038', cwe: 'CWE-693', helpUri: 'https://www.zaproxy.org/'
  }, 'nonce');
  assert.match(html, /GET/);
  assert.match(html, /127\.0\.0\.1:3000\/login/);
  assert.match(html, /unsafe-inline/);
  assert.match(html, /Ajouter CSP/);
  assert.match(html, /Synthèse Security Center pour le développeur/);
  assert.match(html, /Impact possible/);
  assert.match(html, /Plan de correction/);
  assert.match(html, /Détails techniques du scanner/);
});

test('conserve le contexte HTTP et affiche uniquement les preuves réellement liées', () => {
  const html = renderFindingDetailsHtml({ tool: 'ZAP', title: 'CORS', rawSeverity: 'LOW', ruleId: 'cors' }, 'nonce', {
    backTrafficIndex: 2,
    relatedTraffic: [{ index: 2, method: 'GET', path: '/api/users', status: 200, source: 'burp' }]
  });
  assert.match(html, /Retour à la requête HTTP/);
  assert.match(html, /Preuves HTTP associées/);
  assert.match(html, /GET \/api\/users/);
  assert.match(html, /Statut : 200/);
  assert.match(html, /backToHttpRequest/);
  assert.match(html, /openHttpRequest/);
  assert.match(html, /var\(--vscode-editor-background\)/);
  assert.match(html, /class="theme-light"/);
  assert.match(html, /--vscode-editor-background:#f8f9fb/);
});

test('affiche la correction Ollama seulement pour un finding relié au code local', () => {
  const withFile = renderFindingDetailsHtml({ tool: 'Semgrep', title: 'XSS', rawSeverity: 'HIGH', confidence: 'high', ruleId: 'xss', absolutePath: 'C:\\repo\\app.js' }, 'nonce');
  assert.match(withFile, /Proposer une correction avec Ollama/);
  assert.match(withFile, /generateAiFix/);
  assert.match(withFile, /Demande envoyée à Ollama/);
  assert.match(withFile, /aiFixStatus/);
  const withoutFile = renderFindingDetailsHtml({ tool: 'ZAP', title: 'Header', rawSeverity: 'LOW', confidence: 'medium', ruleId: 'header' }, 'nonce');
  assert.match(withoutFile, /aucun fichier source local/);
  const relativeFile = renderFindingDetailsHtml({ tool: 'Semgrep', title: 'XSS', rawSeverity: 'HIGH', confidence: 'high', ruleId: 'xss', file: 'src/app.js' }, 'nonce');
  assert.match(relativeFile, /Proposer une correction avec Ollama/);
});

test('échappe les données venant du scanner', () => {
  const html = renderFindingDetailsHtml({
    tool: 'ZAP', title: '<script>alert(1)</script>', rawSeverity: 'LOW',
    ruleId: '1', endpoint: 'http://127.0.0.1'
  }, 'nonce');
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /Synthèse Security Center/);
  assert.match(html, /Interprétation prudente générée/);
  assert.match(html, /validation manuelle/);
  assert.match(html, /Examiner l’endpoint et la réponse associés/);
});

test('affiche les versions et la correction d’une CVE Trivy', () => {
  const html = renderFindingDetailsHtml({
    tool: 'Trivy', title: 'CVE-2026-0001 — demo', rawSeverity: 'HIGH', confidence: 'high',
    ruleId: 'CVE-2026-0001', category: 'dependency', packageName: 'demo',
    installedVersion: '1.0.0', fixedVersion: '1.0.1', target: 'juice-shop:latest',
    description: 'Dépendance vulnérable', references: ['https://example.test/cve']
  }, 'nonce');
  assert.match(html, /Version installée/);
  assert.match(html, /1\.0\.0/);
  assert.match(html, /1\.0\.1/);
  assert.match(html, /juice-shop:latest/);
  assert.doesNotMatch(html, /rapport baseline ZAP/);
});

test('réutilise la fiche de dépendance pour OSV-Scanner', () => {
  const html = renderFindingDetailsHtml({
    tool: 'OSV-Scanner', title: 'CVE-2026-1234 — demo', rawSeverity: 'HIGH',
    ruleId: 'CVE-2026-1234', category: 'dependency', packageName: 'demo',
    installedVersion: '1.0.0', fixedVersion: '1.0.1', target: 'package-lock.json'
  }, 'nonce');
  assert.match(html, /Package/);
  assert.match(html, /Version corrigée/);
  assert.match(html, /1\.0\.1/);
});

test('affiche le commit historique Gitleaks sans valeur secrète', () => {
  const html = renderFindingDetailsHtml({
    tool: 'Gitleaks', title: 'Clé interne', ruleId: 'internal-key', file: 'config.js',
    startLine: 4, rawSeverity: 'HIGH', commit: 'a520e158cb65c43d24e2c55d84f09b05a2511a03',
    confidence: 'high', triageStatus: 'new', sourceContext: 'production'
  }, 'nonce');
  assert.match(html, /Commit d’introduction/);
  assert.match(html, /a520e158cb65c43d24e2c55d84f09b05a2511a03/);
  assert.match(html, /valeur du secret est volontairement masquée/);
});
