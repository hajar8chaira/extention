const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { detectLocalZap, alertsToReport, openApiImportRequest } = require('../src/zap-local');

test('détecte automatiquement l’installation ZAP Windows', () => {
  if (process.platform === 'win32') assert.match(detectLocalZap(), /zap\.bat$/i);
});

test('prépare un import OpenAPI local par URL ou fichier', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'zap-openapi-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'openapi.json');
  fs.writeFileSync(file, '{}');
  assert.deepEqual(openApiImportRequest('http://127.0.0.1:3000/openapi.json', 'http://127.0.0.1:3000'), {
    action: 'importUrl', params: { url: 'http://127.0.0.1:3000/openapi.json', hostOverride: 'http://127.0.0.1:3000' }
  });
  assert.deepEqual(openApiImportRequest(file, 'http://127.0.0.1:3000'), {
    action: 'importFile', params: { file, target: 'http://127.0.0.1:3000' }
  });
  assert.throws(() => openApiImportRequest('https://example.com/openapi.json', 'http://127.0.0.1:3000'), /distante est interdite/);
});

test('convertit les alertes REST ZAP vers le rapport normalisé existant', () => {
  const report = alertsToReport([
    { alertRef: '10038', alert: 'CSP Header Not Set', riskcode: '2', confidence: '2', cweid: '693', url: 'http://127.0.0.1:3000/a', method: 'GET', evidence: 'header' },
    { alertRef: '10038', alert: 'CSP Header Not Set', riskcode: '2', confidence: '2', cweid: '693', url: 'http://127.0.0.1:3000/b', method: 'GET' }
  ]);
  assert.equal(report.site[0].alerts.length, 1);
  assert.equal(report.site[0].alerts[0].instances.length, 2);
  assert.equal(report.site[0].alerts[0].pluginid, '10038');
});
