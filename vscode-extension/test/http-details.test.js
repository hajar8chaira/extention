const test = require('node:test');
const assert = require('node:assert/strict');
const { renderHttpReplayHtml, renderSafeHttpRequestHtml } = require('../src/http-details');

test('affiche une preuve de replay HTTP et échappe les corps', () => {
  const html = renderHttpReplayHtml({
    name: 'GET /health', source: 'har',
    request: { method: 'GET', url: 'http://127.0.0.1:3000/health', sensitive_headers: ['authorization'] }
  }, {
    statusCode: 200,
    durationMs: 123,
    linkedFindingsBefore: 2,
    linkedFindingsAfter: null,
    body: '<script>alert(1)</script>',
    comparison: { originalStatusCode: 200, statusChanged: false, bodyChanged: true }
  }, 'nonce');
  assert.match(html, /Réponse modifiée/);
  assert.match(html, /authorization/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /123 ms/);
  assert.match(html, /Findings liés avant/);
  assert.match(html, />2<\/div>/);
  assert.match(html, /non évalué — aucun nouveau scan/);
  assert.match(html, /ne prouvent pas à eux seuls/);
});

test('affiche une requête HTTP complète uniquement sous forme assainie', () => {
  const html = renderSafeHttpRequestHtml({
    method: 'POST', path: '/api/login', url: 'http://127.0.0.1:3000/api/login', source: 'BURP', duration: '12 ms',
    headers: [{ name: 'authorization', value: '[REDACTED]' }], responseHeaders: [{ name: 'set-cookie', value: '[REDACTED]' }],
    parameters: [{ location: 'body', name: 'password', value: '[REDACTED]' }], requestBody: '{"password":"[REDACTED]"}',
    statusCode: 200, responseType: 'application/json', responsePreview: '{}', safeRequest: 'POST /api/login\nauthorization: [REDACTED]',
    linkedFindings: [{ index: 1, severity: 'HIGH', title: 'Auth weakness', source: 'ZAP' }]
  }, 'nonce');
  assert.match(html, /Corps assaini de la requête/);
  assert.match(html, /Auth weakness/);
  assert.match(html, /Copier la requête assainie/);
  assert.match(html, /Rejouer la requête/);
  assert.doesNotMatch(html, /Bearer secret-value/);
});

test('affiche la vulnérabilité corrigée liée à la preuve', () => {
  const html = renderHttpReplayHtml(
    { name: 'POST local', source: 'burp', request: { method: 'POST', url: 'http://127.0.0.1:3000/api/items', sensitive_headers: [] } },
    { statusCode: 200, body: '{}', comparison: { originalStatusCode: 200, statusChanged: false, bodyChanged: false } },
    'nonce',
    { title: 'IDOR panier', tool: 'ZAP', triageStatus: 'fixed' }
  );
  assert.match(html, /Preuve liée à la correction/);
  assert.match(html, /IDOR panier/);
  assert.match(html, /statut fixed/);
});
