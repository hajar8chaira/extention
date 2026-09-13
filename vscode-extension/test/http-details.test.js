const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { renderHttpReplayHtml, renderSafeHttpRequestHtml, renderReplayConfirmationHtml } = require('../src/http-details');

// ------------------------------------------------ confirmation avant replay

const PREVIEW = Object.freeze({
  method: 'GET',
  path: '/rest/products/search?q=apple',
  url: 'http://192.168.222.132:3000/rest/products/search?q=apple',
  source: 'MITMPROXY',
  headers: [
    { name: 'host', value: '192.168.222.132:3000' },
    { name: 'user-agent', value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/152.0.0.0' },
    { name: 'cookie', value: '[REDACTED]' },
    { name: 'if-none-match', value: 'W/"399-Xmmlc"' }
  ],
  parameters: [{ location: 'query', name: 'q', value: 'apple' }],
  requestBody: ''
});

test('confirmation de replay : toutes les données de l’ancienne boîte restent visibles, structurées', () => {
  const html = renderReplayConfirmationHtml(PREVIEW, { isWrite: false, confirmLabel: 'Rejouer la requête', sensitiveHeaders: ['cookie'] }, 'nonce');
  assert.match(html, /Confirmer le replay de la requête/);
  // Méthode, chemin et URL assainie.
  assert.match(html, /<span class="method read">GET<\/span>/);
  assert.match(html, /\/rest\/products\/search\?q=apple/);
  assert.match(html, /http:\/\/192\.168\.222\.132:3000\/rest\/products\/search\?q=apple/);
  assert.match(html, /MITMPROXY/);
  // Chaque en-tête assaini, sous forme clé/valeur, la valeur masquée signalée.
  for (const header of PREVIEW.headers) assert.ok(html.includes(`<dt>${header.name}</dt>`), `en-tête ${header.name} absent`);
  assert.match(html, /<span class="redacted">\[REDACTED\]<\/span>/);
  assert.match(html, /1 masqué<\/span><span class="names">cookie<\/span>/);
  // Paramètres avec leur emplacement.
  assert.match(html, /<span class="location">query<\/span><span class="name">q<\/span><\/dt><dd>apple<\/dd>/);
  // Actions : même libellé d'action, et une annulation.
  assert.match(html, /id="confirm">Rejouer la requête<\/button>/);
  assert.match(html, /id="cancel">Annuler<\/button>/);
  assert.match(html, /aria-label="Fermer"/);
  // Une lecture ne porte pas l'avertissement des requêtes qui modifient l'état.
  assert.ok(!html.includes('peut modifier l’état de l’application'));
});

test('confirmation de replay : une requête d’écriture garde son avertissement et son libellé', () => {
  const html = renderReplayConfirmationHtml({ ...PREVIEW, method: 'POST', headers: [], parameters: [], requestBody: '{"password":"[REDACTED]"}' },
    { isWrite: true, confirmLabel: 'Confirmer et rejouer', sensitiveHeaders: [] }, 'nonce');
  assert.match(html, /Cette requête peut modifier l’état de l’application\./);
  assert.match(html, /<span class="method create">POST<\/span>/);
  assert.match(html, /id="confirm">Confirmer et rejouer<\/button>/);
  // États vides explicites, identiques aux textes de l'ancienne boîte.
  assert.match(html, /<p class="empty">Aucun<\/p>/);
  assert.match(html, /Aucun paramètre structuré affichable/);
  assert.match(html, /Corps assaini/);
});

test('confirmation de replay : contenu échappé, page fermée aux ressources externes, deux seuls messages', () => {
  const html = renderReplayConfirmationHtml({ ...PREVIEW, headers: [{ name: 'x-test', value: '<script>alert(1)</script>' }] },
    { confirmLabel: 'Rejouer la requête' }, 'n0nce');
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /default-src 'none'; style-src 'nonce-n0nce'; script-src 'nonce-n0nce';/);
  assert.ok(!/https?:\/\/(?!192\.168\.222\.132)/.test(html.replace(/http:\/\/192\.168\.222\.132[^<"]*/g, '')), 'aucune ressource externe');
  const types = [...html.matchAll(/send\('([a-zA-Z]+)'\)/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(types)].sort(), ['replayCancel', 'replayConfirm']);
  assert.match(html, /event\.key === 'Escape'\) send\('replayCancel'\)/);
});

test('confirmation de replay : le flux de replay garde exactement son contrat', () => {
  const extension = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const command = extension.match(/registerCommand\('securityCenter\.replayHttpScenario'[\s\S]*?\n  \}\)\);/)[0];
  // La confirmation intégrée remplace la boîte native, avec le même libellé d'action…
  assert.match(command, /const previewConfirmation = await confirmHttpReplay\(safePreview, \{/);
  assert.match(command, /confirmLabel: isWrite \? 'Confirmer et rejouer' : 'Rejouer la requête'/);
  // …et tout ce qui suit la décision est inchangé.
  assert.match(command, /if \(!previewConfirmation\) return;/);
  assert.ok(command.indexOf('confirmHttpReplay(') < command.indexOf('authorizeReplayTarget('), 'la confirmation précède toujours l’autorisation');
  assert.ok(command.indexOf('authorizeReplayTarget(') < command.indexOf('replayScenario('), 'l’autorisation précède toujours l’envoi');
  // Confirmer rend le libellé ; annuler, fermer ou Échap rendent `undefined`.
  const helper = extension.match(/function confirmHttpReplay\([\s\S]*?\n  \}/)[0];
  assert.match(helper, /message\?\.type === 'replayConfirm'\) settle\(confirmLabel\)/);
  assert.match(helper, /message\?\.type === 'replayCancel'\) settle\(undefined\)/);
  assert.match(helper, /panel\.onDidDispose\(\(\) => settle\(undefined\)\)/);
  // La boîte native d'origine reste le recours si la page ne peut pas s'ouvrir.
  assert.match(helper, /showInformationMessage\(fallbackMessage, \{ modal: true \}, confirmLabel\)/);
});

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
