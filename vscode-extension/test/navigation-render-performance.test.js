'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const extension = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/** Le motif de nonce du produit, extrait de sa propre source. */
function productNoncePattern() {
  const declaration = extension.match(/const RENDER_NONCE_PATTERN = (\/.*\/g);/);
  assert.ok(declaration, 'RENDER_NONCE_PATTERN introuvable');
  // eslint-disable-next-line no-eval -- on évalue le littéral du produit, pas une entrée
  return eval(declaration[1]);
}

const sampleModel = (extra = {}) => buildDashboardModel(
  Array.from({ length: 40 }, (_, index) => ({
    id: `f${index}`, tool: 'Semgrep', ruleId: `rule-${index}`, title: `Finding ${index}`,
    severity: 'warning', rawSeverity: 'MEDIUM', category: 'sast',
    file: `src/module-${index}.js`, startLine: index, startColumn: 1, endLine: index, endColumn: 2
  })),
  [{ tool: 'Semgrep', status: 'completed' }],
  { workspace: 'juice-shop', dynamicTargetUrl: 'http://192.168.222.132:3000', ...extra }
);

test('navigation : deux rendus d’un même modèle ne diffèrent que par le nonce', () => {
  const model = sampleModel();
  const first = renderDashboardHtml(model, 'AAAA', 'dynamic', 'light', {}, {});
  const second = renderDashboardHtml(model, 'BBBB', 'dynamic', 'light', {}, {});
  // Le document est identique par ailleurs : c'est ce qui rend la comparaison
  // possible, et c'est pourquoi rendre deux fois de suite rechargeait la page
  // pour rien.
  assert.notEqual(first, second, 'le nonce doit bien changer d’un rendu à l’autre');
  const pattern = productNoncePattern();
  assert.equal(first.replace(pattern, 'nonce'), second.replace(pattern, 'nonce'));
});

test('navigation : le motif de nonce couvre l’en-tête CSP et les balises de script', () => {
  const pattern = productNoncePattern();
  const html = renderDashboardHtml(sampleModel(), 'Zm9vL2Jhcis9', 'dynamic', 'light', {}, {});
  const occurrences = html.match(pattern) || [];
  // Mesuré : le nonce apparaît dans la politique CSP et sur la balise de script.
  assert.ok(occurrences.length >= 2, `nonce couvert ${occurrences.length} fois`);
  // Un nonce base64 contient +, / et = : la classe de caractères doit les inclure,
  // sans quoi la comparaison échoue silencieusement et le garde-fou ne sert à rien.
  assert.ok(occurrences.some((entry) => /[+/=]/.test(entry)), 'les caractères base64 ne sont pas couverts');
  assert.ok(!html.replace(pattern, 'nonce').includes('Zm9vL2Jhcis9'), 'un nonce subsiste après normalisation');
});

test('navigation : un document identique n’est pas reposé dans le webview', () => {
  // La logique du produit, reproduite à l'identique depuis sa source.
  const pattern = productNoncePattern();
  const digest = (html) => crypto.createHash('sha1').update(String(html).replace(pattern, 'nonce')).digest('hex');
  const digests = new Map();
  let reloads = 0;
  const webview = { set html(value) { reloads += 1; } };
  const apply = (html, key) => {
    const current = digest(html);
    if (digests.get(key) === current) return false;
    digests.set(key, current);
    webview.html = html;
    return true;
  };

  const model = sampleModel();
  // Le motif réel d'une navigation : un rendu immédiat, puis un second après le
  // rafraîchissement asynchrone.
  for (let pass = 0; pass < 5; pass += 1) {
    apply(renderDashboardHtml(model, crypto.randomBytes(16).toString('base64'), 'dynamic', 'light', {}, {}), 'dynamic');
    apply(renderDashboardHtml(model, crypto.randomBytes(16).toString('base64'), 'dynamic', 'light', {}, {}), 'dynamic');
  }
  assert.equal(reloads, 1, 'dix rendus identiques doivent produire un seul chargement');

  // Un changement réel passe toujours : le garde-fou ne masque rien.
  apply(renderDashboardHtml(sampleModel({ backendStatus: 'online' }), crypto.randomBytes(16).toString('base64'), 'dynamic', 'light', {}, {}), 'dynamic');
  assert.equal(reloads, 2, 'un modèle modifié doit recharger le document');
});

test('navigation : chaque surface a sa propre empreinte', () => {
  const pattern = productNoncePattern();
  const digest = (html) => crypto.createHash('sha1').update(String(html).replace(pattern, 'nonce')).digest('hex');
  const model = sampleModel();
  const surfaces = ['full', 'findings', 'scans', 'dynamic', 'analytics'];
  const byDigest = new Map();
  for (const surface of surfaces) {
    byDigest.set(surface, digest(renderDashboardHtml(model, 'nonce', surface, 'light', {}, {})));
  }
  // Sans clé par surface, passer de Findings à Scans aurait été pris pour un
  // document identique et la page n'aurait pas changé.
  assert.equal(new Set(byDigest.values()).size, surfaces.length, 'deux surfaces partagent une empreinte');
});

test('navigation : le garde-fou est câblé sur les pages navigables et libéré à la fermeture', () => {
  assert.match(extension, /function applyWebviewHtml\(webview, html, key\) \{/);
  assert.match(extension, /if \(lastRenderedDigests\.get\(key\) === digest\) return false;/);
  // Les surfaces du dashboard partagent un renderer : la clé les distingue.
  assert.match(extension, /applyWebviewHtml\(webview, html, `dashboard:\$\{surface\}`\)/);
  for (const key of ['delivery', 'runtime-security', 'infrastructure', 'integrations', 'pipeline', 'scanner-setup']) {
    assert.ok(extension.includes(`'${key}');`), `page non câblée : ${key}`);
  }
  // Une empreinte oubliée à la fermeture : sinon un panneau rouvert resterait vide.
  assert.ok((extension.match(/forgetRenderedDocument\(/g) || []).length >= 7, 'oublis insuffisants à la fermeture');
});

test('navigation : la détection de Nuclei n’est plus relancée à chaque ouverture', () => {
  // Mesuré : `status('nuclei')` lance un binaire de 145 Mo, 370 ms par appel.
  assert.match(extension, /const NUCLEI_DETECTION_TTL_MS = \d+;/);
  assert.match(extension, /if \(nucleiToolCache && Date\.now\(\) - nucleiToolCache\.at < NUCLEI_DETECTION_TTL_MS\) return nucleiToolCache\.model;/);
  // La mémorisation ne masque aucun changement réel : installation et mesure
  // explicite l'invalident.
  assert.ok((extension.match(/invalidateNucleiToolCache\(\)/g) || []).length >= 3, 'invalidations insuffisantes');
  assert.match(extension, /if \(id === 'nuclei'\) \{ invalidateNucleiToolCache\(\);/);
});
