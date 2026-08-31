const test = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_BACKEND_URL, BACKEND_STATE, normalizeBackendUrl, resolveBackendUrl,
  isDefaultBackendUrl, classifyBackendError, isHealthPayload, probeBackend
} = require('../src/backend-config');
const { renderTrendReportHtml } = require('../src/trends');

/** Une configuration VS Code minimale : `get(key, fallback)`. */
const configuration = (values = {}) => ({
  get: (key, fallback) => (key in values ? values[key] : fallback)
});

const HEALTH_OK = { status: 'ok', service: 'security-center-backend' };

// ------------------------------------------------------------ source unique

test('l’adresse par défaut est déclarée une seule fois et résolue depuis les réglages', () => {
  assert.equal(DEFAULT_BACKEND_URL, 'http://127.0.0.1:8765');
  assert.equal(resolveBackendUrl(configuration()), DEFAULT_BACKEND_URL);
  assert.equal(
    resolveBackendUrl(configuration({ 'backend.url': 'http://10.0.0.5:9000/' })),
    'http://10.0.0.5:9000'
  );
});

test('une adresse invalide dans les réglages ne fait pas tomber l’extension', () => {
  assert.equal(resolveBackendUrl(configuration({ 'backend.url': 'pas une url' })), DEFAULT_BACKEND_URL);
  assert.equal(resolveBackendUrl(undefined), DEFAULT_BACKEND_URL);
});

test('des identifiants dans l’adresse sont refusés : la clé va dans SecretStorage', () => {
  assert.throws(() => normalizeBackendUrl('http://user:pass@127.0.0.1:8765'), /identifiants/);
  assert.throws(() => normalizeBackendUrl('ftp://127.0.0.1:8765'), /HTTP/);
  assert.throws(() => normalizeBackendUrl(''), /Renseignez/);
});

test('aucun code source ne réintroduit l’adresse en dur', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const extension = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // L'adresse existait a 28 emplacements ; elle n'a plus qu'une definition.
  assert.doesNotMatch(extension, /http:\/\/127\.0\.0\.1:8765/);
  assert.match(extension, /resolveBackendUrl\(/);
});

// ----------------------------------------------------------------- sondage

test('backend en ligne : /health nomme le service', async () => {
  const result = await probeBackend(DEFAULT_BACKEND_URL, { check: async () => HEALTH_OK });
  assert.equal(result.state, BACKEND_STATE.ONLINE);
  assert.equal(result.online, true);
  assert.equal(result.url, DEFAULT_BACKEND_URL);
});

test('backend hors ligne : ECONNREFUSED n’est pas masqué, et aucune commande n’est demandée à l’utilisateur', async () => {
  const result = await probeBackend(DEFAULT_BACKEND_URL, {
    check: async () => { throw new Error('connect ECONNREFUSED 127.0.0.1:8765'); }
  });
  assert.equal(result.state, BACKEND_STATE.OFFLINE);
  assert.equal(result.online, false);
  assert.match(result.hint, /Réessayez/);
  // Le backend local est démarré par l'extension : il n'y a plus de commande
  // Docker à copier, et le hint n'en propose aucune.
  assert.equal(result.startCommand, '');
  assert.doesNotMatch(result.hint, /docker/i);
});

test('backend distant hors ligne : aucune commande de démarrage local n’est proposée non plus', async () => {
  const result = await probeBackend('http://10.0.0.5:9000', {
    check: async () => { throw new Error('connect ECONNREFUSED 10.0.0.5:9000'); }
  });
  assert.equal(result.state, BACKEND_STATE.OFFLINE);
  assert.equal(result.startCommand, '');
});

test('backend en dépassement de délai est distingué de hors ligne', async () => {
  const result = await probeBackend(DEFAULT_BACKEND_URL, {
    check: async () => { throw new Error('ETIMEDOUT'); }
  });
  assert.equal(result.state, BACKEND_STATE.TIMEOUT);
  assert.notEqual(result.state, BACKEND_STATE.OFFLINE);
});

test('un socket qui répond n’est pas une preuve : réponse inattendue', async () => {
  const result = await probeBackend(DEFAULT_BACKEND_URL, {
    check: async () => ({ status: 'ok', service: 'un-autre-service' })
  });
  assert.equal(result.state, BACKEND_STATE.INVALID_RESPONSE);
  assert.equal(result.online, false);
  assert.equal(isHealthPayload({ status: 'ok', service: 'nginx' }), false);
  assert.equal(isHealthPayload(HEALTH_OK), true);
});

test('une clé d’API refusée est un état distinct', async () => {
  const result = await probeBackend(DEFAULT_BACKEND_URL, {
    check: async () => { throw new Error('Backend HTTP 401: Invalid or missing Security Center API key'); }
  });
  assert.equal(result.state, BACKEND_STATE.AUTH_ERROR);
});

test('une adresse non configurable est signalée comme non configurée', async () => {
  const result = await probeBackend('', { check: async () => HEALTH_OK });
  assert.equal(result.state, BACKEND_STATE.NOT_CONFIGURED);
});

test('la classification distingue les familles d’erreur', () => {
  assert.equal(classifyBackendError(new Error('connect ECONNREFUSED')), BACKEND_STATE.OFFLINE);
  assert.equal(classifyBackendError(new Error('ETIMEDOUT')), BACKEND_STATE.TIMEOUT);
  assert.equal(classifyBackendError(new Error('HTTP 403')), BACKEND_STATE.AUTH_ERROR);
  assert.equal(classifyBackendError(new Error('Le backend a renvoyé un JSON invalide.')), BACKEND_STATE.INVALID_RESPONSE);
});

test('l’adresse par défaut est reconnue quelle que soit sa forme', () => {
  assert.equal(isDefaultBackendUrl('http://127.0.0.1:8765/'), true);
  assert.equal(isDefaultBackendUrl('http://127.0.0.1:8766'), false);
  assert.equal(isDefaultBackendUrl('n’importe quoi'), false);
});

// ------------------------------------------- reutilisation de l'adresse

test('une adresse modifiée est celle que les domaines dépendants utilisent', async () => {
  const custom = configuration({ 'backend.url': 'http://10.0.0.5:9000' });
  const resolved = resolveBackendUrl(custom);
  let probed = '';
  await probeBackend(resolved, { check: async (url) => { probed = url; return HEALTH_OK; } });
  // Trends, Dynamic Security et Burp appellent tous probeBackend/resolveBackendUrl :
  // l'adresse sondee est celle des reglages, jamais la valeur par defaut.
  assert.equal(probed, 'http://10.0.0.5:9000');
  assert.notEqual(probed, DEFAULT_BACKEND_URL);
});

// --------------------------------------------------- Trends hors ligne

test('backend hors ligne : Trends n’affiche pas zéro mais « — »', () => {
  const html = renderTrendReportHtml(
    { latest: { active: 0, critical: 0, high: 0, medium: 0, low: 0 }, change: null, mttrHours: null, resolvedCount: 0, points: [] },
    'nonce', 'light', 'connect ECONNREFUSED 127.0.0.1:8765'
  );
  assert.match(html, /Backend indisponible/);
  assert.match(html, /id="kpi-active-val">—</);
  assert.match(html, /id="kpi-critical-val">—</);
  assert.match(html, /Historique indisponible/);
  // Le CTA doit conduire a la configuration, pas seulement inviter a reessayer.
  assert.match(html, /Configurer le backend/);
  assert.match(html, /Réessayer/);
});

test('backend en ligne : un vrai zéro observé reste un zéro', () => {
  const html = renderTrendReportHtml(
    { latest: { active: 0, critical: 0, high: 0, medium: 0, low: 0 }, change: null, mttrHours: null, resolvedCount: 0, points: [] },
    'nonce', 'light', ''
  );
  assert.match(html, /id="kpi-active-val">0</);
  assert.doesNotMatch(html, /Backend indisponible/);
});

test('aucune clé d’API n’est rendue dans la page de tendances', () => {
  const html = renderTrendReportHtml(
    { latest: { active: 3, critical: 1, high: 2, medium: 0, low: 0 }, change: null, mttrHours: 5, resolvedCount: 1, points: [] },
    'nonce', 'light', ''
  );
  assert.doesNotMatch(html, /apiKey|api_key|SECURITY_CENTER_API_KEY/i);
});
