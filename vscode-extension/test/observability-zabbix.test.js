'use strict';

/**
 * Phase O3 — Zabbix.
 *
 * Zabbix is the test of whether Infrastructure is provider-neutral or merely
 * Prometheus-shaped. It shares nothing with the first adapter: one JSON-RPC
 * endpoint, a mandatory bearer token, numeric host ids, template-defined item
 * keys, and errors returned as HTTP 200 with a JSON-RPC error body. Each of
 * those is asserted here, because each is a place where reusing Prometheus's
 * assumptions would have produced something that looked right and lied.
 *
 * Every value is invented. No address, token, host id or item from any real
 * deployment appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  zabbixAdapter, API_PATH, LIMITS, ZabbixApiError, candidateSearchKeys,
  availabilityOf, entitiesFrom, inventoryFrom, metricFor, selectEntity, classifyFailure
} = require('../src/integrations/observability-zabbix');
const {
  OBSERVABILITY_PROVIDERS, observabilityAdapter, isSupportedObservabilityProvider,
  supportedObservabilityProviders
} = require('../src/integrations/observability');
const {
  CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON, PROVIDER_STATUS,
  assertObservabilityAdapter, resolveCapabilities
} = require('../src/integrations/observability-contract');
const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const markup = (html) => html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));

const FICTIONAL = Object.freeze({
  frontend: 'https://zabbix.example.invalid/zabbix',
  token: 'zabbix-fixture-api-token',
  hostA: '90001',
  hostB: '90002',
  nameA: 'fixture-host-one',
  nameB: 'fixture-host-two'
});

const config = (extra = {}) => ({ url: FICTIONAL.frontend, ...extra });
const secrets = { apiToken: FICTIONAL.token };

/** A fake Zabbix that answers per JSON-RPC method. */
function server(answers = {}) {
  const calls = [];
  const request = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : {};
    calls.push({ url, options, body, method: body.method });
    const answer = answers[body.method];
    if (answer instanceof Error) throw answer;
    if (typeof answer === 'function') return { jsonrpc: '2.0', result: answer(body), id: body.id };
    if (answer && answer.error) return { jsonrpc: '2.0', error: answer.error, id: body.id };
    return { jsonrpc: '2.0', result: answer === undefined ? [] : answer, id: body.id };
  };
  return { calls, request };
}

const host = (id, name, overrides = {}) => ({
  hostid: id, host: name, name, status: '0',
  interfaces: [{ available: '1', ip: '198.51.100.1', port: '10050' }],
  ...overrides
});

const item = (key, lastvalue, units = '%') => ({
  itemid: `i-${key}`, key_: key, lastvalue: String(lastvalue), units, value_type: '0', name: key
});

// ===========================================================================
// Contract and registry
// ===========================================================================

test('zabbix : l adaptateur respecte le contrat observabilite', () => {
  assert.doesNotThrow(() => assertObservabilityAdapter(zabbixAdapter));
  assert.equal(observabilityAdapter('zabbix'), zabbixAdapter);
  assert.equal(isSupportedObservabilityProvider('zabbix'), true);
  // Supporte veut dire « adosse a un adaptateur », pas « present dans une
  // liste ecrite le jour ou celui-ci a ete ajoute ».
  assert.ok(supportedObservabilityProviders().some((provider) => provider.id === 'zabbix'));
  for (const provider of supportedObservabilityProviders()) {
    assert.notEqual(observabilityAdapter(provider.id), null, provider.id);
  }
  const provider = OBSERVABILITY_PROVIDERS.find((entry) => entry.id === 'zabbix');
  assert.equal(provider.implemented, true);
  assert.equal(provider.configurationFields.length, 3);
});

test('zabbix : le schema est celui de Zabbix, pas celui de Prometheus', () => {
  const ids = zabbixAdapter.configurationFields.map((field) => field.id);
  assert.deepEqual(ids, ['url', 'apiToken', 'allowSelfSigned']);
  const token = zabbixAdapter.configurationFields.find((field) => field.id === 'apiToken');
  assert.equal(token.secret, true);
  assert.equal(token.required, true, 'Zabbix exige un jeton, Prometheus non');
  // Aucun champ emprunte a l autre adaptateur.
  const prometheus = observabilityAdapter('prometheus').configurationFields.map((field) => field.id);
  assert.equal(prometheus.includes('bearerToken'), true);
  assert.equal(ids.includes('bearerToken'), false);
});

test('zabbix : rien de Prometheus ne fuit dans l adaptateur, ni l inverse', () => {
  const zabbix = source('src/integrations/observability-zabbix.js');
  for (const foreign of ['PromQL', '/api/v1/query', '/api/v1/targets', 'node_cpu_seconds_total', 'node_memory_', 'node_filesystem_', 'mountpoint']) {
    assert.ok(!zabbix.includes(foreign), `${foreign} n appartient pas a Zabbix`);
  }
  const prometheus = source('src/integrations/observability-prometheus.js');
  for (const foreign of ['api_jsonrpc', 'host.get', 'item.get', 'hostid', 'lastvalue']) {
    assert.ok(!prometheus.includes(foreign), `${foreign} n appartient pas a Prometheus`);
  }
});

// ===========================================================================
// Transport and authentication
// ===========================================================================

test('zabbix : une seule entree JSON-RPC, jeton en en-tete', async () => {
  const { calls, request } = server({ 'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)], 'item.get': [] });
  await zabbixAdapter.fetchStatus(config(), secrets, { request });

  assert.ok(calls.length > 0);
  for (const call of calls) {
    assert.ok(call.url.endsWith(API_PATH), call.url);
    assert.equal(call.options.method, 'POST');
    assert.equal(call.options.headers.authorization, `Bearer ${FICTIONAL.token}`);
    assert.match(call.options.headers['content-type'], /json-rpc/);
    assert.doesNotMatch(call.url, new RegExp(FICTIONAL.token));
    assert.equal(call.body.jsonrpc, '2.0');
    // Le jeton ne voyage jamais dans le corps : la propriete `auth` a disparu.
    assert.equal('auth' in call.body, false);
    assert.equal('auth' in (call.body.params || {}), false);
  }
});

test('zabbix : sans URL ou sans jeton, aucune requete n est emise', async () => {
  for (const [conf, sec] of [[{}, secrets], [config(), {}]]) {
    const { calls, request } = server({ 'host.get': [] });
    const model = await zabbixAdapter.fetchStatus(conf, sec, { request });
    assert.equal(calls.length, 0);
    assert.equal(model.status, PROVIDER_STATUS.NOT_CONFIGURED);
  }
});

test('zabbix : un echec d authentification arrive en HTTP 200, dans le corps', async () => {
  // C est la difference qui compte : le transport ne verra jamais de 401.
  const { request } = server({
    'host.get': { error: { code: -32602, message: 'Not authorised.', data: 'Session terminated, re-login, please.' } }
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });
  assert.equal(model.status, PROVIDER_STATUS.AUTH_ERROR);
  assert.match(model.message, /rejected this API token/);
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.ERROR);
});

test('zabbix : chaque classe d echec est distinguee', () => {
  assert.equal(classifyFailure(new ZabbixApiError({ code: -32602, message: 'Not authorised.' })), 'auth-error');
  assert.equal(classifyFailure(new ZabbixApiError({ code: -32602, message: 'Invalid params.' })), 'api-error');
  assert.equal(classifyFailure({ code: 'TIMEOUT' }), 'timeout');
  assert.equal(classifyFailure({ code: 'HTTP_ERROR', message: 'Service externe HTTP 404.' }), 'not-found');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'self-signed certificate in certificate chain' }), 'tls-error');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'connect ECONNREFUSED' }), 'unreachable');
  assert.equal(classifyFailure({ code: 'MALFORMED' }), 'malformed');
});

test('zabbix : injoignable, expire ou introuvable se distinguent dans le modele', async () => {
  const cases = [
    [new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE'), PROVIDER_STATUS.OFFLINE],
    [new IntegrationHttpError('slow', 'TIMEOUT'), PROVIDER_STATUS.TIMEOUT],
    [new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR'), PROVIDER_STATUS.OFFLINE]
  ];
  for (const [error, expected] of cases) {
    const { request } = server({ 'host.get': error });
    const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });
    assert.equal(model.status, expected, error.message);
    assert.ok(model.message);
  }
});

test('zabbix : une reponse malformee ne devient pas un inventaire credible', async () => {
  for (const answer of [null, 'nonsense', { unexpected: true }]) {
    const { request } = server({ 'host.get': answer });
    const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });
    assert.deepEqual(model.entities, []);
    assert.equal(model.inventory.total, 0);
  }
});

test('zabbix : TLS strict par defaut, relache seulement sur un vrai booleen', async () => {
  const strict = server({ 'host.get': [] });
  await zabbixAdapter.fetchStatus(config(), secrets, { request: strict.request });
  assert.equal(strict.calls[0].options.tls, undefined);

  for (const value of ['true', 1, 'yes', {}]) {
    const io = server({ 'host.get': [] });
    await zabbixAdapter.fetchStatus(config({ allowSelfSigned: value }), secrets, { request: io.request });
    assert.equal(io.calls[0].options.tls, undefined, JSON.stringify(value));
  }

  const relaxed = server({ 'host.get': [] });
  await zabbixAdapter.fetchStatus(config({ allowSelfSigned: true }), secrets, { request: relaxed.request });
  assert.deepEqual(relaxed.calls[0].options.tls, { allowSelfSigned: true });

  // Et rien de global, ni ici ni chez le voisin.
  for (const file of ['src/integrations/observability-zabbix.js', 'src/integrations/observability-prometheus.js']) {
    assert.doesNotMatch(source(file), /NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized/);
  }
});

test('zabbix : le jeton ne survit ni dans le modele ni dans le HTML', async () => {
  const { request } = server({ 'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)], 'item.get': [item('system.cpu.util', 12)] });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });
  assert.doesNotMatch(JSON.stringify(model), new RegExp(FICTIONAL.token));

  const html = renderInfrastructurePageHtml({
    prometheus: { ...model, values: config(), secretsConfigured: { apiToken: true } }, openConfig: true
  }, 'n', 'light');
  assert.doesNotMatch(html, new RegExp(FICTIONAL.token));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
});

// ===========================================================================
// Host discovery
// ===========================================================================

test('zabbix : les hotes sont decouverts, jamais saisis', async () => {
  const { calls, request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)],
    'item.get': []
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });

  const discovery = calls.find((call) => call.method === 'host.get');
  assert.ok(discovery, 'la decouverte est une requete, pas une configuration');
  assert.equal(discovery.body.params.limit, LIMITS.HOSTS, 'bornee');
  assert.deepEqual(discovery.body.params.selectInterfaces, ['available', 'ip', 'dns', 'port']);
  // L identifiant reste interne ; le nom lisible est ce qui remonte.
  assert.equal(model.entities[0].id, FICTIONAL.hostA);
  assert.equal(model.entities[0].name, FICTIONAL.nameA);
  // Aucun identifiant d hote n est demande a l utilisateur.
  assert.equal(zabbixAdapter.configurationFields.some((field) => /host/i.test(field.id)), false);
});

test('zabbix : la disponibilite vient des interfaces, pas de l hote', () => {
  assert.equal(availabilityOf({ interfaces: [{ available: '1' }] }), 'available');
  assert.equal(availabilityOf({ interfaces: [{ available: '2' }] }), 'unavailable');
  assert.equal(availabilityOf({ interfaces: [{ available: '0' }] }), '', 'inconnu n est pas indisponible');
  assert.equal(availabilityOf({ active_available: '1' }), 'available', 'un agent actif signale autrement');
  assert.equal(availabilityOf({}), '', 'aucun signal : rien n est affirme');
});

test('zabbix : un inventaire sans signal ne compte pas zero disponible', () => {
  const silent = inventoryFrom(entitiesFrom([
    { hostid: '1', name: 'a', interfaces: [] }, { hostid: '2', name: 'b', interfaces: [] }
  ]));
  assert.equal(silent.known, true);
  assert.equal(silent.total, 2);
  assert.equal(silent.up, null, 'aucun signal : le compte est absent, pas nul');
  assert.equal(silent.display, '2 hosts');

  const signalled = inventoryFrom(entitiesFrom([
    host('1', 'a'), host('2', 'b', { interfaces: [{ available: '2' }] })
  ]));
  assert.deepEqual([signalled.up, signalled.total], [1, 2]);
  assert.equal(signalled.display, '1/2 UP');
});

// ===========================================================================
// Multi-host — the rule this domain established
// ===========================================================================

test('zabbix : plusieurs hotes ne sont jamais reduits silencieusement au premier', async () => {
  const { calls, request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA), host(FICTIONAL.hostB, FICTIONAL.nameB)],
    'item.get': [item('system.cpu.util', 99)]
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });

  assert.equal(model.selectedEntity, '');
  assert.equal(model.selectionRequired, true);
  assert.equal(calls.some((call) => call.method === 'item.get'), false, 'aucune metrique lue pour un hote non choisi');
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.metrics[capability].available, false, capability);
    assert.equal(model.metrics[capability].reason, METRIC_REASON.ENTITY_NOT_SELECTED, capability);
  }
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED, 'en attente d un choix, pas hors ligne');
});

test('zabbix : l hote choisi decide des valeurs lues', async () => {
  const { calls, request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA), host(FICTIONAL.hostB, FICTIONAL.nameB)],
    'item.get': (body) => (body.params.hostids === FICTIONAL.hostB
      ? [item('system.cpu.util', 80)]
      : [item('system.cpu.util', 20)])
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request, entity: FICTIONAL.hostB });

  assert.equal(model.selectedEntity, FICTIONAL.hostB);
  assert.equal(model.selectionRequired, false);
  assert.equal(model.metrics[CAPABILITY.CPU].display, '80%');
  const read = calls.find((call) => call.method === 'item.get');
  assert.equal(read.body.params.hostids, FICTIONAL.hostB);
  assert.equal(read.body.params.limit, LIMITS.ITEMS, 'bornee');
  // Deux requetes au total, quel que soit le nombre d hotes.
  assert.equal(calls.length, 2);
});

test('zabbix : un hote unique ne demande aucun choix ; un hote inconnu n en substitue aucun', async () => {
  const single = server({ 'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)], 'item.get': [item('system.cpu.util', 5)] });
  const one = await zabbixAdapter.fetchStatus(config(), secrets, { request: single.request });
  assert.equal(one.selectedEntity, FICTIONAL.hostA);
  assert.equal(one.selectionRequired, false);

  assert.deepEqual(selectEntity([FICTIONAL.hostA, FICTIONAL.hostB], 'absent'), { entity: '', selectionRequired: true });
  assert.deepEqual(selectEntity([FICTIONAL.hostA], ''), { entity: FICTIONAL.hostA, selectionRequired: false });
});

// ===========================================================================
// Capabilities proven by items
// ===========================================================================

test('zabbix : une capacite est prouvee par les items de l hote', async () => {
  const { request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)],
    'item.get': [item('system.cpu.util', 37), item('vm.memory.utilization', 61)]
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });

  assert.equal(model.metrics[CAPABILITY.CPU].display, '37%');
  assert.equal(model.metrics[CAPABILITY.MEMORY].display, '61%');
  assert.equal(model.capabilities[CAPABILITY.CPU], RESOLVED_STATE.READY);
  assert.equal(model.capabilities[CAPABILITY.MEMORY], RESOLVED_STATE.READY);
  // Ce que ce modele de supervision n expose pas reste indisponible.
  assert.equal(model.capabilities[CAPABILITY.LOAD], RESOLVED_STATE.UNAVAILABLE);
  assert.equal(model.metrics[CAPABILITY.LOAD].reason, METRIC_REASON.NOT_EXPORTED);
  assert.equal(model.metrics[CAPABILITY.LOAD].value, null, 'jamais zero');
  assert.equal(model.status, PROVIDER_STATUS.HEALTHY, 'un modele partiel n est pas une panne');
});

test('zabbix : une cle qui rapporte le libre est convertie, pas recopiee', () => {
  const free = metricFor([item('vm.memory.size[pavailable]', 30)], CAPABILITY.MEMORY);
  assert.equal(free.metric.display, '70%', '30 % libre = 70 % utilise');
  const direct = metricFor([item('vm.memory.utilization', 30)], CAPABILITY.MEMORY);
  assert.equal(direct.metric.display, '30%');
});

test('zabbix : plusieurs systemes de fichiers ne sont pas moyennes ni choisis', () => {
  const single = metricFor([item('vfs.fs.size[/,pused]', 42)], CAPABILITY.DISK);
  assert.equal(single.metric.display, '42%', 'un seul systeme de fichiers est repondable');

  const several = metricFor([
    item('vfs.fs.size[/,pused]', 10), item('vfs.fs.size[/data,pused]', 90)
  ], CAPABILITY.DISK);
  assert.equal(several.metric.available, false);
  assert.equal(several.metric.reason, METRIC_REASON.AMBIGUOUS);
  assert.equal(several.metric.value, null, 'ni moyenne, ni pire cas, ni premier venu');
});

test('zabbix : un vrai zero reste un zero', () => {
  const zero = metricFor([item('system.cpu.util', 0)], CAPABILITY.CPU);
  assert.equal(zero.metric.available, true);
  assert.equal(zero.metric.display, '0%');
  assert.equal(zero.state, RESOLVED_STATE.READY);

  // Une valeur illisible n est pas une valeur.
  const unreadable = metricFor([item('system.cpu.util', 'n/a')], CAPABILITY.CPU);
  assert.equal(unreadable.metric.available, false);
  assert.equal(unreadable.metric.value, null);
});

test('zabbix : les cles candidates sont cherchees, jamais supposees', async () => {
  const { calls, request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)],
    'item.get': []
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });
  const read = calls.find((call) => call.method === 'item.get');
  assert.deepEqual(read.body.params.search.key_, candidateSearchKeys());
  assert.equal(read.body.params.searchByAny, true);
  // Aucun item : toutes les metriques hote sont indisponibles, sans erreur.
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.capabilities[capability], RESOLVED_STATE.UNAVAILABLE, capability);
  }
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
});

// ===========================================================================
// Failure isolation
// ===========================================================================

test('zabbix : une lecture d items en echec ne coule pas le fournisseur', async () => {
  const { request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA)],
    'item.get': { error: { code: -32602, message: 'Invalid params.', data: 'Incorrect API "item".' } }
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request });

  // L API a repondu : le fournisseur est joignable, pas hors ligne.
  assert.notEqual(model.status, PROVIDER_STATUS.OFFLINE);
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED);
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(model.inventory.total, 1);
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.capabilities[capability], RESOLVED_STATE.ERROR, capability);
    assert.equal(model.metrics[capability].reason, METRIC_REASON.QUERY_FAILED, capability);
    assert.equal(model.metrics[capability].value, null, 'jamais zero');
  }
});

test('zabbix : la resolution generique respecte la preuve de l adaptateur', () => {
  const resolved = resolveCapabilities(zabbixAdapter, {
    configured: true,
    evidence: { hostInventory: RESOLVED_STATE.READY, cpu: RESOLVED_STATE.READY, memory: RESOLVED_STATE.ERROR, disk: RESOLVED_STATE.UNAVAILABLE, load: RESOLVED_STATE.UNAVAILABLE }
  });
  assert.equal(resolved[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(resolved[CAPABILITY.CPU], RESOLVED_STATE.READY);
  assert.equal(resolved[CAPABILITY.MEMORY], RESOLVED_STATE.ERROR);
  assert.equal(resolved[CAPABILITY.DISK], RESOLVED_STATE.UNAVAILABLE);

  // Configure sans preuve : rien n est promu.
  const unproven = resolveCapabilities(zabbixAdapter, { configured: true });
  assert.equal(unproven[CAPABILITY.CPU], RESOLVED_STATE.REQUIRES_CONFIG);
  assert.equal(unproven[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY, 'l inventaire se prouve en repondant');
  assert.equal(zabbixAdapter.capabilities[CAPABILITY.CPU], DECLARED_STATE.REQUIRES_PROBE);
});

// ===========================================================================
// Rendering through the generic page
// ===========================================================================

test('zabbix : la page rend Zabbix sans rien connaitre de Zabbix', async () => {
  const { request } = server({
    'host.get': [host(FICTIONAL.hostA, FICTIONAL.nameA), host(FICTIONAL.hostB, FICTIONAL.nameB)],
    'item.get': [item('system.cpu.util', 44), item('vm.memory.utilization', 55)]
  });
  const model = await zabbixAdapter.fetchStatus(config(), secrets, { request, entity: FICTIONAL.hostA });
  const html = markup(renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light'));

  // Le manifeste de Zabbix, pas celui de Prometheus.
  assert.match(html, /<h3>Monitored hosts<\/h3>/);
  assert.doesNotMatch(html, /<h3>Targets<\/h3>/);
  assert.match(html, /44%/);
  assert.match(html, /55%/);
  assert.ok(html.includes(FICTIONAL.nameA), 'le nom lisible, pas l identifiant');
  // Un selecteur d hote : deux hotes ont ete decouverts.
  assert.match(html, /id="observability-host"/);

  // Et le rendu generique ne connait rien de ce fournisseur.
  const pages = source('src/enterprise-domain-pages.js');
  for (const leaked of ['zabbix', 'api_jsonrpc', 'host.get', 'item.get', 'hostid', 'lastvalue']) {
    assert.ok(!pages.toLowerCase().includes(leaked.toLowerCase()), `${leaked} ne doit pas atteindre la page`);
  }
});

test('zabbix : aucune valeur de deploiement dans le code de production', () => {
  const zabbix = source('src/integrations/observability-zabbix.js');
  assert.doesNotMatch(zabbix, /\b\d{1,3}(\.\d{1,3}){3}\b/, 'aucune adresse IP');
  assert.doesNotMatch(zabbix, /localhost|127\.0\.0\.1/);
  assert.doesNotMatch(zabbix, /hostid\s*[:=]\s*['"]\d+['"]/, 'aucun identifiant d hote fige');
  assert.doesNotMatch(zabbix, /apiToken\s*[:=]\s*['"][^'"]+['"]/, 'aucun jeton en dur');
  for (const field of zabbixAdapter.configurationFields) {
    assert.equal(field.value, undefined, `${field.id} ne doit pas etre pre-rempli`);
    assert.equal(field.default, undefined, `${field.id} ne doit pas avoir de defaut`);
  }
  assert.match(zabbixAdapter.configurationFields[0].placeholder, /host/, 'un exemple, pas une adresse');
});
