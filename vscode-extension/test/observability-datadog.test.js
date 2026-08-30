'use strict';

/**
 * Phase O4 — Datadog.
 *
 * The third Infrastructure adapter, and the one that shares least with the
 * first two: a SaaS API with several regional bases, two credentials instead of
 * one, a paginated host inventory rather than a scrape list, and metrics that
 * arrive as timeseries point lists rather than instant vectors.
 *
 * The assertions that matter most here are about disk. Prometheus and Zabbix
 * each produced a wrong host-level disk figure once — one by reading the
 * numerator and denominator from different filesystems, the other by averaging
 * per-device percentages. Datadog offers the same trap (`system.disk.in_use` is
 * a per-device fraction) and the same honest way out (byte totals). Which one
 * this adapter takes is pinned below.
 *
 * Every value is invented. No site, key, host name or measurement from any real
 * organisation appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  datadogAdapter, HOSTS_PATH, QUERY_PATH, LIMITS,
  entitiesFrom, inventoryFrom, latestPoint, selectEntity, classifyFailure
} = require('../src/integrations/observability-datadog');
const {
  OBSERVABILITY_PROVIDERS, observabilityAdapter, isSupportedObservabilityProvider
} = require('../src/integrations/observability');
const {
  CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON, PROVIDER_STATUS,
  assertObservabilityAdapter, resolveCapabilities, visibleSections
} = require('../src/integrations/observability-contract');
const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const markup = (html) => html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
// Comments explain the traps this adapter avoids, so they name them. Assertions
// about what the code *does* must read the code, not the prose around it.
const code = (file) => source(file).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const FICTIONAL = Object.freeze({
  site: 'https://api.fixture-observability.invalid',
  apiKey: 'fixture-datadog-api-key-000',
  applicationKey: 'fixture-datadog-application-key-000',
  hostA: 'fixture-host-alpha',
  hostB: 'fixture-host-beta'
});

const config = () => ({ url: FICTIONAL.site });
const secrets = () => ({ apiKey: FICTIONAL.apiKey, applicationKey: FICTIONAL.applicationKey });

const hostsPayload = (hosts) => ({ host_list: hosts, total_matching: hosts.length });
const seriesPayload = (points, scope = '') => ({
  status: 'ok',
  series: points === null ? [] : [{ metric: 'fixture.metric', scope, pointlist: points }]
});
const point = (value, offset = 0) => [1700000000000 + offset * 15000, value];

/**
 * A fake Datadog. Answers by path and by the query expression, and records
 * every URL and header so the tests can assert on what actually left the
 * process rather than on intentions.
 */
function server({ hosts = [], metrics = {}, fail = {} } = {}) {
  const calls = [];
  async function request(url, options = {}) {
    calls.push({ url, options });
    const parsed = new URL(url);
    if (parsed.pathname === HOSTS_PATH) {
      if (fail.hosts) throw fail.hosts;
      return hostsPayload(hosts);
    }
    if (parsed.pathname === QUERY_PATH) {
      const query = parsed.searchParams.get('query') || '';
      for (const [fragment, error] of Object.entries(fail.queries || {})) {
        if (query.includes(fragment)) throw error;
      }
      for (const [fragment, payload] of Object.entries(metrics)) {
        if (query.includes(fragment)) return payload;
      }
      return seriesPayload(null);
    }
    throw new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR');
  }
  return { calls, request };
}

const twoHosts = () => ([
  { name: FICTIONAL.hostA, host_name: FICTIONAL.hostA, up: true, last_reported_time: 1700000000 },
  { name: FICTIONAL.hostB, host_name: FICTIONAL.hostB, up: false, last_reported_time: 1699999000 }
]);
const oneHost = () => ([{ name: FICTIONAL.hostA, host_name: FICTIONAL.hostA, up: true, last_reported_time: 1700000000 }]);

// ===========================================================================
// Contract and registration
// ===========================================================================

test('datadog : l adaptateur respecte le contrat observabilite', () => {
  assert.doesNotThrow(() => assertObservabilityAdapter(datadogAdapter));
  assert.equal(datadogAdapter.id, 'datadog');
});

test('datadog : le registre l expose comme reellement supporte', () => {
  assert.equal(observabilityAdapter('datadog'), datadogAdapter);
  assert.equal(isSupportedObservabilityProvider('datadog'), true);
  const entry = OBSERVABILITY_PROVIDERS.find((provider) => provider.id === 'datadog');
  assert.equal(entry.implemented, true);
  assert.ok(entry.configurationFields.length > 0);
});

test('datadog : deux identifiants, tous deux secrets, et un site configurable', () => {
  const fields = datadogAdapter.configurationFields;
  const byId = Object.fromEntries(fields.map((field) => [field.id, field]));
  assert.equal(byId.url.type, 'url');
  assert.equal(byId.url.required, true);
  // Datadog exige reellement les deux : une cle API seule ne lit ni hotes ni metriques.
  assert.equal(byId.apiKey.secret, true);
  assert.equal(byId.applicationKey.secret, true);
  assert.equal(byId.apiKey.type, 'password');
  assert.equal(byId.applicationKey.type, 'password');
  // Datadog est un service public : aucun motif d assouplir TLS.
  assert.equal(byId.allowSelfSigned, undefined);
});

test('datadog : TLS strict, aucune relaxation possible dans l adaptateur', () => {
  const adapter = code('src/integrations/observability-datadog.js');
  assert.doesNotMatch(adapter, /allowSelfSigned/);
  assert.doesNotMatch(adapter, /rejectUnauthorized/);
  assert.doesNotMatch(adapter, /NODE_TLS/);
});

test('datadog : les capacites declarees separent l inventaire des metriques', () => {
  const declared = datadogAdapter.capabilities;
  assert.equal(declared[CAPABILITY.HOST_INVENTORY], DECLARED_STATE.READY);
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(declared[capability], DECLARED_STATE.REQUIRES_PROBE);
  }
});

test('datadog : configure ne vaut pas capable tant qu aucune sonde n a repondu', () => {
  const resolved = resolveCapabilities(datadogAdapter, { configured: true, evidence: {} });
  assert.equal(resolved[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(resolved[CAPABILITY.CPU], RESOLVED_STATE.REQUIRES_CONFIG);
  assert.equal(resolved[CAPABILITY.DISK], RESOLVED_STATE.REQUIRES_CONFIG);
});

// ===========================================================================
// Configuration
// ===========================================================================

test('datadog : la configuration exige site et identifiants', () => {
  assert.equal(datadogAdapter.validateConfiguration({}).valid, false);
  assert.equal(datadogAdapter.validateConfiguration({ url: 'pas-une-url' }).valid, false);
  assert.equal(datadogAdapter.validateConfiguration(config()).valid, true);
});

test('datadog : sans configuration, aucun appel reseau', async () => {
  const { calls, request } = server({ hosts: oneHost() });
  const model = await datadogAdapter.fetchStatus({}, {}, { request });
  assert.equal(model.status, PROVIDER_STATUS.NOT_CONFIGURED);
  assert.equal(calls.length, 0);
});

test('datadog : testConnection interroge vraiment le service', async () => {
  const { calls, request } = server({ hosts: oneHost() });
  const result = await datadogAdapter.testConnection(config(), secrets(), { request });
  assert.equal(result.ok, true);
  assert.ok(calls.length > 0, 'un test de connexion sans appel ne teste rien');
  assert.equal(new URL(calls[0].url).pathname, HOSTS_PATH);
});

// ===========================================================================
// Secrets and addressing
// ===========================================================================

test('datadog : les cles voyagent en en-tete, jamais dans l URL', async () => {
  const { calls, request } = server({ hosts: oneHost() });
  await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.ok(calls.length > 1);
  for (const call of calls) {
    assert.doesNotMatch(call.url, /fixture-datadog/);
    assert.equal(call.options.headers['dd-api-key'], FICTIONAL.apiKey);
    assert.equal(call.options.headers['dd-application-key'], FICTIONAL.applicationKey);
  }
});

test('datadog : le site vient de la configuration, aucun hote code en dur', async () => {
  const { calls, request } = server({ hosts: oneHost() });
  await datadogAdapter.fetchStatus(config(), secrets(), { request });
  for (const call of calls) {
    assert.ok(call.url.startsWith(FICTIONAL.site), `URL hors du site configure : ${call.url}`);
    assert.doesNotMatch(call.url, /datadoghq/);
  }
});

test('datadog : la page ne restitue jamais une cle', async () => {
  const { request } = server({ hosts: oneHost() });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  const html = renderInfrastructurePageHtml({
    prometheus: { ...model, values: config(), secretsConfigured: { apiKey: true, applicationKey: true } },
    openConfig: true
  }, 'n', 'light');
  assert.doesNotMatch(html, new RegExp(FICTIONAL.apiKey));
  assert.doesNotMatch(html, new RegExp(FICTIONAL.applicationKey));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
});

// ===========================================================================
// Inventory
// ===========================================================================

test('datadog : les hotes sont decouverts, jamais saisis', async () => {
  const { calls, request } = server({ hosts: twoHosts() });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.deepEqual(model.hosts, [FICTIONAL.hostA, FICTIONAL.hostB]);
  assert.equal(model.inventory.up, 1);
  assert.equal(model.inventory.total, 2);
  const inventoryCall = new URL(calls[0].url);
  assert.equal(inventoryCall.searchParams.get('count'), String(LIMITS.HOSTS));
});

test('datadog : la lecture d inventaire est bornee', () => {
  assert.ok(LIMITS.HOSTS > 0 && LIMITS.HOSTS <= 1000);
  assert.ok(LIMITS.MAX_BYTES <= 1024 * 1024);
  assert.ok(LIMITS.TIMEOUT_MS > 0 && LIMITS.TIMEOUT_MS <= 30000);
});

test('datadog : sans signal de disponibilite, l inventaire ne compte pas de UP', () => {
  const entities = entitiesFrom(hostsPayload([{ name: 'a', host_name: 'a' }, { name: 'b', host_name: 'b' }]));
  const inventory = inventoryFrom(entities);
  assert.equal(inventory.up, null, 'inconnu n est pas zero');
  assert.equal(inventory.total, 2);
  assert.doesNotMatch(inventory.display, /UP/);
});

test('datadog : un hote sans identifiant est ignore plutot que devine', () => {
  const entities = entitiesFrom(hostsPayload([{ up: true }, { name: 'c', host_name: 'c', up: true }]));
  assert.deepEqual(entities.map((entity) => entity.id), ['c']);
});

test('datadog : un seul hote est selectionne, plusieurs sont demandes', async () => {
  const single = await datadogAdapter.fetchStatus(config(), secrets(), { request: server({ hosts: oneHost() }).request });
  assert.equal(single.selectedEntity, FICTIONAL.hostA);
  assert.equal(single.selectionRequired, false);

  const many = await datadogAdapter.fetchStatus(config(), secrets(), { request: server({ hosts: twoHosts() }).request });
  assert.equal(many.selectionRequired, true);
  assert.equal(many.metrics[CAPABILITY.CPU].available, false);
  assert.equal(many.metrics[CAPABILITY.CPU].reason, METRIC_REASON.ENTITY_NOT_SELECTED);
  // Attendre un choix n est pas une panne.
  assert.equal(many.capabilities[CAPABILITY.CPU], RESOLVED_STATE.READY);
  assert.equal(selectEntity([FICTIONAL.hostA, FICTIONAL.hostB], FICTIONAL.hostB).entity, FICTIONAL.hostB);
});

test('datadog : aucune metrique n est lue tant qu aucun hote n est choisi', async () => {
  const { calls, request } = server({ hosts: twoHosts() });
  await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(calls.filter((call) => new URL(call.url).pathname === QUERY_PATH).length, 0);
});

// ===========================================================================
// Metrics
// ===========================================================================

test('datadog : le CPU est deduit du temps inactif', async () => {
  const { request } = server({
    hosts: oneHost(),
    metrics: { 'system.cpu.idle': seriesPayload([point(78)]) }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.metrics[CAPABILITY.CPU].available, true);
  assert.equal(Math.round(model.metrics[CAPABILITY.CPU].value), 22);
  assert.equal(model.metrics[CAPABILITY.CPU].display, '22%');
});

test('datadog : la memoire est deduite de la fraction utilisable', async () => {
  const { request } = server({
    hosts: oneHost(),
    metrics: { 'system.mem.pct_usable': seriesPayload([point(0.25)]) }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  // 0.25 utilisable => 75 % utilisee. Une fraction n est pas un pourcentage.
  assert.equal(Math.round(model.metrics[CAPABILITY.MEMORY].value), 75);
});

test('datadog : le disque est un rapport d octets, jamais une moyenne de pourcentages', async () => {
  const { calls, request } = server({
    hosts: oneHost(),
    metrics: {
      'system.disk.used': seriesPayload([point(30 * 1e9)]),
      'system.disk.total': seriesPayload([point(120 * 1e9)])
    }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.metrics[CAPABILITY.DISK].display, '25%');

  // La preuve est dans la requete : des sommes d octets, pas une fraction par peripherique.
  const diskQueries = calls
    .map((call) => new URL(call.url).searchParams.get('query'))
    .filter((query) => query && query.includes('system.disk'));
  assert.equal(diskQueries.length, 2);
  for (const query of diskQueries) assert.match(query, /^sum:/);
  assert.doesNotMatch(code('src/integrations/observability-datadog.js'), /system\.disk\.in_use/);
});

test('datadog : un total de disque nul ne devient pas une division', async () => {
  const { request } = server({
    hosts: oneHost(),
    metrics: {
      'system.disk.used': seriesPayload([point(0)]),
      'system.disk.total': seriesPayload([point(0)])
    }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.metrics[CAPABILITY.DISK].available, false);
  assert.equal(model.metrics[CAPABILITY.DISK].value, null);
  assert.equal(model.metrics[CAPABILITY.DISK].reason, METRIC_REASON.NOT_EXPORTED);
});

test('datadog : la charge est une valeur brute, pas un pourcentage', async () => {
  const { request } = server({
    hosts: oneHost(),
    metrics: { 'system.load.1': seriesPayload([point(1.37)]) }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.metrics[CAPABILITY.LOAD].display, '1.37');
  assert.doesNotMatch(model.metrics[CAPABILITY.LOAD].display, /%/);
  assert.equal(model.metrics.load1, model.metrics[CAPABILITY.LOAD]);
});

test('datadog : une serie absente reste indisponible et ne devient jamais zero', async () => {
  const { request } = server({ hosts: oneHost(), metrics: {} });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.metrics[capability].available, false);
    assert.equal(model.metrics[capability].value, null);
    assert.equal(model.metrics[capability].reason, METRIC_REASON.NOT_EXPORTED);
    // Non exportee n est pas en erreur : le deploiement n a simplement pas cette serie.
    assert.equal(model.capabilities[capability], RESOLVED_STATE.UNAVAILABLE);
  }
});

test('datadog : le dernier point reel est retenu malgre les seaux vides', () => {
  assert.equal(latestPoint(seriesPayload([point(10, 0), point(42, 1), [1700000030000, null]])), 42);
  assert.equal(latestPoint(seriesPayload(null)), null);
  assert.equal(latestPoint({}), null);
});

test('datadog : la fenetre de lecture est bornee et coherente', async () => {
  const now = 1700000000000;
  const { calls, request } = server({ hosts: oneHost(), metrics: { 'system.load.1': seriesPayload([point(1)]) } });
  await datadogAdapter.fetchStatus(config(), secrets(), { request, now });
  const query = calls.map((call) => new URL(call.url)).find((url) => url.pathname === QUERY_PATH);
  const from = Number(query.searchParams.get('from'));
  const to = Number(query.searchParams.get('to'));
  assert.equal(to - from, LIMITS.WINDOW_SECONDS);
  assert.equal(to, Math.floor(now / 1000));
});

// ===========================================================================
// Failure isolation
// ===========================================================================

test('datadog : une requete en echec ne degrade que sa capacite', async () => {
  const { request } = server({
    hosts: oneHost(),
    metrics: { 'system.mem.pct_usable': seriesPayload([point(0.4)]) },
    fail: { queries: { 'system.cpu.idle': new IntegrationHttpError('Service externe HTTP 500.', 'HTTP_ERROR') } }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.capabilities[CAPABILITY.CPU], RESOLVED_STATE.ERROR);
  assert.equal(model.metrics[CAPABILITY.CPU].reason, METRIC_REASON.QUERY_FAILED);
  // La memoire a repondu, et le reste de la page tient.
  assert.equal(model.metrics[CAPABILITY.MEMORY].available, true);
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED);
  assert.deepEqual(model.failures.map((failure) => failure.capability), [CAPABILITY.CPU]);
});

test('datadog : un inventaire en echec est signale sans divulguer l erreur brute', async () => {
  const { request } = server({
    fail: { hosts: new IntegrationHttpError('Authentification refusee par le service externe.', 'AUTH_ERROR') }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request });
  assert.equal(model.status, PROVIDER_STATUS.AUTH_ERROR);
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.ERROR);
  assert.doesNotMatch(model.message, new RegExp(FICTIONAL.apiKey));
  assert.doesNotMatch(model.message, new RegExp(FICTIONAL.applicationKey));
  assert.ok(model.message.length > 0);
});

test('datadog : les familles d echec sont distinguees', () => {
  assert.equal(classifyFailure(new IntegrationHttpError('x', 'AUTH_ERROR')), 'auth-error');
  assert.equal(classifyFailure(new IntegrationHttpError('x', 'TIMEOUT')), 'timeout');
  assert.equal(classifyFailure(new IntegrationHttpError('Service externe HTTP 429.', 'HTTP_ERROR')), 'rate-limited');
  assert.equal(classifyFailure(new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR')), 'not-found');
  assert.equal(classifyFailure(new IntegrationHttpError('Service externe HTTP 500.', 'HTTP_ERROR')), 'query-failed');
  assert.equal(classifyFailure(new IntegrationHttpError('self signed certificate', 'OFFLINE')), 'tls-error');
  assert.equal(classifyFailure(new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE')), 'unreachable');
});

// ===========================================================================
// Rendering
// ===========================================================================

test('datadog : la page est dessinee depuis le manifeste, sans connaitre le fournisseur', async () => {
  const { request } = server({
    hosts: twoHosts(),
    metrics: { 'system.cpu.idle': seriesPayload([point(60)]) }
  });
  const model = await datadogAdapter.fetchStatus(config(), secrets(), { request, entity: FICTIONAL.hostA });
  const html = markup(renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light'));

  assert.match(html, /<h3>Infrastructure hosts<\/h3>/);
  assert.match(html, /<h3>Host health<\/h3>/);
  assert.match(html, /40%/);
  assert.ok(html.includes(FICTIONAL.hostA));
  assert.match(html, /id="observability-host"/);

  const pages = source('src/enterprise-domain-pages.js');
  assert.doesNotMatch(pages, /datadog/i);
  assert.doesNotMatch(pages, /dd-api-key/i);
});

test('datadog : les sections declarees sont celles que le contrat sait dessiner', () => {
  const resolved = resolveCapabilities(datadogAdapter, {
    configured: true,
    evidence: { [CAPABILITY.HOST_INVENTORY]: RESOLVED_STATE.READY, [CAPABILITY.CPU]: RESOLVED_STATE.READY }
  });
  const sections = visibleSections(datadogAdapter, resolved);
  assert.deepEqual(sections.map((section) => section.id), ['hosts', 'host-health']);
});
