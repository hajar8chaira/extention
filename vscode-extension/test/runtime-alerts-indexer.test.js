'use strict';

/**
 * Alert history moves to the search backend.
 *
 * `GET /security/events` was never a Wazuh route — `/security/*` is the RBAC
 * namespace — so a Manager answering 404 was answering correctly, and one bad
 * call was taking the whole provider offline. Alerts come from the alert index
 * now, which is where the Manager actually ships them.
 *
 * Every value here is invented: no address, credential, agent, rule or host
 * from any real deployment appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  ALERT_INDEX_PATTERN, DATASET, LIMITS, candidatePaths, resolveFieldMap,
  missingRequiredFields, alertSearchQuery, severityForLevel, levelRangeFor
} = require('../src/integrations/siem-indexer');
const { wazuhAdapter, alertsFromIndexer, wazuhLevelToSeverity } = require('../src/integrations/siem-wazuh');
const { resolveRuntimeCapabilities, runtimeCapabilityTabs, RUNTIME_CAPABILITY_STATE } = require('../src/integrations/siem-navigation');
const { CAPABILITY, CAPABILITY_STATE } = require('../src/integrations/siem-contract');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

const FICTIONAL = Object.freeze({
  managerUrl: 'https://manager.example.invalid:55000',
  indexerUrl: 'https://indexer.example.invalid:9200',
  indexerUsername: 'reader',
  indexerPassword: 'alert-fixture-secret',
  agentId: '910',
  agentName: 'fixture-host-beta',
  ruleId: '90001'
});

const caps = (entry) => Object.fromEntries(Object.entries(entry).map(([field, type]) => [
  field, { [type]: { type, searchable: true, aggregatable: type !== 'text' } }
]));

/** Schema A — an alert index that fills nearly everything. */
const ALERTS_A = {
  indices: ['alerts-a'],
  fields: caps({
    '@timestamp': 'date',
    'rule.id': 'keyword',
    'rule.level': 'long',
    'rule.description': 'text',
    'rule.mitre.id': 'keyword',
    'agent.id': 'keyword',
    'agent.name': 'keyword',
    'agent.ip': 'ip',
    'data.srcuser': 'keyword',
    'full_log': 'text'
  })
};

/** Schema B — no MITRE, no user, no agent name: only the essentials. */
const ALERTS_B = {
  indices: ['alerts-b'],
  fields: caps({ 'rule.id': 'keyword', 'rule.level': 'long', 'rule.description': 'text', 'agent.id': 'keyword' })
};

/** Schema C — an index that exists but describes something else. */
const ALERTS_C = { indices: ['alerts-c'], fields: caps({ 'agent.id': 'keyword' }) };

function alertDocument(overrides = {}) {
  return {
    '@timestamp': '2026-08-20T09:01:00Z',
    rule: { id: FICTIONAL.ruleId, level: 12, description: 'Fixture detection', mitre: { id: ['T9999'] } },
    agent: { id: FICTIONAL.agentId, name: FICTIONAL.agentName },
    data: { srcuser: 'fixture-user' },
    ...overrides
  };
}

function recorder(responses = []) {
  const calls = [];
  const queue = [...responses];
  const request = async (target, options = {}) => {
    calls.push({ target, options, body: options.body ? JSON.parse(options.body) : null });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return next || {};
  };
  return { calls, request };
}

function config(extra = {}) {
  return {
    url: FICTIONAL.managerUrl,
    username: 'manager-user',
    indexerUrl: FICTIONAL.indexerUrl,
    indexerUsername: FICTIONAL.indexerUsername,
    ...extra
  };
}

const secrets = { password: 'manager-secret', indexerPassword: FICTIONAL.indexerPassword };

// ===========================================================================
// The Manager stops calling a route it never had
// ===========================================================================

test('alertes : plus aucune route d historique n est demandee a l API de gestion', () => {
  for (const file of ['src/integrations/siem-wazuh.js', 'src/integrations/siem.js']) {
    assert.doesNotMatch(source(file), /security\/events/, `${file} ne doit plus appeler cette route`);
  }
  // Seules les routes que cette API expose reellement subsistent.
  const adapter = source('src/integrations/siem-wazuh.js');
  assert.equal((adapter.match(/joinUrl\(/g) || []).length, 3);
  for (const route of ['/security/user/authenticate', '/manager/info', '/agents']) {
    assert.ok(adapter.includes(`'${route}'`), `${route} doit rester`);
  }
});

test('alertes : un 404 sur une capacite adossee a l Indexer ne coule pas le fournisseur', async () => {
  // L API de gestion repond ; l index d alertes n existe pas.
  const manager = recorder([{ data: { affected_items: [{ id: FICTIONAL.agentId, name: FICTIONAL.agentName, status: 'active' }] } }]);
  const model = await wazuhAdapter.fetchStatus(config(), secrets, {
    request: manager.request, requestTextImpl: async () => JSON.stringify({ data: { token: 'fixture-jwt' } })
  });
  assert.equal(model.connectionStatus, 'online', 'la gestion a repondu : le fournisseur est en ligne');
  assert.equal(model.endpointSummary.total, 1, 'les assets restent servis');

  const missing = await wazuhAdapter.probeAlerts(config(), secrets, {
    request: recorder([new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR')]).request
  });
  assert.equal(missing.ok, false);
  assert.equal(missing.state, 'error');

  // Et la resolution isole la panne sur ses seules capacites.
  const resolved = resolveRuntimeCapabilities(wazuhAdapter, model, { alerts: { state: 'error' }, mitre: { state: 'error' } });
  assert.equal(resolved[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(resolved[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.ERROR);
});

// ===========================================================================
// Capability lifecycle
// ===========================================================================

test('alertes : la capacite est offerte, jamais annoncee prete sans sonde', () => {
  assert.equal(wazuhAdapter.capabilities.alerts, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(wazuhAdapter.capabilities.mitre, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(wazuhAdapter.capabilities.assets, CAPABILITY_STATE.READY);
  assert.equal(typeof wazuhAdapter.probeAlerts, 'function');
  assert.equal(typeof wazuhAdapter.fetchAlerts, 'function');

  const stored = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' });
  assert.equal(stored[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.deepEqual(runtimeCapabilityTabs(stored).map((tab) => tab.id), ['overview', 'assets']);
});

test('alertes : sans configuration de moteur de recherche, aucune requete', async () => {
  const { calls, request } = recorder([ALERTS_A]);
  const probe = await wazuhAdapter.probeAlerts({ url: FICTIONAL.managerUrl }, {}, { request });
  assert.equal(calls.length, 0, 'un deploiement sans Indexer n emet rien');
  assert.equal(probe.state, CAPABILITY_STATE.REQUIRES_CONFIG);
});

test('alertes : une sonde reussie ouvre les sections Alerts et MITRE', async () => {
  const { calls, request } = recorder([ALERTS_A]);
  const probe = await wazuhAdapter.probeAlerts(config(), secrets, { request });
  assert.equal(probe.ok, true);
  assert.equal(probe.state, CAPABILITY_STATE.READY);
  // Une seule requete de decouverte, bornee a ses champs candidats.
  assert.equal(calls.length, 1);
  assert.match(calls[0].target, /_field_caps/);
  assert.doesNotMatch(calls[0].target, /fields=\*/);
  assert.ok(calls[0].target.includes(encodeURIComponent(ALERT_INDEX_PATTERN)) || calls[0].target.includes(ALERT_INDEX_PATTERN));

  const resolved = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.deepEqual(runtimeCapabilityTabs(resolved).map((tab) => tab.id), ['overview', 'alerts', 'assets', 'mitre']);
});

test('alertes : un index absent ou hors sujet ne devient pas une capacite prete', async () => {
  const empty = await wazuhAdapter.probeAlerts(config(), secrets, { request: recorder([{ indices: [], fields: {} }]).request });
  assert.equal(empty.ok, false);
  const unsupported = await wazuhAdapter.probeAlerts(config(), secrets, { request: recorder([ALERTS_C]).request });
  assert.equal(unsupported.ok, false);
  assert.equal(unsupported.state, 'error');
  assert.match(unsupported.message, /rule identifier/);
});

// ===========================================================================
// Runtime schema tolerance
// ===========================================================================

test('alertes : le resolveur ne retient que les champs confirmes', () => {
  const rich = resolveFieldMap(ALERTS_A, DATASET.ALERTS);
  assert.equal(rich.ruleId.path, 'rule.id');
  assert.equal(rich.mitreIds.path, 'rule.mitre.id');
  assert.equal(rich.assetName.path, 'agent.name');

  const lean = resolveFieldMap(ALERTS_B, DATASET.ALERTS);
  assert.equal(lean.ruleId.path, 'rule.id');
  assert.equal(lean.mitreIds, undefined);
  assert.equal(lean.assetName, undefined);
  assert.equal(lean.srcUser, undefined);
  assert.deepEqual(missingRequiredFields(lean, DATASET.ALERTS), []);
  assert.deepEqual(missingRequiredFields(resolveFieldMap(ALERTS_C, DATASET.ALERTS), DATASET.ALERTS), ['ruleId']);

  // Les candidats d alerte et de vulnerabilite sont deux ensembles distincts.
  assert.notDeepEqual(candidatePaths(DATASET.ALERTS), candidatePaths(DATASET.VULNERABILITIES));
});

test('alertes : un horodatage alternatif est accepte sans configuration', () => {
  const map = resolveFieldMap({ fields: caps({ 'rule.id': 'keyword', timestamp: 'date' }) }, DATASET.ALERTS);
  assert.equal(map.timestamp.path, 'timestamp', 'le second candidat sert quand le premier manque');
});

test('alertes : rien n est fabrique quand le document est pauvre', () => {
  const map = resolveFieldMap(ALERTS_A, DATASET.ALERTS);
  const [rich, bare] = alertsFromIndexer([
    { id: 'doc-1', source: alertDocument() },
    { id: 'doc-2', source: { rule: { id: FICTIONAL.ruleId, level: 3 } } }
  ], map);

  assert.equal(rich.severity, 'CRITICAL');
  assert.equal(rich.endpoint, FICTIONAL.agentName);
  assert.equal(rich.user, 'fixture-user');
  assert.deepEqual(rich.mitreTechniques, ['T9999']);

  assert.equal(bare.severity, 'LOW');
  assert.equal(bare.endpoint, '');
  assert.equal(bare.user, '');
  assert.deepEqual(bare.mitreTechniques, [], 'aucune technique inferee');
  assert.equal(bare.title, 'Runtime security alert');
});

test('alertes : la severite vient du niveau de regle, avec une seule table', () => {
  for (const [level, severity] of [[15, 'CRITICAL'], [12, 'CRITICAL'], [11, 'HIGH'], [8, 'HIGH'], [7, 'MEDIUM'], [4, 'MEDIUM'], [3, 'LOW'], [1, 'LOW'], [0, 'INFO']]) {
    assert.equal(severityForLevel(level), severity, `niveau ${level}`);
    assert.equal(wazuhLevelToSeverity(level), severity, `adaptateur, niveau ${level}`);
  }
  assert.equal(wazuhLevelToSeverity('bogus'), 'INFO');
  // Le filtre de severite est la meme table, exprimee en intervalle.
  assert.deepEqual(levelRangeFor('CRITICAL'), { gte: 12 });
  assert.deepEqual(levelRangeFor('HIGH'), { gte: 8, lt: 12 });
  assert.deepEqual(levelRangeFor('LOW'), { gte: 1, lt: 4 });
  assert.equal(levelRangeFor('NOPE'), null);
});

// ===========================================================================
// Bounded query
// ===========================================================================

test('alertes : la requete est bornee, triee, et jamais un telechargement d index', () => {
  const map = resolveFieldMap(ALERTS_A, DATASET.ALERTS);
  const body = alertSearchQuery(map, {});
  assert.equal(body.from, 0);
  assert.equal(body.size, LIMITS.ALERT_WINDOW);
  assert.equal(body.track_total_hits, true);
  assert.deepEqual(body.sort, [{ '@timestamp': { order: 'desc' } }]);

  // Aucun appelant ne peut demander l index entier.
  assert.equal(alertSearchQuery(map, { limit: 100000 }).size, LIMITS.MAX_ALERT_WINDOW);
  assert.equal(alertSearchQuery(map, { limit: -5 }).size, LIMITS.ALERT_WINDOW);

  // Sans champ d horodatage utilisable, aucun tri invente.
  assert.equal(alertSearchQuery(resolveFieldMap(ALERTS_B, DATASET.ALERTS), {}).sort, undefined);
});

test('alertes : les filtres sont traduits dans la requete', () => {
  const map = resolveFieldMap(ALERTS_A, DATASET.ALERTS);
  const filtered = alertSearchQuery(map, { severity: 'HIGH', asset: FICTIONAL.agentName, rule: FICTIONAL.ruleId });
  const clauses = filtered.query.bool.filter;
  assert.ok(clauses.some((clause) => clause.term && clause.term['agent.name'] === FICTIONAL.agentName));
  assert.ok(clauses.some((clause) => clause.term && clause.term['rule.id'] === FICTIONAL.ruleId));
  // La severite n est pas un champ : c est l intervalle de niveaux correspondant.
  assert.ok(clauses.some((clause) => clause.range && clause.range['rule.level'] && clause.range['rule.level'].gte === 8));

  // Un filtre dont le champ n existe pas est abandonne, jamais devine.
  const lean = alertSearchQuery(resolveFieldMap(ALERTS_B, DATASET.ALERTS), { asset: FICTIONAL.agentName });
  assert.ok(lean.query.bool.filter.some((clause) => clause.term && clause.term['agent.id'] === FICTIONAL.agentName));

  // La recherche libre reste bornee et sans joker actif.
  const searched = alertSearchQuery(map, { search: '*'.repeat(300) });
  assert.equal(searched.query.bool.minimum_should_match, 1);
  assert.ok(JSON.stringify(searched.query.bool.should).length < 2000);
});

test('alertes : la lecture est une requete unique, distincte de celle des vulnerabilites', async () => {
  const { calls, request } = recorder([
    ALERTS_A,
    { hits: { total: { value: 2 }, hits: [{ _id: 'doc-1', _source: alertDocument() }] } }
  ]);
  const result = await wazuhAdapter.fetchAlerts(config(), secrets, { request });
  assert.equal(result.ok, true);
  assert.equal(result.alerts.length, 1);
  // Une decouverte + une recherche. Aucune boucle par agent.
  assert.equal(calls.length, 2);
  const search = calls[1];
  assert.match(search.target, /_search/);
  assert.ok(search.target.includes(ALERT_INDEX_PATTERN), 'la famille d index des alertes');
  assert.doesNotMatch(search.target, /wazuh-states-vulnerabilities/, 'jamais melangee aux vulnerabilites');
  assert.doesNotMatch(JSON.stringify(calls.map((call) => call.body)), new RegExp(FICTIONAL.agentId));
});

test('alertes : une lecture en echec ne rend pas une liste vide credible', async () => {
  const { request } = recorder([ALERTS_A, new IntegrationHttpError('Service externe HTTP 500.', 'HTTP_ERROR')]);
  const result = await wazuhAdapter.fetchAlerts(config(), secrets, { request });
  assert.equal(result.ok, false);
  assert.equal(result.state, 'error');
  assert.deepEqual(result.alerts, []);
  assert.ok(result.message);
});

// ===========================================================================
// Security
// ===========================================================================

test('alertes : les identifiants voyagent en en-tete et ne sont jamais rendus', async () => {
  const { calls, request } = recorder([ALERTS_A, { hits: { total: { value: 0 }, hits: [] } }]);
  await wazuhAdapter.fetchAlerts(config(), secrets, { request });
  for (const call of calls) {
    assert.doesNotMatch(call.target, /reader|alert-fixture-secret|@/);
    assert.match(call.options.headers.authorization, /^Basic /);
  }

  const html = renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: alertsFromIndexer([{ id: 'doc-1', source: alertDocument() }], resolveFieldMap(ALERTS_A, DATASET.ALERTS)),
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 1, high: 0, medium: 0, low: 0 },
      values: config(), secretsConfigured: { password: true, indexerPassword: true }
    },
    tab: 'alerts',
    capabilityEvidence: { alerts: { state: 'ready' }, mitre: { state: 'ready' } }
  }, 'n', 'light');
  assert.doesNotMatch(html, /alert-fixture-secret/);
  assert.doesNotMatch(html, /manager-secret/);
});

test('alertes : le TLS Indexer reste independant de celui de la gestion', async () => {
  const relaxed = recorder([ALERTS_A]);
  await wazuhAdapter.probeAlerts(config({ indexerAllowSelfSigned: true }), secrets, { request: relaxed.request });
  assert.deepEqual(relaxed.calls[0].options.tls, { allowSelfSigned: true });

  const strict = recorder([ALERTS_A]);
  await wazuhAdapter.probeAlerts(config({ allowSelfSigned: true }), secrets, { request: strict.request });
  assert.equal(strict.calls[0].options.tls, null, 'le reglage de gestion ne relache pas l Indexer');
});

// ===========================================================================
// Rendering
// ===========================================================================

function page(evidence, alerts = [], overrides = {}) {
  return markup(renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [{ name: FICTIONAL.agentName, os: 'Fixture OS', status: 'active', ip: '198.51.100.7', lastSeen: 'now' }],
      alerts,
      agentSummary: { active: 1, total: 1, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: alerts.length, high: 0, medium: 0, low: 0 },
      ...overrides
    },
    capabilityEvidence: evidence
  }, 'n', 'light'));
}

test('alertes : une gestion saine reste « en ligne » quand la source d alertes tombe', () => {
  const html = page({ alerts: { state: 'error' }, mitre: { state: 'error' } });
  const rows = [...html.matchAll(/capability-row"><span>([^<]+)<\/span><em[^>]*>([^<]+)</g)]
    .map((match) => `${match[1]}=${match[2]}`);
  assert.deepEqual(rows, ['Wazuh API=Online', 'Alerts=Error', 'Assets=Available', 'MITRE=Error']);
  // La navigation survit et les assets restent consultables.
  assert.deepEqual([...html.matchAll(/data-tab="([a-z]+)"/g)].map((match) => match[1]).filter((id, index, all) => all.indexOf(id) === index),
    ['overview', 'alerts', 'assets', 'mitre']);
  assert.doesNotMatch(html, /<span>Critical<\/span><strong>0<\/strong>/, 'aucun compteur invente');
});

test('alertes : sans moteur de recherche configure, la page invite au lieu de mentir', () => {
  const html = page({});
  assert.deepEqual([...html.matchAll(/data-tab="([a-z]+)"/g)].map((match) => match[1]), ['overview', 'assets']);
  assert.match(html, /Additional data sources/);
  assert.match(html, /Alerts, MITRE, Vulnerabilities require access/);
  // Ce que la gestion sert continue de s afficher.
  assert.match(html, new RegExp(FICTIONAL.agentName));
});
