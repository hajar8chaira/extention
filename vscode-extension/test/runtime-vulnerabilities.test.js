'use strict';

/**
 * Phase 6 — Wazuh vulnerability detection through the Indexer.
 *
 * Every fixture here is invented. No address, credential, agent, CVE or package
 * from any real deployment appears in this file or in the source it exercises:
 * the point of the tests is that the adapter learns a deployment at runtime, so
 * a test that knew one would be testing the wrong thing.
 *
 * Three synthetic schemas stand in for the version differences the adapter has
 * to tolerate — rich, partial, and minimal.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  VULNERABILITY_INDEX_PATTERN, LIMITS, INDEXER_ERROR, classifyIndexerError,
  createIndexerClient, candidatePaths, resolveFieldMap, missingRequiredFields,
  summaryQuery, searchQuery, parseSummary, parseHits
} = require('../src/integrations/siem-indexer');
const {
  normalizeVulnerabilityRecord, normalizeVulnerabilityQuery, severityCounts,
  vulnerabilityDetailSections, vulnerabilityKey
} = require('../src/integrations/siem-vulnerabilities');
const { wazuhAdapter } = require('../src/integrations/siem-wazuh');
const { resolveRuntimeCapabilities, runtimeCapabilityTabs, RUNTIME_CAPABILITY_STATE } = require('../src/integrations/siem-navigation');
const { CAPABILITY, CAPABILITY_STATE } = require('../src/integrations/siem-contract');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

// ---------------------------------------------------------------------------
// Synthetic deployments. None of these values exists anywhere real.
// ---------------------------------------------------------------------------

const FICTIONAL = Object.freeze({
  indexerUrl: 'https://indexer.example.invalid:9200',
  indexerUsername: 'reader',
  indexerPassword: 'fixture-secret-value',
  agentId: '900',
  agentName: 'fixture-host-alpha',
  agentIp: '192.0.2.10',
  cve: 'CVE-1999-0001',
  packageName: 'fixture-lib'
});

const caps = (entry) => Object.fromEntries(Object.entries(entry).map(([path, type]) => [
  path, { [type]: { type, searchable: true, aggregatable: !['text'].includes(type) } }
]));

/** Schema A — a deployment that fills nearly everything. */
const SCHEMA_A = {
  indices: ['idx-a'],
  fields: caps({
    'vulnerability.id': 'keyword',
    'vulnerability.severity': 'keyword',
    'vulnerability.score.base': 'float',
    'vulnerability.score.version': 'keyword',
    'vulnerability.description': 'text',
    'vulnerability.detected_at': 'date',
    'vulnerability.published_at': 'date',
    'vulnerability.reference': 'keyword',
    'vulnerability.under_evaluation': 'boolean',
    'package.name': 'keyword',
    'package.version': 'keyword',
    'package.architecture': 'keyword',
    'agent.id': 'keyword',
    'agent.name': 'keyword',
    'agent.ip': 'ip',
    'host.os.full': 'keyword'
  })
};

/** Schema B — no score, no references, a free-text condition instead. */
const SCHEMA_B = {
  indices: ['idx-b'],
  fields: caps({
    'vulnerability.id': 'keyword',
    'vulnerability.severity': 'keyword',
    'package.name': 'keyword',
    'package.version': 'keyword',
    'package.condition': 'keyword',
    'agent.id': 'keyword'
  })
};

/** Schema C — the bare minimum a vulnerability can be. */
const SCHEMA_C = { indices: ['idx-c'], fields: caps({ 'vulnerability.id': 'keyword' }) };

/** Schema D — an index that exists but describes something else entirely. */
const SCHEMA_D = { indices: ['idx-d'], fields: caps({ 'package.name': 'keyword' }) };

function documentA(overrides = {}) {
  return {
    vulnerability: {
      id: FICTIONAL.cve, severity: 'Critical', score: { base: 9.8, version: '3.1' },
      description: 'Fixture description.', detected_at: '2020-01-01T00:00:00Z',
      published_at: '2019-12-01T00:00:00Z', reference: ['https://example.invalid/a'],
      under_evaluation: false
    },
    package: { name: FICTIONAL.packageName, version: '1.0.0', architecture: 'x86_64' },
    agent: { id: FICTIONAL.agentId, name: FICTIONAL.agentName, ip: FICTIONAL.agentIp },
    host: { os: { full: 'Fixture OS 1.0' } },
    ...overrides
  };
}

/** A fake transport that records every call and returns queued payloads. */
function recorder(responses = []) {
  const calls = [];
  const queue = [...responses];
  const request = async (target, options = {}) => {
    calls.push({ target, options, body: options.body ? JSON.parse(options.body) : null });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return typeof next === 'function' ? next(target, options) : (next || {});
  };
  return { calls, request };
}

function indexerConfig(extra = {}) {
  return {
    url: 'https://manager.example.invalid:55000',
    username: 'manager-user',
    indexerUrl: FICTIONAL.indexerUrl,
    indexerUsername: FICTIONAL.indexerUsername,
    ...extra
  };
}

const indexerSecrets = { password: 'manager-secret', indexerPassword: FICTIONAL.indexerPassword };

// ===========================================================================
// Capability lifecycle
// ===========================================================================

test('6 : Wazuh declare les vulnerabilites « a configurer », jamais « pretes »', () => {
  assert.equal(wazuhAdapter.capabilities.vulnerabilities, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(typeof wazuhAdapter.probeVulnerabilities, 'function');
  assert.equal(typeof wazuhAdapter.fetchVulnerabilities, 'function');
});

test('6 : sans configuration Indexer, aucune requete n est emise', async () => {
  const { calls, request } = recorder([SCHEMA_A]);
  const probe = await wazuhAdapter.probeVulnerabilities({ url: 'https://manager.example.invalid:55000' }, {}, { request });
  assert.equal(calls.length, 0, 'aucun appel reseau');
  assert.equal(probe.ok, false);
  assert.equal(probe.state, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(probe.code, INDEXER_ERROR.NOT_CONFIGURED);
});

test('6 : une URL Indexer sans identifiants ne declenche pas de requete', async () => {
  const { calls, request } = recorder([SCHEMA_A]);
  const probe = await wazuhAdapter.probeVulnerabilities({ indexerUrl: FICTIONAL.indexerUrl }, {}, { request });
  assert.equal(calls.length, 0);
  assert.equal(probe.state, CAPABILITY_STATE.REQUIRES_CONFIG);
});

test('6 : des identifiants stockes ne suffisent pas a rendre la capacite prete', () => {
  // Aucune sonde : la capacite reste « a configurer », donc aucun onglet.
  const resolved = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' });
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(runtimeCapabilityTabs(resolved).some((tab) => tab.id === 'vulnerabilities'), false);
});

test('6 : une sonde reussie rend la capacite prete et fait apparaitre la section', async () => {
  const { request } = recorder([SCHEMA_A]);
  const probe = await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(probe.ok, true);
  assert.equal(probe.state, CAPABILITY_STATE.READY);

  const resolved = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }, vulnerabilities: { state: 'ready' }
  });
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.READY);
  assert.deepEqual(runtimeCapabilityTabs(resolved).map((tab) => tab.id), ['overview', 'alerts', 'assets', 'mitre', 'vulnerabilities']);
});

test('6 : une sonde en echec isole la capacite sans toucher aux autres', async () => {
  const { request } = recorder([new IntegrationHttpError('Authentification refusee par le service externe.', 'AUTH_ERROR')]);
  const probe = await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(probe.ok, false);
  assert.equal(probe.code, INDEXER_ERROR.AUTH_ERROR);

  const resolved = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' }, {
    vulnerabilities: { state: 'error' }, alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.ERROR);
  // Chaque autre capacite garde l etat que SA propre source a prouve.
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(resolved[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(resolved[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.READY);
});

test('6 : chaque classe d echec Indexer est distinguee', () => {
  assert.equal(classifyIndexerError({ code: 'AUTH_ERROR' }), INDEXER_ERROR.AUTH_ERROR);
  assert.equal(classifyIndexerError({ code: 'TIMEOUT' }), INDEXER_ERROR.TIMEOUT);
  assert.equal(classifyIndexerError({ code: 'HTTP_ERROR', message: 'Service externe HTTP 404.' }), INDEXER_ERROR.INDEX_MISSING);
  assert.equal(classifyIndexerError({ code: 'HTTP_ERROR', message: 'Service externe HTTP 500.' }), INDEXER_ERROR.QUERY_FAILED);
  assert.equal(classifyIndexerError({ code: 'MALFORMED' }), INDEXER_ERROR.MALFORMED);
  assert.equal(classifyIndexerError({ code: 'OFFLINE', message: 'self-signed certificate in certificate chain' }), INDEXER_ERROR.TLS_ERROR);
  assert.equal(classifyIndexerError({ code: 'OFFLINE', message: 'connect ECONNREFUSED' }), INDEXER_ERROR.UNREACHABLE);
});

test('6 : un index absent ou hors sujet ne devient pas une capacite prete', async () => {
  const missing = await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request: recorder([{ indices: [], fields: {} }]).request });
  assert.equal(missing.code, INDEXER_ERROR.INDEX_MISSING);
  const unsupported = await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request: recorder([SCHEMA_D]).request });
  assert.equal(unsupported.code, INDEXER_ERROR.UNSUPPORTED_SCHEMA);
  assert.equal(unsupported.state, 'error');
});

// ===========================================================================
// Runtime field discovery
// ===========================================================================

test('6 : le resolveur ne retient que les champs que le cluster confirme', () => {
  const rich = resolveFieldMap(SCHEMA_A);
  assert.equal(rich.cve.path, 'vulnerability.id');
  assert.equal(rich.cvssScore.path, 'vulnerability.score.base');
  assert.equal(rich.assetName.path, 'agent.name');

  const partial = resolveFieldMap(SCHEMA_B);
  assert.equal(partial.cve.path, 'vulnerability.id');
  assert.equal(partial.packageCondition.path, 'package.condition');
  // Ce que ce deploiement n expose pas n existe pas dans la carte.
  assert.equal(partial.cvssScore, undefined);
  assert.equal(partial.references, undefined);
  assert.equal(partial.assetName, undefined);

  const minimal = resolveFieldMap(SCHEMA_C);
  assert.deepEqual(Object.keys(minimal), ['cve']);
  assert.deepEqual(missingRequiredFields(minimal), [], 'un identifiant suffit a decrire une vulnerabilite');
  assert.deepEqual(missingRequiredFields(resolveFieldMap(SCHEMA_D)), ['cve']);
});

test('6 : un champ text agrege via son sous-champ keyword', () => {
  const map = resolveFieldMap({
    fields: {
      'vulnerability.id': { keyword: { type: 'keyword', searchable: true, aggregatable: true } },
      'agent.name': { text: { type: 'text', searchable: true, aggregatable: false } },
      'agent.name.keyword': { keyword: { type: 'keyword', searchable: true, aggregatable: true } }
    }
  });
  assert.equal(map.assetName.path, 'agent.name', 'affiche depuis le champ de base');
  assert.equal(map.assetName.queryPath, 'agent.name.keyword', 'agrege depuis le sous-champ');
  assert.equal(map.assetName.aggregatable, true);
});

test('6 : la sonde ne demande que ses champs candidats, jamais tous', async () => {
  const { calls, request } = recorder([SCHEMA_A]);
  await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(calls.length, 1, 'une seule requete de decouverte');
  const target = calls[0].target;
  assert.match(target, /_field_caps/);
  assert.doesNotMatch(target, /fields=\*/);
  assert.ok(candidatePaths().length > 10);
  assert.match(target, /vulnerability\.id/);
});

// ===========================================================================
// Requetes : globales, bornees, sans boucle par agent
// ===========================================================================

test('6 : le resume est une agregation globale, pas une requete par agent', async () => {
  const { calls, request } = recorder([SCHEMA_A, {
    hits: { total: { value: 42 } },
    aggregations: {
      severity: { buckets: [{ key: 'Critical', doc_count: 3 }, { key: 'Low', doc_count: 39 }] },
      affectedAssets: { value: 4 },
      assetFacets: { buckets: [{ key: FICTIONAL.agentName, doc_count: 42 }] }
    }
  }]);
  const result = await wazuhAdapter.fetchVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(result.ok, true);
  // Une decouverte + une agregation + une recherche : jamais N requetes.
  assert.equal(calls.length, 3);
  const aggregation = calls.find((call) => call.body && call.body.size === 0);
  assert.ok(aggregation, 'une agregation size:0');
  assert.ok(aggregation.body.aggs.severity, 'distribution des severites cote cluster');
  assert.ok(aggregation.body.aggs.affectedAssets.cardinality, 'assets comptes cote cluster');
  // Aucun identifiant d agent ne parait dans une requete : rien n est boucle.
  const bodies = JSON.stringify(calls.map((call) => call.body));
  assert.doesNotMatch(bodies, new RegExp(FICTIONAL.agentId));
  assert.equal(result.summary.affectedAssets, 4);
  assert.deepEqual(result.summary.assets, [{ value: FICTIONAL.agentName, count: 42 }]);
});

test('6 : la liste est paginee cote serveur et bornee', () => {
  const map = resolveFieldMap(SCHEMA_A);
  const first = searchQuery(map, { page: 1, pageSize: 10 });
  assert.deepEqual([first.from, first.size], [0, 10]);
  assert.equal(first.track_total_hits, true);

  const third = searchQuery(map, { page: 3, pageSize: 10 });
  assert.equal(third.from, 20);

  // Une taille de page absurde est ramenee au plafond.
  assert.equal(searchQuery(map, { pageSize: 10000 }).size, LIMITS.MAX_PAGE_SIZE);
  // Et la profondeur ne peut pas depasser la fenetre de resultats.
  const deep = searchQuery(map, { page: 999999, pageSize: 10 });
  assert.ok(deep.from + deep.size <= LIMITS.MAX_RESULT_WINDOW, 'profondeur bornee');
});

test('6 : les filtres sont traduits dans la requete OpenSearch', () => {
  const map = resolveFieldMap(SCHEMA_A);
  const body = searchQuery(map, { severity: 'Critical', asset: FICTIONAL.agentName, page: 1 });
  const filters = body.query.bool.filter;
  assert.ok(filters.some((clause) => clause.term && clause.term['vulnerability.severity'] === 'Critical'));
  assert.ok(filters.some((clause) => clause.term && clause.term['agent.name'] === FICTIONAL.agentName));

  // Le filtre asset suit le champ que le deploiement expose reellement.
  const byId = searchQuery(resolveFieldMap(SCHEMA_B), { asset: FICTIONAL.agentId });
  assert.ok(byId.query.bool.filter.some((clause) => clause.term && clause.term['agent.id'] === FICTIONAL.agentId));

  // Un filtre dont le champ n existe pas est abandonne, jamais devine.
  const impossible = searchQuery(resolveFieldMap(SCHEMA_C), { severity: 'Critical' });
  assert.deepEqual(impossible.query, { match_all: {} });
});

test('6 : la recherche libre est bornee et neutralise les jokers', () => {
  const map = resolveFieldMap(SCHEMA_A);
  const body = searchQuery(map, { search: '*'.repeat(200) });
  const clause = JSON.stringify(body.query.bool.should);
  assert.ok(clause.length < 2000, 'terme borne');
  assert.match(clause, /\\\\\*/, 'les jokers sont echappes');
  assert.equal(body.query.bool.minimum_should_match, 1);
});

// ===========================================================================
// Normalisation : rien n est invente
// ===========================================================================

test('6 : un enregistrement ne porte que ce que le document contenait', () => {
  const rich = normalizeVulnerabilityRecord(documentA(), resolveFieldMap(SCHEMA_A), { provider: 'Wazuh', providerFindingId: 'doc-1' });
  assert.equal(rich.cve, FICTIONAL.cve);
  assert.equal(rich.cvssScore, 9.8);
  assert.equal(rich.asset, FICTIONAL.agentName);
  assert.equal(rich.uiSeverity, 'CRITICAL');
  assert.deepEqual(rich.references, ['https://example.invalid/a']);

  const partial = normalizeVulnerabilityRecord(
    { vulnerability: { id: FICTIONAL.cve, severity: 'High' }, package: { name: FICTIONAL.packageName, version: '2.0.0', condition: 'Package unfixed' }, agent: { id: FICTIONAL.agentId } },
    resolveFieldMap(SCHEMA_B), { provider: 'Wazuh' }
  );
  assert.equal(partial.packageCondition, 'Package unfixed');
  // Aucun de ces concepts n existe dans ce deploiement : aucun n est fabrique.
  assert.equal('cvssScore' in partial, false);
  assert.equal('fixedVersion' in partial, false);
  assert.equal('cvssVector' in partial, false);
  assert.equal('status' in partial, false);
  assert.equal('cwe' in partial, false);
  assert.equal('mitreTechniques' in partial, false);
  assert.equal('remediation' in partial, false);
});

test('6 : un score absent ou illisible n est jamais zero', () => {
  const map = resolveFieldMap(SCHEMA_A);
  for (const value of [undefined, null, '', 'n/a', {}]) {
    const record = normalizeVulnerabilityRecord(
      documentA({ vulnerability: { id: FICTIONAL.cve, severity: 'High', score: { base: value } } }), map, {}
    );
    assert.equal('cvssScore' in record, false, `${JSON.stringify(value)} ne doit pas devenir un score`);
  }
  // Un vrai zero, lui, reste un zero.
  const zero = normalizeVulnerabilityRecord(documentA({ vulnerability: { id: FICTIONAL.cve, score: { base: 0 } } }), map, {});
  assert.equal(zero.cvssScore, 0);
});

test('6 : une condition de paquet n est pas relue comme une version corrigee', () => {
  const record = normalizeVulnerabilityRecord(
    { vulnerability: { id: FICTIONAL.cve }, package: { name: FICTIONAL.packageName, condition: 'Package less than 9.9.9' }, agent: { id: FICTIONAL.agentId } },
    resolveFieldMap(SCHEMA_B), {}
  );
  assert.equal(record.packageCondition, 'Package less than 9.9.9');
  assert.equal(record.fixedVersion, undefined, 'une condition n est pas une version corrigee');
  const labels = vulnerabilityDetailSections(record).flatMap((section) => section.fields.map((field) => field.label));
  assert.equal(labels.includes('Fixed version'), false);
  assert.ok(labels.includes('Package condition'));
});

test('6 : le detail n affiche que des sections qu il peut remplir', () => {
  const minimal = normalizeVulnerabilityRecord({ vulnerability: { id: FICTIONAL.cve } }, resolveFieldMap(SCHEMA_C), { provider: 'Wazuh' });
  const sections = vulnerabilityDetailSections(minimal);
  assert.deepEqual(sections.map((section) => section.title), ['Vulnerability', 'Provider']);
  const labels = sections.flatMap((section) => section.fields.map((field) => field.label));
  for (const absent of ['CVSS score', 'CVSS version', 'Package', 'Agent ID', 'Detected at', 'Operating system']) {
    assert.equal(labels.includes(absent), false, `${absent} ne doit pas apparaitre`);
  }
});

test('6 : une distribution de severites absente n est pas quatre zeros', () => {
  assert.equal(severityCounts(null), null);
  assert.deepEqual(severityCounts([{ value: 'Critical', count: 2 }]).CRITICAL, 2);
  const parsed = parseSummary({ hits: { total: { value: 0 } } }, resolveFieldMap(SCHEMA_C));
  assert.equal(parsed.severity, null, 'un mapping sans severite ne produit pas de distribution');
  assert.equal(parsed.affectedAssets, null);
  assert.equal(parsed.total, 0);
});

test('6 : une reponse Indexer malformee ne devient pas une liste vide credible', () => {
  assert.deepEqual(parseHits({}), []);
  assert.deepEqual(parseHits({ hits: { hits: 'not-an-array' } }), []);
  assert.equal(parseSummary({ aggregations: { severity: { buckets: 'nope' } } }, resolveFieldMap(SCHEMA_A)).severity.length, 0);
});

test('6 : la requete venue de la webview est toujours bornee', () => {
  assert.deepEqual(normalizeVulnerabilityQuery(), {
    search: '', severity: '', asset: '', cve: '', package: '', page: 1, pageSize: 10, vulnerability: ''
  });
  assert.equal(normalizeVulnerabilityQuery({ pageSize: 9999 }, { maxPageSize: 50 }).pageSize, 50);
  assert.equal(normalizeVulnerabilityQuery({ page: -3 }).page, 1);
  assert.ok(vulnerabilityKey({ cve: FICTIONAL.cve, agentId: FICTIONAL.agentId }).includes(FICTIONAL.cve));
});

// ===========================================================================
// Securite : secrets, TLS
// ===========================================================================

test('6 : les identifiants Indexer partent en en-tete, jamais dans une URL', async () => {
  const { calls, request } = recorder([SCHEMA_A]);
  const client = createIndexerClient({
    url: FICTIONAL.indexerUrl, username: FICTIONAL.indexerUsername, password: FICTIONAL.indexerPassword, request
  });
  await client.fieldCaps(['vulnerability.id']);
  const call = calls[0];
  assert.doesNotMatch(call.target, /reader|fixture-secret-value|@/);
  assert.match(call.options.headers.authorization, /^Basic /);
  assert.equal(Buffer.from(call.options.headers.authorization.slice(6), 'base64').toString(),
    `${FICTIONAL.indexerUsername}:${FICTIONAL.indexerPassword}`);
});

test('6 : le mot de passe Indexer n atteint jamais le HTML rendu', async () => {
  const { request } = recorder([SCHEMA_A, { hits: { total: { value: 1 }, hits: [{ _id: 'doc-1', _source: documentA() }] } }]);
  const data = await wazuhAdapter.fetchVulnerabilities(indexerConfig(), indexerSecrets, { request });
  const html = renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: [], agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      values: indexerConfig(), secretsConfigured: { password: true, indexerPassword: true }
    },
    tab: 'vulnerabilities', vulnerabilities: data, capabilityEvidence: { vulnerabilities: { state: 'ready' } }
  }, 'n', 'light');
  assert.doesNotMatch(html, /fixture-secret-value/);
  assert.doesNotMatch(html, /manager-secret/);
  assert.doesNotMatch(html, /Basic [A-Za-z0-9+/=]/);
});

test('6 : un secret ne fuit pas dans le message d une erreur Indexer', async () => {
  const leaky = new IntegrationHttpError(`connect ECONNREFUSED https://${FICTIONAL.indexerUsername}:${FICTIONAL.indexerPassword}@host`, 'OFFLINE');
  const { request } = recorder([leaky]);
  const probe = await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.doesNotMatch(probe.message, new RegExp(FICTIONAL.indexerPassword));
  assert.doesNotMatch(probe.message, new RegExp(FICTIONAL.indexerUsername));
});

test('6 : l acceptation des certificats auto-signes est desactivee par defaut', async () => {
  const { calls, request } = recorder([SCHEMA_A]);
  await wazuhAdapter.probeVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(calls[0].options.tls, null, 'strict par defaut');

  const field = wazuhAdapter.configurationFields.find((entry) => entry.id === 'indexerAllowSelfSigned');
  assert.ok(field, 'le schema du fournisseur declare l option');
  assert.equal(field.type, 'boolean');
  assert.equal(field.required, undefined);
  assert.equal(field.group, 'advanced');

  // Le rendu generique le traite comme une case a cocher, sans rien coder de
  // specifique a Wazuh : decoche par defaut, cochee seulement si la valeur
  // enregistree est un vrai booleen.
  const off = markup(renderRuntimeSecurityPageHtml({
    runtime: { configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true, agents: [], alerts: [], agentSummary: {}, alertSummary: {}, values: indexerConfig() },
    openConfig: true
  }, 'n', 'light'));
  assert.match(off, /id="runtime-indexerAllowSelfSigned" type="checkbox">/, 'decoche par defaut');
  const on = markup(renderRuntimeSecurityPageHtml({
    runtime: { configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true, agents: [], alerts: [], agentSummary: {}, alertSummary: {}, values: indexerConfig({ indexerAllowSelfSigned: true }) },
    openConfig: true
  }, 'n', 'light'));
  assert.match(on, /id="runtime-indexerAllowSelfSigned" type="checkbox" checked/);
  const pages = source('src/enterprise-domain-pages.js');
  assert.doesNotMatch(pages, /indexerAllowSelfSigned/, 'le rendu ne connait pas ce champ, seulement son type');
});

test('6 : un booleen faux se persiste, et le blanc reste la semantique des secrets', async () => {
  const store = {};
  const vault = new Map();
  const { createSiemConfigurationService } = require('../src/integrations/siem-configuration');
  const service = createSiemConfigurationService({
    configuration: { get: (key, fallback) => (key in store ? store[key] : fallback), update: async (key, value) => { store[key] = value; } },
    secrets: { get: async (key) => vault.get(key) || '', store: async (key, value) => { vault.set(key, value); }, delete: async (key) => { vault.delete(key); } },
    resolveAdapter: (id) => (id === 'wazuh' ? wazuhAdapter : null)
  });

  await service.saveProviderConfiguration('wazuh', {
    url: 'https://manager.example.invalid:55000', username: 'manager-user', password: 'manager-secret',
    indexerAllowSelfSigned: true
  });
  assert.equal(service.getProviderConfig('wazuh').indexerAllowSelfSigned, true);

  // Decocher doit pouvoir s enregistrer : un booleen faux n est pas « rien ».
  await service.saveProviderConfiguration('wazuh', {
    url: 'https://manager.example.invalid:55000', username: 'manager-user', indexerAllowSelfSigned: false
  });
  assert.equal(service.getProviderConfig('wazuh').indexerAllowSelfSigned, false);
  assert.equal(store['runtimeSecurity.providers'].wazuh.indexerAllowSelfSigned, false, 'un vrai booleen est stocke');

  // Et le mot de passe laisse vide est toujours conserve, pas efface.
  assert.equal((await service.getProviderSecrets('wazuh')).password, 'manager-secret');
  // Un secret n a jamais rejoint les reglages ordinaires.
  assert.equal('password' in store['runtimeSecurity.providers'].wazuh, false);
  assert.equal('indexerPassword' in store['runtimeSecurity.providers'].wazuh, false);
});

test('6 : l option TLS ne vaut que pour l Indexer, et seulement si elle est vraie', async () => {
  const relaxed = recorder([SCHEMA_A]);
  await wazuhAdapter.probeVulnerabilities(indexerConfig({ indexerAllowSelfSigned: true }), indexerSecrets, { request: relaxed.request });
  assert.deepEqual(relaxed.calls[0].options.tls, { allowSelfSigned: true });

  // Toute autre valeur qu un vrai booleen n est pas un consentement.
  for (const value of ['true', 1, 'yes', {}]) {
    const strict = recorder([SCHEMA_A]);
    await wazuhAdapter.probeVulnerabilities(indexerConfig({ indexerAllowSelfSigned: value }), indexerSecrets, { request: strict.request });
    assert.equal(strict.calls[0].options.tls, null, `${JSON.stringify(value)} ne doit pas relacher TLS`);
  }

  // Le chemin Manager ne lit jamais cette option et ne passe jamais de TLS.
  const manager = recorder([{ data: { affected_items: [] } }]);
  await wazuhAdapter.fetchStatus(indexerConfig({ indexerAllowSelfSigned: true }), { password: 'manager-secret', token: 'manager-token' }, {
    request: manager.request, requestTextImpl: async () => 'token'
  });
  assert.ok(manager.calls.length > 0);
  for (const call of manager.calls) assert.equal(call.options.tls, undefined, 'le Manager reste strict');
});

test('6 : le transport reste strict tant que personne ne demande le contraire', () => {
  const http = source('src/integrations/http.js');
  assert.match(http, /tls = null/, 'aucune relaxation par defaut');
  assert.match(http, /tls\.allowSelfSigned === true/, 'consentement explicite requis');
  // Jamais de desactivation globale de la verification TLS.
  const production = ['src/integrations/http.js', 'src/integrations/siem-indexer.js', 'src/integrations/siem-wazuh.js', 'src/extension.js'];
  for (const file of production) {
    assert.doesNotMatch(source(file), /NODE_TLS_REJECT_UNAUTHORIZED/, `${file} ne doit pas toucher au TLS global`);
  }
});

test('6 : un avertissement visible accompagne un TLS relache', async () => {
  const { request } = recorder([SCHEMA_A, { hits: { total: { value: 0 }, hits: [] } }]);
  const data = await wazuhAdapter.fetchVulnerabilities(indexerConfig({ indexerAllowSelfSigned: true }), indexerSecrets, { request });
  assert.equal(data.relaxedTls, true);
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: { configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true, agents: [], alerts: [], agentSummary: {}, alertSummary: {} },
    tab: 'vulnerabilities', vulnerabilities: data, capabilityEvidence: { vulnerabilities: { state: 'ready' } }
  }, 'n', 'light'));
  assert.match(html, /Self-signed certificate acceptance is enabled/);
});

// ===========================================================================
// Rendu
// ===========================================================================

function vulnerabilityPage(data, extra = {}) {
  return markup(renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: [],
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 }
    },
    tab: 'vulnerabilities',
    vulnerabilities: data,
    capabilityEvidence: { vulnerabilities: { state: data && data.ok ? 'ready' : 'error' } },
    ...extra
  }, 'n', 'light'));
}

test('6 : une requete reussie sans resultat est un vrai etat vide', async () => {
  const { request } = recorder([SCHEMA_A, { hits: { total: { value: 0 }, hits: [] }, aggregations: {} }]);
  const data = await wazuhAdapter.fetchVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(data.ok, true);
  const html = vulnerabilityPage(data);
  assert.match(html, /No active vulnerabilities were returned by Wazuh\./);
  assert.doesNotMatch(html, /could not be read/);
});

test('6 : une requete en echec n affiche jamais zero vulnerabilite', async () => {
  const { request } = recorder([SCHEMA_A, new IntegrationHttpError('Service externe HTTP 500.', 'HTTP_ERROR')]);
  const data = await wazuhAdapter.fetchVulnerabilities(indexerConfig(), indexerSecrets, { request });
  assert.equal(data.ok, false);
  const html = vulnerabilityPage(data);
  assert.match(html, /vulnerability query failed/i);
  assert.doesNotMatch(html, /No active vulnerabilities were returned/);
  assert.doesNotMatch(html, /<span>Critical<\/span><strong>0<\/strong>/);
  assert.match(html, /data-action="showConfig"/, 'une route de correction est offerte');
});

test('6 : la liste rend ce que le fournisseur a renvoye, et propose l investigation', async () => {
  const { request } = recorder([SCHEMA_A, {
    hits: { total: { value: 1 }, hits: [{ _id: 'doc-1', _source: documentA() }] },
    aggregations: {
      severity: { buckets: [{ key: 'Critical', doc_count: 1 }] },
      affectedAssets: { value: 1 },
      assetFacets: { buckets: [{ key: FICTIONAL.agentName, doc_count: 1 }] }
    }
  }]);
  const data = await wazuhAdapter.fetchVulnerabilities(indexerConfig(), indexerSecrets, { request });
  const html = vulnerabilityPage(data);
  assert.match(html, new RegExp(FICTIONAL.cve));
  assert.match(html, new RegExp(FICTIONAL.packageName));
  assert.match(html, /CVSS 9\.8/);
  assert.match(html, /data-vuln-open="doc-1"/);
  // Les choix de filtre viennent des facettes runtime, jamais d une liste ecrite.
  assert.match(html, new RegExp(`<option value="${FICTIONAL.agentName}"`));
  assert.match(html, /id="vulns-severity"/);

  const detail = vulnerabilityPage(data, { vulnerabilitiesQuery: { vulnerability: 'doc-1' } });
  assert.match(detail, /Vulnerability investigation · Wazuh/);
  assert.match(detail, /data-vuln-open=""/);
  assert.doesNotMatch(detail, /vulns-search/, 'la liste cede la place');
});

test('6 : la section vulnerabilites n existe pas tant qu elle n est pas prouvee', () => {
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: [], agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 }
    }
  }, 'n', 'light'));
  assert.doesNotMatch(html, /data-tab="vulnerabilities"/);
  // Mais une invitation explicite a configurer la source existe, et elle nomme
  // les sections en attente au lieu d en promettre une seule.
  assert.match(html, /Additional data sources/);
  assert.match(html, /Vulnerabilities require access|, Vulnerabilities require access/);
  assert.doesNotMatch(html, /Total records|Affected assets/);
});

// ===========================================================================
// Isolation et neutralite du produit
// ===========================================================================

test('6 : Manager et Indexer ont des frontieres d echec distinctes', () => {
  const extension = source('src/extension.js');
  assert.match(extension, /async function refreshRuntimeVulnerabilities\(\)/);
  const fn = extension.match(/async function refreshRuntimeVulnerabilities\(\)[\s\S]*?\n  \}/)[0];
  // Rien dans ce chemin ne peut modifier l etat de connexion du fournisseur.
  assert.doesNotMatch(fn, /runtimeSecurityStatus\s*=/);
  // La preuve est enregistree par capacite, jamais en remplacant l objet :
  // c est ce qui empeche un rafraichissement d effacer les autres capacites.
  assert.match(fn, /recordCapabilityEvidence\(adapter, 'fetchVulnerabilities'/);
  assert.doesNotMatch(fn, /runtimeCapabilityEvidence\s*=/);
  // Et le rafraichissement Manager n a pas ete enveloppe avec celui-ci.
  const manager = extension.match(/async function refreshRuntimeSecurityStatus\([\s\S]*?\n  \}/)[0];
  assert.doesNotMatch(manager, /fetchVulnerabilities|refreshRuntimeVulnerabilities/);
});

test('6 : le diagnostic rapporte le schema, jamais un secret ni une adresse', () => {
  const extension = source('src/extension.js');
  const fn = extension.match(/async function refreshRuntimeVulnerabilities\(\)[\s\S]*?\n  \}/)[0];
  const logs = fn.match(/scanLog\.appendLine\([\s\S]*?\);/g) || [];
  assert.equal(logs.length, 1, 'une seule ligne par rafraichissement, pas un flux');
  const line = logs[0];
  // Le chemin d un champ est du schema ; une URL, un identifiant ou une valeur
  // de document sont du deploiement et n ont rien a faire dans un journal.
  assert.match(line, /field\.path/);
  assert.doesNotMatch(line, /password|secret|indexerUrl|indexerUsername|baseUrl|authorization/i);
  assert.doesNotMatch(line, /items|_source|summary/);
});

test('6 : les mecaniques Wazuh restent sous la frontiere de l adaptateur', () => {
  // Le motif d index et OpenSearch ne remontent jamais dans la couche generique.
  for (const file of ['src/enterprise-domain-pages.js', 'src/integrations/siem-navigation.js', 'src/integrations/siem-vulnerabilities.js', 'src/integrations/siem.js']) {
    const content = source(file);
    assert.doesNotMatch(content, /wazuh-states|_field_caps|_search|aggregations/, `${file} ne doit rien savoir d OpenSearch`);
  }
  assert.equal(VULNERABILITY_INDEX_PATTERN, 'wazuh-states-vulnerabilities-*');
  // Le motif est declare une seule fois, dans le module Indexer.
  const indexer = source('src/integrations/siem-indexer.js');
  assert.equal((indexer.match(/wazuh-states-vulnerabilities-\*/g) || []).length, 1);
});

test('6 : aucune valeur de deploiement n est ecrite dans le code de production', () => {
  const productionFiles = [
    'src/integrations/siem-indexer.js', 'src/integrations/siem-vulnerabilities.js',
    'src/integrations/siem-wazuh.js', 'src/integrations/siem-navigation.js',
    'src/integrations/siem-configuration.js', 'src/integrations/http.js',
    'src/enterprise-domain-pages.js'
  ];
  for (const file of productionFiles) {
    const content = source(file);
    // Ni adresse, ni identifiant, ni agent, ni CVE, ni paquet.
    assert.doesNotMatch(content, /\b\d{1,3}(\.\d{1,3}){3}\b/, `${file} ne doit contenir aucune adresse IP`);
    assert.doesNotMatch(content, /CVE-\d{4}-\d+/, `${file} ne doit contenir aucun CVE`);
    assert.doesNotMatch(content, /agentId\s*[:=]\s*['"]\d+['"]/, `${file} ne doit fixer aucun agent`);
    assert.doesNotMatch(content, /const agents\s*=\s*\[/, `${file} ne doit pas lister d agents`);
    assert.doesNotMatch(content, /admin['"]?\s*[:=]\s*['"]/, `${file} ne doit contenir aucun identifiant`);
  }
  // Les seules valeurs par defaut sont des exemples de saisie, pas des cibles.
  const fields = wazuhAdapter.configurationFields;
  for (const field of fields) {
    assert.equal(field.value, undefined, `${field.id} ne doit pas etre pre-rempli`);
    assert.equal(field.default, undefined, `${field.id} ne doit pas avoir de defaut`);
  }
  assert.match(fields.find((field) => field.id === 'indexerUrl').placeholder, /host/, 'un exemple, pas une adresse');
});

test('6 : les choix d asset viennent des donnees, jamais d une liste ecrite', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const toolbar = pages.match(/function vulnerabilityToolbar[\s\S]*?\n}/)[0];
  assert.match(toolbar, /summary\.assets/);
  assert.doesNotMatch(toolbar, /Agent 0|00\d/);
  const facet = pages.match(/function facetFilter[\s\S]*?\n}/)[0];
  assert.match(facet, /options\.map/);
});
