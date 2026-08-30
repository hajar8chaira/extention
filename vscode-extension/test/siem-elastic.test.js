'use strict';

/**
 * Phase S2 — Elastic Security.
 *
 * The point of these tests is that Elastic is NOT Wazuh with different names.
 * It talks to Kibana rather than to a search cluster, it has no index pattern
 * of its own, it cannot page, and it has no asset inventory. Each of those is
 * asserted, because each is a place where copying the first adapter would have
 * produced something that looked right and lied.
 *
 * Every value here is invented. No address, key, host, rule or technique from
 * any real deployment appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  elasticAdapter, ALERTS_PATH, LIMITS, spacePath, alertSearchBody, probeBody,
  techniquesFrom, alertsFromKibana, classifyFailure
} = require('../src/integrations/siem-elastic');
const { SIEM_PROVIDERS, siemAdapter, isSupportedSiemProvider } = require('../src/integrations/siem');
const { assertAdapterContract, CAPABILITY_STATE } = require('../src/integrations/siem-contract');
const { resolveRuntimeCapabilities, runtimeCapabilityTabs, RUNTIME_CAPABILITY_STATE } = require('../src/integrations/siem-navigation');
const { CAPABILITY } = require('../src/integrations/siem-contract');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const markup = (html) => html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));

const FICTIONAL = Object.freeze({
  kibana: 'https://kibana.example.invalid:5601',
  apiKey: 'elastic-fixture-api-key',
  space: 'fixture-space',
  host: 'fixture-host-delta',
  user: 'fixture-user',
  ruleId: 'fixture-rule-0001',
  technique: 'T9998'
});

function config(extra = {}) {
  return { url: FICTIONAL.kibana, ...extra };
}
const secrets = { apiKey: FICTIONAL.apiKey };

function recorder(answers = []) {
  const calls = [];
  const queue = [...answers];
  const request = async (url, options = {}) => {
    calls.push({ url, options, body: options.body ? JSON.parse(options.body) : null });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return next || {};
  };
  return { calls, request };
}

function alertDocument(overrides = {}) {
  return {
    _id: 'fixture-alert-1',
    _source: {
      '@timestamp': '2026-08-20T09:01:00Z',
      kibana: {
        alert: {
          severity: 'high',
          reason: 'Fixture detection reason.',
          workflow_status: 'open',
          rule: {
            name: 'Fixture detection rule',
            rule_id: FICTIONAL.ruleId,
            uuid: 'fixture-uuid',
            threat: [{
              framework: 'MITRE ATT&CK',
              tactic: { id: 'TA9999', name: 'Fixture tactic' },
              technique: [{ id: FICTIONAL.technique, name: 'Fixture technique', subtechnique: [{ id: 'T9998.001' }] }]
            }]
          }
        }
      },
      host: { name: FICTIONAL.host },
      user: { name: FICTIONAL.user }
    },
    ...overrides
  };
}

const searchResponse = (hits, total = hits.length) => ({ hits: { total: { value: total, relation: 'eq' }, hits } });

// ===========================================================================
// Contract and registry
// ===========================================================================

test('elastic : l adaptateur respecte le contrat partage', () => {
  assert.doesNotThrow(() => assertAdapterContract(elasticAdapter));
  assert.equal(siemAdapter('elastic'), elasticAdapter);
  assert.equal(isSupportedSiemProvider('elastic'), true);
  const provider = SIEM_PROVIDERS.find((entry) => entry.id === 'elastic');
  assert.equal(provider.implemented, true);
  assert.equal(provider.status, 'supported');
});

test('elastic : le schema decrit Kibana, pas Elasticsearch', () => {
  const ids = elasticAdapter.configurationFields.map((field) => field.id);
  assert.deepEqual(ids, ['url', 'apiKey', 'space', 'allowSelfSigned']);
  const url = elasticAdapter.configurationFields.find((field) => field.id === 'url');
  assert.match(url.label, /Kibana/);
  assert.match(url.hint, /not Elasticsearch/i);
  const key = elasticAdapter.configurationFields.find((field) => field.id === 'apiKey');
  assert.equal(key.secret, true);
  assert.equal(key.required, true);
  const space = elasticAdapter.configurationFields.find((field) => field.id === 'space');
  assert.equal(space.group, 'advanced');
  assert.equal(space.required, undefined);
  const tls = elasticAdapter.configurationFields.find((field) => field.id === 'allowSelfSigned');
  assert.equal(tls.type, 'boolean');
  assert.match(tls.hint, /Off by default/);
});

test('elastic : ne declare que ce que l API des detections sert reellement', () => {
  assert.equal(elasticAdapter.capabilities.alerts, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(elasticAdapter.capabilities.mitre, CAPABILITY_STATE.REQUIRES_CONFIG);
  // Kibana n expose pas d inventaire d hotes que tout deploiement possede :
  // agreger `host.name` depuis les alertes decrirait « les hotes ayant declenche
  // une alerte », pas un parc. La capacite reste indisponible.
  assert.equal(elasticAdapter.capabilities.assets, CAPABILITY_STATE.UNAVAILABLE);
  for (const absent of ['vulnerabilities', 'sca', 'fim', 'incidents', 'rawEvents']) {
    assert.equal(elasticAdapter.capabilities[absent], CAPABILITY_STATE.UNAVAILABLE, absent);
  }
  // Aucun fetcher n est declare pour une capacite indisponible.
  assert.equal(elasticAdapter.fetchVulnerabilities, undefined);
  assert.deepEqual(elasticAdapter.capabilityFetchers.fetchAlerts, ['alerts', 'mitre']);
});

test('elastic : n emprunte rien a l adaptateur Wazuh', () => {
  const elastic = source('src/integrations/siem-elastic.js');
  for (const wazuhism of ['wazuh-alerts', 'wazuh-states', '_field_caps', '/manager/info', 'rule.level', 'agent.id', 'siem-indexer']) {
    assert.ok(!elastic.includes(wazuhism), `${wazuhism} n appartient pas a Elastic`);
  }
  // Et il ne parle qu a Kibana.
  assert.equal(ALERTS_PATH, '/api/detection_engine/signals/search');
  assert.equal((elastic.match(/\/api\//g) || []).length >= 1, true);
});

// ===========================================================================
// Requests
// ===========================================================================

test('elastic : la sonde interroge l API des detections, sans ramener de document', async () => {
  const { calls, request } = recorder([searchResponse([], 7)]);
  const probe = await elasticAdapter.probeAlerts(config(), secrets, { request });

  assert.equal(probe.ok, true);
  assert.equal(probe.state, CAPABILITY_STATE.READY);
  assert.equal(probe.total, 7);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith(ALERTS_PATH), calls[0].url);
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(calls[0].body, probeBody());
  assert.equal(calls[0].body.size, 0);
});

test('elastic : sans URL ou sans cle, aucune requete n est emise', async () => {
  for (const [conf, sec] of [[{}, secrets], [config(), {}]]) {
    const { calls, request } = recorder([searchResponse([])]);
    const probe = await elasticAdapter.probeAlerts(conf, sec, { request });
    assert.equal(calls.length, 0);
    assert.equal(probe.state, CAPABILITY_STATE.REQUIRES_CONFIG);
    assert.equal(probe.code, 'not-configured');
  }
});

test('elastic : l espace Kibana est un prefixe d URL, absent par defaut', async () => {
  assert.equal(spacePath('', ALERTS_PATH), ALERTS_PATH);
  assert.equal(spacePath('fixture space', '/api/x'), '/s/fixture%20space/api/x');

  const withSpace = recorder([searchResponse([])]);
  await elasticAdapter.probeAlerts(config({ space: FICTIONAL.space }), secrets, { request: withSpace.request });
  assert.match(withSpace.calls[0].url, new RegExp(`/s/${FICTIONAL.space}/api/detection_engine`));

  const withoutSpace = recorder([searchResponse([])]);
  await elasticAdapter.probeAlerts(config(), secrets, { request: withoutSpace.request });
  assert.doesNotMatch(withoutSpace.calls[0].url, /\/s\//);
});

test('elastic : la lecture est bornee et triee, jamais paginee cote serveur', async () => {
  const { calls, request } = recorder([searchResponse([alertDocument()])]);
  await elasticAdapter.fetchAlerts(config(), secrets, { request });
  const body = calls[0].body;

  assert.equal(body.size, LIMITS.WINDOW);
  assert.deepEqual(body.sort, [{ '@timestamp': { order: 'desc' } }]);
  assert.equal(body.track_total_hits, true);
  // L API des detections n accepte ni `from` ni `search_after` : ne pas les
  // envoyer est ce qui empeche de promettre une pagination qui n existe pas.
  assert.equal('from' in body, false);
  assert.equal('search_after' in body, false);

  // Aucun appelant ne peut demander l index entier.
  assert.equal(alertSearchBody({ limit: 100000 }).size, LIMITS.MAX_WINDOW);
  assert.equal(alertSearchBody({ limit: -3 }).size, LIMITS.WINDOW);
  assert.equal(alertSearchBody({}).size, LIMITS.WINDOW);
});

// ===========================================================================
// Normalization
// ===========================================================================

test('elastic : un document Kibana devient une alerte normalisee', () => {
  const [alert] = alertsFromKibana([alertDocument()]);
  assert.equal(alert.id, 'fixture-alert-1');
  assert.equal(alert.severity, 'HIGH');
  assert.equal(alert.title, 'Fixture detection rule');
  assert.equal(alert.description, 'Fixture detection reason.');
  assert.equal(alert.ruleId, FICTIONAL.ruleId);
  assert.equal(alert.endpoint, FICTIONAL.host);
  assert.equal(alert.user, FICTIONAL.user);
  assert.equal(alert.source, 'elastic');
  assert.equal(alert.status, 'open');
  assert.deepEqual(alert.mitreTechniques, [FICTIONAL.technique, 'T9998.001']);
});

test('elastic : la severite suit le vocabulaire d Elastic, sans etre re-notee', () => {
  const severities = ['critical', 'high', 'medium', 'low'].map((severity) => alertsFromKibana([
    { _id: 'x', _source: { kibana: { alert: { severity, rule: { name: 'r' } } } } }
  ])[0].severity);
  assert.deepEqual(severities, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  // Aucun score de risque n est converti en severite : Elastic donne les deux
  // separement et le modele ne melange pas les deux notions.
  const elastic = source('src/integrations/siem-elastic.js');
  assert.doesNotMatch(elastic, /risk_score/);
});

test('elastic : ce que le document ne porte pas reste absent', () => {
  const [bare] = alertsFromKibana([{ _id: 'sparse', _source: { kibana: { alert: { rule: {} } } } }]);
  assert.equal(bare.endpoint, '');
  assert.equal(bare.user, '');
  assert.equal(bare.ruleId, '');
  assert.equal(bare.timestamp, '');
  assert.deepEqual(bare.mitreTechniques, [], 'aucune technique inferee');
  assert.equal(bare.title, 'Runtime security alert');
  assert.equal(bare.status, 'open');
});

test('elastic : MITRE vient des menaces de la regle, jamais d ailleurs', () => {
  assert.deepEqual(techniquesFrom(undefined), []);
  assert.deepEqual(techniquesFrom([]), []);
  assert.deepEqual(techniquesFrom([{ tactic: { id: 'TA0001' } }]), [], 'une tactique seule n est pas une technique');
  assert.deepEqual(techniquesFrom([
    { technique: [{ id: 'T1000' }, { id: 'T1000' }] },
    { technique: [{ id: 'T2000', subtechnique: [{ id: 'T2000.001' }] }] }
  ]), ['T1000', 'T2000', 'T2000.001']);
});

test('elastic : une reponse malformee ne devient pas une liste credible', async () => {
  for (const payload of [{}, { hits: null }, { hits: { hits: 'not-an-array' } }]) {
    const { request } = recorder([payload]);
    const result = await elasticAdapter.fetchAlerts(config(), secrets, { request });
    assert.equal(result.ok, true);
    assert.deepEqual(result.alerts, []);
  }
});

// ===========================================================================
// Failure isolation
// ===========================================================================

test('elastic : chaque classe d echec est distinguee et actionnable', () => {
  assert.equal(classifyFailure({ code: 'AUTH_ERROR' }), 'auth-error');
  assert.equal(classifyFailure({ code: 'TIMEOUT' }), 'timeout');
  assert.equal(classifyFailure({ code: 'HTTP_ERROR', message: 'Service externe HTTP 404.' }), 'not-found');
  assert.equal(classifyFailure({ code: 'HTTP_ERROR', message: 'Service externe HTTP 500.' }), 'query-failed');
  assert.equal(classifyFailure({ code: 'MALFORMED' }), 'malformed');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'self-signed certificate in certificate chain' }), 'tls-error');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'connect ECONNREFUSED' }), 'unreachable');
});

test('elastic : un 404 dit que l URL ne pointe pas sur Kibana', async () => {
  const { request } = recorder([new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR')]);
  const probe = await elasticAdapter.probeAlerts(config(), secrets, { request });
  assert.equal(probe.ok, false);
  assert.equal(probe.code, 'not-found');
  assert.match(probe.message, /points at Kibana/);
});

test('elastic : une panne des alertes n emporte que ses propres capacites', () => {
  const resolved = resolveRuntimeCapabilities(elasticAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'error' }, mitre: { state: 'error' }
  });
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(resolved[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.ERROR);
  // Ce que l adaptateur ne sert pas ne devient pas « en erreur ».
  assert.equal(resolved[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
});

test('elastic : les sections offertes sont exactement celles qui sont prouvees', () => {
  const cold = resolveRuntimeCapabilities(elasticAdapter, { configured: true, status: 'online' });
  assert.deepEqual(runtimeCapabilityTabs(cold).map((tab) => tab.id), ['overview'], 'rien sans preuve');

  const probed = resolveRuntimeCapabilities(elasticAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  // Ni Assets ni Vulnerabilities : Elastic n a pas la meme forme que Wazuh.
  assert.deepEqual(runtimeCapabilityTabs(probed).map((tab) => tab.id), ['overview', 'alerts', 'mitre']);
});

// ===========================================================================
// Security
// ===========================================================================

test('elastic : la cle part en en-tete, jamais dans une URL', async () => {
  const { calls, request } = recorder([searchResponse([])]);
  await elasticAdapter.probeAlerts(config({ space: FICTIONAL.space }), secrets, { request });
  const call = calls[0];
  assert.doesNotMatch(call.url, new RegExp(FICTIONAL.apiKey));
  assert.doesNotMatch(call.url, /@/);
  assert.equal(call.options.headers.authorization, `ApiKey ${FICTIONAL.apiKey}`);
  assert.equal(call.options.headers['kbn-xsrf'], 'true');
});

test('elastic : TLS strict par defaut, relache seulement sur un vrai booleen', async () => {
  const strict = recorder([searchResponse([])]);
  await elasticAdapter.probeAlerts(config(), secrets, { request: strict.request });
  assert.equal(strict.calls[0].options.tls, undefined);

  for (const value of ['true', 1, 'yes', {}]) {
    const io = recorder([searchResponse([])]);
    await elasticAdapter.probeAlerts(config({ allowSelfSigned: value }), secrets, { request: io.request });
    assert.equal(io.calls[0].options.tls, undefined, JSON.stringify(value));
  }

  const relaxed = recorder([searchResponse([])]);
  await elasticAdapter.probeAlerts(config({ allowSelfSigned: true }), secrets, { request: relaxed.request });
  assert.deepEqual(relaxed.calls[0].options.tls, { allowSelfSigned: true });

  assert.doesNotMatch(source('src/integrations/siem-elastic.js'), /NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized/);
});

test('elastic : aucune cle ne survit dans un etat ni dans un message', async () => {
  const leaky = new IntegrationHttpError(`connect ECONNREFUSED ApiKey ${FICTIONAL.apiKey}`, 'OFFLINE');
  const { request } = recorder([leaky]);
  const model = await elasticAdapter.fetchStatus(config(), secrets, { request });
  assert.doesNotMatch(JSON.stringify(model), new RegExp(FICTIONAL.apiKey));
  assert.doesNotMatch(model.message || '', /ApiKey [A-Za-z0-9+/=._-]{8}/);
});

test('elastic : la cle n atteint jamais le HTML rendu', async () => {
  const { request } = recorder([searchResponse([alertDocument()])]);
  const model = await elasticAdapter.fetchStatus(config(), secrets, { request });
  const alerts = await elasticAdapter.fetchAlerts(config(), secrets, { request });
  const html = renderRuntimeSecurityPageHtml({
    runtime: {
      ...model, alerts: alerts.alerts,
      alertSummary: { critical: 0, high: 1, medium: 0, low: 0 },
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      values: config({ space: FICTIONAL.space }), secretsConfigured: { apiKey: true }
    },
    openConfig: true,
    capabilityEvidence: { alerts: { state: 'ready' }, mitre: { state: 'ready' } }
  }, 'n', 'light');
  assert.doesNotMatch(html, new RegExp(FICTIONAL.apiKey));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
});

// ===========================================================================
// Rendering through the generic page
// ===========================================================================

test('elastic : la page rend Elastic sans rien connaitre d Elastic', async () => {
  const { request } = recorder([searchResponse([alertDocument()])]);
  const model = await elasticAdapter.fetchStatus(config(), secrets, { request });
  const alerts = await elasticAdapter.fetchAlerts(config(), secrets, { request });
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: {
      ...model, alerts: alerts.alerts,
      alertSummary: { critical: 0, high: 1, medium: 0, low: 0 },
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 }
    },
    tab: 'alerts',
    capabilityEvidence: { alerts: { state: 'ready' }, mitre: { state: 'ready' } }
  }, 'n', 'light'));

  assert.match(html, /Provider: Elastic Security/);
  assert.ok(html.includes('Fixture detection rule'));
  assert.ok(html.includes(FICTIONAL.host));
  assert.deepEqual([...html.matchAll(/data-tab="([a-z]+)"/g)].map((match) => match[1])
    .filter((id, index, all) => all.indexOf(id) === index), ['overview', 'alerts', 'mitre']);

  // Le rendu generique ne nomme aucun fournisseur ni aucune route.
  const pages = source('src/enterprise-domain-pages.js');
  for (const leaked of ['elastic', 'kibana', 'detection_engine', 'kibana.alert']) {
    assert.ok(!pages.toLowerCase().includes(leaked.toLowerCase()), `${leaked} ne doit pas atteindre la page`);
  }
});

test('elastic : aucune valeur de deploiement dans le code de production', () => {
  const elastic = source('src/integrations/siem-elastic.js');
  assert.doesNotMatch(elastic, /\b\d{1,3}(\.\d{1,3}){3}\b/, 'aucune adresse IP');
  assert.doesNotMatch(elastic, /localhost|127\.0\.0\.1/);
  assert.doesNotMatch(elastic, /apiKey\s*[:=]\s*['"][^'"]+['"]/, 'aucune cle en dur');
  for (const field of elasticAdapter.configurationFields) {
    assert.equal(field.value, undefined, `${field.id} ne doit pas etre pre-rempli`);
    assert.equal(field.default, undefined, `${field.id} ne doit pas avoir de defaut`);
  }
  assert.match(elasticAdapter.configurationFields[0].placeholder, /host/, 'un exemple, pas une adresse');
});
