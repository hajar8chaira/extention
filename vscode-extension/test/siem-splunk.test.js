'use strict';

/**
 * Phase S3 — Splunk Enterprise Security.
 *
 * Splunk shares nothing with the two SIEM adapters before it: no document
 * index, no detections route, only SPL submitted to a management API with
 * form-encoded parameters. Each of those differences is asserted, because each
 * is a place where copying an earlier adapter would produce something that
 * looked right and returned nothing.
 *
 * Every value is invented. No address, token, host, notable or technique from
 * any real deployment appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  splunkAdapter, SEARCH_PATH, NOTABLE_INDEX, LIMITS, notableSearch,
  techniquesFrom, alertsFromNotables, classifyFailure
} = require('../src/integrations/siem-splunk');
const { SIEM_PROVIDERS, siemAdapter, isSupportedSiemProvider } = require('../src/integrations/siem');
const { assertAdapterContract, CAPABILITY_STATE, CAPABILITY } = require('../src/integrations/siem-contract');
const { resolveRuntimeCapabilities, runtimeCapabilityTabs, RUNTIME_CAPABILITY_STATE } = require('../src/integrations/siem-navigation');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const markup = (html) => html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));

const FICTIONAL = Object.freeze({
  management: 'https://splunk.example.invalid:8089',
  token: 'splunk-fixture-token',
  host: 'fixture-host-epsilon',
  user: 'fixture-analyst',
  search: 'Fixture - Correlation Search',
  technique: 'T9997'
});

const config = (extra = {}) => ({ url: FICTIONAL.management, ...extra });
const secrets = { token: FICTIONAL.token };

function server(answers = []) {
  const calls = [];
  const queue = [...answers];
  const request = async (url, options = {}) => {
    const params = options.body ? new URLSearchParams(options.body) : new URLSearchParams();
    calls.push({ url, options, params, search: params.get('search') });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return next || { results: [] };
  };
  return { calls, request };
}

const notable = (overrides = {}) => ({
  _time: '2026-08-20T09:01:00Z',
  event_id: 'fixture-notable-1',
  rule_name: 'Fixture notable rule',
  search_name: FICTIONAL.search,
  urgency: 'high',
  status_label: 'In Progress',
  dest: FICTIONAL.host,
  user: FICTIONAL.user,
  'annotations.mitre_attack.mitre_technique_id': [FICTIONAL.technique],
  ...overrides
});

// ===========================================================================
// Contract and registry
// ===========================================================================

test('splunk : l adaptateur respecte le contrat partage', () => {
  assert.doesNotThrow(() => assertAdapterContract(splunkAdapter));
  assert.equal(siemAdapter('splunk'), splunkAdapter);
  assert.equal(isSupportedSiemProvider('splunk'), true);
  assert.equal(SIEM_PROVIDERS.find((entry) => entry.id === 'splunk').implemented, true);
});

test('splunk : le schema vise l interface de gestion, pas l interface web', () => {
  const ids = splunkAdapter.configurationFields.map((field) => field.id);
  assert.deepEqual(ids, ['url', 'token', 'allowSelfSigned']);
  const url = splunkAdapter.configurationFields.find((field) => field.id === 'url');
  assert.match(url.hint, /8089/);
  assert.match(url.hint, /not the web interface/i);
  const token = splunkAdapter.configurationFields.find((field) => field.id === 'token');
  assert.equal(token.secret, true);
  assert.equal(token.required, true);
  // Aucun champ speculatif de l ancien catalogue n a survecu.
  assert.equal(ids.includes('index'), false, 'l index des notables est un fait produit, pas un reglage');
});

test('splunk : ne declare que ce que les notables servent reellement', () => {
  assert.equal(splunkAdapter.capabilities.alerts, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(splunkAdapter.capabilities.mitre, CAPABILITY_STATE.REQUIRES_CONFIG);
  // Les hotes vus dans un notable ne sont pas un inventaire faisant autorite.
  assert.equal(splunkAdapter.capabilities.assets, CAPABILITY_STATE.UNAVAILABLE);
  // Un notable EST l alerte : le compter aussi comme incident serait le compter deux fois.
  assert.equal(splunkAdapter.capabilities.incidents, CAPABILITY_STATE.UNAVAILABLE);
  for (const absent of ['vulnerabilities', 'sca', 'fim', 'rawEvents']) {
    assert.equal(splunkAdapter.capabilities[absent], CAPABILITY_STATE.UNAVAILABLE, absent);
  }
  assert.deepEqual(splunkAdapter.capabilityFetchers.fetchAlerts, ['alerts', 'mitre']);
});

test('splunk : n emprunte rien aux adaptateurs precedents', () => {
  const splunk = source('src/integrations/siem-splunk.js');
  for (const foreign of ['wazuh-alerts', '_field_caps', '/manager/info', 'detection_engine', 'kibana.alert', 'ApiKey ']) {
    assert.ok(!splunk.includes(foreign), `${foreign} n appartient pas a Splunk`);
  }
  for (const other of ['src/integrations/siem-wazuh.js', 'src/integrations/siem-elastic.js']) {
    assert.ok(!source(other).includes('search/jobs'), `${other} ne doit rien savoir de Splunk`);
  }
});

// ===========================================================================
// The search: form-encoded, one shot, bounded
// ===========================================================================

test('splunk : la recherche est envoyee en formulaire, pas en JSON', async () => {
  const { calls, request } = server([{ results: [notable()] }]);
  await splunkAdapter.fetchAlerts(config(), secrets, { request });

  const call = calls[0];
  assert.ok(call.url.endsWith(SEARCH_PATH), call.url);
  assert.equal(call.options.method, 'POST');
  assert.match(call.options.headers['content-type'], /x-www-form-urlencoded/);
  // Le corps est bien encode en formulaire : un corps JSON renverrait vide.
  assert.doesNotMatch(call.options.body, /^\{/);
  assert.equal(call.params.get('output_mode'), 'json');
});

test('splunk : exec_mode oneshot evite tout cycle de job', async () => {
  const { calls, request } = server([{ results: [] }]);
  await splunkAdapter.fetchAlerts(config(), secrets, { request });

  assert.equal(calls[0].params.get('exec_mode'), 'oneshot');
  // Une seule requete : aucun SID, aucun sondage, aucune recuperation separee.
  assert.equal(calls.length, 1);
  for (const call of calls) {
    assert.doesNotMatch(call.url, /\/jobs\/[^/]+\/results/);
  }
  // Et le generique n apprend jamais que Splunk a un cycle de recherche.
  const pages = source('src/enterprise-domain-pages.js');
  for (const leaked of ['search/jobs', 'exec_mode', 'oneshot', 'splunk', 'notable']) {
    assert.ok(!pages.toLowerCase().includes(leaked.toLowerCase()), `${leaked} ne doit pas atteindre la page`);
  }
});

test('splunk : la lecture est bornee des deux cotes', async () => {
  const { calls, request } = server([{ results: [] }]);
  await splunkAdapter.fetchAlerts(config(), secrets, { request });
  const call = calls[0];

  assert.equal(call.params.get('count'), String(LIMITS.WINDOW));
  assert.match(call.search, new RegExp(`index=${NOTABLE_INDEX}`));
  // `head` borne ce que le moteur produit, `count` ce que l API renvoie.
  assert.match(call.search, new RegExp(`head ${LIMITS.WINDOW}`));
  assert.equal(call.params.get('earliest_time'), LIMITS.EARLIEST, 'fenetre temporelle explicite');

  // Aucun appelant ne peut demander une recherche illimitee.
  assert.equal(notableSearch({ limit: 100000 }).size, LIMITS.MAX_WINDOW);
  assert.equal(notableSearch({ limit: -5 }).size, LIMITS.WINDOW);
  assert.equal(notableSearch({}).size, LIMITS.WINDOW);
});

test('splunk : la sonde demande une seule ligne', async () => {
  const { calls, request } = server([{ results: [] }]);
  const probe = await splunkAdapter.probeAlerts(config(), secrets, { request });
  assert.equal(probe.ok, true);
  assert.equal(probe.state, CAPABILITY_STATE.READY);
  assert.match(calls[0].search, /head 1$/);
  assert.equal(calls[0].params.get('count'), '1');
});

test('splunk : sans URL ou sans jeton, aucune requete n est emise', async () => {
  for (const [conf, sec] of [[{}, secrets], [config(), {}]]) {
    const { calls, request } = server([{ results: [] }]);
    const probe = await splunkAdapter.probeAlerts(conf, sec, { request });
    assert.equal(calls.length, 0);
    assert.equal(probe.state, CAPABILITY_STATE.REQUIRES_CONFIG);
  }
});

// ===========================================================================
// Normalization
// ===========================================================================

test('splunk : un notable devient une alerte normalisee', () => {
  const [alert] = alertsFromNotables([notable()]);
  assert.equal(alert.id, 'fixture-notable-1');
  assert.equal(alert.severity, 'HIGH', 'urgency est le vocabulaire documente d ES');
  assert.equal(alert.title, 'Fixture notable rule');
  assert.equal(alert.ruleId, FICTIONAL.search);
  assert.equal(alert.endpoint, FICTIONAL.host);
  assert.equal(alert.user, FICTIONAL.user);
  assert.equal(alert.status, 'In Progress');
  assert.equal(alert.source, 'splunk');
  assert.deepEqual(alert.mitreTechniques, [FICTIONAL.technique]);
});

test('splunk : urgency couvre le vocabulaire documente', () => {
  const severities = ['critical', 'high', 'medium', 'low', 'informational']
    .map((urgency) => alertsFromNotables([{ urgency, rule_name: 'r' }])[0].severity);
  assert.deepEqual(severities, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
});

test('splunk : un score de risque n est jamais converti en severite', () => {
  const splunk = source('src/integrations/siem-splunk.js');
  assert.doesNotMatch(splunk, /risk_score|severityFromScale/);
  // Un notable qui ne porte qu un score n a pas de severite inventee.
  const [alert] = alertsFromNotables([{ rule_name: 'r', risk_score: '90' }]);
  assert.equal(alert.severity, 'INFO', 'la valeur par defaut du modele, pas une deduction');
});

test('splunk : ce que le notable ne porte pas reste absent', () => {
  const [named] = alertsFromNotables([{ search_name: FICTIONAL.search }]);
  // Sans `rule_name`, le nom de la recherche correlee EST le nom du notable.
  assert.equal(named.title, FICTIONAL.search);
  assert.equal(named.ruleId, FICTIONAL.search);

  const [bare] = alertsFromNotables([{}]);
  assert.equal(bare.endpoint, '');
  assert.equal(bare.user, '');
  assert.equal(bare.rawReference, '');
  assert.deepEqual(bare.mitreTechniques, [], 'aucune technique inferee');
  assert.equal(bare.title, 'Runtime security alert');
  assert.equal(bare.status, 'open');
  assert.ok(bare.id, 'une identite reste derivable');
});

test('splunk : MITRE vient des annotations, sous leurs deux formes', () => {
  assert.deepEqual(techniquesFrom({}), []);
  assert.deepEqual(techniquesFrom({ 'annotations.mitre_attack.mitre_technique_id': 'T1000' }), ['T1000']);
  assert.deepEqual(techniquesFrom({ 'annotations.mitre_attack.mitre_technique_id': ['T1000', 'T1000', 'T2000'] }), ['T1000', 'T2000']);
  assert.deepEqual(techniquesFrom({ annotations: { mitre_attack: { mitre_technique_id: ['T3000'] } } }), ['T3000']);
  // Le nom de la regle n est jamais une source de techniques.
  assert.deepEqual(techniquesFrom({ rule_name: 'T1110 brute force' }), []);
});

test('splunk : une reponse malformee ne devient pas une liste credible', async () => {
  for (const payload of [{}, { results: null }, { results: 'nope' }, null]) {
    const { request } = server([payload]);
    const result = await splunkAdapter.fetchAlerts(config(), secrets, { request });
    assert.equal(result.ok, true);
    assert.deepEqual(result.alerts, []);
  }
});

// ===========================================================================
// Failures
// ===========================================================================

test('splunk : chaque classe d echec est distinguee', () => {
  assert.equal(classifyFailure({ code: 'AUTH_ERROR' }), 'auth-error');
  assert.equal(classifyFailure({ code: 'TIMEOUT' }), 'timeout');
  assert.equal(classifyFailure({ code: 'HTTP_ERROR', message: 'Service externe HTTP 404.' }), 'not-found');
  assert.equal(classifyFailure({ code: 'HTTP_ERROR', message: 'Service externe HTTP 500.' }), 'search-failed');
  assert.equal(classifyFailure({ code: 'MALFORMED' }), 'malformed');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'self-signed certificate in certificate chain' }), 'tls-error');
  assert.equal(classifyFailure({ code: 'OFFLINE', message: 'connect ECONNREFUSED' }), 'unreachable');
});

test('splunk : les etats de connexion sont distincts et actionnables', async () => {
  const cases = [
    [new IntegrationHttpError('refuse', 'AUTH_ERROR'), 'auth-error', /rejected this token/],
    [new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE'), 'offline', /unreachable/],
    [new IntegrationHttpError('slow', 'TIMEOUT'), 'timeout', /did not answer/],
    [new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR'), 'offline', /management interface/]
  ];
  for (const [error, expected, message] of cases) {
    const { request } = server([error]);
    const model = await splunkAdapter.fetchStatus(config(), secrets, { request });
    assert.equal(model.connectionStatus, expected, error.message);
    assert.match(model.message, message);
  }
});

test('splunk : une panne des notables n emporte que ses propres capacites', () => {
  const resolved = resolveRuntimeCapabilities(splunkAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'error' }, mitre: { state: 'error' }
  });
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(resolved[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(resolved[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);

  const probed = resolveRuntimeCapabilities(splunkAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.deepEqual(runtimeCapabilityTabs(probed).map((tab) => tab.id), ['overview', 'alerts', 'mitre']);
});

// ===========================================================================
// Security
// ===========================================================================

test('splunk : le jeton part en en-tete, jamais dans une URL ni un corps', async () => {
  const { calls, request } = server([{ results: [] }]);
  await splunkAdapter.fetchAlerts(config(), secrets, { request });
  const call = calls[0];
  assert.equal(call.options.headers.authorization, `Bearer ${FICTIONAL.token}`);
  assert.doesNotMatch(call.url, new RegExp(FICTIONAL.token));
  assert.doesNotMatch(call.url, /@/);
  assert.doesNotMatch(call.options.body, new RegExp(FICTIONAL.token));
});

test('splunk : TLS strict par defaut, relache seulement sur un vrai booleen', async () => {
  const strict = server([{ results: [] }]);
  await splunkAdapter.fetchAlerts(config(), secrets, { request: strict.request });
  assert.equal(strict.calls[0].options.tls, undefined);

  for (const value of ['true', 1, 'yes', {}]) {
    const io = server([{ results: [] }]);
    await splunkAdapter.fetchAlerts(config({ allowSelfSigned: value }), secrets, { request: io.request });
    assert.equal(io.calls[0].options.tls, undefined, JSON.stringify(value));
  }

  const relaxed = server([{ results: [] }]);
  await splunkAdapter.fetchAlerts(config({ allowSelfSigned: true }), secrets, { request: relaxed.request });
  assert.deepEqual(relaxed.calls[0].options.tls, { allowSelfSigned: true });

  assert.doesNotMatch(source('src/integrations/siem-splunk.js'), /NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized/);
});

test('splunk : aucun jeton ne survit dans un etat, un message ou le HTML', async () => {
  const leaky = new IntegrationHttpError(`connect ECONNREFUSED Bearer ${FICTIONAL.token}`, 'OFFLINE');
  const { request } = server([leaky]);
  const model = await splunkAdapter.fetchStatus(config(), secrets, { request });
  assert.doesNotMatch(JSON.stringify(model), new RegExp(FICTIONAL.token));

  const ok = server([{ results: [notable()] }]);
  const good = await splunkAdapter.fetchStatus(config(), secrets, { request: ok.request });
  const html = renderRuntimeSecurityPageHtml({
    runtime: {
      ...good, alerts: [], alertSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      values: config(), secretsConfigured: { token: true }
    },
    openConfig: true
  }, 'n', 'light');
  assert.doesNotMatch(html, new RegExp(FICTIONAL.token));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
});

// ===========================================================================
// Rendering through the generic page
// ===========================================================================

test('splunk : la page rend Splunk sans rien connaitre de Splunk', async () => {
  const { request } = server([{ results: [notable()] }]);
  const model = await splunkAdapter.fetchStatus(config(), secrets, { request });
  const alerts = await splunkAdapter.fetchAlerts(config(), secrets, { request });
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: {
      ...model, alerts: alerts.alerts,
      alertSummary: { critical: 0, high: 1, medium: 0, low: 0 },
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 }
    },
    tab: 'alerts',
    capabilityEvidence: { alerts: { state: 'ready' }, mitre: { state: 'ready' } }
  }, 'n', 'light'));

  assert.match(html, /Provider: Splunk Enterprise Security/);
  assert.ok(html.includes('Fixture notable rule'));
  assert.ok(html.includes(FICTIONAL.host));
  // Ni Assets ni Vulnerabilities : Splunk n a pas la forme de Wazuh.
  assert.deepEqual([...html.matchAll(/data-tab="([a-z]+)"/g)].map((match) => match[1])
    .filter((id, index, all) => all.indexOf(id) === index), ['overview', 'alerts', 'mitre']);
});

test('splunk : aucune valeur de deploiement dans le code de production', () => {
  const splunk = source('src/integrations/siem-splunk.js');
  assert.doesNotMatch(splunk, /\b\d{1,3}(\.\d{1,3}){3}\b/, 'aucune adresse IP');
  assert.doesNotMatch(splunk, /localhost|127\.0\.0\.1/);
  assert.doesNotMatch(splunk, /token\s*[:=]\s*['"][^'"]{6,}['"]/, 'aucun jeton en dur');
  for (const field of splunkAdapter.configurationFields) {
    assert.equal(field.value, undefined, `${field.id} ne doit pas etre pre-rempli`);
    assert.equal(field.default, undefined, `${field.id} ne doit pas avoir de defaut`);
  }
});
