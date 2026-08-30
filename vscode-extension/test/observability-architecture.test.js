'use strict';

/**
 * Infrastructure is a domain with an adapter slot.
 *
 * Prometheus is the first adapter, not the architecture. What these tests pin
 * is the boundary: the generic layer knows capabilities, section kinds and a
 * normalized model, and knows nothing about PromQL, `/api/v1/*`, `node_*` or
 * any provider's name.
 *
 * Every value here is invented. No address, host, job or metric from any real
 * deployment appears in this file or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  CAPABILITY, DECLARED_STATE, RESOLVED_STATE, SECTION_KIND, SECTION_KINDS,
  assertObservabilityAdapter, resolveCapabilities, visibleSections, buildInfrastructureModel,
  unavailableMetric
} = require('../src/integrations/observability-contract');
const {
  OBSERVABILITY_PROVIDERS, observabilityAdapter, isSupportedObservabilityProvider,
  plannedObservabilityProviders, supportedObservabilityProviders
} = require('../src/integrations/observability');
const { prometheusAdapter } = require('../src/integrations/observability-prometheus');
const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');
const { createProviderConfigurationService } = require('../src/integrations/provider-configuration');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const markup = (html) => html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));

const FICTIONAL = Object.freeze({
  endpoint: 'https://metrics.example.invalid:9090',
  token: 'observability-fixture-secret',
  host: 'fixture-host-alpha:9100'
});

// ===========================================================================
// Contract
// ===========================================================================

function stubAdapter(overrides = {}) {
  return {
    id: 'fixture', label: 'Fixture backend', configurationFields: [],
    validateConfiguration: () => ({ valid: true, errors: [] }),
    testConnection: async () => ({ ok: true }),
    fetchStatus: async () => buildInfrastructureModel({}),
    ...overrides
  };
}

test('contrat : un adaptateur valide est accepte, un adaptateur incomplet non', () => {
  assert.doesNotThrow(() => assertObservabilityAdapter(stubAdapter()));
  assert.doesNotThrow(() => assertObservabilityAdapter(prometheusAdapter));

  assert.throws(() => assertObservabilityAdapter(null), /invalide/);
  assert.throws(() => assertObservabilityAdapter(stubAdapter({ id: '' })), /id et un label/);
  assert.throws(() => assertObservabilityAdapter({ ...stubAdapter(), fetchStatus: undefined }), /fetchStatus/);
  assert.throws(() => assertObservabilityAdapter(stubAdapter({ configurationFields: null })), /configurationFields/);
});

test('contrat : les capacites et les types de champ sont un vocabulaire ferme', () => {
  assert.throws(() => assertObservabilityAdapter(stubAdapter({ capabilities: { telepathy: 'ready' } })), /Capacite inconnue/);
  assert.throws(() => assertObservabilityAdapter(stubAdapter({ capabilities: { cpu: 'peut-etre' } })), /Etat de capacite invalide/);
  assert.throws(() => assertObservabilityAdapter(stubAdapter({
    configurationFields: [{ id: 'x', label: 'X', type: 'colour' }]
  })), /Type de champ inconnu/);
  // Les capacites sont optionnelles : un adaptateur qui n en declare aucune
  // n en supporte aucune.
  assert.doesNotThrow(() => assertObservabilityAdapter(stubAdapter({ capabilities: undefined })));
});

test('contrat : une section reference un type connu et une capacite connue', () => {
  assert.throws(() => assertObservabilityAdapter(stubAdapter({
    sections: [{ id: 's', kind: 'carousel', capability: CAPABILITY.CPU }]
  })), /Type de section inconnu/);
  assert.throws(() => assertObservabilityAdapter(stubAdapter({
    sections: [{ id: 's', kind: SECTION_KIND.METRIC_TILES, capability: 'telepathy' }]
  })), /capacite inconnue/);
  // L ensemble des types est ferme : le rendu les implemente, pas les fournisseurs.
  assert.deepEqual([...SECTION_KINDS].sort(), ['entity-inventory', 'metric-tiles', 'status-list']);
});

test('contrat : configure n est pas capable', () => {
  const adapter = stubAdapter({ capabilities: { cpu: DECLARED_STATE.REQUIRES_PROBE, hostInventory: DECLARED_STATE.READY } });

  // Non configure : rien n est pret.
  const cold = resolveCapabilities(adapter, { configured: false });
  assert.equal(cold[CAPABILITY.CPU], RESOLVED_STATE.REQUIRES_CONFIG);
  assert.equal(cold[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.REQUIRES_CONFIG);

  // Configure, sans preuve : ce qui exige une sonde reste non prouve.
  const configured = resolveCapabilities(adapter, { configured: true });
  assert.equal(configured[CAPABILITY.CPU], RESOLVED_STATE.REQUIRES_CONFIG);
  assert.equal(configured[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);

  // La preuve decide, dans les deux sens, capacite par capacite.
  const probed = resolveCapabilities(adapter, {
    configured: true, evidence: { cpu: RESOLVED_STATE.READY, hostInventory: RESOLVED_STATE.ERROR }
  });
  assert.equal(probed[CAPABILITY.CPU], RESOLVED_STATE.READY);
  assert.equal(probed[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.ERROR);

  // Une capacite indisponible n est jamais promue.
  const never = resolveCapabilities(stubAdapter({ capabilities: { disk: DECLARED_STATE.UNAVAILABLE } }), {
    configured: true, evidence: { disk: RESOLVED_STATE.READY }
  });
  assert.equal(never[CAPABILITY.DISK], RESOLVED_STATE.UNAVAILABLE);
});

test('contrat : le vocabulaire reste le plus petit qui decrive ce qui existe', () => {
  assert.deepEqual(Object.values(CAPABILITY).sort(), ['cpu', 'disk', 'hostInventory', 'load', 'memory']);
  // Rien de speculatif tant qu aucun adaptateur ne peut le prouver.
  for (const speculative of ['uptime', 'network', 'serviceHealth', 'containers']) {
    assert.equal(Object.values(CAPABILITY).includes(speculative), false, speculative);
  }
});

test('contrat : une metrique absente n est jamais un zero', () => {
  const metric = unavailableMetric();
  assert.equal(metric.available, false);
  assert.equal(metric.value, null);
  assert.equal(metric.display, 'Unavailable');
  assert.ok(metric.reason);
  const model = buildInfrastructureModel({ metrics: { cpu: metric } });
  assert.equal(model.metrics.cpu.value, null);
});

// ===========================================================================
// The Prometheus boundary
// ===========================================================================

test('adaptateur : tout ce qui est Prometheus vit derriere la frontiere', () => {
  const generic = [
    'src/enterprise-domain-pages.js', 'src/integrations/observability.js',
    'src/integrations/observability-contract.js', 'src/integrations/observability-catalogue.js',
    'src/extension.js'
  ];
  for (const file of generic) {
    const content = source(file);
    for (const leaked of ['/api/v1/query', '/api/v1/targets', 'node_cpu_seconds_total', 'node_memory_', 'node_filesystem_', 'node_load1', 'activeTargets', 'PromQL']) {
      assert.ok(!content.includes(leaked), `${leaked} ne doit pas atteindre ${file}`);
    }
  }
  // Et l adaptateur, lui, les connait tous.
  const adapter = source('src/integrations/observability-prometheus.js');
  for (const owned of ['/api/v1/query', '/api/v1/targets', 'node_cpu_seconds_total', 'node_filesystem_size_bytes']) {
    assert.ok(adapter.includes(owned), `${owned} appartient a l adaptateur`);
  }
});

test('adaptateur : le rendu ne contient aucune condition sur un nom de fournisseur', () => {
  const pages = source('src/enterprise-domain-pages.js');
  for (const id of OBSERVABILITY_PROVIDERS.map((provider) => provider.id)) {
    assert.ok(!pages.includes(`'${id}'`), `${id} ne doit pas etre nomme dans le rendu`);
  }
  assert.doesNotMatch(pages, /provider === '[a-z]+'/);
});

test('adaptateur : le schema Prometheus reflete ce que le client sait faire', () => {
  const ids = prometheusAdapter.configurationFields.map((field) => field.id);
  assert.deepEqual(ids, ['url', 'bearerToken', 'allowSelfSigned']);
  const token = prometheusAdapter.configurationFields.find((field) => field.id === 'bearerToken');
  assert.equal(token.secret, true);
  assert.equal(token.type, 'password');
  const tls = prometheusAdapter.configurationFields.find((field) => field.id === 'allowSelfSigned');
  assert.equal(tls.type, 'boolean');
  assert.match(tls.hint, /Off by default/);
  // L inventaire se prouve en repondant ; les metriques hote se sondent.
  assert.equal(prometheusAdapter.capabilities[CAPABILITY.HOST_INVENTORY], DECLARED_STATE.READY);
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(prometheusAdapter.capabilities[capability], DECLARED_STATE.REQUIRES_PROBE, capability);
  }
});

// ===========================================================================
// Transport: secrets and TLS
// ===========================================================================

function recorder(routes) {
  const calls = [];
  const request = async (url, options = {}) => {
    calls.push({ url, options });
    for (const [fragment, answer] of Object.entries(routes)) {
      if (url.includes(fragment)) return typeof answer === 'function' ? answer() : answer;
    }
    return { data: { result: [] } };
  };
  return { calls, request };
}

test('transport : le jeton part en en-tete, jamais dans une URL', async () => {
  const { calls, request } = recorder({ '/targets': { data: { activeTargets: [] } } });
  await prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint }, { bearerToken: FICTIONAL.token }, { request });
  assert.ok(calls.length > 0);
  for (const call of calls) {
    assert.doesNotMatch(call.url, new RegExp(FICTIONAL.token));
    assert.equal(call.options.headers.authorization, `Bearer ${FICTIONAL.token}`);
  }
});

test('transport : TLS strict par defaut, relache seulement sur un vrai booleen', async () => {
  const strict = recorder({});
  await prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint }, {}, { request: strict.request });
  for (const call of strict.calls) assert.equal(call.options.tls, undefined);

  for (const value of ['true', 1, 'yes', {}]) {
    const io = recorder({});
    await prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint, allowSelfSigned: value }, {}, { request: io.request });
    for (const call of io.calls) assert.equal(call.options.tls, undefined, JSON.stringify(value));
  }

  const relaxed = recorder({});
  await prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint, allowSelfSigned: true }, {}, { request: relaxed.request });
  for (const call of relaxed.calls) assert.deepEqual(call.options.tls, { allowSelfSigned: true });

  // Jamais de desactivation globale, nulle part.
  for (const file of ['src/integrations/observability-prometheus.js', 'src/integrations/observability.js', 'src/enterprise-domain-pages.js']) {
    assert.doesNotMatch(source(file), /NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized/);
  }
});

test('transport : le jeton n atteint jamais le HTML', async () => {
  const { request } = recorder({ '/targets': { data: { activeTargets: [] } } });
  const model = await prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint }, { bearerToken: FICTIONAL.token }, { request });
  const html = renderInfrastructurePageHtml({
    prometheus: { ...model, values: { url: FICTIONAL.endpoint }, secretsConfigured: { bearerToken: true } },
    openConfig: true
  }, 'n', 'light');
  assert.doesNotMatch(html, new RegExp(FICTIONAL.token));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
});

// ===========================================================================
// Configuration and persistence
// ===========================================================================

function configurationHarness(store = {}, vault = new Map()) {
  return createProviderConfigurationService({
    configuration: { get: (key, fallback) => (key in store ? store[key] : fallback), update: async (key, value) => { store[key] = value; } },
    secrets: { get: async (key) => vault.get(key) || '', store: async (key, value) => { vault.set(key, value); }, delete: async (key) => { vault.delete(key); } },
    resolveAdapter: observabilityAdapter,
    keys: { activeProvider: 'infrastructure.provider', providersConfig: 'infrastructure.providers', secretPrefix: 'securityCenter.observability' },
    legacy: { provider: 'prometheus', fields: { url: 'prometheus.url' }, secrets: { bearerToken: 'securityCenter.prometheus.bearerToken' } }
  });
}

test('configuration : les secrets ne vont que dans SecretStorage', async () => {
  const store = {};
  const vault = new Map();
  const service = configurationHarness(store, vault);
  await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.endpoint, bearerToken: FICTIONAL.token, allowSelfSigned: false });

  assert.equal(store['infrastructure.providers'].prometheus.url, FICTIONAL.endpoint);
  assert.equal(store['infrastructure.providers'].prometheus.allowSelfSigned, false, 'un booleen faux se persiste');
  assert.equal('bearerToken' in store['infrastructure.providers'].prometheus, false);
  assert.equal(vault.get('securityCenter.observability.prometheus.bearerToken'), FICTIONAL.token);
  // La webview ne recoit qu un booleen.
  assert.deepEqual(await service.describeProviderSecrets('prometheus'), { bearerToken: true });
});

test('configuration : une installation Prometheus existante continue de fonctionner', async () => {
  // Exactement l etat d avant cette phase : une URL et un secret aux anciennes cles.
  const store = { 'prometheus.url': FICTIONAL.endpoint };
  const vault = new Map([['securityCenter.prometheus.bearerToken', FICTIONAL.token]]);
  const service = configurationHarness(store, vault);

  assert.equal(service.getActiveProviderId(), 'prometheus', 'aucun fournisseur actif declare, mais une config heritee');
  assert.equal(service.getProviderConfig('prometheus').url, FICTIONAL.endpoint);
  assert.equal((await service.getProviderSecrets('prometheus')).bearerToken, FICTIONAL.token);
  // Rien n a ete reecrit ni supprime.
  assert.equal(store['prometheus.url'], FICTIONAL.endpoint);
  assert.equal(vault.get('securityCenter.prometheus.bearerToken'), FICTIONAL.token);
  assert.equal(store['infrastructure.providers'], undefined);
});

test('configuration : un fournisseur sans adaptateur ne peut rien enregistrer', async () => {
  const service = configurationHarness();
  for (const provider of plannedObservabilityProviders()) {
    assert.equal(observabilityAdapter(provider.id), null, provider.id);
    assert.equal(isSupportedObservabilityProvider(provider.id), false, provider.id);
    const saved = await service.saveProviderConfiguration(provider.id, { url: FICTIONAL.endpoint });
    assert.equal(saved.ok, false, provider.id);
  }
  // Les deux listes partitionnent le catalogue, et « supporte » veut dire
  // « adosse a un adaptateur » — un invariant, pas une liste figee.
  assert.equal(
    supportedObservabilityProviders().length + plannedObservabilityProviders().length,
    OBSERVABILITY_PROVIDERS.length
  );
  for (const provider of supportedObservabilityProviders()) {
    assert.notEqual(observabilityAdapter(provider.id), null, provider.id);
    assert.ok(provider.configurationFields.length > 0, provider.id);
  }
});

test('catalogue : identite seulement, aucune configuration inventee', () => {
  const catalogue = source('src/integrations/observability-catalogue.js');
  const code = catalogue.slice(catalogue.indexOf('const OBSERVABILITY_CATALOGUE')).split('\n')
    .map((line) => line.replace(/\/\/.*$/, '')).join('\n');
  assert.doesNotMatch(code, /configurationFields|capabilities|https?:\/\/|token|apiKey|orgId|bucket/i);
  for (const provider of OBSERVABILITY_PROVIDERS) {
    assert.equal(provider.configurationFields.length > 0, provider.implemented, provider.id);
    assert.ok(provider.label && provider.summary, provider.id);
  }
  // Grafana n est pas un backend de metriques.
  assert.equal(OBSERVABILITY_PROVIDERS.some((provider) => provider.id === 'grafana'), false);
});

// ===========================================================================
// Rendering
// ===========================================================================

test('rendu : la configuration est pilotee par le schema de l adaptateur', () => {
  const html = markup(renderInfrastructurePageHtml({}, 'n', 'light'));
  const rendered = [...html.matchAll(/id="observability-([a-zA-Z]+)"/g)].map((match) => match[1]).filter((id) => id !== 'provider');
  assert.deepEqual(rendered.sort(), ['allowSelfSigned', 'bearerToken', 'url']);
  assert.match(html, /id="observability-allowSelfSigned" type="checkbox"/);
  // Tous les fournisseurs sont proposes, aucun badge.
  assert.equal((html.match(/name="observability-provider-choice"/g) || []).length, OBSERVABILITY_PROVIDERS.length);
  assert.doesNotMatch(html, /provider-badge|Coming later/);
});

test('rendu : un fournisseur sans adaptateur n offre ni champ ni action', () => {
  for (const provider of plannedObservabilityProviders()) {
    const html = markup(renderInfrastructurePageHtml({ prometheus: { provider: provider.id, configured: false } }, 'n', 'light'));
    assert.doesNotMatch(html, /data-action="testInfrastructureConfig"/, provider.id);
    assert.doesNotMatch(html, /data-action="saveInfrastructureConfig"/, provider.id);
    assert.doesNotMatch(html, /id="observability-(?!provider)[a-zA-Z]+"/, provider.id);
    assert.ok(html.includes(`Security Center does not integrate ${provider.label} yet.`), provider.id);
  }
});

test('rendu : les sections suivent le manifeste, pas le nom du fournisseur', () => {
  // Un adaptateur synthetique compose un tableau de bord different a partir des
  // memes types de sections. Le rendu ne change pas d une ligne.
  const html = markup(renderInfrastructurePageHtml({
    prometheus: {
      configured: true, provider: 'fixture', label: 'Fixture backend', status: 'healthy',
      metrics: { cpu: { available: true, display: '7%' } },
      targets: { known: true, up: 1, total: 1, display: '1/1 UP', items: [] },
      capabilities: { hostInventory: 'ready', cpu: 'ready' },
      sections: [
        { id: 'hosts', kind: 'entity-inventory', capability: 'hostInventory', title: 'Monitored hosts' },
        { id: 'cpu', kind: 'metric-tiles', capability: ['cpu'], title: 'Processor' },
        { id: 'health', kind: 'status-list', capability: ['cpu', 'memory'], title: 'Capability health' }
      ]
    }
  }, 'n', 'light'));

  assert.match(html, /<h3>Monitored hosts<\/h3>/);
  assert.match(html, /<h3>Processor<\/h3>/);
  assert.match(html, /<h3>Capability health<\/h3>/);
  assert.match(html, /7%/);
  // Et aucune des sections de Prometheus n a ete imposee.
  assert.doesNotMatch(html, /<h3>Targets<\/h3>/);
  assert.doesNotMatch(html, /<h3>Host health<\/h3>/);
});

test('rendu : les sections apparaissent et disparaissent avec la preuve', () => {
  const base = {
    configured: true, provider: 'prometheus', label: 'Prometheus', status: 'healthy',
    targets: { known: true, up: 1, total: 1, display: '1/1 UP', items: [] }, metrics: {}
  };
  // Rien de prouve : les tuiles disent « Unavailable », jamais un zero.
  const bare = markup(renderInfrastructurePageHtml({ prometheus: { ...base, capabilities: { hostInventory: 'ready' } } }, 'n', 'light'));
  assert.match(bare, /<h3>Host health<\/h3>/);
  assert.doesNotMatch(bare, /<strong>0<\/strong>/);
  assert.ok((bare.match(/Unavailable/g) || []).length >= 4);

  // Non configure : aucune section, seulement l invitation a se connecter.
  const cold = markup(renderInfrastructurePageHtml({}, 'n', 'light'));
  assert.doesNotMatch(cold, /<h3>Host health<\/h3>/);
  assert.match(cold, /Connect observability/);
});
