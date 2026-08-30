'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const contract = require('../src/integrations/siem-contract');
const { CONNECTION_STATUS, buildRuntimeSecurityModel, assertAdapterContract } = contract;
const { siemAdapter, SIEM_PROVIDERS } = require('../src/integrations/siem');
const { wazuhAdapter } = require('../src/integrations/siem-wazuh');

// ---------------------------------------------------------------- le contrat

test('contrat : chaque adaptateur implemente respecte le contrat partage', () => {
  const implemented = SIEM_PROVIDERS.filter((provider) => provider.implemented);
  assert.ok(implemented.length > 0);
  for (const provider of implemented) {
    const adapter = siemAdapter(provider.id);
    assert.ok(adapter, `${provider.id} doit exposer un adaptateur`);
    assert.doesNotThrow(() => assertAdapterContract(adapter));
    assert.equal(typeof adapter.getConfigurationSchema, 'function');
  }
  // Un schema est une affirmation sur le produit d un autre editeur : seul un
  // adaptateur ecrit contre son API reelle peut en formuler un.
  for (const provider of SIEM_PROVIDERS.filter((entry) => !entry.implemented)) {
    assert.deepEqual(provider.configurationFields, [], `${provider.id} ne doit declarer aucun champ`);
    assert.deepEqual(provider.supportedCapabilities, [], `${provider.id} ne doit declarer aucune capacite`);
  }
  for (const provider of implemented) {
    assert.ok(provider.configurationFields.length > 0, `${provider.id} doit declarer ses champs`);
    for (const field of provider.configurationFields) {
      assert.ok(field.id && field.label && field.type, `${provider.id}.${field.id} incomplet`);
    }
  }
});

test('contrat : un adaptateur incomplet est refuse', () => {
  assert.throws(() => assertAdapterContract(null), /invalide/);
  assert.throws(() => assertAdapterContract({ id: 'x' }), /label/);
  assert.throws(() => assertAdapterContract({ id: 'x', label: 'X' }), /configurationFields/);
  assert.throws(() => assertAdapterContract({ id: 'x', label: 'X', configurationFields: [] }), /validateConfiguration/);
});

test('contrat : la severite de chaque fournisseur retombe sur un vocabulaire unique', () => {
  assert.equal(contract.normalizeSeverity('critical'), 'CRITICAL');
  assert.equal(contract.normalizeSeverity('WARNING'), 'MEDIUM');
  assert.equal(contract.normalizeSeverity('notice'), 'INFO');
  assert.equal(contract.normalizeSeverity('quelque chose'), 'INFO');
  // Echelles numeriques : Wazuh 0-15, Elastic/Sentinel 0-100.
  assert.equal(contract.severityFromScale(14, { max: 15 }), 'CRITICAL');
  assert.equal(contract.severityFromScale(50, { max: 100 }), 'MEDIUM');
  assert.equal(contract.severityFromScale('x'), null, 'une valeur illisible ne vaut pas INFO');
});

test('contrat : une donnee absente reste absente, jamais zero', () => {
  const model = buildRuntimeSecurityModel({ provider: 'demo', label: 'Demo', configured: true });
  assert.equal(model.endpoints.length, 0);
  assert.equal(model.lastSync, null, 'aucune date inventee');
  const endpoint = contract.normalizeEndpoint({ name: 'h1' });
  assert.equal(endpoint.lastSeen, null, 'last seen non fourni reste null');
  assert.equal(endpoint.ip, '');
  // Les compteurs d un modele vide sont de vrais zeros comptes, pas des faux.
  assert.deepEqual(model.alertSummary, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
});

test('contrat : une erreur de transport devient un etat, jamais une exception', () => {
  assert.equal(contract.statusFromError({ code: 'AUTH_ERROR' }), CONNECTION_STATUS.AUTH_ERROR);
  assert.equal(contract.statusFromError({ code: 'TIMEOUT' }), CONNECTION_STATUS.TIMEOUT);
  assert.equal(contract.statusFromError({ code: 'REDIRECT' }), CONNECTION_STATUS.UNSUPPORTED_RESPONSE);
  assert.equal(contract.statusFromError({ code: 'TOO_LARGE' }), CONNECTION_STATUS.UNSUPPORTED_RESPONSE);
  assert.equal(contract.statusFromError({}), CONNECTION_STATUS.ERROR);
});

test('contrat : les champs secrets sont identifiables et jamais valides comme du texte', () => {
  for (const provider of SIEM_PROVIDERS) {
    const fields = provider.configurationFields;
    const secrets = contract.secretConfigKeys(fields);
    const publics = contract.publicConfigKeys(fields);
    for (const key of secrets) assert.ok(!publics.includes(key), `${key} ne peut pas etre a la fois secret et public`);
    // La validation ne reclame jamais un secret dans l objet de configuration.
    const withoutSecrets = Object.fromEntries(publics.map((key) => [key, 'x']));
    const result = contract.validateAgainstFields(fields, { ...withoutSecrets });
    assert.equal(result.valid, true, `${provider.id} ne doit pas exiger de secret dans la config publique`);
  }
});

// ------------------------------------------------------------------- Wazuh

const wazuhConfig = { url: 'https://wazuh.local:55000', username: 'api' };
const wazuhSecrets = { password: 's3cr3t-not-in-output' };

test('Wazuh : la configuration est validee, URL comprise', () => {
  assert.equal(wazuhAdapter.validateConfiguration(wazuhConfig).valid, true);
  assert.equal(wazuhAdapter.validateConfiguration({ username: 'api' }).valid, false);
  const badUrl = wazuhAdapter.validateConfiguration({ url: 'ftp://host', username: 'api' });
  assert.equal(badUrl.valid, false);
  // Un identifiant dans l URL est refuse par le durcissement HTTP existant.
  assert.equal(wazuhAdapter.validateConfiguration({ url: 'https://u:p@host:55000', username: 'api' }).valid, false);
});

test('Wazuh : URL et en-tetes construits correctement, secret jamais dans l URL', async () => {
  const calls = [];
  await wazuhAdapter.fetchStatus(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async (url, opts) => { calls.push({ url, headers: opts.headers }); return JSON.stringify({ data: { token: 'jwt-token' } }); },
    request: async (url, opts) => { calls.push({ url, headers: opts.headers }); return { data: { affected_items: [] } }; }
  });
  const auth = calls[0];
  assert.match(auth.url, /\/security\/user\/authenticate\?raw=true$/);
  assert.match(auth.headers.authorization, /^Basic /);
  assert.ok(!auth.url.includes('s3cr3t'), 'le secret ne doit jamais atteindre une URL');
  for (const call of calls.slice(1)) {
    assert.equal(call.headers.authorization, 'Bearer jwt-token');
    assert.ok(!call.url.includes('s3cr3t'));
  }
  assert.ok(calls.some((c) => c.url.includes('/manager/info')));
  assert.ok(calls.some((c) => c.url.includes('/agents')));
  // L'API de gestion n'expose pas d'historique d'alertes : ne rien lui demander
  // de tel est ce qui empeche un 404 de faire tomber tout le fournisseur.
  assert.ok(!calls.some((c) => c.url.includes('/security/events')));
});

test('Wazuh : les hotes sont normalises dans le modele partage', async () => {
  const model = await wazuhAdapter.fetchStatus(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => JSON.stringify({ data: { token: 't' } }),
    request: async (url) => {
      if (url.includes('/manager/info')) return { data: { affected_items: [{ version: 'v4.7.0' }] } };
      if (url.includes('/agents')) return { data: { affected_items: [
        { id: '001', name: 'ubuntu-runtime', ip: '10.0.0.5', os: { name: 'Ubuntu' }, status: 'active', lastKeepAlive: '2026-08-20T09:00:00Z' },
        { id: '002', name: 'win-box', status: 'disconnected' }
      ] } };
      throw new Error(`route inattendue : ${url}`);
    }
  });
  assert.equal(model.provider.id, 'wazuh');
  assert.equal(model.connectionStatus, CONNECTION_STATUS.DEGRADED, '1 hote actif sur 2');
  assert.equal(model.version, 'v4.7.0');
  assert.equal(model.endpointSummary.total, 2);
  assert.equal(model.endpointSummary.active, 1);
  assert.equal(model.endpointSummary.disconnected, 1);
  // Les alertes ne viennent pas de cette API : le modele n'en invente aucune.
  assert.deepEqual(model.alerts, []);
  assert.equal(model.alertSummary.total, 0);
  assert.deepEqual(model.techniques, []);
});

test('Wazuh : les alertes de l Indexer sont normalisees dans le modele partage', () => {
  const { alertsFromIndexer } = require('../src/integrations/siem-wazuh');
  const fieldMap = Object.fromEntries(Object.entries({
    timestamp: '@timestamp', ruleId: 'rule.id', ruleLevel: 'rule.level',
    ruleDescription: 'rule.description', mitreIds: 'rule.mitre.id',
    assetName: 'agent.name', srcUser: 'data.srcuser', fullLog: 'full_log'
  }).map(([key, path]) => [key, { path, queryPath: path, type: 'keyword', aggregatable: true }]));

  const alerts = alertsFromIndexer([
    { id: 'doc-1', source: { '@timestamp': '2026-08-20T09:01:00Z', rule: { id: '5710', level: 12, description: 'SSH brute-force', mitre: { id: ['T1110'] } }, agent: { name: 'fixture-host' }, data: { srcuser: 'root' } } },
    { id: 'doc-2', source: { '@timestamp': '2026-08-20T09:02:00Z', rule: { id: '1002', level: 5, description: 'Suspicious log' } } }
  ], fieldMap);

  assert.equal(alerts.length, 2);
  assert.equal(alerts[0].severity, 'CRITICAL');
  assert.equal(alerts[1].severity, 'MEDIUM');
  assert.equal(alerts[0].ruleId, '5710');
  assert.equal(alerts[0].endpoint, 'fixture-host');
  assert.equal(alerts[0].user, 'root');
  assert.deepEqual(alerts[0].mitreTechniques, ['T1110']);
  assert.equal(alerts[0].rawReference, 'doc-1');
  // Ce que le document ne portait pas reste vide, jamais reconstruit.
  assert.equal(alerts[1].endpoint, '');
  assert.equal(alerts[1].user, '');
  assert.deepEqual(alerts[1].mitreTechniques, []);
});

test('Wazuh : une reponse malformee ne casse rien et ne fabrique rien', async () => {
  const model = await wazuhAdapter.fetchStatus(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => 'pas du json',
    request: async () => ({ unexpected: 'shape' })
  });
  assert.equal(model.provider.id, 'wazuh');
  assert.equal(model.alerts.length, 0);
  assert.equal(model.endpoints.length, 0);
  assert.equal(model.alertSummary.total, 0);
  // Aucun hote => pas de degradation inventee.
  assert.equal(model.connectionStatus, CONNECTION_STATUS.ONLINE);
});

test('Wazuh : un echec devient un etat sanitise, sans secret', async () => {
  const model = await wazuhAdapter.fetchStatus(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => { const e = new Error('Authentification refusee par le service externe.'); e.code = 'AUTH_ERROR'; throw e; },
    request: async () => ({})
  });
  assert.equal(model.connectionStatus, CONNECTION_STATUS.AUTH_ERROR);
  assert.ok(!JSON.stringify(model).includes('s3cr3t'), 'aucun secret dans le modele');
  const test1 = await wazuhAdapter.testConnection(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => { const e = new Error('Le service externe ne repond pas.'); e.code = 'TIMEOUT'; throw e; },
    request: async () => ({})
  });
  assert.equal(test1.ok, false);
  assert.equal(test1.status, CONNECTION_STATUS.TIMEOUT);
});

test('Wazuh : testConnection appelle reellement l adaptateur', async () => {
  let reached = false;
  const ok = await wazuhAdapter.testConnection(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => JSON.stringify({ data: { token: 't' } }),
    request: async () => { reached = true; return { data: { affected_items: [] } }; }
  });
  assert.equal(reached, true, 'aucun succes simule : le provider est reellement interroge');
  assert.equal(ok.ok, true);
  assert.equal(ok.status, CONNECTION_STATUS.ONLINE);
  // Une configuration invalide echoue avant tout appel reseau.
  let called = false;
  const invalid = await wazuhAdapter.testConnection({ url: '' }, {}, { request: async () => { called = true; return {}; } });
  assert.equal(invalid.ok, false);
  assert.equal(invalid.status, CONNECTION_STATUS.INVALID_CONFIG);
  assert.equal(called, false);
});

test('Wazuh : sans identifiants, l etat le dit au lieu d appeler le service', async () => {
  let called = false;
  const model = await wazuhAdapter.fetchStatus(wazuhConfig, {}, { request: async () => { called = true; return {}; } });
  assert.equal(called, false);
  assert.equal(model.connectionStatus, CONNECTION_STATUS.NOT_CONFIGURED);
  assert.equal(model.credentialsConfigured, false);
  assert.equal(model.configured, true, 'l endpoint reste configure');
});

test('Wazuh : la compatibilite du modele historique est preservee', async () => {
  const model = await wazuhAdapter.fetchStatus(wazuhConfig, wazuhSecrets, {
    requestTextImpl: async () => JSON.stringify({ data: { token: 't' } }),
    request: async (url) => url.includes('/agents')
      ? { data: { affected_items: [{ id: '1', name: 'h', status: 'active' }] } }
      : { data: { affected_items: [] } }
  });
  // Les noms lus par la page, la carte Dashboard et la page Integrations.
  for (const key of ['label', 'status', 'agents', 'agentSummary', 'lastChecked', 'category', 'configured', 'baseUrl', 'credentialsConfigured']) {
    assert.ok(key in model, `${key} doit rester disponible`);
  }
  assert.equal(model.category, 'siem');
  assert.equal(model.label, 'Wazuh');
  assert.equal(model.agentSummary.active, 1);
  assert.equal(model.agents[0].name, 'h');
});

// ===========================================================================
// Phase 3 — capacites de fournisseur
//
// Runtime Security couvre des produits tres differents : Wazuh expose des
// agents et un etat de vulnerabilite, Sentinel des incidents et des entites,
// QRadar des offenses. Declarer les capacites par adaptateur est ce qui permet
// au cadre partage d'offrir a chaque fournisseur ses propres sections sans que
// la page accumule des conditions sur le nom du fournisseur.
// ===========================================================================

const {
  CAPABILITY, CAPABILITY_STATE, CAPABILITY_STATES, CAPABILITY_FETCHERS,
  normalizeCapabilities, capabilityState, hasCapability, supportedCapabilities
} = contract;

test('capacites : le vocabulaire couvre les besoins des SIEM cibles', () => {
  const values = Object.values(CAPABILITY);
  for (const expected of ['alerts', 'vulnerabilities', 'assets', 'incidents', 'sca', 'fim', 'mitre', 'rawEvents']) {
    assert.ok(values.includes(expected), `${expected} doit exister`);
  }
  // Trois etats, pas un booleen : « implemente mais non configure » est un fait
  // distinct de « ce fournisseur ne sait pas faire ».
  assert.deepEqual([...CAPABILITY_STATES].sort(), ['ready', 'requires-config', 'unavailable']);
});

test('capacites : un adaptateur sans declaration n en supporte aucune', () => {
  // Retro-compatibilite : les stubs existants restent valides.
  const resolved = normalizeCapabilities({});
  assert.equal(Object.values(resolved).every((state) => state === CAPABILITY_STATE.UNAVAILABLE), true);
  assert.deepEqual(supportedCapabilities({}), []);
  assert.equal(hasCapability({}, CAPABILITY.ALERTS), false);
  assert.doesNotThrow(() => assertAdapterContract({
    id: 'x', label: 'X', configurationFields: [],
    validateConfiguration() {}, testConnection() {}, fetchStatus() {}
  }));
});

test('capacites : Wazuh ne declare pretes que celles reellement servies', () => {
  const resolved = normalizeCapabilities(wazuhAdapter);
  // La seule adossee a une requete de l'API de gestion.
  assert.equal(resolved.assets, CAPABILITY_STATE.READY);
  // Alertes, MITRE et vulnerabilites viennent du moteur de recherche : offertes,
  // pas prouvees, tant qu'aucune sonde n'a repondu.
  assert.equal(resolved.alerts, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(resolved.mitre, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(resolved.vulnerabilities, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.deepEqual(supportedCapabilities(wazuhAdapter), ['alerts', 'vulnerabilities', 'assets', 'mitre']);
});

test('capacites : les vulnerabilites Wazuh ne sont pas annoncees pretes', () => {
  // Depuis Wazuh 4.8 l'etat de vulnerabilite ne vient plus de l'API Manager
  // mais de l'Indexer. L'adaptateur sait l'interroger, donc la capacite est
  // « a configurer » — jamais « prete » sans une sonde reussie.
  assert.equal(capabilityState(wazuhAdapter, CAPABILITY.VULNERABILITIES), CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(typeof wazuhAdapter.probeVulnerabilities, 'function');
  for (const capability of ['sca', 'fim', 'incidents', 'rawEvents']) {
    assert.equal(capabilityState(wazuhAdapter, capability), CAPABILITY_STATE.UNAVAILABLE, `${capability} ne doit pas etre annoncee`);
  }
  // Et aucune requete correspondante n'existe encore.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', 'siem-wazuh.js'), 'utf8');
  assert.ok(!source.includes('/vulnerability'), 'aucun appel vulnerabilite');
  assert.ok(!source.includes('/sca'), 'aucun appel SCA');
  assert.ok(!source.includes('/syscheck'), 'aucun appel FIM');
});

test('capacites : un etat ou une capacite inconnus sont refuses', () => {
  const base = { id: 'x', label: 'X', configurationFields: [], validateConfiguration() {}, testConnection() {}, fetchStatus() {} };
  assert.throws(() => assertAdapterContract({ ...base, capabilities: { alerts: 'peut-etre' } }), /Etat de capacite invalide/);
  assert.throws(() => assertAdapterContract({ ...base, capabilities: { telepathy: 'ready' } }), /Capacite inconnue/);
  assert.throws(() => assertAdapterContract({ ...base, capabilities: [] }), /doivent etre un objet/);
  // Un etat inconnu passe par `normalizeCapabilities` retombe sur indisponible.
  assert.equal(normalizeCapabilities({ capabilities: { alerts: 'peut-etre' } }).alerts, CAPABILITY_STATE.UNAVAILABLE);
});

test('capacites : un fetcher sans capacite declaree est refuse', () => {
  // Du code mort qui promettrait une donnee que rien n'affichera.
  const base = { id: 'x', label: 'X', configurationFields: [], validateConfiguration() {}, testConnection() {}, fetchStatus() {} };
  assert.throws(
    () => assertAdapterContract({ ...base, fetchVulnerabilities() {} }),
    /expose fetchVulnerabilities\(\) mais declare vulnerabilities indisponible/
  );
  // Le meme fetcher est accepte des que la capacite est annoncee.
  assert.doesNotThrow(() => assertAdapterContract({
    ...base, capabilities: { vulnerabilities: CAPABILITY_STATE.REQUIRES_CONFIG }, fetchVulnerabilities() {}
  }));
  // Une capacite `ready` n'exige PAS de fetcher : alertes et actifs arrivent
  // aujourd'hui par `fetchStatus`.
  assert.doesNotThrow(() => assertAdapterContract({ ...base, capabilities: { alerts: CAPABILITY_STATE.READY } }));
  assert.deepEqual(Object.keys(CAPABILITY_FETCHERS).sort(), ['alerts', 'assets', 'fim', 'incidents', 'sca', 'vulnerabilities']);
});

test('capacites : le catalogue expose les capacites resolues', () => {
  const { catalogueEntry } = require('../src/integrations/siem-catalogue');
  for (const provider of SIEM_PROVIDERS) {
    // Un adaptateur implemente fait autorite ; sinon le catalogue fournit les
    // capacites que son futur adaptateur exposera.
    const source = siemAdapter(provider.id) || catalogueEntry(provider.id);
    assert.deepEqual(provider.capabilities, normalizeCapabilities(source));
    assert.deepEqual(provider.supportedCapabilities, supportedCapabilities(source));
  }
  // Une surface peut donc decider ses sections sans importer l'adaptateur.
  assert.deepEqual(SIEM_PROVIDERS[0].supportedCapabilities, ['alerts', 'vulnerabilities', 'assets', 'mitre']);
});

test('capacites : Phase 3 est purement additive', () => {
  // Aucun champ du modele normalise n'a disparu.
  const model = require('../src/integrations/siem-contract').buildRuntimeSecurityModel({ provider: 'wazuh', label: 'Wazuh', configured: true });
  for (const key of ['provider', 'category', 'configured', 'baseUrl', 'credentialsConfigured', 'connectionStatus',
    'endpoints', 'endpointSummary', 'alerts', 'alertSummary', 'techniques', 'rules', 'lastSync',
    'id', 'label', 'status', 'lastChecked', 'agents', 'agentSummary']) {
    assert.ok(key in model, `${key} doit rester present`);
  }
  // Le contrat requis n'a pas change.
  assert.deepEqual([...contract.REQUIRED_ADAPTER_METHODS], ['validateConfiguration', 'testConnection', 'fetchStatus']);
  // Et aucune requete reseau n'a ete ajoutee a l'adaptateur.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', 'siem-wazuh.js'), 'utf8');
  assert.equal((source.match(/joinUrl\(/g) || []).length, 3, '3 URLs de gestion : auth + 2 lectures');
});
