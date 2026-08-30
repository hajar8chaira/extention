'use strict';

/**
 * The Infrastructure save path, end to end.
 *
 * A real deployment exposed the defect: the endpoint was visible in the form,
 * « Save configuration » answered « Prometheus endpoint est requis. », and
 * nothing was ever persisted. The form was innocent — it posted the value it
 * displayed. What was missing was the settings key underneath: the observability
 * service writes `securityCenter.infrastructure.providers`, and that key was
 * never declared in the manifest, while its Runtime Security twin
 * (`securityCenter.runtimeSecurity.providers`) was. VS Code refuses to write an
 * unregistered key and answers the default on every read, so the write threw
 * and every read came back empty.
 *
 * These tests therefore walk the whole path rather than any one piece of it:
 * the rendered input, the webview collector executed for real, the persistence
 * service against a VS Code-faithful configuration stub, and the manifest that
 * decides whether any of it can be stored at all.
 *
 * Every value is invented. No address or credential from any real deployment
 * appears here.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');
const { createProviderConfigurationService } = require('../src/integrations/provider-configuration');
const { observabilityAdapter, OBSERVABILITY_PROVIDERS } = require('../src/integrations/observability');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const manifest = JSON.parse(source('package.json'));
const declaredSettings = new Set(Object.keys(manifest.contributes.configuration.properties || {}));

const FICTIONAL = Object.freeze({
  prometheus: 'http://metrics.fixture.invalid:9090',
  zabbix: 'https://zabbix.fixture.invalid/zabbix',
  datadog: 'https://api.fixture-observability.invalid',
  token: 'fixture-observability-token-000',
  apiKey: 'fixture-datadog-api-key-000',
  applicationKey: 'fixture-datadog-application-key-000'
});

// ---------------------------------------------------------------------------
// The webview, executed rather than described
// ---------------------------------------------------------------------------

/** Attributes of one tag, as the browser would read them. */
function attributesOf(tag) {
  const out = {};
  for (const match of tag.matchAll(/([a-zA-Z-]+)(?:="([^"]*)")?/g)) {
    if (match[1] === 'input') continue;
    out[match[1]] = match[2] === undefined ? '' : match[2];
  }
  return out;
}

/**
 * Runs the page's own `config()` against the page's own markup.
 *
 * Only the selectors the collector actually uses are implemented — the point is
 * to execute the real script, not to reimplement a browser. `typed` lets a test
 * simulate a user editing a field before pressing Save.
 */
function collectConfig(html, typed = {}) {
  const cardStart = html.lastIndexOf('<section', html.indexOf('class="domain-card setup-card'));
  const cardEnd = html.indexOf('</section>', html.indexOf('domain-actions', cardStart));
  const nodes = [...html.matchAll(/<input[^>]*>/g)].map((match) => {
    const attributes = attributesOf(match[0]);
    const id = attributes.id || '';
    return {
      id,
      name: attributes.name || '',
      type: attributes.type || 'text',
      value: id in typed ? typed[id] : (attributes.value || ''),
      checked: 'checked' in attributes,
      inCard: match.index >= cardStart && match.index < cardEnd
    };
  });

  const document = {
    getElementById: (id) => nodes.find((node) => node.id === id) || null,
    querySelector(selector) {
      const radio = /input\[name="([^"]+)"\]:checked/.exec(selector);
      return radio ? (nodes.find((node) => node.name === radio[1] && node.checked) || null) : null;
    },
    querySelectorAll(selector) {
      const scoped = /^\.setup-card input\[id\^="([^"]+)"\]$/.exec(selector);
      if (scoped) return nodes.filter((node) => node.inCard && node.id.startsWith(scoped[1]));
      const named = /^input\[name="([^"]+)"\]$/.exec(selector);
      if (named) return nodes.filter((node) => node.name === named[1]);
      return [];
    }
  };

  const sandbox = {
    console, JSON, Object, String, Array, Set, Number, document,
    window: { addEventListener() {} },
    acquireVsCodeApi: () => ({ postMessage() {} })
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  // Le script de la page, pas celui du shell : c est celui qui porte config().
  const script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map((match) => match[1])
    .find((block) => block.includes('const config=')) || '';
  vm.runInContext(`${script.slice(0, script.indexOf('const showConfig'))}\nglobalThis.__config=config();`, sandbox, { timeout: 5000 });
  return sandbox.__config;
}

const renderForm = (prometheus) => renderInfrastructurePageHtml(
  { prometheus: { configured: true, status: 'healthy', metrics: {}, capabilities: {}, targets: {}, ...prometheus }, openConfig: true },
  'n', 'light'
);

// ---------------------------------------------------------------------------
// A VS Code-faithful settings store
// ---------------------------------------------------------------------------

/**
 * `WorkspaceConfiguration`, including the part that broke this.
 *
 * VS Code refuses to write a key no extension declared, and answers the caller's
 * fallback when reading one. A stub that accepts any key would have let this bug
 * through, which is exactly what happened.
 */
function workspaceConfiguration(initial = {}) {
  const store = { ...initial };
  return {
    store,
    get: (key, fallback) => (key in store ? store[key] : fallback),
    update: async (key, value) => {
      if (!declaredSettings.has(`securityCenter.${key}`)) {
        throw new Error(`Unable to write to Workspace Settings because securityCenter.${key} is not a registered configuration.`);
      }
      store[key] = value;
    }
  };
}

/** The Infrastructure service, wired exactly as `extension.js` wires it. */
function observabilityService(initial = {}) {
  const configuration = workspaceConfiguration(initial);
  const secretStore = new Map();
  const service = createProviderConfigurationService({
    configuration,
    secrets: {
      get: async (key) => secretStore.get(key) || '',
      store: async (key, value) => void secretStore.set(key, value),
      delete: async (key) => void secretStore.delete(key)
    },
    resolveAdapter: observabilityAdapter,
    domainLabel: 'observabilite',
    keys: {
      activeProvider: 'infrastructure.provider',
      providersConfig: 'infrastructure.providers',
      secretPrefix: 'securityCenter.observability'
    },
    legacy: {
      provider: 'prometheus',
      fields: { url: 'prometheus.url' },
      secrets: { bearerToken: 'securityCenter.prometheus.bearerToken' }
    }
  });
  return { service, configuration, secretStore };
}

// ===========================================================================
// The manifest — the key the whole path stands on
// ===========================================================================

test('sauvegarde : les cles de configuration Infrastructure sont declarees', () => {
  // Sans declaration, VS Code refuse l ecriture et rend le defaut a la lecture :
  // le formulaire ne peut alors RIEN enregistrer, quel que soit le fournisseur.
  assert.ok(declaredSettings.has('securityCenter.infrastructure.provider'));
  assert.ok(declaredSettings.has('securityCenter.infrastructure.providers'));
  // La symetrie avec Runtime Security, qui fonctionnait deja, est le point.
  assert.ok(declaredSettings.has('securityCenter.runtimeSecurity.provider'));
  assert.ok(declaredSettings.has('securityCenter.runtimeSecurity.providers'));
});

test('sauvegarde : le magasin declare n accueille aucun secret', () => {
  const declaration = manifest.contributes.configuration.properties['securityCenter.infrastructure.providers'];
  assert.equal(declaration.type, 'object');
  assert.deepEqual(declaration.default, {});
  const text = JSON.stringify(declaration);
  assert.doesNotMatch(text, /"(password|token|apiKey|secret)"/i);
  assert.match(text, /SecretStorage/);
});

// ===========================================================================
// The rendered form posts what it shows
// ===========================================================================

test('sauvegarde : l URL affichee est bien celle que Save envoie', () => {
  const html = renderForm({ provider: 'prometheus', values: { url: FICTIONAL.prometheus }, secretsConfigured: {} });
  assert.ok(html.includes(`id="observability-url"`) && html.includes(`value="${FICTIONAL.prometheus}"`));

  const posted = collectConfig(html);
  assert.equal(posted.provider, 'prometheus');
  assert.equal(posted.url, FICTIONAL.prometheus, 'le collecteur doit relire le champ rendu');
});

test('sauvegarde : une valeur heritee est affichee ET renvoyee', () => {
  // `{}` est verite en JavaScript : `values || fallback` rendait un champ vide
  // pour tout appelant portant un `baseUrl` et une carte vide, et le formulaire
  // rejetait ensuite son propre champ comme manquant.
  const html = renderForm({ provider: 'prometheus', baseUrl: FICTIONAL.prometheus, values: {}, secretsConfigured: {} });
  assert.ok(html.includes(`value="${FICTIONAL.prometheus}"`), 'la valeur heritee doit etre affichee');
  assert.equal(collectConfig(html).url, FICTIONAL.prometheus);
});

test('sauvegarde : une URL visible ne declenche jamais « requis »', async () => {
  const { service } = observabilityService();
  const html = renderForm({ provider: 'prometheus', values: { url: FICTIONAL.prometheus }, secretsConfigured: {} });
  const { provider, ...values } = collectConfig(html);

  const saved = await service.saveProviderConfiguration(provider, values);
  assert.equal(saved.ok, true, (saved.errors || []).join(' '));
  assert.equal(saved.config.url, FICTIONAL.prometheus);
});

test('sauvegarde : une URL saisie a la main suit le meme chemin', async () => {
  const { service } = observabilityService();
  const html = renderForm({ provider: 'prometheus', values: {}, secretsConfigured: {} });
  const { provider, ...values } = collectConfig(html, { 'observability-url': FICTIONAL.prometheus });

  assert.equal(values.url, FICTIONAL.prometheus);
  const saved = await service.saveProviderConfiguration(provider, values);
  assert.equal(saved.ok, true, (saved.errors || []).join(' '));
});

test('sauvegarde : une URL vide reste refusee, et pour la bonne raison', async () => {
  const { service } = observabilityService();
  const html = renderForm({ provider: 'prometheus', values: {}, secretsConfigured: {} });
  const { provider, ...values } = collectConfig(html);

  assert.equal(values.url, '');
  const saved = await service.saveProviderConfiguration(provider, values);
  assert.equal(saved.ok, false);
  assert.match(saved.errors.join(' '), /Prometheus endpoint est requis\./);
});

// ===========================================================================
// Persistence, and reading it back
// ===========================================================================

test('sauvegarde : la configuration enregistree est relue apres re-rendu', async () => {
  const { service } = observabilityService();
  await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus });

  assert.equal(service.getActiveProviderId(), 'prometheus');
  assert.equal(service.getProviderConfig('prometheus').url, FICTIONAL.prometheus);

  // Ce que la page recevrait au rendu suivant — et le champ le porte a nouveau.
  const html = renderForm({ provider: 'prometheus', values: service.getProviderConfig('prometheus'), secretsConfigured: {} });
  assert.ok(html.includes(`value="${FICTIONAL.prometheus}"`));
  assert.equal(collectConfig(html).url, FICTIONAL.prometheus);
});

test('sauvegarde : la configuration Prometheus historique resout toujours', async () => {
  const { service, configuration } = observabilityService({ 'prometheus.url': FICTIONAL.prometheus });

  // Aucune sauvegarde n a eu lieu : la cle historique suffit a resoudre.
  assert.equal(service.getActiveProviderId(), 'prometheus');
  assert.equal(service.getProviderConfig('prometheus').url, FICTIONAL.prometheus);
  const active = await service.resolveActiveProvider();
  assert.equal(active.config.url, FICTIONAL.prometheus);

  // Et un enregistrement ne l efface pas : il ecrit a cote.
  const saved = await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus });
  assert.equal(saved.ok, true);
  assert.equal(configuration.store['prometheus.url'], FICTIONAL.prometheus);
});

test('sauvegarde : une ecriture refusee est rapportee, jamais perdue', async () => {
  const { service, configuration } = observabilityService();
  configuration.update = async () => { throw new Error('workspace en lecture seule'); };

  const saved = await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus });
  assert.equal(saved.ok, false, 'une sauvegarde qui n a rien ecrit ne doit pas repondre ok');
  assert.match(saved.errors.join(' '), /non enregistree/);
});

// ===========================================================================
// The same collector, the same store, for every provider
// ===========================================================================

test('sauvegarde : Zabbix passe par le meme collecteur generique', async () => {
  const { service, configuration, secretStore } = observabilityService();
  const html = renderForm({ provider: 'zabbix', values: { url: FICTIONAL.zabbix }, secretsConfigured: {} });
  const { provider, ...values } = collectConfig(html, { 'observability-apiToken': FICTIONAL.token });

  assert.equal(provider, 'zabbix');
  assert.equal(values.url, FICTIONAL.zabbix);
  const saved = await service.saveProviderConfiguration(provider, values);
  assert.equal(saved.ok, true, (saved.errors || []).join(' '));
  assert.equal(service.getProviderConfig('zabbix').url, FICTIONAL.zabbix);
  // Le jeton part en SecretStorage, pas dans les parametres.
  assert.equal(secretStore.get('securityCenter.observability.zabbix.apiToken'), FICTIONAL.token);
  assert.doesNotMatch(JSON.stringify(configuration.store), new RegExp(FICTIONAL.token));
});

test('sauvegarde : Datadog passe par le meme collecteur generique', async () => {
  const { service, secretStore } = observabilityService();
  const html = renderForm({ provider: 'datadog', values: { url: FICTIONAL.datadog }, secretsConfigured: {} });
  const { provider, ...values } = collectConfig(html, {
    'observability-apiKey': FICTIONAL.apiKey,
    'observability-applicationKey': FICTIONAL.applicationKey
  });

  assert.equal(provider, 'datadog');
  const saved = await service.saveProviderConfiguration(provider, values);
  assert.equal(saved.ok, true, (saved.errors || []).join(' '));
  assert.equal(service.getProviderConfig('datadog').url, FICTIONAL.datadog);
  assert.equal(secretStore.get('securityCenter.observability.datadog.apiKey'), FICTIONAL.apiKey);
  assert.equal(secretStore.get('securityCenter.observability.datadog.applicationKey'), FICTIONAL.applicationKey);
});

test('sauvegarde : un secret ne revient jamais dans les parametres ni dans la page', async () => {
  const { service, configuration } = observabilityService();
  await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus, bearerToken: FICTIONAL.token });

  assert.doesNotMatch(JSON.stringify(configuration.store), new RegExp(FICTIONAL.token));
  const described = await service.describeProviderSecrets('prometheus');
  assert.deepEqual(described, { bearerToken: true });

  const html = renderForm({ provider: 'prometheus', values: service.getProviderConfig('prometheus'), secretsConfigured: described });
  assert.doesNotMatch(html, new RegExp(FICTIONAL.token));
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
  // Et un champ secret laisse vide ne l efface pas.
  const again = await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus, bearerToken: '' });
  assert.equal(again.ok, true);
  assert.equal((await service.getProviderSecrets('prometheus')).bearerToken, FICTIONAL.token);
});

test('sauvegarde : un booleen a false reste enregistrable', async () => {
  const { service } = observabilityService();
  await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus, allowSelfSigned: true });
  assert.equal(service.getProviderConfig('prometheus').allowSelfSigned, true);

  // Decocher est une reponse : sans cela on ne pourrait jamais revenir en strict.
  await service.saveProviderConfiguration('prometheus', { url: FICTIONAL.prometheus, allowSelfSigned: false });
  assert.equal(service.getProviderConfig('prometheus').allowSelfSigned, false);

  // Et la case decochee du formulaire porte bien `false`, pas une chaine vide.
  const html = renderForm({ provider: 'prometheus', values: { url: FICTIONAL.prometheus }, secretsConfigured: {} });
  assert.equal(collectConfig(html).allowSelfSigned, false);
});

test('sauvegarde : le collecteur ne nomme aucun fournisseur', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const collector = pages.slice(pages.indexOf('function pageScript'), pages.indexOf('function renderRuntimeSecurityPageHtml'));
  for (const name of OBSERVABILITY_PROVIDERS.map((provider) => provider.id)) {
    assert.doesNotMatch(collector, new RegExp(name, 'i'), `${name} ne doit pas apparaitre dans le collecteur`);
  }
  // Ni l ancien nom de champ propre a Prometheus.
  assert.doesNotMatch(pages, /prometheusUrl/);
  assert.doesNotMatch(source('src/integrations/provider-configuration.js'), /prometheus|zabbix|datadog|wazuh/i);
});
