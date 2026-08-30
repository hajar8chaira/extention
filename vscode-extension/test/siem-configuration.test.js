'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createSiemConfigurationService, secretKeyFor, LEGACY_WAZUH } = require('../src/integrations/siem-configuration');
const { wazuhAdapter } = require('../src/integrations/siem-wazuh');
const { assertAdapterContract } = require('../src/integrations/siem-contract');

/**
 * Un second adaptateur EXISTANT UNIQUEMENT DANS LES TESTS.
 *
 * Il sert a prouver que la persistance supporte reellement plusieurs
 * fournisseurs — coexistence, bascule, retour — sans livrer de faux fournisseur
 * dans le produit. Il n'est jamais enregistre au catalogue.
 */
const probeAdapter = assertAdapterContract({
  id: 'probe',
  label: 'Probe SIEM',
  configurationFields: [
    { id: 'url', type: 'url', label: 'Endpoint', required: true },
    { id: 'tenant', type: 'text', label: 'Tenant', required: false },
    { id: 'token', type: 'password', label: 'Token', required: true, secret: true }
  ],
  getConfigurationSchema() { return this.configurationFields; },
  validateConfiguration: (config) => (String(config.url || '').startsWith('https://')
    ? { valid: true, errors: [] }
    : { valid: false, errors: ['Endpoint invalide.'] }),
  testConnection: async () => ({ ok: true, status: 'online' }),
  fetchStatus: async () => ({ provider: { id: 'probe', label: 'Probe SIEM' } })
});

const ADAPTERS = { wazuh: wazuhAdapter, probe: probeAdapter };
const resolveAdapter = (id) => ADAPTERS[String(id || '').toLowerCase()] || null;

/** Faux ports VS Code : settings en memoire + SecretStorage en memoire. */
function harness({ settings = {}, storedSecrets = {} } = {}) {
  const store = { ...settings };
  const vault = new Map(Object.entries(storedSecrets));
  const configuration = {
    get: (key, fallback) => (key in store ? store[key] : fallback),
    update: async (key, value) => { store[key] = value; }
  };
  const secrets = {
    get: async (key) => vault.get(key) || '',
    store: async (key, value) => { vault.set(key, value); },
    delete: async (key) => { vault.delete(key); }
  };
  return { store, vault, service: createSiemConfigurationService({ configuration, secrets, resolveAdapter }) };
}

const WAZUH_OK = { url: 'https://wazuh.local:55000', username: 'api', password: 'w-secret' };
const PROBE_OK = { url: 'https://probe.local', tenant: 't1', token: 'p-secret' };

// -------------------------------------------------- compatibilite historique

test('config : une installation Wazuh historique reste active sans reconfiguration', async () => {
  const { service } = harness({
    settings: { 'wazuh.url': 'https://legacy:55000', 'wazuh.username': 'legacy-user' },
    storedSecrets: { [LEGACY_WAZUH.secretKey]: 'legacy-password' }
  });
  assert.equal(service.getActiveProviderId(), 'wazuh', 'Wazuh reste le fournisseur actif');
  const config = service.getProviderConfig('wazuh');
  assert.equal(config.url, 'https://legacy:55000');
  assert.equal(config.username, 'legacy-user');
  const secrets = await service.getProviderSecrets('wazuh');
  assert.equal(secrets.password, 'legacy-password', 'le secret historique est toujours lu');
  const active = await service.resolveActiveProvider();
  assert.equal(active.adapter.id, 'wazuh');
  assert.equal(active.secrets.password, 'legacy-password');
});

test('config : les cles historiques ne sont ni reecrites ni supprimees', async () => {
  const { store, vault, service } = harness({
    settings: { 'wazuh.url': 'https://legacy:55000', 'wazuh.username': 'legacy-user' },
    storedSecrets: { [LEGACY_WAZUH.secretKey]: 'legacy-password' }
  });
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  assert.equal(store['wazuh.url'], 'https://legacy:55000', 'la cle historique est conservee telle quelle');
  assert.equal(vault.get(LEGACY_WAZUH.secretKey), 'legacy-password', 'le secret historique est conserve');
  // Le nouveau secret est ecrit dans son espace de noms.
  assert.equal(vault.get(secretKeyFor('wazuh', 'password')), 'w-secret');
});

test('config : la configuration generique prime sur la configuration historique', async () => {
  const { service } = harness({
    settings: {
      'wazuh.url': 'https://legacy:55000',
      'runtimeSecurity.provider': 'wazuh',
      'runtimeSecurity.providers': { wazuh: { url: 'https://new:55000', username: 'new-user' } }
    }
  });
  const config = service.getProviderConfig('wazuh');
  assert.equal(config.url, 'https://new:55000');
  assert.equal(config.username, 'new-user');
});

// ------------------------------------------------------- fournisseur actif

test('config : le fournisseur actif est explicite, jamais devine', async () => {
  // Deux configurations presentes, aucun fournisseur actif declare, aucune
  // configuration historique : rien n est devine.
  const { service } = harness({
    settings: { 'runtimeSecurity.providers': { wazuh: { url: 'https://a' }, probe: { url: 'https://b' } } }
  });
  assert.equal(service.getActiveProviderId(), '', 'aucun fournisseur ne doit etre devine');
  const active = await service.resolveActiveProvider();
  assert.equal(active.adapter, null);
});

test('config : un fournisseur inconnu est refuse et n active rien', async () => {
  const { service } = harness({ settings: { 'runtimeSecurity.provider': 'splunk' } });
  assert.equal(service.getActiveProviderId(), '', 'un id sans adaptateur ne peut pas etre actif');
  await assert.rejects(() => service.setActiveProvider('splunk'), /inconnu/);
  const saved = await service.saveProviderConfiguration('splunk', { url: 'https://x' });
  assert.equal(saved.ok, false);
  assert.match(saved.errors[0], /inconnu/);
});

// ------------------------------------------------------------ enregistrement

test('config : une configuration valide est enregistree PUIS activee', async () => {
  const { store, vault, service } = harness();
  const saved = await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  assert.equal(saved.ok, true);
  assert.equal(store['runtimeSecurity.provider'], 'wazuh');
  assert.deepEqual(store['runtimeSecurity.providers'].wazuh, { url: 'https://wazuh.local:55000', username: 'api' });
  assert.equal(vault.get(secretKeyFor('wazuh', 'password')), 'w-secret');
  // Le secret n est jamais range dans les settings.
  assert.ok(!JSON.stringify(store).includes('w-secret'), 'aucun secret dans la configuration');
});

test('config : une validation en echec ne change pas le fournisseur actif', async () => {
  const { store, vault, service } = harness();
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  const failed = await service.saveProviderConfiguration('probe', { url: 'http://not-https', token: 'x' });
  assert.equal(failed.ok, false);
  assert.equal(store['runtimeSecurity.provider'], 'wazuh', 'le fournisseur actif est inchange');
  assert.equal(store['runtimeSecurity.providers'].probe, undefined, 'rien n est persiste');
  assert.equal(vault.get(secretKeyFor('probe', 'token')), undefined, 'aucun secret enregistre');
});

test('config : un secret requis manquant bloque l enregistrement', async () => {
  const { store, service } = harness();
  const failed = await service.saveProviderConfiguration('probe', { url: 'https://probe.local' });
  assert.equal(failed.ok, false);
  assert.match(failed.errors[0], /Token/);
  assert.equal(store['runtimeSecurity.provider'], undefined);
});

test('config : un champ secret laisse vide conserve le secret existant', async () => {
  const { vault, service } = harness();
  await service.saveProviderConfiguration('probe', PROBE_OK);
  const again = await service.saveProviderConfiguration('probe', { url: 'https://probe2.local', tenant: 't2', token: '' });
  assert.equal(again.ok, true);
  assert.equal(vault.get(secretKeyFor('probe', 'token')), 'p-secret', 'le secret est conserve, pas efface');
  assert.equal(again.config.url, 'https://probe2.local');
});

// ---------------------------------------------------------------- bascule

test('config : configurer B ne detruit pas la configuration de A', async () => {
  const { store, vault, service } = harness();
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  await service.saveProviderConfiguration('probe', PROBE_OK);
  assert.equal(store['runtimeSecurity.provider'], 'probe', 'B devient actif');
  assert.deepEqual(store['runtimeSecurity.providers'].wazuh, { url: 'https://wazuh.local:55000', username: 'api' });
  assert.equal(vault.get(secretKeyFor('wazuh', 'password')), 'w-secret', 'le secret de A survit');
});

test('config : revenir a A restaure sa configuration sans ressaisie', async () => {
  const { service } = harness();
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  await service.saveProviderConfiguration('probe', PROBE_OK);
  await service.setActiveProvider('wazuh');
  const active = await service.resolveActiveProvider();
  assert.equal(active.providerId, 'wazuh');
  assert.equal(active.config.url, 'https://wazuh.local:55000');
  assert.equal(active.config.username, 'api');
  assert.equal(active.secrets.password, 'w-secret', 'le secret de A est retrouve');
});

// --------------------------------------------------------------- disconnect

test('config : disconnect efface la selection, pas la configuration', async () => {
  const { store, vault, service } = harness();
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  const result = await service.disconnect();
  assert.equal(result.ok, true);
  assert.equal(service.getActiveProviderId(), '', 'plus de fournisseur actif');
  // Mais rien n est detruit : se reconnecter ne doit pas exiger une ressaisie.
  assert.deepEqual(store['runtimeSecurity.providers'].wazuh, { url: 'https://wazuh.local:55000', username: 'api' });
  assert.equal(vault.get(secretKeyFor('wazuh', 'password')), 'w-secret');
  await service.setActiveProvider('wazuh');
  assert.equal(service.getActiveProviderId(), 'wazuh');
});

test('config : la suppression des identifiants est une action explicite et distincte', async () => {
  const { store, vault, service } = harness();
  await service.saveProviderConfiguration('probe', PROBE_OK);
  await service.forgetProviderSecrets('probe');
  assert.equal(vault.get(secretKeyFor('probe', 'token')), undefined, 'le secret est supprime');
  assert.deepEqual(store['runtimeSecurity.providers'].probe, { url: 'https://probe.local', tenant: 't1' },
    'la configuration non secrete demeure');
  assert.equal((await service.forgetProviderSecrets('inconnu')).ok, false);
});

// ------------------------------------------------------------------ secrets

test('config : aucun secret ne peut atteindre une webview', async () => {
  const { service } = harness();
  await service.saveProviderConfiguration('probe', PROBE_OK);
  // Ce que la webview recoit : des booleens, jamais des valeurs.
  const described = await service.describeProviderSecrets('probe');
  assert.deepEqual(described, { token: true });
  assert.ok(!JSON.stringify(described).includes('p-secret'));
  // Et la configuration publique ne contient aucun champ secret.
  const config = service.getProviderConfig('probe');
  assert.equal(config.token, undefined, 'un secret n est jamais dans la config publique');
  assert.ok(!JSON.stringify(config).includes('p-secret'));
});

test('config : les secrets sont ranges par fournisseur', async () => {
  const { vault, service } = harness();
  await service.saveProviderConfiguration('wazuh', WAZUH_OK);
  await service.saveProviderConfiguration('probe', PROBE_OK);
  assert.equal(secretKeyFor('wazuh', 'password'), 'securityCenter.runtimeSecurity.wazuh.password');
  assert.equal(secretKeyFor('probe', 'token'), 'securityCenter.runtimeSecurity.probe.token');
  assert.equal(vault.get(secretKeyFor('wazuh', 'password')), 'w-secret');
  assert.equal(vault.get(secretKeyFor('probe', 'token')), 'p-secret');
  // Aucun croisement entre espaces de noms.
  assert.equal((await service.getProviderSecrets('probe')).password, undefined);
});

// ------------------------------------------------------- lecture par Wazuh

test('config : Wazuh interroge bien la configuration resolue par le service', async () => {
  const { service } = harness({
    settings: { 'wazuh.url': 'https://legacy:55000', 'wazuh.username': 'legacy-user' },
    storedSecrets: { [LEGACY_WAZUH.secretKey]: 'legacy-password' }
  });
  const active = await service.resolveActiveProvider();
  const calls = [];
  await active.adapter.fetchStatus(active.config, active.secrets, {
    requestTextImpl: async (url, opts) => { calls.push({ url, headers: opts.headers }); return JSON.stringify({ data: { token: 'jwt' } }); },
    request: async (url) => { calls.push({ url }); return { data: { affected_items: [] } }; }
  });
  assert.ok(calls[0].url.startsWith('https://legacy:55000'), 'l URL historique est bien utilisee');
  const basic = Buffer.from('legacy-user:legacy-password').toString('base64');
  assert.equal(calls[0].headers.authorization, `Basic ${basic}`, 'identifiants historiques utilises');
  assert.ok(!calls.some((call) => call.url.includes('legacy-password')));
});
