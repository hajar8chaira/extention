const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const delivery = require('../src/integrations/delivery');
const {
  PROVIDER_STATUS, CAPABILITY, RESOLVED_STATE, RUN_OUTCOME, SECTION_KIND,
  DECLARED_STATE, assertDeliveryAdapter, buildDeliveryModel
} = require('../src/integrations/delivery-contract');
const { jenkinsDeliveryAdapter, toDeliveryModel } = require('../src/integrations/delivery-jenkins');
const view = require('../src/delivery-provider-view');

// --------------------------------------------------------------- catalogue

test('le catalogue liste les plateformes et distingue l’adaptateur implémenté', () => {
  const ids = delivery.DELIVERY_PROVIDERS.map((provider) => provider.id);
  assert.ok(ids.includes('jenkins'));
  assert.ok(ids.includes('gitlab-ci'));
  assert.ok(ids.includes('github-actions'));
  assert.deepEqual(delivery.supportedDeliveryProviders().map((provider) => provider.id), ['jenkins']);
});

test('un fournisseur catalogue-only n’a ni schéma ni capacité', () => {
  const gitlab = delivery.deliveryProvider('gitlab-ci');
  assert.equal(gitlab.implemented, false);
  assert.equal(gitlab.status, 'planned');
  // Pas de schéma : la surface n'a rien pour dessiner un formulaire.
  assert.deepEqual(gitlab.configurationFields, []);
  assert.deepEqual(gitlab.sections, []);
  assert.ok(Object.values(gitlab.capabilities).every((state) => state === DECLARED_STATE.UNAVAILABLE));
});

test('configurer un fournisseur sans adaptateur est refusé, pas simulé', async () => {
  const validation = delivery.validateDeliveryConfiguration('github-actions', { url: 'http://x' });
  assert.equal(validation.valid, false);
  assert.match(validation.errors[0], /aucun adaptateur/i);

  const tested = await delivery.testDeliveryConnection('github-actions', {});
  assert.equal(tested.connected, false);
  assert.equal(tested.status, PROVIDER_STATUS.NOT_CONFIGURED);
});

test('un fournisseur inconnu renvoie un modèle non configuré au lieu de lever', async () => {
  const model = await delivery.fetchDeliveryModel('travis', {});
  assert.equal(model.status, PROVIDER_STATUS.NOT_CONFIGURED);
  assert.equal(model.run, null);
});

// ---------------------------------------------------------------- contrat

test('le contrat refuse un adaptateur incomplet', () => {
  assert.throws(() => assertDeliveryAdapter({ id: 'x' }), /n’implémente pas/);
  assert.throws(
    () => assertDeliveryAdapter({
      id: 'x', validateConfiguration() {}, testConnection() {}, fetchDelivery() {},
      capabilities: { inventedCapability: 'ready' }
    }),
    /Capacité Delivery inconnue/
  );
  assert.throws(
    () => assertDeliveryAdapter({
      id: 'x', validateConfiguration() {}, testConnection() {}, fetchDelivery() {},
      sections: [{ kind: 'bespoke-layout' }]
    }),
    /Section Delivery inconnue/
  );
});

// ------------------------------------------------------- adaptateur Jenkins

const JOB_PAYLOAD = {
  number: 12, displayName: '#12', building: false, result: 'SUCCESS',
  timestamp: 1_700_000_000_000, duration: 42_000, url: 'http://ci.local/job/security-pipeline/12/',
  actions: [{ lastBuiltRevision: { SHA1: 'a520e158cb65a520e158cb65a520e158cb650000' } }],
  artifacts: [{ fileName: 'security-center-report.json', relativePath: 'reports/security-center-report.json' }]
};

test('Jenkins reste fonctionnel après le refactor : le modèle porte le dernier build', async () => {
  const model = await jenkinsDeliveryAdapter.fetchDelivery(
    { url: 'http://ci.local', job: 'security-pipeline', token: 't' },
    {
      workspaceCommit: 'a520e158cb65a520e158cb65a520e158cb650000',
      request: async () => JOB_PAYLOAD,
      requestText: async () => { throw new Error('artefact introuvable'); }
    }
  );
  assert.equal(model.providerId, 'jenkins');
  assert.equal(model.providerLabel, 'Jenkins');
  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(model.run.outcome, RUN_OUTCOME.SUCCESS);
  assert.equal(model.run.providerResult, 'SUCCESS');
  assert.equal(model.run.durationMs, 42_000);
  assert.equal(model.pipeline, 'security-pipeline');
  assert.equal(model.credentialsConfigured, true);
});

test('build absent n’est pas build échoué', () => {
  const model = toDeliveryModel(
    { configured: true, state: 'NOT_STARTED', build: null, job: 'p', baseUrl: 'http://ci.local', ci: {} },
    { url: 'http://ci.local', job: 'p' }
  );
  assert.equal(model.run, null);
  assert.notEqual(model.status, PROVIDER_STATUS.ERROR);
  assert.equal(model.capabilities[CAPABILITY.LAST_RUN].state, RESOLVED_STATE.NOT_REPORTED);
});

test('fournisseur injoignable : hors ligne, sans verdict d’exécution inventé', () => {
  const model = toDeliveryModel(
    { configured: true, state: 'ERROR', error: 'Le serveur ne répond pas.', job: 'p', baseUrl: 'http://ci.local' },
    { url: 'http://ci.local', job: 'p' }
  );
  assert.equal(model.status, PROVIDER_STATUS.OFFLINE);
  assert.equal(model.run, null);
  assert.equal(model.capabilities[CAPABILITY.LAST_RUN].state, RESOLVED_STATE.UNAVAILABLE);
});

test('fournisseur non configuré n’est pas un fournisseur hors ligne', () => {
  const model = toDeliveryModel({ configured: false, state: 'NOT_CONFIGURED' }, {});
  assert.equal(model.status, PROVIDER_STATUS.NOT_CONFIGURED);
  assert.notEqual(model.status, PROVIDER_STATUS.OFFLINE);
});

test('les étapes et le déploiement sont déclarés non rapportés, pas absents', () => {
  const model = toDeliveryModel(
    { configured: true, state: 'SUCCESS', build: { number: 1, state: 'SUCCESS', artifacts: [] }, job: 'p', baseUrl: 'u', ci: {} },
    { url: 'u', job: 'p' }
  );
  assert.equal(model.capabilities[CAPABILITY.STAGES].state, RESOLVED_STATE.NOT_REPORTED);
  assert.ok(model.capabilities[CAPABILITY.STAGES].reason.length > 0);
  assert.equal(model.capabilities[CAPABILITY.DEPLOYMENT_STATUS].state, RESOLVED_STATE.NOT_REPORTED);
});

test('la connexion Jenkins est testable et mappée sur le vocabulaire du domaine', async () => {
  const ok = await jenkinsDeliveryAdapter.testConnection(
    { url: 'http://ci.local', job: 'p' }, { request: async () => ({ name: 'p' }) }
  );
  assert.equal(ok.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(ok.connected, true);

  const denied = await jenkinsDeliveryAdapter.testConnection(
    { url: 'http://ci.local', job: 'p' },
    { request: async () => { throw new Error('Jenkins a refusé l’authentification.'); } }
  );
  assert.equal(denied.status, PROVIDER_STATUS.AUTH_ERROR);
  assert.equal(denied.connected, false);
});

test('une configuration incomplète est refusée avant tout appel réseau', () => {
  assert.equal(delivery.validateDeliveryConfiguration('jenkins', { url: '', job: '' }).valid, false);
  assert.equal(delivery.validateDeliveryConfiguration('jenkins', { url: 'http://ci.local', job: 'p' }).valid, true);
  // Des identifiants dans l'URL sont refusés : ils finiraient dans les réglages.
  assert.equal(delivery.validateDeliveryConfiguration('jenkins', { url: 'http://u:p@ci.local', job: 'p' }).valid, false);
});

// ------------------------------------------------------- renderer générique

/** Un adaptateur synthétique : il doit produire une page sans toucher au renderer. */
const syntheticModel = buildDeliveryModel({
  providerId: 'synthetic-ci',
  providerLabel: 'Synthetic CI',
  status: PROVIDER_STATUS.HEALTHY,
  target: 'https://synthetic.example',
  pipeline: 'main-pipeline',
  capabilities: {
    [CAPABILITY.PIPELINE_STATUS]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.LAST_RUN]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.STAGES]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.ARTIFACTS]: { state: RESOLVED_STATE.NOT_REPORTED, reason: 'Aucun artefact.' },
    [CAPABILITY.DEPLOYMENT_STATUS]: { state: RESOLVED_STATE.READY, reason: '' }
  },
  run: { id: '77', displayName: 'run-77', outcome: RUN_OUTCOME.UNSTABLE, providerResult: 'UNSTABLE', durationMs: 90_000, branch: 'main', commit: 'deadbeef' },
  stages: [{ name: 'build', outcome: RUN_OUTCOME.SUCCESS }, { name: 'scan', outcome: RUN_OUTCOME.UNSTABLE }],
  sections: [
    { kind: SECTION_KIND.CONNECTION, title: 'Connexion' },
    { kind: SECTION_KIND.RUN_SUMMARY, title: 'Dernière exécution' },
    { kind: SECTION_KIND.STAGE_LIST, title: 'Étapes' }
  ]
});

test('un adaptateur synthétique rend une page complète sans modifier le renderer', () => {
  const html = view.renderDeliverySections(syntheticModel);
  assert.match(html, /Synthetic CI/);
  assert.match(html, /main-pipeline/);
  assert.match(html, /run-77/);
  assert.match(html, /Instable/);
  // Les étapes déclarées par l'adaptateur sont rendues : le renderer ne sait
  // pas que Jenkins n'en expose pas.
  assert.match(html, /build/);
  assert.match(html, /scan/);
});

test('le renderer générique ne contient aucune condition sur un nom de fournisseur', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'delivery-provider-view.js'), 'utf8');
  for (const vendor of ['jenkins', 'gitlab', 'github', 'circleci', 'bitbucket', 'azure']) {
    assert.doesNotMatch(
      source.toLowerCase(),
      new RegExp(`providerid\\s*===\\s*['"\`]${vendor}`),
      `le renderer ne doit pas brancher sur ${vendor}`
    );
  }
  // Aucun vocabulaire fournisseur en dur non plus.
  assert.doesNotMatch(source, /Jenkinsfile|Jenkins\b/);
});

test('une exécution absente est rendue « non rapporté », jamais « échec »', () => {
  const model = buildDeliveryModel({
    providerId: 'synthetic-ci', providerLabel: 'Synthetic CI',
    status: PROVIDER_STATUS.DEGRADED,
    capabilities: { [CAPABILITY.LAST_RUN]: { state: RESOLVED_STATE.NOT_REPORTED, reason: 'Aucune exécution.' } },
    run: null,
    sections: [{ kind: SECTION_KIND.RUN_SUMMARY, title: 'Dernière exécution' }]
  });
  const html = view.renderDeliverySections(model);
  assert.match(html, /Non rapporté/);
  assert.match(html, /n’est pas un échec/);
  assert.doesNotMatch(html, />Échec</);
});

test('un secret n’est jamais rendu dans le HTML du formulaire', () => {
  const provider = delivery.deliveryProvider('jenkins');
  const html = view.renderProviderForm(provider, {
    configuration: { url: 'http://ci.local', job: 'p', user: 'admin', token: 'super-secret-token' },
    secretsConfigured: { token: true }
  });
  assert.doesNotMatch(html, /super-secret-token/);
  assert.match(html, /Laisser vide pour conserver la valeur enregistrée/);
  // Les champs non secrets sont bien restitués.
  assert.match(html, /value="http:\/\/ci\.local"/);
  assert.match(html, /value="admin"/);
});

test('le formulaire d’un fournisseur catalogue-only n’expose ni champ ni action', () => {
  const html = view.renderProviderForm(delivery.deliveryProvider('circleci'), {});
  assert.match(html, /aucun adaptateur n’est encore disponible/);
  assert.doesNotMatch(html, /data-action="deliverySave"/);
  assert.doesNotMatch(html, /data-action="deliveryTest"/);
  assert.doesNotMatch(html, /<input/);
});

test('le sélecteur liste tous les fournisseurs et signale ceux sans adaptateur', () => {
  const html = view.renderProviderSelector(delivery.DELIVERY_PROVIDERS, 'jenkins');
  assert.match(html, /value="jenkins"\s+selected/);
  assert.match(html, /GitLab CI\/CD — adaptateur indisponible/);
  assert.match(html, /Jenkins</);
});

test('le modèle porte le libellé du fournisseur, pour que le dashboard ne le code pas en dur', () => {
  assert.equal(syntheticModel.providerLabel, 'Synthetic CI');
  const html = view.renderDeliverySections(syntheticModel);
  assert.doesNotMatch(html, /Jenkins/);
});
