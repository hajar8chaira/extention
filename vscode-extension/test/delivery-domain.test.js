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
  assert.ok(ids.includes('azure-pipelines'));
  // Jenkins, GitLab et GitHub ont un adaptateur ; les trois autres restent
  // catalogue-only tant que personne n'a ecrit le leur contre leur vraie API.
  assert.deepEqual(delivery.supportedDeliveryProviders().map((provider) => provider.id), ['jenkins', 'gitlab-ci', 'github-actions']);
});

test('un fournisseur catalogue-only n’a ni schéma ni capacité', () => {
  for (const id of ['azure-pipelines', 'circleci', 'bitbucket-pipelines']) {
    const provider = delivery.deliveryProvider(id);
    assert.equal(provider.implemented, false, id);
    assert.equal(provider.status, 'planned', id);
    // Pas de schéma : la surface n'a rien pour dessiner un formulaire.
    assert.deepEqual(provider.configurationFields, [], id);
    assert.deepEqual(provider.sections, [], id);
    assert.ok(Object.values(provider.capabilities).every((state) => state === DECLARED_STATE.UNAVAILABLE), id);
  }
});

test('configurer un fournisseur sans adaptateur est refusé, pas simulé', async () => {
  const validation = delivery.validateDeliveryConfiguration('azure-pipelines', { url: 'http://x' });
  assert.equal(validation.valid, false);
  assert.match(validation.errors[0], /aucun adaptateur/i);

  const tested = await delivery.testDeliveryConnection('azure-pipelines', {});
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
  assert.match(html, /Jenkins</);
  // Les trois fournisseurs implémentés sont proposés sans réserve…
  assert.match(html, /GitLab CI\/CD</);
  assert.match(html, /GitHub Actions</);
  assert.doesNotMatch(html, /GitLab CI\/CD — adaptateur indisponible/);
  assert.doesNotMatch(html, /GitHub Actions — adaptateur indisponible/);
  // …et les trois autres restent explicitement indisponibles.
  assert.match(html, /Azure DevOps Pipelines — adaptateur indisponible/);
  assert.match(html, /CircleCI — adaptateur indisponible/);
  assert.match(html, /Bitbucket Pipelines — adaptateur indisponible/);
});

test('le modèle porte le libellé du fournisseur, pour que le dashboard ne le code pas en dur', () => {
  assert.equal(syntheticModel.providerLabel, 'Synthetic CI');
  const html = view.renderDeliverySections(syntheticModel);
  assert.doesNotMatch(html, /Jenkins/);
});

// ------------------------------------------- architecture maître/détail

const {
  renderProviderHub, renderProviderWorkspace, providerHubEntries, HUB_STATE, renderDeliveryProviderPageHtml
} = require('../src/delivery-provider-view');
const { DELIVERY_PROVIDERS: HUB_PROVIDERS } = require('../src/integrations/delivery');

/** Le balisage seul : ni la feuille de style ni le script de la page. */
const markup = (html) => html.slice(html.indexOf('</style>'), html.indexOf('<script'));

const jenkinsHubModel = {
  providerId: 'jenkins', providerLabel: 'Jenkins', status: 'healthy', statusLabel: 'Healthy',
  pipeline: 'security-pipeline', target: 'http://192.168.222.132:8080', fetchedAt: '2026-09-10T18:00:00.000Z'
};

test('hub : chaque fournisseur reçoit l’état qui décrit ce qui est réellement su', () => {
  const entries = providerHubEntries(HUB_PROVIDERS, {
    model: jenkinsHubModel,
    activeProviderId: 'jenkins',
    configurations: { jenkins: { url: 'http://192.168.222.132:8080', job: 'security-pipeline' }, 'gitlab-ci': { url: 'https://gitlab.com' }, 'github-actions': {} }
  });
  const byId = Object.fromEntries(entries.map((entry) => [entry.id, entry]));
  assert.equal(byId.jenkins.state, HUB_STATE.ACTIVE);
  assert.equal(byId.jenkins.status, 'Healthy');
  assert.equal(byId.jenkins.pipeline, 'security-pipeline');
  // Configuré mais jamais interrogé : « configuré », jamais « connecté ».
  assert.equal(byId['gitlab-ci'].state, HUB_STATE.CONFIGURED);
  assert.equal(byId['gitlab-ci'].status, '', 'aucun statut de connexion inventé');
  assert.equal(byId['github-actions'].state, HUB_STATE.UNCONFIGURED);
  // Les trois fournisseurs de catalogue restent non disponibles.
  for (const id of ['azure-pipelines', 'circleci', 'bitbucket-pipelines']) {
    assert.equal(byId[id].state, HUB_STATE.UNAVAILABLE, `${id} ne doit pas paraître fonctionnel`);
  }
});

test('hub : un fournisseur non disponible n’offre aucune action', () => {
  const entries = providerHubEntries(HUB_PROVIDERS, { model: {}, activeProviderId: '', configurations: {} });
  const html = renderProviderHub(entries, {});
  const unavailable = html.slice(html.indexOf('Azure DevOps'), html.indexOf('CircleCI'));
  assert.match(unavailable, /Non disponible/);
  assert.ok(!unavailable.includes('data-action="deliveryOpenWorkspace"'), 'propose d’ouvrir un espace inexistant');
  assert.ok(!unavailable.includes('data-action="deliveryConfigureSelected"'), 'propose de configurer un adaptateur absent');
  // Un fournisseur non configuré, lui, propose la configuration et rien d'autre.
  const unconfigured = html.slice(html.indexOf('GitHub Actions'), html.indexOf('Azure DevOps'));
  assert.match(unconfigured, /Non configuré/);
  assert.match(unconfigured, /data-action="deliveryConfigureSelected"/);
  assert.ok(!unconfigured.includes('data-action="deliveryOpenWorkspace"'));
});

test('hub : les fournisseurs sont structurés en catalogue compact avec actions hiérarchisées', () => {
  const entries = providerHubEntries(HUB_PROVIDERS, {
    model: jenkinsHubModel,
    activeProviderId: 'jenkins',
    configurations: { jenkins: { url: 'http://192.168.222.132:8080', job: 'security-pipeline' } }
  });
  const html = renderProviderHub(entries, {});
  const jenkins = html.slice(html.indexOf('Jenkins'), html.indexOf('GitLab CI/CD'));
  const gitlab = html.slice(html.indexOf('GitLab CI/CD'), html.indexOf('GitHub Actions'));
  const unavailable = html.slice(html.indexOf('Azure DevOps'), html.indexOf('CircleCI'));

  assert.match(html, /CONNECTED \/ AVAILABLE/);
  assert.match(html, /OTHER PROVIDERS/);
  assert.match(html, /class="hub-available-grid"/);
  assert.match(html, /class="hub-provider-list"/);
  assert.match(html, /class="hub-description"/);
  assert.match(jenkins, /class="hub-facts"/, 'un fournisseur actif affiche ses métadonnées compactes');
  assert.match(jenkins, /data-action="deliveryOpenWorkspace"/);
  assert.match(jenkins, /class="secondary" data-action="deliveryConfigureSelected"/);
  assert.match(gitlab, /class="secondary" data-action="deliveryConfigureSelected"/, 'Configurer reste secondaire avant configuration');
  assert.match(unavailable, /class="hub-provider-row unavailable"/);
  assert.ok(!html.includes('Aucun adaptateur n’interroge cette plateforme aujourd’hui.'));
  assert.ok(!html.includes('hub-card unavailable'), 'les providers indisponibles ne reprennent pas le poids des cartes actives');
});

test('page : le hub et l’espace dédié sont deux vues, jamais la même', () => {
  const options = {
    model: jenkinsHubModel, providers: HUB_PROVIDERS, selectedProvider: 'jenkins',
    selectedProviderDefinition: HUB_PROVIDERS.find((provider) => provider.id === 'jenkins'),
    configuration: { url: 'http://192.168.222.132:8080', job: 'security-pipeline' },
    secretsConfigured: { token: true }, activeProvider: 'jenkins',
    configurations: { jenkins: { url: 'http://192.168.222.132:8080', job: 'security-pipeline' } }
  };
  const hub = markup(renderDeliveryProviderPageHtml({ ...options, view: 'hub' }, 'n', 'light', {}));
  const workspace = markup(renderDeliveryProviderPageHtml({ ...options, view: 'provider' }, 'n', 'light', {}));

  assert.equal((hub.match(/data-provider-card=/g) || []).length, HUB_PROVIDERS.length);
  assert.ok(!hub.includes('class="workspace-head'), 'le hub n’affiche aucun espace dédié');
  assert.equal((workspace.match(/data-provider-card=/g) || []).length, 0, 'l’espace dédié n’affiche aucune carte de hub');
  assert.match(workspace, /class="workspace-head/);
  assert.match(workspace, /data-action="deliveryBackToHub"/);
});

test('page : les trois duplications de l’ancienne page ont disparu', () => {
  const options = {
    model: jenkinsHubModel, providers: HUB_PROVIDERS, selectedProvider: 'jenkins',
    selectedProviderDefinition: HUB_PROVIDERS.find((provider) => provider.id === 'jenkins'),
    configuration: {}, secretsConfigured: {}, activeProvider: 'jenkins', configurations: {}
  };
  for (const view of ['hub', 'provider']) {
    const body = markup(renderDeliveryProviderPageHtml({ ...options, view }, 'n', 'light', {}));
    // Les tuiles de résumé, le sélecteur et la section Connexion répétaient le
    // fournisseur, son statut, sa dernière synchro et son pipeline.
    assert.ok(!body.includes('delivery-head-tile'), `tuiles de résumé encore présentes en vue ${view}`);
    assert.ok(!body.includes('data-section="connection"'), `section Connexion encore présente en vue ${view}`);
  }
});

test('page : le vocabulaire natif vient des adaptateurs, pas du renderer', () => {
  // L'invariant du domaine : le renderer générique ne nomme aucun fournisseur.
  // Les mots propres à chacun — « Dernier pipeline », « Jobs » — sont déclarés
  // par son adaptateur, et le renderer les affiche tels quels.
  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'delivery-provider-view.js'), 'utf8');
  for (const name of ['jenkins', 'gitlab', 'github']) {
    assert.ok(!new RegExp(`['"\`]${name}`, 'i').test(view), `le renderer nomme ${name}`);
  }
  const model = {
    ...jenkinsHubModel,
    sections: [{ kind: 'run-summary', title: 'Dernier pipeline' }, { kind: 'stage-list', title: 'Jobs' }],
    capabilities: {}, run: null, stages: [], artifacts: []
  };
  const html = renderProviderWorkspace(model, null, {});
  assert.match(html, /Dernier pipeline/);
  assert.match(html, /Jobs/);
});
