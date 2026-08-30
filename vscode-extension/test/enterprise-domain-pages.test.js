'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderRuntimeSecurityPageHtml: renderRuntimePage, renderInfrastructurePageHtml, domainCss } = require('../src/enterprise-domain-pages');
// Depuis que l'historique d'alertes vient du moteur de recherche du
// fournisseur et non de son API de gestion, la page a besoin de la preuve
// d'execution qu'une sonde reussie fournit. Les tests qui examinent un etat
// degrade passent la leur et gagnent.
const READY_EVIDENCE = Object.freeze({ alerts: { state: 'ready' }, mitre: { state: 'ready' } });
function renderRuntimeSecurityPageHtml(model = {}, nonce = '', theme = 'light') {
  return renderRuntimePage({ capabilityEvidence: READY_EVIDENCE, ...model }, nonce, theme);
}

const { PROMETHEUS_STATUS } = require('../src/integrations/observability');
const { RUNTIME_STATUS } = require('../src/integrations/siem');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

function commandBody(extension, command) {
  const start = extension.indexOf(`registerCommand('${command}'`);
  if (start < 0) return '';
  const next = extension.indexOf('registerCommand(', start + 20);
  return extension.slice(start, next < 0 ? extension.length : next);
}

function runtimeStatus(overrides = {}) {
  return {
    configured: true,
    provider: 'wazuh',
    label: 'Wazuh',
    status: RUNTIME_STATUS.ONLINE,
    baseUrl: 'https://wazuh.local:55000',
    username: 'api',
    credentialsConfigured: true,
    lastChecked: new Date(Date.now() - 9000).toISOString(),
    agentSummary: { active: 1, total: 1, disconnected: 0, neverConnected: 0 },
    alertSummary: { critical: 1, high: 1, medium: 0, low: 0 },
    agents: [{ name: 'ubuntu-runtime', os: 'Ubuntu 22.04', status: 'active', ip: '10.0.0.5', lastSeen: '9 sec ago' }],
    alerts: [{
      severity: 'CRITICAL',
      title: 'SSH brute-force attempt',
      summary: 'Authentication failures exceeded the normalized threshold.',
      host: 'ubuntu-runtime',
      ruleId: '5710',
      category: 'authentication_failed',
      mitreTechniques: ['T1110'],
      timestamp: '2026-08-20T09:01:00Z',
      status: 'open'
    }],
    ...overrides
  };
}

function prometheusStatus(overrides = {}) {
  return {
    configured: true,
    provider: 'prometheus',
    label: 'Prometheus',
    status: PROMETHEUS_STATUS.HEALTHY,
    baseUrl: 'http://prometheus.local:9090',
    selectedHost: 'ubuntu-runtime:9100',
    targets: {
      up: 2,
      total: 2,
      display: '2/2 UP',
      lastScrapeAgeSeconds: 8,
      items: [
        { name: 'node-exporter', instance: 'ubuntu-runtime:9100', endpoint: 'http://ubuntu-runtime:9100/metrics', health: 'up', lastScrape: new Date(Date.now() - 8000).toISOString() },
        { name: 'api-runtime', instance: 'api-runtime:9100', endpoint: 'http://api-runtime:9100/metrics', health: 'up', lastScrape: new Date(Date.now() - 9000).toISOString() }
      ]
    },
    metrics: {
      cpu: { available: true, display: '21%' },
      memory: { available: true, display: '3.4 GB / 9.7 GB' },
      disk: { available: true, display: '12%' },
      load1: { available: true, display: '0.42' }
    },
    ...overrides
  };
}

test('runtime security starts as a generic SIEM setup page without fake data or secrets', () => {
  const html = renderRuntimeSecurityPageHtml({}, 'n', 'light');
  assert.match(html, /Runtime Security/);
  assert.match(html, /SIEM provider not configured/);
  assert.match(html, /Connect your SIEM/);
  assert.match(html, /id="runtime-provider"/);
  // Le fournisseur vient desormais du catalogue SIEM : Wazuh reste offert, mais
  // comme UN adaptateur du domaine, plus comme le domaine lui-meme.
  assert.match(html, /class="provider-catalogue"/);
  assert.match(html, /<span class="provider-name">Wazuh<\/span>/);
  assert.match(html, /value="wazuh"/);
  assert.match(html, /API endpoint/);
  assert.match(html, /Username/);
  assert.match(html, /Password/);
  assert.match(html, /Test connection/);
  assert.match(html, /Save configuration/);
  // Formulation utilisateur : plus de nom de propriete ni de booleen brut.
  assert.match(html, /Credential is never rendered back into this webview\./);
  assert.doesNotMatch(html, /credentialsConfigured/);
  assert.doesNotMatch(html, /Wazuh Dashboard|Wazuh Security Center|Wazuh · Not configured/);
  assert.doesNotMatch(html, /<strong>0<\/strong>/);
  assert.doesNotMatch(html, /secret-password|Bearer |Basic /i);
});

test('runtime security configured view renders normalized provider facts and alert details only', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: runtimeStatus(), openConfig: true }, 'n', 'dark');
  assert.match(html, /<body class="[^"]*theme-dark[^"]*"/);
  assert.match(html, /Provider: Wazuh/);
  assert.match(html, /Alert summary/);
  assert.match(html, /Monitored assets \/ agents/);
  assert.match(html, /Recent alerts/);
  assert.match(html, /ubuntu-runtime/);
  assert.match(html, /Rule 5710/);
  assert.match(html, /MITRE T1110/);
  assert.match(html, /Credential configured in SecretStorage\./);
  assert.doesNotMatch(html, /credentialsConfigured/);
  assert.doesNotMatch(html, /full_log|affected_items|secret-password|Bearer |Basic /i);
});

test('runtime security failure states stay explicit and do not fall back to prior success counts', () => {
  const html = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({
      status: RUNTIME_STATUS.AUTH_ERROR,
      message: 'Authentication failed',
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      alerts: [],
      agents: []
    })
  }, 'n', 'light');
  assert.match(html, /Authentication failed/);
  assert.match(html, /Provider is unavailable|Authentication failed/);
  assert.match(html, /No recent runtime alerts returned by the SIEM provider/);
  assert.doesNotMatch(html, /SSH brute-force attempt|Rule 5710/);
});

test('infrastructure starts as a generic observability setup page without fake zero metrics', () => {
  const html = renderInfrastructurePageHtml({}, 'n', 'light');
  assert.match(html, /Infrastructure/);
  assert.match(html, /Observability provider not configured/);
  assert.match(html, /Connect observability/);
  assert.match(html, /id="observability-provider"/);
  // Le fournisseur vient du catalogue : Prometheus reste offert comme UN
  // adaptateur du domaine, et c'est lui qui nomme son propre endpoint.
  assert.match(html, /class="provider-catalogue"/);
  assert.match(html, /<span class="provider-name">Prometheus<\/span>/);
  assert.match(html, /Prometheus endpoint/);
  assert.match(html, /value="prometheus"/);
  assert.match(html, /Test connection/);
  assert.match(html, /Save configuration/);
  assert.doesNotMatch(html, /Grafana/);
  assert.doesNotMatch(html, /Prometheus · Not configured/);
  assert.doesNotMatch(html, /<strong>0<\/strong>/);
});

test('infrastructure configured view renders real provider metrics, targets and theme contract', () => {
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus() }, 'n', 'dark');
  assert.match(html, /<body class="[^"]*theme-dark[^"]*"/);
  assert.match(html, /Provider: Prometheus/);
  assert.match(html, /2\/2 UP/);
  assert.match(html, /node-exporter/);
  assert.match(html, /ubuntu-runtime:9100/);
  assert.match(html, /21%/);
  assert.match(html, /3\.4 GB \/ 9\.7 GB/);
  assert.match(html, /12%/);
  assert.match(html, /0\.42/);
});

test('infrastructure unavailable metrics stay unavailable while genuine zero remains zero', () => {
  const html = renderInfrastructurePageHtml({
    prometheus: prometheusStatus({
      metrics: {
        cpu: { available: true, display: '0%' },
        memory: { available: false, display: 'Unavailable' },
        disk: { available: false, display: 'Unavailable' },
        load1: { available: false, display: 'Unavailable' }
      }
    })
  }, 'n', 'light');
  assert.match(html, /CPU<\/span><strong>0%<\/strong>/);
  assert.equal((html.match(/Unavailable/g) || []).length >= 3, true);
});

test('dashboard domain cards are generic before configuration and route to domain pages', () => {
  const model = buildDashboardModel([], [], {
    enterprise: {
      prometheus: { configured: false, status: PROMETHEUS_STATUS.NOT_CONFIGURED },
      runtime: { configured: false, status: RUNTIME_STATUS.NOT_CONFIGURED, label: 'Wazuh' },
      delivery: { configured: false }
    }
  });
  const html = renderDashboardHtml(model, 'n', 'full', 'light');
  assert.match(html, /Security Domains/);
  assert.match(html, /Application Security/);
  assert.match(html, /Runtime Security/);
  assert.match(html, /Infrastructure/);
  assert.match(html, /Delivery Security/);
  assert.match(html, /AI Companion/);
  assert.match(html, /data-command="securityCenter.configureSiem"/);
  assert.match(html, /data-command="securityCenter.configureObservability"/);
  assert.doesNotMatch(html, /Wazuh · Not configured|Prometheus · Not configured|CPU 0|RAM 0/);
});

test('enterprise domain configuration keeps provider secrets in SecretStorage and uses webview forms', () => {
  const extension = source('src/extension.js');
  // Les secrets passent par le service provider-neutre, qui les range sous
  // `securityCenter.runtimeSecurity.<provider>.<secret>` dans SecretStorage.
  assert.match(extension, /secrets: context\.secrets/);
  // Le mecanisme de persistance est desormais partage entre domaines ; ce sont
  // les cles qui restent propres a Runtime Security.
  const siemService = source('src/integrations/siem-configuration.js');
  assert.match(siemService, /secretPrefix: SECRET_PREFIX/);
  assert.match(siemService, /LEGACY_WAZUH/);
  const shared = source('src/integrations/provider-configuration.js');
  assert.match(shared, /secrets\.store\(secretKeyFor\(adapter\.id, field\.id\)/);
  assert.match(shared, /secrets\.get\(secretKeyFor\(adapter\.id, field\.id\)/);
  assert.doesNotMatch(extension, /update\('wazuh\.(password|token|secret)'/);
  assert.match(commandBody(extension, 'securityCenter.configureSiem'), /openRuntimeSecurityPage\(\{ configure: true \}\)/);
  assert.match(commandBody(extension, 'securityCenter.configureWazuh'), /openRuntimeSecurityPage\(\{ configure: true \}\)/);
  assert.match(commandBody(extension, 'securityCenter.configureObservability'), /openInfrastructurePage\(\{ configure: true \}\)/);
  assert.match(commandBody(extension, 'securityCenter.configurePrometheus'), /openInfrastructurePage\(\{ configure: true \}\)/);
  assert.doesNotMatch(commandBody(extension, 'securityCenter.configureSiem'), /showInputBox/);
  assert.doesNotMatch(commandBody(extension, 'securityCenter.configureObservability'), /showInputBox/);
});

test('enterprise domain pages keep watermark and responsive styling subtle', () => {
  const css = domainCss();
  assert.match(css, /\.domain-watermark/);
  assert.match(css, /opacity:\.035/);
  assert.match(css, /@media\(max-width:860px\)/);
});

test('runtime : aucun texte de debogage brut dans l interface', () => {
  // `credentialsConfigured: true` etait rendu tel quel a l utilisateur : un nom
  // de propriete et un booleen JavaScript, sur une page de demonstration.
  const configured = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({ credentialsConfigured: true }),
    openConfig: true
  }, 'n', 'light');
  const missing = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({ credentialsConfigured: false }),
    openConfig: true
  }, 'n', 'light');
  for (const html of [configured, missing]) {
    assert.doesNotMatch(html, /credentialsConfigured/, 'aucun nom de propriete interne ne doit etre affiche');
    assert.doesNotMatch(html, /:\s*(true|false)\b/, 'aucun booleen brut ne doit etre affiche comme valeur');
  }
  // Formulation utilisateur, alignee sur celle deja employee par la page Integrations.
  assert.match(configured, /Credential configured in SecretStorage\./);
  assert.match(missing, /Credential is never rendered back into this webview\./);
});

test('runtime : l etat des identifiants reste modelise et visible normalement', () => {
  // Le champ du modele n est pas supprime : il pilote toujours le libelle du
  // champ mot de passe et la tuile d etat.
  const configured = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({ credentialsConfigured: true }),
    openConfig: true
  }, 'n', 'light');
  assert.match(configured, /Leave empty to keep the stored credential/);
  const dataView = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({ credentialsConfigured: true })
  }, 'n', 'light');
  assert.match(dataView, /Credentials/);
  assert.match(dataView, /Configured/);
});

test('runtime : aucun secret n atteint la webview', () => {
  const html = renderRuntimeSecurityPageHtml({
    runtime: runtimeStatus({ credentialsConfigured: true, username: 'analyst' }),
    openConfig: true
  }, 'n', 'light');
  assert.doesNotMatch(html, /s3cr3t|password"\s*value=|value="[^"]*token/i);
  assert.match(html, /type="password"/);
  assert.doesNotMatch(html, /<input id="runtime-password"[^>]*value=/);
});

// ===========================================================================
// Runtime Security est un DOMAINE, pas un produit Wazuh
//
// La configuration presentait un `<select>` a une seule entree — « Wazuh » —
// ce qui faisait passer une categorie entiere du produit pour l integration
// d un seul editeur. Wazuh est le premier adaptateur, pas le domaine.
// ===========================================================================

const {
  SIEM_PROVIDERS: CK8_PROVIDERS, SIEM_PROVIDER_STATUS: CK8_STATUS, DEFAULT_SIEM_PROVIDER: CK8_DEFAULT,
  siemProvider: ck8Provider, siemProviderLabel: ck8Label, isSupportedSiemProvider: ck8Supported,
  supportedSiemProviders: ck8SupportedList, plannedSiemProviders: ck8PlannedList,
  buildRuntimeSecurityStatus: ck8Build, RUNTIME_STATUS: CK8_RUNTIME
} = require('../src/integrations/siem');

const ck8Runtime = (over = {}) => ({
  configured: true, provider: 'wazuh', label: 'Wazuh', status: CK8_RUNTIME.ONLINE,
  baseUrl: 'https://wazuh.local:55000', username: 'api', credentialsConfigured: true,
  lastChecked: new Date().toISOString(),
  agentSummary: { active: 1, total: 1, disconnected: 0, neverConnected: 0 },
  alertSummary: { critical: 1, high: 0, medium: 0, low: 0 },
  agents: [{ name: 'host-1', os: 'Ubuntu', status: 'active', ip: '10.0.0.5', lastSeen: '9 sec ago' }],
  alerts: [{ severity: 'CRITICAL', title: 'SSH brute-force', summary: 's', host: 'host-1', ruleId: '5710', category: 'auth', mitreTechniques: ['T1110'], timestamp: '2026-08-20T09:01:00Z', status: 'open' }],
  ...over
});

test('SIEM : le catalogue couvre tous les fournisseurs cibles du produit', () => {
  // Runtime Security est un domaine multi-SIEM : le catalogue liste ce que le
  // produit integre, l'adaptateur decide ce qui peut reellement se connecter.
  const ids = CK8_PROVIDERS.map((provider) => provider.id);
  for (const expected of ['wazuh', 'splunk', 'sentinel', 'elastic', 'qradar', 'chronicle', 'graylog', 'arcsight', 'sumologic']) {
    assert.ok(ids.includes(expected), `${expected} doit figurer au catalogue`);
  }
  // « Custom SIEM » a ete retire : il promettait un moteur de correspondance
  // generique qui n existe pas.
  assert.equal(ids.includes('custom'), false);
  for (const provider of CK8_PROVIDERS) {
    assert.ok(provider.label && provider.id);
    // Seul un adaptateur peut decrire une connexion. Sans lui, aucun champ —
    // un schema jamais implemente est une affirmation sur le produit d autrui.
    const declared = provider.configurationFields.length > 0;
    assert.equal(declared, provider.implemented, `${provider.id}: champs declares == adaptateur present`);
    assert.equal(provider.supportedCapabilities.length > 0, provider.implemented, `${provider.id}: capacites == adaptateur present`);
  }
  const pages = fs.readFileSync(path.join(__dirname, '..', 'src', 'enterprise-domain-pages.js'), 'utf8');
  assert.doesNotMatch(pages, /<option value="wazuh"/, 'le select code en dur doit avoir disparu');
});

test('SIEM : Wazuh est un identifiant de fournisseur, pas le domaine', () => {
  assert.equal(ck8Provider('wazuh').id, 'wazuh');
  assert.equal(ck8Label('wazuh'), 'Wazuh');
  assert.equal(CK8_DEFAULT, 'wazuh');
  // Le modele normalise range Wazuh sous la categorie generique.
  assert.equal(ck8Build({ configured: true }).category, 'siem');
  // Un identifiant inconnu n invente pas de libelle.
  assert.equal(ck8Label('nessus'), '');
  assert.equal(ck8Provider('nessus'), null);
});

test('SIEM : seuls les fournisseurs adosses a un adaptateur sont connectables', () => {
  // Un fournisseur devient connectable en gagnant un adaptateur ecrit contre
  // son API reelle — jamais en etant ajoute au catalogue.
  // Connectable veut dire « adosse a un adaptateur ». La liste s allonge a
  // chaque adaptateur reellement ecrit, donc c est l invariant qui est teste.
  for (const supported of ck8SupportedList()) {
    assert.ok(supported.implemented, supported.id);
    assert.ok(supported.configurationFields.length > 0, supported.id);
  }
  assert.equal(ck8Supported('wazuh'), true);
  assert.equal(ck8Supported('elastic'), true);
  for (const planned of ck8PlannedList()) {
    assert.equal(ck8Supported(planned.id), false, `${planned.id} ne doit pas etre traite comme implemente`);
  }
  // Le domaine est multi-SIEM : tous les fournisseurs du catalogue sont
  // proposes (le script de la page reference aussi ce nom, on ne compte donc
  // que les balises input), mais seul Wazuh peut etre teste et enregistre.
  const html = renderRuntimeSecurityPageHtml({ runtime: ck8Runtime(), openConfig: true }, 'n', 'light');
  const radios = html.match(/<input type="radio" name="runtime-provider-choice"/g) || [];
  assert.equal(radios.length, CK8_PROVIDERS.length);
  assert.match(html, /value="wazuh"[^>]*checked|checked[^>]*value="wazuh"/);
  assert.match(html, /data-action="testRuntimeConfig"/, 'Wazuh reste testable');
});

test('SIEM : chaque fournisseur du catalogue est selectionnable, sans mur « a venir »', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: ck8Runtime(), openConfig: true }, 'n', 'light');
  for (const provider of CK8_PROVIDERS) {
    assert.ok(html.includes(provider.label), `${provider.label} doit etre visible`);
    assert.match(html, new RegExp(`value="${provider.id}"`), `${provider.id} doit etre selectionnable`);
  }
  // Aucun mur « Coming later » et aucune rangee decorative separee : on
  // n inspecte que le balisage, la feuille de style etant partagee.
  const markup = html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
  assert.doesNotMatch(markup, /Coming later/);
  assert.doesNotMatch(markup, /provider-planned/);
  assert.doesNotMatch(markup, /provider-badge/);
});

test('SIEM : une configuration de fournisseur planifie est refusee cote extension', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const guard = source.match(/async function applyWazuhConfiguration\([\s\S]*?saveProviderConfiguration/);
  assert.ok(guard, 'la configuration SIEM doit exister');
  assert.match(guard[0], /isSupportedSiemProvider\(requested\)/);
  assert.match(guard[0], /return \{[\s\S]*?ok: false/);
  // La decision appartient a l extension, pas a la webview.
  assert.match(guard[0], /n'est pas encore disponible/);
});

test('SIEM : la page consomme le modele normalise, jamais du JSON Wazuh brut', () => {
  const pages = fs.readFileSync(path.join(__dirname, '..', 'src', 'enterprise-domain-pages.js'), 'utf8');
  // Formes propres a l API Wazuh : elles restent dans l adaptateur.
  for (const wazuhShape of ['affected_items', 'lastKeepAlive', 'predecoder', 'full_log', '/manager/info', '/security/events']) {
    assert.ok(!pages.includes(wazuhShape), `${wazuhShape} ne doit pas atteindre la page`);
  }
  // La page lit le modele neutre.
  for (const neutral of ['alertSummary', 'runtime.agents', 'mitreTechniques', 'lastChecked', 'runtime.label']) {
    assert.ok(pages.includes(neutral), `${neutral} doit venir du modele normalise`);
  }
});

test('SIEM : la page configuree reste « Runtime Security » avec une identite de fournisseur', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: ck8Runtime() }, 'n', 'light');
  assert.match(html, /Runtime Security/);
  assert.doesNotMatch(html, /Wazuh Dashboard/i);
  // Petite identite de fournisseur, pas un titre de page.
  assert.match(html, /Provider/);
  assert.ok(html.includes('Wazuh'));
  // Le modele normalise est bien rendu.
  for (const label of ['Alert summary', 'Critical', 'High', 'Medium', 'Low', 'Connection', 'Last sync']) {
    assert.ok(html.includes(label), `${label} doit rester affiche`);
  }
});

test('SIEM : la configuration Wazuh existante continue de se charger', async () => {
  // Les cles historiques sont toujours LUES — par le service provider-neutre,
  // qui ne les reecrit ni ne les supprime. Aucune migration destructive.
  const legacy = fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', 'siem-configuration.js'), 'utf8');
  assert.match(legacy, /url: 'wazuh\.url'/);
  assert.match(legacy, /username: 'wazuh\.username'/);
  assert.match(legacy, /secretKey: 'securityCenter\.wazuh\.password'/);
  assert.match(legacy, /hasLegacyWazuhConfiguration/);
  // Et l adaptateur repond toujours de la meme facon — depuis l adaptateur,
  // qui est desormais le seul endroit ou vit le client Wazuh.
  const { wazuhAdapter } = require('../src/integrations/siem-wazuh');
  const status = await wazuhAdapter.fetchStatus({}, {});
  assert.equal(status.configured, false);
  assert.equal(status.category, 'siem');
  const unconfigured = await wazuhAdapter.fetchStatus({ url: 'https://host.example.invalid:55000' }, {});
  assert.equal(unconfigured.status, CK8_RUNTIME.NOT_CONFIGURED);
  assert.equal(unconfigured.credentialsConfigured, false);
});

test('SIEM : la carte Dashboard reste generique tant qu aucun fournisseur n est connecte', () => {
  const dashboard = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  const card = dashboard.match(/domainCard\(\{ title: 'Runtime Security'[\s\S]*?\}\)/);
  assert.ok(card, 'la carte Runtime Security doit exister');
  // Non configuree : langage de domaine, jamais un nom d editeur.
  assert.match(card[0], /'Not configured'/);
  assert.match(card[0], /'SIEM provider'/);
  assert.doesNotMatch(card[0], /'Wazuh'/, 'la carte ne doit jamais etre etiquetee Wazuh en dur');
  // Configuree : l identite du fournisseur vient du modele.
  assert.match(card[0], /runtime\.label \|\| 'SIEM'/);
});

test('SIEM : aucun secret de fournisseur n atteint la webview', () => {
  const html = renderRuntimeSecurityPageHtml({
    runtime: ck8Runtime({ credentialsConfigured: true, username: 'analyst' }), openConfig: true
  }, 'n', 'light');
  assert.match(html, /type="password"/);
  assert.doesNotMatch(html, /<input id="runtime-password"[^>]*value=/);
  assert.doesNotMatch(html, /credentialsConfigured/);
  // Le catalogue n embarque aucun materiel d authentification.
  for (const provider of CK8_PROVIDERS) {
    assert.ok(!('password' in provider) && !('token' in provider) && !('secret' in provider), `${provider.id} ne doit porter aucun secret`);
  }
});

test('SIEM : un futur adaptateur se branche sur le meme contrat normalise', () => {
  // Le contrat que devra remplir `createSplunkAdapter` : la page ne change pas.
  const status = ck8Build({ provider: 'splunk', label: 'Splunk Enterprise Security', configured: true, status: CK8_RUNTIME.ONLINE, agents: [], alerts: [] });
  for (const key of ['provider', 'label', 'category', 'configured', 'status', 'agents', 'alerts', 'agentSummary', 'alertSummary', 'lastChecked']) {
    assert.ok(key in status, `${key} doit faire partie du modele normalise`);
  }
  assert.equal(status.category, 'siem');
  assert.equal(status.provider, 'splunk');
  // Et la page sait deja le rendre sans connaitre l adaptateur.
  const html = renderRuntimeSecurityPageHtml({ runtime: { ...status, alertSummary: { critical: 0, high: 0, medium: 0, low: 0 }, agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 } } }, 'n', 'light');
  assert.match(html, /Runtime Security/);
  assert.ok(html.includes('Splunk Enterprise Security'));
});

test('SIEM : aucune refonte visuelle hors du selecteur de fournisseur', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: ck8Runtime(), openConfig: true }, 'n', 'light');
  // Les structures existantes sont conservees.
  // La carte reste la meme carte : la passe de mise en page lui ajoute une
  // classe de disposition, elle ne remplace ni sa structure ni ses actions.
  for (const marker of ['class="domain-card setup-card config-workspace-card"', 'data-action="testRuntimeConfig"', 'data-action="saveRuntimeConfig"', 'data-action="cancelConfig"', 'id="runtime-url"', 'id="runtime-username"', 'id="runtime-password"', 'id="runtime-provider"']) {
    assert.ok(html.includes(marker), `${marker} doit rester`);
  }
  // Le nouveau catalogue n introduit aucune couleur codee en dur.
  const pages = fs.readFileSync(path.join(__dirname, '..', 'src', 'enterprise-domain-pages.js'), 'utf8');
  const css = pages.match(/\.provider-catalogue[\s\S]*?\.provider-planned \.provider-badge\{[^}]*\}/);
  assert.ok(css, 'les styles du catalogue doivent exister');
  assert.doesNotMatch(css[0], /#[0-9a-fA-F]{3,6}\b/, 'le catalogue doit utiliser les jetons du systeme visuel');
});

// ===========================================================================
// Infrastructure est un DOMAINE, pas un produit Prometheus
//
// La configuration presentait un `<select>` a une seule entree et un libelle
// « Prometheus URL » : une categorie entiere du produit paraissait liee a un
// seul outil de metriques. Prometheus est le premier adaptateur, pas le domaine.
// ===========================================================================

const {
  OBSERVABILITY_PROVIDERS: CK9_PROVIDERS, OBSERVABILITY_PROVIDER_STATUS: CK9_STATUS,
  DEFAULT_OBSERVABILITY_PROVIDER: CK9_DEFAULT,
  observabilityProvider: ck9Provider, observabilityProviderLabel: ck9Label,
  isSupportedObservabilityProvider: ck9Supported,
  supportedObservabilityProviders: ck9SupportedList, plannedObservabilityProviders: ck9PlannedList,
  buildPrometheusStatus: ck9Build, fetchPrometheusStatus: ck9Fetch, PROMETHEUS_STATUS: CK9_PROM
} = require('../src/integrations/observability');

test('Observability : le catalogue est la source unique d identite des fournisseurs', () => {
  const ids = CK9_PROVIDERS.map((provider) => provider.id);
  for (const expected of ['prometheus', 'datadog', 'newrelic', 'zabbix', 'influxdb', 'opentelemetry']) {
    assert.ok(ids.includes(expected), `${expected} doit figurer au catalogue`);
  }
  for (const provider of CK9_PROVIDERS) {
    assert.ok([CK9_STATUS.SUPPORTED, CK9_STATUS.PLANNED].includes(provider.status), `${provider.id} doit declarer un etat`);
    assert.ok(provider.label && provider.id);
  }
  // Grafana n est pas un backend de metriques : le catalogue ne le promet pas.
  assert.ok(!ids.includes('grafana'), 'Grafana est une couche de visualisation, pas une source de metriques');
  // Aucune duplication : la page lit le catalogue, jamais un nom d outil.
  const pages = source('src/enterprise-domain-pages.js');
  assert.match(pages, /OBSERVABILITY_PROVIDERS/);
  assert.doesNotMatch(pages, /<option value="prometheus"/, 'le select code en dur doit avoir disparu');
  // Seul un adaptateur peut decrire une connexion : sans lui, aucun champ.
  for (const provider of CK9_PROVIDERS) {
    assert.equal(provider.configurationFields.length > 0, provider.implemented, `${provider.id}`);
  }
});

test('Observability : Prometheus est un identifiant de fournisseur, pas le domaine', () => {
  assert.equal(ck9Provider('prometheus').id, 'prometheus');
  assert.equal(ck9Label('prometheus'), 'Prometheus');
  assert.equal(CK9_DEFAULT, 'prometheus');
  assert.equal(ck9Build({ configured: true }).category, 'observability');
  assert.equal(ck9Label('graphite'), '');
  assert.equal(ck9Provider('graphite'), null);
});

test('Observability : seuls les fournisseurs adosses a un adaptateur sont configurables', () => {
  // Un backend devient configurable en gagnant un adaptateur ecrit contre son
  // API reelle — jamais en etant ajoute au catalogue.
  // Configurable veut dire « adosse a un adaptateur », pas « inscrit dans une
  // liste figee le jour ou celui-ci a ete ajoute ».
  for (const supported of ck9SupportedList()) {
    assert.ok(supported.implemented, supported.id);
    assert.ok(supported.configurationFields.length > 0, supported.id);
  }
  assert.equal(ck9Supported('prometheus'), true);
  for (const planned of ck9PlannedList()) {
    assert.equal(ck9Supported(planned.id), false, `${planned.id} ne doit pas etre traite comme implemente`);
  }
  // Le domaine est multi-fournisseurs : tous sont proposes, un seul est jouable.
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus(), openConfig: true }, 'n', 'light');
  const radios = html.match(/<input type="radio" name="observability-provider-choice"/g) || [];
  assert.equal(radios.length, CK9_PROVIDERS.length);
  assert.match(html, /value="prometheus"[^>]*checked|checked[^>]*value="prometheus"/);
  assert.match(html, /data-action="testInfrastructureConfig"/);
});

test('Observability : les fournisseurs planifies sont annonces sans etre jouables', () => {
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus(), openConfig: true }, 'n', 'light');
  // Catalogue neutre : aucun badge, aucun mur « a venir ».
  const markup = html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
  assert.doesNotMatch(markup, /Additional adapters/);
  assert.doesNotMatch(markup, /Coming later/);
  assert.doesNotMatch(markup, /provider-badge/);
  for (const planned of ck9PlannedList()) {
    assert.ok(html.includes(planned.label), `${planned.label} doit etre visible au catalogue`);
    // Selectionnable pour voir ou il en est, mais sans action ni champ.
    const own = renderInfrastructurePageHtml({ prometheus: { provider: planned.id, configured: false } }, 'n', 'light');
    assert.doesNotMatch(own, /data-action="testInfrastructureConfig"/, planned.id);
    assert.doesNotMatch(own, /data-action="saveInfrastructureConfig"/, planned.id);
    assert.ok(own.includes(`Security Center does not integrate ${planned.label} yet.`), planned.id);
  }
  // Aucun etat de connexion ni metrique fabriquee pour un adaptateur absent.
  assert.doesNotMatch(html, /Datadog[^<]*(Healthy|Connected|Online)/i);
});

test('Observability : une configuration de fournisseur planifie est refusee cote extension', () => {
  const extension = source('src/extension.js');
  const guard = extension.match(/async function applyPrometheusConfiguration\([\s\S]*?saveProviderConfiguration/);
  assert.ok(guard, 'la configuration observabilite doit exister');
  assert.match(guard[0], /isSupportedObservabilityProvider\(requested\)/);
  assert.match(guard[0], /ok: false/);
  assert.match(guard[0], /n'est pas encore disponible/);
});

test('Observability : la page consomme le modele normalise, jamais du JSON Prometheus brut', () => {
  const pages = source('src/enterprise-domain-pages.js');
  // Formes propres a l API Prometheus : elles restent dans l adaptateur.
  for (const raw of ['/api/v1/query', '/api/v1/targets', 'activeTargets', 'node_cpu_seconds_total', 'node_memory_MemTotal', 'scrapeUrl', 'data.result']) {
    assert.ok(!pages.includes(raw), `${raw} ne doit pas atteindre la page`);
  }
  // La page lit le modele neutre.
  for (const neutral of ['model.metrics', 'targets?.display', 'lastScrapeAgeSeconds', 'selectedHost']) {
    assert.ok(pages.includes(neutral), `${neutral} doit venir du modele normalise`);
  }
});

test('Observability : la page configuree reste « Infrastructure »', () => {
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus() }, 'n', 'light');
  assert.match(html, /Infrastructure/);
  assert.doesNotMatch(html, /Prometheus Dashboard/i);
  assert.match(html, /Provider: Prometheus/);
  for (const label of ['System health', 'Host health', 'Targets', 'CPU', 'Memory', 'Disk', 'Load', 'Last scrape']) {
    assert.ok(html.includes(label), `${label} doit rester affiche`);
  }
  // Le libelle du fournisseur vient du modele, jamais d un repli code en dur.
  const pages = source('src/enterprise-domain-pages.js');
  assert.doesNotMatch(pages, /prometheus\.label \|\| 'Prometheus'/);
  assert.match(pages, /prometheus\.label \|\| 'Observability'/);
});

test('Observability : la configuration Prometheus existante continue de se charger', async () => {
  const extension = source('src/extension.js');
  assert.match(extension, /securityCenter\.prometheus\.bearerToken/);
  assert.match(extension, /fields: \{ url: 'prometheus\.url' \}/);
  assert.match(extension, /secrets: \{ bearerToken: PROMETHEUS_BEARER_SECRET_KEY \}/);
  // La sauvegarde passe par le service provider-neutre ; les anciennes cles
  // restent lues, jamais reecrites.
  assert.match(extension, /observabilityConfiguration\.saveProviderConfiguration/);
  // L adaptateur repond toujours de la meme facon.
  const empty = await ck9Fetch({ baseUrl: '' });
  assert.equal(empty.configured, false);
  assert.equal(empty.category, 'observability');
  assert.equal(empty.provider, 'prometheus');
  const invalid = await ck9Fetch({ baseUrl: 'not a url' });
  assert.equal(invalid.status, CK9_PROM.QUERY_ERROR);
});

test('Observability : le test de connexion Prometheus est inchange', () => {
  // Logique reseau intacte : memes requetes, memes chemins — mais desormais
  // derriere la frontiere de l adaptateur, ou elles appartiennent.
  const adapter = source('src/integrations/observability-prometheus.js');
  assert.match(adapter, /joinUrl\(baseUrl, '\/api\/v1\/query', \{ query \}\)/);
  assert.match(adapter, /joinUrl\(baseUrl, '\/api\/v1\/targets', \{ state: 'active' \}\)/);
  assert.match(source('src/integrations/observability.js'), /async function fetchPrometheusStatus/);
  // Les requetes PromQL ne sont pas modifiees.
  const { QUERIES } = require('../src/integrations/observability-prometheus');
  assert.deepEqual(Object.keys(QUERIES).sort(), ['cpu', 'diskAvailable', 'diskSize', 'load1', 'memoryAvailable', 'memoryTotal']);
  // Le bouton de test existe toujours pour le fournisseur supporte.
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus(), openConfig: true }, 'n', 'light');
  assert.match(html, /data-action="testInfrastructureConfig"/);
});

test('Observability : une metrique indisponible reste « Unavailable », jamais zero', () => {
  const html = renderInfrastructurePageHtml({
    prometheus: prometheusStatus({
      metrics: {
        cpu: { available: false, display: 'Unavailable' },
        memory: { available: false, display: 'Unavailable' },
        disk: { available: false, display: 'Unavailable' },
        load1: { available: false, display: 'Unavailable' }
      },
      targets: { up: null, total: null, display: 'Unavailable', lastScrapeAgeSeconds: null, items: [] }
    })
  }, 'n', 'light');
  assert.doesNotMatch(html, /<strong>0<\/strong>/);
  assert.doesNotMatch(html, /<strong>0%<\/strong>/);
  assert.ok((html.match(/Unavailable/g) || []).length >= 4);
  // Et un vrai zero reste un vrai zero — la regle vaut pour tout adaptateur.
  const genuineZero = renderInfrastructurePageHtml({
    prometheus: prometheusStatus({ metrics: { cpu: { available: true, display: '0%' }, memory: { available: false, display: 'Unavailable' }, disk: { available: false, display: 'Unavailable' }, load1: { available: false, display: 'Unavailable' } } })
  }, 'n', 'light');
  assert.match(genuineZero, /CPU<\/span><strong>0%<\/strong>/);
});

test('Observability : aucun jeton n atteint la webview', () => {
  const html = renderInfrastructurePageHtml({
    prometheus: prometheusStatus({ credentialsConfigured: true }), openConfig: true
  }, 'n', 'light');
  // Le champ secret existe (c est son schema) mais n a jamais de valeur, et
  // aucun materiel d authentification ne traverse la webview.
  // « Bearer token » est un libelle de schema ; ce qui ne doit jamais paraitre,
  // c est une valeur ou un en-tete d autorisation.
  assert.doesNotMatch(html, /credentialsConfigured/);
  assert.doesNotMatch(html, /Bearer [A-Za-z0-9+/=._-]{12,}/);
  assert.doesNotMatch(html, /type="password"[^>]*value=/);
  // Le catalogue ne transporte aucun materiel d authentification.
  for (const provider of CK9_PROVIDERS) {
    assert.ok(!('token' in provider) && !('apiKey' in provider) && !('secret' in provider), `${provider.id} ne doit porter aucun secret`);
  }
  // Le secret reste lu depuis SecretStorage, cote extension uniquement.
  const extension = source('src/extension.js');
  // Le secret est lu par le service provider-neutre, depuis SecretStorage.
  assert.match(extension, /secrets: \{ bearerToken: PROMETHEUS_BEARER_SECRET_KEY \}/);
  assert.match(extension, /secrets: context\.secrets/);
});

test('Observability : la carte Dashboard et la navigation restent generiques', () => {
  const dashboard = source('src/dashboard.js');
  const card = dashboard.match(/domainCard\(\{ title: 'Infrastructure'[\s\S]*?\}\)/);
  assert.ok(card, 'la carte Infrastructure doit exister');
  assert.match(card[0], /'Not configured'/);
  assert.match(card[0], /'Observability'/);
  assert.doesNotMatch(card[0], /'Prometheus'/, 'la carte ne doit jamais etre etiquetee Prometheus en dur');
  assert.match(card[0], /prometheus\.label \|\| 'Observability'/);
  // La navigation nomme les domaines, pas les outils.
  const shell = source('src/security-center-shell.js');
  assert.doesNotMatch(shell, />Prometheus<|>Wazuh</, 'la navigation ne doit porter aucune marque d outil');
});

test('Observability : un futur adaptateur se branche sur le meme contrat', () => {
  // Le contrat que devra remplir `createDatadogAdapter` : la page ne change pas.
  const status = ck9Build({
    configured: true, baseUrl: 'https://api.datadoghq.com', status: CK9_PROM.HEALTHY,
    targets: { up: 3, total: 3, display: '3/3 UP', lastScrapeAgeSeconds: 5, items: [] },
    metrics: { cpu: { available: true, display: '11%' }, memory: { available: false, display: 'Unavailable' }, disk: { available: false, display: 'Unavailable' }, load1: { available: false, display: 'Unavailable' } }
  });
  for (const key of ['provider', 'label', 'category', 'configured', 'status', 'targets', 'metrics', 'lastChecked', 'credentialsConfigured']) {
    assert.ok(key in status, `${key} doit faire partie du modele normalise`);
  }
  // Un adaptateur compose son tableau de bord a partir des memes types de
  // sections : le rendu suit son manifeste, jamais son nom.
  const html = renderInfrastructurePageHtml({
    prometheus: {
      ...status, label: 'Datadog', provider: 'datadog',
      sections: [{ id: 'host', kind: 'metric-tiles', capability: ['cpu', 'memory', 'disk', 'load'], title: 'Host health' }]
    }
  }, 'n', 'light');
  assert.match(html, /Infrastructure/);
  assert.match(html, /Provider: Datadog/);
  assert.match(html, /3\/3 UP/);
  assert.match(html, /11%/);
  // L honnetete des metriques vaut pour tout adaptateur.
  assert.ok((html.match(/Unavailable/g) || []).length >= 3);
});

test('Observability : la page Integrations montre le domaine, pas l outil', () => {
  const integrations = source('src/integrations-page.js');
  assert.doesNotMatch(integrations, /<h3>Prometheus<\/h3><p>Observability<\/p>/);
  assert.match(integrations, /<h3>Observability<\/h3><p>Provider: /);
});

test('Observability : aucune refonte visuelle hors du selecteur', () => {
  const html = renderInfrastructurePageHtml({ prometheus: prometheusStatus(), openConfig: true }, 'n', 'light');
  for (const marker of ['class="domain-card setup-card config-workspace-card"', 'data-action="testInfrastructureConfig"', 'data-action="saveInfrastructureConfig"', 'data-action="cancelConfig"', 'id="observability-url"', 'id="observability-provider"']) {
    assert.ok(html.includes(marker), `${marker} doit rester`);
  }
  // Le catalogue reutilise les styles deja introduits pour le domaine SIEM :
  // aucune seconde feuille de style, aucune couleur codee en dur.
  const pages = source('src/enterprise-domain-pages.js');
  assert.equal((pages.match(/\.provider-catalogue\{/g) || []).length, 1, 'un seul bloc de styles de catalogue');
});

// ===========================================================================
// A.2 — Les reglages generiques sont declares, et Disconnect existe vraiment
// ===========================================================================

const a2Manifest = require('../package.json');
const a2Props = a2Manifest.contributes.configuration.properties;
const a2Source = (file) => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

test('A2 : les reglages provider-neutres sont declares au manifeste', () => {
  const active = a2Props['securityCenter.runtimeSecurity.provider'];
  const providers = a2Props['securityCenter.runtimeSecurity.providers'];
  assert.ok(active, 'runtimeSecurity.provider doit etre declare');
  assert.ok(providers, 'runtimeSecurity.providers doit etre declare');
  assert.equal(active.type, 'string');
  assert.equal(active.default, '', 'aucun fournisseur actif par defaut');
  assert.equal(providers.type, 'object');
  assert.deepEqual(providers.default, {});
});

test('A2 : le schema ne duplique pas le catalogue de fournisseurs', () => {
  const active = a2Props['securityCenter.runtimeSecurity.provider'];
  // Une enumeration figee dans package.json divergerait du registre des
  // adaptateurs des le prochain fournisseur ajoute.
  assert.equal(active.enum, undefined, 'pas d enum fige qui pourrait diverger');
  assert.match(active.description, /catalogue/i);
});

test('A2 : les descriptions disent ou vivent les identifiants', () => {
  const active = a2Props['securityCenter.runtimeSecurity.provider'];
  const providers = a2Props['securityCenter.runtimeSecurity.providers'];
  assert.match(active.description, /SecretStorage/);
  const providersText = `${providers.markdownDescription || ''}${providers.description || ''}`;
  assert.match(providersText, /SecretStorage/);
  assert.match(providersText, /non secr/i);
});

test('A2 : le schema des configurations fournisseur n encourage aucun secret', () => {
  const providers = a2Props['securityCenter.runtimeSecurity.providers'];
  const text = JSON.stringify(providers);
  // Aucune propriete nommee comme un secret n est proposee par le schema.
  for (const forbidden of ['"password"', '"token"', '"apiKey"', '"clientSecret"', '"secret"']) {
    assert.ok(!text.includes(forbidden), `${forbidden} ne doit pas figurer au schema`);
  }
  const providersText = `${providers.markdownDescription || ''}${providers.description || ''}`;
  assert.match(providersText, /jeton|mot de passe/i, 'la description doit interdire explicitement les secrets');
});

test('A2 : le service n ecrit jamais un champ secret dans les reglages', async () => {
  // Contrat verifie sur le service lui-meme, pas seulement sur la documentation.
  const { createSiemConfigurationService, secretKeyFor: a2SecretKey } = require('../src/integrations/siem-configuration');
  const { wazuhAdapter: a2Wazuh } = require('../src/integrations/siem-wazuh');
  const store = {};
  const vault = new Map();
  const service = createSiemConfigurationService({
    configuration: { get: (k, d) => (k in store ? store[k] : d), update: async (k, v) => { store[k] = v; } },
    secrets: { get: async (k) => vault.get(k) || '', store: async (k, v) => { vault.set(k, v); }, delete: async (k) => { vault.delete(k); } },
    resolveAdapter: (id) => (id === 'wazuh' ? a2Wazuh : null)
  });
  await service.saveProviderConfiguration('wazuh', { url: 'https://w:55000', username: 'api', password: 'TOP-SECRET' });
  const serialized = JSON.stringify(store);
  assert.ok(!serialized.includes('TOP-SECRET'), 'aucun secret dans les reglages');
  assert.equal(store['runtimeSecurity.providers'].wazuh.password, undefined);
  assert.equal(store['runtimeSecurity.providers'].wazuh.indexerPassword, undefined, 'aucun secret Indexer non plus');
  // Les champs optionnels laisses vides ne sont pas persistes.
  assert.deepEqual(Object.keys(store['runtimeSecurity.providers'].wazuh).sort(), ['url', 'username']);
  assert.equal(vault.get(a2SecretKey('wazuh', 'password')), 'TOP-SECRET', 'le secret va bien dans SecretStorage');
});

test('A2 : les reglages Wazuh historiques restent declares', () => {
  assert.ok(a2Props['securityCenter.wazuh.url'], 'wazuh.url doit rester declare');
  assert.ok(a2Props['securityCenter.wazuh.username'], 'wazuh.username doit rester declare');
  // Aucun reglage de secret n a jamais existe et il ne doit pas en apparaitre.
  for (const key of Object.keys(a2Props)) {
    assert.ok(!/wazuh\.(password|token|secret)/.test(key), `${key} ne doit pas exister`);
  }
});

// ------------------------------------------------------------- Disconnect

test('A2 : Runtime Security configure expose une action Disconnect reelle', () => {
  const configured = renderRuntimeSecurityPageHtml({ runtime: runtimeStatus() }, 'n', 'light');
  assert.match(configured, /data-action="disconnectRuntime"/);
  assert.match(configured, /Disconnect provider/);
  // Non configure : pas de bouton, donc pas de bouton mort.
  const empty = renderRuntimeSecurityPageHtml({}, 'n', 'light');
  assert.doesNotMatch(empty, /data-action="disconnectRuntime"/);
});

test('A2 : le bouton Disconnect a un vrai gestionnaire', () => {
  const extension = a2Source('src/extension.js');
  assert.match(extension, /message\.action === 'disconnectRuntime'[\s\S]{0,80}confirmDisconnectRuntimeSecurity\(\)/);
  assert.match(extension, /async function confirmDisconnectRuntimeSecurity\(\)/);
  // Le script de la page transmet bien les actions inconnues a l extension.
  const pages = a2Source('src/enterprise-domain-pages.js');
  assert.match(pages, /vscode\.postMessage\(\{type:'action',action\}\)/);
});

test('A2 : la confirmation nomme le fournisseur actif, jamais Wazuh en dur', () => {
  const extension = a2Source('src/extension.js');
  const handler = extension.match(/async function confirmDisconnectRuntimeSecurity\(\)[\s\S]*?\n  \}/);
  assert.ok(handler);
  assert.match(handler[0], /siemProvider\(activeId\)\?\.label/, 'le libelle vient du fournisseur actif');
  assert.match(handler[0], /modal: true/, 'une action d etat exige une confirmation');
  assert.doesNotMatch(handler[0], /Wazuh/, 'aucun nom de fournisseur code en dur');
  // Le texte dit ce qui est CONSERVE : c est la partie non verifiable par l utilisateur.
  assert.match(handler[0], /conserv/i);
});

test('A2 : annuler la confirmation ne change rien', () => {
  const extension = a2Source('src/extension.js');
  const handler = extension.match(/async function confirmDisconnectRuntimeSecurity\(\)[\s\S]*?\n  \}/);
  // Sortie avant tout effet de bord si l utilisateur n a pas confirme.
  const guard = handler[0].indexOf("if (confirmation !== 'Déconnecter') return");
  const effect = handler[0].indexOf('await disconnectRuntimeSecurity()');
  assert.ok(guard > -1 && effect > guard, 'aucun effet avant la confirmation');
  // Et rien ne se produit si aucun fournisseur n est actif.
  assert.match(handler[0], /if \(!activeId\) return \{ ok: false, reason: 'not-configured' \}/);
});

test('A2 : disconnect efface la selection et conserve tout le reste', async () => {
  const { createSiemConfigurationService, secretKeyFor: a2SecretKey } = require('../src/integrations/siem-configuration');
  const { wazuhAdapter: a2Wazuh } = require('../src/integrations/siem-wazuh');
  const store = {};
  const vault = new Map();
  const service = createSiemConfigurationService({
    configuration: { get: (k, d) => (k in store ? store[k] : d), update: async (k, v) => { store[k] = v; } },
    secrets: { get: async (k) => vault.get(k) || '', store: async (k, v) => { vault.set(k, v); }, delete: async (k) => { vault.delete(k); } },
    resolveAdapter: (id) => (id === 'wazuh' ? a2Wazuh : null)
  });
  await service.saveProviderConfiguration('wazuh', { url: 'https://w:55000', username: 'api', password: 'keep-me' });
  await service.disconnect();

  assert.equal(service.getActiveProviderId(), '', 'plus de fournisseur actif');
  assert.deepEqual(store['runtimeSecurity.providers'].wazuh, { url: 'https://w:55000', username: 'api' }, 'config conservee');
  assert.equal(vault.get(a2SecretKey('wazuh', 'password')), 'keep-me', 'identifiants conserves');

  // Reconnexion sans ressaisie : la configuration et le secret sont deja la.
  await service.setActiveProvider('wazuh');
  const active = await service.resolveActiveProvider();
  assert.equal(active.config.url, 'https://w:55000');
  assert.equal(active.config.username, 'api');
  assert.equal(active.secrets.password, 'keep-me');
  // Et la webview ne recoit toujours qu un booleen.
  // Un booleen par champ secret declare, y compris ceux restes vides.
  assert.deepEqual(await service.describeProviderSecrets('wazuh'), { password: true, indexerPassword: false });
});

test('A2 : apres disconnect l interface repasse en Not configured', () => {
  const extension = a2Source('src/extension.js');
  const disconnectFn = extension.match(/async function disconnectRuntimeSecurity\(\)[\s\S]*?\n  \}/);
  assert.ok(disconnectFn);
  assert.match(disconnectFn[0], /siemConfiguration\.disconnect\(\)/);
  assert.match(disconnectFn[0], /buildRuntimeSecurityStatus\(\{ configured: false \}\)/);
  assert.match(disconnectFn[0], /renderRuntimeSecurityPage\(\)/);
  // Le rendu non configure est bien l etat « Not configured ».
  const html = renderRuntimeSecurityPageHtml({}, 'n', 'light');
  assert.match(html, /SIEM provider not configured/);
});

test('A2 : disconnect ne touche ni scanners, ni findings, ni etat de scan', () => {
  const extension = a2Source('src/extension.js');
  const handler = extension.match(/async function (confirm)?[Dd]isconnectRuntimeSecurity\(\)[\s\S]*?\n  \}/g).join('\n');
  for (const forbidden of ['currentFindings', 'currentScanStatuses', 'currentSecuritySnapshot', 'saveLocalScanCache', 'LOCAL_SCAN_HISTORY_KEY', 'PIPELINE_STATE_KEY', 'secrets.delete', 'forgetProviderSecrets']) {
    assert.ok(!handler.includes(forbidden), `disconnect ne doit pas toucher ${forbidden}`);
  }
});

test('A2 : disconnect reutilise le vocabulaire d audit existant, sans identifiant', () => {
  const extension = a2Source('src/extension.js');
  const handler = extension.match(/async function confirmDisconnectRuntimeSecurity\(\)[\s\S]*?\n  \}/)[0];
  assert.match(handler, /action: 'integration\.configuration\.changed'/, 'vocabulaire existant reutilise');
  const { EMITTED_AUDIT_ACTIONS } = require('../src/audit-events');
  assert.ok(EMITTED_AUDIT_ACTIONS.includes('integration.configuration.changed'));
  // Metadonnees : jamais d identifiant.
  const metadata = handler.match(/metadata: \{[^}]*\}/)[0];
  for (const forbidden of ['password', 'token', 'secret', 'credential']) {
    assert.ok(!metadata.toLowerCase().includes(forbidden), `${forbidden} ne doit pas etre audite`);
  }
});

test('A2 : « Configure provider » reste l unique route de changement de fournisseur', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: runtimeStatus() }, 'n', 'light');
  // Une seule action de reglages du fournisseur : pas de doublon « Change
  // provider », et pas non plus un second bouton dans la carte de connexion
  // depuis que l entete en porte un. Une invitation contextuelle a configurer
  // une source de donnees precise n est pas cette route-la.
  assert.equal((html.match(/data-action="showConfig">Settings/g) || []).length, 1);
  assert.doesNotMatch(html, /data-action="changeProvider"/);
  assert.match(html, /data-action="showConfig">Settings/);
});

test('A2 : aucune refonte visuelle pour l ajout de Disconnect', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: runtimeStatus() }, 'n', 'light');
  // Le bouton reutilise la classe secondaire existante et la meme rangee.
  assert.match(html, /<button class="secondary" data-action="disconnectRuntime">/);
  const pages = a2Source('src/enterprise-domain-pages.js');
  assert.doesNotMatch(pages, /\.disconnect-button|\.danger-button/, 'aucune classe CSS ajoutee');
});
