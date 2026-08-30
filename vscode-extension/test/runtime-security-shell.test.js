'use strict';

/**
 * Phase 5A — Runtime Security operational shell.
 *
 * Two product rules are load-bearing here and are asserted rather than assumed:
 *   1. a capability the provider does not offer has no tab at all;
 *   2. stored credentials never promote a capability — only a real probe can,
 *      and no probe exists yet.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  RUNTIME_CAPABILITY_STATE, CAPABILITY_TABS, OVERVIEW_TAB,
  resolveRuntimeCapabilities, runtimeCapabilityTabs, resolveRuntimeTab, runtimeNavigation
} = require('../src/integrations/siem-navigation');
const { CAPABILITY, CAPABILITY_STATE, CAPABILITY_STATES } = require('../src/integrations/siem-contract');
const { siemAdapter, RUNTIME_STATUS } = require('../src/integrations/siem');
const { renderRuntimeSecurityPageHtml: renderRuntimePage } = require('../src/enterprise-domain-pages');
// Depuis que l'historique d'alertes vient du moteur de recherche du
// fournisseur et non de son API de gestion, la page a besoin de la preuve
// d'execution qu'une sonde reussie fournit. Les tests qui examinent un etat
// degrade passent la leur et gagnent.
const READY_EVIDENCE = Object.freeze({ alerts: { state: 'ready' }, mitre: { state: 'ready' } });
function renderRuntimeSecurityPageHtml(model = {}, nonce = '', theme = 'light') {
  return renderRuntimePage({ capabilityEvidence: READY_EVIDENCE, ...model }, nonce, theme);
}


const repoRoot = path.join(__dirname, '..');

/** The page markup only: the stylesheet and the event-wiring script are shared. */
function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

function connectedRuntime(overrides = {}) {
  return {
    configured: true,
    provider: 'wazuh',
    label: 'Wazuh',
    status: RUNTIME_STATUS.ONLINE,
    baseUrl: 'https://wazuh.local:55000',
    username: 'api',
    credentialsConfigured: true,
    lastChecked: new Date(Date.now() - 9000).toISOString(),
    agentSummary: { active: 1, total: 2, disconnected: 1, neverConnected: 0 },
    alertSummary: { critical: 1, high: 1, medium: 0, low: 0 },
    agents: [
      { name: 'ubuntu-runtime', os: 'Ubuntu 22.04', status: 'active', ip: '10.0.0.5', lastSeen: '9 sec ago' },
      { name: 'api-runtime', os: 'Debian 12', status: 'disconnected', ip: '10.0.0.6', lastSeen: '2 h ago' }
    ],
    alerts: [
      { severity: 'CRITICAL', title: 'SSH brute-force attempt', summary: 'Authentication failures exceeded the threshold.', host: 'ubuntu-runtime', ruleId: '5710', category: 'authentication_failed', mitreTechniques: ['T1110'], timestamp: '2026-08-20T09:01:00Z', status: 'open' },
      { severity: 'HIGH', title: 'Suspicious sudo usage', summary: 'Privilege escalation attempt.', host: 'api-runtime', ruleId: '5402', category: 'privilege_escalation', mitreTechniques: ['T1110', 'T1548'], timestamp: '2026-08-20T09:04:00Z', status: 'open' }
    ],
    ...overrides
  };
}

function tabIds(html) {
  return [...markup(html).matchAll(/<button data-tab="([a-z]+)"/g)].map((match) => match[1]);
}

function activeTab(html) {
  const found = markup(html).match(/<button data-tab="([a-z]+)" aria-current="true"/);
  return found ? found[1] : '';
}

// ---------------------------------------------------------------------------
// Capability resolution
// ---------------------------------------------------------------------------

test('5A : une capacite absente le reste, quelle que soit la configuration stockee', () => {
  const wazuh = siemAdapter('wazuh');
  // Wazuh declare vulnerabilities « a configurer » : possible, pas prouve. SCA
  // et FIM restent indisponibles, aucun adaptateur ne les interroge.
  assert.equal(wazuh.capabilities.vulnerabilities, CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(wazuh.capabilities.sca, CAPABILITY_STATE.UNAVAILABLE);

  const withIndexer = resolveRuntimeCapabilities(wazuh, connectedRuntime({
    values: { url: 'https://w:55000', username: 'api', indexerUrl: 'https://w:9200', indexerUsername: 'admin' },
    secretsConfigured: { password: true, indexerPassword: true }
  }));
  // Des identifiants Indexer stockes ne sont pas une preuve de capacite : sans
  // sonde reussie, la capacite reste « a configurer » et n a aucun onglet.
  assert.equal(withIndexer[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(withIndexer[CAPABILITY.SCA], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
  assert.equal(withIndexer[CAPABILITY.FIM], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
  // Les alertes et MITRE viennent du meme moteur de recherche et suivent la
  // meme regle : des identifiants ne les prouvent pas davantage.
  assert.equal(withIndexer[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(withIndexer[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  // Ce que l API de gestion sert seule reste disponible.
  assert.equal(withIndexer[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.READY);

  // Seule une sonde reussie promeut, et elle ne promeut qu elle-meme.
  const probed = resolveRuntimeCapabilities(wazuh, connectedRuntime(), {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.equal(probed[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(probed[CAPABILITY.MITRE], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(probed[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
});

test('5A : « error » est un etat resolu, jamais un etat declare', () => {
  // Un adaptateur ne peut pas se declarer casse : le vocabulaire declare du
  // contrat ne contient pas « error ».
  assert.ok(!CAPABILITY_STATES.includes(RUNTIME_CAPABILITY_STATE.ERROR));

  const broken = resolveRuntimeCapabilities(siemAdapter('wazuh'), connectedRuntime({
    status: RUNTIME_STATUS.AUTH_ERROR, message: 'Authentication failed'
  }));
  // Ce que l API de gestion sert tombe avec elle.
  assert.equal(broken[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.ERROR);
  // Une capacite absente ne devient pas « en erreur » : elle n a jamais existe.
  assert.equal(broken[CAPABILITY.SCA], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
  // Et une capacite servie par un AUTRE service ne tombe pas avec elle.
  assert.equal(broken[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(broken[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);

  // « error » n arrive a une capacite adossee a un autre service que par sa
  // propre preuve d execution.
  const alertsDown = resolveRuntimeCapabilities(siemAdapter('wazuh'), connectedRuntime(), { alerts: { state: 'error' } });
  assert.equal(alertsDown[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(alertsDown[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.READY);
});

test('5A : sans configuration, les capacites offertes demandent une configuration', () => {
  const resolved = resolveRuntimeCapabilities(siemAdapter('wazuh'), { configured: false });
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(resolved[CAPABILITY.VULNERABILITIES], RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG);
  assert.equal(resolved[CAPABILITY.SCA], RUNTIME_CAPABILITY_STATE.UNAVAILABLE);
});

test('5A : un fournisseur inconnu n expose aucune section en dehors de l apercu', () => {
  const nav = runtimeNavigation(null, connectedRuntime({ provider: 'splunk', label: 'Splunk' }), 'alerts');
  assert.deepEqual(nav.tabs.map((tab) => tab.id), [OVERVIEW_TAB.id]);
  assert.equal(nav.tab, OVERVIEW_TAB.id);
});

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

test('5A : la navigation derive des capacites, sans condition propre a Wazuh', () => {
  // Sans preuve d execution, seul ce que l API de gestion sert a une section.
  const resolved = resolveRuntimeCapabilities(siemAdapter('wazuh'), connectedRuntime());
  assert.deepEqual(runtimeCapabilityTabs(resolved).map((tab) => tab.id), ['overview', 'assets']);
  const probed = resolveRuntimeCapabilities(siemAdapter('wazuh'), connectedRuntime(), {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.deepEqual(runtimeCapabilityTabs(probed).map((tab) => tab.id), ['overview', 'alerts', 'assets', 'mitre']);

  // La meme fonction, avec une capacite de plus, produit l onglet de plus —
  // c est ce qui fera apparaitre Vulnerabilities en phase 6 sans toucher a la page.
  const withVulnerabilities = resolveRuntimeCapabilities(
    { capabilities: { alerts: 'ready', assets: 'ready', mitre: 'ready', vulnerabilities: 'ready' } },
    connectedRuntime()
  );
  assert.deepEqual(
    runtimeCapabilityTabs(withVulnerabilities).map((tab) => tab.id),
    ['overview', 'alerts', 'assets', 'mitre', 'vulnerabilities']
  );

  const pages = fs.readFileSync(path.join(repoRoot, 'src', 'enterprise-domain-pages.js'), 'utf8');
  assert.doesNotMatch(pages, /provider\s*===\s*'wazuh'|provider\s*===\s*"wazuh"/, 'aucune condition Wazuh dans le rendu');
});

test('5A : une section demandee qui n existe pas retombe sur l apercu', () => {
  const tabs = runtimeCapabilityTabs(resolveRuntimeCapabilities(siemAdapter('wazuh'), connectedRuntime(), {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  }));
  assert.equal(resolveRuntimeTab(tabs, 'vulnerabilities'), 'overview');
  assert.equal(resolveRuntimeTab(tabs, ''), 'overview');
  assert.equal(resolveRuntimeTab(tabs, 'ALERTS'), 'alerts');
});

test('5A : chaque onglet de capacite pointe vers une capacite du contrat', () => {
  const known = Object.values(CAPABILITY);
  for (const tab of CAPABILITY_TABS) {
    assert.ok(known.includes(tab.capability), `${tab.id} doit referencer une capacite declaree`);
  }
});

// ---------------------------------------------------------------------------
// Rendu
// ---------------------------------------------------------------------------

test('5A : la page rend exactement les onglets resolus, et aucun onglet desactive', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: connectedRuntime() }, 'n', 'light');
  assert.deepEqual(tabIds(html), ['overview', 'alerts', 'assets', 'mitre']);
  assert.equal(activeTab(html), 'overview');
  assert.doesNotMatch(markup(html), /data-tab="vulnerabilities"|data-tab="sca"|data-tab="fim"/);
  assert.doesNotMatch(markup(html), /Unavailable\)/, 'aucun onglet decoratif marque indisponible');
  // Aucun compteur de vulnerabilites tant que rien ne les interroge : une
  // invitation a configurer la source est permise, un chiffre ne l est pas.
  assert.doesNotMatch(markup(html), /Total records|Affected assets|<h3>Vulnerabilities<\/h3>/);
});

test('5A : la navigation route vers la section demandee', () => {
  for (const [tab, heading] of [['alerts', '<h3>Alerts</h3>'], ['assets', '<h3>Assets</h3>'], ['mitre', 'MITRE ATT&amp;CK']]) {
    const html = renderRuntimeSecurityPageHtml({ runtime: connectedRuntime(), tab }, 'n', 'light');
    assert.equal(activeTab(html), tab);
    assert.ok(markup(html).includes(heading), `${tab} doit rendre sa section`);
  }
  // L apercu reste la section par defaut et garde ses raccourcis.
  const overview = markup(renderRuntimeSecurityPageHtml({ runtime: connectedRuntime(), tab: 'overview' }, 'n', 'light'));
  assert.match(overview, /<h3>Alert summary<\/h3>/);
  assert.match(overview, /<h3>Recent alerts<\/h3>/);
});

test('5A : l apercu limite ses listes et renvoie vers la section complete', () => {
  const runtime = connectedRuntime({
    agents: Array.from({ length: 9 }, (unused, index) => ({ name: `host-${index}`, os: 'Linux', status: 'active', ip: `10.0.0.${index}`, lastSeen: 'now' })),
    alerts: Array.from({ length: 9 }, (unused, index) => ({ severity: 'HIGH', title: `alert-${index}`, host: 'host-0', ruleId: String(1000 + index), mitreTechniques: [], timestamp: '2026-08-20T09:00:00Z' }))
  });
  const overview = markup(renderRuntimeSecurityPageHtml({ runtime }, 'n', 'light'));
  assert.equal((overview.match(/class="asset-row"/g) || []).length, 5);
  assert.equal((overview.match(/data-alert-index="\d+"[^>]*>/g) || []).length > 0, true);
  assert.equal((overview.match(/class="alert-row [a-z]+"/g) || []).length, 5);
  assert.match(overview, /data-tab="assets">View all/);
  assert.match(overview, /data-tab="alerts">View all/);

  // La section complete, elle, ne tronque rien.
  const assets = markup(renderRuntimeSecurityPageHtml({ runtime, tab: 'assets' }, 'n', 'light'));
  assert.equal((assets.match(/class="asset-row"/g) || []).length, 9);
});

test('5A : MITRE agrege les techniques des regles, sans rien inferer', () => {
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: connectedRuntime(), tab: 'mitre' }, 'n', 'light'));
  // T1110 porte deux alertes, T1548 une seule ; l ordre suit le nombre.
  const techniques = [...html.matchAll(/<article class="mitre-row">\s*<span[^>]*>(T\d+)</g)].map((match) => match[1]);
  assert.deepEqual(techniques, ['T1110', 'T1548']);
  assert.match(html, /2 alerts/);
  assert.match(html, /1 alert</);
  // Les techniques viennent des alertes normalisees : aucune source alternative.
  const pages = fs.readFileSync(path.join(repoRoot, 'src', 'enterprise-domain-pages.js'), 'utf8');
  const extractor = pages.match(/function mitreTechniques\(runtime\)[\s\S]*?\n}/)[0];
  assert.match(extractor, /alert\.mitreTechniques/);
  assert.doesNotMatch(extractor, /cve|package|title/i);
});

test('5A : une capacite en erreur degrade sa seule section, pas le domaine', () => {
  const runtime = connectedRuntime({ status: RUNTIME_STATUS.AUTH_ERROR, message: 'Authentication failed', alerts: [], agents: [], alertSummary: { critical: 0, high: 0, medium: 0, low: 0 }, agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 } });
  const html = renderRuntimeSecurityPageHtml({ runtime, capabilityEvidence: { alerts: { state: 'error' }, mitre: { state: 'error' } } }, 'n', 'light');
  // La navigation survit : les autres sections restent accessibles.
  assert.deepEqual(tabIds(html), ['overview', 'alerts', 'assets', 'mitre']);
  const overview = markup(html);
  // L absence de donnee n est pas un zero : aucun compteur n est affiche.
  assert.doesNotMatch(overview, /<span>Critical<\/span><strong>0<\/strong>/);
  assert.match(overview, /Alert counts could not be read from the provider|Authentication failed/);
  // Et l etat par capacite est lisible, capacite par capacite.
  assert.match(overview, /class="capability-row"/);
  assert.match(overview, /Wazuh API/);
});

test('5A : la sante par capacite ne liste jamais une capacite non offerte', () => {
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: connectedRuntime() }, 'n', 'light'));
  const rows = [...html.matchAll(/class="capability-row"><span>([^<]+)<\/span><em[^>]*>([^<]+)</g)]
    .map((match) => `${match[1]}=${match[2]}`);
  assert.deepEqual(rows, ['Wazuh API=Online', 'Alerts=Available', 'Assets=Available', 'MITRE=Available']);
});

test('5A : la page non configuree n affiche aucune navigation de capacite', () => {
  const html = renderRuntimeSecurityPageHtml({}, 'n', 'light');
  assert.deepEqual(tabIds(html), []);
  assert.match(html, /Connect your SIEM/);
});

test('5A : l entete porte le fournisseur, l etat, la derniere synchro et les actions', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: connectedRuntime() }, 'n', 'light');
  assert.match(html, /Provider: Wazuh/);
  assert.match(html, /class="domain-hero-meta">Last sync:/);
  assert.match(html, /data-action="refreshRuntime"/);
  assert.match(html, /data-action="showConfig">Settings/);
});

test('5A : la navigation utilise le meme contrat de message que la page Pipeline', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: connectedRuntime() }, 'n', 'light');
  assert.match(html, /postMessage\(\{type:'tab',tab:b\.dataset\.tab\}\)/);
  const extension = fs.readFileSync(path.join(repoRoot, 'src', 'extension.js'), 'utf8');
  const handler = extension.match(/async function openRuntimeSecurityPage\([\s\S]*?\n  \}/)[0];
  assert.match(handler, /message\?\.type === 'tab'/);
  assert.match(handler, /runtimeTab = String\(message\.tab \|\| 'overview'\)/);
});

test('5A : aucune requete fournisseur n a ete ajoutee', () => {
  // Phase 5A est une phase de navigation : l adaptateur Wazuh interroge encore
  // exactement les memes points d entree qu avant.
  const adapter = fs.readFileSync(path.join(repoRoot, 'src', 'integrations', 'siem-wazuh.js'), 'utf8');
  // Authentification + /manager/info + /agents : les trois seules routes de
  // gestion que cette API expose reellement.
  assert.equal((adapter.match(/joinUrl\(/g) || []).length, 3, 'les memes trois appels Manager API');
  // Les champs Indexer sont declares, mais rien ne les lit encore.
  const reader = adapter.match(/async function fetchStatus\([\s\S]*?\n}/)[0];
  assert.doesNotMatch(reader, /indexerUrl|indexerUsername|indexerPassword/);
});
