'use strict';

/**
 * Phase 7 — Runtime Security alerts: search, filters, bounded pages, and the
 * two levels of detail (inline preview, full investigation).
 *
 * The rule under test throughout is that nothing is invented: every filter
 * option, every fact and every count comes from an alert the provider actually
 * returned.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  alertEndpoint, alertDescription, alertKey, normalizeAlertQuery, isFiltered,
  alertFacets, filterAlerts, paginateAlerts, findAlert, alertDetailFields, DEFAULT_PAGE_SIZE
} = require('../src/integrations/siem-alerts');
const { renderRuntimeSecurityPageHtml: renderRuntimePage } = require('../src/enterprise-domain-pages');
// Depuis que l'historique d'alertes vient du moteur de recherche du
// fournisseur et non de son API de gestion, la page a besoin de la preuve
// d'execution qu'une sonde reussie fournit. Les tests qui examinent un etat
// degrade passent la leur et gagnent.
const READY_EVIDENCE = Object.freeze({ alerts: { state: 'ready' }, mitre: { state: 'ready' } });
function renderRuntimeSecurityPageHtml(model = {}, nonce = '', theme = 'light') {
  return renderRuntimePage({ capabilityEvidence: READY_EVIDENCE, ...model }, nonce, theme);
}

const { RUNTIME_STATUS } = require('../src/integrations/siem');
const { normalizeAlert } = require('../src/integrations/siem-contract');

const repoRoot = path.join(__dirname, '..');

function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

function alert(overrides = {}) {
  return {
    id: 'alert-1',
    timestamp: '2026-08-20T09:01:00Z',
    severity: 'CRITICAL',
    title: 'SSH brute-force attempt',
    description: 'Authentication failures exceeded the normalized threshold.',
    ruleId: '5710',
    source: 'wazuh',
    endpoint: 'ubuntu-runtime',
    user: 'root',
    mitreTechniques: ['T1110'],
    rawReference: 'wazuh:1234',
    status: 'open',
    ...overrides
  };
}

function runtime(alerts, overrides = {}) {
  return {
    configured: true,
    provider: 'wazuh',
    label: 'Wazuh',
    status: RUNTIME_STATUS.ONLINE,
    credentialsConfigured: true,
    lastChecked: new Date().toISOString(),
    agents: [],
    agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
    alertSummary: { critical: 1, high: 0, medium: 0, low: 0 },
    alerts,
    ...overrides
  };
}

function manyAlerts(count) {
  return Array.from({ length: count }, (unused, index) => alert({
    id: `alert-${index}`,
    severity: ['CRITICAL', 'HIGH', 'LOW'][index % 3],
    title: `Detection ${index}`,
    ruleId: String(5700 + (index % 4)),
    endpoint: `host-${index % 3}`,
    timestamp: `2026-08-20T09:${String(index % 60).padStart(2, '0')}:00Z`
  }));
}

// ---------------------------------------------------------------------------
// Field reading
// ---------------------------------------------------------------------------

test('7 : les alertes normalisees du fournisseur sont lues avec les bons noms de champs', () => {
  // Le modele normalise dit `endpoint` / `description` ; les anciennes fixtures
  // disent `host` / `summary`. Les deux doivent s afficher.
  const normalized = normalizeAlert({ endpoint: 'ubuntu-runtime', description: 'real body', severity: 'CRITICAL' }, { source: 'wazuh' });
  assert.equal(alertEndpoint(normalized), 'ubuntu-runtime');
  assert.equal(alertDescription(normalized), 'real body');
  assert.equal(alertEndpoint({ host: 'legacy-host' }), 'legacy-host');
  assert.equal(alertDescription({ summary: 'legacy body' }), 'legacy body');

  // Et la page affiche l asset reel plutot que « Unknown host ».
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime([normalized]), tab: 'alerts' }, 'n', 'light'));
  assert.match(html, /ubuntu-runtime/);
  assert.doesNotMatch(html, /Unknown host/);
});

test('7 : une alerte garde une identite stable, meme sans id fournisseur', () => {
  assert.equal(alertKey(alert()), 'alert-1');
  assert.equal(alertKey(alert({ id: '' })), 'wazuh:1234');
  assert.equal(alertKey({ ruleId: '5710', timestamp: 'T' }, 3), '5710:T');
  assert.equal(alertKey({}, 4), 'rule:4');
});

// ---------------------------------------------------------------------------
// Filtres
// ---------------------------------------------------------------------------

test('7 : les options de filtre viennent uniquement des alertes retournees', () => {
  const facets = alertFacets([
    alert({ severity: 'CRITICAL', endpoint: 'a', ruleId: '1' }),
    alert({ severity: 'LOW', endpoint: 'b', ruleId: '2' }),
    alert({ severity: 'LOW', endpoint: 'b', ruleId: '2' }),
    alert({ severity: 'HIGH', endpoint: '', ruleId: '' })
  ]);
  assert.deepEqual(facets.severities, [
    { value: 'CRITICAL', count: 1 }, { value: 'HIGH', count: 1 }, { value: 'LOW', count: 2 }
  ]);
  assert.deepEqual(facets.agents, [{ value: 'a', count: 1 }, { value: 'b', count: 2 }]);
  assert.deepEqual(facets.rules, [{ value: '1', count: 1 }, { value: '2', count: 2 }]);
  // Un champ vide n ouvre pas une option vide.
  assert.equal(facets.agents.some((entry) => entry.value === ''), false);
});

test('7 : la recherche porte sur ce qu un humain lit, pas sur des identifiants caches', () => {
  const alerts = [alert(), alert({ id: 'other', title: 'Sudo misuse', description: '', ruleId: '5402', endpoint: 'api', user: '', mitreTechniques: [], rawReference: 'wazuh:9999' })];
  assert.equal(filterAlerts(alerts, { search: 'brute-force' }).length, 1);
  assert.equal(filterAlerts(alerts, { search: 'THRESHOLD' }).length, 1, 'insensible a la casse');
  assert.equal(filterAlerts(alerts, { search: '5402' }).length, 1);
  assert.equal(filterAlerts(alerts, { search: 'T1110' }).length, 1);
  assert.equal(filterAlerts(alerts, { search: 'api' }).length, 1);
  // L identifiant brut n est pas une surface de recherche.
  assert.equal(filterAlerts(alerts, { search: 'wazuh:9999' }).length, 0);
});

test('7 : severite, agent et regle se combinent', () => {
  const alerts = [
    alert({ id: '1', severity: 'CRITICAL', endpoint: 'a', ruleId: '10' }),
    alert({ id: '2', severity: 'CRITICAL', endpoint: 'b', ruleId: '10' }),
    alert({ id: '3', severity: 'LOW', endpoint: 'a', ruleId: '11' })
  ];
  assert.deepEqual(filterAlerts(alerts, { severity: 'CRITICAL' }).map((item) => item.id), ['1', '2']);
  assert.deepEqual(filterAlerts(alerts, { agent: 'a' }).map((item) => item.id), ['1', '3']);
  assert.deepEqual(filterAlerts(alerts, { severity: 'CRITICAL', agent: 'a' }).map((item) => item.id), ['1']);
  assert.deepEqual(filterAlerts(alerts, { rule: '11' }).map((item) => item.id), ['3']);
  // Une requete vide ne filtre rien.
  assert.equal(filterAlerts(alerts, {}).length, 3);
  assert.equal(isFiltered({}), false);
  assert.equal(isFiltered({ agent: 'a' }), true);
});

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

test('7 : la pagination borne la liste et se recale sur une page perimee', () => {
  const alerts = manyAlerts(23);
  const first = paginateAlerts(alerts, { page: 1 });
  assert.equal(first.items.length, DEFAULT_PAGE_SIZE);
  assert.deepEqual([first.from, first.to, first.total, first.pageCount], [1, 10, 23, 3]);

  const last = paginateAlerts(alerts, { page: 3 });
  assert.equal(last.items.length, 3);
  assert.deepEqual([last.from, last.to], [21, 23]);

  // Une page hors bornes — un filtre venant de reduire le jeu — se recale.
  assert.equal(paginateAlerts(alerts, { page: 99 }).page, 3);
  assert.equal(paginateAlerts(alerts, { page: -4 }).page, 1);
  assert.equal(paginateAlerts([], { page: 2 }).page, 1);
  assert.deepEqual(paginateAlerts([], {}).items, []);
  assert.equal(paginateAlerts([], {}).from, 0);
});

test('7 : la requete est toujours complete, quoi qu envoie la webview', () => {
  assert.deepEqual(normalizeAlertQuery(), { search: '', severity: '', agent: '', rule: '', page: 1, alert: '' });
  assert.deepEqual(normalizeAlertQuery({ severity: 'critical', page: '2', search: '  ssh  ' }),
    { search: 'ssh', severity: 'CRITICAL', agent: '', rule: '', page: 2, alert: '' });
  assert.equal(normalizeAlertQuery({ page: 'abc' }).page, 1);
});

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

test('7 : le detail n expose que les champs reellement fournis', () => {
  const complete = alertDetailFields(alert(), { label: 'Wazuh' }).map((field) => field.label);
  assert.deepEqual(complete, ['Severity', 'Status', 'Detected at', 'Provider', 'Rule ID', 'Agent / asset', 'User', 'MITRE techniques', 'Raw reference']);

  // Ce que le fournisseur n a pas envoye est absent — pas un « Unavailable »,
  // pas une valeur reconstruite.
  const sparse = alertDetailFields(alert({ user: '', mitreTechniques: [], rawReference: '', ruleId: '' }), { label: 'Wazuh' });
  const labels = sparse.map((field) => field.label);
  assert.equal(labels.includes('User'), false);
  assert.equal(labels.includes('MITRE techniques'), false);
  assert.equal(labels.includes('Raw reference'), false);
  assert.equal(labels.includes('Rule ID'), false);
  assert.equal(sparse.every((field) => field.value && field.value !== 'Unavailable'), true);
});

test('7 : la vue d investigation remplace la liste et sait revenir', () => {
  const alerts = manyAlerts(12);
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(alerts), tab: 'alerts', alertsQuery: { alert: 'alert-4' } }, 'n', 'light'));
  assert.match(html, /Detection 4/);
  assert.match(html, /Alert investigation · Wazuh/);
  assert.match(html, /data-alert-open=""/, 'un retour explicite vers la liste');
  // Une destination, pas une surcouche : la liste et sa barre de filtres cedent la place.
  assert.doesNotMatch(html, /alerts-toolbar/);
  assert.doesNotMatch(html, /data-alerts-page/);

  // Une alerte inconnue ne bloque pas la section : on retombe sur la liste.
  const missing = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(alerts), tab: 'alerts', alertsQuery: { alert: 'nope' } }, 'n', 'light'));
  assert.match(missing, /alerts-toolbar/);
});

test('7 : l apercu rapide reste disponible a cote de l investigation', () => {
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime([alert()]), tab: 'alerts' }, 'n', 'light'));
  // Deux routes depuis une ligne : l apercu inline (index) et l investigation (cle).
  assert.match(html, /data-alert-index="0" aria-label="Preview runtime alert"/);
  assert.match(html, /data-alert-open="alert-1">Investigate/);
  assert.match(html, /class="alert-detail" data-alert-detail="0" hidden/);
});

// ---------------------------------------------------------------------------
// Rendu de la section
// ---------------------------------------------------------------------------

test('7 : la section Alerts rend la barre de filtres, le compte et la pagination', () => {
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(manyAlerts(23)), tab: 'alerts' }, 'n', 'light'));
  assert.equal((html.match(/class="alert-row/g) || []).length, DEFAULT_PAGE_SIZE);
  assert.match(html, /Showing 1–10 of 23 alerts returned by Wazuh at the last refresh\./);
  assert.match(html, /id="alerts-search"/);
  assert.match(html, /id="alerts-severity"/);
  assert.match(html, /id="alerts-agent"/);
  assert.match(html, /id="alerts-rule"/);
  assert.match(html, /data-alerts-page="2"/);
  assert.match(html, /Page 1 of 3/);

  const page3 = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(manyAlerts(23)), tab: 'alerts', alertsQuery: { page: 3 } }, 'n', 'light'));
  assert.equal((page3.match(/class="alert-row/g) || []).length, 3);
  assert.match(page3, /Showing 21–23 of 23/);
  assert.match(page3, /data-alerts-page="4" disabled|data-alerts-page="4"[^>]*disabled/);
});

test('7 : une seule alerte ne declenche pas de pagination', () => {
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime([alert()]), tab: 'alerts' }, 'n', 'light'));
  assert.doesNotMatch(html, /data-alerts-page/);
  assert.match(html, /Showing 1–1 of 1 alert returned by Wazuh/);
});

test('7 : vide par filtre et vide par fournisseur ne disent pas la meme chose', () => {
  const filteredOut = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(manyAlerts(5)), tab: 'alerts', alertsQuery: { search: 'inexistant' } }, 'n', 'light'));
  assert.match(filteredOut, /No alert matches these filters\./);
  assert.doesNotMatch(filteredOut, /No recent runtime alerts returned by the SIEM provider\./);

  const nothingReturned = markup(renderRuntimeSecurityPageHtml({ runtime: runtime([]), tab: 'alerts' }, 'n', 'light'));
  assert.match(nothingReturned, /No recent runtime alerts returned by the SIEM provider\./);
  assert.doesNotMatch(nothingReturned, /No alert matches these filters\./);
});

test('7 : une capacite alertes en erreur ne montre aucun compteur invente', () => {
  const broken = runtime([], { status: RUNTIME_STATUS.AUTH_ERROR, message: 'Authentication failed', alertSummary: { critical: 0, high: 0, medium: 0, low: 0 } });
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: broken, tab: 'alerts', capabilityEvidence: { alerts: { state: 'error' }, mitre: { state: 'error' } }
  }, 'n', 'light'));
  assert.doesNotMatch(html, /<span>Critical<\/span><strong>0<\/strong>/);
  assert.match(html, /Authentication failed|Alert counts could not be read/);
  // La section reste navigable : la barre de filtres et l etat vide subsistent.
  assert.match(html, /No recent runtime alerts returned by the SIEM provider\./);
});

test('7 : la barre de filtres n offre que ce que le fournisseur a renvoye', () => {
  // Aucune alerte ne porte d utilisateur ni de regle : aucun filtre correspondant.
  const bare = [alert({ ruleId: '', endpoint: '', user: '', mitreTechniques: [] })];
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(bare), tab: 'alerts' }, 'n', 'light'));
  assert.match(html, /id="alerts-severity"/);
  assert.doesNotMatch(html, /id="alerts-agent"/);
  assert.doesNotMatch(html, /id="alerts-rule"/);
});

// ---------------------------------------------------------------------------
// Contrat avec l extension
// ---------------------------------------------------------------------------

test('7 : la requete d alertes suit le meme contrat de message que les onglets', () => {
  const html = renderRuntimeSecurityPageHtml({ runtime: runtime(manyAlerts(23)), tab: 'alerts' }, 'n', 'light');
  assert.match(html, /postMessage\(\{type:'alerts',query:/);
  const extension = fs.readFileSync(path.join(repoRoot, 'src', 'extension.js'), 'utf8');
  const handler = extension.match(/async function openRuntimeSecurityPage\([\s\S]*?\n  \}/)[0];
  assert.match(handler, /message\?\.type === 'alerts'/);
  assert.match(handler, /runtimeAlertsQuery = \{/);
  // Changer de section ferme l investigation en cours.
  assert.match(handler, /runtimeAlertsQuery = \{ \.\.\.runtimeAlertsQuery, alert: '' \}/);
});

test('7 : aucune requete fournisseur n a ete ajoutee pour les alertes', () => {
  const adapter = fs.readFileSync(path.join(repoRoot, 'src', 'integrations', 'siem-wazuh.js'), 'utf8');
  // L API de gestion n a jamais servi d historique d alertes : trois routes.
  assert.equal((adapter.match(/joinUrl\(/g) || []).length, 3, 'les memes trois appels Manager API');
  // Le filtrage et la pagination travaillent sur ce que l adaptateur a deja rendu.
  const alertsModule = fs.readFileSync(path.join(repoRoot, 'src', 'integrations', 'siem-alerts.js'), 'utf8');
  assert.doesNotMatch(alertsModule, /require\('\.\/http'\)|requestJson|joinUrl|fetch\(/);
});

test('7 : ni les vulnerabilites ni la correlation n ont bouge', () => {
  const pages = fs.readFileSync(path.join(repoRoot, 'src', 'enterprise-domain-pages.js'), 'utf8');
  // La page ne depend d aucun module de correlation ni d aucune lecture Indexer :
  // le libelle « Advanced — Indexer » du formulaire reste de la configuration.
  assert.doesNotMatch(pages, /require\('\.\/(intelligence|correlation)/);
  assert.doesNotMatch(pages, /indexerUrl|_search|wazuh-states/);
  const html = markup(renderRuntimeSecurityPageHtml({ runtime: runtime(manyAlerts(3)), tab: 'alerts' }, 'n', 'light'));
  // Aucune section vulnerabilites n a ete ouverte : seul le champ de
  // configuration Indexer, deja present, en parle.
  assert.doesNotMatch(html, /data-tab="vulnerabilities"/);
  assert.doesNotMatch(html, /<h3>Vulnerabilities<\/h3>/);
});
