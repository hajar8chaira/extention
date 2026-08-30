'use strict';

/**
 * Capability evidence is per capability, and who decides it is the adapter.
 *
 * Two defects are pinned here. The first was live: refreshing vulnerabilities
 * replaced the evidence object wholesale, erasing the alert and MITRE evidence
 * gathered moments earlier — so both sections vanished after every refresh. The
 * second was quieter: generic orchestration knew that « MITRE follows alerts »,
 * which is true of Wazuh and of nothing else.
 *
 * The recorder below is the extension's merge rule, exercised in isolation from
 * VS Code. Its shape is asserted against the real source so the two cannot
 * drift apart.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { wazuhAdapter } = require('../src/integrations/siem-wazuh');
const { SIEM_PROVIDERS, siemAdapter } = require('../src/integrations/siem');
const { resolveRuntimeCapabilities, runtimeCapabilityTabs, RUNTIME_CAPABILITY_STATE } = require('../src/integrations/siem-navigation');
const { CAPABILITY } = require('../src/integrations/siem-contract');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

/** The merge rule as the extension implements it, adapter-driven throughout. */
function createEvidenceRecorder(adapter) {
  let evidence = {};
  return {
    record(fetcherName, state) {
      const backed = adapter?.capabilityFetchers?.[fetcherName];
      const capabilities = Array.isArray(backed) && backed.length ? backed : [];
      const next = { ...evidence };
      for (const capability of capabilities) {
        if (state) next[capability] = { state };
        else delete next[capability];
      }
      evidence = next;
      return evidence;
    },
    get current() { return evidence; }
  };
}

// ---------------------------------------------------------------------------
// The merge rule
// ---------------------------------------------------------------------------

test('isolation : rafraichir les vulnerabilites n efface pas les alertes ni MITRE', () => {
  const recorder = createEvidenceRecorder(wazuhAdapter);
  recorder.record('fetchAlerts', 'ready');
  recorder.record('fetchVulnerabilities', 'error');

  assert.deepEqual(recorder.current, {
    alerts: { state: 'ready' },
    mitre: { state: 'ready' },
    vulnerabilities: { state: 'error' }
  });
});

test('isolation : rafraichir les alertes n efface pas les vulnerabilites', () => {
  const recorder = createEvidenceRecorder(wazuhAdapter);
  recorder.record('fetchVulnerabilities', 'ready');
  recorder.record('fetchAlerts', 'error');

  assert.deepEqual(recorder.current, {
    vulnerabilities: { state: 'ready' },
    alerts: { state: 'error' },
    mitre: { state: 'error' }
  });
});

test('isolation : un rafraichissement repete ne perd rien en chemin', () => {
  const recorder = createEvidenceRecorder(wazuhAdapter);
  for (let round = 0; round < 3; round += 1) {
    recorder.record('fetchAlerts', 'ready');
    recorder.record('fetchVulnerabilities', 'ready');
  }
  assert.deepEqual(Object.keys(recorder.current).sort(), ['alerts', 'mitre', 'vulnerabilities']);
});

test('isolation : un fetcher absent ne retire que ses propres capacites', () => {
  const recorder = createEvidenceRecorder(wazuhAdapter);
  recorder.record('fetchAlerts', 'ready');
  recorder.record('fetchVulnerabilities', 'ready');
  // L adaptateur ne sert plus les vulnerabilites : elles seules disparaissent.
  recorder.record('fetchVulnerabilities', '');
  assert.deepEqual(Object.keys(recorder.current).sort(), ['alerts', 'mitre']);
  assert.equal(recorder.current.vulnerabilities, undefined);
});

test('isolation : un fetcher inconnu de l adaptateur ne touche rien', () => {
  const recorder = createEvidenceRecorder(wazuhAdapter);
  recorder.record('fetchAlerts', 'ready');
  recorder.record('fetchSomethingElse', 'error');
  assert.deepEqual(Object.keys(recorder.current).sort(), ['alerts', 'mitre']);
});

// ---------------------------------------------------------------------------
// The relationship is the adapter's, not the orchestrator's
// ---------------------------------------------------------------------------

test('isolation : la relation « MITRE suit les alertes » est declaree par l adaptateur', () => {
  assert.deepEqual(wazuhAdapter.capabilityFetchers.fetchAlerts, ['alerts', 'mitre']);
  assert.deepEqual(wazuhAdapter.capabilityFetchers.fetchVulnerabilities, ['vulnerabilities']);

  // Un autre adaptateur peut declarer tout autre chose, sans toucher au generique.
  const elsewhere = createEvidenceRecorder({
    capabilityFetchers: { fetchAlerts: ['alerts'], fetchIncidents: ['incidents', 'mitre'] }
  });
  elsewhere.record('fetchAlerts', 'error');
  elsewhere.record('fetchIncidents', 'ready');
  assert.deepEqual(elsewhere.current, {
    alerts: { state: 'error' }, incidents: { state: 'ready' }, mitre: { state: 'ready' }
  });
});

test('isolation : l orchestration generique ne cable aucune relation', () => {
  const extension = source('src/extension.js');
  const alerts = extension.match(/async function refreshRuntimeAlerts\(\)[\s\S]*?\n  \}/)[0];
  const vulnerabilities = extension.match(/async function refreshRuntimeVulnerabilities\(\)[\s\S]*?\n  \}/)[0];

  for (const fn of [alerts, vulnerabilities]) {
    // Plus aucune affectation globale : c est ce qui effacait les autres.
    assert.doesNotMatch(fn, /runtimeCapabilityEvidence\s*=/);
    assert.match(fn, /recordCapabilityEvidence\(adapter, '/);
    // Et plus aucune capacite ecrite en dur comme consequence d une autre :
    // la normalisation des techniques reste une mise en forme de donnees.
    assert.doesNotMatch(fn, /mitre\s*:/i);
    assert.doesNotMatch(fn, /alerts:\s*\{ state/);
  }
  // Le seul endroit qui ecrit la preuve la fusionne, capacite par capacite.
  const recorder = extension.match(/function recordCapabilityEvidence\([\s\S]*?\n  \}/)[0];
  assert.match(recorder, /adapter\?\.capabilityFetchers\?\.\[fetcherName\]/);
  assert.match(recorder, /\{ \.\.\.runtimeCapabilityEvidence \}/);
});

test('isolation : Manager et Indexer gardent des frontieres distinctes', () => {
  // Une panne Indexer laisse intact ce que l API de gestion sert.
  const resolved = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'online' }, {
    alerts: { state: 'error' }, mitre: { state: 'error' }, vulnerabilities: { state: 'error' }
  });
  assert.equal(resolved[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.READY);
  assert.equal(resolved[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.deepEqual(runtimeCapabilityTabs(resolved).map((tab) => tab.id), ['overview', 'alerts', 'assets', 'mitre', 'vulnerabilities']);

  // Et l inverse : une panne de l API de gestion ne touche pas ce qu un autre
  // service a prouve.
  const managerDown = resolveRuntimeCapabilities(wazuhAdapter, { configured: true, status: 'auth-error' }, {
    alerts: { state: 'ready' }, mitre: { state: 'ready' }
  });
  assert.equal(managerDown[CAPABILITY.ASSETS], RUNTIME_CAPABILITY_STATE.ERROR);
  assert.equal(managerDown[CAPABILITY.ALERTS], RUNTIME_CAPABILITY_STATE.READY);
});

// ---------------------------------------------------------------------------
// The catalogue promises nothing it cannot keep
// ---------------------------------------------------------------------------

test('isolation : un fournisseur sans adaptateur n expose ni schema ni capacite', () => {
  const unimplemented = SIEM_PROVIDERS.filter((provider) => !provider.implemented);
  // Le catalogue reste multi-SIEM et garde des entrees non implementees : c est
  // sur celles-la que porte l invariant. Leur nombre baisse a chaque adaptateur
  // ecrit, donc on ne le fige pas.
  assert.ok(SIEM_PROVIDERS.length >= 8, 'le catalogue reste multi-SIEM');
  assert.ok(unimplemented.length > 0, 'il reste des fournisseurs sans adaptateur');
  for (const provider of unimplemented) {
    assert.equal(siemAdapter(provider.id), null, `${provider.id} n a pas d adaptateur`);
    assert.deepEqual(provider.configurationFields, [], `${provider.id} : aucun champ invente`);
    assert.deepEqual(provider.supportedCapabilities, [], `${provider.id} : aucune capacite inventee`);
    assert.equal(provider.status, 'available');
    assert.ok(provider.label && provider.summary, `${provider.id} garde son identite`);
  }
  // « Custom SIEM » promettait un moteur de correspondance generique inexistant.
  assert.equal(SIEM_PROVIDERS.some((provider) => provider.id === 'custom'), false);
});

test('isolation : le catalogue ne declare aucun point d entree ni aucune authentification', () => {
  // Le code, pas l en-tete de documentation qui explique justement pourquoi.
  const catalogue = source('src/integrations/siem-catalogue.js');
  const code = catalogue.slice(catalogue.indexOf('const SIEM_CATALOGUE')).split('\n')
    .map((line) => line.replace(/\/\/.*$/, ''))
    .join('\n');
  assert.doesNotMatch(code, /configurationFields|capabilities|https?:\/\/|token|apiKey|clientSecret|accessKey/i);
  // Rien que de l identite.
  const { SIEM_CATALOGUE } = require('../src/integrations/siem-catalogue');
  for (const entry of SIEM_CATALOGUE) {
    assert.deepEqual(Object.keys(entry).sort().filter((key) => !['docsHint'].includes(key)), ['icon', 'id', 'label', 'summary']);
  }
});

test('isolation : un fournisseur sans adaptateur n offre aucune action', () => {
  for (const provider of SIEM_PROVIDERS.filter((entry) => !entry.implemented)) {
    const html = renderRuntimeSecurityPageHtml({
      runtime: { configured: false, provider: provider.id, label: provider.label }
    }, 'n', 'light');
    const markup = html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
    assert.doesNotMatch(markup, /data-action="testRuntimeConfig"/, provider.id);
    assert.doesNotMatch(markup, /data-action="saveRuntimeConfig"/, provider.id);
    assert.ok(markup.includes(`Security Center does not integrate ${provider.label} yet.`));
    // Aucun champ, donc rien a saisir ni a enregistrer.
    assert.doesNotMatch(markup, /id="runtime-(?!provider)[a-zA-Z]+"/, provider.id);
  }
  // Aucun badge : les deux catalogues restent visuellement neutres.
  const html = renderRuntimeSecurityPageHtml({ runtime: { configured: false } }, 'n', 'light');
  const markup = html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
  assert.doesNotMatch(markup, /provider-badge|Coming later|Supported</);
});
