'use strict';

/**
 * Wazuh Manager TLS — an option of its own.
 *
 * Two connections, two certificates, two decisions. A deployment can trust one
 * and not the other in either direction, so the two booleans never read each
 * other and neither one has a default that relaxes anything.
 *
 * Every value below is invented; nothing here knows a real deployment.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { wazuhAdapter } = require('../src/integrations/siem-wazuh');
const { renderRuntimeSecurityPageHtml } = require('../src/enterprise-domain-pages');
const { buildRuntimeSecurityModel, CONFIG_GROUP, fieldsInGroup } = require('../src/integrations/siem-contract');
const { isCertificateError, IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

const FICTIONAL = Object.freeze({
  managerUrl: 'https://manager.example.invalid:55000',
  managerUsername: 'manager-account',
  managerPassword: 'manager-fixture-secret',
  indexerUrl: 'https://indexer.example.invalid:9200',
  indexerUsername: 'indexer-account',
  indexerPassword: 'indexer-fixture-secret'
});

const MANAGER_SECRETS = { password: FICTIONAL.managerPassword };

/** Records every request the adapter makes, and what transport options it used. */
function recorder(responses = []) {
  const calls = [];
  const queue = [...responses];
  const request = async (target, options = {}) => {
    calls.push({ target, options });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return next || {};
  };
  const requestTextImpl = async (target, options = {}) => {
    calls.push({ target, options, text: true });
    return JSON.stringify({ data: { token: 'fixture-jwt' } });
  };
  return { calls, request, requestTextImpl };
}

function managerConfig(extra = {}) {
  return { url: FICTIONAL.managerUrl, username: FICTIONAL.managerUsername, ...extra };
}

async function fetchWith(config, options = {}) {
  const io = recorder([{ data: { affected_items: [] } }]);
  const model = await wazuhAdapter.fetchStatus(config, MANAGER_SECRETS, {
    request: io.request, requestTextImpl: io.requestTextImpl, ...options
  });
  return { ...io, model };
}

// ---------------------------------------------------------------------------
// The option itself
// ---------------------------------------------------------------------------

test('TLS Manager : l option existe dans le schema, dans le groupe principal', () => {
  const field = wazuhAdapter.configurationFields.find((entry) => entry.id === 'allowSelfSigned');
  assert.ok(field, 'le schema du fournisseur declare l option Manager');
  assert.equal(field.type, 'boolean');
  assert.equal(field.required, undefined);
  assert.equal(field.secret, undefined);
  // Manager dans le groupe principal, Indexer dans le groupe avance.
  assert.ok(fieldsInGroup(wazuhAdapter.configurationFields, CONFIG_GROUP.PRIMARY).some((entry) => entry.id === 'allowSelfSigned'));
  assert.ok(fieldsInGroup(wazuhAdapter.configurationFields, CONFIG_GROUP.ADVANCED).some((entry) => entry.id === 'indexerAllowSelfSigned'));
  // Deux booleens distincts : aucun interrupteur global.
  const booleans = wazuhAdapter.configurationFields.filter((entry) => entry.type === 'boolean').map((entry) => entry.id);
  assert.deepEqual(booleans.sort(), ['allowSelfSigned', 'indexerAllowSelfSigned']);
  // Le libelle n affirme rien sur la securite de l option.
  assert.match(field.hint, /Off by default/);
  assert.doesNotMatch(field.hint, /secure|safe/i);
});

test('TLS Manager : par defaut, aucune option TLS n accompagne les requetes', async () => {
  const { calls } = await fetchWith(managerConfig());
  assert.ok(calls.length > 0);
  for (const call of calls) {
    assert.equal(call.options.tls, undefined, 'le chemin strict reste exactement ce qu il etait');
  }
});

test('TLS Manager : une configuration enregistree sans le champ reste stricte', async () => {
  // Exactement la forme d une configuration d avant cette option.
  const { calls } = await fetchWith({ url: FICTIONAL.managerUrl, username: FICTIONAL.managerUsername });
  for (const call of calls) assert.equal(call.options.tls, undefined);
});

test('TLS Manager : seul un vrai booleen vaut consentement', async () => {
  for (const value of ['true', 1, 'yes', 'on', {}, [], 'false']) {
    const { calls } = await fetchWith(managerConfig({ allowSelfSigned: value }));
    for (const call of calls) {
      assert.equal(call.options.tls, undefined, `${JSON.stringify(value)} ne doit pas relacher TLS`);
    }
  }
});

test('TLS Manager : active, la relaxation accompagne chaque appel Manager', async () => {
  const { calls, model } = await fetchWith(managerConfig({ allowSelfSigned: true }));
  // Authentification + /manager/info + /agents : les routes que cette API a.
  assert.equal(calls.length, 3, 'ni plus ni moins de requetes de gestion');
  for (const call of calls) {
    assert.deepEqual(call.options.tls, { allowSelfSigned: true }, `${call.target} doit porter l option`);
  }
  const targets = calls.map((call) => call.target).join(' ');
  for (const route of ['/security/user/authenticate', '/manager/info', '/agents']) {
    assert.ok(targets.includes(route), `${route} doit rester appele`);
  }
  // Le modele le declare, la page n a rien a deviner.
  assert.equal(model.relaxedTls, true);
});

test('TLS Manager : la relaxation reste portee par la requete, jamais par le process', () => {
  const http = source('src/integrations/http.js');
  assert.match(http, /tls = null/, 'strict par defaut');
  assert.match(http, /tls\.allowSelfSigned === true/, 'consentement explicite');
  const clients = [
    'src/integrations/siem-wazuh.js', 'src/integrations/siem-indexer.js',
    'src/extension.js', 'src/enterprise-domain-pages.js', 'src/sonarqube-api.js', 'src/jenkins.js',
    'src/integrations/observability.js'
  ];
  for (const file of [...clients, 'src/integrations/http.js']) {
    assert.doesNotMatch(source(file), /NODE_TLS_REJECT_UNAUTHORIZED/, `${file} ne doit pas toucher au TLS global`);
  }
  // Aucun client ne desactive lui-meme la verification : seul le transport le
  // fait, sur une seule ligne, gardee par le consentement explicite.
  for (const file of clients) {
    assert.doesNotMatch(source(file), /rejectUnauthorized/, `${file} ne doit pas manipuler la verification`);
  }
  assert.equal((http.match(/rejectUnauthorized/g) || []).length, 1);
  const transport = http.match(/if \(url\.protocol === 'https:' && tls[^\n]*\n/)[0];
  assert.match(transport, /requestOptions\.rejectUnauthorized = false/);
});

// ---------------------------------------------------------------------------
// Independence
// ---------------------------------------------------------------------------

test('TLS Manager : l option Indexer n atteint jamais le Manager', async () => {
  const { calls } = await fetchWith(managerConfig({ indexerAllowSelfSigned: true, indexerUrl: FICTIONAL.indexerUrl }));
  for (const call of calls) assert.equal(call.options.tls, undefined, 'le Manager ignore le reglage Indexer');
});

test('TLS Manager : l option Manager n atteint jamais l Indexer', async () => {
  const calls = [];
  const request = async (target, options = {}) => {
    calls.push({ target, options });
    return { indices: ['fixture-index'], fields: { 'vulnerability.id': { keyword: { type: 'keyword', searchable: true, aggregatable: true } } } };
  };
  await wazuhAdapter.probeVulnerabilities({
    ...managerConfig({ allowSelfSigned: true }),
    indexerUrl: FICTIONAL.indexerUrl, indexerUsername: FICTIONAL.indexerUsername
  }, { ...MANAGER_SECRETS, indexerPassword: FICTIONAL.indexerPassword }, { request });
  assert.ok(calls.length > 0);
  for (const call of calls) assert.equal(call.options.tls, null, 'l Indexer ignore le reglage Manager');
});

test('TLS Manager : les quatre combinaisons sont exprimables', async () => {
  for (const [manager, indexer] of [[false, false], [true, false], [false, true], [true, true]]) {
    const { calls } = await fetchWith(managerConfig({ allowSelfSigned: manager, indexerAllowSelfSigned: indexer }));
    const expected = manager ? { allowSelfSigned: true } : undefined;
    for (const call of calls) assert.deepEqual(call.options.tls, expected, `Manager=${manager} Indexer=${indexer}`);
  }
});

// ---------------------------------------------------------------------------
// Test connection
// ---------------------------------------------------------------------------

test('TLS Manager : « Test connection » respecte l option Manager', async () => {
  const strict = recorder([new IntegrationHttpError('unable to verify the first certificate', 'OFFLINE')]);
  strict.requestTextImpl = async () => { throw new IntegrationHttpError('unable to verify the first certificate', 'OFFLINE'); };
  const rejected = await wazuhAdapter.testConnection(managerConfig(), MANAGER_SECRETS, {
    request: strict.request, requestTextImpl: strict.requestTextImpl
  });
  assert.equal(rejected.ok, false);
  assert.match(rejected.model.message, /certificate is not trusted/);

  const relaxed = recorder([{ data: { affected_items: [] } }]);
  const accepted = await wazuhAdapter.testConnection(managerConfig({ allowSelfSigned: true }), MANAGER_SECRETS, {
    request: relaxed.request, requestTextImpl: relaxed.requestTextImpl
  });
  assert.equal(accepted.ok, true, 'la connexion atteint l API et poursuit vers l authentification');
  for (const call of relaxed.calls) assert.deepEqual(call.options.tls, { allowSelfSigned: true });
});

// ---------------------------------------------------------------------------
// Failure wording
// ---------------------------------------------------------------------------

test('TLS Manager : un certificat refuse produit un message actionnable', async () => {
  for (const raw of ['unable to verify the first certificate', 'self-signed certificate in certificate chain', 'DEPTH_ZERO_SELF_SIGNED_CERT']) {
    assert.equal(isCertificateError({ message: raw }), true, `${raw} doit etre reconnu`);
    const io = recorder([new IntegrationHttpError(raw, 'OFFLINE')]);
    io.requestTextImpl = async () => { throw new IntegrationHttpError(raw, 'OFFLINE'); };
    const model = await wazuhAdapter.fetchStatus(managerConfig(), MANAGER_SECRETS, {
      request: io.request, requestTextImpl: io.requestTextImpl
    });
    assert.match(model.message, /Manager certificate is not trusted/);
    assert.match(model.message, /self-signed Manager option/, 'le remede possible est nomme');
    assert.doesNotMatch(model.message, /unable to verify|DEPTH_ZERO/, 'pas de wording Node brut');
  }
  // Une vraie panne reseau garde son propre message.
  const offline = recorder([new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE')]);
  offline.requestTextImpl = async () => { throw new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE'); };
  const model = await wazuhAdapter.fetchStatus(managerConfig(), MANAGER_SECRETS, {
    request: offline.request, requestTextImpl: offline.requestTextImpl
  });
  assert.doesNotMatch(model.message, /certificate is not trusted/);
});

test('TLS Manager : aucun identifiant ne survit dans un message d erreur', async () => {
  // Les deux vecteurs reels : des identifiants dans une URL, et un en-tete
  // d autorisation recopie dans un message d erreur.
  const leaks = [
    `connect ECONNREFUSED https://${FICTIONAL.managerUsername}:${FICTIONAL.managerPassword}@manager.example.invalid`,
    `request failed with Basic ${Buffer.from(`${FICTIONAL.managerUsername}:${FICTIONAL.managerPassword}`).toString('base64')}`
  ];
  for (const raw of leaks) {
    const io = recorder([new IntegrationHttpError(raw, 'OFFLINE')]);
    io.requestTextImpl = async () => { throw new IntegrationHttpError(raw, 'OFFLINE'); };
    const model = await wazuhAdapter.fetchStatus(managerConfig(), MANAGER_SECRETS, {
      request: io.request, requestTextImpl: io.requestTextImpl
    });
    assert.doesNotMatch(model.message || '', new RegExp(FICTIONAL.managerPassword), raw);
    assert.doesNotMatch(model.message || '', /Basic [A-Za-z0-9+/=]{8}/, raw);
  }
});

// ---------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------

function page(runtimeOverrides = {}, model = {}) {
  return markup(renderRuntimeSecurityPageHtml({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: [],
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      ...runtimeOverrides
    },
    ...model
  }, 'n', 'light'));
}

test('TLS Manager : l avertissement Manager n apparait que lorsqu il est actif', () => {
  assert.doesNotMatch(page(), /TLS verification relaxed/);
  assert.match(page({ relaxedTls: true }), /Provider API TLS verification relaxed/);
  // Il vit dans la carte de connexion, la ou l on lit l etat du fournisseur.
  const html = page({ relaxedTls: true });
  const connection = html.slice(html.indexOf('<h3>Connection</h3>'), html.indexOf('class="tabs"'));
  assert.match(connection, /Provider API TLS verification relaxed/);
  // Et il ne montre ni identifiant ni certificat.
  assert.doesNotMatch(html, new RegExp(FICTIONAL.managerPassword));
  assert.doesNotMatch(html, /BEGIN CERTIFICATE|fingerprint/i);
});

test('TLS Manager : les deux avertissements restent distincts et peuvent coexister', () => {
  const vulnerabilities = {
    ok: true, state: 'ready', relaxedTls: true, items: [],
    summary: { total: 0, severity: [], affectedAssets: 0, assets: [] }, page: 1, pageSize: 10, total: 0
  };
  const both = page({ relaxedTls: true }, {
    tab: 'vulnerabilities', vulnerabilities, capabilityEvidence: { vulnerabilities: { state: 'ready' } }
  });
  assert.match(both, /Provider API TLS verification relaxed/);
  assert.match(both, /Vulnerability data source TLS verification relaxed/);
  assert.equal((both.match(/TLS verification relaxed/g) || []).length, 2, 'deux connexions, deux phrases');
  // Aucune phrase ne pretend que l autre connexion est intacte.
  assert.doesNotMatch(both, /the main provider API is unaffected/);

  // L Indexer seul garde son avertissement, sans en inventer un pour le Manager.
  const indexerOnly = page({}, {
    tab: 'vulnerabilities', vulnerabilities, capabilityEvidence: { vulnerabilities: { state: 'ready' } }
  });
  assert.match(indexerOnly, /Vulnerability data source TLS verification relaxed/);
  assert.doesNotMatch(indexerOnly, /Provider API TLS verification relaxed/);

  // Et le Manager seul n en invente pas un pour l Indexer.
  const managerOnly = page({ relaxedTls: true }, {
    tab: 'vulnerabilities',
    vulnerabilities: { ...vulnerabilities, relaxedTls: false },
    capabilityEvidence: { vulnerabilities: { state: 'ready' } }
  });
  assert.match(managerOnly, /Provider API TLS verification relaxed/);
  assert.doesNotMatch(managerOnly, /Vulnerability data source TLS verification relaxed/);
});

test('TLS Manager : le rendu ne connait aucun champ de configuration TLS', () => {
  const pages = source('src/enterprise-domain-pages.js');
  // La page lit un fait declare par le modele, jamais un identifiant de champ.
  assert.doesNotMatch(pages, /allowSelfSigned/);
  assert.match(pages, /source\.relaxedTls !== true/);
  // Et la case a cocher vient du schema, par le rendu booleen generique.
  const html = markup(renderRuntimeSecurityPageHtml({
    runtime: { configured: false, provider: 'wazuh', label: 'Wazuh', values: { allowSelfSigned: true } }
  }, 'n', 'light'));
  assert.match(html, /id="runtime-allowSelfSigned" type="checkbox" checked/);
  assert.match(html, /id="runtime-indexerAllowSelfSigned" type="checkbox">/);
});

test('TLS Manager : le modele partage porte le fait, avec un defaut strict', () => {
  assert.equal(buildRuntimeSecurityModel({ provider: 'x', label: 'X' }).relaxedTls, false);
  assert.equal(buildRuntimeSecurityModel({ provider: 'x', label: 'X', relaxedTls: true }).relaxedTls, true);
  // Additif : rien du modele existant n a disparu.
  const model = buildRuntimeSecurityModel({ provider: 'x', label: 'X', configured: true });
  for (const key of ['provider', 'configured', 'credentialsConfigured', 'connectionStatus', 'endpoints',
    'endpointSummary', 'alerts', 'alertSummary', 'techniques', 'rules', 'lastSync',
    'id', 'label', 'status', 'lastChecked', 'agents', 'agentSummary']) {
    assert.ok(key in model, `${key} doit rester`);
  }
});
