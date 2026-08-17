const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CAMPAIGN_STATUS, TERMINAL_STATUSES, CAPTURE_STATE, LEGACY_CAMPAIGN_ID,
  campaignId, createCampaign, applyProgress, completeCampaign, progressFor, observed,
  toTransaction, parameterNames, withAssociation, captureSessionFrom,
  restoreCampaign, legacyBucket, hasCampaignIdentity
} = require('../src/dynamic-campaign');
const { createLocalScanCache, restoreLocalScanCache } = require('../src/local-scan-cache');
const { associationFor, ASSOCIATION_CONFIDENCE, ZAP_UNKNOWN_METHOD } = require('../src/dashboard');
const { waitForPassiveQueue, waitForProgress } = require('../src/zap-local');

const TARGET = 'http://127.0.0.1:3000';
const zapCampaign = (overrides = {}) => createCampaign({ source: 'zap', target: TARGET, mode: 'baseline', ...overrides });

// ------------------------------------------------------- identité

test('chaque exécution reçoit un identifiant unique et triable', () => {
  const ids = new Set();
  for (let index = 0; index < 200; index += 1) ids.add(campaignId('zap'));
  assert.equal(ids.size, 200, 'aucune collision');
  const a = zapCampaign();
  const b = zapCampaign();
  assert.notEqual(a.id, b.id);
  assert.match(a.id, /^zap-\d{8}-\d{6}-[0-9a-f]+$/);
  // Une session Burp obtient son propre préfixe.
  assert.match(campaignId('burp'), /^burp-/);
});

test('une source inconnue est refusée plutôt qu’acceptée en silence', () => {
  assert.throws(() => createCampaign({ source: 'nessus' }), /Source de campagne inconnue/);
});

test('une campagne neuve ne prétend rien sur l’authentification', () => {
  const campaign = zapCampaign({ auth: { mode: 'login' } });
  assert.equal(campaign.auth.mode, 'login');
  // Configurer des identifiants n'est pas la preuve qu'ils ont fonctionné.
  assert.equal(campaign.auth.status, 'unknown');
  assert.equal(campaign.status, CAMPAIGN_STATUS.STARTING);
  assert.equal(campaign.completedAt, null);
});

// ------------------------------------------------------- cycle de vie

test('le cycle de vie n’enregistre que des observations réelles', () => {
  let campaign = zapCampaign();
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.SPIDERING, progress: 0 });
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.SPIDERING, progress: 42 });
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.SPIDERING, progress: 100 });
  assert.equal(progressFor(campaign, CAMPAIGN_STATUS.SPIDERING), 100);
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.ACTIVE_SCANNING, progress: 68 });
  assert.equal(campaign.status, CAMPAIGN_STATUS.ACTIVE_SCANNING);
  assert.equal(progressFor(campaign, CAMPAIGN_STATUS.ACTIVE_SCANNING), 68);
  // Une étape jamais observée reste absente : ni 0 %, ni « terminée ».
  assert.equal(observed(campaign, CAMPAIGN_STATUS.PASSIVE_WAIT), false);
  assert.equal(progressFor(campaign, CAMPAIGN_STATUS.PASSIVE_WAIT), null);
});

test('un sondage qui répète la même valeur n’est pas un événement', () => {
  let campaign = applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 40 });
  const before = campaign.lifecycle.length;
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.SPIDERING, progress: 40 });
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.SPIDERING, progress: 40 });
  assert.equal(campaign.lifecycle.length, before, 'aucune entrée dupliquée');
});

test('une progression absente reste nulle et ne devient jamais zéro', () => {
  const campaign = applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.PASSIVE_WAIT, progress: null, detail: 'File passive indisponible' });
  const entry = campaign.lifecycle[campaign.lifecycle.length - 1];
  assert.equal(entry.progress, null);
  assert.match(entry.detail, /indisponible/);
  // Une valeur non numérique est traitée comme une absence, pas comme 0.
  assert.equal(applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 'n/a' }).lifecycle.at(-1).progress, null);
});

test('un pourcentage hors bornes est ramené dans 0-100', () => {
  assert.equal(applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 150 }).lifecycle.at(-1).progress, 100);
  assert.equal(applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: -20 }).lifecycle.at(-1).progress, 0);
});

test('un état inconnu est refusé', () => {
  assert.throws(() => applyProgress(zapCampaign(), { state: 'MAGIC' }), /État de campagne inconnu/);
});

// --------------------------------------------- issues : succès, échec, annulation

test('les trois issues terminales closent la campagne', () => {
  for (const status of [CAMPAIGN_STATUS.COMPLETED, CAMPAIGN_STATUS.PARTIAL, CAMPAIGN_STATUS.CANCELLED, CAMPAIGN_STATUS.FAILED]) {
    const campaign = completeCampaign(zapCampaign(), { status });
    assert.equal(campaign.status, status);
    assert.ok(campaign.completedAt, 'une campagne close est datée');
    assert.ok(TERMINAL_STATUSES.includes(campaign.status));
  }
  assert.throws(() => completeCampaign(zapCampaign(), { status: CAMPAIGN_STATUS.SPIDERING }), /Issue de campagne invalide/);
});

test('une campagne close ne peut pas être réouverte par un événement tardif', () => {
  const done = completeCampaign(applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 50 }), { status: CAMPAIGN_STATUS.CANCELLED });
  const late = applyProgress(done, { state: CAMPAIGN_STATUS.ACTIVE_SCANNING, progress: 90 });
  assert.equal(late.status, CAMPAIGN_STATUS.CANCELLED);
  assert.equal(late.lifecycle.length, done.lifecycle.length);
});

test('une annulation conserve ce qui avait été observé', () => {
  let campaign = applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 73 });
  campaign = completeCampaign(campaign, { status: CAMPAIGN_STATUS.CANCELLED });
  assert.equal(progressFor(campaign, CAMPAIGN_STATUS.SPIDERING), 73);
  assert.equal(observed(campaign, CAMPAIGN_STATUS.ACTIVE_SCANNING), false);
});

// ------------------------------------------- transactions et appartenance

const scenario = (path, method, extra = {}) => ({
  request: {
    url: `${TARGET}${path}`, method,
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.p.s', cookie: 'session=abc123', accept: 'application/json' },
    ...extra
  },
  response: { statusCode: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'session=xyz' } },
  durationMs: 91
});

test('une transaction appartient à la campagne qui l’a produite', () => {
  const campaign = zapCampaign();
  const other = zapCampaign();
  const transaction = toTransaction(scenario('/api/products', 'GET'), { campaignId: campaign.id, index: 0 });
  assert.equal(transaction.campaignId, campaign.id);
  assert.notEqual(transaction.campaignId, other.id);
  assert.match(transaction.id, new RegExp(`^${campaign.id}:0:GET:/api/products$`));
});

test('les findings d’une campagne ne fuient pas vers une autre', () => {
  const first = completeCampaign(zapCampaign(), { status: CAMPAIGN_STATUS.COMPLETED, findingIds: ['zap:1', 'zap:2'] });
  const second = completeCampaign(zapCampaign(), { status: CAMPAIGN_STATUS.COMPLETED, findingIds: ['zap:3'] });
  assert.deepEqual(first.findingIds, ['zap:1', 'zap:2']);
  assert.deepEqual(second.findingIds, ['zap:3']);
  assert.ok(!second.findingIds.some((id) => first.findingIds.includes(id)));
  // Les doublons sont réduits sans être inventés.
  assert.equal(completeCampaign(zapCampaign(), { status: CAMPAIGN_STATUS.COMPLETED, findingIds: ['a', 'a', 'b'] }).statistics.findings, 2);
});

test('les statistiques comptent les endpoints réellement distincts', () => {
  const campaign = zapCampaign();
  const transactions = [
    toTransaction(scenario('/api/products', 'GET'), { campaignId: campaign.id, index: 0 }),
    toTransaction(scenario('/api/products', 'GET'), { campaignId: campaign.id, index: 1 }),
    toTransaction(scenario('/rest/user/login', 'POST'), { campaignId: campaign.id, index: 2 })
  ];
  const done = completeCampaign(campaign, { status: CAMPAIGN_STATUS.COMPLETED, transactions });
  assert.equal(done.statistics.transactions, 3);
  assert.equal(done.statistics.uniqueEndpoints, 2);
});

// --------------------------------------------------------- rédaction

test('aucun en-tête sensible n’entre dans une transaction persistée', () => {
  const transaction = toTransaction(scenario('/rest/user/login', 'POST'), { campaignId: 'zap-x', index: 0 });
  const blob = JSON.stringify(transaction);
  assert.ok(!blob.includes('eyJhbGciOiJIUzI1NiJ9'), 'aucun JWT');
  assert.ok(!blob.includes('abc123'), 'aucun cookie de requête');
  assert.ok(!blob.includes('xyz'), 'aucun cookie de réponse');
  assert.equal(transaction.request.headers.authorization, '[REDACTED]');
  assert.equal(transaction.request.headers.cookie, '[REDACTED]');
  assert.equal(transaction.response.headers['set-cookie'], '[REDACTED]');
  // Un en-tête anodin reste lisible.
  assert.equal(transaction.request.headers.accept, 'application/json');
});

test('aucun corps de requête n’est persisté, seulement les noms de paramètres', () => {
  const transaction = toTransaction(
    scenario('/rest/user/login', 'POST', { body: JSON.stringify({ email: 'a@b.c', password: 'Sup3rSecret!' }) }),
    { campaignId: 'zap-x', index: 0 }
  );
  const blob = JSON.stringify(transaction);
  assert.ok(!blob.includes('Sup3rSecret!'), 'aucun mot de passe');
  assert.ok(!blob.includes('a@b.c'), 'aucune valeur de corps');
  assert.equal(transaction.request.hasBody, true);
  assert.deepEqual(transaction.request.parameterNames, ['email', 'password']);
  assert.ok(!('body' in transaction.request), 'la transaction ne contient pas de corps');
});

test('une valeur sensible dans la query est rédigée, la clé conservée', () => {
  const transaction = toTransaction(scenario('/search?q=shoes&token=s3cr3t', 'GET'), { campaignId: 'zap-x', index: 0 });
  assert.equal(transaction.request.query.q, 'shoes');
  assert.equal(transaction.request.query.token, '[REDACTED]');
  assert.ok(!JSON.stringify(transaction).includes('s3cr3t'));
});

test('les noms de paramètres sont lus sans inventer quand le corps est illisible', () => {
  assert.deepEqual(parameterNames({ body: 'email=a%40b.c&password=x' }), ['email', 'password']);
  assert.deepEqual(parameterNames({ body: '<<binaire>>' }), []);
  assert.deepEqual(parameterNames({}), []);
});

test('un horodatage absent reste nul plutôt qu’inventé', () => {
  const transaction = toTransaction(scenario('/api/products', 'GET'), { campaignId: 'zap-x', index: 0 });
  assert.equal(transaction.timestamp, null);
  assert.equal(toTransaction({ request: { url: TARGET, method: 'GET' }, response: {} }, { campaignId: 'x' }).response.durationMs, null);
  assert.equal(toTransaction({ request: { url: TARGET, method: 'GET' }, response: {} }, { campaignId: 'x' }).response.status, null);
});

// ---------------------------------------------- invariant d'association

test('appartenir à la même campagne n’augmente jamais la confiance', () => {
  const campaign = zapCampaign();
  const finding = { endpoint: `${TARGET}/rest/user/login`, method: 'POST', parameter: 'email', tool: 'ZAP' };
  // Le moteur d'association reste le seul juge, et il ignore la campagne.
  const strong = associationFor(scenario('/rest/user/login', 'POST'), finding);
  assert.equal(strong.confidence, ASSOCIATION_CONFIDENCE.STRONG);
  const transaction = withAssociation(
    toTransaction(scenario('/rest/user/login', 'POST'), { campaignId: campaign.id, index: 0 }),
    { findingIds: ['zap:1'], confidence: strong.confidence }
  );
  assert.equal(transaction.association.confidence, ASSOCIATION_CONFIDENCE.STRONG);
  // Les quatre niveaux existants sont inchangés.
  assert.equal(associationFor(scenario('/rest/user/login', 'POST', { body: '{"email":"a@b.c"}' }), finding).confidence, ASSOCIATION_CONFIDENCE.EXACT);
  assert.equal(associationFor(scenario('/rest/user/login', 'GET'), finding).confidence, null);
  assert.equal(associationFor(scenario('/', 'GET'), { endpoint: `${TARGET}/`, method: ZAP_UNKNOWN_METHOD }).confidence, ASSOCIATION_CONFIDENCE.PROBABLE);
});

// ------------------------------------------------------- session Burp

test('connecté signifie capture en direct', () => {
  const campaign = createCampaign({ source: 'burp', target: TARGET });
  const session = captureSessionFrom({ connected: true, received_requests: 12, last_seen: '2026-08-17T09:00:00Z', connector: 'security-center-burp' }, { campaign });
  assert.equal(session.state, CAPTURE_STATE.LIVE);
  assert.equal(session.connected, true);
  assert.equal(session.currentSessionId, campaign.id);
  assert.equal(session.lastSessionId, null);
  assert.equal(session.receivedRequests, 12);
});

test('déconnecté avec des requêtes stockées est un historique, pas du direct', () => {
  // C'est l'état réel observé sur le backend : connected=false, received=1.
  const campaign = createCampaign({ source: 'burp', target: TARGET });
  const session = captureSessionFrom({ connected: false, received_requests: 1, last_seen: null }, { campaign });
  assert.equal(session.state, CAPTURE_STATE.HISTORICAL);
  assert.equal(session.connected, false);
  assert.equal(session.currentSessionId, null, 'aucune session courante quand le connecteur est absent');
  assert.equal(session.lastSessionId, campaign.id);
  assert.equal(session.receivedRequests, 1);
  // Le backend ne fournit pas d'horodatage : c'est dit, pas inventé.
  assert.equal(session.lastSeen, null);
  assert.equal(session.lastSeenKnown, false);
});

test('jamais connecté et sans requête n’est pas un historique', () => {
  const session = captureSessionFrom({ connected: false, received_requests: 0, last_seen: null });
  assert.equal(session.state, CAPTURE_STATE.NEVER_CONNECTED);
  assert.equal(session.currentSessionId, null);
  assert.equal(session.lastSessionId, null);
});

test('un statut absent ou malformé ne fabrique aucune session', () => {
  for (const status of [null, undefined, {}, { connected: 'yes' }]) {
    const session = captureSessionFrom(status);
    assert.equal(session.connected, false);
    assert.equal(session.receivedRequests, 0);
  }
});

// --------------------------------------------- persistance et rechargement

test('une campagne survit à la sérialisation du cache local', () => {
  let campaign = applyProgress(zapCampaign(), { state: CAMPAIGN_STATUS.SPIDERING, progress: 100 });
  campaign = applyProgress(campaign, { state: CAMPAIGN_STATUS.ACTIVE_SCANNING, progress: 68 });
  campaign = completeCampaign(campaign, {
    status: CAMPAIGN_STATUS.COMPLETED, findingIds: ['zap:1'],
    transactions: [toTransaction(scenario('/api/products', 'GET'), { campaignId: campaign.id, index: 0 })]
  });
  // Exactement le chemin de persistance existant : dashboardOptions du cache.
  const cache = createLocalScanCache('C:/ws', [], [], { dynamicCampaign: campaign, httpScenarios: [] });
  const roundTripped = JSON.parse(JSON.stringify(cache));
  const restored = restoreLocalScanCache(roundTripped, 'C:/ws');
  const reloaded = restoreCampaign(restored.dashboardOptions.dynamicCampaign);
  assert.equal(reloaded.id, campaign.id, 'la MÊME campagne est retrouvée');
  assert.equal(reloaded.status, CAMPAIGN_STATUS.COMPLETED);
  assert.equal(progressFor(reloaded, CAMPAIGN_STATUS.ACTIVE_SCANNING), 68);
  assert.deepEqual(reloaded.findingIds, ['zap:1']);
  assert.equal(reloaded.transactions.length, 1);
  assert.equal(reloaded.restored, true);
});

test('un cache legacy sans campagne ne casse rien et n’invente aucune attribution', () => {
  const legacyCache = createLocalScanCache('C:/ws', [], [], { httpScenarios: [scenario('/api/products', 'GET')] });
  const restored = restoreLocalScanCache(JSON.parse(JSON.stringify(legacyCache)), 'C:/ws');
  assert.equal(restored.dashboardOptions.dynamicCampaign, undefined);
  assert.equal(restoreCampaign(restored.dashboardOptions.dynamicCampaign), null);
  // Les données restent visibles, explicitement non attribuées.
  const bucket = legacyBucket(restored.dashboardOptions.httpScenarios.length);
  assert.equal(bucket.id, LEGACY_CAMPAIGN_ID);
  assert.equal(bucket.legacy, true);
  assert.equal(bucket.status, 'UNATTRIBUTED');
  assert.equal(bucket.statistics.transactions, 1);
  assert.equal(bucket.target, '', 'aucune cible revendiquée');
  assert.deepEqual(bucket.lifecycle, [], 'aucun cycle de vie inventé');
  assert.equal(hasCampaignIdentity({ dynamicCampaign: bucket }), false);
  assert.equal(hasCampaignIdentity({ dynamicCampaign: null }), false);
});

test('une campagne persistée corrompue est rejetée, pas réparée à moitié', () => {
  for (const broken of [
    null, {}, { id: 'x' }, { id: 'x', source: 'nessus', status: 'COMPLETED' },
    { id: 'x', source: 'zap', status: 'MAGIC' }, { source: 'zap', status: 'COMPLETED' }
  ]) {
    assert.equal(restoreCampaign(broken), null, `${JSON.stringify(broken)} doit être rejetée`);
  }
  // Un cycle de vie contenant une entrée inconnue est filtré, pas propagé.
  const restored = restoreCampaign({
    id: 'zap-1', source: 'zap', status: 'COMPLETED',
    lifecycle: [{ state: 'SPIDERING', progress: 50 }, { state: 'MAGIC', progress: 10 }]
  });
  assert.equal(restored.lifecycle.length, 1);
  assert.equal(restored.lifecycle[0].state, 'SPIDERING');
});

test('une campagne valide est reconnue comme telle', () => {
  const campaign = completeCampaign(zapCampaign(), { status: CAMPAIGN_STATUS.COMPLETED });
  assert.equal(hasCampaignIdentity({ dynamicCampaign: campaign }), true);
});

// ------------------------------ progression ZAP : la source des valeurs

test('waitForProgress relaie le pourcentage réel renvoyé par ZAP', async () => {
  const observations = [];
  const responses = [{ status: '0' }, { status: '45' }, { status: '100' }];
  let call = 0;
  // On substitue uniquement la couche réseau ; la boucle testée est la vraie.
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => responses[Math.min(call++, responses.length - 1)] });
  try {
    await waitForProgress('http://127.0.0.1:8090', 'k', 'spider', '1', 30000, undefined, (percent) => observations.push(percent));
  } finally { global.fetch = originalFetch; }
  assert.deepEqual(observations, [0, 45, 100]);
});

test('la file passive est signalée indisponible plutôt que satisfaite', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
  try {
    const result = await waitForPassiveQueue('http://127.0.0.1:8090', 'k', 5000);
    assert.equal(result.available, false, 'une file inaccessible n’est jamais « vidée »');
    assert.ok(result.reason);
    assert.notEqual(result.drained, true);
  } finally { global.fetch = originalFetch; }
});

test('la file passive dérive son pourcentage des deux nombres de ZAP', async () => {
  const queue = [{ recordsToScan: '10' }, { recordsToScan: '5' }, { recordsToScan: '0' }];
  let call = 0;
  const observations = [];
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => queue[Math.min(call++, queue.length - 1)] });
  try {
    const result = await waitForPassiveQueue('http://127.0.0.1:8090', 'k', 30000, undefined, (percent) => observations.push(percent));
    assert.equal(result.available, true);
    assert.equal(result.drained, true);
    // 10 → 5 → 0 sur une file initiale de 10.
    assert.deepEqual(observations, [0, 50, 100]);
  } finally { global.fetch = originalFetch; }
});

test('aucune progression ne provient d’un minuteur', () => {
  const fs = require('fs');
  const path = require('path');
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dynamic-campaign.js'), 'utf8');
  assert.ok(!/setInterval|setTimeout|requestAnimationFrame/.test(source), 'le modèle ne planifie rien');
  const zap = fs.readFileSync(path.join(__dirname, '..', 'src', 'zap-local.js'), 'utf8');
  // Le seul setTimeout de zap-local cadence l'interrogation de l'API ZAP ; il
  // n'incrémente jamais un pourcentage.
  assert.ok(!/progress\s*[+]{2}|progress\s*\+=|percent\s*\+=/.test(zap), 'aucun pourcentage synthétique');
});
