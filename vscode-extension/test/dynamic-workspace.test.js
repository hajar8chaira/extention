const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  coverageEvidenceFrom, endpointKeyOf, buildDynamicWorkspace,
  dynamicWorkspaceState, restoreDynamicWorkspaceState,
  renderDynamicSections, dynamicSectionsCss, dynamicSectionsScript,
  ZAP_ACTIVE_RANGES, ZAP_PASSIVE_RANGES
} = require('../src/dynamic-workspace');
const { COVERAGE_STATE } = require('../src/dynamic-inventory');
const { RETEST_STATE, retestVerdict } = require('../src/dynamic-retest');
const { normalizeAuthProfile, AUTH_KIND, AUTH_STATUS, maskSecret, authHeadersFor } = require('../src/dynamic-auth');
const { toTransaction, createCampaign, completeCampaign, captureSessionFrom } = require('../src/dynamic-campaign');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { createLocalScanCache, restoreLocalScanCache } = require('../src/local-scan-cache');

const ORIGIN = 'http://127.0.0.1:3000';

const scenario = (pathAndQuery, method = 'GET', extra = {}) => ({
  request: {
    url: `${ORIGIN}${pathAndQuery}`, method,
    headers: extra.auth ? { authorization: 'Bearer REEL-TOKEN-XYZ', cookie: 'session=abc123' } : { accept: 'application/json' },
    ...(extra.body ? { body: extra.body } : {})
  },
  response: { statusCode: extra.status ?? 200, headers: { 'content-type': 'application/json' }, body: extra.responseBody || '' },
  source: extra.source || 'burp',
  timestamp: extra.at || '2026-08-17T10:00:00.000Z'
});

const canonical = (list) => list.map((item, index) => toTransaction(item, { campaignId: 'burp-live', index }));

const zapFinding = (ruleId, pathname, method, extra = {}) => ({
  id: `zap:${ruleId}:${pathname}`, tool: 'ZAP', ruleId: String(ruleId),
  endpoint: `${ORIGIN}${pathname}`, method, title: extra.title || `Alerte ${ruleId}`, ...extra
});

// =============================================== preuve de couverture réelle

test('une alerte ZAP active marque l’endpoint testé activement', () => {
  const evidence = coverageEvidenceFrom({ findings: [zapFinding(40018, '/rest/user/login', 'POST')] });
  assert.deepEqual(evidence.activelyTested, ['POST /rest/user/login']);
  assert.deepEqual(evidence.passivelyAnalyzed, []);
  assert.equal(evidence.endpointLevelEvidence, true);
});

test('une alerte ZAP passive marque l’endpoint analysé passivement', () => {
  const evidence = coverageEvidenceFrom({ findings: [zapFinding(10038, '/', 'GET'), zapFinding(10021, '/api/basket', 'GET')] });
  assert.deepEqual(evidence.passivelyAnalyzed, ['GET /', 'GET /api/basket']);
  assert.deepEqual(evidence.activelyTested, []);
});

test('un scan ZAP global terminé ne marque RIEN comme testé activement', () => {
  // C'est l'invariant central de cette phase : la complétion globale n'est pas
  // une preuve par endpoint.
  const campaign = completeCampaign(createCampaign({ source: 'zap', target: ORIGIN }), { status: 'COMPLETED' });
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/a'), scenario('/b'), scenario('/c')]),
    findings: [], campaign, targetUrl: ORIGIN
  });
  assert.equal(model.evidence.zapRan, true, 'le scan a bien tourné');
  assert.equal(model.evidence.endpointLevelEvidence, false, 'mais sans preuve par endpoint');
  for (const endpoint of model.inventory) {
    assert.equal(endpoint.coverage, COVERAGE_STATE.OBSERVED, `${endpoint.key} ne doit pas être promu`);
  }
  assert.equal(model.coverage.activelyTested, 0);
  assert.equal(model.coverage.tested, 0);
});

test('un identifiant de règle inconnu retombe sur l’état le plus faible', () => {
  const evidence = coverageEvidenceFrom({ findings: [zapFinding('inconnu', '/x', 'GET')] });
  assert.deepEqual(evidence.activelyTested, [], 'jamais promu en actif sur une règle non reconnue');
  assert.deepEqual(evidence.passivelyAnalyzed, ['GET /x']);
});

test('les plages de règles ZAP sont déclarées, pas devinées', () => {
  assert.ok(ZAP_ACTIVE_RANGES.some(([low, high]) => 40018 >= low && 40018 <= high));
  assert.ok(ZAP_PASSIVE_RANGES.some(([low, high]) => 10038 >= low && 10038 <= high));
});

test('un finding sans méthode n’est attribué à aucun endpoint', () => {
  // Le normalisateur ZAP écrit « HTTP » quand la méthode manque : elle ne peut
  // pas désigner un verbe, donc aucune preuve n'est attribuée.
  assert.equal(endpointKeyOf('HTTP', `${ORIGIN}/`), '');
  assert.equal(endpointKeyOf('', `${ORIGIN}/`), '');
  assert.equal(endpointKeyOf('GET', ''), '');
  const evidence = coverageEvidenceFrom({ findings: [zapFinding(40018, '/x', 'HTTP')] });
  assert.deepEqual(evidence.activelyTested, []);
});

test('la preuve atterrit sur la route normalisée que l’inventaire détient', () => {
  assert.equal(endpointKeyOf('GET', `${ORIGIN}/users/123`), 'GET /users/{id}');
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/users/1'), scenario('/users/2')]),
    findings: [zapFinding(40018, '/users/7', 'GET')], targetUrl: ORIGIN
  });
  assert.equal(model.inventory.length, 1);
  assert.equal(model.inventory[0].key, 'GET /users/{id}');
  assert.equal(model.inventory[0].coverage, COVERAGE_STATE.ACTIVELY_TESTED);
});

test('un replay marque l’endpoint rejoué', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/search?q=a')]),
    replayRecords: [{ method: 'GET', endpoint: `${ORIGIN}/search` }], targetUrl: ORIGIN
  });
  assert.equal(model.inventory[0].coverage, COVERAGE_STATE.REPLAYED);
  assert.equal(model.coverage.replayed, 1);
});

test('les quatre sources réelles alimentent la même couverture ordonnée', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/burp'), scenario('/passif'), scenario('/rejoue'), scenario('/actif')]),
    findings: [zapFinding(10038, '/passif', 'GET'), zapFinding(40018, '/actif', 'GET')],
    replayRecords: [{ method: 'GET', endpoint: `${ORIGIN}/rejoue` }],
    targetUrl: ORIGIN
  });
  const byKey = Object.fromEntries(model.inventory.map((endpoint) => [endpoint.key, endpoint.coverage]));
  assert.equal(byKey['GET /burp'], COVERAGE_STATE.OBSERVED);
  assert.equal(byKey['GET /passif'], COVERAGE_STATE.PASSIVELY_ANALYZED);
  assert.equal(byKey['GET /rejoue'], COVERAGE_STATE.REPLAYED);
  assert.equal(byKey['GET /actif'], COVERAGE_STATE.ACTIVELY_TESTED);
});

// ============================================ ingestion depuis le canonique

test('l’inventaire est alimenté par le modèle canonique de transaction', () => {
  const transactions = canonical([scenario('/api/basket', 'GET', { auth: true }), scenario('/api/basket', 'GET', { auth: true })]);
  // Le modèle canonique a déjà assaini : la valeur du jeton n'existe plus.
  assert.equal(transactions[0].request.headers.authorization, '[REDACTED]');
  const model = buildDynamicWorkspace({ transactions, targetUrl: ORIGIN });
  assert.equal(model.inventory.length, 1, 'aucun endpoint dupliqué');
  assert.equal(model.inventory[0].requestCount, 2);
  assert.equal(model.inventory[0].authenticated, true);
});

test('des transactions ajoutées ne dupliquent pas un endpoint existant', () => {
  const first = buildDynamicWorkspace({ transactions: canonical([scenario('/users/1')]), targetUrl: ORIGIN });
  const second = buildDynamicWorkspace({ transactions: canonical([scenario('/users/1'), scenario('/users/2'), scenario('/users/3')]), targetUrl: ORIGIN });
  assert.equal(first.inventory.length, 1);
  assert.equal(second.inventory.length, 1);
  assert.equal(second.inventory[0].requestCount, 3);
});

// ==================================================== persistance

test('l’état persisté ne contient aucun secret', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/rest/user/login', 'POST', { auth: true, body: '{"email":"a@b.c","password":"Sup3r!"}', responseBody: '{"access_token":"eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaa"}' })]),
    authProfile: normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true, maskedValue: maskSecret('eyJhbGciOiJIUzI1NiJ9.charge') }),
    targetUrl: ORIGIN
  });
  const state = dynamicWorkspaceState(model);
  const blob = JSON.stringify(state);
  assert.ok(!blob.includes('REEL-TOKEN-XYZ'), 'aucun jeton de requête');
  assert.ok(!blob.includes('abc123'), 'aucun cookie');
  assert.ok(!blob.includes('Sup3r!'), 'aucun mot de passe');
  assert.ok(!blob.includes('eyJhbGciOiJIUzI1NiJ9.aaaa'), 'aucun jeton de réponse');
  assert.ok(!/"authorization"\s*:\s*"(?!\[REDACTED\])/i.test(blob));
  // Les métadonnées d'authentification, elles, survivent.
  assert.equal(state.auth.kind, AUTH_KIND.BEARER);
  assert.equal(state.auth.secretConfigured, true);
});

test('un aperçu de réponse n’est jamais persisté', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/x')]),
    retests: [{
      findingId: 'zap:1', endpoint: `${ORIGIN}/x`, method: 'GET', title: 'T', state: RETEST_STATE.VALIDATED,
      verdict: { reason: 'evidence_gone', evidence: { at: '2026-08-17T10:00:00Z', previous: { status: 500 } }, comparison: { status: { replay: 200 }, preview: { preview: 'CORPS DE REPONSE SENSIBLE' }, originalPreview: { preview: 'AVANT' } } }
    }],
    targetUrl: ORIGIN
  });
  const state = dynamicWorkspaceState(model);
  const blob = JSON.stringify(state);
  assert.ok(!blob.includes('CORPS DE REPONSE SENSIBLE'), 'l’aperçu ne va pas sur disque');
  assert.ok(!blob.includes('AVANT'));
  assert.ok(!blob.includes('comparison'));
  // Le résultat exploitable, lui, est conservé.
  assert.equal(state.retests[0].state, RETEST_STATE.VALIDATED);
  assert.equal(state.retests[0].previousStatus, 500);
  assert.equal(state.retests[0].replayStatus, 200);
});

test('l’état survit au cache de scan local et se marque restauré', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/users/1'), scenario('/users/2')]),
    findings: [zapFinding(40018, '/users/9', 'GET')],
    campaign: completeCampaign(createCampaign({ source: 'zap', target: ORIGIN }), { status: 'COMPLETED' }),
    targetUrl: ORIGIN
  });
  const state = dynamicWorkspaceState(model);
  // Exactement le chemin de persistance existant.
  const cache = createLocalScanCache('C:/ws', [], [], { dynamicWorkspace: state });
  const restored = restoreLocalScanCache(JSON.parse(JSON.stringify(cache)), 'C:/ws');
  const reloaded = restoreDynamicWorkspaceState(restored.dashboardOptions.dynamicWorkspace);
  assert.equal(reloaded.restored, true, 'jamais présenté comme du direct');
  assert.equal(reloaded.inventory.length, 1);
  assert.equal(reloaded.inventory[0].key, 'GET /users/{id}');
  assert.equal(reloaded.inventory[0].coverage, COVERAGE_STATE.ACTIVELY_TESTED);
  assert.equal(reloaded.campaignId, model.campaignId);
  assert.ok(reloaded.savedAt);
});

test('un état persisté illisible est rejeté, pas réparé', () => {
  for (const raw of [null, undefined, {}, 'texte', [], { inventory: 'x' }]) {
    assert.equal(restoreDynamicWorkspaceState(raw), null, JSON.stringify(raw));
  }
  // Les entrées sans clé sont filtrées plutôt que propagées.
  const restored = restoreDynamicWorkspaceState({ inventory: [{ key: 'GET /a' }, {}, null] });
  assert.equal(restored.inventory.length, 1);
});

// ================================================ couverture authentifiée

test('un profil configuré ne suffit pas à revendiquer un scan authentifié', () => {
  const profile = normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true });
  const notValidated = buildDynamicWorkspace({
    transactions: canonical([scenario('/api/basket', 'GET', { auth: true })]),
    findings: [zapFinding(40018, '/api/basket', 'GET')],
    authProfile: profile, authValidated: false, targetUrl: ORIGIN
  });
  assert.equal(notValidated.authClaim.authenticated, false);
  assert.match(notValidated.authClaim.reason, /n’a pas été validée/);
  const validated = buildDynamicWorkspace({
    transactions: canonical([scenario('/api/basket', 'GET', { auth: true })]),
    findings: [zapFinding(40018, '/api/basket', 'GET')],
    authProfile: profile, authValidated: true, targetUrl: ORIGIN
  });
  assert.equal(validated.authClaim.authenticated, true);
  assert.match(validated.authClaim.reason, /1 endpoint/);
});

test('sans endpoint protégé atteint, la couverture authentifiée n’est pas revendiquée', () => {
  const model = buildDynamicWorkspace({
    transactions: canonical([scenario('/public')]),
    authProfile: normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true }),
    authValidated: true, targetUrl: ORIGIN
  });
  assert.equal(model.authClaim.authenticated, false);
  assert.match(model.authClaim.reason, /aucun endpoint protégé/);
});

// =========================================== rendu des sections de page

const workspaceWith = (overrides = {}) => buildDynamicWorkspace({
  transactions: canonical([scenario('/users/1'), scenario('/users/2'), scenario('/api/basket', 'GET', { auth: true }), scenario('/rest/user/login', 'POST', { status: 500 })]),
  findings: [zapFinding(40018, '/rest/user/login', 'POST', { title: 'SQL Injection' }), zapFinding(10038, '/api/basket', 'GET')],
  targetUrl: ORIGIN, ...overrides
});

test('les cinq sections sont rendues avec l’état réel', () => {
  const html = renderDynamicSections(workspaceWith());
  for (const id of ['dyn-overview', 'dyn-inventory', 'dyn-coverage', 'dyn-auth', 'dyn-retests']) {
    assert.match(html, new RegExp(`id="${id}"`), `${id} absent`);
  }
  assert.match(html, /Inventaire d’API/);
  assert.match(html, /Couverture dynamique/);
  // La méthode et la route occupent deux cellules distinctes du tableau.
  assert.match(html, /<span class="dyn-method">GET<\/span>/);
  assert.match(html, /<code>\/users\/\{id\}<\/code>/);
  assert.match(html, /Testé activement/);
  assert.match(html, /route normalisée/);
});

test('la page dynamique embarque les sections, le CSS et le script', () => {
  const html = renderDashboardHtml(
    buildDashboardModel([], [], { dynamicWorkspace: workspaceWith(), dynamicTargetUrl: ORIGIN }),
    'n', 'dynamic', 'light'
  );
  assert.match(html, /id="dyn-inventory"/);
  assert.match(html, /\.dyn-metric/, 'CSS injecté');
  assert.match(html, /dyn-inventory-body/, 'script de filtrage injecté');
  // La navigation parente existante est préservée.
  assert.match(html, /data-command="securityCenter\.openDashboard"/);
});

test('sans espace de travail, la page ne change pas', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', 'light');
  assert.ok(!html.includes('dyn-overview'));
  assert.ok(!html.includes('.dyn-metric'), 'aucun CSS inutile');
  // Les sections ZAP et Burp existantes restent en place.
  assert.match(html, /<h2>ZAP<\/h2>/);
  assert.match(html, /<h2>Burp<\/h2>/);
});

test('rien n’est affiché comme zéro testé quand rien n’a été évalué', () => {
  const empty = buildDynamicWorkspace({ transactions: [], targetUrl: ORIGIN });
  assert.equal(empty.coverageEvaluated, false);
  const html = renderDynamicSections(empty);
  assert.match(html, /Non évalué/);
  assert.match(html, /Aucun endpoint découvert/);
  assert.match(html, /Aucune couverture n’a été évaluée/);
  // Aucune métrique ne doit afficher un 0 qui se lirait comme un résultat.
  assert.ok(!/<strong>0<\/strong>/.test(html.slice(html.indexOf('dyn-overview'), html.indexOf('dyn-inventory'))));
});

test('les états vides sont honnêtes et nommés', () => {
  const html = renderDynamicSections(buildDynamicWorkspace({ transactions: [], targetUrl: '' }));
  assert.match(html, /Aucune cible configurée/);
  assert.match(html, /Aucune campagne dynamique/);
  assert.match(html, /Aucun profil d’authentification/);
  assert.match(html, /Aucun re-test/);
});

test('une session Burp historique est distinguée du direct', () => {
  const live = renderDynamicSections(workspaceWith({
    burpSession: captureSessionFrom({ connected: true, received_requests: 12, last_seen: '2026-08-17T10:00:00Z', connector: 'security-center-burp' }, { campaign: createCampaign({ source: 'burp' }) })
  }));
  assert.match(live, /Capture en direct/);
  const historical = renderDynamicSections(workspaceWith({
    burpSession: captureSessionFrom({ connected: false, received_requests: 1, last_seen: null }, { campaign: createCampaign({ source: 'burp' }) })
  }));
  assert.match(historical, /pas du trafic en direct/);
  assert.match(historical, /Non fourni par le connecteur/);
  assert.match(historical, /ne permet pas de démarrer ou d’arrêter une capture/);
});

test('les re-tests affichent résultat, raison et statuts', () => {
  const html = renderDynamicSections(workspaceWith({
    retests: [{
      findingId: 'zap:1', endpoint: `${ORIGIN}/rest/user/login`, method: 'POST', title: 'SQL Injection',
      state: RETEST_STATE.VALIDATED,
      verdict: { reason: 'evidence_gone', evidence: { at: '2026-08-17T11:00:00Z', previous: { status: 500 } }, comparison: { status: { replay: 401 } } }
    }]
  }));
  assert.match(html, /Validé — non reproduit/);
  assert.match(html, /n’apparaît plus dans la réponse/);
  assert.match(html, /500 → 401/);
  assert.match(html, /jamais verdict/);
});

test('la couverture explique pourquoi observé n’est pas testé', () => {
  const html = renderDynamicSections(workspaceWith());
  assert.match(html, /Apparaître dans le trafic d’un proxy établit qu’un endpoint existe, pas qu’un test/);
  assert.match(html, /Observés — non testés/);
});

test('un scan ZAP sans preuve par endpoint est expliqué, pas présumé', () => {
  const html = renderDynamicSections(buildDynamicWorkspace({
    transactions: canonical([scenario('/a')]),
    campaign: completeCampaign(createCampaign({ source: 'zap', target: ORIGIN }), { status: 'COMPLETED' }),
    targetUrl: ORIGIN
  }));
  assert.match(html, /n’a produit aucune preuve par endpoint/);
});

// ================================================ sécurité du rendu

test('aucun secret ne franchit le HTML des sections', () => {
  const html = renderDynamicSections(workspaceWith({
    transactions: canonical([scenario('/rest/user/login', 'POST', { auth: true, body: '{"password":"Sup3r!"}' })]),
    authProfile: normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true, maskedValue: maskSecret('eyJhbGciOiJIUzI1NiJ9.charge.sig') })
  }));
  assert.ok(!html.includes('REEL-TOKEN-XYZ'));
  assert.ok(!html.includes('abc123'));
  assert.ok(!html.includes('Sup3r!'));
  assert.ok(!html.includes('charge.sig'));
  // Le masque, lui, est affiché pour identifier le profil.
  assert.match(html, /eyJh…•/);
  assert.match(html, /jamais réaffiché/);
});

test('le contenu hostile est échappé', () => {
  const html = renderDynamicSections(buildDynamicWorkspace({
    transactions: canonical([scenario('/x?<script>alert(1)</script>=1')]),
    findings: [zapFinding(40018, '/x', 'GET', { title: '<img src=x onerror=alert(1)>' })],
    targetUrl: '<script>bad()</script>'
  }));
  assert.ok(!html.includes('<script>alert(1)'));
  assert.ok(!html.includes('<img src=x onerror'));
  assert.ok(!html.includes('<script>bad()'));
});

test('le CSS n’utilise que des variables de thème, sans fond noir codé en dur', () => {
  const css = dynamicSectionsCss();
  assert.ok(!/background:\s*#(000|111|222|fff)\b/i.test(css), 'aucun fond codé en dur');
  assert.ok(!/color:\s*#(000|fff)\b/i.test(css));
  assert.match(css, /var\(--vscode-widget-border\)/);
  assert.match(css, /var\(--vscode-descriptionForeground\)/);
  assert.match(css, /var\(--vscode-input-background\)/);
});

test('le script de la page ne sonde rien et ne calcule aucun état', () => {
  const script = dynamicSectionsScript();
  assert.ok(!/setInterval|setTimeout|fetch\(/.test(script), 'aucun polling');
  // Il filtre des lignes déjà présentes : aucun recalcul, aucun aller-retour.
  assert.match(script, /row\.hidden = !show/);
  assert.match(script, /postMessage\(\{ type: 'dynamicEndpoint'/);
});

// ============================================ pas de dépendance circulaire

test('les modules dynamiques se chargent sans dépendance circulaire cassée', () => {
  // Un require au niveau module aurait fermé un cycle dashboard → workspace →
  // inventory → dashboard, et Node aurait rendu des exports à moitié initialisés.
  for (const file of ['dynamic-inventory.js', 'dynamic-retest.js', 'dynamic-campaign.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
    const topLevel = source.split('\n').filter((line) => /^const .*= require\('\.\/dashboard'\)/.test(line));
    assert.deepEqual(topLevel, [], `${file} require dashboard au niveau module`);
  }
  // Et le chemin réel du produit fonctionne : dashboard chargé en premier.
  const dashboard = require('../src/dashboard');
  assert.equal(typeof dashboard.endpointPath, 'function');
  const model = buildDynamicWorkspace({ transactions: canonical([scenario('/users/1')]), targetUrl: ORIGIN });
  assert.equal(model.inventory.length, 1, 'l’inventaire fonctionne via le chemin du produit');
});

test('le module d’intégration ne calcule aucune logique de sécurité', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dynamic-workspace.js'), 'utf8');
  assert.ok(!/function\s+(associationFor|retestVerdict|summarizeCoverage|buildApiInventory)\b/.test(source),
    'aucune réimplémentation des moteurs existants');
  assert.match(source, /require\('\.\/dynamic-inventory'\)/);
  assert.match(source, /require\('\.\/dynamic-retest'\)/);
  assert.match(source, /require\('\.\/dynamic-auth'\)/);
});

// ============================ raccordement du profil au chemin ZAP existant

test('un profil résolu produit exactement la forme que zapAuthEnv consomme', () => {
  const { zapAuthEnv } = require('../src/zap');
  const profile = normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true });
  const [header, value] = Object.entries(authHeadersFor(profile, 'jeton-de-test'))[0];
  const rendered = zapAuthEnv({ header, value }, ORIGIN);
  assert.match(rendered, /^ZAP_AUTH_HEADER=Authorization$/m);
  assert.match(rendered, /^ZAP_AUTH_HEADER_VALUE=Bearer jeton-de-test$/m);
  assert.match(rendered, /^ZAP_AUTH_HEADER_SITE=host\.docker\.internal:3000$/m);
});

test('la protection contre l’injection d’en-tête du chemin existant s’applique au profil', () => {
  const { zapAuthEnv } = require('../src/zap');
  // Le garde-fou CRLF de zapAuthEnv est réutilisé, pas réécrit.
  assert.throws(() => zapAuthEnv({ header: 'X-Api-Key', value: 'a\r\nZAP_AUTH_HEADER=Cookie' }, ORIGIN), /invalide/);
  assert.throws(() => zapAuthEnv({ header: 'X\nY', value: 'a' }, ORIGIN), /invalide/);
});

test('runZap accepte un profil résolu sans passer par un second moteur de login', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'zap.js'), 'utf8');
  assert.match(source, /resolvedAuth \|\| await authenticateForZap/, 'un seul point de résolution');
  // Le nettoyage du secret sur disque reste celui du chemin existant.
  assert.match(source, /mode: 0o600/);
  assert.match(source, /fs\.rm\(reportDirectory, \{ recursive: true, force: true \}\)/);
  // La définition et l’unique appel : deux occurrences, pas trois.
  assert.equal((source.match(/zapAuthEnv\(authResult, targetUrl\)/g) || []).length, 2);
});

test('les en-têtes du profil ne sont produits que sur demande explicite', () => {
  const profile = normalizeAuthProfile({ kind: AUTH_KIND.COOKIE, secretConfigured: true });
  assert.deepEqual(authHeadersFor(profile, ''), {}, 'sans secret, aucun en-tête');
  assert.deepEqual(authHeadersFor(null, 'x'), {});
  assert.deepEqual(authHeadersFor(normalizeAuthProfile({ kind: AUTH_KIND.NONE }), 'x'), {});
  assert.deepEqual(authHeadersFor(profile, 'session=abc'), { Cookie: 'session=abc' });
});

// ============================== garde-fous du câblage de l’extension

test('l’extension ne persiste que l’état assaini du workspace', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /dynamicWorkspaceState: dynamicWorkspaceState\(workspace\)/, 'la persistance passe par le projeteur');
  assert.ok(!/dynamicWorkspaceState: currentDashboardOptions\.dynamicWorkspace\b/.test(source),
    'le modèle vivant n’est jamais écrit tel quel');
  // Les secrets ne transitent que par SecretStorage.
  assert.match(source, /context\.secrets\.store\(secretKeyFor\(profile\.id\), secret\)/);
  assert.ok(!/dynamicAuthProfile: \{[^}]*secret(?!Configured)/.test(source), 'aucun secret dans les métadonnées du profil');
  assert.match(source, /publicProfile\(profile\)/, 'seule la projection publique atteint le modèle');
});

test('un profil non validé ou non sélectionné n’authentifie pas le scan', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /dynamicAuthProfile\?\.selected && dynamicAuthProfile\.status === AUTH_STATUS\.VALID/);
  assert.match(source, /selected: false/, 'un profil créé n’est pas actif d’office');
});

test('le re-test ne déclenche jamais un scan ZAP complet', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const command = source.slice(source.indexOf("'securityCenter.retestDynamicFinding'"));
  const body = command.slice(0, command.indexOf("dashboardProvider.openPage('dynamic')"));
  assert.ok(!/runZap|beginZapCampaign|scanZap/.test(body), 'aucun lancement de scan dans le re-test');
  assert.match(body, /replayScenario/, 'une seule requête rejouée');
  assert.match(body, /retestVerdict\(/, 'le verdict vient du moteur, pas du code de statut');
  assert.match(body, /\{ modal: true \}/, 'confirmation explicite avant envoi');
});

test('le clic sur une ligne d’inventaire passe par un index, jamais par une URL', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const handler = source.slice(source.indexOf("message?.type === 'dynamicEndpoint'"));
  const body = handler.slice(0, handler.indexOf('return;'));
  assert.match(body, /Number\.isInteger\(message\.index\)/, 'index validé');
  assert.ok(!/message\.(url|endpoint|path)/.test(body), 'aucune cible fournie par le webview');
});

test('le workspace est reconstruit sur des événements, jamais sur une horloge', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const normalized = source.split('\r').join('');
  const rebuild = normalized.slice(normalized.indexOf('function rebuildDynamicWorkspace'));
  const body = rebuild.slice(0, rebuild.indexOf('\n  }\n'));
  assert.ok(!/setInterval|setTimeout/.test(body), 'aucun polling');
  // Reconstruit à la fin de campagne et au rafraîchissement Burp — les deux
  // moments où les entrées changent réellement.
  assert.match(normalized, /rebuildDynamicWorkspace\(\);\n\s*await persistDynamicWorkspace\(\);\n\s*await saveLocalScanCache\(\);/);
  assert.match(normalized, /burpSession: captureSessionFrom[\s\S]{0,400}rebuildDynamicWorkspace\(\)/);
});

test('la restauration se présente comme restaurée, jamais comme du direct', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /restoreDynamicWorkspaceState\(restoredScan\.dashboardOptions\?\.dynamicWorkspaceState\)/);
  const restored = restoreDynamicWorkspaceState({ inventory: [{ key: 'GET /a', coverage: COVERAGE_STATE.OBSERVED }] });
  assert.equal(restored.restored, true);
  assert.match(renderDynamicSections(restored), /État restauré/);
});

// ================== formes d’appel réelles (bugs trouvés en validation réelle)

test('le verdict de re-test consomme la sortie réelle de replayScenario', async () => {
  const http = require('http');
  const { replayScenario } = require('../src/http-scenarios');
  // Un vrai serveur et une vraie requête : c’est ce qui a révélé que
  // retestVerdict lit `.response` et qu’un objet plat donne « no_response ».
  let fixed = false;
  const payload = '<script>alert(1)</script>';
  const server = http.createServer((request, response) => {
    const query = new URL(request.url, 'http://127.0.0.1').searchParams.get('q') || '';
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(fixed ? '<p>aucun resultat</p>' : `<p>resultat ${query}</p>`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const scenario = {
      request: { url: `http://127.0.0.1:${port}/search?q=${encodeURIComponent(payload)}`, method: 'GET', headers: {} },
      response: { statusCode: 200, body: `<p>resultat ${payload}</p>` }
    };
    const finding = { id: 'zap:40012', tool: 'ZAP', ruleId: '40012', title: 'Reflected XSS', endpoint: scenario.request.url, method: 'GET', evidence: payload };
    const verdictFor = async () => {
      const replay = await replayScenario(scenario, { allowWrite: false, timeoutMs: 8000 });
      return retestVerdict({
        finding, original: scenario,
        replay: { response: { statusCode: replay.statusCode, headers: replay.headers, body: replay.body } }
      });
    };
    const before = await verdictFor();
    assert.equal(before.state, RETEST_STATE.STILL_PRESENT);
    assert.equal(before.reason, 'evidence_present');
    fixed = true;
    const after = await verdictFor();
    assert.equal(after.state, RETEST_STATE.VALIDATED);
    assert.equal(after.reason, 'evidence_gone');
    // HTTP 200 des deux côtés : le verdict ne vient donc pas du code de statut.
    assert.equal(after.comparison.status.replay, 200);
  } finally {
    server.close();
  }
});

test('l’extension passe les deux formes attendues par les moteurs', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // retestVerdict lit `.response` sur les deux côtés.
  assert.match(source, /original: scenario,/);
  assert.match(source, /replay: \{ response: \{ statusCode: replay\.statusCode/);
  assert.ok(!/replay: \{ statusCode: replay\.statusCode/.test(source), 'jamais un replay plat');
  // interpretValidation lit `status`, et a besoin du statut précédent pour
  // distinguer une session expirée d’un identifiant jamais valide.
  assert.match(source, /interpretValidation\(\{ status: response\.statusCode, previousStatus: profile\.status \}\)/);
  assert.ok(!/interpretValidation\(\{ statusCode/.test(source));
});

test('interpretValidation distingue expirée et invalide', () => {
  const { interpretValidation } = require('../src/dynamic-auth');
  assert.equal(interpretValidation({ status: 200 }).status, AUTH_STATUS.VALID);
  assert.equal(interpretValidation({ status: 401 }).status, AUTH_STATUS.INVALID);
  assert.equal(interpretValidation({ status: 401, previousStatus: AUTH_STATUS.VALID }).status, AUTH_STATUS.EXPIRED);
  assert.equal(interpretValidation({ status: 500 }).status, AUTH_STATUS.UNKNOWN);
  assert.equal(interpretValidation({ error: 'ECONNREFUSED' }).status, AUTH_STATUS.UNKNOWN);
});
