const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  COVERAGE_STATE, ENDPOINT_SOURCE, NORMALIZATION_CONFIDENCE, COVERAGE_LABELS,
  looksLikeIdentifier, templatePath, templateFromObservations,
  buildApiInventory, summarizeCoverage, isAuthenticated, strongest
} = require('../src/dynamic-inventory');
const {
  RETEST_STATE, VERDICT_REASON, REASON_LABELS, MAX_COMPARABLE_BODY, PREVIEW_LIMIT,
  safePreview, compareReplay, evaluateSecurityCondition, expectedHeaderFor,
  retestVerdict, advanceRetest, createRetestRecord
} = require('../src/dynamic-retest');
const {
  AUTH_KIND, AUTH_STATUS, secretKeyFor, normalizeAuthProfile, maskSecret,
  authHeadersFor, interpretValidation, authenticatedCoverageClaim, publicProfile
} = require('../src/dynamic-auth');

const ORIGIN = 'http://127.0.0.1:3000';

const tx = (pathAndQuery, method = 'GET', extra = {}) => ({
  url: `${ORIGIN}${pathAndQuery}`,
  method,
  request: { url: `${ORIGIN}${pathAndQuery}`, method, headers: extra.auth ? { authorization: '[REDACTED]' } : {} },
  response: { status: extra.status ?? 200, contentType: extra.contentType || 'application/json', headers: {} },
  source: extra.source || 'burp',
  timestamp: extra.at || '2026-08-17T10:00:00.000Z'
});

// ================================================ normalisation d'endpoint

test('un segment est un identifiant seulement sur des formes reconnues', () => {
  for (const value of ['123', '0', '550e8400-e29b-41d4-a716-446655440000', '507f1f77bcf86cd799439011', '01HQ3M4N5P6Q7R8S9T0V']) {
    assert.equal(looksLikeIdentifier(value), true, value);
  }
  for (const value of ['users', 'shoes', 'login', 'v1', 'api', 'report.pdf', 'index.html', '', 'a']) {
    assert.equal(looksLikeIdentifier(value), false, value);
  }
});

test('les identifiants sont remplacés, les mots conservés', () => {
  assert.equal(templatePath('/users/123').template, '/users/{id}');
  assert.equal(templatePath('/users/123/orders/456').template, '/users/{id}/orders/{id}');
  assert.equal(templatePath('/api/v1/users/550e8400-e29b-41d4-a716-446655440000').template, '/api/v1/users/{id}');
  // Un slug ou un nom de fichier n'est jamais un identifiant.
  assert.equal(templatePath('/products/shoes').template, '/products/shoes');
  assert.equal(templatePath('/files/report.pdf').template, '/files/report.pdf');
  assert.equal(templatePath('/').template, '/');
  assert.equal(templatePath('/health').confidence, NORMALIZATION_CONFIDENCE.NONE);
  assert.equal(templatePath('/users/9').confidence, NORMALIZATION_CONFIDENCE.HIGH);
});

test('la fusion par observation exige au moins trois valeurs distinctes', () => {
  // Deux valeurs : `/status/up` et `/status/down` sont deux endpoints.
  assert.equal(templateFromObservations(['/status/up', '/status/down']).size, 0);
  // Trois valeurs à la même position : c'est une route paramétrée.
  const templates = templateFromObservations(['/tag/red', '/tag/green', '/tag/blue']);
  assert.equal(templates.get('/tag/red'), '/tag/{id}');
  assert.equal(templates.size, 3);
  // Des chemins qui diffèrent à deux positions ne sont jamais fusionnés.
  assert.equal(templateFromObservations(['/a/x', '/b/y', '/c/z']).size, 0);
});

test('deux chemins numériques deviennent une seule route', () => {
  const inventory = buildApiInventory({ transactions: [tx('/users/123'), tx('/users/456'), tx('/users/789')] });
  assert.equal(inventory.length, 1);
  assert.equal(inventory[0].key, 'GET /users/{id}');
  assert.equal(inventory[0].requestCount, 3);
  assert.deepEqual(inventory[0].concretePaths, ['/users/123', '/users/456', '/users/789']);
  assert.equal(inventory[0].normalization, NORMALIZATION_CONFIDENCE.HIGH);
});

test('des endpoints insuffisamment similaires restent distincts', () => {
  const inventory = buildApiInventory({ transactions: [tx('/products/shoes'), tx('/products/hats')] });
  assert.equal(inventory.length, 2, 'une fusion ici masquerait un endpoint');
  assert.deepEqual(inventory.map((endpoint) => endpoint.key).sort(), ['GET /products/hats', 'GET /products/shoes']);
});

test('la méthode fait partie de l’identité de l’endpoint', () => {
  const inventory = buildApiInventory({ transactions: [tx('/api/orders', 'GET'), tx('/api/orders', 'POST'), tx('/api/orders', 'DELETE')] });
  assert.equal(inventory.length, 3);
  assert.deepEqual(inventory.map((endpoint) => endpoint.method), ['DELETE', 'GET', 'POST']);
});

test('un même endpoint agrège requêtes, paramètres et types', () => {
  const inventory = buildApiInventory({
    transactions: [
      tx('/search?q=a&page=1', 'GET', { contentType: 'application/json', at: '2026-08-17T09:00:00.000Z', status: 200 }),
      tx('/search?q=b&limit=10', 'GET', { contentType: 'text/html', at: '2026-08-17T11:00:00.000Z', status: 500 })
    ]
  });
  const endpoint = inventory[0];
  assert.equal(endpoint.requestCount, 2);
  assert.deepEqual(endpoint.queryParameters, ['limit', 'page', 'q']);
  assert.deepEqual(endpoint.contentTypes, ['application/json', 'text/html']);
  assert.equal(endpoint.firstSeen, '2026-08-17T09:00:00.000Z');
  assert.equal(endpoint.lastSeen, '2026-08-17T11:00:00.000Z');
  assert.equal(endpoint.lastStatusCode, 500);
  assert.equal(endpoint.host, '127.0.0.1:3000');
});

test('la source est déduite du trafic, jamais supposée', () => {
  const inventory = buildApiInventory({
    transactions: [tx('/a', 'GET', { source: 'burp' }), tx('/b', 'GET', { source: 'zap-spider' }), tx('/c', 'GET', { source: 'har-import' }), tx('/d', 'GET', { source: 'replay' })]
  });
  const sources = Object.fromEntries(inventory.map((endpoint) => [endpoint.key, endpoint.sources]));
  assert.deepEqual(sources['GET /a'], [ENDPOINT_SOURCE.BURP]);
  assert.deepEqual(sources['GET /b'], [ENDPOINT_SOURCE.ZAP]);
  assert.deepEqual(sources['GET /c'], [ENDPOINT_SOURCE.HAR]);
  assert.deepEqual(sources['GET /d'], [ENDPOINT_SOURCE.REPLAY]);
});

test('un trafic malformé ne produit aucun endroit inventé', () => {
  const inventory = buildApiInventory({
    transactions: [null, undefined, {}, { request: {} }, { url: '' }, { url: 'pas-une-url', method: 'GET' }]
  });
  // Seule l'URL relative exploitable subsiste, et rien n'est fabriqué.
  assert.ok(inventory.length <= 1);
  assert.deepEqual(buildApiInventory({}), []);
  assert.deepEqual(buildApiInventory({ transactions: null }), []);
});

// ==================================================== couverture dynamique

test('apparaître dans le trafic n’est PAS être testé', () => {
  const inventory = buildApiInventory({ transactions: [tx('/api/products')] });
  assert.equal(inventory[0].coverage, COVERAGE_STATE.OBSERVED);
  assert.notEqual(inventory[0].coverage, COVERAGE_STATE.ACTIVELY_TESTED);
  const coverage = summarizeCoverage(inventory);
  assert.equal(coverage.observed, 1);
  assert.equal(coverage.tested, 0, 'observé ne compte jamais comme testé');
  assert.equal(coverage.untested, 1);
  assert.equal(coverage.coveragePercent, 0);
});

test('chaque niveau de preuve élève la couverture, jamais l’inverse', () => {
  const transactions = [tx('/a'), tx('/b'), tx('/c'), tx('/d')];
  const inventory = buildApiInventory({
    transactions,
    passivelyAnalyzed: ['GET /b'],
    replayed: ['GET /c'],
    activelyTested: ['GET /d']
  });
  const byKey = Object.fromEntries(inventory.map((endpoint) => [endpoint.key, endpoint.coverage]));
  assert.equal(byKey['GET /a'], COVERAGE_STATE.OBSERVED);
  assert.equal(byKey['GET /b'], COVERAGE_STATE.PASSIVELY_ANALYZED);
  assert.equal(byKey['GET /c'], COVERAGE_STATE.REPLAYED);
  assert.equal(byKey['GET /d'], COVERAGE_STATE.ACTIVELY_TESTED);
  // Une preuve plus faible ne dégrade pas une plus forte.
  assert.equal(strongest(COVERAGE_STATE.ACTIVELY_TESTED, COVERAGE_STATE.OBSERVED), COVERAGE_STATE.ACTIVELY_TESTED);
  assert.equal(strongest(COVERAGE_STATE.OBSERVED, COVERAGE_STATE.REPLAYED), COVERAGE_STATE.REPLAYED);
});

test('un endpoint déclaré par OpenAPI mais jamais atteint est visible', () => {
  const inventory = buildApiInventory({
    transactions: [tx('/api/products')],
    openapiEndpoints: [{ method: 'DELETE', path: '/api/admin/users' }, { method: 'GET', path: '/api/products' }]
  });
  const admin = inventory.find((endpoint) => endpoint.key === 'DELETE /api/admin/users');
  assert.equal(admin.coverage, COVERAGE_STATE.NOT_TESTED);
  assert.equal(admin.requestCount, 0);
  assert.deepEqual(admin.sources, [ENDPOINT_SOURCE.OPENAPI]);
  // Un endpoint déclaré ET observé porte les deux sources.
  const products = inventory.find((endpoint) => endpoint.key === 'GET /api/products');
  assert.deepEqual(products.sources.sort(), [ENDPOINT_SOURCE.BURP, ENDPOINT_SOURCE.OPENAPI]);
  const coverage = summarizeCoverage(inventory);
  assert.equal(coverage.notReached, 1);
  assert.equal(coverage.total, 2);
});

test('un inventaire vide donne zéro pour cent, pas cent', () => {
  const coverage = summarizeCoverage([]);
  assert.equal(coverage.total, 0);
  assert.equal(coverage.coveragePercent, 0);
  assert.equal(coverage.activeCoveragePercent, 0);
  assert.equal(coverage.tested, 0);
});

test('le pourcentage compte les endpoints réellement testés', () => {
  const transactions = [tx('/a'), tx('/b'), tx('/c'), tx('/d')];
  const coverage = summarizeCoverage(buildApiInventory({ transactions, activelyTested: ['GET /a'], replayed: ['GET /b'] }));
  assert.equal(coverage.tested, 2);
  assert.equal(coverage.coveragePercent, 50);
  assert.equal(coverage.activeCoveragePercent, 25);
  assert.deepEqual(coverage.methods, ['GET']);
});

test('chaque état de couverture a un libellé', () => {
  for (const state of Object.values(COVERAGE_STATE)) {
    assert.ok(COVERAGE_LABELS[state], `${state} sans libellé`);
  }
  // Et le libellé de OBSERVED dit explicitement « non testé ».
  assert.match(COVERAGE_LABELS.OBSERVED, /non testé/);
});

// ================================================ association des findings

test('un finding est rattaché par l’association existante, pas par l’hôte', () => {
  const inventory = buildApiInventory({
    transactions: [tx('/rest/user/login', 'POST'), tx('/api/products', 'GET')],
    findings: [{ id: 'zap:1', tool: 'ZAP', endpoint: `${ORIGIN}/rest/user/login`, method: 'POST', parameter: 'email' }]
  });
  const login = inventory.find((endpoint) => endpoint.key === 'POST /rest/user/login');
  const products = inventory.find((endpoint) => endpoint.key === 'GET /api/products');
  assert.equal(login.findingCount, 1);
  assert.deepEqual(login.findingIds, ['zap:1']);
  assert.ok(login.sources.includes(ENDPOINT_SOURCE.ZAP));
  // Un autre endpoint du même hôte n'hérite de rien.
  assert.equal(products.findingCount, 0);
});

test('une méthode divergente empêche le rattachement', () => {
  const inventory = buildApiInventory({
    transactions: [tx('/rest/user/login', 'GET')],
    findings: [{ id: 'zap:1', tool: 'ZAP', endpoint: `${ORIGIN}/rest/user/login`, method: 'POST' }]
  });
  assert.equal(inventory[0].findingCount, 0);
});

test('l’authentification est déduite de la présence d’un en-tête, jamais de sa valeur', () => {
  assert.equal(isAuthenticated({ request: { headers: { authorization: '[REDACTED]' } } }), true);
  assert.equal(isAuthenticated({ request: { headers: { cookie: '[REDACTED]' } } }), true);
  assert.equal(isAuthenticated({ request: { headers: { 'x-api-key': '[REDACTED]' } } }), true);
  assert.equal(isAuthenticated({ authenticated: true }), true);
  assert.equal(isAuthenticated({ request: { headers: { accept: 'application/json' } } }), false);
  assert.equal(isAuthenticated({}), false);
  const inventory = buildApiInventory({ transactions: [tx('/me', 'GET', { auth: true }), tx('/me', 'GET')] });
  assert.equal(inventory[0].authenticated, true);
  assert.equal(inventory[0].authenticatedRequests, 1);
  assert.equal(inventory[0].requestCount, 2);
});

// ================================================ comparaison de replay

const response = (status, body = '', headers = {}, durationMs = 100) => ({ response: { status, body, headers, durationMs } });

test('la comparaison rapporte les faits structurels', () => {
  const comparison = compareReplay(
    response(500, 'a'.repeat(200), { 'content-type': 'text/html' }, 240),
    response(403, 'b'.repeat(20), { 'content-type': 'application/json', 'content-security-policy': 'default-src' }, 91)
  );
  assert.deepEqual(comparison.status, { original: 500, replay: 403, changed: true });
  assert.equal(comparison.contentType.original, 'text/html');
  assert.equal(comparison.contentType.replay, 'application/json');
  assert.deepEqual(comparison.duration, { original: 240, replay: 91 });
  assert.deepEqual(comparison.size, { original: 200, replay: 20 });
  assert.deepEqual(comparison.headerChanges, [{ header: 'content-security-policy', change: 'added' }]);
  assert.equal(comparison.bodyChanged, true);
  assert.equal(comparison.bodySignificantlyChanged, true);
});

test('un corps identique n’est pas signalé comme changé', () => {
  const comparison = compareReplay(response(200, 'même'), response(200, 'même'));
  assert.equal(comparison.bodyChanged, false);
  assert.equal(comparison.bodySignificantlyChanged, false);
  assert.equal(comparison.status.changed, false);
  assert.deepEqual(comparison.headerChanges, []);
});

test('la valeur d’un en-tête n’est jamais comparée ni affichée', () => {
  const comparison = compareReplay(
    response(200, 'ok', { 'set-cookie': 'session=AVANT' }),
    response(200, 'ok', { 'set-cookie': 'session=APRES' })
  );
  const blob = JSON.stringify(comparison);
  assert.ok(!blob.includes('AVANT'));
  assert.ok(!blob.includes('APRES'));
  // Un en-tête sensible n'entre même pas dans la liste comparable.
  assert.ok(!comparison.headerChanges.some((change) => /cookie/i.test(change.header)));
});

test('un corps trop volumineux n’est pas comparé textuellement', () => {
  const huge = 'x'.repeat(MAX_COMPARABLE_BODY + 10);
  const comparison = compareReplay(response(200, huge), response(200, 'petit'));
  assert.equal(comparison.bodyComparable, false);
  assert.equal(comparison.bodyChanged, null, 'aucune conclusion sur un corps non comparable');
  assert.equal(comparison.bodySignificantlyChanged, null);
  // Le statut reste exploitable.
  assert.equal(comparison.status.changed, false);
});

test('un aperçu est tronqué et supprimé quand il semble contenir un secret', () => {
  const long = safePreview('y'.repeat(PREVIEW_LIMIT + 50));
  assert.equal(long.preview.length, PREVIEW_LIMIT);
  assert.equal(long.truncated, true);
  for (const body of ['{"access_token":"eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnopqrst"}', 'Authorization: Bearer abcdefghijklmnopqrstuvwx', 'set-cookie: session=abc']) {
    const preview = safePreview(body);
    assert.equal(preview.suppressed, true, body.slice(0, 30));
    assert.match(preview.preview, /APERÇU SUPPRIMÉ/);
    assert.ok(!preview.preview.includes('eyJhbGciOiJIUzI1NiJ9'));
  }
  assert.deepEqual(safePreview(''), { preview: '', truncated: false, suppressed: false });
});

// ================================================== retest ciblé

const cspFinding = { id: 'zap:csp', ruleId: '10038', title: 'Content Security Policy (CSP) Header Not Set', endpoint: `${ORIGIN}/`, method: 'GET' };
const sqlFinding = { id: 'zap:sqli', ruleId: '40018', title: 'SQL Injection', evidence: 'SQL syntax error', endpoint: `${ORIGIN}/rest/user/login`, method: 'POST' };

test('un statut 200 ne valide JAMAIS un finding à lui seul', () => {
  const verdict = retestVerdict({
    finding: { id: 'x', ruleId: 'inconnu', title: 'Quelque chose' },
    original: response(500, 'boom'), replay: response(200, 'ok')
  });
  assert.equal(verdict.state, RETEST_STATE.INCONCLUSIVE);
  assert.equal(verdict.reason, VERDICT_REASON.NO_CHECK);
  assert.notEqual(verdict.state, RETEST_STATE.VALIDATED);
});

test('une preuve disparue valide, une preuve présente non', () => {
  const gone = retestVerdict({ finding: sqlFinding, original: response(500, 'SQL syntax error near'), replay: response(200, '{"ok":true}') });
  assert.equal(gone.state, RETEST_STATE.VALIDATED);
  assert.equal(gone.reason, VERDICT_REASON.EVIDENCE_GONE);
  const present = retestVerdict({ finding: sqlFinding, original: response(500, 'SQL syntax error near'), replay: response(500, 'SQL syntax error near') });
  assert.equal(present.state, RETEST_STATE.STILL_PRESENT);
  assert.equal(present.reason, VERDICT_REASON.EVIDENCE_PRESENT);
});

test('un en-tête de sécurité ajouté valide, toujours absent non', () => {
  const added = retestVerdict({ finding: cspFinding, original: response(200, '<html>'), replay: response(200, '<html>', { 'content-security-policy': "default-src 'self'" }) });
  assert.equal(added.state, RETEST_STATE.VALIDATED);
  assert.equal(added.reason, VERDICT_REASON.HEADER_ADDED);
  assert.equal(added.detail, 'content-security-policy');
  const missing = retestVerdict({ finding: cspFinding, original: response(200, '<html>'), replay: response(200, '<html>') });
  assert.equal(missing.state, RETEST_STATE.STILL_PRESENT);
  assert.equal(missing.reason, VERDICT_REASON.HEADER_STILL_MISSING);
});

test('les en-têtes reconnus couvrent les alertes ZAP usuelles', () => {
  assert.equal(expectedHeaderFor('10020', 'Missing Anti-clickjacking Header'), 'x-frame-options');
  assert.equal(expectedHeaderFor('10035', 'Strict-Transport-Security Header Not Set'), 'strict-transport-security');
  assert.equal(expectedHeaderFor('10021', 'X-Content-Type-Options Header Missing'), 'x-content-type-options');
  // Une alerte qui n'est pas « en-tête absent » n'ouvre aucune vérification.
  assert.equal(expectedHeaderFor('10038', 'Content Security Policy Header Misconfigured'), '');
  assert.equal(expectedHeaderFor('40018', 'SQL Injection'), '');
});

test('un replay en échec ou absent est non concluant', () => {
  assert.equal(retestVerdict({ finding: sqlFinding, replayError: 'ECONNREFUSED 127.0.0.1:3000' }).state, RETEST_STATE.INCONCLUSIVE);
  assert.equal(retestVerdict({ finding: sqlFinding, replayError: 'x' }).reason, VERDICT_REASON.REPLAY_FAILED);
  assert.equal(retestVerdict({ finding: sqlFinding, replay: null }).state, RETEST_STATE.INCONCLUSIVE);
  assert.equal(retestVerdict({ finding: sqlFinding, replay: {} }).reason, VERDICT_REASON.NO_RESPONSE);
});

test('un replay qui n’atteint pas le bon endpoint ne conclut rien', () => {
  for (const association of ['PROBABLE', 'WEAK', null]) {
    if (association === null) continue;
    const verdict = retestVerdict({ finding: sqlFinding, original: response(500, 'SQL syntax error'), replay: response(200, 'ok'), association });
    assert.equal(verdict.state, RETEST_STATE.INCONCLUSIVE, association);
    assert.equal(verdict.reason, VERDICT_REASON.ENDPOINT_MISMATCH);
  }
  // Une association prouvée laisse le verdict s'exprimer.
  assert.equal(retestVerdict({ finding: sqlFinding, original: response(500, 'SQL syntax error'), replay: response(200, 'ok'), association: 'EXACT' }).state, RETEST_STATE.VALIDATED);
});

test('la preuve du finding précédent est conservée quel que soit le verdict', () => {
  for (const args of [
    { finding: sqlFinding, original: response(500, 'SQL syntax error'), replay: response(200, 'ok') },
    { finding: sqlFinding, original: response(500, 'SQL syntax error'), replay: response(500, 'SQL syntax error') },
    { finding: sqlFinding, original: response(500, 'SQL syntax error'), replayError: 'boom' }
  ]) {
    const verdict = retestVerdict(args);
    assert.equal(verdict.evidence.findingId, 'zap:sqli');
    assert.equal(verdict.evidence.endpoint, `${ORIGIN}/rest/user/login`);
    assert.ok(verdict.evidence.at, 'le verdict est daté');
    if (args.original) assert.equal(verdict.evidence.previous.status, 500, 'l’état précédent survit');
  }
});

test('chaque raison de verdict a une phrase lisible', () => {
  for (const reason of Object.values(VERDICT_REASON)) {
    assert.ok(REASON_LABELS[reason], `${reason} sans libellé`);
  }
});

test('la condition de sécurité n’est pas évaluable sans réponse', () => {
  assert.equal(evaluateSecurityCondition(sqlFinding, {}).reason, VERDICT_REASON.NO_RESPONSE);
  assert.equal(evaluateSecurityCondition(sqlFinding, { response: { status: 200 } }).reason, VERDICT_REASON.BODY_UNAVAILABLE);
  // Une preuve trop courte n'est pas une preuve exploitable.
  assert.equal(evaluateSecurityCondition({ evidence: 'ab' }, response(200, 'xx').response ? { response: { status: 200, body: 'xx', headers: {} } } : {}).reason, VERDICT_REASON.NO_CHECK);
});

// =============================================== cycle de vie du retest

test('le cycle de vie n’accepte que les transitions légales', () => {
  const record = createRetestRecord(sqlFinding, { campaignId: 'zap-1' });
  assert.equal(record.state, RETEST_STATE.FOUND);
  assert.equal(record.findingId, 'zap:sqli');
  assert.equal(record.campaignId, 'zap-1');
  const applied = advanceRetest(record, RETEST_STATE.FIX_APPLIED);
  const retesting = advanceRetest(applied, RETEST_STATE.RETESTING);
  const validated = advanceRetest(retesting, RETEST_STATE.VALIDATED, { reason: 'evidence_gone' });
  assert.equal(validated.state, RETEST_STATE.VALIDATED);
  assert.equal(validated.history.length, 4);
  assert.deepEqual(validated.history.map((entry) => entry.state), ['FOUND', 'FIX_APPLIED', 'RETESTING', 'VALIDATED']);
});

test('un verdict ne peut pas être atteint sans avoir été re-testé', () => {
  const record = createRetestRecord(sqlFinding);
  // Sauter directement à VALIDATED serait exactement la fausse validation à éviter.
  assert.throws(() => advanceRetest(record, RETEST_STATE.VALIDATED), /Transition de re-test invalide/);
  assert.throws(() => advanceRetest(record, RETEST_STATE.STILL_PRESENT), /invalide/);
  const applied = advanceRetest(record, RETEST_STATE.FIX_APPLIED);
  assert.throws(() => advanceRetest(applied, RETEST_STATE.VALIDATED), /invalide/);
});

test('un finding validé qui réapparaît repasse par FOUND', () => {
  let record = createRetestRecord(sqlFinding);
  record = advanceRetest(advanceRetest(record, RETEST_STATE.RETESTING), RETEST_STATE.VALIDATED);
  // Une régression rouvre le cycle, elle ne le contredit pas en place.
  assert.throws(() => advanceRetest(record, RETEST_STATE.RETESTING), /invalide/);
  const reopened = advanceRetest(record, RETEST_STATE.FOUND);
  assert.equal(reopened.state, RETEST_STATE.FOUND);
  // Un état non concluant, lui, peut être re-tenté directement.
  let inconclusive = createRetestRecord(sqlFinding);
  inconclusive = advanceRetest(advanceRetest(inconclusive, RETEST_STATE.RETESTING), RETEST_STATE.INCONCLUSIVE);
  assert.equal(advanceRetest(inconclusive, RETEST_STATE.RETESTING).state, RETEST_STATE.RETESTING);
});

// =============================================== authentification DAST

test('un profil ne transporte jamais le secret', () => {
  for (const key of ['value', 'token', 'secret', 'password']) {
    assert.throws(() => normalizeAuthProfile({ kind: AUTH_KIND.BEARER, [key]: 'x' }), /jamais le secret/, key);
  }
  // Même une clé présente mais vide est refusée : c'est la forme qui compte.
  assert.throws(() => normalizeAuthProfile({ kind: AUTH_KIND.BEARER, token: '' }), /jamais le secret/);
});

test('un profil public est sûr à persister et à afficher', () => {
  const profile = publicProfile({
    kind: AUTH_KIND.BEARER, secretConfigured: true,
    maskedValue: maskSecret('eyJhbGciOiJIUzI1NiJ9.charge.signature'),
    value: 'SECRET-REEL', token: 'T', password: 'P'
  });
  const blob = JSON.stringify(profile);
  assert.ok(!blob.includes('SECRET-REEL'));
  assert.ok(!blob.includes('charge.signature'));
  assert.equal(profile.secretConfigured, true);
  assert.match(profile.maskedValue, /^eyJh…•/);
  assert.ok(profile.statusLabel);
});

test('le masque identifie sans révéler', () => {
  assert.equal(maskSecret(''), '');
  assert.equal(maskSecret('court'), '••• (5 caractères)', 'un secret court ne montre rien');
  const masked = maskSecret('eyJhbGciOiJIUzI1NiJ9abcdefgh');
  assert.match(masked, /^eyJh…••• \(28 caractères\)$/);
  assert.ok(!masked.includes('abcdefgh'));
});

test('un en-tête réservé ou invalide est refusé', () => {
  for (const header of ['Host', 'content-length', 'Connection', 'transfer-encoding']) {
    assert.throws(() => normalizeAuthProfile({ kind: AUTH_KIND.HEADER, header }), /ne peut pas être défini|invalide/, header);
  }
  for (const header of ['', 'X Api Key', 'x:api', 'a'.repeat(60)]) {
    assert.throws(() => normalizeAuthProfile({ kind: AUTH_KIND.HEADER, header }), /invalide/, JSON.stringify(header));
  }
  assert.equal(normalizeAuthProfile({ kind: AUTH_KIND.HEADER, header: 'X-Api-Key' }).header, 'X-Api-Key');
});

test('la clé SecretStorage est dérivée, jamais choisie', () => {
  assert.equal(secretKeyFor('prod'), 'securityCenter.dynamic.auth.prod');
  for (const id of ['../../etc/passwd', 'a b', '', 'x'.repeat(80), 'a/b']) {
    assert.throws(() => secretKeyFor(id), /invalide/, JSON.stringify(id));
  }
});

test('les en-têtes d’authentification sont construits au moment de l’usage', () => {
  const bearer = normalizeAuthProfile({ kind: AUTH_KIND.BEARER });
  assert.deepEqual(authHeadersFor(bearer, 'abc123'), { Authorization: 'Bearer abc123' });
  assert.deepEqual(authHeadersFor(bearer, 'Bearer abc123'), { Authorization: 'Bearer abc123' }, 'pas de double préfixe');
  const cookie = normalizeAuthProfile({ kind: AUTH_KIND.COOKIE, cookieName: 'sid' });
  assert.deepEqual(authHeadersFor(cookie, 'abc'), { Cookie: 'sid=abc' });
  assert.deepEqual(authHeadersFor(cookie, 'sid=abc; other=1'), { Cookie: 'sid=abc; other=1' });
  const custom = normalizeAuthProfile({ kind: AUTH_KIND.HEADER, header: 'X-Api-Key' });
  assert.deepEqual(authHeadersFor(custom, 'k'), { 'X-Api-Key': 'k' });
  // Sans secret, la requête reste anonyme au lieu d'être cassée.
  assert.deepEqual(authHeadersFor(bearer, ''), {});
  assert.deepEqual(authHeadersFor(normalizeAuthProfile({ kind: AUTH_KIND.NONE }), 'x'), {});
  assert.deepEqual(authHeadersFor(null, 'x'), {});
});

test('la validation distingue refus, expiration et indécision', () => {
  assert.equal(interpretValidation({ status: 200 }).status, AUTH_STATUS.VALID);
  assert.equal(interpretValidation({ status: 204 }).status, AUTH_STATUS.VALID);
  assert.equal(interpretValidation({ status: 401, previousStatus: AUTH_STATUS.CONFIGURED }).status, AUTH_STATUS.INVALID);
  assert.equal(interpretValidation({ status: 403, previousStatus: AUTH_STATUS.VALID }).status, AUTH_STATUS.EXPIRED);
  assert.equal(interpretValidation({ status: 500 }).status, AUTH_STATUS.UNKNOWN);
  assert.equal(interpretValidation({ error: 'timeout' }).status, AUTH_STATUS.UNKNOWN);
  assert.equal(interpretValidation({}).status, AUTH_STATUS.UNKNOWN);
});

test('un jeton configuré ne suffit PAS à revendiquer une couverture authentifiée', () => {
  const profile = normalizeAuthProfile({ kind: AUTH_KIND.BEARER, secretConfigured: true });
  const configuredOnly = authenticatedCoverageClaim({ profile, validated: false, protectedEndpointsReached: 12 });
  assert.equal(configuredOnly.authenticated, false);
  assert.match(configuredOnly.reason, /n’a pas été validée/);
  const noEndpoint = authenticatedCoverageClaim({ profile, validated: true, protectedEndpointsReached: 0 });
  assert.equal(noEndpoint.authenticated, false);
  assert.match(noEndpoint.reason, /aucun endpoint protégé/);
  const real = authenticatedCoverageClaim({ profile, validated: true, protectedEndpointsReached: 18 });
  assert.equal(real.authenticated, true);
  assert.match(real.reason, /18 endpoint/);
  // Sans profil, le scan est anonyme et le dit.
  assert.equal(authenticatedCoverageClaim({}).authenticated, false);
});

// ============================================== garanties transverses

test('aucun module dynamique ne lance de processus ni ne planifie de travail', () => {
  for (const file of ['dynamic-inventory.js', 'dynamic-retest.js', 'dynamic-auth.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
    assert.ok(!/child_process|execFile|spawn\(/.test(source), `${file} lance un processus`);
    assert.ok(!/setInterval|setTimeout|requestAnimationFrame/.test(source), `${file} planifie du travail`);
    // Aucun de ces modules ne fait de réseau : le transport reste ailleurs.
    assert.ok(!/require\('https?'\)/.test(source), `${file} ouvre un transport`);
  }
});

test('l’inventaire réutilise le moteur d’association existant', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dynamic-inventory.js'), 'utf8');
  assert.match(source, /require\('\.\/dashboard'\)/);
  assert.match(source, /associationFor/);
  // Et n'implémente pas sa propre logique de rapprochement.
  assert.ok(!/function\s+associationFor/.test(source), 'aucun second moteur d’association');
});

test('la protection de cible locale du replay reste intacte', () => {
  const { validateLocalUrl } = require('../src/http-scenarios');
  assert.throws(() => validateLocalUrl('http://example.com/x'), /locales autorisées/);
  assert.throws(() => validateLocalUrl('file:///etc/passwd'), /HTTP et HTTPS/);
  assert.ok(validateLocalUrl('http://127.0.0.1:3000/x'));
});
