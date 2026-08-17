const test = require('node:test');
const assert = require('node:assert/strict');

const {
  associationFor, linkedFindingsForScenario, linkedFindingsWithConfidence,
  transactionParameters, buildSafeHttpPreview, buildDashboardModel, renderDashboardHtml,
  ASSOCIATION_CONFIDENCE, ZAP_UNKNOWN_METHOD, endpointPath
} = require('../src/dashboard');

const ORIGIN = 'http://127.0.0.1:3000';

const finding = (path, method, title, parameter = '') => ({
  endpoint: `${ORIGIN}${path}`, method, title, parameter, tool: 'ZAP', rawSeverity: 'HIGH'
});

const transaction = (path, method, extra = {}) => ({
  request: { url: `${ORIGIN}${path}`, method, headers: {}, ...extra },
  response: { statusCode: 200, headers: {} }
});

// ------------------------------- une méthode qui diverge est un rejet net

test('un endpoint ne peut pas hériter d’un finding appartenant à un autre', () => {
  const findings = [finding('/rest/user/login', 'POST', 'Injection SQL', 'email')];
  // C'est l'invariant central : GET /foo n'hérite jamais de POST /api/login.
  assert.deepEqual(linkedFindingsForScenario(transaction('/foo', 'GET'), findings), []);
  assert.deepEqual(linkedFindingsForScenario(transaction('/rest/user/login', 'GET'), findings), []);
  assert.deepEqual(linkedFindingsForScenario(transaction('/rest/user', 'POST'), findings), []);
  // Et la bonne transaction, elle, retrouve bien son finding.
  assert.equal(linkedFindingsForScenario(transaction('/rest/user/login', 'POST'), findings).length, 1);
});

test('une méthode différente est refusée même sur un chemin identique', () => {
  const findings = [finding('/api/orders', 'DELETE', 'Contrôle d’accès manquant')];
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'HEAD']) {
    assert.equal(associationFor(transaction('/api/orders', method), findings[0]).confidence, null,
      `${method} ne doit pas correspondre à DELETE`);
  }
  assert.equal(associationFor(transaction('/api/orders', 'DELETE'), findings[0]).confidence, ASSOCIATION_CONFIDENCE.STRONG);
});

test('rien n’est associé sur un hôte, une cible ou un CWE partagés', () => {
  const sameHostDifferentPath = finding('/api/products', 'GET', 'XSS');
  assert.equal(associationFor(transaction('/api/users', 'GET'), sameHostDifferentPath).confidence, null);
  // Un finding sans endpoint n'est jamais rattaché, quel que soit le reste.
  assert.equal(associationFor(transaction('/api/users', 'GET'), { cwe: 'CWE-79', method: 'GET', tool: 'ZAP' }).confidence, null);
  // Un finding statique (pas d'endpoint) ne se rattache pas au trafic.
  assert.equal(associationFor(transaction('/api/users', 'GET'), { file: 'src/a.js', startLine: 10, tool: 'Semgrep' }).confidence, null);
});

// ------------------------------------------------- les quatre niveaux

test('EXACT exige que le paramètre soit réellement exercé par la requête', () => {
  const sqli = finding('/rest/user/login', 'POST', 'Injection SQL', 'email');
  const jsonBody = transaction('/rest/user/login', 'POST', { body: JSON.stringify({ email: 'a@b.c', password: 'x' }) });
  const exact = associationFor(jsonBody, sqli);
  assert.equal(exact.confidence, ASSOCIATION_CONFIDENCE.EXACT);
  assert.ok(exact.reasons.some((reason) => /réellement présent/.test(reason)));
  // Le même finding sur une requête qui n'exerce pas ce paramètre reste STRONG.
  const other = associationFor(transaction('/rest/user/login', 'POST', { body: JSON.stringify({ captcha: '1' }) }), sqli);
  assert.equal(other.confidence, ASSOCIATION_CONFIDENCE.STRONG);
  assert.ok(other.reasons.some((reason) => /absent de cette requête/.test(reason)));
});

test('le paramètre est reconnu dans la query, le corps formulaire et le JSON', () => {
  assert.ok(transactionParameters(transaction('/search?q=abc&page=2', 'GET')).has('q'));
  assert.ok(transactionParameters(transaction('/login', 'POST', { body: 'email=a%40b.c&password=x' })).has('email'));
  assert.ok(transactionParameters(transaction('/login', 'POST', { body: '{"email":"a@b.c"}' })).has('email'));
  assert.ok(transactionParameters(transaction('/login', 'POST', { parameters: [{ name: 'token', location: 'header' }] })).has('token'));
  // Un corps illisible n'invente aucun paramètre.
  assert.equal(transactionParameters(transaction('/x', 'POST', { body: '<<binary>>' })).size, 0);
});

test('STRONG quand le chemin et la méthode concordent sans preuve de paramètre', () => {
  const association = associationFor(transaction('/', 'GET'), finding('/', 'GET', 'CSP manquant'));
  assert.equal(association.confidence, ASSOCIATION_CONFIDENCE.STRONG);
  assert.ok(association.reasons.some((reason) => /Méthode identique : GET/.test(reason)));
});

test('PROBABLE quand le scanner n’a pas fourni la méthode, et c’est dit', () => {
  // Le normalisateur ZAP stocke le littéral « HTTP » quand l'alerte n'a pas de
  // méthode. Comparé à un vrai GET, ce sentinelle faisait disparaître le lien.
  const noMethod = finding('/', ZAP_UNKNOWN_METHOD, 'Cookie sans attribut Secure');
  const association = associationFor(transaction('/', 'GET'), noMethod);
  assert.equal(association.confidence, ASSOCIATION_CONFIDENCE.PROBABLE);
  assert.ok(association.reasons.some((reason) => /non fournie par le scanner/.test(reason)));
  // Un finding sans méthode du tout se comporte pareil.
  assert.equal(associationFor(transaction('/', 'GET'), finding('/', '', 'Header manquant')).confidence, ASSOCIATION_CONFIDENCE.PROBABLE);
});

test('un sentinelle de méthode ne fait plus disparaître un lien légitime', () => {
  const findings = [finding('/', ZAP_UNKNOWN_METHOD, 'X-Frame-Options manquant')];
  // Avant, l'égalité 'HTTP' === 'GET' échouait et le finding n'apparaissait nulle part.
  assert.equal(linkedFindingsForScenario(transaction('/', 'GET'), findings).length, 1);
});

// -------------------------------- plusieurs findings sur la même racine

test('plusieurs alertes passives sur GET / sont légitimes et hiérarchisées', () => {
  const findings = [
    finding('/', 'GET', 'CSP manquant'),
    finding('/', 'GET', 'X-Frame-Options manquant'),
    finding('/', ZAP_UNKNOWN_METHOD, 'Cookie sans attribut HttpOnly'),
    finding('/rest/user/login', 'POST', 'Injection SQL', 'email')
  ];
  const linked = linkedFindingsWithConfidence(transaction('/', 'GET'), findings);
  // Trois alertes appartiennent réellement à la racine ; celle du login, non.
  assert.equal(linked.length, 3);
  assert.ok(!linked.some((entry) => entry.finding.title === 'Injection SQL'));
  assert.deepEqual(linked.map((entry) => entry.confidence),
    [ASSOCIATION_CONFIDENCE.STRONG, ASSOCIATION_CONFIDENCE.STRONG, ASSOCIATION_CONFIDENCE.PROBABLE]);
});

// ------------------------------------------------- restitution dans l'UI

test('l’aperçu HTTP expose le niveau d’association et ce qu’il vaut', () => {
  const findings = [
    finding('/rest/user/login', 'POST', 'Injection SQL', 'email'),
    finding('/rest/user/login', ZAP_UNKNOWN_METHOD, 'Divulgation d’information')
  ];
  const preview = buildSafeHttpPreview(
    transaction('/rest/user/login', 'POST', { body: JSON.stringify({ email: 'a@b.c' }) }),
    findings
  );
  const [exact, probable] = preview.linkedFindings;
  assert.equal(exact.confidence, ASSOCIATION_CONFIDENCE.EXACT);
  assert.equal(exact.proven, true);
  assert.match(exact.confidenceLabel, /exacte/);
  assert.equal(probable.confidence, ASSOCIATION_CONFIDENCE.PROBABLE);
  assert.equal(probable.proven, false);
  // Une association non prouvée doit le dire explicitement.
  assert.match(probable.confidenceLabel, /non prouvée/);
});

test('l’aperçu n’attache aucun finding d’un autre endpoint', () => {
  const preview = buildSafeHttpPreview(transaction('/', 'GET'), [finding('/rest/user/login', 'POST', 'Injection SQL', 'email')]);
  assert.deepEqual(preview.linkedFindings, []);
});

// ------------------------------------------- état de la cible et preuve

test('l’état de la cible porte la preuve qui l’a établi', () => {
  const verified = buildDashboardModel([], [], {
    dynamicTargetUrl: ORIGIN, dynamicTargetState: 'online',
    dynamicTargetEvidence: { source: 'zap-scan', at: '2026-08-17T09:00:00.000Z', target: ORIGIN }
  });
  assert.equal(verified.dynamicTargetState, 'online');
  assert.equal(verified.dynamicTargetEvidence.source, 'zap-scan');
  const html = renderDashboardHtml(verified, 'n', 'dynamic', 'light');
  assert.match(html, /Confirmée par l’analyse ZAP/);
  assert.ok(!html.includes('n’a pas encore été vérifiée'), 'plus de contradiction avec un scan terminé');
});

test('sans preuve, la cible reste explicitement non vérifiée', () => {
  const unknown = buildDashboardModel([], [], { dynamicTargetUrl: ORIGIN, dynamicTargetState: 'unknown' });
  assert.equal(unknown.dynamicTargetEvidence, null);
  const html = renderDashboardHtml(unknown, 'n', 'dynamic', 'light');
  assert.match(html, /Inconnue \/ non vérifiée/);
  assert.match(html, /n’a pas encore été vérifiée/);
  // Aucune date n'est inventée.
  assert.ok(!html.includes('Confirmée par'));
});

// ------------------------------------------------------ pas de fuite

test('aucun secret ne franchit l’association ni l’aperçu', () => {
  const preview = buildSafeHttpPreview(
    transaction('/rest/user/login', 'POST', {
      headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig', cookie: 'session=abc123' },
      body: JSON.stringify({ email: 'a@b.c', password: 'Sup3rSecret!' })
    }),
    [finding('/rest/user/login', 'POST', 'Injection SQL', 'email')]
  );
  const blob = JSON.stringify(preview);
  assert.ok(!blob.includes('eyJhbGciOiJIUzI1NiJ9'), 'aucun JWT');
  assert.ok(!blob.includes('abc123'), 'aucun cookie de session');
  assert.ok(!blob.includes('Sup3rSecret!'), 'aucun mot de passe');
  // Le lien reste correct malgré la rédaction.
  assert.equal(preview.linkedFindings.length, 1);
});

test('la normalisation de chemin ne fusionne pas des endpoints distincts', () => {
  assert.equal(endpointPath(`${ORIGIN}/api/users/12`), '/api/users/12');
  assert.notEqual(endpointPath(`${ORIGIN}/api/users/12`), endpointPath(`${ORIGIN}/api/users/37`));
  // Un finding sur /api/users/12 ne se rattache pas à /api/users/37.
  assert.equal(associationFor(transaction('/api/users/37', 'GET'), finding('/api/users/12', 'GET', 'IDOR')).confidence, null);
  // Seule la barre finale est neutralisée, ce qui est sûr.
  assert.equal(endpointPath(`${ORIGIN}/api/users/`), '/api/users');
});
