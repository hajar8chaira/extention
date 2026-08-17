const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeJavaScriptText, analyzeLiveDocument } = require('../src/live/liveDetector');
const { JAVASCRIPT_LIVE_RULES } = require('../src/live/liveRules/javascriptRules');
const { analyzeFindings } = require('../src/pipeline');
const { correlateSast, tierFor, TIER_LABELS } = require('../src/intelligence/correlation-v2');
const { unifyFindings, unifiedFinding } = require('../src/intelligence/finding-model');
const { evaluateReachability, isStaticAsset } = require('../src/intelligence/reachability');
const { prioritizeFinding, WEIGHTS } = require('../src/intelligence/prioritization');

const scan = (text) => analyzeJavaScriptText({ text, uri: 'file:///a.js', documentVersion: 1, rules: JAVASCRIPT_LIVE_RULES });
const ids = (text) => new Set(scan(text).map((finding) => finding.ruleId));

// --------------------------------------------------- détecteurs Live (B14)

const DETECTORS = [
  ['unsafe-eval', 'eval(req.query.x);'],
  ['unsafe-function-constructor', 'const f = new Function(req.query.body);'],
  ['sql-string-concatenation', 'const q = "SELECT * FROM users WHERE id = \'" + req.query.id + "\'";'],
  ['dynamic-command-execution', 'child_process.exec(req.query.cmd);'],
  ['unsafe-innerhtml', 'el.innerHTML = req.query.html;'],
  ['weak-hash', 'crypto.createHash("md5").update(x);'],
  ['hardcoded-credential', 'const apiKey = "' + 'sk_' + 'live_' + '51H8xQ2eZvKYlo2Cabcdefgh";'],
  ['tls-verification-disabled', 'new https.Agent({ rejectUnauthorized: false });'],
  ['potential-path-traversal', 'fs.readFileSync("../" + req.query.path);'],
  ['shell-child-process', 'spawn("sh", [req.query.a], { shell: true });']
];

for (const [ruleId, code] of DETECTORS) {
  test(`détecte ${ruleId}`, () => {
    assert.ok(ids(code).has(ruleId), `${ruleId} non détecté sur : ${code}`);
  });
}

test('les dix détecteurs se déclenchent sur un fichier réaliste', () => {
  const text = DETECTORS.map(([, code]) => code).join('\n');
  const detected = ids(text);
  for (const [ruleId] of DETECTORS) assert.ok(detected.has(ruleId), `${ruleId} manquant`);
});

test('exec recevant directement une donnée de requête est détecté', () => {
  // Forme la plus dangereuse et historiquement manquée : aucune concaténation.
  assert.ok(ids('child_process.exec(req.query.cmd);').has('dynamic-command-execution'));
  assert.ok(ids('exec(req.body.command);').has('dynamic-command-execution'));
  assert.ok(ids('exec(`ls ${req.query.dir}`);').has('dynamic-command-execution'));
  assert.ok(ids('exec("ls " + req.query.dir);').has('dynamic-command-execution'));
});

test('une requête SQL assemblée en variable est détectée', () => {
  // La chaîne SQL contient une apostrophe : le motif doit la tolérer.
  assert.ok(ids('const q = "SELECT * FROM users WHERE name = \'" + req.query.name + "\'";').has('sql-string-concatenation'));
  assert.ok(ids('const q = `SELECT * FROM t WHERE id = ${req.params.id}`;').has('sql-string-concatenation'));
  assert.ok(ids('db.query("SELECT * FROM t WHERE id = " + req.query.id);').has('sql-string-concatenation'));
});

test('le code sûr ne déclenche aucun détecteur', () => {
  const safe = [
    'const q = "SELECT * FROM users WHERE id = ?"; db.query(q, [id]);',
    'crypto.createHash("sha256").update(x);',
    'execFile("git", ["status"]);',
    'el.textContent = req.query.html;',
    'new https.Agent({ rejectUnauthorized: true });'
  ].join('\n');
  assert.equal(scan(safe).length, 0);
});

test('les commentaires ne déclenchent pas de détection', () => {
  assert.equal(scan('// eval(req.query.x);\n/* exec(req.query.cmd); */').length, 0);
});

test('un fichier en cours de frappe n’est pas analysé', () => {
  // Parenthèses non équilibrées : le fichier est incomplet.
  assert.equal(scan('eval(req.query.x').length, 0);
});

test('les langages non pris en charge sont ignorés', async () => {
  const findings = await analyzeLiveDocument({ languageId: 'python', version: 1, uri: 'file:///a.py', getText: () => 'eval(request.args)' });
  assert.deepEqual(findings, []);
});

test('l’annulation interrompt l’analyse', () => {
  const findings = analyzeJavaScriptText({
    text: DETECTORS.map(([, code]) => code).join('\n'), uri: 'file:///a.js',
    documentVersion: 1, rules: JAVASCRIPT_LIVE_RULES, signal: { aborted: true }
  });
  assert.deepEqual(findings, []);
});

// ------------------------------------------- corrélation à trois niveaux

function sast(id, tool, line, cwe = 'CWE-89', ruleId = 'sqli') {
  return unifiedFinding({
    id, tool, ruleId, title: 'Injection SQL', severity: 'error', rawSeverity: 'HIGH',
    category: 'security', cwe, file: 'server.js', absolutePath: '/r/server.js',
    startLine: line, startColumn: 0
  });
}

test('les niveaux de corrélation dérivent de la confiance', () => {
  assert.equal(tierFor('high'), 'confirmed');
  assert.equal(tierFor('medium'), 'probable');
  assert.equal(tierFor('low'), 'candidate');
  assert.equal(tierFor(undefined), 'candidate');
  assert.equal(TIER_LABELS.confirmed, 'Confirmée');
});

test('lignes proches et CWE commun donnent une corrélation confirmée', () => {
  const [cluster] = correlateSast([sast('a', 'Semgrep', 41), sast('b', 'SonarQube', 42)]);
  assert.equal(cluster.tier, 'confirmed');
  assert.equal(cluster.confidence, 'high');
});

test('même fichier et même CWE mais lignes éloignées reste candidate', () => {
  const [cluster] = correlateSast([sast('a', 'Semgrep', 10), sast('b', 'SonarQube', 400)]);
  assert.equal(cluster.tier, 'candidate');
  assert.equal(cluster.confidence, 'low');
  assert.match(cluster.reasons.join(' '), /non prouvé/);
});

test('une corrélation candidate n’apporte aucun point de priorité', () => {
  const candidate = { ...sast('a', 'Semgrep', 10), correlation: { corroboratingTools: ['SonarQube'], confidence: 'low', tier: 'candidate', tools: ['Semgrep', 'SonarQube'] } };
  const confirmed = { ...sast('a', 'Semgrep', 10), correlation: { corroboratingTools: ['SonarQube'], confidence: 'high', tier: 'confirmed', tools: ['Semgrep', 'SonarQube'] } };
  const candidateScore = prioritizeFinding(candidate).priority;
  const confirmedScore = prioritizeFinding(confirmed).priority;
  assert.equal(confirmedScore.score - candidateScore.score, WEIGHTS.correlationTier.confirmed);
  // La corrélation candidate reste visible, mais pèse zéro.
  const reason = candidateScore.reasons.find((item) => item.kind === 'correlation');
  assert.equal(reason.points, 0);
  assert.match(reason.label, /candidate, non confirmée/);
});

test('une corrélation probable pèse moins qu’une confirmée', () => {
  const base = sast('a', 'Semgrep', 10);
  const probable = prioritizeFinding({ ...base, correlation: { corroboratingTools: ['Snyk'], confidence: 'medium', tier: 'probable', tools: ['Semgrep', 'Snyk'] } }).priority.score;
  const confirmed = prioritizeFinding({ ...base, correlation: { corroboratingTools: ['Snyk'], confidence: 'high', tier: 'confirmed', tools: ['Semgrep', 'Snyk'] } }).priority.score;
  const none = prioritizeFinding(base).priority.score;
  assert.ok(none < probable && probable < confirmed);
});

test('le résumé compte les niveaux séparément', () => {
  const { correlation } = analyzeFindings([
    ...['Semgrep', 'SonarQube'].map((tool, index) => sast(`near-${index}`, tool, 41 + index)),
    ...['Semgrep', 'Snyk'].map((tool, index) => sast(`far-${index}`, tool, 100 + index * 300, 'CWE-79', 'xss'))
  ], {});
  assert.equal(correlation.byTier.confirmed + correlation.byTier.candidate, correlation.total);
  assert.equal(correlation.confirmed, correlation.byTier.confirmed);
});

// ------------------------------------- reachability : code vs runtime

function zap(endpoint, id = endpoint) {
  return unifiedFinding({
    id, tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint,
    method: 'GET', absolutePath: '', title: 'Header manquant', rawSeverity: 'LOW'
  });
}

test('les ressources statiques sont reconnues', () => {
  for (const asset of ['/style.css', '/app.js', '/logo.svg', '/favicon.ico', '/robots.txt', '/f.woff2']) {
    assert.equal(isStaticAsset(`http://x${asset}`), true, asset);
  }
  assert.equal(isStaticAsset('http://x/api/login'), false);
});

test('une observation runtime ne compte pas comme atteignabilité de code', () => {
  const { summary } = evaluateReachability(unifyFindings([
    { id: 'z1', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/style.css', method: 'GET', absolutePath: '', title: 'x', rawSeverity: 'LOW' },
    { id: 'z2', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/api/login', method: 'POST', absolutePath: '', title: 'y', rawSeverity: 'HIGH' }
  ]));
  assert.equal(summary.runtime.observed, 2);
  assert.equal(summary.runtime.staticAssets, 1);
  assert.equal(summary.runtime.applicationEndpoints, 1);
  // Aucun de ces résultats n'apparaît dans le décompte d'atteignabilité du code.
  assert.deepEqual(summary.statusCounts, {});
});

test('un endpoint applicatif observé pèse plus qu’une ressource statique', () => {
  const { findings } = evaluateReachability(unifyFindings([
    { id: 'z1', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/style.css', method: 'GET', absolutePath: '', title: 'x', rawSeverity: 'HIGH' },
    { id: 'z2', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/api/login', method: 'POST', absolutePath: '', title: 'y', rawSeverity: 'HIGH' }
  ]));
  const [asset, endpoint] = findings.map((finding) => prioritizeFinding(finding).priority);
  assert.ok(endpoint.score > asset.score);
  assert.equal(asset.reasons.find((reason) => reason.kind === 'runtime').points, WEIGHTS.runtimeStaticAsset);
  assert.equal(endpoint.reasons.find((reason) => reason.kind === 'runtime').points, WEIGHTS.runtimeObserved);
});

test('la raison de priorité nomme la source runtime réelle', () => {
  const { findings } = evaluateReachability(unifyFindings([
    { id: 'z', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/api/login', method: 'POST', absolutePath: '', title: 'y', rawSeverity: 'HIGH' }
  ]));
  const reason = prioritizeFinding(findings[0]).priority.reasons.find((item) => item.kind === 'runtime');
  assert.match(reason.label, /Observé à l’exécution par zap/);
  assert.match(reason.label, /POST http:\/\/x\/api\/login/);
});
