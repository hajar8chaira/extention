const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { unifiedFinding, unifyFindings, cweList, vulnerabilityIds, ecosystemOf, stageOf } = require('../src/intelligence/finding-model');
const { correlateFindingsV2, correlateSca, correlateSast, correlateIac, correlateDastSast, ruleTokens } = require('../src/intelligence/correlation-v2');
const { extractRoutes, routePattern, pathMatchesRoute, matchEndpoint, buildRouteMap } = require('../src/intelligence/route-map');

function raw(overrides = {}) {
  return {
    id: `f-${Math.random().toString(36).slice(2, 8)}`, tool: 'Semgrep', ruleId: 'rule', title: 'Titre',
    severity: 'error', rawSeverity: 'HIGH', category: 'security', file: 'src/a.js', absolutePath: '/repo/src/a.js',
    startLine: 9, startColumn: 0, confidence: 'medium', ...overrides
  };
}

function dependency(overrides = {}) {
  return unifiedFinding(raw({
    category: 'dependency', file: 'package-lock.json', absolutePath: '/repo/package-lock.json',
    unlocated: true, startLine: 0, packageName: 'lodash', installedVersion: '4.17.11',
    vulnerabilityAliases: ['CVE-2020-8203'], ruleId: 'CVE-2020-8203', ecosystem: 'npm', ...overrides
  }));
}

function sast(overrides = {}) {
  return unifiedFinding(raw(overrides));
}

// --------------------------------------------------------- modèle unifié

test('le modèle unifié n’invente aucun champ absent', () => {
  const finding = unifiedFinding(raw({ tool: 'Semgrep' }));
  assert.equal(finding.endpoint, '');
  assert.equal(finding.package, '');
  assert.equal(finding.image, '');
  assert.equal(finding.reachability, null);
  assert.equal(finding.priority, null);
  assert.equal(finding.correlation, null);
});

test('un résultat ZAP n’expose pas de fichier source', () => {
  const zap = unifiedFinding(raw({
    tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', file: 'POST http://x/api/login',
    absolutePath: '', endpoint: 'http://x/api/login', method: 'POST', parameter: 'username', unlocated: false
  }));
  assert.equal(zap.file, '');
  assert.equal(zap.line, null);
  assert.equal(zap.endpoint, 'http://x/api/login');
  assert.equal(zap.stage, 'dast');
});

test('un résultat de dépendance n’est jamais localisé à une ligne', () => {
  const finding = dependency();
  assert.equal(finding.file, '');
  assert.equal(finding.line, null);
  assert.equal(finding.manifest, 'package-lock.json');
  assert.equal(finding.stage, 'sca');
});

test('un manifeste rapporté à l’offset 0 ne devient pas « ligne 1 »', () => {
  // Trivy et OSV rapportent leurs CVE au décalage 0 sans marquer `unlocated` :
  // sans cette règle, le gate afficherait un « package-lock.json:1 » inventé.
  const trivyLike = unifiedFinding(raw({
    tool: 'Trivy', category: 'dependency', file: 'package-lock.json',
    absolutePath: '/repo/package-lock.json', startLine: 0, packageName: 'lodash'
  }));
  assert.equal(trivyLike.line, null);
  assert.equal(trivyLike.file, '');
  assert.equal(trivyLike.manifest, 'package-lock.json');
  // Une position réellement résolue par le scanner reste conservée.
  const located = unifiedFinding(raw({
    tool: 'Trivy', category: 'dependency', file: 'Dockerfile',
    absolutePath: '/repo/Dockerfile', startLine: 11, packageName: 'openssl'
  }));
  assert.equal(located.line, 12);
});

test('la métadonnée brute du scanner est préservée', () => {
  const original = raw({ tool: 'Trivy', status: 'fixed', vendorSpecific: { x: 1 } });
  const finding = unifiedFinding(original);
  assert.equal(finding.raw, original);
  assert.deepEqual(finding.raw.vendorSpecific, { x: 1 });
});

test('extrait CWE et CVE sans confondre un nom de règle avec un identifiant', () => {
  assert.deepEqual(cweList({ cwe: 'CWE-89, CWE-79' }), ['CWE-89', 'CWE-79']);
  assert.deepEqual(vulnerabilityIds({ ruleId: 'javascript.sqli', vulnerabilityAliases: [] }).cve, []);
  assert.deepEqual(vulnerabilityIds({ ruleId: 'CVE-2020-8203' }).cve, ['CVE-2020-8203']);
  assert.deepEqual(vulnerabilityIds({ vulnerabilityAliases: ['SNYK-JS-LODASH-1', 'CVE-2020-8203'] }).vendor, ['SNYK-JS-LODASH-1']);
});

test('déduit l’écosystème sans deviner à partir d’un chemin arbitraire', () => {
  assert.equal(ecosystemOf({ ecosystem: 'npm' }), 'npm');
  assert.equal(ecosystemOf({ packageManager: 'pip' }), 'pypi');
  assert.equal(ecosystemOf({ file: 'api/requirements.txt' }), 'pypi');
  assert.equal(ecosystemOf({ file: 'src/random/file.txt' }), '');
});

test('classe chaque finding dans une étape du pipeline', () => {
  assert.equal(stageOf({ category: 'secret' }), 'secrets');
  assert.equal(stageOf({ category: 'dependency' }), 'sca');
  assert.equal(stageOf({ category: 'misconfiguration' }), 'iac');
  assert.equal(stageOf({ category: 'dynamic' }), 'dast');
  assert.equal(stageOf({ category: 'security' }), 'sast');
  assert.equal(unifyFindings([raw(), raw()]).length, 2);
});

// ---------------------------------------------------------- corrélation SCA

test('Trivy et OSV signalant la même CVE forment une seule vulnérabilité', () => {
  const clusters = correlateSca([
    dependency({ id: 't1', tool: 'Trivy' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].type, 'sca');
  assert.equal(clusters[0].confidence, 'high');
  assert.deepEqual(clusters[0].tools, ['OSV-Scanner', 'Trivy']);
  assert.ok(clusters[0].reasons.some((reason) => reason.includes('CVE-2020-8203')));
});

test('Trivy et Snyk signalant la même CVE sont corrélés, preuves préservées', () => {
  const { clusters } = correlateFindingsV2([
    dependency({ id: 't1', tool: 'Trivy' }),
    dependency({ id: 's1', tool: 'Snyk', vulnerabilityAliases: ['SNYK-JS-LODASH-567746', 'CVE-2020-8203'] })
  ]);
  assert.equal(clusters.length, 1);
  assert.deepEqual(clusters[0].tools, ['Snyk', 'Trivy']);
  assert.equal(clusters[0].sources.length, 2);
  assert.ok(clusters[0].sources.every((source) => source.findingId && source.tool));
});

test('trois scanners sur la même CVE forment un seul groupe', () => {
  const { clusters, findings } = correlateFindingsV2([
    dependency({ id: 't1', tool: 'Trivy' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner' }),
    dependency({ id: 's1', tool: 'Snyk' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].count, 3);
  assert.deepEqual(findings[0].correlation.corroboratingTools.sort(), ['OSV-Scanner', 'Snyk']);
});

test('des CVE différentes sur le même paquet ne sont pas fusionnées', () => {
  const clusters = correlateSca([
    dependency({ id: 't1', tool: 'Trivy', vulnerabilityAliases: ['CVE-2020-8203'], ruleId: 'CVE-2020-8203' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner', vulnerabilityAliases: ['CVE-2021-23337'], ruleId: 'CVE-2021-23337' })
  ]);
  assert.equal(clusters.length, 0);
});

test('la même CVE sur deux paquets différents n’est pas fusionnée', () => {
  const clusters = correlateSca([
    dependency({ id: 't1', tool: 'Trivy', packageName: 'lodash' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner', packageName: 'underscore' })
  ]);
  assert.equal(clusters.length, 0);
});

test('un écosystème différent empêche la fusion', () => {
  const clusters = correlateSca([
    dependency({ id: 't1', tool: 'Trivy', ecosystem: 'npm' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner', ecosystem: 'pypi' })
  ]);
  assert.equal(clusters.length, 0);
});

test('un désaccord de version réduit la confiance sans casser la corrélation', () => {
  const clusters = correlateSca([
    dependency({ id: 't1', tool: 'Trivy', installedVersion: '4.17.11' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner', installedVersion: '4.17.15' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].confidence, 'medium');
  assert.ok(clusters[0].reasons.some((reason) => reason.includes('Versions rapportées différentes')));
});

test('un seul scanner ne crée pas de corrélation', () => {
  assert.equal(correlateSca([dependency({ id: 't1', tool: 'Trivy' }), dependency({ id: 't2', tool: 'Trivy', packageName: 'lodash' })]).length, 0);
});

// --------------------------------------------------------- corrélation SAST

test('un CWE commun seul ne fusionne jamais deux fichiers différents', () => {
  const clusters = correlateSast([
    sast({ id: 'a', tool: 'Semgrep', file: 'src/a.js', absolutePath: '/repo/src/a.js', cwe: 'CWE-89' }),
    sast({ id: 'b', tool: 'SonarQube', file: 'src/b.js', absolutePath: '/repo/src/b.js', cwe: 'CWE-89' })
  ]);
  assert.equal(clusters.length, 0);
});

test('même fichier, lignes proches et CWE commun donnent une confiance haute', () => {
  const clusters = correlateSast([
    sast({ id: 'a', tool: 'Semgrep', startLine: 41, cwe: 'CWE-89' }),
    sast({ id: 'b', tool: 'SonarQube', startLine: 42, cwe: 'CWE-89' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].confidence, 'high');
  assert.ok(clusters[0].reasons.some((reason) => reason.includes('CWE commun')));
});

test('même fichier mais lignes éloignées reste une corrélation faible et visible', () => {
  const clusters = correlateSast([
    sast({ id: 'a', tool: 'Semgrep', startLine: 10, cwe: 'CWE-89' }),
    sast({ id: 'b', tool: 'Snyk', startLine: 400, cwe: 'CWE-89' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].confidence, 'low');
});

test('une famille de règle commune corrèle sans CWE partagé', () => {
  const clusters = correlateSast([
    sast({ id: 'a', tool: 'Semgrep', ruleId: 'javascript.lang.security.sql-injection', startLine: 20, cwe: '' }),
    sast({ id: 'b', tool: 'Snyk', ruleId: 'javascript/SqlInjection/sql', startLine: 21, cwe: '' })
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].confidence, 'medium');
  assert.ok(ruleTokens('javascript.lang.security.sql-injection').has('sql'));
});

test('deux résultats du même outil ne sont jamais corrélés entre eux', () => {
  assert.equal(correlateSast([
    sast({ id: 'a', tool: 'Semgrep', startLine: 41, cwe: 'CWE-89' }),
    sast({ id: 'b', tool: 'Semgrep', startLine: 42, cwe: 'CWE-89' })
  ]).length, 0);
});

// ---------------------------------------------------------- corrélation IaC

test('Trivy IaC et Snyk IaC sur la même ressource sont corrélés', () => {
  const clusters = correlateIac([
    unifiedFinding(raw({ id: 'a', tool: 'Trivy', category: 'misconfiguration', file: 'deploy/k8s.yaml', absolutePath: '/r/deploy/k8s.yaml', startLine: 16, resource: 'spec.containers[0].privileged', ruleId: 'AVD-KSV-0017' })),
    unifiedFinding(raw({ id: 'b', tool: 'Snyk', category: 'misconfiguration', file: 'deploy/k8s.yaml', absolutePath: '/r/deploy/k8s.yaml', startLine: 16, resource: 'spec.containers[0].privileged', ruleId: 'SNYK-CC-K8S-42' }))
  ]);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].confidence, 'high');
  assert.ok(clusters[0].reasons.some((reason) => reason.includes('Même ressource')));
});

test('deux fichiers IaC différents ne sont pas corrélés', () => {
  assert.equal(correlateIac([
    unifiedFinding(raw({ id: 'a', tool: 'Trivy', category: 'misconfiguration', file: 'a.yaml', absolutePath: '/r/a.yaml', resource: 'x' })),
    unifiedFinding(raw({ id: 'b', tool: 'Snyk', category: 'misconfiguration', file: 'b.yaml', absolutePath: '/r/b.yaml', resource: 'x' }))
  ]).length, 0);
});

// --------------------------------------------------------- routes et DAST

test('reconnaît les déclarations de routes Express, Flask et Spring', () => {
  const express = extractRoutes("app.post('/api/login', handler);\nrouter.get(\"/api/users/:id\", show);", 'routes/api.js');
  assert.deepEqual(express.map((route) => [route.method, route.pattern]), [['POST', '/api/login'], ['GET', '/api/users/*']]);
  const flask = extractRoutes("@app.route('/api/login', methods=['POST'])\ndef login(): pass", 'app.py');
  assert.equal(flask[0].method, 'POST');
  assert.equal(flask[0].pattern, '/api/login');
  const spring = extractRoutes('@GetMapping("/api/health")\npublic String health() {}', 'App.java');
  assert.equal(spring[0].pattern, '/api/health');
});

test('associe une URL concrète à une route paramétrée sans déborder', () => {
  assert.equal(routePattern('/api/users/:id'), '/api/users/*');
  assert.equal(pathMatchesRoute('http://x/api/users/12', '/api/users/*'), true);
  assert.equal(pathMatchesRoute('http://x/api/users/12/admin', '/api/users/*'), false);
  assert.equal(pathMatchesRoute('http://x/api/login', '/api/login'), true);
});

test('corrèle un endpoint dynamique au code qui le sert', () => {
  const routeMap = { supported: true, routes: extractRoutes("app.post('/api/login', (req,res) => { db.query(req.body.user); });", 'routes/login.js') };
  const clusters = correlateDastSast([
    unifiedFinding(raw({ id: 'z1', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', absolutePath: '', endpoint: 'http://127.0.0.1:3000/api/login', method: 'POST', cwe: 'CWE-89', parameter: 'user' })),
    sast({ id: 's1', tool: 'Semgrep', file: 'routes/login.js', absolutePath: '/repo/routes/login.js', startLine: 0, cwe: 'CWE-89' })
  ], routeMap);
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].type, 'dast-sast');
  assert.equal(clusters[0].confidence, 'high');
  assert.ok(clusters[0].reasons.some((reason) => reason.includes('servi par la route')));
});

test('sans route déclarée, aucun endpoint n’est rattaché à un fichier', () => {
  const clusters = correlateDastSast([
    unifiedFinding(raw({ id: 'z1', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', absolutePath: '', endpoint: 'http://x/api/login', method: 'POST', cwe: 'CWE-89' })),
    sast({ id: 's1', tool: 'Semgrep', file: 'routes/login.js', absolutePath: '/repo/routes/login.js', cwe: 'CWE-89' })
  ], { supported: false, routes: [] });
  assert.equal(clusters.length, 0);
});

test('une route trouvée sans CWE compatible ne crée pas de corrélation', () => {
  const routeMap = { supported: true, routes: extractRoutes("app.post('/api/login', h);", 'routes/login.js') };
  const clusters = correlateDastSast([
    unifiedFinding(raw({ id: 'z1', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', absolutePath: '', endpoint: 'http://x/api/login', method: 'POST', cwe: 'CWE-1004' })),
    sast({ id: 's1', tool: 'Semgrep', file: 'routes/login.js', absolutePath: '/repo/routes/login.js', cwe: 'CWE-89' })
  ], routeMap);
  assert.equal(clusters.length, 0);
});

test('construit la carte des routes depuis un vrai workspace', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'routemap-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'routes'));
  fs.writeFileSync(path.join(root, 'routes', 'api.js'), "app.get('/api/ping', (req,res)=>res.send('ok'));\n");
  fs.mkdirSync(path.join(root, 'node_modules', 'evil'), { recursive: true });
  fs.writeFileSync(path.join(root, 'node_modules', 'evil', 'index.js'), "app.get('/should/not/appear', h);\n");
  const routeMap = await buildRouteMap(root);
  assert.equal(routeMap.supported, true);
  assert.deepEqual(routeMap.routes.map((route) => route.pattern), ['/api/ping']);
  assert.deepEqual(routeMap.frameworks, ['express']);
  assert.equal(matchEndpoint(routeMap, 'http://127.0.0.1:3000/api/ping', 'GET').length, 1);
});

// -------------------------------------------------------------- annotation

test('annote les findings et résume la corrélation', () => {
  const result = correlateFindingsV2([
    dependency({ id: 't1', tool: 'Trivy' }),
    dependency({ id: 'o1', tool: 'OSV-Scanner' }),
    sast({ id: 'x', tool: 'Semgrep' })
  ]);
  const correlated = result.findings.find((finding) => finding.id === 't1');
  assert.equal(correlated.correlation.confidence, 'high');
  assert.deepEqual(correlated.correlation.types, ['sca']);
  assert.equal(result.findings.find((finding) => finding.id === 'x').correlation, null);
  assert.equal(result.summary.total, 1);
  assert.deepEqual(result.summary.byType, { sca: 1 });
  assert.equal(result.summary.routeMapAvailable, false);
});

test('la corrélation ne perd aucun finding', () => {
  const input = [dependency({ id: 't1', tool: 'Trivy' }), dependency({ id: 'o1', tool: 'OSV-Scanner' }), sast({ id: 'x' })];
  assert.equal(correlateFindingsV2(input).findings.length, input.length);
});
