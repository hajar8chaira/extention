const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { unifiedFinding } = require('../src/intelligence/finding-model');
const {
  evaluateReachability, evaluateDependency, buildImportIndex, importsOfPackage, entryPointFiles, STATES
} = require('../src/intelligence/reachability');
const { prioritizeFinding, prioritizeFindings, explainPriority, WEIGHTS, levelFor } = require('../src/intelligence/prioritization');

function dependency(overrides = {}) {
  return unifiedFinding({
    id: 'dep-1', tool: 'Trivy', category: 'dependency', ruleId: 'CVE-2020-8203', title: 'CVE',
    severity: 'error', rawSeverity: 'HIGH', file: 'package-lock.json', absolutePath: '/repo/package-lock.json',
    unlocated: true, startLine: 0, packageName: 'lodash', installedVersion: '4.17.11', ecosystem: 'npm',
    vulnerabilityAliases: ['CVE-2020-8203'], ...overrides
  });
}

function code(overrides = {}) {
  return unifiedFinding({
    id: 'code-1', tool: 'Semgrep', category: 'security', ruleId: 'sqli', title: 'SQLi',
    severity: 'error', rawSeverity: 'HIGH', file: 'routes/login.js', absolutePath: '/repo/routes/login.js',
    startLine: 41, startColumn: 0, cwe: 'CWE-89', ...overrides
  });
}

const ANALYSED_EMPTY = { analysed: true, index: new Map([['lodash', []]]), scannedFiles: 12, files: [] };
function analysedWith(entries) {
  return { analysed: true, index: new Map([['lodash', entries]]), scannedFiles: 12, files: entries.map((entry) => entry.file) };
}

// ------------------------------------------------------------- imports

test('reconnaît les imports réels sans faux positif de sous-chaîne', () => {
  assert.equal(importsOfPackage("const _ = require('lodash');", 'lodash').length, 1);
  assert.equal(importsOfPackage("import merge from 'lodash/merge';", 'lodash').length, 1);
  assert.equal(importsOfPackage("import x from 'lodash-es';", 'lodash').length, 0);
  assert.equal(importsOfPackage('import requests\n', 'requests').length, 1);
  assert.equal(importsOfPackage('from requests.auth import HTTPBasicAuth\n', 'requests').length, 1);
});

test('indexe les imports depuis un vrai workspace', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reach-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'util.js'), "const _ = require('lodash');\n");
  fs.mkdirSync(path.join(root, 'node_modules', 'x'), { recursive: true });
  fs.writeFileSync(path.join(root, 'node_modules', 'x', 'i.js'), "require('lodash');\n");
  const index = await buildImportIndex(root, ['lodash']);
  assert.equal(index.analysed, true);
  assert.deepEqual(index.index.get('lodash').map((entry) => entry.file), ['src/util.js']);
});

// -------------------------------------------------------- reachability

test('expose exactement les états prévus', () => {
  assert.deepEqual(STATES, ['not_evaluated', 'present', 'imported', 'statically_reachable', 'dynamically_confirmed', 'not_reachable', 'unknown']);
});

test('une dépendance présente mais non importée devient not_reachable, jamais par erreur', () => {
  const result = evaluateDependency(dependency(), { importIndex: ANALYSED_EMPTY, entryPoints: new Set(), dynamicallyConfirmedIds: new Set() });
  assert.equal(result.state, 'not_reachable');
  assert.equal(result.confidence, 'low');
  assert.match(result.reason, /imports dynamiques ne sont pas résolus/);
});

test('une analyse d’imports en échec donne unknown, jamais not_reachable', () => {
  const failed = evaluateDependency(dependency(), { importIndex: { analysed: false, index: new Map() }, entryPoints: new Set(), dynamicallyConfirmedIds: new Set() });
  assert.equal(failed.state, 'unknown');
  const missing = evaluateDependency(dependency(), { importIndex: null, entryPoints: new Set(), dynamicallyConfirmedIds: new Set() });
  assert.equal(missing.state, 'unknown');
});

test('une dépendance importée hors point d’entrée reste imported', () => {
  const result = evaluateDependency(dependency(), {
    importIndex: analysedWith([{ file: 'src/util.js', line: 1, statement: "require('lodash')" }]),
    entryPoints: new Set(), dynamicallyConfirmedIds: new Set()
  });
  assert.equal(result.state, 'imported');
  assert.equal(result.evidence[0].file, 'src/util.js');
});

test('une dépendance importée par un point d’entrée devient statiquement atteignable', () => {
  const result = evaluateDependency(dependency(), {
    importIndex: analysedWith([{ file: 'routes/login.js', line: 3, statement: "require('lodash')" }]),
    entryPoints: new Set(['routes/login.js']), dynamicallyConfirmedIds: new Set()
  });
  assert.equal(result.state, 'statically_reachable');
  assert.equal(result.confidence, 'medium');
  assert.match(result.reason, /Aucun graphe d’appel complet/);
});

test('une preuve dynamique corrélée donne dynamically_confirmed', () => {
  const result = evaluateDependency(dependency(), {
    importIndex: ANALYSED_EMPTY, entryPoints: new Set(), dynamicallyConfirmedIds: new Set(['dep-1'])
  });
  assert.equal(result.state, 'dynamically_confirmed');
  assert.equal(result.confidence, 'high');
});

test('un résultat ZAP est une observation runtime, pas une atteignabilité de code', () => {
  const zap = unifiedFinding({ id: 'z', tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint: 'http://x/api/login', method: 'POST', parameter: 'user', evidence: "' OR '1'='1", absolutePath: '', title: 'x', rawSeverity: 'HIGH' });
  const { findings, summary } = evaluateReachability([zap]);
  // L'observation dynamique est un fait distinct de « ce code est atteignable ».
  assert.equal(findings[0].runtime.observed, true);
  assert.equal(findings[0].runtime.source, 'zap');
  assert.equal(findings[0].runtime.method, 'POST');
  assert.equal(findings[0].runtime.url, 'http://x/api/login');
  assert.equal(findings[0].reachability.state, 'not_evaluated');
  // Et il ne gonfle pas le compteur d'atteignabilité du code.
  assert.equal(summary.counts.dynamically_confirmed, undefined);
  assert.equal(summary.runtime.observed, 1);
  assert.equal(summary.runtime.applicationEndpoints, 1);
});

test('une ressource statique observée n’est pas un chemin applicatif exercé', () => {
  const assets = ['http://x/style.css', 'http://x/app.js', 'http://x/favicon.ico', 'http://x/robots.txt']
    .map((endpoint, index) => unifiedFinding({ id: `a${index}`, tool: 'ZAP', category: 'dynamic', sourceContext: 'runtime', endpoint, method: 'GET', absolutePath: '', title: 'header', rawSeverity: 'LOW' }));
  const { summary } = evaluateReachability(assets);
  assert.equal(summary.runtime.observed, 4);
  assert.equal(summary.runtime.staticAssets, 4);
  assert.equal(summary.runtime.applicationEndpoints, 0);
});

test('un secret n’a pas d’atteignabilité inventée', () => {
  const secret = unifiedFinding({ id: 's', tool: 'Gitleaks', category: 'secret', file: 'config.js', absolutePath: '/r/config.js', startLine: 2, title: 'secret', rawSeverity: 'CRITICAL' });
  const { findings } = evaluateReachability([secret]);
  assert.equal(findings[0].reachability.state, 'not_evaluated');
});

test('un fichier déclarant une route est un point d’entrée', () => {
  const points = entryPointFiles({ routes: [{ file: 'routes/login.js' }] }, ['src/index.js', 'src/other.js']);
  assert.ok(points.has('routes/login.js'));
  assert.ok(points.has('src/index.js'));
  assert.ok(!points.has('src/other.js'));
});

test('le résumé d’atteignabilité reflète l’exécution réelle', () => {
  const { summary } = evaluateReachability([dependency()], { importIndex: ANALYSED_EMPTY });
  assert.equal(summary.analysed, true);
  assert.equal(summary.scannedFiles, 12);
  assert.equal(summary.counts.not_reachable, 1);
});

// --------------------------------------------------------- priorisation

function withReach(finding, state, confidence = 'medium') {
  return { ...finding, reachability: { state, confidence, reason: '', evidence: [] } };
}

test('le score est déterministe', () => {
  const finding = withReach(dependency(), 'imported');
  assert.equal(prioritizeFinding(finding).priority.score, prioritizeFinding(finding).priority.score);
});

test('la sévérité pilote le socle du score', () => {
  const high = prioritizeFinding(withReach(dependency({ rawSeverity: 'HIGH' }), 'present'));
  const low = prioritizeFinding(withReach(dependency({ rawSeverity: 'LOW' }), 'present'));
  assert.ok(high.priority.score > low.priority.score);
  assert.equal(high.priority.reasons[0].points, WEIGHTS.severity.HIGH);
});

test('l’atteignabilité fait monter ou descendre la priorité', () => {
  const base = dependency();
  const notReachable = prioritizeFinding(withReach(base, 'not_reachable')).priority.score;
  const imported = prioritizeFinding(withReach(base, 'imported')).priority.score;
  const reachable = prioritizeFinding(withReach(base, 'statically_reachable')).priority.score;
  const confirmed = prioritizeFinding(withReach(base, 'dynamically_confirmed')).priority.score;
  assert.ok(notReachable < imported);
  assert.ok(imported < reachable);
  assert.ok(reachable < confirmed);
});

test('une confirmation dynamique n’est pas comptée deux fois', () => {
  const confirmed = withReach({ ...code(), endpoint: 'http://x/api/login' }, 'dynamically_confirmed');
  const exposure = confirmed.priority?.reasons || prioritizeFinding(confirmed).priority.reasons;
  assert.equal(exposure.filter((reason) => reason.kind === 'exposure').length, 0);
  assert.equal(exposure.filter((reason) => reason.kind === 'reachability').length, 1);
});

test('plusieurs scanners indépendants ajoutent un bonus unique', () => {
  const twoTools = prioritizeFinding(withReach({ ...dependency(), correlation: { corroboratingTools: ['OSV-Scanner'], confidence: 'medium', types: ['sca'] } }, 'imported'));
  const threeTools = prioritizeFinding(withReach({ ...dependency(), correlation: { corroboratingTools: ['OSV-Scanner', 'Snyk'], confidence: 'medium', types: ['sca'] } }, 'imported'));
  const multi = threeTools.priority.reasons.filter((reason) => reason.kind === 'correlation');
  assert.equal(multi.length, 1);
  assert.equal(twoTools.priority.score, threeTools.priority.score);
});

test('un secret de production est prioritaire, pas un secret de test', () => {
  const secret = unifiedFinding({ id: 's', tool: 'Gitleaks', category: 'secret', file: 'config.js', absolutePath: '/r/config.js', startLine: 1, rawSeverity: 'CRITICAL', title: 'secret', sourceContext: 'production' });
  const testSecret = unifiedFinding({ id: 's2', tool: 'Gitleaks', category: 'secret', file: 'test/config.js', absolutePath: '/r/test/config.js', startLine: 1, rawSeverity: 'CRITICAL', title: 'secret', sourceContext: 'test' });
  assert.ok(prioritizeFinding(secret).priority.score > prioritizeFinding(testSecret).priority.score);
});

test('un finding trié comme faux positif chute fortement', () => {
  const active = prioritizeFinding(withReach(dependency(), 'statically_reachable')).priority.score;
  const dismissed = prioritizeFinding(withReach(dependency({ triageStatus: 'false_positive' }), 'statically_reachable')).priority.score;
  assert.ok(dismissed < active);
});

test('un exploit connu compte seulement s’il est publié par le scanner', () => {
  const withExploit = prioritizeFinding(withReach(dependency({ exploitMaturity: 'Proof of Concept' }), 'imported'));
  const withoutExploit = prioritizeFinding(withReach(dependency({ exploitMaturity: 'No known exploit' }), 'imported'));
  assert.ok(withExploit.priority.score > withoutExploit.priority.score);
  assert.equal(withoutExploit.priority.reasons.some((reason) => reason.kind === 'exploit'), false);
});

test('le score reste borné entre 0 et 100', () => {
  const maximal = prioritizeFinding(withReach({
    ...code(), cvssScore: 9.8, fixAvailable: true, endpoint: 'http://x/a',
    correlation: { corroboratingTools: ['ZAP', 'SonarQube'], confidence: 'high', types: ['dast-sast'] },
    raw: { exploitMaturity: 'Functional' }, severity: 'CRITICAL'
  }, 'dynamically_confirmed'));
  assert.ok(maximal.priority.score <= 100);
  assert.ok(maximal.priority.score >= 85);
  const minimal = prioritizeFinding(withReach(dependency({ rawSeverity: 'INFO', triageStatus: 'false_positive' }), 'not_reachable'));
  assert.ok(minimal.priority.score >= 0);
});

test('chaque score est expliqué ligne par ligne', () => {
  const finding = prioritizeFinding(withReach({ ...code(), fixAvailable: true }, 'dynamically_confirmed'));
  const explanation = explainPriority(finding);
  assert.match(explanation, /\/ 100/);
  assert.match(explanation, /Sévérité HIGH/);
  assert.match(explanation, /Confirmée dynamiquement/);
  assert.ok(finding.priority.reasons.every((reason) => reason.label && Number.isFinite(reason.points)));
});

test('les niveaux de priorité suivent des seuils explicites', () => {
  assert.equal(levelFor(90).level, 'critical');
  assert.equal(levelFor(70).level, 'high');
  assert.equal(levelFor(45).level, 'medium');
  assert.equal(levelFor(10).level, 'low');
});

test('la sévérité seule n’atteint jamais la bande critique', () => {
  // Une CRITICAL sans aucune preuve d’atteignabilité ne doit pas écraser une
  // HIGH réellement confirmée : c’est tout l’intérêt de la priorisation.
  const severeButUnproven = prioritizeFinding(withReach(dependency({ rawSeverity: 'CRITICAL' }), 'present'));
  assert.equal(severeButUnproven.priority.level, 'medium');
  const highButConfirmed = prioritizeFinding(withReach({
    ...code(), fixAvailable: true,
    correlation: { corroboratingTools: ['ZAP'], confidence: 'high', types: ['dast-sast'] }
  }, 'dynamically_confirmed'));
  assert.equal(highButConfirmed.priority.level, 'critical');
  assert.ok(highButConfirmed.priority.score > severeButUnproven.priority.score);
});

test('l’atteignabilité fait franchir les bandes à sévérité constante', () => {
  const base = dependency({ rawSeverity: 'CRITICAL' });
  assert.equal(prioritizeFinding(withReach(base, 'present')).priority.level, 'medium');
  assert.equal(prioritizeFinding(withReach(base, 'statically_reachable')).priority.level, 'high');
  assert.equal(prioritizeFinding(withReach({ ...base, correlation: { corroboratingTools: ['OSV-Scanner'], confidence: 'high', types: ['sca'] } }, 'dynamically_confirmed')).priority.level, 'critical');
});

test('le résumé classe les priorités et expose le sommet', () => {
  const { summary } = prioritizeFindings([
    withReach({ ...dependency({ id: 'a', rawSeverity: 'CRITICAL' }), correlation: { corroboratingTools: ['OSV-Scanner'], confidence: 'high', types: ['sca'] } }, 'dynamically_confirmed'),
    withReach(dependency({ id: 'b', rawSeverity: 'LOW' }), 'not_reachable')
  ]);
  assert.equal(summary.counts.critical, 1);
  assert.equal(summary.top[0].id, 'a');
  assert.ok(summary.highest >= 80);
});
