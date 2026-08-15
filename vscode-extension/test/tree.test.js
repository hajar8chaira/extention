const test = require('node:test');
const assert = require('node:assert/strict');
const { groupFindings, groupRules, summarizeFindings } = require('../src/tree');

const findings = [
  { id: 's2', tool: 'Semgrep', ruleId: 'rule-a', title: 'Règle A', file: 'src/b.js', startLine: 4 },
  { id: 'g1', tool: 'Gitleaks', ruleId: 'secret-a', title: 'Secret A', file: 'src/a.js', startLine: 2 },
  { id: 's1', tool: 'Semgrep', ruleId: 'rule-a', title: 'Règle A', file: 'src/b.js', startLine: 1 }
];

test('regroupe les résultats par outil puis par fichier', () => {
  const groups = groupFindings(findings);
  assert.deepEqual(groups.map((group) => group.label), ['Gitleaks', 'Semgrep']);
  assert.equal(groups[1].count, 2);
  assert.equal(groups[1].children[0].count, 2);
  assert.equal(groups[1].children[0].children[0].kind, 'rule');
  assert.deepEqual(groups[1].children[0].children[0].children.map((item) => item.finding.startLine), [1, 4]);
});

test('produit un résumé lisible par scanner', () => {
  assert.equal(summarizeFindings(findings), 'Gitleaks: 1 • Semgrep: 2');
});

test('affiche aussi un scanner terminé sans résultat', () => {
  const groups = groupFindings([], [{ tool: 'Gitleaks', status: 'completed' }, { tool: 'Semgrep', status: 'failed', error: 'timeout' }]);
  assert.deepEqual(groups.map((group) => [group.label, group.count, group.status]), [
    ['Gitleaks', 0, 'completed'],
    ['Semgrep', 0, 'failed']
  ]);
  assert.equal(groups[1].error, 'timeout');
});

test('regroupe les doublons visuels sans supprimer les occurrences', () => {
  const groups = groupRules(findings.filter((finding) => finding.tool === 'Semgrep'));
  assert.equal(groups.length, 1);
  assert.equal(groups[0].kind, 'rule');
  assert.equal(groups[0].count, 2);
  assert.equal(groups[0].children.length, 2);
  assert.ok(groups[0].children.every((item) => item.occurrence));
});

test('regroupe ZAP par vulnérabilité puis par endpoint', () => {
  const zapFindings = [
    { id: 'z1', tool: 'ZAP', ruleId: '10038', title: 'CSP Header Not Set', file: 'GET http://local/a', endpoint: 'http://local/a', startLine: 0 },
    { id: 'z2', tool: 'ZAP', ruleId: '10038', title: 'CSP Header Not Set', file: 'GET http://local/b', endpoint: 'http://local/b', startLine: 0 },
    { id: 'z3', tool: 'ZAP', ruleId: '10110', title: 'Dangerous JS Functions', file: 'GET http://local/main.js', endpoint: 'http://local/main.js', startLine: 0 }
  ];
  const [zap] = groupFindings(zapFindings);
  assert.equal(zap.label, 'ZAP');
  assert.equal(zap.children.length, 2);
  const csp = zap.children.find((child) => child.ruleId === '10038');
  assert.equal(csp.count, 2);
  assert.ok(csp.children.every((child) => child.kind === 'endpoint'));
});
