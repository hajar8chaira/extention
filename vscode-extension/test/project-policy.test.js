const test = require('node:test');
const assert = require('node:assert/strict');
const { parsePolicyYaml, validatePolicy, evaluatePolicy } = require('../src/project-policy');

test('parse et valide une politique projet', () => {
  const raw = parsePolicyYaml(`
version: 1
scanners:
  semgrep: true
  zap: false
policy:
  fail_on: HIGH
  max_active: 3
  include_tests: false
licenses:
  denied: [AGPL-3.0, GPL-3.0]
gitleaks:
  history: true
  history_incremental: true
  config: config/gitleaks.toml
semgrep:
  custom_rules: security-rules/semgrep.yml
zap:
  active: true
  policy_min_severity: HIGH
  context: zap.context
  user: local-user
exclusions:
  global_files: [node_modules/**, dist/**]
  semgrep_files: [generated/**]
  semgrep_rules: [company.allowed-rule]
  trivy_files: [vendor/**]
  zap_routes: [/logout]
execution:
  max_parallel_scanners: 3
`);
  const policy = validatePolicy(raw);
  assert.equal(policy.scanners.Semgrep, true);
  assert.equal(policy.scanners.ZAP, false);
  assert.equal(policy.failOn, 'HIGH');
  assert.equal(policy.maxActive, 3);
  assert.equal(policy.includeTests, false);
  assert.deepEqual(policy.licensesDenied, ['AGPL-3.0', 'GPL-3.0']);
  assert.equal(policy.gitleaksHistory, true);
  assert.equal(policy.gitleaksHistoryIncremental, true);
  assert.equal(policy.gitleaksConfig, 'config/gitleaks.toml');
  assert.equal(policy.semgrepCustomRules, 'security-rules/semgrep.yml');
  assert.equal(policy.zapActive, true);
  assert.equal(policy.zapPolicyMinSeverity, 'HIGH');
  assert.equal(policy.zapContext, 'zap.context');
  assert.equal(policy.zapUser, 'local-user');
  assert.deepEqual(policy.exclusions.global_files, ['node_modules/**', 'dist/**']);
  assert.deepEqual(policy.exclusions.semgrep_rules, ['company.allowed-rule']);
  assert.equal(policy.maxParallelScanners, 3);
});

test('rejette un scanner et un seuil inconnus', () => {
  assert.throws(() => validatePolicy(parsePolicyYaml('scanners:\n  inconnu: true')), /Scanner inconnu/);
  assert.throws(() => validatePolicy(parsePolicyYaml('policy:\n  fail_on: URGENT')), /Seuil de sévérité inconnu/);
});

test('rejette une indentation YAML ambiguë', () => {
  assert.throws(() => parsePolicyYaml('policy:\n   fail_on: HIGH'), /indentation attendue/);
});

test('rejette une politique de licences qui n’est pas une liste', () => {
  assert.throws(() => validatePolicy(parsePolicyYaml('licenses:\n  denied: GPL-3.0')), /doit être une liste/);
});

test('évalue précisément les alertes bloquantes et ignore les tests', () => {
  const policy = validatePolicy(parsePolicyYaml('policy:\n  fail_on: HIGH\n  max_active: 1\n  include_tests: false'));
  const result = evaluatePolicy([
    { rawSeverity: 'CRITICAL', sourceContext: 'test', triageStatus: 'new' },
    { rawSeverity: 'HIGH', sourceContext: 'production', triageStatus: 'new' },
    { rawSeverity: 'CRITICAL', sourceContext: 'production', triageStatus: 'accepted' },
    { rawSeverity: 'LOW', sourceContext: 'production', triageStatus: 'new' }
  ], policy);
  assert.equal(result.passed, false);
  assert.equal(result.activeCount, 2);
  assert.equal(result.blockingCount, 1);
  assert.deepEqual(result.reasons, [
    '1 alerte(s) au seuil HIGH ou supérieur',
    '2 alerte(s) actives > maximum 1'
  ]);
});

test('retourne une conformité lorsque les critères sont respectés', () => {
  const policy = validatePolicy(parsePolicyYaml('policy:\n  fail_on: CRITICAL\n  max_active: 2'));
  const result = evaluatePolicy([{ rawSeverity: 'LOW', sourceContext: 'production', triageStatus: 'new' }], policy);
  assert.equal(result.passed, true);
  assert.deepEqual(result.reasons, []);
});

test('conserve les alertes ZAP faibles sans les compter dans le blocage', () => {
  const policy = validatePolicy(parsePolicyYaml('policy:\n  fail_on: HIGH\n  max_active: 0\nzap:\n  policy_min_severity: HIGH'));
  const result = evaluatePolicy([
    { tool: 'ZAP', rawSeverity: 'LOW', sourceContext: 'runtime', triageStatus: 'new' },
    { tool: 'ZAP', rawSeverity: 'MEDIUM', sourceContext: 'runtime', triageStatus: 'new' }
  ], policy);
  assert.equal(result.passed, true);
  assert.equal(result.activeCount, 0);
  assert.equal(result.totalActiveCount, 2);
  assert.equal(result.ignoredByToolThreshold, 2);
});

test('bloque toujours une alerte ZAP HIGH', () => {
  const policy = validatePolicy(parsePolicyYaml('policy:\n  fail_on: HIGH\n  max_active: 0\nzap:\n  policy_min_severity: HIGH'));
  const result = evaluatePolicy([{ tool: 'ZAP', rawSeverity: 'HIGH', sourceContext: 'runtime', triageStatus: 'new' }], policy);
  assert.equal(result.passed, false);
  assert.equal(result.activeCount, 1);
  assert.equal(result.blockingCount, 1);
});
