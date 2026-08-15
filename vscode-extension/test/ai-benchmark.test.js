const test = require('node:test');
const assert = require('node:assert/strict');
const { BENCHMARK_CASES } = require('../src/ai/benchmark-cases');
const { DEFAULT_QUALITY_THRESHOLDS, percentile, summarizeModelExecutions, isEligibleFastModel, runBenchmark } = require('../src/ai/benchmark');
const { recommendModelRole } = require('../src/ai/smart-routing');
const { runTwoModelRemediation } = require('../src/ai/remediation-router');
const { redactSecrets } = require('../src/ai/context-builder');
const { FAILURE_REASONS, classifyBenchmarkExecution } = require('../src/ai/benchmark-classification');
const { runMiniProjectValidation } = require('../src/ai/benchmark-project-runner');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('le benchmark v2 fournit 25 cas contrôlés sans exécution automatique', () => {
  assert.equal(BENCHMARK_CASES.length, 25);
  for (const item of BENCHMARK_CASES) {
    assert.ok(item.vulnerableSnippet);
    assert.ok(item.finding.ruleId);
    assert.ok(item.expectedSecurityProperty);
    assert.ok(item.expectedPattern instanceof RegExp);
  }
});

test('classifie les échecs du benchmark de façon déterministe', () => {
  assert.equal(classifyBenchmarkExecution({ validatorResult: 'TIMEOUT' }), FAILURE_REASONS.TIMEOUT);
  assert.equal(classifyBenchmarkExecution({ validatorResult: 'PARSE_ERROR' }), FAILURE_REASONS.INVALID_JSON);
  assert.equal(classifyBenchmarkExecution({ validatorAccepted: true, securityValidated: false, unsafeAlternative: true }), FAILURE_REASONS.UNSAFE_ALTERNATIVE);
  assert.equal(classifyBenchmarkExecution({ validatorAccepted: true, securityValidated: false }), FAILURE_REASONS.ROOT_CAUSE_NOT_FIXED);
  assert.equal(classifyBenchmarkExecution({ validatorAccepted: true, securityValidated: true, testResult: 'failed' }), FAILURE_REASONS.FUNCTIONAL_REGRESSION);
  assert.equal(classifyBenchmarkExecution({ validatorAccepted: true, securityValidated: true }), FAILURE_REASONS.SECURE_FIX);
});

test('valide un patch dans une copie temporaire avec tests et re-scan réel', async () => {
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-fixture-'));
  try {
    await fs.writeFile(path.join(fixture, 'app.js'), 'module.exports = (name) => `hello ${name}`;\n', 'utf8');
    await fs.writeFile(path.join(fixture, 'test.js'), "const test=require('node:test');const assert=require('node:assert/strict');const greet=require('./app');test('works',()=>assert.equal(greet('dev'),'hello dev'));\n", 'utf8');
    const result = await runMiniProjectValidation({ fixtureDirectory: fixture, relativeSource: 'app.js', patchedSource: 'module.exports = (name) => `hello ${name}`;\n' });
    assert.equal(result.testResult, 'passed');
    assert.equal(result.rescanResult, 'finding_absent');
  } finally { await fs.rm(fixture, { recursive: true, force: true }); }
});

test('calcule uniquement des métriques provenant des exécutions fournies', () => {
  const rows = [
    { model: 'fast', durationMs: 100, parseSuccess: true, validatorAccepted: true, securityValidated: true, testResult: 'passed', rescanResult: 'finding_absent', fallbackUsed: false },
    { model: 'fast', durationMs: 300, parseSuccess: false, validatorAccepted: false, securityValidated: false, testResult: 'failed', rescanResult: 'finding_present', fallbackUsed: true }
  ];
  const summary = summarizeModelExecutions('fast', rows);
  assert.equal(summary.averageLatencyMs, 200);
  assert.equal(summary.medianLatencyMs, 100);
  assert.equal(summary.p95LatencyMs, 300);
  assert.equal(summary.structuredOutputRate, 0.5);
  assert.equal(summary.fallbackFrequency, 0.5);
  assert.equal(summarizeModelExecutions('missing', rows).averageLatencyMs, null);
  assert.equal(percentile([], 95), null);
});

test('privilégie la qualité avant la vitesse pour l’éligibilité Fast', () => {
  assert.equal(isEligibleFastModel({ executions: 10, averageLatencyMs: 50, structuredOutputRate: 1, validatorAcceptanceRate: 0.7, securityValidationRate: 1, testPassRate: 1 }), false);
  assert.equal(isEligibleFastModel({ executions: 10, averageLatencyMs: 5000, structuredOutputRate: 1, validatorAcceptanceRate: 1, securityValidationRate: 1, testPassRate: 1 }), true);
  assert.equal(isEligibleFastModel({ executions: 10, averageLatencyMs: 50, structuredOutputRate: 1, validatorAcceptanceRate: 1, securityValidationRate: 1, testPassRate: null }), false);
  assert.equal(DEFAULT_QUALITY_THRESHOLDS.securityValidationRate >= DEFAULT_QUALITY_THRESHOLDS.testPassRate, true);
});

test('le routeur intelligent préparatoire est déterministe et ne lance aucun modèle', () => {
  assert.equal(recommendModelRole({ finding: { ruleId: 'simple-xss', startLine: 1, endLine: 1 }, context: { excerpt: 'x' } }).role, 'fast');
  assert.deepEqual(recommendModelRole({ finding: { ruleId: 'authorization-idor', startLine: 1, endLine: 1 }, context: { excerpt: 'x' } }), { role: 'advanced', reasons: ['complex_rule'] });
  assert.equal(recommendModelRole({ finding: { startLine: 1, endLine: 10 }, context: { excerpt: 'x' } }).role, 'advanced');
});

test('le harness exécute chaque cas explicitement et ne fabrique aucun score', async () => {
  let calls = 0;
  const result = await runBenchmark({ models: ['m1', 'm2'], cases: BENCHMARK_CASES.slice(0, 2), executeCase: async () => { calls += 1; return { parseSuccess: true, validatorAccepted: true, securityValidated: true, testResult: 'passed', rescanResult: 'finding_absent' }; } });
  assert.equal(calls, 4);
  assert.equal(result.executions.length, 4);
  assert.equal(result.summaries.length, 2);
});

test('le rapport réel peut conserver uniquement une proposition assainie', () => {
  const generatedPatch = { oldText: redactSecrets("password = 'secret-value'"), newText: 'password = process.env.PASSWORD' };
  assert.equal(JSON.stringify(generatedPatch).includes('secret-value'), false);
  assert.match(generatedPatch.oldText, /REDACTED/);
});

test('Fast et Advanced reçoivent le même contexte masqué et le même validateur', async () => {
  const context = { excerpt: redactSecrets("password = 'secret-value'") };
  const contexts = []; const validatorCalls = [];
  await runTwoModelRemediation({
    configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: true }, installedModels: ['fast', 'advanced'], context,
    generate: async ({ role, context: received }) => { contexts.push(received); return { role }; },
    validate: async (proposal, metadata) => { validatorCalls.push(metadata.role); if (proposal.role === 'fast') throw new Error('ambiguous replacement'); return { generated: proposal, parsed: { hunks: [{}] } }; }
  });
  assert.equal(context.excerpt.includes('secret-value'), false);
  assert.equal(contexts[0], contexts[1]);
  assert.deepEqual(validatorCalls, ['fast', 'advanced']);
});

test('le flux Live ne déclenche aucun benchmark ni routage automatique', () => {
  const liveSources = ['../src/live/liveDetector', '../src/live/liveSecurityService'];
  for (const source of liveSources) {
    const exported = require(source);
    assert.equal(Object.values(exported).includes(runBenchmark), false);
    assert.equal(Object.values(exported).includes(runTwoModelRemediation), false);
  }
});
