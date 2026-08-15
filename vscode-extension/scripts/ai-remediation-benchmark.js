#!/usr/bin/env node
const { createAiProvider } = require('../src/ai/provider-registry');
const { redactSecrets } = require('../src/ai/context-builder');
const { replacementToPatch, parseUnifiedDiff, validatePatchForFinding } = require('../src/ai/patch-validator');
const { remediationResult } = require('../src/ai/remediation-result');
const { BENCHMARK_CASES } = require('../src/ai/benchmark-cases');
const { runBenchmark } = require('../src/ai/benchmark');
const { classifyBenchmarkExecution } = require('../src/ai/benchmark-classification');

function readArguments(argv) {
  const modelsAt = argv.indexOf('--models');
  const baseAt = argv.indexOf('--base-url');
  const casesAt = argv.indexOf('--cases');
  const models = modelsAt >= 0 ? String(argv[modelsAt + 1] || '').split(',').map((value) => value.trim()).filter(Boolean) : [];
  const caseIds = casesAt >= 0 ? String(argv[casesAt + 1] || '').split(',').map((value) => value.trim()).filter(Boolean) : [];
  return { models, caseIds, baseUrl: baseAt >= 0 ? argv[baseAt + 1] : 'http://127.0.0.1:11434' };
}

async function main() {
  const { models, caseIds, baseUrl } = readArguments(process.argv.slice(2));
  if (!models.length) throw new Error('Usage: node scripts/ai-remediation-benchmark.js --models fast-model,advanced-model [--base-url http://127.0.0.1:11434]');
  const provider = createAiProvider('ollama', { baseUrl });
  const installed = await provider.listModels();
  const missing = models.filter((model) => !installed.some((name) => name === model || name.split(':')[0] === model.split(':')[0]));
  if (missing.length) throw new Error(`Model not installed: ${missing.join(', ')}`);
  const selectedCases = caseIds.length ? BENCHMARK_CASES.filter((item) => caseIds.includes(item.id)) : BENCHMARK_CASES;
  if (!selectedCases.length || (caseIds.length && selectedCases.length !== caseIds.length)) throw new Error('One or more benchmark case identifiers are unknown.');
  const report = await runBenchmark({ models, cases: selectedCases, executeCase: async ({ model, benchmarkCase }) => {
    const source = benchmarkCase.vulnerableSnippet;
    const context = {
      finding: benchmarkCase.finding, file: benchmarkCase.finding.file,
      excerpt: `1: ${redactSecrets(source)}`, excerptStartLine: 1, excerptEndLine: 1,
      contextKinds: { imports: 0, declarations: 0, enclosingFunction: false }
    };
    try {
      let proposal = await provider.generateFix({ model, context, timeoutMs: 120000 });
      if (proposal.oldText.includes('[REDACTED]')) {
        if (proposal.newText.includes('[REDACTED]')) throw new Error('The proposed fix retained a redacted secret.');
        proposal = { ...proposal, oldText: source };
      }
      const parsed = validatePatchForFinding(parseUnifiedDiff(replacementToPatch(source, benchmarkCase.finding.file, proposal.oldText, proposal.newText)), benchmarkCase.finding);
      const securityValidated = benchmarkCase.expectedPattern ? benchmarkCase.expectedPattern.test(proposal.newText) : true;
      const unsafeAlternative = !securityValidated && benchmarkCase.unsafeAlternativePatterns.some((pattern) => pattern.test(proposal.newText));
      const execution = {
        parseSuccess: true, validatorAccepted: true,
        securityValidated, unsafeAlternative,
        testResult: 'not_available', rescanResult: 'not_available', validatorResult: remediationResult({ parsed, model }).state
        , generatedPatch: { oldText: redactSecrets(proposal.oldText), newText: redactSecrets(proposal.newText) }
      };
      return { ...execution, failureReason: classifyBenchmarkExecution({ ...execution, oldText: proposal.oldText, newText: proposal.newText }) };
    } catch (error) {
      const classified = remediationResult({ error, model });
      const execution = { parseSuccess: classified.state !== 'PARSE_ERROR', validatorAccepted: false, securityValidated: false, testResult: 'not_available', rescanResult: 'not_available', validatorResult: classified.state };
      return { ...execution, failureReason: classifyBenchmarkExecution(execution) };
    }
  }});
  process.stdout.write(`${JSON.stringify({ generatedAt: new Date().toISOString(), cases: selectedCases.length, ...report }, null, 2)}\n`);
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
