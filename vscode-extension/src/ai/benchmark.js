const DEFAULT_QUALITY_THRESHOLDS = Object.freeze({ structuredOutputRate: 0.9, validatorAcceptanceRate: 0.85, securityValidationRate: 0.85, testPassRate: 0.8 });

function percentile(values, percentage) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((percentage / 100) * sorted.length) - 1)];
}

function rate(results, predicate, eligible = () => true) {
  const denominator = results.filter(eligible);
  return denominator.length ? denominator.filter(predicate).length / denominator.length : null;
}

function summarizeModelExecutions(model, executions) {
  const actual = executions.filter((item) => item.model === model && Number.isFinite(item.durationMs));
  if (!actual.length) return { model, executions: 0, averageLatencyMs: null, medianLatencyMs: null, p95LatencyMs: null, structuredOutputRate: null, validatorAcceptanceRate: null, securityValidationRate: null, testPassRate: null, rescanSuccessRate: null, fallbackFrequency: null, fixSecurityRate: null, regressionRate: null, failureCounts: {} };
  const durations = actual.map((item) => item.durationMs);
  const failureCounts = actual.reduce((counts, item) => {
    const reason = item.failureReason || 'UNCLASSIFIED';
    counts[reason] = (counts[reason] || 0) + 1;
    return counts;
  }, {});
  return {
    model, executions: actual.length,
    averageLatencyMs: Math.round(durations.reduce((sum, value) => sum + value, 0) / durations.length),
    medianLatencyMs: percentile(durations, 50), p95LatencyMs: percentile(durations, 95),
    structuredOutputRate: rate(actual, (item) => item.parseSuccess === true),
    validatorAcceptanceRate: rate(actual, (item) => item.validatorAccepted === true),
    securityValidationRate: rate(actual, (item) => item.securityValidated === true),
    testPassRate: rate(actual, (item) => item.testResult === 'passed', (item) => item.testResult !== 'not_available'),
    rescanSuccessRate: rate(actual, (item) => item.rescanResult === 'finding_absent', (item) => item.rescanResult !== 'not_available'),
    fallbackFrequency: rate(actual, (item) => item.fallbackUsed === true),
    fixSecurityRate: rate(actual, (item) => item.failureReason === 'SECURE_FIX'),
    regressionRate: rate(actual, (item) => ['SECURITY_REGRESSION', 'FUNCTIONAL_REGRESSION'].includes(item.failureReason)),
    failureCounts
  };
}

function isEligibleFastModel(summary, thresholds = DEFAULT_QUALITY_THRESHOLDS) {
  if (!summary || summary.executions === 0) return false;
  return ['structuredOutputRate', 'validatorAcceptanceRate', 'securityValidationRate', 'testPassRate']
    .every((key) => Number.isFinite(summary[key]) && summary[key] >= thresholds[key]);
}

async function runBenchmark({ models, cases, executeCase, onResult }) {
  const executions = [];
  for (const model of models) {
    for (const benchmarkCase of cases) {
      const startedAt = Date.now();
      const result = await executeCase({ model, benchmarkCase });
      const execution = { model, caseId: benchmarkCase.id, durationMs: Date.now() - startedAt, fallbackUsed: false, ...result };
      executions.push(execution); onResult?.(execution);
    }
  }
  return { executions, summaries: models.map((model) => summarizeModelExecutions(model, executions)) };
}

module.exports = { DEFAULT_QUALITY_THRESHOLDS, percentile, summarizeModelExecutions, isEligibleFastModel, runBenchmark };
