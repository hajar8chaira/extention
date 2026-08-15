const METRICS_KEY = 'securityCenter.ai.remediationMetrics';

function buildRemediationMetric(result, options = {}) {
  const attempts = (result?.attempts || []).map((attempt) => ({
    role: attempt.role,
    model: attempt.model,
    durationMs: Math.max(0, Number(attempt.durationMs || 0)),
    parseSuccess: attempt.classification?.state !== 'PARSE_ERROR',
    validatorResult: attempt.classification?.state || 'UNKNOWN',
    patchAccepted: Boolean(attempt.ok)
  }));
  return {
    id: options.id,
    recordedAt: options.recordedAt || new Date().toISOString(),
    attempts,
    fallbackUsed: Boolean(result?.fallbackUsed),
    fallbackReason: result?.fallbackReason || null,
    finalModel: result?.ok ? result.model : null,
    finalRole: result?.ok ? result.role : null,
    patchAccepted: Boolean(result?.ok),
    testResult: options.testResult || 'not_run',
    rescanResult: options.rescanResult || 'not_run'
  };
}

async function saveLocalRemediationMetric(workspaceState, metric, limit = 100) {
  const existing = workspaceState.get(METRICS_KEY, []);
  const filtered = existing.filter((item) => item.id !== metric.id);
  await workspaceState.update(METRICS_KEY, [metric, ...filtered].slice(0, limit));
  return metric;
}

module.exports = { METRICS_KEY, buildRemediationMetric, saveLocalRemediationMetric };
