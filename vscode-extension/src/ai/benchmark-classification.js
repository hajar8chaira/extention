const FAILURE_REASONS = Object.freeze({
  SECURE_FIX: 'SECURE_FIX', ROOT_CAUSE_NOT_FIXED: 'ROOT_CAUSE_NOT_FIXED',
  UNSAFE_ALTERNATIVE: 'UNSAFE_ALTERNATIVE', SECURITY_REGRESSION: 'SECURITY_REGRESSION',
  FUNCTIONAL_REGRESSION: 'FUNCTIONAL_REGRESSION', AMBIGUOUS_PATCH: 'AMBIGUOUS_PATCH',
  INVALID_PATCH: 'INVALID_PATCH', NO_CHANGE: 'NO_CHANGE', INVALID_JSON: 'INVALID_JSON', TIMEOUT: 'TIMEOUT'
});

function classifyBenchmarkExecution(input = {}) {
  const state = String(input.validatorResult || input.errorState || '').toUpperCase();
  if (state.includes('TIMEOUT')) return FAILURE_REASONS.TIMEOUT;
  if (state.includes('PARSE') || state.includes('JSON')) return FAILURE_REASONS.INVALID_JSON;
  if (state.includes('NO_CHANGE') || (input.oldText != null && input.oldText === input.newText)) return FAILURE_REASONS.NO_CHANGE;
  if (state.includes('AMBIGUOUS')) return FAILURE_REASONS.AMBIGUOUS_PATCH;
  if (input.validatorAccepted !== true) return FAILURE_REASONS.INVALID_PATCH;
  if (input.securityRegression === true) return FAILURE_REASONS.SECURITY_REGRESSION;
  if (input.testResult === 'failed') return FAILURE_REASONS.FUNCTIONAL_REGRESSION;
  if (input.securityValidated !== true || input.rescanResult === 'finding_present') {
    return input.unsafeAlternative === true ? FAILURE_REASONS.UNSAFE_ALTERNATIVE : FAILURE_REASONS.ROOT_CAUSE_NOT_FIXED;
  }
  return FAILURE_REASONS.SECURE_FIX;
}
module.exports = { FAILURE_REASONS, classifyBenchmarkExecution };
