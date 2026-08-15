const FAILURE_MESSAGE = 'Security Center could not generate a correction that passed validation.';
const FAILURE_DETAIL = 'Both local models were unable to produce a safely applicable patch. No file was modified.';
const FAILURE_ACTIONS = Object.freeze(['Explain issue', 'Open finding', 'Retry']);

function isExhaustedRemediation(result) {
  return Boolean(result && !result.ok && (result.attempts || []).length >= 2);
}

module.exports = { FAILURE_MESSAGE, FAILURE_DETAIL, FAILURE_ACTIONS, isExhaustedRemediation };
