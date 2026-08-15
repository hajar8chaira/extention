const REMEDIATION_STATES = Object.freeze({
  VALID: 'VALID',
  INVALID: 'INVALID',
  AMBIGUOUS: 'AMBIGUOUS',
  UNSAFE: 'UNSAFE',
  NO_CHANGE: 'NO_CHANGE',
  PARSE_ERROR: 'PARSE_ERROR',
  MODEL_ERROR: 'MODEL_ERROR',
  TIMEOUT: 'TIMEOUT'
});

const SAFE_FALLBACK_REASONS = Object.freeze({
  [REMEDIATION_STATES.INVALID]: 'fast_validation_failure',
  [REMEDIATION_STATES.AMBIGUOUS]: 'ambiguous_patch',
  [REMEDIATION_STATES.UNSAFE]: 'unsafe_patch',
  [REMEDIATION_STATES.NO_CHANGE]: 'no_change',
  [REMEDIATION_STATES.PARSE_ERROR]: 'invalid_output',
  [REMEDIATION_STATES.MODEL_ERROR]: 'model_error',
  [REMEDIATION_STATES.TIMEOUT]: 'timeout'
});

function safeFallbackReason(state) {
  return SAFE_FALLBACK_REASONS[state] || 'fast_validation_failure';
}

function fallbackReasonMessage(reason) {
  const messages = {
    fast_validation_failure: 'The Fast proposal did not pass Security Center validation.',
    ambiguous_patch: 'The Fast proposal was ambiguous and could not be applied safely.',
    unsafe_patch: 'The Fast proposal was blocked by Security Center safety rules.',
    no_change: 'The Fast proposal did not make a meaningful change.',
    invalid_output: 'The Fast model did not return the required structured patch.',
    model_error: 'The Fast model could not complete the request.',
    timeout: 'The Fast model exceeded the allowed time.'
  };
  return messages[reason] || messages.fast_validation_failure;
}

function classifyRemediationError(error) {
  const message = String(error?.message || error || '');
  const name = String(error?.name || '');
  if (/TimeoutError|AbortError/i.test(name) || /timeout|délai|budget.*dépass/i.test(message)) return REMEDIATION_STATES.TIMEOUT;
  if (/JSON valide|réponse .*incomplète/i.test(message)) return REMEDIATION_STATES.PARSE_ERROR;
  if (/ambigu/i.test(message)) return REMEDIATION_STATES.AMBIGUOUS;
  if (/ne modifie pas|no change|patch vide|aucun hunk/i.test(message)) return REMEDIATION_STATES.NO_CHANGE;
  if (/payload offensif|fichier sensible|hors workspace|chemin .*interdit|trop de lignes|trop volumineux|renommage .*interdit/i.test(message)) return REMEDIATION_STATES.UNSAFE;
  if (/Ollama HTTP|modèle .*sélectionné|model.*not found|fetch failed|ECONNREFUSED/i.test(message)) return REMEDIATION_STATES.MODEL_ERROR;
  return REMEDIATION_STATES.INVALID;
}

function remediationResult({ error, parsed, model, role = 'fast' }) {
  return {
    state: error ? classifyRemediationError(error) : REMEDIATION_STATES.VALID,
    role,
    model: String(model || ''),
    parsed: Boolean(parsed),
    reason: error ? String(error.message || error) : ''
  };
}

module.exports = { REMEDIATION_STATES, SAFE_FALLBACK_REASONS, safeFallbackReason, fallbackReasonMessage, classifyRemediationError, remediationResult };
