const LIVE_SECURITY_STATES = Object.freeze(['disabled', 'idle', 'analyzing', 'clean', 'issues', 'error', 'paused']);

function isLiveSecurityState(value) {
  return LIVE_SECURITY_STATES.includes(value);
}

function createLiveFinding({ uri, range, rule, documentVersion, originalText }) {
  return Object.freeze({
    id: `live:${rule.id}:${range.start.line}:${range.start.character}`,
    uri,
    range,
    severity: rule.severity,
    ruleId: rule.id,
    title: rule.title,
    description: rule.description,
    recommendation: rule.recommendation,
    cwe: rule.cwe,
    confidence: rule.confidence,
    source: 'Security Center Live',
    label: rule.confidence === 'high' ? 'Potential issue' : 'Live warning',
    quickFixAvailable: Boolean(rule.quickFixAvailable),
    originalText,
    documentVersion
  });
}

module.exports = { LIVE_SECURITY_STATES, createLiveFinding, isLiveSecurityState };
