const SENSITIVE_KEY = /(authorization|cookie|password|passwd|secret|token|api[-_]?key|private[-_]?key)/i;

const LEGACY_PREFIXES = [
  [/^status:/, 'TRIAGE'],
  [/^zap:/, 'DAST'],
  [/^http-replay:/, 'HTTP']
];

const CATEGORY_MAP = {
  'finding.triage.changed': 'TRIAGE',
  'finding.risk.accepted': 'TRIAGE',
  'finding.fixed': 'TRIAGE',
  'finding.fix.validated': 'TRIAGE',
  'ai.fix.requested': 'REMEDIATION',
  'ai.fix.applied': 'REMEDIATION',
  'ai.rollback': 'REMEDIATION',
  'scanner.run.started': 'SCANNER',
  'scanner.run.completed': 'SCANNER',
  'scanner.run.failed': 'SCANNER',
  'scanner.retry': 'SCANNER',
  'policy.gate.evaluated': 'POLICY',
  'policy.gate.blocked': 'POLICY',
  'supplychain.sbom.generated': 'SUPPLY_CHAIN',
  'supplychain.provenance.generated': 'SUPPLY_CHAIN',
  'supplychain.key.generated': 'SUPPLY_CHAIN',
  'supplychain.artifact.signed': 'SUPPLY_CHAIN',
  'supplychain.signature.verified': 'SUPPLY_CHAIN',
  'policy.changed': 'CONFIGURATION',
  'scanner.configuration.changed': 'CONFIGURATION',
  'ai.configuration.changed': 'CONFIGURATION'
};

const RESULT_MAP = {
  'finding.triage.changed': 'SUCCESS',
  'finding.risk.accepted': 'ACCEPTED',
  'finding.fixed': 'SUCCESS',
  'finding.fix.validated': 'VALIDATED',
  'ai.fix.requested': 'PENDING',
  'ai.fix.applied': 'SUCCESS',
  'ai.rollback': 'ROLLBACK',
  'scanner.run.started': 'PENDING',
  'scanner.run.completed': 'SUCCESS',
  'scanner.run.failed': 'FAILED',
  'scanner.retry': 'PENDING',
  'policy.gate.evaluated': 'SUCCESS',
  'policy.gate.blocked': 'BLOCKED',
  'supplychain.sbom.generated': 'SUCCESS',
  'supplychain.provenance.generated': 'SUCCESS',
  'supplychain.key.generated': 'SUCCESS',
  'supplychain.artifact.signed': 'SUCCESS',
  'supplychain.signature.verified': 'VALIDATED',
  'policy.changed': 'SUCCESS',
  'scanner.configuration.changed': 'SUCCESS',
  'ai.configuration.changed': 'SUCCESS'
};

function redactAuditValue(value, key = '') {
  if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((item) => redactAuditValue(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactAuditValue(item, name)]));
  }
  return value;
}

function legacyCategory(action) {
  if (CATEGORY_MAP[action]) return CATEGORY_MAP[action];
  return LEGACY_PREFIXES.find(([pattern]) => pattern.test(action))?.[1] || null;
}

function legacyResult(action) {
  if (RESULT_MAP[action]) return RESULT_MAP[action];
  if (/:authorized$/.test(action)) return 'AUTHORIZED';
  if (/:completed$/.test(action)) return 'SUCCESS';
  const status = action.match(/^status:(.+)$/)?.[1];
  return ({ confirmed: 'CONFIRMED', accepted: 'ACCEPTED', false_positive: 'IGNORED', validated: 'VALIDATED', fixed: 'SUCCESS' })[status] || null;
}

function normalizeAuditEvent(event) {
  const action = String(event.action || 'unknown');
  return {
    ...event,
    category: event.category || legacyCategory(action),
    actor_type: event.actor_type || event.actorType || (event.actor ? 'USER' : 'SYSTEM'),
    actor: event.actor || 'Security Center',
    result: event.result || legacyResult(action),
    scan_id: event.scan_id === 0 ? null : (event.scan_id ?? event.scanId ?? null),
    finding_id: event.finding_id || event.findingId || null,
    metadata: redactAuditValue(event.metadata || {})
  };
}

function sanitizeAuditEvent(event) {
  const normalized = normalizeAuditEvent(event);
  return { ...normalized, metadata: redactAuditValue(normalized.metadata), reason: redactAuditValue(normalized.reason || ''), comment: redactAuditValue(normalized.comment || '') };
}

module.exports = { SENSITIVE_KEY, redactAuditValue, legacyCategory, legacyResult, normalizeAuditEvent, sanitizeAuditEvent };
