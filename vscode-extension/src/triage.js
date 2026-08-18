const ALLOWED_STATUSES = Object.freeze([
  'new', 'triaged', 'probable', 'confirmed', 'fixed', 'validated', 'false_positive', 'accepted',
  // Verification lifecycle states. Added rather than substituted: every status
  // above keeps its persisted spelling and its meaning, so existing caches,
  // backend records and dashboards read exactly as before.
  'fix_proposed', 'validating', 'still_present', 'validation_failed', 'inconclusive', 'regressed'
]);

/**
 * Outcomes that mean « the vulnerability was not shown to be gone ».
 *
 * They stay ACTIVE on purpose. A verification that failed, was cancelled, or
 * came back inconclusive tells us nothing reassuring, and the one thing a
 * security tool must never do is quietly downgrade an unknown into a resolution.
 */
const UNRESOLVED_VERIFICATION = Object.freeze([
  'validating', 'still_present', 'validation_failed', 'inconclusive', 'regressed', 'fix_proposed'
]);

function findingKey(finding) {
  return finding.fingerprint || finding.id;
}

function normalizeStatus(status) {
  return ALLOWED_STATUSES.includes(status) ? status : 'new';
}

function applyFindingStatuses(findings, statuses = {}) {
  return findings.map((finding) => ({
    ...finding,
    triageStatus: normalizeStatus(statuses[findingKey(finding)])
  }));
}

function isActiveFinding(finding) {
  return !['false_positive', 'fixed', 'validated'].includes(normalizeStatus(finding.triageStatus));
}

function validatedAfterScan(previousFindings, currentFindings, scannerStatuses) {
  const completedTools = new Set((scannerStatuses || [])
    .filter((scanner) => scanner.status === 'completed')
    .map((scanner) => scanner.tool));
  const currentKeys = new Set((currentFindings || []).map(findingKey));
  return (previousFindings || []).filter((finding) =>
    normalizeStatus(finding.triageStatus) === 'fixed'
    && completedTools.has(finding.tool)
    && !currentKeys.has(findingKey(finding))
  );
}

function retainValidatedFindings(currentFindings, validatedFindings, validatedAt = new Date().toISOString()) {
  const currentKeys = new Set((currentFindings || []).map(findingKey));
  return [
    ...(currentFindings || []),
    ...(validatedFindings || [])
      .filter((finding) => !currentKeys.has(findingKey(finding)))
      .map((finding) => ({ ...finding, triageStatus: 'validated', validatedAt }))
  ];
}

/**
 * Separates « a fix was applied » from « the issue is gone ».
 *
 * Both were previously counted together as resolved, which is the conflation
 * this split exists to remove: `fixApplied` is a claim awaiting evidence, and
 * `validated` is the evidence. Callers that legitimately want the old combined
 * number can still add them, but they now have to say so.
 */
function remediationCounters(findings = []) {
  const counted = { fixApplied: 0, validated: 0, stillPresent: 0, inconclusive: 0, regressed: 0 };
  for (const finding of Array.isArray(findings) ? findings : []) {
    const status = normalizeStatus(finding?.triageStatus);
    if (status === 'fixed') counted.fixApplied += 1;
    else if (status === 'validated') counted.validated += 1;
    else if (status === 'still_present') counted.stillPresent += 1;
    else if (status === 'inconclusive' || status === 'validation_failed') counted.inconclusive += 1;
    else if (status === 'regressed') counted.regressed += 1;
  }
  return counted;
}

module.exports = {
  ALLOWED_STATUSES, UNRESOLVED_VERIFICATION, findingKey, normalizeStatus, applyFindingStatuses,
  isActiveFinding, validatedAfterScan, retainValidatedFindings, remediationCounters
};
