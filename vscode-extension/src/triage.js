const ALLOWED_STATUSES = Object.freeze([
  'new', 'triaged', 'probable', 'confirmed', 'fixed', 'validated', 'false_positive', 'accepted'
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

module.exports = { ALLOWED_STATUSES, findingKey, normalizeStatus, applyFindingStatuses, isActiveFinding, validatedAfterScan, retainValidatedFindings };
