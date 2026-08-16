'use strict';

const SNAPSHOT_VERSION = 1;

function executionType(requestedTools, allTools = []) {
  if (!Array.isArray(requestedTools) || !requestedTools.length) return 'full';
  if (requestedTools.length === 1) return 'retry';
  return requestedTools.length >= allTools.length && allTools.every((tool) => requestedTools.includes(tool)) ? 'full' : 'partial';
}

function createExecution({ executionId, requestedTools, allTools, parentExecutionId, startedAt = new Date().toISOString() }) {
  return {
    executionId: String(executionId),
    type: executionType(requestedTools, allTools),
    scanners: [...requestedTools],
    ...(parentExecutionId ? { parentExecutionId: String(parentExecutionId) } : {}),
    startedAt,
    status: 'running'
  };
}

function resultSet(scanner, findings, status, execution, completedAt = new Date().toISOString()) {
  return {
    scanner,
    sourceExecutionId: String(execution.executionId),
    completedAt,
    status: status.status,
    findings: [...findings],
    scannerStatus: { ...status, tool: scanner, sourceExecutionId: String(execution.executionId), completedAt }
  };
}

function snapshotFromLegacy(findings = [], scanners = [], options = {}) {
  const fallbackId = String(options.executionId || options.scanId || `legacy-${options.savedAt || 'unknown'}`);
  const resultSets = {};
  for (const scanner of scanners) {
    if (scanner.status !== 'completed') continue;
    resultSets[scanner.tool] = {
      scanner: scanner.tool,
      sourceExecutionId: String(scanner.sourceExecutionId || fallbackId),
      completedAt: scanner.completedAt || options.savedAt || '',
      status: 'completed',
      findings: findings.filter((finding) => finding.tool === scanner.tool),
      scannerStatus: { ...scanner, sourceExecutionId: String(scanner.sourceExecutionId || fallbackId) }
    };
  }
  return { version: SNAPSHOT_VERSION, resultSets, lastExecutionId: fallbackId };
}

function normalizeSnapshot(snapshot, legacy = {}) {
  if (snapshot?.version === SNAPSHOT_VERSION && snapshot.resultSets && typeof snapshot.resultSets === 'object') return snapshot;
  return snapshotFromLegacy(legacy.findings, legacy.scanners, legacy.options);
}

function beginRefresh(snapshot, execution) {
  const normalized = normalizeSnapshot(snapshot);
  const refresh = {};
  for (const scanner of execution.scanners) refresh[scanner] = { state: 'pending', activeExecutionId: execution.executionId };
  return { ...normalized, activeExecution: execution, refresh };
}

function updateRefresh(snapshot, scanner, state, extra = {}) {
  return { ...snapshot, refresh: { ...(snapshot.refresh || {}), [scanner]: { ...(snapshot.refresh?.[scanner] || {}), state, ...extra } } };
}

function completeExecution(snapshot, execution, executionFindings, scannerStatuses, finishedAt = new Date().toISOString()) {
  const resultSets = { ...(snapshot.resultSets || {}) };
  const refresh = { ...(snapshot.refresh || {}) };
  for (const status of scannerStatuses) {
    if (status.status === 'completed') resultSets[status.tool] = resultSet(status.tool, executionFindings.filter((finding) => finding.tool === status.tool), status, execution, finishedAt);
    refresh[status.tool] = {
      state: status.status === 'completed' ? 'completed' : status.status === 'cancelled' ? 'cancelled' : 'failed',
      activeExecutionId: execution.executionId,
      ...(status.error ? { error: status.error } : {})
    };
  }
  return {
    version: SNAPSHOT_VERSION,
    resultSets,
    refresh,
    lastExecutionId: execution.executionId,
    lastExecution: { ...execution, finishedAt, status: scannerStatuses.every((item) => item.status === 'completed') ? 'completed' : 'partial' },
    activeExecution: null
  };
}

function projectSnapshot(snapshot) {
  const normalized = normalizeSnapshot(snapshot);
  const findings = [];
  const scanners = [];
  const preferredOrder = ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'ZAP'];
  const availableTools = new Set([...Object.keys(normalized.resultSets || {}), ...Object.keys(normalized.refresh || {})]);
  const tools = [...preferredOrder.filter((tool) => availableTools.delete(tool)), ...availableTools];
  for (const tool of tools) {
    const set = normalized.resultSets?.[tool];
    const refreshing = normalized.activeExecution && normalized.refresh?.[tool];
    if (set) findings.push(...set.findings.map((finding) => refreshing ? { ...finding, previousResultRefreshing: true } : finding));
    if (refreshing) {
      scanners.push({
        ...(set?.scannerStatus || { tool }), tool,
        status: normalized.refresh[tool].state,
        refreshState: normalized.refresh[tool].state,
        activeExecutionId: normalized.refresh[tool].activeExecutionId,
        previousValidResult: Boolean(set),
        previousFindingCount: set?.findings.length || 0,
        sourceExecutionId: set?.sourceExecutionId,
        completedAt: set?.completedAt,
        error: normalized.refresh[tool].error
      });
    } else if (set) scanners.push({
      ...set.scannerStatus, tool, status: 'completed', sourceExecutionId: set.sourceExecutionId, completedAt: set.completedAt,
      ...(normalized.refresh?.[tool] && normalized.refresh[tool].state !== 'completed'
        ? { lastRefreshStatus: normalized.refresh[tool].state, lastRefreshError: normalized.refresh[tool].error, lastRefreshExecutionId: normalized.refresh[tool].activeExecutionId }
        : {})
    });
    else if (normalized.refresh?.[tool]) scanners.push({ tool, status: normalized.refresh[tool].state, activeExecutionId: normalized.refresh[tool].activeExecutionId, error: normalized.refresh[tool].error });
  }
  return { findings, scanners, activeExecution: normalized.activeExecution, lastExecution: normalized.lastExecution };
}

module.exports = { SNAPSHOT_VERSION, executionType, createExecution, snapshotFromLegacy, normalizeSnapshot, beginRefresh, updateRefresh, completeExecution, projectSnapshot };
