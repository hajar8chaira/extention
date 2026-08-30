'use strict';

const SNAPSHOT_VERSION = 1;
const TERMINAL_SCANNER_STATUSES = new Set(['completed', 'failed', 'cancelled', 'skipped', 'not_configured', 'disabled', 'unavailable', 'error']);
const SUCCESSFUL_SCANNER_STATUSES = new Set(['completed']);

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

function scannerStatusValue(status) {
  return String(status?.status || status || '').toLowerCase().replace(/[\s-]+/g, '_');
}

function isTerminalScannerStatus(status) {
  return TERMINAL_SCANNER_STATUSES.has(scannerStatusValue(status));
}

function isSuccessfulScannerStatus(status) {
  return SUCCESSFUL_SCANNER_STATUSES.has(scannerStatusValue(status));
}

function finishedScannerCount(scannerStatuses = []) {
  return scannerStatuses.filter(isTerminalScannerStatus).length;
}

function successfulScannerCount(scannerStatuses = []) {
  return scannerStatuses.filter(isSuccessfulScannerStatus).length;
}

function aggregateRunStatus(scannerStatuses = [], options = {}) {
  if (options.cancelled) return 'cancelled';
  if (!Array.isArray(scannerStatuses) || !scannerStatuses.length) return 'idle';
  if (scannerStatuses.some((status) => !isTerminalScannerStatus(status))) return 'running';
  if (scannerStatuses.some((status) => scannerStatusValue(status) === 'cancelled')) return 'cancelled';
  return scannerStatuses.every(isSuccessfulScannerStatus) ? 'completed' : 'partial';
}

function completeExecution(snapshot, execution, executionFindings, scannerStatuses, finishedAt = new Date().toISOString()) {
  const resultSets = { ...(snapshot.resultSets || {}) };
  const refresh = { ...(snapshot.refresh || {}) };
  for (const status of scannerStatuses) {
    if (status.status === 'completed') resultSets[status.tool] = resultSet(status.tool, executionFindings.filter((finding) => finding.tool === status.tool), status, execution, finishedAt);
    const terminalState = isTerminalScannerStatus(status) ? scannerStatusValue(status) : 'failed';
    refresh[status.tool] = {
      state: terminalState,
      activeExecutionId: execution.executionId,
      ...(status.error ? { error: status.error } : {})
    };
  }
  return {
    version: SNAPSHOT_VERSION,
    resultSets,
    refresh,
    lastExecutionId: execution.executionId,
    lastExecution: { ...execution, finishedAt, status: aggregateRunStatus(scannerStatuses) },
    activeExecution: null
  };
}

function projectSnapshot(snapshot) {
  const normalized = normalizeSnapshot(snapshot);
  const findings = [];
  const scanners = [];
  const currentRunFindings = [];
  const preferredOrder = ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP'];
  const availableTools = new Set([...Object.keys(normalized.resultSets || {}), ...Object.keys(normalized.refresh || {})]);
  const tools = [...preferredOrder.filter((tool) => availableTools.delete(tool)), ...availableTools];
  for (const tool of tools) {
    const set = normalized.resultSets?.[tool];
    const refreshing = normalized.activeExecution && normalized.refresh?.[tool];
    const refresh = normalized.refresh?.[tool];
    if (set) findings.push(...set.findings.map((finding) => refreshing ? { ...finding, previousResultRefreshing: true } : finding));
    if (refreshing && refresh.state === 'completed' && Array.isArray(refresh.findings)) {
      currentRunFindings.push(...refresh.findings);
    }
    if (refreshing) {
      scanners.push({
        ...(set?.scannerStatus || { tool }), tool,
        status: refresh.state,
        refreshState: refresh.state,
        activeExecutionId: refresh.activeExecutionId,
        previousValidResult: Boolean(set),
        previousFindingCount: set?.findings.length || 0,
        lastCompletedRun: set ? {
          sourceExecutionId: set.sourceExecutionId,
          completedAt: set.completedAt,
          resultCount: set.findings.length,
          scannerStatus: set.scannerStatus
        } : null,
        currentRun: {
          sourceExecutionId: refresh.activeExecutionId,
          status: refresh.state,
          resultCount: refresh.state === 'completed' && Array.isArray(refresh.findings) ? refresh.findings.length : null,
          findings: refresh.state === 'completed' && Array.isArray(refresh.findings) ? [...refresh.findings] : [],
          durationMs: Number.isFinite(refresh.durationMs) ? refresh.durationMs : null,
          startedAt: refresh.startedAt || '',
          completedAt: refresh.completedAt || '',
          details: refresh.state === 'completed' ? refresh.details || '' : '',
          error: refresh.error || ''
        },
        sourceExecutionId: refresh.state === 'completed' ? refresh.activeExecutionId : set?.sourceExecutionId,
        completedAt: refresh.state === 'completed' ? refresh.completedAt || set?.completedAt : set?.completedAt,
        details: refresh.state === 'completed' ? refresh.details : undefined,
        durationMs: refresh.state === 'completed' ? refresh.durationMs : undefined,
        error: refresh.error
      });
    } else if (set) {
      const lastRefresh = normalized.refresh?.[tool];
      const lastRefreshFailed = lastRefresh && lastRefresh.state !== 'completed';
      scanners.push({
        ...set.scannerStatus,
        tool,
        status: lastRefreshFailed ? lastRefresh.state : 'completed',
        sourceExecutionId: lastRefreshFailed ? lastRefresh.activeExecutionId : set.sourceExecutionId,
        completedAt: lastRefreshFailed ? '' : set.completedAt,
        durationMs: lastRefreshFailed ? undefined : set.scannerStatus?.durationMs,
        details: lastRefreshFailed ? undefined : set.scannerStatus?.details,
        error: lastRefreshFailed ? lastRefresh.error : set.scannerStatus?.error,
        currentRun: lastRefreshFailed ? {
          sourceExecutionId: lastRefresh.activeExecutionId,
          status: lastRefresh.state,
          resultCount: null,
          findings: [],
          durationMs: Number.isFinite(lastRefresh.durationMs) ? lastRefresh.durationMs : null,
          error: lastRefresh.error || ''
        } : {
          sourceExecutionId: set.sourceExecutionId,
          status: 'completed',
          resultCount: set.findings.length,
          findings: [...set.findings],
          durationMs: Number.isFinite(set.scannerStatus?.durationMs) ? set.scannerStatus.durationMs : null,
          completedAt: set.completedAt,
          details: set.scannerStatus?.details || ''
        },
        lastCompletedRun: {
          sourceExecutionId: set.sourceExecutionId,
          completedAt: set.completedAt,
          resultCount: set.findings.length,
          scannerStatus: set.scannerStatus
        },
        ...(lastRefreshFailed
          ? { previousValidResult: true, previousFindingCount: set.findings.length, lastRefreshStatus: lastRefresh.state, lastRefreshError: lastRefresh.error, lastRefreshExecutionId: lastRefresh.activeExecutionId }
          : {})
      });
    } else if (refresh) scanners.push({
      tool,
      status: refresh.state,
      activeExecutionId: refresh.activeExecutionId,
      error: refresh.error,
      currentRun: {
        sourceExecutionId: refresh.activeExecutionId,
        status: refresh.state,
        resultCount: null,
        findings: [],
        durationMs: Number.isFinite(refresh.durationMs) ? refresh.durationMs : null,
        error: refresh.error || ''
      },
      lastCompletedRun: null
    });
  }
  return { findings, scanners, currentRunFindings, activeExecution: normalized.activeExecution, lastExecution: normalized.lastExecution };
}

module.exports = {
  SNAPSHOT_VERSION,
  TERMINAL_SCANNER_STATUSES,
  SUCCESSFUL_SCANNER_STATUSES,
  executionType,
  createExecution,
  snapshotFromLegacy,
  normalizeSnapshot,
  beginRefresh,
  updateRefresh,
  completeExecution,
  projectSnapshot,
  scannerStatusValue,
  isTerminalScannerStatus,
  isSuccessfulScannerStatus,
  finishedScannerCount,
  successfulScannerCount,
  aggregateRunStatus
};
