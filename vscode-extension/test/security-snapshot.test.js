'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  executionType, createExecution, snapshotFromLegacy, normalizeSnapshot,
  beginRefresh, updateRefresh, completeExecution, projectSnapshot
} = require('../src/security-snapshot');
const { createLocalScanCache, restoreLocalScanCache } = require('../src/local-scan-cache');

const tools = ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'ZAP'];
const finding = (tool, id, severity = 'HIGH') => ({ tool, id, title: `${tool} ${id}`, rawSeverity: severity });
const completed = (tool) => ({ tool, status: 'completed', durationMs: 10 });

function fullSnapshot() {
  const execution = createExecution({ executionId: 'full-1', requestedTools: tools, allTools: tools, startedAt: '2026-01-01T00:00:00Z' });
  let snapshot = beginRefresh(snapshotFromLegacy(), execution);
  snapshot = completeExecution(snapshot, execution, tools.map((tool) => finding(tool, 'old')), tools.map(completed), '2026-01-01T00:01:00Z');
  return snapshot;
}

test('execution types distinguish full, partial and retry', () => {
  assert.equal(executionType(tools, tools), 'full');
  assert.equal(executionType(['Semgrep', 'Trivy'], tools), 'partial');
  assert.equal(executionType(['ZAP'], tools), 'retry');
});

test('full scan creates five independently sourced result sets', () => {
  const snapshot = fullSnapshot();
  assert.deepEqual(Object.keys(snapshot.resultSets).sort(), [...tools].sort());
  assert.equal(projectSnapshot(snapshot).findings.length, 5);
  assert.ok(projectSnapshot(snapshot).scanners.every((item) => item.sourceExecutionId === 'full-1'));
});

test('ZAP-only retry preserves the four untouched scanner result sets', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools, parentExecutionId: 'full-1' });
  const running = updateRefresh(beginRefresh(before, retry), 'ZAP', 'running');
  const projection = projectSnapshot(running);
  assert.equal(projection.findings.length, 5);
  assert.equal(projection.scanners.find((item) => item.tool === 'Semgrep').status, 'completed');
  assert.equal(projection.scanners.find((item) => item.tool === 'ZAP').status, 'running');
  assert.equal(projection.scanners.find((item) => item.tool === 'ZAP').previousValidResult, true);
});

test('successful ZAP retry replaces only ZAP and keeps provenance for other tools', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools, parentExecutionId: 'full-1' });
  const after = completeExecution(beginRefresh(before, retry), retry, [finding('ZAP', 'new')], [completed('ZAP')], '2026-01-02T00:00:00Z');
  assert.equal(after.resultSets.ZAP.findings[0].id, 'new');
  assert.equal(after.resultSets.ZAP.sourceExecutionId, 'zap-2');
  assert.equal(after.resultSets.Semgrep.sourceExecutionId, 'full-1');
  assert.equal(projectSnapshot(after).findings.length, 5);
});

test('failed retry keeps the previous valid result and exposes refresh failure', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools });
  const after = completeExecution(beginRefresh(before, retry), retry, [], [{ tool: 'ZAP', status: 'failed', error: 'target unavailable' }]);
  assert.equal(after.resultSets.ZAP.sourceExecutionId, 'full-1');
  assert.equal(after.resultSets.ZAP.findings.length, 1);
  assert.equal(after.refresh.ZAP.state, 'failed');
});

test('cancelled retry does not delete a prior scanner result', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'semgrep-2', requestedTools: ['Semgrep'], allTools: tools });
  const after = completeExecution(beginRefresh(before, retry), retry, [], [{ tool: 'Semgrep', status: 'cancelled' }]);
  assert.equal(after.resultSets.Semgrep.sourceExecutionId, 'full-1');
});

test('a successful zero-finding scanner result intentionally replaces its old findings', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'semgrep-2', requestedTools: ['Semgrep'], allTools: tools });
  const after = completeExecution(beginRefresh(before, retry), retry, [], [completed('Semgrep')]);
  assert.deepEqual(after.resultSets.Semgrep.findings, []);
  assert.equal(projectSnapshot(after).findings.length, 4);
});

test('multiple retries retain latest valid result independently per scanner', () => {
  let snapshot = fullSnapshot();
  const zap = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools });
  snapshot = completeExecution(beginRefresh(snapshot, zap), zap, [finding('ZAP', 'z2')], [completed('ZAP')]);
  const semgrep = createExecution({ executionId: 'semgrep-3', requestedTools: ['Semgrep'], allTools: tools });
  snapshot = completeExecution(beginRefresh(snapshot, semgrep), semgrep, [finding('Semgrep', 's3')], [completed('Semgrep')]);
  assert.equal(snapshot.resultSets.ZAP.sourceExecutionId, 'zap-2');
  assert.equal(snapshot.resultSets.Semgrep.sourceExecutionId, 'semgrep-3');
  assert.equal(snapshot.resultSets.Trivy.sourceExecutionId, 'full-1');
});

test('cache reload restores the consolidated snapshot without flattening provenance', () => {
  const snapshot = fullSnapshot();
  const projection = projectSnapshot(snapshot);
  const cache = createLocalScanCache('C:\\work\\app', projection.findings, projection.scanners, { scanStatus: 'completed' }, '2026-01-01T00:00:00Z', snapshot);
  const restored = restoreLocalScanCache(cache, 'C:\\work\\app');
  const normalized = normalizeSnapshot(restored.securitySnapshot, restored);
  assert.equal(normalized.resultSets.ZAP.sourceExecutionId, 'full-1');
  assert.equal(projectSnapshot(normalized).findings.length, 5);
});

test('legacy cache migrates completed scanner results into snapshot sets', () => {
  const migrated = normalizeSnapshot(null, { findings: [finding('Semgrep', 'a')], scanners: [completed('Semgrep'), { tool: 'ZAP', status: 'failed' }], options: { savedAt: 'old' } });
  assert.equal(migrated.resultSets.Semgrep.findings.length, 1);
  assert.equal(migrated.resultSets.ZAP, undefined);
});

test('refresh state transitions do not mutate the prior snapshot', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools });
  const pending = beginRefresh(before, retry);
  const running = updateRefresh(pending, 'ZAP', 'running');
  assert.equal(before.activeExecution, null);
  assert.equal(pending.refresh.ZAP.state, 'pending');
  assert.equal(running.refresh.ZAP.state, 'running');
});

test('parent execution and immutable execution scope are retained', () => {
  const execution = createExecution({ executionId: 2, requestedTools: ['ZAP'], allTools: tools, parentExecutionId: 1 });
  assert.equal(execution.executionId, '2');
  assert.equal(execution.parentExecutionId, '1');
  assert.deepEqual(execution.scanners, ['ZAP']);
});

test('full scan with ZAP failure keeps successful scanner result sets only', () => {
  const execution = createExecution({ executionId: 'full-failed-zap', requestedTools: tools, allTools: tools });
  const statuses = tools.map((tool) => tool === 'ZAP'
    ? { tool, status: 'failed', error: 'authentication refused' }
    : completed(tool));
  const findings = tools.filter((tool) => tool !== 'ZAP').map((tool) => finding(tool, 'current'));
  const snapshot = completeExecution(beginRefresh(snapshotFromLegacy(), execution), execution, findings, statuses);
  const projection = projectSnapshot(snapshot);
  assert.equal(projection.findings.length, 4);
  assert.equal(snapshot.resultSets.ZAP, undefined);
  assert.equal(projection.scanners.find((item) => item.tool === 'ZAP').status, 'failed');
});

test('mixed partial retry replaces successful tools and preserves failed tools', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'partial-2', requestedTools: ['Semgrep', 'Trivy'], allTools: tools });
  const after = completeExecution(
    beginRefresh(before, retry),
    retry,
    [finding('Semgrep', 'new')],
    [completed('Semgrep'), { tool: 'Trivy', status: 'failed', error: 'timeout' }]
  );
  assert.equal(after.resultSets.Semgrep.sourceExecutionId, 'partial-2');
  assert.equal(after.resultSets.Trivy.sourceExecutionId, 'full-1');
  assert.equal(after.resultSets.Trivy.findings[0].id, 'old');
});

test('successful retry replaces findings without duplicating the old result set', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools });
  const after = completeExecution(beginRefresh(before, retry), retry, [finding('ZAP', 'new')], [completed('ZAP')]);
  const zapFindings = projectSnapshot(after).findings.filter((item) => item.tool === 'ZAP');
  assert.deepEqual(zapFindings.map((item) => item.id), ['new']);
});

test('completed projection keeps prior provenance but exposes retry failure as current state', () => {
  const before = fullSnapshot();
  const retry = createExecution({ executionId: 'zap-2', requestedTools: ['ZAP'], allTools: tools });
  const after = completeExecution(
    beginRefresh(before, retry),
    retry,
    [],
    [{ tool: 'ZAP', status: 'failed', error: 'target unavailable' }]
  );
  const zap = projectSnapshot(after).scanners.find((item) => item.tool === 'ZAP');
  assert.equal(zap.status, 'failed');
  assert.equal(zap.sourceExecutionId, 'zap-2');
  assert.equal(zap.currentRun.resultCount, null);
  assert.equal(zap.lastCompletedRun.sourceExecutionId, 'full-1');
  assert.equal(zap.lastRefreshStatus, 'failed');
  assert.equal(zap.lastRefreshError, 'target unavailable');
  assert.equal(zap.lastRefreshExecutionId, 'zap-2');
});
