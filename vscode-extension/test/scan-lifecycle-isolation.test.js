const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  createExecution, snapshotFromLegacy, beginRefresh, updateRefresh,
  completeExecution, projectSnapshot, aggregateRunStatus, finishedScannerCount,
  successfulScannerCount
} = require('../src/security-snapshot');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { appendLocalHistory } = require('../src/scan-history-page');

const allTools = ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP'];
const finding = (tool, id, title = `${tool} ${id}`) => ({ id, fingerprint: id, tool, title, rawSeverity: 'HIGH', file: `${tool}.js`, triageStatus: 'new' });
const completed = (tool) => ({ tool, status: 'completed', durationMs: 25, details: 'done' });

function completedSnapshot() {
  const oldFindings = [
    finding('Semgrep', 'semgrep-old', 'Old Semgrep finding'),
    finding('Gitleaks', 'gitleaks-old', 'Old Gitleaks secret'),
    finding('Trivy', 'trivy-old', 'Old Trivy CVE')
  ];
  return snapshotFromLegacy(oldFindings, ['Semgrep', 'Gitleaks', 'Trivy'].map(completed), {
    executionId: 'previous-scan',
    savedAt: '2026-08-19T10:00:00Z'
  });
}

function pipelinePopover(html, tool) {
  const id = `pipeline-${String(tool).toLowerCase().replace(/[^a-z0-9]+/g, '-')}-findings`;
  const start = html.indexOf(`id="${id}"`);
  assert.notEqual(start, -1, `${tool} popover should exist`);
  const end = html.indexOf('</div>', start);
  return html.slice(start, end + '</div>'.length);
}

function scannerDetailsSection(html) {
  const start = html.indexOf('<section class="page-scanner-details">');
  assert.notEqual(start, -1, 'scanner details section should exist');
  const end = html.indexOf('</section>', start);
  return html.slice(start, end + '</section>'.length);
}

test('terminal scanners are counted separately from successful scanners', () => {
  const statuses = [
    completed('Semgrep'),
    completed('Gitleaks'),
    completed('Trivy'),
    completed('OSV-Scanner'),
    { tool: 'SonarQube', status: 'failed', error: 'SonarQube inaccessible' },
    completed('Snyk'),
    completed('ZAP')
  ];

  assert.equal(finishedScannerCount(statuses), 7);
  assert.equal(successfulScannerCount(statuses), 6);
  assert.equal(aggregateRunStatus(statuses), 'partial');
});

test('all successful terminal scanners aggregate to completed', () => {
  const statuses = allTools.map(completed);
  assert.equal(finishedScannerCount(statuses), 7);
  assert.equal(successfulScannerCount(statuses), 7);
  assert.equal(aggregateRunStatus(statuses), 'completed');
});

test('pending or running scanners keep the aggregate run active', () => {
  const statuses = [
    completed('Semgrep'),
    { tool: 'Gitleaks', status: 'running' },
    { tool: 'Trivy', status: 'pending' }
  ];

  assert.equal(finishedScannerCount(statuses), 1);
  assert.equal(successfulScannerCount(statuses), 1);
  assert.equal(aggregateRunStatus(statuses), 'running');
});

test('cancelled scanners are terminal but not successful', () => {
  const statuses = [
    completed('Semgrep'),
    { tool: 'Gitleaks', status: 'cancelled', error: 'cancelled' }
  ];

  assert.equal(finishedScannerCount(statuses), 2);
  assert.equal(successfulScannerCount(statuses), 1);
  assert.equal(aggregateRunStatus(statuses), 'cancelled');
});

test('skipped and not configured scanners are terminal without fabricating success', () => {
  const statuses = [
    completed('Semgrep'),
    { tool: 'Snyk', status: 'skipped', error: 'disabled by config' },
    { tool: 'ZAP', status: 'not_configured', error: 'target not configured' }
  ];

  assert.equal(finishedScannerCount(statuses), 3);
  assert.equal(successfulScannerCount(statuses), 1);
  assert.equal(aggregateRunStatus(statuses), 'partial');
});

test('starting a new scan does not expose previous scanner counts as current', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: allTools, allTools });
  const projection = projectSnapshot(beginRefresh(completedSnapshot(), execution));
  const gitleaks = projection.scanners.find((scanner) => scanner.tool === 'Gitleaks');
  assert.equal(gitleaks.status, 'pending');
  assert.equal(gitleaks.currentRun.resultCount, null);
  assert.deepEqual(gitleaks.currentRun.findings, []);

  const html = renderDashboardHtml(buildDashboardModel(projection.findings, projection.scanners, {
    scanStatus: 'running',
    activeExecution: execution,
    currentRunFindings: projection.currentRunFindings,
    snapshotAvailable: true
  }), 'nonce');
  assert.match(html, /Gitleaks[\s\S]*<strong>—<\/strong><small>alertes<\/small>/);
});

test('a pending scanner never renders previous findings in hover or details', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Gitleaks'], allTools });
  const projection = projectSnapshot(beginRefresh(completedSnapshot(), execution));
  const model = buildDashboardModel(projection.findings, projection.scanners, {
    scanStatus: 'running',
    activeExecution: execution,
    currentRunFindings: projection.currentRunFindings,
    snapshotAvailable: true
  });
  const pipelineHtml = renderDashboardHtml(model, 'nonce');
  const gitleaksPopover = pipelinePopover(pipelineHtml, 'Gitleaks');
  assert.match(gitleaksPopover, /Gitleaks · — finding\(s\)/);
  assert.match(gitleaksPopover, /No current result for this execution yet/);
  assert.doesNotMatch(gitleaksPopover, /Old Gitleaks secret/);

  model.activeScanner = 'Gitleaks';
  const detailsHtml = scannerDetailsSection(renderDashboardHtml(model, 'nonce', 'scanner-details'));
  assert.match(detailsHtml, /No current result is available for this scanner yet/);
  assert.match(detailsHtml, /<span>Findings<\/span>\s*<strong>—<\/strong>/);
  assert.doesNotMatch(detailsHtml, /Old Gitleaks secret/);
});

test('completing scanner A does not populate scanner B', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Semgrep', 'Gitleaks'], allTools });
  let snapshot = beginRefresh(completedSnapshot(), execution);
  snapshot = updateRefresh(snapshot, 'Semgrep', 'completed', {
    findings: [finding('Semgrep', 'semgrep-new', 'New Semgrep finding')],
    durationMs: 50
  });
  const projection = projectSnapshot(snapshot);
  const semgrep = projection.scanners.find((scanner) => scanner.tool === 'Semgrep');
  const gitleaks = projection.scanners.find((scanner) => scanner.tool === 'Gitleaks');
  assert.equal(semgrep.currentRun.resultCount, 1);
  assert.equal(gitleaks.currentRun.resultCount, null);
  assert.deepEqual(gitleaks.currentRun.findings, []);
});

test('a completed scanner shows only its new run results', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Semgrep'], allTools });
  let snapshot = beginRefresh(completedSnapshot(), execution);
  snapshot = updateRefresh(snapshot, 'Semgrep', 'completed', {
    findings: [finding('Semgrep', 'semgrep-new', 'New Semgrep finding')],
    durationMs: 50
  });
  const projection = projectSnapshot(snapshot);
  const model = buildDashboardModel(projection.findings, projection.scanners, {
    scanStatus: 'running',
    activeExecution: execution,
    currentRunFindings: projection.currentRunFindings,
    snapshotAvailable: true
  });
  model.activeScanner = 'Semgrep';
  const html = scannerDetailsSection(renderDashboardHtml(model, 'nonce', 'scanner-details'));
  assert.match(html, /New Semgrep finding/);
  assert.doesNotMatch(html, /Old Semgrep finding/);
  assert.match(html, /<span>Findings<\/span>\s*<strong>1<\/strong>/);
});

test('a failed scanner does not fall back to its previous successful count', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Gitleaks'], allTools });
  const snapshot = completeExecution(
    beginRefresh(completedSnapshot(), execution),
    execution,
    [],
    [{ tool: 'Gitleaks', status: 'failed', error: 'timeout' }]
  );
  const projection = projectSnapshot(snapshot);
  const gitleaks = projection.scanners.find((scanner) => scanner.tool === 'Gitleaks');
  assert.equal(gitleaks.status, 'failed');
  assert.equal(gitleaks.currentRun.resultCount, null);
  assert.equal(gitleaks.lastCompletedRun.resultCount, 1);

  const model = buildDashboardModel(projection.findings, projection.scanners, { scanStatus: 'partial', snapshotAvailable: true });
  assert.equal(model.finishedScanners, 3);
  assert.equal(model.successfulScanners, 2);
  model.activeScanner = 'Gitleaks';
  const fullHtml = renderDashboardHtml(model, 'nonce');
  assert.match(fullHtml, /Scan partiel — 3\/3 scanners terminés — 2\/3 réussis/);
  assert.match(fullHtml, />↻ Relancer<\/button>/);
  assert.doesNotMatch(fullHtml, /Analyse en cours…/);

  const detailsHtml = scannerDetailsSection(renderDashboardHtml(model, 'nonce', 'scanner-details'));
  assert.match(detailsHtml, /Scan failed/);
  assert.match(detailsHtml, /<span>Findings<\/span>\s*<strong>—<\/strong>/);
  assert.doesNotMatch(detailsHtml, /Old Gitleaks secret/);
});

test('six successful scanners plus failed SonarQube renders as a finished partial run', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: allTools, allTools });
  const newFindings = allTools
    .filter((tool) => tool !== 'SonarQube' && tool !== 'OSV-Scanner' && tool !== 'Snyk')
    .map((tool) => finding(tool, `${tool.toLowerCase()}-new`, `New ${tool} finding`));
  const statuses = allTools.map((tool) => tool === 'SonarQube'
    ? { tool, status: 'failed', error: 'SonarQube inaccessible' }
    : completed(tool));
  const snapshot = completeExecution(beginRefresh(completedSnapshot(), execution), execution, newFindings, statuses);
  const projection = projectSnapshot(snapshot);
  const model = buildDashboardModel(projection.findings, projection.scanners, {
    scanStatus: snapshot.lastExecution.status,
    snapshotAvailable: true,
    lastExecution: snapshot.lastExecution
  });

  assert.equal(snapshot.lastExecution.status, 'partial');
  assert.equal(model.finishedScanners, 7);
  assert.equal(model.successfulScanners, 6);

  const html = renderDashboardHtml(model, 'nonce');
  assert.match(html, /Scan partiel — 7\/7 scanners terminés — 6\/7 réussis/);
  assert.match(html, /7\/7 scanners terminés · 6\/7 réussis/);
  assert.match(html, />↻ Relancer<\/button>/);
  assert.doesNotMatch(html, /Analyse en cours…/);

  const sonar = projection.scanners.find((scanner) => scanner.tool === 'SonarQube');
  assert.equal(sonar.currentRun.resultCount, null);
  assert.deepEqual(sonar.currentRun.findings, []);
  assert.equal(sonar.lastCompletedRun, null);
});

test('progress completion accounting uses terminal finished count', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/extension.js'), 'utf8');
  assert.match(source, /aggregateRunStatus\(scanStatuses, \{ cancelled \}\)/);
  assert.match(source, /finishedScannerCount\(scanStatuses\)/);
  assert.match(source, /successfulScannerCount\(scanStatuses\)/);
  assert.doesNotMatch(source, /scanStatuses\.filter\(\(scanner\) => scanner\.status === 'completed'\)\.length;\s*vscode\.window\.showInformationMessage/);
});

test('scan history retains old results', () => {
  const history = appendLocalHistory([], {
    localId: 'old',
    savedAt: '2026-08-19T10:00:00Z',
    findings: [finding('Gitleaks', 'gitleaks-old', 'Old Gitleaks secret')],
    scanners: [completed('Gitleaks')]
  });
  assert.equal(history.length, 1);
  assert.equal(history[0].findings[0].title, 'Old Gitleaks secret');
});

test('persistent workspace findings are not destroyed when a new scan starts', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Gitleaks'], allTools });
  const projection = projectSnapshot(beginRefresh(completedSnapshot(), execution));
  assert.ok(projection.findings.some((item) => item.title === 'Old Gitleaks secret'));
  assert.equal(projection.currentRunFindings.length, 0);
});

test('cancelling a scan preserves history without marking pending scanners completed', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Semgrep', 'Gitleaks'], allTools });
  const snapshot = completeExecution(
    beginRefresh(completedSnapshot(), execution),
    execution,
    [],
    [
      { tool: 'Semgrep', status: 'cancelled', error: 'cancelled' },
      { tool: 'Gitleaks', status: 'cancelled', error: 'not run' }
    ]
  );
  const projection = projectSnapshot(snapshot);
  assert.equal(projection.scanners.find((scanner) => scanner.tool === 'Gitleaks').status, 'cancelled');
  assert.equal(projection.scanners.find((scanner) => scanner.tool === 'Gitleaks').currentRun.resultCount, null);
  assert.ok(projection.findings.some((item) => item.title === 'Old Gitleaks secret'));
});

test('partial scans distinguish current-run findings from workspace posture', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['Semgrep', 'Gitleaks'], allTools });
  let snapshot = beginRefresh(completedSnapshot(), execution);
  snapshot = updateRefresh(snapshot, 'Semgrep', 'completed', {
    findings: [finding('Semgrep', 'semgrep-new', 'New Semgrep finding')],
    durationMs: 50
  });
  const projection = projectSnapshot(snapshot);
  assert.ok(projection.findings.some((item) => item.title === 'Old Gitleaks secret'));
  assert.deepEqual(projection.currentRunFindings.map((item) => item.title), ['New Semgrep finding']);

  const html = renderDashboardHtml(buildDashboardModel(projection.findings, projection.scanners, {
    scanStatus: 'running',
    activeExecution: execution,
    currentRunFindings: projection.currentRunFindings,
    snapshotAvailable: true
  }), 'nonce');
  assert.match(html, /Résultats du run courant/);
  assert.match(html, /New Semgrep finding/);
  assert.match(pipelinePopover(html, 'Gitleaks'), /Gitleaks · — finding\(s\)/);
});

test('a genuine zero-finding scanner displays 0 only after completion', () => {
  const execution = createExecution({ executionId: 'scan-2', requestedTools: ['OSV-Scanner'], allTools });
  const pendingProjection = projectSnapshot(beginRefresh(completedSnapshot(), execution));
  const pendingOsv = pendingProjection.scanners.find((scanner) => scanner.tool === 'OSV-Scanner');
  assert.equal(pendingOsv.currentRun.resultCount, null);

  let snapshot = beginRefresh(completedSnapshot(), execution);
  snapshot = updateRefresh(snapshot, 'OSV-Scanner', 'completed', { findings: [], durationMs: 10 });
  const completedProjection = projectSnapshot(snapshot);
  const completedOsv = completedProjection.scanners.find((scanner) => scanner.tool === 'OSV-Scanner');
  assert.equal(completedOsv.currentRun.resultCount, 0);

  const model = buildDashboardModel(completedProjection.findings, completedProjection.scanners, {
    scanStatus: 'running',
    activeExecution: execution,
    currentRunFindings: completedProjection.currentRunFindings,
    snapshotAvailable: true
  });
  model.activeScanner = 'OSV-Scanner';
  const html = scannerDetailsSection(renderDashboardHtml(model, 'nonce', 'scanner-details'));
  assert.match(html, /<span>Findings<\/span>\s*<strong>0<\/strong>/);
  assert.match(html, /No findings detected by OSV-Scanner in the current scanner run/);
});
