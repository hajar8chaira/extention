const test = require('node:test');
const assert = require('node:assert/strict');
const { buildTrendReport, renderTrendReportHtml } = require('../src/trends');

function scan(id, date, findings) {
  return { scan_id: id, result: { finished_at: date, findings } };
}

test('calcule les tendances actives et le MTTR avec preuves temporelles', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }, { id: 'b', rawSeverity: 'LOW', triageStatus: 'new' }]),
    scan(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'validated' }, { id: 'b', rawSeverity: 'LOW', triageStatus: 'new' }])
  ];
  // Nom d'action REEL emis aujourd'hui par l'extension (extension.js — bloc de
  // revalidation apres re-scan). L'ancien fixture utilisait « status:validated »,
  // un nom que le produit n'emet plus : le test passait alors que le MTTR etait
  // mort en production.
  const report = buildTrendReport(scans, [{ finding_id: 'a', action: 'finding.fix.validated', created_at: '2026-08-02T00:00:00Z' }], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points.length, 2);
  assert.equal(report.latest.active, 1);
  assert.equal(report.change, -1);
  assert.equal(report.mttrHours, 24);
  assert.equal(report.resolvedCount, 1);
});

test('MTTR : chaque nom d’action de resolution reellement emis est reconnu', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }]),
    scan(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'validated' }])
  ];
  // Les trois noms que `createAuditEvent` recoit aujourd'hui pour une correction
  // reellement verifiee, plus les deux noms historiques encore presents dans les
  // backends existants.
  for (const action of ['finding.fixed', 'finding.fix.validated', 'fix.verification.validated', 'status:fixed', 'status:validated']) {
    const report = buildTrendReport(scans, [{ finding_id: 'a', action, created_at: '2026-08-02T00:00:00Z' }], 90, new Date('2026-08-03T00:00:00Z'));
    assert.equal(report.mttrHours, 24, `${action} devrait produire un MTTR`);
    assert.equal(report.resolvedCount, 1, `${action} devrait compter une resolution`);
  }
});

test('MTTR : une correction appliquee mais non verifiee ne compte pas', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }]),
    scan(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'fixed' }])
  ];
  // `fix.verification.*` couvre neuf etats du cycle de vie. Seul `validated` est
  // une resolution : compter `fixed` (patch applique, verification en attente)
  // mesurerait le delai de patch en l'appelant MTTR. Un risque accepte n'est pas
  // davantage une correction.
  for (const action of ['fix.verification.fixed', 'fix.verification.still_present', 'fix.verification.inconclusive', 'fix.verification.validation_failed', 'fix.verification.regressed', 'finding.risk.accepted', 'finding.triage.changed']) {
    const report = buildTrendReport(scans, [{ finding_id: 'a', action, created_at: '2026-08-02T00:00:00Z' }], 90, new Date('2026-08-03T00:00:00Z'));
    assert.equal(report.mttrHours, null, `${action} ne doit pas produire de MTTR`);
    assert.equal(report.resolvedCount, 0, `${action} ne doit pas compter de resolution`);
  }
});

test('MTTR : une alerte portant une empreinte est resolvable par son finding_id', () => {
  // Gitleaks, SonarQube et Snyk fournissent une empreinte. L'index « premiere
  // apparition » etait alors range sous l'empreinte, alors que l'evenement
  // d'audit porte `finding_id` : la recherche echouait et l'alerte disparaissait
  // silencieusement du MTTR, quel que soit le nom d'action.
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', fingerprint: 'fp-a', rawSeverity: 'HIGH', triageStatus: 'new' }]),
    scan(2, '2026-08-02T00:00:00Z', [{ id: 'a', fingerprint: 'fp-a', rawSeverity: 'HIGH', triageStatus: 'validated' }])
  ];
  const byId = buildTrendReport(scans, [{ finding_id: 'a', action: 'finding.fix.validated', created_at: '2026-08-02T00:00:00Z' }], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(byId.mttrHours, 24);
  assert.equal(byId.resolvedCount, 1);
  // L'empreinte reste une identite valide : rien n'est retire.
  const byFingerprint = buildTrendReport(scans, [{ finding_id: 'fp-a', action: 'finding.fix.validated', created_at: '2026-08-02T00:00:00Z' }], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(byFingerprint.mttrHours, 24);
  assert.equal(byFingerprint.resolvedCount, 1);
});

test('MTTR : les deux evenements emis pour une meme correction ne comptent qu’une fois', () => {
  // L'extension emet `finding.fixed` PUIS `finding.fix.validated` pour la meme
  // alerte dans la meme boucle. La resolution ne doit etre comptee qu'une fois.
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }]),
    scan(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'validated' }])
  ];
  const report = buildTrendReport(scans, [
    { finding_id: 'a', action: 'finding.fixed', created_at: '2026-08-02T00:00:00Z' },
    { finding_id: 'a', action: 'finding.fix.validated', created_at: '2026-08-02T00:00:00Z' }
  ], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.resolvedCount, 1);
  assert.equal(report.mttrHours, 24);
});

test('n\u2019invente pas de MTTR sans \u00e9v\u00e9nement de correction', () => {
  const report = buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.mttrHours, null);
  assert.match(renderTrendReportHtml(report, 'nonce'), /Aucune correction valid\u00e9e/);
});

test('\u00e9chappe les donn\u00e9es du rapport de tendances', () => {
  const report = buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 90, new Date('2026-08-03T00:00:00Z'));
  const html = renderTrendReportHtml(report, 'nonce');
  assert.match(html, /Tendances de s\u00e9curit\u00e9/);
  assert.match(html, /script-src 'nonce-nonce'/);
});

test('la page tendances suit le th\u00e8me global et revient au dashboard', () => {
  const report = buildTrendReport([], [], 90, new Date('2026-08-03T00:00:00Z'));
  const light = renderTrendReportHtml(report, 'nonce', 'light');
  const dark = renderTrendReportHtml(report, 'nonce', 'dark');
  assert.match(light, /class="theme-light[^"]*"/);
  assert.match(dark, /class="theme-dark[^"]*"/);
  // La page vit dans le cadre applicatif : le retour au dashboard est porte par
  // la navigation partagee, et Trends & MTTR y est l'item courant.
  assert.match(light, /class="sc-internal-nav"/);
  assert.match(light, /data-command="securityCenter\.openDashboard"/);
  assert.match(light, /<button class="sc-nav-item active"[^>]*data-command="securityCenter\.showTrends"/);
  assert.doesNotMatch(light, /\u2190 Dashboard/);
  assert.doesNotMatch(light, /#58a6ff/);
});

test('calcule correctement la r\u00e9partition des s\u00e9v\u00e9rit\u00e9s, y compris moyennes et faibles', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [
      { id: '1', rawSeverity: 'CRITICAL', triageStatus: 'new' },
      { id: '2', rawSeverity: 'ERROR', triageStatus: 'new' },
      { id: '3', rawSeverity: 'HIGH', triageStatus: 'new' },
      { id: '4', rawSeverity: 'MEDIUM', triageStatus: 'new' },
      { id: '5', rawSeverity: 'WARNING', triageStatus: 'new' },
      { id: '6', rawSeverity: 'LOW', triageStatus: 'new' },
      { id: '7', rawSeverity: 'INFO', triageStatus: 'new' }
    ])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  const pt = report.points[0];
  assert.equal(pt.critical, 1); // CRITICAL
  assert.equal(pt.high, 2);     // HIGH + ERROR
  assert.equal(pt.medium, 2);   // MEDIUM + WARNING
  assert.equal(pt.low, 2);      // LOW + INFO
});

test('filtre les points en fonction des jours demand\u00e9s (7, 30, 90)', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', []), // 1 jour avant
    scan(2, '2026-07-20T00:00:00Z', []), // 13 jours avant
    scan(3, '2026-07-01T00:00:00Z', [])  // 32 jours avant
  ];
  const now = new Date('2026-08-02T00:00:00Z');
  
  const report7 = buildTrendReport(scans, [], 7, now);
  const report30 = buildTrendReport(scans, [], 30, now);
  const report90 = buildTrendReport(scans, [], 90, now);
  
  assert.equal(report7.points.length, 1);
  assert.equal(report30.points.length, 2);
  assert.equal(report90.points.length, 3);
});

test('le rendu HTML supporte la structure multi-p\u00e9riode et inclut le s\u00e9lecteur et le graphique', () => {
  const scans = [scan(1, '2026-08-01T00:00:00Z', [])];
  const now = new Date('2026-08-02T00:00:00Z');
  
  const reports = {
    7: buildTrendReport(scans, [], 7, now),
    30: buildTrendReport(scans, [], 30, now),
    90: buildTrendReport(scans, [], 90, now)
  };
  
  const html = renderTrendReportHtml(reports, 'nonce-test');
  
  // S\u00e9lecteur de p\u00e9riode
  assert.match(html, /class="period-selector"/);
  assert.match(html, /data-days="7"/);
  assert.match(html, /data-days="30"/);
  assert.match(html, /data-days="90"/);
  
  // Graphique SVG et l\u00e9gende
  assert.match(html, /id="svg-chart"/);
  assert.match(html, /class="trend-legend"/);
  assert.match(html, /data-series="total"/);
  assert.match(html, /data-series="critical"/);
  
  // Activit\u00e9 r\u00e9cente et conteneur de tooltip
  assert.match(html, /id="recent-activity-list"/);
  assert.match(html, /id="tooltip"/);
  assert.match(html, /class="trend-chart-wrapper"/);
  
  // Historique de la p\u00e9riode collapsible
  assert.match(html, /<details class="raw-history-details"/);
  assert.match(html, /Historique de la p\u00e9riode/);
});

function scanWithScanners(id, date, findings, scanners) {
  return { scan_id: id, result: { finished_at: date, findings, scanners } };
}

test('light theme has no hardcoded dark side background', () => {
  const report = buildTrendReport([], [], 90, new Date('2026-08-03T00:00:00Z'));
  const html = renderTrendReportHtml(report, 'nonce', 'light');
  assert.doesNotMatch(html, /background:\s*(#000|#111|#1e1e1e|#202020)/);
});

test('valid positive trend', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [
      { id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' },
      { id: 'b', rawSeverity: 'HIGH', triageStatus: 'new' }
    ], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[1].trend.display, '\u2191 100.0 % D\u00e9gradation');
  assert.equal(report.points[1].trend.color, 'bad');
});

test('valid negative trend', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [
      { id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' },
      { id: 'b', rawSeverity: 'HIGH', triageStatus: 'new' }
    ], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[1].trend.display, '\u2193 50.0 % Am\u00e9lioration');
  assert.equal(report.points[1].trend.color, 'good');
});

test('zero change', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[1].trend.display, '\u2192 0 % Stable');
  assert.equal(report.points[1].trend.color, 'neutral');
});

test('unavailable trend for partial/incomplete state due to different scanner coverage', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [
      { tool: 'Semgrep', status: 'completed' },
      { tool: 'ZAP', status: 'completed' }
    ])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[0].trend.display, 'N/A Non comparable');
  assert.equal(report.points[0].trend.color, 'muted');
  assert.match(report.points[0].trend.tooltip, /couverture de scanners incompl\u00e8te/);
});

test('failed/cancelled scan does not produce fake 0%', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'failed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[1].trend.display, 'N/A Non comparable');
  assert.equal(report.points[1].trend.color, 'muted');
  assert.match(report.points[1].trend.tooltip, /couverture de scanners incompl\u00e8te/);
});

test('real zero finding snapshot can produce a valid trend', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-03T00:00:00Z'));
  assert.equal(report.points[1].trend.display, '\u2192 0 % Stable');
  assert.equal(report.points[1].trend.color, 'neutral');
});

// ============================================================
// NEW TESTS: chart upgrade
// ============================================================

test('default visible series: Total, Critical, High enabled — Medium, Low disabled', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Total, Critical, High legend buttons should have the 'active' class
  assert.match(html, /legend-btn active" data-series="total"/);
  assert.match(html, /legend-btn active" data-series="critical"/);
  assert.match(html, /legend-btn active" data-series="high"/);
  // Medium and Low should NOT have 'active'
  assert.match(html, /legend-btn" data-series="medium"/);
  assert.match(html, /legend-btn" data-series="low"/);

  // In the JS state, critical and high default to true
  assert.match(html, /critical:\s*true/);
  assert.match(html, /high:\s*true/);
  assert.match(html, /medium:\s*false/);
  assert.match(html, /low:\s*false/);
});

test('chart viewBox is 900x400 (large chart)', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /viewBox="0 0 900 400"/);
  // Chart wrapper height should be 400px
  assert.match(html, /height:\s*400px/);
});

test('chart footer container exists in HTML output', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /id="chart-footer"/);
  assert.match(html, /class="chart-footer"/);
});

test('brush timeline container exists in HTML output', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /id="brush-container"/);
  assert.match(html, /id="brush-svg"/);
  assert.match(html, /class="brush-svg"/);
});

test('crosshair CSS class is defined', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /\.chart-crosshair/);
});

test('pin/unpin: script handles click-to-pin and Escape-to-unpin', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Script should contain pinnedPointIndex state variable
  assert.match(html, /pinnedPointIndex/);
  // Should handle click events on svg
  assert.match(html, /svg\.addEventListener\('click'/);
  // Should handle Escape key
  assert.match(html, /e\.key === 'Escape'/);
  // Should handle click outside
  assert.match(html, /wrapper\.contains\(e\.target\)/);
});

test('tooltip contains change vs previous comparable text in script', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Script should contain buildTooltipHtml that shows prev comparable delta
  assert.match(html, /vs pr\u00e9c\u00e9dent comparable/);
  assert.match(html, /Premier snapshot comparable/);
  assert.match(html, /Non comparable/);
});

test('non-comparable points: rendered with transparent fill and dashed stroke (no line connection)', () => {
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'failed' }]),
    scanWithScanners(3, '2026-08-03T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-04T00:00:00Z'));
  // targetTools = {Semgrep} (max completed set size = 1)
  // Scan 1: completed = {Semgrep}, no failed -> comparable
  // Scan 2: Semgrep failed -> not comparable
  // Scan 3: completed = {Semgrep}, no failed -> comparable
  assert.equal(report.points[0].isComparable, true);
  assert.equal(report.points[1].isComparable, false);
  assert.equal(report.points[2].isComparable, true);
  
  // The renderChart script should skip non-comparable from path coordinates
  const html = renderTrendReportHtml({ 7: report }, 'nonce', 'dark');
  assert.match(html, /filter\(cp => cp\.pt\.isComparable\)/);
  // Non-comparable points get transparent fill and dashed stroke
  assert.match(html, /fill', 'transparent'/);
  assert.match(html, /stroke-dasharray', '3,2'/);
});

test('no artificial zero drop: chart path only connects comparable points', () => {
  // Build 3 scans: comparable, non-comparable (failed), comparable
  const scans = [
    scanWithScanners(1, '2026-08-01T00:00:00Z', [
      { id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' },
      { id: 'b', rawSeverity: 'HIGH', triageStatus: 'new' }
    ], [{ tool: 'Semgrep', status: 'completed' }]),
    scanWithScanners(2, '2026-08-02T00:00:00Z', [], [{ tool: 'Semgrep', status: 'failed' }]),
    scanWithScanners(3, '2026-08-03T00:00:00Z', [
      { id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }
    ], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const report = buildTrendReport(scans, [], 90, new Date('2026-08-04T00:00:00Z'));
  // Second point has 0 active findings but is non-comparable
  assert.equal(report.points[1].active, 0);
  assert.equal(report.points[1].isComparable, false);
  // The line path must not include point[1] — confirmed by the filter logic
  // Also trend for point[2] should be vs point[0], not point[1]
  assert.equal(report.points[2].trend.display, '\u2193 50.0 % Am\u00e9lioration');
});

test('adaptive X-axis labels logic in script', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Must contain the generateXLabels helper and adaptive label count
  assert.match(html, /function generateXLabels/);
  assert.match(html, /targetLabels/);
  // Adaptive: fewer labels on narrow, more on wide
  assert.match(html, /wrapperWidth < 500 \? 4/);
  assert.match(html, /wrapperWidth < 700 \? 5 : 7/);
});

test('dynamic Y-axis uses niceYTicks with rounded values', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /function niceYTicks/);
  assert.match(html, /niceCandidates/);
});

test('chart summary header shows snapshot count and date range', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Must contain updateChartSummary function that shows first -> last dates
  assert.match(html, /function updateChartSummary/);
  assert.match(html, /fmtDate\(first\)/);
  assert.match(html, /\u2192/);  // arrow between date range
  assert.match(html, /derni\u00e8re analyse/);
});

test('brush timeline has drag interaction handlers', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /function renderBrush/);
  assert.match(html, /brushPointerDown/);
  assert.match(html, /brushPointerMove/);
  assert.match(html, /brushPointerUp/);
  assert.match(html, /dragMode/);
  assert.match(html, /brush-viewport/);
  assert.match(html, /brush-handle/);
});

test('brush is hidden for fewer than 8 points', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // The threshold is allPoints.length < 8
  assert.match(html, /allPoints\.length < 8/);
  // Brush starts hidden
  assert.match(html, /id="brush-container" style="display: none;"/);
});

test('7/30/90-day data: all produce valid reports and renderTrendReportHtml handles multi-period', () => {
  const now = new Date('2026-08-10T00:00:00Z');
  const scans = [];
  // Create 15 scans across 60 days
  for (let i = 0; i < 15; i++) {
    const date = new Date(now.getTime() - (i * 4 + 1) * 86400000).toISOString();
    scans.push(scanWithScanners(i + 1, date, [
      { id: `f${i}`, rawSeverity: 'HIGH', triageStatus: 'new' }
    ], [{ tool: 'Semgrep', status: 'completed' }]));
  }
  
  const r7 = buildTrendReport(scans, [], 7, now);
  const r30 = buildTrendReport(scans, [], 30, now);
  const r90 = buildTrendReport(scans, [], 90, now);
  
  assert.ok(r7.points.length <= r30.points.length);
  assert.ok(r30.points.length <= r90.points.length);
  assert.equal(r90.points.length, 15);
  
  const html = renderTrendReportHtml({ 7: r7, 30: r30, 90: r90 }, 'nonce');
  assert.match(html, /id="svg-chart"/);
  assert.match(html, /id="brush-container"/);
  assert.match(html, /id="chart-footer"/);
});

test('responsive: chart wrapper has responsive media queries', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  // Must include media query for narrow widths
  assert.match(html, /@media \(max-width: 768px\)/);
  assert.match(html, /@media \(max-width: 480px\)/);
  // Chart wrapper height changes at breakpoints
  assert.match(html, /height:\s*280px/);
  assert.match(html, /height:\s*220px/);
});

test('light theme: important values use --vscode-foreground, no faded gray for KPIs', () => {
  const scans = [
    scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'CRITICAL', triageStatus: 'new' }])
  ];
  const html = renderTrendReportHtml({ 7: buildTrendReport(scans, [], 7, new Date('2026-08-02T00:00:00Z')) }, 'nonce', 'light');
  // Card strong (KPI values) should use --vscode-foreground
  assert.match(html, /\.card strong[\s\S]*?color:\s*var\(--vscode-foreground\)/);
  // Footer values use --vscode-foreground
  assert.match(html, /\.chart-footer-value[\s\S]*?color:\s*var\(--vscode-foreground\)/);
  // No hardcoded dark backgrounds
  assert.doesNotMatch(html, /background:\s*(#000|#111|#1e1e1e|#202020)/);
});

test('area fill gradient uses fallback hex color for Total series', () => {
  const html = renderTrendReportHtml(
    { 7: buildTrendReport([scan(1, '2026-08-01T00:00:00Z', [{ id: 'a', rawSeverity: 'HIGH', triageStatus: 'new' }])], [], 7, new Date('2026-08-02T00:00:00Z')) },
    'nonce', 'dark'
  );
  assert.match(html, /colorsFallback\.total/);
  assert.match(html, /total-area-grad/);
});

test('old persisted scan compatibility: maps snake_case properties and computes trends correctly', () => {
  const { normalizeScanToCamelCase } = require('../src/backend');
  const legacyScan = {
    scan_id: 1,
    result: {
      finished_at: '2026-08-01T00:00:00Z',
      findings: [
        {
          id: 'vuln-1',
          tool: 'Semgrep',
          raw_severity: 'HIGH',
          triage_status: 'new'
        }
      ],
      scanners: [
        { tool: 'Semgrep', status: 'completed' }
      ]
    }
  };

  const normalized = normalizeScanToCamelCase(legacyScan);
  const report = buildTrendReport([normalized], [], 90, new Date('2026-08-02T00:00:00Z'));
  
  assert.equal(report.points.length, 1);
  assert.equal(report.points[0].high, 1);
  assert.equal(report.points[0].active, 1);
});
