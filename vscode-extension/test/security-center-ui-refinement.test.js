const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderFindingDetailsHtml } = require('../src/finding-details');

function appFinding(extra = {}) {
  return {
    id: 'app-1',
    tool: 'Semgrep',
    ruleId: 'javascript.lang.security.detect-eval',
    title: 'Use of eval',
    severity: 'error',
    rawSeverity: 'CRITICAL',
    cwe: 'CWE-95',
    file: 'src/controllers/orders.js',
    absolutePath: 'C:/repo/src/controllers/orders.js',
    startLine: 12,
    startColumn: 2,
    description: 'Dynamic code execution is dangerous.',
    triageStatus: 'new',
    ...extra
  };
}

function dashboardHtml(options = {}) {
  const findings = [
    appFinding(),
    appFinding({ id: 'app-2', rawSeverity: 'HIGH', severity: 'warning', title: 'SQL injection', cwe: 'CWE-89', startLine: 18 }),
    appFinding({ id: 'app-3', rawSeverity: 'MEDIUM', severity: 'warning', title: 'Weak header', startLine: 21 }),
    appFinding({ id: 'app-4', rawSeverity: 'LOW', severity: 'information', title: 'Informational issue', startLine: 25 })
  ];
  const model = buildDashboardModel(findings, [
    { tool: 'Semgrep', status: 'completed', currentRun: { findings, resultCount: findings.length } },
    { tool: 'Gitleaks', status: 'completed', currentRun: { findings: [], resultCount: 0 } },
    { tool: 'Trivy', status: 'completed', currentRun: { findings: [], resultCount: 0 } },
    { tool: 'OSV-Scanner', status: 'completed', currentRun: { findings: [], resultCount: 0 } },
    { tool: 'SonarQube', status: 'failed', error: 'SERVER_UNAVAILABLE' },
    { tool: 'Snyk', status: 'completed', currentRun: { findings: [], resultCount: 0 } },
    { tool: 'ZAP', status: 'completed', currentRun: { findings: [], resultCount: 0 } }
  ], { workspace: options.workspace || 'dynamic-workspace', enterprise: options.enterprise, scanStatus: 'completed' });
  return renderDashboardHtml(model, 'nonce', 'full', options.theme || 'light', {}, {});
}

function scannerDetailsHtml(scannerName, finding) {
  const model = buildDashboardModel([finding], [
    { tool: scannerName, status: 'completed', currentRun: { findings: [finding], resultCount: 1 } }
  ], { workspace: 'scanner-workspace' });
  model.activeScanner = scannerName;
  return renderDashboardHtml(model, 'nonce', 'scanner-details', 'light', {}, {});
}

test('Security Center hero renders real dashboard state without hardcoded workspace or fake trends', () => {
  const html = dashboardHtml({ workspace: 'tenant-alpha' });
  assert.match(html, /class="overview-summary security-center-hero"/);
  assert.match(html, /class="hero-metric-panel"/);
  assert.match(html, /class="posture-header"><span>Security posture<\/span><strong>4 active<\/strong><\/div>/);
  assert.match(html, /class="hero-metric-group hero-severity-grid"/);
  assert.match(html, /class="hero-metric-group hero-operations-grid"/);
  assert.match(html, /class="security-product-mark"/);
  assert.match(html, /Security Center/);
  assert.match(html, /Vue de sécurité du workspace <strong>tenant-alpha<\/strong>/);
  assert.doesNotMatch(html, /juice-shop/);
  assert.match(html, /<div class="overview-kpi hero-metric critical"><span class="hero-metric-label"><i class="hero-metric-dot critical"><\/i>Critical<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric high"><span class="hero-metric-label"><i class="hero-metric-dot high"><\/i>High<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric medium"><span class="hero-metric-label"><i class="hero-metric-dot medium"><\/i>Medium<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric low"><span class="hero-metric-label"><i class="hero-metric-dot low"><\/i>Low<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric production">[\s\S]*<strong>0<\/strong><small>priority findings<\/small><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric scanners">[\s\S]*Scanner coverage[\s\S]*<b>86%<\/b>[\s\S]*<strong>6 \/ 7<\/strong>[\s\S]*style="width: 86%"[\s\S]*6 completed · 1 failed/);
  assert.doesNotMatch(html, /État actuel/);
  assert.doesNotMatch(html, /depuis hier|\+\d+\s+(?:depuis|since)/);
});

test('theme control is icon-only while keeping accessible labels', () => {
  const light = dashboardHtml({ theme: 'light' });
  const lightButton = light.match(/<button id="theme-toggle"[^>]*>([\s\S]*?)<\/button>/)?.[0] || '';
  assert.match(lightButton, /aria-label="Passer au thème sombre"/);
  assert.match(lightButton, /title="Passer au thème sombre"/);
  assert.match(lightButton, /<span class="theme-toggle-icon" aria-hidden="true">☾<\/span>/);
  assert.doesNotMatch(lightButton.replace(/aria-label="[^"]*"|title="[^"]*"/g, ''), /Sombre|Clair|Dark|Light/);

  const dark = dashboardHtml({ theme: 'dark' });
  const darkButton = dark.match(/<button id="theme-toggle"[^>]*>([\s\S]*?)<\/button>/)?.[0] || '';
  assert.match(darkButton, /aria-label="Passer au thème clair"/);
  assert.match(darkButton, /title="Passer au thème clair"/);
  assert.match(darkButton, /<span class="theme-toggle-icon" aria-hidden="true">☀<\/span>/);
  assert.doesNotMatch(darkButton.replace(/aria-label="[^"]*"|title="[^"]*"/g, ''), /Sombre|Clair|Dark|Light/);
});

test('hero rollback keeps posture compact without score caption or severity mini-cards', () => {
  const html = dashboardHtml();
  const source = require('fs').readFileSync(require('path').join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  assert.doesNotMatch(html, /risk-ring-caption|Security score/);
  assert.doesNotMatch(html, /hero-orbit/);
  assert.doesNotMatch(source, /hero-severity-grid \.overview-kpi \{[^}]*border:/);
  assert.match(source, /body\.surface-full \.risk-copy h2 \{[^}]*font-size: clamp\(32px, 2\.4vw, 42px\)/);
  assert.match(source, /body\.surface-full \.security-center-hero \{[^}]*align-items: center/);
});

test('Security domain cards preserve existing commands and honest not-configured state', () => {
  const html = dashboardHtml();
  assert.match(html, /Security Domains/);
  assert.match(html, /body\.surface-full \.domain-card \{[^}]*display: flex;[^}]*flex-direction: column/);
  assert.match(html, /body\.surface-full \.domain-card button \{[^}]*margin-top: auto/);
  for (const command of [
    'securityCenter.openFindingsPage',
    'securityCenter.configureSiem',
    'securityCenter.openSecurityDelivery',
    'securityCenter.configureObservability',
    'securityCenter.openLiveSecurityPage'
  ]) {
    assert.match(html, new RegExp(`data-command="${command}"`));
  }
  assert.match(html, /Not configured[\s\S]{0,260}Runtime Security[\s\S]{0,240}SIEM provider[\s\S]{0,240}securityCenter\.configureSiem/);
  assert.match(html, /Not configured[\s\S]{0,260}Infrastructure[\s\S]{0,240}Observability[\s\S]{0,240}securityCenter\.configureObservability/);
  assert.doesNotMatch(html, /Runtime Security[\s\S]{0,120}Healthy/);
});

test('scanner details use structured evidence and keep action buttons visible with existing mappings', () => {
  const longPath = 'src/a/very/long/path/that/should/not/push/buttons/out/of/the/card/controllers/orders/security-sensitive-flow.js';
  const html = scannerDetailsHtml('Semgrep', appFinding({ file: longPath, autofix: { kind: 'semgrep' } }));
  assert.match(html, /class="detail-body evidence-grid"/);
  assert.match(html, /class="finding-card-actions"/);
  assert.match(html, /action-open-file/);
  assert.match(html, /action-open-details/);
  assert.match(html, /action-apply-fix/);
  assert.match(html, /Open code/);
  assert.match(html, /View details →/);
  assert.match(html, /Fix &amp; Verify/);
  assert.match(html, /data-search="[^"]*security-sensitive-flow\.js/);
});

test('Gitleaks scanner detail still masks secret values in the structured layout', () => {
  const html = scannerDetailsHtml('Gitleaks', {
    id: 'secret-1',
    tool: 'Gitleaks',
    ruleId: 'generic-api-key',
    title: 'Secret detected',
    severity: 'error',
    rawSeverity: 'HIGH',
    file: 'users.yml',
    startLine: 87,
    fingerprint: 'abcd1234efgh5678',
    triageStatus: 'new'
  });
  assert.match(html, /Type de secret \/ Règle/);
  assert.match(html, /abcd1234…/);
  assert.match(html, /•••••••• \(Masqué\)/);
  assert.doesNotMatch(html, /abcd1234efgh5678/);
  assert.doesNotMatch(html, /secretValue|rawSecret|generic-api-key-[A-Za-z0-9]+/);
});

test('finding details align existing Open code, Ollama and Verify actions in one toolbar', () => {
  const html = renderFindingDetailsHtml(appFinding(), 'nonce', {});
  assert.match(html, /class="finding-action-toolbar"/);
  assert.match(html, /id="open-code" class="context-action secondary-action"/);
  assert.match(html, /id="ai-fix" class="ai-action primary-action"/);
  assert.match(html, /data-verify="1" class="context-action secondary-action"/);
  assert.match(html, /type: 'openFindingCode'/);
  assert.match(html, /type: 'verifyFix'/);
  assert.match(html, /type: 'generateAiFix'/);
});

test('new UI refinement keeps dark mode, responsiveness and local-only assets/fonts', () => {
  const dashboard = dashboardHtml({ theme: 'dark' });
  const details = renderFindingDetailsHtml(appFinding(), 'nonce', { theme: 'dark' });
  assert.match(dashboard, /body\.theme-dark/);
  assert.match(details, /body\.theme-dark/);
  assert.match(dashboard, /@media\s*\(max-width:\s*1200px\)/);
  assert.match(dashboard, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(details, /@media\s*\(max-width:\s*700px\)/);
  assert.doesNotMatch(dashboard + details, /https:\/\/fonts|fonts\.googleapis|fonts\.gstatic|<img[^>]+src="https?:\/\//);
});

test('dashboard visual polish keeps balanced grids without adding fake data hooks', () => {
  const dashboard = dashboardHtml();
  assert.match(dashboard, /body\.surface-full \.overview-triple \{[^}]*grid-template-columns: minmax\(260px, \.9fr\) minmax\(280px, 1fr\) minmax\(320px, 1\.1fr\);[^}]*align-items: stretch/);
  assert.match(dashboard, /body\.surface-full \.overview-triple > \.overview-panel \{[^}]*height: 100%/);
  assert.match(dashboard, /body\.surface-full \.overview-split \{[^}]*grid-template-columns: minmax\(430px, 1\.5fr\) minmax\(320px, \.95fr\)/);
  assert.match(dashboard, /body\.surface-full \.overview-split > \.overview-panel:first-child \{[^}]*max-height: 560px;[^}]*overflow: auto/);
  assert.match(dashboard, /body\.surface-full \.hero-severity-grid \{[^}]*grid-template-columns: repeat\(4, minmax\(0, 1fr\)\)/);
  assert.match(dashboard, /body\.surface-full \.hero-operations-grid \{[^}]*grid-template-columns: minmax\(128px, \.82fr\) minmax\(190px, 1\.18fr\)/);
  assert.match(dashboard, /body\.surface-full \.scanner-coverage-bar span \{[^}]*linear-gradient\(90deg, var\(--sc-primary\)/);
  assert.match(dashboard, /@media\s*\(max-width:\s*980px\)[\s\S]*body\.surface-full \.hero-severity-grid \{ grid-template-columns: repeat\(2, minmax\(0, 1fr\)\); \}/);
  assert.match(dashboard, /@media\s*\(max-width:\s*680px\)[\s\S]*body\.surface-full \.hero-severity-grid \{ grid-template-columns: 1fr; gap: 10px; \}/);
  assert.match(dashboard, /body\.surface-full \.security-center-hero::after/);
  assert.doesNotMatch(dashboard, /since yesterday|depuis hier|sparkline|trend-arrow|faker|Math\.random/);
});
