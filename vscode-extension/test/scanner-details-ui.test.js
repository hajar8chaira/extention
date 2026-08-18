const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

test('Dashboard row can trigger scanner details', () => {
  const model = buildDashboardModel([], [{ tool: 'Semgrep', status: 'completed' }], {});
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  // Verify row click handler setup is present in script
  assert.match(html, /data-scanner="Semgrep"/);
  assert.match(html, /openScannerDetails/);
});

test('Back to Dashboard action is present in scanner details', () => {
  const model = buildDashboardModel([], [], {});
  model.activeScanner = 'Semgrep';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  assert.match(html, /data-command="securityCenter\.openDashboard"/);
  assert.match(html, /Retour au Dashboard/);
});

test('Semgrep details are rendered correctly', () => {
  const findings = [{
    id: 'semgrep-id-1',
    tool: 'Semgrep',
    ruleId: 'rules.eval',
    title: 'Eval finding',
    severity: 'error',
    rawSeverity: 'CRITICAL',
    cwe: 'CWE-95',
    file: 'src/app.js',
    startLine: 10,
    startColumn: 5,
    description: 'Use of eval is dangerous',
    originalText: 'eval(userInput);',
    triageStatus: 'new'
  }];
  const model = buildDashboardModel(findings, [{ tool: 'Semgrep', status: 'completed' }], {});
  model.activeScanner = 'Semgrep';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  assert.match(html, /rules\.eval/);
  assert.match(html, /CWE-95/);
  assert.match(html, /src\/app\.js:11:6/);
  assert.match(html, /eval\(userInput\);/);
});

test('Gitleaks secret is never exposed', () => {
  const findings = [{
    id: 'gitleaks-id-1',
    tool: 'Gitleaks',
    ruleId: 'generic-api-key',
    title: 'Secret detected',
    severity: 'error',
    rawSeverity: 'HIGH',
    file: 'config.js',
    startLine: 5,
    startColumn: 1,
    fingerprint: 'abcd1234efgh5678',
    triageStatus: 'new'
  }];
  const model = buildDashboardModel(findings, [{ tool: 'Gitleaks', status: 'completed' }], {});
  model.activeScanner = 'Gitleaks';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  // Verify fingerprint is sliced and secret is masked
  assert.match(html, /abcd1234…/);
  assert.match(html, /•••••••• \(Masqué\)/);
  assert.doesNotMatch(html, /abcd1234efgh5678/);
});

test('Trivy renders tabs and category breakdown', () => {
  const findings = [
    {
      id: 'trivy-id-1',
      tool: 'Trivy',
      ruleId: 'CVE-2023-1234',
      title: 'Vulnerability 1',
      severity: 'error',
      rawSeverity: 'HIGH',
      category: 'dependency',
      packageName: 'express',
      installedVersion: '4.17.1',
      fixedVersion: '4.18.2'
    },
    {
      id: 'trivy-id-2',
      tool: 'Trivy',
      ruleId: 'AVD-0001',
      title: 'Misconfiguration 1',
      severity: 'warning',
      rawSeverity: 'MEDIUM',
      category: 'misconfiguration',
      file: 'Dockerfile',
      startLine: 2,
      solution: 'Do not run as root'
    }
  ];
  const model = buildDashboardModel(findings, [{ tool: 'Trivy', status: 'completed' }], {});
  model.activeScanner = 'Trivy';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  // Verify tabs presence
  assert.match(html, /trivy-dependencies/);
  assert.match(html, /trivy-iac/);
  assert.match(html, /trivy-container/);
  assert.match(html, /trivy-licenses/);
  
  // Verify dependency fields
  assert.match(html, /CVE-2023-1234/);
  assert.match(html, /express/);
  
  // Verify IaC fields
  assert.match(html, /Dockerfile:3/);
  assert.match(html, /Do not run as root/);
});

test('OSV details and reachability badge render', () => {
  const findings = [{
    id: 'osv-id-1',
    tool: 'OSV-Scanner',
    ruleId: 'GHSA-abcd-1234',
    title: 'OSV advisory',
    severity: 'warning',
    rawSeverity: 'MEDIUM',
    category: 'dependency',
    packageName: 'lodash',
    installedVersion: '4.17.20',
    fixedVersion: '4.17.21',
    file: 'package-lock.json',
    reachable: true
  }];
  const model = buildDashboardModel(findings, [{ tool: 'OSV-Scanner', status: 'completed' }], {});
  model.activeScanner = 'OSV-Scanner';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  assert.match(html, /GHSA-abcd-1234/);
  assert.match(html, /lodash/);
  assert.match(html, /Oui \(Haute priorité\)/);
});

test('SonarQube renders with security, reliability, and maintainability categories', () => {
  const findings = [
    {
      id: 'sonar-id-1',
      tool: 'SonarQube',
      ruleId: 'S1234',
      title: 'Security Bug',
      severity: 'error',
      rawSeverity: 'CRITICAL',
      category: 'security',
      file: 'index.js',
      startLine: 5,
      issueType: 'VULNERABILITY'
    },
    {
      id: 'sonar-id-2',
      tool: 'SonarQube',
      ruleId: 'S5678',
      title: 'Reliability issue',
      severity: 'warning',
      rawSeverity: 'MEDIUM',
      category: 'reliability',
      file: 'index.js',
      startLine: 12,
      issueType: 'BUG'
    }
  ];
  const model = buildDashboardModel(findings, [{ tool: 'SonarQube', status: 'completed' }], {});
  model.activeScanner = 'SonarQube';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  assert.match(html, /Security/);
  assert.match(html, /Reliability/);
  assert.match(html, /Maintainability/);
});

test('Snyk capability tabs are rendered', () => {
  const findings = [{
    id: 'snyk-id-1',
    tool: 'Snyk',
    ruleId: 'SNYK-JS-LODASH-1234',
    title: 'Snyk vuln',
    severity: 'error',
    rawSeverity: 'HIGH',
    snykCapability: 'openSource',
    packageName: 'lodash',
    installedVersion: '4.17.20'
  }];
  const model = buildDashboardModel(findings, [{ tool: 'Snyk', status: 'completed' }], {});
  model.activeScanner = 'Snyk';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  assert.match(html, /snyk-oss/);
  assert.match(html, /snyk-code/);
  assert.match(html, /snyk-iac/);
});

test('ZAP links and dynamic actions are present', () => {
  const findings = [{
    id: 'zap-id-1',
    tool: 'ZAP',
    ruleId: '10038',
    title: 'CSP Header missing',
    severity: 'information',
    rawSeverity: 'LOW',
    category: 'dynamic',
    method: 'GET',
    endpoint: 'http://127.0.0.1:3000/'
  }];
  const model = buildDashboardModel(findings, [{ tool: 'ZAP', status: 'completed' }], {
    httpScenarios: [{
      request: { method: 'GET', url: 'http://127.0.0.1:3000/' },
      response: { statusCode: 200 }
    }]
  });
  model.activeScanner = 'ZAP';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  // ZAP redirect link
  assert.match(html, /Open Dynamic Security →/);
  // HTTP Request Replay and Open buttons (since matching scenario exists)
  assert.match(html, /action-open-request/);
  assert.match(html, /action-replay-traffic/);
});

test('Renders correct states: zero, failed, and not run', () => {
  // 1. Zero state
  let model = buildDashboardModel([], [{ tool: 'Semgrep', status: 'completed' }], {});
  model.activeScanner = 'Semgrep';
  let html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  assert.match(html, /No findings detected by Semgrep/);
  
  // 2. Failed state
  model = buildDashboardModel([], [{ tool: 'Semgrep', status: 'failed', error: 'Internal failure' }], {});
  model.activeScanner = 'Semgrep';
  html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  assert.match(html, /Scan failed/);
  assert.match(html, /Internal failure/);
  assert.match(html, /Open scanner configuration/);
  
  // 3. Not run state
  model = buildDashboardModel([], [], { disabledScanners: ['Semgrep'] });
  model.activeScanner = 'Semgrep';
  html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  assert.match(html, /No result available for this scanner/);
});

test('Light/dark compatibility and responsive structure are present in CSS', () => {
  const model = buildDashboardModel([], [], {});
  model.activeScanner = 'Semgrep';
  const html = renderDashboardHtml(model, 'nonce', 'scanner-details');
  
  // CSS class declarations and media queries presence
  assert.match(html, /\.page-scanner-details/);
  assert.match(html, /body\.surface-scanner-details/);
  assert.match(html, /@media\s*\(max-width:\s*480px\)/);
  assert.match(html, /theme-/);
});
