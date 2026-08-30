'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderFindingDetailsHtml } = require('../src/finding-details');

const scannerCases = [
  ['Semgrep', 'semgrep', 'Semgrep-only finding'],
  ['Gitleaks', 'gitleaks', 'Gitleaks-only finding'],
  ['Trivy', 'trivy', 'Trivy-only finding'],
  ['OSV-Scanner', 'osv', 'OSV-only finding'],
  ['SonarQube', 'sonarqube', 'Sonar-only finding'],
  ['Snyk', 'snyk', 'Snyk-only finding'],
  ['ZAP', 'zap', 'ZAP-only finding']
];

function source(file) {
  return fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
}

function commandBody(extension, command) {
  const start = extension.indexOf(`registerCommand('${command}'`);
  if (start < 0) return '';
  const next = extension.indexOf('registerCommand(', start + 20);
  return extension.slice(start, next < 0 ? extension.length : next);
}

function scannerDetailsSection(html) {
  const start = html.indexOf('<section class="page-scanner-details">');
  assert.ok(start >= 0, 'scanner details section is rendered');
  return html.slice(start, html.indexOf('</section>', start) + '</section>'.length);
}

test('dashboard scanner rows carry stable scanner IDs and post scannerId payloads', () => {
  const model = buildDashboardModel([], scannerCases.map(([tool]) => ({ tool, status: 'completed' })), {});
  const html = renderDashboardHtml(model, 'nonce', 'full');
  for (const [tool, scannerId] of scannerCases) {
    assert.match(html, new RegExp(`data-scanner-id="${scannerId}"`), `${tool} row should expose stable scannerId`);
  }
  assert.match(html, /postMessage\(\{ type: 'openScannerDetails', scannerId: button\.dataset\.scannerId, scanner: button\.dataset\.scanner \}\)/);
});

test('scanner detail navigation rerenders an existing panel instead of keeping the first scanner HTML', () => {
  const extension = source('src/extension.js');
  const body = extension.slice(extension.indexOf('openScannerDetails(scannerIdOrName)'), extension.indexOf('setData(findings, scanners, options)', extension.indexOf('openScannerDetails(scannerIdOrName)')));
  assert.match(body, /scannerToolFromId\(scannerIdOrName\)/);
  assert.match(body, /existing\.reveal\(vscode\.ViewColumn\.Active\)/);
  assert.match(body, /this\.renderWebview\(existing\.webview, 'scanner-details'\)/);
  assert.doesNotMatch(body, /this\.activeScanner = scannerName/);
});

test('each scanner details page scopes findings to its own scanner and never falls back to Semgrep', () => {
  const findings = scannerCases.map(([tool, , title], index) => ({
    id: `${tool}-${index}`,
    tool,
    ruleId: `${tool}-RULE`,
    title,
    severity: index % 2 ? 'warning' : 'error',
    rawSeverity: index % 2 ? 'MEDIUM' : 'HIGH',
    file: `${tool.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.js`,
    startLine: index,
    startColumn: 0,
    triageStatus: 'new',
    category: tool === 'ZAP' ? 'dynamic' : tool === 'Trivy' || tool === 'OSV-Scanner' ? 'dependency' : 'security',
    packageName: tool === 'Trivy' || tool === 'OSV-Scanner' || tool === 'Snyk' ? 'pkg' : undefined,
    installedVersion: '1.0.0',
    snykCapability: tool === 'Snyk' ? 'openSource' : undefined,
    endpoint: tool === 'ZAP' ? 'http://127.0.0.1:3000/' : undefined
  }));
  const model = buildDashboardModel(findings, scannerCases.map(([tool]) => ({ tool, status: 'completed' })), {});
  for (const [tool, scannerId, title] of scannerCases) {
    model.activeScanner = tool;
    const section = scannerDetailsSection(renderDashboardHtml(model, 'nonce', 'scanner-details'));
    assert.match(section, new RegExp(`data-active-scanner-id="${scannerId}"`));
    assert.match(section, new RegExp(title));
    for (const [, , otherTitle] of scannerCases.filter(([other]) => other !== tool)) {
      assert.doesNotMatch(section, new RegExp(otherTitle), `${tool} page leaked ${otherTitle}`);
    }
  }
});

test('findings page uses modern scanner-ID filters, active chips and investigation preview actions', () => {
  const findings = [
    {
      id: 'semgrep-1',
      tool: 'Semgrep',
      ruleId: 'javascript.xss',
      title: 'Unquoted template variable',
      severity: 'error',
      rawSeverity: 'HIGH',
      file: 'frontend/src/app.ts',
      absolutePath: 'C:\\workspace\\frontend\\src\\app.ts',
      startLine: 14,
      sourceContext: 'production',
      triageStatus: 'new',
      reachability: { status: 'POTENTIALLY_REACHABLE', confidence: 'medium', reason: 'Route maps to user input.' }
    },
    {
      id: 'gitleaks-1',
      tool: 'Gitleaks',
      ruleId: 'generic-api-key',
      title: 'Hard-coded credential detected',
      severity: 'error',
      rawSeverity: 'CRITICAL',
      file: 'lib/insecurity.ts',
      startLine: 53,
      sourceContext: 'test',
      triageStatus: 'accepted'
    }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], {}), 'nonce', 'findings');
  assert.match(html, /findings-hero/);
  assert.match(html, /Investigation Preview/);
  assert.match(html, /data-tool-id="semgrep"/);
  assert.match(html, /data-tool-id="gitleaks"/);
  assert.match(html, /<select id="finding-tool"><option value="">Tous les outils<\/option><option value="gitleaks">Gitleaks<\/option><option value="semgrep">Semgrep<\/option><\/select>/);
  assert.match(html, /id="finding-context"/);
  assert.match(html, /id="finding-reachability"/);
  assert.match(html, /id="finding-filter-chips"/);
  assert.match(html, /card\.dataset\.toolId === tool\.value/);
  assert.match(html, /className = 'filter-chip'/);
  assert.match(html, /id="preview-details"/);
  assert.match(html, /id="preview-code"/);
  assert.match(html, /securityCenter\.verifyFindingFix/);
  assert.match(html, /data-finding-index="0"/);
  assert.match(html, /data-finding-code-index="0"/);
});

test('finding details render an investigation workspace with preserved actions and fact labels', () => {
  const html = renderFindingDetailsHtml({
    id: 'finding-1',
    tool: 'Semgrep',
    title: 'Unquoted template variable',
    rawSeverity: 'HIGH',
    severity: 'error',
    confidence: 'high',
    ruleId: 'javascript.xss',
    cwe: 'CWE-79',
    file: 'frontend/src/app.ts',
    absolutePath: 'C:\\workspace\\frontend\\src\\app.ts',
    startLine: 14,
    description: 'Template variable is not quoted.',
    developerImpact: 'Could allow script injection if user controlled.',
    developerAction: 'Quote the template variable and rerun Semgrep.',
    reachability: { status: 'POTENTIALLY_REACHABLE', confidence: 'medium', reason: 'Route maps to user input.' },
    triageStatus: 'new'
  }, 'nonce', { scannerLogoUris: { Semgrep: 'vscode-resource:/scanner/semgrep.svg' } });
  assert.match(html, /finding-detail-hero/);
  assert.match(html, /detail-scanner-logo/);
  assert.match(html, /Overview/);
  assert.match(html, /Evidence/);
  assert.match(html, /Reachability/);
  assert.match(html, /Remediation/);
  assert.match(html, /Verification/);
  assert.match(html, /Technical Details/);
  assert.match(html, /class="fact verified"/);
  assert.match(html, /class="fact inferred"/);
  assert.match(html, /id="open-code"/);
  assert.match(html, /data-verify="1"/);
  assert.match(html, /type: 'openFindingCode'/);
  assert.match(html, /type: 'verifyFix'/);
  assert.match(html, /generateAiFix/);
});

test('scanner detail command remains preserved as a compatibility entry point', () => {
  const extension = source('src/extension.js');
  assert.match(commandBody(extension, 'securityCenter.openScannerDetails'), /dashboardProvider\.openScannerDetails\(scannerName\)/);
});
