const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const manifest = require('../package.json');
const { SCANNER_PRESENTATION, scannerLogoUri, isTrustedWebviewAssetUri } = require('../src/scanner-presentation');
const { buildDashboardModel, renderDashboardHtml, summarizeScannerError } = require('../src/dashboard');

const repoRoot = path.join(__dirname, '..');
const scannerTools = ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP'];

function logoAssets(prefix = 'vscode-webview-resource:/media/scanners') {
  return {
    cspSource: 'vscode-webview:',
    scannerLogoUris: Object.fromEntries(scannerTools.map((tool) => [
      tool,
      `${prefix}/${SCANNER_PRESENTATION[tool].logo}`
    ]))
  };
}

test('every configured scanner has a local logo or safe fallback', () => {
  for (const tool of scannerTools) {
    const presentation = SCANNER_PRESENTATION[tool];
    assert.ok(presentation, `${tool} must have presentation metadata`);
    assert.equal(presentation.label, tool);
    assert.ok(presentation.description);
    assert.ok(presentation.category);
    assert.ok(presentation.fallbackIcon);
    if (presentation.logo) {
      assert.ok(fs.existsSync(path.join(repoRoot, 'media', 'scanners', presentation.logo)), `${tool} logo is missing`);
    }
  }
});

test('scanner logo runtime URIs never accept remote HTTP or HTTPS URLs', () => {
  for (const tool of scannerTools) {
    assert.equal(scannerLogoUri(tool, { scannerLogoUris: { [tool]: `https://example.test/${tool}.svg` } }), '');
    assert.equal(scannerLogoUri(tool, { scannerLogoUris: { [tool]: `http://example.test/${tool}.svg` } }), '');
    assert.match(scannerLogoUri(tool, logoAssets()), /^vscode-webview-resource:/);
  }
});

test('scanner logo URI accepts VS Code HTTPS webview asset origins but not arbitrary remote origins', () => {
  const cdnUri = 'https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/hajar/Desktop/pfa-start/vscode-extension/media/scanners/semgrep.svg';
  assert.equal(isTrustedWebviewAssetUri(cdnUri, { cspSource: 'https://*.vscode-cdn.net' }), true);
  assert.equal(scannerLogoUri('Semgrep', {
    cspSource: 'https://*.vscode-cdn.net',
    scannerLogoUris: { Semgrep: cdnUri }
  }), cdnUri);
  assert.equal(isTrustedWebviewAssetUri('https://example.test/semgrep.svg', { cspSource: 'https://*.vscode-cdn.net' }), false);
  assert.equal(scannerLogoUri('Semgrep', {
    cspSource: 'https://*.vscode-cdn.net',
    scannerLogoUris: { Semgrep: 'https://example.test/semgrep.svg' }
  }), '');
});

test('light and dark themes render scanner assets through local webview URIs', () => {
  const model = buildDashboardModel([], scannerTools.map((tool) => ({ tool, status: 'completed', currentRun: { resultCount: 0, findings: [] } })), {
    scanStatus: 'completed'
  });
  for (const theme of ['light', 'dark']) {
    const html = renderDashboardHtml(model, 'nonce', 'full', theme, {}, logoAssets());
    assert.match(html, /img-src vscode-webview:/);
    assert.equal((html.match(/class="scanner-logo-img"/g) || []).length, scannerTools.length);
    assert.doesNotMatch(html, /src="https?:\/\//);
  }
});

test('known scanners render packaged img assets without fallback when webview URI exists', () => {
  const assets = logoAssets('https://file+.vscode-resource.vscode-cdn.net/media/scanners');
  assets.cspSource = 'https://*.vscode-cdn.net';
  const model = buildDashboardModel([], scannerTools.map((tool) => ({
    tool,
    status: 'completed',
    currentRun: { resultCount: 0, findings: [] }
  })), { scanStatus: 'completed' });
  const html = renderDashboardHtml(model, 'nonce', 'full', 'light', {}, assets);
  assert.match(html, /img-src https:\/\/\*\.vscode-cdn\.net/);
  for (const tool of scannerTools) {
    assert.match(html, new RegExp(`data-scanner-logo="${SCANNER_PRESENTATION[tool].id}"[\\s\\S]{0,180}<img class="scanner-logo-img"`), `${tool} must render an img logo`);
  }
  assert.doesNotMatch(html, /scanner-logo fallback/, 'known scanners with asset URIs must not render generic fallback icons');
});

test('unknown scanner still gets fallback icon when no packaged logo exists', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{
    tool: 'CustomScanner',
    status: 'completed',
    currentRun: { resultCount: 0, findings: [] }
  }], { scanStatus: 'completed' }), 'nonce', 'full', 'light', {}, logoAssets());
  assert.match(html, /data-scanner-logo="customscanner"/);
  assert.match(html, /scanner-logo fallback/);
});

test('dashboard webview roots and CSP include scanner media assets', () => {
  const extensionSource = fs.readFileSync(path.join(repoRoot, 'src', 'extension.js'), 'utf8');
  assert.match(extensionSource, /scannerAssetRoot = vscode\.Uri\.joinPath\(context\.extensionUri, 'media', 'scanners'\)/);
  assert.match(extensionSource, /providerAssetRoot = vscode\.Uri\.joinPath\(context\.extensionUri, 'media', 'providers'\)/);
  assert.match(extensionSource, /brandingAssetRoot = vscode\.Uri\.joinPath\(context\.extensionUri, 'media', 'branding'\)/);
  assert.match(extensionSource, /localResourceRoots: \[companionAssetRoot, scannerAssetRoot, providerAssetRoot, brandingAssetRoot\]/);
  assert.match(extensionSource, /new DashboardProvider\([\s\S]*context\.extensionUri/);
  const html = renderDashboardHtml(buildDashboardModel([], []), 'nonce', 'full', 'light', {}, { cspSource: 'https://*.vscode-cdn.net', scannerLogoUris: {} });
  assert.match(html, /img-src https:\/\/\*\.vscode-cdn\.net/);
});

test('SonarQube failure status remains truthful and credentials are never rendered', () => {
  const secret = 'squ_123456789SECRET';
  const model = buildDashboardModel([], [{
    tool: 'SonarQube',
    status: 'failed',
    error: `Le serveur SonarQube http://127.0.0.1:9000 est injoignable. ${secret}`
  }], { scanStatus: 'partial' });
  const html = renderDashboardHtml(model, 'nonce', 'full', 'light', {}, logoAssets());
  assert.match(html, /SonarQube inaccessible/);
  assert.match(html, /Échec/);
  assert.doesNotMatch(html, new RegExp(secret));
  assert.doesNotMatch(html, /SonarQube[\s\S]*Prêt[\s\S]*0<\/strong><small>alertes/);
});

test('retry uses the existing scanner retry mechanism', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{
    tool: 'SonarQube',
    status: 'failed',
    error: 'Le serveur SonarQube http://127.0.0.1:9000 est injoignable.'
  }], { scanStatus: 'partial' }), 'nonce', 'full', 'light', {}, logoAssets());
  assert.match(html, /data-retry-scanner="SonarQube"/);
  const extensionSource = fs.readFileSync(path.join(repoRoot, 'src', 'extension.js'), 'utf8');
  assert.match(extensionSource, /message\?\.type === 'retryScanner'[\s\S]*securityCenter\.retryScanner/);
  assert.match(extensionSource, /registerCommand\('securityCenter\.retryScanner'[\s\S]*securityCenter\.scanWorkspace/);
});

test('scanner IDs still map to the same scanner implementations', () => {
  const extensionSource = fs.readFileSync(path.join(repoRoot, 'src', 'extension.js'), 'utf8');
  const expected = {
    Semgrep: 'runSemgrep',
    Gitleaks: 'runGitleaks',
    Trivy: 'runTrivy',
    'OSV-Scanner': 'runOsv',
    SonarQube: 'runSonarQube',
    Snyk: 'runSnyk',
    ZAP: 'runZap'
  };
  for (const [tool, runner] of Object.entries(expected)) {
    const escapedTool = tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(extensionSource, new RegExp(`tool: '${escapedTool}'[\\s\\S]*execute: \\(\\) => ${runner}\\(`));
  }
});

test('presentation registry does not duplicate scanner commands or business runners', () => {
  const source = fs.readFileSync(path.join(repoRoot, 'src', 'scanner-presentation.js'), 'utf8');
  assert.doesNotMatch(source, /registerCommand|scanWorkspace|retryScanner|runSemgrep|runGitleaks|runTrivy|runOsv|runSonarQube|runSnyk|runZap/);
  const commands = (manifest.contributes.commands || []).map((command) => command.command);
  assert.equal(commands.length, new Set(commands).size, 'manifest command IDs must remain unique');
});

test('stale-current-run scanner isolation remains intact with logos enabled', () => {
  const html = renderDashboardHtml(buildDashboardModel([
    { tool: 'Gitleaks', title: 'Old secret', rawSeverity: 'HIGH' }
  ], [{
    tool: 'Gitleaks',
    status: 'pending',
    currentRun: { resultCount: null, findings: [] },
    lastCompletedRun: { resultCount: 66 }
  }], { scanStatus: 'running', snapshotAvailable: true }), 'nonce', 'full', 'light', {}, logoAssets());
  assert.match(html, /Gitleaks[\s\S]*<strong>—<\/strong><small>alertes<\/small>/);
  assert.doesNotMatch(html, /66<\/strong><small>alertes/);
});

test('SonarQube unreachable errors are normalized without hiding failed status', () => {
  const summary = summarizeScannerError('Le serveur SonarQube http://127.0.0.1:9000 est injoignable.');
  assert.match(summary, /SonarQube inaccessible/);
  assert.doesNotMatch(summary, /Prêt|succès|0 alerte/i);
});
