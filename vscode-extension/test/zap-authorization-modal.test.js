'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderSidebarLauncherHtml } = require('../src/sidebar-launcher');

const TARGET = 'http://127.0.0.1:3000';

function loadExtension() {
  const vscodeStub = {
    EventEmitter: class { constructor() { this.event = () => ({ dispose() {} }); } fire() {} dispose() {} },
    ThemeIcon: class { constructor(id) { this.id = id; } },
    TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    ViewColumn: { Active: -1 },
    Uri: { file: (p) => ({ fsPath: p, toString: () => p }), parse: (p) => ({ toString: () => p }) },
    commands: { registerCommand: () => ({ dispose() {} }), executeCommand: async () => undefined },
    window: {
      createWebviewPanel: () => { throw new Error('non utilise'); },
      registerWebviewViewProvider: () => ({ dispose() {} }),
      showErrorMessage: async () => undefined, showWarningMessage: async () => undefined,
      showInformationMessage: async () => undefined, createOutputChannel: () => ({ appendLine() {}, dispose() {} })
    },
    workspace: {
      getConfiguration: () => ({ get: (_key, fallback) => fallback, update: async () => undefined }),
      workspaceFolders: [], onDidChangeConfiguration: () => ({ dispose() {} })
    },
    Range: class {}, Position: class {}, Diagnostic: class {}, CodeAction: class {},
    WorkspaceEdit: class {}, RelativePattern: class {}, MarkdownString: class {},
    CodeLens: class {}, Location: class {}, Selection: class {},
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    StatusBarAlignment: { Left: 1, Right: 2 }
  };
  const load = Module._load;
  Module._load = function (request, ...rest) {
    if (request === 'vscode') return vscodeStub;
    return load.call(this, request, ...rest);
  };
  try { return require('../src/extension'); } finally { Module._load = load; }
}

const {
  resolveZapActiveScanConsent, zapRequestedForScan, zapModeFromPolicy, DashboardProvider
} = loadExtension();

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
const dashboardSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
const sidebarSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'sidebar-launcher.js'), 'utf8');

function cfg(values = {}) {
  return { get: (key, fallback) => Object.prototype.hasOwnProperty.call(values, key) ? values[key] : fallback };
}

function webviewHost({ active = true, visible = true } = {}) {
  let receive = null;
  const webview = {
    html: '',
    onDidReceiveMessage: (handler) => { receive = handler; }
  };
  return {
    panel: { active, visible, webview, onDidDispose: () => ({ dispose() {} }) },
    webview,
    receive: (message) => receive?.(message)
  };
}

test('native fallback authorizes active scan when no Security Center surface is available', async () => {
  const calls = [];
  const decision = await resolveZapActiveScanConsent({
    mode: 'active',
    target: TARGET,
    window: {
      showWarningMessage: async (...args) => {
        calls.push(args);
        return 'Authorize active scan';
      }
    }
  });

  assert.deepEqual(decision, { mode: 'active', authorized: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 4);
  assert.match(calls[0][0], /Security Center — ZAP active scan/);
  assert.match(calls[0][0], /http:\/\/127\.0\.0\.1:3000/);
  assert.equal(calls[0][1], 'Use passive scan');
  assert.equal(calls[0][2], 'Authorize active scan');
  assert.equal(calls[0][3], 'Cancel analysis');
});

test('global ZAP preflight can choose passive fallback and continue the multi-scan', async () => {
  const decision = await resolveZapActiveScanConsent({
    mode: 'active',
    target: TARGET,
    window: { showWarningMessage: async () => 'Use passive scan' }
  });

  assert.deepEqual(decision, { mode: 'baseline', passiveFallback: true });
});

test('global ZAP preflight cancellation cancels before a run is marked active', async () => {
  const decision = await resolveZapActiveScanConsent({
    mode: 'openapi',
    target: TARGET,
    window: { showWarningMessage: async () => 'Cancel analysis' }
  });

  assert.deepEqual(decision, { cancelled: true });
  const source = extensionSource();
  assert.ok(source.indexOf('resolveZapActiveScanConsent') < source.indexOf('scanInProgress = true'));
  assert.match(source, /analyse annulée avant démarrage/);
});

test('Dashboard scan requiring ZAP consent opens one Security Center modal without Scans page ownership', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', 'full', 'light', {
    zapPreflight: { id: 'zap-1', mode: 'active', target: TARGET }
  });

  assert.equal((html.match(/class="sc-zap-preflight"/g) || []).length, 1);
  assert.equal((html.match(/id="security-center-modal-root"/g) || []).length, 1);
  assert.match(html, /id="security-center-modal-root"><div class="sc-modal-overlay sc-modal-backdrop"/);
  assert.match(html, /Autoriser l’analyse ZAP active/);
  assert.match(html, /Dynamic Security · ZAP/);
  assert.match(html, /http:\/\/127\.0\.0\.1:3000/);
  assert.match(html, /data-zap-preflight-decision="passive"/);
  assert.match(html, /data-zap-preflight-decision="active"/);
  assert.match(html, /data-zap-preflight-decision="cancel"/);
  assert.doesNotMatch(html, /data-zap-confirm|data-zap-cancel/);
});

test('ZAP preflight modal is mounted outside normal page content in a viewport overlay', () => {
  const source = dashboardSource();
  const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', 'findings', 'light', {
    zapPreflight: { id: 'zap-fixed', mode: 'active', target: TARGET }
  });
  const pageIndex = html.indexOf('<section class="page-findings">');
  const pageEndIndex = html.indexOf('<section class="page-scans">');
  const rootIndex = html.indexOf('id="security-center-modal-root"');
  const scriptIndex = html.indexOf('<script nonce=');
  assert.ok(pageIndex > -1, 'findings page content should exist');
  assert.ok(rootIndex > pageEndIndex, 'modal root must be after normal page sections, not inside Findings content');
  assert.ok(rootIndex < scriptIndex, 'modal root should be mounted at the body/shell boundary before scripts');
  assert.match(html, /<body class="[^"]*sc-modal-open[^"]*"/);
  assert.match(html, /<section class="sc-zap-preflight"[^>]*role="dialog"[^>]*aria-modal="true"/);
  assert.match(source, /\.sc-modal-overlay,\s*\.sc-modal-backdrop \{[\s\S]*position: fixed;[\s\S]*inset: 0;[\s\S]*display: flex;[\s\S]*align-items: center;[\s\S]*justify-content: center;[\s\S]*z-index: 1000/);
  assert.match(source, /\.sc-zap-preflight \{[\s\S]*width: min\(600px, calc\(100vw - 48px\)\);[\s\S]*max-height: calc\(100vh - 48px\);[\s\S]*overflow-y: auto/);
  assert.match(source, /body\.sc-modal-open \{ overflow: hidden; \}/);
});

test('ZAP preflight modal uses the same shared modal root across Security Center pages', () => {
  for (const surface of ['full', 'findings', 'scans', 'dynamic', 'analytics']) {
    const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', surface, 'light', {
      zapPreflight: { id: `zap-${surface}`, mode: 'openapi', target: TARGET }
    });
    assert.equal((html.match(/id="security-center-modal-root"/g) || []).length, 1, `${surface} should have one modal root`);
    assert.equal((html.match(/data-zap-preflight-id=/g) || []).length, 1, `${surface} should have one ZAP modal`);
    assert.match(html, /id="security-center-modal-root"><div class="sc-modal-overlay sc-modal-backdrop"/, `${surface} should render modal into the shared root`);
  }
});

test('Escape and close controls map to ZAP preflight cancellation', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', 'scans', 'light', {
    zapPreflight: { id: 'zap-escape', mode: 'openapi', target: TARGET }
  });

  assert.match(html, /class="sc-modal-close"[\s\S]*data-zap-preflight-decision="cancel"/);
  assert.match(html, /event\.key === 'Escape'[\s\S]*resolveZapPreflight\('cancel'\)/);
  assert.match(html, /event\.key === 'Tab'[\s\S]*last\.focus\(\)/);
  assert.match(html, /zapReturnFocus\?\.focus\?\.\(\)/);
});

test('styled Security Center preflight resolves active, passive, and cancel decisions', async () => {
  for (const [decision, expected] of [
    ['active', { mode: 'active', authorized: true }],
    ['passive', { mode: 'baseline', passiveFallback: true }],
    ['cancel', { cancelled: true }]
  ]) {
    const provider = new DashboardProvider(() => {});
    const host = webviewHost();
    provider.fullPanel = host.panel;
    provider.registerMessages(host.webview);

    const pending = provider.requestZapPreflight({ mode: 'active', target: TARGET });
    assert.match(host.webview.html, /sc-zap-preflight/);
    assert.doesNotMatch(renderDashboardHtml(buildDashboardModel([], []), 'n', 'scans'), /data-zap-preflight-id=/);
    host.receive({ type: 'zapPreflightResolved', id: provider.zapPreflight.id, decision });

    assert.deepEqual(await pending, expected);
    assert.equal(provider.zapPreflight, undefined);
    assert.doesNotMatch(host.webview.html, /data-zap-preflight-id=/);
  }
});

test('styled modal suppresses native ZAP fallback when a Security Center panel owns the preflight', async () => {
  const provider = new DashboardProvider(() => {});
  const host = webviewHost();
  provider.fullPanel = host.panel;
  provider.registerMessages(host.webview);

  const pending = resolveZapActiveScanConsent({
    dashboardProvider: provider,
    mode: 'active',
    target: TARGET,
    window: { showWarningMessage: async () => { throw new Error('native dialog should not open'); } }
  });
  assert.match(host.webview.html, /sc-zap-preflight/);
  host.receive({ type: 'zapPreflightResolved', id: provider.zapPreflight.id, decision: 'passive' });

  assert.deepEqual(await pending, { mode: 'baseline', passiveFallback: true });
});

test('baseline ZAP mode and disabled ZAP do not require unnecessary consent', () => {
  assert.equal(zapModeFromPolicy({}), 'baseline');
  assert.equal(zapModeFromPolicy({ zapActive: true }), 'active');
  assert.equal(zapModeFromPolicy({ zapOpenapi: 'openapi.yaml', zapActive: true }), 'openapi');

  assert.equal(zapRequestedForScan(cfg({ 'zap.enabled': true }), { scanners: { ZAP: true } }, undefined), true);
  assert.equal(zapRequestedForScan(cfg({ 'zap.enabled': false }), { scanners: { ZAP: true } }, undefined), false);
  assert.equal(zapRequestedForScan(cfg({ 'zap.enabled': true }), { scanners: { ZAP: false } }, undefined), false);
  assert.equal(zapRequestedForScan(cfg({ 'zap.enabled': true }), { scanners: { ZAP: true } }, new Set(['Semgrep'])), false);
});

test('Dashboard, Quick Actions, command palette, and Scans page converge on the shared scan command', () => {
  const source = extensionSource();
  assert.match(source, /registerCommand\('securityCenter\.scanWorkspace'/);
  assert.match(source, /registerCommand\('securityCenter\.scanSelected'[\s\S]*executeCommand\('securityCenter\.scanWorkspace', selected\.map/);
  assert.match(source, /registerCommand\('securityCenter\.scanZap'[\s\S]*executeCommand\('securityCenter\.scanWorkspace', \['ZAP'\]\)/);

  const dashboardHtml = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', 'full');
  assert.match(dashboardHtml, /data-command="securityCenter\.scanWorkspace"/);

  const scansHtml = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'completed', mode: 'baseline' }], { scanStatus: 'completed' }), 'n', 'scans');
  assert.match(scansHtml, /data-command="securityCenter\.scanZap"/);
});

test('page-owned ZAP blocking confirmation is deactivated everywhere', () => {
  const state = { zapConfirmationVisible: true, zapConfirmation: { mode: 'active', target: TARGET } };
  const model = buildDashboardModel([], [{ tool: 'ZAP', status: 'pending' }], { scanStatus: 'idle' });
  for (const surface of ['full', 'scans', 'dynamic']) {
    const html = renderDashboardHtml(model, 'n', surface, 'light', state);
    assert.doesNotMatch(html, /Autoriser l'analyse ZAP|Autoriser l’analyse ZAP/);
    assert.doesNotMatch(html, /data-zap-confirm|data-zap-cancel/);
  }
  const sidebar = renderSidebarLauncherHtml(model, 'n', 'light', state);
  assert.doesNotMatch(sidebar, /Autoriser l’analyse ZAP/);
  assert.doesNotMatch(sidebar, /data-zap-confirm|data-zap-cancel/);
  assert.doesNotMatch(dashboardSource(), /zap-confirmation-backdrop/);
  assert.doesNotMatch(sidebarSource(), /zap-backdrop/);
});

test('webview ZAP command no longer opens a page-local consent gate', () => {
  const commands = [];
  const provider = new DashboardProvider((...args) => { commands.push(args); });
  let receive = null;
  provider.registerMessages({ onDidReceiveMessage: (handler) => { receive = handler; } });
  provider.render = () => {};
  provider.openPage = (page) => { throw new Error(`unexpected page navigation to ${page}`); };

  receive({ type: 'command', command: 'securityCenter.scanZap' });

  assert.deepEqual(commands, [['securityCenter.scanZap']]);
  assert.equal(provider.zapConfirmationVisible, undefined);
  assert.equal(provider.zapConfirmation, undefined);
});

test('scan orchestration does not retain dashboardProvider ZAP authorization', () => {
  const source = extensionSource();
  assert.doesNotMatch(source, /requestZapAuthorization/);
  assert.doesNotMatch(source, /confirmZapScan|cancelZapScan|requestZapScan/);
  assert.match(source, /const decision = await resolveZapActiveScanConsent/);
  assert.match(source, /preflightZapMode = decision\.mode \|\| preflightZapMode/);
});

test('ZAP passive and active modes remain represented on the Scans page', () => {
  const passive = renderDashboardHtml(buildDashboardModel([], [
    { tool: 'ZAP', status: 'completed', mode: 'baseline', currentRun: { resultCount: 0, findings: [] } }
  ], { scanStatus: 'completed', dynamicTargetUrl: TARGET }), 'n', 'scans');
  assert.match(passive, /<h4>ZAP<\/h4><p>Passif baseline<\/p>/);

  const active = renderDashboardHtml(buildDashboardModel([], [
    { tool: 'ZAP', status: 'running', mode: 'active', currentRun: { resultCount: null, findings: [] } }
  ], { scanStatus: 'running', dynamicTargetUrl: TARGET }), 'n', 'scans');
  assert.match(active, /<h4>ZAP<\/h4><p>Actif<\/p>/);
});
