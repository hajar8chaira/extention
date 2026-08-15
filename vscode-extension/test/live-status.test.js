const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveStatusBar, statusPresentation, statusTooltip } = require('../src/live/liveStatus');

test('mappe les états Live vers les Codicons natifs attendus', () => {
  assert.equal(statusPresentation('disabled', 0).text, '$(eye-closed) Live');
  assert.equal(statusPresentation('clean', 0).text, '$(eye) Live');
  assert.equal(statusPresentation('analyzing', 0).text, '$(sync~spin) Live');
  assert.equal(statusPresentation('issues', 2).text, '$(warning) Live · 2');
  assert.equal(statusPresentation('error', 0).text, '$(error) Live');
  assert.equal(statusPresentation('idle', 0).text, '$(eye) Live');
  assert.equal(statusPresentation('issues', 1).command, 'securityCenter.openLiveSecurityPage');
});

test('le tooltip reste concis et contextualisé', () => {
  const tooltip = statusTooltip('issues', 'src/app.js', 2);
  assert.match(tooltip, /Potential issues/);
  assert.match(tooltip, /src\/app\.js/);
  assert.match(tooltip, /Live warnings: 2/);
});

test('le tooltip affiche un bref apercu des alertes sans surcharger la barre', () => {
  const tooltip = statusTooltip('issues', 'src/app.js', 2, [
    { severity: 'high', title: 'Possible injection in the current handler' },
    { severity: 'medium', title: 'Unsafe redirect' }
  ]);
  assert.match(tooltip, /HIGH: Possible injection/);
  assert.match(tooltip, /MEDIUM: Unsafe redirect/);
  assert.match(tooltip, /Click to open Live Security/);
});

test('la bulle Live est prioritaire à droite et visible immédiatement', () => {
  const created = [];
  const api = {
    StatusBarAlignment: { Left: 1, Right: 2 },
    window: {
      activeTextEditor: undefined,
      createStatusBarItem: (alignment, priority) => {
        const item = { alignment, priority, shown: false, show() { this.shown = true; }, dispose: () => {} };
        created.push(item);
        return item;
      },
      onDidChangeActiveTextEditor: () => ({ dispose: () => {} })
    }
  };
  const service = { getState: () => 'idle', onDidChangeState: () => ({ dispose: () => {} }) };
  const diagnostics = { findingsForDocument: () => [], onDidChange: () => ({ dispose: () => {} }) };
  const status = new LiveStatusBar({ api, service, diagnostics });
  assert.equal(created.length, 2);
  assert.equal(created[0].alignment, api.StatusBarAlignment.Right);
  assert.equal(created[0].priority, 10000);
  assert.equal(created[0].shown, true);
  assert.equal(created[0].text, '$(eye) Live');
  assert.equal(created[1].priority, 9999);
  assert.equal(created[1].text, '$(hubot) Watching');
  status.dispose();
});

test('affiche une notification compacte à l’activation et pour une nouvelle alerte', () => {
  const stateListeners = [];
  const diagnosticListeners = [];
  const messages = [];
  const api = {
    StatusBarAlignment: { Right: 2 },
    window: {
      activeTextEditor: undefined,
      createStatusBarItem: () => ({ show: () => {}, dispose: () => {} }),
      onDidChangeActiveTextEditor: () => ({ dispose: () => {} }),
      showInformationMessage: (message) => { messages.push(message); return Promise.resolve(); },
      showWarningMessage: (message) => { messages.push(message); return Promise.resolve(); }
    }
  };
  let state = 'disabled';
  const service = { getState: () => state, onDidChangeState: (listener) => { stateListeners.push(listener); return { dispose: () => {} }; } };
  const diagnostics = {
    findingsForDocument: () => [],
    onDidChange: (listener) => { diagnosticListeners.push(listener); return { dispose: () => {} }; }
  };
  const status = new LiveStatusBar({ api, service, diagnostics });
  state = 'idle'; stateListeners[0]('idle');
  state = 'issues';
  diagnosticListeners[0]({ findings: [{ uri: 'file:///app.js', ruleId: 'unsafe-eval', severity: 'high', title: 'Unsafe eval', range: { start: { line: 1 } } }] });
  assert.match(messages[0], /active and watching/);
  assert.match(messages[1], /HIGH — Unsafe eval/);
  status.dispose();
});
