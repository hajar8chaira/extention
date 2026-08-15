const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveStatusBar, statusPresentation, statusTooltip } = require('../src/live/liveStatus');

test('mappe les états Live vers les Codicons natifs attendus', () => {
  assert.equal(statusPresentation('disabled', 0).text, '$(shield) Live off');
  assert.equal(statusPresentation('clean', 0).text, '$(pass-filled) Live clean');
  assert.equal(statusPresentation('analyzing', 0).text, '$(sync~spin) Scanning code');
  assert.equal(statusPresentation('issues', 2).text, '$(warning) 2 live alerts');
  assert.equal(statusPresentation('error', 0).text, '$(error) Live unavailable');
  assert.equal(statusPresentation('idle', 0).text, '$(eye) Live watching');
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
  let alignment;
  let priority;
  let shown = false;
  const item = { show: () => { shown = true; }, dispose: () => {} };
  const api = {
    StatusBarAlignment: { Left: 1, Right: 2 },
    window: {
      activeTextEditor: undefined,
      createStatusBarItem: (nextAlignment, nextPriority) => { alignment = nextAlignment; priority = nextPriority; return item; },
      onDidChangeActiveTextEditor: () => ({ dispose: () => {} })
    }
  };
  const service = { getState: () => 'idle', onDidChangeState: () => ({ dispose: () => {} }) };
  const diagnostics = { findingsForDocument: () => [], onDidChange: () => ({ dispose: () => {} }) };
  const status = new LiveStatusBar({ api, service, diagnostics });
  assert.equal(alignment, api.StatusBarAlignment.Right);
  assert.equal(priority, 10000);
  assert.equal(shown, true);
  assert.equal(item.text, '$(eye) Live watching');
  status.dispose();
});

test('affiche une notification compacte à l’activation et pour une nouvelle alerte', () => {
  const stateListeners = [];
  const diagnosticListeners = [];
  const messages = [];
  const item = { show: () => {}, dispose: () => {} };
  const api = {
    StatusBarAlignment: { Right: 2 },
    window: {
      activeTextEditor: undefined,
      createStatusBarItem: () => item,
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
