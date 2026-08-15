const test = require('node:test');
const assert = require('node:assert/strict');
const { SecurityStatusBar, dashboardStatusPresentation } = require('../src/securityStatusBar');

test('presents risk, critical findings and scanners without running a command', () => {
  const presentation = dashboardStatusPresentation({
    riskScore: 73,
    riskLevel: 'high',
    scanStatus: 'running',
    findings: [
      { rawSeverity: 'CRITICAL', triageStatus: 'new' },
      { rawSeverity: 'CRITICAL', triageStatus: 'accepted' },
      { rawSeverity: 'HIGH', triageStatus: 'new' }
    ],
    scanners: [
      { tool: 'Semgrep', status: 'completed' },
      { tool: 'Gitleaks', status: 'running' },
      { tool: 'Trivy', status: 'pending' }
    ]
  });
  assert.equal(presentation.risk.text, '$(shield) Recalcul...');
  assert.equal(presentation.critical.text, '$(error) 1');
  assert.equal(presentation.scanners.text, '$(sync~spin) 1/3');
  assert.equal(presentation.risk.command, 'securityCenter.openDashboard');
  assert.equal(presentation.critical.command, 'securityCenter.openFindingsPage');
  assert.equal(presentation.scanners.command, 'securityCenter.openScansPage');
});

test('distinguishes completed and partial scanner states', () => {
  const completed = dashboardStatusPresentation({
    scanners: [{ status: 'completed' }, { status: 'completed' }], scanStatus: 'completed'
  });
  const partial = dashboardStatusPresentation({
    scanners: [{ status: 'completed' }, { status: 'failed' }], scanStatus: 'partial'
  });
  assert.equal(completed.scanners.text, '$(check) 2/2');
  assert.equal(partial.scanners.text, '$(warning) 1/2');
});

test('creates native status items and updates them without invoking scanners', () => {
  const items = [];
  let commandExecutions = 0;
  const api = {
    StatusBarAlignment: { Left: 1 },
    ThemeColor: class ThemeColor { constructor(id) { this.id = id; } },
    commands: { executeCommand: () => { commandExecutions += 1; } },
    window: {
      createStatusBarItem: (alignment, priority) => {
        const item = { alignment, priority, showCount: 0, disposeCount: 0, show() { this.showCount += 1; }, dispose() { this.disposeCount += 1; } };
        items.push(item);
        return item;
      }
    }
  };
  const bar = new SecurityStatusBar({ api });
  bar.update({ riskScore: 100, riskLevel: 'critical', findings: [{ rawSeverity: 'CRITICAL' }], scanners: [{ status: 'failed' }], scanStatus: 'partial' });
  assert.equal(items.length, 3);
  assert.deepEqual(items.map((item) => item.priority), [103, 102, 101]);
  assert.equal(items[0].text, '$(shield) 100');
  assert.equal(items[2].text, '$(warning) 0/1');
  assert.equal(items[1].text, '$(error) 1');
  assert.equal(items[2].text, '$(warning) 0/1');
  assert.equal(items[2].backgroundColor.id, 'statusBarItem.warningBackground');
  assert.equal(commandExecutions, 0);
  bar.dispose();
  assert.deepEqual(items.map((item) => item.disposeCount), [1, 1, 1]);
});
