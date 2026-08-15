function activeFindings(model = {}) {
  return (model.findings || []).filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus));
}

function scannerSummary(model = {}) {
  const scanners = model.scanners || [];
  const completed = scanners.filter((scanner) => scanner.status === 'completed').length;
  const failedTools = scanners.filter((scanner) => ['failed', 'cancelled'].includes(scanner.status)).map((scanner) => scanner.tool).filter(Boolean);
  const running = scanners.some((scanner) => ['running', 'refreshing'].includes(scanner.status)) || model.scanStatus === 'running';
  const failed = scanners.some((scanner) => ['failed', 'cancelled'].includes(scanner.status)) || ['failed', 'cancelled', 'partial'].includes(model.scanStatus);
  return {
    completed,
    total: scanners.length,
    failedTools,
    state: running ? 'running' : failed ? 'failed' : scanners.length && completed === scanners.length ? 'completed' : 'idle'
  };
}

function dashboardStatusPresentation(model = {}) {
  const findings = activeFindings(model);
  const critical = findings.filter((finding) => ['CRITICAL', 'ERROR'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  const scanners = scannerSummary(model);
  return {
    risk: {
      text: scanners.state === 'running' ? '$(shield) Recalcul...' : `$(shield) ${Number(model.riskScore || 0)}`,
      tooltip: `Security Center — risque ${String(model.riskLevel || 'non évalué')} (${Number(model.riskScore || 0)}/100)`,
      command: 'securityCenter.openDashboard'
    },
    critical: {
      text: `$(error) ${critical}`,
      tooltip: `${critical} finding${critical === 1 ? '' : 's'} critique${critical === 1 ? '' : 's'} — ouvrir Findings`,
      command: 'securityCenter.openFindingsPage'
    },
    scanners: {
      text: scanners.state === 'running'
        ? `$(sync~spin) ${scanners.completed}/${scanners.total}`
        : scanners.state === 'failed'
          ? scanners.failedTools.length === 1
            ? `$(error) ${scanners.failedTools[0]} failed`
            : `$(warning) ${scanners.completed}/${scanners.total}`
          : `$(check) ${scanners.completed}/${scanners.total}`,
      tooltip: scanners.state === 'running'
        ? `Analyse en cours — ${scanners.completed}/${scanners.total} scanners terminés`
        : scanners.state === 'failed'
          ? `Scan partiel — ${scanners.completed}/${scanners.total} scanners terminés`
          : `${scanners.completed}/${scanners.total} scanners terminés`,
      command: 'securityCenter.openScansPage',
      state: scanners.state
    }
  };
}

class SecurityStatusBar {
  constructor({ api }) {
    this.api = api;
    this.riskItem = api.window.createStatusBarItem(api.StatusBarAlignment.Left, 103);
    this.criticalItem = api.window.createStatusBarItem(api.StatusBarAlignment.Left, 102);
    this.scannerItem = api.window.createStatusBarItem(api.StatusBarAlignment.Left, 101);
    this.items = [this.riskItem, this.criticalItem, this.scannerItem];
    this.items.forEach((item) => item.show());
    this.update({});
  }
  update(model) {
    const presentation = dashboardStatusPresentation(model);
    this.apply(this.riskItem, presentation.risk, 'Security Center Risk');
    this.apply(this.criticalItem, presentation.critical, 'Security Center Critical Findings');
    this.apply(this.scannerItem, presentation.scanners, 'Security Center Scanners');
  }
  apply(item, presentation, name) {
    item.text = presentation.text;
    item.tooltip = presentation.tooltip;
    item.command = presentation.command;
    item.name = name;
    item.accessibilityInformation = { label: presentation.tooltip, role: 'button' };
    if (this.api.ThemeColor) {
      item.backgroundColor = presentation.state === 'failed'
        ? new this.api.ThemeColor('statusBarItem.warningBackground')
        : undefined;
    }
  }
  dispose() { this.items.forEach((item) => item.dispose()); }
}

module.exports = { SecurityStatusBar, activeFindings, scannerSummary, dashboardStatusPresentation };
