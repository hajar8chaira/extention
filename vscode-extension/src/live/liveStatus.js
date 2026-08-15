function statusPresentation(state, count) {
  const command = 'securityCenter.openLiveSecurityPage';
  if (state === 'disabled' || state === 'paused') return { text: '$(eye-closed) Live', command };
  if (state === 'analyzing') return { text: '$(sync~spin) Live', command };
  if (state === 'issues') return { text: `$(warning) Live · ${count}`, command };
  if (state === 'error') return { text: '$(error) Live', command };
  return { text: '$(eye) Live', command };
}

function conciseTitle(value, maxLength = 46) {
  const clean = String(value || 'Potential security issue').replace(/\s+/g, ' ').trim();
  return clean.length > maxLength ? `${clean.slice(0, maxLength - 1)}…` : clean;
}

function statusTooltip(state, file, count, findings = []) {
  const stateLabel = {
    disabled: 'Disabled', paused: 'Paused', idle: 'Watching', analyzing: 'Analyzing',
    clean: 'Clean', issues: 'Potential issues', error: 'Unavailable'
  }[state] || state;
  const lines = [`Live Security: ${stateLabel}`, `Current file: ${file || 'none'}`, `Live warnings: ${count}`];
  for (const finding of findings.slice(0, 3)) {
    lines.push(`• ${String(finding.severity || 'warning').toUpperCase()}: ${conciseTitle(finding.title, 72)}`);
  }
  if (findings.length > 3) lines.push(`+ ${findings.length - 3} more`);
  lines.push('Click to open Live Security');
  return lines.join('\n');
}

class LiveStatusBar {
  constructor({ api, service, diagnostics, workspacePath = '' }) {
    this.api = api;
    this.service = service;
    this.diagnostics = diagnostics;
    this.workspacePath = workspacePath;
    this.activeDocument = api.window.activeTextEditor?.document;
    this.lastState = service.getState();
    // Keep the Live indicator visible even when extensions already occupy the
    // left side of the status bar. A high-priority right item behaves like a
    // compact, native activity bubble without covering the editor.
    this.item = api.window.createStatusBarItem(api.StatusBarAlignment.Right, 10000);
    this.companionItem = api.window.createStatusBarItem(api.StatusBarAlignment.Right, 9999);
    this.subscriptions = [
      service.onDidChangeState((state) => this.onStateChanged(state)),
      diagnostics.onDidChange((event) => this.onDiagnosticsChanged(event)),
      api.window.onDidChangeActiveTextEditor((editor) => { if (editor?.document) this.activeDocument = editor.document; this.render(); })
    ];
    this.render();
    this.item.show();
    this.companionItem.show();
  }
  onStateChanged(state) {
    const previous = this.lastState;
    this.lastState = state;
    this.render();
    if (previous === 'disabled' && state !== 'disabled') {
      this.api.window.showInformationMessage?.(
        'Live Security is active and watching the current JavaScript/TypeScript file.',
        'Open Live Security'
      ).then?.((choice) => {
        if (choice === 'Open Live Security') this.api.commands?.executeCommand?.('securityCenter.openLiveSecurityPage');
      });
    }
  }
  onDiagnosticsChanged(event = {}) {
    const newest = Array.isArray(event.findings) ? event.findings[0] : undefined;
    if (newest && event.reason !== 'suppressed') {
      this.briefFinding = newest;
      const signature = `${newest.uri || ''}:${newest.ruleId || ''}:${newest.range?.start?.line ?? ''}`;
      if (signature !== this.lastNotifiedFinding) {
        this.lastNotifiedFinding = signature;
        this.api.window.showWarningMessage?.(
          `Live Security: ${String(newest.severity || 'warning').toUpperCase()} — ${conciseTitle(newest.title, 80)}`,
          'Open'
        ).then?.((choice) => {
          if (choice === 'Open') this.api.commands?.executeCommand?.('securityCenter.openLiveSecurityPage');
        });
      }
      if (this.briefTimer) clearTimeout(this.briefTimer);
      this.briefTimer = setTimeout(() => {
        this.briefFinding = undefined;
        this.briefTimer = undefined;
        this.render();
      }, 4500);
    }
    this.render();
  }
  render() {
    const state = this.service.getState();
    const findings = this.diagnostics.findingsForDocument(this.activeDocument);
    const file = this.activeDocument?.uri?.fsPath
      ? require('path').relative(this.workspacePath, this.activeDocument.uri.fsPath).replaceAll('\\', '/')
      : '';
    const presentation = statusPresentation(state, findings.length);
    this.item.text = this.briefFinding && state === 'issues'
      ? `$(warning) ${String(this.briefFinding.severity || 'warning').toUpperCase()} · ${conciseTitle(this.briefFinding.title)}`
      : presentation.text;
    this.item.command = presentation.command;
    this.item.tooltip = statusTooltip(state, file, findings.length, findings);
    this.item.name = 'Security Center Live Security';
    this.item.accessibilityInformation = {
      label: `Live Security. ${state}. ${findings.length} warning${findings.length === 1 ? '' : 's'}. Click to open.`,
      role: 'button'
    };
    if (this.api.ThemeColor) {
      this.item.backgroundColor = state === 'issues'
        ? new this.api.ThemeColor('statusBarItem.warningBackground')
        : state === 'error'
          ? new this.api.ThemeColor('statusBarItem.errorBackground')
          : undefined;
    }
    this.companionItem.text = (state === 'disabled' || state === 'paused')
      ? '$(hubot) Off'
      : state === 'analyzing'
        ? '$(hubot) Checking'
        : state === 'issues'
          ? `$(hubot) ${findings.length} issue${findings.length === 1 ? '' : 's'}`
          : '$(hubot) Watching';
    this.companionItem.command = 'securityCenter.openLiveSecurityPage';
    this.companionItem.tooltip = state === 'disabled' ? 'Security Companion est désactivé' : `Security Companion observe le fichier courant — ${findings.length} alerte${findings.length === 1 ? '' : 's'}`;
    this.companionItem.name = 'Security Center Companion';
    this.companionItem.accessibilityInformation = { label: this.companionItem.tooltip, role: 'button' };
  }
  dispose() {
    if (this.briefTimer) clearTimeout(this.briefTimer);
    for (const subscription of this.subscriptions.splice(0)) subscription.dispose();
    this.item.dispose();
    this.companionItem.dispose();
  }
}

module.exports = { LiveStatusBar, conciseTitle, statusPresentation, statusTooltip };
