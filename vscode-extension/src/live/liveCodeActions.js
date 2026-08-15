const path = require('path');

const LIVE_SELECTOR = Object.freeze(['javascript', 'javascriptreact', 'typescript', 'typescriptreact']);

function deterministicReplacement(finding, currentText) {
  if (finding.ruleId !== 'tls-verification-disabled') return undefined;
  if (/^rejectUnauthorized\s*:\s*false$/.test(currentText.trim())) return currentText.replace(/false/, 'true');
  if (/^NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?$/.test(currentText.trim())) {
    return currentText.replace(/(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?)0/, (_match, prefix) => `${prefix}1`);
  }
  return undefined;
}

function liveFindingReference(finding) {
  return [finding.uri, finding.documentVersion, finding.ruleId];
}

function toRemediationFinding(finding, workspacePath, uri) {
  const absolutePath = uri.fsPath;
  const relative = path.relative(workspacePath, absolutePath).replaceAll('\\', '/');
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Le finding Live doit rester dans le workspace.');
  return {
    id: finding.id,
    tool: 'Security Center Live',
    ruleId: finding.ruleId,
    title: finding.title,
    description: finding.description,
    cwe: finding.cwe,
    rawSeverity: finding.severity,
    severity: finding.severity,
    file: relative,
    absolutePath,
    startLine: finding.range.start.line,
    startColumn: finding.range.start.character,
    endLine: finding.range.end.line,
    endColumn: finding.range.end.character,
    liveSecurity: true,
    liveDocumentVersion: finding.documentVersion
  };
}

class LiveCodeActionProvider {
  constructor({ api, diagnostics }) {
    this.api = api;
    this.diagnostics = diagnostics;
  }

  provideCodeActions(document, range) {
    const finding = this.diagnostics.findFinding(document, range.start);
    if (!finding) return [];
    const reference = liveFindingReference(finding);
    const actions = [];
    if (finding.quickFixAvailable) {
      const fix = new this.api.CodeAction('Security Center Live: Apply safe fix', this.api.CodeActionKind.QuickFix);
      fix.command = { command: 'securityCenter.applyLiveQuickFix', title: 'Apply safe fix', arguments: reference };
      fix.isPreferred = true;
      actions.push(fix);
    }
    const explain = new this.api.CodeAction('Security Center Live: Explain issue', this.api.CodeActionKind.QuickFix);
    explain.command = { command: 'securityCenter.explainLiveFinding', title: 'Explain issue', arguments: reference };
    actions.push(explain);
    const ai = new this.api.CodeAction('Security Center Live: Generate fix with Ollama', this.api.CodeActionKind.QuickFix);
    ai.command = { command: 'securityCenter.generateLiveAiFix', title: 'Generate fix with Ollama', arguments: reference };
    actions.push(ai);
    const ignore = new this.api.CodeAction('Security Center Live: Ignore for this session', this.api.CodeActionKind.QuickFix);
    ignore.command = { command: 'securityCenter.ignoreLiveFindingForSession', title: 'Ignore for this session', arguments: reference };
    actions.push(ignore);
    return actions;
  }
}

module.exports = { LIVE_SELECTOR, LiveCodeActionProvider, deterministicReplacement, liveFindingReference, toRemediationFinding };
