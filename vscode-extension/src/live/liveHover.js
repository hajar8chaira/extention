function commandLink(label, command, args) {
  const query = args === undefined ? '' : `?${encodeURIComponent(JSON.stringify(args))}`;
  return `[${label}](command:${command}${query})`;
}

function buildLiveHoverMarkdown(finding, api) {
  const markdown = new api.MarkdownString();
  markdown.isTrusted = {
    enabledCommands: ['securityCenter.explainLiveFinding', 'securityCenter.applyLiveQuickFix', 'securityCenter.generateLiveAiFix', 'securityCenter.openDashboard']
  };
  markdown.supportHtml = false;
  markdown.supportThemeIcons = true;
  const severity = String(finding.severity || 'medium').toUpperCase();
  const metadata = [severity, finding.cwe, 'Security Center Live'].filter(Boolean).join(' · ');
  markdown.appendMarkdown(`**$(warning) ${finding.title}**\n\n`);
  markdown.appendMarkdown(`${metadata}\n\n`);
  markdown.appendMarkdown(`${finding.description}\n\n`);
  if (finding.recommendation) markdown.appendMarkdown(`**Recommended:**  \n${finding.recommendation}\n\n`);
  const reference = [finding.uri, finding.documentVersion, finding.ruleId];
  if (finding.quickFixAvailable) markdown.appendMarkdown(`Quick Fix available. ${commandLink('Apply safe fix', 'securityCenter.applyLiveQuickFix', reference)}\n\n`);
  markdown.appendMarkdown(`${commandLink('Explain', 'securityCenter.explainLiveFinding', reference)} · ${commandLink('AI Fix', 'securityCenter.generateLiveAiFix', reference)} · ${commandLink('Open Security Center', 'securityCenter.openDashboard')}\n\n`);
  markdown.appendMarkdown('Security Center Live · Analyzed locally');
  return markdown;
}

class LiveHoverProvider {
  constructor({ api, diagnostics }) {
    this.api = api;
    this.diagnostics = diagnostics;
  }

  provideHover(document, position) {
    const finding = this.diagnostics.findFinding(document, position);
    if (!finding) return undefined;
    const range = new this.api.Range(
      finding.range.start.line,
      finding.range.start.character,
      finding.range.end.line,
      finding.range.end.character
    );
    return new this.api.Hover(buildLiveHoverMarkdown(finding, this.api), range);
  }
}

module.exports = { LiveHoverProvider, buildLiveHoverMarkdown, commandLink };
