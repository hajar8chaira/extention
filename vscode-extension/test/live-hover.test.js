const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveHoverProvider, buildLiveHoverMarkdown, commandLink } = require('../src/live/liveHover');

class MarkdownString {
  constructor() { this.value = ''; }
  appendMarkdown(value) { this.value += value; }
}
class Range {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    this.start = { line: startLine, character: startCharacter };
    this.end = { line: endLine, character: endCharacter };
  }
}
class Hover {
  constructor(contents, range) { this.contents = contents; this.range = range; }
}
const api = { MarkdownString, Range, Hover };
const finding = {
  uri: 'file:///repo/app.js', documentVersion: 7,
  range: { start: { line: 4, character: 2 }, end: { line: 4, character: 22 } },
  severity: 'high', ruleId: 'sql-string-concatenation', title: 'Potential SQL injection',
  description: 'User-controlled input may be concatenated into a SQL query.',
  recommendation: 'Use a parameterized query.', cwe: 'CWE-89', confidence: 'high',
  source: 'Security Center Live', quickFixAvailable: false
};

test('construit un hover Live concis, local et sans prétendre utiliser Ollama', () => {
  const markdown = buildLiveHoverMarkdown(finding, api);
  assert.match(markdown.value, /Potential SQL injection/);
  assert.match(markdown.value, /HIGH · CWE-89 · Security Center Live/);
  assert.match(markdown.value, /Use a parameterized query/);
  assert.match(markdown.value, /Analyzed locally/);
  assert.doesNotMatch(markdown.value, /Ollama/);
  assert.deepEqual(markdown.isTrusted.enabledCommands, ['securityCenter.explainLiveFinding', 'securityCenter.applyLiveQuickFix', 'securityCenter.generateLiveAiFix', 'securityCenter.openDashboard']);
  assert.match(markdown.value, /AI Fix/);
});

test('n’annonce Quick Fix que lorsque le modèle le permet', () => {
  assert.doesNotMatch(buildLiveHoverMarkdown(finding, api).value, /Quick Fix available/);
  assert.match(buildLiveHoverMarkdown({ ...finding, quickFixAvailable: true }, api).value, /Quick Fix available/);
});

test('encode les arguments des liens de commande sans HTML personnalisé', () => {
  const link = commandLink('Explain', 'securityCenter.explainLiveFinding', ['file:///a b.js', 2]);
  assert.match(link, /^\[Explain\]\(command:securityCenter\.explainLiveFinding\?/);
  assert.match(decodeURIComponent(link), /file:\/\/\/a b\.js/);
});

test('retourne un hover uniquement sur un finding Live courant', () => {
  const provider = new LiveHoverProvider({ api, diagnostics: { findFinding: () => finding } });
  const hover = provider.provideHover({}, { line: 4, character: 6 });
  assert.equal(hover.range.start.line, 4);
  assert.match(hover.contents.value, /Explain/);
  const absent = new LiveHoverProvider({ api, diagnostics: { findFinding: () => undefined } });
  assert.equal(absent.provideHover({}, { line: 0, character: 0 }), undefined);
});
