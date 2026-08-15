const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { LiveCodeActionProvider, deterministicReplacement, toRemediationFinding } = require('../src/live/liveCodeActions');

class CodeAction {
  constructor(title, kind) { this.title = title; this.kind = kind; }
}
const api = { CodeAction, CodeActionKind: { QuickFix: 'quickfix' } };
const finding = {
  id: 'live:tls:1:0', uri: 'file:///repo/app.js', documentVersion: 4,
  range: { start: { line: 1, character: 0 }, end: { line: 1, character: 25 } },
  severity: 'high', ruleId: 'tls-verification-disabled', title: 'TLS verification disabled',
  description: 'TLS verification is disabled.', cwe: 'CWE-295', quickFixAvailable: true,
  originalText: 'rejectUnauthorized: false'
};

test('propose un Quick Fix uniquement pour une transformation déterministe', () => {
  assert.equal(deterministicReplacement(finding, 'rejectUnauthorized: false'), 'rejectUnauthorized: true');
  assert.equal(deterministicReplacement(finding, "NODE_TLS_REJECT_UNAUTHORIZED='0'"), "NODE_TLS_REJECT_UNAUTHORIZED='1'");
  assert.equal(deterministicReplacement({ ...finding, ruleId: 'sql-string-concatenation' }, 'query(sql + input)'), undefined);
  assert.equal(deterministicReplacement(finding, 'rejectUnauthorized: value'), undefined);
});

test('expose Quick Fix, explication et Ollama dans les actions natives', () => {
  const provider = new LiveCodeActionProvider({ api, diagnostics: { findFinding: () => finding } });
  const actions = provider.provideCodeActions({}, { start: { line: 1, character: 2 } });
  assert.deepEqual(actions.map((action) => action.command.command), [
    'securityCenter.applyLiveQuickFix', 'securityCenter.explainLiveFinding', 'securityCenter.generateLiveAiFix',
    'securityCenter.ignoreLiveFindingForSession'
  ]);
  assert.equal(actions[0].isPreferred, true);
});

test('ne propose aucun Quick Fix spéculatif', () => {
  const provider = new LiveCodeActionProvider({ api, diagnostics: { findFinding: () => ({ ...finding, quickFixAvailable: false }) } });
  const actions = provider.provideCodeActions({}, { start: { line: 1, character: 2 } });
  assert.equal(actions.some((action) => action.command.command === 'securityCenter.applyLiveQuickFix'), false);
});

test('convertit un finding Live vers la requête de remédiation existante sans le persister', () => {
  const workspace = path.resolve('C:/repo');
  const converted = toRemediationFinding(finding, workspace, { fsPath: path.resolve(workspace, 'src/app.js') });
  assert.equal(converted.tool, 'Security Center Live');
  assert.equal(converted.file, 'src/app.js');
  assert.equal(converted.liveSecurity, true);
  assert.equal(converted.liveDocumentVersion, 4);
});

test('refuse de déléguer un finding Live hors workspace', () => {
  assert.throws(() => toRemediationFinding(finding, path.resolve('C:/repo'), { fsPath: path.resolve('C:/other/app.js') }), /workspace/);
});
