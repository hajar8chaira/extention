const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { buildAutofixPlan } = require('../src/autofix');

test('prépare uniquement une correction Semgrep native dans le workspace', () => {
  const workspace = path.resolve('C:/workspace');
  const finding = {
    tool: 'Semgrep', absolutePath: path.join(workspace, 'src/app.js'),
    autofix: 'safe(value)', originalText: 'danger(value)',
    startLine: 2, startColumn: 4, endLine: 2, endColumn: 17
  };
  const plan = buildAutofixPlan(finding, workspace, 'danger(value)');
  assert.equal(plan.replacement, 'safe(value)');
  assert.equal(plan.startLine, 2);
});

test('refuse une correction obsolète ou située hors workspace', () => {
  const workspace = path.resolve('C:/workspace');
  assert.throws(() => buildAutofixPlan({
    tool: 'Semgrep', absolutePath: path.join(workspace, 'src/app.js'), autofix: 'safe()', originalText: 'old()'
  }, workspace, 'changed()'), /changé depuis le scan/);
  assert.throws(() => buildAutofixPlan({
    tool: 'Semgrep', absolutePath: path.resolve('C:/outside/app.js'), autofix: 'safe()'
  }, workspace, 'old()'), /rester dans le workspace/);
});

test('refuse une suggestion qui ne vient pas de Semgrep', () => {
  assert.throws(() => buildAutofixPlan({ tool: 'ZAP', autofix: 'x', absolutePath: 'C:/workspace/a.js' }, 'C:/workspace', ''), /Semgrep/);
});
