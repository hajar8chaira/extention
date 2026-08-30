const test = require('node:test');
const assert = require('node:assert/strict');
const { companionCopy, escapeHtml, renderCompanionHtml } = require('../src/live/liveCompanion');

function finding(overrides = {}) {
  return {
    uri: 'file:///repo/src/app.js', documentVersion: 3, ruleId: 'sql-string-concatenation',
    title: 'Potential SQL injection', severity: 'high',
    range: { start: { line: 41, character: 2 }, end: { line: 41, character: 20 } },
    ...overrides
  };
}

test('associe les états Live aux messages discrets du compagnon', () => {
  assert.equal(companionCopy('disabled', 0).label, 'Live Security off');
  assert.equal(companionCopy('idle', 0).label, 'Watching your code');
  assert.equal(companionCopy('analyzing', 0).label, 'Checking current file…');
  assert.equal(companionCopy('clean', 0).label, 'No live issues');
  assert.equal(companionCopy('issues', 2).label, '2 potential security issues');
  assert.equal(companionCopy('error', 0).label, 'Live analysis unavailable');
});

test('rend seulement les findings du modèle courant avec les actions mini-panneau', () => {
  const html = renderCompanionHtml({ state: 'issues', file: 'src/app.js', findings: [finding()] }, 'nonce', 'vscode-resource:/security-companion.png', 'vscode-webview:');
  assert.match(html, /Security Companion/);
  // La mascotte est l'asset local autorise par la CSP de webview.
  assert.match(html, /<img class="mascot mascot-warning /);
  assert.match(html, /@keyframes sc-breathe/);
  assert.match(html, /img-src vscode-webview:/);
  assert.match(html, /Potential SQL injection/);
  assert.match(html, /Line 42/);
  assert.match(html, />Open</);
  assert.match(html, />Explain</);
  assert.match(html, />Fix</);
  assert.match(html, /src\/app\.js/);
});

test('respecte reduced motion et les thèmes VS Code sans couleurs figées', () => {
  const html = renderCompanionHtml({ state: 'analyzing', file: '', findings: [] }, 'nonce');
  assert.match(html, /prefers-reduced-motion:reduce/);
  assert.match(html, /var\(--vscode-sideBar-background\)/);
  assert.match(html, /var\(--vscode-foreground\)/);
  assert.match(html, /color-scheme:light/);
  assert.doesNotMatch(renderCompanionHtml({ state: 'analyzing', file: '', findings: [] }, 'nonce', '', '', 'dark'), /--vscode-editor-background:#f7f8fa/);
  assert.doesNotMatch(html, /<video|canvas/i);
});

test('échappe le contenu issu du code dans la webview', () => {
  const html = renderCompanionHtml({ state: 'issues', file: '<script>x</script>', findings: [finding({ title: '<img src=x>' })] }, 'nonce');
  assert.doesNotMatch(html, /<script>x<\/script>|<img src=x>/);
  assert.match(html, /&lt;script&gt;/);
  assert.equal(escapeHtml('a&b'), 'a&amp;b');
});

test('affiche les états vide et désactivé sans dupliquer les findings persistés', () => {
  const clean = renderCompanionHtml({ state: 'clean', file: 'src/app.js', findings: [] }, 'nonce');
  assert.match(clean, /Current file looks clean/);
  const disabled = renderCompanionHtml({ state: 'disabled', file: '', findings: [] }, 'nonce');
  assert.match(disabled, /Enable Live Security/);
  assert.doesNotMatch(disabled, /Dashboard findings|scan history/i);
});


