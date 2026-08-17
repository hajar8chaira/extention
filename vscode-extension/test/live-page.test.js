const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveSessionActivity, renderLiveSecurityPage } = require('../src/live/livePage');

function finding(overrides = {}) {
  return { id: 'live:eval:1:0', uri: 'file:///repo/app.js', documentVersion: 2, ruleId: 'unsafe-eval', title: 'Potential unsafe eval', severity: 'high', cwe: 'CWE-95', range: { start: { line: 1, character: 0 }, end: { line: 1, character: 8 } }, quickFixAvailable: false, ...overrides };
}

test('suit les détections et résolutions uniquement pendant la session', () => {
  const activity = new LiveSessionActivity({ now: () => new Date('2026-08-13T10:00:00Z') });
  activity.update('file:///repo/app.js', [finding()]);
  activity.update('file:///repo/app.js', []);
  const snapshot = activity.snapshot();
  assert.equal(snapshot.detected, 1);
  assert.equal(snapshot.resolved, 1);
  assert.equal(snapshot.prevented, 1);
  assert.equal(snapshot.recent.length, 2);
});

test('montre un conseil une seule fois après répétition de la même règle', () => {
  const activity = new LiveSessionActivity();
  activity.update('file:///repo/a.js', [finding({ recommendation: 'Avoid eval.' })]);
  activity.update('file:///repo/b.js', [finding({ id: 'live:eval:2:0', uri: 'file:///repo/b.js', recommendation: 'Avoid eval.' })]);
  assert.equal(activity.snapshot().tip, 'Avoid eval.');
});

test('affiche le compagnon animé et le contexte connu uniquement avec preuves', () => {
  const html = renderLiveSecurityPage({ state: 'analyzing', file: 'src/app.js', findings: [], activity: { detected: 0, resolved: 0, prevented: 0, recent: [], tip: '' }, ollamaModel: '', knownFindings: [{ title: 'Known issue' }], companion: { mascotState: 'thinking', message: { kind: 'scanning', headline: 'J’analyse les modifications…' }, liveFindingCount: 0 } }, 'nonce', 'vscode-resource:/security-companion.png', 'vscode-webview:');
  // Le compagnon décoratif en PNG est remplacé par la vraie mascotte animée,
  // pilotée par le modèle partagé. Une seule mascotte sur la page.
  assert.ok(!html.includes('security-companion.png'));
  assert.equal((html.match(/<svg class="mascot/g) || []).length, 1);
  assert.match(html, /class="mascot mascot-thinking/);
  assert.match(html, /@keyframes/);
  assert.match(html, /Checking current file/);
  assert.match(html, /Known findings in this file/);
  assert.match(html, /prefers-reduced-motion:reduce/);
  assert.match(html, /img-src vscode-webview:/);
});

test('garde le compagnon actif même lorsque le fichier ouvert n’est pas encore supporté', () => {
  const html = renderLiveSecurityPage({ state: 'idle', file: 'README.md', supportedFile: false, findings: [], activity: { detected: 0, resolved: 0, prevented: 0, recent: [], tip: '' }, ollamaModel: '', knownFindings: [] }, 'nonce', 'vscode-resource:/security-companion.png', 'vscode-webview:');
  assert.match(html, /Watching your code/);
  assert.match(html, /README\.md is not analyzed yet/);
  assert.match(html, /JavaScript and TypeScript/);
  assert.match(html, /class="theme-light active idle"/);
});

test('rend une page Live dédiée sans historique des scans normaux', () => {
  const html = renderLiveSecurityPage({ state: 'issues', file: 'src/app.js', findings: [finding()], activity: { detected: 3, resolved: 2, recent: [] }, ollamaModel: 'qwen2.5-coder:14b' }, 'nonce');
  assert.match(html, /Live Security/);
  assert.match(html, /Current file warnings/);
  assert.match(html, /Session warnings/);
  assert.match(html, /Resolved live/);
  assert.match(html, /Potential unsafe eval/);
  assert.match(html, /JavaScript \/ TypeScript/);
  assert.match(html, /qwen2\.5-coder:14b/);
  assert.match(html, /Used only on request/);
  assert.doesNotMatch(html, /scan history|Semgrep|ZAP|Burp/i);
  assert.match(html, /var\(--vscode-editor-background\)/);
});

test('échappe les données Live affichées dans la page', () => {
  const html = renderLiveSecurityPage({ state: 'clean', file: '<script>', findings: [], activity: { detected: 0, resolved: 0, recent: [] }, ollamaModel: '<model>' }, 'nonce');
  assert.doesNotMatch(html, /<script><\/script>|<model>/);
  assert.match(html, /&lt;script&gt;/);
});

