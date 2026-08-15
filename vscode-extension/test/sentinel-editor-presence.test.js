const test = require('node:test');
const assert = require('node:assert/strict');
const { SentinelEditorPresence, firstChangedLine, validFindingsForDocument } = require('../src/live/sentinelEditorPresence');

class Range { constructor(startLine, startCharacter, endLine, endCharacter) { this.start = { line: startLine, character: startCharacter }; this.end = { line: endLine, character: endCharacter }; } }
function documentFixture({ uri = 'file:///repo/app.js', version = 2, languageId = 'javascript' } = {}) {
  const fsPath = uri.replace('file:///', 'C:\\').replaceAll('/', '\\');
  return { uri: { scheme: 'file', fsPath, toString: () => uri }, version, languageId, lineCount: 50, isClosed: false, isUntitled: false, getText: () => 'const value = input;' };
}
function finding(document, line = 4, title = 'Possible SQL Injection') {
  return { uri: document.uri.toString(), documentVersion: document.version, severity: 'high', title, ruleId: `rule-${line}`, range: { start: { line, character: 2 }, end: { line, character: 12 } } };
}
function harness({ languageId = 'javascript', enabled = true } = {}) {
  const document = documentFixture({ languageId });
  const applied = new Map();
  const editor = { document, setDecorations: (type, values) => applied.set(type.key, values) };
  const changeListeners = [], editorListeners = [], stateListeners = [], diagnosticListeners = [];
  let state = enabled ? 'idle' : 'disabled';
  let storedFindings = [];
  let detectorCalls = 0;
  const decorations = [];
  const api = {
    Range, ThemeColor: class { constructor(id) { this.id = id; } }, OverviewRulerLane: { Right: 4 },
    Uri: { joinPath: (_base, ...parts) => ({ fsPath: parts.join('/'), toString: () => parts.join('/') }) },
    window: {
      activeTextEditor: editor,
      createTextEditorDecorationType: () => { const value = { key: `d${decorations.length}`, dispose: () => {} }; decorations.push(value); return value; },
      onDidChangeActiveTextEditor: (listener) => { editorListeners.push(listener); return { dispose: () => {} }; }
    }
  };
  const workspace = {
    getWorkspaceFolder: () => ({}),
    onDidChangeTextDocument: (listener) => { changeListeners.push(listener); return { dispose: () => {} }; }
  };
  const service = { isEnabled: () => enabled, getState: () => state, onDidChangeState: (listener) => { stateListeners.push(listener); return { dispose: () => {} }; } };
  const diagnostics = {
    findingsForDocument: (doc) => storedFindings.filter((item) => item.uri === doc.uri.toString() && item.documentVersion === doc.version),
    onDidChange: (listener) => { diagnosticListeners.push(listener); return { dispose: () => {} }; }
  };
  const presence = new SentinelEditorPresence({ api, service, diagnostics, extensionUri: {}, workspace, transientMs: { checking: 20, clean: 20, resolved: 20, issue: 20 } });
  return {
    api, workspace, service, diagnostics, presence, document, editor, applied, decorations,
    edit: (line) => changeListeners[0]({ document, contentChanges: [{ range: { start: { line } } }] }),
    state: (next) => { state = next; stateListeners[0](next); },
    publish: (items, reason = 'analysis') => { storedFindings = items; diagnosticListeners[0]({ uri: document.uri.toString(), findings: items, reason }); },
    switchEditor: (next) => { api.window.activeTextEditor = next; editorListeners[0](next); },
    detectorCalls: () => detectorCalls
  };
}

test('extrait uniquement la première ligne réellement modifiée', () => {
  assert.equal(firstChangedLine({ contentChanges: [{ range: { start: { line: 8 } } }, { range: { start: { line: 3 } } }] }), 3);
});

test('affiche la présence puis l’état analyzing sur la ligne modifiée sans invoquer le détecteur', () => {
  const ctx = harness();
  ctx.edit(12);
  assert.equal(ctx.applied.get('d1')[0].start.line, 12);
  ctx.state('analyzing');
  assert.equal(ctx.applied.get('d1')[0].start.line, 12);
  assert.equal(ctx.detectorCalls(), 0);
  ctx.presence.dispose();
});

test('affiche un état propre transitoire après un résultat vide', () => {
  const ctx = harness(); ctx.edit(7); ctx.publish([]);
  assert.equal(ctx.applied.get('d2')[0].start.line, 7);
  ctx.presence.dispose();
});

test('affiche plusieurs findings et seulement le plus récent en texte inline', () => {
  const ctx = harness(); const findings = [finding(ctx.document, 4), finding(ctx.document, 9, 'Unsafe command execution')];
  ctx.publish(findings);
  assert.equal(ctx.applied.get('d3').length, 2);
  assert.equal(ctx.applied.get('d4').length, 1);
  assert.match(ctx.applied.get('d4')[0].renderOptions.after.contentText, /Possible SQL Injection/);
  ctx.presence.dispose();
});

test('montre Resolved lorsque les findings de la version précédente disparaissent', () => {
  const ctx = harness(); ctx.publish([finding(ctx.document, 5)]); ctx.publish([]);
  assert.equal(ctx.applied.get('d5')[0].start.line, 5);
  ctx.presence.dispose();
});

test('ignore les résultats obsolètes et les fichiers non supportés', () => {
  const ctx = harness();
  ctx.publish([{ ...finding(ctx.document, 4), documentVersion: 1 }]);
  assert.equal((ctx.applied.get('d3') || []).length, 0);
  ctx.presence.dispose();
  const unsupported = harness({ languageId: 'python' }); unsupported.edit(3);
  assert.equal((unsupported.applied.get('d1') || []).length, 0);
  unsupported.presence.dispose();
});

test('nettoie l’ancien éditeur au changement et toutes les décorations à la désactivation', () => {
  const ctx = harness(); ctx.edit(2); ctx.publish([finding(ctx.document, 2)]);
  const nextDocument = documentFixture({ uri: 'file:///repo/next.js', version: 1 });
  const nextApplied = new Map();
  const nextEditor = { document: nextDocument, setDecorations: (type, values) => nextApplied.set(type.key, values) };
  ctx.switchEditor(nextEditor);
  assert.equal((ctx.applied.get('d3') || []).length, 0);
  ctx.state('disabled');
  for (const decoration of ctx.decorations) assert.equal((nextApplied.get(decoration.key) || []).length, 0);
  ctx.presence.dispose();
});

test('filtre strictement URI et version avant toute décoration', () => {
  const document = documentFixture();
  assert.equal(validFindingsForDocument([finding(document), { ...finding(document), documentVersion: 1 }], document).length, 1);
});
