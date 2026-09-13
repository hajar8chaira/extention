const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveSecurityService } = require('../src/live/liveSecurityService');
const { analyzeLiveDocument } = require('../src/live/liveDetector');

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const VULNERABLE_SOURCE = [
  "const { exec } = require('child_process');",
  'function handler(req) {',
  '  eval(req.query.code);',
  '  exec(`ls ${req.query.dir}`);',
  "  document.getElementById('out').innerHTML = req.query.html;",
  '}'
].join('\n');

function documentFixture(overrides = {}) {
  const fsPath = overrides.fsPath || 'C:\\repo\\src\\app.js';
  const uri = { scheme: 'file', fsPath, toString: () => `file:///${fsPath.replace(/\\/g, '/')}` };
  const text = overrides.text ?? VULNERABLE_SOURCE;
  return { uri, fileName: fsPath, languageId: overrides.languageId || 'javascript', version: 1, isClosed: false, isUntitled: false, getText: () => text };
}

function harness({ configuration = {}, document = documentFixture(), activeEditor = true } = {}) {
  const values = { 'live.enabled': true, 'live.debounceMs': 5, 'live.scanOnChange': true, 'live.scanOnSave': true, ...configuration };
  const listeners = { configuration: new Set(), change: new Set(), save: new Set(), editor: new Set() };
  const subscribe = (set, listener) => { set.add(listener); return { dispose: () => set.delete(listener) }; };
  const workspace = {
    getConfiguration: () => ({
      get: (key, fallback) => (values[key] === undefined ? fallback : values[key]),
      update: async (key, value) => {
        values[key] = value;
        for (const listener of listeners.configuration) listener({ affectsConfiguration: (name) => name.startsWith('securityCenter.live') });
      }
    }),
    getWorkspaceFolder: (uri) => (uri?.fsPath?.startsWith('C:\\repo') ? { uri: { fsPath: 'C:\\repo' } } : undefined),
    onDidChangeConfiguration: (listener) => subscribe(listeners.configuration, listener),
    onDidChangeTextDocument: (listener) => subscribe(listeners.change, listener),
    onDidSaveTextDocument: (listener) => subscribe(listeners.save, listener)
  };
  const window = {
    activeTextEditor: activeEditor ? { document } : undefined,
    onDidChangeActiveTextEditor: (listener) => subscribe(listeners.editor, listener)
  };
  const published = [];
  const diagnostics = { publish: (findings, token) => published.push({ findings, token }), clear: () => {} };
  let analyses = 0;
  const service = new LiveSecurityService({
    workspace, window, diagnostics,
    analyzeDocument: async (doc, context) => { analyses += 1; return analyzeLiveDocument(doc, context); }
  });
  return {
    service, workspace, window, values, published, document,
    analyses: () => analyses,
    diagnosticCount: () => published.reduce((total, entry) => total + entry.findings.length, 0),
    openEditor: (nextDocument) => {
      window.activeTextEditor = nextDocument ? { document: nextDocument } : undefined;
      for (const listener of listeners.editor) listener(window.activeTextEditor);
    },
    fireChange: (doc) => { for (const listener of listeners.change) listener({ document: doc }); },
    fireSave: (doc) => { for (const listener of listeners.save) listener(doc); }
  };
}

test('ouvrir un fichier vulnérable produit des diagnostics sans frappe ni sauvegarde', async () => {
  const ctx = harness({ activeEditor: false });
  ctx.openEditor(ctx.document);
  await wait(30);
  assert.equal(ctx.analyses(), 1);
  assert.ok(ctx.diagnosticCount() >= 3, `attendu au moins 3 findings, reçu ${ctx.diagnosticCount()}`);
  const rules = ctx.published.flatMap((entry) => entry.findings.map((finding) => finding.ruleId)).join(' ');
  for (const expected of ['unsafe-eval', 'dynamic-command-execution', 'unsafe-innerhtml']) {
    assert.ok(rules.includes(expected), `règle ${expected} absente de : ${rules}`);
  }
  assert.equal(ctx.service.getState(), 'issues');
  ctx.service.dispose();
});

test('un éditeur déjà ouvert à l’activation est analysé sans événement supplémentaire', async () => {
  const ctx = harness();
  await wait(30);
  assert.equal(ctx.analyses(), 1);
  assert.ok(ctx.diagnosticCount() > 0);
  ctx.service.dispose();
});

test('ouvrir un fichier propre ne produit aucun diagnostic', async () => {
  const ctx = harness({ document: documentFixture({ text: 'export const total = (a, b) => a + b;\n' }) });
  await wait(30);
  assert.equal(ctx.analyses(), 1);
  assert.equal(ctx.diagnosticCount(), 0);
  assert.equal(ctx.service.getState(), 'clean');
  ctx.service.dispose();
});

test('ouvrir un fichier non supporté n’analyse rien', async () => {
  const ctx = harness({ document: documentFixture({ fsPath: 'C:\\repo\\src\\app.py', languageId: 'python', text: 'eval(user_input)' }) });
  await wait(30);
  assert.equal(ctx.analyses(), 0);
  assert.equal(ctx.published.length, 0);
  ctx.service.dispose();
});

test('un document vide ouvert n’est pas analysé', async () => {
  const ctx = harness({ document: documentFixture({ text: '   \n' }) });
  await wait(30);
  assert.equal(ctx.analyses(), 0);
  ctx.service.dispose();
});

test('Live Security désactivé ne scanne rien à l’ouverture', async () => {
  const ctx = harness({ configuration: { 'live.enabled': false }, activeEditor: false });
  ctx.openEditor(ctx.document);
  await wait(30);
  assert.equal(ctx.analyses(), 0);
  assert.equal(ctx.published.length, 0);
  assert.equal(ctx.service.getState(), 'disabled');
  ctx.service.dispose();
});

test('revenir sur un onglet déjà analysé ne relance pas d’analyse', async () => {
  const ctx = harness();
  await wait(30);
  const other = documentFixture({ fsPath: 'C:\\repo\\src\\other.js', text: 'export const ok = 1;\n' });
  ctx.openEditor(other);
  await wait(30);
  const analysesAfterSwitch = ctx.analyses();
  ctx.openEditor(ctx.document);
  await wait(30);
  assert.equal(ctx.analyses(), analysesAfterSwitch);
  ctx.service.dispose();
});

test('ouverture puis frappe et sauvegarde ne dupliquent pas les diagnostics', async () => {
  const ctx = harness();
  await wait(30);
  assert.equal(ctx.analyses(), 1, 'une seule analyse à l’ouverture');
  const openFindings = ctx.published.at(-1).findings.length;
  ctx.document.version += 1;
  ctx.fireChange(ctx.document);
  await wait(30);
  assert.equal(ctx.analyses(), 2, 'la frappe rejoue une analyse, sans en ajouter une seconde pour l’ouverture');
  ctx.fireSave(ctx.document);
  await wait(30);
  assert.equal(ctx.published.at(-1).findings.length, openFindings, 'les findings ne s’accumulent pas');
  for (const entry of ctx.published) {
    const keys = entry.findings.map((finding) => `${finding.ruleId}:${finding.range.start.line}:${finding.range.start.character}`);
    assert.deepEqual(keys, [...new Set(keys)], 'aucun diagnostic dupliqué dans une publication');
  }
  ctx.service.dispose();
});

test('la frappe immédiatement après l’ouverture ne déclenche qu’une analyse', async () => {
  const ctx = harness();
  ctx.document.version += 1;
  ctx.fireChange(ctx.document);
  await wait(30);
  assert.equal(ctx.analyses(), 1);
  ctx.service.dispose();
});

test('désactiver puis réactiver Live Security réanalyse le fichier ouvert', async () => {
  const ctx = harness();
  await wait(30);
  await ctx.service.disable();
  await ctx.service.enable();
  await wait(30);
  assert.equal(ctx.analyses(), 2);
  ctx.service.dispose();
});
