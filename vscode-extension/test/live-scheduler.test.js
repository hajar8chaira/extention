const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveScheduler, isSupportedDocument } = require('../src/live/liveScheduler');

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function documentFixture(overrides = {}) {
  const uri = { scheme: 'file', fsPath: 'C:\\repo\\src\\app.js', toString: () => 'file:///C:/repo/src/app.js' };
  return { uri, fileName: uri.fsPath, languageId: 'javascript', version: 1, isClosed: false, isUntitled: false, getText: () => 'const ok = true;', ...overrides };
}
function harness({ analyzeDocument = async () => [], debounceMs = 15 } = {}) {
  const document = documentFixture();
  const workspace = { getWorkspaceFolder: (uri) => uri?.fsPath?.startsWith('C:\\repo') ? { uri: { fsPath: 'C:\\repo' } } : undefined };
  const window = { activeTextEditor: { document } };
  const states = [], results = [];
  const scheduler = new LiveScheduler({ workspace, window, analyzeDocument, debounceMs, onState: (state) => states.push(state), onResult: (result) => results.push(result) });
  return { document, workspace, window, states, results, scheduler };
}

test('regroupe la frappe rapide en une seule analyse après debounce', async () => {
  let calls = 0;
  const ctx = harness({ analyzeDocument: async () => { calls += 1; return []; } });
  ctx.scheduler.schedule(ctx.document); ctx.document.version += 1;
  ctx.scheduler.schedule(ctx.document); ctx.document.version += 1;
  ctx.scheduler.schedule(ctx.document);
  await wait(35);
  assert.equal(calls, 1);
  assert.deepEqual(ctx.states.slice(-2), ['analyzing', 'clean']);
  ctx.scheduler.dispose();
});

test('annule une analyse obsolète et ignore son résultat', async () => {
  const resolvers = [];
  const ctx = harness({ analyzeDocument: () => new Promise((resolve) => resolvers.push(resolve)), debounceMs: 1 });
  ctx.scheduler.schedule(ctx.document); await wait(5);
  ctx.document.version += 1; ctx.scheduler.schedule(ctx.document); await wait(5);
  resolvers[0](['obsolete']); resolvers[1]([]); await wait(5);
  assert.deepEqual(ctx.results, [[]]);
  ctx.scheduler.dispose();
});

test('ignore un document qui n’est plus actif', async () => {
  let calls = 0;
  const ctx = harness({ analyzeDocument: async () => { calls += 1; return []; } });
  ctx.scheduler.schedule(ctx.document);
  ctx.window.activeTextEditor = { document: documentFixture({ uri: { scheme: 'file', fsPath: 'C:\\repo\\src\\other.js', toString: () => 'file:///C:/repo/src/other.js' } }) };
  await wait(30);
  assert.equal(calls, 0);
  ctx.scheduler.dispose();
});

test('refuse les langages non supportés et les fichiers hors workspace', () => {
  const ctx = harness();
  assert.equal(ctx.scheduler.schedule(documentFixture({ languageId: 'python' })), false);
  const outside = documentFixture({ uri: { scheme: 'file', fsPath: 'D:\\outside\\app.js', toString: () => 'file:///D:/outside/app.js' } });
  ctx.window.activeTextEditor.document = outside;
  assert.equal(ctx.scheduler.schedule(outside), false);
  ctx.scheduler.dispose();
});

test('ignore dépendances, builds, fichiers générés, minifiés et volumineux', () => {
  const workspace = { getWorkspaceFolder: () => ({}) };
  for (const fileName of ['C:\\repo\\node_modules\\x.js', 'C:\\repo\\dist\\x.js', 'C:\\repo\\src\\x.min.js', 'C:\\repo\\generated\\x.js']) {
    const uri = { scheme: 'file', fsPath: fileName, toString: () => `file:///${fileName}` };
    assert.equal(isSupportedDocument(documentFixture({ fileName, uri }), workspace), false);
  }
  assert.equal(isSupportedDocument(documentFixture({ getText: () => 'x'.repeat(513 * 1024) }), workspace), false);
});

test('dispose annule le travail planifié', async () => {
  let calls = 0;
  const ctx = harness({ analyzeDocument: async () => { calls += 1; return []; }, debounceMs: 20 });
  ctx.scheduler.schedule(ctx.document); ctx.scheduler.dispose(); await wait(30);
  assert.equal(calls, 0);
});

test('mesure chaque analyse sans journaliser le contenu du document', async () => {
  const timings = [];
  const ctx = harness({ analyzeDocument: async () => [] });
  ctx.scheduler.onTiming = (timing) => timings.push(timing);
  ctx.scheduler.schedule(ctx.document, true);
  await wait(15);
  assert.equal(timings.length, 1);
  assert.equal(timings[0].uri, ctx.document.uri.toString());
  assert.equal(typeof timings[0].analysisMs, 'number');
  assert.equal(typeof timings[0].cpuMs, 'number');
  assert.equal('source' in timings[0], false);
  ctx.scheduler.dispose();
});

test('réduit automatiquement les analyses lentes aux sauvegardes', async () => {
  let calls = 0;
  let reductions = 0;
  const ctx = harness({ analyzeDocument: async () => { calls += 1; await wait(4); return []; }, debounceMs: 1 });
  ctx.scheduler.slowAnalysisThresholdMs = -1;
  ctx.scheduler.maxConsecutiveSlowAnalyses = 1;
  ctx.scheduler.onPerformanceReduced = () => { reductions += 1; };
  ctx.scheduler.schedule(ctx.document, true); await wait(30);
  assert.equal(reductions, 1);
  assert.equal(ctx.scheduler.saveOnlyMode, true);
  ctx.document.version += 1;
  assert.equal(ctx.scheduler.schedule(ctx.document, false), false);
  assert.equal(ctx.scheduler.schedule(ctx.document, true), true);
  await wait(10);
  assert.equal(calls, 2);
  ctx.scheduler.dispose();
});
