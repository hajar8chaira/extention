const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveSecurityService } = require('../src/live/liveSecurityService');

function fakeWorkspace(initial = {}) {
  const values = { 'live.enabled': false, 'live.debounceMs': 450, 'live.scanOnChange': true, 'live.scanOnSave': true, ...initial };
  const configurationListeners = new Set();
  const changeListeners = new Set();
  const saveListeners = new Set();
  let disposed = 0;
  const subscribe = (set, listener) => {
    set.add(listener);
    return { dispose: () => { if (set.delete(listener)) disposed += 1; } };
  };
  return {
    getConfiguration: () => ({
      get: (key, fallback) => values[key] ?? fallback,
      update: async (key, value) => {
        values[key] = value;
        for (const listener of configurationListeners) listener({ affectsConfiguration: (name) => name.startsWith('securityCenter.live') });
      }
    }),
    onDidChangeConfiguration: (listener) => subscribe(configurationListeners, listener),
    onDidChangeTextDocument: (listener) => subscribe(changeListeners, listener),
    onDidSaveTextDocument: (listener) => subscribe(saveListeners, listener),
    counts: () => ({ configuration: configurationListeners.size, change: changeListeners.size, save: saveListeners.size, disposed }),
    values
  };
}

test('Live Security est désactivé par défaut sans écouteurs de documents', () => {
  const workspace = fakeWorkspace();
  const service = new LiveSecurityService({ workspace });
  assert.equal(service.getState(), 'disabled');
  assert.deepEqual(workspace.counts(), { configuration: 1, change: 0, save: 0, disposed: 0 });
  service.dispose();
});

test('active Live Security et installe uniquement ses écouteurs de cycle de vie', async () => {
  const workspace = fakeWorkspace();
  const service = new LiveSecurityService({ workspace });
  assert.equal(await service.enable(), 'idle');
  assert.equal(workspace.values['live.enabled'], true);
  assert.deepEqual(workspace.counts(), { configuration: 1, change: 1, save: 1, disposed: 0 });
  service.dispose();
});

test('désactive Live Security et nettoie immédiatement les écouteurs', async () => {
  const workspace = fakeWorkspace({ 'live.enabled': true });
  const service = new LiveSecurityService({ workspace });
  assert.equal(await service.disable(), 'disabled');
  assert.deepEqual(workspace.counts(), { configuration: 1, change: 0, save: 0, disposed: 2 });
  service.dispose();
});

test('toggle conserve la préférence après rechargement du workspace', async () => {
  const workspace = fakeWorkspace();
  const first = new LiveSecurityService({ workspace });
  assert.equal(await first.toggle(), 'idle');
  first.dispose();
  const reloaded = new LiveSecurityService({ workspace });
  assert.equal(reloaded.getState(), 'idle');
  assert.equal(await reloaded.toggle(), 'disabled');
  reloaded.dispose();
});

test('respecte les options des écouteurs sans lancer de travail de fond', () => {
  const workspace = fakeWorkspace({ 'live.enabled': true, 'live.scanOnChange': false, 'live.scanOnSave': true });
  const service = new LiveSecurityService({ workspace });
  assert.deepEqual(workspace.counts(), { configuration: 1, change: 0, save: 1, disposed: 0 });
  service.dispose();
});

test('la désactivation de l’extension nettoie tous les écouteurs', () => {
  const workspace = fakeWorkspace({ 'live.enabled': true });
  const service = new LiveSecurityService({ workspace });
  service.dispose();
  assert.equal(service.getState(), 'disabled');
  assert.deepEqual(workspace.counts(), { configuration: 0, change: 0, save: 0, disposed: 3 });
  service.dispose();
});

test('désactiver Live Security efface immédiatement ses diagnostics', async () => {
  const workspace = fakeWorkspace({ 'live.enabled': true });
  let clears = 0;
  const service = new LiveSecurityService({ workspace, diagnostics: { clear: () => { clears += 1; }, publish: () => {} } });
  await service.disable();
  assert.ok(clears >= 1);
  service.dispose();
});
