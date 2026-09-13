'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { ScannerToolManager, INSTALL_ERROR } = require('../src/scanner-tool-manager');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

async function sandbox(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'semgrep-cancel-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }).catch(() => {}));
  return new ScannerToolManager(dir);
}

test('Semgrep : un signal déjà annulé n’ouvre aucun processus d’installation', async (t) => {
  const manager = await sandbox(t);
  let probes = 0;
  manager.findOnPath = async () => { probes += 1; return 'python'; };
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => manager.installSemgrep(() => {}, { signal: controller.signal }),
    (error) => error.cancelled === true && error.code === INSTALL_ERROR.CANCELLED
  );
  assert.equal(probes, 0, 'aucun interpréteur n’est même recherché');
});

test('Semgrep : un processus tué par l’annulation est rapporté comme annulation, pas comme échec', async (t) => {
  const manager = await sandbox(t);
  const controller = new AbortController();
  controller.abort();
  // Ce que renvoie réellement `execFile` quand son signal est déclenché.
  const abortError = Object.assign(new Error('The operation was aborted'), { name: 'AbortError', code: 'ABORT_ERR' });
  await assert.rejects(
    () => manager.cancellableStep(() => Promise.reject(abortError), controller.signal),
    (error) => error.cancelled === true && error.code === INSTALL_ERROR.CANCELLED
  );
  // Une vraie panne d'installation garde son identité : elle ne devient jamais
  // une « annulation » silencieuse.
  const failure = Object.assign(new Error('pip a échoué'), { code: 1 });
  await assert.rejects(
    () => manager.cancellableStep(() => Promise.reject(failure), new AbortController().signal),
    (error) => error === failure
  );
  assert.deepEqual(await manager.cancellableStep(() => Promise.resolve('ok'), new AbortController().signal), 'ok');
});

test('Semgrep : le signal atteint réellement les deux processus enfants', () => {
  const source = src('scanner-tool-manager.js');
  const installer = source.match(/async installSemgrep\([\s\S]*?\n  \}/)[0];
  const spawns = installer.match(/execFileAsync\([^;]*?\)/gs) || [];
  assert.equal(spawns.length, 2, 'venv puis pip');
  for (const spawn of spawns) {
    assert.match(spawn, /signal/, `un processus d’installation ignore encore l’annulation : ${spawn.slice(0, 60)}`);
  }
  // L'annulation est vérifiée avant de commencer et avant de déclarer l'outil prêt.
  assert.match(installer, /throwIfAborted\(signal\);[\s\S]*?await this\.activateManagedPath\(\)/);
});
