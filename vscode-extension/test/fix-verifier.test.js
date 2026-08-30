const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { declaredTestScript, runDeclaredTests } = require('../src/ai/fix-verifier');

test('n’exécute que le script test déclaré par package.json', async (t) => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'security-center-tests-'));
  t.after(() => fs.rmSync(folder, { recursive: true, force: true }));
  fs.writeFileSync(path.join(folder, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  assert.equal(declaredTestScript(folder).label, 'npm test');
  const result = await runDeclaredTests(folder, 1000, (file, args, options, callback) => {
    // Toujours `npm test`, dans le dossier du projet. Sous Windows le lanceur
    // passe par l'interpreteur : `execFile('npm.cmd', …)` leve EINVAL depuis la
    // mitigation CVE-2024-27980.
    if (process.platform === 'win32') {
      assert.match(file, /cmd\.exe$/i);
      assert.deepEqual(args, ['/d', '/s', '/c', 'npm.cmd', 'test']);
    } else {
      assert.equal(file, 'npm');
      assert.deepEqual(args, ['test']);
    }
    assert.equal(options.cwd, folder); callback(null, 'ok', '');
  });
  assert.equal(result.status, 'passed');
  assert.equal(result.command, 'npm test');
});

test('ignore un projet sans véritable script de tests', () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'security-center-tests-'));
  fs.writeFileSync(path.join(folder, 'package.json'), JSON.stringify({ scripts: { test: 'echo Error: no test specified' } }));
  assert.equal(declaredTestScript(folder), null);
  fs.rmSync(folder, { recursive: true, force: true });
});
