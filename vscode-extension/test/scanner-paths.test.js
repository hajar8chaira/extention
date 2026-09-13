'use strict';

/**
 * Chemins rapportés par les scanners, indépendants du système hôte.
 *
 * Régression GitHub Actions (Linux) : un workspace Windows `C:\repo` était
 * résolu relativement au répertoire courant Linux. Les cas sont exécutés avec
 * un hôte POSIX simulé, donc aussi sur un poste Windows.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  isWindowsAbsolutePath, isPosixAbsolutePath, isAbsoluteScannerPath, resolveScannerPath
} = require('../src/scanner-paths');

const POSIX = { platform: 'linux' };
const WINDOWS = { platform: 'win32' };

test('1. chemin Windows absolu sur un hôte POSIX : jamais préfixé par le cwd', () => {
  const resolved = resolveScannerPath('C:\\repo', 'package-lock.json', POSIX);
  assert.equal(resolved, 'C:\\repo\\package-lock.json');
  assert.ok(!resolved.includes(process.cwd()), 'aucun répertoire courant hôte');
  assert.equal(resolveScannerPath('C:\\workspace', 'frontend/src/app/auth.spec.ts', POSIX), 'C:\\workspace\\frontend\\src\\app\\auth.spec.ts');
  // Une cible déjà absolue Windows est conservée, pas jointe au workspace.
  assert.equal(resolveScannerPath('/home/runner/work/repo', 'D:\\other\\file.js', POSIX), 'D:\\other\\file.js');
});

test('2. lecteur Windows avec barres obliques', () => {
  assert.equal(isWindowsAbsolutePath('C:/workspace'), true);
  assert.equal(resolveScannerPath('C:/workspace', 'frontend/src/app.ts', POSIX), 'C:\\workspace\\frontend\\src\\app.ts');
  assert.equal(isWindowsAbsolutePath('C:foo'), false, 'un chemin relatif au lecteur n’est pas absolu');
});

test('3. chemin UNC', () => {
  assert.equal(isWindowsAbsolutePath('\\\\server\\share\\repo'), true);
  assert.equal(resolveScannerPath('\\\\server\\share\\repo', 'src/a.js', POSIX), '\\\\server\\share\\repo\\src\\a.js');
  assert.equal(isWindowsAbsolutePath('//server/share'), false, 'un chemin POSIX // reste POSIX');
});

test('4. chemin POSIX absolu : sémantique POSIX inchangée', () => {
  assert.equal(isPosixAbsolutePath('/home/foo/bar'), true);
  assert.equal(resolveScannerPath('/home/runner/work/repo', 'src/a.js', POSIX), '/home/runner/work/repo/src/a.js');
  assert.equal(resolveScannerPath('/repo', '/etc/other.js', POSIX), '/etc/other.js');
  assert.equal(resolveScannerPath('/repo', 'src/a.js', POSIX), path.posix.resolve('/repo', 'src/a.js'));
});

test('5. chemin relatif : non considéré absolu, résolu normalement', () => {
  for (const relative of ['src/a.js', 'frontend\\src\\app.ts', './package.json', '']) {
    assert.equal(isAbsoluteScannerPath(relative), false, relative);
  }
  assert.equal(resolveScannerPath('C:\\repo', './package.json', POSIX), 'C:\\repo\\package.json');
  assert.equal(resolveScannerPath('/repo', 'lib/../src/a.js', POSIX), '/repo/src/a.js');
});

test('hôte Windows : résolution native strictement inchangée', () => {
  for (const [base, target] of [['C:\\repo', 'package-lock.json'], ['C:/workspace', 'a/b.ts'], ['\\\\server\\share\\x', 'y.js']]) {
    assert.equal(resolveScannerPath(base, target, WINDOWS), path.win32.resolve(base, target));
  }
  // Sur l'hôte courant, le comportement par défaut reste celui de path.resolve pour les chemins natifs.
  const nativeBase = process.platform === 'win32' ? 'C:\\repo' : '/repo';
  assert.equal(resolveScannerPath(nativeBase, 'src/a.js'), path.resolve(nativeBase, 'src/a.js'));
});
