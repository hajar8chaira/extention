const test = require('node:test');
const assert = require('node:assert/strict');
const { parseGitPaths, normalizeRelative, validateGitBase, incrementalScanPlan, retainUnchangedFindings } = require('../src/incremental');

test('fusionne les fichiers Git modifiés et non suivis sans doublons', () => {
  assert.deepEqual(parseGitPaths('src\\a.js\nsrc/b.js\n', 'src/b.js\nnew.txt\n'), ['new.txt', 'src/a.js', 'src/b.js']);
  assert.equal(normalizeRelative('.\\src\\a.js'), 'src/a.js');
});

test('un scan incrémental conserve les alertes des fichiers non modifiés', () => {
  const findings = [
    { id: 'a', tool: 'Semgrep', file: 'src/a.js' },
    { id: 'b', tool: 'Semgrep', file: 'src/b.js' },
    { id: 'c', tool: 'Gitleaks', file: 'src/a.js' },
    { id: 'd', tool: 'Trivy', file: 'package-lock.json' }
  ];
  const retained = retainUnchangedFindings(findings, ['Semgrep', 'Gitleaks'], ['src/a.js']);
  assert.deepEqual(retained.map((finding) => finding.id), ['b', 'd']);
});

test('planifie les scanners CI selon les fichiers réellement modifiés', () => {
  const sourceOnly = incrementalScanPlan(['src/app.ts', 'README.md'], ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner']);
  assert.deepEqual(sourceOnly.tools, ['Semgrep', 'Gitleaks']);
  assert.deepEqual(sourceOnly.sourceFiles, ['src/app.ts']);
  const dependencies = incrementalScanPlan(['package-lock.json', 'Dockerfile'], []);
  assert.deepEqual(dependencies.tools, ['Gitleaks', 'Trivy', 'OSV-Scanner']);
  assert.equal(dependencies.dependencyChanged, true);
});

test('valide strictement la base Git fournie au CLI', () => {
  assert.equal(validateGitBase('origin/main'), 'origin/main');
  assert.equal(validateGitBase('abc123~1'), 'abc123~1');
  assert.throws(() => validateGitBase('--output=/tmp/file'), /invalide/);
  assert.throws(() => validateGitBase('main;whoami'), /invalide/);
});
