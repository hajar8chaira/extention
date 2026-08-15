const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanArgs, dockerArgs, historyScanArgs, dockerHistoryArgs, globToGitleaksRegex, generatedConfig } = require('../src/gitleaks');

test('produit un rapport JSON redacté sur stdout', () => {
  const args = scanArgs('/workspace');
  assert.ok(args.includes('json'));
  assert.ok(args.includes('-'));
  assert.ok(args.includes('--redact'));
  assert.ok(args.includes('/workspace'));
});

test('traduit les exclusions globales vers une allowlist Gitleaks native', async (t) => {
  assert.match('node_modules/pkg/file.js', new RegExp(globToGitleaksRegex('node_modules/**')));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gitleaks-policy-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const generated = await generatedConfig(root, '', ['dist/**']);
  const content = fs.readFileSync(generated.filePath, 'utf8');
  assert.match(content, /\[allowlist\]/);
  assert.match(content, /dist/);
  await fs.promises.rm(generated.directory, { recursive: true, force: true });
});

test('monte le workspace en lecture seule dans Docker', () => {
  const args = dockerArgs('C:\\repo');
  assert.ok(args.includes('C:\\repo:/src:ro'));
  assert.ok(args.includes('zricethezav/gitleaks:latest'));
});

test('scanne tout l’historique Git ou seulement les nouveaux commits', () => {
  const full = historyScanArgs('/workspace');
  assert.ok(full.includes('--log-opts=--all'));
  const incremental = historyScanArgs('/workspace', 'abc123', '.gitleaks.toml');
  assert.ok(incremental.includes('--log-opts=abc123..HEAD'));
  assert.deepEqual(incremental.slice(-3), ['--config', '.gitleaks.toml', '/workspace']);
});

test('traduit la configuration Gitleaks vers le chemin Docker monté', () => {
  const args = dockerHistoryArgs('C:\\repo', '', 'config/gitleaks.toml');
  assert.ok(args.includes('C:\\repo:/src:ro'));
  assert.ok(args.includes('/src/config/gitleaks.toml'));
});
