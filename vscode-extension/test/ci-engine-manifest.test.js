'use strict';

/**
 * Mise à jour automatique du CI Engine par manifeste (D, E, F, G).
 *
 * Le vrai bootstrap lit un manifeste security-center-latest.json servi par URL
 * file://, comme Jenkins lirait celui publié par le build Security Center.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const { spawnSync } = require('child_process');

const BOOTSTRAP = path.join(__dirname, '..', '..', 'ci-engine', 'scenter-engine-bootstrap.sh');

function bashPath() {
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  if (process.platform === 'win32') return fs.existsSync(gitBash) ? gitBash : null;
  return 'bash';
}
const BASH = bashPath();
const SKIP = !BASH && 'bash indisponible';

function posix(file) {
  if (process.platform !== 'win32') return file;
  return file.replace(/^([A-Za-z]):\\/, (_, drive) => `/${drive.toLowerCase()}/`).replace(/\\/g, '/');
}

const NODE_HOME = posix(path.dirname(process.execPath));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-engine-manifest-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));
const tools = path.join(root, 'jenkins_home', 'tools');
const manifestFile = path.join(root, 'releases', 'scenter-latest', 'security-center-latest.json');
const MANIFEST_URL = pathToFileURL(manifestFile).href;

function enginePackage(version) {
  const base = path.join(root, `build-${version}`);
  const dir = path.join(base, 'package');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'security-center-vscode', version, bin: { 'security-center': './src/cli.js' } }, null, 2));
  fs.writeFileSync(path.join(dir, 'src', 'cli.js'), "#!/usr/bin/env node\nconsole.log('Security Center headless ' + require('../package.json').version);\n");
  const tgz = path.join(root, `security-center-vscode-${version}.tgz`);
  const packed = spawnSync(BASH, ['-c', `tar -czf "${posix(tgz)}" -C "${posix(base)}" package`], { encoding: 'utf8' });
  assert.equal(packed.status, 0, packed.stderr);
  return { version, url: pathToFileURL(tgz).href, sha: crypto.createHash('sha256').update(fs.readFileSync(tgz)).digest('hex') };
}

const commitOf = (label) => crypto.createHash('sha1').update(label).digest('hex');

function publishManifest(pkg, commit, overrides = {}) {
  fs.mkdirSync(path.dirname(manifestFile), { recursive: true });
  const manifest = {
    schemaVersion: 1, name: 'security-center-vscode', version: pkg.version, commit,
    buildTimestamp: new Date().toISOString(),
    tgz: { file: `security-center-vscode-${pkg.version}.tgz`, url: pkg.url, sha256: pkg.sha, size: 1 },
    vsix: { file: `security-center-vscode-${pkg.version}.vsix`, url: 'https://example.invalid/x.vsix', sha256: 'a'.repeat(64), size: 1 },
    ...overrides
  };
  fs.writeFileSync(manifestFile, typeof overrides === 'string' ? overrides : JSON.stringify(manifest, null, 2));
  return manifest;
}

function recordingNpm() {
  const log = path.join(root, 'npm-calls.log');
  const wrapper = path.join(root, 'npm-recording');
  if (!fs.existsSync(wrapper)) {
    const realNpm = posix(path.join(path.dirname(process.execPath), 'npm'));
    fs.writeFileSync(wrapper, `#!/usr/bin/env bash\necho "$*" >> "${posix(log)}"\nexec "${realNpm}" "$@"\n`, { mode: 0o755 });
  }
  return { npm: posix(wrapper), installs: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter((line) => /^install /.test(line)).length : 0) };
}

function runBootstrap(toolsDir, env = {}) {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SCENTER_')));
  const result = spawnSync(BASH, [posix(BOOTSTRAP)], {
    encoding: 'utf8', timeout: 180000,
    env: { ...inherited, SCENTER_TOOLS_DIR: posix(toolsDir), SCENTER_NODE_HOME: NODE_HOME, SCENTER_BOOTSTRAP_LOCK_TIMEOUT: '20', ...env }
  });
  const stdout = result.stdout || '';
  const field = (name) => (stdout.match(new RegExp(`^${name}=(.*)$`, 'm')) || [])[1];
  return { status: result.status, output: `${stdout}${result.stderr || ''}`, action: field('SCENTER_ENGINE_ACTION'), version: field('SCENTER_ENGINE_VERSION'), commit: field('SCENTER_ENGINE_COMMIT'), source: field('SCENTER_ENGINE_SOURCE') };
}

const marker = () => JSON.parse(fs.readFileSync(path.join(tools, 'security-center', 'scenter-ci-engine.json'), 'utf8'));
let v1;
let v2;
let npm;
function fixtures() {
  if (!v1) { v1 = enginePackage('1.0.0'); v2 = enginePackage('2.0.0'); npm = recordingNpm(); }
}

// ------------------------------------------------------------ D

test('D — build du manifeste déjà installé : aucune réinstallation', { skip: SKIP }, () => {
  fixtures();
  publishManifest(v1, commitOf('v1'));
  const first = runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL, SCENTER_NPM: npm.npm });
  assert.equal(first.status, 0, first.output);
  assert.equal(first.action, 'installed');
  assert.equal(first.source, 'manifest');
  assert.equal(first.commit, commitOf('v1'));
  assert.equal(marker().commit, commitOf('v1'));
  assert.equal(marker().resolvedBy, 'manifest');
  assert.equal(npm.installs(), 1);

  const again = runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL, SCENTER_NPM: npm.npm });
  assert.equal(again.status, 0, again.output);
  assert.equal(again.action, 'unchanged');
  assert.equal(again.commit, commitOf('v1'));
  assert.equal(npm.installs(), 1, 'npm install non relancé');
});

// ------------------------------------------------------------ E

test('E — nouveau manifeste publié : mise à jour automatique, même URL Jenkins', { skip: SKIP }, () => {
  fixtures();
  publishManifest(v2, commitOf('v2'));
  // Les anciennes variables directes ne l'emportent jamais sur le manifeste.
  const result = runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL, SCENTER_NPM: npm.npm, SCENTER_ENGINE_TGZ_URL: v1.url, SCENTER_ENGINE_SHA256: v1.sha });
  assert.equal(result.status, 0, result.output);
  assert.equal(result.action, 'updated');
  assert.equal(result.version, '2.0.0');
  assert.equal(result.commit, commitOf('v2'));
  assert.match(result.output, /direct SCENTER_ENGINE_TGZ_URL and SCENTER_ENGINE_SHA256 values are ignored/);
  assert.equal(marker().sha256, v2.sha);
  assert.equal(marker().previousSha256, v1.sha);
  assert.equal(npm.installs(), 2);
});

// ------------------------------------------------------------ F

test('F — SHA-256 du manifeste différent du TGZ : ERROR, moteur inchangé', { skip: SKIP }, () => {
  fixtures();
  publishManifest(v1, commitOf('tampered'), { tgz: { file: 'x.tgz', url: v1.url, sha256: crypto.createHash('sha256').update('other').digest('hex'), size: 1 } });
  const failureReport = path.join(root, 'report-f.json');
  const result = runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL, SCENTER_NPM: npm.npm, SCENTER_BOOTSTRAP_FAILURE_REPORT: posix(failureReport) });
  assert.equal(result.status, 2, result.output);
  assert.match(result.output, /checksum mismatch/);
  assert.equal(marker().sha256, v2.sha, 'le moteur installé n’est pas remplacé');
  assert.equal(npm.installs(), 2);
  assert.equal(JSON.parse(fs.readFileSync(failureReport, 'utf8')).verdict.status, 'ERROR');

  // Version annoncée différente de celle du paquet : refusé aussi.
  publishManifest(v1, commitOf('wrong-version'), { version: '9.9.9' });
  const wrongVersion = runBootstrap(path.join(root, 'tools-version'), { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL });
  assert.equal(wrongVersion.status, 2, wrongVersion.output);
  assert.match(wrongVersion.output, /manifest names version 9\.9\.9 but the package is version 1\.0\.0/);
});

// ------------------------------------------------------------ G

test('G — manifeste malformé, incomplet ou injoignable : ERROR, aucune installation', { skip: SKIP }, () => {
  fixtures();
  const fresh = path.join(root, 'tools-g');
  const cases = [
    ['JSON invalide', '{ not json', /invalid CI Engine manifest.*not valid JSON/],
    ['commit absent', JSON.stringify({ schemaVersion: 1, name: 'security-center-vscode', version: '1.0.0', buildTimestamp: new Date().toISOString(), tgz: { url: v1.url, sha256: v1.sha } }), /commit must be a 40-hex git SHA/],
    ['SHA-256 absent', JSON.stringify({ schemaVersion: 1, name: 'security-center-vscode', version: '1.0.0', commit: commitOf('x'), buildTimestamp: new Date().toISOString(), tgz: { url: v1.url } }), /tgz\.sha256 must be a 64-hex SHA-256/],
    ['autre paquet', JSON.stringify({ schemaVersion: 1, name: 'left-pad', version: '1.0.0', commit: commitOf('x'), buildTimestamp: new Date().toISOString(), tgz: { url: v1.url, sha256: v1.sha } }), /name must be security-center-vscode/],
    ['URL non http/file', JSON.stringify({ schemaVersion: 1, name: 'security-center-vscode', version: '1.0.0', commit: commitOf('x'), buildTimestamp: new Date().toISOString(), tgz: { url: 'javascript:alert(1)', sha256: v1.sha } }), /tgz\.url must be an http\(s\) or file URL/]
  ];
  for (const [label, content, expected] of cases) {
    fs.writeFileSync(manifestFile, content);
    const result = runBootstrap(fresh, { SCENTER_ENGINE_MANIFEST_URL: MANIFEST_URL });
    assert.equal(result.status, 2, `${label} :\n${result.output}`);
    assert.match(result.output, expected, label);
  }
  const unreachable = runBootstrap(fresh, {
    SCENTER_ENGINE_MANIFEST_URL: 'https://build-reader:s3cr3t@127.0.0.1:9/releases/security-center-latest.json?token=abc123',
    SCENTER_ENGINE_DOWNLOAD_TOKEN: 'ghp_dont_log_me_42'
  });
  assert.equal(unreachable.status, 2);
  assert.match(unreachable.output, /CI Engine manifest unreachable: https:\/\/127\.0\.0\.1:9\/releases\/security-center-latest\.json/);
  assert.doesNotMatch(unreachable.output, /s3cr3t|abc123|ghp_dont_log_me_42|build-reader/, 'aucun secret journalisé');
  assert.equal(fs.existsSync(path.join(fresh, 'security-center', 'scenter-ci-engine.json')), false, 'aucun moteur installé');
});
