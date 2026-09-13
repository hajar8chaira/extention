'use strict';

/**
 * Bootstrap automatique du CI Engine sur Jenkins (cas A à E).
 *
 * Le vrai script ci-engine/scenter-engine-bootstrap.sh est exécuté, avec de
 * vrais paquets npm servis par URL file:// et un vrai `npm install`. Seul le
 * répertoire d'outils est temporaire.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const { spawnSync } = require('child_process');

const { validateCiReport } = require('../src/ci-report');
const { CI_ENGINE_STATE, detectCiEngine } = require('../src/ci-engine');

const BOOTSTRAP = path.join(__dirname, '..', '..', 'ci-engine', 'scenter-engine-bootstrap.sh');
const JENKINSFILE = path.join(__dirname, '..', 'templates', 'Jenkinsfile');

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

/** A real npm package shaped like the CI Engine: security-center bin, LF shebang. */
function enginePackage(root, version, { crlf = false } = {}) {
  const base = path.join(root, `build-${version}${crlf ? '-crlf' : ''}`);
  const dir = path.join(base, 'package');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'security-center-vscode', version, bin: { 'security-center': './src/cli.js' }
  }, null, 2));
  const eol = crlf ? '\r\n' : '\n';
  fs.writeFileSync(path.join(dir, 'src', 'cli.js'), [
    '#!/usr/bin/env node',
    "console.log('Security Center headless ' + require('../package.json').version);",
    ''
  ].join(eol));
  const tgz = path.join(root, `security-center-vscode-${version}${crlf ? '-crlf' : ''}.tgz`);
  const packed = spawnSync(BASH, ['-c', `tar -czf "${posix(tgz)}" -C "${posix(base)}" package`], { encoding: 'utf8' });
  assert.equal(packed.status, 0, packed.stderr);
  return { tgz, url: pathToFileURL(tgz).href, sha: crypto.createHash('sha256').update(fs.readFileSync(tgz)).digest('hex'), version };
}

/** npm, wrapped to record every invocation. */
function recordingNpm(root) {
  const log = path.join(root, 'npm-calls.log');
  const wrapper = path.join(root, 'npm-recording');
  const realNpm = posix(path.join(path.dirname(process.execPath), 'npm'));
  fs.writeFileSync(wrapper, `#!/usr/bin/env bash\necho "$*" >> "${posix(log)}"\nexec "${realNpm}" "$@"\n`, { mode: 0o755 });
  return { npm: posix(wrapper), installs: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter((line) => /^install /.test(line)).length : 0) };
}

function runBootstrap(tools, env = {}) {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SCENTER_')));
  const result = spawnSync(BASH, [posix(BOOTSTRAP)], {
    encoding: 'utf8',
    timeout: 180000,
    env: { ...inherited, SCENTER_TOOLS_DIR: posix(tools), SCENTER_NODE_HOME: NODE_HOME, SCENTER_BOOTSTRAP_LOCK_TIMEOUT: '20', ...env }
  });
  const stdout = result.stdout || '';
  const field = (name) => (stdout.match(new RegExp(`^${name}=(.*)$`, 'm')) || [])[1];
  return {
    status: result.status,
    output: `${stdout}${result.stderr || ''}`,
    engineStatus: field('SCENTER_ENGINE_STATUS'),
    action: field('SCENTER_ENGINE_ACTION'),
    version: field('SCENTER_ENGINE_VERSION')
  };
}

const marker = (tools) => JSON.parse(fs.readFileSync(path.join(tools, 'security-center', 'scenter-ci-engine.json'), 'utf8'));
const installedCommand = (tools) => ['bin/security-center', 'security-center']
  .map((relative) => path.join(tools, 'security-center', relative))
  .find((candidate) => fs.existsSync(candidate));

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-engine-bootstrap-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));
const tools = path.join(root, 'jenkins_home', 'tools');
let v1;
let v2;
let recorder;
/** Packages and npm recorder, built once, whichever test runs first. */
function ensureFixtures() {
  if (!v1) {
    v1 = enginePackage(root, '1.0.0');
    v2 = enginePackage(root, '2.0.0');
    recorder = recordingNpm(root);
  }
}

// ------------------------------------------------------------ A / B / C

test('A — moteur absent : provisionné, vérifié, mis en cache, enregistré', { skip: SKIP }, () => {
  ensureFixtures();
  const result = runBootstrap(tools, { SCENTER_ENGINE_TGZ_URL: v1.url, SCENTER_ENGINE_SHA256: v1.sha, SCENTER_NPM: recorder.npm });
  assert.equal(result.status, 0, result.output);
  assert.equal(result.engineStatus, 'READY');
  assert.equal(result.action, 'installed');
  assert.equal(result.version, '1.0.0');
  assert.ok(installedCommand(tools), 'la commande security-center est installée');
  assert.equal(marker(tools).sha256, v1.sha);
  assert.equal(marker(tools).installedBy, 'jenkins-bootstrap');
  assert.ok(fs.existsSync(path.join(tools, 'security-center-packages', `sha256-${v1.sha}.tgz`)), 'paquet mis en cache persistant');
  assert.equal(recorder.installs(), 1);
});

test('B — moteur attendu déjà installé : aucune réinstallation', { skip: SKIP }, () => {
  const result = runBootstrap(tools, { SCENTER_ENGINE_TGZ_URL: v1.url, SCENTER_ENGINE_SHA256: v1.sha, SCENTER_NPM: recorder.npm });
  assert.equal(result.status, 0, result.output);
  assert.equal(result.action, 'unchanged');
  assert.equal(result.version, '1.0.0');
  assert.equal(recorder.installs(), 1, 'npm install n’a pas été relancé');
  // Même sans URL : le build attendu est déjà là, rien à télécharger.
  const offline = runBootstrap(tools, { SCENTER_ENGINE_SHA256: v1.sha, SCENTER_NPM: recorder.npm });
  assert.equal(offline.status, 0, offline.output);
  assert.equal(offline.action, 'unchanged');
});

test('C — autre build attendu : mise à jour automatique, ancien paquet conservé', { skip: SKIP }, () => {
  const result = runBootstrap(tools, { SCENTER_ENGINE_TGZ_URL: v2.url, SCENTER_ENGINE_SHA256: v2.sha, SCENTER_NPM: recorder.npm });
  assert.equal(result.status, 0, result.output);
  assert.equal(result.action, 'updated');
  assert.equal(result.version, '2.0.0');
  assert.equal(marker(tools).sha256, v2.sha);
  assert.equal(marker(tools).previousSha256, v1.sha);
  assert.equal(recorder.installs(), 2);
  assert.ok(fs.existsSync(path.join(tools, 'security-center-packages', `sha256-${v1.sha}.tgz`)), 'ancien paquet gardé pour rollback');
});

// ------------------------------------------------------------ D

test('D — somme SHA-256 différente : ERROR, rien installé, rapport ERROR pour Security Delivery', { skip: SKIP }, () => {
  ensureFixtures();
  const wrongSha = crypto.createHash('sha256').update('not the configured package').digest('hex');
  const failureReport = path.join(root, 'workspace-d', 'security-center-report.json');
  fs.mkdirSync(path.dirname(failureReport), { recursive: true });
  const result = runBootstrap(tools, {
    SCENTER_ENGINE_TGZ_URL: v1.url, SCENTER_ENGINE_SHA256: wrongSha,
    SCENTER_NPM: recorder.npm, SCENTER_BOOTSTRAP_FAILURE_REPORT: posix(failureReport)
  });
  assert.equal(result.status, 2, result.output);
  assert.equal(result.engineStatus, 'ERROR');
  assert.match(result.output, /checksum mismatch/);
  assert.equal(recorder.installs(), 2, 'aucun npm install sur un paquet rejeté');
  assert.equal(marker(tools).sha256, v2.sha, 'le moteur installé n’est pas touché');
  assert.ok(!fs.existsSync(path.join(tools, 'security-center-packages', `sha256-${wrongSha}.tgz`)), 'paquet rejeté jamais mis en cache');

  const validated = validateCiReport(fs.readFileSync(failureReport, 'utf8'));
  assert.equal(validated.ok, true, validated.reason);
  assert.deepEqual(validated.report.verdict, { status: 'ERROR', exitCode: 2 });
  assert.equal(validated.report.execution.status, 'engine_unavailable');
  assert.match(validated.report.execution.error, /checksum mismatch/);
  assert.equal(detectCiEngine({ reportState: 'REPORTED', report: validated.report }).state, CI_ENGINE_STATE.NOT_DETECTED);

  // L'analyse n'est pas lancée : elle exige un bootstrap réussi.
  const jenkinsfile = fs.readFileSync(JENKINSFILE, 'utf8');
  assert.match(jenkinsfile, /env\.SC_ENGINE_READY = status == 0 \? 'true' : 'false'/);
  assert.match(jenkinsfile, /stage\('Security Center Analysis'\) \{\s*when \{\s*expression \{ env\.SC_ENGINE_READY == 'true' \}/);
});

test('D — une URL avec identifiants ou jeton n’est jamais journalisée', { skip: SKIP }, () => {
  ensureFixtures();
  const fresh = path.join(root, 'tools-url');
  const result = runBootstrap(fresh, {
    SCENTER_ENGINE_TGZ_URL: 'http://ci-admin:s3cr3t-password@127.0.0.1:9/engine.tgz?signature=t0k3n-value',
    SCENTER_ENGINE_SHA256: v1.sha
  });
  assert.equal(result.status, 2);
  assert.match(result.output, /download failed from http:\/\/127\.0\.0\.1:9\/engine\.tgz/);
  assert.doesNotMatch(result.output, /s3cr3t-password|t0k3n-value|ci-admin/);
});

// ------------------------------------------------------------ E

test('E — bootstrap impossible : ERROR explicite, jamais de repli silencieux', { skip: SKIP }, () => {
  ensureFixtures();
  const fresh = path.join(root, 'tools-e');
  const noUrl = runBootstrap(fresh, { SCENTER_ENGINE_SHA256: v1.sha });
  assert.equal(noUrl.status, 2, `sans URL :\n${noUrl.output}`);
  assert.match(noUrl.output, /SCENTER_ENGINE_TGZ_URL is not configured/);

  const noSha = runBootstrap(fresh, { SCENTER_ENGINE_TGZ_URL: v1.url });
  assert.equal(noSha.status, 2, `sans SHA-256 :\n${noSha.output}`);
  assert.match(noSha.output, /SCENTER_ENGINE_SHA256 is not configured/);

  const emptyNode = path.join(root, 'no-node');
  fs.mkdirSync(emptyNode, { recursive: true });
  const noNode = runBootstrap(fresh, { SCENTER_ENGINE_TGZ_URL: v1.url, SCENTER_ENGINE_SHA256: v1.sha, SCENTER_NODE_HOME: posix(emptyNode) });
  assert.equal(noNode.status, 2, `sans Node.js :\n${noNode.output}`);
  assert.match(noNode.output, /Node\.js not found/);

  const crlf = enginePackage(root, '3.0.0', { crlf: true });
  const notLinuxSafe = runBootstrap(fresh, { SCENTER_ENGINE_TGZ_URL: crlf.url, SCENTER_ENGINE_SHA256: crlf.sha });
  assert.equal(notLinuxSafe.status, 2, `paquet CRLF :\n${notLinuxSafe.output}`);
  assert.match(notLinuxSafe.output, /not Linux-safe/);
  assert.ok(!installedCommand(fresh), 'aucun moteur installé');

  // Un moteur précédent ne remplace pas le build exigé : l'ancien est présent, le nouveau est introuvable.
  const staleSha = crypto.createHash('sha256').update('build that was never published').digest('hex');
  const stale = runBootstrap(tools, { SCENTER_ENGINE_TGZ_URL: pathToFileURL(path.join(root, 'missing.tgz')).href, SCENTER_ENGINE_SHA256: staleSha });
  assert.equal(stale.status, 2, `le moteur installé n’est pas utilisé à la place du build exigé :\n${stale.output}`);

  // Déploiement ignoré : Policy Gate échoue sur 2, Deploy exige 0.
  const jenkinsfile = fs.readFileSync(JENKINSFILE, 'utf8');
  assert.match(jenkinsfile, /if \(env\.SC_EXIT == '2'\) \{[\s\S]*?error\(/);
  assert.match(jenkinsfile, /stage\('Deploy'\) \{[\s\S]*?when \{[\s\S]*?env\.SC_EXIT == '0'/);
});

// ------------------------------------------------------------ Jenkinsfile

test('le Jenkinsfile embarque exactement le script de bootstrap canonique', { skip: SKIP }, () => {
  const script = fs.readFileSync(BOOTSTRAP, 'utf8');
  const jenkinsfile = fs.readFileSync(JENKINSFILE, 'utf8');
  const opening = "def SCENTER_ENGINE_BOOTSTRAP = '''";
  const start = jenkinsfile.indexOf(opening) + opening.length;
  assert.ok(start > opening.length);
  assert.equal(jenkinsfile.slice(start, jenkinsfile.indexOf("'''", start)), script, 'copie embarquée identique');
  assert.ok(!script.includes('\\'), 'aucun antislash : la chaîne Groovy reste identique au script');
  assert.ok(!script.includes('\r'), 'fins de ligne LF');
  assert.ok(script.startsWith('#!/usr/bin/env bash\n'));
  const syntax = spawnSync(BASH, ['-n', posix(BOOTSTRAP)], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(jenkinsfile, /sh\(returnStatus: true, label: 'Bootstrap Security Center CI Engine', script: SCENTER_ENGINE_BOOTSTRAP\)/);
  const code = script.split('\n').filter((line) => !line.trim().startsWith('#')).join('\n');
  assert.doesNotMatch(code, /npm (pack|publish)|registry\.npmjs/, 'aucune dépendance au registre public');
});
