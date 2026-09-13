'use strict';

/**
 * Node.js pendant `security-center scan` sur le runtime CI.
 *
 * Régression Jenkins réelle : le bootstrap trouvait le Node.js géré par
 * SCENTER_NODE_HOME, mais l'analyse échouait sur « /usr/bin/env: 'node': No such
 * file or directory » — `security-center` démarre par #!/usr/bin/env node et le
 * PATH de l'analyse ne contenait que le moteur.
 *
 * Le script de résolution est extrait du Jenkinsfile et exécuté, puis un vrai
 * exécutable #!/usr/bin/env node est lancé avec le PATH que Jenkins construit
 * pour withEnv(["PATH+SCENTER_ENGINE=…", "PATH+SCENTER_NODE=…"]).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const JENKINSFILE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
const PREPARE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Prepare CI Runtime workspace')"), JENKINSFILE.indexOf("stage('Bootstrap Security Center CI Engine')"));
const ANALYSIS = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Security Center Analysis')"), JENKINSFILE.indexOf("stage('Policy Gate')"));
const RESOLVE = /env\.SC_NODE_BIN = sh\(returnStdout: true, label: 'Resolve Node\.js for Security Center', script: '''([\s\S]*?)'''\)\.trim\(\)/.exec(PREPARE)?.[1];

/**
 * An absolute bash path. The scripts below run with a deliberately minimal PATH,
 * and spawnSync looks a bare command name up in the *child's* PATH on Linux: a
 * bare "bash" would not even start there.
 */
function bashPath() {
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  if (process.platform === 'win32') return fs.existsSync(gitBash) ? gitBash : null;
  const found = spawnSync('bash', ['-c', 'command -v bash'], { encoding: 'utf8' });
  const located = found.status === 0 ? found.stdout.trim() : '';
  return path.isAbsolute(located) ? located : null;
}
const BASH = bashPath();
const SKIP = !BASH && 'bash indisponible';

function posix(file) {
  if (process.platform !== 'win32') return file;
  return file.replace(/^([A-Za-z]):\\/, (_, drive) => `/${drive.toLowerCase()}/`).replace(/\\/g, '/');
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-runtime-node-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));

function executable(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode: 0o755 });
}

/** A managed Node.js home, like <remoteRoot>/tools/node22 on the runtime host. */
function managedNodeHome(name) {
  const home = path.join(root, name, 'tools', 'node22');
  executable(path.join(home, 'bin', 'node'), '#!/bin/sh\nif [ "$1" = "--version" ]; then echo v22.23.1; exit 0; fi\necho "managed-node ran $*"\n');
  return home;
}

/** Runs a script in Git Bash / bash with exactly the given environment (PATH included). */
function runBash(script, env) {
  const result = spawnSync(BASH, ['-c', script], { encoding: 'utf8', env: { SYSTEMROOT: process.env.SYSTEMROOT || '', ...env } });
  // A harness that could not start bash must fail as such, never as "undefined" output.
  if (result.error) throw new Error(`bash could not start (${BASH}): ${result.error.message}`);
  return result;
}

/** Jenkins withEnv PATH+XYZ: each entry is prepended to the inherited PATH. */
const jenkinsPath = (entries, inherited) => [...entries, inherited].filter(Boolean).join(':');

test('the analysis stage puts the resolved Node.js bin on PATH together with the engine bin', () => {
  assert.ok(RESOLVE, 'Node.js resolution present in Prepare CI Runtime workspace');
  assert.match(ANALYSIS, /withEnv\(\["PATH\+SCENTER_ENGINE=\$\{env\.SC_ENGINE_BIN\}", "PATH\+SCENTER_NODE=\$\{env\.SC_NODE_BIN\}"\]\) \{[\s\S]*?security-center scan/,
    'security-center scan runs inside the withEnv that adds both bins');
  assert.ok(PREPARE.indexOf('env.SC_ENGINE_BIN = ') < PREPARE.indexOf('env.SC_NODE_BIN = '), 'resolved on the runtime agent, before bootstrap and analysis');
});

test('managed Node.js is on PATH during security-center scan, and the #!/usr/bin/env node shebang resolves it', { skip: SKIP }, () => {
  const home = managedNodeHome('managed');
  const resolved = runBash(RESOLVE, { SCENTER_NODE_HOME: posix(home), PATH: '/usr/bin:/bin' });
  assert.equal(resolved.status, 0, resolved.stderr);
  assert.equal(resolved.stdout.trim(), `${posix(home)}/bin`, 'SC_NODE_BIN is the managed Node.js bin directory');

  const engineBin = path.join(root, 'engine', 'bin');
  executable(path.join(engineBin, 'security-center'), '#!/usr/bin/env node\nconsole.log("never read by the fake node");\n');
  const scan = `security-center scan --workspace . --format json`;

  // Before the fix: only the engine bin was added, the shebang cannot find node.
  const broken = runBash(scan, { PATH: jenkinsPath([posix(engineBin)], '') });
  assert.notEqual(broken.status, 0);
  assert.match(`${broken.stderr}${broken.stdout}`, /node.*No such file or directory|env: .?node.?: No such file/i, 'reproduces the real Jenkins failure');

  // After the fix: PATH+SCENTER_ENGINE and PATH+SCENTER_NODE, as withEnv builds them.
  const fixed = runBash(scan, { PATH: jenkinsPath([posix(engineBin), resolved.stdout.trim()], '') });
  assert.equal(fixed.status, 0, `${fixed.stderr}${fixed.stdout}`);
  assert.match(fixed.stdout, /^managed-node ran .*security-center scan --workspace \. --format json$/m, 'the shebang ran the managed Node.js');
});

test('fallbacks: bootstrap default home, then system Node.js; clear failure when Node.js is unavailable', { skip: SKIP }, () => {
  const tools = path.join(root, 'default-tools');
  const defaultHome = path.join(tools, 'node22');
  executable(path.join(defaultHome, 'bin', 'node'), '#!/bin/sh\necho v22.23.1\n');
  const byDefault = runBash(RESOLVE, { SCENTER_TOOLS_DIR: posix(tools), PATH: '/usr/bin:/bin' });
  assert.equal(byDefault.status, 0, byDefault.stderr);
  assert.equal(byDefault.stdout.trim(), `${posix(defaultHome)}/bin`);

  const systemBin = path.join(root, 'system', 'bin');
  executable(path.join(systemBin, 'node'), '#!/bin/sh\necho v20.18.0\n');
  const system = runBash(RESOLVE, { SCENTER_TOOLS_DIR: posix(path.join(root, 'empty-tools')), PATH: `${posix(systemBin)}:/usr/bin:/bin` });
  assert.equal(system.status, 0, system.stderr);
  assert.equal(system.stdout.trim(), posix(systemBin), 'system Node.js when no managed one exists');

  const configuredButEmpty = runBash(RESOLVE, { SCENTER_NODE_HOME: posix(path.join(root, 'missing-home')), PATH: `${posix(systemBin)}:/usr/bin:/bin` });
  assert.equal(configuredButEmpty.stdout.trim(), posix(systemBin), 'a configured home without node still falls back to system Node.js');

  const none = runBash(RESOLVE, { SCENTER_NODE_HOME: posix(path.join(root, 'missing-home')), SCENTER_TOOLS_DIR: posix(path.join(root, 'empty-tools')), PATH: '/usr/bin:/bin' });
  if (spawnSync(BASH, ['-c', 'command -v node'], { env: { PATH: '/usr/bin:/bin' } }).status === 0) return;
  assert.equal(none.status, 1);
  assert.equal(none.stdout.trim(), '', 'no PATH entry is produced');
  assert.match(none.stderr, /Security Center : Node\.js introuvable sur ce runtime CI \(SCENTER_NODE_HOME=.*missing-home\)\. Relancez Configure CI Runtime\./);
});

test('no host-specific path is hardcoded', () => {
  assert.doesNotMatch(JENKINSFILE, /\/home\/deploy|192\.168\.|\/home\/[a-z_][a-z0-9_-]*\/scenter-agent/i);
  assert.doesNotMatch(RESOLVE, /\/home\//);
  assert.match(RESOLVE, /\$SCENTER_NODE_HOME\/bin\/node/, 'the managed Node.js configured on the runtime node');
});
