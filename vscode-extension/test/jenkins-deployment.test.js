'use strict';

/**
 * Deploy et Health Check du Jenkinsfile, profil « Docker on remote SSH host ».
 *
 * Les scripts sont extraits du Jenkinsfile et exécutés avec bash. `ssh` est un
 * double qui enregistre ses arguments et exécute la commande distante localement,
 * avec un `docker` double : le vrai script choisit ce qu'il envoie, le double ne
 * décide de rien. Le health check interroge un vrai serveur HTTP local.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const { JOB_PARAMETERS, normalizeDeploymentConfig, jobParameterValues, checkScript } = require('../src/deployment');
const { describeHostKey } = require('../src/ssh-host-key');

const JENKINSFILE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8').replace(/\r\n/g, '\n');
const DEPLOY_SCRIPT = /def SCENTER_DOCKER_SSH_DEPLOY = '''([\s\S]*?)'''/.exec(JENKINSFILE)?.[1];
const HEALTH_SCRIPT = /label: 'Health Check', script: '([^']+)'/.exec(JENKINSFILE)?.[1];
const POLICY_GATE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Policy Gate')"), JENKINSFILE.indexOf("stage('Supply chain evidence')"));
const DEPLOY_STAGE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Deploy')"), JENKINSFILE.indexOf("stage('Health Check')"));
const HEALTH_STAGE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Health Check')"), JENKINSFILE.indexOf('  post {\n    always {'));

function bashPath() {
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  if (process.platform === 'win32') return fs.existsSync(gitBash) ? gitBash : null;
  const found = spawnSync('bash', ['-c', 'command -v bash'], { encoding: 'utf8' });
  const located = found.status === 0 ? found.stdout.trim() : '';
  return path.isAbsolute(located) ? located : null;
}
const BASH = bashPath();
const posix = (file) => (process.platform === 'win32' ? file.replace(/^([A-Za-z]):\\/, (_, drive) => `/${drive.toLowerCase()}/`).replace(/\\/g, '/') : file);
const SYSTEM_PATH = process.platform === 'win32' ? '/usr/bin:/bin:/mingw64/bin' : '/usr/bin:/bin';
const tool = (name) => BASH && spawnSync(BASH, ['-c', `command -v ${name}`], { encoding: 'utf8', env: { PATH: SYSTEM_PATH, SYSTEMROOT: process.env.SYSTEMROOT || '' } }).status === 0;
const SKIP = (!BASH && 'bash indisponible') || (!tool('git') && 'git indisponible');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-deploy-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));

const SECRET = 'SCENTER-TEST-PRIVATE-KEY-MATERIAL-7f3a';
const sshString = (value) => { const data = Buffer.from(value); const length = Buffer.alloc(4); length.writeUInt32BE(data.length); return Buffer.concat([length, data]); };
const HOST_KEY = describeHostKey(Buffer.concat([sshString('ssh-ed25519'), sshString(Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url'))]));
const WHOAMI = normalizeDeploymentConfig({
  host: '192.168.222.132', sshUser: 'deploy', credentialId: 'vm-deploy-key', containerName: 'scenter-whoami',
  containerPort: '80', publishedPort: '8088', healthCheckUrl: 'http://192.168.222.132:8088/'
}).config;

function executable(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode: 0o755 });
}

/** Local and remote doubles: ssh runs the remote command here, with a docker double on the remote PATH. */
function doubles(name) {
  const dir = path.join(root, name);
  const local = path.join(dir, 'local-bin');
  const remote = path.join(dir, 'remote-bin');
  executable(path.join(local, 'ssh'), `#!/bin/sh
printf 'ssh' >> "$FAKE_LOG"; for arg in "$@"; do printf ' [%s]' "$arg" >> "$FAKE_LOG"; done; echo >> "$FAKE_LOG"
for arg in "$@"; do case "$arg" in UserKnownHostsFile=*) cp "\${arg#UserKnownHostsFile=}" "$FAKE_DIR/known_hosts.seen" ;; esac; done
case "$FAKE_SSH" in
  hostkey) echo "Host key verification failed." >&2; exit 255 ;;
  auth) echo "deploy@192.168.222.132: Permission denied (publickey)." >&2; exit 255 ;;
esac
for arg in "$@"; do command="$arg"; done
PATH="$FAKE_REMOTE_PATH" exec sh -c "$command"
`);
  executable(path.join(remote, 'docker'), `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
  info)
    case "$FAKE_DOCKER" in
      permission) echo "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" >&2; exit 1 ;;
      down) echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1 ;;
    esac
    echo 27.3.1 ;;
  build) cat > "$FAKE_DIR/context.tar"; echo "Successfully built" ;;
  container) [ -n "$FAKE_EXISTING" ] ;;
  ps)
    case "$*" in
      *publish=*) [ -n "$FAKE_PORT_OWNER" ] && echo "$FAKE_PORT_OWNER" ;;
      *label=security-center.managed=true*) [ "$FAKE_EXISTING" = managed ] && echo scenter-whoami ;;
    esac
    exit 0 ;;
  rm) exit 0 ;;
  run) echo 4f1d2c3b4a59 ;;
esac
`);
  fs.writeFileSync(path.join(dir, 'log'), '');
  return { dir, local, remote, log: path.join(dir, 'log') };
}

/** An application repository with one commit, like the Jenkins workspace after Checkout. */
function repository(name, { dockerfile = true } = {}) {
  const dir = path.join(root, name, 'workspace');
  fs.mkdirSync(dir, { recursive: true });
  const git = (...args) => spawnSync(BASH, ['-c', `git ${args.map((arg) => `'${arg}'`).join(' ')}`], { cwd: dir, encoding: 'utf8', env: { PATH: SYSTEM_PATH, SYSTEMROOT: process.env.SYSTEMROOT || '', HOME: posix(root) } });
  git('init', '-q');
  if (dockerfile) fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM scratch\nEXPOSE 80\n');
  fs.writeFileSync(path.join(dir, 'app.go'), 'package main\n');
  git('add', '.');
  git('-c', 'user.email=ci@example.invalid', '-c', 'user.name=CI', 'commit', '-q', '-m', 'app');
  return { dir, commit: git('rev-parse', 'HEAD').stdout.trim() };
}

/** Runs the Jenkinsfile deploy script with the job parameters Security Center writes. */
function deploy(name, { fake = {}, parameters = {}, dockerfile = true } = {}) {
  const tools = doubles(name);
  const repo = repository(name, { dockerfile });
  const keyFile = path.join(tools.dir, 'ssh-key');
  fs.writeFileSync(keyFile, `-----BEGIN OPENSSH PRIVATE KEY-----\n${SECRET}\n-----END OPENSSH PRIVATE KEY-----\n`);
  const env = {
    SYSTEMROOT: process.env.SYSTEMROOT || '', HOME: posix(root),
    PATH: `${posix(tools.local)}:${SYSTEM_PATH}`,
    ...jobParameterValues(WHOAMI, HOST_KEY), ...parameters,
    SC_SOURCE_COMMIT: repo.commit,
    SCENTER_DEPLOY_KEY: posix(keyFile),
    FAKE_LOG: posix(tools.log), FAKE_DIR: posix(tools.dir),
    FAKE_REMOTE_PATH: `${fake.docker === 'missing' ? '' : `${posix(tools.remote)}:`}${SYSTEM_PATH}`,
    FAKE_SSH: fake.ssh || '', FAKE_DOCKER: fake.docker || '', FAKE_EXISTING: fake.existing || '', FAKE_PORT_OWNER: fake.portOwner || ''
  };
  const result = spawnSync(BASH, ['-c', DEPLOY_SCRIPT], { cwd: repo.dir, encoding: 'utf8', env });
  if (result.error) throw new Error(`bash could not start (${BASH}): ${result.error.message}`);
  const reasonFile = path.join(repo.dir, '.scenter-deploy-reason');
  return {
    ...result, repo, tools,
    log: fs.readFileSync(tools.log, 'utf8'),
    reason: fs.existsSync(reasonFile) ? fs.readFileSync(reasonFile, 'utf8') : null,
    knownHosts: fs.existsSync(path.join(tools.dir, 'known_hosts.seen')) ? fs.readFileSync(path.join(tools.dir, 'known_hosts.seen'), 'utf8') : ''
  };
}

// ------------------------------------------------------------ PASS / BLOCK

test('BLOCK -> no deployment: the gate stops the build, and only a PASS reaches the managed deploy', () => {
  assert.ok(DEPLOY_SCRIPT && HEALTH_SCRIPT, 'scripts present in the Jenkinsfile');
  assert.match(POLICY_GATE, /if \(env\.SC_EXIT == '1'\) \{\s*env\.SC_DEPLOY_REASON = 'Policy Gate BLOCK : livraison refusée par security-center\.yml\.'\s*error\(/);
  assert.match(DEPLOY_STAGE, /when \{\s*allOf \{\s*expression \{ env\.SC_EXIT == '0' \}\s*expression \{ currentBuild\.currentResult == 'SUCCESS' \}/);
  // The script and the SSH credential are used in the Deploy stage and nowhere else.
  assert.equal(JENKINSFILE.split('SCENTER_DOCKER_SSH_DEPLOY').length - 1, 2, 'defined once, used once');
  assert.ok(DEPLOY_STAGE.includes('script: SCENTER_DOCKER_SSH_DEPLOY'));
  assert.equal((JENKINSFILE.match(/sshUserPrivateKey\(/g) || []).length, 1);
  assert.ok(DEPLOY_STAGE.indexOf('when {') < DEPLOY_STAGE.indexOf('sshUserPrivateKey('), 'the credential is bound only after the PASS guard');
  assert.match(JENKINSFILE, /env\.SC_DEPLOY_STATUS = 'SKIPPED'\s*env\.SC_DEPLOY_REASON = 'Analyse Security Center non terminée\.'/, 'a blocked build reports SKIPPED');
  assert.match(DEPLOY_STAGE, /PASS, mais aucun déploiement n’est configuré : Security Delivery → Jenkins → Deployment\./, 'no Jenkins variable to invent');
});

test('PASS -> deployment configuration used: the job parameters are exactly what Deploy and Health Check read', { skip: SKIP }, () => {
  const read = new Set([...(DEPLOY_STAGE + DEPLOY_SCRIPT + HEALTH_STAGE).matchAll(/SCENTER_(?:DEPLOY_[A-Z_]+|HEALTHCHECK_URL)/g)].map((match) => match[0]));
  read.delete('SCENTER_DEPLOY_KEY');
  read.delete('SCENTER_DEPLOY_COMMAND');
  assert.deepEqual([...read].sort(), JOB_PARAMETERS.map(([name]) => name).sort(), 'every managed parameter is used, and nothing else is expected');

  const result = deploy('pass');
  assert.equal(result.status, 0, `${result.stderr}\n${result.log}`);
  assert.equal(result.reason, null);
  const image = `scenter/scenter-whoami:${result.repo.commit.slice(0, 12)}`;
  const ssh = result.log.split('\n').filter((line) => line.startsWith('ssh '));
  assert.equal(ssh.length, 3, 'docker check, image build, container replacement');
  for (const line of ssh) {
    for (const expected of ['[-o] [BatchMode=yes]', '[-o] [StrictHostKeyChecking=yes]', '[-o] [UserKnownHostsFile=.scenter-deploy-known-hosts]', '[-o] [GlobalKnownHostsFile=/dev/null]', '[-p] [22]', '[deploy@192.168.222.132]']) {
      assert.ok(line.includes(expected), `${expected} in ${line}`);
    }
    assert.match(line, /\[-i\] \[[^\]]*ssh-key\]/, 'the key file bound by Jenkins');
  }
  assert.equal(result.knownHosts.trim(), `192.168.222.132 ssh-ed25519 ${HOST_KEY.key}`, 'only the approved host key');
  assert.match(result.log, new RegExp(`^docker build -t ${image.replace(/[.:/]/g, '\\$&')} -$`, 'm'));
  assert.match(result.log, new RegExp(`^docker run -d --name scenter-whoami --label security-center\\.managed=true --restart unless-stopped --security-opt no-new-privileges -p 8088:80 ${image.replace(/[.:/]/g, '\\$&')}$`, 'm'));
  assert.doesNotMatch(result.log, /--privileged|docker\.sock|\s-v\s|--volume|--cap-add|--network host/);
  const listing = spawnSync(BASH, ['-c', `tar -tf '${posix(path.join(result.tools.dir, 'context.tar'))}'`], { encoding: 'utf8', env: { PATH: SYSTEM_PATH } });
  assert.deepEqual(listing.stdout.trim().split(/\r?\n/).sort(), ['Dockerfile', 'app.go'], 'the analysed commit is the build context');
  assert.match(result.stdout, /conteneur scenter-whoami déployé/);
  for (const leftover of ['.scenter-deploy-known-hosts', '.scenter-deploy-context.tar', '.scenter-deploy-ssh.err']) {
    assert.equal(fs.existsSync(path.join(result.repo.dir, leftover)), false, `${leftover} cleaned up`);
  }

  const redeploy = deploy('redeploy', { fake: { existing: 'managed', portOwner: 'scenter-whoami' } });
  assert.equal(redeploy.status, 0, redeploy.stderr);
  assert.match(redeploy.log, /^docker rm -f scenter-whoami$/m, 'the previous Security Center container is replaced');
});

test('credential secret never exposed: the key is only a file path handed to ssh', { skip: SKIP }, () => {
  for (const result of [deploy('secret-pass'), deploy('secret-fail', { fake: { ssh: 'auth' } })]) {
    for (const text of [result.stdout, result.stderr, result.log, result.reason || '', result.knownHosts]) {
      assert.ok(!text.includes(SECRET), 'key material never printed, logged or recorded');
    }
  }
  assert.doesNotMatch(DEPLOY_SCRIPT, /cat "\$SCENTER_DEPLOY_KEY"|echo "\$SCENTER_DEPLOY_KEY"|set -x/);
  assert.match(DEPLOY_SCRIPT, /^set \+x$/m);
  assert.doesNotMatch(DEPLOY_STAGE, /\$\{env\.SCENTER_DEPLOY_[A-Z_]+\}[^\n]*script:|script: "/, 'no profile value is interpolated into a shell command by Groovy');
});

test('Docker unavailable -> precise error, nothing built or started', { skip: SKIP }, () => {
  const cases = [
    [{ docker: 'missing' }, "Docker n'est pas installé sur 192.168.222.132 : un administrateur doit installer Docker Engine."],
    [{ docker: 'permission' }, "L'utilisateur deploy ne peut pas utiliser Docker sur 192.168.222.132 : un administrateur doit l'ajouter au groupe docker."],
    [{ docker: 'down' }, /^Le démon Docker de 192\.168\.222\.132 ne répond pas : Cannot connect to the Docker daemon/],
    [{ ssh: 'hostkey' }, "Clé d'hôte SSH de 192.168.222.132 différente de la clé approuvée : déploiement refusé. Relancez Configure Deployment dans Security Center."],
    [{ ssh: 'auth' }, 'Authentification SSH refusée pour deploy@192.168.222.132 avec le credential vm-deploy-key.'],
    [{ existing: 'foreign' }, "Un conteneur scenter-whoami non déployé par Security Center existe sur 192.168.222.132 : il n'est jamais remplacé."],
    [{ portOwner: 'traefik' }, 'Le port 8088 de 192.168.222.132 est déjà publié par un autre conteneur.']
  ];
  for (const [fake, expected] of cases) {
    const result = deploy(`fail-${Object.values(fake).join('-')}`, { fake });
    assert.equal(result.status, 1, JSON.stringify(fake));
    if (expected instanceof RegExp) assert.match(result.reason, expected);
    else assert.equal(result.reason, expected);
    assert.doesNotMatch(result.log, /^docker (run|rm)/m, `${JSON.stringify(fake)}: nothing replaced`);
  }
  assert.doesNotMatch(deploy('fail-docker-build-guard', { fake: { docker: 'missing' } }).log, /^docker build/m);

  const invalid = deploy('invalid-profile', { parameters: { SCENTER_DEPLOY_CONTAINER: 'x; rm -rf /' } });
  assert.equal(invalid.reason, 'Profil de déploiement invalide : nom du conteneur.');
  assert.equal(invalid.log, '', 'an invalid profile never reaches ssh');
  assert.equal(deploy('no-dockerfile', { dockerfile: false }).reason.startsWith('Aucun Dockerfile à la racine du commit'), true);
});

test('the validation check reports Docker facts precisely on the deployment host', { skip: SKIP }, () => {
  const tools = doubles('check');
  const runCheck = (dockerMode, withDocker = true) => spawnSync(BASH, ['-c', checkScript(WHOAMI)], {
    encoding: 'utf8',
    env: { SYSTEMROOT: process.env.SYSTEMROOT || '', PATH: `${withDocker ? `${posix(tools.remote)}:` : ''}${SYSTEM_PATH}`, FAKE_LOG: posix(tools.log), FAKE_DIR: posix(tools.dir), FAKE_DOCKER: dockerMode }
  }).stdout;
  assert.match(runCheck('', false), /^SCENTER_DEPLOYCHECK_DOCKER=missing$/m);
  assert.match(runCheck('permission'), /^SCENTER_DEPLOYCHECK_DOCKER=permission-denied$/m);
  assert.match(runCheck('down'), /^SCENTER_DEPLOYCHECK_DOCKER=unreachable$/m);
  const ready = runCheck('');
  assert.match(ready, /^SCENTER_DEPLOYCHECK_DOCKER=ready 27\.3\.1$/m);
  assert.match(ready, /^SCENTER_DEPLOYCHECK_CONTAINER=absent$/m);
  assert.match(ready, /^SCENTER_DEPLOYCHECK_DONE=1$/m);
});

// ------------------------------------------------------------ Health Check

/**
 * Runs the Health Check script against a real local HTTP server. `sleep` is a
 * recording shell function so retries are instant: a function wins over PATH
 * everywhere, whereas Git Bash's launcher puts /usr/bin ahead of any test bin.
 */
async function healthCheck(name, responses) {
  const sleepLog = path.join(root, name, 'sleep.log');
  fs.mkdirSync(path.dirname(sleepLog), { recursive: true });
  fs.writeFileSync(sleepLog, '');
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(responses[Math.min(requests.length, responses.length) - 1]);
    response.end('ok');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const child = spawn(BASH, ['-c', `sleep() { echo "sleep $*" >> "$SLEEP_LOG"; }\n${HEALTH_SCRIPT}`], {
      env: { SYSTEMROOT: process.env.SYSTEMROOT || '', PATH: SYSTEM_PATH, SLEEP_LOG: posix(sleepLog), SCENTER_HEALTHCHECK_URL: `http://127.0.0.1:${server.address().port}/` }
    });
    const status = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
    return { status, requests, sleeps: fs.readFileSync(sleepLog, 'utf8').trim().split('\n').filter(Boolean) };
  } finally {
    server.close();
  }
}
const HEALTH_SKIP = (!BASH && 'bash indisponible') || (!tool('curl') && 'curl indisponible');

test('successful health check: PASSED as soon as the deployed application answers', { skip: HEALTH_SKIP }, async () => {
  assert.match(HEALTH_STAGE, /when \{\s*expression \{ env\.SC_DEPLOY_STATUS == 'SUCCEEDED' \}/, 'only after a successful deployment');
  assert.match(HEALTH_STAGE, /env\.SC_HEALTH_STATUS = status == 0 \? 'PASSED' : 'FAILED'/);
  const immediate = await healthCheck('health-ok', [200]);
  assert.deepEqual([immediate.status, immediate.requests.length, immediate.sleeps.length], [0, 1, 0]);
  const starting = await healthCheck('health-starting', [503, 503, 200]);
  assert.deepEqual([starting.status, starting.requests.length, starting.sleeps], [0, 3, ['sleep 6', 'sleep 6']], 'a container that is still starting gets retried');
});

test('failed health check: FAILED after the bounded retries, and the build fails', { skip: HEALTH_SKIP }, async () => {
  assert.match(HEALTH_STAGE, /if \(status != 0\) \{\s*error\('Health check en échec après déploiement\.'\)/);
  const result = await healthCheck('health-down', [503]);
  assert.equal(result.status, 1);
  assert.equal(result.requests.length, 10, 'ten attempts, never an endless wait');
});
