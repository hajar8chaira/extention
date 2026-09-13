'use strict';

/**
 * Bootstrap du CI Engine : aucune attente silencieuse ni infinie (A à G).
 *
 * Régression Jenkins réelle : après « node vX, npm Y », plus aucune ligne pendant
 * plus de 5 minutes. Le vrai script est exécuté contre de vrais serveurs HTTP
 * locaux qui répondent, redirigent, se bloquent ou coupent le transfert.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

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
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-engine-timeouts-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));

function enginePackage(version) {
  const base = path.join(root, `build-${version}`);
  const dir = path.join(base, 'package');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'security-center-vscode', version, bin: { 'security-center': './src/cli.js' } }, null, 2));
  fs.writeFileSync(path.join(dir, 'src', 'cli.js'), "#!/usr/bin/env node\nconsole.log('Security Center headless ' + require('../package.json').version);\n");
  const tgz = path.join(root, `security-center-vscode-${version}.tgz`);
  const packed = spawnSync(BASH, ['-c', `tar -czf "${posix(tgz)}" -C "${posix(base)}" package`], { encoding: 'utf8' });
  assert.equal(packed.status, 0, packed.stderr);
  const bytes = fs.readFileSync(tgz);
  return { version, bytes, sha: crypto.createHash('sha256').update(bytes).digest('hex') };
}

const commitOf = (label) => crypto.createHash('sha1').update(label).digest('hex');

/** A local artifact host. Routes: status/redirect/hang/stall/serve. */
function startServer(routes) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = http.createServer((request, response) => {
      const route = routes[request.url.split('?')[0]];
      if (!route) { response.writeHead(404); response.end('not found'); return; }
      route(request, response);
    });
    server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((done) => { for (const socket of sockets) socket.destroy(); server.close(done); })
    }));
  });
}

const serveJson = (value) => (request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
const serveBytes = (bytes) => (request, response) => { response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes.length }); response.end(bytes); };
const redirectTo = (location) => (request, response) => { response.writeHead(302, { location }); response.end(); };
const hang = () => () => {};
const stall = (bytes) => (request, response) => { response.writeHead(200, { 'content-length': bytes.length }); response.write(bytes.subarray(0, 16)); };

function manifestFor(pkg, tgzUrl, label) {
  return {
    schemaVersion: 1, name: 'security-center-vscode', version: pkg.version, commit: commitOf(label),
    buildTimestamp: new Date().toISOString(),
    tgz: { file: `security-center-vscode-${pkg.version}.tgz`, url: tgzUrl, sha256: pkg.sha, size: pkg.bytes.length },
    vsix: { file: 'x.vsix', url: 'https://example.invalid/x.vsix', sha256: 'a'.repeat(64), size: 1 }
  };
}

/** Runs the real bootstrap asynchronously, so the local servers keep answering. */
function runBootstrap(toolsDir, env = {}, { killAfterPhase = null } = {}) {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SCENTER_')));
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(BASH, [posix(BOOTSTRAP)], {
      env: {
        ...inherited, SCENTER_TOOLS_DIR: posix(toolsDir), SCENTER_NODE_HOME: NODE_HOME,
        SCENTER_BOOTSTRAP_CONNECT_TIMEOUT: '3', SCENTER_BOOTSTRAP_MANIFEST_TIMEOUT: '4',
        SCENTER_BOOTSTRAP_DOWNLOAD_TIMEOUT: '4', SCENTER_BOOTSTRAP_LOCK_TIMEOUT: '4', ...env
      }
    });
    let output = '';
    const onData = (chunk) => {
      output += chunk;
      if (killAfterPhase && output.includes(killAfterPhase) && !child.killed) child.kill('SIGKILL');
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    const guard = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (status) => {
      clearTimeout(guard);
      const field = (name) => (output.match(new RegExp(`^${name}=(.*)$`, 'm')) || [])[1];
      resolve({ status, output, elapsedMs: Date.now() - started, action: field('SCENTER_ENGINE_ACTION'), version: field('SCENTER_ENGINE_VERSION') });
    });
  });
}

/** A route that never answers, and leaves `file` once the request has arrived. */
const hangAndRecord = (file) => (request) => { fs.writeFileSync(file, request.url); };

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Starts the bootstrap from a bash driver, waits until `afterPhase` is logged
 * (and, with `afterFile`, until that file exists: the request really reached the
 * server, so the bootstrap is inside the bounded download and not just before
 * it), then sends `signal` to the real bash process — the process Jenkins
 * signals on abort. (Killing the Windows `bash.exe` launcher from Node would not
 * reach it.) Readiness, delivery and the exit status go to a separate file: the
 * bootstrap's own log is never written by two processes.
 */
function signalDuringPhase(toolsDir, env, { signal, afterPhase, afterFile = null }) {
  const id = `${signal}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const driver = path.join(root, `driver-${id}.sh`);
  const logFile = posix(path.join(root, `driver-${id}.log`));
  const metaFile = posix(path.join(root, `driver-${id}.meta`));
  const readyTest = afterFile ? `grep -q "${afterPhase}" "${logFile}" && [ -f "${posix(afterFile)}" ]` : `grep -q "${afterPhase}" "${logFile}"`;
  fs.writeFileSync(driver, [
    '#!/usr/bin/env bash',
    `bash "${posix(BOOTSTRAP)}" > "${logFile}" 2>&1 &`,
    'pid=$!',
    'ready=no',
    'for attempt in $(seq 1 600); do',
    `  if ${readyTest} 2>/dev/null; then ready=yes; break; fi`,
    '  if ! kill -0 "$pid" 2>/dev/null; then break; fi',
    '  sleep 0.1',
    'done',
    `if kill -${signal} "$pid" 2>/dev/null; then delivered=yes; else delivered=no; fi`,
    'wait "$pid"',
    'status=$?',
    `printf 'ready=%s\\ndelivered=%s\\nbootstrap-exit=%s\\n' "$ready" "$delivered" "$status" > "${metaFile}"`,
    ''
  ].join('\n'), { mode: 0o755 });
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SCENTER_')));
  return new Promise((resolve) => {
    const child = spawn(BASH, [posix(driver)], {
      env: { ...inherited, SCENTER_TOOLS_DIR: posix(toolsDir), SCENTER_NODE_HOME: NODE_HOME, SCENTER_BOOTSTRAP_CONNECT_TIMEOUT: '3', ...env }
    });
    const guard = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', () => {
      clearTimeout(guard);
      const read = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '');
      const output = read(path.join(root, `driver-${id}.log`));
      const meta = read(path.join(root, `driver-${id}.meta`));
      const field = (name) => (meta.match(new RegExp(`^${name}=(.*)$`, 'm')) || [])[1];
      resolve({ output, status: Number(field('bootstrap-exit')), ready: field('ready') === 'yes', delivered: field('delivered') === 'yes' });
    });
  });
}

const phases = (output) => [...output.matchAll(/^\[scenter-engine\] (.+)$/gm)].map((match) => match[1]);
const lockDir = (toolsDir) => path.join(toolsDir, 'security-center-packages', '.bootstrap.lock');
const markerOf = (toolsDir) => path.join(toolsDir, 'security-center', 'scenter-ci-engine.json');

let v1;
let v2;
function fixtures() { if (!v1) { v1 = enginePackage('1.0.0'); v2 = enginePackage('2.0.0'); } }

// ------------------------------------------------------------ A / E / G

test('A / E / G — manifeste GitHub-style avec redirections inter-hôtes : installé, phases journalisées', { skip: SKIP }, async (t) => {
  fixtures();
  let port;
  const server = await startServer({
    // Comme GitHub : le lien de release redirige vers un autre hôte de stockage.
    '/hajar8chaira/extention/releases/download/scenter-latest/security-center-latest.json': (request, response) => redirectTo(`http://localhost:${port}/release-assets/latest.json?X-Amz-Signature=secret-signature`)(request, response),
    '/release-assets/latest.json': (request, response) => serveJson(manifestFor(v1, `http://127.0.0.1:${port}/hajar8chaira/extention/releases/download/scenter-build-x/pkg.tgz`, 'v1'))(request, response),
    '/hajar8chaira/extention/releases/download/scenter-build-x/pkg.tgz': (request, response) => redirectTo(`http://localhost:${port}/release-assets/pkg.tgz?token=signed-query`)(request, response),
    '/release-assets/pkg.tgz': (request, response) => serveBytes(v1.bytes)(request, response)
  });
  port = server.port;
  t.after(() => server.close());
  const tools = path.join(root, 'tools-a');
  const result = await runBootstrap(tools, {
    SCENTER_ENGINE_MANIFEST_URL: `http://127.0.0.1:${port}/hajar8chaira/extention/releases/download/scenter-latest/security-center-latest.json`
  });
  assert.equal(result.status, 0, result.output);
  assert.equal(result.action, 'installed');
  assert.equal(result.version, '1.0.0');
  assert.doesNotMatch(result.output, /secret-signature|signed-query/, 'aucune URL signée journalisée');

  // G. Chaque phase est annoncée avant d'être exécutée, dans l'ordre réel.
  const log = phases(result.output);
  const expectedOrder = [
    /^resolving Node\.js and npm$/,
    /^node v/,
    /^acquiring install lock \(.+, timeout 4s\)$/,
    /^install lock acquired$/,
    /^fetching engine manifest \(http:\/\/127\.0\.0\.1:\d+\/.+security-center-latest\.json, timeout 4s\)$/,
    /^validating engine manifest$/,
    /^manifest received: security-center-vscode@1\.0\.0, commit [0-9a-f]{40}/,
    /^checking installed engine$/,
    /^downloading engine package \(http:\/\/127\.0\.0\.1:\d+\/.+pkg\.tgz, timeout 4s\)$/,
    /^verifying SHA-256$/,
    /^validating engine package$/,
    /^installing engine \(security-center-vscode@1\.0\.0 into .+, timeout 300s\)$/,
    /^verifying installed CLI$/,
    /^recording installed engine$/
  ];
  let cursor = 0;
  for (const pattern of expectedOrder) {
    const index = log.findIndex((line, position) => position >= cursor && pattern.test(line));
    assert.ok(index >= 0, `phase ${pattern} absente ou hors d'ordre :\n${log.join('\n')}`);
    cursor = index + 1;
  }
  assert.equal(fs.existsSync(lockDir(tools)), false, 'verrou libéré');

  // Même build : aucune réinstallation, et toujours des phases visibles.
  const again = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: `http://127.0.0.1:${port}/hajar8chaira/extention/releases/download/scenter-latest/security-center-latest.json` });
  assert.equal(again.status, 0, again.output);
  assert.equal(again.action, 'unchanged');
  assert.ok(phases(again.output).includes('checking installed engine'));
});

// ------------------------------------------------------------ B

test('B — manifeste qui ne répond jamais : délai borné, ERROR / exit 2, phase nommée', { skip: SKIP }, async (t) => {
  fixtures();
  const server = await startServer({ '/security-center-latest.json': hang() });
  t.after(() => server.close());
  const report = path.join(root, 'report-b.json');
  const result = await runBootstrap(path.join(root, 'tools-b'), {
    SCENTER_ENGINE_MANIFEST_URL: `http://127.0.0.1:${server.port}/security-center-latest.json`,
    SCENTER_BOOTSTRAP_FAILURE_REPORT: posix(report)
  });
  assert.equal(result.status, 2, result.output);
  assert.match(result.output, /ERROR during 'fetching engine manifest .+': CI Engine manifest unreachable: .+\(manifest download timed out after 4s\)/);
  assert.ok(result.elapsedMs < 45000, `borné (${result.elapsedMs} ms)`);
  const failure = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.equal(failure.verdict.status, 'ERROR');
  assert.equal(failure.execution.status, 'engine_unavailable');
  assert.match(failure.execution.error, /fetching engine manifest.+timed out after 4s/);
  assert.equal(fs.existsSync(lockDir(path.join(root, 'tools-b'))), false, 'verrou libéré après l’échec');
});

// ------------------------------------------------------------ C / F

test('C / F — paquet dont le transfert se bloque : délai borné, exit 2, moteur existant intact', { skip: SKIP }, async (t) => {
  fixtures();
  let port;
  const routes = {};
  const server = await startServer(routes);
  port = server.port;
  t.after(() => server.close());
  const tools = path.join(root, 'tools-c');
  const manifestUrl = `http://127.0.0.1:${port}/latest.json`;

  // Moteur v1 installé normalement.
  routes['/latest.json'] = serveJson(manifestFor(v1, `http://127.0.0.1:${port}/v1.tgz`, 'v1'));
  routes['/v1.tgz'] = serveBytes(v1.bytes);
  const installed = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: manifestUrl });
  assert.equal(installed.status, 0, installed.output);
  const markerBefore = fs.readFileSync(markerOf(tools), 'utf8');

  // Le build v2 est publié, mais son transfert s'arrête après quelques octets.
  routes['/latest.json'] = serveJson(manifestFor(v2, `http://127.0.0.1:${port}/v2.tgz`, 'v2'));
  routes['/v2.tgz'] = stall(v2.bytes);
  const stalled = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: manifestUrl });
  assert.equal(stalled.status, 2, stalled.output);
  assert.match(stalled.output, /ERROR during 'downloading engine package .+': download failed from .+v2\.tgz \(engine package download timed out after 4s\)/);
  assert.ok(stalled.elapsedMs < 60000, `borné (${stalled.elapsedMs} ms)`);

  // F. Échec avant installation : ancien moteur, enregistrement et commande inchangés.
  assert.equal(fs.readFileSync(markerOf(tools), 'utf8'), markerBefore, 'enregistrement du moteur intact');
  const packages = fs.readdirSync(path.join(tools, 'security-center-packages'));
  assert.deepEqual(packages.filter((name) => name.startsWith('.download-') || name.startsWith('.manifest-') || name.startsWith('.auth-')), [], 'aucun fichier temporaire');
  assert.ok(!packages.includes(`sha256-${v2.sha}.tgz`), 'paquet partiel jamais mis en cache');
  routes['/latest.json'] = serveJson(manifestFor(v1, `http://127.0.0.1:${port}/v1.tgz`, 'v1'));
  const back = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: manifestUrl });
  assert.equal(back.status, 0, back.output);
  assert.equal(back.action, 'unchanged', 'le moteur v1 est toujours vérifié et utilisable');
});

// ------------------------------------------------------------ D

test('D — verrou détenu par un autre bootstrap vivant : attente journalisée puis exit 2 borné', { skip: SKIP }, async () => {
  fixtures();
  const tools = path.join(root, 'tools-d');
  fs.mkdirSync(lockDir(tools), { recursive: true });
  // Un détenteur sur un autre agent : son processus ne peut pas être vérifié ici.
  fs.writeFileSync(path.join(lockDir(tools), 'owner'), `pid=4242 host=other-agent started=${Math.floor(Date.now() / 1000)} build=jenkins-security-pipeline-7`);
  const result = await runBootstrap(tools, { SCENTER_ENGINE_TGZ_URL: 'http://127.0.0.1:9/x.tgz', SCENTER_ENGINE_SHA256: v1.sha });
  assert.equal(result.status, 2, result.output);
  assert.match(result.output, /waiting for install lock held by pid 4242 on other-agent, build jenkins-security-pipeline-7 \(0s of 4s\)/);
  assert.match(result.output, /ERROR during 'acquiring install lock .+': install lock still held after 4s: .+\.bootstrap\.lock \(pid 4242 on other-agent, build jenkins-security-pipeline-7\)\. If no Security Center build is running, remove that directory\./);
  assert.ok(result.elapsedMs < 30000, `borné (${result.elapsedMs} ms)`);
  assert.ok(fs.existsSync(lockDir(tools)), 'le verrou d’un autre agent n’est pas volé');
});

test('D / F — verrou abandonné (processus tué, ancien bootstrap, trop vieux) : repris immédiatement', { skip: SKIP }, async (t) => {
  fixtures();
  const server = await startServer({});
  t.after(() => server.close());
  const host = spawnSync(BASH, ['-c', 'hostname 2>/dev/null || uname -n'], { encoding: 'utf8' }).stdout.trim();

  // 1. Processus tué (SIGKILL par Jenkins) : même hôte, PID mort.
  const killed = path.join(root, 'tools-killed');
  fs.mkdirSync(lockDir(killed), { recursive: true });
  fs.writeFileSync(path.join(lockDir(killed), 'owner'), `pid=999999 host=${host} started=${Math.floor(Date.now() / 1000)} build=aborted`);
  const afterKill = await runBootstrap(killed, { SCENTER_ENGINE_TGZ_URL: `http://127.0.0.1:${server.port}/missing.tgz`, SCENTER_ENGINE_SHA256: v1.sha });
  assert.match(afterKill.output, /removing abandoned install lock: its owner process 999999 on .+ is no longer running/);
  assert.match(afterKill.output, /install lock acquired/);
  assert.equal(afterKill.status, 2, 'échoue ensuite sur le téléchargement, pas sur le verrou');
  assert.doesNotMatch(afterKill.output, /waiting for install lock/);

  // 2. Verrou sans propriétaire laissé par l'ancien bootstrap, plus vieux que le seuil.
  const legacy = path.join(root, 'tools-legacy');
  fs.mkdirSync(lockDir(legacy), { recursive: true });
  const old = new Date(Date.now() - 2 * 3600 * 1000);
  fs.utimesSync(lockDir(legacy), old, old);
  const afterLegacy = await runBootstrap(legacy, { SCENTER_ENGINE_TGZ_URL: `http://127.0.0.1:${server.port}/missing.tgz`, SCENTER_ENGINE_SHA256: v1.sha, SCENTER_BOOTSTRAP_LOCK_STALE_AFTER: '600' });
  assert.match(afterLegacy.output, /removing abandoned install lock: it is \d+s old \(abandoned after 600s\)/);
  assert.match(afterLegacy.output, /install lock acquired/);

  // 3. Bootstrap tué pendant le téléchargement : le build suivant reprend sans attendre.
  const aborted = path.join(root, 'tools-aborted');
  const hanging = await startServer({ '/hang.tgz': hang() });
  t.after(() => hanging.close());
  const first = await signalDuringPhase(aborted, { SCENTER_ENGINE_TGZ_URL: `http://127.0.0.1:${hanging.port}/hang.tgz`, SCENTER_ENGINE_SHA256: v1.sha, SCENTER_BOOTSTRAP_DOWNLOAD_TIMEOUT: '60' }, { signal: 'KILL', afterPhase: 'downloading engine package' });
  assert.equal(first.status, 137, `SIGKILL, aucun nettoyage possible :\n${first.output}`);
  assert.ok(fs.existsSync(path.join(lockDir(aborted), 'owner')), 'le kill brutal laisse le verrou, comme sur Jenkins');
  const next = await runBootstrap(aborted, { SCENTER_ENGINE_TGZ_URL: `http://127.0.0.1:${server.port}/missing.tgz`, SCENTER_ENGINE_SHA256: v1.sha });
  assert.match(next.output, /removing abandoned install lock: its owner process \d+ on .+ is no longer running/);
  assert.doesNotMatch(next.output, /waiting for install lock/);
});

test('F — interruption par signal : verrou et temporaires libérés, ERROR explicite', { skip: SKIP }, async (t) => {
  fixtures();
  const routes = {};
  const server = await startServer(routes);
  const port = server.port;
  t.after(() => server.close());
  const tools = path.join(root, 'tools-signal');
  const manifestUrl = `http://127.0.0.1:${port}/latest.json`;

  // Moteur v1 installé normalement : l'interruption ne doit pas l'abîmer.
  routes['/latest.json'] = serveJson(manifestFor(v1, `http://127.0.0.1:${port}/v1.tgz`, 'v1'));
  routes['/v1.tgz'] = serveBytes(v1.bytes);
  const installed = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: manifestUrl });
  assert.equal(installed.status, 0, installed.output);
  const markerBefore = fs.readFileSync(markerOf(tools), 'utf8');

  // Le build v2 est publié, mais son hôte ne répond jamais.
  const requested = path.join(root, 'signal-v2-requested');
  routes['/latest.json'] = serveJson(manifestFor(v2, `http://127.0.0.1:${port}/v2.tgz`, 'v2'));
  routes['/v2.tgz'] = hangAndRecord(requested);

  // Un vrai SIGTERM au bash du bootstrap (abort Jenkins), envoyé seulement une fois
  // la phase journalisée ET la requête reçue : le téléchargement borné est en cours.
  const started = Date.now();
  const result = await signalDuringPhase(tools, {
    SCENTER_ENGINE_MANIFEST_URL: manifestUrl, SCENTER_BOOTSTRAP_DOWNLOAD_TIMEOUT: '60'
  }, { signal: 'TERM', afterPhase: 'downloading engine package', afterFile: requested });
  assert.ok(result.ready, `le téléchargement bloqué a démarré avant le signal :\n${result.output}`);
  assert.ok(result.delivered, `SIGTERM reçu par le bootstrap encore vivant :\n${result.output}`);
  assert.equal(result.status, 2, result.output);
  assert.ok(Date.now() - started < 45000, `l’abort n’attend pas la fin du téléchargement bloqué (60s) :\n${result.output}`);

  // Contrat exact : la phase porte la source (sans requête) et la borne.
  const phase = `downloading engine package (http://127.0.0.1:${port}/v2.tgz, timeout 60s)`;
  assert.match(result.output, new RegExp(`^\\[scenter-engine\\] ${escapeRegExp(phase)}$`, 'm'), result.output);
  assert.match(result.output, new RegExp(`^\\[scenter-engine\\] ERROR during '${escapeRegExp(phase)}': interrupted by signal TERM \\(build aborted or agent stopping\\)`, 'm'), result.output);
  assert.match(result.output, /^SCENTER_ENGINE_STATUS=ERROR$/m, result.output);

  // Verrou et temporaires libérés, rien de partiel en cache, ancien moteur intact.
  assert.equal(fs.existsSync(lockDir(tools)), false, 'verrou libéré à l’interruption');
  const packages = fs.readdirSync(path.join(tools, 'security-center-packages'));
  assert.deepEqual(packages.filter((name) => name.startsWith('.download-') || name.startsWith('.manifest-') || name.startsWith('.auth-')), [], 'aucun fichier temporaire');
  assert.ok(!packages.includes(`sha256-${v2.sha}.tgz`), 'paquet interrompu jamais mis en cache');
  assert.equal(fs.readFileSync(markerOf(tools), 'utf8'), markerBefore, 'enregistrement du moteur intact');
  routes['/latest.json'] = serveJson(manifestFor(v1, `http://127.0.0.1:${port}/v1.tgz`, 'v1'));
  const back = await runBootstrap(tools, { SCENTER_ENGINE_MANIFEST_URL: manifestUrl });
  assert.equal(back.status, 0, back.output);
  assert.equal(back.action, 'unchanged', 'le moteur v1 est toujours vérifié et utilisable');
});

test('bornes invalides refusées avant toute action', { skip: SKIP }, async () => {
  const result = await runBootstrap(path.join(root, 'tools-bounds'), { SCENTER_BOOTSTRAP_MANIFEST_TIMEOUT: 'forever', SCENTER_ENGINE_SHA256: 'a'.repeat(64) });
  assert.equal(result.status, 2);
  assert.match(result.output, /invalid SCENTER_BOOTSTRAP_MANIFEST_TIMEOUT value 'forever'/);
});
