'use strict';

/**
 * Le scan actif réel sur http://192.168.222.132:3000 échouait vers 38 % avec
 * « ZAP_SCAN_FAILED · fetch failed ». La cause mesurée : la JVM du démon ZAP
 * s'est arrêtée faute de mémoire système (hs_err_pid117612.log), et le sondage
 * `ascan/view/status` suivant a trouvé un port fermé. Ces tests tiennent la
 * politique qui en découle : une lecture perdue est relue, une panne confirmée
 * est nommée, et rien ne se cache derrière « fetch failed ».
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const {
  zapApi, readZapView, waitForProgress, portListening, ZapApiError, ZAP_API_ERROR, ZAP_STATUS_POLL_POLICY
} = require('../src/zap-local');

const API_KEY = 'ff138416018bba44c03f87660a59ff596caf6645b85bcfb8';
const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

function withFetch(impl, run) {
  const original = global.fetch;
  global.fetch = impl;
  return Promise.resolve().then(run).finally(() => { global.fetch = original; });
}

function fetchFailed(code = 'ECONNREFUSED') {
  const cause = Object.assign(new Error(`connect ${code} 127.0.0.1:11669`), { code, errno: -4078, syscall: 'connect', address: '127.0.0.1', port: 11669 });
  return new TypeError('fetch failed', { cause });
}

const ok = (payload) => ({ ok: true, status: 200, json: async () => payload });

/** Un démon factice : vivant jusqu'à ce qu'on le fasse mourir. */
function fakeDaemon({ stdout = [], stderr = [] } = {}) {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.zapDiagnostics = { stdout, stderr };
  child.die = (code = 1) => { child.exitCode = code; child.emit('exit', code, null); child.emit('close', code, null); };
  return child;
}

async function closedPort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

// ------------------------------------------------------------------ zapApi

test('un fetch échoué devient une panne nommée, avec l’appel exact et sa cause réseau', async () => {
  await withFetch(async () => { throw fetchFailed('ECONNRESET'); }, async () => {
    const error = await zapApi('http://127.0.0.1:11669', API_KEY, 'ascan', 'view', 'status', { scanId: 0 }, 10000).catch((e) => e);
    assert.ok(error instanceof ZapApiError);
    assert.equal(error.code, ZAP_API_ERROR.ZAP_API_UNREACHABLE);
    assert.doesNotMatch(error.message, /fetch failed/);
    assert.equal(error.details.operation, 'ascan.view.status');
    assert.equal(error.details.method, 'GET');
    assert.equal(error.details.endpoint, '/JSON/ascan/view/status/');
    assert.equal(error.details.host, '127.0.0.1');
    assert.equal(error.details.port, 11669);
    assert.equal(error.details.timeoutMs, 10000);
    assert.equal(error.details.error, 'fetch failed');
    assert.deepEqual(
      { code: error.details.cause.code, errno: error.details.cause.errno, syscall: error.details.cause.syscall },
      { code: 'ECONNRESET', errno: -4078, syscall: 'connect' }
    );
    assert.doesNotMatch(JSON.stringify(error.details), new RegExp(API_KEY), 'la clé d’API ne sort jamais');
  });
});

test('une réponse HTTP d’erreur garde son statut et son corps, sans la clé', async () => {
  await withFetch(async () => ({ ok: false, status: 500, text: async () => `boom apikey=${API_KEY}` }), async () => {
    const error = await zapApi('http://127.0.0.1:11669', API_KEY, 'ascan', 'view', 'status', { scanId: 0 }).catch((e) => e);
    assert.equal(error.code, ZAP_API_ERROR.ZAP_API_HTTP_ERROR);
    assert.equal(error.message, 'API ZAP status : HTTP 500.');
    assert.equal(error.details.status, 500);
    assert.doesNotMatch(error.details.body, new RegExp(API_KEY));
  });
});

test('un délai dépassé est distingué d’une connexion refusée', async () => {
  await withFetch(async () => { throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }); }, async () => {
    const error = await zapApi('http://127.0.0.1:11669', API_KEY, 'ascan', 'view', 'status', {}, 10000).catch((e) => e);
    assert.equal(error.code, ZAP_API_ERROR.ZAP_API_TIMEOUT);
  });
});

// ------------------------------------------------------- politique de relecture

test('une lecture de statut perdue est relue et le scan continue sa vraie progression', async () => {
  const answers = [ok({ status: '37' }), 'fail', ok({ status: '38' }), ok({ status: '100' })];
  let call = 0;
  const seen = [];
  const retries = [];
  await withFetch(async () => {
    const answer = answers[Math.min(call++, answers.length - 1)];
    if (answer === 'fail') throw fetchFailed('ECONNRESET');
    return answer;
  }, () => waitForProgress('http://127.0.0.1:11669', API_KEY, 'ascan', '0', 60000, null, (percent) => seen.push(percent), {
    stallMs: 60000, child: fakeDaemon(), backoffMs: 1, onRetry: (info) => retries.push(info)
  }));
  assert.deepEqual(seen, [37, 38, 100], 'aucune progression inventée pendant la relecture');
  assert.equal(retries.length, 1);
  assert.equal(retries[0].failure.cause.code, 'ECONNRESET');
});

test('un démon mort pendant le scan actif est nommé avec sa vraie raison, sans épuiser les tentatives', async () => {
  const child = fakeDaemon({ stdout: [
    '# There is insufficient memory for the Java Runtime Environment to continue.',
    '# Native memory allocation (malloc) failed to allocate 1330576 bytes for Chunk::new',
    '# D:\\SecurityCenter\\temp\\hs_err_pid117612.log'
  ] });
  let calls = 0;
  const error = await withFetch(async () => { calls += 1; child.die(1); throw fetchFailed('ECONNREFUSED'); },
    () => readZapView('http://127.0.0.1:11669', API_KEY, 'ascan', 'status', { scanId: 0 }, { child, backoffMs: 1, exitGraceMs: 1, lastSuccess: { percent: 38 } })
  ).catch((e) => e);
  assert.equal(calls, 1, 'un processus mort ne se relit pas');
  assert.equal(error.code, ZAP_API_ERROR.ZAP_OUT_OF_MEMORY);
  assert.match(error.message, /s’est arrêté pendant le scan actif : la JVM n’a plus pu allouer de mémoire/);
  assert.doesNotMatch(error.message, /fetch failed/);
  assert.equal(error.details.processAlive, false);
  assert.equal(error.details.exitCode, 1);
  assert.equal(error.details.lastSuccess.percent, 38);
  assert.match(error.details.crashReport, /hs_err_pid117612\.log/);
  assert.equal(error.details.failures[0].cause.code, 'ECONNREFUSED');
  assert.ok(error.diagnostics, 'la sortie du démon accompagne l’erreur pour le journal');
});

test('un démon mort sans trace mémoire reste ZAP_PROCESS_EXITED', async () => {
  const child = fakeDaemon({ stderr: ['Exception in thread "main"'] });
  const error = await withFetch(async () => { child.die(3); throw fetchFailed(); },
    () => readZapView('http://127.0.0.1:11669', API_KEY, 'ascan', 'status', {}, { child, backoffMs: 1, exitGraceMs: 1 })
  ).catch((e) => e);
  assert.equal(error.code, ZAP_API_ERROR.ZAP_PROCESS_EXITED);
  assert.match(error.message, /\(code 3\)/);
});

test('trois échecs, démon vivant et port fermé : ZAP_API_UNREACHABLE, jamais masqué', async () => {
  const port = await closedPort();
  let calls = 0;
  const error = await withFetch(async () => { calls += 1; throw fetchFailed('ECONNREFUSED'); },
    () => readZapView(`http://127.0.0.1:${port}`, API_KEY, 'ascan', 'status', {}, { child: fakeDaemon(), backoffMs: 1, exitGraceMs: 1 })
  ).catch((e) => e);
  assert.equal(calls, ZAP_STATUS_POLL_POLICY.ATTEMPTS);
  assert.equal(error.code, ZAP_API_ERROR.ZAP_API_UNREACHABLE);
  assert.match(error.message, /Connexion perdue avec l’API ZAP locale pendant le scan actif/);
  assert.equal(error.details.processAlive, true);
  assert.equal(error.details.portListening, false);
  assert.equal(error.details.failures.length, 3);
});

test('trois échecs alors que le port écoute : ZAP_STATUS_POLL_FAILED', async () => {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const error = await withFetch(async () => { throw Object.assign(new Error('aborted'), { name: 'TimeoutError' }); },
      () => readZapView(`http://127.0.0.1:${port}`, API_KEY, 'ascan', 'status', {}, { child: fakeDaemon(), backoffMs: 1, exitGraceMs: 1 })
    ).catch((e) => e);
    assert.equal(error.code, ZAP_API_ERROR.ZAP_STATUS_POLL_FAILED);
    assert.match(error.message, /n’a pas pu être lu après 3 tentatives/);
    assert.equal(error.details.portListening, true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('une requête refusée par ZAP n’est pas relue', async () => {
  let calls = 0;
  const error = await withFetch(async () => { calls += 1; return ({ ok: false, status: 400, text: async () => 'bad scanId' }); },
    () => readZapView('http://127.0.0.1:11669', API_KEY, 'ascan', 'status', {}, { child: fakeDaemon(), backoffMs: 1 })
  ).catch((e) => e);
  assert.equal(calls, 1);
  assert.equal(error.code, ZAP_API_ERROR.ZAP_API_HTTP_ERROR);
});

test('le port d’écoute est réellement sondé', async () => {
  assert.equal(await portListening('127.0.0.1', await closedPort()), false);
});

// ---------------------------------------------------------------- câblage

test('la concurrence du scan actif est bornée avant son démarrage, et relue', () => {
  const { ZAP_ACTIVE_SCAN_THREADS_PER_HOST } = require('../src/zap-local');
  assert.equal(ZAP_ACTIVE_SCAN_THREADS_PER_HOST, 8);
  const local = src('zap-local.js');
  const helper = local.slice(local.indexOf('async function boundActiveScanConcurrency'), local.indexOf('async function waitForProgress'));
  const set = helper.indexOf("'ascan', 'action', 'setOptionThreadPerHost', { Integer: ZAP_ACTIVE_SCAN_THREADS_PER_HOST }");
  assert.ok(set > 0, 'le plafond est posé par une action unique');
  assert.match(helper.slice(set), /const applied = await threadsPerHost\(\)/, 'puis relu');
  // Appelé dans la branche active, juste avant le démarrage — jamais en baseline.
  const call = local.indexOf('await boundActiveScanConcurrency(baseUrl, apiKey, pollOptions, diagnose);');
  const start = local.indexOf("'ascan', 'action', 'scan'");
  const baseline = local.indexOf("report('ACTIVE_SKIPPED'");
  assert.ok(baseline > 0 && baseline < call && call < start);
});

test('le scan actif ne relance jamais son démarrage, et ses lectures connaissent le démon', () => {
  const local = src('zap-local.js');
  // Le démarrage est une action : un seul appel direct, jamais une relecture.
  assert.match(local, /await zapApi\(baseUrl, apiKey, 'ascan', 'action', 'scan'/);
  assert.doesNotMatch(local, /readZapView\([^)]*'action'/);
  assert.match(local, /'ascan', active\.scan,[\s\S]{0,200}pollOptions\)/);
  assert.match(local, /'spider', spider\.scan,[\s\S]{0,200}pollOptions\)/);
  assert.match(local, /readZapView\(baseUrl, apiKey, 'core', 'alerts'/);
  // Et le détail technique d'une panne confirmée va au journal.
  assert.match(src('extension.js'), /ZAP — détail technique : \$\{JSON\.stringify\(error\.details\)\}/);
});
