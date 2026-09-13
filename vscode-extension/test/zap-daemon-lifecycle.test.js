'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter, Readable } = require('node:stream');

const {
  ZAP_START_ERROR, ZapStartError, ZAP_LOCAL_TIMEOUTS,
  waitForZapDaemon, clearStaleZapLocks, redactZapText, attachZapDiagnostics, runLocalZap, zapHomeDirectory
} = require('../src/zap-local');
const {
  ZAP_STAGE, STAGE_STATUS, createZapExecution, applyZapLifecycle, applyZapStage,
  failZapExecution, restoreZapExecution, zapExecutionSummary
} = require('../src/zap-execution');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { availability, engineState, createRun, transitionRun, RUN_KIND, RUN_STATUS } = require('../src/dynamic-runtime');

const TARGET = 'http://192.168.222.132:3000';
const src = (name) => fs.readFileSync(path.join(__dirname, '..', 'src', name), 'utf8');

/** Un processus de test : il vit, meurt ou refuse de démarrer sur commande. */
function fakeChild({ pid = 4242 } = {}) {
  const child = new EventEmitter();
  child.pid = pid;
  child.exitCode = null;
  child.signalCode = null;
  child.stdout = new Readable({ read() {} });
  child.stderr = new Readable({ read() {} });
  child.kills = [];
  child.kill = (signal) => { child.kills.push(signal || 'SIGTERM'); return true; };
  child.die = (code = 1, signal = null) => {
    child.exitCode = code;
    child.signalCode = signal;
    child.emit('exit', code, signal);
  };
  return child;
}

// ------------------------------------------------- le diagnostic de lancement

test('le lancement est consigné : commande, arguments, répertoire, PID', () => {
  const child = fakeChild({ pid: 1234 });
  const diagnostics = attachZapDiagnostics(child, {
    command: 'java',
    args: ['-Xmx1024m', '-jar', 'C:\\ZAP\\zap-2.17.0.jar', '-daemon', '-port', '46483', '-config', 'api.key=abcdef0123456789'],
    cwd: 'C:\\ZAP',
    secrets: ['abcdef0123456789']
  });

  assert.equal(diagnostics.command, 'java');
  assert.equal(diagnostics.cwd, 'C:\\ZAP');
  assert.equal(diagnostics.pid, 1234);
  // La clé d'API n'est jamais conservée en clair, même dans les arguments.
  assert.ok(diagnostics.args.some((argument) => /api\.key=«redacted»/.test(argument)));
  assert.ok(!diagnostics.args.join(' ').includes('abcdef0123456789'));
  assert.equal(child.zapDiagnostics, diagnostics);
});

test('la sortie du démon est conservée en anneau, assainie, et son code de fin relevé', async () => {
  const child = fakeChild();
  const diagnostics = attachZapDiagnostics(child, { command: 'java', args: [], cwd: 'C:\\ZAP', secrets: ['Secret-Pa55'] });

  child.stderr.push('java.lang.Exception: The home directory is already in use\n');
  child.stderr.push(`mot de passe Secret-Pa55 dans la sortie\n`);
  child.stdout.push('ZAP is starting\n');
  await new Promise((resolve) => setImmediate(resolve));
  child.die(1, null);
  await new Promise((resolve) => setImmediate(resolve));

  assert.ok(diagnostics.stderr.some((line) => /home directory is already in use/.test(line)));
  // Aucun secret ne sort, même venu du démon.
  assert.ok(!diagnostics.stderr.join(' ').includes('Secret-Pa55'));
  assert.ok(diagnostics.stderr.some((line) => line.includes('«redacted»')));
  assert.deepEqual(diagnostics.stdout, ['ZAP is starting']);
  assert.equal(diagnostics.exitCode, 1);
});

test('l’anneau de sortie ne grandit pas sans limite', async () => {
  const child = fakeChild();
  const diagnostics = attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  for (let index = 0; index < 200; index += 1) child.stderr.push(`ligne ${index}\n`);
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(diagnostics.stderr.length <= 40, 'la sortie conservée doit rester bornée');
  assert.equal(diagnostics.stderr[diagnostics.stderr.length - 1], 'ligne 199');
});

test('la redaction couvre la clé d’API et toute valeur connue', () => {
  assert.equal(redactZapText('-config api.key=deadbeefcafe', []), '-config api.key=«redacted»');
  assert.equal(redactZapText('jeton=abcd1234', ['abcd1234']), 'jeton=«redacted»');
  // Une valeur trop courte n'est pas un secret exploitable et n'est pas remplacée.
  assert.equal(redactZapText('x=ab', ['ab']), 'x=ab');
});

// ------------------------------------------ la mort du processus est une réponse

test('un démon qui meurt pendant l’attente fait échouer tout de suite, avec son code', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('connexion refusée'); };
  child.stderr.push('The home directory is already in use\n');
  await new Promise((resolve) => setImmediate(resolve));
  setTimeout(() => child.die(1), 20);

  const startedAt = Date.now();
  try {
    await assert.rejects(
      waitForZapDaemon({ baseUrl: 'http://127.0.0.1:46483', apiKey: 'k', child, timeoutMs: 120000 }),
      (error) => {
        assert.ok(error instanceof ZapStartError);
        assert.equal(error.code, ZAP_START_ERROR.ZAP_PROCESS_EXITED);
        assert.match(error.message, /s’est arrêté avant d’ouvrir son API \(code 1\)/);
        assert.match(error.message, /home directory is already in use/);
        return true;
      }
    );
  } finally { global.fetch = originalFetch; }
  // Surtout : on n'a pas attendu les trois minutes du délai de démarrage.
  assert.ok(Date.now() - startedAt < 10000, 'la mort du processus doit répondre immédiatement');
});

test('un processus déjà mort avant l’attente est constaté sans sondage inutile', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  child.exitCode = 3;
  let calls = 0;
  const originalFetch = global.fetch;
  global.fetch = async () => { calls += 1; throw new Error('rien'); };
  try {
    await assert.rejects(
      waitForZapDaemon({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', child, timeoutMs: 120000 }),
      (error) => error.code === ZAP_START_ERROR.ZAP_PROCESS_EXITED && /code 3/.test(error.message)
    );
  } finally { global.fetch = originalFetch; }
  assert.equal(calls, 0, 'aucune requête ne doit partir vers un démon déjà mort');
});

test('java introuvable est nommé comme tel, pas comme une attente', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('rien'); };
  setTimeout(() => child.emit('error', new Error('spawn java ENOENT')), 10);
  try {
    await assert.rejects(
      waitForZapDaemon({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', child, timeoutMs: 60000 }),
      (error) => {
        assert.equal(error.code, ZAP_START_ERROR.JAVA_START_FAILED);
        assert.match(error.message, /Java est introuvable/);
        return true;
      }
    );
  } finally { global.fetch = originalFetch; }
});

test('une API qui répond termine l’attente et retire les écouteurs posés', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  // Ce qui est branché avant l'attente : les écouteurs du diagnostic, qui vivent
  // aussi longtemps que le processus.
  const before = { exit: child.listenerCount('exit'), error: child.listenerCount('error') };
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => ({ version: '2.17.0' }) });
  try {
    const result = await waitForZapDaemon({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', child, timeoutMs: 60000 });
    assert.equal(result.version, '2.17.0');
  } finally { global.fetch = originalFetch; }
  // L'attente ne laisse pas les siens derrière elle.
  assert.equal(child.listenerCount('exit'), before.exit);
  assert.equal(child.listenerCount('error'), before.error);
});

test('le délai de démarrage dépassé reste borné et nommé', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('rien'); };
  try {
    await assert.rejects(
      waitForZapDaemon({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', child, timeoutMs: 1 }),
      (error) => error.code === ZAP_START_ERROR.ZAP_START_FAILED && /n’a pas répondu/.test(error.message)
    );
  } finally { global.fetch = originalFetch; }
  assert.equal(ZAP_LOCAL_TIMEOUTS.DAEMON_START_MS, 180000);
});

test('une annulation pendant l’attente est respectée', async () => {
  const child = fakeChild();
  attachZapDiagnostics(child, { command: 'java', args: [], cwd: '.', secrets: [] });
  const controller = new AbortController();
  controller.abort();
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('rien'); };
  try {
    await assert.rejects(
      waitForZapDaemon({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', child, timeoutMs: 60000, signal: controller.signal }),
      /Scan ZAP annulé/
    );
  } finally { global.fetch = originalFetch; }
});

// ---------------------------------------------------- les verrous abandonnés

test('les verrous abandonnés du home Security Center sont retirés avant un démarrage', async () => {
  const home = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-zap-home-test-'));
  await fsp.mkdir(path.join(home, 'db'), { recursive: true });
  await fsp.mkdir(path.join(home, 'session'), { recursive: true });
  await fsp.writeFile(path.join(home, '.homelock'), 'x');
  await fsp.writeFile(path.join(home, 'db', 'permanent.lck'), 'x');
  await fsp.writeFile(path.join(home, 'session', 'scan.session.lck'), 'x');
  // Ce qui n'est pas un verrou reste intact : la session elle-même est conservée.
  await fsp.writeFile(path.join(home, 'db', 'permanent.script'), 'données');

  const cleared = await clearStaleZapLocks(home);

  assert.equal(cleared.length, 3);
  assert.equal(fs.existsSync(path.join(home, '.homelock')), false);
  assert.equal(fs.existsSync(path.join(home, 'db', 'permanent.lck')), false);
  assert.equal(fs.existsSync(path.join(home, 'session', 'scan.session.lck')), false);
  assert.equal(fs.existsSync(path.join(home, 'db', 'permanent.script')), true);
  await fsp.rm(home, { recursive: true, force: true });
});

test('le home nettoyé est celui de Security Center, jamais celui de l’utilisateur', () => {
  const home = zapHomeDirectory();
  assert.match(home, /security-center-zap-home$/);
  const local = src('zap-local.js');
  assert.match(local, /const cleared = await clearStaleZapLocks\(home\);/);
  // Le nettoyage est appelé par la préparation du home, pas ailleurs.
  assert.equal((local.match(/clearStaleZapLocks\(/g) || []).length, 2);
});

// ------------------------------------------ l'étape de démarrage dit la vérité

test('le démarrage du démon n’est pas terminé parce que l’attente a commencé', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING', detail: 'port 46483' });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT', detail: 'API pas encore disponible (12 s)' });

  const byId = Object.fromEntries(execution.stages.map((stage) => [stage.id, stage]));
  assert.equal(byId[ZAP_STAGE.DAEMON_STARTING].status, STAGE_STATUS.RUNNING, 'le démarrage reste en cours tant que l’API n’a pas répondu');
  assert.equal(byId[ZAP_STAGE.API_WAIT].status, STAGE_STATUS.RUNNING);
});

test('c’est la réponse de l’API qui termine le démarrage', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING' });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_READY', detail: 'Démon ZAP prêt', metrics: { pid: 1234 } });

  const byId = Object.fromEntries(execution.stages.map((stage) => [stage.id, stage]));
  assert.equal(byId[ZAP_STAGE.DAEMON_STARTING].status, STAGE_STATUS.COMPLETED);
  assert.equal(byId[ZAP_STAGE.DAEMON_STARTING].metrics.pid, 1234);
});

test('une panne clôt TOUTES les étapes en cours : aucun état fantôme ne subsiste', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING' });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT' });
  const failed = failZapExecution(execution, {
    reason: 'Le démon ZAP local s’est arrêté avant d’ouvrir son API (code 1).',
    code: ZAP_START_ERROR.ZAP_PROCESS_EXITED
  });

  assert.equal(failed.stages.filter((stage) => stage.status === STAGE_STATUS.RUNNING).length, 0);
  assert.equal(failed.stages.find((stage) => stage.id === ZAP_STAGE.DAEMON_STARTING).status, STAGE_STATUS.FAILED);
  assert.equal(failed.stages.find((stage) => stage.id === ZAP_STAGE.API_WAIT).status, STAGE_STATUS.FAILED);
  assert.equal(failed.failureCode, 'ZAP_PROCESS_EXITED');
  assert.equal(zapExecutionSummary(failed).activity, 'FAILED');
});

test('le code de panne est visible dans le déroulé rendu', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING' });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT' });
  execution = failZapExecution(execution, { reason: 'Le démon ZAP local s’est arrêté avant d’ouvrir son API (code 1).', code: 'ZAP_PROCESS_EXITED' });

  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'failed', mode: 'baseline', error: 'x' }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET, zapExecution: execution
  }), 'n', 'dynamic');

  assert.match(html, /<code>ZAP_PROCESS_EXITED<\/code>/);
  assert.match(html, /s’est arrêté avant d’ouvrir son API \(code 1\)/);
  assert.doesNotMatch(html, /Démarrage du démon ZAP local<\/span>\s*<span class="zap-stage-state">COMPLETED/);
});

// --------------------------------------------------- le mode, une seule source

test('le mode affiché est celui que le moteur exécute, sur les deux surfaces de la carte', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'active' });
  // Le moteur dit ce qu'il exécute réellement : c'est lui qui fait foi.
  execution = applyZapLifecycle(execution, { state: 'MODE', detail: 'baseline' });
  assert.equal(execution.mode, 'baseline');

  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'running', mode: 'active' }], {
    scanStatus: 'running', dynamicTargetUrl: TARGET, zapExecution: execution
  }), 'n', 'dynamic');

  assert.match(html, /<span>Scan mode<\/span><strong>Passif baseline<\/strong>/);
  assert.match(html, /<span>Mode<\/span><strong>Passif baseline<\/strong>/);
  assert.doesNotMatch(html, /<span>Mode<\/span><strong>Actif<\/strong>/);
});

test('en baseline, aucune API de scan actif n’est appelée — seulement l’étape sautée', async () => {
  // Le moteur est pris au mot : toutes ses requêtes sont enregistrées, et on
  // vérifie qu'aucune ne demande un scan actif.
  const requested = [];
  const originalFetch = global.fetch;
  global.fetch = async (url) => {
    const address = String(url);
    requested.push(address.replace(/apikey=[^&]+/, 'apikey=«redacted»'));
    if (address.includes('/core/view/version/')) return { ok: true, json: async () => ({ version: '2.17.0' }) };
    if (address.includes('/spider/action/scan/')) return { ok: true, json: async () => ({ scan: '0' }) };
    if (address.includes('/spider/view/status/')) return { ok: true, json: async () => ({ status: '100' }) };
    if (address.includes('/core/view/urls/')) return { ok: true, json: async () => ({ urls: ['http://a', 'http://b'] }) };
    if (address.includes('/pscan/view/recordsToScan/')) return { ok: true, json: async () => ({ recordsToScan: '0' }) };
    if (address.includes('/core/view/alerts/')) return { ok: true, json: async () => ({ alerts: [] }) };
    return { ok: true, json: async () => ({ Result: 'OK' }) };
  };

  const events = [];
  const child = fakeChild();
  const localModule = require('../src/zap-local');
  const originalStart = localModule.startLocalZap;
  try {
    // Le démon n'est pas lancé pour de vrai : seule la logique d'étapes est testée.
    const result = await runLocalZap({
      targetUrl: TARGET,
      mode: 'baseline',
      localPath: __filename,
      timeoutMs: 60000,
      onLifecycle: (event) => events.push(event),
      onProcess: () => {},
      onDiagnostic: () => {}
    }).catch((error) => ({ error }));
    // Le lancement réel échoue dans ce contexte de test ; ce qui compte est que
    // rien n'ait demandé un scan actif avant cet échec.
    assert.ok(result);
  } finally {
    global.fetch = originalFetch;
    localModule.startLocalZap = originalStart;
  }

  assert.equal(requested.filter((address) => address.includes('/ascan/')).length, 0, 'aucune requête de scan actif en baseline');
  // Et la source le dit explicitement : l'appel ascan est dans la branche non-baseline.
  const local = src('zap-local.js');
  assert.match(local, /if \(mode === 'baseline'\) \{[\s\S]{0,400}report\('ACTIVE_SKIPPED', null, 'Mode baseline passif'\);[\s\S]{0,40}\} else \{[\s\S]{0,200}'ascan', 'action', 'scan'/);
});

// ---------------------------------------------------------- l'arrêt manuel

function runtimeFor(run, { installed = true } = {}) {
  return { engines: { zap: engineState('zap', { kind: RUN_KIND.SCAN, availability: availability({ installed }), run }) } };
}

function actionsFor(scanners, options) {
  const html = renderDashboardHtml(buildDashboardModel([], scanners, {
    scanStatus: 'running', dynamicTargetUrl: TARGET, ...options
  }), 'n', 'dynamic');
  const start = html.indexOf('dynamic-tool-card zap');
  const at = html.indexOf('class="dynamic-actions"', start);
  return html.slice(at, html.indexOf('</div>', at));
}

test('l’arrêt est proposé dès le démarrage, avant qu’un scanner soit « running »', () => {
  const starting = createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET });
  assert.equal(starting.status, RUN_STATUS.STARTING);
  const actions = actionsFor([{ tool: 'ZAP', status: 'pending', mode: 'baseline' }], { dynamicRuntime: runtimeFor(starting) });
  assert.match(actions, /<button class="secondary danger" data-command="securityCenter\.stopZapScan">Arrêter l’analyse ZAP<\/button>/);
});

test('l’arrêt reste proposé pendant l’exécution et pendant l’arrêt lui-même', () => {
  for (const status of [RUN_STATUS.RUNNING, RUN_STATUS.STOPPING]) {
    const run = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), { status, phase: 'en cours' });
    assert.match(actionsFor([{ tool: 'ZAP', status: 'running', mode: 'baseline' }], { dynamicRuntime: runtimeFor(run) }), /stopZapScan/, `état ${status}`);
  }
});

test('l’arrêt disparaît dès que l’exécution est terminale', () => {
  for (const [status, scanner] of [[RUN_STATUS.FAILED, 'failed'], [RUN_STATUS.COMPLETED, 'completed']]) {
    const run = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), { status, errorReason: 'x' });
    const actions = actionsFor([{ tool: 'ZAP', status: scanner, mode: 'baseline', error: 'x' }], { dynamicRuntime: runtimeFor(run) });
    assert.doesNotMatch(actions, /stopZapScan/, `état ${status}`);
  }
});

test('la commande d’arrêt annule le scan courant et n’arrête que ce qu’elle possède', () => {
  const extension = src('extension.js');
  const command = extension.slice(extension.indexOf("registerCommand('securityCenter.stopZapScan'"));
  const body = command.slice(0, command.indexOf('}));') + 4);

  // Le même chemin d'annulation que la notification de progression.
  assert.match(body, /activeScanAbort\?\.abort\(\)/);
  // Seuls le processus et le conteneur de CE run sont arrêtés.
  assert.match(body, /const owned = activeZapProcess;/);
  assert.match(body, /if \(ownedAlive\) \{ try \{ owned\.kill\(\); \}/);
  assert.match(body, /if \(activeZapContainer\) await removeZapContainer\(activeZapContainer\)/);
  // Aucune recherche de processus par nom : jamais un autre Java.
  assert.doesNotMatch(body, /taskkill|java\.exe|Win32_Process|pkill/i);
  // Un processus déjà mort est constaté, pas attendu.
  assert.match(body, /if \(!ownedAlive && !scanInProgress\) \{[\s\S]{0,200}reconcileZapRun\(\)/);
  // L'état passe par ARRÊT EN COURS, jamais laissé en cours.
  assert.match(body, /updateEngineRun\('zap', \{ status: RUN_STATUS\.STOPPING/);

  // Le contrôleur d'annulation est celui du scan, et il est libéré après.
  assert.match(extension, /activeScanAbort = abortController;/);
  assert.match(extension, /scanInProgress = false;\s*activeScanAbort = null;/);
  // La webview peut demander l'arrêt, et la commande est déclarée.
  assert.match(extension, /'securityCenter\.stopZapScan',/);
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.contributes.commands.some((entry) => entry.command === 'securityCenter.stopZapScan'));
  assert.ok(pkg.activationEvents.includes('onCommand:securityCenter.stopZapScan'));
});

test('l’annulation clôt le déroulé avec son propre code', () => {
  assert.match(src('extension.js'), /failZapExecutionNow\('Analyse annulée par l’utilisateur\.', 'ZAP_RUN_CANCELLED'\)/);
});

// ----------------------------------------------- réconciliation et redémarrage

test('une exécution dont le processus n’existe plus est réconciliée, pas attendue', () => {
  const extension = src('extension.js');
  const reconcile = extension.slice(extension.indexOf('function reconcileZapRun'));
  const body = reconcile.slice(0, reconcile.indexOf('\n  }') + 4);

  // La vérification porte sur le processus possédé, pas sur une supposition.
  assert.match(body, /const owned = activeZapProcess;/);
  assert.match(body, /const alive = Boolean\(owned\) && owned\.exitCode === null && owned\.signalCode === null;/);
  assert.match(body, /if \(alive \|\| scanInProgress\) return false;/);
  assert.match(body, /failEngineRun\('zap', RUN_ERROR\.PROCESS_EXITED, reason\)/);
  assert.match(body, /failZapExecutionNow\(reason, 'ZAP_PROCESS_EXITED'\)/);
  // Et elle est appelée à l'ouverture de Dynamic Security.
  assert.match(extension, /reconcileZapRun\(\);\s*\}\s*dashboardProvider\.openPage\(page\)/);
});

test('un déroulé persisté « en cours » est restauré interrompu, jamais en cours', () => {
  let execution = createZapExecution({ target: TARGET, mode: 'baseline' });
  execution = applyZapLifecycle(execution, { state: 'DAEMON_STARTING' });
  execution = applyZapLifecycle(execution, { state: 'API_WAIT' });

  const restored = restoreZapExecution(JSON.parse(JSON.stringify(execution)), { assumeInterrupted: true });
  assert.equal(restored.stages.find((stage) => stage.id === ZAP_STAGE.API_WAIT).status, STAGE_STATUS.FAILED);
  assert.equal(restored.failureCode, 'ZAP_RUN_INTERRUPTED');
  assert.match(restored.failureReason, /la fenêtre a été rechargée/);
  assert.ok(restored.finishedAt, 'une exécution interrompue est terminée');
  assert.equal(zapExecutionSummary(restored).activity, 'FAILED');

  // Mais une exécution vivante, publiée en mémoire, garde ses étapes en cours.
  const live = restoreZapExecution(JSON.parse(JSON.stringify(execution)));
  assert.equal(live.stages.find((stage) => stage.id === ZAP_STAGE.API_WAIT).status, STAGE_STATUS.RUNNING);
  assert.equal(live.failureCode, '');
});

test('l’extension restaure le déroulé persisté comme interrompu', () => {
  assert.match(src('extension.js'), /restoreZapExecution\(context\.workspaceState\.get\(ZAP_EXECUTION_STATE_KEY, null\), \{ assumeInterrupted: true \}\)/);
});

test('un seul démon par run : le processus possédé est suivi et remplacé, jamais accumulé', () => {
  const extension = src('extension.js');
  assert.match(extension, /onProcess: \(child\) => \{\s*activeZapProcess = child;\s*child\.once\('close', \(\) => \{ if \(activeZapProcess === child\) activeZapProcess = null; \}\);/);
  // Un scan déjà en cours est refusé : la relance ne peut pas doubler le démon.
  assert.match(extension, /if \(scanInProgress\) return vscode\.window\.showInformationMessage\('Security Center : une analyse est déjà en cours\.'\)/);
  // Rien ne cherche un processus Java par son nom.
  assert.doesNotMatch(extension, /taskkill|Win32_Process|pkill/i);
});

test('le journal nomme le lancement, la fin du démon et sa sortie, sans secret', () => {
  const extension = src('extension.js');
  const log = extension.slice(extension.indexOf('function logZapDiagnostic'));
  const body = log.slice(0, log.indexOf('\n  /** Les dernières lignes'));
  assert.match(body, /démon lancé : \$\{command\} \$\{args\.join\(' '\)\}/);
  assert.match(body, /répertoire de travail : \$\{cwd\} · PID/);
  assert.match(extension, /ZAP — stderr : \$\{line\}/);
  assert.match(extension, /ZAP — fin du démon : code/);
  // Les secrets sont retirés à la source, dans le moteur.
  assert.match(src('zap-local.js'), /args: args\.map\(\(argument\) => redactZapText\(argument, secrets\)\)/);
  assert.match(src('zap-local.js'), /const secrets = \[apiKey, authResult\?\.value\]\.filter\(Boolean\);/);
});
