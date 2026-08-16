const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SERVER_CONTAINER, SERVER_IMAGE, SERVER_VOLUMES, LOCAL_SERVER_STATES,
  serverRunArgs, serverStartArgs, serverStopArgs, serverInspectArgs,
  inspectLocalServer, localServerState, startLocalServer, stopLocalServer, waitForLocalServer
} = require('../src/sonarqube-server');
const { renderSonarCard, sonarDiagnosis } = require('../src/scanner-setup-page');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';

function sonar(overrides = {}) {
  return {
    enabled: true, mode: 'auto', serverType: 'local', hostUrl: 'http://127.0.0.1:9000',
    tokenConfigured: true, scannerVersion: '6.2.1', dockerAvailable: true,
    serverOnline: true, serverVersion: '26.8', localServerState: 'ready', ...overrides
  };
}

/** Records every docker invocation without running anything. */
function recorder(responses = {}) {
  const calls = [];
  const exec = async (executable, args) => {
    calls.push({ executable, args });
    const verb = args.find((arg) => ['run', 'start', 'stop', 'inspect'].includes(arg));
    if (responses[verb] instanceof Error) throw responses[verb];
    return { stdout: responses[verb] ?? '', stderr: '' };
  };
  return { exec, calls };
}

// ------------------------------------------------ arguments et sécurité

test('la création du serveur reproduit exactement le compose et reste sur la loopback', () => {
  const args = serverRunArgs();
  assert.ok(args.includes('--name') && args.includes(SERVER_CONTAINER));
  assert.ok(args.includes('127.0.0.1:9000:9000'), 'jamais exposé sur toutes les interfaces');
  assert.equal(args.some((arg) => String(arg).startsWith('0.0.0.0')), false);
  assert.ok(args.includes(SERVER_IMAGE));
  for (const [volume, mountPath] of SERVER_VOLUMES) assert.ok(args.includes(`${volume}:${mountPath}`), `volume ${volume} manquant`);
});

test('aucune commande privilégiée ni socket Docker pour le serveur', () => {
  for (const args of [serverRunArgs(), serverStartArgs(), serverStopArgs(), serverInspectArgs()]) {
    assert.equal(args.includes('--privileged'), false);
    assert.equal(args.some((arg) => String(arg).includes('docker.sock')), false);
    assert.equal(args.some((arg) => String(arg).includes('--cap-add')), false);
  }
});

test('l’arrêt ne supprime jamais de volume ni de conteneur', () => {
  const args = serverStopArgs();
  assert.deepEqual(args.slice(-2), ['stop', SERVER_CONTAINER]);
  for (const forbidden of ['-v', '--volumes', 'rm', 'down', 'prune']) {
    assert.equal(args.includes(forbidden), false, `« ${forbidden} » interdit dans la commande d’arrêt`);
  }
});

test('seul le conteneur géré par Security Center est ciblé', () => {
  for (const args of [serverStartArgs(), serverStopArgs(), serverInspectArgs()]) {
    assert.ok(args.includes(SERVER_CONTAINER), 'le conteneur est nommé explicitement');
    // Aucune sélection large : pas de filtre, pas de joker, pas de « tous ».
    for (const broad of ['--all', '-a', '--filter', '-q', '--quiet']) {
      assert.equal(args.includes(broad), false, `« ${broad} » sélectionnerait d’autres conteneurs`);
    }
    assert.equal(args.some((arg) => String(arg).includes('*')), false);
  }
});

// -------------------------------------------------------------- états

test('un conteneur en cours d’exécution ne suffit pas à déclarer le serveur prêt', () => {
  assert.equal(localServerState({ containerStatus: 'running', health: null }), LOCAL_SERVER_STATES.STARTING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'STARTING' } }), LOCAL_SERVER_STATES.INITIALIZING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'DB_MIGRATION_RUNNING' } }), LOCAL_SERVER_STATES.INITIALIZING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'UP' } }), LOCAL_SERVER_STATES.READY);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'DOWN' } }), LOCAL_SERVER_STATES.ERROR);
});

test('les états hors exécution sont distingués', () => {
  assert.equal(localServerState({ dockerAvailable: false }), LOCAL_SERVER_STATES.DOCKER_UNAVAILABLE);
  assert.equal(localServerState({ containerStatus: null }), LOCAL_SERVER_STATES.MISSING);
  assert.equal(localServerState({ containerStatus: 'exited' }), LOCAL_SERVER_STATES.STOPPED);
  assert.equal(localServerState({ containerStatus: 'created' }), LOCAL_SERVER_STATES.STOPPED);
  assert.equal(localServerState({ containerStatus: 'dead' }), LOCAL_SERVER_STATES.ERROR);
  assert.equal(localServerState({ containerStatus: 'restarting' }), LOCAL_SERVER_STATES.STARTING);
});

test('un conteneur absent est détecté sans erreur', async () => {
  const { exec } = recorder({ inspect: new Error('No such object') });
  assert.equal(await inspectLocalServer({ exec }), null);
});

// ------------------------------------------------------- cycle de vie

test('un serveur déjà installé est redémarré, jamais recréé', async () => {
  const { exec, calls } = recorder({ inspect: 'exited\n' });
  const result = await startLocalServer({ exec });
  assert.equal(result.action, 'started');
  assert.equal(calls.some((call) => call.args.includes('run')), false, 'aucune recréation ne doit avoir lieu');
  assert.ok(calls.some((call) => call.args.includes('start')));
});

test('un serveur inexistant est créé une seule fois', async () => {
  const { exec, calls } = recorder({ inspect: new Error('absent') });
  assert.equal((await startLocalServer({ exec })).action, 'created');
  assert.equal(calls.filter((call) => call.args.includes('run')).length, 1);
});

test('un serveur déjà démarré n’est pas relancé inutilement', async () => {
  const { exec, calls } = recorder({ inspect: 'running\n' });
  assert.equal((await startLocalServer({ exec })).action, 'already-running');
  assert.equal(calls.length, 1, 'seule l’inspection doit avoir lieu');
});

test('l’arrêt n’agit que sur un serveur réellement démarré', async () => {
  const running = recorder({ inspect: 'running\n' });
  assert.equal((await stopLocalServer({ exec: running.exec })).action, 'stopped');
  assert.ok(running.calls.some((call) => call.args.includes('stop')));
  const stopped = recorder({ inspect: 'exited\n' });
  assert.equal((await stopLocalServer({ exec: stopped.exec })).action, 'already-stopped');
  assert.equal(stopped.calls.some((call) => call.args.includes('stop')), false);
  const missing = recorder({ inspect: new Error('absent') });
  assert.equal((await stopLocalServer({ exec: missing.exec })).action, 'missing');
});

// ------------------------------------------------------ attente bornée

test('l’attente se termine dès que SonarQube répond UP', async () => {
  const answers = [{ status: 'STARTING' }, { status: 'STARTING' }, { status: 'UP' }];
  let index = 0;
  const seen = [];
  const outcome = await waitForLocalServer({
    checkStatus: async () => answers[index++],
    pollIntervalMs: 0, delay: async () => {}, onProgress: (state) => seen.push(state)
  });
  assert.equal(outcome.state, LOCAL_SERVER_STATES.READY);
  assert.deepEqual(seen, ['initializing', 'initializing']);
});

test('l’attente est bornée et ne boucle jamais indéfiniment', async () => {
  let attempts = 0;
  let clock = 0;
  const outcome = await waitForLocalServer({
    checkStatus: async () => { attempts += 1; throw new Error('injoignable'); },
    timeoutMs: 1000, pollIntervalMs: 0,
    now: () => (clock += 400), delay: async () => {}
  });
  assert.equal(outcome.state, LOCAL_SERVER_STATES.ERROR);
  assert.equal(outcome.reason, 'timeout');
  assert.ok(attempts >= 1 && attempts < 20, `${attempts} tentatives, borne respectée`);
});

test('l’attente respecte l’annulation', async () => {
  const controller = new AbortController();
  controller.abort();
  const outcome = await waitForLocalServer({ checkStatus: async () => ({ status: 'UP' }), signal: controller.signal });
  assert.equal(outcome.reason, 'cancelled');
});

// ------------------------------------------------------------- rendu

test('sans serveur choisi, les deux scénarios sont proposés et rien n’est démarré', () => {
  const html = renderSonarCard(sonar({ serverType: '', localServerState: '' }), false);
  assert.match(html, /Aucun serveur configuré/);
  assert.match(html, /data-sonar-server="local"/);
  assert.match(html, /data-sonar-server="existing"/);
  assert.match(html, /Installer localement avec Docker/);
  assert.match(html, /Utiliser un serveur existant/);
  assert.equal(sonarDiagnosis(sonar({ serverType: '' })).label, 'Activé — serveur manquant');
  // Aucune fausse connexion affichée.
  assert.equal(html.includes('Connecté'), false);
});

test('serveur local installé mais arrêté propose Démarrer sans réinstaller', () => {
  const html = renderSonarCard(sonar({ localServerState: 'stopped', serverOnline: false }), false);
  assert.match(html, /Serveur local installé — arrêté/);
  assert.match(html, /data-sonar-server-start/);
  assert.match(html, />Démarrer le serveur</);
  assert.equal(html.includes('Installer / démarrer'), false);
  assert.match(html, /« Arrêter » ne supprime aucun volume/);
});

test('serveur local absent propose l’installation contrôlée', () => {
  const html = renderSonarCard(sonar({ localServerState: 'missing', serverOnline: false }), false);
  assert.match(html, /Non installé/);
  assert.match(html, /Installer \/ démarrer le serveur/);
  assert.match(html, /demandera confirmation/);
});

test('serveur local prêt propose Ouvrir et Arrêter, sans redémarrage', () => {
  const html = renderSonarCard(sonar({ localServerState: 'ready' }), false);
  assert.match(html, /<dt>Type<\/dt><dd>Serveur local Docker<\/dd>/);
  assert.match(html, /<dt>État<\/dt><dd>Prêt<\/dd>/);
  assert.match(html, /data-sonar-open/);
  assert.match(html, /data-sonar-server-stop/);
  assert.equal(html.includes('data-sonar-server-start'), false, 'aucun redémarrage inutile');
});

test('démarrage et initialisation affichent une progression, pas un état prêt', () => {
  for (const state of ['starting', 'initializing']) {
    const html = renderSonarCard(sonar({ localServerState: state, serverOnline: false }), false);
    assert.match(html, /spinner/);
    assert.match(html, /Security Center attend que le serveur réponde réellement/);
    assert.equal(html.includes('<dt>État</dt><dd>Prêt</dd>'), false);
  }
});

test('Docker absent explique la contrainte et laisse le serveur existant possible', () => {
  const html = renderSonarCard(sonar({ dockerAvailable: false, localServerState: 'docker-unavailable', serverOnline: false }), false);
  assert.match(html, /Docker est requis pour le serveur SonarQube local/);
  assert.match(html, /data-sonar-server="existing"/);
  assert.equal(html.includes('data-sonar-server-start'), false);
});

test('serveur existant n’expose jamais d’arrêt de conteneur', () => {
  const html = renderSonarCard(sonar({ serverType: 'existing', hostUrl: 'https://sonarqube.company.com' }), false);
  assert.match(html, /<dt>Type<\/dt><dd>Serveur existant<\/dd>/);
  assert.match(html, /sonarqube\.company\.com/);
  assert.equal(html.includes('data-sonar-server-stop'), false, 'jamais d’arrêt d’un serveur d’entreprise');
  assert.equal(html.includes('data-sonar-server-start'), false);
  assert.match(html, /data-sonar-server-url/);
});

test('les deux composants restent visuellement distincts', () => {
  const html = renderSonarCard(sonar(), false);
  assert.match(html, /<h3 class="sonar-section">SonarScanner<small>Analyse le code du workspace/);
  assert.match(html, /<h3 class="sonar-section">Serveur SonarQube<small>Reçoit, traite et expose/);
  assert.match(html, /<h3 class="sonar-section">Authentification/);
  // Le mode du scanner ne pilote pas le serveur.
  assert.match(html, /<dt>Mode configuré<\/dt>/);
  assert.match(html, /<dt>Type<\/dt><dd>Serveur local Docker<\/dd>/);
});

// ------------------------------------------------------- combinaisons

const COMBINATIONS = [
  ['scanner Local + serveur local Docker', { mode: 'local', scannerVersion: '6.2.1', serverType: 'local', localServerState: 'ready' }, 'Local', 'Serveur local Docker'],
  ['scanner Docker + serveur local Docker', { mode: 'docker', serverType: 'local', localServerState: 'ready' }, 'Docker', 'Serveur local Docker'],
  ['scanner Local + serveur distant', { mode: 'local', scannerVersion: '6.2.1', serverType: 'existing', hostUrl: 'https://sonarqube.company.com' }, 'Local', 'Serveur existant'],
  ['scanner Docker + serveur distant', { mode: 'docker', serverType: 'existing', hostUrl: 'https://sonarqube.company.com' }, 'Docker', 'Serveur existant'],
  ['scanner Auto → Local + serveur local', { mode: 'auto', scannerVersion: '6.2.1', serverType: 'local', localServerState: 'ready' }, 'Local', 'Serveur local Docker'],
  ['scanner Auto → Docker + serveur distant', { mode: 'auto', scannerVersion: '', serverType: 'existing', hostUrl: 'https://sonarqube.company.com' }, 'Docker', 'Serveur existant']
];

for (const [name, overrides, expectedScanner, expectedServer] of COMBINATIONS) {
  test(`${name} : les deux choix restent indépendants et prêts`, () => {
    const model = sonar(overrides);
    const html = renderSonarCard(model, false);
    assert.match(html, new RegExp(`<dt>Mode utilisé</dt><dd>${expectedScanner}</dd>`));
    assert.match(html, new RegExp(`<dt>Type</dt><dd>${expectedServer}</dd>`));
    assert.equal(sonarDiagnosis(model).state, 'ready', `${name} doit être prêt`);
  });
}

// --------------------------------------------------- politique projet

test('la politique projet prime et l’UI ne prétend pas Prêt', () => {
  const blocked = sonarDiagnosis(sonar({ blockedByProjectPolicy: true }));
  assert.equal(blocked.label, 'Désactivé par la politique projet');
  assert.match(blocked.hint, /security-center\.yml/);
  assert.match(renderSonarCard(sonar({ blockedByProjectPolicy: true }), false), /Désactivé par la politique projet/);
});

test('un token refusé par le serveur est signalé sans être exposé', () => {
  const model = sonar({ authenticationValid: false });
  assert.equal(sonarDiagnosis(model).label, 'Token refusé');
  const html = renderSonarCard(model, false);
  assert.match(html, /refusé par le serveur/);
  assert.equal(html.includes(TOKEN), false);
  assert.equal(html.includes('squ_'), false);
});

test('aucun identifiant administrateur n’apparaît dans la carte', () => {
  const html = renderSonarCard(sonar({ hostUrl: 'http://admin:motdepasse@127.0.0.1:9000' }), false);
  for (const value of ['motdepasse', 'admin:', 'password', 'Mot de passe']) {
    assert.equal(html.includes(value), false, `${value} ne doit jamais apparaître`);
  }
});

test('les actions du serveur sont verrouillées pendant un démarrage en cours', () => {
  const html = renderSonarCard(sonar({ localServerState: 'stopped', serverOnline: false, busy: true }), false);
  const buttons = html.match(/<button[^>]*>/g) || [];
  assert.ok(buttons.length > 0);
  assert.ok(buttons.every((button) => button.includes('disabled')), 'aucun double-clic possible pendant une opération');
});
