'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { JAVA_PROBE_ARGS, interpretJavaProbe, detectJavaRuntime } = require('../src/java-runtime');
const { zapAvailabilityFrom } = require('../src/zap-engines');
const { engineState, RUN_KIND, RUN_STATUS, createRun, transitionRun } = require('../src/dynamic-runtime');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (name) => fs.readFileSync(path.join(__dirname, '..', 'src', name), 'utf8');
const ZAP_BAT = 'C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat';
const TARGET = 'http://192.168.222.132:3000';

/**
 * La sortie réellement capturée sur le poste quand `java -version` sortait en
 * code 1 : la JVM s'identifie, puis n'obtient pas sa mémoire.
 */
const SATURATED_PAGEFILE_OUTPUT = [
  "OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(0x000000060b000000, 528482304, 0) failed;",
  "error='Le fichier de pagination est insuffisant pour terminer cette operation' (DOS error/errno=1455)",
  '#',
  '# There is insufficient memory for the Java Runtime Environment to continue.'
].join('\n');

const BANNER = 'openjdk version "17.0.8.1" 2023-08-24\nOpenJDK Runtime Environment Temurin-17.0.8.1+1';

function detectedFor(java, { localPath = ZAP_BAT, dockerVersion = '' } = {}) {
  return {
    localPath,
    hasJava: java.found,
    javaVersion: java.version,
    javaWarning: java.warning,
    javaReason: java.reason,
    dockerVersion,
    localUsable: Boolean(localPath) && java.found === true,
    dockerUsable: Boolean(dockerVersion)
  };
}

function badgeFor(detected, engine = 'auto') {
  const tool = zapAvailabilityFrom(detected, engine);
  return { tool, status: engineState('zap', { kind: RUN_KIND.SCAN, availability: tool }).status };
}

// ------------------------------------------------------------- la sonde Java

test('la sonde ne réserve pas le tas par défaut de la JVM', () => {
  // Une question d'existence ne doit pas dépendre de la mémoire engageable.
  assert.deepEqual([...JAVA_PROBE_ARGS], ['-Xmx32m', '-version']);
  assert.match(src('extension.js'), /return detectJavaRuntime\(\{ run: execFileAsync \}\);/);
});

test('une JVM qui s’identifie est trouvée, même sortie en code non nul', () => {
  // C'est la condition observée : code 1, fichier de pagination saturé.
  const probe = interpretJavaProbe({
    exitCode: 1,
    stderr: SATURATED_PAGEFILE_OUTPUT,
    error: Object.assign(new Error('Command failed: java -version'), { code: 1 })
  });

  assert.equal(probe.found, true, 'Java est appelable : la JVM a répondu');
  assert.match(probe.warning, /n’a pas pu réserver sa mémoire/);
  assert.match(probe.warning, /fichier de pagination/);
  assert.equal(probe.reason, '', 'une remarque n’est pas une raison d’indisponibilité');
});

test('une JVM normale est trouvée avec sa version', () => {
  const probe = interpretJavaProbe({ exitCode: 0, stderr: BANNER });
  assert.equal(probe.found, true);
  assert.equal(probe.version, '17.0.8.1');
  assert.equal(probe.warning, '');
});

test('une sortie non nulle avec bannière de version garde la version et signale le code', () => {
  const probe = interpretJavaProbe({ exitCode: 2, stderr: `${BANNER}\nquelque chose d’autre` });
  assert.equal(probe.found, true);
  assert.equal(probe.version, '17.0.8.1');
  assert.match(probe.warning, /code 2/);
});

test('Java réellement absent reste absent, avec sa raison', () => {
  const missing = interpretJavaProbe({
    exitCode: 1, stderr: '', error: Object.assign(new Error('spawn java ENOENT'), { code: 'ENOENT' })
  });
  assert.equal(missing.found, false);
  assert.match(missing.reason, /n’est pas installé, ou n’est pas dans le PATH/);

  const mute = interpretJavaProbe({ exitCode: 127, stderr: 'commande introuvable' });
  assert.equal(mute.found, false);
  assert.match(mute.reason, /code 127/);
});

test('la sonde ne lève jamais : une panne d’exécution est une observation', async () => {
  const thrown = await detectJavaRuntime({ run: async () => { throw Object.assign(new Error('spawn java ENOENT'), { code: 'ENOENT' }); } });
  assert.equal(thrown.found, false);
  const noRunner = await detectJavaRuntime({});
  assert.equal(noRunner.found, false);
  assert.match(noRunner.reason, /Aucun exécuteur/);

  const ok = await detectJavaRuntime({ run: async () => ({ stdout: '', stderr: BANNER }) });
  assert.deepEqual(ok, { found: true, version: '17.0.8.1', warning: '', reason: '' });
});

// ------------------------------------------------- la disponibilité qui en suit

test('ZAP local installé + Java appelable ⇒ READY, Docker absent ou non', () => {
  for (const dockerVersion of ['', '24.0.7']) {
    const { tool, status } = badgeFor(detectedFor(interpretJavaProbe({ exitCode: 0, stderr: BANNER }), { dockerVersion }));
    assert.equal(tool.usable, true, `docker « ${dockerVersion || 'absent'} »`);
    assert.equal(status, RUN_STATUS.READY);
    assert.equal(tool.reason, '', 'un moteur utilisable n’a pas de raison d’indisponibilité');
  }
});

test('la JVM saturée ne rend pas ZAP local indisponible — elle ajoute une remarque', () => {
  const java = interpretJavaProbe({
    exitCode: 1, stderr: SATURATED_PAGEFILE_OUTPUT,
    error: Object.assign(new Error('Command failed'), { code: 1 })
  });
  const { tool, status } = badgeFor(detectedFor(java));

  assert.equal(status, RUN_STATUS.READY);
  assert.equal(tool.reason, '');
  // La remarque est portée par le détail, là où la carte l'affiche sans alarmer.
  assert.match(tool.detail, /fichier de pagination Windows est saturé/);
  assert.match(tool.detail, /Moteur Local/);
});

test('Docker n’est qu’une alternative : son absence ne retire rien à un local valide', () => {
  const java = interpretJavaProbe({ exitCode: 0, stderr: BANNER });
  const { tool } = badgeFor(detectedFor(java, { dockerVersion: '' }));
  const local = tool.alternatives.find((entry) => entry.name === 'ZAP local');
  const docker = tool.alternatives.find((entry) => entry.name === 'Moteur Docker');

  assert.equal(local.satisfied, true);
  assert.equal(docker.satisfied, false);
  assert.equal(tool.usable, true);
  // Le détail de l'alternative locale cite le chemin et la version de Java.
  assert.match(local.detail, /zap\.bat/);
  assert.match(local.detail, /Java 17\.0\.8\.1/);
});

test('la raison nomme ce qui manque vraiment, jamais les deux en bloc', () => {
  const javaOnly = badgeFor(detectedFor(interpretJavaProbe({ exitCode: 0, stderr: BANNER }), { localPath: '' })).tool;
  assert.match(javaOnly.reason, /Java est disponible \(17\.0\.8\.1\) mais aucune installation ZAP locale/);

  const zapOnly = badgeFor(detectedFor(interpretJavaProbe({
    exitCode: 1, stderr: '', error: Object.assign(new Error('spawn java ENOENT'), { code: 'ENOENT' })
  }))).tool;
  assert.match(zapOnly.reason, /ZAP local est installé/);
  assert.match(zapOnly.reason, /Java n’a pas répondu/);
  assert.doesNotMatch(zapOnly.reason, /Installez ZAP,/, 'on n’envoie pas installer un ZAP déjà installé');

  const neither = badgeFor(detectedFor({ found: false, version: '', warning: '', reason: '' }, { localPath: '' })).tool;
  assert.match(neither.reason, /Ni ZAP local \(avec Java\) ni le moteur Docker/);
});

// ---------------------------------- rien ne vient d'un historique ni d'un état

test('la disponibilité ne se déduit d’aucun scan, d’aucun processus, d’aucun run passé', () => {
  const java = interpretJavaProbe({ exitCode: 0, stderr: BANNER });
  const detected = detectedFor(java);

  // Un run terminé en échec : l'outil reste utilisable, l'état redevient READY.
  const failed = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), {
    status: RUN_STATUS.FAILED, errorReason: 'Le démon ZAP local s’est arrêté avant d’ouvrir son API (code 1).'
  });
  const tool = zapAvailabilityFrom(detected, 'auto');
  const state = engineState('zap', { kind: RUN_KIND.SCAN, availability: tool, run: failed });
  assert.equal(state.status, RUN_STATUS.READY);
  assert.equal(state.reason, '', 'la raison d’un échec passé n’est pas la raison d’indisponibilité courante');
  // L'échec reste lisible, ailleurs : dans l'historique du run.
  assert.match(state.execution.lastRun.errorReason, /s’est arrêté avant d’ouvrir son API/);

  // Et la détection ne lit rien d'autre que ce qu'on lui passe.
  const engines = src('zap-engines.js');
  const builder = engines.slice(engines.indexOf('function zapAvailabilityFrom'));
  assert.doesNotMatch(builder.slice(0, builder.indexOf('\n}')), /scan|history|lastRun|workspaceState|previous/i);
});

test('la détection est refaite à chaque appel, sans valeur persistée', () => {
  const extension = src('extension.js');
  const detector = extension.slice(extension.indexOf('async function zapEnginesDetected'));
  const body = detector.slice(0, detector.indexOf('\n  }') + 4);

  // Trois mesures, faites maintenant.
  assert.match(body, /detectLocalZap\(configured\.get\('zap\.localPath', ''\)\)/);
  assert.match(body, /javaRuntime\(\)\.catch/);
  assert.match(body, /ensureDockerAvailable\(8000\)/);
  // Rien n'est lu d'un état persisté ni d'un historique.
  assert.doesNotMatch(body, /workspaceState|globalState|currentScanStatuses|lastRun|dynamicEngines/);
});

test('la disponibilité est publiée à l’activation sans dépendre du backend', () => {
  const extension = src('extension.js');
  assert.match(extension, /zapAvailability\(\)\s*\.then\(\(tool\) => \{ setEngineAvailability\('zap', tool\); publishDashboard\(\); \}\)/);
  // Et la mesure de l'ouverture de Dynamic Security reste en place.
  assert.match(extension, /zapAvailability\(\)\.then\(\(tool\) => \{ setEngineAvailability\('zap', tool\); publishDashboard\(\); \}\)\.catch\(\(\) => \{\}\);/);
});

// --------------------------------------------------------------- diagnostics

test('le diagnostic de disponibilité est écrit à chaque évaluation, sans secret', () => {
  const extension = src('extension.js');
  const logger = extension.slice(extension.indexOf('function logZapAvailability'));
  const body = logger.slice(0, logger.indexOf('\n  }') + 4);

  assert.match(body, /ZAP availability :/);
  assert.match(body, /Java: \$\{detected\.hasJava \? /);
  assert.match(body, /Local ZAP: \$\{detected\.localPath \|\| 'not detected'\}/);
  assert.match(body, /Local usable: \$\{detected\.localUsable \? 'yes' : 'no'\}/);
  assert.match(body, /Docker usable: \$\{detected\.dockerUsable \? /);
  assert.match(body, /Final: \$\{tool\.usable \? RUN_STATUS\.READY : RUN_STATUS\.UNAVAILABLE\}/);
  // Une JVM dégradée est dite, pas masquée.
  assert.match(body, /Java warning: \$\{detected\.javaWarning\}/);
  // Aucun secret : ni clé, ni jeton, ni mot de passe.
  assert.doesNotMatch(body, /apiKey|api\.key|secret|token|password/i);
  // Et il est appelé par la mesure elle-même.
  assert.match(extension, /logZapAvailability\(detected, tool\);\s*return tool;/);
});

// ------------------------------------------------------------- le badge rendu

test('la carte affiche PRÊT pour un ZAP local valide, malgré un échec précédent', () => {
  const java = interpretJavaProbe({ exitCode: 0, stderr: BANNER });
  const tool = zapAvailabilityFrom(detectedFor(java), 'auto');
  const failed = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), {
    status: RUN_STATUS.FAILED, errorReason: 'ZAP_PROCESS_EXITED'
  });
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'failed', mode: 'baseline', error: 'Le démon ZAP local s’est arrêté.' }], {
    scanStatus: 'completed',
    dynamicTargetUrl: TARGET,
    dynamicRuntime: { engines: { zap: engineState('zap', { kind: RUN_KIND.SCAN, availability: tool, run: failed }) } }
  }), 'n', 'dynamic');

  assert.match(html, /<span class="tool-status ready">PRÊT<\/span>/);
  assert.doesNotMatch(html, /Ni ZAP local \(avec Java\) ni le moteur Docker/);
  // L'échec précédent reste visible, et l'analyse reste lançable.
  assert.match(html, /Le démon ZAP local s’est arrêté\./);
  assert.match(html, /data-command="securityCenter\.scanZap"/);
});

test('un ZAP réellement indisponible le reste, avec la raison mesurée', () => {
  const tool = zapAvailabilityFrom(detectedFor({ found: false, version: '', warning: '', reason: 'Java n’est pas installé, ou n’est pas dans le PATH.' }), 'auto');
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    scanStatus: 'idle',
    dynamicTargetUrl: TARGET,
    dynamicRuntime: { engines: { zap: engineState('zap', { kind: RUN_KIND.SCAN, availability: tool }) } }
  }), 'n', 'dynamic');

  assert.match(html, /INDISPONIBLE/);
  assert.match(html, /ZAP local est installé/);
  assert.match(html, /Java n’a pas répondu/);
});
