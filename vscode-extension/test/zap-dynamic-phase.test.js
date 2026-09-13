'use strict';

// ============================================================================
// Phase ZAP de Dynamic Security : disponibilité réelle des deux moteurs, bouton,
// cycle de vie DynamicRun, destination des findings, nettoyage.
// ============================================================================

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { availability, engineState, restoreRun, reconcileRun, RUN_KIND, RUN_STATUS, RUN_ERROR } = require('../src/dynamic-runtime');
const { zapEngineChoice, zapEngineLabel, zapAvailabilityFrom, zapPhaseText } = require('../src/zap-engines');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { scannerIdForTool } = require('../src/scanner-presentation');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

/** La carte ZAP de la page Dynamic Security, isolée du reste. */
function zapCard(options = {}) {
  const html = renderDashboardHtml(
    buildDashboardModel([], options.scanners || [], {
      workspace: 'demo', dynamicTargetUrl: 'http://192.168.222.132:3000', ...options
    }),
    'nonce', 'dynamic', 'light', {}, {}
  );
  const start = html.indexOf('dynamic-tool-card zap');
  assert.ok(start > 0, 'carte ZAP introuvable');
  return html.slice(start, html.indexOf('</article>', start));
}

/** Un instantané DynamicRun minimal pour la carte ZAP. */
function zapRunModel(tool, status = 'READY', execution = {}) {
  return {
    engines: {
      zap: {
        engine: 'zap', kind: 'scan', status, reason: status === 'UNAVAILABLE' ? tool.reason : '',
        statusLabel: { READY: 'PRÊT', RUNNING: 'EN COURS', UNAVAILABLE: 'INDISPONIBLE' }[status] || status,
        availability: tool,
        execution: {
          neverExecuted: true, runId: '', status: 'IDLE', phase: '', progress: null,
          target: 'http://192.168.222.132:3000', startedAt: null, finishedAt: null, lastActivity: null,
          requestCount: null, findingCount: null, errorCode: '', errorReason: '', lastRun: null, ...execution
        }
      }
    }
  };
}

// ------------------------------------------------------- disponibilité réelle

test('ZAP : un moteur suffit — la disponibilité n’est plus la somme des deux', () => {
  // La cause du « INDISPONIBLE » affiché : les deux moteurs étaient décrits comme
  // des prérequis, donc cumulatifs. Ce sont des alternatives.
  const localSeul = availability({
    installed: true,
    alternatives: [
      { name: 'ZAP local', satisfied: true, detail: 'C:/Program Files/ZAP' },
      { name: 'Moteur Docker', satisfied: false, detail: 'Moteur Docker indisponible' }
    ]
  });
  assert.equal(localSeul.usable, true, 'un ZAP local utilisable suffit');
  assert.equal(localSeul.reason, '', 'un outil utilisable n’a aucune raison à donner');

  const aucun = availability({
    installed: false,
    alternatives: [
      { name: 'ZAP local', satisfied: false, detail: 'Aucune installation locale détectée' },
      { name: 'Moteur Docker', satisfied: false, detail: 'Moteur Docker indisponible' }
    ]
  });
  assert.equal(aucun.usable, false);
  assert.match(aucun.reason, /ZAP local/);
  assert.match(aucun.reason, /Docker/);

  // Les prérequis, eux, restent cumulatifs : c’est leur sens, et les autres
  // moteurs s’y appuient.
  const cumulatif = availability({
    installed: true,
    prerequisites: [
      { name: 'Binaire', satisfied: true },
      { name: 'Templates', satisfied: false }
    ]
  });
  assert.equal(cumulatif.usable, false);
  assert.match(cumulatif.reason, /Prérequis manquant : Templates/);
});

test('ZAP : la carte est PRÊTE dès qu’un moteur est utilisable', () => {
  const local = zapAvailabilityFrom({
    localUsable: true, hasJava: true, localPath: 'C:/Program Files/ZAP/Zed Attack Proxy/zap.bat',
    dockerUsable: false, dockerVersion: ''
  }, 'auto');
  assert.equal(local.usable, true);
  assert.equal(local.reason, '');
  assert.match(local.detail, /^Moteur Local · /);
  assert.equal(engineState('zap', { kind: RUN_KIND.SCAN, availability: local }).status, RUN_STATUS.READY);
  // Docker manquant reste visible comme alternative non satisfaite, sans bloquer.
  assert.deepEqual(local.alternatives.map((item) => item.satisfied), [true, false]);

  const docker = zapAvailabilityFrom({ localUsable: false, dockerUsable: true, dockerVersion: '29.2.1' }, 'auto');
  assert.equal(docker.usable, true);
  assert.equal(docker.detail, 'Moteur Docker 29.2.1');
  assert.equal(engineState('zap', { kind: RUN_KIND.SCAN, availability: docker }).status, RUN_STATUS.READY);

  const aucun = zapAvailabilityFrom({ localUsable: false, dockerUsable: false }, 'auto');
  const carte = engineState('zap', { kind: RUN_KIND.SCAN, availability: aucun });
  assert.equal(carte.status, RUN_STATUS.UNAVAILABLE);
  assert.match(carte.reason, /Ni ZAP local/);
  assert.match(carte.reason, /moteur Docker/);
  // Chacun des deux chemins est nommé, avec ce qui lui manque.
  assert.deepEqual(aucun.alternatives.map((item) => item.name), ['ZAP local', 'Moteur Docker']);

  // Java manquant devant un ZAP installé nomme la vraie cause, et la raison de
  // la sonde quand elle en a une.
  const sansJava = zapAvailabilityFrom({ localUsable: false, hasJava: false, localPath: 'C:/ZAP/zap.bat', dockerUsable: false }, 'auto');
  assert.equal(sansJava.alternatives[0].detail, 'Java indisponible');
  const sansJavaDit = zapAvailabilityFrom({
    localUsable: false, hasJava: false, localPath: 'C:/ZAP/zap.bat', dockerUsable: false,
    javaReason: 'Java n’est pas installé, ou n’est pas dans le PATH.'
  }, 'auto');
  assert.equal(sansJavaDit.alternatives[0].detail, 'Java indisponible : Java n’est pas installé, ou n’est pas dans le PATH.');
});

test('ZAP : la disponibilité vient de la détection, jamais de l’historique de scans', () => {
  const extension = src('extension.js');
  const detection = extension.match(/async function zapEnginesDetected\(\)[\s\S]*?\n  \}/)[0];
  // Trois faits indépendants, mesurés : Java, l’installation locale, Docker.
  assert.match(detection, /detectLocalZap\(configured\.get\('zap\.localPath', ''\)\)/);
  // La sonde Java est interrogée pour ce qu'elle a observé, pas pour un booléen :
  // une JVM qui s'identifie sans pouvoir réserver sa mémoire reste une JVM.
  assert.match(detection, /javaRuntime\(\)/);
  assert.match(detection, /ensureDockerAvailable\(8000\)/);
  // Aucun de ces faits ne consulte `model.scanners`, qui décrit l’historique.
  assert.ok(!detection.includes('scanners'), 'la détection consulte l’historique de scans');
});

// --------------------------------------------------------- choix du moteur

test('ZAP : le moteur choisi est celui qui peut réellement s’exécuter', () => {
  assert.equal(zapEngineChoice('auto', { localUsable: true, dockerUsable: true }).engine, 'local');
  assert.equal(zapEngineChoice('auto', { localUsable: false, dockerUsable: true }).engine, 'docker');
  assert.equal(zapEngineChoice('auto', { localUsable: false, dockerUsable: false }).engine, 'auto');

  // Le moteur configuré est respecté tant qu’il est utilisable.
  assert.deepEqual(
    zapEngineChoice('local', { localUsable: true, dockerUsable: true }),
    { engine: 'local', requested: 'local', substituted: false }
  );

  // Docker demandé mais éteint, ZAP local installé : le scan a lieu, et la
  // substitution est dite au lieu d’être silencieuse.
  assert.deepEqual(
    zapEngineChoice('docker', { localUsable: true, dockerUsable: false }),
    { engine: 'local', requested: 'docker', substituted: true }
  );

  // Aucun des deux : le moteur demandé est conservé, et c’est `runZap` qui dira
  // l’échec réel plutôt qu’une raison devinée à sa place.
  assert.deepEqual(zapEngineChoice('docker', {}), { engine: 'docker', requested: 'docker', substituted: false });

  assert.equal(zapEngineLabel('local'), 'Local');
  assert.equal(zapEngineLabel('docker'), 'Docker');
  assert.equal(zapEngineLabel('auto'), '');
});

// ------------------------------------------------------------------- bouton

test('ZAP : le bouton ne dépend plus de ZAP local, mais de la disponibilité mesurée', () => {
  const extension = src('extension.js');
  const command = extension.match(/registerCommand\('securityCenter\.scanZap'[\s\S]*?\n  \}\)\);/)[0];
  // L’ancienne condition refusait le scan sans ZAP local, même quand le moteur
  // Docker aurait suffi.
  assert.ok(!command.includes('!(await javaAvailable()) || !detectLocalZap()'), 'le bouton exige encore ZAP local');
  assert.match(command, /const tool = await zapAvailability\(\)/);
  assert.match(command, /if \(tool && !tool\.usable\)/);
  // La mesure qui décide est celle qui est publiée sur la carte.
  assert.match(command, /setEngineAvailability\('zap', tool\)/);
  // Le scan reste celui du pipeline existant, avec son préflight et ses contrôles.
  assert.match(command, /executeCommand\('securityCenter\.scanWorkspace', \['ZAP'\]\)/);
  // ZAP désactivé dans les réglages est dit, au lieu d’un scan ignoré en silence.
  assert.match(command, /zap\.enabled/);
});

test('ZAP : l’autorisation de cible et les contrôles existants restent en place', () => {
  const extension = src('extension.js');
  const slot = extension.match(/if \(zapRequested\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  // Une cible distante non autorisée arrête tout avant qu’un moteur démarre.
  assert.match(slot, /assertTargetAuthorized\(cfg\.get\('zap\.targetUrl'/);
  assert.match(slot, /allowRemote: cfg\.get\('zap\.targetMode', TARGET_MODE\.LOCAL\) === TARGET_MODE\.REMOTE/);
  assert.match(slot, /&& cfg\.get\('zap\.remoteAuthorized', false\) === true/);
  // Les réglages, l’authentification et les exclusions restent ceux du pipeline.
  assert.match(slot, /excludedRoutes: projectPolicy\?\.exclusions\.zap_routes \|\| \[\]/);
  assert.match(slot, /resolvedAuth: resolvedDynamicAuth/);
  // La normalisation et la persistance ne changent pas de chemin.
  assert.match(slot, /normalize: \(payload, workspacePath\) => normalizeZapOutput\(/);
});

// -------------------------------------------------------- cycle de vie réel

test('ZAP : l’exécution publie son moteur et ses étapes dans DynamicRun', () => {
  const extension = src('extension.js');
  const slot = extension.match(/if \(zapRequested\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  // Le moteur est dit avant que quoi que ce soit démarre.
  assert.match(slot, /onEngine: \(engine\) => \{/);
  assert.match(slot, /zapEngineUsed = zapEngineLabel\(engine\)/);
  // Chaque observation de ZAP devient une phase visible sur la carte.
  assert.match(slot, /const phase = zapPhaseText\(event, zapEngineUsed\)/);
  assert.match(slot, /updateEngineRun\('zap', \{ status: RUN_STATUS\.RUNNING, phase, progress: event\?\.progress \?\? null \}\)/);
  // La campagne ZAP existante continue de recevoir les mêmes événements.
  assert.match(slot, /publishDynamicLifecycle\(event\)/);
  // Le moteur retenu vient de la disponibilité mesurée juste avant le scan.
  assert.match(slot, /const choice = zapEngineChoice\(projectPolicy\?\.zapEngine \|\| 'auto', detectedEngines \|\| \{\}\)/);
  assert.match(slot, /engine: choice\.engine/);
  // STARTING → RUNNING → COMPLETED ou FAILED : le socle commun, inchangé.
  assert.match(extension, /beginEngineRun\(dynamicEngine, \{ kind: RUN_KIND\.SCAN[^\n]*dynamicEngine === 'zap' \? 'Preparing'/);
  assert.match(extension, /setEngineRun\(dynamicEngine, completeRun\(finished, \{ findingCount: scanFindings\.length/);
  assert.match(extension, /failEngineRun\(dynamicEngineOf\(scan\.tool\), RUN_ERROR\.SCAN_FAILED, error\.message\)/);
  assert.match(extension, /failEngineRun\(dynamicEngineOf\(scan\.tool\), RUN_ERROR\.CANCELLED/);
  // Le moteur utilisé rejoint l’identité du scanner, donc la carte et l’historique.
  assert.match(extension, /zapEngineUsed \? \{ engine: zapEngineUsed \} : \{\}/);
});

test('ZAP : les étapes sont dites, jamais une progression inventée', () => {
  // Les cinq étapes que la carte annonce.
  assert.equal(zapPhaseText({ state: 'STARTING' }), 'Preparing');
  assert.equal(zapPhaseText({ state: 'SPIDERING' }), 'Spidering / baseline');
  assert.equal(zapPhaseText({ state: 'PASSIVE_WAIT' }), 'Passive analysis');
  assert.equal(zapPhaseText({ state: 'ACTIVE_SCANNING' }), 'Active scanning');
  assert.equal(zapPhaseText({ state: 'COLLECTING_RESULTS' }), 'Collecting alerts');
  // Sans pourcentage, aucun pourcentage n’est affiché : pas même zéro.
  assert.ok(!zapPhaseText({ state: 'SPIDERING', progress: null }).includes('%'));
  assert.ok(!zapPhaseText({ state: 'SPIDERING', progress: undefined }).includes('%'));
  // Avec un pourcentage réel — celui de l’API ZAP — il est repris tel quel.
  assert.equal(zapPhaseText({ state: 'ACTIVE_SCANNING', progress: 42 }, 'Local'), 'Moteur Local · Active scanning 42 %');
  assert.equal(zapPhaseText({ state: 'PASSIVE_WAIT', progress: 0 }, 'Local'), 'Moteur Local · Passive analysis 0 %');
  // Le détail que ZAP donne est conservé.
  assert.match(zapPhaseText({ state: 'PASSIVE_WAIT', progress: 50, detail: '12 enregistrement(s) en file' }), /12 enregistrement/);
  // Un état inconnu ne devient pas une phase inventée.
  assert.equal(zapPhaseText({ state: 'INCONNU' }), '');
  assert.equal(zapPhaseText(null), '');
});

test('ZAP : le moteur Docker rend compte de ses étapes sans réécrire le scanner', () => {
  const zap = src('zap.js');
  // Le chemin Docker ne disait rien entre le lancement et le rapport.
  assert.match(zap, /report\('STARTING', null, 'Préparation du conteneur ZAP'\)/);
  assert.match(zap, /report\('SPIDERING', null, `Docker · \$\{mode === 'active'/);
  assert.match(zap, /report\('COLLECTING_RESULTS', null, 'Lecture du rapport ZAP'\)/);
  // Aucun pourcentage n’accompagne ces étapes : le conteneur n’en publie pas.
  assert.ok(!/report\('SPIDERING', [0-9]/.test(zap), 'une progression est inventée côté Docker');
  // Le moteur local garde ses rappels de cycle de vie, inchangés.
  const local = src('zap-local.js');
  assert.match(local, /report\('SPIDERING', percent\)/);
  assert.match(local, /report\('PASSIVE_WAIT', percent/);
  assert.match(local, /report\('ACTIVE_SCANNING', percent\)/);
  assert.match(local, /report\('COLLECTING_RESULTS'\)/);
});

// ---------------------------------------------------------------- findings

test('ZAP : la carte annonce le moteur réellement utilisé', () => {
  const local = zapAvailabilityFrom({ localUsable: true, hasJava: true, localPath: 'C:/ZAP/zap.bat' }, 'auto');
  const pret = zapCard({ dynamicRuntime: zapRunModel(local, 'READY') });
  assert.match(pret, /PRÊT/);
  assert.ok(!pret.includes('Prérequis manquant'), 'la carte annonce encore un prérequis manquant');
  assert.match(pret, /Moteur Local · C:\/ZAP\/zap\.bat/);

  // Après un scan, c’est le moteur qui l’a exécuté que la carte nomme.
  const apres = zapCard({
    scanners: [{ tool: 'ZAP', status: 'completed', engine: 'Local', details: '1 résultat(s)' }],
    dynamicRuntime: zapRunModel(local, 'READY')
  });
  assert.match(apres, /<span>Engine<\/span><strong>Local<\/strong>/);
});

test('ZAP : « Voir les findings ZAP » ouvre la vue complète, filtrée sur ZAP', () => {
  const card = zapCard();
  assert.match(card, /data-command="securityCenter\.openZapFindings">Voir les findings ZAP</);
  // Le bouton ne renvoie plus vers la section des seules priorités, où un ZAP
  // sans HIGH ni CRITICAL semblait n’avoir rien trouvé.
  assert.ok(!card.includes('data-dynamic-filter-target="zap"'), 'le bouton mène encore à la section prioritaire');
  const extension = src('extension.js');
  assert.match(extension, /registerCommand\('securityCenter\.openZapFindings'[\s\S]{0,400}?openFindingsForTool\('zap'\)/);
  assert.match(extension, /'securityCenter\.openZapFindings',/);
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.contributes.commands.some((entry) => entry.command === 'securityCenter.openZapFindings'));
  // L’identifiant préréglé est celui qu’emploie le filtre Scanner de la page.
  assert.equal(scannerIdForTool('ZAP'), 'zap');
});

test('ZAP : la page Findings s’ouvre filtrée sur ZAP, toutes sévérités', () => {
  const findings = [
    { tool: 'ZAP', title: 'Info ZAP', rawSeverity: 'INFO', endpoint: 'http://192.168.222.132:3000/' },
    { tool: 'ZAP', title: 'Medium ZAP', rawSeverity: 'MEDIUM', endpoint: 'http://192.168.222.132:3000/rest' },
    { tool: 'Semgrep', title: 'Autre outil', rawSeverity: 'HIGH', file: 'src/app.js' }
  ];
  const page = renderDashboardHtml(
    buildDashboardModel(findings, [{ tool: 'ZAP', status: 'completed' }], { workspace: 'demo' }),
    'nonce', 'findings', 'light', { findingsTool: 'zap' }, {}
  );
  assert.match(page, /<option value="zap" selected>/);
  // Aucune sévérité n’est imposée : la vue ouverte les montre toutes.
  assert.ok(!page.includes('<option value="high" selected>'), 'une sévérité est imposée au filtre');
  // Les findings ZAP de faible sévérité sont bien dans la page ouverte.
  assert.match(page, /Info ZAP/);
  assert.match(page, /Medium ZAP/);
});

// ---------------------------------------------------------------- nettoyage

test('ZAP : rien ne survit à la fenêtre, ni à l’annulation', () => {
  const extension = src('extension.js');
  // Le démon local est confié à l’extension, qui l’arrête si la fenêtre se ferme.
  assert.match(extension, /onProcess: \(child\) => \{\s*activeZapProcess = child;/);
  assert.match(extension, /const child = activeZapProcess;\s*if \(child && child\.exitCode === null && child\.signalCode === null\) \{\s*try \{ child\.kill\(\); \}/);
  assert.match(extension, /if \(activeZapContainer\) removeZapContainer\(activeZapContainer\)/);

  const zap = src('zap.js');
  // Tuer le client Docker n’arrête pas le conteneur : il porte donc un nom.
  assert.match(zap, /\.\.\.\(containerName \? \['--name', containerName\] : \[\]\)/);
  assert.match(zap, /dockerCliArgs\(\['rm', '--force', containerName\]\)/);
  // Terminé, échoué ou annulé : le `finally` passe dans les trois cas.
  assert.match(zap, /\} finally \{[\s\S]*?await removeZapContainer\(containerName\);/);

  const local = src('zap-local.js');
  assert.match(local, /try \{ onProcess\?\.\(child\); \}/);
  // Le démon local est arrêté par son API, et tué si elle ne répond pas — puis
  // sa sortie est vérifiée, parce qu'un arrêt accepté n'est pas un arrêt constaté.
  assert.match(local, /'core', 'action', 'shutdown'[\s\S]{0,80}catch \{[\s\S]{0,120}child\?\.kill\(\);/);
  assert.match(local, /if \(!afterKill\) child\.kill\('SIGKILL'\);/);
  assert.match(local, /\} finally \{[\s\S]{0,200}await stopLocalZap\(child, baseUrl, apiKey\)/);
});

test('ZAP : une exécution restaurée « en cours » ne survit pas au rechargement', () => {
  const persiste = restoreRun({
    id: 'zap-1', engine: 'zap', kind: RUN_KIND.SCAN, status: RUN_STATUS.RUNNING,
    target: 'http://192.168.222.132:3000', phase: 'Moteur Local · Spidering / baseline 40 %'
  });
  // Un rechargement de fenêtre tue les processus enfants : le scan n’existe plus.
  const reconcilie = reconcileRun(persiste, { alive: false });
  assert.equal(reconcilie.status, RUN_STATUS.FAILED);
  assert.equal(reconcilie.errorCode, RUN_ERROR.STALE_PROCESS);
  assert.match(reconcilie.errorReason, /n’existe plus après le rechargement/);
  // La carte ne dit donc plus « en cours ».
  assert.notEqual(
    engineState('zap', { kind: RUN_KIND.SCAN, run: reconcilie, availability: availability({ installed: true }) }).status,
    RUN_STATUS.RUNNING
  );
  // Aucun scan n’est réputé vivant au démarrage sans preuve.
  const extension = src('extension.js');
  assert.match(extension, /const alive = engine === 'mitmproxy' \? captureAlive[\s\S]{0,160}: false;/);
});
