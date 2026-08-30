const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const manifest = require('../package.json');
const extensionSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

const { LiveCompanionProvider, renderCompanionHtml } = require('../src/live/liveCompanion');
const { buildCompanionVisualModel, companionMessageFor, secondaryFor, CompanionMessageGate, shortMessageFor } = require('../src/live/companionMessages');
const { renderMascotSvg, mascotCss, mascotVisualFor, DEFAULT_MASCOT_IMAGE } = require('../src/live/companionMascot');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const live = (ruleId = 'unsafe-eval', severity = 'high') => ({
  ruleId, severity, title: 'Potential unsafe eval',
  range: { start: { line: 41, character: 2 }, end: { line: 41, character: 20 } },
  uri: 'file:///routes/login.ts', documentVersion: 1, quickFixAvailable: false
});

function provider({ state = 'idle', findings = [], pipeline = {} } = {}) {
  return new LiveCompanionProvider({
    api: {
      window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/routes/login.ts' } } } },
      workspace: { getConfiguration: () => ({ get: (key, fallback) => fallback }) }
    },
    service: { getState: () => state, onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => findings },
    executeCommand: () => {}, workspacePath: 'C:/ws', getPipelineContext: () => pipeline
  });
}

// ------------------------------------- la grande vue n'est plus contribuée

test('la WebviewView securityCenter.liveCompanion n’est plus contribuée', () => {
  const views = manifest.contributes.views.securityCenter;
  assert.ok(!views.some((view) => view.id === 'securityCenter.liveCompanion'),
    'la vue Security Companion ne doit plus figurer dans package.json');
  assert.ok(!views.some((view) => view.name === 'Security Companion'));
  assert.ok(!manifest.activationEvents.includes('onView:securityCenter.liveCompanion'),
    'l’événement d’activation de la vue supprimée doit disparaître aussi');
});

test('la sidebar va directement des contrôles aux Vulnérabilités', () => {
  const ids = manifest.contributes.views.securityCenter.map((view) => view.id);
  assert.deepEqual(ids, ['securityCenter.dashboard', 'securityCenter.findings']);
  // Pas de conteneur vide laissé derrière : la vue est retirée, pas masquée.
  assert.equal(ids.length, 2);
});

test('aucun fournisseur de vue n’est enregistré pour l’identifiant retiré', () => {
  assert.ok(!/registerWebviewViewProvider\(\s*'securityCenter\.liveCompanion'/.test(extensionSource),
    'le registerWebviewViewProvider de la vue supprimée doit disparaître');
  // Et rien ne tente de focaliser une vue qui n'existe plus.
  assert.ok(!extensionSource.includes("'securityCenter.liveCompanion.focus'"),
    'focaliser un identifiant de vue supprimé ne ferait rien silencieusement');
});

// ------------------------------------------------- le moteur reste intact

test('le moteur du Companion est préservé', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues', findings: [live()], file: 'routes/login.ts',
    pipeline: { scanStatus: 'completed', scanFindingCount: 556, policyStatus: 'BLOCK' }
  });
  for (const key of ['state', 'mascotState', 'message', 'shortMessage', 'liveFindingCount', 'fullScan', 'actions']) {
    assert.ok(key in visual, `le modèle visuel a perdu ${key}`);
  }
  assert.equal(visual.state, 'findings');
  assert.equal(visual.liveFindingCount, 1);
  assert.equal(visual.fullScan.findingCount, 556);
});

test('la priorité des messages et le garde anti-spam fonctionnent toujours', () => {
  assert.equal(companionMessageFor('clean', { policyStatus: 'BLOCK' }).kind, 'policy-block');
  // Un gate vert est un fait projet : il devient la ligne secondaire, jamais
  // le titre — le fichier courant garde la priorité.
  assert.equal(companionMessageFor('clean', { policyStatus: 'PASS' }).kind, 'clean');
  assert.equal(secondaryFor(null, { policyStatus: 'PASS' }).kind, 'policy-pass');
  assert.equal(companionMessageFor('error', { error: 'boom' }).kind, 'error');
  const gate = new CompanionMessageGate({ cooldownMs: 10000 });
  const message = companionMessageFor('clean', {});
  assert.equal(gate.accept(message), true);
  assert.equal(gate.accept(message), false, 'un message identique ne repasse pas');
  assert.equal(gate.accept(companionMessageFor('error', { error: 'boom' })), true, 'une priorité haute passe outre le cooldown');
});

test('le contexte fichier courant, la santé des scanners et le pipeline restent branchés', () => {
  const model = provider({
    state: 'issues', findings: [live()],
    pipeline: { scanStatus: 'completed', scanFindingCount: 12, policyStatus: 'WARN', scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }] }
  }).model();
  assert.equal(model.file, 'routes/login.ts');
  assert.equal(model.findings.length, 1);
  assert.equal(model.policyStatus, 'WARN');
  assert.ok(model.visual, 'le provider construit toujours le modèle visuel partagé');
});

test('le provider survit sans vue attachée', () => {
  const instance = provider({ state: 'clean' });
  assert.equal(instance.view, undefined);
  // render() passe le garde puis sort au contrôle de visibilité : aucun crash
  // même si plus aucune surface n'est montée.
  assert.doesNotThrow(() => instance.render());
  assert.doesNotThrow(() => instance.render());
  const captured = [];
  const subscribed = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }) }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'clean', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [] },
    executeCommand: () => {}, onVisualModel: (visual) => captured.push(visual)
  });
  subscribed.render();
  // Le point d'accroche pour la future surface compacte est toujours là.
  assert.equal(captured.length, 1);
  assert.equal(captured[0].state, 'clean');
});

test('la mascotte et ses animations sont préservées', () => {
  const html = renderMascotSvg('warning');
  assert.match(html, /<img class="mascot mascot-warning /);
  assert.equal(DEFAULT_MASCOT_IMAGE, 'media/live/security-companion.png');
  assert.match(html, /src="media\/live\/security-companion\.png"/);
  assert.match(html, /data-companion-asset="local"/);
  assert.match(mascotCss(), /@keyframes/);
  assert.match(mascotCss(), /\.mascot-warning\{animation:sc-attend/);
  assert.equal(mascotVisualFor('findings', { severity: 'critical' }), 'critical');
});

// --------------------------------------- les commandes restent disponibles

test('les commandes Full Scan et Live Security existent toujours', () => {
  const commands = manifest.contributes.commands.map((command) => command.command);
  for (const command of [
    'securityCenter.scanWorkspace', 'securityCenter.openLiveSecurityPage',
    'securityCenter.enableLiveSecurity', 'securityCenter.disableLiveSecurity',
    'securityCenter.toggleLiveSecurity', 'securityCenter.focusLiveSecurity'
  ]) {
    assert.ok(commands.includes(command), `la commande ${command} a disparu`);
  }
});

test('focusLiveSecurity ouvre la page Live Security au lieu d’une vue supprimée', () => {
  assert.match(extensionSource, /registerCommand\('securityCenter\.focusLiveSecurity'[\s\S]{0,320}liveSecurityPageProvider\.open\(\)/);
});

// -------------------------------------- plus aucune duplication de message

test('une surface ne rend jamais deux fois la même chaîne de statut', () => {
  const model = provider({
    state: 'clean',
    pipeline: { scanStatus: 'completed', scanFindingCount: 556, scanPriorityCount: 41 }
  }).model();
  const html = renderCompanionHtml(model, 'n');
  const headline = model.message.headline;
  // Le titre parle du fichier courant ; le scan complet est en secondaire.
  assert.equal(headline, 'Aucun problème Live détecté dans ce fichier');
  assert.equal(model.visual.secondary.headline, 'Dernier scan complet : 556 findings');
  // C'était le bug : le même texte dans l'en-tête et dans la bulle.
  const occurrences = html.split(headline).length - 1;
  assert.equal(occurrences, 1, `« ${headline} » rendu ${occurrences} fois`);
  assert.ok(!/<div class="state"><strong>/.test(html), 'l’en-tête ne doit plus répéter le titre du message');
});

test('aucun titre de message n’est dupliqué, quel que soit l’état', () => {
  for (const state of ['idle', 'clean', 'analyzing', 'issues', 'disabled', 'error']) {
    for (const pipeline of [{}, { scanStatus: 'completed', scanFindingCount: 556 }, { policyStatus: 'BLOCK' }, { policyStatus: 'PASS' }]) {
      const model = provider({ state, findings: state === 'issues' ? [live()] : [], pipeline }).model();
      const html = renderCompanionHtml(model, 'n');
      const headline = model.message.headline;
      const occurrences = html.split(headline).length - 1;
      assert.ok(occurrences <= 1, `état ${state} : « ${headline} » rendu ${occurrences} fois`);
    }
  }
});

test('le détail ne répète pas le titre', () => {
  const model = provider({ state: 'clean', pipeline: { scanStatus: 'completed', scanFindingCount: 556, scanPriorityCount: 41 } }).model();
  assert.notEqual(model.message.detail, model.message.headline);
  assert.ok(!model.message.detail.includes(model.message.headline));
  // Et le message court reste une reformulation, pas une copie collée.
  assert.notEqual(shortMessageFor(model.message, []), model.message.detail);
});

// ------------------------------------------ le dashboard reste sans mascotte

test('le dashboard ne contient toujours aucune mascotte complète', () => {
  for (const surface of ['sidebar', 'full', 'findings', 'scans', 'dynamic', 'analytics']) {
    const html = renderDashboardHtml(buildDashboardModel([], []), 'n', surface, 'light');
    assert.ok(!html.includes('<img class="mascot'), `mascotte réapparue sur ${surface}`);
    assert.ok(!html.includes('companion-card'), `carte compagnon réapparue sur ${surface}`);
  }
});
