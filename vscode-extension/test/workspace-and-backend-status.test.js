'use strict';

/**
 * Deux faits que le dashboard affichait faux, et la raison commune.
 *
 * « Aucun workspace » et « Backend unknown » n'étaient pas deux bugs : c'était
 * le même. Les deux valeurs n'étaient écrites qu'à l'intérieur du `.then()` d'un
 * appel réseau au backend lancé à l'activation. Quand cet appel échouait — service
 * arrêté, port pris par une autre installation, clé d'API refusée — le `.catch()`
 * ne faisait rien : le workspace n'était jamais renseigné et le badge restait sur
 * sa valeur par défaut.
 *
 * Ces tests fixent la séparation : le workspace se lit dans l'éditeur, le badge
 * se lit dans le gestionnaire de backend, et aucun des deux ne dépend du sort
 * d'une requête de données.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { describeWorkspaceIdentity, NO_WORKSPACE_LABEL } = require('../src/workspace-identity');
const { dashboardBackendStatus, DASHBOARD_BACKEND_STATUS, RESOLVED_MODE } = require('../src/backend-manager');
const { BACKEND_STATE, describeBackend } = require('../src/backend-config');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const extensionSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/** Un dossier tel que VS Code l'expose. */
const folder = (name, fsPath) => ({ name, uri: { fsPath } });

const JUICE_SHOP = folder('juice-shop', 'C:\\Users\\hajar\\Desktop\\pfa-start\\test-application\\juice-shop');

// ==================================================== A. identité du workspace

test('aucun dossier ouvert : l’état est annoncé, pas deviné', () => {
  for (const empty of [undefined, null, []]) {
    const identity = describeWorkspaceIdentity(empty);
    assert.equal(identity.label, NO_WORKSPACE_LABEL);
    assert.equal(identity.isEmpty, true);
    assert.equal(identity.folderCount, 0);
  }
});

test('un dossier ouvert : le basename réel, jamais le chemin complet', () => {
  const identity = describeWorkspaceIdentity([JUICE_SHOP]);
  assert.equal(identity.label, 'juice-shop');
  assert.equal(identity.folderCount, 1);
  assert.equal(identity.multiRoot, false);
  assert.equal(identity.primaryPath, JUICE_SHOP.uri.fsPath);
  // Le libellé nomme le dossier ; il ne divulgue pas l'arborescence de la machine.
  assert.doesNotMatch(identity.label, /[\\/]/);
});

test('un dossier sans nom : le dernier segment du chemin, pas « Aucun workspace »', () => {
  const identity = describeWorkspaceIdentity([{ uri: { fsPath: '/home/dev/projets/api-paiement/' } }]);
  assert.equal(identity.label, 'api-paiement');
  assert.equal(identity.isEmpty, false);
});

test('multi-root : le nom du workspace VS Code s’il existe, sinon un compte honnête', () => {
  const folders = [JUICE_SHOP, folder('extension', '/w/extension')];
  assert.equal(describeWorkspaceIdentity(folders, 'securite (Workspace)').label, 'securite (Workspace)');
  // Sans fichier .code-workspace nommé, désigner le premier dossier comme « le »
  // workspace serait faux : on annonce le nombre.
  assert.equal(describeWorkspaceIdentity(folders).label, '2 workspaces');
  assert.equal(describeWorkspaceIdentity(folders).multiRoot, true);
  assert.equal(describeWorkspaceIdentity([JUICE_SHOP, folder('a', '/a'), folder('b', '/b')]).label, '3 workspaces');
});

test('changement de workspace : la réponse suit l’éditeur, sans cache à invalider', () => {
  // La fonction est pure : deux états successifs de VS Code donnent deux
  // réponses. Aucune valeur ne survit à un changement de dossier.
  assert.equal(describeWorkspaceIdentity([JUICE_SHOP]).label, 'juice-shop');
  assert.equal(describeWorkspaceIdentity([folder('autre-projet', '/w/autre')]).label, 'autre-projet');
  assert.equal(describeWorkspaceIdentity([]).label, NO_WORKSPACE_LABEL);
});

test('l’extension écoute le changement de dossiers et relit l’éditeur', () => {
  assert.match(extensionSource, /vscode\.workspace\.onDidChangeWorkspaceFolders\(/,
    'sans ce listener, ouvrir un dossier ne met pas le dashboard à jour');
  assert.match(extensionSource, /describeWorkspaceIdentity\(vscode\.workspace\.workspaceFolders, vscode\.workspace\.name\)/,
    'le workspace doit être lu dans VS Code, pas reconstruit');
});

test('au rechargement, le workspace est connu avant tout scan et tout appel réseau', () => {
  // Le modèle est semé à l'activation. C'était la régression : le champ n'était
  // écrit que dans le `.then()` d'un appel au backend.
  assert.match(extensionSource, /let currentDashboardOptions = \{\s*\n\s*workspace: currentWorkspaceIdentity\(\)\.label/,
    'le workspace doit être renseigné dès l’activation');
  const activation = extensionSource.slice(extensionSource.indexOf('Promise.all([listHttpScenarios'));
  assert.doesNotMatch(activation.slice(0, 900), /workspace: vscode\.workspace\.workspaceFolders/,
    'le workspace ne doit plus dépendre de la réussite d’un appel au backend');
});

test('le dashboard affiche le basename reçu, et « Aucun workspace » seulement s’il l’est', () => {
  const withFolder = buildDashboardModel([], [], { workspace: 'juice-shop' });
  assert.equal(withFolder.workspace, 'juice-shop');
  assert.match(renderDashboardHtml(withFolder, 'n', 'full', 'light', {}, {}), /juice-shop/);

  assert.equal(buildDashboardModel([], [], {}).workspace, NO_WORKSPACE_LABEL);
});

// ================================================== B. état réel du backend

const statusFor = (state, resolvedMode = RESOLVED_MODE.LOCAL) => ({
  ...describeBackend({ state, url: 'http://127.0.0.1:8765' }), resolvedMode
});

test('backend en ligne localement : « online »', () => {
  assert.equal(dashboardBackendStatus(statusFor(BACKEND_STATE.ONLINE)), DASHBOARD_BACKEND_STATUS.ONLINE);
});

test('backend distant joignable : « remote », pas « online »', () => {
  // Il répond, mais il n'est ni démarré ni arrêtable ici : l'interface le dit.
  assert.equal(
    dashboardBackendStatus(statusFor(BACKEND_STATE.ONLINE, RESOLVED_MODE.REMOTE)),
    DASHBOARD_BACKEND_STATUS.REMOTE
  );
});

test('backend en démarrage : « starting »', () => {
  assert.equal(dashboardBackendStatus(statusFor(BACKEND_STATE.STARTING)), DASHBOARD_BACKEND_STATUS.STARTING);
});

test('rien n’écoute : « offline », quelle que soit la façon dont on l’a appris', () => {
  for (const state of [BACKEND_STATE.OFFLINE, BACKEND_STATE.TIMEOUT, BACKEND_STATE.NOT_CONFIGURED]) {
    assert.equal(dashboardBackendStatus(statusFor(state)), DASHBOARD_BACKEND_STATUS.OFFLINE, state);
  }
});

test('service inattendu ou clé refusée : « error », jamais un faux « online »', () => {
  for (const state of [BACKEND_STATE.ERROR, BACKEND_STATE.INVALID_RESPONSE, BACKEND_STATE.AUTH_ERROR]) {
    assert.equal(dashboardBackendStatus(statusFor(state)), DASHBOARD_BACKEND_STATUS.ERROR, state);
  }
});

test('« unknown » est transitoire : aucun état résolu ne le produit', () => {
  // Seule l'absence de réponse du gestionnaire le rend.
  assert.equal(dashboardBackendStatus(null), DASHBOARD_BACKEND_STATUS.UNKNOWN);
  assert.equal(dashboardBackendStatus({}), DASHBOARD_BACKEND_STATUS.UNKNOWN);
  for (const state of Object.values(BACKEND_STATE)) {
    assert.notEqual(dashboardBackendStatus(statusFor(state)), DASHBOARD_BACKEND_STATUS.UNKNOWN,
      `l’état ${state} doit se traduire en un badge affirmatif`);
  }
});

test('un échec de données ne laisse pas le badge sur « unknown » : il redemande l’état', () => {
  assert.match(extensionSource, /refreshBackendBadge\(\{ start: true \}\)/,
    'l’activation doit résoudre le badge, en démarrant le service en mode Auto');
  // Les deux `.catch()` des appels de données interrogent le gestionnaire.
  const catches = extensionSource.match(/\}\)\.catch\(\(\) => \{[\s\S]{0,320}?\}\);/g) || [];
  const refreshing = catches.filter((block) => block.includes('refreshBackendBadge'));
  assert.ok(refreshing.length >= 2,
    'les échecs d’appel de données doivent rafraîchir le badge, pas le laisser tel quel');
});

test('le badge rend un ton juste : distant en ligne, démarrage neutre', () => {
  const render = (backendStatus) => renderDashboardHtml(
    buildDashboardModel([], [], { workspace: 'juice-shop', backendStatus }), 'n', 'compact', 'light', {}, {}
  );
  assert.match(render('online'), /class="backend online"/);
  assert.match(render('remote'), /class="backend online"/);
  assert.match(render('offline'), /class="backend offline"/);
  assert.match(render('error'), /class="backend offline"/);
  assert.match(render('starting'), /class="backend unknown"/);
  // Le mot affiché reste celui de l'état, jamais un « healthy » générique.
  assert.match(render('remote'), /Backend remote/);
  assert.match(render('starting'), /Backend starting/);
});

// ============================== C. les scanners ne dépendent pas du backend

test('aucun scanner ni Live Security n’importe le backend', () => {
  const root = path.join(__dirname, '..', 'src');
  const autonomes = [
    'orchestrator.js', 'semgrep.js', 'gitleaks.js', 'trivy.js', 'osv.js', 'zap.js', 'zap-local.js',
    'sonarqube.js', 'snyk.js', 'correlation.js', 'live/liveDetector.js', 'live/liveSecurityService.js'
  ];
  for (const relative of autonomes) {
    const file = path.join(root, relative);
    if (!fs.existsSync(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /require\('\.\.?\/?backend(-config|-manager)?'\)/,
      `${relative} ne doit pas dépendre du backend Secenter`);
  }
});

test('lancer une analyse n’attend pas le backend', () => {
  // Le scan appelle `ensureBackendOnline` nulle part avant d'exécuter les
  // analyseurs : la persistance vient après, et son échec est rattrapé.
  const scan = extensionSource.slice(extensionSource.indexOf("registerCommand('securityCenter.scanWorkspace'"));
  const beforeRun = scan.slice(0, scan.indexOf('runScanners'));
  assert.doesNotMatch(beforeRun, /await ensureBackendOnline\(\)/,
    'un backend indisponible ne doit pas empêcher une analyse de démarrer');
});

test('le backend Secenter n’est pas l’application analysée', () => {
  // Deux services distincts sur la machine : le port applicatif de la cible
  // dynamique n'est jamais celui du backend de persistance.
  const { DEFAULT_BACKEND_URL } = require('../src/backend-config');
  assert.equal(DEFAULT_BACKEND_URL, 'http://127.0.0.1:8765');
  assert.doesNotMatch(DEFAULT_BACKEND_URL, /:3000/, 'le backend ne doit pas être confondu avec Juice Shop');
});
