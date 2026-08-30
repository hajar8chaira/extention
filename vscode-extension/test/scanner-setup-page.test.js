'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('fs');
const path = require('path');
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');
const { scannerLogoUri } = require('../src/scanner-presentation');

const scannerSetupSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'scanner-setup-page.js'), 'utf8');
const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
const localLogoAssets = () => ({
  scannerLogoUris: {
    Semgrep: 'vscode-resource:/media/scanners/semgrep.svg',
    Gitleaks: 'vscode-resource:/media/scanners/gitleaks.svg',
    Trivy: 'vscode-resource:/media/scanners/trivy.svg',
    'OSV-Scanner': 'vscode-resource:/media/scanners/osv-scanner.svg',
    SonarQube: 'vscode-resource:/media/scanners/sonarqube.svg',
    Snyk: 'vscode-resource:/media/scanners/snyk.svg',
    ZAP: 'vscode-resource:/media/scanners/zap.png'
  },
  cspSource: 'vscode-resource:'
});

test('affiche les scanners locaux et leurs actions sans lancer une installation', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false },
    { id: 'trivy', label: 'Trivy', purpose: 'SCA', installed: true, managed: true, version: '1.2.3', executable: 'C:\\tools\\trivy.exe' }
  ], 'nonce', 'light');

  assert.match(html, /Configuration des scanners/);
  assert.match(html, /Installer localement/);
  assert.match(html, /Utiliser en mode Auto/);
  assert.match(html, /Aucune installation n[^<]*est lanc/);
  assert.match(html, /data-theme="light"/);
  assert.doesNotMatch(html, /fetch\(|XMLHttpRequest|install\(\)/);
});

test('affiche une progression et respecte le thème sombre choisi', () => {
  const html = renderScannerSetupHtml([
    { id: 'osv', label: 'OSV-Scanner', purpose: 'Dépendances', installed: false }
  ], 'nonce', 'dark', {
    osv: { state: 'installing', title: 'Téléchargement', message: 'Vérification en cours', percent: 42 }
  });

  assert.match(html, /data-theme="dark"/);
  assert.match(html, /value="42"/);
  assert.match(html, /Vérification en cours/);
  assert.match(html, /disabled/);
});

test('affiche une confirmation intégrée et thémée avant toute installation', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false }
  ], 'nonce', 'light', {}, {
    ids: ['semgrep'], labels: ['Semgrep'], destination: 'C:\\private\\scanner-tools'
  });

  assert.match(html, /role="dialog"/);
  assert.match(html, /INSTALLATION LOCALE SÉCURISÉE/);
  assert.match(html, /Semgrep/);
  assert.match(html, /C:\\private\\scanner-tools/);
  assert.match(html, /Autoriser et installer/);
  assert.match(html, /Annuler/);
  assert.match(html, /approveInstall/);
  assert.match(html, /cancelInstall/);
  assert.doesNotMatch(html, /showWarningMessage/);
});

test('verrouille les autres installations pendant une installation active', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false },
    { id: 'gitleaks', label: 'Gitleaks', purpose: 'Secrets', installed: false }
  ], 'nonce', 'light', {
    semgrep: { state: 'installing', title: 'Installation', message: 'En cours' }
  });

  assert.match(html, /id="install-all" disabled/);
  assert.match(html, /data-install="gitleaks" disabled/);
  assert.match(html, /id="refresh" class="secondary" disabled/);
});

test('la presentation modernisee ne change pas les commandes de configuration', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: true, version: '1.0.0', executable: '/bin/semgrep' },
    { id: 'gitleaks', label: 'Gitleaks', purpose: 'Secrets', installed: false, executable: '' }
  ], 'nonce', 'light');
  assert.match(html, /class="scanner-logo fallback[^"]*" data-scanner-logo="semgrep"/);
  assert.match(html, /class="scanner-logo fallback[^"]*" data-scanner-logo="gitleaks"/);
  assert.match(html, /class="actions mode-selector"/);
  assert.match(html, /class="actions maintenance-actions"/);
  assert.match(html, /class="path" title="\/bin\/semgrep">\/bin\/semgrep/);
  assert.match(html, /id="install-all"/);
  assert.match(html, /id="refresh" class="secondary"/);
  assert.match(html, /data-install="gitleaks"/);
  assert.match(html, /data-recheck="semgrep"/);
});

test('Scanner Configuration réutilise les logos locaux du registre de présentation partagé', () => {
  const assets = localLogoAssets();
  const statuses = [
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: true },
    { id: 'gitleaks', label: 'Gitleaks', purpose: 'Secrets', installed: true },
    { id: 'trivy', label: 'Trivy', purpose: 'SCA', installed: true },
    { id: 'osv', label: 'OSV-Scanner', purpose: 'Dépendances', installed: true },
    { id: 'zap', label: 'ZAP', purpose: 'DAST', installed: true }
  ];
  const sonar = {
    enabled: true, mode: 'auto', serverType: 'existing', hostUrl: 'http://127.0.0.1:9000',
    tokenConfigured: true, scannerVersion: '6.2.1', dockerAvailable: true, serverOnline: true
  };
  const snyk = {
    enabled: true, mode: 'auto', tokenConfigured: true, authenticationValid: true,
    cliVersion: '1.1290.0', dockerAvailable: true, capabilities: { openSource: true, code: null, iac: null }
  };
  const html = renderScannerSetupHtml(statuses, 'nonce', 'light', {}, null, sonar, snyk, assets);

  for (const [tool, alt] of [
    ['Semgrep', 'Semgrep logo'],
    ['Gitleaks', 'Gitleaks logo'],
    ['Trivy', 'Trivy logo'],
    ['OSV-Scanner', 'OSV-Scanner logo'],
    ['SonarQube', 'SonarQube logo'],
    ['Snyk', 'Snyk logo'],
    ['ZAP', 'ZAP logo']
  ]) {
    const uri = scannerLogoUri(tool, assets);
    assert.ok(uri, `${tool} doit avoir un logo local`);
    assert.match(html, new RegExp(`<img class="scanner-logo-img" src="${uri.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}" alt="${alt}"`));
  }
  assert.doesNotMatch(html, /<img[^>]+src="https?:\/\//);
  assert.match(html, /img-src vscode-resource: data:/);
});

test('Scanner Configuration garde un fallback uniquement quand aucun logo local valide n’existe', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: true }
  ], 'nonce', 'light');

  assert.match(html, /class="scanner-logo fallback[^"]*" data-scanner-logo="semgrep"/);
  assert.doesNotMatch(html, /<img class="scanner-logo-img"/);
});

test('le panneau Scanner Configuration reçoit le même bundle de logos que les autres surfaces', () => {
  const source = extensionSource();
  assert.match(source, /scannerSetupPanel\.webview\.html = renderScannerSetupHtml\(statuses,[\s\S]*sonar, snyk, companionAssetOptions\(scannerSetupPanel\.webview\)\)/);
  for (const logo of ['semgrep.svg', 'gitleaks.svg', 'trivy.svg', 'osv-scanner.svg', 'sonarqube.svg', 'snyk.svg', 'zap.png']) {
    assert.ok(source.includes(logo), `${logo} doit venir du bundle local existant`);
  }
});

test('la grille Scanner Configuration expose les breakpoints 3/2/1 et limite SonarQube sans scroll horizontal', () => {
  const source = scannerSetupSource();
  assert.match(source, /scanner-config-grid/);
  assert.match(source, /\.grid, \.scanner-config-grid \{ display: grid; grid-template-columns: 1fr; grid-auto-flow: row dense;/);
  assert.match(source, /@media \(min-width: 900px\) \{[\s\S]*\.scanner-config-grid \{ grid-template-columns: repeat\(2,minmax\(0, 1fr\)\); \}/);
  assert.match(source, /@media \(min-width: 1400px\) \{[\s\S]*\.scanner-config-grid \{ grid-template-columns: repeat\(3,minmax\(0, 1fr\)\); \}/);
  assert.match(source, /\.scanner-config-grid \.tool\[data-tool='sonarqube'\] \{ grid-column: span 2; \}/);
  assert.match(source, /\.scanner-config-grid \.tool\[data-tool='sonarqube'\] \{ grid-column: auto; \}/);
});

test('les cartes gardent une structure compacte sans modifier les actions', () => {
  const source = scannerSetupSource();
  assert.match(source, /\.tool \{[^}]*display: flex; flex-direction: column;/);
  assert.match(source, /\.tool-controls \{[^}]*margin-top: auto;/);
  assert.match(source, /\.maintenance-actions \{[^}]*justify-content: flex-end; margin-top: auto;/);
  assert.match(source, /\.mode-selector \{ display: grid; grid-template-columns: repeat\(3,minmax\(0, 1fr\)\);/);
  assert.match(source, /\.path \{[^}]*max-height: calc\(2\.9em \+ 12px\);/);
  for (const selector of [
    'data-scanner-enabled',
    'data-recheck',
    'data-scanner-mode',
    'data-sonar-install',
    'data-sonar-token',
    'data-sonar-server-start',
    'data-sonar-server-stop',
    'data-snyk-install',
    'data-snyk-token'
  ]) {
    assert.ok(source.includes(selector), `${selector} doit rester câblé`);
  }
});

test('le script de configuration conserve les messages existants', () => {
  const source = scannerSetupSource();
  for (const message of [
    "type:'refresh'",
    "type:'requestInstallAll'",
    "type:'requestInstall'",
    "type:'setAuto'",
    "type:'setScannerMode'",
    "type:'setScannerEnabled'",
    "type:'setSonarMode'",
    "type:'setSonarEnabled'",
    "type:'configureSonarToken'",
    "type:'chooseSonarServer'",
    "type:'startSonarServer'",
    "type:'stopSonarServer'",
    "type:'configureSonarHostUrl'",
    "type:'openSonarServer'",
    "type:'setSnykMode'",
    "type:'setSnykEnabled'",
    "type:'configureSnykToken'",
    "type:'requestInstall',tool:'sonarscanner'",
    "type:'requestInstall',tool:'snyk'",
    "type:'approveInstall'",
    "type:'cancelInstall'"
  ]) {
    assert.ok(source.includes(message), `${message} absent du script`);
  }
  assert.doesNotMatch(source, /setInterval|requestAnimationFrame|fetch\(|XMLHttpRequest/);
});

test('la page respecte la reduction de mouvement dans sa couche CSS', () => {
  const html = renderScannerSetupHtml([], 'nonce', 'light');
  assert.match(html, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(html, /animation: none !important/);
  assert.match(html, /transition: none !important/);
});

// ===========================================================================
// A — Modes de deploiement du serveur SonarQube
// B — La confirmation d installation est une modale globale
// ===========================================================================

const abFs = require('node:fs');
const abPath = require('node:path');
const { renderScannerSetupHtml: abRender } = require('../src/scanner-setup-page');
const abServer = require('../src/sonarqube-server');
const abSource = (file) => abFs.readFileSync(abPath.join(__dirname, '..', file), 'utf8');

const abSonar = (over = {}) => ({
  enabled: true, mode: 'auto', serverType: 'local', localServerState: 'ready',
  scannerVersion: '5.0', dockerAvailable: true, tokenConfigured: true, ...over
});
// `serverUrl` derive de `sonar.hostUrl` dans le rendu reel.
const abRenderFull = (sonar, { serverUrl = '' } = {}) => abRender([], 'n', 'light', {}, null, { ...sonar, hostUrl: serverUrl || sonar.hostUrl || '' }, null, {});
// Le script de la page cable defensivement TOUS les selecteurs avec `?.` : les
// assertions doivent porter sur le balisage rendu, pas sur ce cablage.
const abRenderSetup = (sonar, options = {}) => {
  const html = abRenderFull(sonar, options);
  return html.slice(0, html.lastIndexOf('<script'));
};

// ------------------------------------------------------------------ SONARQUBE

test('Sonar : le mode SonarScanner et le type de serveur restent independants', () => {
  const manifest = require('../package.json').contributes.configuration.properties;
  assert.ok(manifest['securityCenter.sonar.mode'], 'mode d execution SonarScanner');
  assert.ok(manifest['securityCenter.sonar.serverType'], 'type de deploiement du serveur');
  assert.match(manifest['securityCenter.sonar.serverType'].description, /[Ii]ndependant|[Ii]ndépendant/);
  assert.deepEqual(manifest['securityCenter.sonar.serverType'].enum, ['', 'local', 'existing']);
  // SonarScanner peut rester local pendant que le serveur est distant.
  const html = abRenderSetup(abSonar({ serverType: 'existing', mode: 'local' }), { serverUrl: 'http://192.168.222.133:9000' });
  assert.match(html, /Serveur existant/);
  assert.ok(html.includes('192.168.222.133'));
});

test('Sonar : le serveur local Docker affiche son adresse loopback', () => {
  const html = abRenderSetup(abSonar({ serverType: 'local', localServerState: 'ready' }));
  assert.match(html, /Serveur local Docker/);
  assert.ok(html.includes('http://127.0.0.1:9000'));
  // Image officielle, pas d image maison.
  assert.equal(abServer.SERVER_IMAGE, 'sonarqube:community');
  assert.equal(abServer.SERVER_URL, 'http://127.0.0.1:9000');
});

test('Sonar : le serveur local expose Demarrer/Arreter selon son etat', () => {
  const stopped = abRenderSetup(abSonar({ localServerState: 'stopped' }));
  assert.match(stopped, /data-sonar-server-start/);
  assert.doesNotMatch(stopped, /data-sonar-server-stop/);

  const ready = abRenderSetup(abSonar({ localServerState: 'ready' }));
  assert.match(ready, /data-sonar-server-stop/);
  assert.match(ready, /data-sonar-recheck/, 'Revérifier disponible quand le serveur tourne');
  assert.doesNotMatch(ready, /data-sonar-server-start/);

  const starting = abRenderSetup(abSonar({ localServerState: 'initializing' }));
  assert.match(starting, /data-sonar-recheck/);
  assert.match(starting, /attend que le serveur réponde réellement/);
});

test('Sonar : le serveur distant n expose aucun controle de cycle de vie Docker', () => {
  const html = abRenderSetup(abSonar({ serverType: 'existing' }), { serverUrl: 'https://sonarqube.company.local' });
  assert.doesNotMatch(html, /data-sonar-server-start/, 'pas de demarrage Docker pour un serveur distant');
  assert.doesNotMatch(html, /data-sonar-server-stop/, 'pas d arret Docker pour un serveur distant');
  assert.doesNotMatch(html, /Serveur local Docker/);
  // Security Center ne gere pas le cycle de vie d un serveur qu il ne possede pas.
  assert.match(html, /data-sonar-server-url/, 'modification de l adresse');
  assert.match(html, /data-sonar-open/, 'ouverture du serveur');
  assert.match(html, /data-sonar-recheck/, 'reverification');
});

test('Sonar : l adresse d un serveur distant est configurable et affichee', () => {
  const configured = abRenderSetup(abSonar({ serverType: 'existing' }), { serverUrl: 'http://192.168.222.133:9000' });
  assert.ok(configured.includes('http://192.168.222.133:9000'));
  const empty = abRenderSetup(abSonar({ serverType: 'existing' }), { serverUrl: '' });
  assert.match(empty, /Aucune URL configurée/);
  assert.match(empty, /data-sonar-server-url/);
  // Sans URL, rien a ouvrir ni a reverifier : aucun bouton mort.
  assert.doesNotMatch(empty, /data-sonar-open/);
});

test('Sonar : un conteneur qui tourne n est pas un serveur pret', async () => {
  const { localServerState, LOCAL_SERVER_STATES } = abServer;
  // C est SonarQube qui decide, pas Docker.
  assert.equal(localServerState({ containerStatus: 'running', health: null }), LOCAL_SERVER_STATES.STARTING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'STARTING' } }), LOCAL_SERVER_STATES.INITIALIZING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'DB_MIGRATION_RUNNING' } }), LOCAL_SERVER_STATES.INITIALIZING);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'UP' } }), LOCAL_SERVER_STATES.READY);
  assert.equal(localServerState({ containerStatus: 'running', health: { status: 'DOWN' } }), LOCAL_SERVER_STATES.ERROR);

  // L attente interroge reellement le point de sante avant de declarer « pret ».
  const seen = [];
  const result = await abServer.waitForLocalServer({
    checkStatus: async () => { seen.push(1); return seen.length < 3 ? { status: 'STARTING' } : { status: 'UP' }; },
    pollIntervalMs: 0, timeoutMs: 5000, delay: async () => {}
  });
  assert.equal(result.state, LOCAL_SERVER_STATES.READY);
  assert.equal(seen.length, 3, 'a attendu la reponse HTTP reelle');
  // Et l attente est bornee : jamais de boucle infinie.
  const timedOut = await abServer.waitForLocalServer({
    checkStatus: async () => ({ status: 'STARTING' }),
    pollIntervalMs: 0, timeoutMs: 1, delay: async () => {}, now: (() => { let t = 0; return () => (t += 1000); })()
  });
  assert.equal(timedOut.reason, 'timeout');
});

test('Sonar : le jeton reste dans SecretStorage et n atteint jamais la webview', () => {
  const html = abRenderSetup(abSonar({ tokenConfigured: true }));
  assert.doesNotMatch(html, /data-sonar-token[^>]*value=/, 'aucune valeur de jeton rendue');
  assert.ok(!html.includes('squ_'), 'aucun jeton SonarQube dans le HTML');
  const manifest = require('../package.json').contributes.configuration.properties;
  for (const key of Object.keys(manifest)) {
    assert.ok(!/sonar\.(token|password)/.test(key), `${key} ne doit pas exister comme reglage`);
  }
  const extension = abSource('src/extension.js');
  assert.match(extension, /context\.secrets\.(get|store|delete)\(SONAR_TOKEN_SECRET_KEY\)/);
});

test('Sonar : changer de type de serveur ne touche pas le cycle de vie du scanner', () => {
  const setup = abSource('src/scanner-setup-page.js');
  const extension = abSource('src/extension.js');
  // Le basculement n emet qu un choix de serveur.
  assert.match(setup, /type:'chooseSonarServer',serverType:b\.dataset\.sonarServer/);
  const handler = extension.match(/message\?\.type === 'chooseSonarServer'[\s\S]{0,600}/);
  if (handler) {
    for (const forbidden of ['currentFindings', 'saveLocalScanCache', 'currentSecuritySnapshot', 'runSecurityScan']) {
      assert.ok(!handler[0].includes(forbidden), `le basculement ne doit pas toucher ${forbidden}`);
    }
  }
  // Le mode d execution du scanner a son propre message, distinct.
  assert.match(setup, /type:'setSonarMode',mode:b\.dataset\.sonarMode/);
});

// --------------------------------------------------------------- MODALE

test('Modale : la racine de modales est ancree au viewport', () => {
  const shell = abSource('src/security-center-shell.js');
  assert.match(shell, /#security-center-modal-root \{ position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; \}/);
  assert.match(shell, /#security-center-modal-root:empty \{ display: none; \}/);
});

test('Modale : l overlay d installation couvre le viewport et se centre', () => {
  const setup = abSource('src/scanner-setup-page.js');
  const rule = setup.match(/\.confirm-backdrop \{[^}]*\}/)[0];
  assert.match(rule, /position: fixed/);
  assert.match(rule, /inset: 0/);
  assert.match(rule, /display: flex/);
  assert.match(rule, /align-items: center/);
  assert.match(rule, /justify-content: center/);
  assert.match(rule, /z-index: 1000/);
  // Tres petit viewport : c est la modale qui defile, pas la page.
  assert.match(rule, /overflow: auto/);
  assert.match(setup.match(/\.confirm \{[^}]*\}/)[0], /max-height: calc\(100vh - 48px\)/);
});

test('Modale : la confirmation sort du flux defilant de la page', () => {
  const html = abRender([], 'n', 'light', {}, { labels: ['Semgrep'], destination: 'C:/store' });
  const body = html.slice(html.indexOf('<body'));
  const mainEnd = body.indexOf('</main>');
  const rootIdx = body.indexOf('<div id="security-center-modal-root">');
  const confirmIdx = body.indexOf('<div class="confirm-backdrop"');
  assert.ok(confirmIdx > -1, 'la modale doit etre rendue');
  assert.ok(confirmIdx > mainEnd, 'la modale ne doit plus etre le dernier enfant du contenu defilant');
  assert.ok(confirmIdx > rootIdx, 'la modale vit dans la racine de modales');
  // `.sc-main` porte isolation/position : une modale rendue dedans se resolvait
  // contre lui et finissait en bas de page.
  assert.match(abSource('src/security-center-shell.js'), /\.sc-main \{ position: relative; isolation: isolate;/);
});

test('Modale : sans confirmation la racine reste vide et inerte', () => {
  const html = abRender([], 'n', 'light', {}, null);
  assert.ok(html.includes('<div id="security-center-modal-root"></div>'));
  assert.doesNotMatch(html, /confirm-backdrop"/);
});

test('Modale : les gestionnaires d autorisation et d annulation sont preserves', () => {
  const html = abRender([], 'n', 'light', {}, { labels: ['Semgrep'], destination: 'C:/store' });
  assert.match(html, /id="approve-install"/);
  assert.match(html, /id="cancel-install"/);
  const setup = abSource('src/scanner-setup-page.js');
  assert.match(setup, /getElementById\('approve-install'\)\?\.addEventListener\('click',\(\)=>vscode\.postMessage\(\{type:'approveInstall'\}\)\)/);
  assert.match(setup, /getElementById\('cancel-install'\)\?\.addEventListener\('click',\(\)=>vscode\.postMessage\(\{type:'cancelInstall'\}\)\)/);
  assert.match(html, /role="dialog" aria-modal="true"/);
});

test('Modale : la logique metier d installation est inchangee', () => {
  const html = abRender([], 'n', 'light', {}, { labels: ['Semgrep', 'Trivy'], destination: 'C:/store' });
  // Destination, privileges et provenance restent affiches tels quels.
  assert.match(html, /Sources officielles et vérification SHA-256/);
  assert.match(html, /Aucun droit administrateur/);
  assert.ok(html.includes('C:/store'));
  assert.match(html, /Autoriser l’installation \?/);
  // L engagement de securite reste vrai.
  assert.match(html, /Aucune installation n’est lancée sans votre confirmation/);
  const extension = abSource('src/extension.js');
  assert.match(extension, /approveInstall/);
  assert.match(extension, /cancelInstall/);
});

test('Modale : le preflight ZAP continue d utiliser la meme racine partagee', () => {
  const dashboard = abSource('src/dashboard.js');
  assert.match(dashboard, /<div id="security-center-modal-root">\$\{zapPreflightModal\}<\/div>/);
  assert.match(dashboard, /position: fixed;\s*inset: 0;/);
  // Les deux surfaces partagent le meme identifiant de racine.
  assert.ok(abSource('src/security-center-shell.js').includes('security-center-modal-root'));
  assert.ok(abSource('src/scanner-setup-page.js').includes('modalRoot: confirmationHtml'));
});
