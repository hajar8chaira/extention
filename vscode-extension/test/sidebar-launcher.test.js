'use strict';

/**
 * Le contrat du lanceur compact de la barre d'activite.
 *
 * La regression que ces tests empechent est precise : la vue etroite avait
 * absorbe la navigation complete de Security Center (Investigation, Pipeline,
 * Rapports, Configuration…). Ouvrir l'application affichait alors deux
 * navigations cote a cote. La responsabilite est desormais :
 *
 *   barre d'activite  = lanceur + etat + trois actions
 *   Security Center   = la navigation complete
 *
 * Les tests ci-dessous figent cette frontiere, la reutilisation des commandes
 * existantes, et l'enchainement « ouvrir/reveler PUIS replier la barre ».
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const manifest = require('../package.json');
const { buildDashboardModel } = require('../src/dashboard');
const {
  renderSidebarLauncherHtml, projectName, scanState, liveState, QUICK_ACTIONS
} = require('../src/sidebar-launcher');

const launcherSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'sidebar-launcher.js'), 'utf8');
const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

const render = (options = {}, extra = {}, theme = 'light', uiState = {}) =>
  renderSidebarLauncherHtml({ ...buildDashboardModel([], [], options), ...extra }, 'n', theme, uiState);

const commandsIn = (markup) => [...markup.matchAll(/data-command="([^"]+)"/g)].map(([, command]) => command);

// ================================================ 1. plus de navigation en double

test('le lanceur ne reproduit pas le catalogue de navigation de Security Center', () => {
  const html = render({ scanStatus: 'completed' });
  // Chaque entree ci-dessous appartient a la navigation interne de l'application.
  // Aucune ne doit reapparaitre dans la barre d'activite, sous peine de recreer
  // les deux navigations superposees que ce travail supprime.
  const forbidden = [
    'securityCenter.showScanHistoryPage', 'securityCenter.compareScans', 'securityCenter.showAuditLog',
    'securityCenter.showTrends', 'securityCenter.openSecurityPipeline', 'securityCenter.openSecurityDelivery',
    'securityCenter.generateSbom', 'securityCenter.checkLicenses', 'securityCenter.openScannerSetup',
    'securityCenter.openProjectPolicy', 'securityCenter.configureTeamIntegrations',
    'securityCenter.openFindingsPage', 'securityCenter.openScansPage', 'securityCenter.openAnalyticsPage',
    'securityCenter.openDynamicPage', 'securityCenter.configureBackendApiKey',
    'securityCenter.installPreCommitHook', 'securityCenter.rollbackAiFix', 'securityCenter.configureOllama'
  ];
  const rendered = new Set(commandsIn(html));
  for (const command of forbidden) {
    assert.ok(!rendered.has(command), `${command} appartient a la navigation interne, pas au lanceur`);
  }
  for (const title of ['Analyse fréquente', 'Investigation', 'Rapports', 'Configuration et protection']) {
    assert.ok(!html.includes(title), `le groupe « ${title} » ne doit plus exister dans la barre d'activite`);
  }
  // Et le cadre applicatif complet n'y entre pas non plus.
  assert.ok(!html.includes('sc-internal-nav'), 'le lanceur ne rend pas la navigation laterale de l’application');
  assert.ok(!html.includes('sc-companion-rail'), 'le lanceur ne rend pas le rail de contexte');
});

test('le lanceur garde exactement trois actions rapides, toutes deja enregistrees', () => {
  const html = render();
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  assert.equal(QUICK_ACTIONS.length, 3);
  for (const [command] of QUICK_ACTIONS) {
    assert.ok(declared.has(command), `${command} doit etre une commande deja declaree`);
    assert.ok(html.includes(`data-command="${command}"`), `${command} absent du lanceur`);
  }
  assert.equal((html.match(/class="quick-action"/g) || []).length, 3);
});

test('le lanceur n’importe aucune logique metier', () => {
  const requires = [...launcherSource().matchAll(/require\('([^']+)'\)/g)].map(([, module]) => module);
  assert.deepEqual(requires.sort(), ['./live/companionMascot', './security-center-shell', './theme-controller']);
});

// ============================================== 2. l'action principale et son geste

test('le CTA principal existe, domine la vue et ne cite pas la commande lui-meme', () => {
  const html = render();
  assert.match(html, /<button class="cta" data-open-security-center/);
  assert.match(html, /Ouvrir Security Center/);
  // Le bouton demande une intention ; c'est l'extension qui choisit la commande
  // et l'ordre des operations. Un `data-command` ici court-circuiterait le
  // repliement de la barre laterale.
  const cta = html.slice(html.indexOf('<button class="cta"'), html.indexOf('</button>', html.indexOf('<button class="cta"')));
  assert.ok(!cta.includes('data-command'), 'le CTA passe par openSecurityCenter, pas par une commande directe');
  assert.match(html, /postMessage\(\{ type: 'openSecurityCenter' \}\)/);
});

test('l’extension ouvre ou revele le dashboard PUIS replie la barre laterale', () => {
  const source = extensionSource();
  const start = source.indexOf('async openSecurityCenterFromSidebar()');
  assert.ok(start > 0, 'le geste du lanceur doit vivre dans le fournisseur');
  const body = source.slice(start, source.indexOf('openFullDashboard()', start));
  const opened = body.indexOf("securityCenter.openDashboard");
  const closed = body.indexOf('workbench.action.closeSidebar');
  assert.ok(opened > 0, 'le CTA doit reutiliser la commande d’ouverture existante');
  assert.ok(closed > opened, 'la barre ne se replie qu’APRES l’ouverture du dashboard');
  assert.ok(body.includes('await this.onCommand'), 'l’ouverture est attendue avant le repliement');
  // Le repliement masque le conteneur ; il ne detruit ni la vue ni son fournisseur.
  for (const destructive of ['this.view.dispose', 'this.view = undefined', 'registerWebviewViewProvider']) {
    assert.ok(!body.includes(destructive), `le lanceur ne doit pas ${destructive}`);
  }
});

test('le dashboard reste un singleton : il est revele, jamais duplique', () => {
  const source = extensionSource();
  const body = source.slice(source.indexOf('openFullDashboard()'), source.indexOf('openPage(page)'));
  assert.match(body, /if \(this\.fullPanel\) \{\s*this\.fullPanel\.reveal/);
  assert.equal((body.match(/createWebviewPanel\(/g) || []).length, 1, 'un seul point de creation du dashboard');
  assert.match(body, /onDidDispose\(\(\) => \{[\s\S]*this\.fullPanel = undefined;[\s\S]*\}\)/);
  assert.match(body, /cancelZapPreflightForWebview\(panel\.webview\)/);
});

test('aucune commande n’est creee pour le lanceur', () => {
  const source = extensionSource();
  for (const invented of ['securityCenter.openSecurityCenter', 'securityCenter.closeSidebar', 'securityCenter.openLauncher']) {
    assert.ok(!source.includes(`registerCommand('${invented}'`), `${invented} ne doit pas exister`);
  }
});

// ============================================================ 3. faits reels

test('l’etat de scan vient du modele, et « partiel » n’est jamais une reussite', () => {
  assert.equal(scanState({ scanStatus: 'running' }).code, 'RUNNING');
  assert.equal(scanState({ scanStatus: 'failed' }).code, 'FAILED');
  assert.equal(scanState({
    scanStatus: 'completed', completedScanners: 7, scanners: Array.from({ length: 7 }, () => ({ status: 'completed' }))
  }).code, 'COMPLETED');
  assert.equal(scanState({
    scanStatus: 'completed', completedScanners: 5, scanners: Array.from({ length: 7 }, () => ({ status: 'completed' }))
  }).code, 'PARTIAL');
  // Un statut inconnu ne devient pas « termine ».
  assert.equal(scanState({ scanStatus: 'quelque-chose' }).code, 'IDLE');
});

test('un champ indisponible disparait au lieu d’afficher une valeur inventee', () => {
  const unknown = render({ backendStatus: 'unknown' });
  assert.ok(!unknown.includes('Backend en ligne') && !unknown.includes('Backend hors ligne'));
  assert.match(render({ backendStatus: 'online' }), /Backend en ligne/);
  assert.match(render({ backendStatus: 'offline' }), /Backend hors ligne/);
  // « checking » n'est pas « hors ligne » : ce serait un diagnostic que le
  // modele n'a pas encore rendu.
  assert.match(render({ backendStatus: 'checking' }), /Vérification du backend/);
  // Sans scanner connu, aucun compteur « 0/0 ».
  assert.ok(!render().includes('scanner(s) terminé(s)'));
  assert.match(render({ scanStatus: 'completed' }, { scanners: [{ tool: 'Semgrep', status: 'completed' }], completedScanners: 1 }), /1\/1 scanner\(s\) terminé\(s\)/);
});

test('la posture montre Critical et High reels, pas les cartes du dashboard', () => {
  const html = renderSidebarLauncherHtml(buildDashboardModel(
    [
      { tool: 'Semgrep', title: 'a', rawSeverity: 'CRITICAL' },
      { tool: 'Semgrep', title: 'b', rawSeverity: 'HIGH' },
      { tool: 'Semgrep', title: 'c', rawSeverity: 'HIGH' }
    ], [], { scanStatus: 'completed' }
  ), 'n', 'light');
  assert.match(html, /<div class="stat critical"><strong>1<\/strong>/);
  assert.match(html, /<div class="stat high"><strong>2<\/strong>/);
  assert.match(html, /3 alerte\(s\) active\(s\)/);
  // Les grandes cartes KPI du dashboard n'ont pas leur place dans 250px.
  assert.ok(!html.includes('overview-kpi') && !html.includes('risk-ring'));
});

test('le nom du projet est affiche sans son chemin absolu', () => {
  assert.equal(projectName('C:\\Users\\dev\\Desktop\\pfa\\juice-shop'), 'juice-shop');
  assert.equal(projectName('/home/dev/projects/juice-shop/'), 'juice-shop');
  assert.equal(projectName(''), '');
  const html = render({ workspace: 'C:\\Users\\dev\\Desktop\\pfa\\juice-shop' });
  assert.match(html, /class="project-name"[^>]*>juice-shop</);
  assert.ok(!html.includes('C:\\Users'), 'aucun chemin absolu dans la vue');
});

// ================================================== 4. compagnon, theme, a11y

test('le lanceur montre l’etat Live avec une seule mascotte compacte', () => {
  const watching = render({}, { companion: { state: 'idle', mascotState: 'idle', liveFindingCount: 0, currentFile: 'src/users.yml' }, companionEnabled: true });
  assert.match(watching, /Watching users\.yml/);
  assert.match(watching, /No live issues detected/);
  assert.match(watching, /<strong>0<\/strong><span>Live issues<\/span>/);
  assert.match(watching, /<strong title="users\.yml">users\.yml<\/strong><span>Current file<\/span>/);
  const issues = render({}, { companion: { state: 'findings', mascotState: 'warning', liveFindingCount: 3, liveHighestSeverity: 'HIGH' }, companionEnabled: true });
  assert.match(issues, /Live issues detected/);
  assert.match(issues, /<strong>3<\/strong><span>Live issues<\/span>/);
  const off = render({}, { companion: null, companionEnabled: false });
  assert.match(off, /Live Security is off/);
  assert.match(off, /data-command="securityCenter\.openLiveSecurityPage"/);
  // L'invariant « une seule mascotte par surface » : le lanceur en rend une,
  // sans widget flottant ni seconde carte companion.
  for (const html of [watching, issues, off]) {
    assert.equal((html.match(/<img class="mascot/g) || []).length, 1, 'une seule mascotte dans le lanceur');
    assert.match(html, /src="media\/live\/security-companion\.png"/);
    assert.match(html, /data-companion-asset="local"/);
    assert.ok(!/class="sc-widget/.test(html), 'aucun widget compagnon dans le lanceur');
  }
  assert.equal(liveState({ companionEnabled: false }).active, false);
});

test('le lanceur accepte le meme URI local de mascotte que les autres webviews', () => {
  const html = renderSidebarLauncherHtml(
    { ...buildDashboardModel([], []), companion: { state: 'clean', mascotState: 'success', liveFindingCount: 0 }, companionEnabled: true },
    'n',
    'light',
    {},
    { companionImageUri: 'vscode-webview-resource:/media/live/security-companion.png', cspSource: 'vscode-webview:' }
  );
  assert.match(html, /img-src vscode-webview:/);
  assert.match(html, /src="vscode-webview-resource:\/media\/live\/security-companion\.png"/);
  assert.equal((html.match(/<img class="mascot/g) || []).length, 1);
});

test('le mini companion ne recycle jamais les grands totaux de posture workspace', () => {
  const html = render({ scanStatus: 'completed' }, {
    activeTotal: 556,
    bySeverity: { CRITICAL: 41, HIGH: 80 },
    companion: { state: 'clean', mascotState: 'success', liveFindingCount: 0, currentFile: 'src/users.yml' },
    companionEnabled: true
  });
  const liveCard = html.slice(html.indexOf('<section class="live"'), html.indexOf('</section>', html.indexOf('<section class="live"')));
  assert.match(liveCard, /<strong>0<\/strong><span>Live issues<\/span>/);
  assert.doesNotMatch(liveCard, /556|41|80|Workspace posture/);
});

test('le lanceur n’implemente pas un second systeme de theme', () => {
  const source = launcherSource();
  assert.ok(source.includes('themeOverridesCss()'), 'le lanceur reutilise le controleur de theme existant');
  assert.ok(source.includes('shellTokensCss()'), 'et les jetons du cadre partage');
  // Le theme est repropage par un nouveau rendu, comme pour les autres surfaces :
  // pas de second ecouteur `setTheme`, pas de bascule locale.
  assert.ok(!source.includes("'setTheme'"), 'aucun second canal de theme');
  assert.ok(!source.includes('themeChanged'), 'le lanceur ne pilote pas le theme');
  assert.match(render({}, {}, 'dark'), /<body class="theme-dark">/);
  assert.match(render({}, {}, 'light'), /<body class="theme-light">/);
});

test('la couche visuelle du lanceur passe par les jetons partages', () => {
  // Le bloc propre au lanceur commence apres les deux feuilles reutilisees.
  const source = launcherSource();
  const own = source.slice(source.indexOf('${shellTokensCss()}'), source.indexOf('function renderSidebarLauncherHtml'));
  const hardcoded = own.match(/#[0-9a-fA-F]{3,8}\b/g) || [];
  assert.deepEqual(hardcoded, [], `couleurs en dur dans le lanceur : ${hardcoded.join(', ')}`);
});

test('le lanceur reste utilisable au clavier et ne depend pas de la couleur seule', () => {
  const html = render({ scanStatus: 'completed', backendStatus: 'offline' });
  // Des boutons, pas des div cliquables.
  assert.ok(!/<div[^>]*data-command/.test(html), 'les actions sont des boutons');
  assert.match(html, /\.cta:focus-visible/);
  assert.match(html, /\.quick-action:focus-visible/);
  assert.match(html, /\.live-link:focus-visible/);
  assert.match(html, /aria-label="Ouvrir Security Center"/);
  assert.match(html, /aria-label="Actions rapides"/);
  // Chaque pastille porte un glyphe en plus de sa teinte.
  const pills = [...html.matchAll(/<p class="state-pill [^"]+"[\s\S]*?<\/p>/g)].map(([pill]) => pill);
  assert.ok(pills.length >= 2);
  for (const pill of pills) assert.match(pill, /class="state-glyph" aria-hidden="true">[^<]+</);
});

test('la mise en page ne fige aucune largeur et ne peut pas deborder', () => {
  const css = render();
  assert.match(css, /overflow-x: hidden/);
  assert.match(css, /grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);
  assert.match(css, /@media \(max-width: 259px\)/);
  assert.match(css, /text-overflow: ellipsis/);
  assert.match(css, /flex-wrap: wrap/);
  // Aucune largeur absolue dans le corps du lanceur : la sidebar VS Code est
  // redimensionnable de ~220px a plus de 450px.
  const own = launcherSource().slice(launcherSource().indexOf('* { box-sizing'), launcherSource().indexOf('function renderSidebarLauncherHtml') );
  assert.ok(!/(^|[^-])\bwidth: \d{3,}px/.test(own), 'aucune largeur fixe a trois chiffres');
});

// ========================================================= 5. runtime du webview

test('le lanceur n’acquiert l’API du webview qu’une seule fois', () => {
  const html = render();
  assert.equal((html.match(/acquireVsCodeApi\(\)/g) || []).length, 1);
  assert.equal((html.match(/<script/g) || []).length, 1);
});

test('le script du lanceur est syntaxiquement analysable', () => {
  const script = render().match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
  assert.doesNotThrow(() => new vm.Script(script));
});

test('le lanceur ne porte plus le garde-fou ZAP bloquant', () => {
  // Une analyse lancee depuis la barre d'activite passe par le meme orchestrateur
  // global que le dashboard. Le consentement ZAP ne doit donc plus dependre d'un
  // composant rendu ici.
  const html = render({}, {}, 'light', { zapConfirmationVisible: true, zapConfirmation: { mode: 'active', target: 'http://127.0.0.1:3000' } });
  assert.doesNotMatch(html, /role="alertdialog"/);
  assert.doesNotMatch(html, /Autoriser le scan local/);
  assert.doesNotMatch(html, /data-zap-confirm/);
  assert.doesNotMatch(html, /data-zap-cancel/);
});

test('la barre d’activite est bien la seule surface rendue par le lanceur', () => {
  const source = extensionSource();
  assert.match(source, /surface === 'sidebar'\s*\n?\s*\? renderSidebarLauncherHtml/);
  // Les autres surfaces gardent le document du dashboard, inchange.
  assert.match(source, /: renderDashboardHtml\(model, nonce, surface/);
});
