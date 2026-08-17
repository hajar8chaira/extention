const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const manifest = require('../package.json');
const extensionSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

const { renderCompanionWidget, companionWidgetCss, WIDGET_SIZES } = require('../src/live/companionWidget');
const { renderLiveSecurityPage, LiveSecurityPageProvider } = require('../src/live/livePage');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { buildCompanionVisualModel } = require('../src/live/companionMessages');
const { LiveCompanionProvider } = require('../src/live/liveCompanion');

const live = (severity = 'high', ruleId = 'dynamic-command-execution') => ({
  ruleId, severity, title: 'Commande système alimentée par une entrée utilisateur',
  range: { start: { line: 2, character: 2 }, end: { line: 2, character: 40 } },
  uri: 'file:///ws/routes/login.js', documentVersion: 1, quickFixAvailable: false
});

function visualFor({ state = 'idle', findings = [], file = 'routes/login.js', pipeline = {} } = {}) {
  return buildCompanionVisualModel({ serviceState: state, findings, file, pipeline });
}

function page(overrides = {}) {
  return renderLiveSecurityPage({
    state: 'idle', file: 'routes/login.js', supportedFile: true, findings: [],
    activity: { detected: 0, resolved: 0, prevented: 0, recent: [], tip: '' },
    ollamaModel: '', knownFindings: [], companionEnabled: true, ...overrides
  }, 'n', '', 'vscode-webview:');
}

function livePageProvider({ state = 'idle', findings = [], companionEnabled = true, executed = [] } = {}) {
  const document = { uri: { fsPath: 'C:/ws/routes/login.js' }, languageId: 'javascript' };
  return new LiveSecurityPageProvider({
    api: {
      window: { activeTextEditor: { document }, onDidChangeActiveTextEditor: () => ({ dispose() {} }) },
      workspace: { getConfiguration: () => ({ get: (key, fallback) => (key === 'live.companion.enabled' ? companionEnabled : fallback) }) },
      Uri: { joinPath: () => ({}) }, ViewColumn: { Active: 1 }
    },
    service: { getState: () => state, onDidChangeState: () => ({ dispose() {} }) },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => findings },
    executeCommand: (command, ...args) => executed.push([command, ...args]),
    workspacePath: 'C:/ws',
    getCompanionModel: () => visualFor({ state, findings })
  });
}

// ------------------------- 1-2. l'ancienne grande vue reste absente

test('la WebviewView securityCenter.liveCompanion reste absente', () => {
  assert.ok(!manifest.contributes.views.securityCenter.some((view) => view.id === 'securityCenter.liveCompanion'));
  assert.ok(!manifest.activationEvents.includes('onView:securityCenter.liveCompanion'));
  assert.deepEqual(manifest.contributes.views.securityCenter.map((view) => view.id),
    ['securityCenter.dashboard', 'securityCenter.findings']);
});

test('aucun registerWebviewViewProvider pour l’ancien identifiant', () => {
  assert.ok(!/registerWebviewViewProvider\(\s*'securityCenter\.liveCompanion'/.test(extensionSource));
  assert.ok(!extensionSource.includes("'securityCenter.liveCompanion.focus'"));
});

// ------------------------- 3-5. la page Live Security porte le compagnon

test('la page Live Security reçoit le modèle compagnon du moteur unique', () => {
  const provider = livePageProvider({ state: 'issues', findings: [live()] });
  const model = provider.model();
  assert.ok(model.companion, 'le modèle de page doit porter le modèle compagnon');
  assert.equal(model.companion.mascotState, 'warning');
  assert.equal(model.companion.liveFindingCount, 1);
  assert.equal(model.companionEnabled, true);
  // Et il vient de l'injection, pas d'un calcul local.
  assert.equal(typeof provider.getCompanionModel, 'function');
});

test('la page rend la mascotte compacte quand le compagnon est activé', () => {
  const html = page({ state: 'issues', findings: [live()], companion: visualFor({ state: 'issues', findings: [live()] }) });
  assert.equal((html.match(/<svg class="mascot/g) || []).length, 1, 'une seule mascotte');
  assert.match(html, /class="sc-widget sc-widget-full/);
  assert.match(html, /class="mascot mascot-warning/);
  // Mode FULL : bande 70–100px, très loin des 140px de l'ancien panneau.
  assert.match(html, new RegExp(`sc-widget-full \\.mascot\\{width:${WIDGET_SIZES.full.width}px;height:${WIDGET_SIZES.full.height}px`));
  assert.ok(WIDGET_SIZES.full.height <= 100 && WIDGET_SIZES.full.height >= 70);
  // Ancrée dans le document de la webview, jamais au-dessus du workbench.
  assert.match(html, /\.sc-widget\{position:fixed/);
});

test('la page ne rend rien du compagnon quand le réglage est désactivé', () => {
  const html = page({ state: 'issues', findings: [live()], companion: visualFor({ state: 'issues', findings: [live()] }), companionEnabled: false });
  assert.ok(!html.includes('<svg class="mascot'));
  assert.ok(!html.includes('sc-widget'));
  // Live Security elle-même continue de fonctionner.
  assert.match(html, /Live Security/);
  assert.match(html, /Recent Live Activity/);
  assert.match(html, /Current File/);
});

test('sans modèle compagnon, la page ne rend pas de mascotte par défaut', () => {
  const html = page({ companion: null });
  assert.ok(!html.includes('<svg class="mascot'));
  assert.match(html, /Live Security/);
});

// ------------------------- 6-7. le dashboard partage le même modèle

test('le dashboard consomme le MÊME modèle partagé que la page Live', () => {
  const shared = visualFor({ state: 'issues', findings: [live(), live()] });
  const pageHtml = page({ state: 'issues', findings: [live(), live()], companion: shared });
  const dashHtml = renderDashboardHtml({ ...buildDashboardModel([], []), companion: shared, companionEnabled: true }, 'n', 'full', 'light');
  const posture = (html) => (html.match(/class="mascot mascot-(\w+)/) || [])[1];
  assert.equal(posture(pageHtml), posture(dashHtml), 'les deux surfaces doivent afficher la même posture');
  assert.equal(posture(dashHtml), 'warning');
  // Le même objet nourrit les deux : aucun recalcul côté dashboard.
  assert.equal(shared.liveFindingCount, 2);
  assert.match(dashHtml, /sc-widget-count[^>]*>2</);
});

test('la mascotte du dashboard reste très petite et hors du flux', () => {
  const dashHtml = renderDashboardHtml({ ...buildDashboardModel([], []), companion: visualFor({ state: 'clean' }), companionEnabled: true }, 'n', 'full', 'light');
  assert.match(dashHtml, new RegExp(`sc-widget-compact \\.mascot\\{width:${WIDGET_SIZES.compact.width}px;height:${WIDGET_SIZES.compact.height}px`));
  // Mode COMPACT : bande 42–56px.
  assert.ok(WIDGET_SIZES.compact.height <= 56 && WIDGET_SIZES.compact.width >= 42, 'la présence dashboard doit rester dans la bande 42–56px');
  // Aucune carte, et rien dans le flux : le compagnon flotte en fin de document.
  assert.ok(!dashHtml.includes('companion-card'));
  assert.equal((dashHtml.match(/<svg class="mascot/g) || []).length, 1);
  const body = dashHtml.slice(dashHtml.indexOf('<body'));
  assert.ok(body.indexOf('class="sc-widget') > body.indexOf('</script>'), 'le compagnon est le dernier élément du document');
  // Et surtout pas dans `.operational-banner`, que `body.surface-full >` masque.
  assert.ok(!/operational-banner[^<]*<span[\s\S]{0,300}sc-widget/.test(dashHtml));
});

test('le compagnon compact couvre les pages du dashboard, jamais la sidebar', () => {
  for (const surface of ['full', 'findings', 'scans', 'dynamic', 'analytics']) {
    const html = renderDashboardHtml({ ...buildDashboardModel([], []), companion: visualFor({ state: 'issues', findings: [live()] }), companionEnabled: true }, 'n', surface, 'light');
    assert.match(html, /class="sc-widget sc-widget-compact/, `compagnon absent de la surface ${surface}`);
    assert.equal((html.match(/<svg class="mascot/g) || []).length, 1, `mascotte dupliquée sur ${surface}`);
  }
  // La sidebar est une bande étroite : l'arbre des vulnérabilités a besoin de la place.
  const sidebar = renderDashboardHtml({ ...buildDashboardModel([], []), companion: visualFor({ state: 'issues', findings: [live()] }), companionEnabled: true }, 'n', 'sidebar', 'light');
  assert.ok(!sidebar.includes('sc-widget'));
});

test('le dashboard ne rend rien quand le réglage est désactivé', () => {
  const html = renderDashboardHtml({ ...buildDashboardModel([], []), companion: visualFor({ state: 'issues', findings: [live()] }), companionEnabled: false }, 'n', 'full', 'light');
  assert.ok(!html.includes('sc-widget'));
  assert.match(html, /operational-banner/, 'la bannière de statut reste intacte');
});

// ------------------------- 8-12. les postures viennent de l'état réel

test('l’état warning correspond à un diagnostic Live réel', () => {
  const visual = visualFor({ state: 'issues', findings: [live('high')] });
  assert.equal(visual.mascotState, 'warning');
  assert.equal(visual.liveFindingCount, 1);
  assert.match(visual.message.headline, /commande système/);
  assert.match(renderCompanionWidget(visual, { variant: 'full' }), /mascot-warning/);
});

test('l’état clean correspond à zéro finding Live', () => {
  const visual = visualFor({ state: 'clean', findings: [] });
  assert.equal(visual.mascotState, 'success');
  assert.equal(visual.liveFindingCount, 0);
  assert.match(visual.message.headline, /Aucun problème Live détecté dans ce fichier/);
  // Aucun badge de compte quand il n'y a rien à compter.
  assert.ok(!renderCompanionWidget(visual, { variant: 'full' }).includes('sc-widget-count'));
});

test('l’état critical correspond à un finding Live critique', () => {
  const visual = visualFor({ state: 'issues', findings: [live('critical', 'sql-string-concatenation')] });
  assert.equal(visual.mascotState, 'critical');
  assert.match(renderCompanionWidget(visual, { variant: 'full' }), /sc-widget-bubble sc-important/);
  // Un critique est annoncé de façon assertive.
  assert.match(renderCompanionWidget(visual, { variant: 'full' }), /aria-live="assertive"/);
});

test('l’analyse en cours donne thinking, et Live désactivé donne sleeping', () => {
  assert.equal(visualFor({ state: 'analyzing' }).mascotState, 'thinking');
  const sleeping = visualFor({ state: 'disabled' });
  assert.equal(sleeping.mascotState, 'sleeping');
  assert.match(sleeping.message.headline, /Live Security est désactivé/);
});

test('une erreur d’analyse donne la posture error', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'error', findings: [], pipeline: { error: 'moteur Live indisponible' } });
  assert.equal(visual.mascotState, 'error');
  assert.match(visual.message.headline, /Analyse Live impossible/);
  assert.match(renderCompanionWidget(visual, { variant: 'full' }), /mascot-error/);
});

// ------------------------- 13-14. clic et absence d'IA automatique

test('cliquer le compagnon ouvre le finding avec la commande existante', () => {
  const executed = [];
  const provider = livePageProvider({ state: 'issues', findings: [live()], executed });
  provider.handleMessage({ type: 'companion' });
  assert.deepEqual(executed, [['securityCenter.openLiveFinding', 'file:///ws/routes/login.js', 1, 'dynamic-command-execution']]);
});

test('aucune correction IA n’est jamais déclenchée automatiquement', () => {
  const executed = [];
  const provider = livePageProvider({ state: 'issues', findings: [live()], executed });
  // Rendre la page, lire le modèle, cliquer le compagnon : rien n'appelle l'IA.
  provider.model();
  provider.handleMessage({ type: 'companion' });
  assert.ok(!executed.some(([command]) => command === 'securityCenter.generateLiveAiFix'));
  // Sans finding, le clic ne fait rien du tout plutôt qu'inventer une action.
  const empty = [];
  livePageProvider({ state: 'clean', findings: [], executed: empty }).handleMessage({ type: 'companion' });
  assert.deepEqual(empty, []);
  // La correction IA reste accessible, mais uniquement sur demande explicite.
  const onDemand = [];
  livePageProvider({ state: 'issues', findings: [live()], executed: onDemand })
    .handleMessage({ type: 'fix', ref: ['file:///ws/routes/login.js', 1, 'dynamic-command-execution'] });
  assert.deepEqual(onDemand, [['securityCenter.generateLiveAiFix', 'file:///ws/routes/login.js', 1, 'dynamic-command-execution']]);
});

test('la page ne relaie que les commandes que ses propres boutons émettent', () => {
  const executed = [];
  const provider = livePageProvider({ executed });
  provider.handleMessage({ type: 'command', command: 'securityCenter.disableLiveSecurity' });
  provider.handleMessage({ type: 'command', command: 'workbench.action.terminal.new' });
  provider.handleMessage({ type: 'command', command: 'securityCenter.scanWorkspace' });
  assert.deepEqual(executed, [['securityCenter.disableLiveSecurity']]);
});

// ------------------------- 15. un seul moteur d'état

test('le composant de présentation ne contient aucune logique d’état', () => {
  const widget = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionWidget.js'), 'utf8');
  // On cherche des appels, pas des mentions : la documentation peut nommer le
  // moteur sans l'invoquer.
  for (const symbol of ['buildCompanionVisualModel', 'companionMessageFor', 'findingsForDocument', 'getState', 'severityRank']) {
    assert.ok(!widget.includes(`${symbol}(`), `le widget ne doit pas appeler ${symbol}`);
  }
  assert.ok(!widget.includes("require('./companionMessages')"), 'le widget n’importe pas le moteur de messages');
  // Il ne connaît que le rendu de la mascotte.
  assert.match(widget, /require\('\.\/companionMascot'\)/);
});

test('ni la page Live ni le dashboard ne construisent un second modèle', () => {
  const livePage = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'livePage.js'), 'utf8');
  const dashboard = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  for (const source of [livePage, dashboard]) {
    assert.ok(!source.includes('buildCompanionVisualModel'), 'un seul module construit le modèle compagnon');
    assert.ok(!source.includes('companionMessageFor'), 'un seul module compose les messages');
  }
  const pipelinePage = fs.readFileSync(path.join(__dirname, '..', 'src', 'pipeline-page.js'), 'utf8');
  assert.ok(!pipelinePage.includes('buildCompanionVisualModel'), 'la page pipeline ne construit pas de modèle');
  // Chaque surface lit le même moteur, câblé une fois par surface dans
  // extension.js : Live Security, dashboard, Security Pipeline.
  assert.equal((extensionSource.match(/liveCompanionProvider\.visualModel\(\)/g) || []).length, 3);
});

// ------------------------- 16. pas de chemin absolu, pas de secret

test('aucun chemin absolu Windows ni secret dans le rendu du compagnon', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues',
    findings: [{ ...live(), uri: 'file:///C:/Users/hajar/ws/routes/login.js', title: 'Clé AWS AKIA2E4YXQ7HZ3JLKM5P détectée' }],
    file: 'routes/login.js'
  });
  const widget = renderCompanionWidget(visual, { variant: 'full' });
  assert.ok(!/[A-Za-z]:[\\/]Users/.test(widget), 'aucun chemin absolu');
  assert.ok(!widget.includes('AKIA2E4YXQ7HZ3JLKM5P'), 'aucune valeur de secret');
  // Le chemin exposé reste relatif au workspace.
  assert.equal(visual.currentFile, 'routes/login.js');
});

test('le contenu interpolé reste échappé', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues',
    findings: [{ ...live(), title: '<img src=x onerror="alert(1)">' }],
    file: '<script>bad()</script>'
  });
  const widget = renderCompanionWidget(visual, { variant: 'full' });
  assert.ok(!widget.includes('<img src=x'));
  assert.ok(!widget.includes('<script>'));
});

// ------------------------- pas de retour aux problèmes précédents

test('la mascotte définit toujours sa palette : jamais de silhouette noire', () => {
  const css = companionWidgetCss();
  for (const token of ['--sc-body', '--sc-line', '--sc-visor', '--sc-accent', '--sc-warn', '--sc-danger', '--sc-ok']) {
    assert.match(css, new RegExp(`${token}:var\\(--vscode-[\\w-]+,#[0-9a-fA-F]+\\)`), `${token} sans repli littéral`);
  }
  // Et la bulle a un repli sur chaque couleur de thème qu'elle utilise.
  assert.ok(!/background:var\(--vscode-editorHoverWidget-background\)[;}]/.test(css));
});

test('la bulle reste courte, limitée à deux lignes, et se tait quand inutile', () => {
  const css = companionWidgetCss();
  assert.match(css, /-webkit-line-clamp:2/);
  // `idle` n'a rien à dire sur une page qui parle déjà de Live Security.
  const idle = renderCompanionWidget(visualFor({ state: 'idle', file: '' }), { variant: 'full' });
  assert.ok(!idle.includes('sc-widget-bubble'), 'aucune bulle pour un état sans information');
  assert.match(idle, /<svg class="mascot/, 'la mascotte reste présente');
});

test('aucune mascotte dupliquée sur l’ensemble des surfaces', () => {
  const shared = visualFor({ state: 'issues', findings: [live()] });
  const pageHtml = page({ state: 'issues', findings: [live()], companion: shared });
  assert.equal((pageHtml.match(/<svg class="mascot/g) || []).length, 1);
  assert.ok(!pageHtml.includes('security-companion.png'), 'l’ancien avatar PNG ne coexiste plus avec la mascotte');
  const dashHtml = renderDashboardHtml({ ...buildDashboardModel([], []), companion: shared, companionEnabled: true }, 'n', 'full', 'light');
  assert.equal((dashHtml.match(/<svg class="mascot/g) || []).length, 1);
});

test('le compagnon n’occupe aucune hauteur dans le flux de la page Live', () => {
  const css = companionWidgetCss();
  // `position:fixed` le sort du flux : il ne peut pas repousser le contenu.
  assert.match(css, /\.sc-widget\{position:fixed;right:24px;bottom:28px/);
  // Et il ne capture pas les clics en dehors de ses propres éléments.
  assert.match(css, /pointer-events:none/);
  assert.match(css, /\.sc-widget-mascot,\.sc-widget-bubble,\.sc-widget-action\{pointer-events:auto\}/);
});

test('le moteur reste vivant sans surface montée', () => {
  const instance = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }) }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'clean', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [] },
    executeCommand: () => {}
  });
  assert.equal(instance.view, undefined);
  assert.doesNotThrow(() => instance.render());
  assert.equal(instance.visualModel().state, 'clean');
});
