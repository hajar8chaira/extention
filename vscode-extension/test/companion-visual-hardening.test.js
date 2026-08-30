const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  renderCompanionWidget, companionWidgetCss,
  WIDGET_SIZES, WIDGET_Z_INDEX, SAFE_AREA, BUBBLE_MAX_CHARS
} = require('../src/live/companionWidget');
const { renderPipelinePageHtml } = require('../src/pipeline-page');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { buildCompanionVisualModel } = require('../src/live/companionMessages');

const live = (severity = 'high', ruleId = 'dynamic-command-execution') => ({
  ruleId, severity, title: 'Commande système alimentée par une entrée utilisateur',
  range: { start: { line: 2, character: 2 }, end: { line: 2, character: 40 } },
  uri: 'file:///ws/routes/login.js', documentVersion: 1, quickFixAvailable: false
});

function visualFor({ state = 'idle', findings = [], file = 'routes/login.js', pipeline = {} } = {}) {
  return buildCompanionVisualModel({ serviceState: state, findings, file, pipeline });
}

// ------------------------------------------------------ contraste et thème

test('la bulle tire son fond ET son texte de la même paire de thème', () => {
  const css = companionWidgetCss();
  // Le bug de contraste venait d'un fond de hover widget associé au
  // --vscode-foreground générique. Les deux viennent maintenant de la même
  // paire, qui contraste par construction dans tous les thèmes.
  assert.match(css, /--sc-bubble-bg:var\(--vscode-editorHoverWidget-background,/);
  assert.match(css, /--sc-bubble-fg:var\(--vscode-editorHoverWidget-foreground,/);
  assert.match(css, /\.sc-widget-bubble\{[\s\S]*?color:var\(--sc-bubble-fg\)/);
  assert.match(css, /\.sc-widget-bubble\{[\s\S]*?background:var\(--sc-bubble-bg\)/);
});

test('chaque couleur du compagnon a un repli littéral', () => {
  const css = companionWidgetCss();
  for (const token of ['--sc-bubble-bg', '--sc-bubble-fg', '--sc-bubble-border', '--sc-bubble-muted', '--sc-bubble-shadow', '--sc-bubble-alert', '--sc-focus']) {
    const declaration = css.match(new RegExp(`${token}:([^;\\n]+)`));
    assert.ok(declaration, `${token} absent`);
    assert.match(declaration[1], /#[0-9a-fA-F]{3,8}|rgba?\(/, `${token} sans repli littéral : ${declaration[1]}`);
  }
  // Et aucune paire sombre sur sombre codée en dur.
  assert.ok(!/color:\s*#(333|444|555|666|777|888|999|000)/i.test(css));
  assert.ok(!/background:\s*#(000|111|222)\b/i.test(css));
});

test('la mascotte image garde des replis de presentation, dans les deux themes', () => {
  const css = companionWidgetCss();
  assert.match(css, /\.mascot\{[^}]*object-fit:contain/);
  assert.match(css, /filter:drop-shadow/);
  assert.match(css, /var\(--sc-accent-soft,rgba\(91,95,239,\.\d+\)\)/);
});

// ------------------------------------------------- couche non bloquante

test('la couche flottante ne capture aucun clic sur sa zone transparente', () => {
  const css = companionWidgetCss();
  assert.match(css, /\.sc-widget\{[\s\S]*?pointer-events:none/);
  assert.match(css, /\.sc-widget-mascot,\.sc-widget-bubble,\.sc-widget-action\{pointer-events:auto\}/);
  // La règle « auto » ne doit jamais viser le conteneur lui-même.
  assert.ok(!/\.sc-widget\{[^}]*pointer-events:auto/.test(css));
});

test('la zone de sécurité s’adapte et s’éloigne du bas de l’éditeur', () => {
  const css = companionWidgetCss();
  assert.match(css, new RegExp(`\\.sc-widget\\{position:fixed;right:${SAFE_AREA.wide.right}px;bottom:${SAFE_AREA.wide.bottom}px`));
  assert.match(css, new RegExp(`@media\\(max-width:1000px\\)\\{\\.sc-widget\\{right:${SAFE_AREA.medium.right}px;bottom:${SAFE_AREA.medium.bottom}px\\}\\}`));
  assert.match(css, new RegExp(`right:${SAFE_AREA.small.right}px;bottom:${SAFE_AREA.small.bottom}px`));
  // La marge basse reste franche, pour ne pas coller à la barre d'état.
  assert.ok(SAFE_AREA.wide.bottom >= 24 && SAFE_AREA.small.bottom >= 14);
  assert.ok(SAFE_AREA.wide.right >= 20);
});

test('le niveau d’empilement reste sous les modales et les popovers', () => {
  const dashboard = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  // Le garde-fou ZAP vit dans la modale VS Code, pas dans une overlay webview.
  assert.doesNotMatch(dashboard, /zap-confirmation-backdrop/);
  assert.match(dashboard, /\.pipeline-popover \{[^}]*z-index: 1000/);
  assert.ok(WIDGET_Z_INDEX > 10, 'au-dessus du contenu épinglé');
  assert.ok(WIDGET_Z_INDEX < 1000, 'sous les popovers du dashboard');
  assert.ok(WIDGET_Z_INDEX < 100, 'pas de valeur absurde');
  assert.match(companionWidgetCss(), new RegExp(`z-index:${WIDGET_Z_INDEX}`));
});

// ------------------------------------------------------------- responsive

test('une page étroite réduit la mascotte et fait taire la bulle non importante', () => {
  const css = companionWidgetCss();
  assert.match(css, /@media\(max-width:620px\)/);
  assert.match(css, /\.sc-widget:not\(\.sc-widget-important\) \.sc-widget-bubble\{display:none\}/);
  assert.match(css, new RegExp(`\\.sc-widget-full \\.mascot\\{width:${WIDGET_SIZES.full.narrow.width}px`));
  assert.match(css, new RegExp(`\\.sc-widget-compact \\.mascot\\{width:${WIDGET_SIZES.compact.narrow.width}px`));
  // Une vue très basse ne garde que la mascotte et son badge.
  assert.match(css, /@media\(max-height:420px\)/);
  // Le badge n'est jamais masqué par le responsive.
  assert.ok(!/\.sc-widget-count\{display:none/.test(css));
});

test('les deux modes restent dans leurs bandes de taille', () => {
  assert.ok(WIDGET_SIZES.full.height >= 70 && WIDGET_SIZES.full.height <= 100, 'FULL : 70–100px');
  assert.ok(WIDGET_SIZES.compact.width >= 42 && WIDGET_SIZES.compact.height <= 56, 'COMPACT : 42–56px');
  assert.ok(WIDGET_SIZES.compact.height < WIDGET_SIZES.full.height);
});

// ------------------------------------------------- affichage contextuel

test('le mode compact se tait sauf quand l’état est important', () => {
  const warning = renderCompanionWidget(visualFor({ state: 'issues', findings: [live()] }), { variant: 'compact' });
  assert.match(warning, /sc-widget-bubble/, 'un avertissement parle même en compact');
  assert.match(warning, /sc-widget-important/);
  for (const state of ['clean', 'idle', 'analyzing']) {
    const quiet = renderCompanionWidget(visualFor({ state }), { variant: 'compact' });
    assert.ok(!quiet.includes('sc-widget-bubble'), `l’état ${state} ne doit pas parler en compact`);
    assert.match(quiet, /<img class="mascot/, 'la mascotte reste visible');
  }
  // En mode full, l'analyse et l'état propre s'expriment.
  assert.match(renderCompanionWidget(visualFor({ state: 'analyzing' }), { variant: 'full' }), /sc-widget-bubble/);
  assert.match(renderCompanionWidget(visualFor({ state: 'clean' }), { variant: 'full' }), /sc-widget-bubble/);
  // Mais `idle` ne dit jamais rien, dans aucun mode.
  assert.ok(!renderCompanionWidget(visualFor({ state: 'idle', file: '' }), { variant: 'full' }).includes('sc-widget-bubble'));
});

test('la bulle reste courte, tronquée visuellement et complète au survol', () => {
  const css = companionWidgetCss();
  assert.match(css, /max-width:220px/);
  assert.match(css, /overflow-wrap:anywhere/);
  assert.match(css, /-webkit-line-clamp:2/);
  // La bulle est rembourree et lisible ; figer 11px ne garantissait rien de plus
  // qu'un pixel precis, et cassait au premier ajustement typographique.
  const padding = css.match(/\.sc-widget-bubble\{[^}]*padding:(\d+)px (\d+)px/);
  assert.ok(padding, 'la bulle doit declarer son rembourrage');
  assert.ok(Number(padding[1]) >= 6 && Number(padding[1]) <= 12, 'rembourrage vertical lisible');
  assert.ok(Number(padding[2]) >= 8 && Number(padding[2]) <= 16, 'rembourrage horizontal lisible');
  // Meme raison pour le rayon : ce qui compte est qu'elle soit arrondie, pas
  // qu'elle le soit d'exactement 11 pixels.
  const radius = css.match(/\.sc-widget-bubble\{[^}]*border-radius:(\d+)px/);
  assert.ok(radius && Number(radius[1]) >= 6 && Number(radius[1]) <= 14, 'la bulle reste arrondie');
  // L'ombre vient du jeton de theme, jamais d'une couleur codee en dur.
  assert.match(css, /\.sc-widget-bubble\{[^}]*box-shadow:[^;}]*var\(--sc-bubble-shadow\)/);
  // Une flèche pointe vers la mascotte.
  assert.match(css, /\.sc-widget-bubble::after\{content:""/);
  // Un message trop long est coupé, mais son texte complet reste accessible.
  const long = 'A'.repeat(BUBBLE_MAX_CHARS + 40);
  const widget = renderCompanionWidget(
    { mascotState: 'warning', message: { kind: 'live-findings', headline: long }, liveFindingCount: 1 },
    { variant: 'full' }
  );
  assert.ok(widget.includes('…</span>'), 'le texte visible doit être tronqué');
  assert.ok(widget.includes(`title="${long}"`), 'le texte complet doit rester accessible');
});

// -------------------------------------- priorité Live vs scan complet

test('le mode full porte la ligne projet en secondaire, le compact non', () => {
  const visual = visualFor({
    state: 'clean', findings: [],
    pipeline: { scanStatus: 'completed', scanFindingCount: 556, scanPriorityCount: 41 }
  });
  const full = renderCompanionWidget(visual, { variant: 'full' });
  // Le titre parle du fichier courant ; le scan complet est la ligne secondaire.
  assert.match(full, /sc-widget-headline">Aucun problème Live détecté dans ce fichier</);
  assert.match(full, /sc-widget-secondary">Dernier scan complet : 556 findings</);
  assert.ok(full.indexOf('sc-widget-headline') < full.indexOf('sc-widget-secondary'));
  // Le compact ne répète pas des chiffres que sa page affiche déjà.
  const compact = renderCompanionWidget(visual, { variant: 'compact' });
  assert.ok(!compact.includes('556'));
  assert.ok(!compact.includes('sc-widget-secondary'));
});

test('un finding Live courant reprend toujours le titre au scan complet', () => {
  const visual = visualFor({
    state: 'issues', findings: [live('critical', 'sql-string-concatenation')],
    pipeline: { scanStatus: 'completed', scanFindingCount: 556 }
  });
  assert.equal(visual.message.kind, 'live-critical');
  assert.equal(visual.secondary.kind, 'scan-summary');
  const full = renderCompanionWidget(visual, { variant: 'full' });
  assert.ok(full.indexOf('Attention') < full.indexOf('Dernier scan complet'));
});

// ------------------------------------------------------- couverture pages

test('le Security Pipeline rend le compagnon dans le hero du rail', () => {
  const visual = visualFor({ state: 'issues', findings: [live()] });
  const html = renderPipelinePageHtml({ tab: 'pipeline', stages: [], companion: visual, companionEnabled: true }, 'n', 'light');
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  assert.ok(!/class="sc-widget/.test(html), 'aucun widget flottant ne double le hero');
  assert.equal((html.match(/<img class="mascot/g) || []).length, 1);
  // Désactivé, la page ne porte aucune trace du compagnon.
  const off = renderPipelinePageHtml({ tab: 'pipeline', stages: [], companion: visual, companionEnabled: false }, 'n', 'light');
  assert.ok(!/class="sc-widget|class="sc-assistant/.test(off), 'aucun compagnon rendu quand le reglage est desactive');
  assert.match(off, /Security Pipeline/);
});

test('la page pipeline ne construit aucun modèle de son côté', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'pipeline-page.js'), 'utf8');
  assert.ok(!source.includes('buildCompanionVisualModel('));
  assert.ok(!source.includes('companionMessageFor('));
});

test('deux pages ouvertes montrent le même état à partir du même modèle', () => {
  const shared = visualFor({ state: 'issues', findings: [live(), live()] });
  const surfaces = [
    renderCompanionWidget(shared, { variant: 'full' }),
    renderDashboardHtml({ ...buildDashboardModel([], []), companion: shared, companionEnabled: true }, 'n', 'full', 'light'),
    renderPipelinePageHtml({ tab: 'pipeline', stages: [], companion: shared, companionEnabled: true }, 'n', 'light')
  ];
  const postures = surfaces.map((html) => (html.match(/class="mascot mascot-(\w+)/) || [])[1]);
  assert.deepEqual(postures, ['warning', 'warning', 'warning']);
  const liveCount = (html) => (
    html.match(/sc-widget-count">(\d+)/)
    || html.match(/data-assistant-fact-scope="live-file"[\s\S]*?<strong[^>]*>(\d+)<\/strong>[\s\S]*?Live issues/)
    || []
  )[1];
  const counts = surfaces.map(liveCount);
  assert.deepEqual(counts, ['2', '2', '2']);
});

// ---------------------------------------------------------- accessibilité

test('l’état n’est jamais porté par la seule couleur', () => {
  const critical = renderCompanionWidget(visualFor({ state: 'issues', findings: [live('critical', 'sql-string-concatenation')] }), { variant: 'full' });
  assert.match(critical, /sc-widget-important/);
  assert.match(critical, /aria-live="assertive"/);
  assert.match(critical, /aria-label="Security Companion — /);
  assert.match(critical, /data-companion-state="critical"/);
  // Le badge dit ce qu'il compte, pour un lecteur d'écran.
  assert.match(critical, /class="sc-widget-sr"> problème\(s\) Live dans ce fichier</);
  // Et la posture d'attention change avec l'état.
  assert.match(companionWidgetCss(), /\.mascot-critical\{animation:sc-pulse/);
});

test('un état calme reste annoncé poliment et le mouvement reste désactivable', () => {
  const calm = renderCompanionWidget(visualFor({ state: 'clean' }), { variant: 'full' });
  assert.match(calm, /aria-live="polite"/);
  const still = renderCompanionWidget({ ...visualFor({ state: 'clean' }), animations: false }, { variant: 'full' });
  assert.match(still, /sc-no-motion/);
  assert.match(companionWidgetCss(), /@media\(prefers-reduced-motion:reduce\)/);
  assert.match(companionWidgetCss(), /\.sc-no-motion \.mascot\{animation:none!important;transition:none!important\}/);
});

test('aucun chemin absolu ni secret dans le compagnon durci', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues',
    findings: [{ ...live(), uri: 'file:///C:/Users/hajar/ws/routes/login.js', title: 'Clé AKIA2E4YXQ7HZ3JLKM5P' }],
    file: 'routes/login.js'
  });
  for (const variant of ['full', 'compact']) {
    const widget = renderCompanionWidget(visual, { variant });
    assert.ok(!/[A-Za-z]:[\\/]Users/.test(widget), `chemin absolu en mode ${variant}`);
    assert.ok(!widget.includes('AKIA2E4YXQ7HZ3JLKM5P'), `secret en mode ${variant}`);
  }
});

// -------------------------------------------- cycle de vie des panneaux

test('un panneau fermé libère ses abonnements et ne rend plus rien', () => {
  const { LiveSecurityPageProvider } = require('../src/live/livePage');
  const disposed = [];
  const subscription = (name) => ({ dispose: () => disposed.push(name) });
  let panelDisposeHandler;
  const panel = {
    webview: { html: '', onDidReceiveMessage: () => {}, cspSource: '', asWebviewUri: () => ({ toString: () => '' }) },
    onDidDispose: (handler) => { panelDisposeHandler = handler; },
    reveal: () => {}, dispose: () => panelDisposeHandler?.()
  };
  const provider = new LiveSecurityPageProvider({
    api: {
      window: {
        activeTextEditor: undefined,
        onDidChangeActiveTextEditor: () => subscription('editor'),
        createWebviewPanel: () => panel
      },
      workspace: { getConfiguration: () => ({ get: (key, fallback) => fallback }) },
      Uri: { joinPath: () => ({}) }, ViewColumn: { Active: 1 }
    },
    service: { getState: () => 'clean', onDidChangeState: () => subscription('service') },
    diagnostics: { onDidChange: () => subscription('diagnostics'), findingsForDocument: () => [] },
    executeCommand: () => {}, workspacePath: 'C:/ws',
    getCompanionModel: () => visualFor({ state: 'clean' })
  });
  provider.open();
  assert.ok(provider.panel, 'le panneau est ouvert');
  // Le compagnon est rendu — porté ici par la carte d'assistant du rail, qui
  // remplace le widget flottant dès qu'elle a un fait réel à rapporter.
  assert.ok(provider.panel.webview.html.includes('sc-assistant'), 'le compagnon est rendu');
  // Fermeture par l'utilisateur : le panneau disparaît du provider.
  panel.dispose();
  assert.equal(provider.panel, undefined);
  // Un rafraîchissement du compagnon après fermeture ne doit rien tenter.
  assert.doesNotThrow(() => provider.render());
  // Et `dispose()` libère bien les trois abonnements.
  provider.dispose();
  assert.deepEqual(disposed.sort(), ['diagnostics', 'editor', 'service']);
});
