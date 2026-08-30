'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const manifest = require('../package.json');
const shell = require('../src/security-center-shell');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderScanHistoryHtml } = require('../src/scan-history-page');
const { renderAuditLogHtml } = require('../src/audit');
const { buildTrendReport, renderTrendReportHtml } = require('../src/trends');
const { renderPipelinePageHtml } = require('../src/pipeline-page');
const { renderDeliveryPageHtml } = require('../src/delivery-page');
const { renderIntegrationPageHtml } = require('../src/integrations-page');
const { renderRuntimeSecurityPageHtml, renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');
const { renderFindingDetailsHtml } = require('../src/finding-details');
const { renderScanComparisonHtml } = require('../src/scan-comparison');
const { deliveryStatusFrom } = require('../src/jenkins');

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
const shellSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'security-center-shell.js'), 'utf8');

const trendReport = buildTrendReport([], [], 90, new Date('2026-08-03T00:00:00Z'));

/**
 * Chaque page majeure de Security Center, avec l'item de navigation qu'elle doit
 * marquer et un fragment de son propre contenu. Le fragment est ce qui prouve
 * que la migration n'a pas remplace la page par la coquille.
 */
const PAGES = [
  ['Dashboard', 'securityCenter.openDashboard', /Pipeline d’analyse/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'full', theme)],
  ['Findings', 'securityCenter.openFindingsPage', /class="findings-summary"/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'findings', theme)],
  ['Scans', 'securityCenter.openScansPage', /class="page-scans"/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'scans', theme)],
  ['Scanner Details', 'securityCenter.openScansPage', /class="page-scanner-details"/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'scanner-details', theme)],
  ['Dynamic Security', 'securityCenter.openDynamicPage', /Trafic HTTP/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', theme)],
  ['Runtime Security', 'securityCenter.openRuntimeSecurity', /Connect your SIEM/,
    (theme) => renderRuntimeSecurityPageHtml({}, 'n', theme)],
  ['Infrastructure', 'securityCenter.openInfrastructure', /Connect observability/,
    (theme) => renderInfrastructurePageHtml({}, 'n', theme)],
  ['Analytics', 'securityCenter.openAnalyticsPage', /class="analytics-grid"/,
    (theme) => renderDashboardHtml(buildDashboardModel([], []), 'n', 'analytics', theme)],
  ['Scan History', 'securityCenter.showScanHistoryPage', /Sauvegardes locales/,
    (theme) => renderScanHistoryHtml([], [], '', 'n', theme)],
  // La comparaison allume la section a laquelle elle appartient : l'historique.
  ['Compare Scans', 'securityCenter.showScanHistoryPage', /id="selection-card-A"/,
    (theme) => renderScanComparisonHtml([], 'n', theme)],
  ['Audit Journal', 'securityCenter.showAuditLog', /id="audit-empty"/,
    (theme) => renderAuditLogHtml([], 'n', theme)],
  ['Trends & MTTR', 'securityCenter.showTrends', /id="kpi-active-val"/,
    (theme) => renderTrendReportHtml(trendReport, 'n', theme)],
  ['Security Pipeline', 'securityCenter.openSecurityPipeline', /data-tab="correlations"/,
    (theme) => renderPipelinePageHtml({ tab: 'pipeline' }, 'n', theme)],
  ['Security Delivery', 'securityCenter.openSecurityDelivery', /id="jenkins-form"/,
    (theme) => renderDeliveryPageHtml(deliveryStatusFrom({ configured: false }), 'n', theme)],
  ['Integrations', 'securityCenter.configureTeamIntegrations', /data-provider="prometheus"/,
    (theme) => renderIntegrationPageHtml({}, 'n', theme)],
  ['Scanner Configuration', 'securityCenter.openScannerSetup', /id="install-all"/,
    (theme) => renderScannerSetupHtml([], 'n', theme)],
  ['Finding Details', 'securityCenter.openFindingsPage', /Plan de correction/,
    (theme) => renderFindingDetailsHtml({ tool: 'ZAP', title: 'CORS', rawSeverity: 'LOW', ruleId: 'cors' }, 'n', { theme })]
];

/** Les items cliquables du rail, tels que rendus. */
function navItems(markup) {
  return [...markup.matchAll(/<button class="sc-nav-item([^"]*)"([^>]*)>/g)].map(([, classes, attributes]) => ({
    active: classes.includes('active'),
    command: (attributes.match(/data-command="([^"]+)"/) || [])[1],
    current: attributes.includes('aria-current="page"')
  }));
}

// ============================================ une seule application, partout

test('chaque page majeure rend la navigation interne partagée', () => {
  for (const [name, , , render] of PAGES) {
    const html = render('light');
    assert.match(html, /class="sc-internal-nav"/, `${name} n a pas la navigation partagee`);
    assert.match(html, /class="sc-app-shell/, `${name} n est pas dans la coquille`);
    assert.match(html, /class="sc-main"/, `${name} n a pas de colonne centrale`);
  }
});

test('chaque page marque exactement son propre item de navigation', () => {
  for (const [name, command, , render] of PAGES) {
    const active = navItems(render('light')).filter((item) => item.active);
    assert.equal(active.length, 1, `${name} doit marquer exactement un item`);
    assert.equal(active[0].command, command, `${name} marque le mauvais item`);
    assert.ok(active[0].current, `${name} doit porter aria-current`);
  }
});

test('chaque page garde son contenu propre', () => {
  // La migration entoure les pages ; elle ne les remplace pas par un dashboard.
  for (const [name, , ownContent, render] of PAGES) {
    assert.match(render('light'), ownContent, `${name} a perdu son contenu specifique`);
  }
});

test('chaque page majeure reçoit la même atmosphère Security Center partagée', () => {
  const expectedKinds = {
    Dashboard: 'dashboard',
    Findings: 'investigation',
    Scans: 'scans',
    'Scanner Details': 'details',
    'Dynamic Security': 'dynamic',
    'Runtime Security': 'runtime',
    Infrastructure: 'infrastructure',
    Analytics: 'investigation',
    'Scan History': 'investigation',
    'Compare Scans': 'investigation',
    'Audit Journal': 'investigation',
    'Trends & MTTR': 'investigation',
    'Security Pipeline': 'flow',
    'Security Delivery': 'flow',
    Integrations: 'configuration',
    'Scanner Configuration': 'configuration',
    'Finding Details': 'details'
  };
  for (const [name, , , render] of PAGES) {
    const html = render('light');
    const expectedKind = expectedKinds[name];
    assert.match(html, new RegExp(`<main class="sc-main" data-page-kind="${expectedKind}"`),
      `${name} n expose pas le variant visuel partage`);
    assert.match(html, new RegExp(`<div class="sc-page-atmosphere" data-page-kind="${expectedKind}" aria-hidden="true">`),
      `${name} n a pas l atmosphere partagee`);
    assert.equal((html.match(/class="sc-page-atmosphere"/g) || []).length, 1,
      `${name} doit rendre une seule couche d atmosphere`);
    assert.match(html, /class="sc-glow-layer"/, `${name} n a pas le halo violet`);
    assert.match(html, /class="sc-network-layer"[^>]*focusable="false" aria-hidden="true"/,
      `${name} n a pas le motif reseau decoratif`);
    assert.match(html, /class="sc-watermark"/, `${name} n a pas le filigrane bouclier`);
    const atmosphere = html.slice(html.indexOf('class="sc-page-atmosphere"'), html.indexOf('class="sc-topbar"'));
    assert.doesNotMatch(atmosphere, /data-command=|data-action=|scanWorkspace|finding|scanner/i,
      `${name} a melange decoration et comportement`);
    assert.doesNotMatch(atmosphere, /https?:|<img\b|cdn|fonts\.google/i,
      `${name} charge une ressource distante dans le fond`);
  }
});

test('l atmosphere partagee est visible, non interactive, responsive et themable', () => {
  const css = shell.shellLayoutCss() + shell.shellTopbarCss();
  assert.match(css, /\.sc-main \{[^}]*isolation: isolate;[^}]*overflow-x: hidden;[^}]*radial-gradient/);
  assert.match(css, /\.sc-page-atmosphere \{[^}]*pointer-events: none;[^}]*user-select: none/);
  assert.match(css, /\.sc-watermark \{[^}]*width: clamp\(470px, 40vw, 700px\);[^}]*opacity: \.085/);
  assert.match(css, /\.sc-page-atmosphere\[data-page-kind="dashboard"\] \.sc-watermark \{[^}]*opacity: \.078/);
  assert.match(css, /\.sc-page-atmosphere\[data-page-kind="details"\] \.sc-watermark \{[^}]*opacity: \.095/);
  assert.match(css, /body\.theme-dark \.sc-watermark \{[^}]*opacity: \.105/);
  assert.match(css, /\.sc-network-layer path \{[^}]*stroke-opacity: \.18/);
  assert.match(css, /@media \(max-width: 1200px\) \{[\s\S]*\.sc-watermark \{[^}]*width: min\(590px, 58vw\)/);
  assert.match(css, /@media \(max-width: 680px\) \{[\s\S]*\.sc-network-layer \{ display: none; \}/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{[\s\S]*\.sc-page-atmosphere,[\s\S]*animation: none/);
});

test('la barre superieure partagee reserve son espace sans marge negative', () => {
  const css = shell.shellTopbarCss();
  assert.match(css, /\.sc-topbar \{[^}]*position: sticky;[^}]*top: 0;[^}]*z-index: 5/);
  assert.match(css, /\.sc-topbar \{[^}]*display: grid;[^}]*grid-template-columns: minmax\(0, 1fr\) auto/);
  assert.match(css, /\.sc-topbar \{[^}]*margin: 0 0 20px/);
  assert.doesNotMatch(css, /\.sc-topbar \{[^}]*margin: -/);
  assert.match(css, /\.sc-topbar-title \{ min-width: 0; \}/);
  assert.match(css, /\.sc-topbar-actions \{[^}]*flex-wrap: wrap;[^}]*min-width: 0/);
  assert.match(css, /@media \(max-width: 680px\) \{[\s\S]*\.sc-topbar \{ grid-template-columns: 1fr;[\s\S]*margin: 0 0 16px/);
});

test('aucune page ne duplique l en-tête global Security Center', () => {
  for (const [name, , , render] of PAGES) {
    const html = render('light');
    const body = html.slice(html.indexOf('<body'));
    // Le nom du produit vit dans le rail : une seule occurrence, la marque.
    const brands = (body.match(/Security Center<\/strong>/g) || []).length;
    assert.equal(brands, 1, `${name} affiche ${brands} en-tetes Security Center`);
    assert.doesNotMatch(body, /← Dashboard/, `${name} garde un lien de retour duplique`);
    assert.equal((html.match(/class="sc-topbar"/g) || []).length, 1,
      `${name} doit avoir exactement une barre superieure`);
  }
});

// ============================================================ thème unique

test('chaque page rend les deux thèmes avec le même contrat', () => {
  for (const [name, , , render] of PAGES) {
    const light = render('light');
    const dark = render('dark');
    assert.match(light, /<body class="[^"]*theme-light[^"]*"/, `${name} : thème clair absent`);
    assert.match(dark, /<body class="[^"]*theme-dark[^"]*"/, `${name} : thème sombre absent`);
    // Un seul contrat de thème dans tout le produit. Les pages hebergees par le
    // cadre ecoutent `setTheme` ; la famille du dashboard est re-rendue par son
    // provider, qui porte le bouton de bascule. Aucune n'invente un troisieme
    // mecanisme.
    const listens = /'setTheme'/.test(light);
    const rerendered = /id="theme-toggle"/.test(light);
    assert.ok(listens || rerendered, `${name} n a pas de contrat de theme`);
    assert.doesNotMatch(light, /'setThemeMode'|'changeTheme'|'applyTheme'/,
      `${name} invente un second message de theme`);
  }
});

test('le cadre définit ses jetons dans les deux thèmes', () => {
  const css = shell.shellTokensCss();
  for (const token of ['--sc-muted', '--sc-primary-soft', '--sc-radius-md', '--sc-shadow-sm']) {
    assert.match(css, new RegExp(`${token}:`), `${token} absent du cadre`);
  }
  assert.match(css, /body\.theme-light \{[\s\S]*?--sc-primary-soft/);
  assert.match(css, /body\.theme-dark \{[\s\S]*?--sc-primary-soft/);
});

// ==================================================== frontière de confiance

test('la navigation ne cite que des commandes déclarées et enregistrées', () => {
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  const source = extensionSource();
  const loopRegistered = new Set(['findings', 'scans', 'dynamic', 'analytics']
    .map((page) => `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`));
  for (const command of shell.navCommands()) {
    assert.ok(declared.has(command), `${command} n est pas declaree dans package.json`);
    if (loopRegistered.has(command)) continue;
    assert.match(source, new RegExp(`registerCommand\\('${command.replace(/\./g, '\\.')}'`),
      `${command} n a pas de handler`);
  }
});

test('chaque page hébergée passe la navigation par la frontière de confiance', () => {
  const source = extensionSource();
  // Un webview demande, l'extension decide : un seul relais, verifie une fois.
  assert.match(source, /async function handleShellNavMessage\(message\) \{/);
  assert.match(source, /SHELL_NAV_COMMANDS\.has\(message\.command\)/);
  // Toutes les surfaces migrees s'y branchent.
  const uses = (source.match(/handleShellNavMessage\(message\)/g) || []).length;
  assert.ok(uses >= 7, `seulement ${uses} surfaces relaient la navigation partagee`);
});

test('aucune page ne recâble la navigation deux fois', () => {
  // Les pages qui ecoutaient deja tous les `[data-command]` doivent exclure les
  // items du rail, sinon un clic enverrait deux fois la meme commande.
  for (const file of ['pipeline-page.js', 'delivery-page.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
    assert.match(source, /\[data-command\]:not\(\.sc-nav-item\)/, `${file} double le relais de navigation`);
  }
});

// ================================================================ sécurité

test('le contenu hostile ne traverse pas le cadre', () => {
  const html = shell.renderSecurityCenterShell({
    surface: 'findings',
    nonce: 'n',
    title: '<script>alert(1)</script>',
    subtitle: '"><img onerror=alert(1)>',
    content: '<p>contenu</p>'
  });
  assert.doesNotMatch(html, /<script>alert\(1\)/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /"><img onerror/);
});

test('le cadre ne fabrique aucune donnée de sécurité', () => {
  const source = shellSource();
  // Le cadre ne depend d'aucun modele : il ne peut donc pas inventer un
  // compteur, un finding ou un etat de scanner. Il n'encadre que du HTML deja
  // produit par la page.
  const requires = [...source.matchAll(/require\('([^']+)'\)/g)].map(([, name]) => name);
  assert.deepEqual(requires, ['./theme-controller'], 'le cadre ne doit dependre que du theme');
  // Une page vide reste vide : aucune valeur de remplissage.
  const empty = shell.renderSecurityCenterShell({ surface: 'audit', nonce: 'n', content: '' });
  const main = empty.slice(empty.indexOf('<main class="sc-main">'), empty.indexOf('</main>'));
  assert.doesNotMatch(main, /\d+\s*(alerte|finding|scan)/i, 'le cadre ne doit afficher aucun compteur');
});

// ============================================================== responsive

test('le cadre dégrade sans jamais supprimer la navigation', () => {
  const css = shell.shellLayoutCss();
  assert.match(css, /\.sc-app-shell \{ display: grid; grid-template-columns: minmax\(190px, 208px\) minmax\(0, 1fr\) minmax\(210px, 262px\)/);
  assert.match(css, /@media \(max-width: 1200px\) \{[\s\S]{0,400}\.sc-companion-rail \{ display: none; \}/);
  assert.match(css, /\.sc-app-shell,\s*\.sc-app-shell\.sc-app-shell-norail \{ grid-template-columns: 64px minmax\(0, 1fr\); \}/);
  assert.match(css, /\.sc-main \{[^}]*min-width: 0;/);
});

test('une page sans rail garde deux colonnes plutôt qu un trou', () => {
  const html = shell.renderSecurityCenterShell({ surface: 'audit', nonce: 'n', content: '<p>x</p>' });
  assert.match(html, /class="sc-app-shell sc-app-shell-norail"/);
  assert.doesNotMatch(html, /class="sc-companion-rail"/);
  assert.match(shell.shellLayoutCss(), /\.sc-app-shell-norail \{ grid-template-columns: minmax\(190px, 208px\) minmax\(0, 1fr\); \}/);
});

// ================================================ preservation des commandes

test('toutes les actions majeures restent joignables et inchangées', () => {
  // La migration ne renomme, ne supprime et ne remplace aucune commande : ce
  // test fige la liste que l'utilisateur doit pouvoir atteindre.
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  const source = extensionSource();
  const required = [
    'securityCenter.scanWorkspace', 'securityCenter.scanIncremental', 'securityCenter.compareScans',
    'securityCenter.openFindingsPage', 'securityCenter.openFindingCode', 'securityCenter.verifyFindingFix',
    'securityCenter.generateAiFix', 'securityCenter.rollbackAiFix', 'securityCenter.openDynamicPage',
    'securityCenter.showScanHistoryPage', 'securityCenter.showScanHistory', 'securityCenter.showAuditLog',
    'securityCenter.showTrends', 'securityCenter.openSecurityPipeline', 'securityCenter.openSecurityDelivery',
    'securityCenter.generateSbom', 'securityCenter.checkLicenses', 'securityCenter.openScannerSetup',
    'securityCenter.openProjectPolicy', 'securityCenter.configureOllama', 'securityCenter.configureTeamIntegrations',
    'securityCenter.openRuntimeSecurity', 'securityCenter.openInfrastructure',
    'securityCenter.configureSiem', 'securityCenter.configureObservability',
    'securityCenter.openScansPage', 'securityCenter.openAnalyticsPage', 'securityCenter.openDashboard',
    'securityCenter.openLiveSecurityPage', 'securityCenter.scanZap'
  ];
  // Les quatre pages internes sont enregistrees par une boucle a gabarit.
  const loopRegistered = new Set(['findings', 'scans', 'dynamic', 'analytics']
    .map((page) => `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`));
  // Commandes internes : enregistrees et appelees par le produit, volontairement
  // absentes de la palette. Elles n'apparaissent pas dans package.json.
  const internalOnly = new Set(['securityCenter.openFindingCode']);
  for (const command of required) {
    if (!internalOnly.has(command)) {
      assert.ok(declared.has(command), `${command} a disparu de package.json`);
    }
    if (loopRegistered.has(command)) continue;
    assert.match(source, new RegExp(`registerCommand\\('${command.replace(/\./g, '\\.')}'`),
      `${command} n a plus de handler`);
  }
});

test('les pages migrées gardent leurs propres messages métier', () => {
  // Chaque page continue de parler a son handler d'origine : le cadre n'a
  // remplace aucun de ces contrats.
  const contracts = [
    ['scan-history-page.js', /command: 'loadScan'/],
    ['audit.js', /filter-search/],
    ['trends.js', /data-days/],
    ['pipeline-page.js', /type:'action',action:b\.dataset\.action/],
    ['delivery-page.js', /type:'action',action,config:config\(\)/],
    ['scanner-setup-page.js', /type:'requestInstall',tool:/],
    ['finding-details.js', /type: 'generateAiFix'/],
    ['scan-comparison.js', /command: 'compare'/]
  ];
  for (const [file, contract] of contracts) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
    assert.match(source, contract, `${file} a perdu son contrat metier`);
  }
});

// ============================================ une seule acquisition d'API

test('une page hébergée n acquiert l API du webview qu une seule fois', () => {
  // `acquireVsCodeApi()` leve des qu'elle est appelee deux fois dans un meme
  // webview. Le cadre l'acquiert et la partage ; le script de la page la
  // reutilise. Les deux occurrences textuelles doivent donc etre gardees.
  const guardedPages = PAGES.filter(([name]) => ![
    'Dashboard', 'Findings', 'Scans', 'Scanner Details', 'Dynamic Security', 'Analytics'
  ].includes(name));
  for (const [name, , , render] of guardedPages) {
    const html = render('light');
    const acquisitions = (html.match(/acquireVsCodeApi\(\)/g) || []).length;
    const guards = (html.match(/window\.__scShellApi\s*\|\|/g) || []).length;
    assert.ok(acquisitions >= 1, `${name} n acquiert jamais l API`);
    assert.equal(guards, acquisitions,
      `${name} : ${acquisitions} acquisitions pour ${guards} gardes — la seconde leverait`);
  }
});

test('les ruptures s appliquent aussi aux pages sans rail de contexte', () => {
  // Regression : `.sc-app-shell.sc-app-shell-norail` (0,2,0) l emportait sur le
  // `.sc-app-shell` (0,1,0) des media queries. Les pages sans rail — Historique,
  // Comparaison, Audit, Tendances, Delivery — gardaient donc une navigation de
  // 208px a toutes les largeurs au lieu de se replier en rail d icones, ce qui
  // provoquait un debordement horizontal sur les pages denses.
  const css = shell.shellLayoutCss();
  const medium = css.slice(css.indexOf('@media (max-width: 1200px)'), css.indexOf('@media (max-width: 980px)'));
  const narrow = css.slice(css.indexOf('@media (max-width: 980px)'));
  assert.match(medium, /\.sc-app-shell\.sc-app-shell-norail \{ grid-template-columns: minmax\(180px, 202px\)/,
    'la rupture moyenne ignore les pages sans rail');
  assert.match(narrow, /\.sc-app-shell\.sc-app-shell-norail \{ grid-template-columns: 64px/,
    'la rupture etroite ignore les pages sans rail');
});
