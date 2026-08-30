const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

// Le document du dashboard est desormais compose de deux fichiers : sa propre
// feuille de style et celle du cadre applicatif partage (barre laterale, zone
// centrale, rail de contexte). Les assertions portent sur la page rendue, donc
// sur la reunion des deux sources.
const dashboardSource = () => [
  fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8'),
  fs.readFileSync(path.join(__dirname, '..', 'src', 'security-center-shell.js'), 'utf8')
].join(String.fromCharCode(10));
const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/** Un jeu de findings dont chaque palier de severite est connu et distinct. */
const findings = () => [
  { id: 'c1', tool: 'Semgrep', title: 'Injection', rawSeverity: 'CRITICAL', file: 'routes/search.js', sourceContext: 'production', fingerprint: 'c1' },
  { id: 'c2', tool: 'Gitleaks', title: 'Cle', rawSeverity: 'CRITICAL', file: 'config/keys.pem', fingerprint: 'c2' },
  { id: 'h1', tool: 'Semgrep', title: 'XSS', rawSeverity: 'HIGH', file: 'routes/search.js', fingerprint: 'h1' },
  { id: 'm1', tool: 'Trivy', title: 'CVE', rawSeverity: 'MEDIUM', file: 'package-lock.json', fingerprint: 'm1' },
  { id: 'l1', tool: 'OSV-Scanner', title: 'Vieille dep', rawSeverity: 'LOW', file: 'package.json', fingerprint: 'l1' }
];

const scanners = () => [{ tool: 'Semgrep', status: 'completed', durationMs: 4200 }, { tool: 'Gitleaks', status: 'completed', durationMs: 900 }];

const fullHtml = (extra = {}) => renderDashboardHtml(
  { ...buildDashboardModel(findings(), scanners(), { scanStatus: 'completed', workspace: 'juice-shop', backendStatus: 'online' }), ...extra },
  'n', 'full', 'light', {}
);

// ============================================ les chiffres viennent du modele

test('la bande KPI compte les severites reellement presentes', () => {
  const html = fullHtml();
  // 2 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW : chaque tuile porte son propre compte.
  assert.match(html, /<div class="overview-kpi hero-metric critical"><span class="hero-metric-label"><i class="hero-metric-dot critical"><\/i>Critical<\/span><strong>2<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric high"><span class="hero-metric-label"><i class="hero-metric-dot high"><\/i>High<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric medium"><span class="hero-metric-label"><i class="hero-metric-dot medium"><\/i>Medium<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric low"><span class="hero-metric-label"><i class="hero-metric-dot low"><\/i>Low<\/span><strong>1<\/strong><\/div>/);
  // Un seul finding est marque « production ».
  assert.match(html, /<div class="overview-kpi hero-metric production">[\s\S]*Production[\s\S]*<strong>1<\/strong><small>priority findings<\/small><\/div>/);
  assert.match(html, /Scanner coverage[\s\S]*<b>100%<\/b>[\s\S]*<strong>2 \/ 2<\/strong>/);
});

test('la bande KPI tombe a zero quand aucun scanner n a termine', () => {
  const html = renderDashboardHtml(
    buildDashboardModel(findings(), [{ tool: 'Semgrep', status: 'running' }], { scanStatus: 'running' }),
    'n', 'full', 'light', {}
  );
  // Un scan en cours ne doit pas afficher les comptes d un scan qui n a pas eu
  // lieu : ils sont a zero, pas repris d ailleurs.
  assert.match(html, /<div class="overview-kpi hero-metric critical"><span class="hero-metric-label"><i class="hero-metric-dot critical"><\/i>Critical<\/span><strong>0<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric high"><span class="hero-metric-label"><i class="hero-metric-dot high"><\/i>High<\/span><strong>0<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric medium"><span class="hero-metric-label"><i class="hero-metric-dot medium"><\/i>Medium<\/span><strong>0<\/strong><\/div>/);
});

test('le donut de severite ne dessine que les paliers presents', () => {
  const html = fullHtml();
  for (const key of ['critical', 'high', 'medium', 'low']) {
    assert.match(html, new RegExp(`sev-segment sev-${key}`), `part ${key} absente`);
  }
  // Total = somme reelle des actives, pas un arrondi.
  assert.match(html, /<div class="sev-total"><strong>5<\/strong>/);
  // Aucun palier vide n est dessine.
  const onlyLow = renderDashboardHtml(
    buildDashboardModel([{ id: 'l', tool: 'OSV-Scanner', title: 'L', rawSeverity: 'LOW', file: 'p.json', fingerprint: 'l' }], scanners(), { scanStatus: 'completed' }),
    'n', 'full', 'light', {}
  );
  assert.match(onlyLow, /sev-segment sev-low/);
  assert.doesNotMatch(onlyLow, /sev-segment sev-critical/);
  assert.match(onlyLow, /<div class="sev-total"><strong>1<\/strong>/);
});

test('les zones exposees regroupent les findings deja affiches, sans en inventer', () => {
  const html = fullHtml();
  // routes/search.js porte deux findings, dont un CRITICAL : c est la ligne de tete.
  const row = html.slice(html.indexOf('class="risky-targets"'));
  assert.match(row.slice(0, 900), /routes\/search\.js/);
  assert.match(row.slice(0, 900), /risky-severity critical/);
  // Le compte affiche est bien 2, pas une estimation.
  assert.match(row.slice(0, 900), /<span class="risky-count">2<\/span>/);
  // Un modele vide n affiche aucune ligne fabriquee.
  const empty = renderDashboardHtml(buildDashboardModel([], scanners(), { scanStatus: 'completed' }), 'n', 'full', 'light', {});
  const emptyBlock = empty.slice(empty.indexOf('class="risky-targets"'));
  assert.match(emptyBlock.slice(0, 400), /class="empty"/);
});

test('aucune valeur de la maquette de reference n est codee en dur', () => {
  const source = dashboardSource();
  const start = source.indexOf('const overviewTripleRow');
  const block = source.slice(start, source.indexOf('const companionVisual'));
  assert.ok(block.length > 200, 'le bloc doit exister');
  // Les cartes ne citent que des expressions du modele.
  assert.ok(!/>\s*\d+\s*</.test(block), 'un nombre litteral est rendu dans les cartes');
  assert.ok(!/Math\.random|lorem|authController/i.test(block));
});

// ================================================ le compagnon reste le meme

test('le rail n affiche aucun compagnon quand le moteur n en fournit pas', () => {
  const html = fullHtml();
  // Le balisage, pas la feuille de style : `.sc-rail-live` y est declaree en
  // permanence, ce qui est normal — c est la carte qui ne doit pas exister.
  assert.doesNotMatch(html, /<section class="sc-rail-card sc-rail-live">/,
    'une carte compagnon sans modele serait un assistant invente');
  // Le rail existe quand meme, avec ses faits reels.
  assert.match(html, /class="sc-companion-rail"/);
  assert.match(html, /Actions rapides/);
});

test('le rail n affiche que les faits portes par le modele compagnon partage', () => {
  const html = fullHtml({
    companion: {
      state: 'findings', shortMessage: '2 problemes Live', liveFindingCount: 2,
      liveHighestSeverity: 'HIGH', currentFile: 'C:/projet/routes/search.js'
    },
    companionEnabled: true
  });
  assert.doesNotMatch(html, /<section class="sc-rail-card sc-rail-live">/,
    'les faits Live ne doivent plus etre dupliques dans une seconde carte');
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  assert.match(html, /Live Security Companion/);
  assert.match(html, /data-assistant-status-scope="live">● Attention/);
  assert.match(html, /data-assistant-fact-scope="live-file"[\s\S]*search\.js[\s\S]*Current file/,
    'le fichier courant vient du modele compagnon partage');
  assert.match(html, /data-assistant-fact-scope="live-file"[\s\S]*<strong[^>]*>2<\/strong>[\s\S]*Live issues/,
    'le compteur Live vient du modele compagnon partage');
  assert.match(html, /data-assistant-fact-scope="live-file"[\s\S]*HIGH[\s\S]*Max severity/,
    'la severite Live vient du modele compagnon partage');
  assert.doesNotMatch(html, /data-assistant-fact-scope="workspace-posture"/,
    'la posture workspace ne doit pas encombrer le hero quand Live a deja un contexte local');
  // Le compagnon desactive ne laisse aucun fait Live derriere lui.
  const off = fullHtml({ companion: { state: 'clean', liveFindingCount: 0 }, companionEnabled: false });
  assert.doesNotMatch(off, /<section class="sc-rail-card sc-rail-live">/);
  assert.doesNotMatch(off, /data-assistant-fact-scope="live-file"/);
});

test('le rail ne fabrique ni message ni compteur', () => {
  const source = dashboardSource();
  const assistant = source.slice(source.indexOf('buildAssistantCardModel({'), source.indexOf('const companionPresence'));
  // Le dashboard remet des faits deja calcules a la carte : modele companion,
  // liste courante affichee, et etat des scanners. La carte porte les libelles
  // de scope ; elle ne reconstruit pas un total concurrent.
  assert.match(assistant, /companion: companionVisual/);
  assert.match(assistant, /findings: currentActiveFindings/);
  assert.match(assistant, /scope: currentExecutionActive \? 'current-run' : 'workspace-posture'/);
  assert.match(assistant, /scanners: model\.scanners/);
  assert.ok(!/Math\.random|model\.workspacePostureFindings|model\.findings\.reduce/.test(assistant),
    'le rail ne doit pas fabriquer un compteur concurrent');
});

// ============================================ les commandes restent les memes

test('chaque action du dashboard complet atteint un handler existant et autorise', () => {
  const html = fullHtml({ companion: { state: 'clean', liveFindingCount: 0 }, companionEnabled: true });
  const source = extensionSource();
  const allowlist = source.slice(source.indexOf('const allowed = new Set(['));
  const body = allowlist.slice(0, allowlist.indexOf(']);'));
  // Les quatre pages internes sont enregistrees par une boucle a gabarit.
  const loopRegistered = new Set(['findings', 'scans', 'dynamic', 'analytics']
    .map((page) => `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`));
  const commands = [...new Set([...html.matchAll(/data-command="([^"]+)"/g)].map((match) => match[1]))];
  assert.ok(commands.length >= 25, `trop peu d actions cablees (${commands.length})`);
  for (const command of commands) {
    // Le webview demande, l extension decide : sans liste blanche, le clic est muet.
    assert.ok(body.includes(`'${command}'`), `${command} n est pas dans la liste blanche du webview`);
    if (loopRegistered.has(command)) continue;
    assert.match(source, new RegExp(`registerCommand\\('${command.replace(/\./g, '\\.')}'`),
      `${command} n a pas de handler enregistre`);
  }
});

test('les actions rapides du rail reutilisent des commandes existantes, sans doublon de logique', () => {
  const html = fullHtml();
  for (const command of ['securityCenter.scanWorkspace', 'securityCenter.openFindingsPage',
    'securityCenter.verifyFindingFix', 'securityCenter.openSecurityPipeline']) {
    assert.match(html, new RegExp(`class="sc-rail-action[^"]*" data-command="${command.replace('.', '\\.')}"`),
      `${command} absente des actions rapides`);
  }
  // Le bouton principal se desactive pendant un scan plutot que d en lancer un second.
  const running = renderDashboardHtml(
    buildDashboardModel([], [{ tool: 'Semgrep', status: 'running' }], { scanStatus: 'running' }),
    'n', 'full', 'light', {}
  );
  assert.match(running, /class="sc-rail-action primary" data-command="securityCenter\.scanWorkspace" disabled/);
});

test('toutes les pages hebergees partagent la meme barre superieure', () => {
  // Le cadre applicatif ne vit plus seulement dans le dashboard : ouvrir une
  // page interne doit rester une navigation, pas l ouverture d une autre
  // application. L en-tete « Security Center » duplique par page a donc disparu.
  for (const surface of ['full', 'findings', 'scans', 'dynamic', 'analytics', 'burp-settings', 'scanner-details']) {
    const html = renderDashboardHtml(buildDashboardModel([], []), 'n', surface, 'light', {});
    assert.match(html, /class="sc-topbar"/, `${surface} n a pas la barre partagee`);
    assert.doesNotMatch(html, /<div class="header">/, `l en-tete duplique subsiste sur ${surface}`);
    assert.match(html, /class="sc-internal-nav"/, `${surface} a perdu la navigation interne`);
    assert.equal((html.match(/id="theme-toggle"/g) || []).length, 1, `${surface} doit garder un seul bouton de theme`);
  }
  // La vue etroite de la barre d activite garde son en-tete : elle n a pas la
  // largeur d une navigation laterale.
  const sidebar = renderDashboardHtml(buildDashboardModel([], []), 'n', 'sidebar', 'light', {});
  assert.match(sidebar, /<div class="header">/);
  assert.doesNotMatch(sidebar, /class="sc-topbar"/);
  assert.doesNotMatch(sidebar, /class="sc-internal-nav"/);
});

test('la barre superieure du dashboard suit le contrat partagé sans sous-couche', () => {
  const source = dashboardSource();
  const dashboardTopbar = source.slice(source.indexOf('.sc-topbar {'), source.indexOf('body.surface-full .header-actions'));
  assert.match(dashboardTopbar, /\.sc-topbar \{[^}]*display: grid;[^}]*grid-template-columns: minmax\(0, 1fr\) auto/);
  assert.match(dashboardTopbar, /\.sc-topbar \{[^}]*margin: 0 0 20px/);
  assert.doesNotMatch(dashboardTopbar, /margin: -/);
  assert.match(source, /@media \(max-width: 680px\) \{[\s\S]*\.sc-topbar \{ grid-template-columns: 1fr;[\s\S]*margin: 0 0 16px/);
});

// ================================================= jetons, themes, structure

test('la couche visuelle du dashboard ne code aucune couleur en dur', () => {
  const source = dashboardSource();
  const start = source.indexOf('/* ================================================= dashboard complet');
  const end = source.indexOf('body.surface-sidebar { padding: 12px; }');
  const css = source.slice(start, end);
  assert.ok(css.length > 5000, 'le bloc de presentation doit exister');
  // Tout passe par --sc-* : c est ce qui permet au theme sombre d etre une
  // transformation semantique et non une seconde feuille de style.
  assert.ok(!/#[0-9a-fA-F]{3,8}\b/.test(css), 'une couleur litterale bloquerait le theme sombre');
  for (const token of ['--sc-surface', '--sc-border', '--sc-text', '--sc-muted', '--sc-primary',
    '--sc-critical', '--sc-high', '--sc-medium', '--sc-low']) {
    assert.ok(css.includes(`var(${token})`), `${token} inutilise dans la couche visuelle`);
  }
});

test('les cartes du dashboard portent une signature violette subtile et des scrollbars locales', () => {
  const source = dashboardSource();
  const start = source.indexOf('/* -------------------------------------------- Security Center hero */');
  const end = source.indexOf('body.surface-sidebar { padding: 12px; }');
  const css = source.slice(start, end);
  assert.match(css, /body\.surface-full \.overview-panel,\s*body\.surface-full \.pipeline-panel \{[^}]*border: 1px solid color-mix\(in srgb, var\(--sc-primary\) 12%, var\(--sc-border\)\)/);
  assert.match(css, /background: linear-gradient\(145deg, color-mix\(in srgb, var\(--sc-primary\) 2%, transparent\), transparent 36%\), var\(--sc-surface\)/);
  assert.match(css, /body\.surface-full \.overview-panel-head::after \{[^}]*linear-gradient\(90deg, color-mix\(in srgb, var\(--sc-primary\) 30%, transparent\)/);
  assert.match(css, /body\.surface-full \.recent-scans \{[^}]*scrollbar-width: thin;[^}]*scrollbar-color: color-mix\(in srgb, var\(--sc-primary\) 30%, var\(--sc-border\)\) transparent/);
  assert.match(css, /body\.surface-full \.recent-scans \{[^}]*scrollbar-gutter: stable/);
  assert.match(css, /\.risky-targets \{[^}]*scrollbar-gutter: stable/);
  assert.match(css, /body\.surface-full \.risky-targets::-webkit-scrollbar-thumb,\s*body\.surface-full \.overview-split > \.overview-panel:first-child::-webkit-scrollbar-thumb \{[^}]*border-radius: 999px/);
  assert.match(css, /body\.surface-full \.overview-panel:hover,[\s\S]*body\.surface-full \.pipeline-panel:hover \{[^}]*translateY\(-1px\)/);
  const reducedStart = source.indexOf('@media (prefers-reduced-motion: reduce)');
  const reducedEnd = source.indexOf('@media (min-width: 760px)', reducedStart);
  const reducedMotionBlock = source.slice(reducedStart, reducedEnd);
  assert.match(reducedMotionBlock, /body\.surface-full \.overview-panel:hover/);
  assert.match(reducedMotionBlock, /body\.surface-full \.pipeline-panel:hover/);
  assert.match(reducedMotionBlock, /transform: none/);
});

test('le dashboard complet porte un fond Security Center decoratif et inerte', () => {
  const html = fullHtml();
  const source = dashboardSource();
  assert.match(html, /<div class="sc-page-atmosphere" data-page-kind="dashboard" aria-hidden="true">/);
  assert.match(html, /class="sc-network-layer"/);
  assert.match(html, /class="sc-watermark"/);
  assert.equal((html.match(/class="sc-page-atmosphere"/g) || []).length, 1);
  assert.doesNotMatch(source, /sc-dashboard-atmosphere|sc-dashboard-network|sc-dashboard-watermark/);
  assert.match(source, /\.sc-main \{[^}]*position: relative;[^}]*isolation: isolate;[^}]*radial-gradient/);
  assert.match(source, /\.sc-page-atmosphere \{[^}]*z-index: 0;[^}]*pointer-events: none;[^}]*user-select: none/);
  assert.match(source, /\.sc-main > :not\(\.sc-page-atmosphere\):not\(\.sc-topbar\) \{ position: relative; z-index: 1; \}/);
  assert.match(source, /\.sc-network-layer path \{[^}]*stroke-dasharray: 4 16;[^}]*stroke-opacity: \.18/);
  assert.match(source, /\.sc-watermark \{[^}]*opacity: \.085;[^}]*transform: rotate\(-8deg\)/);
  assert.match(source, /body\.theme-dark \.sc-watermark \{[^}]*opacity: \.105/);
  assert.match(source, /@media \(max-width: 680px\) \{[\s\S]*\.sc-network-layer \{ display: none; \}/);
  assert.match(source, /@media \(prefers-reduced-motion: reduce\) \{[\s\S]*\.sc-page-atmosphere,[\s\S]*animation: none/);
});

test('le fond Security Center ne modifie ni actions ni donnees du dashboard', () => {
  const html = fullHtml();
  const atmosphere = html.slice(html.indexOf('class="sc-page-atmosphere"'), html.indexOf('class="sc-topbar"'));
  assert.ok(atmosphere.length > 200, 'la couche decorative doit etre rendue avant le contenu');
  assert.doesNotMatch(atmosphere, /data-command=|data-assistant-|scanner|finding|scanWorkspace/i);
  assert.doesNotMatch(atmosphere, /<img\b|https?:|cdn|fonts\.google/i);
  for (const command of ['securityCenter.scanWorkspace', 'securityCenter.openFindingsPage',
    'securityCenter.configureTeamIntegrations', 'securityCenter.openSecurityPipeline']) {
    assert.match(html, new RegExp(`data-command="${command.replace('.', '\\.')}"`),
      `${command} doit rester cablee apres ajout du fond`);
  }
});

const scansModel = () => buildDashboardModel([], [
  { tool: 'Semgrep', status: 'completed', durationMs: 30000, completedAt: '2026-08-17T21:27:45.000Z', currentRun: { resultCount: 6, findings: [] } },
  { tool: 'Gitleaks', status: 'completed', durationMs: 3000, completedAt: '2026-08-17T10:38:31.000Z', currentRun: { resultCount: 66, findings: [] } },
  { tool: 'Trivy', status: 'completed', durationMs: 25000, completedAt: '2026-08-17T10:38:31.000Z', currentRun: { resultCount: 138, findings: [] } },
  { tool: 'OSV-Scanner', status: 'completed', durationMs: 1000, completedAt: '2026-08-17T10:38:31.000Z', currentRun: { resultCount: 0, findings: [] } },
  { tool: 'SonarQube', status: 'failed', error: 'SERVER_UNAVAILABLE http://127.0.0.1:9000' },
  { tool: 'Snyk', status: 'completed', durationMs: 11000, completedAt: '2026-08-17T10:38:31.000Z', currentRun: { resultCount: 0, findings: [] } },
  { tool: 'ZAP', status: 'completed', durationMs: 85000, completedAt: '2026-08-14T18:30:36.000Z', authenticated: true, currentRun: { resultCount: 206, findings: [] } }
], {
  scanStatus: 'partial',
  workspace: 'juice-shop',
  backendStatus: 'offline',
  dynamicTargetUrl: 'http://127.0.0.1:3000'
});

test('la page Scans modernisee reste pilotee par le modele', () => {
  const html = renderDashboardHtml(scansModel(), 'n', 'scans', 'light', {}, {
    scannerLogoUris: { ZAP: 'vscode-resource:/media/scanners/zap.png' }
  });
  assert.match(html, /<div class="sc-page-atmosphere" data-page-kind="scans" aria-hidden="true">/);
  assert.match(html, /class="scan-execution-summary"/);
  assert.match(html, /<strong>7\/7 scanners terminés<\/strong>/);
  assert.match(html, /<div class="scan-summary-stat success"><span>Successful<\/span><strong>6<\/strong><\/div>/);
  assert.match(html, /<div class="scan-summary-stat failed"><span>Failed<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="scan-summary-stat total"><span>Total findings<\/span><strong>416<\/strong><\/div>/);
  assert.match(html, /<div class="scan-summary-stat dynamic"><span>Dynamic<\/span><strong>206<\/strong><\/div>/);
  assert.match(html, /Semgrep[\s\S]*SAST[\s\S]*6 findings[\s\S]*30 s[\s\S]*COMPLETED/);
  assert.match(html, /Gitleaks[\s\S]*Secrets[\s\S]*66 secrets[\s\S]*3 s[\s\S]*COMPLETED/);
  assert.match(html, /Trivy[\s\S]*SCA \/ IaC[\s\S]*138 findings[\s\S]*25 s[\s\S]*COMPLETED/);
  assert.match(html, /OSV-Scanner[\s\S]*SCA[\s\S]*0 vulnerabilities[\s\S]*1 s[\s\S]*COMPLETED/);
  const sonar = html.slice(html.indexOf('data-scanner-id="sonarqube"'), html.indexOf('data-scanner-id="snyk"'));
  assert.match(sonar, /scan-status-chip failed">FAILED/);
  assert.match(sonar, /SonarQube inaccessible/);
  assert.match(sonar, /<strong>—<\/strong><small>current run<\/small>/);
  assert.doesNotMatch(sonar, />0<\/strong><small>current run/);
  assert.doesNotMatch(html, /103 CVE|89 configuration findings|0 dependencies · 0 code · 0 IaC/);
});

test('la page Scans preserve les ids, les actions ZAP et les assets locaux', () => {
  const html = renderDashboardHtml(scansModel(), 'n', 'scans', 'light', {}, {
    scannerLogoUris: {
      Semgrep: 'vscode-resource:/media/scanners/semgrep.svg',
      Gitleaks: 'vscode-resource:/media/scanners/gitleaks.svg',
      Trivy: 'vscode-resource:/media/scanners/trivy.svg',
      'OSV-Scanner': 'vscode-resource:/media/scanners/osv-scanner.svg',
      SonarQube: 'vscode-resource:/media/scanners/sonarqube.svg',
      Snyk: 'vscode-resource:/media/scanners/snyk.svg',
      ZAP: 'vscode-resource:/media/scanners/zap.png'
    }
  });
  for (const id of ['semgrep', 'gitleaks', 'trivy', 'osv', 'sonarqube', 'snyk', 'zap']) {
    assert.match(html, new RegExp(`data-scanner-id="${id}"`), `${id} absent de la navigation scanner`);
  }
  for (const command of ['securityCenter.scanZap', 'securityCenter.configureZapCredentials', 'securityCenter.configureZap']) {
    assert.match(html, new RegExp(`data-command="${command.replace('.', '\\.')}"`), `${command} absent de la carte ZAP`);
  }
  assert.match(html, /data-retry-scanner="SonarQube"/);
  assert.match(html, /data-scanner-logo="zap"><img class="scanner-logo-img" src="vscode-resource:\/media\/scanners\/zap\.png"/);
  assert.doesNotMatch(html, /<img[^>]+src="https?:\/\//);
});

test('la couche CSS Scans est opaque, semantique et scopee', () => {
  const source = dashboardSource();
  const scansBlock = source.slice(source.indexOf('/* ------------------------------------------------------------ scans */'), source.indexOf('body.surface-sidebar { padding: 12px; }'));
  assert.match(source, /body\.surface-scans \.pipeline-panel,[\s\S]*body\.surface-scans \.page-scans,[\s\S]*background: color-mix\(in srgb, var\(--sc-surface\) 97%, transparent\)/);
  assert.match(source, /body\.surface-scans \.pipeline-scroll \{[^}]*scrollbar-width: thin;[^}]*scrollbar-color: color-mix\(in srgb, var\(--sc-primary\) 25%, transparent\) transparent/);
  assert.match(source, /body\.surface-scans \.pipeline-scroll::-webkit-scrollbar-thumb:hover \{[^}]*var\(--sc-primary\) 42%/);
  assert.match(source, /body\.surface-scans \.scan-status-chip\.completed \{[^}]*var\(--sc-success\)/);
  assert.match(source, /body\.surface-scans \.scan-status-chip\.failed \{[^}]*var\(--sc-critical\)/);
  assert.match(source, /body\.surface-scans \.scan-status-chip\.running,[\s\S]*var\(--sc-primary\)/);
  assert.match(source, /@media \(prefers-reduced-motion: reduce\) \{[\s\S]*body\.surface-scans \.scan-scanner-row,[\s\S]*transition: none/);
  assert.doesNotMatch(scansBlock, /animation-library|setInterval\(|requestAnimationFrame\(/);
});

test('la severite n est jamais portee par la couleur seule', () => {
  const html = fullHtml();
  // Chaque pastille de severite porte aussi son libelle en texte.
  assert.match(html, /<span class="risky-severity critical">CRITICAL<\/span>/);
  // Et chaque part du donut porte un <title> lisible.
  assert.match(html, /<title>Critical : 2<\/title>/);
  assert.match(html, /<span class="sev-name">High<\/span><\/span>?|<span class="sev-name">High<\/span>/);
});

test('le dashboard complet garde une structure a trois colonnes qui degrade proprement', () => {
  const source = dashboardSource();
  // Large : navigation, contenu, rail.
  assert.match(source, /\.sc-app-shell \{ display: grid; grid-template-columns: minmax\(190px, 208px\) minmax\(0, 1fr\) minmax\(210px, 262px\)/);
  // Moyen : le rail disparait, la navigation reste.
  assert.match(source, /@media \(max-width: 1200px\) \{[\s\S]{0,400}\.sc-companion-rail \{ display: none; \}/);
  // Etroit : la navigation devient un rail d icones ; les cartes s empilent.
  assert.match(source, /\.sc-app-shell,\s*\.sc-app-shell\.sc-app-shell-norail \{ grid-template-columns: 64px minmax\(0, 1fr\); \}/);
  assert.match(source, /body\.surface-full \.overview-triple \{ grid-template-columns: 1fr; \}/);
  // Le body ne se donne pas de largeur maximale : la coquille occupe l onglet.
  assert.match(source, /body\.surface-full, body\.sc-shelled \{\s*width: 100%;\s*max-width: none;\s*padding: 0;/);
  // Seul le pipeline defile horizontalement, jamais la page.
  assert.match(source, /body\.surface-full, body\.sc-shelled \{[^}]*overflow-x: hidden/);
  assert.match(source, /\.pipeline-scroll \{ overflow-x: auto;/);
});

test('aucune regle generique h2 ne peut regrossir les intitules de navigation', () => {
  const source = dashboardSource();
  // Une regle `body.surface-full h2` l emportait sur `.sc-nav-group h2` par
  // specificite et rendait « ANALYZE » plus gros qu un titre de carte.
  assert.doesNotMatch(source, /body\.surface-full h2 \{/);
  assert.match(source, /\.sc-nav-group h2 \{[^}]*font-size: 9\.5px/);
});

test('le mouvement reste optionnel', () => {
  const source = dashboardSource();
  assert.match(source, /@media \(prefers-reduced-motion: reduce\)/);
  // L animation du pipeline n existe que pour un scanner qui tourne vraiment.
  assert.match(source, /\.pipeline-dot\.running, \.pipeline-dot\.refreshing \{ position: relative; animation:/);
});

// ====================================================== injection de contenu

test('un contenu hostile ne traverse pas les nouvelles cartes', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const html = renderDashboardHtml(
    {
      ...buildDashboardModel(
        [{ id: 'x', tool: 'Semgrep', title: hostile, rawSeverity: 'CRITICAL', file: hostile, fingerprint: 'x' }],
        scanners(),
        { scanStatus: 'completed', workspace: hostile, backendStatus: 'online' }
      ),
      companion: { state: 'findings', shortMessage: hostile, liveFindingCount: 1, currentFile: hostile },
      companionEnabled: true
    },
    'n', 'full', 'light', {}
  );
  assert.ok(!html.includes('<img src=x onerror'), 'du balisage brut a traverse le rendu');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'le contenu doit etre echappe, pas supprime');
});

test('les nouvelles cartes n exposent aucune donnee que le modele n exposait deja', () => {
  const source = dashboardSource();
  const block = source.slice(source.indexOf('const themeToggleButton'), source.indexOf('const fullShellOpen'));
  // Aucune lecture de secret, d en-tete sensible ou de sortie brute de scanner.
  assert.ok(!/authorization|cookie|token|password|stdout|stderr|secret/i.test(block),
    'la couche de presentation ne doit lire aucune donnee sensible');
});

// ============================== cycle unifie de verification (Fix & Verify)

test('la carte Fix & Verify garde les etats du cycle distincts', () => {
  const fv = require('../src/fix-verification');
  // L horodatage compte : la carte montre le finding sur lequel on vient d agir,
  // donc c est la verification validee du 18 qui doit apparaitre en verdict.
  const applied = fv.markFixApplied({ id: 'a', tool: 'Semgrep', title: 'Appliquee', rawSeverity: 'HIGH', file: 'a.js', fingerprint: 'a' }, { source: 'ai', at: '2026-08-15T10:00:00.000Z' });
  let validated = fv.markFixApplied({ id: 'b', tool: 'Semgrep', title: 'Validee', rawSeverity: 'HIGH', file: 'b.js', fingerprint: 'b' }, { at: '2026-08-18T09:00:00.000Z' });
  validated = fv.applyVerification(validated, { state: 'validated', validator: 'Semgrep', reason: 'alerte disparue', at: '2026-08-18T09:30:00.000Z' });
  const regressed = fv.applyVerification(fv.markFixApplied({ id: 'c', tool: 'Semgrep', title: 'Reapparue', rawSeverity: 'CRITICAL', file: 'c.js', fingerprint: 'c' }, { at: '2026-08-16T08:00:00.000Z' }), { state: 'regressed', validator: 'Semgrep', reason: 'reapparue', at: '2026-08-16T08:40:00.000Z' });
  const html = renderDashboardHtml(
    buildDashboardModel([applied, validated, regressed], scanners(), { scanStatus: 'completed' }),
    'n', 'full', 'light', {}
  );
  const card = html.slice(html.indexOf('class="verify-tiles"'), html.indexOf('class="verify-timeline"') + 1 || undefined);
  // Une correction appliquee n est pas une correction validee : les deux
  // compteurs restent separes, comme le cycle unifie les distingue.
  assert.match(card, /<strong>1<\/strong><span>Appliquées<\/span>/);
  assert.match(card, /<strong>1<\/strong><span>Validées<\/span>/);
  assert.match(card, /<strong>1<\/strong><span>Réapparues<\/span>/);
  // Le dernier verdict cite son validateur reel, pas une formule.
  assert.match(html, /class="verify-state validated"/);
  assert.match(html, /Vérifié par Semgrep — alerte disparue/);
});

test('la chronologie n affiche que des evenements reellement dates', () => {
  const fv = require('../src/fix-verification');
  let finding = fv.markFixApplied({ id: 'a', tool: 'Semgrep', title: 'T', rawSeverity: 'HIGH', file: 'a.js', fingerprint: 'a' }, { source: 'ai', at: '2026-08-17T10:00:00.000Z' });
  finding = fv.markValidating(finding, { at: '2026-08-17T10:05:00.000Z' });
  finding = fv.applyVerification(finding, { state: 'validated', validator: 'Semgrep', reason: 'disparue', at: '2026-08-17T10:12:00.000Z' });
  const html = renderDashboardHtml(buildDashboardModel([finding], scanners(), { scanStatus: 'completed' }), 'n', 'full', 'light', {});
  const timeline = html.slice(html.indexOf('class="verify-timeline"'), html.indexOf('</ol>'));
  assert.match(timeline, /Correction appliquée \(ai\)/);
  assert.match(timeline, /Vérification lancée/);
  assert.match(timeline, /Disparition confirmée par re-scan/);
  // Aucune etape « detectee » fabriquee : ce finding ne porte pas de date de
  // detection, et une chronologie ne comble pas ses trous.
  assert.doesNotMatch(timeline, /signalée par le scanner/);
  assert.equal((timeline.match(/class="verify-event/g) || []).length, 3);
  // Sans cycle de vie, la carte le dit au lieu d inventer une frise.
  const none = renderDashboardHtml(buildDashboardModel(findings(), scanners(), { scanStatus: 'completed' }), 'n', 'full', 'light', {});
  const empty = none.slice(none.indexOf('Chronologie de vérification'));
  assert.match(empty.slice(0, 400), /class="empty"/);
});

test('les cartes du bas ne cablent que des commandes existantes', () => {
  const html = fullHtml();
  assert.match(html, /class="overview-lower"/);
  assert.match(html, /data-command="securityCenter\.verifyFindingFix"/);
  assert.match(html, /data-command="securityCenter\.showAuditLog"/);
  // Aucune action de remediation automatique n est offerte depuis le dashboard.
  const lower = html.slice(html.indexOf('class="overview-lower"'));
  assert.doesNotMatch(lower.slice(0, 4000), /generateAiFix|applyFindingFix/);
});
