const test = require('node:test');
const assert = require('node:assert/strict');
const { DEFAULT_MASCOT_IMAGE, MASCOT_VISUAL_STATES, renderMascotSvg, mascotCss } = require('../src/live/companionMascot');
const { buildCompanionVisualModel, shortMessageFor, companionMessageFor, secondaryFor } = require('../src/live/companionMessages');
const { renderCompanionHtml, LiveCompanionProvider } = require('../src/live/liveCompanion');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const live = (ruleId = 'unsafe-eval', severity = 'high') => ({
  ruleId, severity, title: 'Potential unsafe eval',
  range: { start: { line: 41, character: 2 }, end: { line: 41, character: 20 } },
  uri: 'file:///routes/login.ts', documentVersion: 1, quickFixAvailable: false
});

function provider({ state = 'idle', findings = [], pipeline = {}, onVisualModel } = {}) {
  return new LiveCompanionProvider({
    api: {
      window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/routes/login.ts' } } } },
      workspace: { getConfiguration: () => ({ get: (key, fallback) => fallback }) }
    },
    service: { getState: () => state, onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => findings },
    executeCommand: () => {}, workspacePath: 'C:/ws',
    getPipelineContext: () => pipeline, onVisualModel
  });
}

// ------------------------------------------------------- asset image locale

test('la mascotte est un asset image local nomme et stable', () => {
  const html = renderMascotSvg('idle');
  assert.equal(DEFAULT_MASCOT_IMAGE, 'media/live/security-companion.png');
  assert.match(html, /^<img class="mascot mascot-idle mascot-regular"/);
  assert.match(html, /src="media\/live\/security-companion\.png"/);
  assert.match(html, /data-companion-asset="local"/);
  assert.doesNotMatch(html, /https?:\/\//);
});

test('l’ancien dessin SVG/CSS ne coexiste pas avec l’asset', () => {
  const html = renderMascotSvg('idle');
  assert.doesNotMatch(html, /<svg|<rect|<circle|<path|class="sc-arm|class="sc-leg/);
  assert.match(html, /role="img"/);
  assert.match(html, /alt="Security Companion"/);
});

test('la presentation anime l’image par transform et filtre uniquement', () => {
  const css = mascotCss();
  assert.match(css, /\.mascot\{[^}]*object-fit:contain/);
  assert.match(css, /\.mascot\{[^}]*filter:drop-shadow/);
  assert.match(css, /transform-origin:50% 78%/);
  assert.doesNotMatch(css, /left:calc|top:calc|requestAnimationFrame|setInterval|setTimeout/);
});

test('les états sont portés par des classes et un attribut de données', () => {
  for (const state of MASCOT_VISUAL_STATES) {
    const html = renderMascotSvg(state);
    assert.match(html, new RegExp(`class="mascot mascot-${state} `));
    assert.match(html, new RegExp(`data-companion-state="${state}"`));
  }
});

test('chaque état applique une motion adaptée à l’asset', () => {
  const css = mascotCss();
  const states = {
    idle: 'sc-breathe', watching: 'sc-breathe', thinking: 'sc-scan',
    warning: 'sc-attend', critical: 'sc-pulse', success: 'sc-success-pulse',
    error: 'sc-shake'
  };
  for (const [state, keyframe] of Object.entries(states)) {
    assert.match(css, new RegExp(`\\.mascot-${state}[^}]*${keyframe}`), `${state} n'applique pas ${keyframe}`);
  }
  assert.match(css, /\.mascot-sleeping\{opacity:\.72;transform:translateY\(8px\)\}/);
});

test('les huit états visuels existent et se rendent', () => {
  assert.equal(MASCOT_VISUAL_STATES.length, 8);
  for (const state of MASCOT_VISUAL_STATES) {
    assert.match(renderMascotSvg(state), new RegExp(`class="mascot mascot-${state} `));
  }
});

test('les animations restent CSS pures et désactivables deux fois', () => {
  const css = mascotCss();
  assert.ok(!/requestAnimationFrame|setInterval|setTimeout/.test(css));
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)/);
  assert.match(css, /\.no-motion \.mascot\{animation:none!important/);
});

// ------------------------------------------------ modèle visuel partagé

test('le modèle partagé porte tout ce dont les deux surfaces ont besoin', () => {
  const model = buildCompanionVisualModel({
    serviceState: 'issues', findings: [live(), live('weak-hash', 'medium')], file: 'routes/login.ts'
  });
  for (const key of ['state', 'mascotState', 'message', 'shortMessage', 'findingCount', 'highestSeverity', 'currentFile', 'actions']) {
    assert.ok(key in model, `champ ${key} manquant`);
  }
  assert.equal(model.state, 'findings');
  assert.equal(model.mascotState, 'warning');
  assert.equal(model.findingCount, 2);
  assert.equal(model.highestSeverity, 'high');
  assert.equal(model.currentFile, 'routes/login.ts');
  assert.deepEqual(model.actions, { view: true, fix: true, fullScan: true, openCompanion: true });
});

test('le message court du dashboard reste une seule clause', () => {
  const withFindings = buildCompanionVisualModel({ serviceState: 'issues', findings: [live(), live()] });
  assert.equal(withFindings.shortMessage, '2 problèmes Live');
  assert.ok(withFindings.shortMessage.length < 40);
  // La portée est toujours nommée : « aucun problème » tout court se lirait
  // comme un verdict sur l'ensemble du workspace.
  assert.equal(shortMessageFor(companionMessageFor('clean', {}), []), 'Aucun problème Live dans ce fichier');
  assert.equal(shortMessageFor(companionMessageFor('idle', { policyStatus: 'BLOCK' }), []), 'La politique bloque la livraison');
  assert.equal(shortMessageFor(companionMessageFor('disabled', {}), []), 'Live Security désactivé');
});







// --------------------------------------------------------- sidebar layout

test('la bulle pointe vers la mascotte et la précède', () => {
  const html = renderCompanionHtml(provider({ state: 'issues', findings: [live()] }).model(), 'n');
  assert.ok(html.indexOf('class="bubble') < html.indexOf('class="mascot-button"'), 'bulle au-dessus');
  // La flèche est centrée sous la bulle, donc dirigée vers le personnage.
  assert.match(html, /\.bubble::after\{content:"";position:absolute;left:50%/);
  assert.match(html, /\.stage\{margin-top:auto;display:grid;justify-items:center/);
});

test('la bulle est limitée à deux lignes et animée en douceur', () => {
  const html = renderCompanionHtml(provider().model(), 'n');
  assert.match(html, /-webkit-line-clamp:2/);
  assert.match(html, /animation:sc-bubble-in/);
});

test('le décompte est groupé avec la mascotte', () => {
  const html = renderCompanionHtml(provider({ state: 'issues', findings: [live(), live('weak-hash', 'medium')] }).model(), 'n');
  assert.match(html, /class="tally"/);
  assert.match(html, /2 Live issues/);
  assert.match(html, /1 High · 1 Medium/);
});

test('la taille du personnage s’adapte à la hauteur disponible', () => {
  const html = renderCompanionHtml(provider().model(), 'n');
  assert.match(html, /width:104px;height:130px/);
  assert.match(html, /@media\(min-height:520px\)\{\.mascot\{width:126px;height:158px/);
  assert.match(html, /@media\(max-height:300px\),\(max-width:180px\)/);
});

// ------------------------------------------------------ widget dashboard











// ---------------------------------------------------------- santé Sonar

test('SonarQube injoignable remonte au compagnon', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'idle',
    pipeline: { scannerHealth: [{ tool: 'SonarQube Server', enabled: true, reason: 'serveur injoignable — vérifiez le serveur.' }] }
  });
  assert.equal(visual.message.kind, 'scanner-health');
  // « ECONNREFUSED » devient une phrase courte et lisible.
  assert.equal(visual.message.headline, 'SonarQube injoignable');
  assert.equal(visual.mascotState, 'idle');
  assert.match(visual.shortMessage, /SonarQube injoignable/);
});

test('SonarQube désactivé ne produit aucun avertissement', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'idle',
    pipeline: { scannerHealth: [{ tool: 'SonarQube Server', enabled: false, reason: 'serveur arrêté' }] }
  });
  assert.notEqual(visual.message.kind, 'scanner-health');
});

test('un finding Live High prime sur la santé scanner et le policy BLOCK', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues', findings: [live()], file: 'a.ts',
    pipeline: { policyStatus: 'BLOCK', scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }] }
  });
  assert.equal(visual.message.kind, 'live-critical');
  assert.equal(visual.mascotState, 'warning');
});

// -------------------------------------------------- accessibilité, sécurité









test('la CSP du dashboard reste inchangée', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'idle' });
  const html = renderDashboardHtml(buildDashboardModel([], [], { companion: visual }), 'n', 'sidebar', 'light');
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(html), 'aucune ressource distante');
  assert.match(html, /img-src 'self'/);
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(html), 'aucune ressource distante');
});

test('les animations désactivées se propagent au rendu', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'idle', animations: false });
  assert.equal(visual.animations, false);
  assert.match(renderCompanionHtml({ ...provider().model(), animations: false }, 'n'), /<body class="[^"]*no-motion/);
});

// ------------------------- régression : une seule mascotte, jamais noire

test('le Companion existe dans la sidebar et nulle part ailleurs', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'issues', findings: [live()], file: 'routes/login.ts' });
  // La sidebar porte le personnage complet.
  const sidebar = renderCompanionHtml(provider({ state: 'issues', findings: [live()] }).model(), 'n');
  assert.match(sidebar, /<img class="mascot mascot-warning /);
  // Aucune surface du dashboard ne doit en contenir un second.
  for (const surface of ['sidebar', 'full', 'findings', 'scans', 'dynamic', 'analytics']) {
    const html = renderDashboardHtml(buildDashboardModel([], [], { companion: visual }), 'n', surface, 'light');
    assert.ok(!html.includes('<img class="mascot'), `mascotte dupliquée sur la surface ${surface}`);
    assert.ok(!html.includes('companion-card'), `carte compagnon résiduelle sur ${surface}`);
  }
});

test('la mascotte image conserve une presentation lisible, jamais de dessin noir CSS', () => {
  const css = mascotCss();
  assert.match(css, /\.mascot\{[^}]*filter:drop-shadow/);
  assert.match(css, /var\(--sc-accent-soft,rgba\(91,95,239,\.\d+\)\)/);
  assert.doesNotMatch(renderMascotSvg('warning'), /fill="#|stroke="#|<svg/);
});

test('la mascotte reste visible même sans aucune variable de thème', () => {
  const css = mascotCss();
  assert.match(css, /drop-shadow\(0 10px 18px var\(--sc-shadow,rgba\(15,23,42,\.\d+\)\)\)/);
  assert.match(css, /object-position:center bottom/);
  assert.ok(!/fill:\s*(black|#000)/.test(css));
});

test('la mascotte garde un nom accessible dans la sidebar', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'issues', findings: [live()] });
  assert.match(renderMascotSvg(visual.mascotState, 'Security Companion — test'),
    /alt="Security Companion — test" role="img"/);
});

test('la sévérité passe par la forme, pas seulement par la couleur', () => {
  const css = mascotCss();
  assert.match(css, /\.mascot-warning\{animation:sc-attend/);
  assert.match(css, /\.mascot-critical\{animation:sc-pulse/);
  assert.match(renderMascotSvg('warning'), /data-companion-state="warning"/);
});

// ------------------- régression : Live et scan complet ne se mélangent jamais

test('un fichier Live propre dans un workspace à 556 findings ne se contredit pas', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'clean',
    findings: [],                       // le fichier courant est propre
    file: 'src/routes/login.ts',
    pipeline: { scanStatus: 'completed', scanFindingCount: 556, scanPriorityCount: 41 }
  });
  const text = `${visual.message.headline} ${visual.message.detail}`;
  // Le bug : « Aucun problème détecté » collé à « 556 finding(s) ».
  assert.ok(!/Aucun problème détecté/.test(text), `message contradictoire : ${text}`);
  assert.ok(!/556/.test(text), `le compte du scan n'appartient pas au message du fichier : ${text}`);
  // Le fichier courant garde le message principal ; le scan passe en secondaire.
  assert.equal(visual.message.kind, 'clean');
  assert.match(visual.message.headline, /Aucun problème Live détecté dans ce fichier/);
  assert.equal(visual.secondary.kind, 'scan-summary');
  assert.match(visual.secondary.headline, /Dernier scan complet : 556 findings/);
});

test('le modèle expose séparément les findings Live et ceux du scan complet', () => {
  const visual = buildCompanionVisualModel({
    serviceState: 'issues',
    findings: [live(), live()],
    pipeline: { scanStatus: 'completed', scanFindingCount: 556, scanPriorityCount: 41 }
  });
  assert.equal(visual.liveFindingCount, 2);
  assert.equal(visual.fullScan.findingCount, 556);
  assert.equal(visual.fullScan.priorityCount, 41);
  // Les problèmes Live du fichier passent devant le compte rendu du scan.
  assert.equal(visual.shortMessage, '2 problèmes Live');
});

test('sans scan connu, aucun compte de scan n’est inventé', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'clean', findings: [], file: 'a.js' });
  assert.equal(visual.fullScan.findingCount, null);
  assert.equal(visual.fullScan.status, '');
  assert.ok(!/0 finding/.test(`${visual.message.headline} ${visual.message.detail}`));
  assert.match(visual.message.headline, /Aucun problème Live détecté dans ce fichier/);
});

test('un scan complet sans finding reste la seule bonne nouvelle autorisée', () => {
  const clean = secondaryFor(null, { scanStatus: 'completed', scanFindingCount: 0 });
  assert.equal(clean.mascot, 'success');
  const loaded = secondaryFor(null, { scanStatus: 'completed', scanFindingCount: 556 });
  assert.notEqual(loaded.mascot, 'success');
});
