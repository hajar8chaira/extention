const test = require('node:test');
const assert = require('node:assert/strict');
const { MASCOT_PARTS, MASCOT_VISUAL_STATES, renderMascotSvg, mascotCss } = require('../src/live/companionMascot');
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

// ------------------------------------------------------- anatomie complète

test('la mascotte a un corps complet avec membres nommés', () => {
  const svg = renderMascotSvg('idle');
  for (const part of MASCOT_PARTS) {
    assert.match(svg, new RegExp(`id="${part}"`), `partie ${part} absente`);
  }
});

test('deux bras avec mains et deux jambes avec pieds', () => {
  const svg = renderMascotSvg('idle');
  assert.equal((svg.match(/class="sc-arm /g) || []).length, 2, 'deux bras');
  assert.equal((svg.match(/class="sc-leg /g) || []).length, 2, 'deux jambes');
  assert.equal((svg.match(/class="sc-hand"/g) || []).length, 2, 'deux mains');
  assert.equal((svg.match(/class="sc-foot"/g) || []).length, 2, 'deux pieds');
  assert.match(svg, /class="sc-antenna"/);
  assert.match(svg, /class="sc-torso"/);
  assert.match(svg, /class="sc-skull"/);
});

test('chaque membre est un groupe transformable indépendamment', () => {
  const css = mascotCss();
  assert.match(css, /\.sc-arm\{transform-origin/);
  assert.match(css, /\.sc-leg\{transform-origin/);
  assert.match(css, /\.sc-head\{transform-origin/);
  assert.match(css, /\.mascot \*\{transform-box:fill-box\}/);
});

test('six expressions de visage sont dessinées', () => {
  const svg = renderMascotSvg('idle');
  for (const eyes of ['sc-eye-dot', 'sc-eye-focus', 'sc-eye-alert', 'sc-eye-happy', 'sc-eye-closed', 'sc-eye-cross']) {
    assert.match(svg, new RegExp(eyes), `expression ${eyes} absente`);
  }
});

test('chaque état révèle une expression et anime des membres', () => {
  const css = mascotCss();
  const expressions = {
    idle: 'sc-eye-dot', watching: 'sc-eye-dot', thinking: 'sc-eye-focus',
    warning: 'sc-eye-alert', critical: 'sc-eye-alert', success: 'sc-eye-happy',
    sleeping: 'sc-eye-closed', error: 'sc-eye-cross'
  };
  for (const [state, eyes] of Object.entries(expressions)) {
    assert.match(css, new RegExp(`\\.mascot-${state} \\.${eyes}\\{opacity:1`), `${state} n'affiche pas ${eyes}`);
  }
  // Les bras bougent réellement dans les états expressifs.
  for (const state of ['idle', 'watching', 'thinking', 'warning', 'critical', 'success', 'error']) {
    assert.match(css, new RegExp(`\\.mascot-${state} \\.sc-arm`), `${state} n'anime aucun bras`);
  }
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
  assert.match(css, /\.no-motion \.mascot \*\{animation:none!important/);
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
  assert.match(html, /width:112px;height:140px/);
  assert.match(html, /@media\(min-height:520px\)\{\.mascot\{width:126px/);
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
  assert.ok(!html.includes('<img '), 'la mascotte est inline, aucune image');
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
  assert.match(sidebar, /<svg class="mascot mascot-warning /);
  // Aucune surface du dashboard ne doit en contenir un second.
  for (const surface of ['sidebar', 'full', 'findings', 'scans', 'dynamic', 'analytics']) {
    const html = renderDashboardHtml(buildDashboardModel([], [], { companion: visual }), 'n', surface, 'light');
    assert.ok(!html.includes('<svg class="mascot'), `mascotte dupliquée sur la surface ${surface}`);
    assert.ok(!html.includes('companion-card'), `carte compagnon résiduelle sur ${surface}`);
  }
});

test('la mascotte définit sa propre palette, jamais de silhouette noire', () => {
  // Cause racine de la régression : les tokens pointaient vers des variables
  // inexistantes, donc `fill` devenait invalide et retombait sur le noir.
  const css = mascotCss();
  for (const token of ['--sc-body', '--sc-line', '--sc-visor', '--sc-accent', '--sc-warn', '--sc-danger', '--sc-ok']) {
    const declaration = new RegExp(`${token}:var\\(--vscode-[\\w-]+,#[0-9a-fA-F]+\\)`);
    assert.match(css, declaration, `${token} n'a pas de valeur de repli littérale`);
  }
  // Les tokens sont portés par .mascot elle-même : aucune page hôte requise.
  assert.ok(css.indexOf('.mascot{') < css.indexOf('--sc-body'), 'les tokens doivent être déclarés sur .mascot');
  // Et aucune couleur du dessin n'est écrite en dur.
  assert.ok(!/fill="#|stroke="#/.test(renderMascotSvg('warning')));
});

test('la mascotte reste colorée même sans aucune variable de thème', () => {
  const css = mascotCss();
  // Chaque propriété colorée passe par un token qui a lui-même un repli.
  for (const property of ['fill:var(--sc-body)', 'stroke:var(--sc-line)', 'fill:var(--sc-visor)', 'fill:var(--sc-accent)']) {
    assert.ok(css.includes(property), `${property} absent`);
  }
  assert.ok(!/fill:\s*(black|#000)/.test(css));
});

test('la mascotte garde un nom accessible dans la sidebar', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'issues', findings: [live()] });
  assert.match(renderMascotSvg(visual.mascotState, 'Security Companion — test'),
    /role="img" aria-label="Security Companion — test"/);
});

test('la sévérité passe par la forme, pas seulement par la couleur', () => {
  const css = mascotCss();
  assert.match(css, /\.mascot-warning \.sc-bang\{opacity:1\}/);
  assert.match(css, /\.mascot-success \.sc-check\{opacity:1/);
  assert.match(css, /\.mascot-warning \.sc-eye-alert\{opacity:1/);
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
