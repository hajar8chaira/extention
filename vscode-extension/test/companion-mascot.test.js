const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { MASCOT_VISUAL_STATES, mascotVisualFor, renderMascotSvg, mascotCss, DEFAULT_MASCOT_IMAGE } = require('../src/live/companionMascot');
const { renderCompanionHtml, LiveCompanionProvider } = require('../src/live/liveCompanion');
const { companionMessageFor } = require('../src/live/companionMessages');

const finding = (overrides = {}) => ({
  ruleId: 'unsafe-eval', severity: 'high', title: 'Potential unsafe eval',
  range: { start: { line: 41, character: 2 }, end: { line: 41, character: 20 } },
  uri: 'file:///routes/login.ts', documentVersion: 1, quickFixAvailable: false, ...overrides
});

function model(overrides = {}) {
  return { state: 'idle', companionState: 'idle', file: 'routes/login.ts', findings: [], ...overrides };
}

// ------------------------------------------------------------- états visuels

test('les huit états visuels demandés existent', () => {
  assert.deepEqual(MASCOT_VISUAL_STATES,
    ['idle', 'watching', 'thinking', 'warning', 'critical', 'success', 'sleeping', 'error']);
});

test('chaque état companion se projette sur un état visuel', () => {
  assert.equal(mascotVisualFor('idle'), 'idle');
  assert.equal(mascotVisualFor('watching'), 'watching');
  assert.equal(mascotVisualFor('analyzing'), 'thinking');
  assert.equal(mascotVisualFor('findings', { severity: 'high' }), 'warning');
  assert.equal(mascotVisualFor('findings', { severity: 'critical' }), 'critical');
  assert.equal(mascotVisualFor('clean'), 'success');
  assert.equal(mascotVisualFor('disabled'), 'sleeping');
  assert.equal(mascotVisualFor('error'), 'error');
  assert.equal(mascotVisualFor('degraded'), 'warning');
});

test('le vocabulaire du service Live est accepté aussi', () => {
  // Sans cette normalisation la mascotte restait « idle » sur un vrai finding.
  assert.equal(mascotVisualFor('issues', { severity: 'high' }), 'warning');
  assert.equal(mascotVisualFor('paused'), 'warning');
});

test('un policy BLOCK rend la mascotte critique', () => {
  assert.equal(mascotVisualFor('idle', { policyStatus: 'BLOCK' }), 'critical');
});

test('un état inconnu retombe sur idle sans planter', () => {
  assert.equal(mascotVisualFor(undefined), 'idle');
  assert.equal(mascotVisualFor('n’importe quoi'), 'idle');
});

// ------------------------------------------------------------------- asset

test('la mascotte est une image locale packagee, sans URL distante', () => {
  const html = renderMascotSvg('idle');
  assert.equal(DEFAULT_MASCOT_IMAGE, 'media/live/security-companion.png');
  assert.match(html, /^<img class="mascot mascot-idle mascot-regular"/);
  assert.match(html, /src="media\/live\/security-companion\.png"/);
  assert.match(html, /data-companion-asset="local"/);
  assert.ok(!/https?:\/\//.test(html), 'aucune URL distante');
  assert.match(html, /role="img"/);
  assert.match(html, /alt="Security Companion"/);
});

test('la classe de la mascotte porte l’état demandé', () => {
  for (const state of MASCOT_VISUAL_STATES) {
    assert.match(renderMascotSvg(state), new RegExp(`class="mascot mascot-${state} `));
  }
});

test('l’asset PNG est package localement et le rendu ne recree pas de SVG', () => {
  const asset = path.join(__dirname, '..', DEFAULT_MASCOT_IMAGE);
  assert.equal(fs.readFileSync(asset).subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.ok(fs.statSync(asset).size > 1024, 'asset PNG vide ou absent');
  const css = mascotCss();
  const html = renderMascotSvg('warning');
  assert.ok(!html.includes('<svg'));
  assert.ok(!/<rect|<circle|<path|fill="#|stroke="#/.test(html));
  assert.match(css, /object-fit:contain/);
  assert.match(css, /var\(--sc-accent[,)]/);
  assert.match(renderCompanionHtml(model(), 'n'), /--sc-danger:var\(--vscode-editorError-foreground/);
});

// ----------------------------------------------------------- animations

test('chaque état animé a une règle CSS dédiée', () => {
  const css = mascotCss();
  for (const [state, keyframe] of [
    ['idle', 'sc-breathe'], ['watching', 'sc-breathe'], ['thinking', 'sc-scan'],
    ['warning', 'sc-attend'], ['critical', 'sc-pulse'], ['success', 'sc-success-pulse'],
    ['error', 'sc-shake']
  ]) {
    assert.match(css, new RegExp(`\\.mascot-${state}[^}]*${keyframe}`), `animation manquante pour ${state}`);
  }
  assert.match(css, /\.mascot-sleeping\{opacity:\.72;transform:translateY\(8px\)\}/);
});

test('les animations respectent la préférence système et le réglage', () => {
  const css = mascotCss();
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)\{\.mascot\{animation:none!important/);
  assert.match(css, /\.no-motion \.mascot\{animation:none!important/);
});

test('désactiver les animations ajoute la classe no-motion', () => {
  assert.match(renderCompanionHtml(model({ animations: false }), 'n'), /<body class="[^"]*no-motion/);
  assert.ok(!/no-motion/.test(renderCompanionHtml(model({ animations: true }), 'n').match(/<body class="[^"]*"/)[0]));
});

// --------------------------------------------------------------- layout

test('la mascotte est ancrée en bas de sa vue', () => {
  const html = renderCompanionHtml(model(), 'n');
  // `margin-top:auto` sur la scène pousse mascotte et bulle vers le bas.
  assert.match(html, /\.stage\{margin-top:auto/);
  assert.match(html, /<div class="stage">/);
});

test('la bulle précède la mascotte dans le flux', () => {
  const html = renderCompanionHtml(model(), 'n');
  assert.ok(html.indexOf('class="bubble') < html.indexOf('class="mascot-button"'));
});

test('un mode compact existe pour une sidebar réduite', () => {
  assert.match(renderCompanionHtml(model(), 'n'), /@media\(max-height:300px\),\(max-width:180px\)/);
});

// --------------------------------------------------------------- bulle

test('la bulle porte le message composé et son niveau d’urgence', () => {
  const message = companionMessageFor('findings', { findings: [finding()], file: 'routes/login.ts' });
  const html = renderCompanionHtml(model({ companionState: 'findings', findings: [finding()], message }), 'n');
  assert.match(html, /<span class="bubble-title">Attention : du code dynamique/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /role="status"/);
});

test('un état critique passe la bulle en aria-live assertive', () => {
  const message = companionMessageFor('error', { error: 'moteur KO' });
  const html = renderCompanionHtml(model({ companionState: 'error', message }), 'n');
  assert.match(html, /aria-live="assertive"/);
  assert.match(html, /class="bubble critical"/);
});

test('la répartition par sévérité est affichée', () => {
  const html = renderCompanionHtml(model({
    companionState: 'findings',
    findings: [finding({ severity: 'high' }), finding({ severity: 'medium', ruleId: 'weak-hash' })]
  }), 'n');
  assert.match(html, /<span>1 High · 1 Medium<\/span>/);
  assert.match(html, /2 Live issues/);
});

// -------------------------------------------------------------- actions

test('seules les actions du finding courant sont exposées', () => {
  const html = renderCompanionHtml(model({ companionState: 'findings', findings: [finding()] }), 'n');
  assert.match(html, /data-action="open-first">View</);
  assert.match(html, /data-action="fix-first">Fix</);
  // « Full Scan » et « Live Security » appartiennent à la sidebar Security
  // Center et à la barre d'état : cette surface ne les duplique plus.
  assert.ok(!html.includes('Full Scan'));
  assert.ok(!html.includes('securityCenter.scanWorkspace'));
  assert.ok(!html.includes('securityCenter.openLiveSecurityPage'));
});

test('sans finding, aucune action de finding n’est proposée', () => {
  const html = renderCompanionHtml(model({ companionState: 'clean' }), 'n');
  assert.ok(!html.includes('data-action="open-first"'));
  assert.ok(!html.includes('data-action="fix-first"'));
  assert.ok(!html.includes('Full Scan'));
});

test('la mascotte est un bouton accessible', () => {
  const html = renderCompanionHtml(model(), 'n');
  assert.match(html, /<button class="mascot-button" data-action="mascot"/);
  // Le nom accessible du bouton est stable : répéter le message ici le faisait
  // annoncer trois fois par un lecteur d'écran. La bulle porte déjà la région
  // live qui l'annonce une fois.
  assert.match(html, /class="mascot-button"[^>]*aria-label="Security Companion"/);
  assert.ok(!html.includes('aria-label="Security Companion — '));
});

// ------------------------------------------------------------- sécurité

test('la CSP reste stricte et sans source distante', () => {
  const html = renderCompanionHtml(model(), 'nonce-x', '', 'vscode-webview:');
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-nonce-x'/);
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(html), 'aucune ressource distante');
  assert.ok(!html.includes('unsafe-eval'));
});

test('tout contenu issu du code est échappé', () => {
  const html = renderCompanionHtml(model({
    file: '<script>x</script>',
    companionState: 'findings',
    findings: [finding({ title: '<img src=x onerror=alert(1)>' })],
    message: { headline: '<b>boom</b>', detail: '"><script>', mascot: 'warning', mood: 'attentive', kind: 'live-findings', priority: 1 }
  }), 'n');
  assert.ok(!html.includes('<script>x</script>'));
  assert.ok(!html.includes('<img src=x onerror'));
  assert.ok(!html.includes('<b>boom</b>'));
  assert.match(html, /&lt;script&gt;/);
});

test('aucun chemin absolu ni secret n’atteint le HTML', () => {
  const html = renderCompanionHtml(model({ file: 'routes/login.ts' }), 'n');
  assert.ok(!/[A-Z]:\\/.test(html), 'aucun chemin Windows absolu');
  assert.ok(!/\/home\/|\/Users\//.test(html));
  // Aucune valeur ressemblant a un secret : cle, jeton UUID ou chaine longue.
  assert.ok(!/sk_live_|ghp_|squ_|Bearer /.test(html));
  assert.ok(!/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(html));
});

// ------------------------------------------ messages sortants validés

test('seules les commandes autorisées sont exécutées depuis la webview', () => {
  const executed = [];
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }) }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'idle', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [] },
    executeCommand: (command, ...args) => executed.push([command, ...args])
  });
  provider.handleMessage({ type: 'command', command: 'securityCenter.enableLiveSecurity' });
  provider.handleMessage({ type: 'command', command: 'workbench.action.terminal.new' });
  // Une commande que la surface ne peut plus émettre n'est plus dans la liste :
  // un whitelist trop large n'élargit que la portée d'une page compromise.
  provider.handleMessage({ type: 'command', command: 'securityCenter.scanWorkspace' });
  assert.deepEqual(executed, [['securityCenter.enableLiveSecurity']]);
});

test('cliquer la mascotte sans finding ne corrige jamais rien', () => {
  const executed = [];
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }) }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'idle', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [] },
    executeCommand: (command) => executed.push(command)
  });
  provider.handleMessage({ type: 'mascot' });
  assert.deepEqual(executed, ['securityCenter.focusLiveSecurity']);
});

test('cliquer la mascotte avec un finding ouvre ce finding', () => {
  const executed = [];
  const live = finding();
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/routes/login.ts' } } } }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'issues', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [live] },
    executeCommand: (...args) => executed.push(args),
    workspacePath: 'C:/ws'
  });
  provider.handleMessage({ type: 'mascot' });
  assert.equal(executed[0][0], 'securityCenter.openLiveFinding');
  assert.equal(executed[0][1], live.uri);
});

test('Fix réutilise le Quick Fix déterministe quand il existe', () => {
  const executed = [];
  const build = (quickFixAvailable) => new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/a.ts' } } } }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'issues', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [finding({ quickFixAvailable })] },
    executeCommand: (...args) => executed.push(args[0]), workspacePath: 'C:/ws'
  });
  build(true).handleMessage({ type: 'fix-first' });
  build(false).handleMessage({ type: 'fix-first' });
  assert.deepEqual(executed, ['securityCenter.applyLiveQuickFix', 'securityCenter.generateLiveAiFix']);
});

// --------------------------------------------- synchronisation findings

test('le compte affiché vient des diagnostics, jamais d’une liste locale', () => {
  const live = [finding(), finding({ ruleId: 'weak-hash', severity: 'medium' })];
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/routes/login.ts' } } } }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'issues', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => live },
    executeCommand: () => {}, workspacePath: 'C:/ws'
  });
  const built = provider.model();
  assert.equal(built.findings.length, live.length);
  assert.equal(built.findings, live, 'la même référence : aucune copie divergente');
  assert.equal(built.file, 'routes/login.ts');
});

test('le contexte pipeline alimente le message sans écraser les findings Live', () => {
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }), activeTextEditor: { document: { uri: { fsPath: 'C:/ws/a.ts' } } } }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'issues', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [finding()] },
    executeCommand: () => {}, workspacePath: 'C:/ws',
    getPipelineContext: () => ({ policyStatus: 'BLOCK', scanStatus: 'running' })
  });
  // Le finding High du fichier courant reste prioritaire sur le policy BLOCK.
  assert.equal(provider.model().message.kind, 'live-critical');
});

test('sans finding Live, le policy BLOCK du pipeline remonte', () => {
  const provider = new LiveCompanionProvider({
    api: { window: { onDidChangeActiveTextEditor: () => ({ dispose() {} }) }, workspace: { getConfiguration: () => ({ get: (k, d) => d }) } },
    service: { getState: () => 'idle', onDidChangeState: () => ({ dispose() {} }), isPerformanceReduced: () => false },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => [] },
    executeCommand: () => {}, getPipelineContext: () => ({ policyStatus: 'BLOCK' })
  });
  assert.equal(provider.model().message.kind, 'policy-block');
  assert.equal(provider.model().policyStatus, 'BLOCK');
});
