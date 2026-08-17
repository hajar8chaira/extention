const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  companionMessageFor, buildCompanionVisualModel, companionActionFor, shortScannerIssue,
  scanProgressHeadline, CompanionMessageGate, TRANSIENT_KINDS, PRIORITIES
} = require('../src/live/companionMessages');
const { mascotCss, renderMascotSvg, MASCOT_VISUAL_STATES } = require('../src/live/companionMascot');
const { renderCompanionWidget, companionWidgetCss, BUBBLE_LINGER_MS } = require('../src/live/companionWidget');
const { LiveSecurityPageProvider } = require('../src/live/livePage');

const live = (severity = 'high', ruleId = 'dynamic-command-execution') => ({
  ruleId, severity, title: 'Commande système alimentée par une entrée utilisateur',
  range: { start: { line: 2, character: 2 }, end: { line: 2, character: 40 } },
  uri: 'file:///ws/routes/login.js', documentVersion: 1, quickFixAvailable: false
});

const visual = (state, pipeline = {}, findings = []) =>
  buildCompanionVisualModel({ serviceState: state, findings, file: 'routes/login.js', pipeline });

function pageProvider({ state = 'clean', findings = [], pipeline = {}, executed = [] } = {}) {
  const document = { uri: { fsPath: 'C:/ws/routes/login.js' }, languageId: 'javascript' };
  return new LiveSecurityPageProvider({
    api: {
      window: { activeTextEditor: { document }, onDidChangeActiveTextEditor: () => ({ dispose() {} }) },
      workspace: { getConfiguration: () => ({ get: (key, fallback) => fallback }) },
      Uri: { joinPath: () => ({}) }, ViewColumn: { Active: 1 }
    },
    service: { getState: () => state, onDidChangeState: () => ({ dispose() {} }) },
    diagnostics: { onDidChange: () => ({ dispose() {} }), findingsForDocument: () => findings },
    executeCommand: (command, ...args) => executed.push([command, ...args]),
    workspacePath: 'C:/ws',
    getCompanionModel: () => buildCompanionVisualModel({ serviceState: state, findings, file: 'routes/login.js', pipeline })
  });
}

// ------------------------------------------------ mouvements par état

test('chaque état visuel a des mouvements réels, sur les membres existants', () => {
  const css = mascotCss();
  const expected = {
    idle: [/\.mascot-idle \.sc-figure\{animation:sc-breathe/, /\.mascot-idle \.sc-eye-dot\{opacity:1;animation:sc-blink/],
    watching: [/\.mascot-watching \.sc-eyes\{animation:sc-look/, /\.mascot-watching \.sc-head\{animation:sc-tilt-soft/, /\.mascot-watching \.sc-arm-right\{animation:sc-point/],
    thinking: [/\.mascot-thinking \.sc-scanline\{opacity:\.9;animation:sc-scan/, /\.mascot-thinking \.sc-dots\{opacity:1\}/, /\.mascot-thinking \.sc-arm-right\{animation:sc-work/, /\.mascot-thinking \.sc-figure\{animation:sc-hop/],
    warning: [/\.mascot-warning \.sc-figure\{animation:sc-recoil/, /\.mascot-warning \.sc-eye-alert\{opacity:1/, /\.mascot-warning \.sc-arm-left\{animation:sc-raise-left/],
    critical: [/\.mascot-critical \.sc-arm-left\{transform:rotate\(-42deg\)\}/, /\.mascot-critical \.sc-arm-right\{transform:rotate\(42deg\)\}/, /\.mascot-critical \.sc-figure\{animation:sc-pulse 2s/],
    success: [/\.mascot-success \.sc-figure\{animation:sc-jump/, /\.mascot-success \.sc-arm-left\{animation:sc-cheer-left/, /\.mascot-success \.sc-check\{opacity:1/],
    error: [/\.mascot-error \.sc-figure\{animation:sc-shake/, /\.mascot-error \.sc-eye-cross\{opacity:1/, /\.mascot-error \.sc-arm-left\{transform:rotate\(-28deg\)\}/],
    sleeping: [/\.mascot-sleeping \.sc-figure\{transform:translateY\(6px\)/, /\.mascot-sleeping \.sc-eye-closed\{opacity:1\}/, /\.mascot-sleeping \.sc-zzz\{opacity:1\}/]
  };
  for (const [state, patterns] of Object.entries(expected)) {
    for (const pattern of patterns) assert.match(css, pattern, `${state} : ${pattern} absent`);
  }
  // Les huit états se rendent avec leur classe.
  for (const state of MASCOT_VISUAL_STATES) {
    assert.match(renderMascotSvg(state), new RegExp(`class="mascot mascot-${state} `));
  }
});

test('les états d’alerte ne clignotent pas et les états calmes ne s’agitent pas', () => {
  const css = mascotCss();
  // Le critique pulse lentement — jamais un stroboscope.
  const pulse = css.match(/\.mascot-critical \.sc-figure\{animation:sc-pulse (\d+(?:\.\d+)?)s/);
  assert.ok(pulse && Number(pulse[1]) >= 1.5, 'la pulsation critique doit rester lente');
  // Le sommeil n'a qu'un Zz qui flotte, rien sur le corps.
  assert.ok(!/\.mascot-sleeping \.sc-figure\{animation/.test(css), 'le sommeil ne doit pas animer le corps');
  // Warning et success se jouent un nombre fini de fois.
  assert.match(css, /\.mascot-warning \.sc-figure\{animation:sc-recoil [\d.]+s ease-out 2\}/);
  assert.match(css, /\.mascot-success \.sc-figure\{animation:sc-jump [\d.]+s [^;}]+ 1\}/);
});

test('aucune animation ne planifie de travail et le mouvement est désactivable deux fois', () => {
  const css = mascotCss();
  assert.ok(!/requestAnimationFrame|setInterval|setTimeout/.test(css));
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)/);
  assert.match(css, /\.no-motion \.mascot \*\{animation:none!important/);
  const widgetCss = companionWidgetCss();
  assert.match(widgetCss, /\.sc-no-motion \.mascot \*\{animation:none!important\}/);
  // Et le composant lui-même n'ouvre aucune boucle.
  const widget = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionWidget.js'), 'utf8');
  assert.ok(!/setInterval|setTimeout|requestAnimationFrame/.test(widget), 'aucun minuteur dans le composant');
});

// -------------------------------------------- messages venus de faits réels

test('la progression du scan est honnête sur le parallélisme', () => {
  assert.equal(scanProgressHeadline({ running: ['Semgrep'], completed: 0, total: 3 }), 'Semgrep en cours…');
  assert.equal(scanProgressHeadline({ running: ['Semgrep', 'Trivy', 'ZAP'], completed: 1, total: 5 }),
    'Analyse de sécurité en cours — 3 scanners actifs');
  // Sans état par scanner, aucune séquence n'est inventée.
  assert.equal(scanProgressHeadline(null), 'Analyse Security Center en cours…');
  const running = companionMessageFor('idle', { scanStatus: 'running', scanProgress: { running: ['Trivy', 'OSV-Scanner'], completed: 2, total: 5 } });
  assert.equal(running.kind, 'scanning');
  assert.equal(running.mascot, 'thinking');
  assert.match(running.detail, /2\/5 scanner\(s\) terminé\(s\)/);
});

test('l’issue du scan distingue terminé, partiel et échoué', () => {
  assert.equal(visual('idle', { scanOutcome: 'completed', scanFindingCount: 12 }, []).message.kind, 'scan-report');
  assert.match(visual('idle', { scanOutcome: 'completed', scanFindingCount: 12 }, []).message.headline, /Analyse terminée — 12 findings/);
  const partial = visual('clean', { scanOutcome: 'partial' });
  assert.equal(partial.message.kind, 'scan-outcome');
  assert.match(partial.message.headline, /erreurs de scanner/);
  const failed = visual('clean', { scanOutcome: 'failed' });
  assert.equal(failed.message.kind, 'scan-outcome');
  assert.match(failed.message.headline, /a échoué/);
  // Un scan sans issue connue ne dit rien.
  assert.notEqual(visual('idle', {}, []).message.kind, 'scan-report');
});

test('un scan partiel prime sur un fichier propre, un scan réussi non', () => {
  // Dire « ce fichier est propre » serait trompeur si la moitié des scanners
  // n'a rien rapporté.
  assert.equal(visual('clean', { scanOutcome: 'partial' }).message.kind, 'scan-outcome');
  // Mais un scan réussi laisse le fichier courant parler, et passe en secondaire.
  const done = visual('clean', { scanOutcome: 'completed', scanStatus: 'completed', scanFindingCount: 556 });
  assert.equal(done.message.kind, 'clean');
  assert.match(done.secondary.headline, /Dernier scan complet : 556 findings/);
  assert.ok(PRIORITIES.indexOf('scan-outcome') < PRIORITIES.indexOf('clean'));
  assert.ok(PRIORITIES.indexOf('scan-report') > PRIORITIES.indexOf('clean'));
});

test('le total du scan n’est jamais annoncé deux fois', () => {
  const noFile = buildCompanionVisualModel({
    serviceState: 'idle', findings: [], file: '',
    pipeline: { scanStatus: 'completed', scanOutcome: 'completed', scanFindingCount: 42 }
  });
  assert.equal(noFile.message.kind, 'scan-report');
  assert.equal(noFile.secondary, null, 'le titre porte déjà le total');
});

test('les échecs de scanner deviennent des phrases courtes et sûres', () => {
  const cases = [
    ['Snyk', 'jeton manquant — configurez-le', 'Jeton Snyk manquant'],
    ['Snyk', 'HTTP 401 Unauthorized', 'Authentification Snyk refusée'],
    ['SonarQube Server', 'ECONNREFUSED 127.0.0.1:9000', 'SonarQube injoignable'],
    ['Trivy', 'docker daemon is running?', 'Docker indisponible'],
    ['ZAP', 'a dépassé le délai maximal', 'ZAP a dépassé le délai'],
    ['Gitleaks', 'ENOENT gitleaks', 'Gitleaks n’est pas installé'],
    ['Semgrep', 'exit code 2 blah blah', 'Semgrep a échoué']
  ];
  for (const [tool, raw, expected] of cases) {
    assert.equal(shortScannerIssue(tool, raw).headline, expected, `${tool} / ${raw}`);
  }
});

test('un échec inconnu ne recopie jamais le texte brut', () => {
  const raw = 'Authorization: Bearer sk-live-9f2a7c1e SECRET at C:\\Users\\hajar\\ws\\x.js';
  const short = shortScannerIssue('Semgrep', raw);
  assert.equal(short.headline, 'Semgrep a échoué');
  const blob = `${short.headline} ${short.detail}`;
  assert.ok(!blob.includes('sk-live-9f2a7c1e'), 'aucun jeton');
  assert.ok(!/[A-Za-z]:\\/.test(blob), 'aucun chemin absolu');
  assert.ok(!blob.includes('Bearer'));
});

test('les états de correction sont rapportés, jamais déclenchés', () => {
  assert.match(visual('clean', { fixState: 'available' }).message.headline, /Correction disponible/);
  assert.match(visual('clean', { fixState: 'applied' }).message.headline, /Correction appliquée/);
  assert.match(visual('clean', { fixState: 'validating' }).message.headline, /Vérification de la correction/);
  assert.match(visual('clean', { fixState: 'validated' }).message.headline, /Correction vérifiée ✓/);
  assert.match(visual('clean', { fixState: 'failed' }).message.headline, /vérification de la correction a échoué/);
  // Aucun de ces messages ne pointe vers une commande de remédiation.
  for (const state of ['available', 'applied', 'validating', 'validated', 'failed']) {
    const action = visual('clean', { fixState: state }).action;
    assert.ok(!/generateLiveAiFix|applyLiveQuickFix|aiFix/.test(action?.command || ''), `action de correction pour ${state}`);
  }
});

test('les preuves supply chain sont rapportées telles qu’elles existent', () => {
  assert.match(visual('idle', { supplyChain: { sbom: 'generated' } }, []).message.headline, /SBOM généré/);
  assert.match(visual('idle', { supplyChain: { provenance: 'generated' } }, []).message.headline, /Provenance générée/);
  assert.match(visual('idle', { supplyChain: { signing: 'signed' } }, []).message.headline, /Artefact signé/);
  assert.match(visual('idle', { supplyChain: { signing: 'verified' } }, []).message.headline, /Signature vérifiée ✓/);
  assert.match(visual('idle', { supplyChain: { signing: 'failed' } }, []).message.headline, /Vérification de signature échouée/);
  // Une étape non exécutée ne produit rien.
  assert.notEqual(visual('idle', { supplyChain: { sbom: '' } }, []).message.kind, 'supply-chain');
  assert.notEqual(visual('idle', {}, []).message.kind, 'supply-chain');
});

test('la politique est rapportée dans ses quatre états', () => {
  assert.match(visual('clean', { policyStatus: 'BLOCK' }).message.headline, /bloque la livraison/);
  assert.match(visual('clean', { policyStatus: 'ERROR' }).message.headline, /est invalide/);
  assert.match(visual('clean', { policyStatus: 'PASS' }).secondary.headline, /[Pp]olitique projet respectée/);
  // WARN n'est pas un blocage : il ne prend pas le titre.
  assert.equal(visual('clean', { policyStatus: 'WARN' }).message.kind, 'clean');
  // NOT_CONFIGURED reste silencieux.
  assert.equal(visual('clean', { policyStatus: '' }).message.kind, 'clean');
});

test('Burp déconnecté est signalé, Burp connecté ne dit rien', () => {
  assert.match(visual('idle', { burpConnected: false }, []).message.headline, /Burp déconnecté/);
  assert.notEqual(visual('idle', { burpConnected: true }, []).message.kind, 'scanner-health');
  // Un connecteur jamais sondé reste silencieux plutôt que présumé cassé.
  assert.notEqual(visual('idle', { burpConnected: null }, []).message.kind, 'scanner-health');
});

// ------------------------------------------------------------- priorité

test('l’échelle suit l’ordre demandé', () => {
  const rank = (kind) => PRIORITIES.indexOf(kind);
  assert.ok(rank('live-critical') < rank('live-findings'));
  assert.ok(rank('live-findings') < rank('error'));
  assert.ok(rank('error') < rank('policy-block'));
  assert.ok(rank('policy-block') < rank('scanner-health'));
  assert.ok(rank('scanner-health') < rank('scanning'));
  assert.ok(rank('scanning') < rank('fix'));
  assert.ok(rank('fix') < rank('scan-outcome'));
  assert.ok(rank('clean') < rank('idle'));
});

test('un fait de priorité haute ne cède jamais à la progression du scan', () => {
  const context = {
    scanStatus: 'running', scanProgress: { running: ['Semgrep', 'Trivy'], completed: 0, total: 4 },
    policyStatus: 'BLOCK', scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }]
  };
  // Un critique du fichier courant devant tout.
  assert.equal(companionMessageFor('findings', { ...context, findings: [live('critical', 'sql-string-concatenation')] }).kind, 'live-critical');
  // Puis le blocage de politique devant la santé des scanners et la progression.
  assert.equal(companionMessageFor('idle', context).kind, 'policy-block');
  // Puis la santé des scanners devant la progression.
  assert.equal(companionMessageFor('idle', { ...context, policyStatus: '' }).kind, 'scanner-health');
  // La progression ne parle que quand rien de plus urgent n'existe.
  assert.equal(companionMessageFor('idle', { scanStatus: 'running', scanProgress: context.scanProgress }).kind, 'scanning');
});

// -------------------------------------------------------- durée des bulles

test('les bulles informatives s’effacent, les alertes restent', () => {
  for (const kind of TRANSIENT_KINDS) assert.ok(['scan-report', 'supply-chain', 'clean'].includes(kind));
  assert.equal(visual('clean', {}).message.transient, true);
  assert.equal(visual('idle', { supplyChain: { signing: 'verified' } }, []).message.transient, true);
  // Une alerte, un blocage ou une erreur ne disparaît pas tout seul.
  for (const model of [
    visual('findings', {}, [live()]),
    visual('clean', { policyStatus: 'BLOCK' }),
    visual('error', { error: 'boom' }),
    visual('clean', { scanOutcome: 'partial' }),
    visual('clean', { scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }] })
  ]) {
    assert.notEqual(model.message.transient, true, `${model.message.kind} ne doit pas s’effacer`);
  }
});

test('l’effacement est une animation CSS, sans minuteur', () => {
  const css = companionWidgetCss();
  assert.match(css, new RegExp(`\\.sc-widget-bubble\\.sc-widget-fading\\{animation:sc-widget-in [\\d.]+s ease-out,sc-widget-out [\\d.]+s ease-in ${BUBBLE_LINGER_MS}ms forwards\\}`));
  assert.match(css, /@keyframes sc-widget-out\{to\{opacity:0/);
  assert.ok(BUBBLE_LINGER_MS >= 4000, 'le temps de lecture doit rester suffisant');
  // La classe n'est posée que sur les messages transitoires.
  assert.match(renderCompanionWidget(visual('clean', {}), { variant: 'full' }), /sc-widget-fading/);
  assert.ok(!renderCompanionWidget(visual('findings', {}, [live()]), { variant: 'full' }).includes('sc-widget-fading'));
});

test('le garde anti-spam évite la répétition et laisse passer l’urgent', () => {
  let clock = 0;
  const gate = new CompanionMessageGate({ cooldownMs: 5000, now: () => clock });
  const analyzing = companionMessageFor('analyzing', { file: 'a.js' });
  assert.equal(gate.accept(analyzing), true);
  // Une frappe par seconde ne produit pas une bulle par frappe.
  for (let index = 0; index < 30; index += 1) {
    clock += 100;
    assert.equal(gate.accept(companionMessageFor('analyzing', { file: 'a.js' })), false);
  }
  // Un critique ne patiente jamais.
  assert.equal(gate.accept(companionMessageFor('findings', { findings: [live('critical', 'sql-string-concatenation')] })), true);
});

// ------------------------------------------------------------ interaction

test('le clic mène là où pointe le message courant', () => {
  assert.equal(companionActionFor(companionMessageFor('findings', { findings: [live()] })).scope, 'finding');
  assert.equal(companionActionFor(companionMessageFor('idle', { scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }] })).command, 'securityCenter.openScannerSetup');
  assert.equal(companionActionFor(companionMessageFor('idle', { policyStatus: 'BLOCK' })).command, 'securityCenter.openSecurityPipeline');
  assert.equal(companionActionFor(companionMessageFor('clean', {})).command, 'securityCenter.openLiveSecurityPage');
  // Aucune action n'est une remédiation.
  for (const kind of PRIORITIES) {
    const action = companionActionFor({ kind });
    assert.ok(!/Fix|fix/.test(action.command), `${kind} pointe vers une correction`);
  }
});

test('un problème de scanner ouvre la configuration, un finding ouvre le finding', () => {
  const scannerClick = [];
  pageProvider({ state: 'clean', pipeline: { scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }] }, executed: scannerClick })
    .handleMessage({ type: 'companion' });
  assert.deepEqual(scannerClick, [['securityCenter.openScannerSetup']]);

  const findingClick = [];
  pageProvider({ state: 'issues', findings: [live()], executed: findingClick }).handleMessage({ type: 'companion' });
  assert.deepEqual(findingClick, [['securityCenter.openLiveFinding', 'file:///ws/routes/login.js', 1, 'dynamic-command-execution']]);

  const policyClick = [];
  pageProvider({ state: 'clean', pipeline: { policyStatus: 'BLOCK' }, executed: policyClick }).handleMessage({ type: 'companion' });
  assert.deepEqual(policyClick, [['securityCenter.openSecurityPipeline']]);
});

test('aucune correction IA ni scanner n’est jamais déclenché par le compagnon', () => {
  for (const pipeline of [
    { fixState: 'available' }, { fixState: 'validated' }, { fixState: 'failed' },
    { scanOutcome: 'completed', scanFindingCount: 5 }, { supplyChain: { signing: 'verified' } },
    { scanStatus: 'running', scanProgress: { running: ['Semgrep'], completed: 0, total: 1 } }
  ]) {
    const executed = [];
    pageProvider({ state: 'clean', pipeline, executed }).handleMessage({ type: 'companion' });
    for (const [command] of executed) {
      assert.ok(!/generateLiveAiFix|applyLiveQuickFix|scanWorkspace|scanSelected/.test(command),
        `${command} déclenché depuis le compagnon`);
    }
  }
});

// -------------------------------------------------- pas de fuite, pas de sonde

test('aucun secret ni chemin absolu ne franchit le compagnon', () => {
  const model = buildCompanionVisualModel({
    serviceState: 'issues',
    findings: [{ ...live(), title: 'Jeton sk-live-9f2a7c1e trouvé', uri: 'file:///C:/Users/hajar/ws/a.js' }],
    file: 'routes/login.js',
    pipeline: { scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'HTTP 401 token sk-live-9f2a7c1e' }] }
  });
  for (const variant of ['full', 'compact']) {
    const widget = renderCompanionWidget(model, { variant });
    assert.ok(!widget.includes('sk-live-9f2a7c1e'), `secret en mode ${variant}`);
    assert.ok(!/[A-Za-z]:[\\/]Users/.test(widget), `chemin absolu en mode ${variant}`);
  }
});

test('le compagnon n’interroge rien : aucune sonde, aucun scanner', () => {
  for (const file of ['companionMessages.js', 'companionWidget.js', 'companionMascot.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', file), 'utf8');
    assert.ok(!/setInterval|setTimeout|requestAnimationFrame/.test(source), `${file} planifie du travail`);
    assert.ok(!/child_process|execFile|spawn|fetch\(|http\.request/.test(source), `${file} lance un processus ou une requête`);
    for (const scanner of ['semgrep', 'gitleaks', 'trivy', 'osv', 'snyk', 'sonar', 'zap', 'ollama']) {
      assert.ok(!new RegExp(`require\\(['"].*${scanner}`, 'i').test(source), `${file} importe ${scanner}`);
    }
  }
});
