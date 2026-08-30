const test = require('node:test');
const assert = require('node:assert/strict');
const {
  companionMessageFor, secondaryFor, CompanionMessageGate, MASCOT_STATES, COMPANION_STATES,
  highestSeverity, summarizeSeverities
} = require('../src/live/companionMessages');
const { companionStateFor, renderCompanionHtml } = require('../src/live/liveCompanion');
const { analyzeJavaScriptText } = require('../src/live/liveDetector');
const { JAVASCRIPT_LIVE_RULES } = require('../src/live/liveRules/javascriptRules');

const finding = (ruleId, severity = 'high', line = 1) => ({
  ruleId, severity, title: ruleId, range: { start: { line, character: 0 }, end: { line, character: 5 } },
  uri: 'file:///a.js', documentVersion: 1
});

// ------------------------------------------------------------------ états

test('les états du companion couvrent le vocabulaire demandé', () => {
  assert.deepEqual(COMPANION_STATES, ['idle', 'analyzing', 'clean', 'findings', 'degraded', 'disabled', 'error']);
  assert.deepEqual(MASCOT_STATES, ['idle', 'watching', 'thinking', 'warning', 'success', 'sleeping']);
});

test('l’état du service est traduit vers le vocabulaire companion', () => {
  assert.equal(companionStateFor('issues'), 'findings');
  assert.equal(companionStateFor('paused'), 'degraded');
  assert.equal(companionStateFor('clean'), 'clean');
  assert.equal(companionStateFor('idle', { performanceReduced: true }), 'degraded');
  assert.equal(companionStateFor('inconnu'), 'idle');
});

test('chaque état produit un message et une mascotte cohérents', () => {
  const cases = [
    ['idle', {}, 'idle'],
    ['analyzing', {}, 'thinking'],
    ['clean', {}, 'success'],
    ['findings', { findings: [finding('weak-hash', 'medium')] }, 'warning'],
    ['degraded', {}, 'warning'],
    ['disabled', {}, 'sleeping'],
    ['error', { error: 'moteur KO' }, 'warning']
  ];
  for (const [state, context, mascot] of cases) {
    const message = companionMessageFor(state, context);
    assert.equal(message.mascot, mascot, `mascotte inattendue pour ${state}`);
    assert.ok(message.headline, `pas de titre pour ${state}`);
    assert.ok(MASCOT_STATES.includes(message.mascot));
  }
});

// -------------------------------------------------------------- priorités

test('une erreur du moteur prime sur la politique et le scan, mais pas sur le fichier', () => {
  // Un finding déjà affiché reste vrai même si l'analyse suivante échoue : le
  // fichier courant garde donc la priorité sur l'erreur du moteur.
  const withFinding = companionMessageFor('error', {
    error: 'moteur indisponible', findings: [finding('unsafe-eval')],
    policyStatus: 'BLOCK', scanStatus: 'running'
  });
  assert.equal(withFinding.kind, 'live-critical');
  // Sans finding ouvert, l'erreur passe devant tout le reste.
  const message = companionMessageFor('error', {
    error: 'moteur indisponible', policyStatus: 'BLOCK', scanStatus: 'running'
  });
  assert.equal(message.kind, 'error');
  assert.match(message.detail, /moteur indisponible/);
});

test('un finding critique prime sur le policy block et le scan en cours', () => {
  const message = companionMessageFor('findings', {
    findings: [finding('dynamic-command-execution', 'high')],
    policyStatus: 'BLOCK', scanStatus: 'running', file: 'routes/login.ts'
  });
  assert.equal(message.kind, 'live-critical');
  assert.match(message.headline, /commande système reçoit une entrée utilisateur/);
  assert.match(message.detail, /routes\/login\.ts/);
});

test('le policy block prime sur le scan en cours quand rien de critique n’est ouvert', () => {
  const message = companionMessageFor('idle', { policyStatus: 'BLOCK', scanStatus: 'running' });
  assert.equal(message.kind, 'policy-block');
  assert.match(message.headline, /politique projet bloque/);
});

test('un scanner mal configuré est signalé avec sa raison réelle', () => {
  const message = companionMessageFor('idle', {
    scannerHealth: [{ tool: 'Snyk', enabled: true, reason: 'jeton manquant' }]
  });
  assert.equal(message.kind, 'scanner-health');
  // Le titre est court et actionnable ; le détail dit où agir.
  assert.equal(message.headline, 'Jeton Snyk manquant');
  assert.match(message.detail, /Configuration des scanners/);
  assert.equal(message.tool, 'Snyk');
});

test('un scanner désactivé ne produit aucun message', () => {
  const message = companionMessageFor('idle', {
    scannerHealth: [{ tool: 'SonarQube', enabled: false, reason: 'serveur arrêté' }]
  });
  assert.notEqual(message.kind, 'scanner-health');
});

test('aucun message n’est inventé quand l’information est absente', () => {
  const message = companionMessageFor('idle', {});
  assert.equal(message.kind, 'idle');
  assert.ok(!/politique|scan|Snyk|SonarQube/i.test(message.headline));
});

// ------------------------------------------------------------- contenu

test('les messages nomment le fichier courant en chemin relatif', () => {
  const message = companionMessageFor('findings', { findings: [finding('weak-hash', 'medium')], file: 'routes/login.ts' });
  assert.match(message.detail, /routes\/login\.ts/);
  assert.ok(!message.detail.includes('C:\\'));
});

test('le résumé de sévérité reflète les findings réels', () => {
  const findings = [finding('a', 'high'), finding('b', 'medium'), finding('c', 'medium')];
  assert.equal(highestSeverity(findings), 'high');
  assert.equal(summarizeSeverities(findings), '1 High · 2 Medium');
});

test('une correction déterministe disponible est mentionnée', () => {
  const message = companionMessageFor('findings', {
    findings: [finding('weak-hash', 'medium')], remediationAvailable: true
  });
  assert.match(message.detail, /correction déterministe est disponible/);
});

test('un scan terminé rapporte les chiffres réels', () => {
  // Un scan terminé est un compte rendu de workspace, pas un verdict sur le
  // fichier ouvert : il ne prend jamais le message principal, il devient la
  // ligne secondaire.
  const context = { scanStatus: 'completed', scanFindingCount: 12, scanPriorityCount: 3 };
  const primary = companionMessageFor('clean', context);
  assert.equal(primary.kind, 'clean');
  const message = secondaryFor(primary, context);
  assert.equal(message.kind, 'scan-summary');
  assert.match(message.headline, /Dernier scan complet : 12 findings/);
  assert.match(message.detail, /3 prioritaire/);
  // Et il reste moins prioritaire que n'importe quelle alerte du fichier.
  assert.ok(message.priority > primary.priority);
});

test('un état propre le dit sans alarmisme', () => {
  const message = companionMessageFor('clean', { file: 'src/a.js' });
  assert.equal(message.kind, 'clean');
  assert.equal(message.mascot, 'success');
  assert.match(message.detail, /src\/a\.js/);
});

// ------------------------------------------------------------- anti-spam

test('un message identique n’est jamais répété', () => {
  const gate = new CompanionMessageGate({ cooldownMs: 1000, now: () => 0 });
  const analyzing = companionMessageFor('analyzing', { file: 'a.js' });
  assert.equal(gate.accept(analyzing), true);
  for (let index = 0; index < 25; index += 1) {
    assert.equal(gate.accept(companionMessageFor('analyzing', { file: 'a.js' })), false);
  }
});

test('un message différent attend le cooldown', () => {
  let clock = 0;
  const gate = new CompanionMessageGate({ cooldownMs: 1000, now: () => clock });
  assert.equal(gate.accept(companionMessageFor('analyzing', {})), true);
  clock = 200;
  assert.equal(gate.accept(companionMessageFor('clean', {})), false, 'trop tôt');
  clock = 1500;
  assert.equal(gate.accept(companionMessageFor('clean', {})), true);
});

test('un message plus urgent ignore le cooldown', () => {
  let clock = 0;
  const gate = new CompanionMessageGate({ cooldownMs: 5000, now: () => clock });
  gate.accept(companionMessageFor('analyzing', {}));
  clock = 10;
  const critical = companionMessageFor('findings', { findings: [finding('unsafe-eval', 'high')] });
  assert.equal(gate.accept(critical), true, 'un finding critique ne doit jamais attendre');
});

test('le gate se réinitialise proprement', () => {
  const gate = new CompanionMessageGate({ cooldownMs: 1000, now: () => 0 });
  const message = companionMessageFor('clean', {});
  gate.accept(message);
  assert.equal(gate.accept(message), false);
  gate.reset();
  assert.equal(gate.accept(message), true);
});

// -------------------------------------------------------------- rendu UI

test('le rendu affiche le message composé et sa mascotte', () => {
  const message = companionMessageFor('findings', { findings: [finding('unsafe-eval', 'high')], file: 'routes/login.ts' });
  const html = renderCompanionHtml({ state: 'issues', file: 'routes/login.ts', findings: [finding('unsafe-eval', 'high')], message }, 'n');
  assert.match(html, /code dynamique est évalué/);
  assert.match(html, /routes\/login\.ts/);
  // La mascotte réagit à la sévérité réelle du finding le plus grave.
  assert.match(html, /<img class="mascot mascot-warning /);
  assert.match(html, /aria-live="polite"/);
});

test('le rendu sans message composé conserve le comportement historique', () => {
  const html = renderCompanionHtml({ state: 'clean', file: 'a.js', findings: [] }, 'n');
  assert.match(html, /No live issues/);
});

// -------------------------------------------- cohérence avec le détecteur

test('le companion compte exactement les findings du détecteur', () => {
  const text = 'eval(req.query.x);\nconst h = crypto.createHash("md5");';
  const findings = analyzeJavaScriptText({ text, uri: 'file:///a.js', documentVersion: 1, rules: JAVASCRIPT_LIVE_RULES });
  const message = companionMessageFor('findings', { findings, file: 'a.js' });
  assert.equal(findings.length, 2);
  assert.equal(message.count, 2);
  assert.match(message.headline, /code dynamique/);
});

test('corriger le code fait passer le companion en état propre', () => {
  const vulnerable = analyzeJavaScriptText({ text: 'eval(req.query.x);', uri: 'file:///a.js', documentVersion: 1, rules: JAVASCRIPT_LIVE_RULES });
  assert.equal(vulnerable.length, 1);
  const fixed = analyzeJavaScriptText({ text: 'JSON.parse(req.query.x);', uri: 'file:///a.js', documentVersion: 2, rules: JAVASCRIPT_LIVE_RULES });
  assert.equal(fixed.length, 0);
  assert.equal(companionMessageFor('clean', { findings: fixed, file: 'a.js' }).kind, 'clean');
});
