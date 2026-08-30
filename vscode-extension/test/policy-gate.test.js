const test = require('node:test');
const assert = require('node:assert/strict');
const { validatePolicy, parsePolicyYaml } = require('../src/project-policy');
const { evaluatePolicyGate, formatGateResult, gateExitCode, STATUS } = require('../src/intelligence/policy-gate');
const { unifiedFinding } = require('../src/intelligence/finding-model');
const { prioritizeFinding } = require('../src/intelligence/prioritization');

function policy(yaml) {
  return validatePolicy(parsePolicyYaml(yaml));
}

function finding(overrides = {}) {
  const base = unifiedFinding({
    id: 'f1', tool: 'Semgrep', category: 'security', ruleId: 'sqli', title: 'Injection SQL',
    rawSeverity: 'CRITICAL', severity: 'error', file: 'src/login.js', absolutePath: '/r/src/login.js',
    startLine: 41, startColumn: 0, cwe: 'CWE-89', ...overrides
  });
  return { ...base, reachability: { state: 'statically_reachable', confidence: 'medium', reason: '', evidence: [] } };
}

function scored(overrides = {}) {
  return prioritizeFinding(finding(overrides));
}

// ------------------------------------------------------------- validation

test('la section gate est facultative et purement additive', () => {
  const withoutGate = policy('version: 1\n');
  assert.equal(withoutGate.gate.configured, false);
  assert.equal(withoutGate.failOn, 'CRITICAL');
  // NOT_CONFIGURED, pas PASS : rien n'a été autorisé faute de règle.
  assert.equal(evaluatePolicyGate([finding()], withoutGate).status, STATUS.NOT_CONFIGURED);
  assert.equal(evaluatePolicyGate([finding()], withoutGate).configured, false);
  assert.equal(gateExitCode(evaluatePolicyGate([finding()], withoutGate)), 0);
});

test('la syntaxe gate réellement supportée est acceptée', () => {
  const parsed = policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n  priority_threshold: 85\n  require_sbom: true\n');
  assert.deepEqual(parsed.gate.failOnSeverity, ['CRITICAL']);
  assert.equal(parsed.gate.blockSecrets, true);
  assert.equal(parsed.gate.priorityThreshold, 85);
  assert.equal(parsed.gate.requireSbom, true);
});

test('une clé gate inconnue est refusée plutôt qu’ignorée en silence', () => {
  assert.throws(() => policy('gate:\n  require_signed_image: true\n'), /Clé inconnue dans gate/);
  assert.throws(() => policy('gate:\n  priority_threshold: 150\n'), /entier entre 0 et 100/);
  assert.throws(() => policy('gate:\n  fail_on_severity: [EXTREME]\n'), /sévérité inconnue/);
});

test('la section supply_chain est validée séparément', () => {
  const parsed = policy('supply_chain:\n  require_provenance: true\n  require_signature: true\n');
  assert.equal(parsed.supplyChain.requireProvenance, true);
  assert.equal(parsed.supplyChain.requireSignature, true);
  assert.throws(() => policy('supply_chain:\n  require_sbom_attestation: true\n'), /Clé inconnue dans supply_chain/);
});

// ---------------------------------------------------------------- verdicts

test('PASS quand aucune règle n’est violée', () => {
  const result = evaluatePolicyGate([finding({ rawSeverity: 'LOW' })], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  assert.equal(result.status, STATUS.PASS);
  assert.equal(result.violations.length, 0);
  assert.equal(gateExitCode(result), 0);
});

test('BLOCK sur une sévérité interdite, avec la raison et l’emplacement', () => {
  const result = evaluatePolicyGate([finding()], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  assert.equal(result.status, STATUS.BLOCK);
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].code, 'severity');
  assert.equal(result.violations[0].file, 'src/login.js');
  assert.equal(result.violations[0].line, 42);
  assert.equal(gateExitCode(result), 1);
  assert.match(formatGateResult(result), /BLOCK/);
});

test('WARN sans blocage quand seule une règle d’avertissement s’applique', () => {
  const result = evaluatePolicyGate([finding({ rawSeverity: 'HIGH' })], policy('gate:\n  fail_on_severity: [CRITICAL]\n  warn_on_severity: [HIGH]\n'));
  assert.equal(result.status, STATUS.WARN);
  assert.equal(result.violations.length, 0);
  assert.equal(result.warnings.length, 1);
  assert.equal(gateExitCode(result), 0);
});

test('un secret exposé bloque quand block_secrets est actif', () => {
  const secret = unifiedFinding({ id: 's1', tool: 'Gitleaks', category: 'secret', title: 'Clé AWS', rawSeverity: 'HIGH', file: 'config/production.js', absolutePath: '/r/config/production.js', startLine: 4 });
  const result = evaluatePolicyGate([secret], policy('gate:\n  block_secrets: true\n'));
  assert.equal(result.status, STATUS.BLOCK);
  assert.equal(result.violations[0].code, 'secret');
  assert.match(result.violations[0].message, /Clé AWS/);
});

test('le seuil de priorité bloque sur le score calculé', () => {
  const high = scored({ rawSeverity: 'CRITICAL' });
  const low = scored({ id: 'f2', rawSeverity: 'LOW' });
  const result = evaluatePolicyGate([high, low], policy('gate:\n  priority_threshold: 60\n'));
  assert.equal(result.status, STATUS.BLOCK);
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].findingId, 'f1');
  assert.match(result.violations[0].rule, /priority_threshold/);
});

test('un seuil de priorité sans score calculé avertit au lieu de bloquer', () => {
  const result = evaluatePolicyGate([finding()], policy('gate:\n  priority_threshold: 50\n'));
  assert.equal(result.status, STATUS.WARN);
  assert.equal(result.warnings[0].code, 'priority-unavailable');
});

test('un finding trié comme faux positif ne déclenche plus le gate', () => {
  const result = evaluatePolicyGate([finding({ triageStatus: 'false_positive' })], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  assert.equal(result.status, STATUS.PASS);
});

test('une même vulnérabilité n’est jamais comptée deux fois', () => {
  const result = evaluatePolicyGate([scored({ rawSeverity: 'CRITICAL' })], policy('gate:\n  fail_on_severity: [CRITICAL]\n  priority_threshold: 40\n'));
  assert.equal(result.violations.filter((item) => item.findingId === 'f1').length, 1);
});

// --------------------------------------------------------------- artefacts

test('un artefact exigé mais absent bloque', () => {
  const result = evaluatePolicyGate([], policy('gate:\n  require_sbom: true\n'), { artifacts: { sbom: { status: 'failed', reason: 'Trivy indisponible' } } });
  assert.equal(result.status, STATUS.BLOCK);
  assert.equal(result.violations[0].code, 'artifact-missing');
  assert.match(result.violations[0].message, /Trivy indisponible/);
});

test('un artefact exigé et généré laisse passer', () => {
  const result = evaluatePolicyGate([], policy('gate:\n  require_sbom: true\n'), { artifacts: { sbom: { status: 'generated' } } });
  assert.equal(result.status, STATUS.PASS);
});

test('une étape jamais exécutée avertit au lieu de conclure', () => {
  const result = evaluatePolicyGate([], policy('supply_chain:\n  require_signature: true\n'));
  assert.equal(result.status, STATUS.WARN);
  assert.equal(result.warnings[0].code, 'artifact-not-evaluated');
  assert.match(result.warnings[0].message, /n’a pas été exécutée/);
});

test('une signature vérifiée satisfait l’exigence supply chain', () => {
  const result = evaluatePolicyGate([], policy('supply_chain:\n  require_signature: true\n'), { artifacts: { signature: { status: 'verified' } } });
  assert.equal(result.status, STATUS.PASS);
});

// -------------------------------------------------- cohérence extension/CLI

test('extension et CLI obtiennent exactement le même verdict', () => {
  // Le gate est une fonction pure : les deux appelants partagent l'implémentation.
  const parsed = policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n');
  const findings = [finding(), unifiedFinding({ id: 's', tool: 'Gitleaks', category: 'secret', title: 'secret', rawSeverity: 'HIGH', file: 'a.js', absolutePath: '/r/a.js', startLine: 1 })];
  const fromExtension = evaluatePolicyGate(findings, parsed);
  const fromCli = evaluatePolicyGate(findings, parsed);
  assert.equal(fromExtension.status, fromCli.status);
  assert.deepEqual(fromExtension.violations.map((item) => item.code), fromCli.violations.map((item) => item.code));
  assert.equal(fromExtension.counts.violations, 2);
});

test('le rendu texte du gate est exploitable en CI', () => {
  const result = evaluatePolicyGate([finding()], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  const text = formatGateResult(result);
  assert.match(text, /POLICY GATE: BLOCK/);
  assert.match(text, /1 violation\(s\) bloquante\(s\)/);
  assert.match(text, /CRITICAL — Injection SQL/);
  assert.match(text, /src\/login\.js:42/);
  // Les signaux qui expliquent la violation accompagnent la ligne.
  assert.match(text, /Atteignabilité : statically_reachable/);
  assert.match(text, /Détecté par Semgrep/);
  // Un score de priorité n'apparaît que s'il a réellement été calculé.
  assert.ok(!/Priorité/.test(text));
  assert.match(formatGateResult(evaluatePolicyGate([scored()], policy('gate:\n  fail_on_severity: [CRITICAL]\n'))), /Priorité \d+\/100/);
});

// ===========================================================================
// Regression : un seul verdict de politique visible (Checkpoint 7)
//
// Deux moteurs tournaient pour le meme scan. Le banniere du Dashboard et la
// notification lisaient l evaluateur historique, la page Security Pipeline lisait
// le Policy Gate. L historique ignore `block_secrets`, `priority_threshold`, les
// regles d artefacts et l etat WARN : une livraison bloquee pouvait donc etre
// annoncee « politique respectee » — un feu vert imerite, pire qu une fausse
// alerte.
// ===========================================================================

const fsCk7 = require('node:fs');
const pathCk7 = require('node:path');
const { evaluatePolicy } = require('../src/project-policy');
const { policyResultFromGate, evaluatePolicyGate: ck7Gate, policyGateError: ck7GateError, STATUS: CK7 } = require('../src/intelligence/policy-gate');
const { analyzeFindings: ck7Analyze } = require('../src/pipeline');
const { buildDashboardModel: ck7Model } = require('../src/dashboard');

const ck7ExtensionSource = () => fsCk7.readFileSync(pathCk7.join(__dirname, '..', 'src', 'extension.js'), 'utf8').split('\r').join('');

const ck7Finding = (over = {}) => ({ id: 'f1', tool: 'Semgrep', rawSeverity: 'HIGH', severity: 'HIGH', title: 'SQLi', triageStatus: 'new', stage: 'sast', ...over });
const ck7Secret = () => ck7Finding({ id: 's1', tool: 'Gitleaks', rawSeverity: 'MEDIUM', severity: 'MEDIUM', title: 'AWS key', stage: 'secrets', category: 'secret' });

/** Le verdict visible, tel que le produit le calcule desormais. */
const visibleVerdict = (gate, policy) => policyResultFromGate(gate, policy);

test('politique : le verdict visible suit le Policy Gate quand les moteurs divergent', () => {
  // Divergence reelle : l historique n a aucune regle sur les secrets.
  const policy = validatePolicy({ version: 1, max_active: 999, gate: { fail_on_severity: ['CRITICAL'], block_secrets: true } });
  const findings = [ck7Secret()];
  const legacy = evaluatePolicy(findings, policy);
  const gate = ck7Gate(findings, policy);
  assert.equal(legacy.passed, true, 'le moteur historique laisse passer le secret');
  assert.equal(gate.status, CK7.BLOCK, 'le Policy Gate bloque la livraison');

  const visible = visibleVerdict(gate, policy);
  assert.equal(visible.passed, false, 'le verdict visible doit suivre le Gate, pas l historique');
  assert.equal(visible.gateStatus, CK7.BLOCK);
  assert.notEqual(visible.passed, legacy.passed, 'le verdict visible ne suit plus l historique');
  // Et la banniere rendue dit bien « non respectee ».
  const html = require('../src/dashboard').renderDashboardHtml(
    ck7Model(findings, [{ tool: 'Gitleaks', status: 'completed' }], { policyResult: visible, scanStatus: 'completed', backendStatus: 'online' }), 'nonce');
  assert.match(html, /Politique projet non respectée/);
  assert.doesNotMatch(html, /Politique projet respectée/);
});

test('politique : Dashboard et Pipeline s accordent — PASS', () => {
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['CRITICAL'] } });
  const analysis = ck7Analyze([ck7Finding({ rawSeverity: 'LOW', severity: 'LOW' })], { policy });
  assert.equal(analysis.policy.status, CK7.PASS);
  const visible = visibleVerdict(analysis.policy, policy);
  assert.equal(visible.passed, true);
  assert.equal(visible.gateStatus, analysis.policy.status, 'meme statut que celui lu par le Pipeline');
});

test('politique : Dashboard et Pipeline s accordent — WARN', () => {
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['CRITICAL'], warn_on_severity: ['HIGH'] } });
  const analysis = ck7Analyze([ck7Finding()], { policy });
  assert.equal(analysis.policy.status, CK7.WARN);
  const visible = visibleVerdict(analysis.policy, policy);
  // WARN n est pas un refus : le CLI le traite en code de sortie 0.
  assert.equal(visible.passed, true);
  assert.equal(visible.gateStatus, CK7.WARN, 'WARN reste distinguable de PASS');
  assert.ok(visible.warningCount > 0);
  assert.equal(visible.gateSummary, analysis.policy.summary);
});

test('politique : Dashboard et Pipeline s accordent — BLOCK', () => {
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['HIGH'] } });
  const analysis = ck7Analyze([ck7Finding()], { policy });
  assert.equal(analysis.policy.status, CK7.BLOCK);
  const visible = visibleVerdict(analysis.policy, policy);
  assert.equal(visible.passed, false);
  assert.equal(visible.gateStatus, CK7.BLOCK);
  assert.deepEqual(visible.reasons, analysis.policy.violations.map((v) => v.message), 'les raisons viennent du Gate');
});

test('politique : ERROR reste distinct de BLOCK', () => {
  const errorGate = ck7GateError('security-center.yml illisible : ligne 4.', { filePath: 'security-center.yml' });
  assert.equal(errorGate.status, CK7.ERROR);
  const visible = visibleVerdict(errorGate, null);
  // Une politique invalide n autorise rien, mais elle n a rien refuse non plus :
  // les deux etats restent separes.
  assert.equal(visible.passed, false);
  assert.equal(visible.gateStatus, CK7.ERROR);
  assert.notEqual(visible.gateStatus, CK7.BLOCK);
  assert.match(visible.reasons[0], /illisible/);
});

test('politique : une absence de regles ne s affiche pas comme « respectee »', () => {
  const policy = validatePolicy({ version: 1 });
  const gate = ck7Gate([ck7Finding()], policy);
  assert.equal(gate.status, CK7.NOT_CONFIGURED);
  // Pas de verdict => pas de banniere. Une politique absente n autorise rien.
  assert.equal(visibleVerdict(gate, policy), null);
  const html = require('../src/dashboard').renderDashboardHtml(
    ck7Model([ck7Finding()], [{ tool: 'Semgrep', status: 'completed' }], { policyResult: null, scanStatus: 'completed', backendStatus: 'online' }), 'nonce');
  assert.doesNotMatch(html, /Politique projet respectée/);
});

test('politique : la notification utilise le meme verdict que la banniere', () => {
  const source = ck7ExtensionSource();
  const block = source.match(/if \(authoritativePolicyResult\) \{[\s\S]*?\n        \}/);
  assert.ok(block, 'la notification doit lire le verdict autoritaire');
  // Chaque etat du vocabulaire existant du Gate, et rien d invente.
  assert.match(block[0], /GATE_STATUS\.BLOCK[\s\S]*politique projet non respectée/);
  assert.match(block[0], /GATE_STATUS\.ERROR[\s\S]*politique projet invalide/);
  assert.match(block[0], /GATE_STATUS\.WARN/);
  // L ancienne source n alimente plus la notification.
  assert.doesNotMatch(source, /if \(policyResult && !policyResult\.passed\)/);
  // Ni la banniere.
  assert.match(source, /policyResult: authoritativePolicyResult/);
  assert.doesNotMatch(source, /policyResult: consolidatedPolicyResult/);
});

test('politique : le moteur historique subsiste sans piloter l affichage', () => {
  const source = ck7ExtensionSource();
  // Toujours calcule : contrat backend et CLI inchanges.
  assert.match(source, /const consolidatedPolicyResult = evaluatePolicy\(currentFindings, projectPolicy\)/);
  assert.match(source, /evaluatePolicy\(triagedFindings, projectPolicy\)/);
  // Le CLI garde son propre chemin historique.
  const orchestrator = fsCk7.readFileSync(pathCk7.join(__dirname, '..', 'src', 'orchestrator.js'), 'utf8');
  assert.match(orchestrator, /evaluatePolicy\(deduplicated, policy\)/);
  // Et il reste exportable/testable tel quel.
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['CRITICAL'] } });
  assert.equal(typeof evaluatePolicy([ck7Finding()], policy).passed, 'boolean');
});

test('politique : la re-evaluation manuelle met aussi la banniere a jour', () => {
  const source = ck7ExtensionSource();
  const reeval = source.match(/async function reevaluatePolicy\(\)[\s\S]*?liveCompanionProvider\.render\(\);/);
  assert.ok(reeval, 'reevaluatePolicy doit exister');
  assert.match(reeval[0], /policyResult: policyResultFromGate\(gate, policy\)/);
  assert.match(reeval[0], /dashboardProvider\.setData\(/);
});

test('politique : le correctif artefacts du Checkpoint 2 tient toujours', () => {
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['CRITICAL'], require_sbom: true } });
  // SBOM present : Gate PASS, verdict visible identique.
  const withSbom = ck7Analyze([], { policy, artifacts: { sbom: { status: 'generated', path: 'security-center/sbom.cdx.json' } } }).policy;
  assert.equal(withSbom.status, CK7.PASS);
  assert.equal(visibleVerdict(withSbom, policy).passed, true);
  assert.equal(visibleVerdict(withSbom, policy).gateStatus, withSbom.status);
  // Artefact exige mais absent : BLOCK, et la banniere le dit.
  const missing = ck7Analyze([], { policy, artifacts: { sbom: { status: 'failed', reason: 'Trivy indisponible' } } }).policy;
  assert.equal(missing.status, CK7.BLOCK);
  const visibleMissing = visibleVerdict(missing, policy);
  assert.equal(visibleMissing.passed, false);
  assert.equal(visibleMissing.gateStatus, missing.status, 'Dashboard et Pipeline restent d accord');
  // Le cablage du Checkpoint 2 n a pas regresse.
  const source = ck7ExtensionSource();
  assert.equal((source.match(/artifacts: Object\.keys\(currentPipelineArtifacts \|\| \{\}\)\.length \? currentPipelineArtifacts : null/g) || []).length, 2);
});

test('politique : le Gate n est jamais reevalue depuis le rendu', () => {
  const dashboard = fsCk7.readFileSync(pathCk7.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  assert.doesNotMatch(dashboard, /evaluatePolicyGate|policyResultFromGate/, 'le Dashboard consomme un resultat, il ne l evalue pas');
  // Le gate n est pas mute pour arranger la presentation.
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['HIGH'] } });
  const gate = ck7Gate([ck7Finding()], policy);
  const before = JSON.stringify(gate);
  policyResultFromGate(gate, policy);
  assert.equal(JSON.stringify(gate), before, 'le modele du Gate reste intact');
});

test('politique : aucune refonte visuelle de la banniere', () => {
  const policy = validatePolicy({ version: 1, gate: { fail_on_severity: ['HIGH'] } });
  const visible = visibleVerdict(ck7Gate([ck7Finding()], policy), policy);
  const html = require('../src/dashboard').renderDashboardHtml(
    ck7Model([ck7Finding()], [{ tool: 'Semgrep', status: 'completed' }], { policyResult: visible, scanStatus: 'completed', backendStatus: 'online' }), 'nonce');
  // Memes classes, memes libelles qu avant.
  assert.match(html, /<div class="policy-banner fail">/);
  assert.match(html, /<strong>Politique projet non respectée<\/strong>/);
  const passing = visibleVerdict(ck7Gate([], validatePolicy({ version: 1, gate: { fail_on_severity: ['HIGH'] } })), policy);
  const passHtml = require('../src/dashboard').renderDashboardHtml(
    ck7Model([], [{ tool: 'Semgrep', status: 'completed' }], { policyResult: passing, scanStatus: 'completed', backendStatus: 'online' }), 'nonce');
  assert.match(passHtml, /<div class="policy-banner pass">/);
});

test('politique : la configuration et l analyse ne sont pas touchees', () => {
  // Analyse YAML, politique de demarrage et reecriture chirurgicale inchangees.
  const projectPolicy = fsCk7.readFileSync(pathCk7.join(__dirname, '..', 'src', 'project-policy.js'), 'utf8');
  for (const fn of ['function parsePolicyYaml', 'function validatePolicy', 'function applyGateToPolicyYaml', 'function starterPolicyYaml', 'function evaluatePolicy']) {
    assert.ok(projectPolicy.includes(fn), `${fn} doit rester`);
  }
  // Les seuils et regles du Gate ne sont pas modifies par ce checkpoint.
  const gateSource = fsCk7.readFileSync(pathCk7.join(__dirname, '..', 'src', 'intelligence', 'policy-gate.js'), 'utf8');
  assert.match(gateSource, /gate\?\.blockSecrets/);
  assert.match(gateSource, /gate\?\.failOnSeverity/);
  assert.match(gateSource, /gate\?\.priorityThreshold/);
});
