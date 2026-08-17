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
