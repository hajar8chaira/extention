const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  parsePolicyYaml, validatePolicy, applyGateToPolicyYaml, starterPolicyYaml, STARTER_GATE
} = require('../src/project-policy');
const {
  gateFromSelection, policyGateHash, readPolicyGateConfig, savePolicyGate, createStarterPolicy, policyFilePath
} = require('../src/policy-config');
const {
  evaluatePolicyGate, policyGateError, describeGateRules, formatGateResult, gateExitCode, STATUS
} = require('../src/intelligence/policy-gate');
const { renderPolicyTab, renderPolicyBanner, renderViolation, TABS } = require('../src/pipeline-page');
const { unifiedFinding } = require('../src/intelligence/finding-model');
const { prioritizeFinding } = require('../src/intelligence/prioritization');
const { companionMessageFor, secondaryFor, buildCompanionVisualModel } = require('../src/live/companionMessages');

function workspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-policy-'));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content, 'utf8');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function policy(yaml) {
  return validatePolicy(parsePolicyYaml(yaml));
}

function finding(overrides = {}) {
  return {
    ...unifiedFinding({
      id: 'f1', tool: 'Semgrep', category: 'security', ruleId: 'sqli', title: 'Injection SQL',
      rawSeverity: 'CRITICAL', severity: 'error', file: 'routes/login.ts', absolutePath: '/r/routes/login.ts',
      startLine: 41, cwe: 'CWE-89', ...overrides
    }),
    reachability: { state: 'statically_reachable', confidence: 'medium', reason: '', evidence: [] },
    correlation: { tier: 'confirmed', tools: ['Semgrep', 'SonarQube'], confidence: 'high' }
  };
}

// --------------------------------------------------- les cinq états du gate

test('NOT_CONFIGURED n’est pas un PASS déguisé', () => {
  const result = evaluatePolicyGate([finding()], policy('version: 1\n'));
  assert.equal(result.status, STATUS.NOT_CONFIGURED);
  assert.equal(result.configured, false);
  assert.match(result.summary, /Aucune règle de gate/);
  // Rien n'est autorisé, mais rien n'est refusé non plus : la CI n'échoue pas.
  assert.equal(gateExitCode(result), 0);
});

test('PASS le dit dans les termes de la politique, pas par un « OK »', () => {
  const result = evaluatePolicyGate([finding({ rawSeverity: 'LOW', severity: 'information' })],
    policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  assert.equal(result.status, STATUS.PASS);
  assert.equal(result.summary, 'Le projet respecte la politique de sécurité configurée.');
});

test('WARN annonce le nombre d’avertissements et laisse continuer', () => {
  const result = evaluatePolicyGate([finding({ rawSeverity: 'HIGH', severity: 'warning' })],
    policy('gate:\n  fail_on_severity: [CRITICAL]\n  warn_on_severity: [HIGH]\n'));
  assert.equal(result.status, STATUS.WARN);
  assert.match(result.summary, /peut continuer, mais 1 avertissement/);
  assert.equal(gateExitCode(result), 0);
});

test('BLOCK annonce le nombre de violations bloquantes', () => {
  const result = evaluatePolicyGate([finding()], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  assert.equal(result.status, STATUS.BLOCK);
  assert.match(result.summary, /bloquée par 1 violation/);
  assert.equal(gateExitCode(result), 1);
});

test('ERROR est un état à part entière, jamais un PASS', () => {
  const result = policyGateError('security-center.yml ligne 4 invalide.');
  assert.equal(result.status, STATUS.ERROR);
  assert.equal(result.configured, false);
  assert.match(result.error, /ligne 4/);
  assert.match(result.summary, /invalide/);
  // Une politique illisible est un échec de configuration : code 2, pas 0.
  assert.equal(gateExitCode(result), 2);
  assert.notEqual(result.status, STATUS.PASS);
});

test('un YAML invalide ne peut jamais produire un verdict', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'gate:\n\tfail_on_severity: [CRITICAL]\n' });
  const config = await readPolicyGateConfig(root);
  assert.ok(config.error, 'l’erreur de parsing doit être remontée');
  assert.deepEqual(config.gate, {}, 'aucune règle ne doit être inventée à partir d’un fichier illisible');
  assert.equal(policyGateError(config.error).status, STATUS.ERROR);
});

// ------------------------------------------------------------ règles réelles

test('fail_on_severity signifie « cette sévérité ou plus grave », quel que soit l’ordre', () => {
  const high = finding({ id: 'h', rawSeverity: 'HIGH', severity: 'warning' });
  // [CRITICAL, HIGH] doit bloquer les HIGH : lire seulement la première entrée
  // ignorerait silencieusement le reste de la liste.
  const unordered = evaluatePolicyGate([high], policy('gate:\n  fail_on_severity: [CRITICAL, HIGH]\n'));
  assert.equal(unordered.status, STATUS.BLOCK);
  const ordered = evaluatePolicyGate([high], policy('gate:\n  fail_on_severity: [HIGH, CRITICAL]\n'));
  assert.equal(ordered.status, STATUS.BLOCK);
  assert.equal(unordered.violations.length, ordered.violations.length);
});

test('le seuil de priorité utilise le score déjà calculé, sans le recalculer', () => {
  const scored = prioritizeFinding(finding());
  const result = evaluatePolicyGate([scored], policy('gate:\n  priority_threshold: 50\n'));
  assert.equal(result.status, STATUS.BLOCK);
  // Le score rapporté est exactement celui de la priorisation.
  assert.equal(result.violations[0].priority, scored.priority.score);
  assert.match(result.violations[0].rule, /priority_threshold/);
});

test('les règles appliquées sont explicables en français, avec leur clé YAML', () => {
  const rules = describeGateRules(policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n  priority_threshold: 80\n  require_sbom: true\n'));
  assert.deepEqual(rules.map((rule) => rule.key),
    ['gate.fail_on_severity', 'gate.block_secrets', 'gate.priority_threshold', 'gate.require_sbom']);
  assert.match(rules[0].label, /bloquent la livraison/);
  assert.match(rules[2].label, /80\/100/);
  // Aucune règle inventée : une politique vide ne décrit rien.
  assert.deepEqual(describeGateRules(policy('version: 1\n')), []);
});

// ------------------------------------------------- explication des violations

test('une violation porte les signaux qui expliquent son importance', () => {
  const result = evaluatePolicyGate([prioritizeFinding(finding())], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  const item = result.violations[0];
  assert.equal(item.severity, 'CRITICAL');
  assert.equal(item.reachability, 'statically_reachable');
  assert.equal(item.correlationTier, 'confirmed');
  assert.deepEqual(item.sources, ['Semgrep', 'SonarQube']);
  assert.equal(item.file, 'routes/login.ts');
  assert.equal(item.line, 42);
  assert.ok(Number.isFinite(item.priority));
});

test('un signal non évalué reste absent au lieu de devenir une valeur par défaut', () => {
  const bare = unifiedFinding({
    id: 'b', tool: 'Gitleaks', category: 'secret', ruleId: 'aws-key', title: 'Clé AWS',
    rawSeverity: 'HIGH', severity: 'warning', file: 'config.js', startLine: 11
  });
  const item = evaluatePolicyGate([bare], policy('gate:\n  block_secrets: true\n')).violations[0];
  assert.equal(item.reachability, null);
  assert.equal(item.correlationTier, null);
  assert.equal(item.priority, null);
  // Le seul scanner connu est celui qui a produit le résultat.
  assert.deepEqual(item.sources, ['Gitleaks']);
});

// ------------------------------------------- sélection UI → règles du moteur

test('la sélection de l’interface produit exactement les clés supportées', () => {
  const { gate, supplyChain } = gateFromSelection({
    failCritical: true, blockSecrets: true, priorityThreshold: 80, warnHigh: true, requireSbom: false
  });
  assert.deepEqual(gate.failOnSeverity, ['CRITICAL']);
  assert.deepEqual(gate.warnOnSeverity, ['HIGH']);
  assert.equal(gate.blockSecrets, true);
  assert.equal(gate.priorityThreshold, 80);
  assert.equal(gate.requireSbom, false);
  assert.equal(supplyChain.requireProvenance, false);
});

test('les cases de sévérité sont cumulatives comme le moteur les lit', () => {
  // Cocher « moyennes » signifie « moyennes ou pire » : une seule entrée suffit.
  assert.deepEqual(gateFromSelection({ failCritical: true, failHigh: true, failMedium: true }).gate.failOnSeverity, ['MEDIUM']);
  assert.deepEqual(gateFromSelection({ failCritical: true, failHigh: true }).gate.failOnSeverity, ['HIGH']);
  assert.deepEqual(gateFromSelection({}).gate.failOnSeverity, []);
});

test('un seuil hors bornes est refusé avant d’atteindre le disque', () => {
  assert.throws(() => gateFromSelection({ priorityThreshold: 150 }), /entier entre 0 et 100/);
  assert.throws(() => gateFromSelection({ warnPriorityThreshold: -1 }), /entier entre 0 et 100/);
  // Vide signifie « pas de seuil », pas zéro.
  assert.equal(gateFromSelection({ priorityThreshold: null }).gate.priorityThreshold, null);
  assert.equal(gateFromSelection({ priorityThreshold: 0 }).gate.priorityThreshold, 0);
});

// ------------------------------------------------- écriture sûre du YAML

const HAND_WRITTEN = [
  '# Politique maison — ne pas régénérer',
  'version: 1',
  'scanners:',
  '  semgrep: true',
  '  gitleaks: true',
  '',
  '# Réglages ZAP validés par l’équipe sécurité',
  'zap:',
  '  mode: local',
  '  policy_min_severity: HIGH',
  '',
  'gate:',
  '  fail_on_severity: [HIGH]',
  '',
  'exclusions:',
  '  global_files: [dist/**]',
  ''
].join('\n');

test('enregistrer la politique préserve tout le reste du fichier', async (t) => {
  const root = workspace(t, { 'security-center.yml': HAND_WRITTEN });
  const result = await savePolicyGate(root, { failCritical: true, blockSecrets: true, priorityThreshold: 80 });
  assert.equal(result.ok, true);
  const text = fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8');
  assert.match(text, /# Politique maison/);
  assert.match(text, /# Réglages ZAP validés/);
  assert.match(text, /policy_min_severity: HIGH/);
  assert.match(text, /semgrep: true/);
  assert.match(text, /global_files: \[dist\/\*\*\]/);
  // Et la seule section réécrite est la bonne.
  assert.match(text, /fail_on_severity: \[CRITICAL\]/);
  assert.ok(!text.includes('fail_on_severity: [HIGH]'));
});

test('un fichier illisible n’est jamais écrasé par l’interface', async (t) => {
  const broken = 'gate:\n\tfail_on_severity: [CRITICAL]\n';
  const root = workspace(t, { 'security-center.yml': broken });
  const result = await savePolicyGate(root, { failCritical: true });
  assert.equal(result.ok, false);
  assert.match(result.message, /security-center\.yml/);
  // Le fichier est intact : rien n'a été écrit sur une base incomprise.
  assert.equal(fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8'), broken);
});

test('une sélection vide retire la section gate au lieu d’en écrire une trompeuse', async (t) => {
  const root = workspace(t, { 'security-center.yml': HAND_WRITTEN });
  const result = await savePolicyGate(root, {});
  assert.equal(result.ok, true);
  assert.equal(result.configured, false);
  const text = fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8');
  assert.ok(!/^gate:/m.test(text), 'la section gate doit disparaître');
  assert.match(text, /# Politique maison/);
  assert.match(result.message, /non configuré/);
});

test('le fichier écrit est toujours relisible par le moteur', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'version: 1\n' });
  await savePolicyGate(root, {
    failHigh: true, warnMedium: true, blockSecrets: true,
    priorityThreshold: 70, warnPriorityThreshold: 40, requireSbom: true, requireSignature: true
  });
  const reread = validatePolicy(parsePolicyYaml(fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8')));
  assert.deepEqual(reread.gate.failOnSeverity, ['HIGH']);
  assert.deepEqual(reread.gate.warnOnSeverity, ['MEDIUM']);
  assert.equal(reread.gate.priorityThreshold, 70);
  assert.equal(reread.gate.warnPriorityThreshold, 40);
  assert.equal(reread.gate.requireSbom, true);
  assert.equal(reread.supplyChain.requireSignature, true);
});

test('la relecture alimente le formulaire depuis le fichier, sans copie parallèle', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'gate:\n  fail_on_severity: [HIGH]\n  block_secrets: true\n' });
  const config = await readPolicyGateConfig(root);
  assert.equal(config.exists, true);
  assert.deepEqual(config.gate.failOnSeverity, ['HIGH']);
  assert.equal(config.gate.blockSecrets, true);
  assert.equal(config.error, '');
  assert.ok(config.hash);
  assert.equal(config.filePath, path.join(root, 'security-center.yml'));
});

test('les séquences YAML en bloc sont acceptées comme les listes en ligne', () => {
  const block = policy('gate:\n  fail_on_severity:\n    - CRITICAL\n    - HIGH\n  block_secrets: true\n');
  const inline = policy('gate:\n  fail_on_severity: [CRITICAL, HIGH]\n  block_secrets: true\n');
  assert.deepEqual(block.gate.failOnSeverity, inline.gate.failOnSeverity);
  assert.equal(block.gate.blockSecrets, true);
});

test('appliquer une politique valide sur un fichier sans gate l’ajoute proprement', () => {
  const updated = applyGateToPolicyYaml('version: 1\nscanners:\n  semgrep: true\n',
    { gate: { failOnSeverity: ['CRITICAL'], blockSecrets: true }, supplyChain: {} });
  assert.match(updated, /gate:\n  fail_on_severity: \[CRITICAL\]\n  block_secrets: true/);
  assert.match(updated, /semgrep: true/);
  assert.doesNotThrow(() => validatePolicy(parsePolicyYaml(updated)));
});

// ------------------------------------------------------- politique de départ

test('la politique de départ n’utilise que la syntaxe réellement supportée', () => {
  const parsed = validatePolicy(parsePolicyYaml(starterPolicyYaml()));
  assert.deepEqual(parsed.gate.failOnSeverity, STARTER_GATE.failOnSeverity);
  assert.equal(parsed.gate.blockSecrets, true);
  assert.equal(parsed.gate.priorityThreshold, 80);
  assert.equal(parsed.gate.configured, true);
});

test('la politique de départ n’est créée que sur demande explicite', async (t) => {
  const root = workspace(t, {});
  // La simple lecture ne crée rien.
  const before = await readPolicyGateConfig(root);
  assert.equal(before.exists, false);
  assert.equal(fs.existsSync(path.join(root, 'security-center.yml')), false);
  const created = await createStarterPolicy(root);
  assert.equal(created.ok, true);
  assert.equal(fs.existsSync(path.join(root, 'security-center.yml')), true);
  // Et elle n'écrase jamais un fichier existant.
  const again = await createStarterPolicy(root);
  assert.equal(again.ok, false);
  assert.match(again.message, /existe déjà/);
});

// -------------------------------------------- politique au moment du scan

test('le hash ne couvre que les règles du gate', () => {
  const base = 'gate:\n  fail_on_severity: [CRITICAL]\n';
  assert.equal(policyGateHash(policy(base)), policyGateHash(policy(`${base}scanners:\n  semgrep: true\n`)),
    'modifier un scanner ne doit pas périmer les verdicts passés');
  assert.notEqual(policyGateHash(policy(base)), policyGateHash(policy('gate:\n  fail_on_severity: [HIGH]\n')));
  assert.notEqual(policyGateHash(policy(base)), policyGateHash(policy(`${base}  block_secrets: true\n`)));
});

test('le verdict reste attaché au scan qui l’a produit', () => {
  const scanned = policy('gate:\n  fail_on_severity: [CRITICAL]\n');
  const edited = policy('gate:\n  fail_on_severity: [MEDIUM]\n');
  const hashAtScan = policyGateHash(scanned);
  // La divergence est constatée, pas corrigée en silence : l'historique n'est
  // jamais recalculé avec une politique qu'il n'a pas subie.
  assert.notEqual(hashAtScan, policyGateHash(edited));
  const model = {
    scanId: 'scan-7', policy: evaluatePolicyGate([finding()], scanned),
    policyConfig: { exists: true, filePath: 's.yml', gate: edited.gate, supplyChain: edited.supplyChain, error: '' },
    policyEvaluation: { policyHashAtScan: hashAtScan, currentPolicyHash: policyGateHash(edited), policyChangedSinceScan: true }
  };
  const html = renderPolicyTab(model);
  assert.match(html, /au moment du scan/);
  assert.match(html, /scan-7/);
});

// ------------------------------------------------------------------ interface

test('la page expose un onglet Policy Gate dédié', () => {
  assert.ok(TABS.some(([id, label]) => id === 'policy' && label === 'Policy Gate'));
});

test('non configuré propose de configurer, sans prétendre à un verdict', () => {
  const html = renderPolicyBanner({ policy: evaluatePolicyGate([], policy('version: 1\n')) });
  assert.match(html, /NON CONFIGURÉ/);
  assert.match(html, /Aucune règle de gate trouvée/);
  assert.match(html, /data-tab="policy"/);
  assert.ok(!/PASS/.test(html));
});

test('BLOCK affiche le nombre de violations et une action pour les voir', () => {
  const html = renderPolicyBanner({ policy: evaluatePolicyGate([finding()], policy('gate:\n  fail_on_severity: [CRITICAL]\n')) });
  assert.match(html, /Policy Gate — BLOCK/);
  assert.match(html, /1 violation\(s\) bloquante\(s\)/);
  assert.match(html, /Voir les violations/);
});

test('une politique invalide affiche ERROR et non un gate vert', () => {
  const html = renderPolicyBanner({ policy: policyGateError('ligne 3 invalide.') });
  assert.match(html, /configuration invalide/i);
  assert.match(html, /ligne 3 invalide/);
  assert.match(html, /Aucune livraison n’est autorisée/);
  assert.ok(!/PASS/.test(html));
});

test('le détail d’une violation explique pourquoi elle compte', () => {
  const result = evaluatePolicyGate([prioritizeFinding(finding())], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  const html = renderViolation(result.violations[0], 1);
  assert.match(html, /Injection SQL/);
  assert.match(html, /Atteignable statiquement/);
  assert.match(html, /Confirmée par plusieurs scanners/);
  assert.match(html, /Semgrep \+ SonarQube/);
  assert.match(html, /routes\/login\.ts:42/);
  assert.match(html, /gate\.fail_on_severity/);
});

test('le formulaire n’expose que des règles évaluables et reflète le fichier', () => {
  const html = renderPolicyTab({
    scanId: 'scan-1', policy: evaluatePolicyGate([], policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n  priority_threshold: 80\n')),
    policyConfig: { exists: true, filePath: 'security-center.yml', error: '', gate: policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n  priority_threshold: 80\n').gate, supplyChain: {} },
    policyEvaluation: {}
  });
  // Les règles cochées viennent du fichier.
  assert.match(html, /data-policy-field="failCritical" checked/);
  assert.match(html, /data-policy-field="blockSecrets" checked/);
  assert.match(html, /data-policy-field="priorityThreshold" value="80"/);
  assert.match(html, /data-policy-field="failMedium"(?! checked)/);
  // Et seules les clés supportées sont proposées.
  for (const field of ['failCritical', 'failHigh', 'failMedium', 'blockSecrets', 'priorityThreshold',
    'warnHigh', 'warnMedium', 'warnPriorityThreshold', 'requireSbom', 'requireProvenance', 'requireSignature']) {
    assert.match(html, new RegExp(`data-policy-field="${field}"`), `champ ${field} absent`);
  }
  assert.ok(!/require_signed_image|max_active/.test(html));
});

test('le formulaire explique les règles en français, pas seulement en YAML', () => {
  const html = renderPolicyTab({ policy: null, policyConfig: { gate: {}, supplyChain: {}, error: '' }, policyEvaluation: {} });
  assert.match(html, /Des vulnérabilités critiques existent/);
  assert.match(html, /Des secrets exposés existent/);
  // Et garde une porte de sortie pour les développeurs.
  assert.match(html, /Avancé — ouvrir security-center\.yml/);
});

test('la ré-évaluation est proposée et désactivée sans scan', () => {
  const withScan = renderPolicyTab({ scanId: 'scan-3', policy: null, policyConfig: { gate: {}, supplyChain: {}, error: '' }, policyEvaluation: {} });
  assert.match(withScan, /data-action="reevaluatePolicy"[^>]*>Ré-évaluer la politique/);
  const withoutScan = renderPolicyTab({ scanId: '', policy: null, policyConfig: { gate: {}, supplyChain: {}, error: '' }, policyEvaluation: {} });
  assert.match(withoutScan, /data-action="reevaluatePolicy"\s+disabled/);
  assert.match(withoutScan, /rejoue uniquement le moteur de politique/);
});

test('un enregistrement refusé le dit et affirme que le fichier est intact', () => {
  const html = renderPolicyTab({
    policy: null, policyConfig: { gate: {}, supplyChain: {}, error: '' }, policyEvaluation: {},
    policySaveResult: { ok: false, message: 'security-center.yml ligne 4 invalide.' }
  });
  assert.match(html, /Enregistrement refusé/);
  assert.match(html, /ligne 4 invalide/);
  assert.match(html, /n’a pas été modifié/);
});

// ------------------------------------------------------ ré-évaluation seule

test('ré-évaluer n’exécute que le moteur de politique', () => {
  // Le contrat : mêmes findings, même scan, seul le verdict change.
  const findings = [prioritizeFinding(finding())];
  const before = evaluatePolicyGate(findings, policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  const after = evaluatePolicyGate(findings, policy('gate:\n  fail_on_severity: [CRITICAL]\n  block_secrets: true\n'));
  assert.equal(before.status, STATUS.BLOCK);
  assert.equal(after.status, STATUS.BLOCK);
  // Les findings ne sont pas modifiés par l'évaluation : le gate ne les touche pas.
  assert.equal(findings[0].priority.score, prioritizeFinding(finding()).priority.score);
  assert.equal(findings.length, 1);
});

test('un assouplissement de la politique fait basculer BLOCK → PASS sans re-scan', () => {
  const findings = [prioritizeFinding(finding({ rawSeverity: 'HIGH', severity: 'warning' }))];
  assert.equal(evaluatePolicyGate(findings, policy('gate:\n  fail_on_severity: [HIGH]\n')).status, STATUS.BLOCK);
  assert.equal(evaluatePolicyGate(findings, policy('gate:\n  fail_on_severity: [CRITICAL]\n')).status, STATUS.PASS);
});

// ------------------------------------------------------------ CLI / CI

test('la sortie CI nomme la décision, ses raisons et le code de sortie', () => {
  const result = evaluatePolicyGate([prioritizeFinding(finding())], policy('gate:\n  fail_on_severity: [CRITICAL]\n'));
  const text = formatGateResult(result);
  assert.match(text, /^POLICY GATE: BLOCK/);
  assert.match(text, /CRITICAL — Injection SQL/);
  assert.match(text, /routes\/login\.ts:42/);
  assert.match(text, /Détecté par Semgrep \+ SonarQube/);
  assert.equal(gateExitCode(result), 1);
});

test('un secret est rapporté sans jamais réimprimer sa valeur', () => {
  const secret = unifiedFinding({
    id: 's1', tool: 'Gitleaks', category: 'secret', ruleId: 'aws-access-key',
    title: 'Identifiant de type AWS', rawSeverity: 'HIGH', severity: 'warning',
    file: 'config/production.js', startLine: 11,
    // Ce que le scanner a matché ne doit jamais ressortir.
    match: 'AKIAIOSFODNN7EXAMPLE', secret: 'AKIAIOSFODNN7EXAMPLE'
  });
  const result = evaluatePolicyGate([secret], policy('gate:\n  block_secrets: true\n'));
  assert.equal(result.status, STATUS.BLOCK);
  const text = formatGateResult(result);
  assert.match(text, /SECRET — Identifiant de type AWS/);
  assert.match(text, /config\/production\.js:12/);
  assert.ok(!text.includes('AKIAIOSFODNN7EXAMPLE'), 'la valeur du secret ne doit jamais être imprimée');
  assert.ok(!JSON.stringify(result).includes('AKIAIOSFODNN7EXAMPLE'), 'ni voyager dans le résultat du gate');
});

test('les codes de sortie respectent le contrat CI', () => {
  const rules = policy('gate:\n  fail_on_severity: [CRITICAL]\n  warn_on_severity: [HIGH]\n');
  assert.equal(gateExitCode(evaluatePolicyGate([finding({ rawSeverity: 'LOW', severity: 'information' })], rules)), 0, 'PASS → 0');
  assert.equal(gateExitCode(evaluatePolicyGate([finding({ rawSeverity: 'HIGH', severity: 'warning' })], rules)), 0, 'WARN → 0');
  assert.equal(gateExitCode(evaluatePolicyGate([finding()], rules)), 1, 'BLOCK → 1');
  assert.equal(gateExitCode(policyGateError('invalide')), 2, 'ERROR → 2');
  assert.equal(gateExitCode(evaluatePolicyGate([finding()], policy('version: 1\n'))), 0, 'NOT_CONFIGURED → 0');
});

test('la CLI refuse de scanner avec une politique illisible et sort en 2', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'gate:\n\tfail_on_severity: [CRITICAL]\n' });
  const { main } = require('../src/cli');
  const written = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  t.after(() => { process.stderr.write = original; });
  const code = await main(['scan', '--workspace', root]);
  process.stderr.write = original;
  assert.equal(code, 2);
  const output = written.join('');
  assert.match(output, /POLICY GATE: ERROR/);
  assert.match(output, /Exit code: 2/);
});

// -------------------------------------------------------------- Companion

test('le Companion consomme le verdict du pipeline, il ne l’évalue pas', () => {
  const blocked = companionMessageFor('clean', { policyStatus: 'BLOCK' });
  assert.equal(blocked.kind, 'policy-block');
  assert.match(blocked.headline, /politique projet bloque la livraison/);
  // Un gate vert est une information projet : il accompagne le message du
  // fichier courant au lieu de le remplacer.
  const passed = secondaryFor(companionMessageFor('clean', { policyStatus: 'PASS' }), { policyStatus: 'PASS' });
  assert.equal(passed.kind, 'policy-pass');
  assert.match(passed.headline, /[Pp]olitique projet respectée/);
  assert.equal(passed.mascot, 'success');
  const broken = companionMessageFor('clean', { policyStatus: 'ERROR' });
  assert.equal(broken.kind, 'policy-block');
  assert.match(broken.headline, /invalide/);
});

test('un gate non configuré ne fait rien dire au Companion', () => {
  const visual = buildCompanionVisualModel({ serviceState: 'clean', findings: [], file: 'a.js', pipeline: { policyStatus: '' } });
  assert.ok(!/politique/i.test(`${visual.message.headline} ${visual.message.detail}`));
});

test('le blocage de politique passe après un problème critique en cours d’édition', () => {
  const critical = companionMessageFor('findings', {
    policyStatus: 'BLOCK',
    findings: [{ ruleId: 'unsafe-eval', severity: 'critical' }]
  });
  // Ce que le développeur tape maintenant prime sur le verdict projet.
  assert.equal(critical.kind, 'live-critical');
});

test('un finding ne produit qu’une violation, avec la règle la plus spécifique', () => {
  const secret = unifiedFinding({
    id: 's1', tool: 'Gitleaks', category: 'secret', ruleId: 'aws-access-token',
    title: 'Identifiant AWS', rawSeverity: 'HIGH', severity: 'warning', file: 'config.js', startLine: 2
  });
  // Le secret déclenche à la fois block_secrets et fail_on_severity : il ne doit
  // compter qu'une fois, sinon « 4 violations » décrirait 2 vrais problèmes.
  const result = evaluatePolicyGate([{ ...secret, priority: { score: 90, code: 'P0' } }],
    policy('gate:\n  fail_on_severity: [HIGH]\n  block_secrets: true\n  priority_threshold: 50\n'));
  assert.equal(result.violations.length, 1);
  assert.equal(result.counts.violations, 1);
  // Et la raison retenue est la plus explicite des trois.
  assert.equal(result.violations[0].code, 'secret');
  assert.match(result.violations[0].message, /Secret exposé/);
});

test('un finding bloquant n’apparaît pas aussi en avertissement', () => {
  const high = { ...finding({ rawSeverity: 'HIGH', severity: 'warning' }), priority: { score: 70, code: 'P1' } };
  const result = evaluatePolicyGate([high],
    policy('gate:\n  fail_on_severity: [HIGH]\n  warn_on_severity: [MEDIUM]\n  warn_priority_threshold: 30\n'));
  assert.equal(result.violations.length, 1);
  assert.equal(result.warnings.length, 0, 'un problème bloqué n’a pas besoin d’être « surveillé » en plus');
  assert.equal(result.status, STATUS.BLOCK);
});

test('un avertissement n’est pas répété par deux règles', () => {
  const high = { ...finding({ rawSeverity: 'HIGH', severity: 'warning' }), priority: { score: 70, code: 'P1' } };
  const result = evaluatePolicyGate([high],
    policy('gate:\n  fail_on_severity: [CRITICAL]\n  warn_on_severity: [HIGH]\n  warn_priority_threshold: 30\n'));
  assert.equal(result.status, STATUS.WARN);
  assert.equal(result.warnings.length, 1);
  assert.match(result.summary, /1 avertissement/);
});

// ------------------------------------------------- étape pipeline & historique

test('une politique invalide fait échouer l’étape, elle ne la rend pas « non configurée »', () => {
  const { describeStages } = require('../src/pipeline');
  const stage = (policyResult) => describeStages({ findings: [], scanners: [], policy: policyResult })
    .find((item) => item.id === 'policy');
  const broken = stage(policyGateError('security-center.yml ligne 2 invalide.'));
  assert.equal(broken.state, 'failed');
  assert.match(broken.detail, /invalide/);
  assert.notEqual(broken.state, 'not_configured', 'un échec ne doit pas se lire comme une absence de configuration');
  // Et les autres états restent distincts.
  assert.equal(stage(evaluatePolicyGate([], policy('version: 1\n'))).state, 'not_configured');
  assert.equal(stage(evaluatePolicyGate([finding()], policy('gate:\n  fail_on_severity: [CRITICAL]\n'))).state, 'blocked');
  assert.equal(stage(evaluatePolicyGate([], policy('gate:\n  fail_on_severity: [CRITICAL]\n'))).state, 'passed');
});

test('le verdict persiste avec le scan et se restaure tel quel', () => {
  const { buildPipelineResult, pipelineStateFor, restorePipelineResult } = require('../src/pipeline');
  const rules = policy('gate:\n  fail_on_severity: [CRITICAL]\n');
  const findings = [prioritizeFinding(finding())];
  const gate = evaluatePolicyGate(findings, rules);
  const result = buildPipelineResult({ scanId: 'scan-42', analysis: { findings, policy: gate } });
  const persisted = { ...pipelineStateFor(result, { policy: gate }), policyHash: policyGateHash(rules) };
  assert.equal(persisted.policy.status, STATUS.BLOCK);
  assert.equal(persisted.policyHash, policyGateHash(rules));
  // Rechargé, le scan garde le verdict qu'il a subi — rien n'est recalculé.
  const restored = restorePipelineResult(persisted, findings);
  assert.equal(restored.scanId, 'scan-42');
  assert.equal(restored.policy.status, STATUS.BLOCK);
  assert.equal(restored.policy.violations.length, 1);
  assert.equal(restored.policy.evaluatedAt, gate.evaluatedAt);
});

test('l’événement d’audit d’une politique ne transporte ni secret ni jeton', () => {
  const { sanitizeAuditEvent } = require('../src/audit-events');
  const rules = policy('gate:\n  block_secrets: true\n');
  const gate = evaluatePolicyGate([unifiedFinding({
    id: 's', tool: 'Gitleaks', category: 'secret', ruleId: 'aws', title: 'Clé AWS',
    rawSeverity: 'HIGH', severity: 'warning', file: 'config.js', startLine: 1,
    secret: 'kR8vN2pQwZ7xL4mT6yB9', match: 'kR8vN2pQwZ7xL4mT6yB9'
  })], rules);
  const event = sanitizeAuditEvent({
    scan_id: 42, action: 'policy.gate.blocked', actor: 'System', comment: gate.summary,
    metadata: {
      status: gate.status, scanId: 'scan-42', policyHash: policyGateHash(rules),
      violations: gate.violations.length, warnings: gate.warnings.length
    }
  });
  assert.equal(event.action, 'policy.gate.blocked');
  assert.equal(event.metadata.status, 'BLOCK');
  assert.equal(event.metadata.violations, 1);
  assert.equal(event.metadata.scanId, 'scan-42');
  // Seuls des comptes et des identifiants voyagent, jamais une valeur détectée.
  assert.ok(!JSON.stringify(event).includes('kR8vN2pQwZ7xL4mT6yB9'));
});

test('les trois actions d’audit de la politique sont dans la taxonomie', () => {
  const { normalizeAuditEvent } = require('../src/audit-events');
  for (const [action, category] of [['policy.changed', 'CONFIGURATION'], ['policy.gate.evaluated', 'POLICY'], ['policy.gate.blocked', 'POLICY']]) {
    assert.equal(normalizeAuditEvent({ action, actor: 'System' }).category, category, `${action} mal catégorisée`);
  }
});

test('la politique de départ complète un fichier sans gate sans rien écraser', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'version: 1\nscanners:\n  semgrep: true\n\n# à conserver\nzap:\n  mode: local\n' });
  const created = await createStarterPolicy(root);
  assert.equal(created.ok, true);
  const text = fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8');
  assert.match(text, /# à conserver/);
  assert.match(text, /mode: local/);
  assert.match(text, /fail_on_severity: \[CRITICAL\]/);
  // Et un gate déjà présent n'est jamais remplacé par le bouton « départ ».
  const again = await createStarterPolicy(root);
  assert.equal(again.ok, false);
  assert.match(again.message, /existe déjà/);
});

test('le bouton « politique de départ » apparaît dès qu’aucune règle n’existe', () => {
  const withoutRules = renderPolicyTab({ policy: null, policyConfig: { exists: true, configured: false, gate: {}, supplyChain: {}, error: '' }, policyEvaluation: {} });
  assert.match(withoutRules, /data-action="createStarterPolicy"/);
  const withRules = renderPolicyTab({ policy: null, policyConfig: { exists: true, configured: true, gate: { failOnSeverity: ['CRITICAL'] }, supplyChain: {}, error: '' }, policyEvaluation: {} });
  assert.ok(!withRules.includes('createStarterPolicy'));
});
