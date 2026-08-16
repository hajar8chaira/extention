const test = require('node:test');
const assert = require('node:assert/strict');
const { defaultOptions, buildScans } = require('../src/orchestrator');
const { parsePolicyYaml, validatePolicy, TOOL_KEYS } = require('../src/project-policy');
const { parseArgs, help } = require('../src/cli');
const { toSarif } = require('../src/sarif');
const { groupFindings, summarizeFindings } = require('../src/tree');
const { normalizeSonarQubeOutput } = require('../src/findings');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';

function sonarFindings() {
  return normalizeSonarQubeOutput({
    projectKey: 'demo',
    serverUrl: 'http://127.0.0.1:9000',
    components: [{ key: 'demo:src/a.js', path: 'src/a.js' }],
    rules: { 'js:S2076': { key: 'js:S2076', name: 'Injection', securityStandards: ['cwe:78'] } },
    issues: [{ key: 'AY-1', rule: 'js:S2076', component: 'demo:src/a.js', type: 'VULNERABILITY', severity: 'BLOCKER', message: 'Commande dynamique', textRange: { startLine: 12, startOffset: 2, endOffset: 20 } }]
  }, '/repo');
}

// --------------------------------------------------------- orchestrateur

test('SonarQube reste absent du pipeline tant qu’il n’est pas activé', () => {
  const scans = buildScans('/repo', null, defaultOptions(), undefined);
  assert.deepEqual(scans.map((scan) => scan.tool), ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'ZAP']);
});

test('SonarQube rejoint la phase statique une fois activé', () => {
  const scans = buildScans('/repo', null, defaultOptions({ sonarEnabled: true }), undefined);
  assert.deepEqual(scans.map((scan) => scan.tool), ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'ZAP']);
  const sonar = scans.find((scan) => scan.tool === 'SonarQube');
  // La phase dynamique reste réservée à ZAP.
  assert.notEqual(sonar.dynamic, true);
  assert.equal(scans.find((scan) => scan.tool === 'ZAP').dynamic, true);
});

test('SonarQube respecte la sélection explicite de scanners', () => {
  const scans = buildScans('/repo', null, defaultOptions({ sonarEnabled: true, selectedTools: ['SonarQube'] }), undefined);
  assert.deepEqual(scans.map((scan) => scan.tool), ['SonarQube']);
});

test('la politique projet peut désactiver SonarQube comme les autres scanners', () => {
  const policy = { scanners: { SonarQube: false }, exclusions: { global_files: [], semgrep_files: [], semgrep_rules: [], trivy_files: [], zap_routes: [] } };
  const scans = buildScans('/repo', policy, defaultOptions({ sonarEnabled: true }), undefined);
  assert.equal(scans.some((scan) => scan.tool === 'SonarQube'), false);
});

test('les options SonarQube ont des valeurs sûres par défaut', () => {
  const options = defaultOptions();
  assert.equal(options.sonarEnabled, false);
  assert.equal(options.sonarMode, 'auto');
  assert.equal(options.sonarHostUrl, 'http://127.0.0.1:9000');
  assert.equal(options.sonarToken, '');
});

// ------------------------------------------------------- politique projet

test('security-center.yml accepte scanners.sonarqube sans changer la syntaxe', () => {
  const policy = validatePolicy(parsePolicyYaml([
    'version: 1',
    'scanners:',
    '  semgrep: true',
    '  sonarqube: true',
    'sonarqube:',
    '  mode: docker',
    '  include_code_smells: true',
    ''
  ].join('\n')));
  assert.equal(TOOL_KEYS.sonarqube, 'SonarQube');
  assert.equal(policy.scanners.SonarQube, true);
  assert.equal(policy.sonarMode, 'docker');
  assert.equal(policy.sonarIncludeCodeSmells, true);
});

test('la politique projet ne peut pas rediriger le serveur SonarQube', () => {
  const policy = validatePolicy(parsePolicyYaml('sonarqube:\n  mode: auto\n  host_url: http://attaquant.example\n'));
  // host_url est ignoré : l'URL provient uniquement des paramètres VS Code.
  assert.equal(policy.sonarHostUrl, undefined);
  assert.equal(JSON.stringify(policy).includes('attaquant'), false);
});

test('rejette un mode SonarQube inconnu dans la politique', () => {
  assert.throws(
    () => validatePolicy(parsePolicyYaml('sonarqube:\n  mode: kubernetes\n')),
    /sonarqube.mode doit être auto, local ou docker/
  );
  assert.throws(
    () => validatePolicy(parsePolicyYaml('sonarqube:\n  include_code_smells: peut-etre\n')),
    /include_code_smells doit être true ou false/
  );
});

test('une politique sans section sonarqube laisse les réglages VS Code décider', () => {
  const policy = validatePolicy(parsePolicyYaml('version: 1\n'));
  assert.equal(policy.sonarMode, '', 'aucun mode imposé');
  assert.equal(policy.sonarIncludeCodeSmells, undefined);
  // C'est ce qui permet à `projectPolicy?.sonarMode || cfg.get(...)` de
  // retomber sur le paramètre utilisateur.
  assert.equal(policy.sonarMode || 'depuis-vscode', 'depuis-vscode');
});

// ------------------------------------------------------------------- CLI

test('le CLI documente SonarQube et la provenance du jeton', () => {
  assert.match(help(), /SonarQube/);
  assert.match(help(), /SONAR_TOKEN/);
  const args = parseArgs(['--tools', 'Semgrep,SonarQube', '--sonar-host-url', 'http://127.0.0.1:9000', '--sonar-project-key', 'demo']);
  assert.deepEqual(args.tools, ['Semgrep', 'SonarQube']);
  assert.equal(args.sonarHostUrl, 'http://127.0.0.1:9000');
  assert.equal(args.sonarProjectKey, 'demo');
});

test('le CLI n’accepte aucun jeton SonarQube en argument', () => {
  assert.equal(help().includes('--sonar-token'), false);
});

// ------------------------------------------------ pipeline commun aval

test('les findings SonarQube alimentent la TreeView comme les autres outils', () => {
  const findings = sonarFindings();
  const roots = groupFindings(findings, [{ tool: 'SonarQube', status: 'completed' }]);
  const sonarRoot = roots.find((root) => root.label === 'SonarQube');
  assert.equal(sonarRoot.count, 1);
  assert.equal(sonarRoot.children[0].label, 'src/a.js');
  assert.match(summarizeFindings(findings), /SonarQube: 1/);
});

test('les findings SonarQube sont exportés en SARIF par le pipeline commun', () => {
  const sarif = toSarif({ findings: sonarFindings() });
  const [result] = sarif.runs[0].results;
  // SARIF n'accepte pas « : » dans un ruleId : la clé Sonar d'origine reste
  // disponible dans originalRuleId, comme pour les autres scanners.
  assert.equal(result.ruleId, 'sonarqube/js-S2076');
  assert.equal(result.properties.originalRuleId, 'js:S2076');
  assert.equal(result.level, 'error');
  assert.equal(result.properties.scanner, 'SonarQube');
  assert.equal(result.partialFingerprints.securityCenterFingerprint, 'AY-1');
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/a.js');
});

test('un finding SonarQube localisé porte un chemin exploitable par Problems', () => {
  const [finding] = sonarFindings();
  assert.ok(finding.absolutePath, 'Problems a besoin d’un chemin absolu');
  assert.equal(finding.startLine, 11);
  assert.equal(finding.unlocated, false);
});

test('aucun jeton ne peut transiter par un finding normalisé', () => {
  const findings = normalizeSonarQubeOutput({
    projectKey: 'demo',
    serverUrl: 'http://127.0.0.1:9000',
    components: [{ key: 'demo:a.js', path: 'a.js' }],
    rules: {},
    issues: [{ key: 'AY-9', rule: 'js:S1', component: 'demo:a.js', type: 'BUG', severity: 'MAJOR', message: `trace ${TOKEN}`, line: 2 }]
  }, '/repo');
  const serialized = JSON.stringify(findings);
  // Le message vient du serveur : il est conservé tel quel, mais aucune
  // métadonnée ajoutée par Security Center ne transporte de secret.
  assert.equal(findings[0].helpUri.includes(TOKEN), false);
  assert.equal(serialized.match(/squ_/g).length, 1, 'seul le message serveur peut contenir cette chaîne');
});
