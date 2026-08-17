const test = require('node:test');
const assert = require('node:assert/strict');
const { renderScannerSetupHtml, renderSnykCard, snykDiagnosis, usedSnykMode } = require('../src/scanner-setup-page');
const { renderFindingDetailsHtml } = require('../src/finding-details');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { normalizeSnykOutput, hasReportableLocation } = require('../src/findings');
const { compareScans, renderScanComparisonHtml } = require('../src/scan-comparison');
const { groupFindings, summarizeFindings } = require('../src/tree');
const { projectSnapshot, snapshotFromLegacy } = require('../src/security-snapshot');

const TOKEN = '11111111-2222-3333-4444-555555555555';
const MANAGED = [
  { id: 'semgrep', label: 'Semgrep', purpose: 'Analyse statique du code (SAST)', installed: true, version: '1.2.3', executable: '/bin/semgrep', managed: false },
  { id: 'gitleaks', label: 'Gitleaks', purpose: 'Détection de secrets', installed: false, version: '', executable: '', managed: false },
  { id: 'trivy', label: 'Trivy', purpose: 'Dépendances, conteneurs et IaC', installed: true, version: '0.50', executable: '/bin/trivy', managed: true },
  { id: 'osv', label: 'OSV-Scanner', purpose: 'Vulnérabilités des dépendances', installed: true, version: '2.0', executable: '/bin/osv-scanner', managed: true }
];

const SONAR = {
  enabled: true, mode: 'auto', serverType: 'existing', hostUrl: 'http://127.0.0.1:9000', tokenConfigured: true,
  scannerVersion: '6.2.1', scannerPath: '/opt/sonar/bin/sonar-scanner',
  dockerAvailable: true, serverOnline: true, serverVersion: '26.8.0', serverMessage: ''
};

function snyk(overrides = {}) {
  return {
    enabled: true, mode: 'auto', tokenConfigured: true, authenticationValid: true,
    cliVersion: '1.1298.0', cliPath: '/usr/local/bin/snyk', dockerAvailable: true,
    includeOpenSource: true, includeCode: false, includeIaC: false,
    capabilities: { openSource: true, code: null, iac: null },
    ...overrides
  };
}

function setupHtml(overrides) {
  return renderScannerSetupHtml(MANAGED, 'nonce123', 'light', {}, null, SONAR, overrides === null ? null : snyk(overrides));
}

function snykFindings(payload) {
  return normalizeSnykOutput(payload, '/repo');
}

const OSS_PAYLOAD = {
  openSource: {
    results: [{
      packageManager: 'npm', projectName: 'demo', displayTargetFile: 'package-lock.json',
      vulnerabilities: [{
        id: 'SNYK-JS-LODASH-567746', title: 'Prototype Pollution', severity: 'high',
        packageName: 'lodash', version: '4.17.11', from: ['demo@1.0.0', 'lodash@4.17.11'],
        upgradePath: ['demo@1.0.0', 'lodash@4.17.21'], isUpgradable: true,
        identifiers: { CVE: ['CVE-2020-8203'], CWE: ['CWE-1321'] },
        fixedIn: ['4.17.21'], cvssScore: 7.4, exploit: 'Proof of Concept',
        description: 'Pollution de prototype.', packageManager: 'npm'
      }]
    }]
  }
};

const CODE_PAYLOAD = {
  code: {
    sarif: {
      runs: [{
        tool: { driver: { rules: [{ id: 'javascript/Sqli', shortDescription: { text: 'SQL Injection' }, properties: { cwe: ['CWE-89'] } }] } },
        results: [{
          ruleId: 'javascript/Sqli', level: 'error', message: { text: 'Injection SQL possible.' },
          fingerprints: { 'snyk/assets/finding/v1': 'identity-1' },
          locations: [{ physicalLocation: { artifactLocation: { uri: 'routes/search.js' }, region: { startLine: 42, startColumn: 9 } } }],
          codeFlows: [{ threadFlows: [{ locations: [{ location: { physicalLocation: { artifactLocation: { uri: 'routes/search.js' }, region: { startLine: 12 } } } }] }] }]
        }]
      }]
    }
  }
};

const IAC_PAYLOAD = {
  iac: {
    results: [{
      targetFile: 'deploy/k8s.yaml',
      infrastructureAsCodeIssues: [{
        publicId: 'SNYK-CC-K8S-42', title: 'Conteneur privilégié', severity: 'high', lineNumber: 17,
        subType: 'Deployment', path: ['spec', 'privileged'],
        iacDescription: { issue: 'Mode privilégié', impact: 'Accès hôte', resolve: 'Retirer privileged' }
      }]
    }]
  }
};

// ------------------------------------------- Configuration des scanners

test('Snyk apparaît dans Configuration des scanners avec sa description', () => {
  const html = setupHtml();
  assert.match(html, /<h2>Snyk<\/h2>/);
  assert.match(html, /Analyse SCA \/ SAST \/ IaC/);
  assert.match(html, /data-tool="snyk"/);
});

test('aucun scanner existant ne disparaît quand Snyk est ajouté', () => {
  const html = setupHtml();
  for (const label of ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk']) {
    assert.ok(html.includes(`<h2>${label}</h2>`), `${label} absent de la page`);
  }
});

test('la page reste rendue sans diagnostic Snyk', () => {
  const html = setupHtml(null);
  assert.ok(!html.includes('data-tool="snyk"'));
  assert.match(html, /<h2>SonarQube<\/h2>/);
});

test('la carte expose mode configuré et mode utilisé séparément', () => {
  const html = renderSnykCard(snyk({ mode: 'auto' }), false);
  assert.match(html, /<dt>Mode configuré<\/dt><dd>Auto<\/dd>/);
  assert.match(html, /<dt>Mode utilisé<\/dt><dd>Local<\/dd>/);
  assert.match(html, /1\.1298\.0/);
});

test('Auto retombe sur Docker quand le CLI local est absent', () => {
  assert.equal(usedSnykMode(snyk({ cliVersion: '' })), 'Docker');
  assert.equal(usedSnykMode(snyk({ cliVersion: '', dockerAvailable: false })), '');
  assert.equal(usedSnykMode(snyk({ mode: 'docker' })), 'Docker');
  assert.equal(usedSnykMode(snyk({ mode: 'local', cliVersion: '' })), '');
  const html = renderSnykCard(snyk({ cliVersion: '' }), false);
  assert.match(html, /<dt>Mode utilisé<\/dt><dd>Docker<\/dd>/);
  assert.match(html, /snyk\/snyk:linux/);
});

test('les trois modes sont proposés', () => {
  const html = renderSnykCard(snyk(), false);
  for (const mode of ['auto', 'local', 'docker']) assert.ok(html.includes(`data-snyk-mode="${mode}"`), `mode ${mode} absent`);
});

test('la bascule d’activation reflète l’état courant', () => {
  assert.match(renderSnykCard(snyk({ enabled: true }), false), /data-snyk-enabled="false"[^>]*>Désactiver Snyk/);
  assert.match(renderSnykCard(snyk({ enabled: false }), false), /data-snyk-enabled="true"[^>]*>Activer Snyk/);
});

test('l’installation locale est proposée seulement quand elle est pertinente', () => {
  assert.match(renderSnykCard(snyk({ cliVersion: '' }), false), /data-snyk-install/);
  assert.ok(!renderSnykCard(snyk(), false).includes('data-snyk-install'), 'CLI présent : aucune installation proposée');
  assert.ok(!renderSnykCard(snyk({ cliVersion: '', mode: 'docker' }), false).includes('data-snyk-install'), 'mode Docker : aucune installation locale');
});

test('l’installation en cours est visible sur la carte', () => {
  const html = renderSnykCard(snyk({ cliVersion: '', installing: { state: 'installing', title: 'Installation du CLI Snyk', message: 'Téléchargement 40%', percent: 40 } }), false);
  assert.match(html, /Installation du CLI Snyk/);
  assert.match(html, /<progress max="100" value="40">/);
});

test('la carte affiche l’état du jeton, jamais sa valeur', () => {
  const configured = renderSnykCard(snyk(), false);
  assert.match(configured, /<dt>Token<\/dt><dd>Configuré/);
  assert.ok(!configured.includes(TOKEN));
  assert.match(renderSnykCard(snyk({ tokenConfigured: false }), false), /<dt>Token<\/dt><dd><span class="muted">Non configuré/);
  assert.match(renderSnykCard(snyk(), false), /data-snyk-token/);
});

test('aucun jeton ne peut atteindre le HTML de la page complète', () => {
  const html = renderScannerSetupHtml(MANAGED, 'nonce', 'light', {}, null, SONAR, { ...snyk(), token: TOKEN, apiToken: TOKEN });
  assert.ok(!html.includes(TOKEN));
});

test('les capacités sont rapportées séparément', () => {
  const html = renderSnykCard(snyk({ includeCode: true, includeIaC: true, capabilities: { openSource: true, code: false, iac: null } }), false);
  assert.match(html, /<dt>Open Source<\/dt><dd>Disponible<\/dd>/);
  assert.match(html, /<dt>Code<\/dt><dd>Indisponible pour ce compte\/configuration<\/dd>/);
  assert.match(html, /<dt>IaC<\/dt><dd><span class="muted">Non vérifié/);
  assert.match(renderSnykCard(snyk(), false), /<dt>Code<\/dt><dd><span class="muted">Non activé/);
});

// ------------------------------------------------------------- diagnostic

test('diagnostic : prêt quand tout est en place', () => {
  const diagnosis = snykDiagnosis(snyk());
  assert.equal(diagnosis.state, 'ready');
  assert.equal(diagnosis.label, 'Prêt');
});

test('diagnostic : désactivé', () => {
  assert.equal(snykDiagnosis(snyk({ enabled: false })).state, 'disabled');
  assert.equal(snykDiagnosis(snyk({ enabled: false })).label, 'Désactivé');
});

test('diagnostic : désactivé par la politique projet', () => {
  const diagnosis = snykDiagnosis(snyk({ blockedByProjectPolicy: true }));
  assert.equal(diagnosis.label, 'Désactivé par la politique projet');
  assert.match(diagnosis.hint, /security-center\.yml/);
});

test('diagnostic : activé mais jeton manquant', () => {
  const diagnosis = snykDiagnosis(snyk({ tokenConfigured: false }));
  assert.equal(diagnosis.state, 'missing');
  assert.equal(diagnosis.label, 'Token manquant');
});

test('diagnostic : jeton refusé', () => {
  assert.equal(snykDiagnosis(snyk({ authenticationValid: false })).label, 'Token refusé');
});

test('diagnostic : CLI absent en mode Local, Docker indisponible en mode Docker', () => {
  assert.equal(snykDiagnosis(snyk({ mode: 'local', cliVersion: '' })).label, 'CLI absent');
  assert.equal(snykDiagnosis(snyk({ mode: 'docker', dockerAvailable: false })).label, 'Docker indisponible');
  assert.equal(snykDiagnosis(snyk({ cliVersion: '', dockerAvailable: false })).label, 'CLI absent');
});

test('diagnostic : plusieurs manques sont résumés sans désactiver Snyk', () => {
  const diagnosis = snykDiagnosis(snyk({ tokenConfigured: false, cliVersion: '', dockerAvailable: false }));
  assert.equal(diagnosis.label, 'Activé — configuration incomplète');
  assert.match(diagnosis.hint, /CLI absent • Token manquant/);
});

test('diagnostic : prêt en Docker quand seul le CLI local manque', () => {
  const diagnosis = snykDiagnosis(snyk({ cliVersion: '' }));
  assert.equal(diagnosis.state, 'ready');
  assert.equal(diagnosis.label, 'Prêt — Docker');
});

// ------------------------------------------------- détails d’un résultat

test('un résultat SCA Snyk montre la chaîne de dépendance et le correctif', () => {
  const [finding] = snykFindings(OSS_PAYLOAD);
  const html = renderFindingDetailsHtml(finding, 'nonce');
  assert.match(html, /Dépendance vulnérable signalée par Snyk/);
  assert.match(html, /lodash/);
  assert.match(html, /4\.17\.21/);
  assert.match(html, /CVE-2020-8203/);
  assert.match(html, /CWE-1321/);
  assert.match(html, /Proof of Concept/);
  assert.ok(!html.includes('Preuve ZAP'), 'aucun champ dynamique ZAP pour un résultat SCA');
});

test('un résultat Snyk Code montre le flux de données', () => {
  const [finding] = snykFindings(CODE_PAYLOAD);
  const html = renderFindingDetailsHtml(finding, 'nonce');
  assert.match(html, /Résultat Snyk Code/);
  assert.match(html, /Flux de données/);
  assert.match(html, /routes\/search\.js:12/);
  assert.match(html, /CWE-89/);
});

test('un résultat Snyk IaC montre la ressource et la remédiation', () => {
  const [finding] = snykFindings(IAC_PAYLOAD);
  const html = renderFindingDetailsHtml(finding, 'nonce');
  assert.match(html, /Snyk IaC/);
  assert.match(html, /SNYK-CC-K8S-42/);
  assert.match(html, /spec\.privileged/);
  assert.match(html, /Retirer privileged/);
  assert.match(html, /<div class="label">Ligne<\/div><div>17<\/div>/);
});

test('un résultat SCA n’affiche jamais de fausse ligne', () => {
  const [finding] = snykFindings(OSS_PAYLOAD);
  const html = renderFindingDetailsHtml(finding, 'nonce');
  assert.match(html, /package-lock\.json/);
  assert.ok(!/<div class="label">Ligne<\/div><div>1<\/div>/.test(html));
});

// ------------------------------------------------------ dashboard et arbre

test('Snyk est présenté comme scanner du pipeline sur le dashboard', () => {
  const model = buildDashboardModel(snykFindings(OSS_PAYLOAD), [{ tool: 'Snyk', status: 'completed', details: '1 dépendance(s) • 0 code • 0 IaC' }]);
  const html = renderDashboardHtml(model, 'nonce');
  assert.match(html, /Snyk/);
  assert.match(html, /Dépendances, code et IaC/);
});

test('les résultats Snyk sont comptés par outil', () => {
  const findings = [...snykFindings(OSS_PAYLOAD), ...snykFindings(CODE_PAYLOAD)];
  assert.match(summarizeFindings(findings), /Snyk: 2/);
  const groups = groupFindings(findings, [{ tool: 'Snyk', status: 'completed' }]);
  const snykGroup = groups.find((group) => group.label === 'Snyk');
  assert.equal(snykGroup.count, 2);
});

test('Snyk apparaît dans l’arbre même sans résultat', () => {
  const groups = groupFindings([], [{ tool: 'Snyk', status: 'completed' }]);
  assert.ok(groups.some((group) => group.label === 'Snyk'));
});

// ------------------------------------------------- TreeView et Problems

test('un résultat Snyk Code localisé peut aller dans Problems', () => {
  const [finding] = snykFindings(CODE_PAYLOAD);
  assert.equal(hasReportableLocation(finding), true);
  assert.equal(finding.startLine, 41);
});

test('un résultat Snyk IaC localisé peut aller dans Problems', () => {
  const [finding] = snykFindings(IAC_PAYLOAD);
  assert.equal(hasReportableLocation(finding), true);
});

test('un résultat Snyk Open Source ne crée jamais d’entrée Problems', () => {
  const [finding] = snykFindings(OSS_PAYLOAD);
  assert.equal(hasReportableLocation(finding), false);
  // Le manifeste reste connu pour que le clic puisse l’ouvrir.
  assert.ok(finding.absolutePath.endsWith('package-lock.json'));
});

test('un résultat Snyk Code sans localisation ne crée pas d’entrée Problems', () => {
  const [finding] = snykFindings({ code: { sarif: { runs: [{ tool: { driver: { rules: [] } }, results: [{ ruleId: 'x', message: { text: 'y' } }] }] } } });
  assert.equal(hasReportableLocation(finding), false);
});

test('les résultats existants gardent leur comportement Problems', () => {
  assert.equal(hasReportableLocation({ absolutePath: '/repo/a.js', startLine: 3 }), true);
  assert.equal(hasReportableLocation({ absolutePath: '' }), false);
  assert.equal(hasReportableLocation({ absolutePath: '/repo/a.js', unlocated: true }), false);
});

test('les résultats Snyk sont catégorisés par capacité dans les comparaisons', () => {
  const [oss] = snykFindings(OSS_PAYLOAD);
  const [code] = snykFindings(CODE_PAYLOAD);
  const [iac] = snykFindings(IAC_PAYLOAD);
  const scanners = [{ tool: 'Snyk', status: 'completed' }];
  const comparison = compareScans(
    { result: { scanners, findings: [] } },
    { result: { scanners, findings: [oss, code, iac] } }
  );
  assert.equal(comparison.added.length, 3);
  const html = renderScanComparisonHtml(comparison, 'nonce');
  assert.match(html, /Dependencies/);
  assert.match(html, /IaC \/ Cloud/);
});

test('Snyk conserve sa place dans le snapshot et l’historique', () => {
  const snapshot = snapshotFromLegacy(snykFindings(OSS_PAYLOAD), [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'Snyk', status: 'completed', details: '1 dépendance(s) • 0 code • 0 IaC' }
  ]);
  const projection = projectSnapshot(snapshot);
  const tools = projection.scanners.map((scanner) => scanner.tool);
  assert.ok(tools.includes('Snyk'));
  assert.ok(tools.indexOf('Snyk') > tools.indexOf('Semgrep'));
  assert.equal(projection.findings.filter((finding) => finding.tool === 'Snyk').length, 1);
});
