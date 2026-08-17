const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const {
  normalizeSnykOutput, normalizeSnykOpenSource, normalizeSnykCode, normalizeSnykIaC,
  snykSeverity, snykDependencyPath, snykOpenSourceFingerprint, deduplicateFindings
} = require('../src/findings');
const { toSarif } = require('../src/sarif');

const WORKSPACE = path.resolve('/repo');

function openSourceProject(vulnerabilities, overrides = {}) {
  return {
    ok: false,
    packageManager: 'npm',
    projectName: 'juice-shop',
    displayTargetFile: 'package-lock.json',
    vulnerabilities,
    ...overrides
  };
}

function vulnerability(overrides = {}) {
  return {
    id: 'SNYK-JS-LODASH-567746',
    title: 'Prototype Pollution',
    severity: 'high',
    packageName: 'lodash',
    version: '4.17.11',
    packageManager: 'npm',
    from: ['juice-shop@1.0.0', 'express@4.17.1', 'lodash@4.17.11'],
    upgradePath: [false, 'express@4.18.0', 'lodash@4.17.21'],
    isUpgradable: true,
    isPatchable: false,
    identifiers: { CVE: ['CVE-2020-8203'], CWE: ['CWE-1321'] },
    cvssScore: 7.4,
    CVSSv3: 'CVSS:3.1/AV:N/AC:H',
    fixedIn: ['4.17.21'],
    exploit: 'Proof of Concept',
    description: 'Les versions affectées sont vulnérables à la pollution de prototype.',
    references: [{ url: 'https://security.snyk.io/vuln/SNYK-JS-LODASH-567746' }],
    ...overrides
  };
}

const CODE_SARIF = {
  runs: [{
    tool: {
      driver: {
        name: 'SnykCode',
        rules: [{
          id: 'javascript/Sqli',
          shortDescription: { text: 'SQL Injection' },
          defaultConfiguration: { level: 'error' },
          help: { text: 'Une entrée non fiable atteint une requête SQL.' },
          properties: { cwe: ['CWE-89'], tags: ['javascript', 'security'] }
        }]
      }
    },
    results: [{
      ruleId: 'javascript/Sqli',
      level: 'error',
      message: { text: 'Entrée non assainie utilisée dans une requête SQL.' },
      fingerprints: { '0': 'abc', 'snyk/assets/finding/v1': 'stable-identity-1' },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: 'routes/search.js' },
          region: { startLine: 42, startColumn: 9, endLine: 42, endColumn: 40 }
        }
      }],
      codeFlows: [{
        threadFlows: [{
          locations: [
            { location: { physicalLocation: { artifactLocation: { uri: 'routes/search.js' }, region: { startLine: 12 } } } },
            { location: { physicalLocation: { artifactLocation: { uri: 'routes/search.js' }, region: { startLine: 42 } } } }
          ]
        }]
      }],
      properties: { priorityScore: 850, isAutofixable: true }
    }]
  }]
};

const IAC_RESULT = [{
  targetFile: 'deploy/k8s.yaml',
  projectName: 'infra',
  infrastructureAsCodeIssues: [{
    id: 'SNYK-CC-K8S-42',
    publicId: 'SNYK-CC-K8S-42',
    title: 'Conteneur exécuté en mode privilégié',
    severity: 'high',
    lineNumber: 17,
    subType: 'Deployment',
    path: ['spec', 'template', 'spec', 'containers[0]', 'securityContext', 'privileged'],
    documentation: 'https://security.snyk.io/rules/cloud/SNYK-CC-K8S-42',
    iacDescription: {
      issue: 'Le conteneur demande le mode privilégié.',
      impact: 'Un conteneur privilégié peut accéder aux périphériques de l’hôte.',
      resolve: 'Retirer securityContext.privileged ou le mettre à false.'
    }
  }]
}];

// ------------------------------------------------------------ Snyk Open Source

test('normalise une vulnérabilité de dépendance simple', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.equal(finding.tool, 'Snyk');
  assert.equal(finding.category, 'dependency');
  assert.equal(finding.snykCapability, 'openSource');
  assert.equal(finding.ruleId, 'SNYK-JS-LODASH-567746');
  assert.equal(finding.packageName, 'lodash');
  assert.equal(finding.installedVersion, '4.17.11');
  assert.equal(finding.fixedVersion, '4.17.21');
  assert.equal(finding.packageManager, 'npm');
  assert.equal(finding.projectName, 'juice-shop');
  assert.equal(finding.file, 'package-lock.json');
  assert.equal(finding.absolutePath, path.resolve(WORKSPACE, 'package-lock.json'));
});

test('conserve CVE, CWE, CVSS et maturité d’exploitation', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.equal(finding.cwe, 'CWE-1321');
  assert.ok(finding.vulnerabilityAliases.includes('CVE-2020-8203'));
  assert.ok(finding.vulnerabilityAliases.includes('SNYK-JS-LODASH-567746'));
  assert.equal(finding.cvssScore, 7.4);
  assert.equal(finding.cvssVector, 'CVSS:3.1/AV:N/AC:H');
  assert.equal(finding.exploitMaturity, 'Proof of Concept');
  assert.match(finding.title, /CVE-2020-8203/);
});

test('conserve le chemin de dépendance sans le projet racine', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.deepEqual(finding.dependencyPath, ['express@4.17.1', 'lodash@4.17.11']);
  assert.deepEqual(snykDependencyPath(['racine@1.0.0']), ['racine@1.0.0']);
  assert.deepEqual(snykDependencyPath(undefined), []);
});

test('conserve le chemin de mise à niveau en ignorant les entrées non applicables', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.deepEqual(finding.upgradePath, ['express@4.18.0', 'lodash@4.17.21']);
  assert.equal(finding.isUpgradable, true);
  assert.equal(finding.isPatchable, false);
});

test('gère plusieurs vulnérabilités et plusieurs projets --all-projects', () => {
  const findings = normalizeSnykOpenSource([
    openSourceProject([vulnerability(), vulnerability({ id: 'SNYK-JS-MINIMIST-1', packageName: 'minimist', version: '1.2.0' })]),
    openSourceProject([vulnerability({ id: 'SNYK-PYTHON-FLASK-1', packageName: 'flask', version: '1.0' })], {
      displayTargetFile: 'api/requirements.txt', packageManager: 'pip'
    })
  ], WORKSPACE);
  assert.equal(findings.length, 3);
  assert.deepEqual([...new Set(findings.map((finding) => finding.file))], ['package-lock.json', 'api/requirements.txt']);
});

test('sans correctif publié, aucune version corrigée n’est inventée', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability({ fixedIn: [], nearestFixedInVersion: '' })]), WORKSPACE);
  assert.equal(finding.fixedVersion, '');
  assert.ok(!finding.title.includes('→'));
});

test('un résultat SCA reste non localisé plutôt que d’inventer une ligne', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.equal(finding.unlocated, true);
  assert.equal(finding.startLine, 0);
  assert.ok(finding.absolutePath, 'le manifeste reste ouvrable depuis les détails');
});

// ------------------------------------------------------------------ empreinte

test('l’empreinte SCA repose sur package, version, vulnérabilité et manifeste', () => {
  const [finding] = normalizeSnykOpenSource(openSourceProject([vulnerability()]), WORKSPACE);
  assert.equal(finding.fingerprint, snykOpenSourceFingerprint({
    manifest: 'package-lock.json', vulnerabilityId: 'SNYK-JS-LODASH-567746', packageName: 'lodash', version: '4.17.11'
  }));
  assert.ok(!finding.fingerprint.includes(':0:'), 'aucune ligne dans l’empreinte');
});

test('la même vulnérabilité dans deux manifestes reste distincte', () => {
  const findings = normalizeSnykOpenSource([
    openSourceProject([vulnerability()]),
    openSourceProject([vulnerability()], { displayTargetFile: 'ui/package-lock.json' })
  ], WORKSPACE);
  assert.equal(findings.length, 2);
  assert.notEqual(findings[0].fingerprint, findings[1].fingerprint);
});

test('un doublon exact est fusionné même sans numéro de ligne', () => {
  const findings = normalizeSnykOpenSource([openSourceProject([vulnerability(), vulnerability()])], WORKSPACE);
  assert.equal(findings.length, 1);
});

// ------------------------------------------------------------------ Snyk Code

test('normalise un résultat Snyk Code localisé', () => {
  const [finding] = normalizeSnykCode(CODE_SARIF, WORKSPACE);
  assert.equal(finding.tool, 'Snyk');
  assert.equal(finding.snykCapability, 'code');
  assert.equal(finding.ruleId, 'javascript/Sqli');
  assert.equal(finding.file, 'routes/search.js');
  assert.equal(finding.startLine, 41);
  assert.equal(finding.startColumn, 8);
  assert.equal(finding.unlocated, false);
  assert.equal(finding.rawSeverity, 'HIGH');
  assert.equal(finding.cwe, 'CWE-89');
  assert.equal(finding.priorityScore, 850);
});

test('conserve le flux de données source → sink', () => {
  const [finding] = normalizeSnykCode(CODE_SARIF, WORKSPACE);
  assert.equal(finding.dataFlow.length, 2);
  assert.equal(finding.dataFlowSource.line, 12);
  assert.equal(finding.dataFlowSink.line, 42);
});

test('privilégie l’identité stable fournie par Snyk pour l’empreinte', () => {
  const [finding] = normalizeSnykCode(CODE_SARIF, WORKSPACE);
  assert.equal(finding.fingerprint, 'snyk:code:stable-identity-1');
  const moved = JSON.parse(JSON.stringify(CODE_SARIF));
  moved.runs[0].results[0].locations[0].physicalLocation.region.startLine = 99;
  assert.equal(normalizeSnykCode(moved, WORKSPACE)[0].fingerprint, finding.fingerprint);
});

test('un résultat Snyk Code sans localisation reste exploitable', () => {
  const [finding] = normalizeSnykCode({
    runs: [{ tool: { driver: { rules: [] } }, results: [{ ruleId: 'js/Generic', level: 'warning', message: { text: 'Problème global' } }] }]
  }, WORKSPACE);
  assert.equal(finding.unlocated, true);
  assert.equal(finding.absolutePath, '');
  assert.equal(finding.rawSeverity, 'MEDIUM');
  assert.equal(finding.title, 'Problème global');
});

test('une capacité indisponible ne produit aucun résultat sans planter', () => {
  assert.deepEqual(normalizeSnykCode(null, WORKSPACE), []);
  assert.deepEqual(normalizeSnykCode({ runs: [] }, WORKSPACE), []);
  assert.deepEqual(normalizeSnykIaC([], WORKSPACE), []);
});

// ------------------------------------------------------------------- Snyk IaC

test('normalise une mauvaise configuration IaC', () => {
  const [finding] = normalizeSnykIaC(IAC_RESULT, WORKSPACE);
  assert.equal(finding.tool, 'Snyk');
  assert.equal(finding.category, 'misconfiguration');
  assert.equal(finding.snykCapability, 'iac');
  assert.equal(finding.ruleId, 'SNYK-CC-K8S-42');
  assert.equal(finding.policyId, 'SNYK-CC-K8S-42');
  assert.equal(finding.file, 'deploy/k8s.yaml');
  assert.equal(finding.startLine, 16);
  assert.equal(finding.unlocated, false);
  assert.equal(finding.resource, 'spec.template.spec.containers[0].securityContext.privileged');
  assert.equal(finding.resourceType, 'Deployment');
  assert.match(finding.solution, /privileged/);
  assert.match(finding.impact, /périphériques/);
});

test('ignore les résultats IaC explicitement ignorés dans Snyk', () => {
  const ignored = JSON.parse(JSON.stringify(IAC_RESULT));
  ignored[0].infrastructureAsCodeIssues[0].isIgnored = true;
  assert.deepEqual(normalizeSnykIaC(ignored, WORKSPACE), []);
});

// ------------------------------------------------------------------ sévérités

test('applique le barème Snyk au barème Security Center', () => {
  assert.equal(snykSeverity('critical'), 'CRITICAL');
  assert.equal(snykSeverity('HIGH'), 'HIGH');
  assert.equal(snykSeverity('medium'), 'MEDIUM');
  assert.equal(snykSeverity('low'), 'LOW');
  assert.equal(snykSeverity('inconnu'), 'MEDIUM');
  const [critical] = normalizeSnykOpenSource(openSourceProject([vulnerability({ severity: 'critical' })]), WORKSPACE);
  assert.equal(critical.rawSeverity, 'CRITICAL');
  assert.equal(critical.severity, 'error');
  const [low] = normalizeSnykOpenSource(openSourceProject([vulnerability({ severity: 'low' })]), WORKSPACE);
  assert.equal(low.severity, 'information');
});

// --------------------------------------------------------- pipeline et SARIF

test('normalizeSnykOutput agrège les trois capacités dans un seul modèle', () => {
  const findings = normalizeSnykOutput({
    openSource: { results: [openSourceProject([vulnerability()])] },
    code: { sarif: CODE_SARIF },
    iac: { results: IAC_RESULT }
  }, WORKSPACE);
  assert.equal(findings.length, 3);
  assert.deepEqual(findings.map((finding) => finding.snykCapability), ['openSource', 'code', 'iac']);
  assert.ok(findings.every((finding) => finding.tool === 'Snyk' && finding.fingerprint && finding.id));
});

test('un payload Snyk vide ne produit aucun résultat', () => {
  assert.deepEqual(normalizeSnykOutput({}, WORKSPACE), []);
  assert.deepEqual(normalizeSnykOutput(null, WORKSPACE), []);
});

test('les résultats Snyk traversent la déduplication commune du pipeline', () => {
  const findings = normalizeSnykOutput({ openSource: { results: [openSourceProject([vulnerability()])] } }, WORKSPACE);
  assert.equal(deduplicateFindings([...findings, ...findings]).length, 1);
});

test('les résultats Snyk alimentent le SARIF commun', () => {
  const findings = normalizeSnykOutput({
    openSource: { results: [openSourceProject([vulnerability()])] },
    code: { sarif: CODE_SARIF }
  }, WORKSPACE);
  const sarif = toSarif({ findings });
  assert.equal(sarif.runs[0].results.length, 2);
  assert.ok(sarif.runs[0].results.every((result) => result.properties.scanner === 'Snyk'));
  assert.ok(sarif.runs[0].tool.driver.rules.every((rule) => rule.id.startsWith('snyk/')));
  assert.equal(sarif.runs[0].results[0].partialFingerprints.securityCenterFingerprint, findings[0].fingerprint);
});
