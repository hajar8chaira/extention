'use strict';

/**
 * Consommation automatique du CI Engine par Jenkins (cas F à K).
 *
 * Le vrai CLI (`main`) est exécuté : politique projet, Policy Gate, verdict,
 * rapport CI. Seules l'exécution des scanners et la génération des preuves
 * supply chain sont simulées. Security Delivery est lu depuis les artefacts
 * archivés, comme en production.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { evaluatePolicy } = require('../src/project-policy');

const orchestratorPath = require.resolve('../src/orchestrator');
const orchestrator = require('../src/orchestrator');
let run = { findings: [], scanners: [], failures: [] };
let captured = null;
require.cache[orchestratorPath].exports = {
  ...orchestrator,
  runSecurityScan: async (input) => {
    captured = input;
    return {
      workspace: input.workspacePath, correlations: [], finishedAt: new Date().toISOString(),
      ...run, policyResult: evaluatePolicy(run.findings, input.policy)
    };
  }
};
const pipelinePath = require.resolve('../src/pipeline');
const realPipeline = require('../src/pipeline');
let supplyChain = async () => ({});
require.cache[pipelinePath].exports = { ...realPipeline, runSupplyChainStages: (args) => supplyChain(args) };

const { main } = require('../src/cli');
const { validateCiReport, validateDeliveryRecord } = require('../src/ci-report');
const { fetchDeliveryStatus } = require('../src/jenkins');
const { toDeliveryModel } = require('../src/integrations/delivery-jenkins');
const { renderDeliverySections } = require('../src/delivery-provider-view');
const { CAPABILITY, RESOLVED_STATE } = require('../src/integrations/delivery-contract');
const { version: ENGINE_VERSION } = require('../package.json');

const JENKINSFILE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
/** The executable part of the pipeline: comment lines (Groovy and shell) removed. */
const JENKINSFILE_CODE = JENKINSFILE.split('\n').filter((line) => !/^\s*(\/\/|#)/.test(line)).join('\n');

const PROJECT_YAML = `version: 1
scanners:
  semgrep: true
  gitleaks: true
  trivy: true
  osv: true
  sonarqube: false
  snyk: false
  zap: false
policy:
  include_tests: false
gate:
  fail_on_severity: [CRITICAL]
  warn_on_severity: [HIGH]
  block_secrets: true
  require_sbom: true
supply_chain:
  require_provenance: true
`;

const COMPLETED = [
  { tool: 'Semgrep', status: 'completed' }, { tool: 'Gitleaks', status: 'completed' },
  { tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }
];
const finding = (severity) => ({
  id: `sg:${severity}`, tool: 'Semgrep', ruleId: `rule-${severity.toLowerCase()}`, rawSeverity: severity,
  severity: 'error', title: `Résultat ${severity}`, file: 'routes/login.ts', startLine: 4, stage: 'sast'
});

/** Real SBOM and provenance files, as the supply-chain stages would produce them. */
const producedEvidence = ({ workspacePath }) => {
  const sbom = path.join(workspacePath, 'security-center', 'sbom.cdx.json');
  fs.mkdirSync(path.dirname(sbom), { recursive: true });
  fs.writeFileSync(sbom, '{"bomFormat":"CycloneDX"}');
  fs.writeFileSync(`${sbom}.provenance.json`, '{"_type":"https://in-toto.io/Statement/v1"}');
  return { sbom: { status: 'generated', path: sbom }, provenance: { status: 'generated', path: `${sbom}.provenance.json` } };
};
const failedEvidence = async () => ({
  sbom: { status: 'failed', reason: 'Trivy indisponible pour générer le SBOM' },
  provenance: { status: 'failed', reason: 'Aucun artefact à attester : générez un SBOM ou indiquez un fichier.' }
});

async function scan(t, { yml = PROJECT_YAML, findings = [], scanners = COMPLETED, failures = [], evidence = producedEvidence, args = [] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-jenkins-engine-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'security-center.yml'), yml);
  run = { findings, scanners, failures };
  supplyChain = async (input) => evidence(input);
  captured = null;
  const original = process.stderr.write;
  process.stderr.write = () => true;
  let exitCode;
  // The exact command of the Jenkinsfile: no --tools, no --fail-on.
  try {
    exitCode = await main(['scan', '--workspace', root, '--format', 'json', '--output', path.join(root, 'security-center-full-report.json'),
      '--ci-report', path.join(root, 'security-center-report.json'), '--sbom', '--provenance', ...args]);
  } finally {
    process.stderr.write = original;
  }
  const text = fs.readFileSync(path.join(root, 'security-center-report.json'), 'utf8');
  return { root, exitCode, text, ci: JSON.parse(text) };
}

const deployAllowed = (exitCode) => String(exitCode) === '0';

// ------------------------------------------------------------ F

test('F — le CLI prend la sélection de scanners dans security-center.yml, sans --tools', async (t) => {
  const { exitCode } = await scan(t);
  assert.equal(exitCode, 0);
  assert.deepEqual(captured.options.selectedTools, []);
  assert.equal(captured.options.sonarEnabled, false);
  assert.equal(captured.options.snykEnabled, false);
  const tools = orchestrator.buildScans(captured.workspacePath, captured.policy, orchestrator.defaultOptions(captured.options)).map((item) => item.tool);
  assert.deepEqual(tools, ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner'], 'ZAP désactivé par le YAML, SonarQube et Snyk non activés');

  // SonarQube activé dans le YAML : exécuté sans que Jenkins le demande.
  const withSonar = await scan(t, { yml: PROJECT_YAML.replace('sonarqube: false', 'sonarqube: true') });
  assert.equal(withSonar.exitCode, 0);
  assert.equal(captured.options.sonarEnabled, true);
  assert.ok(orchestrator.buildScans(captured.workspacePath, captured.policy, orchestrator.defaultOptions(captured.options)).some((item) => item.tool === 'SonarQube'));

  // Le pipeline ne duplique aucun choix de sécurité.
  const command = JENKINSFILE.slice(JENKINSFILE.indexOf('security-center scan'), JENKINSFILE.indexOf("'''", JENKINSFILE.indexOf('security-center scan')));
  assert.doesNotMatch(command, /--tools|--fail-on/);
  assert.doesNotMatch(JENKINSFILE_CODE, /fail_on_severity|block_secrets|require_sbom|require_provenance|SC_TOOLS/);
  for (const flag of ['--workspace "$WORKSPACE"', '--format json', '--output security-center-full-report.json', '--ci-report security-center-report.json', '--sbom', '--provenance']) {
    assert.ok(command.includes(flag), flag);
  }
});

// ------------------------------------------------------------ G / H / I

test('G — finding CRITICAL : BLOCK, sortie 1, déploiement ignoré', async (t) => {
  const { exitCode, ci } = await scan(t, { findings: [finding('CRITICAL')] });
  assert.equal(exitCode, 1);
  assert.deepEqual(ci.verdict, { status: 'BLOCK', exitCode: 1 });
  assert.equal(ci.policy.status, 'BLOCK');
  assert.equal(deployAllowed(exitCode), false);
  assert.match(JENKINSFILE, /if \(env\.SC_EXIT == '1'\) \{[\s\S]*?Policy Gate BLOCK[\s\S]*?error\(/);
});

test('H — scanner en échec : ERROR, sortie 2, déploiement ignoré', async (t) => {
  const { exitCode, ci } = await scan(t, {
    findings: [finding('CRITICAL')],
    scanners: [...COMPLETED.slice(0, 3), { tool: 'OSV-Scanner', status: 'failed', details: 'osv-scanner introuvable' }],
    failures: ['OSV-Scanner: osv-scanner introuvable']
  });
  assert.equal(exitCode, 2);
  assert.deepEqual(ci.verdict, { status: 'ERROR', exitCode: 2 });
  assert.equal(ci.execution.status, 'partial');
  assert.equal(deployAllowed(exitCode), false);
  // Tout code hors contrat devient ERROR côté Jenkins.
  assert.match(JENKINSFILE, /env\.SC_EXIT = \(status in \[0, 1, 2\]\) \? status\.toString\(\) : '2'/);
});

test('I — analyse propre : PASS, sortie 0, déploiement autorisé', async (t) => {
  const { exitCode, ci } = await scan(t);
  assert.equal(exitCode, 0);
  assert.deepEqual(ci.verdict, { status: 'PASS', exitCode: 0 });
  assert.equal(ci.policy.status, 'PASS');
  assert.equal(ci.supplyChain.sbom, 'generated');
  assert.equal(ci.supplyChain.sbomPath, 'security-center/sbom.cdx.json');
  assert.equal(ci.supplyChain.provenancePath, 'security-center/sbom.cdx.json.provenance.json');
  assert.equal(deployAllowed(exitCode), true);
  assert.match(JENKINSFILE, /stage\('Deploy'\) \{[\s\S]*?allOf \{[\s\S]*?env\.SC_EXIT == '0'[\s\S]*?currentBuild\.currentResult == 'SUCCESS'/);
});

// ------------------------------------------------------------ J

test('J — SBOM et provenance exigés mais absents : jamais PASS', async (t) => {
  const { exitCode, ci } = await scan(t, { evidence: failedEvidence });
  assert.notEqual(exitCode, 0);
  assert.notEqual(ci.verdict.status, 'PASS');
  assert.equal(ci.verdict.status, 'BLOCK');
  assert.ok(ci.policy.reasons.some((reason) => reason.code === 'artifact-missing'));
  assert.equal(ci.supplyChain.sbom, 'failed');
  assert.equal(ci.supplyChain.sbomPath, null);
  assert.equal(deployAllowed(exitCode), false);
});

test('J — une preuve déclarée produite mais absente du disque est rapportée « missing »', async (t) => {
  const { ci } = await scan(t, {
    evidence: ({ workspacePath }) => ({
      sbom: { status: 'generated', path: path.join(workspacePath, 'security-center', 'sbom.cdx.json') },
      provenance: { status: 'generated', path: path.join(workspacePath, 'security-center', 'sbom.cdx.json.provenance.json') }
    })
  });
  assert.equal(ci.supplyChain.sbom, 'missing');
  assert.equal(ci.supplyChain.provenance, 'missing');
  // Et le pipeline vérifie encore les preuves déclarées avant de déployer.
  assert.match(JENKINSFILE, /stage\('Supply chain evidence'\)[\s\S]*?fs\.existsSync\(file\)[\s\S]*?process\.exit\(1\)/);
});

// ------------------------------------------------------------ K

function jenkinsBuild(artifacts) {
  return {
    number: 42, result: 'SUCCESS', building: false, timestamp: 1789000000000, duration: 61000,
    url: 'http://jenkins.local/job/security-pipeline/42/', displayName: '#42',
    actions: [{ lastBuiltRevision: { SHA1: 'ee60a1d11aa1b2c3d4e5f60718293a4b5c6d7e8f', branch: [{ name: 'refs/remotes/origin/master', SHA1: 'ee60a1d11aa1b2c3d4e5f60718293a4b5c6d7e8f' }] } }],
    artifacts: artifacts.map((relativePath) => ({ fileName: path.basename(relativePath), relativePath }))
  };
}

async function delivery(files) {
  const status = await fetchDeliveryStatus({
    baseUrl: 'http://jenkins.local', job: 'security-pipeline',
    request: async () => jenkinsBuild(Object.keys(files)),
    requestText: async (url) => {
      const match = Object.keys(files).find((relativePath) => url.endsWith(`/artifact/${relativePath}`));
      if (!match) throw new Error(`unexpected artefact ${url}`);
      return files[match];
    }
  });
  return toDeliveryModel(status, { url: 'http://jenkins.local', job: 'security-pipeline' });
}

test('K — Security Delivery lit rapport, étapes, verdict, moteur, preuves, déploiement et health check', async (t) => {
  const { text } = await scan(t);
  const record = JSON.stringify({
    schemaVersion: 1, verdict: 'PASS', exitCode: 0, engineReady: true,
    deployment: { status: 'SUCCEEDED', reason: 'Déployé après PASS du Policy Gate.' },
    healthCheck: { status: 'PASSED', detail: 'Application joignable après déploiement.' }
  });
  const model = await delivery({
    'security-center-report.json': text,
    'security-center-delivery.json': record,
    'security-center/sbom.cdx.json': '{}',
    'security-center/sbom.cdx.json.provenance.json': '{}'
  });
  const report = model.securityReport;
  assert.equal(report.reported, true);
  assert.deepEqual(report.verdict, { status: 'PASS', exitCode: 0 });
  assert.equal(report.ciEngine.label, 'CI Engine: Installed');
  assert.equal(report.ciEngine.version, ENGINE_VERSION);
  assert.equal(report.supplyChain.sbom, 'generated');
  assert.equal(report.supplyChain.provenancePath, 'security-center/sbom.cdx.json.provenance.json');
  assert.equal(model.run.commit, 'ee60a1d11aa1b2c3d4e5f60718293a4b5c6d7e8f');
  assert.equal(model.run.branch, 'master');
  assert.equal(model.capabilities[CAPABILITY.STAGES].state, RESOLVED_STATE.READY);
  assert.ok(model.stages.some((stage) => stage.name === 'Security Center · Policy Gate'));
  assert.equal(model.capabilities[CAPABILITY.DEPLOYMENT_STATUS].state, RESOLVED_STATE.READY);
  assert.equal(model.deployment.status, 'SUCCEEDED');
  assert.equal(model.deployment.healthCheck.status, 'PASSED');
  assert.ok(model.artifacts.some((artifact) => artifact.path === 'security-center/sbom.cdx.json'));
  const html = renderDeliverySections(model);
  for (const label of ['Verdict CI', 'CI Engine', 'Déploiement', 'Health check']) assert.ok(html.includes(label), label);

  // Le pipeline archive tout ce que Security Delivery lit.
  for (const pattern of ['security-center-report.json', 'security-center-full-report.json', 'security-center/*.cdx.json', 'security-center/*.provenance.json', '**/*.sigstore.json', 'security-center-delivery.json']) {
    assert.ok(JENNKINSFILE_ARCHIVES().includes(pattern), `archivé : ${pattern}`);
  }
});

function JENNKINSFILE_ARCHIVES() {
  return [...JENKINSFILE.matchAll(/archiveArtifacts artifacts: '([^']+)'/g)].flatMap((match) => match[1].split(',').map((item) => item.trim()));
}

test('K — bootstrap en échec : Security Delivery montre ERROR, moteur non détecté, déploiement ignoré', async () => {
  const failure = JSON.stringify({
    schemaVersion: 1, generatedAt: '2026-09-13T06:00:00Z', verdict: { status: 'ERROR', exitCode: 2 }, engine: null,
    execution: { scanId: '', status: 'engine_unavailable', failedScanners: [], error: 'checksum mismatch for https://artifacts.local/engine.tgz' },
    stages: null, repository: { commit: null, branch: null },
    policy: { status: 'NOT_EVALUATED', configured: false, blockingCount: 0, warningCount: 0, summary: '', reasons: [], legacyNotice: '' },
    scanners: []
  });
  const record = JSON.stringify({
    schemaVersion: 1, verdict: 'ERROR', exitCode: 2, engineReady: false,
    deployment: { status: 'SKIPPED', reason: 'CI Engine indisponible : bootstrap en échec.' },
    healthCheck: { status: 'SKIPPED', detail: 'Aucun déploiement.' }
  });
  const model = await delivery({ 'security-center-report.json': failure, 'security-center-delivery.json': record });
  assert.deepEqual(model.securityReport.verdict, { status: 'ERROR', exitCode: 2 });
  assert.equal(model.securityReport.ciEngine.label, 'CI Engine: Not detected');
  assert.match(model.securityReport.ciEngine.reason, /checksum mismatch/);
  assert.equal(model.deployment.status, 'SKIPPED');
  assert.equal(model.stages.length, 0, 'aucune étape inventée');
});

test('K — un enregistrement de livraison inconnu ou absent n’est jamais présenté comme un succès', async (t) => {
  assert.equal(validateDeliveryRecord(JSON.stringify({ schemaVersion: 1, deployment: { status: 'DONE' } })).ok, false);
  assert.equal(validateDeliveryRecord('{').ok, false);
  const partial = validateDeliveryRecord(JSON.stringify({ schemaVersion: 1, deployment: { status: 'NOT_CONFIGURED', reason: 'x' }, healthCheck: { status: 'MAYBE' } }));
  assert.equal(partial.record.healthCheck, null);
  const { text } = await scan(t);
  const model = await delivery({ 'security-center-report.json': text });
  assert.equal(model.capabilities[CAPABILITY.DEPLOYMENT_STATUS].state, RESOLVED_STATE.NOT_REPORTED);
  assert.equal(model.deployment, null);
  assert.equal(validateCiReport(text).ok, true);
});

// ------------------------------------------------------------ flux

test('le pipeline suit exactement le flux attendu', () => {
  const stages = [...JENKINSFILE.matchAll(/stage\('([^']+)'\)/g)].map((match) => match[1]);
  assert.deepEqual(stages, ['Checkout', 'Security Center CI Runtime', 'Prepare CI Runtime workspace', 'Bootstrap Security Center CI Engine', 'Security Center Analysis', 'Policy Gate', 'Supply chain evidence', 'Deploy', 'Health Check']);
  assert.match(JENKINSFILE, /PATH = "\/var\/jenkins_home\/tools\/node22\/bin:\$\{env\.PATH\}"/);
  // Le moteur vient du home Security Center résolu comme par le bootstrap, jamais
  // d'un ancien emplacement forcé que l'utilisateur Jenkins ne peut pas écrire.
  assert.doesNotMatch(JENKINSFILE, /SCENTER_TOOLS_DIR = '|tools\/security-center\/bin/);
  assert.match(JENKINSFILE, /def scenterHome = env\.SCENTER_HOME \?: "\$\{env\.JENKINS_HOME \?: '\/var\/jenkins_home'\}\/\.security-center"/);
  assert.match(JENKINSFILE, /def enginePrefix = env\.SCENTER_ENGINE_PREFIX \?: \(env\.SCENTER_HOME \? "\$\{scenterHome\}\/engine" : \(env\.SCENTER_TOOLS_DIR \? "\$\{env\.SCENTER_TOOLS_DIR\}\/security-center" : "\$\{scenterHome\}\/engine"\)\)/);
  assert.match(JENKINSFILE, /withEnv\(\["PATH\+SCENTER_ENGINE=\$\{env\.SC_ENGINE_BIN\}", "PATH\+SCENTER_NODE=\$\{env\.SC_NODE_BIN\}"\]\) \{\s*\/\/[^\n]*\n[^\n]*\n\s*def status = sh\(\s*returnStatus: true,\s*label: 'Security Center Analysis'/);
  assert.match(JENKINSFILE, /triggers \{\s*pollSCM\('H\/2 \* \* \* \*'\)\s*\}/);
  assert.match(JENKINSFILE, /git\(repository\)/);
  assert.doesNotMatch(JENKINSFILE_CODE, /vscode-extension|npm pack|docker exec/);
  assert.match(JENKINSFILE, /stage\('Health Check'\) \{\s*when \{\s*expression \{ env\.SC_DEPLOY_STATUS == 'SUCCEEDED' \}/);
});
