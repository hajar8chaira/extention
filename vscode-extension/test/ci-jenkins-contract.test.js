'use strict';

/**
 * Contrat Jenkins / rapport CI : verdict 0/1/2, étapes Security Center réelles,
 * preuves supply chain adossées à de vrais fichiers, credentials optionnels.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { verdictOf, withoutSignatureRequirement, gateArtifactsFrom } = require('../src/cli');
const { buildCiReport, validateCiReport, archivedPath } = require('../src/ci-report');
const { evaluatePolicyGate } = require('../src/intelligence/policy-gate');
const { toDeliveryModel } = require('../src/integrations/delivery-jenkins');
const { CAPABILITY, RESOLVED_STATE, RUN_OUTCOME } = require('../src/integrations/delivery-contract');

const template = () => fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');

function tempWorkspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ci-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), content);
  }
  return root;
}

// ---------------------------------------------------------------- verdict

test('verdict : 0 = PASS, 1 = BLOCK, 2 = ERROR', () => {
  assert.deepEqual(verdictOf({ policyGate: { status: 'PASS' }, failures: [] }), { status: 'PASS', exitCode: 0 });
  assert.deepEqual(verdictOf({ policyGate: { status: 'WARN' }, failures: [] }), { status: 'PASS', exitCode: 0 });
  assert.deepEqual(verdictOf({ policyGate: { status: 'NOT_CONFIGURED' }, failures: [] }), { status: 'PASS', exitCode: 0 });
  assert.deepEqual(verdictOf({ policyGate: { status: 'BLOCK' }, failures: [] }), { status: 'BLOCK', exitCode: 1 });
  assert.deepEqual(verdictOf({ policyGate: { status: 'ERROR' }, failures: [] }), { status: 'ERROR', exitCode: 2 });
});

test('verdict : l’échec d’exécution prime sur le BLOCK, un ERROR ne devient jamais PASS', () => {
  const completed = [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Trivy', status: 'completed' }];
  const trivyFailed = [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Trivy', status: 'failed' }];
  // 1. Finding bloquant, analyse complète → BLOCK.
  assert.deepEqual(verdictOf({ policyGate: { status: 'BLOCK' }, scanners: completed, failures: [] }), { status: 'BLOCK', exitCode: 1 });
  // 2. Scanner en échec, rien de bloquant → ERROR.
  assert.deepEqual(verdictOf({ policyGate: { status: 'PASS' }, scanners: trivyFailed, failures: ['Trivy: timeout'] }), { status: 'ERROR', exitCode: 2 });
  // 3. Scanner en échec ET finding bloquant → ERROR : une analyse incomplète ne rend pas de verdict.
  assert.deepEqual(verdictOf({ policyGate: { status: 'BLOCK' }, scanners: trivyFailed, failures: ['Trivy: timeout'] }), { status: 'ERROR', exitCode: 2 });
  // 4. Analyse complète et propre → PASS.
  assert.deepEqual(verdictOf({ policyGate: { status: 'PASS' }, scanners: completed, failures: [] }), { status: 'PASS', exitCode: 0 });
  // Un scanner annulé est une exécution incomplète, même sans entrée dans `failures`.
  assert.deepEqual(verdictOf({ policyGate: { status: 'BLOCK' }, scanners: [{ tool: 'ZAP', status: 'cancelled' }], failures: [] }), { status: 'ERROR', exitCode: 2 });
  assert.deepEqual(verdictOf({ policyGate: null, policyResult: null, failures: ['ZAP: refus'] }), { status: 'ERROR', exitCode: 2 });
  // La politique historique (sans gate) garde son refus sur une analyse complète.
  assert.deepEqual(verdictOf({ policyResult: { passed: false }, failures: [] }), { status: 'BLOCK', exitCode: 1 });
});

test('verdict : le rapport CI garde le résultat du gate quand le verdict global est ERROR', () => {
  const report = { policyGate: { status: 'BLOCK', configured: true, violations: [{ code: 'severity' }], warnings: [] }, scanners: [{ tool: 'Trivy', status: 'failed', details: 'docker introuvable' }], findings: [], failures: ['Trivy: docker introuvable'] };
  const ci = buildCiReport(report, { verdict: verdictOf(report) });
  assert.deepEqual(ci.verdict, { status: 'ERROR', exitCode: 2 });
  assert.equal(ci.policy.status, 'BLOCK', 'le gate rapporte toujours sa décision');
  assert.equal(ci.execution.status, 'partial');
});

// ---------------------------------------------------------------- signature et gate

test('signature : le gate lit l’enregistrement Cosign du CLI', () => {
  const policy = { gate: { configured: false }, supplyChain: { configured: true, requireSignature: true } };
  const verified = evaluatePolicyGate([], policy, { artifacts: gateArtifactsFrom({ signing: { status: 'verified' } }) });
  assert.equal(verified.status, 'PASS');
  // Signée mais non vérifiée : une signature vérifiée est exigée.
  const signedOnly = evaluatePolicyGate([], policy, { artifacts: gateArtifactsFrom({ signing: { status: 'signed' } }) });
  assert.equal(signedOnly.status, 'BLOCK');
  assert.equal(gateArtifactsFrom({}), null);
});

test('signature : exigée, elle ne bloque pas sa propre création', () => {
  const policy = { gate: { configured: false }, supplyChain: { configured: true, requireSignature: true, requireProvenance: false } };
  const before = evaluatePolicyGate([], withoutSignatureRequirement(policy), { artifacts: gateArtifactsFrom({ sbom: { status: 'generated' } }) });
  assert.notEqual(before.status, 'BLOCK');
  // Les autres règles restent appliquées avant la signature.
  const withProvenance = { ...policy, supplyChain: { ...policy.supplyChain, requireProvenance: true } };
  const blocked = evaluatePolicyGate([], withoutSignatureRequirement(withProvenance), { artifacts: gateArtifactsFrom({ sbom: { status: 'generated' } }) });
  assert.equal(blocked.status, 'BLOCK');
});

// ---------------------------------------------------------------- rapport CI

test('rapport CI : la raison d’un scanner en échec vient de `details`', () => {
  const report = buildCiReport({
    scanners: [
      { tool: 'Trivy', status: 'failed', details: 'docker introuvable' },
      { tool: 'Semgrep', status: 'completed', details: '12 résultats' }
    ],
    findings: [],
    failures: ['Trivy: docker introuvable']
  });
  assert.equal(report.scanners[0].error, 'docker introuvable');
  assert.equal(report.scanners[1].error, '', 'un scanner terminé n’a pas d’erreur');
  assert.deepEqual(report.execution.failedScanners, ['Trivy']);
});

test('rapport CI : verdict et étapes Security Center copiés, jamais inventés', () => {
  const stages = [
    { id: 'sast', label: 'SAST', kind: 'scan', state: 'passed', count: 3, detail: 'Semgrep' },
    { id: 'policy', label: 'Policy Gate', kind: 'decision', state: 'blocked', count: 2, detail: '2 violations' },
    { id: 'odd', label: 'Odd', kind: 'scan', state: 'invented' }
  ];
  const report = buildCiReport({ findings: [], scanners: [], failures: [], pipeline: { scanId: 'h-1', status: 'blocked', stages } }, { verdict: { status: 'BLOCK', exitCode: 1 } });
  assert.deepEqual(report.verdict, { status: 'BLOCK', exitCode: 1 });
  assert.deepEqual(report.stages.map((stage) => [stage.id, stage.state]), [['sast', 'passed'], ['policy', 'blocked'], ['odd', 'unknown']]);
  // Sans pipeline (`--no-intelligence`), pas d'étapes.
  assert.equal(buildCiReport({ findings: [], scanners: [], failures: [] }).stages, null);
  assert.equal(buildCiReport({ findings: [], scanners: [], failures: [] }).verdict, null);

  const validated = validateCiReport(JSON.stringify(report));
  assert.equal(validated.ok, true);
  assert.equal(validated.report.stages.length, 3);
  assert.deepEqual(validated.report.verdict, { status: 'BLOCK', exitCode: 1 });
});

test('rapport CI : un ancien rapport sans verdict ni étapes reste valide', () => {
  const legacy = { schemaVersion: 1, execution: { scanId: 'x', status: 'completed' }, policy: { status: 'PASS' }, scanners: [] };
  const validated = validateCiReport(JSON.stringify(legacy));
  assert.equal(validated.ok, true);
  assert.equal(validated.report.verdict, null);
  assert.equal(validated.report.stages, null);
});

test('rapport CI : un code de sortie falsifié ne contredit pas le verdict', () => {
  const forged = { schemaVersion: 1, verdict: { status: 'PASS', exitCode: 2 }, execution: {}, policy: { status: 'PASS' }, scanners: [] };
  assert.deepEqual(validateCiReport(JSON.stringify(forged)).report.verdict, { status: 'PASS', exitCode: 0 });
  const unknown = { ...forged, verdict: { status: 'OK' } };
  assert.equal(validateCiReport(JSON.stringify(unknown)).report.verdict, null);
});

// ---------------------------------------------------------------- supply chain

test('supply chain : un statut produit sans fichier est « missing », jamais SIGNED/VERIFIED', (t) => {
  const root = tempWorkspace(t);
  const report = buildCiReport({
    workspace: root, findings: [], scanners: [], failures: [],
    pipeline: { artifacts: {
      sbom: { status: 'generated', path: path.join(root, 'security-center', 'sbom.cdx.json') },
      provenance: { status: 'generated', path: path.join(root, 'security-center', 'sbom.cdx.json.provenance.json') },
      signing: { status: 'verified', artifact: path.join(root, 'security-center', 'sbom.cdx.json'), signaturePath: path.join(root, 'security-center', 'sbom.cdx.json.sigstore.json') }
    } }
  });
  assert.deepEqual(report.supplyChain, {
    sbom: 'missing', provenance: 'missing', signature: 'missing', signatureVerified: false,
    sbomPath: null, provenancePath: null, signaturePath: null
  });
});

test('supply chain : les vrais fichiers sont rapportés avec leur chemin relatif au workspace', (t) => {
  const root = tempWorkspace(t, {
    'security-center/sbom.cdx.json': '{}',
    'security-center/sbom.cdx.json.provenance.json': '{}',
    'security-center/sbom.cdx.json.sigstore.json': '{}'
  });
  const sbom = path.join(root, 'security-center', 'sbom.cdx.json');
  const report = buildCiReport({
    workspace: root, findings: [], scanners: [], failures: [],
    pipeline: { artifacts: {
      sbom: { status: 'generated', path: sbom },
      provenance: { status: 'generated', path: `${sbom}.provenance.json` },
      signing: { status: 'verified', artifact: sbom, signaturePath: `${sbom}.sigstore.json` }
    } }
  });
  assert.deepEqual(report.supplyChain, {
    sbom: 'generated', provenance: 'generated', signature: 'verified', signatureVerified: true,
    sbomPath: 'security-center/sbom.cdx.json',
    provenancePath: 'security-center/sbom.cdx.json.provenance.json',
    signaturePath: 'security-center/sbom.cdx.json.sigstore.json'
  });
  // Un échec reste un échec, sans chemin.
  const failed = buildCiReport({ workspace: root, findings: [], scanners: [], failures: [], pipeline: { artifacts: { signing: { status: 'failed', reason: 'clé absente' } } } });
  assert.equal(failed.supplyChain.signature, 'failed');
  assert.equal(failed.supplyChain.signatureVerified, false);
});

test('supply chain : un chemin relu depuis Jenkins ne peut pas sortir du workspace', () => {
  assert.equal(archivedPath('security-center/sbom.cdx.json'), 'security-center/sbom.cdx.json');
  for (const hostile of ['../etc/passwd', '/etc/passwd', 'C:/Windows/x', 'a/../../b', '', 42]) {
    assert.equal(archivedPath(hostile), null, `${hostile} doit être refusé`);
  }
  const forged = { schemaVersion: 1, execution: {}, policy: { status: 'PASS' }, scanners: [], supplyChain: { signature: 'signed', signatureVerified: true, signaturePath: '../x.sigstore.json' } };
  const validated = validateCiReport(JSON.stringify(forged)).report.supplyChain;
  assert.equal(validated.signatureVerified, false, 'VERIFIED exige le statut verified');
  assert.equal(validated.signaturePath, null);
});

// ---------------------------------------------------------------- Security Delivery

const reportedStatus = (report, identity = { inconsistent: false }) => ({
  configured: true, state: 'SUCCESS', job: 'p', baseUrl: 'http://ci.local',
  build: { number: 7, state: 'SUCCESS', artifacts: [{ fileName: 'security-center-report.json', relativePath: 'security-center-report.json' }] },
  ci: { state: 'REPORTED', report, reason: '', artifactPath: 'security-center-report.json' },
  identity
});

test('Security Delivery : les étapes viennent du rapport Security Center archivé', () => {
  const report = validateCiReport(JSON.stringify({
    schemaVersion: 1, verdict: { status: 'BLOCK' }, execution: { scanId: 'h-7' }, policy: { status: 'BLOCK' }, scanners: [],
    stages: [
      { id: 'secrets', label: 'Secrets', state: 'passed' },
      { id: 'dast', label: 'DAST', state: 'not_configured' },
      { id: 'policy', label: 'Policy Gate', state: 'blocked' }
    ]
  })).report;
  const model = toDeliveryModel(reportedStatus(report), { url: 'http://ci.local', job: 'p' });
  assert.equal(model.capabilities[CAPABILITY.STAGES].state, RESOLVED_STATE.READY);
  assert.deepEqual(model.stages.map((stage) => [stage.name, stage.outcome]), [
    ['Security Center · Secrets', RUN_OUTCOME.SUCCESS],
    ['Security Center · DAST', RUN_OUTCOME.NOT_STARTED],
    ['Security Center · Policy Gate', RUN_OUTCOME.FAILED]
  ]);
  assert.ok(model.stages.every((stage) => stage.source === 'security-center-report'), 'jamais présentées comme des étapes Jenkins');
  assert.deepEqual(model.securityReport.verdict, { status: 'BLOCK', exitCode: 1 });
});

test('Security Delivery : pas d’étapes sans rapport, ni depuis un rapport incohérent', () => {
  const report = validateCiReport(JSON.stringify({ schemaVersion: 1, execution: {}, policy: { status: 'PASS' }, scanners: [], stages: [{ id: 'sast', label: 'SAST', state: 'passed' }] })).report;
  const inconsistent = toDeliveryModel(reportedStatus(report, { inconsistent: true }), { url: 'u', job: 'p' });
  assert.equal(inconsistent.capabilities[CAPABILITY.STAGES].state, RESOLVED_STATE.NOT_REPORTED);
  assert.deepEqual(inconsistent.stages, []);
  const withoutStages = toDeliveryModel(reportedStatus({ ...report, stages: null }), { url: 'u', job: 'p' });
  assert.equal(withoutStages.capabilities[CAPABILITY.STAGES].state, RESOLVED_STATE.NOT_REPORTED);
  assert.match(withoutStages.capabilities[CAPABILITY.STAGES].reason, /ne contient pas d’étapes/);
});

// ---------------------------------------------------------------- Jenkinsfile

test('Jenkinsfile : SonarQube et Snyk ne sont exigés que s’ils sont activés', () => {
  const jenkinsfile = template();
  assert.doesNotMatch(jenkinsfile, /credentials\('security-center-(sonar|snyk)-token'\)/, 'aucun credential exigé d’office');
  assert.match(jenkinsfile, /enabledInPolicy\('sonarqube'\)[\s\S]*string\(credentialsId: 'security-center-sonar-token'/);
  assert.match(jenkinsfile, /enabledInPolicy\('snyk'\)[\s\S]*string\(credentialsId: 'security-center-snyk-token'/);
  assert.match(jenkinsfile, /withCredentials\(bindings\)/);
});

test('Jenkinsfile : noms réels des preuves, signature optionnelle via le flux CLI existant', () => {
  const jenkinsfile = template();
  assert.doesNotMatch(jenkinsfile, /intoto\.jsonl/);
  assert.match(jenkinsfile, /security-center\/\*\.provenance\.json/);
  assert.match(jenkinsfile, /\*\*\/\*\.sigstore\.json/);
  assert.match(jenkinsfile, /security-center\/\*\.cdx\.json/);
  assert.match(jenkinsfile, /\$\{SC_COSIGN_KEY:\+--sign-key "\$SC_COSIGN_KEY"\}/);
  assert.match(jenkinsfile, /\$\{SC_COSIGN_PUB:\+--verify-key "\$SC_COSIGN_PUB"\}/);
  assert.match(jenkinsfile, /variable: 'COSIGN_PASSWORD'/, 'le CLI lit le mot de passe dans COSIGN_PASSWORD');
});
