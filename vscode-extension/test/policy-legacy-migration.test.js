'use strict';

/**
 * Migration legacy `policy:` → Policy Gate.
 *
 * Un seul décideur : dès que `gate:` ou `supply_chain:` est configuré, seul le
 * Policy Gate décide. `policy.fail_on`, `policy.max_active` et `--fail-on` sont
 * nommés comme ignorés, jamais appliqués en silence. Sans gate, le legacy reste
 * inchangé.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  parsePolicyYaml, validatePolicy, evaluatePolicy, gateDecides, legacyPolicyNotice, renderGateSection, STARTER_GATE
} = require('../src/project-policy');
const { readPolicyGateConfig, savePolicyGate } = require('../src/policy-config');
const { renderPolicyTab } = require('../src/pipeline-page');

// Seule l'exécution des scanners est simulée. Politique legacy, gate, pipeline,
// verdict et rapport CI sont les vrais.
const orchestratorPath = require.resolve('../src/orchestrator');
let run = { findings: [], scanners: [], failures: [] };
require.cache[orchestratorPath] = {
  id: orchestratorPath, filename: orchestratorPath, loaded: true,
  exports: {
    runSecurityScan: async ({ workspacePath, policy }) => ({
      workspace: workspacePath, correlations: [], finishedAt: new Date().toISOString(),
      ...run, policyResult: evaluatePolicy(run.findings, policy)
    })
  }
};
const { main } = require('../src/cli');

const MIXED = `version: 1
policy:
  fail_on: HIGH
  max_active: 0
gate:
  fail_on_severity: [CRITICAL]
  warn_on_severity: [HIGH]
`;

const LEGACY = `version: 1
policy:
  fail_on: HIGH
  max_active: 0
`;

const NOTICE = 'Policy Gate actif : policy.fail_on et policy.max_active sont des règles legacy et ne participent plus au verdict.';

const finding = (severity) => ({
  id: `sg:${severity}`, tool: 'Semgrep', ruleId: `rule-${severity.toLowerCase()}`, rawSeverity: severity,
  severity: severity === 'LOW' ? 'info' : 'error', title: `Résultat ${severity}`, file: 'src/app.js', startLine: 1, stage: 'sast'
});
const COMPLETED = [{ tool: 'Semgrep', status: 'completed' }];

function workspace(t, yml) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-legacy-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  if (yml !== null) fs.writeFileSync(path.join(root, 'security-center.yml'), yml);
  return root;
}

async function scan(t, yml, { findings = [], scanners = COMPLETED, failures = [], args = [] } = {}) {
  const root = workspace(t, yml);
  run = { findings, scanners, failures };
  const logs = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk) => { logs.push(String(chunk)); return true; };
  let exitCode;
  try {
    exitCode = await main(['scan', '--workspace', root, '--output', path.join(root, 'full.json'), '--ci-report', path.join(root, 'ci.json'), ...args]);
  } finally {
    process.stderr.write = original;
  }
  const ci = JSON.parse(fs.readFileSync(path.join(root, 'ci.json'), 'utf8'));
  return { exitCode, ci, log: logs.join('') };
}

// ------------------------------------------------ gate + legacy (cas A à D)

test('A — gate + legacy, finding HIGH seul : gate WARN, verdict PASS, sortie 0', async (t) => {
  const { exitCode, ci, log } = await scan(t, MIXED, { findings: [finding('HIGH')] });
  assert.equal(ci.policy.status, 'WARN');
  assert.deepEqual(ci.verdict, { status: 'PASS', exitCode: 0 });
  assert.equal(exitCode, 0);
  // Les règles legacy ne sont pas appliquées en silence : elles sont nommées.
  assert.ok(log.includes(NOTICE), 'le journal CLI nomme les règles ignorées');
  assert.equal(ci.policy.legacyNotice, NOTICE);
});

test('B — gate + legacy, finding LOW seul : gate PASS, verdict PASS, sortie 0', async (t) => {
  const { exitCode, ci } = await scan(t, MIXED, { findings: [finding('LOW')] });
  assert.equal(ci.policy.status, 'PASS');
  assert.deepEqual(ci.verdict, { status: 'PASS', exitCode: 0 });
  assert.equal(exitCode, 0, 'max_active: 0 ne bloque plus quand le gate décide');
});

test('C — gate + legacy, finding CRITICAL : gate BLOCK, verdict BLOCK, sortie 1', async (t) => {
  const { exitCode, ci } = await scan(t, MIXED, { findings: [finding('CRITICAL')] });
  assert.equal(ci.policy.status, 'BLOCK');
  assert.deepEqual(ci.verdict, { status: 'BLOCK', exitCode: 1 });
  assert.equal(exitCode, 1);
});

test('D — gate + legacy, scanner en échec : verdict ERROR, sortie 2', async (t) => {
  const { exitCode, ci } = await scan(t, MIXED, {
    findings: [finding('HIGH')],
    scanners: [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Trivy', status: 'failed', details: 'docker introuvable' }],
    failures: ['Trivy: docker introuvable']
  });
  assert.deepEqual(ci.verdict, { status: 'ERROR', exitCode: 2 });
  assert.equal(exitCode, 2);
});

test('gate + --fail-on : le drapeau ne bloque pas et il est signalé comme ignoré', async (t) => {
  const { exitCode, ci, log } = await scan(t, MIXED, { findings: [finding('HIGH')], args: ['--fail-on', 'LOW'] });
  assert.equal(exitCode, 0);
  assert.deepEqual(ci.verdict, { status: 'PASS', exitCode: 0 });
  assert.match(log, /Policy Gate actif : policy\.fail_on, policy\.max_active et --fail-on sont des règles legacy/);
});

test('gate configuré mais non exécuté (--no-intelligence) : ERROR, jamais de repli legacy', async (t) => {
  const { exitCode, ci } = await scan(t, MIXED, { findings: [finding('HIGH')], args: ['--no-intelligence'] });
  assert.equal(exitCode, 2);
  assert.deepEqual(ci.verdict, { status: 'ERROR', exitCode: 2 });
});

// ------------------------------------------------ legacy seul (cas E)

test('E — projet legacy sans gate : fail_on et max_active gardent leur comportement', async (t) => {
  const high = await scan(t, LEGACY, { findings: [finding('HIGH')] });
  assert.equal(high.exitCode, 1, 'fail_on: HIGH bloque HIGH');
  assert.deepEqual(high.ci.verdict, { status: 'BLOCK', exitCode: 1 });
  assert.equal(high.ci.policy.status, 'NOT_CONFIGURED');
  assert.equal(high.ci.policy.legacyNotice, '', 'aucun avertissement de migration sans gate');

  const low = await scan(t, LEGACY, { findings: [finding('LOW')] });
  assert.equal(low.exitCode, 1, 'max_active: 0 bloque dès un résultat actif');

  const clean = await scan(t, LEGACY, { findings: [] });
  assert.equal(clean.exitCode, 0);
  assert.doesNotMatch(clean.log, /Policy Gate actif/);
});

test('E — --fail-on legacy est préservé sans gate', async (t) => {
  const blocked = await scan(t, null, { findings: [finding('CRITICAL')], args: ['--fail-on', 'CRITICAL'] });
  assert.equal(blocked.exitCode, 1);
  const accepted = await scan(t, null, { findings: [finding('LOW')], args: ['--fail-on', 'CRITICAL'] });
  assert.equal(accepted.exitCode, 0);
  const overridden = await scan(t, LEGACY, { findings: [finding('HIGH')], args: ['--fail-on', 'CRITICAL'] });
  assert.equal(overridden.exitCode, 1, 'max_active: 0 du fichier reste appliqué avec --fail-on');
});

// ------------------------------------------------ modèle de décision

test('un seul décideur : evaluatePolicy ne bloque plus quand le gate est configuré', () => {
  const findings = [finding('HIGH'), finding('LOW')];
  const mixed = evaluatePolicy(findings, validatePolicy(parsePolicyYaml(MIXED)));
  assert.equal(mixed.passed, true);
  assert.equal(mixed.decidedBy, 'gate');
  assert.deepEqual(mixed.legacyIgnored, ['policy.fail_on', 'policy.max_active']);
  assert.deepEqual(mixed.reasons, []);
  const legacy = evaluatePolicy(findings, validatePolicy(parsePolicyYaml(LEGACY)));
  assert.equal(legacy.passed, false);
  assert.equal(legacy.decidedBy, undefined);
});

test('supply_chain seul suffit à faire décider le gate', () => {
  const policy = validatePolicy(parsePolicyYaml(`version: 1
policy:
  fail_on: HIGH
supply_chain:
  require_provenance: true
`));
  assert.equal(gateDecides(policy), true);
  assert.equal(legacyPolicyNotice(policy), 'Policy Gate actif : policy.fail_on est une règle legacy et ne participe plus au verdict.');
});

test('include_tests n’est pas une règle legacy', () => {
  const policy = validatePolicy(parsePolicyYaml(`version: 1
policy:
  include_tests: false
gate:
  fail_on_severity: [CRITICAL]
`));
  assert.equal(legacyPolicyNotice(policy), '');
  assert.equal(policy.includeTests, false, 'le gate lit toujours include_tests');
});

// ------------------------------------------------ modèle de politique

test('ouvrir la politique ne génère plus aucun modèle, donc aucun seuil legacy contradictoire', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const start = source.indexOf("registerCommand('securityCenter.openProjectPolicy'");
  const body = source.slice(start, source.indexOf("registerCommand('securityCenter.generateSbom'", start));
  assert.ok(start > 0, 'la commande existe');
  assert.doesNotMatch(body, /writeFile|const template/);
  assert.doesNotMatch(body, /'  fail_on: HIGH'|'  max_active: 0'/);
  // Le gate de départ, lui, reste cohérent quand l'utilisateur le crée explicitement.
  const generated = validatePolicy(parsePolicyYaml(['version: 1', 'policy:', '  include_tests: false', ...renderGateSection(STARTER_GATE), ''].join('\n')));
  assert.equal(gateDecides(generated), true);
  assert.equal(legacyPolicyNotice(generated), '');
  assert.equal(generated.includeTests, false);
});

// ------------------------------------------------ UI Policy Gate

test('UI : un fichier gate + legacy affiche les règles ignorées, sans rien supprimer', async (t) => {
  const root = workspace(t, MIXED);
  const config = await readPolicyGateConfig(root);
  assert.equal(config.legacyNotice, NOTICE);
  const html = renderPolicyTab({ policy: null, policyConfig: config, policyEvaluation: {} });
  assert.match(html, /data-policy-legacy/);
  assert.match(html, /Règles legacy ignorées par le Policy Gate/);
  assert.ok(html.includes('policy.fail_on et policy.max_active'));

  const saved = await savePolicyGate(root, { failCritical: true, warnHigh: true });
  assert.equal(saved.ok, true);
  assert.ok(saved.message.includes(NOTICE), 'l’enregistrement rappelle les règles ignorées');
  const text = fs.readFileSync(path.join(root, 'security-center.yml'), 'utf8');
  assert.match(text, /^  fail_on: HIGH$/m, 'la configuration existante n’est pas supprimée');
  assert.match(text, /^  max_active: 0$/m);
});

test('UI : aucun avertissement pour un projet legacy seul ou un gate sans legacy', async (t) => {
  const legacy = await readPolicyGateConfig(workspace(t, LEGACY));
  assert.equal(legacy.legacyNotice, '');
  assert.doesNotMatch(renderPolicyTab({ policy: null, policyConfig: legacy, policyEvaluation: {} }), /data-policy-legacy/);
  const clean = await readPolicyGateConfig(workspace(t, `version: 1
gate:
  fail_on_severity: [CRITICAL]
`));
  assert.equal(clean.legacyNotice, '');
});
