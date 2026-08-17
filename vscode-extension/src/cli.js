#!/usr/bin/env node
const fs = require('fs/promises');
const path = require('path');
const { runSecurityScan } = require('./orchestrator');
const { toSarif } = require('./sarif');
const { loadProjectPolicy, SEVERITY_RANK } = require('./project-policy');
const { changedFilesAgainstBase, incrementalScanPlan } = require('./incremental');
const { analyzeWorkspace, mergeIntelligence, runSupplyChainStages, buildPipelineResult, describeStages } = require('./pipeline');
const { evaluatePolicyGate, formatGateResult, gateExitCode, policyGateError, STATUS } = require('./intelligence/policy-gate');
const { signBlob, verifyBlob } = require('./supply-chain/cosign');

function parseArgs(argv) {
  const result = { workspace: process.cwd(), format: 'json', output: '', tools: [], zapAuthorized: false, actor: '', justification: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') result.help = true;
    else if (arg === '--zap-authorized') result.zapAuthorized = true;
    else if (arg === '--incremental') result.incremental = true;
    else if (arg === '--snyk-code') result.snykCode = true;
    else if (arg === '--snyk-iac') result.snykIac = true;
    else if (arg === '--sbom') result.sbom = true;
    else if (arg === '--provenance') result.provenance = true;
    else if (arg === '--no-intelligence') result.noIntelligence = true;
    else if (arg.startsWith('--')) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      if (index + 1 >= argv.length) throw new Error(`Valeur manquante pour ${arg}.`);
      result[key] = argv[++index];
    } else throw new Error(`Argument inconnu : ${arg}.`);
  }
  result.tools = typeof result.tools === 'string' ? result.tools.split(',').map((item) => item.trim()).filter(Boolean) : [];
  if (!['json', 'sarif'].includes(result.format)) throw new Error('--format accepte json ou sarif.');
  if (result.failOn && !(String(result.failOn).toUpperCase() in SEVERITY_RANK)) throw new Error('--fail-on utilise une sévérité inconnue.');
  if (result.zapAuthorized && (!String(result.actor).trim() || !String(result.justification).trim())) {
    throw new Error('--zap-authorized exige --actor et --justification pour la traçabilité.');
  }
  if (result.incremental && !String(result.baseRef || '').trim()) throw new Error('--incremental exige --base-ref <SHA ou ref>.');
  if (result.snykMode && !['auto', 'local', 'docker'].includes(String(result.snykMode))) throw new Error('--snyk-mode accepte auto, local ou docker.');
  return result;
}

function help() {
  return `Security Center headless\n\nUsage:\n  security-center scan --workspace . --format sarif --output results.sarif\n\nOptions:\n  --tools Semgrep,Gitleaks,Trivy,OSV-Scanner,SonarQube,Snyk,ZAP\n  --incremental --base-ref <SHA ou ref>\n  --semgrep-config p/security-audit\n  --fail-on HIGH\n  --zap-authorized --actor <nom> --justification <raison>\n  --target-url http://127.0.0.1:3000\n  --sonar-host-url http://127.0.0.1:9000 --sonar-project-key <cle>\n    Le jeton provient uniquement de la variable d'environnement SONAR_TOKEN.\n  --snyk-mode auto|local|docker --snyk-code --snyk-iac\n    Le jeton provient uniquement de la variable d'environnement SNYK_TOKEN.\n\nPipeline (corrélation, reachability, priorité, policy gate) : actif par défaut.\n  --no-intelligence            n'exécute que les scanners\n  --sbom                       génère le SBOM CycloneDX comme artefact\n  --provenance                 génère la provenance in-toto/SLSA de l'artefact\n  --sign-key <cosign.key> [--sign-artifact <fichier>]\n    Le mot de passe provient uniquement de la variable d'environnement COSIGN_PASSWORD.\n  --verify-key <cosign.pub>    vérifie la signature produite\n  --artifact-dir <dossier>     destination des artefacts générés\n\nPolicy Gate — security-center.yml est la seule source de vérité :\n  gate:\n    fail_on_severity: [CRITICAL]   # cette sévérité ou plus grave bloque\n    warn_on_severity: [HIGH]       # signalé sans bloquer\n    block_secrets: true            # un secret exposé bloque\n    priority_threshold: 80         # priorité >= 80 bloque\n    require_sbom: false            # un SBOM doit avoir été généré\n  supply_chain:\n    require_provenance: false\n    require_signature: false\n\nCodes de sortie : 0 accepté (PASS, WARN ou politique absente),\n  1 refusé par la politique projet (BLOCK),\n  2 échec d'exécution ou politique illisible.\n`;
}

async function main(argv = process.argv.slice(2)) {
  if (argv[0] === 'scan') argv = argv.slice(1);
  const args = parseArgs(argv);
  if (args.help) { process.stdout.write(help()); return 0; }
  const workspacePath = path.resolve(args.workspace);
  let policy;
  try {
    policy = await loadProjectPolicy(workspacePath);
  } catch (error) {
    // An unusable policy is a configuration failure, not a refusal and certainly
    // not an acceptance: exit 2, and no scan is run on a policy we cannot apply.
    process.stderr.write(`${formatGateResult(policyGateError(error.message))}\n\nExit code: 2\n`);
    return 2;
  }
  if (args.failOn) policy = {
    version: 1, scanners: {}, failOn: String(args.failOn).toUpperCase(), maxActive: policy?.maxActive ?? 999999,
    includeTests: policy?.includeTests ?? true, licensesDenied: policy?.licensesDenied || [],
    gitleaksHistory: policy?.gitleaksHistory || false, gitleaksHistoryIncremental: policy?.gitleaksHistoryIncremental ?? true,
    gitleaksConfig: policy?.gitleaksConfig || '', semgrepCustomRules: policy?.semgrepCustomRules || '',
    zapActive: policy?.zapActive || false, zapOpenapi: policy?.zapOpenapi || '', zapContext: policy?.zapContext || '', zapUser: policy?.zapUser || '',
    exclusions: policy?.exclusions || { global_files: [], semgrep_files: [], semgrep_rules: [], trivy_files: [], zap_routes: [] },
    maxParallelScanners: policy?.maxParallelScanners || 2, ...policy, failOn: String(args.failOn).toUpperCase()
  };
  const incremental = args.incremental
    ? incrementalScanPlan(await changedFilesAgainstBase(workspacePath, args.baseRef), args.tools)
    : null;
  if (incremental) process.stderr.write(`[incremental] ${incremental.changedFiles.length} fichier(s) modifié(s) — scanners: ${incremental.tools.join(', ') || 'aucun'}\n`);
  const selectedTools = incremental ? incremental.tools : args.tools;
  const report = selectedTools.length || (!incremental && !args.tools.length) ? await runSecurityScan({
    workspacePath,
    policy,
    options: {
      selectedTools, targetUrl: args.targetUrl || 'http://127.0.0.1:3000', zapAuthorized: args.zapAuthorized,
      semgrepConfig: args.semgrepConfig || 'p/security-audit', semgrepTargets: incremental?.sourceFiles || [],
      gitleaksHistory: incremental ? true : undefined, gitleaksSinceCommit: incremental ? args.baseRef : '',
      // SonarQube runs headless only when the caller asked for it and supplied a
      // token through the environment. It is never derived from the workspace.
      sonarEnabled: selectedTools.includes('SonarQube') && !incremental,
      sonarMode: args.sonarMode || 'auto',
      sonarHostUrl: args.sonarHostUrl || process.env.SONAR_HOST_URL || 'http://127.0.0.1:9000',
      sonarProjectKey: args.sonarProjectKey || '',
      sonarToken: process.env.SONAR_TOKEN || '',
      // Snyk follows the exact same headless contract as SonarQube: explicitly
      // requested, and authenticated only through the environment.
      snykEnabled: selectedTools.includes('Snyk') && !incremental,
      snykMode: args.snykMode || 'auto',
      snykToken: process.env.SNYK_TOKEN || '',
      snykIncludeOpenSource: true,
      snykIncludeCode: args.snykCode === true,
      snykIncludeIaC: args.snykIac === true
    },
    onScannerUpdate: (event) => process.stderr.write(`[${event.tool}] ${event.status}${event.details ? ` — ${event.details}` : ''}\n`)
  }) : { workspace: workspacePath, findings: [], scanners: [], correlations: [], policyResult: policy ? { passed: true, activeCount: 0, blockingCount: 0, reasons: [], policy } : null, failures: [], finishedAt: new Date().toISOString() };
  if (incremental) report.incremental = incremental;
  report.audit = args.zapAuthorized ? { action: 'zap:headless:authorized', actor: args.actor.trim(), comment: args.justification.trim(), createdAt: new Date().toISOString() } : undefined;

  // The very same pipeline services the extension uses. There is no separate
  // CI implementation of correlation, reachability, priority or the gate.
  let pipeline = null;
  if (!args.noIntelligence) {
    const startedAt = new Date().toISOString();
    const analysis = await analyzeWorkspace({ workspacePath, findings: report.findings, policy });
    report.findings = mergeIntelligence(report.findings, analysis);
    report.correlationClusters = analysis.clusters;
    process.stderr.write(`[pipeline] ${analysis.clusters.length} corrélation(s) • ${analysis.priority.counts.critical} priorité(s) critique(s)\n`);

    const artifacts = await runSupplyChainStages({
      workspacePath,
      sbom: args.sbom ? { enabled: true, mode: args.trivyMode || 'auto', outputDirectory: args.artifactDir || '' } : null,
      provenance: args.provenance ? { enabled: true, outputPath: '' } : null,
      scanners: report.scanners,
      policy: analysis.policy,
      startedAt
    });
    // The gate is re-evaluated once the artefacts exist so `require_sbom` is
    // judged on what was actually produced rather than on an empty stage.
    const gate = Object.keys(artifacts).length
      ? evaluatePolicyGate(analysis.findings, policy, { artifacts })
      : analysis.policy;

    if (args.signKey) {
      if (gate.status === STATUS.BLOCK) {
        artifacts.signing = { status: 'failed', reason: 'Signature refusée : la politique projet a bloqué ce scan.' };
      } else {
        const subject = args.signArtifact || artifacts.sbom?.path || '';
        if (!subject) artifacts.signing = { status: 'failed', reason: 'Aucun artefact à signer. Utilisez --sbom ou --sign-artifact.' };
        else {
          try {
            artifacts.signing = await signBlob({
              filePath: subject, keyPath: args.signKey,
              password: process.env.COSIGN_PASSWORD || '', confirmed: true
            });
          } catch (error) { artifacts.signing = { status: 'failed', reason: error.message }; }
        }
      }
    }
    if (args.verifyKey && artifacts.signing?.status === 'signed') {
      try {
        artifacts.signing = {
          ...artifacts.signing,
          ...await verifyBlob({ filePath: artifacts.signing.artifact, publicKeyPath: args.verifyKey, signaturePath: artifacts.signing.signaturePath })
        };
      } catch (error) { artifacts.signing = { ...artifacts.signing, status: 'failed', reason: error.message }; }
    }

    pipeline = buildPipelineResult({
      scanId: `headless-${Date.now()}`, workspace: workspacePath, startedAt,
      scanners: report.scanners, rawFindings: report.findings,
      analysis: { ...analysis, policy: gate }, artifacts, failures: report.failures
    });
    report.pipeline = {
      ...pipeline,
      findings: undefined,
      clusters: undefined,
      // `describeStages` reads `scanners`; the pipeline result names the same
      // data `scannerResults`, so it has to be mapped explicitly.
      stages: describeStages({ ...pipeline, ...analysis, policy: gate, scanners: report.scanners })
    };
    report.policyGate = gate;
    // The gate verdict and the exit code are printed together so a CI log states
    // the decision and its consequence in one place.
    process.stderr.write(`${formatGateResult(gate)}\n\nExit code: ${report.failures.length ? 2 : gateExitCode(gate)}\n`);
  }

  const output = args.format === 'sarif' ? toSarif(report) : report;
  const serialized = `${JSON.stringify(output, null, 2)}\n`;
  if (args.output) await fs.writeFile(path.resolve(args.output), serialized, 'utf8');
  else process.stdout.write(serialized);
  // Exit codes keep the historical contract: 2 = execution or configuration
  // problem, 1 = the project policy refuses this state, 0 = accepted. WARN is
  // accepted: promoting a warning to a block is done in the policy itself.
  if (report.failures.length) return 2;
  if (report.policyGate) {
    const code = gateExitCode(report.policyGate);
    if (code) return code;
  }
  if (report.policyResult && !report.policyResult.passed) return 1;
  return 0;
}

if (require.main === module) main().then((code) => { process.exitCode = code; }).catch((error) => { process.stderr.write(`Security Center: ${error.message}\n`); process.exitCode = 2; });

module.exports = { parseArgs, help, main };
