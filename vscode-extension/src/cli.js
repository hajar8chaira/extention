#!/usr/bin/env node
const fs = require('fs/promises');
const path = require('path');
const { runSecurityScan } = require('./orchestrator');
const { toSarif } = require('./sarif');
const { loadProjectPolicy, SEVERITY_RANK, gateDecides, legacyPolicyNotice } = require('./project-policy');
const { changedFilesAgainstBase, incrementalScanPlan } = require('./incremental');
const { analyzeWorkspace, mergeIntelligence, runSupplyChainStages, buildPipelineResult, describeStages } = require('./pipeline');
const { evaluatePolicyGate, formatGateResult, gateExitCode, policyGateError, STATUS } = require('./intelligence/policy-gate');
const { signBlob, verifyBlob } = require('./supply-chain/cosign');
const { buildCiReport, CI_REPORT_FILENAME } = require('./ci-report');
// The installed package identifies the CI Engine in the reports it writes.
const { name: ENGINE_PACKAGE, version: ENGINE_VERSION } = require('../package.json');
// The source commit stamped by the Security Center build. Absent in a source
// checkout: the report then says nothing about a commit rather than guessing one.
const ENGINE_COMMIT = (() => {
  try { return require('../build-info.json').commit || null; } catch { return null; }
})();
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

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
  return `Security Center headless\n\nUsage:\n  security-center scan --workspace . --format sarif --output results.sarif\n\nOptions:\n  --tools Semgrep,Gitleaks,Trivy,OSV-Scanner,SonarQube,Snyk,ZAP\n  --incremental --base-ref <SHA ou ref>\n  --semgrep-config p/security-audit\n  --fail-on HIGH\n  --zap-authorized --actor <nom> --justification <raison>\n  --target-url http://127.0.0.1:3000\n  --sonar-host-url http://127.0.0.1:9000 --sonar-project-key <cle>\n    Le jeton provient uniquement de la variable d'environnement SONAR_TOKEN.\n  --snyk-mode auto|local|docker --snyk-code --snyk-iac\n    Le jeton provient uniquement de la variable d'environnement SNYK_TOKEN.\n\nPipeline (corrélation, reachability, priorité, policy gate) : actif par défaut.\n  --no-intelligence            n'exécute que les scanners\n  --sbom                       génère le SBOM CycloneDX comme artefact\n  --provenance                 génère la provenance in-toto/SLSA de l'artefact\n  --sign-key <cosign.key> [--sign-artifact <fichier>]\n    Le mot de passe provient uniquement de la variable d'environnement COSIGN_PASSWORD.\n  --verify-key <cosign.pub>    vérifie la signature produite\n  --artifact-dir <dossier>     destination des artefacts générés
  --ci-report <fichier>        rapport CI normalisé (schéma stable, sans secret),
    destiné à être archivé par Jenkins puis relu par l'extension VS Code\n\nPolicy Gate — security-center.yml est la seule source de vérité :\n  gate:\n    fail_on_severity: [CRITICAL]   # cette sévérité ou plus grave bloque\n    warn_on_severity: [HIGH]       # signalé sans bloquer\n    block_secrets: true            # un secret exposé bloque\n    priority_threshold: 80         # priorité >= 80 bloque\n    require_sbom: false            # un SBOM doit avoir été généré\n  supply_chain:\n    require_provenance: false\n    require_signature: false\n\nCodes de sortie : 0 accepté (PASS, WARN ou politique absente),\n  1 refusé par la politique projet (BLOCK),\n  2 échec d'exécution ou politique illisible.\n`;
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
  // One verdict decider. With a Policy Gate configured, the legacy thresholds —
  // from the file or from `--fail-on` — no longer take part in the verdict, and
  // the log says so instead of pretending they apply.
  const policyNotice = legacyPolicyNotice(policy, { cliFailOn: args.failOn || '' });
  if (policyNotice) process.stderr.write(`[policy] ${policyNotice}` + '\n');
  // `--fail-on` keeps its legacy meaning only where the legacy policy decides.
  if (args.failOn && !gateDecides(policy)) policy = {
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
      // Without --tools, security-center.yml selects the scanners — SonarQube
      // and Snyk included — so a CI pipeline never duplicates that choice.
      sonarEnabled: (selectedTools.includes('SonarQube') || (!selectedTools.length && policy?.scanners?.SonarQube === true)) && !incremental,
      sonarMode: args.sonarMode || 'auto',
      sonarHostUrl: args.sonarHostUrl || process.env.SONAR_HOST_URL || 'http://127.0.0.1:9000',
      sonarProjectKey: args.sonarProjectKey || '',
      sonarToken: process.env.SONAR_TOKEN || '',
      // Snyk follows the exact same headless contract as SonarQube: explicitly
      // requested, and authenticated only through the environment.
      snykEnabled: (selectedTools.includes('Snyk') || (!selectedTools.length && policy?.scanners?.Snyk === true)) && !incremental,
      snykMode: args.snykMode || 'auto',
      snykToken: process.env.SNYK_TOKEN || '',
      snykIncludeOpenSource: true,
      snykIncludeCode: args.snykCode === true,
      snykIncludeIaC: args.snykIac === true
    },
    onScannerUpdate: (event) => process.stderr.write(`[${event.tool}] ${event.status}${event.details ? ` — ${event.details}` : ''}\n`)
  }) : { workspace: workspacePath, findings: [], scanners: [], correlations: [], policyResult: policy ? { passed: true, activeCount: 0, blockingCount: 0, reasons: [], policy } : null, failures: [], finishedAt: new Date().toISOString() };
  if (incremental) report.incremental = incremental;
  if (policyNotice) report.policyNotice = policyNotice;
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
    // The gate reads a signature under `signature`; the CLI keeps Cosign's
    // record under `signing`, like the extension. Same record, both names —
    // otherwise `require_signature` could never be satisfied.
    const gateArtifacts = () => gateArtifactsFrom(artifacts);

    if (args.signKey) {
      // Signing is refused on a BLOCK, but not on the one requirement signing
      // itself satisfies: a required signature cannot exist before it is made.
      const beforeSigning = evaluatePolicyGate(analysis.findings, withoutSignatureRequirement(policy), { artifacts: gateArtifacts() });
      if (beforeSigning.status === STATUS.BLOCK) {
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

    // The gate is evaluated once every artefact exists, so `require_sbom`,
    // `require_provenance` and `require_signature` are judged on what was
    // actually produced rather than on an empty stage.
    const gate = gateArtifacts()
      ? evaluatePolicyGate(analysis.findings, policy, { artifacts: gateArtifacts() })
      : analysis.policy;

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
  }

  // One verdict, computed once: the exit code and the CI report cannot disagree.
  const verdict = verdictOf(report);
  if (report.policyGate) {
    // The gate verdict and the exit code are printed together so a CI log states
    // the decision and its consequence in one place.
    process.stderr.write(`${formatGateResult(report.policyGate)}` + '\n\nExit code: ' + verdict.exitCode + '\n');
  }

  // The CI report contract: a small, sanitized projection Jenkins can archive and
  // the extension can read back. The full JSON output is unchanged.
  if (args.ciReport) {
    const { commit, branch } = await gitIdentity(workspacePath);
    const ciReport = buildCiReport(report, { commit, branch, verdict, workspace: workspacePath, engine: { name: ENGINE_PACKAGE, version: ENGINE_VERSION, commit: ENGINE_COMMIT } });
    await fs.writeFile(path.resolve(args.ciReport), `${JSON.stringify(ciReport, null, 2)}
`, 'utf8');
    process.stderr.write(`[ci-report] ${path.resolve(args.ciReport)}
`);
  }

  const output = args.format === 'sarif' ? toSarif(report) : report;
  const serialized = `${JSON.stringify(output, null, 2)}\n`;
  if (args.output) await fs.writeFile(path.resolve(args.output), serialized, 'utf8');
  else process.stdout.write(serialized);
  return verdict.exitCode;
}

/**
 * The CI verdict contract: 0 = PASS, 1 = BLOCK, 2 = ERROR.
 *
 *   PASS  — the analysis completed and the policy permits delivery.
 *   BLOCK — the analysis completed and the policy rejects delivery.
 *   ERROR — the analysis is incomplete or unreliable: a scanner failed or was
 *           cancelled, or the policy could not be applied.
 *
 * Execution failure takes precedence over the policy: a verdict drawn from an
 * incomplete analysis is not a verdict. The gate keeps its own result (it may
 * still say BLOCK in the report); only the overall CI verdict is ERROR.
 * WARN and NOT_CONFIGURED are accepted (0).
 */
function verdictOf(report = {}) {
  const scannerFailed = (report.scanners || []).some((scanner) => ['failed', 'cancelled'].includes(scanner?.status));
  if ((report.failures || []).length || scannerFailed) return { status: 'ERROR', exitCode: 2 };
  // A configured gate is the only decider: when it did not run (for example
  // `--no-intelligence`), there is no verdict — never a legacy fallback.
  if (report.policyResult?.decidedBy === 'gate' && !report.policyGate) return { status: 'ERROR', exitCode: 2 };
  const gateCode = report.policyGate ? gateExitCode(report.policyGate) : 0;
  if (gateCode === 2) return { status: 'ERROR', exitCode: 2 };
  if (gateCode === 1 || (report.policyResult && !report.policyResult.passed)) return { status: 'BLOCK', exitCode: 1 };
  return { status: 'PASS', exitCode: 0 };
}

/** The artefacts as the gate reads them, or null when no supply-chain stage ran. */
function gateArtifactsFrom(artifacts = {}) {
  if (!artifacts || !Object.keys(artifacts).length) return null;
  return { ...artifacts, ...(artifacts.signing ? { signature: artifacts.signing } : {}) };
}

/** The policy as it stands before signing: every rule except the signature. */
function withoutSignatureRequirement(policy) {
  if (!policy?.supplyChain?.requireSignature) return policy;
  return {
    ...policy,
    supplyChain: { ...policy.supplyChain, requireSignature: false, configured: policy.supplyChain.requireProvenance === true }
  };
}

/**
 * The commit and branch the scan ran against.
 *
 * Read from git, never guessed. In a detached CI checkout the branch is often
 * absent; it stays empty rather than being inferred from an environment variable
 * that may describe something else.
 */
async function gitIdentity(workspacePath) {
  const read = async (args) => {
    try { return (await execFileAsync('git', ['-C', workspacePath, ...args], { windowsHide: true, timeout: 8000 })).stdout.trim(); }
    catch { return ''; }
  };
  const commit = await read(['rev-parse', 'HEAD']);
  let branch = await read(['rev-parse', '--abbrev-ref', 'HEAD']);
  if (branch === 'HEAD') branch = '';
  return { commit, branch };
}

if (require.main === module) main().then((code) => { process.exitCode = code; }).catch((error) => { process.stderr.write(`Security Center: ${error.message}\n`); process.exitCode = 2; });

module.exports = { parseArgs, help, main, verdictOf, withoutSignatureRequirement, gateArtifactsFrom };
