#!/usr/bin/env node
const fs = require('fs/promises');
const path = require('path');
const { runSecurityScan } = require('./orchestrator');
const { toSarif } = require('./sarif');
const { loadProjectPolicy, SEVERITY_RANK } = require('./project-policy');
const { changedFilesAgainstBase, incrementalScanPlan } = require('./incremental');

function parseArgs(argv) {
  const result = { workspace: process.cwd(), format: 'json', output: '', tools: [], zapAuthorized: false, actor: '', justification: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') result.help = true;
    else if (arg === '--zap-authorized') result.zapAuthorized = true;
    else if (arg === '--incremental') result.incremental = true;
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
  return result;
}

function help() {
  return `Security Center headless\n\nUsage:\n  security-center scan --workspace . --format sarif --output results.sarif\n\nOptions:\n  --tools Semgrep,Gitleaks,Trivy,OSV-Scanner,ZAP\n  --incremental --base-ref <SHA ou ref>\n  --semgrep-config p/security-audit\n  --fail-on HIGH\n  --zap-authorized --actor <nom> --justification <raison>\n  --target-url http://127.0.0.1:3000\n`;
}

async function main(argv = process.argv.slice(2)) {
  if (argv[0] === 'scan') argv = argv.slice(1);
  const args = parseArgs(argv);
  if (args.help) { process.stdout.write(help()); return 0; }
  const workspacePath = path.resolve(args.workspace);
  let policy = await loadProjectPolicy(workspacePath);
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
    options: { selectedTools, targetUrl: args.targetUrl || 'http://127.0.0.1:3000', zapAuthorized: args.zapAuthorized, semgrepConfig: args.semgrepConfig || 'p/security-audit', semgrepTargets: incremental?.sourceFiles || [], gitleaksHistory: incremental ? true : undefined, gitleaksSinceCommit: incremental ? args.baseRef : '' },
    onScannerUpdate: (event) => process.stderr.write(`[${event.tool}] ${event.status}${event.details ? ` — ${event.details}` : ''}\n`)
  }) : { workspace: workspacePath, findings: [], scanners: [], correlations: [], policyResult: policy ? { passed: true, activeCount: 0, blockingCount: 0, reasons: [], policy } : null, failures: [], finishedAt: new Date().toISOString() };
  if (incremental) report.incremental = incremental;
  report.audit = args.zapAuthorized ? { action: 'zap:headless:authorized', actor: args.actor.trim(), comment: args.justification.trim(), createdAt: new Date().toISOString() } : undefined;
  const output = args.format === 'sarif' ? toSarif(report) : report;
  const serialized = `${JSON.stringify(output, null, 2)}\n`;
  if (args.output) await fs.writeFile(path.resolve(args.output), serialized, 'utf8');
  else process.stdout.write(serialized);
  if (report.failures.length) return 2;
  if (report.policyResult && !report.policyResult.passed) return 1;
  return 0;
}

if (require.main === module) main().then((code) => { process.exitCode = code; }).catch((error) => { process.stderr.write(`Security Center: ${error.message}\n`); process.exitCode = 2; });

module.exports = { parseArgs, help, main };
