const path = require('path');
const { runSemgrep } = require('./semgrep');
const { runGitleaks } = require('./gitleaks');
const { runTrivy } = require('./trivy');
const { runOsv } = require('./osv');
const { runZap } = require('./zap');
const { runSonarQube } = require('./sonarqube');
const { runSnyk } = require('./snyk');
const { normalizeSemgrepOutput, normalizeGitleaksOutput, normalizeTrivyOutput, normalizeOsvOutput, normalizeZapOutput, normalizeSonarQubeOutput, normalizeSnykOutput, deduplicateFindings } = require('./findings');
const { correlateFindings } = require('./correlation');
const { loadProjectPolicy, evaluatePolicy } = require('./project-policy');
const { runWithConcurrency } = require('./scheduler');

function defaultOptions(options = {}) {
  return {
    semgrepMode: 'docker', semgrepConfig: 'p/security-audit', gitleaksMode: 'docker',
    trivyMode: 'docker', trivyImage: '', timeoutMs: 600000, targetUrl: 'http://127.0.0.1:3000',
    selectedTools: [], zapAuthorized: false,
    // SonarQube needs an external server and a token, so it stays opt-in.
    sonarEnabled: false, sonarMode: 'auto', sonarHostUrl: 'http://127.0.0.1:9000',
    sonarProjectKey: '', sonarToken: '', sonarIncludeCodeSmells: false,
    // Snyk needs an account and a token, so it stays opt-in as well. Only
    // Open Source is on by default: Code and IaC depend on the Snyk plan.
    snykEnabled: false, snykMode: 'auto', snykToken: '',
    snykIncludeOpenSource: true, snykIncludeCode: false, snykIncludeIaC: false,
    ...options
  };
}

function buildScans(workspacePath, policy, options, signal) {
  const scans = [{
    tool: 'Semgrep',
    execute: () => runSemgrep({ workspacePath, mode: options.semgrepMode, config: [options.semgrepConfig, policy?.semgrepCustomRules].filter(Boolean), exclusions: { files: [...(policy?.exclusions.global_files || []), ...(policy?.exclusions.semgrep_files || [])], rules: policy?.exclusions.semgrep_rules || [] }, targets: options.semgrepTargets || [], timeoutMs: options.timeoutMs, signal }),
    normalize: normalizeSemgrepOutput
  }, {
    tool: 'Gitleaks',
    execute: () => runGitleaks({ workspacePath, mode: options.gitleaksMode, history: options.gitleaksHistory ?? Boolean(policy?.gitleaksHistory), sinceCommit: options.gitleaksSinceCommit || '', configPath: policy?.gitleaksConfig || '', exclusions: policy?.exclusions.global_files || [], timeoutMs: options.timeoutMs, signal }),
    normalize: normalizeGitleaksOutput
  }, {
    tool: 'Trivy',
    execute: () => runTrivy({ workspacePath, mode: options.trivyMode, imageName: options.trivyImage, exclusions: [...(policy?.exclusions.global_files || []), ...(policy?.exclusions.trivy_files || [])], timeoutMs: options.timeoutMs, signal }),
    normalize: normalizeTrivyOutput
  }, {
    tool: 'OSV-Scanner',
    execute: () => runOsv({ workspacePath, timeoutMs: options.timeoutMs, signal }),
    normalize: normalizeOsvOutput
  }];
  // SonarQube joins the static phase and the shared scheduler, but only when it
  // is explicitly enabled: it is the one scanner that requires a live server.
  if (options.sonarEnabled) scans.push({
    tool: 'SonarQube',
    execute: () => runSonarQube({
      workspacePath,
      mode: policy?.sonarMode || options.sonarMode,
      hostUrl: options.sonarHostUrl,
      projectKey: options.sonarProjectKey,
      token: options.sonarToken,
      includeCodeSmells: options.sonarIncludeCodeSmells,
      exclusions: policy?.exclusions.global_files || [],
      timeoutMs: Math.max(options.timeoutMs, 900000),
      signal
    }),
    normalize: normalizeSonarQubeOutput
  });
  // Snyk joins the same static phase and the same scheduler. Enabled but
  // incomplete stays enabled: the runner reports the missing piece instead of
  // the pipeline silently dropping the scanner.
  if (options.snykEnabled) scans.push({
    tool: 'Snyk',
    execute: () => runSnyk({
      workspacePath,
      mode: policy?.snykMode || options.snykMode,
      token: options.snykToken,
      includeOpenSource: policy?.snykCapabilities?.includeOpenSource ?? options.snykIncludeOpenSource,
      includeCode: policy?.snykCapabilities?.includeCode ?? options.snykIncludeCode,
      includeIaC: policy?.snykCapabilities?.includeIaC ?? options.snykIncludeIaC,
      exclusions: policy?.exclusions.global_files || [],
      timeoutMs: options.timeoutMs,
      signal
    }),
    normalize: normalizeSnykOutput
  });
  const zapMode = policy?.zapOpenapi ? 'openapi' : policy?.zapActive ? 'active' : 'baseline';
  if (zapMode === 'baseline' || options.zapAuthorized) scans.push({
    tool: 'ZAP', dynamic: true,
    execute: () => runZap({ targetUrl: options.targetUrl, workspacePath, mode: zapMode, engine: policy?.zapEngine || 'auto', localPath: policy?.zapLocalPath || '', openapi: policy?.zapOpenapi || '', context: policy?.zapContext || '', user: policy?.zapUser || '', auth: policy?.zapAuth, excludedRoutes: policy?.exclusions.zap_routes || [], timeoutMs: options.timeoutMs, signal }),
    normalize: (payload, root) => normalizeZapOutput(payload, root, options.targetUrl)
  });
  const selected = new Set(options.selectedTools || []);
  return scans.filter((scan) => (!selected.size || selected.has(scan.tool)) && policy?.scanners[scan.tool] !== false);
}

async function runSecurityScan(input) {
  const workspacePath = path.resolve(input.workspacePath);
  const options = defaultOptions(input.options);
  const policy = input.policy || await loadProjectPolicy(workspacePath);
  const controller = new AbortController();
  if (input.signal) input.signal.addEventListener('abort', () => controller.abort(), { once: true });
  const scans = buildScans(workspacePath, policy, options, controller.signal);
  if (!scans.length) throw new Error('Aucun scanner actif.');
  const findings = [];
  const statuses = [];
  const failures = [];
  const notify = (event) => input.onScannerUpdate?.(event);
  const runOne = async (scan) => {
    const started = Date.now();
    notify({ tool: scan.tool, status: 'running' });
    try {
      const result = await scan.execute();
      const normalized = scan.normalize(result.payload, workspacePath);
      findings.push(...normalized);
      const status = { tool: scan.tool, status: 'completed', details: `${normalized.length} résultat(s)`, durationMs: Date.now() - started };
      statuses.push(status); notify(status);
    } catch (error) {
      const status = { tool: scan.tool, status: controller.signal.aborted ? 'cancelled' : 'failed', details: error.message, durationMs: Date.now() - started };
      statuses.push(status); failures.push(`${scan.tool}: ${error.message}`); notify(status);
    }
  };
  const staticScans = scans.filter((scan) => !scan.dynamic);
  await runWithConcurrency(staticScans, policy?.maxParallelScanners || 2, runOne, controller.signal);
  for (const scan of scans.filter((item) => item.dynamic)) if (!controller.signal.aborted) await runOne(scan);
  const deduplicated = deduplicateFindings(findings);
  const correlations = correlateFindings(deduplicated);
  const policyResult = evaluatePolicy(deduplicated, policy);
  return { workspace: workspacePath, findings: deduplicated, scanners: statuses, correlations, policyResult, failures, finishedAt: new Date().toISOString() };
}

module.exports = { defaultOptions, buildScans, runSecurityScan };
