const fs = require('fs/promises');
const path = require('path');
const { runSemgrep } = require('../src/semgrep');
const { runGitleaks } = require('../src/gitleaks');
const { runTrivy } = require('../src/trivy');
const { runOsv } = require('../src/osv');
const { runZap } = require('../src/zap');
const {
  normalizeSemgrepOutput, normalizeGitleaksOutput, normalizeTrivyOutput,
  normalizeOsvOutput, normalizeZapOutput, deduplicateFindings
} = require('../src/findings');
const { correlateFindings } = require('../src/correlation');
const { saveScanResult } = require('../src/backend');

async function main() {
  const workspacePath = path.resolve(process.argv[2] || path.join(__dirname, '..', '..', 'test-application', 'juice-shop'));
  const reportRoot = path.resolve(process.argv[3] || path.join(__dirname, '..', '..', 'security-reports'));
  const backendUrl = process.env.SECURITY_CENTER_BACKEND || 'http://127.0.0.1:8765';
  const targetUrl = process.env.SECURITY_CENTER_ZAP_TARGET || 'http://127.0.0.1:3000';
  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const reportDirectory = path.join(reportRoot, runId);
  await fs.mkdir(reportDirectory, { recursive: true });

  const definitions = [
    ['Semgrep', () => runSemgrep({ workspacePath, mode: 'docker', config: 'p/security-audit', timeoutMs: 900000 }), normalizeSemgrepOutput],
    ['Gitleaks', () => runGitleaks({ workspacePath, mode: 'docker', timeoutMs: 900000 }), normalizeGitleaksOutput],
    ['Trivy', () => runTrivy({ workspacePath, mode: 'docker', timeoutMs: 900000 }), normalizeTrivyOutput],
    ['OSV-Scanner', () => runOsv({ workspacePath, timeoutMs: 900000 }), normalizeOsvOutput],
    ['ZAP', () => runZap({ targetUrl, timeoutMs: 900000 }), (payload, root) => normalizeZapOutput(payload, root, targetUrl)]
  ];
  const findings = [];
  const scanners = [];
  for (const [tool, execute, normalize] of definitions) {
    const startedAt = Date.now();
    process.stdout.write(`${tool}: running\n`);
    try {
      const result = await execute();
      const normalized = normalize(result.payload, workspacePath);
      findings.push(...normalized);
      scanners.push({ tool, status: 'completed', details: `${normalized.length} résultat(s)`, durationMs: Date.now() - startedAt });
      await fs.writeFile(path.join(reportDirectory, `${tool.toLowerCase().replace(/[^a-z]+/g, '-')}.raw.json`), JSON.stringify(result.payload, null, 2));
      process.stdout.write(`${tool}: ${normalized.length} finding(s)\n`);
    } catch (error) {
      scanners.push({ tool, status: 'failed', error: error.message, durationMs: Date.now() - startedAt });
      process.stdout.write(`${tool}: FAILED - ${error.message}\n`);
    }
  }
  const correlated = correlateFindings(deduplicateFindings(findings));
  const result = { workspace: workspacePath, findings: correlated.findings, scanners, correlations: correlated.correlations };
  const stored = await saveScanResult(backendUrl, result);
  const summary = {
    scanId: stored.scan_id,
    workspace: workspacePath,
    total: correlated.findings.length,
    byTool: Object.fromEntries(definitions.map(([tool]) => [tool, correlated.findings.filter((item) => item.tool === tool).length])),
    bySeverity: correlated.findings.reduce((counts, item) => ({ ...counts, [item.rawSeverity]: (counts[item.rawSeverity] || 0) + 1 }), {}),
    correlations: correlated.correlations.length,
    scanners
  };
  await fs.writeFile(path.join(reportDirectory, 'normalized.json'), JSON.stringify(result, null, 2));
  await fs.writeFile(path.join(reportDirectory, 'summary.json'), JSON.stringify(summary, null, 2));
  process.stdout.write(`${JSON.stringify({ reportDirectory, ...summary }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
