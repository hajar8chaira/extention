'use strict';

/**
 * Unified read model over the normalized findings the scanners already produce.
 *
 * This layer never invents data. It exposes the fields every scanner *can*
 * supply under one vocabulary so the intelligence stages (correlation,
 * reachability, prioritization) stop re-deriving them from each scanner's own
 * shape. A field the scanner did not provide stays empty — a ZAP alert has no
 * source file unless a mapping actually proved one, and a dependency finding
 * carries no reachability until the reachability engine evaluated it.
 *
 * The original finding is preserved verbatim under `raw`.
 */

const path = require('path');

const CVE_PATTERN = /\b(CVE-\d{4}-\d{4,})\b/gi;
const GHSA_PATTERN = /\b(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b/gi;

function normalizePath(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

function uniqueUpper(values) {
  return [...new Set(values.map((value) => String(value || '').trim().toUpperCase()).filter(Boolean))];
}

/** Every CWE identifier the scanner attached, whatever field carried it. */
function cweList(finding) {
  const sources = [finding.cwe, ...(Array.isArray(finding.cwes) ? finding.cwes : [])];
  return uniqueUpper(String(sources.filter(Boolean).join(', ')).match(/CWE-\d+/gi) || []);
}

/**
 * Vulnerability identifiers, split so correlation can rely on the strong ones.
 * `ruleId` is included only when it actually *is* an identifier — a Semgrep
 * rule name must never be mistaken for a CVE.
 */
function vulnerabilityIds(finding) {
  const candidates = [
    finding.ruleId,
    ...(Array.isArray(finding.vulnerabilityAliases) ? finding.vulnerabilityAliases : []),
    ...(Array.isArray(finding.cves) ? finding.cves : [])
  ].filter(Boolean).join(' ');
  const cve = uniqueUpper(candidates.match(CVE_PATTERN) || []);
  const ghsa = uniqueUpper(candidates.match(GHSA_PATTERN) || []);
  // Vendor identifiers (SNYK-JS-…, GO-2024-…) are strong too, but only when the
  // scanner published them as a vulnerability alias rather than a rule name.
  const vendor = uniqueUpper((Array.isArray(finding.vulnerabilityAliases) ? finding.vulnerabilityAliases : [])
    .filter((alias) => /^(snyk|osv|go|rustsec|pysec|dsa|rhsa|usn)-/i.test(String(alias))));
  return { cve, ghsa, vendor };
}

/**
 * Ecosystem of a dependency finding. Derived only from what the scanner said or
 * from an unambiguous manifest name — never guessed from an arbitrary path.
 */
function ecosystemOf(finding) {
  const declared = String(finding.ecosystem || finding.packageManager || '').trim().toLowerCase();
  if (declared) {
    const aliases = {
      npm: 'npm', yarn: 'npm', pnpm: 'npm', 'node.js': 'npm', node: 'npm',
      pip: 'pypi', pypi: 'pypi', poetry: 'pypi', pipenv: 'pypi',
      maven: 'maven', gradle: 'maven', golang: 'go', go: 'go', gomodules: 'go',
      cargo: 'cargo', 'crates.io': 'cargo', rubygems: 'rubygems', bundler: 'rubygems',
      composer: 'composer', packagist: 'composer', nuget: 'nuget'
    };
    return aliases[declared] || declared;
  }
  const manifest = path.posix.basename(normalizePath(finding.file || finding.target || '')).toLowerCase();
  const byManifest = {
    'package-lock.json': 'npm', 'package.json': 'npm', 'yarn.lock': 'npm', 'pnpm-lock.yaml': 'npm',
    'requirements.txt': 'pypi', 'poetry.lock': 'pypi', 'pipfile.lock': 'pypi',
    'pom.xml': 'maven', 'build.gradle': 'maven', 'go.mod': 'go', 'go.sum': 'go',
    'cargo.lock': 'cargo', 'gemfile.lock': 'rubygems', 'composer.lock': 'composer'
  };
  return byManifest[manifest] || '';
}

/**
 * True only when the scanner pointed at a real position in a real file.
 *
 * Dependency findings name a manifest, not a line: Trivy and OSV both report
 * them at offset 0, which would otherwise surface as a confident
 * `package-lock.json:1`. A manifest position only counts when the scanner
 * genuinely resolved one.
 */
function hasSourceLocation(finding) {
  if (!finding.file || finding.unlocated || finding.absolutePath === '') return false;
  if (finding.category === 'dependency') return Number(finding.startLine) > 0;
  return Number(finding.startLine) >= 0;
}

/**
 * What the developer should do, as stated by the scanner. Never synthesised
 * from severity alone.
 */
function remediationOf(finding) {
  if (finding.solution) return String(finding.solution);
  if (finding.developerAction) return String(finding.developerAction);
  if (finding.fixedVersion && finding.packageName) {
    return `Mettre à niveau ${finding.packageName} vers ${finding.fixedVersion} ou une version ultérieure.`;
  }
  return '';
}

/**
 * Which high-level pipeline stage a finding belongs to. Snyk reports three
 * domains under one tool name, so its own capability decides.
 */
function stageOf(finding) {
  if (finding.category === 'secret') return 'secrets';
  if (finding.category === 'dependency') return 'sca';
  if (finding.category === 'misconfiguration') return 'iac';
  if (finding.category === 'dynamic' || finding.sourceContext === 'runtime') return 'dast';
  if (finding.category === 'license') return 'license';
  return 'sast';
}

function unifiedFinding(finding) {
  const identifiers = vulnerabilityIds(finding);
  const located = hasSourceLocation(finding);
  return {
    id: String(finding.id || ''),
    fingerprint: String(finding.fingerprint || finding.id || ''),
    tool: String(finding.tool || ''),
    stage: stageOf(finding),
    category: String(finding.category || ''),
    ruleId: String(finding.ruleId || ''),

    severity: String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase(),
    uiSeverity: String(finding.severity || ''),
    confidence: String(finding.confidence || '').toLowerCase(),

    cwe: cweList(finding),
    cve: identifiers.cve,
    vulnerabilityIds: [...identifiers.cve, ...identifiers.ghsa, ...identifiers.vendor],
    cvssScore: Number.isFinite(Number(finding.cvssScore)) ? Number(finding.cvssScore) : null,

    package: String(finding.packageName || ''),
    packageVersion: String(finding.installedVersion || ''),
    fixedVersion: String(finding.fixedVersion || ''),
    dependencyPath: Array.isArray(finding.dependencyPath) ? [...finding.dependencyPath] : [],
    ecosystem: ecosystemOf(finding),

    // Location is reported only when it was actually measured.
    file: located ? normalizePath(finding.file) : '',
    line: located ? Number(finding.startLine) + 1 : null,
    column: located ? Number(finding.startColumn) + 1 : null,
    manifest: finding.category === 'dependency' ? normalizePath(finding.file || finding.target || '') : '',

    endpoint: String(finding.endpoint || ''),
    method: String(finding.method || ''),
    parameter: String(finding.parameter || ''),

    image: String(finding.imageName || finding.dockerImage || ''),
    resource: String(finding.resource || ''),

    title: String(finding.title || ''),
    description: String(finding.description || ''),
    evidence: String(finding.evidence || ''),
    remediation: remediationOf(finding),
    fixAvailable: Boolean(finding.fixedVersion || finding.autofix || finding.isUpgradable),

    sourceContext: String(finding.sourceContext || ''),
    triageStatus: String(finding.triageStatus || ''),
    sourceScannerIds: [String(finding.id || '')],

    // Filled in by the later stages; deliberately absent here.
    correlation: null,
    reachability: null,
    priority: null,

    raw: finding
  };
}

function unifyFindings(findings = []) {
  return findings.filter(Boolean).map(unifiedFinding);
}

module.exports = {
  unifiedFinding, unifyFindings, cweList, vulnerabilityIds, ecosystemOf,
  hasSourceLocation, remediationOf, stageOf, normalizePath
};
