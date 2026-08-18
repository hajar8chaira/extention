'use strict';

/**
 * The CI report contract.
 *
 * A projection of the result Security Center already produced — not a second
 * result model. Nothing here evaluates a policy, correlates a finding or counts
 * a severity a second time: every value is copied from the CLI report, which is
 * the historical truth of what the build actually decided.
 *
 * Two things shape the contract:
 *
 *   - It is deliberately small. Full findings are not included. A Gitleaks
 *     finding can carry a matched secret and a ZAP finding can carry request
 *     evidence; an artefact archived on a CI server and downloaded by every
 *     developer is the worst place for either. Only counts, statuses and the
 *     gate's own reasons travel.
 *
 *   - It is validated on the way back in. An artefact fetched from Jenkins is
 *     untrusted input: it is size-capped, JSON-parsed defensively, checked
 *     against the schema version and stripped of prototype-polluting keys before
 *     anything reads it.
 */

/** Bumped only when the shape changes in a way a reader must know about. */
const CI_REPORT_SCHEMA = 1;

/** The conventional artefact name the Jenkinsfile archives. */
const CI_REPORT_FILENAME = 'security-center-report.json';

/**
 * A CI report is a summary. Two megabytes is far beyond what the contract needs
 * and well below what would stall the extension.
 */
const MAX_CI_REPORT_BYTES = 2 * 1024 * 1024;

/** Keys that must never survive a JSON.parse of untrusted input. */
const POLLUTING_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);

const SEVERITY_BUCKETS = Object.freeze(['critical', 'high', 'medium', 'low']);

function severityOf(finding) {
  return String(finding?.rawSeverity || finding?.severity || '').toUpperCase();
}

/** Severity counts, from the findings the run really produced. */
function summarize(findings = []) {
  const counts = { findings: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    const severity = severityOf(finding);
    if (severity === 'CRITICAL') counts.critical += 1;
    else if (severity === 'HIGH' || severity === 'ERROR') counts.high += 1;
    else if (severity === 'MEDIUM' || severity === 'WARNING') counts.medium += 1;
    else if (severity === 'LOW') counts.low += 1;
  }
  return counts;
}

/**
 * The gate's blocking reasons, reduced to what is safe to publish.
 *
 * The rule, the title and the location travel. The matched value never does —
 * `formatGateResult` already established that a secret can be reported without
 * being reprinted, and the same holds for an artefact.
 */
function reasonsFrom(gate) {
  return (gate?.violations || []).slice(0, 50).map((violation) => ({
    code: String(violation.code || ''),
    rule: String(violation.rule || ''),
    title: String(violation.title || violation.message || ''),
    severity: String(violation.severity || ''),
    file: String(violation.file || ''),
    line: Number.isFinite(violation.line) ? violation.line : null,
    priority: Number.isFinite(violation.priority) ? violation.priority : null
  }));
}

/** Scanner outcomes, so CI can show which tool never reported. */
function scannersFrom(report) {
  return (report.scanners || []).map((scanner) => ({
    name: String(scanner.tool || ''),
    status: String(scanner.status || 'unknown'),
    findings: (report.findings || []).filter((finding) => finding.tool === scanner.tool).length,
    // A scanner error is a short summary, never a stack trace or a command line.
    error: scanner.error ? String(scanner.error).slice(0, 300) : ''
  }));
}

/** Supply-chain statuses, only for stages that ran. */
function supplyChainFrom(artifacts) {
  if (!artifacts || typeof artifacts !== 'object') return { sbom: null, provenance: null, signature: null };
  const status = (value) => (value?.status ? String(value.status) : null);
  return {
    sbom: status(artifacts.sbom),
    provenance: status(artifacts.provenance),
    signature: status(artifacts.signing),
    // Verification metadata the build itself established, if any.
    signatureVerified: artifacts.signing?.status === 'verified'
  };
}

/**
 * Builds the CI report from a CLI result.
 *
 * `commit` and `branch` are supplied by the caller because git is the caller's
 * concern; when they are unknown they stay `null` rather than being guessed.
 */
function buildCiReport(report = {}, { commit = '', branch = '', generatedAt = new Date().toISOString() } = {}) {
  const gate = report.policyGate || null;
  const pipeline = report.pipeline || null;
  const findings = report.findings || [];
  const failures = report.failures || [];
  return {
    schemaVersion: CI_REPORT_SCHEMA,
    generatedAt,
    execution: {
      scanId: String(pipeline?.scanId || ''),
      // `partial` is a real outcome: some scanner never reported, so the totals
      // below are incomplete and a reader must not treat them as exhaustive.
      status: failures.length ? 'partial' : (pipeline ? String(pipeline.status || 'completed') : 'completed'),
      failedScanners: failures.map((failure) => String(failure.tool || failure || '')).filter(Boolean)
    },
    repository: {
      commit: commit ? String(commit) : null,
      branch: branch ? String(branch) : null
    },
    policy: gate
      ? {
        status: String(gate.status || ''),
        configured: gate.configured === true,
        blockingCount: (gate.violations || []).length,
        warningCount: (gate.warnings || []).length,
        summary: String(gate.summary || ''),
        reasons: reasonsFrom(gate)
      }
      : { status: 'NOT_CONFIGURED', configured: false, blockingCount: 0, warningCount: 0, summary: '', reasons: [] },
    scanners: scannersFrom(report),
    summary: summarize(findings),
    intelligence: {
      // Copied from the summaries the engines produced. Absent stays absent.
      correlation: pipeline?.correlationSummary?.total ?? null,
      reachability: pipeline?.reachabilitySummary?.analysed ? pipeline.reachabilitySummary.counts || null : null,
      prioritization: pipeline?.prioritySummary?.distribution || null
    },
    supplyChain: supplyChainFrom(pipeline?.artifacts)
  };
}

/** Removes polluting keys at every depth before anything reads the object. */
function stripPollution(value, depth = 0) {
  if (depth > 12 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => stripPollution(item, depth + 1));
  const clean = Object.create(null);
  for (const [key, item] of Object.entries(value)) {
    if (POLLUTING_KEYS.includes(key)) continue;
    clean[key] = stripPollution(item, depth + 1);
  }
  // Back to a plain object so callers can spread and serialize it normally.
  return { ...clean };
}

/**
 * Validates an artefact fetched from Jenkins.
 *
 * Returns `{ ok, report, reason }` rather than throwing: a malformed artefact is
 * a state the page must describe, not a crash. Never returns a partially
 * accepted report — an unrecognised schema is rejected outright, because reading
 * it with today's assumptions is how a wrong verdict gets displayed.
 */
function validateCiReport(input, { maxBytes = MAX_CI_REPORT_BYTES } = {}) {
  if (input === null || input === undefined || input === '') return { ok: false, reason: 'Rapport absent.' };
  let parsed = input;
  if (typeof input === 'string') {
    const size = Buffer.byteLength(input, 'utf8');
    if (size > maxBytes) {
      return { ok: false, reason: `Rapport trop volumineux (${Math.round(size / 1024)} Kio, maximum ${Math.round(maxBytes / 1024)} Kio).` };
    }
    try { parsed = JSON.parse(input); }
    catch { return { ok: false, reason: 'Rapport illisible : JSON invalide.' }; }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'Rapport illisible : objet JSON attendu.' };
  }
  const clean = stripPollution(parsed);
  if (Number(clean.schemaVersion) !== CI_REPORT_SCHEMA) {
    return { ok: false, reason: `Version de schéma non prise en charge : ${clean.schemaVersion ?? 'absente'} (attendue ${CI_REPORT_SCHEMA}).` };
  }
  if (!clean.policy || typeof clean.policy !== 'object') return { ok: false, reason: 'Rapport incomplet : verdict de politique absent.' };
  if (!clean.execution || typeof clean.execution !== 'object') return { ok: false, reason: 'Rapport incomplet : identité de scan absente.' };
  if (!Array.isArray(clean.scanners)) return { ok: false, reason: 'Rapport incomplet : liste des scanners absente.' };
  // Normalized to the exact shape the page reads, so a field the producer omitted
  // cannot surface as `undefined` in the UI.
  return {
    ok: true,
    report: {
      schemaVersion: CI_REPORT_SCHEMA,
      generatedAt: clean.generatedAt ? String(clean.generatedAt) : null,
      execution: {
        scanId: clean.execution.scanId ? String(clean.execution.scanId) : null,
        status: clean.execution.status ? String(clean.execution.status) : 'unknown',
        failedScanners: Array.isArray(clean.execution.failedScanners) ? clean.execution.failedScanners.map(String) : []
      },
      repository: {
        commit: clean.repository?.commit ? String(clean.repository.commit) : null,
        branch: clean.repository?.branch ? String(clean.repository.branch) : null
      },
      policy: {
        status: String(clean.policy.status || 'NOT_CONFIGURED'),
        configured: clean.policy.configured === true,
        blockingCount: Number(clean.policy.blockingCount) || 0,
        warningCount: Number(clean.policy.warningCount) || 0,
        summary: String(clean.policy.summary || ''),
        reasons: Array.isArray(clean.policy.reasons) ? clean.policy.reasons.slice(0, 50).map((reason) => ({
          code: String(reason?.code || ''), rule: String(reason?.rule || ''),
          title: String(reason?.title || ''), severity: String(reason?.severity || ''),
          file: String(reason?.file || ''),
          line: Number.isFinite(reason?.line) ? reason.line : null,
          priority: Number.isFinite(reason?.priority) ? reason.priority : null
        })) : []
      },
      scanners: clean.scanners.slice(0, 40).map((scanner) => ({
        name: String(scanner?.name || ''), status: String(scanner?.status || 'unknown'),
        findings: Number(scanner?.findings) || 0,
        error: scanner?.error ? String(scanner.error).slice(0, 300) : ''
      })),
      summary: Object.fromEntries(['findings', ...SEVERITY_BUCKETS].map((key) => [key, Number(clean.summary?.[key]) || 0])),
      intelligence: {
        correlation: Number.isFinite(clean.intelligence?.correlation) ? clean.intelligence.correlation : null,
        reachability: clean.intelligence?.reachability && typeof clean.intelligence.reachability === 'object' ? clean.intelligence.reachability : null,
        prioritization: clean.intelligence?.prioritization && typeof clean.intelligence.prioritization === 'object' ? clean.intelligence.prioritization : null
      },
      supplyChain: {
        sbom: clean.supplyChain?.sbom ? String(clean.supplyChain.sbom) : null,
        provenance: clean.supplyChain?.provenance ? String(clean.supplyChain.provenance) : null,
        signature: clean.supplyChain?.signature ? String(clean.supplyChain.signature) : null,
        signatureVerified: clean.supplyChain?.signatureVerified === true
      }
    }
  };
}

/**
 * No secret may ever reach an archived artefact.
 *
 * Used as a last check before writing and as a regression guard in tests: the
 * contract carries counts and statuses, so any credential-shaped key in it is a
 * defect, not a feature.
 */
const FORBIDDEN_REPORT_KEY = /^(authorization|cookie|set-cookie|token|api[-_]?key|secret|password|passwd|jwt|bearer|private[-_]?key)$/i;

function findForbiddenKeys(value, trail = [], found = []) {
  if (!value || typeof value !== 'object' || trail.length > 12) return found;
  if (Array.isArray(value)) {
    value.forEach((item, index) => findForbiddenKeys(item, [...trail, String(index)], found));
    return found;
  }
  for (const [key, item] of Object.entries(value)) {
    if (FORBIDDEN_REPORT_KEY.test(key)) found.push([...trail, key].join('.'));
    findForbiddenKeys(item, [...trail, key], found);
  }
  return found;
}

module.exports = {
  CI_REPORT_SCHEMA, CI_REPORT_FILENAME, MAX_CI_REPORT_BYTES, POLLUTING_KEYS, FORBIDDEN_REPORT_KEY,
  buildCiReport, validateCiReport, stripPollution, summarize, reasonsFrom, scannersFrom,
  supplyChainFrom, findForbiddenKeys
};
