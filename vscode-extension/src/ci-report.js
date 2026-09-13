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

const fs = require('fs');
const path = require('path');

/**
 * Bumped only when the shape changes in a way a reader must know about.
 * `verdict`, `stages` and the supply-chain paths were added as optional fields:
 * a reader of schema 1 that ignores them keeps working.
 */
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
  return (report.scanners || []).map((scanner) => {
    const status = String(scanner.status || 'unknown');
    // The orchestrator records a failure's reason in `details`; `error` is kept
    // for producers that use it. A completed scanner's details are not an error.
    const reason = scanner.error || (['failed', 'cancelled'].includes(status) ? scanner.details : '');
    return {
      name: String(scanner.tool || ''),
      status,
      findings: (report.findings || []).filter((finding) => finding.tool === scanner.tool).length,
      // A scanner error is a short summary, never a stack trace or a command line.
      error: reason ? String(reason).slice(0, 300) : ''
    };
  });
}

/** The tool a failure names: `{ tool }`, or the orchestrator's « Tool: reason ». */
function failedScannerName(failure) {
  if (failure && typeof failure === 'object') return String(failure.tool || '');
  return String(failure || '').split(':')[0].trim();
}

/** A path as it appears in the build's workspace, never the agent's absolute path. */
function workspaceRelative(workspace, file) {
  const absolute = path.resolve(String(file));
  if (workspace) {
    const relative = path.relative(path.resolve(String(workspace)), absolute);
    if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) return relative.split(path.sep).join('/');
  }
  return path.basename(absolute);
}

/**
 * One piece of supply-chain evidence.
 *
 * A produced status (`generated`, `signed`, `verified`) is only reported when
 * the file it names exists on disk. Otherwise it is `missing`: a record that
 * says « signed » about a signature nobody can archive is not evidence.
 */
function evidenceFrom(record, files, { workspace, exists }) {
  if (!record?.status) return { status: null, path: null };
  const status = String(record.status);
  if (!['generated', 'signed', 'verified'].includes(status)) return { status, path: null };
  const paths = files.map((file) => (file ? String(file) : ''));
  if (!paths[0] || paths.some((file) => !file || !exists(file))) return { status: 'missing', path: null };
  return { status, path: workspaceRelative(workspace, paths[0]) };
}

/** Supply-chain statuses, only for stages that ran, backed by real files. */
function supplyChainFrom(artifacts, { workspace = '', exists = fs.existsSync } = {}) {
  const empty = { sbom: null, provenance: null, signature: null, signatureVerified: false, sbomPath: null, provenancePath: null, signaturePath: null };
  if (!artifacts || typeof artifacts !== 'object') return empty;
  const options = { workspace, exists };
  const sbom = evidenceFrom(artifacts.sbom, [artifacts.sbom?.path], options);
  const provenance = evidenceFrom(artifacts.provenance, [artifacts.provenance?.path], options);
  // A signature is evidence only when the bundle and the file it signs both exist.
  const signature = evidenceFrom(artifacts.signing, [artifacts.signing?.signaturePath, artifacts.signing?.artifact], options);
  return {
    sbom: sbom.status,
    provenance: provenance.status,
    signature: signature.status,
    // Verification the build itself established, on a bundle that exists.
    signatureVerified: signature.status === 'verified',
    sbomPath: sbom.path,
    provenancePath: provenance.path,
    signaturePath: signature.path
  };
}

/** The states `describeStages` produces. Anything else is reported as unknown. */
const STAGE_STATES = Object.freeze(['not_configured', 'ready', 'running', 'passed', 'warning', 'blocked', 'skipped', 'failed']);

/**
 * The Security Center stages of this run, copied from `pipeline.stages`.
 *
 * These are the engine's own stages (Secrets, SAST, SCA, Policy Gate, SBOM…),
 * not Jenkins stages. `null` when the pipeline did not run (`--no-intelligence`):
 * absent stays absent.
 */
function stagesFrom(pipeline) {
  if (!Array.isArray(pipeline?.stages)) return null;
  return pipeline.stages.slice(0, 30).map((stage) => ({
    id: String(stage?.id || ''),
    label: String(stage?.label || stage?.id || ''),
    kind: String(stage?.kind || ''),
    state: STAGE_STATES.includes(stage?.state) ? stage.state : 'unknown',
    count: Number.isFinite(stage?.count) ? stage.count : null,
    detail: stage?.detail ? String(stage.detail).slice(0, 300) : ''
  }));
}

/** The CLI verdict names and the exit code each one means. */
const VERDICT_EXIT_CODES = Object.freeze({ PASS: 0, BLOCK: 1, ERROR: 2 });

function verdictFrom(verdict) {
  const status = String(verdict?.status || '');
  return status in VERDICT_EXIT_CODES ? { status, exitCode: VERDICT_EXIT_CODES[status] } : null;
}

/**
 * Builds the CI report from a CLI result.
 *
 * `commit` and `branch` are supplied by the caller because git is the caller's
 * concern; when they are unknown they stay `null` rather than being guessed.
 */
function buildCiReport(report = {}, {
  commit = '', branch = '', generatedAt = new Date().toISOString(),
  verdict = null, workspace = report.workspace || '', exists = fs.existsSync, engine = null
} = {}) {
  const gate = report.policyGate || null;
  const pipeline = report.pipeline || null;
  const findings = report.findings || [];
  const failures = report.failures || [];
  return {
    schemaVersion: CI_REPORT_SCHEMA,
    generatedAt,
    // The CLI's own decision, the one its exit code carries. `null` when the
    // producer did not state it; never recomputed here.
    verdict: verdictFrom(verdict),
    // Which CI Engine wrote this report, so a reader can tell its version.
    engine: engineFrom(engine),
    execution: {
      scanId: String(pipeline?.scanId || ''),
      // `partial` is a real outcome: some scanner never reported, so the totals
      // below are incomplete and a reader must not treat them as exhaustive.
      status: failures.length ? 'partial' : (pipeline ? String(pipeline.status || 'completed') : 'completed'),
      failedScanners: failures.map(failedScannerName).filter(Boolean)
    },
    stages: stagesFrom(pipeline),
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
        reasons: reasonsFrom(gate),
        // Legacy rules the gate supersedes, named rather than silently dropped.
        legacyNotice: String(report.policyNotice || '')
      }
      : { status: 'NOT_CONFIGURED', configured: false, blockingCount: 0, warningCount: 0, summary: '', reasons: [], legacyNotice: String(report.policyNotice || '') },
    scanners: scannersFrom(report),
    summary: summarize(findings),
    intelligence: {
      // Copied from the summaries the engines produced. Absent stays absent.
      correlation: pipeline?.correlationSummary?.total ?? null,
      reachability: pipeline?.reachabilitySummary?.analysed ? pipeline.reachabilitySummary.counts || null : null,
      prioritization: pipeline?.prioritySummary?.distribution || null
    },
    supplyChain: supplyChainFrom(pipeline?.artifacts, { workspace, exists })
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
      // Optional: reports written before these fields existed stay valid.
      verdict: verdictFrom(clean.verdict),
      engine: engineFrom(clean.engine),
      execution: {
        scanId: clean.execution.scanId ? String(clean.execution.scanId) : null,
        status: clean.execution.status ? String(clean.execution.status) : 'unknown',
        failedScanners: Array.isArray(clean.execution.failedScanners) ? clean.execution.failedScanners.map(String) : [],
        // Why the execution could not happen (e.g. CI Engine bootstrap failure).
        error: clean.execution.error ? String(clean.execution.error).slice(0, 300) : ''
      },
      stages: stagesFrom({ stages: clean.stages }),
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
        legacyNotice: String(clean.policy.legacyNotice || '').slice(0, 300),
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
        signatureVerified: clean.supplyChain?.signatureVerified === true && clean.supplyChain?.signature === 'verified',
        sbomPath: archivedPath(clean.supplyChain?.sbomPath),
        provenancePath: archivedPath(clean.supplyChain?.provenancePath),
        signaturePath: archivedPath(clean.supplyChain?.signaturePath)
      }
    }
  };
}

/** The delivery record the Jenkins pipeline archives next to the CI report. */
const DELIVERY_RECORD_FILENAME = 'security-center-delivery.json';
const DEPLOYMENT_STATUSES = Object.freeze(['SUCCEEDED', 'FAILED', 'SKIPPED', 'NOT_CONFIGURED']);
const HEALTH_CHECK_STATUSES = Object.freeze(['PASSED', 'FAILED', 'SKIPPED', 'NOT_CONFIGURED']);

/**
 * Validates the deployment / health-check record fetched from Jenkins.
 *
 * Untrusted input like the CI report: size-capped, parsed defensively, stripped
 * of polluting keys. An unknown status is rejected or left null — never mapped
 * to a success.
 */
function validateDeliveryRecord(input, { maxBytes = 64 * 1024 } = {}) {
  if (input === null || input === undefined || input === '') return { ok: false, reason: 'Enregistrement de livraison absent.' };
  let parsed = input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > maxBytes) return { ok: false, reason: 'Enregistrement de livraison trop volumineux.' };
    try { parsed = JSON.parse(input); } catch { return { ok: false, reason: 'Enregistrement de livraison illisible : JSON invalide.' }; }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, reason: 'Enregistrement de livraison illisible.' };
  const clean = stripPollution(parsed);
  if (Number(clean.schemaVersion) !== 1) {
    return { ok: false, reason: `Version d’enregistrement de livraison non prise en charge : ${clean.schemaVersion ?? 'absente'}.` };
  }
  const deploymentStatus = String(clean.deployment?.status || '');
  if (!DEPLOYMENT_STATUSES.includes(deploymentStatus)) return { ok: false, reason: 'Statut de déploiement inconnu.' };
  const healthStatus = String(clean.healthCheck?.status || '');
  return {
    ok: true,
    record: {
      verdict: verdictFrom({ status: clean.verdict }),
      engineReady: clean.engineReady === true,
      deployment: { status: deploymentStatus, reason: String(clean.deployment?.reason || '').slice(0, 300) },
      healthCheck: HEALTH_CHECK_STATUSES.includes(healthStatus)
        ? { status: healthStatus, detail: String(clean.healthCheck?.detail || '').slice(0, 300) }
        : null
    }
  };
}

const ENGINE_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** The engine that wrote the report. An unparsable version stays null, never guessed. */
function engineFrom(engine) {
  if (!engine || typeof engine !== 'object') return null;
  const name = typeof engine.name === 'string' ? engine.name.slice(0, 100) : '';
  const version = typeof engine.version === 'string' && ENGINE_VERSION_PATTERN.test(engine.version) ? engine.version : null;
  // The build's source commit, when the engine was built by the Security Center pipeline.
  const commit = typeof engine.commit === 'string' && /^[0-9a-f]{40}$/.test(engine.commit) ? engine.commit : null;
  return name || version ? { name, version, commit } : null;
}

/** A workspace-relative artefact path from untrusted input, or null. */
function archivedPath(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text || text.length > 300 || path.isAbsolute(text) || /^[A-Za-z]:/.test(text)) return null;
  if (text.split(/[\\/]/).includes('..')) return null;
  return text;
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
  supplyChainFrom, stagesFrom, verdictFrom, engineFrom, archivedPath, findForbiddenKeys, STAGE_STATES, VERDICT_EXIT_CODES,
  DELIVERY_RECORD_FILENAME, DEPLOYMENT_STATUSES, HEALTH_CHECK_STATUSES, validateDeliveryRecord
};
