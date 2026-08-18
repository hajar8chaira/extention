'use strict';

/**
 * Unified fix verification.
 *
 * One lifecycle for every finding, whatever produced the fix. The invariant it
 * exists to enforce is small and absolute: **applying a patch is not evidence
 * that a vulnerability is gone**. Neither is an AI returning a diff, nor an HTTP
 * status changing, nor a developer clicking "fixed". Only re-running the thing
 * that found the issue — and observing that the *same* finding is no longer
 * there — makes a fix VALIDATED.
 *
 * This module decides and interprets. It does not run scanners: verifiers are
 * injected, which is what lets the whole lifecycle be tested without Docker, a
 * network, or a live target, and what keeps scanner semantics untouched.
 *
 * It deliberately reuses the existing status vocabulary from `triage.js` rather
 * than introducing a second finding model. `fixed` and `validated` keep their
 * persisted spelling; the new states are the ones that were missing.
 */

const { findingKey, normalizeStatus } = require('./triage');

/**
 * The lifecycle.
 *
 * `FIX_APPLIED` is spelled `fixed` on disk because that is what every existing
 * cache, backend record and workspace state already contains. What changes is
 * its *meaning*: it now says « a fix was applied, verification pending » and is
 * never displayed as a validated result.
 */
const VERIFICATION_STATE = Object.freeze({
  OPEN: 'new',
  FIX_PROPOSED: 'fix_proposed',
  FIX_APPLIED: 'fixed',
  VALIDATING: 'validating',
  VALIDATED: 'validated',
  STILL_PRESENT: 'still_present',
  VALIDATION_FAILED: 'validation_failed',
  INCONCLUSIVE: 'inconclusive',
  REGRESSED: 'regressed'
});

/** Statuses that carry a developer decision rather than a verification result. */
const DECISION_STATES = Object.freeze(['false_positive', 'accepted']);

const STATE_LABELS = Object.freeze({
  new: 'Ouverte',
  fix_proposed: 'Correction proposée',
  fixed: 'Correction appliquée — vérification en attente',
  validating: 'Vérification en cours…',
  validated: '✓ Validée',
  still_present: '✕ Toujours présente',
  validation_failed: 'Vérification impossible',
  inconclusive: '? Non concluant',
  regressed: '⚠ Réapparue après validation',
  false_positive: 'Faux positif',
  accepted: 'Risque accepté'
});

/** Why a verification ended where it did. Always shown next to the state. */
const VERIFICATION_REASON = Object.freeze({
  ABSENT_AFTER_RESCAN: 'absent_after_rescan',
  PRESENT_AFTER_RESCAN: 'present_after_rescan',
  RETEST_EVIDENCE_GONE: 'retest_evidence_gone',
  RETEST_EVIDENCE_PRESENT: 'retest_evidence_present',
  NO_VERIFIER: 'no_verifier',
  SCANNER_UNAVAILABLE: 'scanner_unavailable',
  SCANNER_INCOMPLETE: 'scanner_incomplete',
  CANCELLED: 'cancelled',
  TIMEOUT: 'timeout',
  VALIDATOR_ERROR: 'validator_error',
  NOT_APPLIED: 'not_applied'
});

const REASON_LABELS = Object.freeze({
  absent_after_rescan: 'Le même finding n’apparaît plus après une nouvelle analyse.',
  present_after_rescan: 'Le même finding est toujours signalé après une nouvelle analyse.',
  retest_evidence_gone: 'La preuve relevée par le scanner n’apparaît plus lors du re-test.',
  retest_evidence_present: 'La preuve relevée par le scanner est toujours présente lors du re-test.',
  no_verifier: 'Aucun vérificateur sûr n’existe pour ce type de finding.',
  scanner_unavailable: 'Le scanner nécessaire n’est pas disponible.',
  scanner_incomplete: 'L’analyse de vérification ne s’est pas terminée.',
  cancelled: 'La vérification a été annulée.',
  timeout: 'La vérification a dépassé son délai.',
  validator_error: 'Le vérificateur a échoué.',
  not_applied: 'Aucune correction n’a encore été appliquée.'
});

/**
 * How a fix reached the code. Recorded because « who wrote the patch » and
 * « was it verified » are separate questions, and conflating them is exactly the
 * failure this module prevents.
 */
const FIX_SOURCE = Object.freeze({
  QUICK_FIX: 'quick_fix',
  AI: 'ai',
  MANUAL: 'manual'
});

/** The verifier families. One per way of obtaining evidence, not one per tool. */
const VERIFIER = Object.freeze({
  SAST_RESCAN: 'sast_rescan',
  SECRET_RESCAN: 'secret_rescan',
  SCA_RESCAN: 'sca_rescan',
  IAC_RESCAN: 'iac_rescan',
  DAST_RETEST: 'dast_retest',
  NONE: 'none'
});

const TOOL_VERIFIER = Object.freeze({
  SEMGREP: VERIFIER.SAST_RESCAN,
  SONARQUBE: VERIFIER.SAST_RESCAN,
  GITLEAKS: VERIFIER.SECRET_RESCAN,
  'OSV-SCANNER': VERIFIER.SCA_RESCAN,
  ZAP: VERIFIER.DAST_RETEST
});

/**
 * Which verifier can produce evidence for this finding.
 *
 * Trivy and Snyk each cover two families, so the category decides: a
 * misconfiguration is re-read from configuration files, a vulnerable dependency
 * from the manifest. A finding whose tool cannot be re-run safely gets no
 * verifier at all — and that is reported as INCONCLUSIVE rather than papered over.
 */
function verificationStrategyFor(finding) {
  const tool = String(finding?.tool || '').toUpperCase();
  const category = String(finding?.category || '').toLowerCase();
  if (category === 'dynamic' || tool === 'ZAP') {
    return { verifier: VERIFIER.DAST_RETEST, tool: finding?.tool || 'ZAP' };
  }
  if (tool === 'TRIVY' || tool === 'SNYK') {
    return {
      verifier: category === 'misconfiguration' ? VERIFIER.IAC_RESCAN : VERIFIER.SCA_RESCAN,
      tool: finding.tool
    };
  }
  const known = TOOL_VERIFIER[tool];
  if (known) return { verifier: known, tool: finding.tool };
  return { verifier: VERIFIER.NONE, tool: finding?.tool || '' };
}

/**
 * The identity two scans are compared on.
 *
 * Reuses the existing fingerprint whenever a scanner supplies one — Gitleaks,
 * SonarQube and Snyk all do — and falls back to the same composite the scan
 * comparison already uses. Titles are never part of it: two different findings
 * can share a title, and a scanner rewording a message must not read as a fix.
 */
function verificationIdentity(finding) {
  if (!finding) return '';
  if (finding.fingerprint) return String(finding.fingerprint);
  if (finding.id) return String(finding.id);
  const tool = String(finding.tool || '').toUpperCase();
  if (tool === 'ZAP' || String(finding.category || '') === 'dynamic') {
    return [tool, finding.ruleId || '', finding.method || '', finding.endpoint || '', finding.parameter || ''].join('|');
  }
  return [
    tool, finding.ruleId || '', finding.file || finding.endpoint || '',
    finding.startLine ?? '', finding.parameter || ''
  ].join('|');
}

/** True when the scan that must supply the evidence actually finished. */
function toolCompleted(scannerStatuses, tool) {
  const wanted = String(tool || '').toUpperCase();
  return (Array.isArray(scannerStatuses) ? scannerStatuses : [])
    .some((scanner) => String(scanner?.tool || '').toUpperCase() === wanted && scanner?.status === 'completed');
}

function toolState(scannerStatuses, tool) {
  const wanted = String(tool || '').toUpperCase();
  const entry = (Array.isArray(scannerStatuses) ? scannerStatuses : [])
    .find((scanner) => String(scanner?.tool || '').toUpperCase() === wanted);
  return entry?.status || '';
}

/**
 * Reads a rescan result into a verdict.
 *
 * The order of the checks is the safety property. An unavailable or unfinished
 * scanner is answered *before* the absence check, because "the scanner never
 * ran" and "the finding is gone" produce the same empty list — and treating the
 * first as the second would manufacture a validation out of a failure.
 */
function interpretRescan({ finding, findings = [], scannerStatuses = [], tool = '' } = {}) {
  const targetTool = tool || finding?.tool || '';
  const state = toolState(scannerStatuses, targetTool);
  if (state === 'unavailable' || state === 'not_installed') {
    return { outcome: VERIFICATION_STATE.VALIDATION_FAILED, reason: VERIFICATION_REASON.SCANNER_UNAVAILABLE };
  }
  if (state === 'cancelled') {
    return { outcome: VERIFICATION_STATE.VALIDATION_FAILED, reason: VERIFICATION_REASON.CANCELLED };
  }
  if (state === 'timeout') {
    return { outcome: VERIFICATION_STATE.VALIDATION_FAILED, reason: VERIFICATION_REASON.TIMEOUT };
  }
  if (!toolCompleted(scannerStatuses, targetTool)) {
    return { outcome: VERIFICATION_STATE.INCONCLUSIVE, reason: VERIFICATION_REASON.SCANNER_INCOMPLETE };
  }
  const identity = verificationIdentity(finding);
  const present = (Array.isArray(findings) ? findings : [])
    .some((candidate) => verificationIdentity(candidate) === identity);
  return present
    ? { outcome: VERIFICATION_STATE.STILL_PRESENT, reason: VERIFICATION_REASON.PRESENT_AFTER_RESCAN }
    : { outcome: VERIFICATION_STATE.VALIDATED, reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN };
}

/**
 * Maps an existing Dynamic Security retest verdict onto this lifecycle.
 *
 * The DAST verdict is not recomputed here: `retestVerdict()` already decides it
 * from real security evidence, and it is the only thing that may. This is a
 * translation, which is why every unknown verdict lands on INCONCLUSIVE.
 */
function interpretRetest(verdict) {
  if (!verdict) return { outcome: VERIFICATION_STATE.INCONCLUSIVE, reason: VERIFICATION_REASON.VALIDATOR_ERROR };
  if (verdict.state === 'VALIDATED') {
    return { outcome: VERIFICATION_STATE.VALIDATED, reason: VERIFICATION_REASON.RETEST_EVIDENCE_GONE, detail: verdict.reason || '' };
  }
  if (verdict.state === 'STILL_PRESENT') {
    return { outcome: VERIFICATION_STATE.STILL_PRESENT, reason: VERIFICATION_REASON.RETEST_EVIDENCE_PRESENT, detail: verdict.reason || '' };
  }
  return { outcome: VERIFICATION_STATE.INCONCLUSIVE, reason: VERIFICATION_REASON.VALIDATOR_ERROR, detail: verdict.reason || '' };
}

/** A safe, persistable summary. Never carries a secret, a token or a body. */
function evidenceSummary({ verifier, tool, scanId = null, retestId = null, detail = '' } = {}) {
  return {
    verifier: verifier || VERIFIER.NONE,
    tool: String(tool || ''),
    scanId: scanId ?? null,
    retestId: retestId ?? null,
    detail: String(detail || '').slice(0, 200)
  };
}

/**
 * The orchestrator.
 *
 * Picks the strategy, runs the injected verifier, and normalises whatever comes
 * back into one of four outcomes. A verifier that throws is a VALIDATION_FAILED
 * with the error named — never a silent STILL_PRESENT, and never a VALIDATED.
 *
 * `context.runVerifier` receives the strategy and must return either a rescan
 * shape (`{findings, scannerStatuses, scanId}`) or a retest shape (`{verdict,
 * retestId}`). Anything else is a validator error.
 */
async function verifyFindingFix(finding, context = {}) {
  const at = context.now || new Date().toISOString();
  const strategy = verificationStrategyFor(finding);
  const base = { finding: verificationIdentity(finding), validator: strategy.verifier, at };

  if (strategy.verifier === VERIFIER.NONE) {
    return {
      ...base, state: VERIFICATION_STATE.INCONCLUSIVE, reason: VERIFICATION_REASON.NO_VERIFIER,
      evidence: evidenceSummary({ verifier: strategy.verifier, tool: strategy.tool })
    };
  }
  // Verification answers « is it still there », which only means something once
  // something changed. Asking before any fix was applied is a category error.
  if (context.requireFixApplied && !context.fixApplied) {
    return {
      ...base, state: VERIFICATION_STATE.INCONCLUSIVE, reason: VERIFICATION_REASON.NOT_APPLIED,
      evidence: evidenceSummary({ verifier: strategy.verifier, tool: strategy.tool })
    };
  }

  let raw;
  try {
    raw = await context.runVerifier(strategy, finding);
  } catch (error) {
    const cancelled = context.token?.isCancellationRequested || /annul|cancel/i.test(error?.message || '');
    // The scanners phrase a timeout as « a dépassé N secondes », which no
    // spelling of "timeout" matches. Both branches are safe — neither validates —
    // but a run that ran out of time should say so rather than read as a crash.
    const timedOut = /timeout|timed out|délai|delai|dépass|depass|ETIMEDOUT/i.test(error?.message || '');
    return {
      ...base,
      state: VERIFICATION_STATE.VALIDATION_FAILED,
      reason: cancelled ? VERIFICATION_REASON.CANCELLED
        : timedOut ? VERIFICATION_REASON.TIMEOUT
          : VERIFICATION_REASON.VALIDATOR_ERROR,
      evidence: evidenceSummary({ verifier: strategy.verifier, tool: strategy.tool, detail: error?.message || '' })
    };
  }

  if (context.token?.isCancellationRequested) {
    return {
      ...base, state: VERIFICATION_STATE.VALIDATION_FAILED, reason: VERIFICATION_REASON.CANCELLED,
      evidence: evidenceSummary({ verifier: strategy.verifier, tool: strategy.tool })
    };
  }
  if (!raw || typeof raw !== 'object') {
    return {
      ...base, state: VERIFICATION_STATE.VALIDATION_FAILED, reason: VERIFICATION_REASON.VALIDATOR_ERROR,
      evidence: evidenceSummary({ verifier: strategy.verifier, tool: strategy.tool, detail: 'aucun résultat exploitable' })
    };
  }

  const interpreted = strategy.verifier === VERIFIER.DAST_RETEST
    ? interpretRetest(raw.verdict)
    : interpretRescan({ finding, findings: raw.findings, scannerStatuses: raw.scannerStatuses, tool: strategy.tool });

  return {
    ...base,
    state: interpreted.outcome,
    reason: interpreted.reason,
    evidence: evidenceSummary({
      verifier: strategy.verifier, tool: strategy.tool,
      scanId: raw.scanId, retestId: raw.retestId, detail: interpreted.detail
    })
  };
}

/**
 * Records a fix without claiming anything about it.
 *
 * This is the single place the three fix paths — Quick Fix, AI, manual — converge
 * on, and it always lands on FIX_APPLIED. There is no argument that lets a caller
 * skip to VALIDATED, because none of them holds the evidence.
 */
function markFixApplied(finding, { source = FIX_SOURCE.MANUAL, at = new Date().toISOString(), by = '' } = {}) {
  return {
    ...finding,
    triageStatus: VERIFICATION_STATE.FIX_APPLIED,
    fixedAt: at,
    fixSource: source,
    fixedBy: by || finding?.fixedBy || '',
    verificationPending: true,
    verification: null
  };
}

/** Moves a finding into VALIDATING. Purely a display state; it holds no verdict. */
function markValidating(finding, { at = new Date().toISOString() } = {}) {
  return { ...finding, triageStatus: VERIFICATION_STATE.VALIDATING, validationStartedAt: at, verificationPending: true };
}

/**
 * Applies a verification result to a finding.
 *
 * A developer decision — accepted, false positive — outranks a machine verdict
 * and is left alone: the point of accepting a risk is that rescans stop arguing
 * about it. Everything else takes the verdict, and only VALIDATED writes a
 * `validatedAt`, which is what MTTR should be measured from.
 */
function applyVerification(finding, result) {
  if (!result) return finding;
  if (DECISION_STATES.includes(normalizeStatus(finding?.triageStatus))) return finding;
  const verification = {
    state: result.state,
    validator: result.validator,
    reason: result.reason,
    at: result.at,
    evidence: result.evidence || null
  };
  return {
    ...finding,
    triageStatus: result.state,
    verification,
    // History accumulates: a later regression must not erase the proof that the
    // fix did work once.
    verificationHistory: [...(finding?.verificationHistory || []), verification].slice(-10),
    verificationPending: result.state !== VERIFICATION_STATE.VALIDATED,
    ...(result.state === VERIFICATION_STATE.VALIDATED ? { validatedAt: result.at } : {})
  };
}

/**
 * Legacy statuses, read forward.
 *
 * A cache written before this lifecycle existed contains `fixed` findings that
 * were never verified. They restore as « fix applied, verification pending » —
 * not as validated. Anything already spelled `validated` was produced by
 * `validatedAfterScan`, which did compare fingerprints after a completed scan,
 * so it keeps its meaning.
 */
function migrateLegacyStatus(status) {
  const normalized = String(status || '');
  if (normalized === 'fixed') return { status: VERIFICATION_STATE.FIX_APPLIED, verificationPending: true };
  if (normalized === 'validated') return { status: VERIFICATION_STATE.VALIDATED, verificationPending: false };
  return { status: normalized || VERIFICATION_STATE.OPEN, verificationPending: false };
}

/**
 * A validated finding that shows up again.
 *
 * Regression is only claimed when the tool that would have to see it actually
 * ran: a scanner that was skipped tells us nothing about whether the issue came
 * back. The previous validation travels with it as history.
 */
function detectRegressions(previousFindings = [], currentFindings = [], scannerStatuses = []) {
  const current = new Map();
  for (const finding of Array.isArray(currentFindings) ? currentFindings : []) {
    current.set(verificationIdentity(finding), finding);
  }
  const regressed = [];
  for (const previous of Array.isArray(previousFindings) ? previousFindings : []) {
    if (normalizeStatus(previous?.triageStatus) !== VERIFICATION_STATE.VALIDATED) continue;
    const identity = verificationIdentity(previous);
    if (!current.has(identity)) continue;
    if (!toolCompleted(scannerStatuses, previous.tool)) continue;
    const reappeared = current.get(identity);
    regressed.push({
      ...reappeared,
      triageStatus: VERIFICATION_STATE.REGRESSED,
      regressedAt: new Date().toISOString(),
      previousValidation: previous.verification || (previous.validatedAt ? { state: VERIFICATION_STATE.VALIDATED, at: previous.validatedAt } : null),
      verificationHistory: previous.verificationHistory || []
    });
  }
  return regressed;
}

/**
 * What is persisted per finding.
 *
 * Metadata only, and deliberately narrow: a verifier name, a verdict, a reason,
 * an identifier and a short detail. No patch content, no scanner output, no
 * response body — a verification record is copied into caches and reports, and
 * anything sensitive in it would travel with them.
 */
function verificationRecord(finding) {
  const verification = finding?.verification;
  if (!verification) return null;
  return {
    key: findingKey(finding),
    status: finding.triageStatus,
    validator: verification.validator || '',
    validatedAt: finding.validatedAt || null,
    at: verification.at || null,
    reason: verification.reason || '',
    scanId: verification.evidence?.scanId ?? null,
    retestId: verification.evidence?.retestId ?? null,
    tool: verification.evidence?.tool || '',
    detail: String(verification.evidence?.detail || '').slice(0, 200),
    fixSource: finding.fixSource || '',
    verificationPending: finding.verificationPending === true
  };
}

/** Rebuilds verification metadata from a persisted record. */
function restoreVerification(record) {
  if (!record || typeof record !== 'object' || !record.key) return null;
  const status = String(record.status || '');
  if (!Object.values(VERIFICATION_STATE).includes(status) && !DECISION_STATES.includes(status)) return null;
  return {
    key: String(record.key),
    status,
    validatedAt: record.validatedAt || null,
    fixSource: String(record.fixSource || ''),
    verificationPending: record.verificationPending === true,
    verification: {
      state: status,
      validator: String(record.validator || ''),
      reason: String(record.reason || ''),
      at: record.at || null,
      evidence: evidenceSummary({
        verifier: record.validator, tool: record.tool,
        scanId: record.scanId, retestId: record.retestId, detail: record.detail
      })
    }
  };
}

/**
 * Reattaches persisted verification metadata to restored findings.
 *
 * The statuses already survive a restart through the triage state; what was
 * missing was the *evidence* behind them, which is what makes a validated
 * finding auditable rather than merely green. This walks the stored records and
 * puts `verification` back on the findings they belong to.
 *
 * Fails closed on every axis. A record that does not parse is dropped, not
 * repaired. A record is never allowed to introduce a status the finding did not
 * already have — restoring metadata must not be a way to become VALIDATED — so a
 * disagreement keeps the triage status and drops the record. And a finding with
 * no record at all is returned untouched, which is what every pre-existing cache
 * contains.
 */
function restoreVerificationOnFindings(findings = [], records = {}) {
  const stored = records && typeof records === 'object' && !Array.isArray(records) ? records : {};
  return (Array.isArray(findings) ? findings : []).map((finding) => {
    const restored = restoreVerification(stored[findingKey(finding)]);
    if (!restored) return finding;
    // The triage status is the authority. Metadata explains it; it cannot
    // overrule it, and it certainly cannot upgrade it.
    if (normalizeStatus(finding?.triageStatus) !== restored.status) return finding;
    return {
      ...finding,
      verification: restored.verification,
      verificationPending: restored.verificationPending,
      fixSource: finding.fixSource || restored.fixSource || '',
      ...(restored.validatedAt ? { validatedAt: restored.validatedAt } : {})
    };
  });
}

module.exports = {
  VERIFICATION_STATE, DECISION_STATES, STATE_LABELS, VERIFICATION_REASON, REASON_LABELS,
  restoreVerificationOnFindings,
  FIX_SOURCE, VERIFIER, TOOL_VERIFIER,
  verificationStrategyFor, verificationIdentity, toolCompleted, toolState,
  interpretRescan, interpretRetest, evidenceSummary, verifyFindingFix,
  markFixApplied, markValidating, applyVerification, migrateLegacyStatus,
  detectRegressions, verificationRecord, restoreVerification
};
