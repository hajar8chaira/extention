'use strict';

/**
 * Replay comparison and targeted retest.
 *
 * A dynamic finding is verified by re-exercising the one request that produced it,
 * not by re-running a whole scan. This module compares the original transaction
 * with the replay and decides whether the security condition still holds.
 *
 * The rule that governs everything here: **a status code is not a verdict.** An
 * endpoint answering 200 proves the server is up, not that the vulnerability is
 * gone; an endpoint answering 403 may mean the fix worked or that the test lost
 * its session. So a verdict is only issued when the *security condition specific
 * to that finding* can be evaluated — and when it cannot, the answer is
 * INCONCLUSIVE. Never VALIDATED by default.
 */

// Required lazily, like the other dynamic modules: the dashboard renders these
// verdicts, so a top-level require would close a cycle and yield an undefined
// constant at load time.
function associationConfidence() {
  return require('./dashboard').ASSOCIATION_CONFIDENCE;
}

/** Retest lifecycle. Terminal states are the three verdicts. */
const RETEST_STATE = Object.freeze({
  FOUND: 'FOUND',
  FIX_APPLIED: 'FIX_APPLIED',
  RETESTING: 'RETESTING',
  VALIDATED: 'VALIDATED',
  STILL_PRESENT: 'STILL_PRESENT',
  INCONCLUSIVE: 'INCONCLUSIVE'
});

const RETEST_TERMINAL = Object.freeze([RETEST_STATE.VALIDATED, RETEST_STATE.STILL_PRESENT, RETEST_STATE.INCONCLUSIVE]);

const RETEST_LABELS = Object.freeze({
  FOUND: 'Détecté',
  FIX_APPLIED: 'Correction appliquée',
  RETESTING: 'Re-test en cours',
  VALIDATED: 'Validé — non reproduit',
  STILL_PRESENT: 'Toujours reproduit',
  INCONCLUSIVE: 'Non concluant'
});

/** Why a verdict was reached. Shown next to it, never omitted. */
const VERDICT_REASON = Object.freeze({
  EVIDENCE_GONE: 'evidence_gone',
  EVIDENCE_PRESENT: 'evidence_present',
  HEADER_ADDED: 'header_added',
  HEADER_STILL_MISSING: 'header_still_missing',
  NO_CHECK: 'no_check_available',
  NO_RESPONSE: 'no_response',
  BODY_UNAVAILABLE: 'body_unavailable',
  ENDPOINT_MISMATCH: 'endpoint_mismatch',
  REPLAY_FAILED: 'replay_failed'
});

/** Header values are never compared: only presence and a small safe set. */
const COMPARABLE_HEADERS = Object.freeze([
  'content-type', 'content-security-policy', 'x-frame-options', 'x-content-type-options',
  'strict-transport-security', 'referrer-policy', 'permissions-policy',
  'access-control-allow-origin', 'location', 'cache-control'
]);

const SENSITIVE_HEADER = /authorization|cookie|set-cookie|token|api[-_]?key|secret/i;

/** A response body is never returned whole. This is the visible slice. */
const PREVIEW_LIMIT = 400;

/** Beyond this, a body is treated as too large to compare textually. */
const MAX_COMPARABLE_BODY = 512 * 1024;

function headerMap(headers = {}) {
  const map = new Map();
  for (const [name, value] of Object.entries(headers || {})) {
    map.set(String(name).toLowerCase(), String(value ?? ''));
  }
  return map;
}

function bodyOf(response) {
  const body = response?.body ?? response?.content?.text ?? '';
  return typeof body === 'string' ? body : '';
}

function statusOf(response) {
  const value = Number(response?.status ?? response?.statusCode);
  return Number.isFinite(value) ? value : null;
}

/**
 * A safe preview of a response body.
 *
 * Truncated, and suppressed entirely when the body looks like it carries
 * credentials — a replay of an authenticated endpoint frequently returns a token,
 * and a preview is not worth leaking one.
 */
function safePreview(body, { limit = PREVIEW_LIMIT } = {}) {
  const text = String(body || '');
  if (!text) return { preview: '', truncated: false, suppressed: false };
  if (SENSITIVE_HEADER.test(text) || /"(access|refresh|id)_token"|bearer\s+[\w.-]{20,}/i.test(text)) {
    return { preview: '[APERÇU SUPPRIMÉ : la réponse semble contenir un secret]', truncated: false, suppressed: true };
  }
  return {
    preview: text.slice(0, limit),
    truncated: text.length > limit,
    suppressed: false
  };
}

/**
 * Compares an original transaction with its replay.
 *
 * Structural facts only: status, content type, duration, size, and the presence
 * of a small set of security-relevant headers. Header *values* are not diffed —
 * a `Set-Cookie` diff would print a session.
 */
function compareReplay(original, replay) {
  const originalResponse = original?.response || {};
  const replayResponse = replay?.response || {};
  const originalStatus = statusOf(originalResponse);
  const replayStatus = statusOf(replayResponse);
  const originalBody = bodyOf(originalResponse);
  const replayBody = bodyOf(replayResponse);
  const tooLarge = originalBody.length > MAX_COMPARABLE_BODY || replayBody.length > MAX_COMPARABLE_BODY;

  const originalHeaders = headerMap(originalResponse.headers);
  const replayHeaders = headerMap(replayResponse.headers);
  const headerChanges = [];
  for (const name of COMPARABLE_HEADERS) {
    const before = originalHeaders.has(name);
    const after = replayHeaders.has(name);
    if (before === after) continue;
    headerChanges.push({ header: name, change: after ? 'added' : 'removed' });
  }

  const duration = {
    original: Number.isFinite(Number(originalResponse.durationMs)) ? Number(originalResponse.durationMs) : null,
    replay: Number.isFinite(Number(replayResponse.durationMs)) ? Number(replayResponse.durationMs) : null
  };
  const size = { original: originalBody.length || null, replay: replayBody.length || null };

  return {
    status: { original: originalStatus, replay: replayStatus, changed: originalStatus !== replayStatus },
    contentType: {
      original: (originalHeaders.get('content-type') || '').split(';')[0].trim() || null,
      replay: (replayHeaders.get('content-type') || '').split(';')[0].trim() || null
    },
    duration,
    size,
    headerChanges,
    // « Significantly changed » is a size heuristic, and it is labelled as one.
    bodyChanged: tooLarge ? null : originalBody !== replayBody,
    bodySignificantlyChanged: tooLarge ? null : significantlyDifferent(originalBody, replayBody),
    bodyComparable: !tooLarge,
    preview: safePreview(replayBody),
    // The original preview is kept so evidence of the previous state survives.
    originalPreview: safePreview(originalBody)
  };
}

function significantlyDifferent(left, right) {
  if (left === right) return false;
  const longest = Math.max(left.length, right.length);
  if (!longest) return false;
  return Math.abs(left.length - right.length) / longest > 0.25;
}

/**
 * The security condition for a finding, evaluated against the replay.
 *
 * Each branch is a check we can actually perform. Anything else returns
 * `NO_CHECK`, which becomes INCONCLUSIVE — the honest answer when we have no way
 * to tell.
 */
function evaluateSecurityCondition(finding, replay) {
  const response = replay?.response;
  if (!response) return { reproduced: null, reason: VERDICT_REASON.NO_RESPONSE };

  const headers = headerMap(response.headers);
  const rule = String(finding?.ruleId || '').toLowerCase();
  const title = String(finding?.title || '').toLowerCase();

  // A missing-security-header finding has an exact, checkable condition.
  const missingHeader = expectedHeaderFor(rule, title);
  if (missingHeader) {
    return headers.has(missingHeader)
      ? { reproduced: false, reason: VERDICT_REASON.HEADER_ADDED, detail: missingHeader }
      : { reproduced: true, reason: VERDICT_REASON.HEADER_STILL_MISSING, detail: missingHeader };
  }

  // ZAP evidence is a literal string the scanner matched in the response. Its
  // disappearance is real evidence; its presence is proof the issue persists.
  const evidence = String(finding?.evidence || '').trim();
  if (evidence && evidence.length >= 4) {
    const body = bodyOf(response);
    if (!body && !headers.size) return { reproduced: null, reason: VERDICT_REASON.BODY_UNAVAILABLE };
    const haystack = `${body}\n${[...headers.entries()].map(([name, value]) => `${name}: ${value}`).join('\n')}`;
    return haystack.includes(evidence)
      ? { reproduced: true, reason: VERDICT_REASON.EVIDENCE_PRESENT, detail: evidence.slice(0, 60) }
      : { reproduced: false, reason: VERDICT_REASON.EVIDENCE_GONE, detail: evidence.slice(0, 60) };
    }

  return { reproduced: null, reason: VERDICT_REASON.NO_CHECK };
}

/** The response header a « missing header » finding is about, when identifiable. */
function expectedHeaderFor(rule, title) {
  const table = [
    [/content-security-policy|\bcsp\b/, 'content-security-policy'],
    [/x-frame-options|clickjack|frame-ancestors/, 'x-frame-options'],
    [/x-content-type-options|mime.?sniff/, 'x-content-type-options'],
    [/strict-transport-security|\bhsts\b/, 'strict-transport-security'],
    [/referrer-policy/, 'referrer-policy'],
    [/permissions-policy|feature-policy/, 'permissions-policy']
  ];
  const raw = `${rule} ${title}`;
  // ZAP writes alert names in prose — « Content Security Policy Header Not Set » —
  // while the header itself is hyphenated. Both spellings are matched against the
  // same normalized haystack.
  const haystack = raw.toLowerCase().replace(/\s+/g, '-');
  // Only when the finding is actually about the header being absent.
  if (!/missing|absent|manquant|not-set|non-défini|not-configured/.test(haystack)) return '';
  const match = table.find(([pattern]) => pattern.test(haystack));
  return match ? match[1] : '';
}

/**
 * The retest verdict.
 *
 * `VALIDATED` requires positive evidence that the condition no longer holds.
 * A failed replay, an unreachable endpoint or an unrecognised finding type all
 * yield INCONCLUSIVE — the previous finding stays as it was.
 */
function retestVerdict({ finding, original = null, replay = null, replayError = null, association = null } = {}) {
  const evidence = {
    findingId: String(finding?.id || ''),
    ruleId: String(finding?.ruleId || ''),
    endpoint: String(finding?.endpoint || ''),
    method: String(finding?.method || ''),
    // The previous state is preserved whatever the verdict.
    previous: original ? { status: statusOf(original.response), preview: safePreview(bodyOf(original.response)) } : null,
    at: new Date().toISOString()
  };
  if (replayError) {
    return { state: RETEST_STATE.INCONCLUSIVE, reason: VERDICT_REASON.REPLAY_FAILED, detail: String(replayError).slice(0, 200), comparison: null, evidence };
  }
  if (!replay) {
    return { state: RETEST_STATE.INCONCLUSIVE, reason: VERDICT_REASON.NO_RESPONSE, comparison: null, evidence };
  }
  // The replay must have hit the endpoint the finding is about. Verifying a
  // different endpoint would be worse than not verifying at all.
  const CONFIDENCE = associationConfidence();
  if (association && association !== CONFIDENCE.EXACT && association !== CONFIDENCE.STRONG) {
    return { state: RETEST_STATE.INCONCLUSIVE, reason: VERDICT_REASON.ENDPOINT_MISMATCH, comparison: null, evidence };
  }
  const comparison = original ? compareReplay(original, replay) : null;
  const condition = evaluateSecurityCondition(finding, replay);
  if (condition.reproduced === true) {
    return { state: RETEST_STATE.STILL_PRESENT, reason: condition.reason, detail: condition.detail || '', comparison, evidence };
  }
  if (condition.reproduced === false) {
    return { state: RETEST_STATE.VALIDATED, reason: condition.reason, detail: condition.detail || '', comparison, evidence };
  }
  return { state: RETEST_STATE.INCONCLUSIVE, reason: condition.reason, detail: condition.detail || '', comparison, evidence };
}

/**
 * Advances a retest record.
 *
 * Refuses illegal transitions rather than silently accepting them: a verdict
 * cannot be reopened, and a retest cannot be marked validated without having run.
 */
const ALLOWED_TRANSITIONS = Object.freeze({
  FOUND: [RETEST_STATE.FIX_APPLIED, RETEST_STATE.RETESTING],
  FIX_APPLIED: [RETEST_STATE.RETESTING],
  RETESTING: [RETEST_STATE.VALIDATED, RETEST_STATE.STILL_PRESENT, RETEST_STATE.INCONCLUSIVE],
  VALIDATED: [RETEST_STATE.FOUND],
  STILL_PRESENT: [RETEST_STATE.FIX_APPLIED, RETEST_STATE.RETESTING],
  INCONCLUSIVE: [RETEST_STATE.FIX_APPLIED, RETEST_STATE.RETESTING]
});

function advanceRetest(record, nextState, patch = {}) {
  const current = record?.state || RETEST_STATE.FOUND;
  const allowed = ALLOWED_TRANSITIONS[current] || [];
  if (!allowed.includes(nextState)) {
    throw new Error(`Transition de re-test invalide : ${current} → ${nextState}.`);
  }
  return {
    ...record,
    state: nextState,
    history: [...(record?.history || []), { state: nextState, at: new Date().toISOString(), reason: patch.reason || '' }],
    ...patch
  };
}

/** A fresh retest record for a dynamic finding. */
function createRetestRecord(finding, { campaignId = '' } = {}) {
  return {
    findingId: String(finding?.id || ''),
    campaignId: String(campaignId || ''),
    endpoint: String(finding?.endpoint || ''),
    method: String(finding?.method || ''),
    ruleId: String(finding?.ruleId || ''),
    title: String(finding?.title || ''),
    state: RETEST_STATE.FOUND,
    verdict: null,
    history: [{ state: RETEST_STATE.FOUND, at: new Date().toISOString(), reason: '' }]
  };
}

/** Wording for each verdict reason, so no surface has to invent one. */
const REASON_LABELS = Object.freeze({
  evidence_gone: 'La preuve relevée par le scanner n’apparaît plus dans la réponse.',
  evidence_present: 'La preuve relevée par le scanner est toujours présente.',
  header_added: 'L’en-tête de sécurité attendu est désormais présent.',
  header_still_missing: 'L’en-tête de sécurité attendu est toujours absent.',
  no_check_available: 'Aucune vérification automatique n’existe pour ce type de finding.',
  no_response: 'Le re-test n’a produit aucune réponse.',
  body_unavailable: 'La réponse ne contient rien de comparable.',
  endpoint_mismatch: 'La requête rejouée ne correspond pas à l’endpoint du finding.',
  replay_failed: 'Le replay a échoué.'
});

module.exports = {
  RETEST_STATE, RETEST_TERMINAL, RETEST_LABELS, VERDICT_REASON, REASON_LABELS,
  COMPARABLE_HEADERS, PREVIEW_LIMIT, MAX_COMPARABLE_BODY, ALLOWED_TRANSITIONS,
  safePreview, compareReplay, evaluateSecurityCondition, expectedHeaderFor,
  retestVerdict, advanceRetest, createRetestRecord, significantlyDifferent
};
