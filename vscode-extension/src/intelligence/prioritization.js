'use strict';

/**
 * Prioritization engine.
 *
 * Deterministic and explainable: the same finding always produces the same
 * score, and every point is attributed to a named reason the user can read.
 * No machine learning, no hidden heuristics.
 *
 * The weights live in one table so they can be reviewed and tested as data
 * rather than being scattered through the scoring code.
 */

const { STATE_RANK } = require('./reachability');
const { tierFor } = require('./correlation-v2');

const WEIGHTS = Object.freeze({
  severity: { CRITICAL: 45, HIGH: 33, MEDIUM: 20, LOW: 8, INFO: 3, UNKNOWN: 8 },
  // CVSS refines the severity band instead of adding a second severity signal.
  cvssBonus: 6,
  // Severity alone never reaches the top band: what raises a finding is the
  // evidence that it can actually be reached and has been corroborated.
  reachability: {
    dynamically_confirmed: 28,
    statically_reachable: 16,
    imported: 8,
    present: 2,
    not_reachable: -12,
    unknown: 0,
    not_evaluated: 0
  },
  // Independent corroboration, counted once however many tools agree, and
  // weighted by what the correlation actually established. A `candidate` link
  // is a hypothesis — it must not buy the same points as a confirmation.
  correlationTier: { confirmed: 15, probable: 7, candidate: 0 },
  // Runtime evidence is its own signal, separate from code reachability. A hit
  // on a static asset is observed traffic, not an exercised application path.
  runtimeObserved: 6,
  runtimeStaticAsset: 0,
  secretInProduction: 15,
  exposedEndpoint: 8,
  knownExploit: 8,
  fixAvailable: 5,
  testCodePenalty: -15,
  triagedAwayPenalty: -40
});

// Bands are calibrated so the top one requires several independent strong
// signals, not a single severity label:
//   HIGH + confirmée dynamiquement + 2 scanners + correctif  → 81  critique
//   CRITICAL + atteignable statiquement                      → 61  élevée
//   CRITICAL sans aucune preuve d'atteignabilité             → 47  moyenne
const LEVELS = Object.freeze([
  { level: 'critical', code: 'P0', label: 'Critique', min: 80 },
  { level: 'high', code: 'P1', label: 'Élevée', min: 60 },
  { level: 'medium', code: 'P2', label: 'Moyenne', min: 35 },
  { level: 'low', code: 'P3', label: 'Faible', min: 0 }
]);

const PRIORITY_CODES = Object.freeze(['P0', 'P1', 'P2', 'P3']);

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function levelFor(score) {
  return LEVELS.find((entry) => score >= entry.min) || LEVELS.at(-1);
}

/** Exploit maturity as published by the scanner, never inferred. */
function hasKnownExploit(finding) {
  const maturity = String(finding.raw?.exploitMaturity || '').toLowerCase();
  if (!maturity) return false;
  return /proof of concept|functional|high|mature|weaponi/.test(maturity) && !/no known exploit|not defined|unproven/.test(maturity);
}

/**
 * Whether the finding concerns something exposed over HTTP. Only a real
 * endpoint or a real route correlation counts — never a guess from a filename.
 */
function isExposed(finding) {
  if (finding.endpoint) return true;
  return Boolean(finding.correlation?.types?.includes('dast-sast'));
}

/**
 * Scores one finding. Signals that mean the same thing are never counted twice:
 * a dynamically confirmed finding already receives the reachability points, so
 * "DAST confirmed" is not added a second time on top of them.
 */
function prioritizeFinding(finding) {
  const reasons = [];
  let score = 0;

  const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
  const severityPoints = WEIGHTS.severity[severity] ?? WEIGHTS.severity.UNKNOWN;
  score += severityPoints;
  reasons.push({ label: `Sévérité ${severity}`, points: severityPoints, kind: 'severity' });

  // CVSS only tops up a severity band; it never replaces it.
  if (Number.isFinite(finding.cvssScore) && finding.cvssScore >= 9) {
    score += WEIGHTS.cvssBonus;
    reasons.push({ label: `Score CVSS ${finding.cvssScore}`, points: WEIGHTS.cvssBonus, kind: 'cvss' });
  }

  const state = finding.reachability?.state || 'not_evaluated';
  const reachabilityPoints = WEIGHTS.reachability[state] ?? 0;
  if (reachabilityPoints !== 0) {
    score += reachabilityPoints;
    reasons.push({
      label: state === 'dynamically_confirmed' ? 'Confirmée dynamiquement'
        : state === 'statically_reachable' ? 'Atteignable depuis un point d’entrée'
          : state === 'imported' ? 'Composant importé par le code'
            : state === 'not_reachable' ? 'Aucun import trouvé dans le code'
              : 'Présente dans le dépôt',
      points: reachabilityPoints,
      kind: 'reachability'
    });
  }

  const corroborating = finding.correlation?.corroboratingTools || [];
  if (corroborating.length) {
    // The tier is authoritative when present; otherwise it is derived from the
    // confidence so a correlation built by any caller is still weighted right.
    const tier = finding.correlation?.tier || tierFor(finding.correlation?.confidence);
    const points = WEIGHTS.correlationTier[tier] ?? 0;
    const tools = [finding.tool, ...corroborating].join(', ');
    if (points > 0) {
      score += points;
      reasons.push({
        label: tier === 'confirmed'
          ? `Confirmée par ${corroborating.length + 1} scanners indépendants (${tools})`
          : `Corrélation probable entre ${corroborating.length + 1} scanners (${tools})`,
        points,
        kind: 'correlation'
      });
    } else {
      // Recorded with zero weight: visible to the reader, worthless to the score.
      reasons.push({
        label: `Corrélation candidate, non confirmée (${tools})`,
        points: 0,
        kind: 'correlation'
      });
    }
  }

  const runtime = finding.runtime;
  if (runtime?.observed) {
    const points = runtime.staticAsset ? WEIGHTS.runtimeStaticAsset : WEIGHTS.runtimeObserved;
    score += points;
    reasons.push({
      label: runtime.staticAsset
        ? `Observé à l’exécution sur une ressource statique (${runtime.source})`
        : `Observé à l’exécution par ${runtime.source} — ${runtime.method || 'HTTP'} ${runtime.url}`,
      points,
      kind: 'runtime'
    });
  }

  if (finding.stage === 'secrets' && finding.sourceContext !== 'test') {
    score += WEIGHTS.secretInProduction;
    reasons.push({ label: 'Secret exposé dans du code de production', points: WEIGHTS.secretInProduction, kind: 'secret' });
  }

  // Exposure is only added when reachability did not already account for it.
  if (isExposed(finding) && state !== 'dynamically_confirmed') {
    score += WEIGHTS.exposedEndpoint;
    reasons.push({ label: 'Rattachée à un endpoint HTTP exposé', points: WEIGHTS.exposedEndpoint, kind: 'exposure' });
  }

  if (hasKnownExploit(finding)) {
    score += WEIGHTS.knownExploit;
    reasons.push({ label: `Maturité d’exploitation : ${finding.raw.exploitMaturity}`, points: WEIGHTS.knownExploit, kind: 'exploit' });
  }

  if (finding.fixAvailable) {
    score += WEIGHTS.fixAvailable;
    reasons.push({ label: 'Correction disponible', points: WEIGHTS.fixAvailable, kind: 'fix' });
  }

  if (finding.sourceContext === 'test') {
    score += WEIGHTS.testCodePenalty;
    reasons.push({ label: 'Située dans du code de test', points: WEIGHTS.testCodePenalty, kind: 'context' });
  }

  if (['false_positive', 'accepted', 'fixed', 'validated'].includes(finding.triageStatus)) {
    score += WEIGHTS.triagedAwayPenalty;
    reasons.push({ label: `Triée comme « ${finding.triageStatus} »`, points: WEIGHTS.triagedAwayPenalty, kind: 'triage' });
  }

  const priorityScore = clamp(Math.round(score));
  const { level, label, code } = levelFor(priorityScore);
  return {
    ...finding,
    priority: {
      score: priorityScore,
      level,
      // Operational priority code, the vocabulary the UI and CLI report.
      code,
      label,
      reasons,
      // `factors` is the same evidence keyed by signal, for callers that want
      // to reason about the contributions rather than render them.
      factors: reasons.map((reason) => ({ kind: reason.kind, label: reason.label, points: reason.points })),
      explanation: `${code} ${label} — ${priorityScore}/100 : ${reasons.map((reason) => reason.label).join(' ; ')}`,
      // Kept so the UI can explain the arithmetic without recomputing it.
      rawScore: Math.round(score)
    }
  };
}

function prioritizeFindings(findings = []) {
  const scored = findings.map(prioritizeFinding);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const distribution = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const finding of scored) {
    counts[finding.priority.level] += 1;
    distribution[finding.priority.code] += 1;
  }
  const ranked = [...scored].sort((left, right) => right.priority.score - left.priority.score
    || String(left.id).localeCompare(String(right.id)));
  return {
    findings: scored,
    summary: {
      counts,
      distribution,
      highest: ranked[0]?.priority.score ?? 0,
      top: ranked.slice(0, 10).map((finding) => ({
        id: finding.id, title: finding.title, tool: finding.tool,
        score: finding.priority.score, level: finding.priority.level, code: finding.priority.code,
        severity: finding.severity,
        reachability: finding.reachability?.state || 'not_evaluated',
        reachabilityStatus: finding.reachability?.status || 'UNKNOWN',
        correlatedTools: finding.correlation?.tools || [finding.tool],
        explanation: finding.priority.explanation
      }))
    }
  };
}

/** Human-readable explanation, used by both the UI and the CLI. */
function explainPriority(finding) {
  const priority = finding?.priority;
  if (!priority) return '';
  const lines = [`${priority.code} — ${priority.score} / 100 — priorité ${priority.label.toLowerCase()}`, ''];
  for (const reason of priority.reasons) {
    lines.push(`${reason.points >= 0 ? '✓' : '−'} ${reason.label} (${reason.points >= 0 ? '+' : ''}${reason.points})`);
  }
  return lines.join('\n');
}

module.exports = {
  WEIGHTS, LEVELS, PRIORITY_CODES, STATE_RANK,
  prioritizeFinding, prioritizeFindings, explainPriority, levelFor, hasKnownExploit, isExposed
};
