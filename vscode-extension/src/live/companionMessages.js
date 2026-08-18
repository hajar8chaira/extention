'use strict';

/**
 * Security Companion — centralised messages.
 *
 * One function decides what the companion says, from the state it is really in
 * and the context that is really available. No message is composed anywhere
 * else, so the copy cannot drift between the sidebar, the status bar and the
 * page.
 *
 * Two rules govern everything here:
 *   - a message is only produced when the underlying fact is actually known;
 *     an absent scan status or an unknown policy verdict says nothing;
 *   - the companion is an assistant, not a narrator: the highest-priority
 *     useful fact wins and the rest stays silent.
 */

/** Visual states of the mascot, independent from the service state. */
// The canonical remediation lifecycle. Imported rather than re-typed so the
// companion cannot drift from the states it reports on.
const { VERIFICATION_STATE } = require('../fix-verification');

const MASCOT_STATES = Object.freeze(['idle', 'watching', 'thinking', 'warning', 'success', 'sleeping']);

/** Companion states, aligned with the Live Security service plus `degraded`. */
const COMPANION_STATES = Object.freeze(['idle', 'analyzing', 'clean', 'findings', 'degraded', 'disabled', 'error']);

// The CSS in the sidebar keys off these historical class names; the mascot
// vocabulary above is what the rest of the product speaks.
const MASCOT_TO_MOOD = Object.freeze({
  idle: 'watching', watching: 'watching', thinking: 'analyzing',
  warning: 'attentive', success: 'clean', sleeping: 'resting'
});

/**
 * The primary ladder: what the companion says out loud.
 *
 * It is ordered around the file the developer is editing, because that is the
 * only thing the companion knows more about than the page it sits on. A project
 * fact never takes the primary slot from a current-file fact — a clean file in a
 * workspace with 556 findings must read « aucun problème Live dans ce fichier »,
 * not « dernière analyse complète : 556 findings », which was the wrong headline
 * on the Live Security page.
 *
 * Project-level facts are still reported, as `secondary` (see `secondaryFor`).
 */
const PRIORITIES = Object.freeze([
  'live-critical', 'live-findings', 'error', 'policy-block', 'scanner-health',
  // `scan-outcome` is a scan that went wrong — partial, cancelled or failed. It
  // outranks a clean file, because « ce fichier est propre » would be misleading
  // when half the scanners never reported.
  'scanning', 'fix', 'scan-outcome', 'supply-chain', 'clean',
  // `scan-report` is a scan that simply finished. It sits *below* the clean
  // current file on purpose: a clean file in a scanned workspace must read
  // « aucun problème Live dans ce fichier », and the scan total is carried by
  // the secondary line. It still gets its own bubble when no file is open.
  'scan-report', 'disabled', 'idle'
]);

/**
 * Kinds whose bubble should fade on its own.
 *
 * Good news and a finished report are worth a glance, not a permanent banner. A
 * warning, a block or an error stays until the state that produced it changes —
 * the developer decides when it is dealt with, not a timer.
 */
const TRANSIENT_KINDS = Object.freeze(['scan-report', 'supply-chain', 'clean']);

/**
 * The secondary ladder: project-level context, shown small and never as the
 * headline. These kinds never appear in `message`, only in `secondary`.
 */
const SECONDARY_PRIORITIES = Object.freeze(['policy-block-note', 'policy-pass', 'scan-summary']);

function severityRank(value) {
  return { critical: 4, high: 3, error: 3, medium: 2, warning: 2, low: 1, information: 0, info: 0 }[String(value || '').toLowerCase()] ?? 0;
}

/** Highest severity among live findings, or '' when there are none. */
function highestSeverity(findings = []) {
  return [...findings]
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))[0]?.severity || '';
}

function pluralize(count, singular, plural) {
  return count === 1 ? singular : plural;
}

/**
 * The message the companion should be showing.
 *
 * `context` is entirely optional — every field is a fact the caller may or may
 * not have. Missing facts simply never produce a message.
 */
function companionMessageFor(state, context = {}) {
  const {
    findings = [], file = '', scanStatus = '', policyStatus = '',
    scannerHealth = [], remediationAvailable = false, error = '', degradedReason = '',
    scanProgress = null, scanOutcome = '', fixState = '', supplyChain = null, burpConnected = null
  } = context;
  const count = findings.length;
  const severity = highestSeverity(findings);
  const location = file ? ` dans ${file}` : '';

  // 1. What the developer is typing comes first: a finding in the open file is
  //    the one thing the companion knows before any page does.
  if (count && severityRank(severity) >= 3) {
    const headline = criticalHeadline(findings);
    return message('live-critical', 'warning',
      headline, `${count} ${pluralize(count, 'problème potentiel', 'problèmes potentiels')}${location}.`,
      { count, severity });
  }

  // 2. Any other finding in the file being edited. Still the developer's file,
  //    so it comes before the project-level facts and before « I am analysing ».
  if (count) {
    const base = message('live-findings', 'warning',
      `${count} ${pluralize(count, 'problème potentiel détecté', 'problèmes potentiels détectés')}`,
      `${summarizeSeverities(findings)}${location}.`, { count, severity });
    if (remediationAvailable) base.detail = `${base.detail} Une correction déterministe est disponible.`;
    return base;
  }

  // 3. The companion's own engine is broken. Below the file's findings, because a
  //    finding already on screen is still true even if the next analysis fails.
  if (state === 'error') {
    return message('error', 'warning', 'Analyse Live impossible', error || 'Le moteur Live Security a rencontré une erreur.');
  }

  // 4. The project policy refuses the delivery — a project-level fact, so it
  //    ranks below what the developer is typing but above everything else.
  if (String(policyStatus).toUpperCase() === 'BLOCK') {
    return message('policy-block', 'warning', 'La politique projet bloque la livraison',
      'Consultez le Policy Gate dans Security Pipeline.');
  }
  // An unusable policy ranks with a block: nothing is authorised either way.
  if (String(policyStatus).toUpperCase() === 'ERROR') {
    return message('policy-block', 'warning', 'La politique projet est invalide',
      'Corrigez security-center.yml : le Policy Gate n’a pas pu être évalué.');
  }

  // 5. A scanner that is enabled but cannot run — actionable configuration. The
  //    raw failure is turned into one short sentence a developer can act on; the
  //    full error stays in the scan log and on the scanner page.
  const unhealthy = scannerHealth.find((scanner) => scanner?.enabled && scanner?.reason);
  if (unhealthy) {
    const short = shortScannerIssue(unhealthy.tool, unhealthy.reason);
    return message('scanner-health', 'warning', short.headline, short.detail, { tool: unhealthy.tool });
  }
  // The Burp connector is a integration state, not a scanner failure, but it is
  // just as actionable when the developer expects captured traffic.
  if (burpConnected === false) {
    return message('scanner-health', 'warning', 'Burp déconnecté',
      'Aucun heartbeat récent du connecteur Burp.', { tool: 'Burp' });
  }

  // 6. Work in progress.
  if (state === 'analyzing') {
    return message('scanning', 'thinking', 'J’analyse vos modifications…', file ? `Fichier : ${file}` : '');
  }
  if (scanStatus === 'running') {
    return message('scanning', 'thinking', scanProgressHeadline(scanProgress), scanProgressDetail(scanProgress));
  }
  if (state === 'degraded') {
    return message('scanner-health', 'warning', 'Analyse Live réduite',
      degradedReason || 'L’analyse continue à l’enregistrement du fichier.');
  }

  // 7. Where a fix stands. Never an action, only a report: nothing here applies a
  //    fix or asks a model for one.
  const fix = fixMessage(fixState, remediationAvailable);
  if (fix) return fix;

  // 8. A scan that went wrong, then the supply-chain evidence it left behind.
  const outcome = scanOutcomeMessage(scanOutcome);
  if (outcome) return outcome;
  const artifact = supplyChainMessage(supplyChain);
  if (artifact) return artifact;

  // 9. The calm states. A clean *current file* is a real answer and keeps the
  //    primary slot; the last full scan is reported as `secondary` instead.
  if (state === 'disabled') {
    return message('disabled', 'sleeping', 'Live Security est désactivé',
      'Activez-le pour analyser le fichier pendant que vous codez.');
  }
  if (state === 'clean') {
    return message('clean', 'success', 'Aucun problème Live détecté dans ce fichier',
      file ? `${file} est propre pour l’instant.` : 'Le fichier courant est propre.');
  }
  // 10. With no file to talk about, the last scan is the most useful thing left.
  const report = scanReportMessage(scanOutcome, context);
  if (report) return report;
  return message('idle', file ? 'watching' : 'idle',
    file ? 'Je surveille votre code' : 'Live Security est prêt', file ? `Fichier : ${file}` : '');
}

/**
 * A raw scanner failure, as one short sentence.
 *
 * The companion has room for a headline, not for a stack trace. Nothing from the
 * raw text is echoed unless it was already safe: a token, a path or a payload
 * inside the message must never reach the bubble, so an unrecognised failure
 * becomes a generic « X a échoué » rather than a truncated dump.
 */
function shortScannerIssue(tool, reason) {
  const name = String(tool || 'Le scanner').replace(/\s+Server$/, '');
  const raw = String(reason || '');
  if (/jeton|token/i.test(raw) && /manquant|missing|absent/i.test(raw)) {
    return { headline: `Jeton ${name} manquant`, detail: 'Configurez-le dans Configuration des scanners.' };
  }
  if (/401|403|authenticat|auth.*refus|unauthorized/i.test(raw)) {
    return { headline: `Authentification ${name} refusée`, detail: 'Vérifiez le compte configuré pour ce scanner.' };
  }
  if (/injoignable|ECONNREFUSED|connection refused|unreachable|inaccessible/i.test(raw)) {
    return { headline: `${name} injoignable`, detail: 'Vérifiez que le service est démarré.' };
  }
  if (/docker/i.test(raw)) {
    return { headline: 'Docker indisponible', detail: `${name} a besoin de Docker Desktop démarré.` };
  }
  if (/timeout|timed?\s*out|d[ée]lai/i.test(raw)) {
    return { headline: `${name} a dépassé le délai`, detail: 'Relancez uniquement ce scanner.' };
  }
  if (/introuvable|not found|ENOENT|non install/i.test(raw)) {
    return { headline: `${name} n’est pas installé`, detail: 'Installez-le depuis Configuration des scanners.' };
  }
  return { headline: `${name} a échoué`, detail: 'Le détail est dans le journal d’analyse.' };
}

/**
 * What a running scan is doing, honestly.
 *
 * Scanners run in parallel, so naming one while three are working would be a
 * fiction. A single running scanner is named; several are counted.
 */
function scanProgressHeadline(progress) {
  const running = progress?.running || [];
  if (running.length === 1) return `${running[0]} en cours…`;
  if (running.length > 1) return `Analyse de sécurité en cours — ${running.length} scanners actifs`;
  return 'Analyse Security Center en cours…';
}

function scanProgressDetail(progress) {
  if (!progress || !Number.isFinite(progress.total) || !progress.total) return '';
  const done = Number.isFinite(progress.completed) ? progress.completed : 0;
  return `${done}/${progress.total} scanner(s) terminé(s).`;
}

/**
 * A scan that went wrong. A scan that merely finished is `scanReportMessage`,
 * which ranks lower — see PRIORITIES.
 */
function scanOutcomeMessage(outcome) {
  if (outcome === 'partial' || outcome === 'cancelled') {
    return message('scan-outcome', 'warning', 'Analyse terminée avec des erreurs de scanner',
      'Certains scanners n’ont pas produit de résultat : le total est incomplet.');
  }
  if (outcome === 'failed') {
    return message('scan-outcome', 'warning', 'L’analyse a échoué', 'Consultez le journal d’analyse.');
  }
  return null;
}

/** A scan that finished normally, with its real total. */
function scanReportMessage(outcome, context = {}) {
  if (outcome !== 'completed') return null;
  const total = context.scanFindingCount;
  const findings = Number.isFinite(total) ? `${total} ${pluralize(total, 'finding', 'findings')}` : '';
  return message('scan-report', total ? 'watching' : 'success',
    findings ? `Analyse terminée — ${findings}` : 'Analyse terminée',
    Number.isFinite(context.scanPriorityCount) ? `Dont ${context.scanPriorityCount} prioritaire(s).` : '');
}

/**
 * The whole vocabulary of remediation, in one place.
 *
 * Keyed by the canonical `VERIFICATION_STATE` values so the companion cannot
 * drift from the lifecycle it reports on, plus the five short aliases the
 * surfaces used before that lifecycle existed. One table, so there is exactly
 * one interpretation of what a verification state means to a developer.
 *
 * The mascot column carries the safety property: only `validated` may be
 * `success`. `fixed` — a patch applied, nothing verified — is `watching`, and
 * its sentence says so out loud.
 */
const FIX_PRESENTATION = Object.freeze({
  [VERIFICATION_STATE.FIX_PROPOSED]: ['watching', 'Correction disponible',
    'Une correction est proposée. Examinez-la avant de l’appliquer.'],
  [VERIFICATION_STATE.FIX_APPLIED]: ['watching', 'Correction appliquée',
    'Vérifions que la vulnérabilité a réellement disparu.'],
  [VERIFICATION_STATE.VALIDATING]: ['thinking', 'Vérification de la correction…',
    'Le contrôle de sécurité correspondant est en cours.'],
  [VERIFICATION_STATE.VALIDATED]: ['success', 'Correction vérifiée ✓',
    'Le re-scan ne retrouve plus ce problème.'],
  [VERIFICATION_STATE.STILL_PRESENT]: ['warning', 'Le problème est toujours présent',
    'La correction appliquée n’a pas fait disparaître le finding.'],
  [VERIFICATION_STATE.VALIDATION_FAILED]: ['warning', 'Vérification impossible',
    'Le scanner n’a pas fourni assez de preuves pour conclure.'],
  [VERIFICATION_STATE.INCONCLUSIVE]: ['warning', 'Vérification non concluante',
    'Le scanner n’a pas fourni assez de preuves pour conclure.'],
  [VERIFICATION_STATE.REGRESSED]: ['warning', 'Ce problème est réapparu',
    'Il avait été validé auparavant : la vulnérabilité est revenue.'],
  // Aliases kept for the surfaces that already speak this shorter vocabulary.
  available: ['watching', 'Correction disponible',
    'Une correction déterministe est proposée pour ce problème.'],
  applied: ['watching', 'Correction appliquée', 'Relancez une analyse pour la valider.'],
  failed: ['warning', 'La vérification de la correction a échoué',
    'Le problème est encore détecté après re-scan.']
});


/**
 * The severity a remediation verdict carries on its own.
 *
 * A regression is the one verdict that is worse than the finding it came from:
 * something that was proven fixed is back. It escalates even when the file being
 * edited has no live finding to supply a severity.
 */
function fixSeverity(fixState) {
  return String(fixState || '') === VERIFICATION_STATE.REGRESSED ? 'critical' : 'high';
}

/** Where a remediation stands. A report, never a trigger. */
function fixMessage(fixState, remediationAvailable) {
  const presentation = FIX_PRESENTATION[String(fixState || '')];
  if (presentation) {
    const [mascot, headline, detail] = presentation;
    return message('fix', mascot, headline, detail, { fixState: String(fixState) });
  }
  if (remediationAvailable) {
    const [mascot, headline, detail] = FIX_PRESENTATION.available;
    return message('fix', mascot, headline, detail, { fixState: 'available' });
  }
  return null;
}

/**
 * Which remediation state the companion should report, out of a finding list.
 *
 * Bad news first, and deliberately so: a regression outranks a validation,
 * because a companion that leads with « vérifiée ✓ » while another finding has
 * come back is telling the truth about one finding and lying about the state of
 * the workspace. Within equal news, the state that still needs the developer
 * wins over the one that does not.
 *
 * This is the single place a finding list becomes a companion fix state. It
 * reads the canonical triage status and derives nothing of its own.
 */
const FIX_STATE_PRIORITY = Object.freeze([
  VERIFICATION_STATE.REGRESSED,
  VERIFICATION_STATE.STILL_PRESENT,
  VERIFICATION_STATE.VALIDATION_FAILED,
  VERIFICATION_STATE.INCONCLUSIVE,
  VERIFICATION_STATE.VALIDATING,
  VERIFICATION_STATE.FIX_APPLIED,
  VERIFICATION_STATE.FIX_PROPOSED,
  VERIFICATION_STATE.VALIDATED
]);

function verificationFixState(findings = []) {
  const present = new Set(
    (Array.isArray(findings) ? findings : [])
      .map((finding) => String(finding?.triageStatus || ''))
  );
  return FIX_STATE_PRIORITY.find((state) => present.has(state)) || '';
}

/** Supply-chain evidence actually produced by the stages that ran. */
function supplyChainMessage(supplyChain) {
  if (!supplyChain) return null;
  if (supplyChain.signing === 'failed') {
    return message('supply-chain', 'warning', 'Vérification de signature échouée', 'L’artefact n’est pas vérifié.');
  }
  if (supplyChain.signing === 'verified') return message('supply-chain', 'success', 'Signature vérifiée ✓', '');
  if (supplyChain.signing === 'signed') return message('supply-chain', 'success', 'Artefact signé', '');
  if (supplyChain.provenance === 'generated') return message('supply-chain', 'success', 'Provenance générée', '');
  if (supplyChain.sbom === 'generated') return message('supply-chain', 'success', 'SBOM généré', '');
  return null;
}

/**
 * Where a click on the companion should go.
 *
 * Decided here, next to the message, so a surface never has to guess what its
 * own bubble was about. Only commands that already exist are returned, and none
 * of them applies a fix or calls a model.
 */
function companionActionFor(message) {
  if (!message) return null;
  if (message.kind === 'live-critical' || message.kind === 'live-findings') return { command: 'securityCenter.openLiveFinding', scope: 'finding' };
  if (message.kind === 'scanner-health') return { command: 'securityCenter.openScannerSetup', scope: 'scanner' };
  if (message.kind === 'policy-block') return { command: 'securityCenter.openSecurityPipeline', scope: 'policy' };
  if (message.kind === 'supply-chain') return { command: 'securityCenter.openSecurityPipeline', scope: 'supply-chain' };
  if (message.kind === 'scan-outcome' || message.kind === 'scan-report') return { command: 'securityCenter.openDashboard', scope: 'scan' };
  return { command: 'securityCenter.openLiveSecurityPage', scope: 'live' };
}

/**
 * The project-level line, shown small under the primary message.
 *
 * Never a headline, and never the same fact twice: a policy verdict already
 * carried by the primary message is not repeated here. Returns `null` when
 * nothing project-level is actually known — an absent fact stays absent.
 */
function secondaryFor(primary, context = {}) {
  const { scanStatus = '', policyStatus = '' } = context;
  const status = String(policyStatus).toUpperCase();
  // A green gate is worth a quiet mention; a blocking one is already the headline.
  if (status === 'PASS' && primary?.kind !== 'policy-block') {
    return message('policy-pass', 'success', 'Politique projet respectée', '');
  }
  // Never repeat a total the primary message already states.
  if (['scan-report', 'scan-outcome'].includes(primary?.kind)) return null;
  if (scanStatus === 'completed' && Number.isFinite(context.scanFindingCount)) {
    const total = context.scanFindingCount;
    return message('scan-summary', total ? 'watching' : 'success',
      `Dernier scan complet : ${total} ${pluralize(total, 'finding', 'findings')}`,
      Number.isFinite(context.scanPriorityCount) ? `Dont ${context.scanPriorityCount} prioritaire(s).` : '',
      { scanFindingCount: total });
  }
  return null;
}

/** A concrete headline for the most dangerous rule families. */
function criticalHeadline(findings) {
  const rules = new Set(findings.map((finding) => finding.ruleId));
  if (rules.has('dynamic-command-execution') || rules.has('shell-child-process')) {
    return 'Attention : une commande système reçoit une entrée utilisateur';
  }
  if (rules.has('unsafe-eval') || rules.has('unsafe-function-constructor')) {
    return 'Attention : du code dynamique est évalué à l’exécution';
  }
  if (rules.has('sql-string-concatenation')) return 'Attention : une requête SQL est construite par concaténation';
  if (rules.has('hardcoded-credential')) return 'Attention : un secret semble écrit en dur';
  if (rules.has('tls-verification-disabled')) return 'Attention : la vérification TLS est désactivée';
  return 'Attention : problème de sécurité potentiel';
}

function summarizeSeverities(findings) {
  const counts = {};
  for (const finding of findings) {
    const key = String(finding.severity || 'unknown').toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((left, right) => severityRank(right[0]) - severityRank(left[0]))
    .map(([severity, count]) => `${count} ${severity[0].toUpperCase()}${severity.slice(1)}`)
    .join(' · ');
}

/**
 * Rank of a message kind. Lower wins.
 *
 * Secondary kinds rank after every primary one, so an unknown kind can never
 * accidentally outrank a real alert — `indexOf` returning -1 would have made a
 * project note look like the most urgent thing on screen.
 */
function priorityOf(kind) {
  const primary = PRIORITIES.indexOf(kind);
  if (primary !== -1) return primary;
  const secondary = SECONDARY_PRIORITIES.indexOf(kind);
  return secondary === -1 ? PRIORITIES.length + SECONDARY_PRIORITIES.length : PRIORITIES.length + secondary;
}

function message(kind, mascot, headline, detail = '', extra = {}) {
  return {
    kind,
    priority: priorityOf(kind),
    mascot: MASCOT_STATES.includes(mascot) ? mascot : 'idle',
    // Whether the bubble should fade on its own once read.
    transient: TRANSIENT_KINDS.includes(kind),
    mood: MASCOT_TO_MOOD[mascot] || 'watching',
    headline,
    detail,
    ...extra
  };
}

/**
 * Anti-spam gate.
 *
 * The companion must not react to every keystroke. A message is only allowed
 * through when it actually says something new, and a repeat of the same
 * message is held for a cooldown. Higher-priority messages bypass the cooldown:
 * a critical finding should never wait behind « j'analyse… ».
 */
class CompanionMessageGate {
  constructor({ cooldownMs = 1500, now = () => Date.now() } = {}) {
    this.cooldownMs = cooldownMs;
    this.now = now;
    this.lastKey = '';
    this.lastAt = 0;
    this.lastPriority = Number.POSITIVE_INFINITY;
  }
  /** Identity of a message: same kind and same words means same message. */
  static keyOf(message) {
    return `${message.kind}|${message.headline}|${message.detail}`;
  }
  /** True when the companion should update its visible message. */
  accept(message) {
    if (!message) return false;
    const key = CompanionMessageGate.keyOf(message);
    const at = this.now();
    if (key === this.lastKey) {
      // Identical message: refresh nothing, whatever the frequency.
      return false;
    }
    const moreUrgent = message.priority < this.lastPriority;
    if (!moreUrgent && at - this.lastAt < this.cooldownMs) return false;
    this.lastKey = key;
    this.lastAt = at;
    this.lastPriority = message.priority;
    return true;
  }
  reset() {
    this.lastKey = '';
    this.lastAt = 0;
    this.lastPriority = Number.POSITIVE_INFINITY;
  }
}

/**
 * The single visual model both companion surfaces render.
 *
 * The sidebar and the dashboard never compute a state of their own: they read
 * this object. That is what guarantees the two can never disagree — there is
 * only one place where the state is decided.
 */
function buildCompanionVisualModel({
  serviceState = 'idle', findings = [], file = '', pipeline = {}, animations = true
} = {}) {
  const { mascotVisualFor } = require('./companionMascot');
  const companionState = normalizeCompanionState(serviceState, pipeline);
  const message = companionMessageFor(companionState, { findings, file, ...pipeline });
  const severity = highestSeverity(findings);
  const serviceMascot = mascotVisualFor(companionState, { severity, policyStatus: pipeline.policyStatus });
  // A remediation verdict is about a specific finding, and it is what the
  // developer just acted on — so when the ladder settles on a `fix` message, its
  // posture wins over the ambient service state. Without this the mascot kept
  // celebrating `clean` while the bubble said « le problème est toujours présent ».
  //
  // The escalation still comes from `mascotVisualFor`: a regression on a critical
  // finding reads `critical`, not merely `warning`. Nothing new decides posture.
  // `watching` is included deliberately. A fix that is applied but unverified
  // must never inherit the ambient `clean` posture: a celebrating mascot above
  // « vérifions que la vulnérabilité a disparu » is the false success this
  // lifecycle exists to prevent. Attentive is the honest posture.
  const mascotState = message?.kind === 'fix'
    ? (message.mascot === 'warning'
      ? mascotVisualFor('findings', { severity: severity || fixSeverity(pipeline.fixState) })
      : message.mascot)
    : serviceMascot;
  return {
    state: companionState,
    mascotState,
    message,
    // The project-level line. A surface may show it small under the primary
    // message, or drop it entirely when it has no room — never as the headline.
    secondary: secondaryFor(message, pipeline),
    // Where a click on the companion leads, decided with the message.
    action: companionActionFor(message),
    // One short line: never an explanation, just a status.
    shortMessage: shortMessageFor(message, findings),
    // Two independent facts, never merged. `live*` describes the file being
    // edited and comes from the Live detectors; `fullScan` describes the last
    // workspace scan. A surface that shows both must label them separately.
    liveFindingCount: findings.length,
    liveHighestSeverity: severity,
    fullScan: {
      status: pipeline.scanStatus || '',
      findingCount: Number.isFinite(pipeline.scanFindingCount) ? pipeline.scanFindingCount : null,
      priorityCount: Number.isFinite(pipeline.scanPriorityCount) ? pipeline.scanPriorityCount : null
    },
    // Kept as the Live aliases the existing surfaces already read.
    findingCount: findings.length,
    highestSeverity: severity,
    severityBreakdown: summarizeSeverities(findings),
    currentFile: file,
    animations: animations !== false,
    // Actions the surfaces may offer, gated on what really exists.
    actions: {
      view: findings.length > 0,
      fix: findings.length > 0,
      fullScan: true,
      openCompanion: true
    }
  };
}

/** Service vocabulary → companion vocabulary, with the degraded case. */
function normalizeCompanionState(serviceState, { performanceReduced = false } = {}) {
  if (serviceState === 'issues') return 'findings';
  if (serviceState === 'paused') return 'degraded';
  if (performanceReduced && ['idle', 'clean'].includes(serviceState)) return 'degraded';
  return COMPANION_STATES.includes(serviceState) ? serviceState : 'idle';
}

/** A dashboard-sized line: one clause, no sentence. */
function shortMessageFor(message, findings = []) {
  if (!message) return '';
  if (message.kind === 'live-critical' || message.kind === 'live-findings') {
    return `${findings.length} ${findings.length === 1 ? 'problème Live' : 'problèmes Live'}`;
  }
  const short = {
    error: 'Analyse Live impossible',
    disabled: 'Live Security désactivé',
    'policy-block': 'La politique bloque la livraison',
    'scanner-health': message.headline,
    scanning: message.headline.replace(/…$/, '…'),
    // Never "aucun problème" on its own: the sentence has to name its scope,
    // otherwise it reads as a verdict on the whole workspace.
    clean: 'Aucun problème Live dans ce fichier',
    'scan-summary': `Dernière analyse : ${message.scanFindingCount} ${message.scanFindingCount === 1 ? 'finding' : 'findings'}`,
    idle: message.headline
  }[message.kind];
  return short || message.headline;
}

module.exports = {
  verificationFixState, FIX_PRESENTATION,
  MASCOT_STATES, COMPANION_STATES, MASCOT_TO_MOOD, PRIORITIES, SECONDARY_PRIORITIES, TRANSIENT_KINDS,
  companionMessageFor, secondaryFor, companionActionFor, shortScannerIssue,
  scanProgressHeadline, scanOutcomeMessage, scanReportMessage, fixMessage, supplyChainMessage,
  CompanionMessageGate, buildCompanionVisualModel,
  normalizeCompanionState, shortMessageFor,
  highestSeverity, summarizeSeverities, criticalHeadline, severityRank
};
