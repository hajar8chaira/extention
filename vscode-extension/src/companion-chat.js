'use strict';

/**
 * The Security Companion conversation.
 *
 * The Companion explains; it never repairs. That separation is the whole design:
 * this module builds a compact, redacted picture of what Security Center already
 * knows, asks the local model to talk about it, and routes anything that would
 * change a file back through the existing Fix & Verify flow. It holds no patch
 * logic, calls no scanner, and writes nothing.
 *
 * Everything it sends is derived from state that is already on screen. Nothing
 * here reads SecretStorage, and every string that could carry a credential goes
 * through the same redaction the remediation prompts already use.
 */

const { redactSecrets } = require('./ai/secret-redaction');

/** Conversation lifecycle, shared by the rail and the full panel. */
const CHAT_STATE = Object.freeze({
  IDLE: 'idle',
  THINKING: 'thinking',
  ANSWERED: 'answered',
  ERROR: 'error',
  CANCELLED: 'cancelled'
});

const ROLE = Object.freeze({ USER: 'user', ASSISTANT: 'assistant' });

/** Surfaces the assistant can describe. Anything else falls back to workspace. */
const SURFACES = Object.freeze({
  dashboard: 'Workspace overview',
  findings: 'Findings list',
  finding: 'Finding details',
  scans: 'Scan history',
  'scanner-setup': 'Scanner configuration',
  pipeline: 'Security Pipeline',
  runtime: 'Runtime Security',
  infrastructure: 'Infrastructure',
  delivery: 'Security Delivery',
  live: 'Live Security'
});

/**
 * The safety contract the model is held to.
 *
 * Written as constraints rather than encouragement: the failure mode that
 * matters for a security tool is a confident answer that is not backed by
 * evidence, so "say the data is missing" is stated as the preferred outcome.
 */
const ASSISTANT_SYSTEM_PROMPT = [
  'Tu es le Security Companion de Security Center, un assistant de sécurité applicative.',
  'Tu expliques et tu guides. Tu ne modifies jamais de fichier et tu ne produis jamais de patch.',
  '',
  'Règles absolues :',
  '- Réponds d’abord à partir du CONTEXTE Security Center fourni. Il fait autorité.',
  '- Distingue toujours ce qu’un scanner a réellement observé de ce que tu déduis.',
  '- Si le contexte ne contient pas l’information, dis-le explicitement. Ne devine pas.',
  '- N’affirme jamais qu’une vulnérabilité est exploitable sans preuve dans le contexte.',
  '- N’affirme jamais qu’un finding est corrigé si la vérification ne le dit pas.',
  '- N’invente jamais de CVE, de CWE, de règle, de score ou de chiffre.',
  '- Ne révèle aucun secret et ne reproduis aucune valeur masquée.',
  '- Pour un secret exposé : expliquer qu’il faut le révoquer/renouveler puis le charger',
  '  depuis une configuration sécurisée. Remplacer la valeur par un masque ne corrige rien.',
  '- Si l’utilisateur demande une correction, explique que Security Center peut en générer',
  '  une avec validation et confirmation, et renvoie-le vers l’action « Proposer une correction ».',
  '  Ne produis pas le code corrigé toi-même.',
  '',
  'Style : concis et opérationnel. Des puces courtes. Pas de préambule.',
  'Termine par une prochaine action concrète quand elle existe.'
].join('\n');

/** Only these keys ever leave the extension, and only when they have a value. */
function compact(entries) {
  return Object.fromEntries(Object.entries(entries).filter(([, value]) => {
    if (value === null || value === undefined) return false;
    if (typeof value === 'string') return value.trim() !== '';
    if (Array.isArray(value)) return value.length > 0;
    return true;
  }));
}

/** Redacts any free text before it can reach a prompt. */
function safeText(value, limit = 400) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  return redactSecrets(text).slice(0, limit);
}

/**
 * The finding, as the assistant may see it.
 *
 * A scanner title can quote the offending line, so titles and evidence are
 * redacted like everything else. Absent verdicts stay absent: `reachability`
 * missing means « not evaluated », which the model is told to report as such
 * rather than fill in.
 */
function findingContext(finding, { similarFindingCount = null } = {}) {
  if (!finding) return null;
  return compact({
    findingId: safeText(finding.id, 200),
    title: safeText(finding.title, 200),
    scanner: safeText(finding.tool, 60),
    rule: safeText(finding.ruleId, 120),
    cwe: safeText(finding.cwe, 60),
    severity: safeText(finding.rawSeverity || finding.severity, 30),
    priority: Number.isFinite(finding.priority?.score)
      ? `${finding.priority.score}/100${finding.priority.code ? ` (${finding.priority.code})` : ''}` : '',
    priorityReasons: (finding.priority?.reasons || []).slice(0, 4).map((reason) => safeText(reason, 140)),
    file: safeText(finding.file || finding.endpoint, 200),
    line: Number.isFinite(finding.startLine) ? finding.startLine : null,
    reachability: finding.reachability
      ? safeText(`${finding.reachability.status || ''} — ${finding.reachability.reason || ''}`, 240) : '',
    status: safeText(finding.triageStatus, 40),
    verification: finding.verification
      ? compact({
        state: safeText(finding.verification.state, 40),
        reason: safeText(finding.verification.reason, 80),
        verifier: safeText(finding.verification.evidence?.tool || finding.verification.validator, 60),
        at: safeText(finding.verification.at, 40)
      }) : null,
    remediation: safeText(finding.remediation || finding.fix, 300),
    evidence: safeText(finding.evidence, 200),
    aiSummary: safeText(finding.aiSummary, 200),
    correlatedTools: (finding.correlatedTools || []).slice(0, 6).map((tool) => safeText(tool, 40)),
    similarFindingCount: Number.isFinite(similarFindingCount) ? similarFindingCount : null
  });
}

/** Scanner health, from the statuses already displayed. */
function scannerContext(scanners = []) {
  return scanners.slice(0, 10).map((scanner) => compact({
    tool: safeText(scanner.tool, 40),
    status: safeText(scanner.status, 30),
    details: safeText(scanner.details, 140),
    error: safeText(scanner.error, 200),
    durationMs: Number.isFinite(scanner.durationMs) ? scanner.durationMs : null
  }));
}

/**
 * Builds the whole picture, per surface.
 *
 * Kept deliberately small: the model is given what the user is looking at, not
 * the workspace. Sending every finding would be slower, less accurate and would
 * widen the redaction surface for no benefit.
 */
function buildAssistantContext({
  surface = 'dashboard', finding = null, findings = [], scanners = [], scan = null,
  pipeline = null, runtime = null, infrastructure = null, similarFindingCount = null
} = {}) {
  const active = Array.isArray(findings) ? findings : [];
  const base = {
    surface,
    surfaceLabel: SURFACES[surface] || SURFACES.dashboard,
    workspaceFindingCount: active.length
  };

  if (surface === 'finding' && finding) {
    return compact({ ...base, finding: findingContext(finding, { similarFindingCount }) });
  }

  if (surface === 'scanner-setup' || surface === 'scans') {
    return compact({ ...base, scanners: scannerContext(scanners), scanStatus: safeText(scan?.status, 40) });
  }

  if (surface === 'runtime') {
    return compact({
      ...base,
      runtime: runtime ? compact({
        provider: safeText(runtime.provider?.label || runtime.label, 60),
        connectionStatus: safeText(runtime.connectionStatus || runtime.status, 40),
        message: safeText(runtime.message, 200),
        // Booleans only. No credential, no token, ever.
        credentialsConfigured: typeof runtime.credentialsConfigured === 'boolean' ? runtime.credentialsConfigured : null,
        endpoints: runtime.endpointSummary || runtime.agentSummary || null,
        alerts: runtime.alertSummary || null,
        lastSync: safeText(runtime.lastSync || runtime.lastChecked, 40)
      }) : null
    });
  }

  if (surface === 'infrastructure') {
    const metrics = infrastructure?.metrics || {};
    return compact({
      ...base,
      infrastructure: infrastructure ? compact({
        provider: safeText(infrastructure.label, 60),
        status: safeText(infrastructure.status, 40),
        message: safeText(infrastructure.message, 200),
        credentialsConfigured: typeof infrastructure.credentialsConfigured === 'boolean' ? infrastructure.credentialsConfigured : null,
        targets: safeText(infrastructure.targets?.display, 40),
        // « Unavailable » is a real answer and is preserved as one.
        cpu: metrics.cpu?.available ? safeText(metrics.cpu.display, 30) : 'unavailable',
        memory: metrics.memory?.available ? safeText(metrics.memory.display, 40) : 'unavailable',
        disk: metrics.disk?.available ? safeText(metrics.disk.display, 30) : 'unavailable',
        load: metrics.load1?.available ? safeText(metrics.load1.display, 30) : 'unavailable'
      }) : null
    });
  }

  if (surface === 'pipeline') {
    return compact({
      ...base,
      pipeline: pipeline ? compact({
        status: safeText(pipeline.status, 40),
        policy: safeText(pipeline.policy?.status, 40),
        policySummary: safeText(pipeline.policy?.summary, 200),
        correlations: Number.isFinite(pipeline.clusters?.length) ? pipeline.clusters.length : null,
        priorities: pipeline.prioritySummary?.distribution || null,
        intelligence: safeText(pipeline.intelligence?.status, 40)
      }) : null,
      scanners: scannerContext(scanners)
    });
  }

  // Dashboard / findings / anything else: posture only, never the full list.
  const bySeverity = {};
  for (const item of active) {
    const key = String(item.rawSeverity || item.severity || 'UNKNOWN').toUpperCase();
    bySeverity[key] = (bySeverity[key] || 0) + 1;
  }
  return compact({
    ...base,
    severityBreakdown: Object.keys(bySeverity).length ? bySeverity : null,
    scanners: scannerContext(scanners),
    scanStatus: safeText(scan?.status, 40),
    topFindings: active.slice(0, 5).map((item) => compact({
      title: safeText(item.title, 120),
      scanner: safeText(item.tool, 40),
      severity: safeText(item.rawSeverity || item.severity, 30),
      priority: Number.isFinite(item.priority?.score) ? item.priority.score : null
    }))
  });
}

/** The truthful one-line indicator shown above the composer. */
function contextIndicator(context = {}) {
  if (context.finding) {
    const parts = [context.finding.scanner, context.finding.rule].filter(Boolean).join(' · ');
    const location = [context.finding.file, context.finding.line].filter(Boolean).join(':');
    return { label: parts || 'Finding', detail: location || context.finding.title || '' };
  }
  if (context.surface === 'runtime') return { label: 'Runtime Security', detail: context.runtime?.provider || 'Aucun fournisseur' };
  if (context.surface === 'infrastructure') return { label: 'Infrastructure', detail: context.infrastructure?.provider || 'Aucun fournisseur' };
  if (context.surface === 'pipeline') return { label: 'Security Pipeline', detail: context.pipeline?.policy || '' };
  if (context.surface === 'scanner-setup') return { label: 'Configuration des scanners', detail: '' };
  return { label: context.surfaceLabel || 'Workspace overview', detail: context.workspaceFindingCount ? `${context.workspaceFindingCount} finding(s)` : '' };
}

/** Prompt shortcuts. They are questions, not commands: same chat path. */
function quickQuestionsFor(context = {}) {
  if (context.finding) {
    return [
      'Explique ce finding',
      'Pourquoi cette priorité ?',
      'Que dois-je faire ensuite ?',
      context.finding.cwe ? 'Explique le CWE' : 'Explique la règle',
      'Montre les findings similaires'
    ];
  }
  if (context.surface === 'scanner-setup' || context.surface === 'scans') {
    return ['Pourquoi ce scanner a-t-il échoué ?', 'Que vérifie ce scanner ?', 'Comment le configurer ?'];
  }
  if (context.surface === 'runtime') return ['Combien d’agents sont actifs ?', 'Quelles alertes sont critiques ?', 'Le fournisseur est-il connecté ?'];
  if (context.surface === 'infrastructure') return ['Pourquoi une métrique est-elle indisponible ?', 'Quel est l’état des cibles ?'];
  if (context.surface === 'pipeline') return ['Pourquoi la politique bloque-t-elle ?', 'Que corriger en premier ?'];
  return ['Que dois-je corriger en premier ?', 'Résume la posture de sécurité', 'Quel scanner demande mon attention ?'];
}

/**
 * Recognises a repair request so the Companion can hand it to the real flow.
 *
 * Detection is intentionally generous: a false positive costs a helpful sentence
 * plus a button, while a miss would let the model answer a "fix this" prompt with
 * code of its own — exactly what this module exists to prevent.
 */
const FIX_REQUEST = /\b(corrige|corriger|corrigez|répare|reparer|réparer|fix|patch|apply|applique|appliquer)\b/i;

function detectFixRequest(question) {
  return FIX_REQUEST.test(String(question || ''));
}

/**
 * Builds the messages sent to the local model.
 *
 * History is trimmed and re-redacted: a question typed by the user can itself
 * contain a pasted secret, and it must not become a durable prompt payload.
 */
function buildAssistantMessages({ context = {}, history = [], question = '', maxHistory = 6 } = {}) {
  const recent = (Array.isArray(history) ? history : [])
    .filter((entry) => entry && (entry.role === ROLE.USER || entry.role === ROLE.ASSISTANT))
    .slice(-maxHistory)
    .map((entry) => ({ role: entry.role, content: safeText(entry.content, 1200) }));
  return [
    { role: 'system', content: ASSISTANT_SYSTEM_PROMPT },
    {
      role: 'system',
      content: `CONTEXTE Security Center (fait autorité) :\n${JSON.stringify(context, null, 1)}`
    },
    ...recent,
    { role: ROLE.USER, content: safeText(question, 1200) }
  ];
}

/** A session message. No storage, no identity, no profile. */
function chatMessage(role, content, extra = {}) {
  return { role, content: String(content ?? ''), at: new Date().toISOString(), ...extra };
}

/** The sentence shown when a repair is requested, plus the real route. */
function fixRoutingReply() {
  return [
    'Je n’applique pas de correction moi-même : je peux seulement expliquer.',
    '',
    'Security Center peut en générer une avec validation du patch, aperçu du diff et confirmation explicite avant toute écriture, puis relancer le scanner concerné pour vérifier le résultat.',
    '',
    'Prochaine action : « Proposer une correction » sur ce finding.'
  ].join('\n');
}

module.exports = {
  CHAT_STATE,
  ROLE,
  SURFACES,
  ASSISTANT_SYSTEM_PROMPT,
  buildAssistantContext,
  findingContext,
  scannerContext,
  contextIndicator,
  quickQuestionsFor,
  detectFixRequest,
  buildAssistantMessages,
  chatMessage,
  fixRoutingReply,
  safeText
};
