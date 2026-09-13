'use strict';

/**
 * Le socle d'exécution commun de Dynamic Security.
 *
 * Quatre moteurs y coexistent sans se ressembler : ZAP et Nuclei sont des
 * analyses finies, mitmproxy est une capture continue, Burp est un connecteur
 * piloté depuis l'extérieur. Les forcer dans le modèle de campagne existant —
 * qui parle de spidering et de file d'analyse passive — aurait donné à trois
 * moteurs sur quatre un vocabulaire qui ne les décrit pas. Ce module fournit
 * donc l'abstraction minimale qui leur est réellement commune : une exécution
 * a un moteur, une nature, une cible, un état, et ce qu'elle a produit.
 *
 * Trois règles le tiennent :
 *
 *   - **La disponibilité n'est pas l'exécution.** Un outil installé et jamais
 *     lancé est disponible. Il ne devient « indisponible » que si la détection
 *     dit qu'il l'est, jamais parce que l'historique est vide.
 *
 *   - **Un échec est un état de produit.** Un démarrage refusé, un backend
 *     injoignable, un processus qui sort seul : chacun produit un `errorCode`
 *     et une raison lisible portés par l'exécution elle-même. Le journal garde
 *     le détail technique ; il n'est plus le seul endroit où la panne existe.
 *
 *   - **Il n'invente rien.** Une progression absente reste `null`, un compteur
 *     jamais observé reste `null`, une exécution jamais lancée reste absente.
 *
 * Le module est pur : ni `vscode`, ni I/O, ni horloge propre au-delà de celle
 * qu'on lui injecte. La campagne ZAP existante continue de vivre à côté, pour
 * ce qu'elle sait faire de mieux : le détail des étapes d'un scan ZAP.
 */

/** La nature d'une exécution. Elle décide de ce que « terminé » veut dire. */
const RUN_KIND = Object.freeze({
  /** Analyse finie : elle se termine d'elle-même. ZAP, Nuclei. */
  SCAN: 'scan',
  /** Capture continue : elle dure jusqu'à ce qu'on l'arrête. mitmproxy. */
  CAPTURE: 'capture',
  /** Connecteur externe : Security Center ne le démarre pas, il l'attend. Burp. */
  CONNECTOR: 'connector'
});

const RUN_KINDS = Object.freeze(Object.values(RUN_KIND));

/**
 * Les états d'exécution, avec une sémantique explicite chacun.
 *
 * `WAITING_EXTERNAL` est distinct de `IDLE` : le premier dit que Security Center
 * attend quelqu'un d'autre et sait le dire, le second qu'il ne se passe rien.
 * `UNAVAILABLE` ne se déduit jamais d'un historique vide.
 */
const RUN_STATUS = Object.freeze({
  /** Rien en cours, rien attendu. */
  IDLE: 'IDLE',
  /** L'outil est là et peut être lancé maintenant. */
  READY: 'READY',
  /** Démarrage demandé, pas encore confirmé. */
  STARTING: 'STARTING',
  /** En cours, confirmé par le moteur ou par du trafic reçu. */
  RUNNING: 'RUNNING',
  /** Prêt côté Security Center, en attente d'un acteur externe. */
  WAITING_EXTERNAL: 'WAITING_EXTERNAL',
  /** Arrêt demandé, pas encore confirmé. */
  STOPPING: 'STOPPING',
  /** Terminé normalement. */
  COMPLETED: 'COMPLETED',
  /** Terminé sur une panne. Porte toujours un `errorCode`. */
  FAILED: 'FAILED',
  /** L'outil lui-même n'est pas utilisable. Porte toujours une raison. */
  UNAVAILABLE: 'UNAVAILABLE'
});

const RUN_STATUSES = Object.freeze(Object.values(RUN_STATUS));

/** Une exécution qui atteint l'un de ces états est close : on en crée une autre. */
const TERMINAL_RUN_STATUSES = Object.freeze([RUN_STATUS.COMPLETED, RUN_STATUS.FAILED]);

/**
 * Les causes d'échec que le produit sait nommer.
 *
 * Un code est stable et testable ; la raison qui l'accompagne est écrite pour
 * l'utilisateur. Les deux voyagent ensemble, jamais l'un sans l'autre.
 */
const RUN_ERROR = Object.freeze({
  /** Le service local Security Center ne répond pas. */
  BACKEND_UNAVAILABLE: 'BACKEND_UNAVAILABLE',
  /** L'outil n'est pas installé ou n'a pas été détecté. */
  TOOL_UNAVAILABLE: 'TOOL_UNAVAILABLE',
  /** Un prérequis manque (Java, moteur Docker…). */
  PREREQUISITE_MISSING: 'PREREQUISITE_MISSING',
  /** Le démarrage a été refusé ou a échoué avant de produire quoi que ce soit. */
  START_FAILED: 'START_FAILED',
  /** mitmdump n'a pas pu être lancé, ou n'a jamais écouté. */
  MITMDUMP_START_FAILED: 'MITMDUMP_START_FAILED',
  /** L'arrêt demandé n'a pas été confirmé : le port peut rester occupé. */
  STOP_FAILED: 'STOP_FAILED',
  /** Le processus s'est arrêté sans qu'on le lui demande. */
  PROCESS_EXITED: 'PROCESS_EXITED',
  /** Le connecteur externe ne s'est pas manifesté. */
  CONNECTOR_ABSENT: 'CONNECTOR_ABSENT',
  /** Le connecteur externe présente une clé que le backend refuse. */
  AUTH_REJECTED: 'AUTH_REJECTED',
  /** Le backend a rejeté des échanges capturés. */
  INGESTION_REJECTED: 'INGESTION_REJECTED',
  /** Des échanges capturés n'ont pas atteint Security Center : ils sont perdus. */
  INGESTION_FAILED: 'INGESTION_FAILED',
  /** L'analyse s'est terminée en erreur. */
  SCAN_FAILED: 'SCAN_FAILED',
  /** État restauré alors que le processus correspondant n'existe plus. */
  STALE_PROCESS: 'STALE_PROCESS',
  /** Arrêt demandé par l'utilisateur. */
  CANCELLED: 'CANCELLED'
});

/**
 * Les transitions autorisées.
 *
 * Un tableau explicite plutôt qu'une suite de `if` : c'est lui qu'on lit pour
 * savoir ce que le système peut faire, et lui que les tests interrogent.
 */
const ALLOWED_TRANSITIONS = Object.freeze({
  [RUN_STATUS.IDLE]: [RUN_STATUS.READY, RUN_STATUS.STARTING, RUN_STATUS.WAITING_EXTERNAL, RUN_STATUS.UNAVAILABLE],
  [RUN_STATUS.READY]: [RUN_STATUS.STARTING, RUN_STATUS.WAITING_EXTERNAL, RUN_STATUS.UNAVAILABLE, RUN_STATUS.IDLE],
  [RUN_STATUS.STARTING]: [RUN_STATUS.RUNNING, RUN_STATUS.WAITING_EXTERNAL, RUN_STATUS.STOPPING, RUN_STATUS.COMPLETED, RUN_STATUS.FAILED],
  [RUN_STATUS.RUNNING]: [RUN_STATUS.RUNNING, RUN_STATUS.WAITING_EXTERNAL, RUN_STATUS.STOPPING, RUN_STATUS.COMPLETED, RUN_STATUS.FAILED],
  [RUN_STATUS.WAITING_EXTERNAL]: [RUN_STATUS.RUNNING, RUN_STATUS.WAITING_EXTERNAL, RUN_STATUS.STOPPING, RUN_STATUS.COMPLETED, RUN_STATUS.FAILED, RUN_STATUS.UNAVAILABLE, RUN_STATUS.IDLE],
  [RUN_STATUS.STOPPING]: [RUN_STATUS.COMPLETED, RUN_STATUS.FAILED],
  [RUN_STATUS.COMPLETED]: [],
  [RUN_STATUS.FAILED]: [],
  [RUN_STATUS.UNAVAILABLE]: [RUN_STATUS.READY, RUN_STATUS.IDLE, RUN_STATUS.STARTING]
});

/** Libellés d'interface. Le rendu ne réinvente pas de vocabulaire. */
const RUN_STATUS_LABEL = Object.freeze({
  [RUN_STATUS.IDLE]: 'INACTIF',
  [RUN_STATUS.READY]: 'PRÊT',
  [RUN_STATUS.STARTING]: 'DÉMARRAGE',
  [RUN_STATUS.RUNNING]: 'EN COURS',
  [RUN_STATUS.WAITING_EXTERNAL]: 'EN ATTENTE',
  [RUN_STATUS.STOPPING]: 'ARRÊT EN COURS',
  [RUN_STATUS.COMPLETED]: 'TERMINÉ',
  [RUN_STATUS.FAILED]: 'ÉCHEC',
  [RUN_STATUS.UNAVAILABLE]: 'INDISPONIBLE'
});

function isoAt(now) {
  return new Date(typeof now === 'function' ? now() : (now ?? Date.now())).toISOString();
}

/** Un entier de comptage, ou `null` quand rien n'a été observé. */
function countOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}

/** Un pourcentage réel, ou `null`. Zéro n'est jamais un substitut à « inconnu ». */
function percentOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Math.max(0, Math.min(100, Math.round(number)));
}

/** Identifiant triable par construction, distinct même à la milliseconde près. */
function runId(engine, { now = Date.now, random = () => Math.random().toString(16).slice(2, 10) } = {}) {
  const stamp = isoAt(now).replace(/[-:.]/g, '').replace('T', '-').slice(0, 15);
  return `${engine}-${stamp}-${random()}`;
}

/**
 * L'état d'outillage d'un moteur, mesuré et non déduit.
 *
 * `installed` vient d'une détection réelle. `reason` n'est renseignée que
 * lorsque l'outil est indisponible : une raison sur un outil disponible serait
 * un avertissement sans objet.
 *
 * Deux listes, deux logiques, parce que deux questions différentes se posent :
 * `prerequisites` est une conjonction — chacun manque à l'appel — tandis que
 * `alternatives` est une disjonction : un seul suffit. ZAP en est le cas réel.
 * Il s'exécute par une installation locale **ou** par le moteur Docker, et les
 * décrire comme des prérequis rendait « indisponible » un ZAP local
 * parfaitement fonctionnel au seul motif que Docker n'était pas démarré.
 */
function availability({ installed = false, version = '', executable = '', managed = false, prerequisites = [], alternatives = [], reason = '', detail = '', checkedAt = null } = {}) {
  const normalize = (list) => (Array.isArray(list) ? list : [])
    .filter((item) => item && item.name)
    .map((item) => ({
      name: String(item.name),
      satisfied: item.satisfied === true,
      detail: String(item.detail || '')
    }));
  const missing = normalize(prerequisites);
  const options = normalize(alternatives);
  const blocked = missing.filter((item) => !item.satisfied);
  // Sans alternative déclarée, rien à satisfaire : la question ne se pose pas.
  const anyOption = options.length === 0 || options.some((item) => item.satisfied);
  const usable = installed === true && blocked.length === 0 && anyOption;
  return {
    installed: installed === true,
    usable,
    version: String(version || ''),
    executable: String(executable || ''),
    managed: managed === true,
    prerequisites: missing,
    alternatives: options,
    // Une raison est obligatoire dès que l'outil n'est pas utilisable : c'est
    // elle que la carte affiche à la place d'un « indisponible » muet.
    reason: usable
      ? ''
      : String(reason
        || (blocked.length ? `Prérequis manquant : ${blocked.map((item) => item.name).join(', ')}.` : '')
        || (!anyOption ? `Aucun moteur disponible : ${options.map((item) => item.name).join(' ou ')}.` : '')
        || 'Outil non détecté.'),
    detail: String(detail || ''),
    checkedAt: checkedAt || null
  };
}

/** Un moteur dont la disponibilité n'a pas encore été mesurée. */
function unknownAvailability() {
  return { ...availability({ reason: 'Disponibilité non encore vérifiée.' }), checked: false };
}

/**
 * Une nouvelle exécution.
 *
 * Elle naît en `STARTING` par défaut — demandée, pas encore confirmée — parce
 * qu'aucun moteur ne confirme son démarrage instantanément. Un connecteur, lui,
 * naît en `WAITING_EXTERNAL` : personne ne l'a démarré, on l'attend.
 */
function createRun({ engine, kind, target = '', status = '', phase = '', id = '', now = Date.now, random } = {}) {
  if (!engine) throw new Error('Moteur absent.');
  if (!RUN_KINDS.includes(kind)) throw new Error(`Nature d'exécution inconnue : ${kind}.`);
  const initial = status || (kind === RUN_KIND.CONNECTOR ? RUN_STATUS.WAITING_EXTERNAL : RUN_STATUS.STARTING);
  if (!RUN_STATUSES.includes(initial)) throw new Error(`État d'exécution inconnu : ${initial}.`);
  const startedAt = isoAt(now);
  return {
    id: id || runId(engine, { now, random }),
    engine: String(engine),
    kind,
    target: String(target || ''),
    status: initial,
    phase: String(phase || ''),
    progress: null,
    startedAt,
    finishedAt: null,
    lastActivity: null,
    requestCount: null,
    findingCount: null,
    errorCode: '',
    errorReason: '',
    history: [{ status: initial, at: startedAt, phase: String(phase || ''), progress: null, detail: '' }]
  };
}

/** Si la transition est permise. Rester dans le même état ne l'est que pour `RUNNING`. */
function canTransition(from, to) {
  if (!RUN_STATUSES.includes(from) || !RUN_STATUSES.includes(to)) return false;
  return (ALLOWED_TRANSITIONS[from] || []).includes(to);
}

/**
 * Applique une observation d'exécution.
 *
 * Refuse une transition illégale plutôt que de la subir : un scan terminé qui
 * se remettrait à « en cours » est un bug, pas un état. Les compteurs et la
 * progression se mettent à jour sans changer l'état quand `status` est omis.
 */
function transitionRun(run, { status = '', phase, progress, requestCount, findingCount, detail = '', errorCode = '', errorReason = '', now = Date.now } = {}) {
  if (!run) throw new Error('Exécution absente.');
  const next = status || run.status;
  if (!RUN_STATUSES.includes(next)) throw new Error(`État d'exécution inconnu : ${next}.`);
  if (next !== run.status && !canTransition(run.status, next)) {
    throw new Error(`Transition interdite : ${run.status} → ${next}.`);
  }
  const at = isoAt(now);
  const percent = progress === undefined ? run.progress : percentOrNull(progress);
  const requests = requestCount === undefined ? run.requestCount : countOrNull(requestCount);
  const findings = findingCount === undefined ? run.findingCount : countOrNull(findingCount);
  const nextPhase = phase === undefined ? run.phase : String(phase || '');
  const terminal = TERMINAL_RUN_STATUSES.includes(next);
  const changed = next !== run.status || nextPhase !== run.phase || percent !== run.progress
    || requests !== run.requestCount || findings !== run.findingCount;
  return {
    ...run,
    status: next,
    phase: nextPhase,
    progress: percent,
    requestCount: requests,
    findingCount: findings,
    // Seule une observation qui apporte quelque chose fait avancer l'horloge
    // d'activité : un sondage identique n'est pas de l'activité.
    lastActivity: changed ? at : run.lastActivity,
    finishedAt: terminal ? at : run.finishedAt,
    errorCode: next === RUN_STATUS.FAILED ? String(errorCode || run.errorCode || RUN_ERROR.SCAN_FAILED) : (errorCode ? String(errorCode) : run.errorCode),
    errorReason: next === RUN_STATUS.FAILED ? String(errorReason || run.errorReason || '') : (errorReason ? String(errorReason) : run.errorReason),
    history: changed
      ? [...run.history, { status: next, at, phase: nextPhase, progress: percent, detail: String(detail || '') }]
      : run.history
  };
}

/**
 * Enregistre de l'activité observée sans prétendre à un changement d'état.
 *
 * C'est le geste d'une capture : du trafic arrive, l'exécution reste en cours.
 * Le passage `STARTING → RUNNING` est fait ici parce qu'un premier échange reçu
 * est précisément la preuve que la capture fonctionne.
 */
function recordActivity(run, { requestCount, findingCount, at = null, now = Date.now } = {}) {
  if (!run) throw new Error('Exécution absente.');
  if (TERMINAL_RUN_STATUSES.includes(run.status)) return run;
  const requests = requestCount === undefined ? run.requestCount : countOrNull(requestCount);
  const findings = findingCount === undefined ? run.findingCount : countOrNull(findingCount);
  const observed = (requests !== null && requests !== run.requestCount) || (findings !== null && findings !== run.findingCount);
  if (!observed) return run;
  const promoted = run.status === RUN_STATUS.STARTING || run.status === RUN_STATUS.WAITING_EXTERNAL
    ? RUN_STATUS.RUNNING
    : run.status;
  return transitionRun(run, {
    status: promoted,
    requestCount: requests,
    findingCount: findings,
    detail: 'activité observée',
    now: at ? () => new Date(at).getTime() : now
  });
}

/** Clôt une exécution sur une panne nommée. */
function failRun(run, { errorCode = RUN_ERROR.START_FAILED, errorReason = '', now = Date.now } = {}) {
  if (!run) throw new Error('Exécution absente.');
  if (TERMINAL_RUN_STATUSES.includes(run.status)) return run;
  return transitionRun(run, { status: RUN_STATUS.FAILED, errorCode, errorReason, detail: errorReason, now });
}

/** Clôt une exécution normalement, avec ce qu'elle a produit. */
function completeRun(run, { requestCount, findingCount, phase = '', now = Date.now } = {}) {
  if (!run) throw new Error('Exécution absente.');
  if (TERMINAL_RUN_STATUSES.includes(run.status)) return run;
  return transitionRun(run, { status: RUN_STATUS.COMPLETED, requestCount, findingCount, phase, now });
}

/**
 * Réconcilie une exécution restaurée avec la réalité du moment.
 *
 * Un rechargement de fenêtre tue les processus enfants mais pas les données :
 * une capture persistée « en cours » raconterait, après rechargement, un proxy
 * qui n'existe plus. `alive` est la réponse d'une vérification réelle — port
 * ouvert, processus vivant, battement de cœur récent — jamais une supposition.
 */
function reconcileRun(run, { alive = false, now = Date.now, reason = '' } = {}) {
  if (!run) return null;
  if (TERMINAL_RUN_STATUSES.includes(run.status)) return run;
  if (alive) return run;
  if (run.kind === RUN_KIND.CONNECTOR) {
    // Un connecteur externe ne « échoue » pas parce qu'on a rechargé : il n'est
    // simplement plus là, et on le réattend.
    return run.status === RUN_STATUS.WAITING_EXTERNAL ? run : transitionRun(run, {
      status: RUN_STATUS.WAITING_EXTERNAL,
      errorCode: RUN_ERROR.CONNECTOR_ABSENT,
      errorReason: reason || 'Aucun battement du connecteur depuis le rechargement.',
      now
    });
  }
  return transitionRun(run, {
    status: RUN_STATUS.FAILED,
    errorCode: RUN_ERROR.STALE_PROCESS,
    errorReason: reason || 'Le processus n’existe plus après le rechargement de la fenêtre.',
    detail: 'réconciliation au démarrage',
    now
  });
}

/**
 * Restaure une exécution persistée.
 *
 * Tout ce qui n'est pas reconnaissable revient `null` plutôt qu'à moitié
 * construit : un cache écrit par une version antérieure ne doit ni faire tomber
 * la page, ni se faire passer pour une exécution valide.
 */
function restoreRun(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (!raw.id || !raw.engine) return null;
  if (!RUN_KINDS.includes(raw.kind)) return null;
  if (!RUN_STATUSES.includes(raw.status)) return null;
  return {
    id: String(raw.id),
    engine: String(raw.engine),
    kind: raw.kind,
    target: String(raw.target || ''),
    status: raw.status,
    phase: String(raw.phase || ''),
    progress: percentOrNull(raw.progress),
    startedAt: raw.startedAt || null,
    finishedAt: raw.finishedAt || null,
    lastActivity: raw.lastActivity || null,
    requestCount: countOrNull(raw.requestCount),
    findingCount: countOrNull(raw.findingCount),
    errorCode: String(raw.errorCode || ''),
    errorReason: String(raw.errorReason || ''),
    history: Array.isArray(raw.history)
      ? raw.history.filter((entry) => entry && RUN_STATUSES.includes(entry.status)).map((entry) => ({
        status: entry.status,
        at: entry.at || null,
        phase: String(entry.phase || ''),
        progress: percentOrNull(entry.progress),
        detail: String(entry.detail || '')
      }))
      : [],
    restored: true
  };
}

/** Une exécution close, réduite à ce qu'une carte a besoin d'en dire. */
function lastRunSummary(run) {
  if (!run || !TERMINAL_RUN_STATUSES.includes(run.status)) return null;
  return {
    id: run.id,
    status: run.status,
    target: run.target,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    requestCount: run.requestCount,
    findingCount: run.findingCount,
    errorCode: run.errorCode,
    errorReason: run.errorReason
  };
}

/**
 * L'état d'un moteur tel qu'une carte doit le lire.
 *
 * C'est ici que la séparation se joue : `availability` répond « cet outil
 * est-il utilisable ? », `execution` répond « que fait-il en ce moment, et
 * qu'a-t-il fait la dernière fois ? ». Un outil installé et jamais lancé est
 * `READY`, avec `neverExecuted: true` — jamais `UNAVAILABLE`.
 */
function engineState(engine, { kind = RUN_KIND.SCAN, availability: tool = null, run = null, lastRun = null, now = Date.now } = {}) {
  const detected = tool || unknownAvailability();
  const current = run && !TERMINAL_RUN_STATUSES.includes(run.status) ? run : null;
  const finished = lastRunSummary(run) || (lastRun ? lastRunSummary(lastRun) : null);

  let status;
  let reason = '';
  if (current) {
    // Une exécution en cours l'emporte : elle est la réalité observée.
    status = current.status;
    reason = current.errorReason || '';
  } else if (kind === RUN_KIND.CONNECTOR) {
    status = RUN_STATUS.WAITING_EXTERNAL;
    reason = finished?.errorReason || detected.reason || '';
  } else if (!detected.usable) {
    status = RUN_STATUS.UNAVAILABLE;
    reason = detected.reason;
  } else {
    // Disponible et rien en cours : prêt. Ce que la dernière exécution a donné
    // est de l'histoire, et vit dans `lastRun`, pas dans l'état courant.
    status = RUN_STATUS.READY;
    reason = '';
  }

  return {
    engine: String(engine),
    kind,
    status,
    statusLabel: RUN_STATUS_LABEL[status] || status,
    reason,
    availability: detected,
    execution: {
      neverExecuted: !run && !lastRun,
      runId: current?.id || finished?.id || '',
      status: current?.status || finished?.status || RUN_STATUS.IDLE,
      phase: current?.phase || '',
      progress: current?.progress ?? null,
      target: current?.target || finished?.target || '',
      startedAt: current?.startedAt || finished?.startedAt || null,
      finishedAt: finished?.finishedAt || null,
      lastActivity: current?.lastActivity || null,
      requestCount: current?.requestCount ?? finished?.requestCount ?? null,
      findingCount: current?.findingCount ?? finished?.findingCount ?? null,
      errorCode: current?.errorCode || finished?.errorCode || '',
      errorReason: current?.errorReason || finished?.errorReason || '',
      lastRun: finished
    },
    observedAt: isoAt(now)
  };
}

/**
 * L'instantané que la page reçoit : un état par moteur, dans un ordre stable.
 *
 * Les cartes lisent ceci et rien d'autre pour l'état courant. Les résultats
 * historiques restent où ils sont — ils décrivent ce qui a été trouvé, pas ce
 * que le moteur fait maintenant.
 */
function dynamicRuntimeModel(engines = {}, { now = Date.now } = {}) {
  const states = {};
  for (const [engine, entry] of Object.entries(engines || {})) {
    if (!entry) continue;
    states[engine] = engineState(engine, { ...entry, now });
  }
  return {
    engines: states,
    list: Object.values(states),
    // Une seule publication, un seul horodatage : la page sait de quand date
    // l'ensemble de ce qu'elle affiche.
    observedAt: isoAt(now)
  };
}

module.exports = {
  RUN_KIND, RUN_KINDS, RUN_STATUS, RUN_STATUSES, TERMINAL_RUN_STATUSES, RUN_ERROR,
  ALLOWED_TRANSITIONS, RUN_STATUS_LABEL,
  runId, availability, unknownAvailability, createRun, canTransition, transitionRun,
  recordActivity, failRun, completeRun, reconcileRun, restoreRun, lastRunSummary,
  engineState, dynamicRuntimeModel
};
