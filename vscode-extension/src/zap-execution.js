'use strict';

/**
 * Le déroulé réel d'une exécution ZAP, étape par étape.
 *
 * La carte Dynamic Security ne montrait qu'une phase courante et un statut. Un
 * scan qui échouait après cinq minutes ne disait donc pas ce qu'il avait fait
 * pendant ces cinq minutes : quelle étape tournait, si elle avançait, si elle
 * attendait le démon, ni laquelle avait été sautée. Ce module tient ce déroulé.
 *
 * Trois règles, les mêmes que le socle d'exécution :
 *
 *   - **Rien n'est inventé.** Une progression absente reste `null` et s'affiche
 *     comme un état — PENDING, RUNNING, COMPLETED, SKIPPED, FAILED — jamais
 *     comme un pourcentage fabriqué. Les seuls pourcentages qui entrent ici
 *     viennent de `spider/view/status`, `ascan/view/status` et
 *     `pscan/view/recordsToScan`.
 *   - **Une étape sautée le dit.** En baseline passif, le scan actif n'a pas
 *     « réussi » : il est SKIPPED, avec sa raison. Une carte qui le montrerait
 *     terminé laisserait croire que l'application a été testée activement.
 *   - **Le temps observé est du temps mesuré.** `startedAt`, `finishedAt` et
 *     `lastActivity` viennent de l'horloge injectée, à l'instant où une
 *     observation réelle est arrivée.
 *
 * Le module est pur : ni `vscode`, ni I/O, ni horloge propre.
 */

/** Les étapes d'un scan ZAP, dans l'ordre où elles se produisent. */
const ZAP_STAGE = Object.freeze({
  PREFLIGHT: 'PREFLIGHT',
  ENGINE: 'ENGINE',
  DAEMON_STARTING: 'DAEMON_STARTING',
  API_WAIT: 'API_WAIT',
  SPIDERING: 'SPIDERING',
  PASSIVE_WAIT: 'PASSIVE_WAIT',
  ACTIVE_SCANNING: 'ACTIVE_SCANNING',
  COLLECTING_RESULTS: 'COLLECTING_RESULTS',
  NORMALIZING: 'NORMALIZING',
  DAEMON_STOPPING: 'DAEMON_STOPPING',
  COMPLETED: 'COMPLETED'
});

/** L'état d'une étape. Il remplace un pourcentage quand aucun n'est mesurable. */
const STAGE_STATUS = Object.freeze({
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  SKIPPED: 'SKIPPED',
  FAILED: 'FAILED'
});

const STAGE_ORDER = Object.freeze([
  ZAP_STAGE.PREFLIGHT,
  ZAP_STAGE.ENGINE,
  ZAP_STAGE.DAEMON_STARTING,
  ZAP_STAGE.API_WAIT,
  ZAP_STAGE.SPIDERING,
  ZAP_STAGE.PASSIVE_WAIT,
  ZAP_STAGE.ACTIVE_SCANNING,
  ZAP_STAGE.COLLECTING_RESULTS,
  ZAP_STAGE.NORMALIZING,
  ZAP_STAGE.DAEMON_STOPPING,
  ZAP_STAGE.COMPLETED
]);

/** Les libellés d'interface. Le rendu ne réinvente pas de vocabulaire. */
const ZAP_STAGE_LABEL = Object.freeze({
  [ZAP_STAGE.PREFLIGHT]: 'Preflight / autorisation de la cible',
  [ZAP_STAGE.ENGINE]: 'Moteur sélectionné',
  [ZAP_STAGE.DAEMON_STARTING]: 'Démarrage du démon ZAP local',
  [ZAP_STAGE.API_WAIT]: 'Attente de l’API ZAP',
  [ZAP_STAGE.SPIDERING]: 'Spidering / découverte d’URL',
  [ZAP_STAGE.PASSIVE_WAIT]: 'Analyse passive',
  [ZAP_STAGE.ACTIVE_SCANNING]: 'Scan actif',
  [ZAP_STAGE.COLLECTING_RESULTS]: 'Collecte des alertes',
  [ZAP_STAGE.NORMALIZING]: 'Normalisation et persistance des findings',
  [ZAP_STAGE.DAEMON_STOPPING]: 'Arrêt du démon',
  [ZAP_STAGE.COMPLETED]: 'Terminé'
});

const STAGE_STATUS_LABEL = Object.freeze({
  [STAGE_STATUS.PENDING]: 'PENDING',
  [STAGE_STATUS.RUNNING]: 'RUNNING',
  [STAGE_STATUS.COMPLETED]: 'COMPLETED',
  [STAGE_STATUS.SKIPPED]: 'SKIPPED',
  [STAGE_STATUS.FAILED]: 'FAILED'
});

const TERMINAL_STAGE_STATUSES = Object.freeze([STAGE_STATUS.COMPLETED, STAGE_STATUS.SKIPPED, STAGE_STATUS.FAILED]);

function isoAt(now) {
  return new Date(typeof now === 'function' ? now() : (now ?? Date.now())).toISOString();
}

/** Un pourcentage réel, ou `null`. Zéro ne remplace jamais « inconnu ». */
function percentOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Math.max(0, Math.min(100, Math.round(number)));
}

/** Un compteur réel, ou `null`. */
function countOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}

/**
 * Les métriques d'une étape, réduites à celles que ZAP a réellement fournies.
 *
 * Une clé absente de l'observation ne remplace jamais une valeur déjà mesurée,
 * et une valeur non numérique n'entre pas : la carte ne doit pouvoir afficher
 * que des nombres qui ont existé.
 */
function mergeMetrics(previous = {}, incoming = {}) {
  const merged = { ...previous };
  for (const [key, raw] of Object.entries(incoming || {})) {
    const value = key === 'percent' ? percentOrNull(raw) : countOrNull(raw);
    if (value !== null) merged[key] = value;
  }
  return merged;
}

/**
 * Un déroulé neuf : toutes les étapes en attente, rien d'observé.
 *
 * Le mode est porté par le déroulé lui-même parce qu'il décide de ce qu'une
 * étape absente veut dire — en baseline passif, le scan actif n'est pas en
 * retard, il n'aura pas lieu.
 */
function createZapExecution({ target = '', mode = 'baseline', engine = '', now = Date.now } = {}) {
  const startedAt = isoAt(now);
  return {
    target: String(target || ''),
    mode: String(mode || 'baseline'),
    engine: String(engine || ''),
    startedAt,
    finishedAt: null,
    lastActivity: null,
    stages: STAGE_ORDER.map((id) => ({
      id,
      label: ZAP_STAGE_LABEL[id],
      status: STAGE_STATUS.PENDING,
      progress: null,
      detail: '',
      startedAt: null,
      finishedAt: null,
      metrics: {}
    }))
  };
}

/**
 * Applique une observation à une étape.
 *
 * Une étape qui démarre clôt implicitement celles qui la précèdent et qui
 * tournaient encore : ZAP ne revient pas en arrière, et laisser « spidering »
 * en cours pendant l'analyse passive donnerait deux étapes actives à la fois.
 * Une étape déjà close n'est pas rouverte.
 */
function applyZapStage(execution, { stage, status = STAGE_STATUS.RUNNING, progress, detail = '', metrics = {}, closePrevious = true, now = Date.now } = {}) {
  if (!execution) throw new Error('Exécution absente.');
  if (!STAGE_ORDER.includes(stage)) throw new Error(`Étape ZAP inconnue : ${stage}.`);
  if (!Object.values(STAGE_STATUS).includes(status)) throw new Error(`État d'étape inconnu : ${status}.`);
  const at = isoAt(now);
  const index = STAGE_ORDER.indexOf(stage);
  const percent = progress === undefined ? undefined : percentOrNull(progress);

  const stages = execution.stages.map((entry, position) => {
    if (closePrevious && position < index && entry.status === STAGE_STATUS.RUNNING) {
      // L'étape précédente tournait encore : le passage à la suivante est la
      // preuve qu'elle est finie, et l'heure de sa fin est celle-ci.
      //
      // Sauf quand l'appelant dit le contraire. Le démarrage du démon et
      // l'attente de son API se chevauchent réellement : le processus est lancé,
      // puis on attend qu'il ouvre son port. Clore le démarrage dès le début de
      // l'attente l'affichait COMPLETED alors que rien ne prouvait encore que le
      // démon vivait — et c'est précisément ce qu'on voyait sur un démon mort.
      return { ...entry, status: STAGE_STATUS.COMPLETED, finishedAt: at };
    }
    if (position !== index) return entry;
    return {
      ...entry,
      status,
      progress: percent === undefined ? entry.progress : percent,
      detail: detail ? String(detail) : entry.detail,
      startedAt: entry.startedAt || at,
      finishedAt: TERMINAL_STAGE_STATUSES.includes(status) ? at : entry.finishedAt,
      metrics: mergeMetrics(entry.metrics, metrics)
    };
  });

  const previous = execution.stages[index];
  const updated = stages[index];
  // Seule une observation qui apporte quelque chose fait avancer l'horloge
  // d'activité : un sondage qui répète le même pourcentage n'en est pas.
  const changed = previous.status !== updated.status
    || previous.progress !== updated.progress
    || previous.detail !== updated.detail
    || JSON.stringify(previous.metrics) !== JSON.stringify(updated.metrics);

  return {
    ...execution,
    stages,
    engine: stage === ZAP_STAGE.ENGINE && detail ? String(detail) : execution.engine,
    lastActivity: changed ? at : execution.lastActivity,
    finishedAt: stage === ZAP_STAGE.COMPLETED && TERMINAL_STAGE_STATUSES.includes(status) ? at : execution.finishedAt
  };
}

/**
 * Marque le scan actif comme non exécuté, en disant pourquoi.
 *
 * C'est la seule manière honnête de représenter un baseline passif : l'étape
 * existe, elle n'a pas eu lieu, et la carte doit le montrer plutôt que de la
 * taire — une étape absente se lirait comme une étape réussie.
 */
function skipZapStage(execution, { stage, reason = '', now = Date.now } = {}) {
  return applyZapStage(execution, { stage, status: STAGE_STATUS.SKIPPED, detail: reason, now });
}

/** Clôt le déroulé sur une panne, en marquant l'étape qui tournait. */
function failZapExecution(execution, { reason = '', code = '', now = Date.now } = {}) {
  if (!execution) throw new Error('Exécution absente.');
  const at = isoAt(now);
  // Plusieurs étapes peuvent tourner ensemble — démarrage du démon et attente de
  // son API. Une panne les concerne toutes : en laisser une en RUNNING est
  // exactement l'état fantôme qu'on cherche à supprimer.
  const running = execution.stages.filter((entry) => entry.status === STAGE_STATUS.RUNNING);
  const stages = execution.stages.map((entry) => (entry.status === STAGE_STATUS.RUNNING
    ? { ...entry, status: STAGE_STATUS.FAILED, detail: reason ? String(reason) : entry.detail, finishedAt: at }
    : entry));
  return {
    ...execution,
    stages,
    lastActivity: running.length ? at : execution.lastActivity,
    finishedAt: at,
    failureReason: String(reason || ''),
    failureCode: String(code || execution.failureCode || '')
  };
}

/**
 * Ce que la carte a besoin de savoir, dérivé et non recopié.
 *
 * `activity` répond à la seule question qu'on se pose devant un scan lent :
 * avance-t-il, attend-il, ou est-il bloqué ? Elle se lit de l'étape courante et
 * de la date de la dernière observation réelle, jamais d'un minuteur.
 */
function zapExecutionSummary(execution, { now = Date.now, stallMs = 300000 } = {}) {
  if (!execution) return null;
  const current = execution.stages.find((entry) => entry.status === STAGE_STATUS.RUNNING) || null;
  const nowMs = typeof now === 'function' ? now() : (now ?? Date.now());
  const startedMs = execution.startedAt ? new Date(execution.startedAt).getTime() : null;
  const lastMs = execution.lastActivity ? new Date(execution.lastActivity).getTime() : null;
  const finishedMs = execution.finishedAt ? new Date(execution.finishedAt).getTime() : null;
  const elapsedMs = startedMs === null ? null : Math.max(0, (finishedMs ?? nowMs) - startedMs);
  const sinceActivityMs = lastMs === null ? null : Math.max(0, nowMs - lastMs);

  let activity = 'IDLE';
  if (execution.finishedAt) activity = execution.failureReason || execution.failureCode ? 'FAILED' : 'DONE';
  else if (!current) activity = 'WAITING';
  else if (sinceActivityMs !== null && sinceActivityMs >= stallMs) activity = 'STALLED';
  else if (current.progress !== null) activity = 'PROGRESSING';
  else activity = 'WAITING';

  return {
    activity,
    failureCode: execution.failureCode || '',
    failureReason: execution.failureReason || '',
    currentStage: current ? current.id : '',
    currentLabel: current ? current.label : '',
    progress: current ? current.progress : null,
    elapsedMs,
    sinceActivityMs,
    startedAt: execution.startedAt,
    lastActivity: execution.lastActivity,
    finishedAt: execution.finishedAt,
    engine: execution.engine,
    target: execution.target,
    mode: execution.mode,
    completed: execution.stages.filter((entry) => entry.status === STAGE_STATUS.COMPLETED).length,
    skipped: execution.stages.filter((entry) => entry.status === STAGE_STATUS.SKIPPED).length,
    total: execution.stages.length
  };
}

/**
 * Restaure un déroulé persisté.
 *
 * Tout ce qui n'est pas reconnaissable revient `null` : un cache écrit par une
 * version antérieure ne doit ni faire tomber la page, ni se faire passer pour
 * une exécution observée.
 */
function restoreZapExecution(raw, { assumeInterrupted = false } = {}) {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.stages)) return null;
  const byId = new Map(raw.stages.filter((entry) => entry && STAGE_ORDER.includes(entry.id)).map((entry) => [entry.id, entry]));
  if (!byId.size) return null;
  // Un rechargement de fenêtre tue les processus enfants, pas les données. Une
  // étape persistée « en cours » décrit donc un démon qui n'existe plus : elle est
  // restaurée interrompue, jamais en cours. Sans cela, rouvrir la page ressuscitait
  // un scan fantôme.
  // Seule une restauration depuis le disque peut conclure à une interruption :
  // une exécution vivante, publiée en mémoire, passe ici aussi et doit garder ses
  // étapes en cours.
  const interrupted = assumeInterrupted && !raw.finishedAt && raw.stages.some((entry) => entry?.status === STAGE_STATUS.RUNNING);
  const restoredStatus = (status) => (interrupted && status === STAGE_STATUS.RUNNING ? STAGE_STATUS.FAILED : status);
  return {
    target: String(raw.target || ''),
    mode: String(raw.mode || 'baseline'),
    engine: String(raw.engine || ''),
    startedAt: raw.startedAt || null,
    finishedAt: raw.finishedAt || (interrupted ? raw.lastActivity || raw.startedAt || null : null),
    lastActivity: raw.lastActivity || null,
    failureReason: String(raw.failureReason || (interrupted ? 'Analyse interrompue : la fenêtre a été rechargée pendant l’exécution.' : '')),
    failureCode: String(raw.failureCode || (interrupted ? 'ZAP_RUN_INTERRUPTED' : '')),
    stages: STAGE_ORDER.map((id) => {
      const entry = byId.get(id) || {};
      const declared = Object.values(STAGE_STATUS).includes(entry.status) ? entry.status : STAGE_STATUS.PENDING;
      const status = restoredStatus(declared);
      return {
        id,
        label: ZAP_STAGE_LABEL[id],
        status,
        progress: percentOrNull(entry.progress),
        detail: status === STAGE_STATUS.FAILED && declared === STAGE_STATUS.RUNNING
          ? 'Interrompue par le rechargement de la fenêtre'
          : String(entry.detail || ''),
        startedAt: entry.startedAt || null,
        finishedAt: entry.finishedAt || null,
        metrics: mergeMetrics({}, entry.metrics || {})
      };
    })
  };
}

/**
 * L'étape que décrit un événement de cycle de vie du moteur ZAP.
 *
 * Le moteur publie des états ; la carte parle d'étapes. La correspondance est
 * déclarée ici pour qu'un état inconnu ne devienne jamais une étape inventée :
 * il est simplement ignoré.
 */
const LIFECYCLE_TO_STAGE = Object.freeze({
  DAEMON_STARTING: ZAP_STAGE.DAEMON_STARTING,
  STARTING: ZAP_STAGE.DAEMON_STARTING,
  // C'est la réponse de l'API qui clôt le démarrage, pas le retour de `spawn`.
  DAEMON_READY: ZAP_STAGE.DAEMON_STARTING,
  API_WAIT: ZAP_STAGE.API_WAIT,
  SPIDERING: ZAP_STAGE.SPIDERING,
  PASSIVE_WAIT: ZAP_STAGE.PASSIVE_WAIT,
  ACTIVE_SCANNING: ZAP_STAGE.ACTIVE_SCANNING,
  ACTIVE_SKIPPED: ZAP_STAGE.ACTIVE_SCANNING,
  COLLECTING_RESULTS: ZAP_STAGE.COLLECTING_RESULTS,
  NORMALIZING: ZAP_STAGE.NORMALIZING,
  DAEMON_STOPPING: ZAP_STAGE.DAEMON_STOPPING,
  DAEMON_STOPPED: ZAP_STAGE.DAEMON_STOPPING,
  COMPLETED: ZAP_STAGE.COMPLETED
});

/** Applique un événement du moteur, ou rend le déroulé inchangé s'il ne le décrit pas. */
function applyZapLifecycle(execution, event = {}, { now = Date.now } = {}) {
  if (!execution) return execution;
  // Le moteur annonce le mode qu'il exécute réellement. C'est lui qui fait foi :
  // le déroulé et la carte ne peuvent plus en afficher deux différents.
  if (String(event?.state || '') === 'MODE') {
    const mode = String(event.detail || '').trim();
    return mode && mode !== execution.mode ? { ...execution, mode, lastActivity: isoAt(now) } : execution;
  }
  const stage = LIFECYCLE_TO_STAGE[String(event?.state || '')];
  if (!stage) return execution;
  const status = event.state === 'ACTIVE_SKIPPED'
    ? STAGE_STATUS.SKIPPED
    : event.state === 'DAEMON_STOPPED' || event.state === 'COMPLETED' || event.state === 'DAEMON_READY'
      ? STAGE_STATUS.COMPLETED
      : STAGE_STATUS.RUNNING;
  return applyZapStage(execution, {
    stage,
    status,
    progress: event.progress,
    detail: event.detail || '',
    metrics: event.metrics || {},
    // L'attente de l'API ne clôt pas le démarrage du démon : les deux sont en
    // cours ensemble jusqu'à ce que l'API réponde.
    //
    // L'arrêt du démon ne clôt rien non plus. Il passe dans le `finally` du
    // moteur, donc aussi après une panne : un scan actif bloqué à 37 % se lisait
    // COMPLETED dès que le démon s'arrêtait, alors que le run échouait. C'est la
    // clôture du run — succès ou panne — qui décide de l'issue d'une étape.
    closePrevious: stage !== ZAP_STAGE.API_WAIT && stage !== ZAP_STAGE.DAEMON_STOPPING,
    now
  });
}

module.exports = {
  ZAP_STAGE, STAGE_STATUS, STAGE_ORDER, ZAP_STAGE_LABEL, STAGE_STATUS_LABEL, TERMINAL_STAGE_STATUSES,
  LIFECYCLE_TO_STAGE,
  createZapExecution, applyZapStage, applyZapLifecycle, skipZapStage, failZapExecution,
  zapExecutionSummary, restoreZapExecution
};
