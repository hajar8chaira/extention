'use strict';

/**
 * Le coordinateur de rafraîchissement de Dynamic Security.
 *
 * Avant lui, deux horloges se recouvraient : un sondage Burp toutes les cinq
 * secondes pendant toute la session, et un sondage de trafic toutes les trois
 * secondes pendant une capture. Elles relisaient la même liste de scénarios,
 * publiaient chacune de leur côté, et aucune ne savait ce que l'autre venait
 * de faire — d'où des rendus concurrents et une horloge qui tournait pour une
 * page fermée.
 *
 * Ici, il y a une seule horloge. Chaque source déclare sa cadence et dit
 * elle-même si elle a besoin d'être interrogée maintenant ; le coordinateur
 * les appelle quand elles sont dues, et **publie une fois** quand au moins
 * l'une d'elles a rapporté un changement.
 *
 * Trois garanties :
 *
 *   - **Pas de sondage à vide.** Quand plus aucune source n'a de cadence
 *     applicable, l'horloge est arrêtée, pas ralentie. `wake()` la rallume.
 *
 *   - **Pas de recouvrement.** Une source encore en vol n'est pas rappelée ;
 *     un sondage lent ne se met pas en file derrière lui-même.
 *
 *   - **Pas d'interruption.** L'échec d'une source est signalé à l'appelant et
 *     n'empêche jamais les autres de s'exécuter ni l'horloge de continuer.
 *
 * Le module est pur : horloge et minuteries sont injectées, ce qui rend les
 * cadences réellement testables au lieu d'être attendues.
 */

const DEFAULT_TICK_MS = 1000;

/**
 * Crée le coordinateur.
 *
 * `sources` : `{ name, activeIntervalMs, idleIntervalMs, needed, refresh }`.
 *   - `activeIntervalMs` : cadence quand la page Dynamic Security est ouverte.
 *   - `idleIntervalMs`   : cadence quand elle ne l'est pas. `0` signifie « ne
 *     pas interroger » — c'est le défaut, parce qu'aucune donnée de cette page
 *     n'a besoin d'être relue quand personne ne la regarde.
 *   - `needed()` : la source a-t-elle quelque chose à surveiller ? Une capture
 *     arrêtée n'a rien à dire.
 *   - `refresh()` : renvoie `true` si l'état a changé et mérite publication.
 */
function createRefreshCoordinator({
  sources = [],
  publish = () => {},
  onError = () => {},
  now = Date.now,
  setTimer = setInterval,
  clearTimer = clearInterval,
  tickMs = DEFAULT_TICK_MS
} = {}) {
  const entries = sources.map((source) => ({
    name: String(source.name || 'source'),
    activeIntervalMs: Number(source.activeIntervalMs) || 0,
    idleIntervalMs: Number(source.idleIntervalMs) || 0,
    needed: typeof source.needed === 'function' ? source.needed : () => true,
    refresh: source.refresh,
    // `null` signifie « jamais interrogée » : une source neuve est due tout de
    // suite, au lieu d'attendre un intervalle avant sa première lecture.
    lastRunAt: null,
    inFlight: false
  }));

  let timer = null;
  let active = false;
  let stopped = false;

  /** La cadence applicable à une source maintenant, ou 0 si elle ne doit rien faire. */
  function intervalFor(entry) {
    if (!entry.needed()) return 0;
    return active ? entry.activeIntervalMs : entry.idleIntervalMs;
  }

  function anyoneNeedsPolling() {
    return entries.some((entry) => intervalFor(entry) > 0);
  }

  function startTimer() {
    if (timer || stopped) return;
    timer = setTimer(tick, tickMs);
    // Une horloge de rafraîchissement ne retient jamais l'hôte d'extension.
    timer?.unref?.();
  }

  function stopTimer() {
    if (!timer) return;
    clearTimer(timer);
    timer = null;
  }

  async function runSource(entry, at) {
    entry.inFlight = true;
    entry.lastRunAt = at;
    try {
      return (await entry.refresh()) === true;
    } catch (error) {
      onError(entry.name, error);
      return false;
    } finally {
      entry.inFlight = false;
    }
  }

  function tick() {
    if (stopped) return Promise.resolve(false);
    const at = typeof now === 'function' ? now() : Date.now();
    const due = entries.filter((entry) => {
      if (entry.inFlight) return false;
      const interval = intervalFor(entry);
      if (interval <= 0) return false;
      return entry.lastRunAt === null || at - entry.lastRunAt >= interval;
    });
    if (!due.length) {
      // Plus personne à interroger : l'horloge s'arrête au lieu de battre pour rien.
      if (!anyoneNeedsPolling()) stopTimer();
      return Promise.resolve(false);
    }
    return Promise.all(due.map((entry) => runSource(entry, at))).then((results) => {
      const changed = results.some(Boolean);
      // Une seule publication par tick, quel que soit le nombre de sources qui
      // ont bougé : la page reçoit un état cohérent, pas une rafale.
      if (changed) publish();
      if (!anyoneNeedsPolling()) stopTimer();
      return changed;
    });
  }

  return {
    /** Déclare si la page Dynamic Security est visible. Rallume l'horloge si besoin. */
    setActive(value) {
      const next = value === true;
      if (next === active) return;
      active = next;
      if (anyoneNeedsPolling()) startTimer(); else stopTimer();
    },

    /** Rallume l'horloge après un changement d'état (capture démarrée, par exemple). */
    wake() {
      if (stopped) return;
      if (anyoneNeedsPolling()) startTimer();
    },

    /** Interroge immédiatement les sources nommées, ou toutes celles qui sont utiles. */
    async refreshNow(names = null) {
      if (stopped) return false;
      const at = typeof now === 'function' ? now() : Date.now();
      const wanted = entries.filter((entry) => (names ? names.includes(entry.name) : entry.needed()) && !entry.inFlight);
      if (!wanted.length) return false;
      const results = await Promise.all(wanted.map((entry) => runSource(entry, at)));
      const changed = results.some(Boolean);
      if (changed) publish();
      return changed;
    },

    /** Arrête définitivement : fermeture de la page, désactivation de l'extension. */
    stop() {
      stopped = true;
      stopTimer();
    },

    /** Pour les tests et le diagnostic : ce que le coordinateur fait réellement. */
    inspect() {
      return {
        active,
        stopped,
        running: Boolean(timer),
        sources: entries.map((entry) => ({
          name: entry.name,
          intervalMs: intervalFor(entry),
          lastRunAt: entry.lastRunAt,
          inFlight: entry.inFlight
        }))
      };
    },

    /** Exposé pour les tests : exécute un tick sans attendre l'horloge. */
    tick
  };
}

module.exports = { createRefreshCoordinator, DEFAULT_TICK_MS };
