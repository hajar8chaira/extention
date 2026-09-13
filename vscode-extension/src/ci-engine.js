'use strict';

/**
 * CI Engine detection.
 *
 * Tells whether the Security Center CI Engine runs on the delivery provider,
 * from evidence Security Center already reads — never by executing anything on
 * the CI server. The extension reports the state; installing the engine stays an
 * administrator action (`ci-engine/install-scenter-ci.sh`).
 *
 * Evidence: the CI report archived by the last build. A report written by the
 * CLI carries `engine.version`; a Security Center report without it was written
 * by an engine that predates version reporting.
 */

const CI_ENGINE_STATE = Object.freeze({
  INSTALLED: 'INSTALLED',
  NOT_DETECTED: 'NOT_DETECTED',
  VERSION_UNKNOWN: 'VERSION_UNKNOWN'
});

const CI_ENGINE_LABELS = Object.freeze({
  [CI_ENGINE_STATE.INSTALLED]: 'CI Engine: Installed',
  [CI_ENGINE_STATE.NOT_DETECTED]: 'CI Engine: Not detected',
  [CI_ENGINE_STATE.VERSION_UNKNOWN]: 'CI Engine: Version unknown'
});

const ENGINE_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** Why no engine could be observed, per archived-report state. */
const NOT_DETECTED_REASONS = Object.freeze({
  NOT_REPORTED: 'Le dernier build n’a archivé aucun rapport Security Center.',
  INVALID: 'Le rapport archivé n’est pas un rapport Security Center valide.',
  UNAVAILABLE: 'Le rapport archivé n’a pas pu être lu.'
});

function result(state, { version = null, commit = null, reason = '' } = {}) {
  return Object.freeze({ state, label: CI_ENGINE_LABELS[state], version, commit, reason });
}

/**
 * @param {{ reportState?: string, report?: object|null, inconsistent?: boolean }} evidence
 *   `reportState` and `report` as produced by `jenkins.js` (`ci.state`, `ci.report`,
 *   already validated); `inconsistent` when the report belongs to another commit.
 */
function detectCiEngine({ reportState = '', report = null, inconsistent = false } = {}) {
  if (reportState !== 'REPORTED' || !report || typeof report !== 'object') {
    return result(CI_ENGINE_STATE.NOT_DETECTED, {
      reason: NOT_DETECTED_REASONS[reportState] || NOT_DETECTED_REASONS.NOT_REPORTED
    });
  }
  if (inconsistent) {
    return result(CI_ENGINE_STATE.NOT_DETECTED, {
      reason: 'Le rapport archivé appartient à un autre commit : il ne prouve rien pour ce build.'
    });
  }
  // The bootstrap could not provide the engine: the report says so, and no
  // engine ran for this build.
  if (report.execution?.status === 'engine_unavailable') {
    return result(CI_ENGINE_STATE.NOT_DETECTED, {
      reason: `CI Engine indisponible sur le serveur CI : ${report.execution.error || 'bootstrap en échec'}.`
    });
  }
  const version = typeof report.engine?.version === 'string' && ENGINE_VERSION.test(report.engine.version)
    ? report.engine.version
    : null;
  const commit = typeof report.engine?.commit === 'string' && /^[0-9a-f]{40}$/.test(report.engine.commit) ? report.engine.commit : null;
  if (version) return result(CI_ENGINE_STATE.INSTALLED, { version, commit });
  return result(CI_ENGINE_STATE.VERSION_UNKNOWN, {
    reason: 'Un rapport Security Center a été produit, mais le moteur CI ne déclare pas sa version.'
  });
}

module.exports = { CI_ENGINE_STATE, CI_ENGINE_LABELS, detectCiEngine };
