'use strict';

/**
 * Runtime Security navigation, derived from provider capabilities.
 *
 * The page must not know that Wazuh exists. What it needs is the answer to one
 * question — "what can this provider actually show right now?" — and that has
 * two distinct layers which are deliberately kept apart:
 *
 *   - DECLARED  : what the adapter is built to do (`ready` / `requires-config`
 *                 / `unavailable`). Static, part of the adapter contract.
 *   - RESOLVED  : what it can do for the connection currently in hand. Adds
 *                 `error`, which only this layer can produce — an adapter can
 *                 never *declare* itself broken.
 *
 * Two rules make the difference honest:
 *
 *   1. `unavailable` is never promoted. Stored credentials are not proof that a
 *      capability works; only a real probe is, and that belongs to the phase
 *      which actually performs it.
 *   2. Capabilities resolve independently. One failing capability degrades its
 *      own tab, never the whole domain.
 */

const { CAPABILITY, CAPABILITY_STATE, normalizeCapabilities } = require('./siem-contract');

/**
 * Runtime vocabulary: the declared states, plus `error`.
 *
 * Kept separate from CAPABILITY_STATE on purpose — adding `error` there would
 * let an adapter declare a permanent failure as if it were a feature.
 */
const RUNTIME_CAPABILITY_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  UNAVAILABLE: 'unavailable',
  ERROR: 'error'
});

const RUNTIME_CAPABILITY_LABELS = Object.freeze({
  [RUNTIME_CAPABILITY_STATE.READY]: 'Available',
  [RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG]: 'Setup required',
  [RUNTIME_CAPABILITY_STATE.UNAVAILABLE]: 'Unavailable',
  [RUNTIME_CAPABILITY_STATE.ERROR]: 'Error'
});

/** Connection states from which a capability may still be expected to answer. */
const USABLE_CONNECTION = Object.freeze(['online', 'degraded']);

/** The one tab that exists without a capability: it describes the connection. */
const OVERVIEW_TAB = Object.freeze({ id: 'overview', label: 'Overview', capability: '' });

/**
 * Capability → tab, in navigation order. A capability with no entry here has no
 * view of its own (raw events feed other surfaces, they are not a destination).
 */
const CAPABILITY_TABS = Object.freeze([
  Object.freeze({ id: 'alerts', label: 'Alerts', capability: CAPABILITY.ALERTS }),
  Object.freeze({ id: 'assets', label: 'Assets', capability: CAPABILITY.ASSETS }),
  Object.freeze({ id: 'mitre', label: 'MITRE', capability: CAPABILITY.MITRE }),
  Object.freeze({ id: 'vulnerabilities', label: 'Vulnerabilities', capability: CAPABILITY.VULNERABILITIES }),
  Object.freeze({ id: 'sca', label: 'SCA', capability: CAPABILITY.SCA }),
  Object.freeze({ id: 'fim', label: 'File integrity', capability: CAPABILITY.FIM }),
  Object.freeze({ id: 'incidents', label: 'Incidents', capability: CAPABILITY.INCIDENTS })
]);

/**
 * What the provider can do for this connection.
 *
 * `unavailable` in, `unavailable` out — always. Everything else follows the
 * connection: usable keeps its declared state, unusable becomes `error` so the
 * tab can explain itself instead of quietly showing zeros.
 */
/** States a probe is allowed to report. `unavailable` is not one of them. */
const EVIDENCE_STATES = Object.freeze([
  RUNTIME_CAPABILITY_STATE.READY,
  RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG,
  RUNTIME_CAPABILITY_STATE.ERROR
]);

/** Reads one capability's runtime evidence, if a probe produced any. */
function evidenceState(evidence, capability) {
  const witness = evidence && typeof evidence === 'object' ? evidence[capability] : null;
  if (!witness) return '';
  const state = typeof witness === 'string' ? witness : String(witness.state || '');
  return EVIDENCE_STATES.includes(state) ? state : '';
}

/**
 * @param {object} evidence  Per-capability probe results, keyed by capability.
 *   A capability with evidence resolves from that evidence ALONE — which is
 *   what isolates one backing service from another: a provider whose secondary
 *   data source is down keeps every capability its primary API serves.
 */
function resolveRuntimeCapabilities(source, runtime = {}, evidence = {}) {
  const declared = normalizeCapabilities(source);
  const configured = Boolean(runtime && runtime.configured);
  const usable = USABLE_CONNECTION.includes(String(runtime?.status || '').toLowerCase());
  const resolved = {};
  for (const capability of Object.values(CAPABILITY)) {
    const state = declared[capability];
    if (state === CAPABILITY_STATE.UNAVAILABLE) {
      // Never promoted. Configuration presence is not capability proof.
      resolved[capability] = RUNTIME_CAPABILITY_STATE.UNAVAILABLE;
      continue;
    }
    const witnessed = evidenceState(evidence, capability);
    if (witnessed) {
      // Runtime evidence wins outright, in both directions: it is the only way
      // to reach `ready`, and the only thing that can fail here.
      resolved[capability] = witnessed;
      continue;
    }
    if (!configured) {
      resolved[capability] = RUNTIME_CAPABILITY_STATE.REQUIRES_CONFIG;
      continue;
    }
    // Without evidence a capability can never be more than its declaration, so
    // a `requires-config` declaration stays exactly that until a probe runs.
    //
    // Only a capability the primary API is declared to serve degrades with that
    // API. One that requires its own setup has its own backing service, and a
    // primary-connection failure says nothing about it — assuming otherwise is
    // how one broken data source takes down a domain that never depended on it.
    if (usable || state !== CAPABILITY_STATE.READY) resolved[capability] = state;
    else resolved[capability] = RUNTIME_CAPABILITY_STATE.ERROR;
  }
  return Object.freeze(resolved);
}

/**
 * Whether a capability earns a destination of its own.
 *
 * `ready` obviously. `error` too — it was proven usable and now is not, and
 * hiding that would look like the data never existed. `requires-config` does
 * not: a section that has never been proven usable would be a promise, and a
 * promise rendered as navigation is the « coming soon » wall by another name.
 */
function capabilityVisible(resolved, capability) {
  const state = resolved?.[capability];
  return state === RUNTIME_CAPABILITY_STATE.READY || state === RUNTIME_CAPABILITY_STATE.ERROR;
}

/**
 * Whether the provider offers the capability at all — including one that is
 * merely waiting to be configured. This is what lets a surface invite the user
 * to set something up without pretending the section already works.
 */
function capabilityOffered(resolved, capability) {
  return Boolean(resolved?.[capability]) && resolved[capability] !== RUNTIME_CAPABILITY_STATE.UNAVAILABLE;
}

/**
 * The tabs to render. Overview always; a capability tab only when that
 * capability is genuinely offered — an intention to support it later is not a
 * reason to show a dead destination.
 */
function runtimeCapabilityTabs(resolved) {
  return [OVERVIEW_TAB, ...CAPABILITY_TABS.filter((tab) => capabilityVisible(resolved, tab.capability))];
}

/** A requested tab that no longer exists falls back to Overview, never to nothing. */
function resolveRuntimeTab(tabs, requested) {
  const wanted = String(requested || '').trim().toLowerCase();
  return tabs.some((tab) => tab.id === wanted) ? wanted : OVERVIEW_TAB.id;
}

/** Everything a renderer needs about navigation, in one call. */
function runtimeNavigation(source, runtime = {}, requestedTab = '', evidence = {}) {
  const capabilities = resolveRuntimeCapabilities(source, runtime, evidence);
  const tabs = runtimeCapabilityTabs(capabilities);
  return { capabilities, tabs, tab: resolveRuntimeTab(tabs, requestedTab) };
}

module.exports = {
  RUNTIME_CAPABILITY_STATE,
  EVIDENCE_STATES,
  evidenceState,
  RUNTIME_CAPABILITY_LABELS,
  OVERVIEW_TAB,
  CAPABILITY_TABS,
  resolveRuntimeCapabilities,
  capabilityVisible,
  capabilityOffered,
  runtimeCapabilityTabs,
  resolveRuntimeTab,
  runtimeNavigation
};
