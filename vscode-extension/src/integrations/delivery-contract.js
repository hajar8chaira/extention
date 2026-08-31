'use strict';

/**
 * The Security Delivery domain contract.
 *
 * Defines what any CI/CD provider must be able to answer, in vocabulary that
 * belongs to delivery rather than to Jenkins. A job, a pipeline and a workflow
 * run are the same idea under three vendor names; the renderer must never learn
 * any of the three.
 *
 * The capability list is deliberately short. It contains exactly what an
 * adapter can prove today and nothing that merely sounds useful: a vocabulary
 * describing intentions rather than facts is how a catalogue starts lying.
 * `deploymentStatus` is present because Security Delivery must be able to say
 * « not reported » about it — the honest answer when a provider reads the run
 * and not its deployment.
 */

const { FIELD_TYPE, CONFIG_GROUP, fieldsInGroup, validateAgainstFields, toBooleanValue } = require('./siem-contract');

/** Provider-level state, aligned with Runtime Security and Infrastructure. */
const PROVIDER_STATUS = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  HEALTHY: 'healthy',
  DEGRADED: 'degraded',
  OFFLINE: 'offline',
  AUTH_ERROR: 'auth-error',
  ERROR: 'error'
});

const PROVIDER_STATUS_LABELS = Object.freeze({
  [PROVIDER_STATUS.NOT_CONFIGURED]: 'Non configuré',
  [PROVIDER_STATUS.HEALTHY]: 'Connecté',
  [PROVIDER_STATUS.DEGRADED]: 'Dégradé',
  [PROVIDER_STATUS.OFFLINE]: 'Injoignable',
  [PROVIDER_STATUS.AUTH_ERROR]: 'Authentification refusée',
  [PROVIDER_STATUS.ERROR]: 'Erreur'
});

/** What a delivery provider can be asked for. */
const CAPABILITY = Object.freeze({
  PIPELINE_STATUS: 'pipelineStatus',
  LAST_RUN: 'lastRun',
  STAGES: 'stages',
  ARTIFACTS: 'artifacts',
  DEPLOYMENT_STATUS: 'deploymentStatus'
});
const CAPABILITIES = Object.freeze(Object.values(CAPABILITY));

/** What an adapter declares about a capability, before any call is made. */
const DECLARED_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  // The adapter knows how to ask; whether this deployment answers is not
  // something configuration can settle. A Jenkins job with no stage plugin is
  // fully configured and simply exposes no stages.
  REQUIRES_PROBE: 'requires-probe',
  UNAVAILABLE: 'unavailable'
});

/** What a capability resolves to once a real answer exists. */
const RESOLVED_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  NOT_REPORTED: 'not-reported',
  UNAVAILABLE: 'unavailable',
  ERROR: 'error'
});

/**
 * The outcome of a run, as the domain speaks about it.
 *
 * `NOT_REPORTED` and `NOT_STARTED` exist so that « the provider said nothing »
 * is never rendered as `FAILED`. A pipeline that has produced no run has not
 * failed, and a stage the provider does not expose has not failed either.
 */
const RUN_OUTCOME = Object.freeze({
  NOT_REPORTED: 'not-reported',
  NOT_STARTED: 'not-started',
  RUNNING: 'running',
  SUCCESS: 'success',
  UNSTABLE: 'unstable',
  FAILED: 'failed',
  ABORTED: 'aborted'
});

const RUN_OUTCOME_LABELS = Object.freeze({
  [RUN_OUTCOME.NOT_REPORTED]: 'Non rapporté',
  [RUN_OUTCOME.NOT_STARTED]: 'Aucune exécution',
  [RUN_OUTCOME.RUNNING]: 'En cours',
  [RUN_OUTCOME.SUCCESS]: 'Succès',
  [RUN_OUTCOME.UNSTABLE]: 'Instable',
  [RUN_OUTCOME.FAILED]: 'Échec',
  [RUN_OUTCOME.ABORTED]: 'Interrompu'
});

/**
 * The section kinds the Security Delivery page knows how to draw.
 *
 * A closed set. An adapter composes its page from these; it never asks for a
 * bespoke layout, and the renderer never branches on a provider name.
 */
const SECTION_KIND = Object.freeze({
  CONNECTION: 'connection',
  RUN_SUMMARY: 'run-summary',
  STAGE_LIST: 'stage-list',
  ARTIFACT_LIST: 'artifact-list',
  SECURITY_REPORT: 'security-report'
});
const SECTION_KINDS = Object.freeze(Object.values(SECTION_KIND));

/** A capability with no answer — never a fabricated value, always a reason. */
function notReportedCapability(reason = '') {
  return Object.freeze({ state: RESOLVED_STATE.NOT_REPORTED, reason: String(reason || '') });
}

function readyCapability() {
  return Object.freeze({ state: RESOLVED_STATE.READY, reason: '' });
}

/**
 * Builds the normalized delivery model every surface consumes.
 *
 * The dashboard card, the Security Delivery page and the Integrations card all
 * read this shape and nothing else. `providerLabel` is carried in the model on
 * purpose: it is what lets the dashboard stop saying « Jenkins » in its own
 * markup.
 */
function buildDeliveryModel({
  providerId = '',
  providerLabel = '',
  providerIcon = '',
  status = PROVIDER_STATUS.NOT_CONFIGURED,
  message = '',
  credentialsConfigured = false,
  target = '',
  pipeline = '',
  fetchedAt = null,
  capabilities = {},
  run = null,
  stages = [],
  artifacts = [],
  deployment = null,
  securityReport = null,
  sections = [],
  raw = null
} = {}) {
  return Object.freeze({
    providerId: String(providerId || ''),
    providerLabel: String(providerLabel || providerId || ''),
    providerIcon: String(providerIcon || ''),
    status,
    statusLabel: PROVIDER_STATUS_LABELS[status] || status,
    message: String(message || ''),
    configured: status !== PROVIDER_STATUS.NOT_CONFIGURED,
    credentialsConfigured: Boolean(credentialsConfigured),
    // The address of the platform and the name of the thing being watched,
    // whatever each vendor calls them.
    target: String(target || ''),
    pipeline: String(pipeline || ''),
    fetchedAt,
    capabilities: Object.freeze({ ...capabilities }),
    // `run` stays null when nothing was reported. A null run is « not started »
    // or « not reported », never a failed one.
    run: run ? Object.freeze({ ...run }) : null,
    stages: Object.freeze([...(stages || [])]),
    artifacts: Object.freeze([...(artifacts || [])]),
    deployment: deployment ? Object.freeze({ ...deployment }) : null,
    securityReport: securityReport ? Object.freeze({ ...securityReport }) : null,
    sections: Object.freeze([...(sections || [])]),
    // The adapter's own payload, kept for provider-specific detail rendering
    // that the generic renderer passes through without interpreting.
    raw
  });
}

/** The model shown when no provider is selected at all. */
function notConfiguredModel({ providerId = '', providerLabel = '', providerIcon = '', message = '' } = {}) {
  return buildDeliveryModel({
    providerId,
    providerLabel,
    providerIcon,
    status: PROVIDER_STATUS.NOT_CONFIGURED,
    message,
    capabilities: CAPABILITIES.reduce(
      (all, capability) => ({ ...all, [capability]: { state: RESOLVED_STATE.REQUIRES_CONFIG, reason: '' } }),
      {}
    )
  });
}

/** Capability declarations of an adapter, defaulted for every known capability. */
function normalizeCapabilities(adapter) {
  const declared = adapter?.capabilities || {};
  const result = {};
  for (const capability of CAPABILITIES) {
    result[capability] = declared[capability] || DECLARED_STATE.UNAVAILABLE;
  }
  return Object.freeze(result);
}

/** Sections an adapter declares, filtered to the kinds the renderer knows. */
function visibleSections(adapter) {
  return Object.freeze((adapter?.sections || []).filter((section) => SECTION_KINDS.includes(section?.kind)));
}

const REQUIRED_ADAPTER_METHODS = Object.freeze(['validateConfiguration', 'testConnection', 'fetchDelivery']);

/**
 * Refuses an adapter that cannot honour the contract.
 *
 * Fails at load time rather than at render time: a half-implemented adapter
 * that reaches the page is a provider that lies about what it can do.
 */
function assertDeliveryAdapter(adapter) {
  if (!adapter || typeof adapter !== 'object') throw new Error('Adaptateur Delivery invalide.');
  if (!adapter.id) throw new Error('Un adaptateur Delivery doit déclarer un identifiant.');
  for (const method of REQUIRED_ADAPTER_METHODS) {
    if (typeof adapter[method] !== 'function') {
      throw new Error(`L’adaptateur Delivery « ${adapter.id} » n’implémente pas ${method}().`);
    }
  }
  for (const [capability, state] of Object.entries(adapter.capabilities || {})) {
    if (!CAPABILITIES.includes(capability)) {
      throw new Error(`Capacité Delivery inconnue « ${capability} » déclarée par « ${adapter.id} ».`);
    }
    if (!Object.values(DECLARED_STATE).includes(state)) {
      throw new Error(`État déclaré invalide « ${state} » pour « ${capability} ».`);
    }
  }
  for (const section of adapter.sections || []) {
    if (!SECTION_KINDS.includes(section?.kind)) {
      throw new Error(`Section Delivery inconnue « ${section?.kind} » déclarée par « ${adapter.id} ».`);
    }
  }
  return adapter;
}

module.exports = {
  PROVIDER_STATUS,
  PROVIDER_STATUS_LABELS,
  CAPABILITY,
  CAPABILITIES,
  DECLARED_STATE,
  RESOLVED_STATE,
  RUN_OUTCOME,
  RUN_OUTCOME_LABELS,
  SECTION_KIND,
  SECTION_KINDS,
  FIELD_TYPE,
  CONFIG_GROUP,
  fieldsInGroup,
  validateAgainstFields,
  toBooleanValue,
  notReportedCapability,
  readyCapability,
  buildDeliveryModel,
  notConfiguredModel,
  normalizeCapabilities,
  visibleSections,
  REQUIRED_ADAPTER_METHODS,
  assertDeliveryAdapter
};
