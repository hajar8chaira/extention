'use strict';

/**
 * The Observability adapter contract.
 *
 * Infrastructure integrates *a category of product* — metrics backends — not
 * one tool. Every provider reaches the Infrastructure page through this single
 * shape, so the page never learns where its numbers came from and a new backend
 * is added without touching a line of UI.
 *
 * This is a sibling of the SIEM contract, not a copy of it. The mechanisms they
 * share (field schemas, the declared→resolved capability ladder) are borrowed;
 * the vocabulary is not. An alert severity means nothing to a metrics backend,
 * and a CPU percentage means nothing to a SIEM.
 *
 * Two rules the whole design exists to enforce:
 *
 *   1. Configured is not capable. A provider that answers has proved only that
 *      it answers. Whether it can supply CPU is a fact about the deployment,
 *      discovered by asking, and a deployment that exports no such series is
 *      not broken — it simply does not have that capability.
 *
 *   2. Missing is missing. A metric with no value carries `available: false`
 *      and a reason. It never carries `0`, which would read as a measurement.
 */

const { FIELD_TYPE, CONFIG_GROUP, fieldsInGroup, validateAgainstFields, toBooleanValue } = require('./siem-contract');

/**
 * The connection itself — is the provider reachable and authenticated. Separate
 * from what it can serve, which is what capabilities describe.
 */
const PROVIDER_STATUS = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  HEALTHY: 'healthy',
  DEGRADED: 'degraded',
  OFFLINE: 'offline',
  QUERY_ERROR: 'query-error',
  AUTH_ERROR: 'auth-error',
  TIMEOUT: 'timeout'
});

/**
 * The capability vocabulary.
 *
 * Exactly what Infrastructure displays today, and nothing more. `uptime`,
 * `network` and `serviceHealth` are deliberately absent: no adapter can prove
 * one, nothing renders one, and a vocabulary that describes intentions rather
 * than facts is how a catalogue starts lying. Each is added when an adapter
 * arrives that genuinely serves it.
 */
const CAPABILITY = Object.freeze({
  HOST_INVENTORY: 'hostInventory',
  CPU: 'cpu',
  MEMORY: 'memory',
  DISK: 'disk',
  LOAD: 'load'
});

/**
 * What an adapter may *declare* about a capability.
 *
 * `REQUIRES_PROBE` is the state this domain needs and the SIEM one does not:
 * it means « this adapter knows how to ask, and whether the deployment answers
 * is not something configuration can settle ». A Prometheus with no
 * node_exporter is fully configured and simply has no CPU series.
 */
const DECLARED_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  REQUIRES_PROBE: 'requires-probe',
  UNAVAILABLE: 'unavailable'
});
const DECLARED_STATES = Object.freeze(Object.values(DECLARED_STATE));

/** What a capability resolves to once runtime evidence exists. */
const RESOLVED_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  UNAVAILABLE: 'unavailable',
  ERROR: 'error'
});
const RESOLVED_STATES = Object.freeze(Object.values(RESOLVED_STATE));

/**
 * Why a metric has no value.
 *
 * « The provider does not export it », « the query failed » and « we do not
 * know which entity you mean » call for three different user actions, and none
 * of them is a zero.
 */
const METRIC_REASON = Object.freeze({
  NOT_EXPORTED: 'not-exported',
  QUERY_FAILED: 'query-failed',
  ENTITY_NOT_SELECTED: 'entity-not-selected',
  // The provider reported several readings that cannot honestly be combined
  // into one — percentages with no weights, for instance. Picking one silently
  // is how a fleet becomes one arbitrary machine.
  AMBIGUOUS: 'ambiguous',
  // The name this reason carried while the domain only knew about hosts. Kept
  // so no caller had to be edited when entities became the general term.
  HOST_NOT_SELECTED: 'entity-not-selected'
});

/**
 * The section kinds the Infrastructure page knows how to draw.
 *
 * A closed set, on purpose. An adapter composes its dashboard from these; it
 * never asks for a bespoke layout, and the renderer never branches on a
 * provider name. A genuinely new kind is a deliberate addition here, reviewed
 * once, and then available to every adapter.
 */
const SECTION_KIND = Object.freeze({
  ENTITY_INVENTORY: 'entity-inventory',
  METRIC_TILES: 'metric-tiles',
  STATUS_LIST: 'status-list'
});
const SECTION_KINDS = Object.freeze(Object.values(SECTION_KIND));

/** A metric with no value — never `0`, always a reason. */
function unavailableMetric(reason = METRIC_REASON.NOT_EXPORTED) {
  return { available: false, value: null, display: 'Unavailable', reason };
}

function availableMetric(value, display) {
  return { available: true, value, display, reason: '' };
}

/**
 * An entity the provider monitors — a host, a node, whatever it calls them.
 * Provider-specific identifiers are normalized here and nowhere else.
 */
function normalizeEntity(raw = {}) {
  const text = (value) => String(value ?? '').trim();
  return {
    id: text(raw.id),
    name: text(raw.name) || text(raw.id),
    type: text(raw.type) || 'host',
    status: text(raw.status),
    endpoint: text(raw.endpoint),
    lastSeen: text(raw.lastSeen) || null
  };
}

/** An inventory that could not be read. Not the same as « no entities ». */
function unknownInventory() {
  return { known: false, up: null, total: null, display: 'Unavailable' };
}

/**
 * The one model every adapter returns and the Infrastructure page consumes.
 *
 * Historical field names (`targets`, `metrics`, `selectedHost`) are preserved
 * alongside the generic ones so the existing page, the Integrations card and
 * the dashboard keep working while the provider layer is generalised underneath.
 */
function buildInfrastructureModel({
  provider = '', label = '', configured = false, baseUrl = '',
  status = PROVIDER_STATUS.NOT_CONFIGURED, message = '', credentialsConfigured = false,
  entities = [], inventory = null, selectedEntity = '', selectionRequired = false,
  selectableEntities = null,
  metrics = {}, capabilities = {}, failures = [], filesystems = [],
  lastChecked = null, relaxedTls = false, targets = null
} = {}) {
  const normalizedEntities = entities.map(normalizeEntity);
  const entityIds = normalizedEntities.map((entity) => entity.id).filter(Boolean);
  // Being in the inventory and being selectable are two different facts. A
  // provider that monitors something it has no host metrics for still lists it,
  // but offering it as a choice would offer a choice with nothing behind it.
  // Adapters that do not distinguish the two get the previous behaviour.
  const selectable = Array.isArray(selectableEntities)
    ? [...new Set(selectableEntities.map((id) => String(id || '').trim()).filter(Boolean))]
    : entityIds;
  return {
    provider,
    label,
    category: 'observability',
    configured: Boolean(configured),
    baseUrl: String(baseUrl || ''),
    credentialsConfigured: Boolean(credentialsConfigured),
    status,
    message: String(message || ''),
    relaxedTls: Boolean(relaxedTls),

    entities: normalizedEntities,
    selectableEntities: selectable,
    inventory: inventory || unknownInventory(),
    selectedEntity,
    selectionRequired: Boolean(selectionRequired),

    // `load1` is the name every existing surface reads; `load` is the
    // capability. One object under both keys, so the rename cost no caller.
    metrics: { ...metrics, ...(metrics.load && !metrics.load1 ? { load1: metrics.load } : {}) },
    capabilities: { ...capabilities },
    failures: [...failures],
    filesystems: [...filesystems],
    lastChecked,

    // ---- Compatibility surface --------------------------------------------
    hosts: selectable,
    selectedHost: selectedEntity,
    hostSelectionRequired: Boolean(selectionRequired),
    targets: targets || { ...unknownInventory(), items: [], selectedHost: '', lastScrape: '', lastScrapeAgeSeconds: null }
  };
}

/**
 * What a capability resolves to.
 *
 * `unavailable` is never promoted — an adapter that cannot serve something will
 * not start being able to because credentials appeared. Everything else is
 * decided by evidence, and only by evidence: no configuration presence, no
 * connection state, no sibling capability's outcome.
 */
function resolveCapabilities(adapter, { configured = false, evidence = {} } = {}) {
  const declared = normalizeCapabilities(adapter);
  const resolved = {};
  for (const capability of Object.values(CAPABILITY)) {
    const state = declared[capability];
    if (state === DECLARED_STATE.UNAVAILABLE) {
      resolved[capability] = RESOLVED_STATE.UNAVAILABLE;
      continue;
    }
    const witnessed = String(evidence?.[capability]?.state || evidence?.[capability] || '');
    if (RESOLVED_STATES.includes(witnessed)) {
      resolved[capability] = witnessed;
      continue;
    }
    if (!configured) {
      resolved[capability] = RESOLVED_STATE.REQUIRES_CONFIG;
      continue;
    }
    // Configured, no evidence yet: a `ready` declaration is trusted (the
    // adapter says the connection alone proves it); anything that needs a probe
    // stays unproven rather than optimistic.
    resolved[capability] = state === DECLARED_STATE.READY
      ? RESOLVED_STATE.READY
      : RESOLVED_STATE.REQUIRES_CONFIG;
  }
  return Object.freeze(resolved);
}

function normalizeCapabilities(adapter) {
  const declared = adapter && typeof adapter.capabilities === 'object' ? adapter.capabilities : {};
  const resolved = {};
  for (const capability of Object.values(CAPABILITY)) {
    const state = String(declared[capability] || '').trim();
    resolved[capability] = DECLARED_STATES.includes(state) ? state : DECLARED_STATE.UNAVAILABLE;
  }
  return Object.freeze(resolved);
}

/** Sections whose capabilities resolved to something worth drawing. */
function visibleSections(adapter, resolved = {}) {
  const sections = Array.isArray(adapter?.sections) ? adapter.sections : [];
  return sections.filter((section) => {
    const needed = Array.isArray(section.capability) ? section.capability : [section.capability];
    return needed.some((capability) => (
      resolved[capability] === RESOLVED_STATE.READY || resolved[capability] === RESOLVED_STATE.ERROR
    ));
  });
}

const REQUIRED_ADAPTER_METHODS = Object.freeze(['validateConfiguration', 'testConnection', 'fetchStatus']);

function assertObservabilityAdapter(adapter) {
  if (!adapter || typeof adapter !== 'object') throw new Error('Adaptateur observabilite invalide.');
  if (!adapter.id || !adapter.label) throw new Error('Un adaptateur observabilite doit declarer un id et un label.');
  if (!Array.isArray(adapter.configurationFields)) throw new Error(`L'adaptateur ${adapter.id} doit declarer configurationFields.`);
  for (const field of adapter.configurationFields) {
    if (!field.id || !field.label) throw new Error(`Champ incomplet dans ${adapter.id}.`);
    if (field.type && !Object.values(FIELD_TYPE).includes(field.type)) {
      throw new Error(`Type de champ inconnu pour ${adapter.id}.${field.id} : ${field.type}.`);
    }
  }
  for (const method of REQUIRED_ADAPTER_METHODS) {
    if (typeof adapter[method] !== 'function') throw new Error(`L'adaptateur ${adapter.id} doit implementer ${method}().`);
  }
  if (adapter.capabilities !== undefined) {
    if (typeof adapter.capabilities !== 'object' || adapter.capabilities === null || Array.isArray(adapter.capabilities)) {
      throw new Error(`Les capacites de l'adaptateur ${adapter.id} doivent etre un objet.`);
    }
    for (const [capability, state] of Object.entries(adapter.capabilities)) {
      if (!Object.values(CAPABILITY).includes(capability)) {
        throw new Error(`Capacite inconnue pour ${adapter.id} : ${capability}.`);
      }
      if (!DECLARED_STATES.includes(state)) {
        throw new Error(`Etat de capacite invalide pour ${adapter.id}.${capability} : ${state}.`);
      }
    }
  }
  for (const section of adapter.sections || []) {
    if (!SECTION_KINDS.includes(section.kind)) {
      throw new Error(`Type de section inconnu pour ${adapter.id} : ${section.kind}.`);
    }
    const needed = Array.isArray(section.capability) ? section.capability : [section.capability];
    for (const capability of needed) {
      if (!Object.values(CAPABILITY).includes(capability)) {
        throw new Error(`Section ${section.id} de ${adapter.id} reference une capacite inconnue : ${capability}.`);
      }
    }
  }
  return adapter;
}

module.exports = {
  PROVIDER_STATUS,
  CAPABILITY,
  DECLARED_STATE,
  DECLARED_STATES,
  RESOLVED_STATE,
  RESOLVED_STATES,
  METRIC_REASON,
  SECTION_KIND,
  SECTION_KINDS,
  FIELD_TYPE,
  CONFIG_GROUP,
  fieldsInGroup,
  validateAgainstFields,
  toBooleanValue,
  unavailableMetric,
  availableMetric,
  normalizeEntity,
  unknownInventory,
  buildInfrastructureModel,
  normalizeCapabilities,
  resolveCapabilities,
  visibleSections,
  assertObservabilityAdapter,
  REQUIRED_ADAPTER_METHODS
};
