'use strict';

/**
 * The SIEM adapter contract.
 *
 * Security Center integrates *a category of product*, not one vendor. Every
 * provider — Wazuh, Elastic, Splunk, Sentinel, or a customer's own REST API —
 * reaches the Runtime Security page through this single shape, so the page never
 * learns where its data came from and a new platform is added without touching
 * a line of UI.
 *
 * An adapter owns three things and nothing else:
 *   - what configuration it needs (`configurationFields`)
 *   - how to reach its API (`testConnection`, `fetchStatus`)
 *   - how to translate its own vocabulary into the model below (`normalize*`)
 *
 * What an adapter must never do: decide presentation, invent data, or return a
 * shape of its own. A field a provider genuinely cannot supply stays `null` —
 * never `0`, which would read as a measured absence of risk.
 */

const CONNECTION_STATUS = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  ONLINE: 'online',
  DEGRADED: 'degraded',
  OFFLINE: 'offline',
  AUTH_ERROR: 'auth-error',
  TIMEOUT: 'timeout',
  INVALID_CONFIG: 'invalid-config',
  UNSUPPORTED_RESPONSE: 'unsupported-response',
  ERROR: 'error'
});

/** One severity vocabulary for every provider, whatever they call theirs. */
const SEVERITY = Object.freeze(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

const ENDPOINT_STATUS = Object.freeze({
  ACTIVE: 'active',
  DISCONNECTED: 'disconnected',
  NEVER_CONNECTED: 'never-connected',
  UNKNOWN: 'unknown'
});

/** Maps an arbitrary provider severity word onto the shared vocabulary. */
function normalizeSeverity(value, fallback = 'INFO') {
  const text = String(value ?? '').trim().toUpperCase();
  if (SEVERITY.includes(text)) return text;
  if (['CRIT', 'FATAL', 'SEVERE', 'P1', '4'].includes(text)) return 'CRITICAL';
  if (['ERROR', 'MAJOR', 'P2', '3'].includes(text)) return 'HIGH';
  if (['WARN', 'WARNING', 'MODERATE', 'P3', '2'].includes(text)) return 'MEDIUM';
  if (['MINOR', 'P4', '1'].includes(text)) return 'LOW';
  if (['INFORMATIONAL', 'INFORMATION', 'NOTICE', 'DEBUG', 'P5', '0'].includes(text)) return 'INFO';
  return fallback;
}

/** Numeric provider scales (Wazuh 0-15, Elastic/Sentinel 0-100) → vocabulary. */
function severityFromScale(value, { max = 100 } = {}) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  const ratio = Math.max(0, Math.min(1, numeric / max));
  if (ratio >= 0.8) return 'CRITICAL';
  if (ratio >= 0.6) return 'HIGH';
  if (ratio >= 0.3) return 'MEDIUM';
  if (ratio > 0) return 'LOW';
  return 'INFO';
}

function normalizeEndpointStatus(value) {
  const text = String(value ?? '').toLowerCase().replace(/[\s_]+/g, '-');
  if (['active', 'online', 'connected', 'healthy', 'up'].includes(text)) return ENDPOINT_STATUS.ACTIVE;
  if (['disconnected', 'offline', 'inactive', 'down'].includes(text)) return ENDPOINT_STATUS.DISCONNECTED;
  if (['never-connected', 'pending', 'never'].includes(text)) return ENDPOINT_STATUS.NEVER_CONNECTED;
  return ENDPOINT_STATUS.UNKNOWN;
}

/**
 * Where a configuration field belongs in the form.
 *
 * `ADVANCED` is progressive disclosure, not a second class of field: it holds
 * the inputs a provider genuinely does not need for its basic connection. Wazuh
 * connects with the Manager API alone; the Indexer only unlocks capabilities
 * that depend on it.
 */
const CONFIG_GROUP = Object.freeze({ PRIMARY: 'primary', ADVANCED: 'advanced' });

/**
 * Declared field types. `boolean` exists because some provider options are a
 * decision rather than a value — and a decision has to be able to be *no*,
 * which an empty string cannot express.
 */
const FIELD_TYPE = Object.freeze({ TEXT: 'text', URL: 'url', PASSWORD: 'password', BOOLEAN: 'boolean' });

/** Reads a submitted checkbox value without ever guessing from emptiness. */
function toBooleanValue(value) {
  return value === true || value === 'true' || value === 'on' || value === '1';
}

/** Fields of one group, in declaration order. Ungrouped fields are primary. */
function fieldsInGroup(fields = [], group = CONFIG_GROUP.PRIMARY) {
  return (fields || []).filter((field) => (field.group || CONFIG_GROUP.PRIMARY) === group);
}

function text(value, fallback = '') {
  const result = value === null || value === undefined ? '' : String(value).trim();
  return result || fallback;
}

/** A monitored host, in Security Center's words. */
function normalizeEndpoint(raw = {}) {
  return {
    id: text(raw.id),
    name: text(raw.name) || text(raw.hostname) || 'unknown-host',
    hostname: text(raw.hostname) || text(raw.name),
    ip: text(raw.ip),
    os: text(raw.os),
    status: normalizeEndpointStatus(raw.status),
    // Never invented: a provider that does not report last-seen says so.
    lastSeen: text(raw.lastSeen) || null
  };
}

/**
 * One alert, in Security Center's words.
 *
 * `rawReference` is an identifier the user can paste back into their own console
 * — never the provider's raw payload, which could carry secrets or unbounded text.
 */
function normalizeAlert(raw = {}, { source = '' } = {}) {
  const techniques = Array.isArray(raw.mitreTechniques) ? raw.mitreTechniques : [];
  return {
    id: text(raw.id),
    timestamp: text(raw.timestamp) || null,
    severity: normalizeSeverity(raw.severity),
    title: text(raw.title, 'Runtime security alert'),
    description: text(raw.description),
    ruleId: text(raw.ruleId),
    source: text(raw.source) || text(source),
    endpoint: text(raw.endpoint),
    user: text(raw.user),
    mitreTechniques: [...new Set(techniques.map((item) => text(item)).filter(Boolean))],
    rawReference: text(raw.rawReference),
    status: text(raw.status, 'open')
  };
}

function endpointSummary(endpoints = []) {
  return {
    total: endpoints.length,
    active: endpoints.filter((item) => item.status === ENDPOINT_STATUS.ACTIVE).length,
    disconnected: endpoints.filter((item) => item.status === ENDPOINT_STATUS.DISCONNECTED).length,
    neverConnected: endpoints.filter((item) => item.status === ENDPOINT_STATUS.NEVER_CONNECTED).length,
    unknown: endpoints.filter((item) => item.status === ENDPOINT_STATUS.UNKNOWN).length
  };
}

function alertSummary(alerts = []) {
  const count = (level) => alerts.filter((alert) => alert.severity === level).length;
  return {
    total: alerts.length,
    critical: count('CRITICAL'),
    high: count('HIGH'),
    medium: count('MEDIUM'),
    low: count('LOW'),
    info: count('INFO')
  };
}

/**
 * The one model every adapter returns and the Runtime Security page consumes.
 *
 * Historical field names (`agents`, `agentSummary`) are kept alongside the
 * generic ones so the existing page, the Integrations card and the dashboard
 * keep working unchanged while the provider layer is generalised underneath.
 */
function buildRuntimeSecurityModel({
  provider = '', label = '', configured = false, baseUrl = '',
  status = CONNECTION_STATUS.NOT_CONFIGURED, message = '', version = '',
  endpoints = [], alerts = [], rules = [], lastSync = null,
  credentialsConfigured = false,
  // Whether THIS connection was made with relaxed certificate verification.
  // A provider states it; no surface infers it from a configuration field.
  relaxedTls = false
} = {}) {
  const normalizedEndpoints = endpoints.map(normalizeEndpoint);
  const normalizedAlerts = alerts.map((alert) => normalizeAlert(alert, { source: provider }));
  const techniques = [...new Set(normalizedAlerts.flatMap((alert) => alert.mitreTechniques))].sort();
  return {
    provider: { id: String(provider || ''), label: String(label || '') },
    category: 'siem',
    configured: Boolean(configured),
    baseUrl: String(baseUrl || ''),
    credentialsConfigured: Boolean(credentialsConfigured),
    relaxedTls: Boolean(relaxedTls),
    connectionStatus: status,
    message: String(message || ''),
    version: String(version || ''),
    endpoints: normalizedEndpoints,
    endpointSummary: endpointSummary(normalizedEndpoints),
    alerts: normalizedAlerts,
    alertSummary: alertSummary(normalizedAlerts),
    techniques,
    rules: [...new Set(rules.map((rule) => text(rule)).filter(Boolean))],
    lastSync: lastSync || null,

    // ---- Compatibility surface -------------------------------------------
    // The renderer, the dashboard card and the Integrations card were written
    // against these names. Keeping them is what makes the provider layer a
    // pure addition rather than a UI rewrite.
    id: String(provider || ''),
    label: String(label || ''),
    status,
    lastChecked: lastSync || null,
    agents: normalizedEndpoints.map((endpoint) => ({ ...endpoint, lastSeen: endpoint.lastSeen || '' })),
    agentSummary: endpointSummary(normalizedEndpoints)
  };
}

/** Turns a transport failure into a connection status, never into a throw. */
function statusFromError(error) {
  const code = String(error?.code || '');
  if (code === 'AUTH_ERROR') return CONNECTION_STATUS.AUTH_ERROR;
  if (code === 'TIMEOUT') return CONNECTION_STATUS.TIMEOUT;
  if (code === 'OFFLINE' || code === 'INVALID_URL') return CONNECTION_STATUS.OFFLINE;
  if (code === 'TOO_LARGE' || code === 'REDIRECT') return CONNECTION_STATUS.UNSUPPORTED_RESPONSE;
  return CONNECTION_STATUS.ERROR;
}

/** Human wording for a connection state, shared by every provider. */
const CONNECTION_LABELS = Object.freeze({
  'not-configured': 'Not configured',
  online: 'Connected',
  degraded: 'Degraded',
  offline: 'Endpoint unavailable',
  'auth-error': 'Authentication failed',
  timeout: 'Timed out',
  'invalid-config': 'Invalid configuration',
  'unsupported-response': 'Unsupported response',
  error: 'Error'
});

/**
 * Validates a configuration against an adapter's declared fields.
 *
 * Declarative on purpose: the form, the validation and the secret boundary all
 * read the same field list, so a provider cannot end up with a form asking for
 * something its adapter never validates.
 */
function validateAgainstFields(fields = [], config = {}) {
  const errors = [];
  const value = (id) => String(config?.[id] ?? '').trim();
  for (const field of fields) {
    if (field.secret) continue; // secrets never travel through this object
    if (field.type === FIELD_TYPE.BOOLEAN) continue; // false is a valid answer
    if (field.required && !value(field.id)) errors.push(`${field.label} est requis.`);
  }
  return { valid: errors.length === 0, errors };
}

/** The non-secret keys an adapter is allowed to persist. */
function publicConfigKeys(fields = []) {
  return fields.filter((field) => !field.secret).map((field) => field.id);
}

/** The secret keys an adapter expects to receive from SecretStorage. */
function secretConfigKeys(fields = []) {
  return fields.filter((field) => field.secret).map((field) => field.id);
}

/**
 * Guards an adapter against accidentally omitting part of the contract.
 * Used by the registry and by the contract tests.
 */
/**
 * What a SIEM can be asked for.
 *
 * Runtime Security is one domain over very different products: Wazuh reports
 * agents and vulnerability state, Sentinel reports incidents and entities,
 * QRadar reports offenses. Declaring capabilities per adapter is what lets the
 * shared shell show each provider its own sections without the page growing a
 * chain of `if (provider === ...)`.
 */
const CAPABILITY = Object.freeze({
  ALERTS: 'alerts',
  VULNERABILITIES: 'vulnerabilities',
  ASSETS: 'assets',
  INCIDENTS: 'incidents',
  SCA: 'sca',
  FIM: 'fim',
  MITRE: 'mitre',
  RAW_EVENTS: 'rawEvents'
});

/**
 * How available a capability actually is.
 *
 * `REQUIRES_CONFIG` is the honest middle state and the reason this is not a
 * boolean: an adapter can implement a capability that the *deployment* cannot
 * serve yet — Wazuh vulnerability state lives in the Indexer, so it depends on
 * a connection the user may not have configured. That is a different fact from
 * « this provider has no adapter for it », and conflating the two would either
 * hide a working feature or promise a missing one.
 */
const CAPABILITY_STATE = Object.freeze({
  READY: 'ready',
  REQUIRES_CONFIG: 'requires-config',
  UNAVAILABLE: 'unavailable'
});

/**
 * Optional per-capability fetchers.
 *
 * An adapter may serve a capability through `fetchStatus` (summary level) or
 * through a dedicated method (detail level, paginated, cancellable). Both are
 * legitimate, which is why a `READY` capability does not require a fetcher —
 * but a fetcher that exists for an `UNAVAILABLE` capability is dead code, and
 * `assertAdapterContract` refuses it.
 */
const CAPABILITY_FETCHERS = Object.freeze({
  [CAPABILITY.ALERTS]: 'fetchAlerts',
  [CAPABILITY.VULNERABILITIES]: 'fetchVulnerabilities',
  [CAPABILITY.ASSETS]: 'fetchAssets',
  [CAPABILITY.INCIDENTS]: 'fetchIncidents',
  [CAPABILITY.SCA]: 'fetchSca',
  [CAPABILITY.FIM]: 'fetchFim'
});

const CAPABILITY_STATES = Object.freeze(Object.values(CAPABILITY_STATE));

/** Every capability resolved. An adapter that declares none supports none. */
function normalizeCapabilities(adapter) {
  const declared = adapter && typeof adapter.capabilities === 'object' ? adapter.capabilities : {};
  const resolved = {};
  for (const capability of Object.values(CAPABILITY)) {
    const state = String(declared[capability] || '').trim();
    resolved[capability] = CAPABILITY_STATES.includes(state) ? state : CAPABILITY_STATE.UNAVAILABLE;
  }
  return Object.freeze(resolved);
}

function capabilityState(adapter, capability) {
  return normalizeCapabilities(adapter)[capability] || CAPABILITY_STATE.UNAVAILABLE;
}

/** True when the capability is anything other than « this provider cannot ». */
function hasCapability(adapter, capability) {
  return capabilityState(adapter, capability) !== CAPABILITY_STATE.UNAVAILABLE;
}

/** The capabilities a surface may offer for this provider, in declared order. */
function supportedCapabilities(adapter) {
  const resolved = normalizeCapabilities(adapter);
  return Object.values(CAPABILITY).filter((capability) => resolved[capability] !== CAPABILITY_STATE.UNAVAILABLE);
}

const REQUIRED_ADAPTER_METHODS = Object.freeze(['validateConfiguration', 'testConnection', 'fetchStatus']);

function assertAdapterContract(adapter) {
  if (!adapter || typeof adapter !== 'object') throw new Error('Adaptateur SIEM invalide.');
  if (!adapter.id || !adapter.label) throw new Error('Un adaptateur SIEM doit declarer un id et un label.');
  if (!Array.isArray(adapter.configurationFields)) throw new Error(`L'adaptateur ${adapter.id} doit declarer configurationFields.`);
  for (const method of REQUIRED_ADAPTER_METHODS) {
    if (typeof adapter[method] !== 'function') throw new Error(`L'adaptateur ${adapter.id} doit implementer ${method}().`);
  }
  // Les capacites sont optionnelles : un adaptateur qui n'en declare aucune
  // n'en supporte aucune, ce qui garde les stubs existants valides.
  if (adapter.capabilities !== undefined) {
    if (typeof adapter.capabilities !== 'object' || adapter.capabilities === null || Array.isArray(adapter.capabilities)) {
      throw new Error(`Les capacites de l'adaptateur ${adapter.id} doivent etre un objet.`);
    }
    for (const [capability, state] of Object.entries(adapter.capabilities)) {
      if (!Object.values(CAPABILITY).includes(capability)) {
        throw new Error(`Capacite inconnue pour ${adapter.id} : ${capability}.`);
      }
      if (!CAPABILITY_STATES.includes(state)) {
        throw new Error(`Etat de capacite invalide pour ${adapter.id}.${capability} : ${state}.`);
      }
    }
  }
  // Un fetcher declare pour une capacite indisponible est du code mort : il
  // promettrait une donnee que rien n'affichera jamais.
  const resolved = normalizeCapabilities(adapter);
  for (const [capability, fetcher] of Object.entries(CAPABILITY_FETCHERS)) {
    if (typeof adapter[fetcher] === 'function' && resolved[capability] === CAPABILITY_STATE.UNAVAILABLE) {
      throw new Error(`L'adaptateur ${adapter.id} expose ${fetcher}() mais declare ${capability} indisponible.`);
    }
  }
  return adapter;
}

module.exports = {
  CONNECTION_STATUS,
  CONNECTION_LABELS,
  SEVERITY,
  ENDPOINT_STATUS,
  REQUIRED_ADAPTER_METHODS,
  CAPABILITY,
  CAPABILITY_STATE,
  CAPABILITY_STATES,
  CAPABILITY_FETCHERS,
  CONFIG_GROUP,
  FIELD_TYPE,
  toBooleanValue,
  fieldsInGroup,
  normalizeCapabilities,
  capabilityState,
  hasCapability,
  supportedCapabilities,
  normalizeSeverity,
  severityFromScale,
  normalizeEndpointStatus,
  normalizeEndpoint,
  normalizeAlert,
  endpointSummary,
  alertSummary,
  buildRuntimeSecurityModel,
  statusFromError,
  validateAgainstFields,
  publicConfigKeys,
  secretConfigKeys,
  assertAdapterContract
};
