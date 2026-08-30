'use strict';

const { normalizeIntegrationUrl } = require('./http');
const {
  assertAdapterContract, CONNECTION_STATUS, CONNECTION_LABELS, buildRuntimeSecurityModel,
  CAPABILITY, CAPABILITY_STATE, normalizeCapabilities, capabilityState, hasCapability, supportedCapabilities
} = require('./siem-contract');
const { wazuhAdapter } = require('./siem-wazuh');
const { elasticAdapter } = require('./siem-elastic');
const { splunkAdapter } = require('./siem-splunk');
const { SIEM_CATALOGUE } = require('./siem-catalogue');

const RUNTIME_STATUS = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  ONLINE: 'online',
  DEGRADED: 'degraded',
  OFFLINE: 'offline',
  AUTH_ERROR: 'auth-error',
  TIMEOUT: 'timeout',
  ERROR: 'error'
});

const AGENT_STATUS = Object.freeze({
  ACTIVE: 'active',
  DISCONNECTED: 'disconnected',
  NEVER_CONNECTED: 'never-connected',
  UNKNOWN: 'unknown'
});

/**
 * The SIEM catalogue — the single source of provider identity.
 *
 * Runtime Security is a *domain*, not a Wazuh feature. Each entry points at a
 * real adapter implementing the shared contract, so choosing a platform here is
 * a genuine integration rather than a label. Adding a provider means adding an
 * adapter and one line below; no Runtime Security UI changes.
 */
const ADAPTERS = Object.freeze([wazuhAdapter, elasticAdapter, splunkAdapter].map(assertAdapterContract));

/**
 * Implementation state, kept internal.
 *
 * `SUPPORTED` means an adapter exists and can really be talked to. `AVAILABLE`
 * means the platform is part of the Runtime Security product and its connection
 * schema is known, but nothing can connect to it yet. The catalogue is what the
 * user sees; this flag is what decides whether an action is offered — which is
 * how the surface stays multi-SIEM without ever claiming a connection it cannot
 * make.
 */
const SIEM_PROVIDER_STATUS = Object.freeze({ SUPPORTED: 'supported', AVAILABLE: 'available' });

/**
 * The catalogue, merged with whatever is implemented.
 *
 * An implemented adapter is authoritative for its own configuration and
 * capabilities; the catalogue supplies identity and, for the rest, the schema a
 * future adapter will need.
 */
const SIEM_PROVIDERS = Object.freeze(SIEM_CATALOGUE.map((entry) => {
  const adapter = ADAPTERS.find((candidate) => candidate.id === entry.id) || null;
  // Only an adapter can describe a connection or a capability. Without one both
  // are empty: « no adapter » is not « needs configuration », and a schema
  // nobody has implemented against is a claim about another vendor's product.
  const configurationFields = Object.freeze([...(adapter?.configurationFields || [])]);
  return Object.freeze({
    id: entry.id,
    label: adapter?.label || entry.label,
    icon: adapter?.icon || entry.icon || '',
    summary: adapter?.summary || entry.summary || '',
    docsHint: adapter?.docsHint || entry.docsHint || '',
    status: adapter ? SIEM_PROVIDER_STATUS.SUPPORTED : SIEM_PROVIDER_STATUS.AVAILABLE,
    implemented: Boolean(adapter),
    configurationFields,
    configuredBy: configurationFields.map((field) => field.id),
    // Resolved once here so every surface reads the same answer, and so a page
    // can decide which sections to offer without importing the adapter itself.
    capabilities: normalizeCapabilities(adapter),
    supportedCapabilities: supportedCapabilities(adapter)
  });
}));

const DEFAULT_SIEM_PROVIDER = 'wazuh';

/**
 * A provider id, from either shape it travels in.
 *
 * The normalized model carries `provider` as `{ id, label }` while settings and
 * messages carry it as a plain string. Accepting both here is what stops a
 * surface from silently resolving to « no provider » depending on which of the
 * two it happened to be holding.
 */
function providerId(value) {
  const raw = value && typeof value === 'object' ? value.id : value;
  return String(raw || '').toLowerCase();
}

/** The adapter behind a provider id, or null when nothing implements it. */
function siemAdapter(id) {
  return ADAPTERS.find((adapter) => adapter.id === providerId(id)) || null;
}

function siemProvider(id) {
  return SIEM_PROVIDERS.find((provider) => provider.id === providerId(id)) || null;
}

/** A provider Security Center can really connect to right now. */
function isSupportedSiemProvider(id) {
  return siemProvider(id)?.status === SIEM_PROVIDER_STATUS.SUPPORTED;
}

function supportedSiemProviders() {
  return SIEM_PROVIDERS.filter((provider) => provider.status === SIEM_PROVIDER_STATUS.SUPPORTED);
}

/** Catalogued providers that have no adapter yet. Never offered an action. */
function plannedSiemProviders() {
  return SIEM_PROVIDERS.filter((provider) => !provider.implemented);
}

/** The provider label, without ever inventing one for an unknown id. */
function siemProviderLabel(id) {
  return siemProvider(id)?.label || '';
}

function normalizeAgentStatus(value) {
  const text = String(value || '').toLowerCase().replace(/_/g, '-');
  if (text === 'active') return AGENT_STATUS.ACTIVE;
  if (text === 'disconnected') return AGENT_STATUS.DISCONNECTED;
  if (text === 'never-connected' || text === 'never connected' || text === 'never_connected') return AGENT_STATUS.NEVER_CONNECTED;
  return AGENT_STATUS.UNKNOWN;
}

function agentSummary(agents) {
  const total = agents.length;
  const active = agents.filter((agent) => agent.status === AGENT_STATUS.ACTIVE).length;
  const disconnected = agents.filter((agent) => agent.status === AGENT_STATUS.DISCONNECTED).length;
  const neverConnected = agents.filter((agent) => agent.status === AGENT_STATUS.NEVER_CONNECTED).length;
  return { total, active, disconnected, neverConnected };
}

function alertSummary(alerts) {
  return {
    critical: alerts.filter((alert) => alert.severity === 'CRITICAL').length,
    high: alerts.filter((alert) => alert.severity === 'HIGH').length,
    medium: alerts.filter((alert) => alert.severity === 'MEDIUM').length,
    low: alerts.filter((alert) => alert.severity === 'LOW' || alert.severity === 'INFO').length
  };
}

/**
 * The empty/normalized status every surface can render before any provider has
 * answered. It names no vendor: an unconfigured domain has no provider.
 */
function buildRuntimeSecurityStatus({
  provider = '',
  label = '',
  configured = false,
  baseUrl = '',
  status = RUNTIME_STATUS.NOT_CONFIGURED,
  version = '',
  message = '',
  agents = [],
  alerts = [],
  lastChecked = null,
  credentialsConfigured = false
} = {}) {
  return {
    provider,
    label,
    category: 'siem',
    configured: Boolean(configured),
    baseUrl,
    credentialsConfigured: Boolean(credentialsConfigured),
    status,
    version,
    message,
    lastChecked,
    agents,
    alerts,
    agentSummary: agentSummary(agents),
    alertSummary: alertSummary(alerts)
  };
}

module.exports = {
  RUNTIME_STATUS,
  AGENT_STATUS,
  SIEM_PROVIDERS,
  SIEM_PROVIDER_STATUS,
  DEFAULT_SIEM_PROVIDER,
  siemProvider,
  siemProviderLabel,
  isSupportedSiemProvider,
  supportedSiemProviders,
  plannedSiemProviders,
  siemAdapter,
  CAPABILITY,
  CAPABILITY_STATE,
  normalizeCapabilities,
  capabilityState,
  hasCapability,
  supportedCapabilities,
  CONNECTION_STATUS,
  CONNECTION_LABELS,
  buildRuntimeSecurityModel,
  buildRuntimeSecurityStatus,
  normalizeAgentStatus,
  agentSummary,
  alertSummary
};
