'use strict';

/**
 * The Observability registry.
 *
 * Infrastructure is a *domain*, not a Prometheus feature. This file merges the
 * catalogue with whatever adapters exist and answers three questions for every
 * surface: which providers exist, which one can actually be talked to, and what
 * the selected one declares. It contains no endpoint, no query and no metric
 * name — those live inside adapters.
 *
 * The compatibility surface at the bottom keeps the names the Integrations
 * card, the dashboard, the page and the extension have always used, so
 * generalising the layer underneath cost no caller a change.
 */

const { normalizeIntegrationUrl } = require('./http');
const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON,
  SECTION_KIND, assertObservabilityAdapter, normalizeCapabilities, resolveCapabilities,
  visibleSections, buildInfrastructureModel, unavailableMetric, unknownInventory
} = require('./observability-contract');
const {
  prometheusAdapter, valuesByInstance, valuesByFilesystem, pairedFilesystems,
  selectEntity, inventoryFrom, secondsAgo
} = require('./observability-prometheus');
const { zabbixAdapter } = require('./observability-zabbix');
const { datadogAdapter } = require('./observability-datadog');
const { OBSERVABILITY_CATALOGUE, observabilityCatalogueEntry } = require('./observability-catalogue');

const ADAPTERS = Object.freeze([prometheusAdapter, zabbixAdapter, datadogAdapter].map(assertObservabilityAdapter));

/**
 * Implementation state, kept internal.
 *
 * `SUPPORTED` means an adapter exists and can really be queried. `PLANNED`
 * means the backend is part of the product but nothing can connect to it yet —
 * it has no adapter, and therefore no configuration schema and no capabilities.
 */
const OBSERVABILITY_PROVIDER_STATUS = Object.freeze({ SUPPORTED: 'supported', PLANNED: 'planned' });

const OBSERVABILITY_PROVIDERS = Object.freeze(OBSERVABILITY_CATALOGUE.map((entry) => {
  const adapter = ADAPTERS.find((candidate) => candidate.id === entry.id) || null;
  // Only an adapter can describe a connection or a capability. Without one both
  // are empty: a schema nobody has implemented against is a claim about another
  // vendor's product.
  const configurationFields = Object.freeze([...(adapter?.configurationFields || [])]);
  return Object.freeze({
    id: entry.id,
    label: adapter?.label || entry.label,
    icon: adapter?.icon || entry.icon || '',
    summary: adapter?.summary || entry.summary || '',
    docsHint: adapter?.docsHint || entry.docsHint || '',
    status: adapter ? OBSERVABILITY_PROVIDER_STATUS.SUPPORTED : OBSERVABILITY_PROVIDER_STATUS.PLANNED,
    implemented: Boolean(adapter),
    configurationFields,
    configuredBy: configurationFields.map((field) => field.id),
    capabilities: normalizeCapabilities(adapter),
    sections: Object.freeze([...(adapter?.sections || [])])
  });
}));

const DEFAULT_OBSERVABILITY_PROVIDER = 'prometheus';

/** The adapter behind a provider id, or null when nothing implements it. */
function observabilityAdapter(id) {
  return ADAPTERS.find((adapter) => adapter.id === String(id || '').toLowerCase()) || null;
}

function observabilityProvider(id) {
  return OBSERVABILITY_PROVIDERS.find((provider) => provider.id === String(id || '').toLowerCase()) || null;
}

/** A provider Security Center can really query right now. */
function isSupportedObservabilityProvider(id) {
  return observabilityProvider(id)?.status === OBSERVABILITY_PROVIDER_STATUS.SUPPORTED;
}

function supportedObservabilityProviders() {
  return OBSERVABILITY_PROVIDERS.filter((provider) => provider.implemented);
}

/** Catalogued backends that have no adapter yet. Never offered an action. */
function plannedObservabilityProviders() {
  return OBSERVABILITY_PROVIDERS.filter((provider) => !provider.implemented);
}

/** The provider label, without ever inventing one for an unknown id. */
function observabilityProviderLabel(id) {
  return observabilityProvider(id)?.label || '';
}

function displaySecondsAgo(seconds) {
  if (!Number.isFinite(seconds)) return 'Unavailable';
  if (seconds < 60) return `${Math.round(seconds)} seconds ago`;
  const minutes = Math.round(seconds / 60);
  return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
}

// ---------------------------------------------------------------------------
// Compatibility surface
//
// The names below are what the Integrations card, the dashboard, the page and
// the extension have always called. They now delegate to the adapter.
// ---------------------------------------------------------------------------

const PROMETHEUS_STATUS = PROVIDER_STATUS;

function buildPrometheusStatus(model = {}) {
  const provider = model.provider || (model.configured ? DEFAULT_OBSERVABILITY_PROVIDER : '');
  return buildInfrastructureModel({
    ...model,
    provider,
    label: model.label || (provider ? observabilityProviderLabel(provider) : '')
  });
}

/**
 * Reads the active observability provider.
 *
 * Kept on the historical signature so no caller changed; the work is the
 * adapter's, and `entity`/`host` is the same choice under two names.
 */
async function fetchPrometheusStatus({
  baseUrl = '', token = '', timeoutMs = 10000, request, host = '',
  providerId = DEFAULT_OBSERVABILITY_PROVIDER, allowSelfSigned = false
} = {}) {
  const adapter = observabilityAdapter(providerId);
  if (!adapter) return buildInfrastructureModel({ configured: false });
  const options = { timeoutMs, entity: host };
  if (request) options.request = request;
  return adapter.fetchStatus({ url: baseUrl, allowSelfSigned }, { bearerToken: token }, options);
}

/** The historical inventory shape, from the adapter's normalized reading. */
function targetsFrom(payload) {
  const { inventory, entities } = inventoryFrom(payload);
  return {
    ...inventory,
    selectedHost: '',
    items: entities.map((entity) => ({
      name: entity.name,
      instance: entity.id,
      endpoint: entity.endpoint,
      health: entity.status,
      lastScrape: entity.lastSeen
    }))
  };
}

function unknownTargets() {
  return { ...unknownInventory(), selectedHost: '', lastScrape: '', lastScrapeAgeSeconds: null, items: [] };
}

/** A single scalar, for callers that legitimately want one. */
function firstVectorValue(payload) {
  const result = payload?.data?.result;
  if (!Array.isArray(result) || !result.length) return null;
  const number = Number(result[0]?.value?.[1]);
  return Number.isFinite(number) ? number : null;
}

module.exports = {
  // --- registry ------------------------------------------------------------
  OBSERVABILITY_PROVIDERS,
  OBSERVABILITY_PROVIDER_STATUS,
  OBSERVABILITY_CATALOGUE,
  DEFAULT_OBSERVABILITY_PROVIDER,
  observabilityProvider,
  observabilityProviderLabel,
  observabilityAdapter,
  observabilityCatalogueEntry,
  isSupportedObservabilityProvider,
  supportedObservabilityProviders,
  plannedObservabilityProviders,
  // --- contract ------------------------------------------------------------
  PROVIDER_STATUS,
  CAPABILITY,
  DECLARED_STATE,
  RESOLVED_STATE,
  METRIC_REASON,
  SECTION_KIND,
  resolveCapabilities,
  visibleSections,
  buildInfrastructureModel,
  unavailableMetric,
  unknownInventory,
  // --- compatibility -------------------------------------------------------
  PROMETHEUS_STATUS,
  buildPrometheusStatus,
  fetchPrometheusStatus,
  normalizePrometheusUrl: (value) => normalizeIntegrationUrl(value, 'Prometheus'),
  firstVectorValue,
  valuesByInstance,
  valuesByFilesystem,
  pairedFilesystems,
  selectHost: selectEntity,
  targetsFrom,
  unknownTargets,
  secondsAgo,
  displaySecondsAgo
};
