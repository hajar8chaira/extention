'use strict';

/**
 * The Security Delivery registry.
 *
 * Security Delivery is a *domain*, not a Jenkins feature. This file merges the
 * catalogue with whatever adapters exist and answers three questions for every
 * surface: which providers exist, which one can actually be talked to, and what
 * the selected one declares. It contains no endpoint, no credential and no
 * vendor vocabulary — those live inside adapters.
 */

const {
  PROVIDER_STATUS, CAPABILITY, CAPABILITIES, DECLARED_STATE, RESOLVED_STATE,
  RUN_OUTCOME, RUN_OUTCOME_LABELS, SECTION_KIND, FIELD_TYPE, CONFIG_GROUP,
  fieldsInGroup, assertDeliveryAdapter, normalizeCapabilities, visibleSections,
  buildDeliveryModel, notConfiguredModel
} = require('./delivery-contract');
const { jenkinsDeliveryAdapter } = require('./delivery-jenkins');
const { DELIVERY_CATALOGUE, deliveryCatalogueEntry } = require('./delivery-catalogue');

const ADAPTERS = Object.freeze([jenkinsDeliveryAdapter].map(assertDeliveryAdapter));

/**
 * Implementation state, kept internal.
 *
 * `SUPPORTED` means an adapter exists and can really be queried. `PLANNED`
 * means the platform is part of the product but nothing can connect to it yet —
 * it has no adapter, and therefore no configuration schema and no capabilities.
 */
const DELIVERY_PROVIDER_STATUS = Object.freeze({ SUPPORTED: 'supported', PLANNED: 'planned' });

const DELIVERY_PROVIDERS = Object.freeze(DELIVERY_CATALOGUE.map((entry) => {
  const adapter = ADAPTERS.find((candidate) => candidate.id === entry.id) || null;
  // Only an adapter can describe a connection or a capability. Without one both
  // are empty: no schema means the surface cannot draw a form, which is exactly
  // the intent — a form for an unimplemented provider would be a lie with a
  // Save button.
  const configurationFields = Object.freeze([...(adapter?.configurationFields || [])]);
  return Object.freeze({
    id: entry.id,
    label: adapter?.label || entry.label,
    icon: adapter?.icon || entry.icon || '',
    summary: adapter?.summary || entry.summary || '',
    status: adapter ? DELIVERY_PROVIDER_STATUS.SUPPORTED : DELIVERY_PROVIDER_STATUS.PLANNED,
    implemented: Boolean(adapter),
    configurationFields,
    configuredBy: configurationFields.map((field) => field.id),
    secretFields: configurationFields.filter((field) => field.secret).map((field) => field.id),
    capabilities: normalizeCapabilities(adapter),
    sections: visibleSections(adapter)
  });
}));

const DEFAULT_DELIVERY_PROVIDER = 'jenkins';

/** Message shown for a catalogued platform nothing can connect to yet. */
const UNIMPLEMENTED_PROVIDER_MESSAGE =
  'Ce fournisseur est référencé mais aucun adaptateur n’est encore disponible.';

/** The adapter behind a provider id, or null when nothing implements it. */
function deliveryAdapter(id) {
  return ADAPTERS.find((adapter) => adapter.id === String(id || '').toLowerCase()) || null;
}

function deliveryProvider(id) {
  return DELIVERY_PROVIDERS.find((provider) => provider.id === String(id || '').toLowerCase()) || null;
}

/** A provider Security Center can really query right now. */
function isSupportedDeliveryProvider(id) {
  return deliveryProvider(id)?.status === DELIVERY_PROVIDER_STATUS.SUPPORTED;
}

function supportedDeliveryProviders() {
  return DELIVERY_PROVIDERS.filter((provider) => provider.implemented);
}

/**
 * The configuration schema of a provider.
 *
 * Empty for a catalogue-only provider, on purpose: the surface must have
 * nothing to render a form from, rather than rendering an inert one.
 */
function deliveryConfigurationFields(id) {
  return deliveryProvider(id)?.configurationFields || [];
}

function validateDeliveryConfiguration(id, configuration = {}) {
  const adapter = deliveryAdapter(id);
  if (!adapter) return { valid: false, errors: [UNIMPLEMENTED_PROVIDER_MESSAGE] };
  return adapter.validateConfiguration(configuration);
}

async function testDeliveryConnection(id, configuration = {}, options = {}) {
  const adapter = deliveryAdapter(id);
  if (!adapter) {
    return { status: PROVIDER_STATUS.NOT_CONFIGURED, connected: false, message: UNIMPLEMENTED_PROVIDER_MESSAGE };
  }
  return adapter.testConnection(configuration, options);
}

/**
 * Reads the delivery state of the selected provider.
 *
 * Every failure mode returns a model rather than throwing, so one unreachable
 * CI server degrades its own page and nothing else.
 */
async function fetchDeliveryModel(id, configuration = {}, options = {}) {
  const provider = deliveryProvider(id);
  if (!provider) {
    return notConfiguredModel({ providerId: String(id || ''), message: 'Fournisseur de livraison inconnu.' });
  }
  if (!provider.implemented) {
    return notConfiguredModel({
      providerId: provider.id,
      providerLabel: provider.label,
      providerIcon: provider.icon,
      message: UNIMPLEMENTED_PROVIDER_MESSAGE
    });
  }
  try {
    return await deliveryAdapter(provider.id).fetchDelivery(configuration, options);
  } catch (error) {
    return buildDeliveryModel({
      providerId: provider.id,
      providerLabel: provider.label,
      providerIcon: provider.icon,
      status: PROVIDER_STATUS.ERROR,
      message: String(error?.message || 'Lecture de la livraison impossible.'),
      sections: provider.sections
    });
  }
}

/** The provider's own console URL, when its adapter can build one. */
function deliveryConsoleUrl(id, configuration = {}) {
  const adapter = deliveryAdapter(id);
  return typeof adapter?.consoleUrl === 'function' ? adapter.consoleUrl(configuration) : '';
}

module.exports = {
  DELIVERY_PROVIDERS,
  DELIVERY_PROVIDER_STATUS,
  DEFAULT_DELIVERY_PROVIDER,
  UNIMPLEMENTED_PROVIDER_MESSAGE,
  PROVIDER_STATUS,
  CAPABILITY,
  CAPABILITIES,
  DECLARED_STATE,
  RESOLVED_STATE,
  RUN_OUTCOME,
  RUN_OUTCOME_LABELS,
  SECTION_KIND,
  FIELD_TYPE,
  CONFIG_GROUP,
  fieldsInGroup,
  deliveryAdapter,
  deliveryProvider,
  deliveryCatalogueEntry,
  isSupportedDeliveryProvider,
  supportedDeliveryProviders,
  deliveryConfigurationFields,
  validateDeliveryConfiguration,
  testDeliveryConnection,
  fetchDeliveryModel,
  deliveryConsoleUrl,
  notConfiguredModel
};
