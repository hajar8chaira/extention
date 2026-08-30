'use strict';

/**
 * Runtime Security configuration.
 *
 * The persistence mechanism itself is domain-agnostic and now lives in
 * `provider-configuration.js`, where Infrastructure uses the same one. What
 * stays here is what is genuinely Runtime Security's: its storage keys, and the
 * legacy Wazuh settings that must keep resolving for installations configured
 * before the provider layer existed.
 *
 * The public surface is unchanged — `createSiemConfigurationService` returns
 * exactly what it always did, including `hasLegacyWazuhConfiguration`.
 */

const { createProviderConfigurationService } = require('./provider-configuration');

const ACTIVE_PROVIDER_KEY = 'runtimeSecurity.provider';
const PROVIDERS_CONFIG_KEY = 'runtimeSecurity.providers';
const SECRET_PREFIX = 'securityCenter.runtimeSecurity';

/**
 * Legacy Wazuh keys, still read so existing installations keep working without
 * being asked to reconfigure anything. They are never written and never deleted.
 */
const LEGACY_WAZUH = Object.freeze({
  provider: 'wazuh',
  url: 'wazuh.url',
  username: 'wazuh.username',
  secretKey: 'securityCenter.wazuh.password',
  secretId: 'password'
});

/** `securityCenter.runtimeSecurity.<provider>.<secret>` */
function secretKeyFor(providerId, secretId) {
  return `${SECRET_PREFIX}.${String(providerId)}.${String(secretId)}`;
}

function createSiemConfigurationService({ configuration, secrets, resolveAdapter }) {
  if (!configuration || !secrets || typeof resolveAdapter !== 'function') {
    throw new Error('Service de configuration SIEM incomplet.');
  }
  const service = createProviderConfigurationService({
    configuration,
    secrets,
    resolveAdapter,
    domainLabel: 'SIEM',
    keys: {
      activeProvider: ACTIVE_PROVIDER_KEY,
      providersConfig: PROVIDERS_CONFIG_KEY,
      secretPrefix: SECRET_PREFIX
    },
    legacy: {
      provider: LEGACY_WAZUH.provider,
      fields: { url: LEGACY_WAZUH.url, username: LEGACY_WAZUH.username },
      secrets: { [LEGACY_WAZUH.secretId]: LEGACY_WAZUH.secretKey }
    }
  });
  // The name this domain has always exposed, kept so no caller changes.
  return { ...service, hasLegacyWazuhConfiguration: service.hasLegacyConfiguration };
}

module.exports = {
  ACTIVE_PROVIDER_KEY,
  PROVIDERS_CONFIG_KEY,
  SECRET_PREFIX,
  LEGACY_WAZUH,
  secretKeyFor,
  createSiemConfigurationService
};
