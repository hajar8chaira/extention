'use strict';

/**
 * Provider-neutral configuration persistence, for any integration domain.
 *
 * This is the mechanism that Runtime Security proved out, lifted so that
 * Infrastructure can use the same one instead of growing a second copy. It is
 * genuinely domain-agnostic: it knows about *providers*, *fields*, *secrets*
 * and *which provider is active*, and nothing whatsoever about alerts, hosts,
 * metrics or any vendor.
 *
 * Three things stay separated, because conflating them is what makes a
 * single-provider design impossible to extend:
 *
 *   - which provider is *active*  → an explicit setting, never inferred
 *   - each provider's own config  → namespaced, kept even when inactive
 *   - each provider's secrets     → namespaced, only ever in SecretStorage
 *
 * "Never inferred" is the important one. Guessing the active provider from
 * whichever configuration happens to exist works with one provider and silently
 * picks the wrong source the moment there are two.
 *
 * A domain supplies its own storage keys and, optionally, a `legacy` descriptor
 * describing where that domain used to keep a single provider's settings. Those
 * legacy keys are read so existing installations keep working; they are never
 * written and never deleted.
 *
 * The VS Code APIs are injected rather than imported, which is what lets the
 * whole switching/persistence contract be tested without an editor.
 */

const { FIELD_TYPE, toBooleanValue } = require('./siem-contract');

function plainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

/**
 * @param {object} keys     `{ activeProvider, providersConfig, secretPrefix }`
 * @param {object} [legacy] `{ provider, fields: {fieldId: settingKey}, secrets: {secretId: secretKey} }`
 */
function createProviderConfigurationService({
  configuration, secrets, resolveAdapter, keys, legacy = null, domainLabel = 'provider'
}) {
  if (!configuration || !secrets || typeof resolveAdapter !== 'function' || !keys) {
    throw new Error(`Service de configuration ${domainLabel} incomplet.`);
  }
  const { activeProvider: ACTIVE_PROVIDER_KEY, providersConfig: PROVIDERS_CONFIG_KEY, secretPrefix: SECRET_PREFIX } = keys;
  const legacyFields = plainObject(legacy?.fields);
  const legacySecrets = plainObject(legacy?.secrets);

  /** `<secretPrefix>.<provider>.<secret>` */
  const secretKeyFor = (providerId, secretId) => `${SECRET_PREFIX}.${String(providerId)}.${String(secretId)}`;

  const allProviderConfigs = () => plainObject(configuration.get(PROVIDERS_CONFIG_KEY, {}));

  /** True when the pre-provider-layer settings of this domain are present. */
  function hasLegacyConfiguration() {
    return Object.values(legacyFields).some((key) => String(configuration.get(key, '') || '').trim());
  }

  /**
   * The active provider.
   *
   * Explicit setting first. The legacy fallback exists for exactly one case: an
   * installation configured before this layer existed, which has the old
   * settings and no active-provider setting. An unknown or unimplemented id
   * resolves to nothing rather than to a guess.
   */
  function getActiveProviderId() {
    const declared = String(configuration.get(ACTIVE_PROVIDER_KEY, '') || '').trim().toLowerCase();
    if (declared) return resolveAdapter(declared) ? declared : '';
    if (legacy?.provider && hasLegacyConfiguration() && resolveAdapter(legacy.provider)) return legacy.provider;
    return '';
  }

  /**
   * One provider's non-secret configuration.
   *
   * For the legacy provider the namespaced values win, and the old keys fill in
   * whatever they do not define — so a half-migrated workspace still resolves.
   */
  function getProviderConfig(providerId) {
    const id = String(providerId || '').toLowerCase();
    if (!resolveAdapter(id)) return {};
    const stored = plainObject(allProviderConfigs()[id]);
    if (!legacy || id !== legacy.provider) return { ...stored };
    const inherited = {};
    for (const [fieldId, settingKey] of Object.entries(legacyFields)) {
      const value = String(configuration.get(settingKey, '') || '').trim();
      if (value) inherited[fieldId] = value;
    }
    return { ...inherited, ...stored };
  }

  /** Secrets for one provider, read from its declared secret fields only. */
  async function getProviderSecrets(providerId) {
    const adapter = resolveAdapter(providerId);
    if (!adapter) return {};
    const result = {};
    for (const field of adapter.configurationFields.filter((item) => item.secret)) {
      let value = await secrets.get(secretKeyFor(adapter.id, field.id)) || '';
      // Legacy secret, still honoured. Never rewritten behind the user's back:
      // a save writes the namespaced key and the old one simply stops being
      // consulted once that exists.
      if (!value && legacy && adapter.id === legacy.provider && legacySecrets[field.id]) {
        value = await secrets.get(legacySecrets[field.id]) || '';
      }
      if (value) result[field.id] = value;
    }
    return result;
  }

  /** Which secrets exist, without ever revealing them. Safe for a webview. */
  async function describeProviderSecrets(providerId) {
    const adapter = resolveAdapter(providerId);
    if (!adapter) return {};
    const stored = await getProviderSecrets(providerId);
    return Object.fromEntries(
      adapter.configurationFields.filter((field) => field.secret)
        .map((field) => [field.id, Boolean(stored[field.id])])
    );
  }

  async function setActiveProvider(providerId) {
    const id = String(providerId || '').toLowerCase();
    if (id && !resolveAdapter(id)) throw new Error(`Fournisseur inconnu : ${id}.`);
    await configuration.update(ACTIVE_PROVIDER_KEY, id);
    return id;
  }

  /**
   * Saves one provider, then activates it — in that order.
   *
   * Activating first would leave the domain pointing at a provider whose
   * configuration was rejected. Other providers' stored configuration is merged
   * forward untouched, which is what makes switching back free.
   */
  async function saveProviderConfiguration(providerId, values = {}, { activate = true } = {}) {
    const adapter = resolveAdapter(providerId);
    if (!adapter) return { ok: false, errors: [`Fournisseur inconnu : ${providerId}.`] };

    const publicFields = adapter.configurationFields.filter((field) => !field.secret);
    const secretFields = adapter.configurationFields.filter((field) => field.secret);
    const existing = getProviderConfig(adapter.id);

    const publicConfig = {};
    for (const field of publicFields) {
      const provided = values[field.id];
      // A boolean always states itself. « Empty means keep the stored value »
      // is a rule that belongs to secrets: applied to a checkbox it would make
      // unticking impossible, so an explicit `false` is stored as `false`.
      if (field.type === FIELD_TYPE.BOOLEAN) {
        if (provided !== undefined) publicConfig[field.id] = toBooleanValue(provided);
        else if (existing[field.id] !== undefined) publicConfig[field.id] = Boolean(existing[field.id]);
        continue;
      }
      const resolved = provided === undefined || provided === null || String(provided).trim() === ''
        ? String(existing[field.id] ?? '')
        : String(provided).trim();
      // An optional field left blank is simply absent, not stored as an empty
      // string: the persisted configuration should describe what was actually
      // configured rather than list every field a provider could accept.
      if (!resolved && !field.required) continue;
      publicConfig[field.id] = resolved;
    }

    // An empty secret input means « keep the stored one », never « erase it ».
    const storedSecrets = await getProviderSecrets(adapter.id);
    const effectiveSecrets = { ...storedSecrets };
    for (const field of secretFields) {
      const provided = values[field.id];
      if (provided !== undefined && String(provided) !== '') effectiveSecrets[field.id] = String(provided);
    }

    const validation = adapter.validateConfiguration(publicConfig);
    if (!validation.valid) return { ok: false, errors: validation.errors };
    const missingSecret = secretFields.find((field) => field.required && !effectiveSecrets[field.id]);
    if (missingSecret) return { ok: false, errors: [`${missingSecret.label} est requis.`] };

    // Persisting can genuinely fail — an unregistered settings key, a read-only
    // workspace. Thrown from here it would reject inside a webview message
    // handler and vanish, leaving a form that looks like it did nothing. A save
    // that did not save says so, and nothing after it runs.
    try {
      await configuration.update(PROVIDERS_CONFIG_KEY, { ...allProviderConfigs(), [adapter.id]: publicConfig });
    } catch (error) {
      return { ok: false, errors: [`Configuration ${adapter.label || adapter.id} non enregistree : ${error?.message || 'ecriture refusee'}`] };
    }
    for (const field of secretFields) {
      if (values[field.id] !== undefined && String(values[field.id]) !== '') {
        await secrets.store(secretKeyFor(adapter.id, field.id), String(values[field.id]));
      }
    }
    if (activate) await setActiveProvider(adapter.id);
    return { ok: true, providerId: adapter.id, config: publicConfig };
  }

  /**
   * Disconnect clears the *selection*, not the configuration.
   *
   * Reconnecting must not mean retyping an endpoint. Deleting credentials is a
   * separate, explicit action — conflating the two would make an « unplug » look
   * reversible while quietly destroying stored secrets.
   */
  async function disconnect() {
    await configuration.update(ACTIVE_PROVIDER_KEY, '');
    return { ok: true, cleared: 'active-provider' };
  }

  /** Explicit, opt-in credential removal for one provider. */
  async function forgetProviderSecrets(providerId) {
    const adapter = resolveAdapter(providerId);
    if (!adapter) return { ok: false, errors: [`Fournisseur inconnu : ${providerId}.`] };
    for (const field of adapter.configurationFields.filter((item) => item.secret)) {
      await secrets.delete(secretKeyFor(adapter.id, field.id));
    }
    return { ok: true, providerId: adapter.id };
  }

  /** Everything the active provider needs to be queried, in one read. */
  async function resolveActiveProvider() {
    const id = getActiveProviderId();
    if (!id) return { providerId: '', adapter: null, config: {}, secrets: {} };
    const adapter = resolveAdapter(id);
    return { providerId: id, adapter, config: getProviderConfig(id), secrets: await getProviderSecrets(id) };
  }

  return {
    ACTIVE_PROVIDER_KEY,
    PROVIDERS_CONFIG_KEY,
    secretKeyFor,
    hasLegacyConfiguration,
    getActiveProviderId,
    getProviderConfig,
    getProviderSecrets,
    describeProviderSecrets,
    setActiveProvider,
    saveProviderConfiguration,
    disconnect,
    forgetProviderSecrets,
    resolveActiveProvider
  };
}

module.exports = { createProviderConfigurationService };
