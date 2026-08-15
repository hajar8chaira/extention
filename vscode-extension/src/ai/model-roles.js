const MODEL_ROLES = Object.freeze({ FAST: 'fast', ADVANCED: 'advanced' });

function configuredString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

// Resolve logical roles independently from the provider transport. The legacy
// single-model setting remains a compatibility fallback until roles are set.
function resolveModelRoles(configuration = {}) {
  const legacyModel = configuredString(configuration.legacyModel);
  const explicitFast = configuredString(configuration.fast);
  const explicitAdvanced = configuredString(configuration.advanced);
  return {
    provider: configuredString(configuration.provider) || 'ollama',
    models: { fast: explicitFast || legacyModel, advanced: explicitAdvanced || legacyModel },
    fallbackToAdvanced: configuration.fallbackToAdvanced !== false,
    migratedFromLegacy: Boolean(legacyModel) && !explicitFast && !explicitAdvanced
  };
}

function readModelRoleConfiguration(configuration) {
  return resolveModelRoles({
    provider: 'ollama',
    fast: configuration.get('ai.models.fast', ''),
    advanced: configuration.get('ai.models.advanced', ''),
    fallbackToAdvanced: configuration.get('ai.fallbackToAdvanced', true),
    legacyModel: configuration.get('ai.ollama.model', '')
  });
}

module.exports = { MODEL_ROLES, resolveModelRoles, readModelRoleConfiguration };
