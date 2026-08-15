function findInstalledModel(configuredModel, installedModels = []) {
  const expected = String(configuredModel || '').trim();
  if (!expected) return { installed: false, model: '', reason: 'not_configured' };
  const model = installedModels.find((name) => String(name).toLowerCase() === expected.toLowerCase());
  return model
    ? { installed: true, model, reason: 'installed' }
    : { installed: false, model: expected, reason: 'not_installed' };
}

module.exports = { findInstalledModel };
