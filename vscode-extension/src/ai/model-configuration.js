const { readModelRoleConfiguration } = require('./model-roles');

function modelItems(models, selectedModel, role) {
  return models.map((name) => ({
    label: name,
    description: name === selectedModel
      ? 'Actuellement sélectionné'
      : role === 'fast'
        ? 'Utilisé en premier pour une remédiation plus rapide'
        : 'Utilisé pour les corrections complexes ou refusées'
  }));
}

async function configureModelRoles({ configuration, models, showQuickPick, update, configurationTarget }) {
  const current = readModelRoleConfiguration(configuration);
  const fast = await showQuickPick(modelItems(models, current.models.fast, 'fast'), {
    title: 'AI Remediation · Modèle Fast',
    placeHolder: 'Utilisé en premier pour une remédiation plus rapide'
  });
  if (!fast) return undefined;

  const advanced = await showQuickPick(modelItems(models, current.models.advanced, 'advanced'), {
    title: 'AI Remediation · Modèle Advanced',
    placeHolder: 'Utilisé pour les corrections complexes ou quand le modèle Fast est refusé'
  });
  if (!advanced) return undefined;

  const fallback = await showQuickPick([
    { label: 'Oui', value: true, description: 'Réessayer une seule fois avec le modèle Advanced après un refus de validation' },
    { label: 'Non', value: false, description: 'Ne jamais lancer automatiquement le modèle Advanced' }
  ], {
    title: 'AI Remediation · Fallback sécurisé',
    placeHolder: 'Security Center conserve la validation et la confirmation avant application'
  });
  if (!fallback) return undefined;

  await update('ai.models.fast', fast.label, configurationTarget);
  await update('ai.models.advanced', advanced.label, configurationTarget);
  await update('ai.fallbackToAdvanced', fallback.value, configurationTarget);
  return { provider: 'ollama', models: { fast: fast.label, advanced: advanced.label }, fallbackToAdvanced: fallback.value };
}

module.exports = { modelItems, configureModelRoles };
