const { REMEDIATION_STATES, remediationResult, safeFallbackReason } = require('./remediation-result');
const { findInstalledModel } = require('./model-discovery');

const FALLBACK_STATES = new Set([REMEDIATION_STATES.INVALID, REMEDIATION_STATES.AMBIGUOUS, REMEDIATION_STATES.UNSAFE, REMEDIATION_STATES.NO_CHANGE, REMEDIATION_STATES.PARSE_ERROR]);

async function attemptModel({ role, model, context, generate, validate, onState }) {
  const startedAt = Date.now();
  onState?.({ phase: 'generating', role, model });
  try {
    const generated = await generate({ role, model, context });
    const validated = await validate(generated, { role, model });
    const classification = remediationResult({ parsed: validated.parsed, model, role });
    onState?.({ phase: 'validated', ...classification });
    return { ok: true, role, model, generated: validated.generated || generated, parsed: validated.parsed, classification, durationMs: Date.now() - startedAt };
  } catch (error) {
    const classification = remediationResult({ error, model, role });
    onState?.({ phase: 'rejected', ...classification });
    return { ok: false, role, model, error, classification, durationMs: Date.now() - startedAt };
  }
}

async function runTwoModelRemediation({ configuration, installedModels, context, generate, validate, onState }) {
  const fast = findInstalledModel(configuration.models.fast, installedModels);
  if (!fast.installed) return { ok: false, reason: fast.reason, missingRole: 'fast', model: fast.model, attempts: [] };
  const attempts = [];
  const fastAttempt = await attemptModel({ role: 'fast', model: fast.model, context, generate, validate, onState });
  attempts.push(fastAttempt);
  if (fastAttempt.ok) return { ...fastAttempt, fallbackUsed: false, attempts };
  const advanced = findInstalledModel(configuration.models.advanced, installedModels);
  const fallbackEligible = FALLBACK_STATES.has(fastAttempt.classification.state);
  const eligible = configuration.fallbackToAdvanced && fallbackEligible && advanced.installed && advanced.model !== fast.model;
  const fallbackReason = safeFallbackReason(fastAttempt.classification.state);
  if (!eligible) return { ...fastAttempt, fallbackUsed: false, fallbackEligible, fallbackReason, missingRole: !advanced.installed ? 'advanced' : undefined, attempts };
  onState?.({ phase: 'fallback', from: 'fast', to: 'advanced', reason: fallbackReason });
  const advancedAttempt = await attemptModel({ role: 'advanced', model: advanced.model, context, generate, validate, onState });
  attempts.push(advancedAttempt);
  return { ...advancedAttempt, fallbackUsed: true, fallbackReason, attempts, fastFailure: fastAttempt.classification };
}

async function runAdvancedRemediation({ configuration, installedModels, context, generate, validate, onState }) {
  const advanced = findInstalledModel(configuration.models.advanced, installedModels);
  if (!advanced.installed) return { ok: false, reason: advanced.reason, missingRole: 'advanced', model: advanced.model, attempts: [] };
  const attempt = await attemptModel({ role: 'advanced', model: advanced.model, context, generate, validate, onState });
  return { ...attempt, fallbackUsed: true, manualAdvanced: true, attempts: [attempt] };
}

module.exports = { FALLBACK_STATES, attemptModel, runTwoModelRemediation, runAdvancedRemediation };
