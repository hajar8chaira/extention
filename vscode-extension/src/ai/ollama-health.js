'use strict';

/**
 * Ollama health and model discovery.
 *
 * Ollama is optional. Everything Security Center does without it — scanners, Live
 * Security, deterministic quick fixes, the policy gate — keeps working when it is
 * absent, so this module's only job is to say precisely *which* absence we are in.
 * « AI unavailable » is not a diagnosis; « the service answers but its model
 * directory is empty » is one the developer can act on.
 *
 * Two principles:
 *
 *   - Runtime truth comes from Ollama, never from configuration. A model named in
 *     settings is a preference; `/api/tags` is the fact. A configured model that
 *     is not installed is reported as missing, never assumed present.
 *
 *   - A health check never runs inference. Listing models is cheap and answers
 *     the question; generating tokens to find out whether a server exists would
 *     load gigabytes of weights for a status badge. Inference is probed only when
 *     the developer explicitly asks, and only then is a latency reported.
 */

const { localOllamaUrl } = require('./ollama-provider');

/** The states the UI must be able to tell apart. None of them is a guess. */
const OLLAMA_STATUS = Object.freeze({
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  OFFLINE: 'OFFLINE',
  UNREACHABLE: 'UNREACHABLE',
  NO_MODELS: 'NO_MODELS',
  MODEL_MISSING: 'MODEL_MISSING',
  READY: 'READY',
  ERROR: 'ERROR'
});

/**
 * Error taxonomy.
 *
 * A raw transport message is never shown to a developer: `ECONNREFUSED` and a
 * truncated HTML body say nothing actionable, and an inference error body can
 * echo model output. Each code carries a sentence that names the next step.
 */
const OLLAMA_ERROR = Object.freeze({
  OLLAMA_OFFLINE: 'OLLAMA_OFFLINE',
  MODEL_NOT_FOUND: 'MODEL_NOT_FOUND',
  NO_MODELS: 'NO_MODELS',
  TIMEOUT: 'TIMEOUT',
  CANCELLED: 'CANCELLED',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  INFERENCE_ERROR: 'INFERENCE_ERROR'
});

const ERROR_MESSAGES = Object.freeze({
  OLLAMA_OFFLINE: 'Ollama ne répond pas. Démarrez le service Ollama puis réessayez.',
  MODEL_NOT_FOUND: 'Le modèle sélectionné n’est pas installé dans Ollama.',
  NO_MODELS: 'Ollama fonctionne, mais aucun modèle n’est disponible.',
  TIMEOUT: 'Ollama n’a pas répondu dans le délai imparti. Un modèle volumineux peut mettre du temps au premier chargement.',
  CANCELLED: 'Requête annulée.',
  INVALID_RESPONSE: 'Ollama a renvoyé une réponse inexploitable.',
  INFERENCE_ERROR: 'L’inférence Ollama a échoué.'
});

/**
 * Preferred model per role, in order.
 *
 * These are preferences, not requirements: a workspace with other code models
 * must still work. The order matters — the first *installed* entry wins, and when
 * none is installed the fallback is explicit rather than silent.
 */
const ROLE_PREFERENCES = Object.freeze({
  fast: ['qwen2.5-coder:3b', 'qwen2.5-coder:7b', 'qwen2.5-coder:14b'],
  standard: ['qwen2.5-coder:7b', 'qwen2.5-coder:14b', 'qwen2.5-coder:3b'],
  advanced: ['qwen2.5-coder:14b', 'qwen2.5-coder:7b', 'qwen2.5-coder:3b']
});

/** Families Security Center knows how to prompt for code remediation. */
const CODE_MODEL_HINT = /coder|code|deepseek|starcoder|codellama|qwen|granite/i;

/**
 * Normalizes `/api/tags`.
 *
 * Keeps the metadata a developer needs to choose — size, parameter count,
 * quantization — and drops everything else. The digest is deliberately not
 * exposed: it identifies nothing the UI needs and only adds noise.
 */
function normalizeModels(payload) {
  const models = Array.isArray(payload?.models) ? payload.models : [];
  return models
    .map((item) => {
      const name = String(item?.name || item?.model || '').trim();
      if (!name) return null;
      const bytes = Number(item?.size);
      return {
        name,
        sizeBytes: Number.isFinite(bytes) && bytes > 0 ? bytes : null,
        parameterSize: item?.details?.parameter_size ? String(item.details.parameter_size) : null,
        quantization: item?.details?.quantization_level ? String(item.details.quantization_level) : null,
        family: item?.details?.family ? String(item.details.family) : null,
        modifiedAt: item?.modified_at ? String(item.modified_at) : null,
        // A hint, not a verdict: an unrecognised model is still selectable.
        codeCapable: CODE_MODEL_HINT.test(name)
      };
    })
    .filter(Boolean)
    .sort((left, right) => left.name.localeCompare(right.name));
}

/**
 * Maps a thrown error to a code and a safe sentence.
 *
 * The original message is kept only when it is already safe — our own validation
 * errors — and is never taken from an HTTP body.
 */
function classifyOllamaError(error) {
  const raw = String(error?.message || error || '');
  const name = String(error?.name || '');
  if (name === 'AbortError' && /cancel/i.test(raw)) return code(OLLAMA_ERROR.CANCELLED);
  if (name === 'TimeoutError' || /timed?\s*out|timeout|délai/i.test(raw)) return code(OLLAMA_ERROR.TIMEOUT);
  if (name === 'AbortError') return code(OLLAMA_ERROR.CANCELLED);
  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|fetch failed|socket hang up|ECONNRESET/i.test(raw)) {
    return code(OLLAMA_ERROR.OLLAMA_OFFLINE);
  }
  if (/HTTP 404/.test(raw) || /model .*not found|no such model/i.test(raw)) return code(OLLAMA_ERROR.MODEL_NOT_FOUND);
  if (/aucun modèle/i.test(raw)) return code(OLLAMA_ERROR.NO_MODELS);
  if (/JSON|inexploitable|schéma|parse/i.test(raw)) return code(OLLAMA_ERROR.INVALID_RESPONSE);
  if (/uniquement Ollama local/i.test(raw)) {
    // Our own guard rail, and its message is already actionable.
    return { code: OLLAMA_ERROR.INFERENCE_ERROR, message: raw };
  }
  return code(OLLAMA_ERROR.INFERENCE_ERROR);
}

function code(value) {
  return { code: value, message: ERROR_MESSAGES[value] };
}

/**
 * Health of the local Ollama installation.
 *
 * Never runs inference. Returns a complete state whatever happens: a failure is
 * a status, not an exception, because the caller is a status badge.
 */
async function checkOllamaHealth({
  baseUrl = 'http://127.0.0.1:11434', configuredModel = '', fetchImpl = fetch, timeoutMs = 5000
} = {}) {
  const base = { baseUrl: String(baseUrl), configuredModel: String(configuredModel || ''), models: [], installedModels: [] };
  let url;
  try {
    url = localOllamaUrl(baseUrl);
  } catch (error) {
    return { ...base, status: OLLAMA_STATUS.ERROR, reachable: false, version: null, error: classifyOllamaError(error) };
  }
  let tags;
  let version = null;
  try {
    const response = await fetchImpl(new URL('/api/tags', url), { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) throw new Error(`Ollama HTTP ${response.status}.`);
    tags = await response.json();
  } catch (error) {
    const classified = classifyOllamaError(error);
    return {
      ...base,
      status: classified.code === OLLAMA_ERROR.TIMEOUT ? OLLAMA_STATUS.UNREACHABLE : OLLAMA_STATUS.OFFLINE,
      reachable: false, version: null, error: classified
    };
  }
  // The version is a nicety: its absence must never degrade the status.
  try {
    const response = await fetchImpl(new URL('/api/version', url), { signal: AbortSignal.timeout(timeoutMs) });
    if (response.ok) version = String((await response.json())?.version || '') || null;
  } catch { /* an older Ollama may not expose it */ }

  const models = normalizeModels(tags);
  const installedModels = models.map((model) => model.name);
  const configured = findConfiguredModel(configuredModel, installedModels);
  const status = !models.length ? OLLAMA_STATUS.NO_MODELS
    : !configuredModel ? OLLAMA_STATUS.NOT_CONFIGURED
      : configured.installed ? OLLAMA_STATUS.READY : OLLAMA_STATUS.MODEL_MISSING;
  return {
    ...base,
    status,
    reachable: true,
    version,
    models,
    installedModels,
    configuredModelAvailable: configured.installed,
    // `NO_MODELS` is the one reachable state that still carries an error code:
    // the service is fine, the installation is not.
    error: status === OLLAMA_STATUS.NO_MODELS ? code(OLLAMA_ERROR.NO_MODELS)
      : status === OLLAMA_STATUS.MODEL_MISSING ? code(OLLAMA_ERROR.MODEL_NOT_FOUND) : null
  };
}

/** Whether the configured model really is installed. Case-insensitive by tag. */
function findConfiguredModel(configuredModel, installedModels = []) {
  const expected = String(configuredModel || '').trim();
  if (!expected) return { installed: false, model: '', reason: 'not_configured' };
  const match = installedModels.find((name) => String(name).toLowerCase() === expected.toLowerCase());
  return match ? { installed: true, model: match, reason: 'installed' } : { installed: false, model: expected, reason: 'not_installed' };
}

/**
 * The model to use for a role, and why.
 *
 * Deterministic and explicit. A configured model that is installed always wins —
 * the developer's choice is not second-guessed. Otherwise the role preference is
 * tried in order, then any code-capable model, then any model at all. Every
 * outcome names its `reason`, so the UI can say « replacement » instead of
 * silently using something else.
 */
function selectModelForRole(role, installedModels = [], configuredModel = '') {
  const installed = installedModels.map(String).filter(Boolean);
  if (!installed.length) return { model: '', reason: 'no_models', substituted: false };
  const configured = findConfiguredModel(configuredModel, installed);
  if (configured.installed) return { model: configured.model, reason: 'configured', substituted: false };

  const preferences = ROLE_PREFERENCES[role] || ROLE_PREFERENCES.standard;
  const preferred = preferences.find((candidate) => installed.some((name) => name.toLowerCase() === candidate.toLowerCase()));
  if (preferred) {
    const model = installed.find((name) => name.toLowerCase() === preferred.toLowerCase());
    return { model, reason: configuredModel ? 'preference_substituted' : 'preference', substituted: Boolean(configuredModel) };
  }
  const codeModel = installed.find((name) => CODE_MODEL_HINT.test(name));
  if (codeModel) return { model: codeModel, reason: 'code_model_substituted', substituted: true };
  // Last resort, and reported as such: the caller may prefer to ask the user.
  return { model: installed[0], reason: 'unrelated_substituted', substituted: true };
}

/**
 * A deliberate, tiny inference.
 *
 * Only ever called from an explicit « test the model » action. `num_predict: 1`
 * keeps it to a single token: enough to prove the model loads and answers, cheap
 * enough not to matter. The latency returned is real — measured around this call
 * — and is the only place a latency may be shown.
 */
async function probeInference({
  baseUrl = 'http://127.0.0.1:11434', model = '', fetchImpl = fetch, timeoutMs = 60000, signal, now = Date.now
} = {}) {
  if (!model) return { ok: false, latencyMs: null, error: code(OLLAMA_ERROR.MODEL_NOT_FOUND) };
  let url;
  try { url = localOllamaUrl(baseUrl); }
  catch (error) { return { ok: false, latencyMs: null, error: classifyOllamaError(error) }; }
  const startedAt = now();
  try {
    const requestSignal = signal
      ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
      : AbortSignal.timeout(timeoutMs);
    const response = await fetchImpl(new URL('/api/chat', url), {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: requestSignal,
      body: JSON.stringify({
        model, stream: false, keep_alive: '30s',
        options: { temperature: 0, num_predict: 1 },
        messages: [{ role: 'user', content: 'ok' }]
      })
    });
    if (response.status === 404) return { ok: false, latencyMs: null, error: code(OLLAMA_ERROR.MODEL_NOT_FOUND) };
    // The body is not read into the error: it can contain generated text.
    if (!response.ok) return { ok: false, latencyMs: null, error: code(OLLAMA_ERROR.INFERENCE_ERROR) };
    const payload = await response.json();
    const content = payload?.message?.content;
    if (typeof content !== 'string') return { ok: false, latencyMs: null, error: code(OLLAMA_ERROR.INVALID_RESPONSE) };
    return { ok: true, latencyMs: Math.max(0, now() - startedAt), error: null, model };
  } catch (error) {
    return { ok: false, latencyMs: null, error: classifyOllamaError(error) };
  }
}

/** Wording for each status, plus what the developer should do about it. */
const STATUS_PRESENTATION = Object.freeze({
  READY: { label: 'Prêt', hint: '' },
  NO_MODELS: { label: 'Aucun modèle', hint: 'Installez un modèle de code, par exemple : ollama pull qwen2.5-coder:7b' },
  MODEL_MISSING: { label: 'Modèle introuvable', hint: 'Sélectionnez un modèle installé, ou installez celui qui est configuré.' },
  NOT_CONFIGURED: { label: 'Non configuré', hint: 'Choisissez un modèle parmi ceux installés.' },
  OFFLINE: { label: 'Hors ligne', hint: 'Démarrez le service Ollama, puis actualisez.' },
  UNREACHABLE: { label: 'Injoignable', hint: 'Ollama ne répond pas dans le délai imparti.' },
  ERROR: { label: 'Erreur', hint: '' }
});

/**
 * The command that installs a model — as text, never executed.
 *
 * Downloading several gigabytes is the developer's decision, so Security Center
 * shows the exact command and stops there.
 */
function pullCommandFor(model = 'qwen2.5-coder:7b') {
  const safe = String(model).trim().replace(/[^\w.:@/-]/g, '');
  return `ollama pull ${safe || 'qwen2.5-coder:7b'}`;
}

module.exports = {
  OLLAMA_STATUS, OLLAMA_ERROR, ERROR_MESSAGES, ROLE_PREFERENCES, STATUS_PRESENTATION, CODE_MODEL_HINT,
  normalizeModels, classifyOllamaError, checkOllamaHealth, findConfiguredModel,
  selectModelForRole, probeInference, pullCommandFor
};
