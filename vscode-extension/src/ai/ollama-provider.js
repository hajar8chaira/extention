const { redactOutgoingMessages } = require('./secret-redaction');

const RESPONSE_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: { oldText: { type: 'string' }, newText: { type: 'string' }, summary: { type: 'string' }, securityReason: { type: 'string' }, confidence: { type: 'number' }, assumptions: { type: 'array', items: { type: 'string' } }, tests: { type: 'array', items: { type: 'string' } } },
  required: ['oldText', 'newText', 'summary', 'securityReason', 'confidence', 'assumptions', 'tests']
};

function localOllamaUrl(value = 'http://127.0.0.1:11434') {
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) throw new Error('Security Center accepte uniquement Ollama local.');
  return url;
}

function selectFixModel(configuredModel, availableModels, context) {
  const start = Number(context?.finding?.startLine || 0);
  const end = Number(context?.finding?.endLine ?? start);
  const simple = Math.max(1, end - start + 1) <= 1 && String(context?.excerpt || '').length <= 4000;
  const lightModel = (availableModels || []).find((name) => /qwen2\.5-coder:7b/i.test(name));
  return simple && lightModel ? lightModel : configuredModel;
}

function fixPrompt(context) {
  return `Tu corriges uniquement le finding indiqué avec le changement minimal. Retourne uniquement le JSON conforme au schéma. oldText doit être une copie caractère pour caractère du plus petit fragment vulnérable présent dans l'extrait. newText est son remplacement sécurisé. Maximum 20 lignes chacun. Tu ne dois JAMAIS fournir un exemple d'attaque, un payload d'exploitation ou conserver la vulnérabilité. Pour une injection SQL, utilise une requête paramétrée avec placeholder et paramètres séparés. Les préfixes numériques "1: ", "2: ", etc. servent seulement à repérer les lignes : ne les inclus jamais dans oldText ou newText. Ne modifie aucun autre comportement, n'ajoute aucune dépendance ou valeur secrète par défaut, ne propose aucune commande shell et ne change pas les tests pour masquer l'alerte.\n\nFinding:\n${JSON.stringify(context.finding)}\nFichier autorisé: ${context.file}\nExtrait numéroté (${context.excerptStartLine}-${context.excerptEndLine}):\n${context.excerpt}`;
}

function repairPrompt(context, rejectedProposal, validationError) {
  return `La proposition suivante a été refusée: ${validationError}. Retourne oldText comme copie exacte et minimale du code source à remplacer, puis newText comme correction réellement sécurisée. Maximum 20 lignes. Ne retourne aucun payload d'attaque. Pour SQL, emploie un placeholder et passe la valeur séparément. Les numéros suivis de deux-points ne font pas partie du code. N'invente pas d'autre correction.\n\nProposition refusée:\n${String(rejectedProposal).slice(0, 12000)}\n\nExtrait source de référence:\n${context.excerpt}`;
}

function parseModelJson(value) {
  const content = String(value || '').trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  try { return JSON.parse(content); } catch {
    const start = content.indexOf('{'); const end = content.lastIndexOf('}');
    if (start >= 0 && end > start) { try { return JSON.parse(content.slice(start, end + 1)); } catch { /* rejected below */ } }
    throw new Error('Ollama n’a pas retourné un JSON valide.');
  }
}

async function listOllamaModels(baseUrl, fetchImpl = fetch) {
  const response = await fetchImpl(new URL('/api/tags', localOllamaUrl(baseUrl)), { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`Ollama HTTP ${response.status}.`);
  const payload = await response.json();
  return (payload.models || []).map((item) => item.name || item.model).filter(Boolean);
}

async function chat({ baseUrl, model, messages, fetchImpl, timeoutMs, numPredict, signal }) {
  if (!model) throw new Error('Aucun modèle Ollama sélectionné.');
  const requestSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
  // The final secret boundary. Every prompt reaches the model through this one
  // call, so sanitising here covers paths that do not exist yet as well as the
  // two that do — and it holds even if an earlier layer is skipped or a future
  // prompt builder forgets to sanitise its own inputs.
  const safeMessages = redactOutgoingMessages(messages);
  const response = await fetchImpl(new URL('/api/chat', localOllamaUrl(baseUrl)), {
    method: 'POST', headers: { 'content-type': 'application/json' }, signal: requestSignal,
    body: JSON.stringify({ model, stream: false, format: RESPONSE_SCHEMA, keep_alive: '10m', options: { temperature: 0, num_ctx: 4096, num_predict: numPredict }, messages: safeMessages })
  });
  if (!response.ok) throw new Error(`Ollama HTTP ${response.status} — ${(await response.text()).slice(0, 300)}`);
  const payload = await response.json();
  const result = parseModelJson(payload.message?.content || '');
  if (typeof result.oldText !== 'string' || typeof result.newText !== 'string' || typeof result.summary !== 'string' || typeof result.securityReason !== 'string' || typeof result.confidence !== 'number' || !Array.isArray(result.assumptions) || !Array.isArray(result.tests)) throw new Error('Réponse Ollama incomplète.');
  result.confidence = Math.max(0, Math.min(1, result.confidence));
  return { ...result, model: payload.model || model, metrics: { promptTokens: payload.prompt_eval_count || 0, outputTokens: payload.eval_count || 0 } };
}

async function generateOllamaFix({ baseUrl, model, context, fetchImpl = fetch, timeoutMs = 120000, signal }) {
  return chat({ baseUrl, model, fetchImpl, timeoutMs, numPredict: 550, signal, messages: [
    { role: 'system', content: context.finding?.tool === 'Gitleaks'
      ? 'Tu corriges un secret masqué. oldText doit être exactement la ligne contenant [REDACTED]. newText doit supprimer cette entrée ou la remplacer par une référence de configuration sans secret. newText ne doit jamais contenir [REDACTED]. Retourne uniquement le JSON demandé.'
      : 'Tu es un moteur AppSec. Tu proposes un remplacement minimal, jamais une exécution.' },
    { role: 'user', content: fixPrompt(context) }
  ] });
}

async function repairOllamaFix({ baseUrl, model, context, rejectedPatch, validationError, fetchImpl = fetch, timeoutMs = 120000, signal }) {
  const result = await chat({ baseUrl, model, fetchImpl, timeoutMs, numPredict: 250, signal, messages: [
    { role: 'system', content: 'Tu normalises une correction AppSec refusée. Tu ne proposes aucune nouvelle modification.' },
    { role: 'user', content: repairPrompt(context, rejectedPatch, validationError) }
  ] });
  return { ...result, repaired: true };
}

module.exports = { RESPONSE_SCHEMA, localOllamaUrl, selectFixModel, fixPrompt, repairPrompt, parseModelJson, listOllamaModels, generateOllamaFix, repairOllamaFix };
