const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  OLLAMA_STATUS, OLLAMA_ERROR, ROLE_PREFERENCES, STATUS_PRESENTATION,
  normalizeModels, classifyOllamaError, checkOllamaHealth, findConfiguredModel,
  selectModelForRole, probeInference, pullCommandFor
} = require('../src/ai/ollama-health');
const manifest = require('../package.json');

const BASE = 'http://127.0.0.1:11434';

/** A `/api/tags` payload shaped exactly as Ollama 0.32 returns it. */
const tagsPayload = (names = []) => ({
  models: names.map((name) => ({
    name, model: name, modified_at: '2026-08-13T11:55:29.184261+01:00',
    size: name.includes('14b') ? 8988124298 : name.includes('7b') ? 4700000000 : 1929912626,
    digest: 'f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225',
    details: { format: 'gguf', family: 'qwen2', parameter_size: name.includes('14b') ? '14.8B' : '3.1B', quantization_level: 'Q4_K_M' }
  }))
});

/** A fetch double. `tags` and `version` answer; anything else 404s. */
function fetchStub({ tags = null, version = '0.32.6', fail = null, chat = null, status = 200 } = {}) {
  return async (url) => {
    const target = String(url);
    if (fail) throw fail;
    if (target.endsWith('/api/version')) {
      return { ok: true, status: 200, json: async () => ({ version }) };
    }
    if (target.endsWith('/api/tags')) {
      if (status >= 400) return { ok: false, status, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => tags };
    }
    if (target.endsWith('/api/chat')) {
      if (chat?.throws) throw chat.throws;
      return { ok: chat?.status ? chat.status < 400 : true, status: chat?.status || 200, json: async () => chat?.payload ?? { message: { content: 'ok' } }, text: async () => 'body' };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

// ------------------------------------------------------- normalisation

test('les modèles sont normalisés avec les métadonnées utiles', () => {
  const models = normalizeModels(tagsPayload(['qwen2.5-coder:14b', 'qwen2.5-coder:3b']));
  assert.equal(models.length, 2);
  // Triés par nom, pour un affichage stable.
  assert.deepEqual(models.map((model) => model.name), ['qwen2.5-coder:14b', 'qwen2.5-coder:3b']);
  assert.equal(models[0].sizeBytes, 8988124298);
  assert.equal(models[0].parameterSize, '14.8B');
  assert.equal(models[0].quantization, 'Q4_K_M');
  assert.equal(models[0].family, 'qwen2');
  assert.equal(models[0].codeCapable, true);
  // Le digest n'a aucune utilité pour l'UI : il n'est pas exposé.
  assert.ok(!('digest' in models[0]));
});

test('une charge malformée ne produit aucun modèle inventé', () => {
  for (const payload of [null, undefined, {}, { models: null }, { models: 'x' }, { models: [{}] }, { models: [{ name: '' }] }]) {
    assert.deepEqual(normalizeModels(payload), [], JSON.stringify(payload));
  }
  // Une taille absurde reste nulle plutôt que d'être affichée.
  assert.equal(normalizeModels({ models: [{ name: 'a', size: -1 }] })[0].sizeBytes, null);
  assert.equal(normalizeModels({ models: [{ name: 'a', size: 'gros' }] })[0].sizeBytes, null);
});

// ------------------------------------------------- taxonomie d'erreurs

test('chaque échec est classé dans une catégorie actionnable', () => {
  const cases = [
    [new Error('connect ECONNREFUSED 127.0.0.1:11434'), OLLAMA_ERROR.OLLAMA_OFFLINE],
    [new Error('fetch failed'), OLLAMA_ERROR.OLLAMA_OFFLINE],
    [new Error('getaddrinfo ENOTFOUND localhost'), OLLAMA_ERROR.OLLAMA_OFFLINE],
    [Object.assign(new Error('The operation timed out'), { name: 'TimeoutError' }), OLLAMA_ERROR.TIMEOUT],
    [new Error('Ollama HTTP 404.'), OLLAMA_ERROR.MODEL_NOT_FOUND],
    [new Error('model "x" not found'), OLLAMA_ERROR.MODEL_NOT_FOUND],
    [new Error('Aucun modèle Ollama sélectionné.'), OLLAMA_ERROR.NO_MODELS],
    [new Error('Réponse JSON inexploitable'), OLLAMA_ERROR.INVALID_RESPONSE],
    [Object.assign(new Error('cancelled'), { name: 'AbortError' }), OLLAMA_ERROR.CANCELLED],
    [new Error('Ollama HTTP 500.'), OLLAMA_ERROR.INFERENCE_ERROR]
  ];
  for (const [error, expected] of cases) {
    const result = classifyOllamaError(error);
    assert.equal(result.code, expected, error.message);
    assert.ok(result.message && result.message.length > 10, 'chaque code a une phrase utile');
  }
});

test('aucune trace technique ne franchit la classification', () => {
  const hostile = new Error('Ollama HTTP 500 — <html><body>stack at /home/u/.ollama/x.go:42 token=abc123</body></html>');
  const result = classifyOllamaError(hostile);
  assert.equal(result.code, OLLAMA_ERROR.INFERENCE_ERROR);
  assert.ok(!result.message.includes('abc123'));
  assert.ok(!result.message.includes('.go:42'));
  assert.ok(!/<html|<body/.test(result.message));
});

test('le garde-rail « Ollama local uniquement » garde son message', () => {
  const result = classifyOllamaError(new Error('Security Center accepte uniquement Ollama local.'));
  assert.match(result.message, /uniquement Ollama local/);
});

// ------------------------------------------------------- états de santé

test('Ollama hors ligne est OFFLINE, sans exception', async () => {
  const health = await checkOllamaHealth({ baseUrl: BASE, fetchImpl: fetchStub({ fail: new Error('connect ECONNREFUSED') }) });
  assert.equal(health.status, OLLAMA_STATUS.OFFLINE);
  assert.equal(health.reachable, false);
  assert.equal(health.error.code, OLLAMA_ERROR.OLLAMA_OFFLINE);
  assert.deepEqual(health.models, []);
  assert.equal(health.version, null);
});

test('un dépassement de délai est UNREACHABLE, distinct de OFFLINE', async () => {
  const timeout = Object.assign(new Error('The operation timed out'), { name: 'TimeoutError' });
  const health = await checkOllamaHealth({ baseUrl: BASE, fetchImpl: fetchStub({ fail: timeout }) });
  assert.equal(health.status, OLLAMA_STATUS.UNREACHABLE);
  assert.equal(health.error.code, OLLAMA_ERROR.TIMEOUT);
});

test('joignable avec zéro modèle est NO_MODELS, jamais READY', async () => {
  const health = await checkOllamaHealth({ baseUrl: BASE, configuredModel: 'qwen2.5-coder:14b', fetchImpl: fetchStub({ tags: tagsPayload([]) }) });
  assert.equal(health.status, OLLAMA_STATUS.NO_MODELS);
  assert.equal(health.reachable, true, 'le service répond bel et bien');
  assert.equal(health.error.code, OLLAMA_ERROR.NO_MODELS);
  assert.match(health.error.message, /aucun modèle n’est disponible/);
  assert.notEqual(health.status, OLLAMA_STATUS.READY);
});

test('un seul modèle installé suffit à être READY s’il est celui configuré', async () => {
  const health = await checkOllamaHealth({
    baseUrl: BASE, configuredModel: 'qwen2.5-coder:7b', fetchImpl: fetchStub({ tags: tagsPayload(['qwen2.5-coder:7b']) })
  });
  assert.equal(health.status, OLLAMA_STATUS.READY);
  assert.equal(health.configuredModelAvailable, true);
  assert.equal(health.error, null);
  assert.equal(health.version, '0.32.6');
});

test('plusieurs modèles sont tous listés', async () => {
  const health = await checkOllamaHealth({
    baseUrl: BASE, configuredModel: 'qwen2.5-coder:14b',
    fetchImpl: fetchStub({ tags: tagsPayload(['qwen2.5-coder:3b', 'qwen2.5-coder:7b', 'qwen2.5-coder:14b']) })
  });
  assert.equal(health.status, OLLAMA_STATUS.READY);
  assert.equal(health.models.length, 3);
  assert.deepEqual(health.installedModels.sort(), ['qwen2.5-coder:14b', 'qwen2.5-coder:3b', 'qwen2.5-coder:7b']);
});

test('un modèle configuré mais absent est MODEL_MISSING, pas READY', async () => {
  const health = await checkOllamaHealth({
    baseUrl: BASE, configuredModel: 'llama3:70b', fetchImpl: fetchStub({ tags: tagsPayload(['qwen2.5-coder:7b']) })
  });
  assert.equal(health.status, OLLAMA_STATUS.MODEL_MISSING);
  assert.equal(health.configuredModelAvailable, false);
  assert.equal(health.error.code, OLLAMA_ERROR.MODEL_NOT_FOUND);
  // Les modèles réellement présents restent proposés.
  assert.deepEqual(health.installedModels, ['qwen2.5-coder:7b']);
});

test('des modèles présents sans sélection est NOT_CONFIGURED', async () => {
  const health = await checkOllamaHealth({ baseUrl: BASE, configuredModel: '', fetchImpl: fetchStub({ tags: tagsPayload(['qwen2.5-coder:7b']) }) });
  assert.equal(health.status, OLLAMA_STATUS.NOT_CONFIGURED);
});

test('une URL non locale est refusée sans appel réseau', async () => {
  let called = false;
  const health = await checkOllamaHealth({ baseUrl: 'http://ollama.example.com', fetchImpl: async () => { called = true; return {}; } });
  assert.equal(called, false, 'aucune requête vers un hôte distant');
  assert.equal(health.status, OLLAMA_STATUS.ERROR);
  assert.match(health.error.message, /uniquement Ollama local/);
});

test('un HTTP non-OK sur /api/tags est traité comme hors service', async () => {
  const health = await checkOllamaHealth({ baseUrl: BASE, fetchImpl: fetchStub({ status: 503 }) });
  assert.equal(health.reachable, false);
  assert.ok([OLLAMA_STATUS.OFFLINE, OLLAMA_STATUS.UNREACHABLE].includes(health.status));
});

test('une version absente ne dégrade pas le statut', async () => {
  const fetchImpl = async (url) => {
    const target = String(url);
    if (target.endsWith('/api/version')) throw new Error('404');
    return { ok: true, status: 200, json: async () => tagsPayload(['qwen2.5-coder:7b']) };
  };
  const health = await checkOllamaHealth({ baseUrl: BASE, configuredModel: 'qwen2.5-coder:7b', fetchImpl });
  assert.equal(health.status, OLLAMA_STATUS.READY);
  assert.equal(health.version, null);
});

test('le health check ne fait jamais d’inférence', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    return { ok: true, status: 200, json: async () => (String(url).endsWith('/api/version') ? { version: '0.32.6' } : tagsPayload(['qwen2.5-coder:7b'])) };
  };
  await checkOllamaHealth({ baseUrl: BASE, configuredModel: 'qwen2.5-coder:7b', fetchImpl });
  assert.ok(!calls.some((url) => url.includes('/api/chat')), 'aucune génération pour un simple statut');
  assert.ok(!calls.some((url) => url.includes('/api/generate')));
});

// ---------------------------------------------------- sélection de modèle

test('le modèle configuré et installé gagne toujours', () => {
  const installed = ['qwen2.5-coder:3b', 'qwen2.5-coder:7b', 'qwen2.5-coder:14b'];
  for (const role of ['fast', 'standard', 'advanced']) {
    const result = selectModelForRole(role, installed, 'qwen2.5-coder:7b');
    assert.equal(result.model, 'qwen2.5-coder:7b', `le choix du développeur prime pour ${role}`);
    assert.equal(result.reason, 'configured');
    assert.equal(result.substituted, false);
  }
});

test('chaque rôle a sa préférence quand rien n’est configuré', () => {
  const installed = ['qwen2.5-coder:3b', 'qwen2.5-coder:7b', 'qwen2.5-coder:14b'];
  assert.equal(selectModelForRole('fast', installed, '').model, 'qwen2.5-coder:3b');
  assert.equal(selectModelForRole('standard', installed, '').model, 'qwen2.5-coder:7b');
  assert.equal(selectModelForRole('advanced', installed, '').model, 'qwen2.5-coder:14b');
  // Les préférences sont déclarées, pas devinées.
  assert.equal(ROLE_PREFERENCES.fast[0], 'qwen2.5-coder:3b');
  assert.equal(ROLE_PREFERENCES.advanced[0], 'qwen2.5-coder:14b');
});

test('un rôle dégrade dans l’ordre déclaré, sans silence', () => {
  // Seul le 14b est installé : le rôle « fast » l'utilise et le dit.
  const result = selectModelForRole('fast', ['qwen2.5-coder:14b'], '');
  assert.equal(result.model, 'qwen2.5-coder:14b');
  assert.equal(result.reason, 'preference');
  // Avec un modèle configuré introuvable, la substitution est explicite.
  const substituted = selectModelForRole('fast', ['qwen2.5-coder:14b'], 'llama3:70b');
  assert.equal(substituted.model, 'qwen2.5-coder:14b');
  assert.equal(substituted.reason, 'preference_substituted');
  assert.equal(substituted.substituted, true);
});

test('un modèle hors préférences est accepté mais signalé comme substitution', () => {
  const code = selectModelForRole('standard', ['deepseek-coder:6.7b'], 'qwen2.5-coder:7b');
  assert.equal(code.model, 'deepseek-coder:6.7b');
  assert.equal(code.reason, 'code_model_substituted');
  assert.equal(code.substituted, true);
  // Un modèle sans rapport avec le code est le dernier recours, dit comme tel.
  const unrelated = selectModelForRole('standard', ['mistral:7b'], '');
  assert.equal(unrelated.model, 'mistral:7b');
  assert.equal(unrelated.reason, 'unrelated_substituted');
  assert.equal(unrelated.substituted, true);
});

test('sans modèle installé, aucune sélection n’est inventée', () => {
  const result = selectModelForRole('fast', [], 'qwen2.5-coder:7b');
  assert.equal(result.model, '');
  assert.equal(result.reason, 'no_models');
  assert.equal(result.substituted, false);
});

test('la comparaison de modèle configuré est insensible à la casse', () => {
  assert.equal(findConfiguredModel('QWEN2.5-Coder:7B', ['qwen2.5-coder:7b']).installed, true);
  assert.equal(findConfiguredModel('', ['qwen2.5-coder:7b']).reason, 'not_configured');
  assert.equal(findConfiguredModel('absent:1b', ['qwen2.5-coder:7b']).reason, 'not_installed');
});

// ------------------------------------------------------------ inférence

test('une inférence réussie renvoie une latence réelle', async () => {
  let clock = 1000;
  const now = () => clock;
  const fetchImpl = async () => { clock += 2500; return { ok: true, status: 200, json: async () => ({ message: { content: 'ok' } }) }; };
  const probe = await probeInference({ baseUrl: BASE, model: 'qwen2.5-coder:3b', fetchImpl, now });
  assert.equal(probe.ok, true);
  assert.equal(probe.latencyMs, 2500);
  assert.equal(probe.error, null);
  assert.equal(probe.model, 'qwen2.5-coder:3b');
});

test('une inférence ne demande qu’un seul token', async () => {
  let body = null;
  const fetchImpl = async (url, options) => { body = JSON.parse(options.body); return { ok: true, status: 200, json: async () => ({ message: { content: 'ok' } }) }; };
  await probeInference({ baseUrl: BASE, model: 'qwen2.5-coder:3b', fetchImpl });
  assert.equal(body.options.num_predict, 1, 'un test de vie ne génère pas un paragraphe');
  assert.equal(body.stream, false);
  assert.equal(body.model, 'qwen2.5-coder:3b');
});

test('aucune latence n’est rapportée quand l’inférence échoue', async () => {
  for (const [chat, expected] of [
    [{ status: 404 }, OLLAMA_ERROR.MODEL_NOT_FOUND],
    [{ status: 500 }, OLLAMA_ERROR.INFERENCE_ERROR],
    [{ payload: { message: {} } }, OLLAMA_ERROR.INVALID_RESPONSE],
    [{ payload: {} }, OLLAMA_ERROR.INVALID_RESPONSE],
    [{ throws: Object.assign(new Error('timed out'), { name: 'TimeoutError' }) }, OLLAMA_ERROR.TIMEOUT],
    [{ throws: Object.assign(new Error('cancelled'), { name: 'AbortError' }) }, OLLAMA_ERROR.CANCELLED]
  ]) {
    const probe = await probeInference({ baseUrl: BASE, model: 'm:1b', fetchImpl: fetchStub({ chat }) });
    assert.equal(probe.ok, false);
    assert.equal(probe.latencyMs, null, 'pas de latence sans succès');
    assert.equal(probe.error.code, expected, JSON.stringify(chat));
  }
});

test('un corps de réponse d’erreur n’est jamais réaffiché', async () => {
  const fetchImpl = async () => ({ ok: false, status: 500, json: async () => ({}), text: async () => 'secret=abc123 stack at x.go:1' });
  const probe = await probeInference({ baseUrl: BASE, model: 'm:1b', fetchImpl });
  assert.equal(probe.ok, false);
  assert.ok(!JSON.stringify(probe).includes('abc123'));
  assert.ok(!JSON.stringify(probe).includes('x.go:1'));
});

test('une annulation externe est honorée', async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, options) => {
    controller.abort(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
    if (options.signal.aborted) throw Object.assign(new Error('cancelled'), { name: 'AbortError' });
    return { ok: true, status: 200, json: async () => ({ message: { content: 'ok' } }) };
  };
  const probe = await probeInference({ baseUrl: BASE, model: 'm:1b', fetchImpl, signal: controller.signal });
  assert.equal(probe.ok, false);
  assert.equal(probe.error.code, OLLAMA_ERROR.CANCELLED);
});

test('sans modèle, aucune inférence n’est tentée', async () => {
  let called = false;
  const probe = await probeInference({ baseUrl: BASE, model: '', fetchImpl: async () => { called = true; return {}; } });
  assert.equal(called, false);
  assert.equal(probe.error.code, OLLAMA_ERROR.MODEL_NOT_FOUND);
});

// ------------------------------------------- aucun téléchargement automatique

test('la commande d’installation est du texte, jamais exécutée', () => {
  assert.equal(pullCommandFor('qwen2.5-coder:7b'), 'ollama pull qwen2.5-coder:7b');
  // Toute tentative d'injection de commande est neutralisée.
  assert.equal(pullCommandFor('a; rm -rf /'), 'ollama pull arm-rf/');
  assert.equal(pullCommandFor('$(whoami)'), 'ollama pull whoami');
  assert.equal(pullCommandFor(''), 'ollama pull qwen2.5-coder:7b');
  // Et rien dans le module ne lance de processus.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'ai', 'ollama-health.js'), 'utf8');
  assert.ok(!/child_process|execFile|spawn|exec\(/.test(source), 'le module ne lance aucun processus');
  assert.ok(!/api\/pull/.test(source), 'aucun appel à /api/pull');
});

test('l’extension ne déclenche jamais un pull automatiquement', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // La commande peut être copiée dans le presse-papier, jamais exécutée.
  assert.ok(!/exec\w*\([^)]*ollama pull/.test(source));
  assert.match(source, /clipboard\.writeText\(command\)/);
});

// ------------------------------------- dégradation gracieuse sans Ollama

test('les corrections déterministes ne dépendent pas d’Ollama', () => {
  // Le module de quick fix déterministe n'importe aucun client Ollama.
  const autofix = fs.readFileSync(path.join(__dirname, '..', 'src', 'autofix.js'), 'utf8');
  assert.ok(!/ollama/i.test(autofix), 'autofix reste indépendant d’Ollama');
  // Les détecteurs Live non plus.
  const detector = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'liveDetector.js'), 'utf8');
  assert.ok(!/ollama/i.test(detector));
});

test('les garde-fous de remédiation restent en place', () => {
  const provider = fs.readFileSync(path.join(__dirname, '..', 'src', 'ai', 'ollama-provider.js'), 'utf8');
  // Ollama reste contraint au local.
  assert.match(provider, /uniquement Ollama local/);
  // Le schéma de réponse structurée et la validation subsistent.
  assert.match(provider, /RESPONSE_SCHEMA/);
  assert.match(provider, /parseModelJson/);
  // Le validateur de patch et le vérificateur de correction existent toujours.
  for (const file of ['patch-validator.js', 'fix-verifier.js', 'context-builder.js']) {
    assert.ok(fs.existsSync(path.join(__dirname, '..', 'src', 'ai', file)), `${file} doit subsister`);
  }
});

// ------------------------------------------------------- accès utilisateur

test('la commande de diagnostic est déclarée et activable', () => {
  const commands = manifest.contributes.commands.map((command) => command.command);
  assert.ok(commands.includes('securityCenter.checkOllama'));
  assert.ok(commands.includes('securityCenter.configureOllama'), 'la commande existante est préservée');
  assert.ok(manifest.activationEvents.includes('onCommand:securityCenter.checkOllama'));
});

test('chaque statut a un libellé, et les états à corriger ont une consigne', () => {
  for (const status of Object.values(OLLAMA_STATUS)) {
    const presentation = STATUS_PRESENTATION[status];
    assert.ok(presentation, `${status} sans présentation`);
    assert.ok(presentation.label, `${status} sans libellé`);
  }
  // Un état que le développeur doit corriger explique quoi faire.
  assert.match(STATUS_PRESENTATION.NO_MODELS.hint, /ollama pull/);
  assert.match(STATUS_PRESENTATION.OFFLINE.hint, /Démarrez le service/);
  assert.match(STATUS_PRESENTATION.MODEL_MISSING.hint, /Sélectionnez un modèle installé/);
  // Un état sain n'a rien à conseiller.
  assert.equal(STATUS_PRESENTATION.READY.hint, '');
});
