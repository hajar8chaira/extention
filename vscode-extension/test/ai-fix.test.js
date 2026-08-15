const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('node:fs');
const { buildMinimalContext } = require('../src/ai/context-builder');
const { localOllamaUrl, selectFixModel, parseModelJson, generateOllamaFix, repairOllamaFix } = require('../src/ai/ollama-provider');
const { MODEL_ROLES, resolveModelRoles, readModelRoleConfiguration } = require('../src/ai/model-roles');
const { PROVIDERS, createAiProvider } = require('../src/ai/provider-registry');
const { modelItems, configureModelRoles } = require('../src/ai/model-configuration');
const { findInstalledModel } = require('../src/ai/model-discovery');
const { REMEDIATION_STATES, safeFallbackReason, fallbackReasonMessage, classifyRemediationError, remediationResult } = require('../src/ai/remediation-result');
const { runTwoModelRemediation, runAdvancedRemediation } = require('../src/ai/remediation-router');
const { METRICS_KEY, buildRemediationMetric, saveLocalRemediationMetric } = require('../src/ai/remediation-metrics');
const { FAILURE_MESSAGE, FAILURE_DETAIL, FAILURE_ACTIONS, isExhaustedRemediation } = require('../src/ai/remediation-failure');
const { normalizeModelPatch, replacementToPatch, parseUnifiedDiff, reanchorParsedPatch, validatePatchForFinding, applyParsedPatch, calculateFixConfidence } = require('../src/ai/patch-validator');

test('introduit les rôles Fast et Advanced sans les coupler au fournisseur', () => {
  const roles = resolveModelRoles({ provider: 'ollama', fast: 'coder-fast', advanced: 'coder-advanced', fallbackToAdvanced: true });
  assert.deepEqual(MODEL_ROLES, { FAST: 'fast', ADVANCED: 'advanced' });
  assert.deepEqual(roles, { provider: 'ollama', models: { fast: 'coder-fast', advanced: 'coder-advanced' }, fallbackToAdvanced: true, migratedFromLegacy: false });
});

test('migre en mémoire l’ancien modèle Ollama sans modifier la configuration', () => {
  const values = new Map([['ai.ollama.model', 'qwen2.5-coder:14b'], ['ai.fallbackToAdvanced', true]]);
  const configuration = { get: (key, fallback) => values.has(key) ? values.get(key) : fallback };
  const roles = readModelRoleConfiguration(configuration);
  assert.deepEqual(roles.models, { fast: 'qwen2.5-coder:14b', advanced: 'qwen2.5-coder:14b' });
  assert.equal(roles.migratedFromLegacy, true);
});

test('les rôles explicites remplacent progressivement l’ancien réglage', () => {
  assert.deepEqual(resolveModelRoles({ legacyModel: 'legacy', fast: 'fast-local', fallbackToAdvanced: false }), {
    provider: 'ollama', models: { fast: 'fast-local', advanced: 'legacy' }, fallbackToAdvanced: false, migratedFromLegacy: false
  });
});

test('sépare le fournisseur Ollama des rôles de modèles', async () => {
  const requested = [];
  const provider = createAiProvider(PROVIDERS.OLLAMA, { baseUrl: 'http://127.0.0.1:11434', fetchImpl: async (url) => {
    requested.push(url.toString());
    return { ok: true, json: async () => ({ models: [{ name: 'coder-fast' }] }) };
  } });
  assert.equal(provider.id, 'ollama');
  assert.equal(provider.locality, 'local');
  assert.deepEqual(await provider.listModels(), ['coder-fast']);
  assert.match(requested[0], /\/api\/tags$/);
  assert.throws(() => createAiProvider('remote-provider'), /non pris en charge/);
});

test('configure séparément Fast, Advanced et le fallback avec les modèles découverts', async () => {
  const values = new Map([['ai.ollama.model', 'legacy']]);
  const updates = [];
  const picks = [{ label: 'coder-fast' }, { label: 'coder-advanced' }, { label: 'Non', value: false }];
  const result = await configureModelRoles({
    configuration: { get: (key, fallback) => values.has(key) ? values.get(key) : fallback },
    models: ['coder-fast', 'coder-advanced'],
    showQuickPick: async (items) => { assert.ok(items.length); return picks.shift(); },
    update: async (...args) => updates.push(args),
    configurationTarget: 'workspace'
  });
  assert.deepEqual(result, { provider: 'ollama', models: { fast: 'coder-fast', advanced: 'coder-advanced' }, fallbackToAdvanced: false });
  assert.deepEqual(updates.map(([key, value]) => [key, value]), [
    ['ai.models.fast', 'coder-fast'], ['ai.models.advanced', 'coder-advanced'], ['ai.fallbackToAdvanced', false]
  ]);
  assert.match(modelItems(['legacy'], 'legacy', 'fast')[0].description, /Actuellement/);
});

test('refuse explicitement un modèle configuré qui n’est pas installé', () => {
  assert.deepEqual(findInstalledModel('coder-fast', ['coder-fast', 'coder-advanced']), { installed: true, model: 'coder-fast', reason: 'installed' });
  assert.deepEqual(findInstalledModel('missing-model', ['coder-fast']), { installed: false, model: 'missing-model', reason: 'not_installed' });
  assert.deepEqual(findInstalledModel('', ['coder-fast']), { installed: false, model: '', reason: 'not_configured' });
});

test('classifie localement le résultat Fast avec les raisons du validateur', () => {
  assert.equal(remediationResult({ parsed: { hunks: [{}] }, model: 'coder-fast' }).state, REMEDIATION_STATES.VALID);
  assert.equal(classifyRemediationError(new Error('Le texte source proposé par l’IA est ambigu.')), REMEDIATION_STATES.AMBIGUOUS);
  assert.equal(classifyRemediationError(new Error('La proposition IA ressemble à un payload offensif.')), REMEDIATION_STATES.UNSAFE);
  assert.equal(classifyRemediationError(new Error('La correction IA ne modifie pas le code.')), REMEDIATION_STATES.NO_CHANGE);
  assert.equal(classifyRemediationError(new Error('Ollama n’a pas retourné un JSON valide.')), REMEDIATION_STATES.PARSE_ERROR);
  assert.equal(classifyRemediationError(new Error('Ollama HTTP 500.')), REMEDIATION_STATES.MODEL_ERROR);
  const timeout = new Error('aborted'); timeout.name = 'AbortError';
  assert.equal(classifyRemediationError(timeout), REMEDIATION_STATES.TIMEOUT);
  assert.equal(classifyRemediationError(new Error('Le patch ne concerne pas la ligne signalée.')), REMEDIATION_STATES.INVALID);
});

test('expose une raison de fallback sûre et un message utilisateur sans détail du patch', () => {
  assert.equal(safeFallbackReason(REMEDIATION_STATES.AMBIGUOUS), 'ambiguous_patch');
  assert.match(fallbackReasonMessage('ambiguous_patch'), /ambiguous/i);
  assert.equal(fallbackReasonMessage('ambiguous_patch').includes('secret-value'), false);
});

test('permet une tentative Advanced manuelle sans rejouer Fast', async () => {
  const calls = [];
  const result = await runAdvancedRemediation({
    configuration: { models: { advanced: 'advanced' } }, installedModels: ['advanced'], context: { excerpt: 'safe' },
    generate: async ({ role }) => { calls.push(role); return { oldText: 'x', newText: 'y' }; },
    validate: async (generated) => ({ generated, parsed: { hunks: [{}] } })
  });
  assert.equal(result.ok, true);
  assert.equal(result.role, 'advanced');
  assert.equal(result.manualAdvanced, true);
  assert.deepEqual(calls, ['advanced']);
});

test('arrête proprement après deux modèles refusés sans patch permissif', async () => {
  const result = await runTwoModelRemediation({
    configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: true }, installedModels: ['fast', 'advanced'], context: {},
    generate: async ({ role }) => ({ role }),
    validate: async () => { throw new Error('Le texte source proposé par l’IA est ambigu.'); }
  });
  assert.equal(result.ok, false);
  assert.equal(result.attempts.length, 2);
  assert.equal(isExhaustedRemediation(result), true);
  assert.match(FAILURE_MESSAGE, /could not generate/i);
  assert.match(FAILURE_DETAIL, /No file was modified/i);
  assert.deepEqual(FAILURE_ACTIONS, ['Explain issue', 'Open finding', 'Retry']);
});

test('classe timeout et annulation sans boucle Advanced', async () => {
  for (const name of ['TimeoutError', 'AbortError']) {
    let calls = 0;
    const result = await runTwoModelRemediation({
      configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: true }, installedModels: ['fast', 'advanced'], context: {},
      generate: async () => { calls += 1; const error = new Error('aborted'); error.name = name; throw error; }, validate: async () => ({})
    });
    assert.equal(result.ok, false); assert.equal(result.classification.state, 'TIMEOUT'); assert.equal(calls, 1);
  }
});

test('Advanced invalide reste rejeté par le même validateur', async () => {
  const result = await runAdvancedRemediation({
    configuration: { models: { advanced: 'advanced' } }, installedModels: ['advanced'], context: {},
    generate: async () => ({ oldText: 'x', newText: 'unsafe' }), validate: async () => { throw new Error('payload offensif'); }
  });
  assert.equal(result.ok, false);
  assert.equal(result.classification.state, 'UNSAFE');
});

test('conserve localement les métriques de remédiation et met à jour le même essai', async () => {
  const storage = new Map();
  const workspaceState = { get: (key, fallback) => storage.get(key) || fallback, update: async (key, value) => storage.set(key, value) };
  const routed = { ok: true, role: 'advanced', model: 'coder-advanced', fallbackUsed: true, fallbackReason: 'ambiguous_patch', attempts: [
    { ok: false, role: 'fast', model: 'coder-fast', durationMs: 12, classification: { state: 'AMBIGUOUS' } },
    { ok: true, role: 'advanced', model: 'coder-advanced', durationMs: 34, classification: { state: 'VALID' } }
  ] };
  await saveLocalRemediationMetric(workspaceState, buildRemediationMetric(routed, { id: 'metric-1' }));
  await saveLocalRemediationMetric(workspaceState, buildRemediationMetric(routed, { id: 'metric-1', testResult: 'passed', rescanResult: 'finding_absent' }));
  const metrics = storage.get(METRICS_KEY);
  assert.equal(metrics.length, 1);
  assert.equal(metrics[0].attempts[0].validatorResult, 'AMBIGUOUS');
  assert.equal(metrics[0].attempts[1].durationMs, 34);
  assert.equal(metrics[0].fallbackUsed, true);
  assert.equal(metrics[0].finalModel, 'coder-advanced');
  assert.equal(metrics[0].testResult, 'passed');
  assert.equal(metrics[0].rescanResult, 'finding_absent');
});

test('Fast valide continue sans appeler Advanced', async () => {
  const calls = [];
  const context = { excerpt: 'const value = unsafe(input);' };
  const result = await runTwoModelRemediation({
    configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: true },
    installedModels: ['fast', 'advanced'], context,
    generate: async ({ role, model, context: received }) => { calls.push({ role, model }); assert.equal(received, context); return { oldText: 'x', newText: 'y' }; },
    validate: async (generated) => ({ generated, parsed: { hunks: [{}] } })
  });
  assert.equal(result.ok, true);
  assert.equal(result.role, 'fast');
  assert.equal(result.fallbackUsed, false);
  assert.deepEqual(calls, [{ role: 'fast', model: 'fast' }]);
});

test('Fast refusé déclenche Advanced une seule fois avec le même contexte', async () => {
  const calls = [];
  const contexts = [];
  const context = { excerpt: 'apiKey = [REDACTED]' };
  const result = await runTwoModelRemediation({
    configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: true },
    installedModels: ['fast', 'advanced'], context,
    generate: async ({ role, model, context: received }) => { calls.push({ role, model }); contexts.push(received); return { role }; },
    validate: async (generated) => {
      if (generated.role === 'fast') throw new Error('Le texte source proposé par l’IA est ambigu.');
      return { generated, parsed: { hunks: [{}] } };
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.role, 'advanced');
  assert.equal(result.fallbackUsed, true);
  assert.equal(result.attempts.length, 2);
  assert.deepEqual(calls, [{ role: 'fast', model: 'fast' }, { role: 'advanced', model: 'advanced' }]);
  assert.equal(contexts[0], contexts[1]);
  assert.match(contexts[1].excerpt, /\[REDACTED\]/);
});

test('ne fallback pas après une erreur infrastructure ou lorsque désactivé', async () => {
  for (const scenario of [
    { fallbackToAdvanced: true, message: 'Ollama HTTP 500.' },
    { fallbackToAdvanced: false, message: 'Le texte source proposé par l’IA est ambigu.' }
  ]) {
    let calls = 0;
    const result = await runTwoModelRemediation({
      configuration: { models: { fast: 'fast', advanced: 'advanced' }, fallbackToAdvanced: scenario.fallbackToAdvanced },
      installedModels: ['fast', 'advanced'], context: {},
      generate: async () => { calls += 1; throw new Error(scenario.message); },
      validate: async () => { throw new Error('not reached'); }
    });
    assert.equal(result.ok, false);
    assert.equal(result.fallbackUsed, false);
    assert.equal(calls, 1);
  }
});

test('construit un contexte minimal et masque les secrets', () => {
  const workspace = path.resolve('C:/workspace');
  const context = buildMinimalContext({ id: '1', tool: 'Semgrep', file: 'src/a.js', absolutePath: path.join(workspace, 'src/a.js'), startLine: 1, endLine: 1 }, workspace, 'const ok = 1;\nconst apiKey = "very-secret";\nrun(ok);', 1);
  assert.match(context.excerpt, /\[REDACTED\]/);
  assert.doesNotMatch(context.excerpt, /very-secret/);
  const yamlContext = buildMinimalContext({ id: '2', tool: 'Gitleaks', absolutePath: path.join(workspace, 'data/users.yml'), startLine: 1 }, workspace, 'user: test\nkey: bjoernGoogle\nrole: admin', 1);
  assert.match(yamlContext.excerpt, /key: \[REDACTED\]/);
  assert.doesNotMatch(yamlContext.excerpt, /bjoernGoogle/);
  assert.match(buildMinimalContext({ absolutePath: path.join(workspace, 'src/a.ts'), startLine: 0 }, workspace, 'const verify = (token: string, secret: string) => true', 1).excerpt, /token: string, secret: string/);
  assert.throws(() => buildMinimalContext({ absolutePath: path.join(workspace, '.env'), startLine: 0 }, workspace, 'TOKEN=x'), /sensibles/);
});

test('valide et applique un unified diff limité au fichier du finding', () => {
  const patch = '--- a/src/app.js\n+++ b/src/app.js\n@@ -1,2 +1,2 @@\n-const value = unsafe(input);\n+const value = safe(input);\n console.log(value);';
  const parsed = validatePatchForFinding(parseUnifiedDiff(patch), { file: 'src/app.js' });
  assert.equal(applyParsedPatch('const value = unsafe(input);\nconsole.log(value);', parsed), 'const value = safe(input);\nconsole.log(value);');
  assert.throws(() => validatePatchForFinding(parsed, { file: 'src/other.js' }), /au lieu/);
  assert.match(normalizeModelPatch('@@ -1 +1 @@\n-x\n+y', 'src/app.js'), /^--- a\/src\/app\.js/);
});

test('refuse un patch IA dispersé loin du finding', () => {
  const patch = '--- a/src/app.js\n+++ b/src/app.js\n@@ -1 +1 @@\n-x\n+y\n@@ -30 +30 @@\n-a\n+b';
  assert.throws(() => validatePatchForFinding(parseUnifiedDiff(patch), { file: 'src/app.js', startLine: 0 }), /exactement un hunk/);
  const far = parseUnifiedDiff('--- a/src/app.js\n+++ b/src/app.js\n@@ -30 +30 @@\n-a\n+b');
  assert.throws(() => validatePatchForFinding(far, { file: 'src/app.js', startLine: 0 }), /ligne signalée/);
});

test('refuse les créations, traversées et fichiers sensibles', () => {
  assert.throws(() => parseUnifiedDiff('--- /dev/null\n+++ b/src/a.js\n@@ -0,0 +1 @@\n+x'), /interdit|exactement/);
  assert.throws(() => parseUnifiedDiff('--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-x\n+y'), /sensible/);
});

test('appelle uniquement Ollama local avec un résultat structuré', async () => {
  assert.equal(parseModelJson('```json\n{"patch":"x","summary":"y","tests":[]}\n```').summary, 'y');
  assert.throws(() => localOllamaUrl('https://ollama.com'), /local/);
  const fetchImpl = async (url, options) => {
    assert.match(url.toString(), /127\.0\.0\.1:11434\/api\/chat/);
    const body = JSON.parse(options.body);
    assert.equal(body.stream, false);
    assert.equal(body.format.type, 'object');
    assert.equal(body.options.num_ctx, 4096);
    assert.equal(body.options.num_predict, 550);
    return { ok: true, json: async () => ({ model: 'coder', message: { content: JSON.stringify({ oldText: 'x', newText: 'y', summary: 'fix', securityReason: 'raison', confidence: 0.8, assumptions: [], tests: [] }) } }) };
  };
  const result = await generateOllamaFix({ baseUrl: 'http://127.0.0.1:11434', model: 'coder', context: { finding: {}, file: 'src/a.js', excerpt: '1: x', excerptStartLine: 1, excerptEndLine: 1 }, fetchImpl });
  assert.equal(result.summary, 'fix');
});

test('utilise automatiquement le modèle 7B pour une correction simple', () => {
  assert.equal(selectFixModel('qwen2.5-coder:14b', ['qwen2.5-coder:14b', 'qwen2.5-coder:7b'], { finding: { startLine: 16, endLine: 16 }, excerpt: 'alt={{name}}' }), 'qwen2.5-coder:7b');
  assert.equal(selectFixModel('qwen2.5-coder:14b', ['qwen2.5-coder:14b', 'qwen2.5-coder:7b'], { finding: { startLine: 1, endLine: 20 }, excerpt: 'long' }), 'qwen2.5-coder:14b');
});

test('demande à Ollama de normaliser un patch refusé sans affaiblir le validateur', async () => {
  const fetchImpl = async (_url, options) => {
    const body = JSON.parse(options.body);
    assert.match(body.messages[1].content, /oldText/);
    assert.match(body.messages[1].content, /deux hunks/);
    return { ok: true, json: async () => ({ model: 'coder', message: { content: JSON.stringify({ oldText: 'x', newText: 'y', summary: 'normalisé', securityReason: 'raison', confidence: 0.7, assumptions: [], tests: [] }) } }) };
  };
  const result = await repairOllamaFix({ baseUrl: 'http://localhost:11434', model: 'coder', context: { file: 'src/a.js', excerpt: '1: x' }, rejectedPatch: '@@ -1 +1 @@\n-x\n+y\n@@ -3 +3 @@\n-a\n+b', validationError: 'deux hunks', fetchImpl });
  const parsed = validatePatchForFinding(parseUnifiedDiff(replacementToPatch('x', 'src/a.js', result.oldText, result.newText)), { file: 'src/a.js', startLine: 0 });
  assert.equal(parsed.hunks.length, 1);
  assert.equal(result.repaired, true);
});

test('construit le diff depuis un remplacement exact et unique proposé par l’IA', () => {
  const patch = replacementToPatch('before\nunsafe(input)\nafter', 'src/a.js', 'unsafe(input)', 'safe(input)');
  const parsed = validatePatchForFinding(parseUnifiedDiff(patch), { file: 'src/a.js', startLine: 1 });
  assert.equal(applyParsedPatch('before\nunsafe(input)\nafter', parsed), 'before\nsafe(input)\nafter');
  assert.throws(() => replacementToPatch('x\nx', 'src/a.js', 'x', 'y'), /ambigu/);
  assert.throws(() => replacementToPatch('const id = input;', 'src/a.js', 'input', "' OR '1'='1' --"), /payload offensif/);
  const indented = replacementToPatch('function run() {\n  unsafe(input);\n}', 'src/a.js', 'unsafe(input);', 'safe(input);');
  assert.equal(applyParsedPatch('function run() {\n  unsafe(input);\n}', parseUnifiedDiff(indented)), 'function run() {\n  safe(input);\n}');
  const partial = replacementToPatch('  return db.query("id=" + input);', 'src/a.js', 'db.query("id=" + input);', "db.query('id=$1', [input]);");
  assert.equal(applyParsedPatch('  return db.query("id=" + input);', parseUnifiedDiff(partial)), "  return db.query('id=$1', [input]);");
  const angularSource = '        <img [src]="logoSrc" class="logo" alt={{applicationName}}>';
  const angularPatch = replacementToPatch(angularSource, 'navbar.html', 'alt={{applicationName}}', '<img [src]="logoSrc" class="logo" alt="{{applicationName}}">');
  assert.equal(applyParsedPatch(angularSource, parseUnifiedDiff(angularPatch)), '        <img [src]="logoSrc" class="logo" alt="{{applicationName}}">');
  assert.doesNotMatch(applyParsedPatch(angularSource, parseUnifiedDiff(angularPatch)), /class="logo".*class="logo"/);
});

test('réancre un hunk seulement sur un contexte source exact et unique', () => {
  const parsed = parseUnifiedDiff('--- a/src/a.js\n+++ b/src/a.js\n@@ -99 +99 @@\n-const value = unsafe(input);\n+const value = safe(input);');
  const anchored = reanchorParsedPatch('const before = true;\nconst value = unsafe(input);\nconst after = true;', parsed);
  assert.equal(anchored.hunks[0].oldStart, 2);
  assert.equal(applyParsedPatch('const before = true;\nconst value = unsafe(input);\nconst after = true;', anchored), 'const before = true;\nconst value = safe(input);\nconst after = true;');
  assert.throws(() => reanchorParsedPatch('const value = unsafe(input);\nconst value = unsafe(input);', parsed), /ambigu/);
});

test('calcule une confiance indépendante et bornée pour le patch validé', () => {
  const parsed = parseUnifiedDiff('--- a/src/a.js\n+++ b/src/a.js\n@@ -1 +1 @@\n-x\n+y');
  assert.equal(calculateFixConfidence({ confidence: 2, securityReason: 'La donnée est désormais validée correctement.', assumptions: [] }, parsed), 1);
});

test('informe clairement l’utilisateur lorsqu’un finding est devenu obsolète', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /le fichier a changé depuis le scan/);
  assert.match(source, /Votre fichier reste inchangé/);
  assert.match(source, /Relancer Semgrep/);
  assert.match(source, /Aucune modification n’a été appliquée/);
});
