const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SNYK_IMAGE, CONTAINER_SOURCE,
  runSnyk, resolveRunner, resolveInvocation, detectLocalCli, snykCandidates, localInvocation,
  parseSnykVersion, parseSnykJson, acceptPayload, snykPayloadError, excludeNames, openSourceArgs, codeArgs, iacArgs,
  dockerArgs, snykEnvironment, classifyFailure
} = require('../src/snyk');
const { SnykError, maskToken, looksLikeSnykToken, validateToken } = require('../src/snyk-api');

const TOKEN = '11111111-2222-3333-4444-555555555555';
const LOCAL_RUNNER = { mode: 'local', local: { executable: '/usr/bin/snyk', prefixArgs: [], version: '1.1298.0' } };
const DOCKER_RUNNER = { mode: 'docker', local: null };

/** Fake Snyk process: one JSON payload per sub-command, or a thrown failure. */
function fakeExec(responses = {}) {
  const calls = [];
  const exec = async (executable, args, options) => {
    calls.push({ executable, args, options });
    const key = args.includes('code') ? 'code' : args.includes('iac') ? 'iac' : 'openSource';
    const response = responses[key];
    if (response instanceof Error) throw response;
    if (typeof response === 'function') return response({ executable, args, options });
    return { stdout: JSON.stringify(response ?? { ok: true, vulnerabilities: [] }), stderr: '' };
  };
  return { exec, calls };
}

function cliError({ stdout = '', stderr = '', message = 'Command failed', exitCode = 2, killed = false, code } = {}) {
  return Object.assign(new Error(message), { stdout, stderr, exitCode, killed, code });
}

// ------------------------------------------------------------------ détection

test('propose les bons binaires Snyk par plateforme', () => {
  assert.deepEqual(snykCandidates('win32'), ['snyk.exe', 'snyk.cmd', 'snyk']);
  assert.deepEqual(snykCandidates('linux'), ['snyk']);
  assert.deepEqual(snykCandidates('darwin'), ['snyk']);
});

test('lance un wrapper .cmd Windows via l’interpréteur, sans shell', () => {
  const invocation = localInvocation('C:\\npm\\snyk.cmd', 'win32');
  assert.equal(invocation.prefixArgs[0], '/d');
  assert.deepEqual(invocation.prefixArgs.slice(1), ['/s', '/c', 'C:\\npm\\snyk.cmd']);
  assert.deepEqual(localInvocation('/usr/bin/snyk', 'linux'), { executable: '/usr/bin/snyk', prefixArgs: [] });
});

test('extrait la version du CLI Snyk', () => {
  assert.equal(parseSnykVersion('1.1298.0 (standalone)'), '1.1298.0');
  assert.equal(parseSnykVersion(''), '');
});

test('détecte le CLI local et sa version', async () => {
  const detected = await detectLocalCli({
    platform: 'linux',
    hasCommand: async () => '/usr/bin/snyk',
    exec: async () => ({ stdout: '1.1298.0 (standalone)', stderr: '' })
  });
  assert.equal(detected.path, '/usr/bin/snyk');
  assert.equal(detected.version, '1.1298.0');
});

test('retourne null quand aucun CLI Snyk n’est présent', async () => {
  assert.equal(await detectLocalCli({ platform: 'linux', hasCommand: async () => '' }), null);
});

// ------------------------------------------------------------------- resolver

test('Auto choisit le CLI local quand il est disponible', async () => {
  const runner = await resolveRunner('auto', { detect: async () => LOCAL_RUNNER.local, hasCommand: async () => 'docker' });
  assert.equal(runner.mode, 'local');
  assert.equal(runner.local.version, '1.1298.0');
});

test('Auto bascule sur Docker quand le CLI local est absent', async () => {
  const runner = await resolveRunner('auto', { detect: async () => null, hasCommand: async () => '/usr/bin/docker' });
  assert.equal(runner.mode, 'docker');
});

test('Local échoue explicitement quand le CLI est absent', async () => {
  await assert.rejects(
    () => resolveRunner('local', { detect: async () => null, hasCommand: async () => '/usr/bin/docker' }),
    (error) => error instanceof SnykError && error.code === 'CLI_MISSING'
  );
});

test('Docker n’essaie jamais le CLI local', async () => {
  let detected = false;
  const runner = await resolveRunner('docker', {
    detect: async () => { detected = true; return LOCAL_RUNNER.local; },
    hasCommand: async () => '/usr/bin/docker'
  });
  assert.equal(runner.mode, 'docker');
  assert.equal(detected, false);
});

test('Auto échoue quand ni CLI ni Docker ne sont disponibles', async () => {
  await assert.rejects(
    () => resolveRunner('auto', { detect: async () => null, hasCommand: async () => '' }),
    (error) => error instanceof SnykError && error.code === 'DOCKER_MISSING'
  );
});

// ---------------------------------------------------------------- invocations

test('construit une sortie machine pour chaque capacité', () => {
  assert.deepEqual(openSourceArgs(), ['test', '--json', '--all-projects']);
  assert.deepEqual(codeArgs(), ['code', 'test', '--json']);
  assert.deepEqual(iacArgs(), ['iac', 'test', '--json']);
  assert.ok(openSourceArgs({ severityThreshold: 'high' }).includes('--severity-threshold=high'));
});

test('ne transmet à --exclude que des noms, jamais des globs', () => {
  assert.deepEqual(excludeNames(['**/node_modules/**', 'dist', 'src/*.min.js']), ['node_modules', 'dist', 'src']);
  assert.ok(openSourceArgs({ exclusions: ['**/node_modules/**'] }).includes('--exclude=node_modules'));
  assert.ok(!openSourceArgs({ exclusions: ['**/*.map'] }).some((arg) => arg.startsWith('--exclude=')));
});

test('monte le workspace en lecture seule, sans privilège ni socket Docker', () => {
  const args = dockerArgs('/repo', openSourceArgs());
  assert.ok(args.includes(SNYK_IMAGE));
  assert.ok(args.some((arg) => arg.endsWith(`:${CONTAINER_SOURCE}:ro`)));
  assert.ok(args.includes('--rm'));
  assert.ok(!args.includes('--privileged'));
  assert.ok(!args.some((arg) => String(arg).includes('docker.sock')));
  assert.ok(!args.some((arg) => String(arg).includes('--network=host')));
});

test('l’image officielle ne construit jamais le projet analysé', () => {
  // Sans cela, snyk/snyk lance npm/mvn/pip install dans le workspace monté.
  const args = dockerArgs('/repo', openSourceArgs());
  assert.ok(args.includes('COMMAND=:'));
  assert.equal(args[args.indexOf('COMMAND=:') - 1], '-e');
});

test('le jeton est passé par nom d’environnement, jamais dans argv', () => {
  const args = dockerArgs('/repo', openSourceArgs());
  const index = args.indexOf('-e');
  assert.equal(args[index + 1], 'SNYK_TOKEN');
  assert.ok(!args.includes(TOKEN));
  assert.ok(!JSON.stringify(args).includes(TOKEN));
});

test('l’environnement porte le jeton et désactive la télémétrie', () => {
  const env = snykEnvironment(TOKEN, { PATH: '/bin' });
  assert.equal(env.SNYK_TOKEN, TOKEN);
  assert.equal(env.SNYK_DISABLE_ANALYTICS, '1');
  assert.equal(env.PATH, '/bin');
});

test('l’invocation locale exécute le binaire résolu dans le workspace', async () => {
  const invocation = await resolveInvocation('local', '/repo', openSourceArgs(), { runner: LOCAL_RUNNER });
  assert.equal(invocation.executable, '/usr/bin/snyk');
  assert.equal(invocation.mode, 'local');
  assert.deepEqual(invocation.args, ['test', '--json', '--all-projects']);
});

// --------------------------------------------------------------- sortie JSON

test('lit le JSON même précédé de lignes de progression', () => {
  assert.deepEqual(parseSnykJson('Testing /repo...\n{"ok":true}'), { ok: true });
  assert.deepEqual(parseSnykJson('[{"ok":true}]'), [{ ok: true }]);
});

test('refuse une sortie non JSON sans exposer le jeton', () => {
  assert.throws(() => parseSnykJson(''), (error) => error.code === 'INVALID_RESPONSE');
  assert.throws(() => parseSnykJson('{oops'), (error) => error.code === 'INVALID_RESPONSE');
});

// ------------------------------------------------------------- classification

test('classe les échecs Snyk connus', () => {
  const auth = classifyFailure(cliError({ stderr: 'Authentication error (SNYK-0005): MissingApiTokenError' }), {});
  assert.equal(auth.code, 'AUTH_ERROR');
  assert.equal(classifyFailure(cliError({ stderr: 'HTTP 403 Forbidden' }), {}).code, 'AUTH_ERROR');
  assert.equal(classifyFailure(cliError({ stderr: 'Snyk Code is not supported for org' }), {}).code, 'FEATURE_UNAVAILABLE');
  assert.equal(classifyFailure(cliError({ stderr: 'getaddrinfo ENOTFOUND api.snyk.io' }), {}).code, 'NETWORK_ERROR');
  assert.equal(classifyFailure(cliError({ stderr: 'Could not detect supported target files', exitCode: 3 }), {}).code, 'NO_PROJECTS');
  assert.equal(classifyFailure(cliError({ code: 'ENOENT' }), {}).code, 'CLI_MISSING');
  assert.equal(classifyFailure(cliError({ killed: true }), { timeoutMs: 60000 }).code, 'TIMEOUT');
  assert.equal(classifyFailure(cliError({}), { signal: { aborted: true } }).code, 'CANCELED');
  assert.equal(classifyFailure(cliError({ stderr: 'something exploded' }), {}).code, 'FAILED');
});

test('aucun message d’erreur ne répète le jeton', () => {
  const error = classifyFailure(cliError({ stderr: `token ${TOKEN} rejected by boom` }), { token: TOKEN });
  assert.ok(!error.message.includes(TOKEN));
  assert.ok(error.message.includes('***'));
});

test('le masquage couvre le jeton configuré et le format générique', () => {
  assert.ok(!maskToken(`SNYK_TOKEN=${TOKEN}`, TOKEN).includes(TOKEN));
  assert.ok(!maskToken(`utilisation de ${TOKEN}`).includes(TOKEN));
});

test('valide le format d’un jeton Snyk', () => {
  assert.equal(looksLikeSnykToken(TOKEN), true);
  assert.equal(looksLikeSnykToken('pas-un-uuid'), false);
});

test('un corps JSON d’erreur n’est jamais confondu avec un scan propre', () => {
  // Observé réellement : le CLI sort en code 0 en écrivant {"ok":false,"error":…}
  assert.equal(snykPayloadError({ ok: false, error: 'Missing node_modules folder', path: '/repo' }),
    'Missing node_modules folder');
  assert.equal(snykPayloadError({ ok: true, vulnerabilities: [] }), '');
  assert.equal(snykPayloadError([{ ok: false, error: 'boom' }, { ok: true, vulnerabilities: [] }]), '');
  assert.equal(snykPayloadError({ runs: [] }), '');
  // Message exact renvoyé par snyk/snyk:linux sur un dossier sans manifeste.
  assert.throws(() => acceptPayload({ ok: false, error: 'Could not detect supported target files in /app.\nPlease see our documentation', path: '/app' }),
    (error) => error.code === 'NO_PROJECTS');
  assert.throws(() => acceptPayload({ ok: false, error: 'Authentication error: MissingApiTokenError' }),
    (error) => error.code === 'AUTH_ERROR');
  assert.throws(() => acceptPayload({ ok: false, error: "Missing node_modules folder: we can't test without dependencies." }),
    (error) => error.code === 'UNSUPPORTED');
});

test('un scan qui n’a pas pu résoudre les dépendances remonte comme échec', async () => {
  const { exec } = fakeExec({ openSource: { ok: false, error: "Missing node_modules folder: we can't test without dependencies.", path: '/repo' } });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, runner: LOCAL_RUNNER, exec });
  assert.equal(result.payload.openSource.ran, false);
  assert.equal(result.payload.openSource.errorCode, 'UNSUPPORTED');
  assert.ok(result.payload.warnings.some((warning) => /lockfile/.test(warning)));
});

// ------------------------------------------------------------- authentication

test('validateToken distingue refusé, valide et indéterminé', async () => {
  assert.equal(await validateToken('', {}), false);
  assert.equal(await validateToken(TOKEN, { request: async () => ({ data: {} }) }), true);
  assert.equal(await validateToken(TOKEN, { request: async () => { throw new SnykError('AUTH_ERROR', 'refusé'); } }), false);
  assert.equal(await validateToken(TOKEN, { request: async () => { throw new SnykError('NETWORK_ERROR', 'hors ligne'); } }), null);
});

// ------------------------------------------------------------------ exécution

test('refuse de démarrer sans jeton configuré', async () => {
  await assert.rejects(
    () => runSnyk({ workspacePath: '/repo', token: '', runner: LOCAL_RUNNER, exec: fakeExec().exec }),
    (error) => error.code === 'AUTH_ERROR'
  );
});

test('refuse de démarrer sans aucune capacité activée', async () => {
  await assert.rejects(
    () => runSnyk({ workspacePath: '/repo', token: TOKEN, includeOpenSource: false, runner: LOCAL_RUNNER, exec: fakeExec().exec }),
    (error) => error.code === 'CONFIG_ERROR'
  );
});

test('exécute Snyk Open Source seul par défaut', async () => {
  const { exec, calls } = fakeExec({ openSource: { ok: false, vulnerabilities: [{ id: 'SNYK-JS-1' }] } });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, runner: LOCAL_RUNNER, exec });
  assert.equal(calls.length, 1);
  assert.equal(result.payload.openSource.ran, true);
  assert.equal(result.payload.code.ran, false);
  assert.equal(result.payload.iac.ran, false);
  assert.equal(result.payload.capabilities.openSource, true);
});

test('un code de sortie 1 avec du JSON est un scan réussi, pas un échec', async () => {
  const { exec } = fakeExec({
    openSource: cliError({ stdout: JSON.stringify({ ok: false, vulnerabilities: [{ id: 'SNYK-JS-1' }] }), exitCode: 1 })
  });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, runner: LOCAL_RUNNER, exec });
  assert.equal(result.payload.openSource.results[0].vulnerabilities.length, 1);
});

test('Snyk Code indisponible ne fait pas échouer Snyk Open Source', async () => {
  const { exec } = fakeExec({
    openSource: { ok: true, vulnerabilities: [] },
    code: cliError({ stderr: 'Snyk Code is not supported for org xyz' })
  });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, includeCode: true, runner: LOCAL_RUNNER, exec });
  assert.equal(result.payload.openSource.available, true);
  assert.equal(result.payload.code.available, false);
  assert.equal(result.payload.capabilities.code, false);
  assert.ok(result.payload.warnings.some((warning) => warning.startsWith('Snyk Code :')));
});

test('un workspace sans dépendance n’est pas une erreur', async () => {
  const { exec } = fakeExec({ openSource: cliError({ stderr: 'Could not detect supported target files', exitCode: 3 }) });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, runner: LOCAL_RUNNER, exec });
  assert.equal(result.payload.openSource.ran, true);
  assert.deepEqual(result.payload.openSource.results, []);
  assert.equal(result.payload.capabilities.openSource, true);
});

test('un jeton refusé arrête toute l’analyse Snyk', async () => {
  const { exec } = fakeExec({ openSource: cliError({ stderr: 'Authentication failed. Please run snyk auth' }) });
  await assert.rejects(
    () => runSnyk({ workspacePath: '/repo', token: TOKEN, includeCode: true, runner: LOCAL_RUNNER, exec }),
    (error) => error.code === 'AUTH_ERROR'
  );
});

test('exécute les trois capacités quand elles sont demandées', async () => {
  const { exec, calls } = fakeExec({
    openSource: { ok: true, vulnerabilities: [] },
    code: { runs: [{ results: [] }] },
    iac: [{ infrastructureAsCodeIssues: [] }]
  });
  const result = await runSnyk({ workspacePath: '/repo', token: TOKEN, includeCode: true, includeIaC: true, runner: LOCAL_RUNNER, exec });
  assert.equal(calls.length, 3);
  assert.deepEqual(result.payload.capabilities, { openSource: true, code: true, iac: true });
});

test('l’annulation remonte immédiatement sans conteneur orphelin', async () => {
  const controller = new AbortController();
  const removals = [];
  const exec = async (executable, args) => {
    if (args.includes('rm')) { removals.push(args); return { stdout: '', stderr: '' }; }
    controller.abort();
    throw cliError({ message: 'aborted' });
  };
  await assert.rejects(
    () => runSnyk({ workspacePath: '/repo', token: TOKEN, mode: 'docker', runner: DOCKER_RUNNER, signal: controller.signal, exec }),
    (error) => error.code === 'CANCELED'
  );
  assert.equal(removals.length, 1);
  assert.ok(removals[0].includes('-f'));
});

test('le jeton n’apparaît jamais dans les arguments réellement exécutés', async () => {
  const { exec, calls } = fakeExec();
  await runSnyk({ workspacePath: '/repo', token: TOKEN, mode: 'docker', runner: DOCKER_RUNNER, exec });
  assert.ok(!JSON.stringify(calls.map((call) => call.args)).includes(TOKEN));
  assert.equal(calls[0].options.env.SNYK_TOKEN, TOKEN);
});

test('le délai maximal et le workspace sont transmis au processus', async () => {
  const { exec, calls } = fakeExec();
  await runSnyk({ workspacePath: '/repo', token: TOKEN, timeoutMs: 12345, runner: LOCAL_RUNNER, exec });
  assert.equal(calls[0].options.timeout, 12345);
  assert.equal(calls[0].options.windowsHide, true);
  assert.ok(!('shell' in calls[0].options));
});
