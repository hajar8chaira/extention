const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  SCANNER_IMAGE, CONTAINER_SOURCE, CONTAINER_WORK, DEFAULT_EXCLUSIONS,
  runSonarQube, resolveRunner, resolveInvocation, scannerCandidates, localInvocation,
  parseScannerVersion, sanitizeProjectKey, projectKeyFromGitRemote,
  parseScannerProperties, resolveProjectIdentity, mergeExclusions, analysisProperties,
  dockerArgs, dockerHostUrl, sonarEnvFileContent, maskToken
} = require('../src/sonarqube');
const {
  normalizeSonarQubeOutput, sonarQubeSeverity, sonarQubeCwe, sonarQubeComponentPath
} = require('../src/findings');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';
const LOCAL_RUNNER = { mode: 'local', local: { executable: '/usr/bin/sonar-scanner', prefixArgs: [], version: '6.2' } };

function workspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sonar-ws-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
  return root;
}

/** Minimal SonarQube API double: no network, deterministic states. */
function fakeApi(overrides = {}) {
  return {
    checkServerStatus: async () => ({ status: 'UP', version: '25.1' }),
    waitForTask: async () => ({ status: 'SUCCESS', analysisId: 'A1' }),
    fetchIssues: async () => ({ issues: [], components: [], total: 0, truncated: false }),
    fetchHotspots: async () => ({ hotspots: [], components: [], total: 0, truncated: false }),
    fetchRuleMetadata: async () => new Map(),
    ...overrides
  };
}

/** Fake scanner process that writes the report-task.txt the real CLI produces. */
function fakeExec({ ceTaskId = 'AY-task-1', projectKey = 'demo', fail } = {}) {
  const calls = [];
  const exec = async (executable, args, options) => {
    calls.push({ executable, args, options });
    if (fail) throw fail;
    const workDirectory = String(args.find((arg) => String(arg).startsWith('-Dsonar.working.directory=')) || '').split('=')[1];
    const hostDirectory = options?.__hostWorkDirectory || workDirectory;
    fs.writeFileSync(path.join(hostDirectory, 'report-task.txt'), `projectKey=${projectKey}\nceTaskId=${ceTaskId}\ndashboardUrl=http://127.0.0.1:9000/dashboard\n`);
    return { stdout: '', stderr: '' };
  };
  return { exec, calls };
}

// ---------------------------------------------------------------- détection

test('propose les bons binaires SonarScanner par plateforme', () => {
  assert.deepEqual(scannerCandidates('win32'), ['sonar-scanner.bat', 'sonar-scanner.cmd', 'sonar-scanner']);
  assert.deepEqual(scannerCandidates('linux'), ['sonar-scanner']);
  assert.deepEqual(scannerCandidates('darwin'), ['sonar-scanner']);
});

test('invoque un wrapper .bat via l’interpréteur sans shell:true', () => {
  const windows = localInvocation('C:\\sonar\\bin\\sonar-scanner.bat', 'win32');
  assert.match(windows.executable, /cmd\.exe$/i);
  assert.deepEqual(windows.prefixArgs, ['/d', '/s', '/c', 'C:\\sonar\\bin\\sonar-scanner.bat']);
  const posix = localInvocation('/usr/local/bin/sonar-scanner', 'linux');
  assert.equal(posix.executable, '/usr/local/bin/sonar-scanner');
  assert.deepEqual(posix.prefixArgs, []);
  // Un .exe Windows reste appelé directement.
  assert.deepEqual(localInvocation('C:\\sonar\\sonar-scanner.exe', 'win32').prefixArgs, []);
});

test('extrait la version depuis la bannière du CLI', () => {
  assert.equal(parseScannerVersion('INFO: SonarScanner 6.2.1.4610'), '6.2.1.4610');
  assert.equal(parseScannerVersion('SonarScanner CLI v5.0.1'), '5.0.1');
  assert.equal(parseScannerVersion('commande introuvable'), '');
});

test('mode auto : utilise le scanner local lorsqu’il est présent', async () => {
  const runner = await resolveRunner('auto', { detect: async () => LOCAL_RUNNER.local, hasCommand: async () => false });
  assert.equal(runner.mode, 'local');
  assert.equal(runner.local.version, '6.2');
});

test('mode auto : bascule sur Docker lorsque le scanner local est absent', async () => {
  const runner = await resolveRunner('auto', { detect: async () => null, hasCommand: async (command) => command === 'docker' });
  assert.equal(runner.mode, 'docker');
});

test('mode auto : erreur claire quand ni le CLI ni Docker ne sont disponibles', async () => {
  await assert.rejects(
    () => resolveRunner('auto', { detect: async () => null, hasCommand: async () => false }),
    (error) => error.code === 'CONFIG_ERROR' && /Ni SonarScanner local ni Docker/.test(error.message)
  );
});

test('mode local : refuse de basculer sur Docker', async () => {
  await assert.rejects(
    () => resolveRunner('local', { detect: async () => null, hasCommand: async () => true }),
    (error) => error.code === 'CONFIG_ERROR' && /SonarScanner local est introuvable/.test(error.message)
  );
});

test('mode docker : n’essaie jamais le scanner local', async () => {
  let detectCalled = false;
  const runner = await resolveRunner('docker', {
    detect: async () => { detectCalled = true; return LOCAL_RUNNER.local; },
    hasCommand: async () => true
  });
  assert.equal(runner.mode, 'docker');
  assert.equal(detectCalled, false);
});

// ------------------------------------------------------------- arguments

test('monte le workspace en lecture seule et isole le répertoire de travail', () => {
  const args = dockerArgs('/repo', ['-Dsonar.projectKey=demo'], { envFile: '/tmp/x/sonar.env', workHostDirectory: '/tmp/x' });
  assert.ok(args.includes(`${path.resolve('/repo')}:${CONTAINER_SOURCE}:ro`));
  assert.ok(args.includes(`/tmp/x:${CONTAINER_WORK}:rw`));
  assert.ok(args.includes(SCANNER_IMAGE));
  assert.deepEqual(args.slice(args.indexOf('--env-file'), args.indexOf('--env-file') + 2), ['--env-file', '/tmp/x/sonar.env']);
  // Aucun privilège supplémentaire ni socket Docker exposé.
  assert.equal(args.includes('--privileged'), false);
  assert.equal(args.some((arg) => String(arg).includes('docker.sock')), false);
  assert.equal(args.some((arg) => String(arg).includes('/:/')), false);
});

test('atteint un serveur local depuis le conteneur via la passerelle Docker', () => {
  assert.equal(dockerHostUrl('http://127.0.0.1:9000'), 'http://host.docker.internal:9000');
  assert.equal(dockerHostUrl('http://localhost:9000/'), 'http://host.docker.internal:9000');
  // Un serveur distant ne doit jamais être réécrit.
  assert.equal(dockerHostUrl('https://sonar.example.com'), 'https://sonar.example.com');
  assert.ok(dockerArgs('/repo', [], { workHostDirectory: '/tmp/x' }).includes('host.docker.internal:host-gateway'));
});

test('conserve l’URL configurée pour les appels API depuis l’hôte', async (t) => {
  const root = workspace(t);
  const queried = [];
  await runSonarQube({
    workspacePath: root, mode: 'local', hostUrl: 'http://127.0.0.1:9000', token: TOKEN,
    runner: LOCAL_RUNNER, exec: fakeExec().exec, gitRemote: '',
    api: fakeApi({ fetchIssues: async (host) => { queried.push(host); return { issues: [], components: [], total: 0, truncated: false }; } })
  });
  assert.deepEqual(queried, ['http://127.0.0.1:9000']);
});

test('construit les propriétés minimales et applique les exclusions', () => {
  const properties = analysisProperties({
    projectKey: 'demo', projectName: 'Demo',
    exclusions: mergeExclusions(['custom/**']),
    workingDirectory: '/tmp/work'
  });
  assert.ok(properties.includes('-Dsonar.projectKey=demo'));
  assert.ok(properties.includes('-Dsonar.projectName=Demo'));
  assert.ok(properties.includes('-Dsonar.sources=.'));
  assert.ok(properties.includes('-Dsonar.sourceEncoding=UTF-8'));
  assert.ok(properties.includes('-Dsonar.working.directory=/tmp/work'));
  const exclusions = properties.find((value) => value.startsWith('-Dsonar.exclusions='));
  for (const pattern of ['**/node_modules/**', '**/dist/**', '**/coverage/**', '**/security-reports/**', '**/.codex-backups/**', '**/*.min.js', 'custom/**']) {
    assert.ok(exclusions.includes(pattern), `exclusion manquante : ${pattern}`);
  }
});

test('respecte un sonar-project.properties existant sans le remplacer', () => {
  const properties = analysisProperties({
    projectKey: 'ignored', projectName: 'ignored',
    exclusions: DEFAULT_EXCLUSIONS, workingDirectory: '/tmp/work', hasPropertiesFile: true
  });
  assert.deepEqual(properties, ['-Dsonar.working.directory=/tmp/work', '-Dsonar.scm.disabled=true']);
});

test('assemble la commande locale à partir du runner résolu', async () => {
  const invocation = await resolveInvocation('local', '/repo', ['-Dsonar.projectKey=demo'], { runner: LOCAL_RUNNER });
  assert.equal(invocation.mode, 'local');
  assert.equal(invocation.executable, '/usr/bin/sonar-scanner');
  assert.deepEqual(invocation.args, ['-Dsonar.projectKey=demo']);
});

// -------------------------------------------------------- identité projet

test('nettoie une clé de projet vers les caractères acceptés par SonarQube', () => {
  assert.equal(sanitizeProjectKey('mon projet #1'), 'mon-projet-1');
  assert.equal(sanitizeProjectKey('  a.b:c-d_e  '), 'a.b:c-d_e');
  // SonarQube exige au moins un caractère non numérique.
  assert.equal(sanitizeProjectKey('12345'), '');
  assert.equal(sanitizeProjectKey(''), '');
});

test('dérive la clé de projet depuis le remote Git plutôt que du chemin absolu', () => {
  assert.equal(projectKeyFromGitRemote('https://github.com/hajar8chaira/extention.git'), 'hajar8chaira_extention');
  assert.equal(projectKeyFromGitRemote('git@github.com:owner/repo.git'), 'owner_repo');
  assert.equal(projectKeyFromGitRemote('https://gitlab.com/group/sub/repo'), 'sub_repo');
  assert.equal(projectKeyFromGitRemote(''), '');
});

test('applique l’ordre de priorité configuration → properties → git → dossier', () => {
  const base = { gitRemote: 'git@github.com:owner/repo.git', workspacePath: '/home/dev/mon-app' };
  assert.equal(resolveProjectIdentity({ ...base, configuredKey: 'explicite', propertiesKey: 'depuis-fichier' }).projectKey, 'explicite');
  assert.equal(resolveProjectIdentity({ ...base, propertiesKey: 'depuis-fichier' }).projectKey, 'depuis-fichier');
  assert.equal(resolveProjectIdentity(base).projectKey, 'owner_repo');
  assert.equal(resolveProjectIdentity({ workspacePath: '/home/dev/mon-app' }).projectKey, 'mon-app');
  assert.throws(() => resolveProjectIdentity({ workspacePath: '/123' }), (error) => error.code === 'CONFIG_ERROR');
});

test('lit le format key=value partagé par properties et report-task', () => {
  const parsed = parseScannerProperties('# commentaire\nsonar.projectKey=demo\nceTaskId=AY-1\n\nvide\nurl=http://x/y?a=b\n');
  assert.equal(parsed['sonar.projectKey'], 'demo');
  assert.equal(parsed.ceTaskId, 'AY-1');
  assert.equal(parsed.url, 'http://x/y?a=b');
  assert.equal(parsed.vide, undefined);
});

// ------------------------------------------------------------------ secret

test('écrit le jeton dans un env-file et jamais dans les arguments', () => {
  const content = sonarEnvFileContent('http://127.0.0.1:9000', TOKEN);
  assert.equal(content, `SONAR_HOST_URL=http://127.0.0.1:9000\nSONAR_TOKEN=${TOKEN}\n`);
  const args = dockerArgs('/repo', ['-Dsonar.projectKey=demo'], { envFile: '/tmp/x/sonar.env', workHostDirectory: '/tmp/x' });
  assert.equal(args.join(' ').includes(TOKEN), false);
  assert.throws(() => sonarEnvFileContent('http://x', 'jeton\ninjecté'), (error) => error.code === 'CONFIG_ERROR');
});

test('masque le jeton et tout motif de jeton SonarQube dans les textes', () => {
  assert.equal(maskToken(`erreur avec ${TOKEN} ici`, TOKEN), 'erreur avec *** ici');
  // Même sans connaître le jeton, les motifs SonarQube connus sont masqués.
  assert.equal(maskToken('fuite sqp_abcdef0123456789 dans un log'), 'fuite sqp_*** dans un log');
  assert.equal(maskToken('', TOKEN), '');
});

// ------------------------------------------------------- exécution complète

test('exécute le pipeline complet : preflight, scan, attente, récupération', async (t) => {
  const root = workspace(t);
  const { exec, calls } = fakeExec({ projectKey: 'mon-app' });
  const waited = [];
  const result = await runSonarQube({
    workspacePath: root, mode: 'local', hostUrl: 'http://127.0.0.1:9000/', token: TOKEN,
    runner: LOCAL_RUNNER, exec, gitRemote: '',
    api: fakeApi({
      waitForTask: async (host, taskId) => { waited.push(taskId); return { status: 'SUCCESS' }; },
      fetchIssues: async () => ({ issues: [{ key: 'I1', rule: 'js:S1', component: 'mon-app:a.js' }], components: [{ key: 'mon-app:a.js', path: 'a.js' }], total: 1, truncated: false }),
      fetchRuleMetadata: async () => new Map([['js:S1', { key: 'js:S1', name: 'Règle', securityStandards: ['cwe:79'] }]])
    })
  });
  assert.equal(result.mode, 'local');
  assert.equal(result.payload.projectKey, 'mon-app');
  assert.equal(result.payload.serverUrl, 'http://127.0.0.1:9000');
  assert.equal(result.payload.issues.length, 1);
  assert.deepEqual(waited, ['AY-task-1']);
  // Le jeton passe par l'environnement, jamais par la ligne de commande.
  assert.equal(calls[0].args.join(' ').includes(TOKEN), false);
  assert.equal(calls[0].options.env.SONAR_TOKEN, TOKEN);
});

test('n’écrit aucun artefact SonarScanner dans le dépôt analysé', async (t) => {
  const root = workspace(t);
  const { exec, calls } = fakeExec();
  await runSonarQube({ workspacePath: root, mode: 'local', token: TOKEN, runner: LOCAL_RUNNER, exec, gitRemote: '', api: fakeApi() });
  const workingDirectory = calls[0].args.find((arg) => String(arg).startsWith('-Dsonar.working.directory=')).split('=')[1];
  assert.equal(workingDirectory.startsWith(path.resolve(root)), false, 'le répertoire de travail doit rester hors du dépôt');
  assert.deepEqual(fs.readdirSync(root), []);
});

test('n’écrit jamais le jeton sur le disque en mode local', async (t) => {
  const root = workspace(t);
  const seen = [];
  const exec = async (executable, args, options) => {
    const workDirectory = String(args.find((arg) => String(arg).startsWith('-Dsonar.working.directory='))).split('=')[1];
    seen.push(...fs.readdirSync(workDirectory));
    fs.writeFileSync(path.join(workDirectory, 'report-task.txt'), 'projectKey=demo\nceTaskId=T1\n');
    return { stdout: '', stderr: '' };
  };
  await runSonarQube({ workspacePath: root, mode: 'local', token: TOKEN, runner: LOCAL_RUNNER, exec, gitRemote: '', api: fakeApi() });
  assert.deepEqual(seen, [], 'aucun env-file ne doit être créé pour le CLI local');
});

test('refuse de lancer le scanner quand le serveur est injoignable', async (t) => {
  const root = workspace(t);
  const { exec, calls } = fakeExec();
  const { SonarError } = require('../src/sonarqube-api');
  await assert.rejects(
    () => runSonarQube({
      workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec, gitRemote: '',
      api: fakeApi({ checkServerStatus: async () => { throw new SonarError('SERVER_UNAVAILABLE', 'injoignable'); } })
    }),
    (error) => error.code === 'SERVER_UNAVAILABLE'
  );
  assert.equal(calls.length, 0, 'aucun scan ne doit démarrer sans serveur');
});

test('exige un jeton avant toute analyse', async (t) => {
  const root = workspace(t);
  const { exec, calls } = fakeExec();
  await assert.rejects(
    () => runSonarQube({ workspacePath: root, token: '  ', runner: LOCAL_RUNNER, exec, gitRemote: '', api: fakeApi() }),
    (error) => error.code === 'AUTH_ERROR' && /Configurer le jeton SonarQube/.test(error.message)
  );
  assert.equal(calls.length, 0);
});

test('rejette une URL de serveur invalide sans appeler le réseau', async (t) => {
  const root = workspace(t);
  await assert.rejects(
    () => runSonarQube({ workspacePath: root, hostUrl: 'ftp://sonar', token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec().exec, gitRemote: '', api: fakeApi() }),
    (error) => error.code === 'CONFIG_ERROR'
  );
});

test('traduit un échec du scanner sans révéler le jeton', async (t) => {
  const root = workspace(t);
  const failure = Object.assign(new Error('boom'), { stderr: `ERROR: analyse impossible avec ${TOKEN}` });
  await assert.rejects(
    () => runSonarQube({ workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec({ fail: failure }).exec, gitRemote: '', api: fakeApi() }),
    (error) => error.code === 'FAILED' && !error.message.includes(TOKEN) && error.message.includes('***')
  );
});

test('convertit un refus d’authentification du scanner en AUTH_ERROR', async (t) => {
  const root = workspace(t);
  const failure = Object.assign(new Error('boom'), { stderr: 'ERROR: You are not authorized to run analysis' });
  await assert.rejects(
    () => runSonarQube({ workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec({ fail: failure }).exec, gitRemote: '', api: fakeApi() }),
    (error) => error.code === 'AUTH_ERROR'
  );
});

test('marque le scan comme annulé lorsque l’AbortSignal se déclenche', async (t) => {
  const root = workspace(t);
  const controller = new AbortController();
  const exec = async () => { controller.abort(); throw Object.assign(new Error('aborted'), { name: 'AbortError' }); };
  await assert.rejects(
    () => runSonarQube({ workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec, signal: controller.signal, gitRemote: '', api: fakeApi() }),
    (error) => error.code === 'CANCELED'
  );
});

test('propage une annulation survenue pendant le polling serveur', async (t) => {
  const root = workspace(t);
  const { SonarError } = require('../src/sonarqube-api');
  await assert.rejects(
    () => runSonarQube({
      workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec().exec, gitRemote: '',
      api: fakeApi({ waitForTask: async () => { throw new SonarError('CANCELED', 'Analyse SonarQube annulée.'); } })
    }),
    (error) => error.code === 'CANCELED'
  );
});

test('dégrade proprement quand les hotspots sont indisponibles', async (t) => {
  const root = workspace(t);
  const { SonarError } = require('../src/sonarqube-api');
  const result = await runSonarQube({
    workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec().exec, gitRemote: '',
    api: fakeApi({ fetchHotspots: async () => { throw new SonarError('FAILED', `endpoint absent ${TOKEN}`); } })
  });
  assert.equal(result.payload.hotspots.length, 0);
  assert.equal(result.payload.warnings.length, 1);
  assert.equal(result.payload.warnings[0].includes(TOKEN), false);
  assert.match(result.payload.warnings[0], /hotspots indisponibles/);
});

test('inclut les code smells uniquement lorsque la politique le demande', async (t) => {
  const root = workspace(t);
  const requested = [];
  const api = fakeApi({ fetchIssues: async (host, key, options) => { requested.push(options.types); return { issues: [], components: [], total: 0, truncated: false }; } });
  const base = { workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec: fakeExec().exec, gitRemote: '', api };
  await runSonarQube(base);
  await runSonarQube({ ...base, includeCodeSmells: true });
  assert.deepEqual(requested[0], ['VULNERABILITY', 'BUG']);
  assert.deepEqual(requested[1], ['VULNERABILITY', 'BUG', 'CODE_SMELL']);
});

test('lit la clé de projet depuis un sonar-project.properties existant', async (t) => {
  const root = workspace(t, { 'sonar-project.properties': 'sonar.projectKey=cle-du-depot\nsonar.sources=src\n' });
  const { exec, calls } = fakeExec({ projectKey: 'cle-du-depot' });
  const result = await runSonarQube({ workspacePath: root, token: TOKEN, runner: LOCAL_RUNNER, exec, gitRemote: 'git@github.com:owner/repo.git', api: fakeApi() });
  assert.equal(result.payload.projectKey, 'cle-du-depot');
  // Le fichier du dépôt fait autorité : aucune propriété concurrente n'est injectée.
  assert.equal(calls[0].args.some((arg) => String(arg).startsWith('-Dsonar.projectKey=')), false);
  assert.equal(fs.readFileSync(path.join(root, 'sonar-project.properties'), 'utf8').includes('sonar.projectKey=cle-du-depot'), true);
});

// ------------------------------------------------------------ normalisation

test('mappe les sévérités héritées SonarQube vers l’échelle Security Center', () => {
  assert.equal(sonarQubeSeverity({ severity: 'BLOCKER' }), 'CRITICAL');
  assert.equal(sonarQubeSeverity({ severity: 'CRITICAL' }), 'HIGH');
  assert.equal(sonarQubeSeverity({ severity: 'MAJOR' }), 'MEDIUM');
  assert.equal(sonarQubeSeverity({ severity: 'MINOR' }), 'LOW');
  assert.equal(sonarQubeSeverity({ severity: 'INFO' }), 'INFO');
  assert.equal(sonarQubeSeverity({}), 'MEDIUM');
});

test('privilégie les impacts clean-code et retient le plus élevé', () => {
  assert.equal(sonarQubeSeverity({ severity: 'MINOR', impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }] }), 'HIGH');
  assert.equal(sonarQubeSeverity({ impacts: [{ severity: 'LOW' }, { severity: 'BLOCKER' }] }), 'CRITICAL');
  assert.equal(sonarQubeSeverity({ severity: 'BLOCKER', impacts: [{ severity: 'LOW' }] }), 'LOW');
});

test('extrait les CWE depuis securityStandards en ignorant les autres normes', () => {
  assert.equal(sonarQubeCwe(['cwe:89', 'owaspTop10:a3', 'cwe:79', 'cwe:89']), 'CWE-89, CWE-79');
  assert.equal(sonarQubeCwe(['owaspTop10-2021:a1']), '');
  assert.equal(sonarQubeCwe(undefined), '');
});

test('résout le chemin d’un composant via la table ou la clé SonarQube', () => {
  const components = new Map([['demo:src/a.js', { key: 'demo:src/a.js', path: 'src/a.js' }]]);
  assert.equal(sonarQubeComponentPath('demo:src/a.js', components), 'src/a.js');
  assert.equal(sonarQubeComponentPath('demo:lib\\b.ts', components), 'lib/b.ts');
  assert.equal(sonarQubeComponentPath('demo', components), '');
});

test('normalise vulnérabilité, bug et code smell dans le modèle Security Center', () => {
  const findings = normalizeSonarQubeOutput({
    projectKey: 'demo',
    serverUrl: 'http://127.0.0.1:9000',
    components: [{ key: 'demo:src/a.js', path: 'src/a.js' }],
    rules: {
      'js:S2076': { key: 'js:S2076', name: 'Injection de commande', securityStandards: ['cwe:78'] },
      'js:S1848': { key: 'js:S1848', name: 'Objet inutilisé', securityStandards: [] }
    },
    issues: [
      { key: 'AY-1', rule: 'js:S2076', component: 'demo:src/a.js', type: 'VULNERABILITY', severity: 'BLOCKER', message: 'Commande construite dynamiquement', textRange: { startLine: 12, endLine: 12, startOffset: 4, endOffset: 40 }, status: 'OPEN', effort: '15min', tags: ['cwe', 'injection'], creationDate: '2026-08-01T10:00:00+0000' },
      { key: 'AY-2', rule: 'js:S1848', component: 'demo:src/a.js', type: 'CODE_SMELL', severity: 'MINOR', message: 'Objet créé pour rien', line: 30, impacts: [{ softwareQuality: 'MAINTAINABILITY', severity: 'LOW' }] }
    ]
  }, '/repo');

  const [vulnerability, smell] = findings;
  assert.equal(vulnerability.tool, 'SonarQube');
  assert.equal(vulnerability.ruleId, 'js:S2076');
  assert.equal(vulnerability.rawSeverity, 'CRITICAL');
  assert.equal(vulnerability.severity, 'error');
  assert.equal(vulnerability.category, 'security');
  assert.equal(vulnerability.cwe, 'CWE-78');
  assert.equal(vulnerability.file, 'src/a.js');
  assert.equal(vulnerability.absolutePath, path.resolve('/repo', 'src/a.js'));
  assert.equal(vulnerability.startLine, 11, 'les lignes Security Center sont indexées à zéro');
  assert.equal(vulnerability.startColumn, 4);
  assert.equal(vulnerability.endColumn, 40);
  assert.equal(vulnerability.unlocated, false);
  assert.deepEqual(vulnerability.tags, ['cwe', 'injection']);
  assert.equal(vulnerability.effort, '15min');
  assert.match(vulnerability.helpUri, /open=AY-1/);

  assert.equal(smell.category, 'maintainability');
  assert.equal(smell.rawSeverity, 'LOW');
  assert.equal(smell.startLine, 29);
});

test('conserve un finding sans ligne sans fabriquer de position source', () => {
  const [finding] = normalizeSonarQubeOutput({
    projectKey: 'demo',
    components: [],
    issues: [{ key: 'AY-3', rule: 'js:S1', component: 'demo', type: 'BUG', severity: 'MAJOR', message: 'Problème projet' }]
  }, '/repo');
  assert.equal(finding.file, '');
  assert.equal(finding.absolutePath, '', 'aucun chemin absolu ne doit être inventé');
  assert.equal(finding.startLine, 0);
  assert.equal(finding.unlocated, true);
  assert.equal(finding.category, 'reliability');
});

test('normalise les security hotspots avec leur probabilité d’exploitation', () => {
  const [hotspot] = normalizeSonarQubeOutput({
    projectKey: 'demo',
    serverUrl: 'http://127.0.0.1:9000',
    components: [{ key: 'demo:src/b.js', path: 'src/b.js' }],
    rules: { 'js:S4507': { key: 'js:S4507', name: 'Debug activé', securityStandards: ['cwe:489'] } },
    hotspots: [{ key: 'H-1', ruleKey: 'js:S4507', component: 'demo:src/b.js', vulnerabilityProbability: 'HIGH', securityCategory: 'others', status: 'TO_REVIEW', message: 'Vérifier ce point', line: 5 }]
  }, '/repo');
  assert.equal(hotspot.category, 'security-hotspot');
  assert.equal(hotspot.rawSeverity, 'HIGH');
  assert.equal(hotspot.cwe, 'CWE-489');
  assert.equal(hotspot.confidence, 'low', 'un hotspot est un point à revoir, pas une vulnérabilité confirmée');
  assert.equal(hotspot.vulnerabilityProbability, 'HIGH');
  assert.equal(hotspot.startLine, 4);
  assert.match(hotspot.helpUri, /security_hotspots/);
});

test('utilise la clé SonarQube comme fingerprint stable, sans numéro de ligne', () => {
  const build = (line) => normalizeSonarQubeOutput({
    projectKey: 'demo',
    components: [{ key: 'demo:src/a.js', path: 'src/a.js' }],
    issues: [{ key: 'AY-stable', rule: 'js:S1', component: 'demo:src/a.js', type: 'BUG', severity: 'MAJOR', message: 'x', line }]
  }, '/repo')[0];
  const before = build(10);
  const after = build(120);
  assert.equal(before.fingerprint, 'AY-stable');
  assert.equal(before.fingerprint, after.fingerprint, 'un déplacement de code ne doit pas créer un nouveau finding');
  assert.equal(before.id, after.id);
  assert.equal(before.id.includes('10'), false);
});

test('déduplique les résultats SonarQube et tolère un payload vide', () => {
  const duplicated = {
    projectKey: 'demo',
    components: [{ key: 'demo:a.js', path: 'a.js' }],
    issues: [
      { key: 'AY-1', rule: 'js:S1', component: 'demo:a.js', type: 'BUG', severity: 'MAJOR', message: 'x', line: 3 },
      { key: 'AY-2', rule: 'js:S1', component: 'demo:a.js', type: 'BUG', severity: 'MAJOR', message: 'x', line: 3 }
    ]
  };
  assert.equal(normalizeSonarQubeOutput(duplicated, '/repo').length, 1);
  assert.deepEqual(normalizeSonarQubeOutput({}, '/repo'), []);
  assert.deepEqual(normalizeSonarQubeOutput(undefined, '/repo'), []);
});

test('ignore les entrées SonarQube sans clé exploitable', () => {
  const findings = normalizeSonarQubeOutput({
    projectKey: 'demo', components: [],
    issues: [{ rule: 'js:S1', component: 'demo' }, null],
    hotspots: [{ ruleKey: 'js:S2' }]
  }, '/repo');
  assert.deepEqual(findings, []);
});
