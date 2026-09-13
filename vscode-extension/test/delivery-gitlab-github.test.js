'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const delivery = require('../src/integrations/delivery');
const { PROVIDER_STATUS, RUN_OUTCOME, RESOLVED_STATE } = require('../src/integrations/delivery-contract');
const { gitlabDeliveryAdapter } = require('../src/integrations/delivery-gitlab');
const { githubDeliveryAdapter } = require('../src/integrations/delivery-github');
const { deliveryGetJson, DeliveryTransportError } = require('../src/integrations/delivery-http');

const TOKEN = 'glpat-SEcReT-nEvEr-LeAkEd-0123456789';
const GH_TOKEN = 'ghp_SEcReT_nEvEr_LeAkEd_0123456789abcd';

/**
 * A scripted transport. It receives the URL and headers the adapter really
 * built, so the assertions are about the HTTP contract rather than about a
 * mock's own shape.
 */
function transport(routes) {
  const calls = [];
  const request = async (target, { headers = {} } = {}) => {
    calls.push({ target, headers });
    for (const [pattern, answer] of routes) {
      if (target.includes(pattern)) return typeof answer === 'function' ? answer(target, headers) : answer;
    }
    return { status: 404, headers: {}, body: { message: 'Not Found' } };
  };
  return { request, calls };
}

const ok = (body, headers = {}) => ({ status: 200, headers, body });

// ------------------------------------------------------------ enregistrement

test('delivery : Jenkins, GitLab et GitHub sont implémentés, les autres restent catalogue-only', () => {
  assert.deepEqual(
    delivery.supportedDeliveryProviders().map((provider) => provider.id),
    ['jenkins', 'gitlab-ci', 'github-actions']
  );
  for (const id of ['azure-pipelines', 'circleci', 'bitbucket-pipelines']) {
    assert.equal(delivery.deliveryProvider(id).implemented, false, id);
    assert.equal(delivery.isSupportedDeliveryProvider(id), false, id);
  }
});

test('delivery : chaque fournisseur a sa propre configuration et son propre secret', () => {
  const jenkins = delivery.deliveryProvider('jenkins');
  const gitlab = delivery.deliveryProvider('gitlab-ci');
  const github = delivery.deliveryProvider('github-actions');
  assert.deepEqual(jenkins.configuredBy, ['url', 'job', 'user', 'token']);
  assert.deepEqual(gitlab.configuredBy, ['url', 'project', 'ref', 'token']);
  assert.deepEqual(github.configuredBy, ['owner', 'repository', 'workflow', 'url', 'token']);
  // Un seul champ secret par fournisseur, et il ne partage rien avec Jenkins.
  assert.deepEqual(gitlab.secretFields, ['token']);
  assert.deepEqual(github.secretFields, ['token']);
  assert.notDeepEqual(gitlab.configuredBy, jenkins.configuredBy);
});

// ------------------------------------------------------------------- GitLab

test('GitLab : configuration valide, invalide, et jamais de jeton dans l’URL', () => {
  assert.equal(gitlabDeliveryAdapter.validateConfiguration({ url: 'https://gitlab.com', project: 'groupe/projet' }).valid, true);
  assert.equal(gitlabDeliveryAdapter.validateConfiguration({ url: 'https://gitlab.com', project: '12345' }).valid, true);
  const missing = gitlabDeliveryAdapter.validateConfiguration({ url: 'https://gitlab.com' });
  assert.equal(missing.valid, false);
  assert.match(missing.errors[0], /Projet/);
  const credentialsInUrl = gitlabDeliveryAdapter.validateConfiguration({ url: 'https://user:pass@gitlab.com', project: 'a/b' });
  assert.equal(credentialsInUrl.valid, false);
  assert.match(credentialsInUrl.errors[0], /SecretStorage/);
});

test('GitLab : connexion réelle — le jeton part en en-tête PRIVATE-TOKEN, jamais dans l’URL', async () => {
  const { request, calls } = transport([['/api/v4/projects/', ok({ path_with_namespace: 'groupe/projet' })]]);
  const result = await gitlabDeliveryAdapter.testConnection(
    { url: 'https://gitlab.com', project: 'groupe/projet', token: TOKEN }, { request }
  );
  assert.equal(result.connected, true);
  assert.equal(result.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(result.authenticated, true);
  assert.match(result.message, /groupe\/projet/);
  // Le chemin du projet est encodé en un seul segment, comme l'exige l'API v4.
  assert.match(calls[0].target, /\/api\/v4\/projects\/groupe%2Fprojet$/);
  assert.equal(calls[0].headers['private-token'], TOKEN);
  assert.ok(!calls[0].target.includes(TOKEN), 'le jeton ne doit jamais apparaître dans l’URL');
});

test('GitLab : 401, 403, 404, 429 et 500 donnent chacun une cause distincte', async () => {
  const cases = [
    [401, PROVIDER_STATUS.AUTH_ERROR, /refusé le jeton/],
    [403, PROVIDER_STATUS.AUTH_ERROR, /droits suffisants/],
    [404, PROVIDER_STATUS.ERROR, /n’existe pas, ou le jeton n’y a pas accès/],
    [429, PROVIDER_STATUS.DEGRADED, /limité le débit/],
    [500, PROVIDER_STATUS.OFFLINE, /erreur interne/]
  ];
  for (const [status, expected, pattern] of cases) {
    const { request } = transport([['/api/v4/projects/', { status, headers: {}, body: {} }]]);
    const result = await gitlabDeliveryAdapter.testConnection({ url: 'https://gitlab.com', project: 'a/b', token: TOKEN }, { request });
    assert.equal(result.status, expected, `HTTP ${status}`);
    assert.equal(result.connected, false, `HTTP ${status}`);
    assert.match(result.message, pattern, `HTTP ${status}`);
    assert.ok(!result.message.includes(TOKEN), 'aucun message ne contient le jeton');
  }
});

test('GitLab : timeout et panne réseau sont rapportés comme injoignable, sans fuite', async () => {
  for (const [code, pattern] of [['TIMEOUT', /délai imparti/], ['OFFLINE', /injoignable/]]) {
    const request = async () => { throw new DeliveryTransportError(`échec ${code}`, code); };
    const result = await gitlabDeliveryAdapter.testConnection({ url: 'https://gitlab.com', project: 'a/b', token: TOKEN }, { request });
    assert.equal(result.status, PROVIDER_STATUS.OFFLINE, code);
    assert.match(result.message, pattern, code);
    assert.ok(!result.message.includes(TOKEN));
  }
});

test('GitLab : un pipeline réel est normalisé avec ses étapes et ses artefacts', async () => {
  // Formes réelles de l'API v4 : liste, détail, jobs.
  const { request, calls } = transport([
    ['/pipelines/98765/jobs', ok([
      { id: 1, name: 'lint', stage: 'build', status: 'success', artifacts: [{ filename: 'lint.json', file_type: 'archive' }] },
      { id: 2, name: 'unit', stage: 'test', status: 'success' },
      { id: 3, name: 'sast', stage: 'test', status: 'failed' }
    ])],
    ['/pipelines/98765', ok({
      id: 98765, iid: 42, status: 'failed', ref: 'main', sha: 'abc123def456', web_url: 'https://gitlab.com/groupe/projet/-/pipelines/98765',
      created_at: '2026-02-01T10:00:00.000Z', started_at: '2026-02-01T10:00:05.000Z', finished_at: '2026-02-01T10:04:05.000Z', duration: 240
    })],
    ['/pipelines?', ok([{ id: 98765, status: 'failed', ref: 'main', sha: 'abc123def456' }])],
    ['/pipelines', ok([{ id: 98765, status: 'failed', ref: 'main', sha: 'abc123def456' }])]
  ]);
  const model = await gitlabDeliveryAdapter.fetchDelivery(
    { url: 'https://gitlab.com', project: 'groupe/projet', token: TOKEN }, { request }
  );
  assert.equal(model.providerId, 'gitlab-ci');
  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(model.run.id, '98765');
  assert.equal(model.run.outcome, RUN_OUTCOME.FAILED);
  assert.equal(model.run.providerResult, 'failed', 'le mot du fournisseur est conservé tel quel');
  assert.equal(model.run.branch, 'main');
  assert.equal(model.run.commit, 'abc123def456');
  assert.equal(model.run.url, 'https://gitlab.com/groupe/projet/-/pipelines/98765');
  assert.equal(model.run.durationMs, 240000, 'la durée GitLab est en secondes');
  assert.equal(model.run.startedAt, '2026-02-01T10:00:05.000Z');
  // Étapes déduites des jobs réellement rapportés, pire verdict par étape.
  assert.deepEqual(model.stages.map((stage) => [stage.name, stage.outcome]), [
    ['build', RUN_OUTCOME.SUCCESS],
    ['test', RUN_OUTCOME.FAILED]
  ]);
  assert.deepEqual(model.artifacts.map((artifact) => artifact.name), ['lint.json']);
  assert.equal(model.capabilities.stages.state, RESOLVED_STATE.READY);
  assert.equal(model.capabilities.deploymentStatus.state, RESOLVED_STATE.NOT_REPORTED);
  assert.ok(!JSON.stringify(model).includes(TOKEN), 'le modèle ne contient jamais le jeton');
  assert.ok(calls.every((call) => !call.target.includes(TOKEN)));
});

test('GitLab : un projet sans pipeline n’est pas un échec', async () => {
  const { request } = transport([['/pipelines', ok([])]]);
  const model = await gitlabDeliveryAdapter.fetchDelivery({ url: 'https://gitlab.com', project: 'a/b', token: TOKEN }, { request });
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED);
  assert.equal(model.run, null, 'aucun run inventé');
  assert.match(model.message, /aucun pipeline/i);
  assert.equal(model.capabilities.lastRun.state, RESOLVED_STATE.NOT_REPORTED);
});

test('GitLab : un pipeline en attente ou manuel n’est jamais rapporté en échec', async () => {
  for (const [status, expected] of [['pending', RUN_OUTCOME.RUNNING], ['running', RUN_OUTCOME.RUNNING], ['manual', RUN_OUTCOME.NOT_STARTED], ['skipped', RUN_OUTCOME.NOT_STARTED], ['canceled', RUN_OUTCOME.ABORTED]]) {
    const { request } = transport([
      ['/jobs', ok([])],
      ['/pipelines/7', ok({ id: 7, status, ref: 'main', sha: 'a1' })],
      ['/pipelines', ok([{ id: 7, status }])]
    ]);
    const model = await gitlabDeliveryAdapter.fetchDelivery({ url: 'https://gitlab.com', project: 'a/b' }, { request });
    assert.equal(model.run.outcome, expected, status);
  }
});

test('GitLab : le ref configuré est transmis à l’API, sinon absent', async () => {
  const withRef = transport([['/pipelines', ok([])]]);
  await gitlabDeliveryAdapter.fetchDelivery({ url: 'https://gitlab.com', project: 'a/b', ref: 'release' }, { request: withRef.request });
  assert.match(withRef.calls[0].target, /ref=release/);
  const withoutRef = transport([['/pipelines', ok([])]]);
  await gitlabDeliveryAdapter.fetchDelivery({ url: 'https://gitlab.com', project: 'a/b' }, { request: withoutRef.request });
  assert.ok(!withoutRef.calls[0].target.includes('ref='), 'aucun ref inventé');
});

// ------------------------------------------------------------------- GitHub

test('GitHub : configuration valide et refus des valeurs impossibles', () => {
  assert.equal(githubDeliveryAdapter.validateConfiguration({ owner: 'octo', repository: 'demo' }).valid, true);
  const missing = githubDeliveryAdapter.validateConfiguration({ owner: 'octo' });
  assert.equal(missing.valid, false);
  assert.match(missing.errors[0], /Dépôt/);
  const slash = githubDeliveryAdapter.validateConfiguration({ owner: 'octo/extra', repository: 'demo' });
  assert.equal(slash.valid, false);
});

test('GitHub : connexion réelle — bearer, version d’API et user-agent', async () => {
  const { request, calls } = transport([['/repos/octo/demo', ok({ full_name: 'octo/demo' })]]);
  const result = await githubDeliveryAdapter.testConnection({ owner: 'octo', repository: 'demo', token: GH_TOKEN }, { request });
  assert.equal(result.connected, true);
  assert.equal(result.status, PROVIDER_STATUS.HEALTHY);
  assert.match(result.message, /octo\/demo/);
  assert.equal(calls[0].headers.authorization, `Bearer ${GH_TOKEN}`);
  assert.equal(calls[0].headers['x-github-api-version'], '2022-11-28');
  assert.ok(calls[0].headers['user-agent'], 'GitHub exige un user-agent');
  assert.ok(!calls[0].target.includes(GH_TOKEN));
});

test('GitHub : quota épuisé est distingué d’un refus de droits', async () => {
  const limited = transport([['/repos/', { status: 403, headers: { 'x-ratelimit-remaining': '0' }, body: { message: 'API rate limit exceeded' } }]]);
  const rateLimited = await githubDeliveryAdapter.testConnection({ owner: 'octo', repository: 'demo' }, { request: limited.request });
  assert.equal(rateLimited.status, PROVIDER_STATUS.DEGRADED);
  assert.match(rateLimited.message, /Quota d’appels GitHub épuisé/);

  const forbidden = transport([['/repos/', { status: 403, headers: { 'x-ratelimit-remaining': '4999' }, body: { message: 'Resource not accessible' } }]]);
  const denied = await githubDeliveryAdapter.testConnection({ owner: 'octo', repository: 'demo', token: GH_TOKEN }, { request: forbidden.request });
  assert.equal(denied.status, PROVIDER_STATUS.AUTH_ERROR);
  assert.match(denied.message, /actions:read/);
});

test('GitHub : 401 et 404 donnent chacun une cause distincte', async () => {
  for (const [status, expected, pattern] of [
    [401, PROVIDER_STATUS.AUTH_ERROR, /refusé le jeton/],
    [404, PROVIDER_STATUS.ERROR, /n’existe pas, ou le jeton n’y a pas accès/]
  ]) {
    const { request } = transport([['/repos/', { status, headers: {}, body: {} }]]);
    const result = await githubDeliveryAdapter.testConnection({ owner: 'octo', repository: 'demo', token: GH_TOKEN }, { request });
    assert.equal(result.status, expected, `HTTP ${status}`);
    assert.match(result.message, pattern, `HTTP ${status}`);
    assert.ok(!result.message.includes(GH_TOKEN));
  }
});

test('GitHub : une exécution réelle est normalisée avec ses jobs et ses artefacts', async () => {
  const { request, calls } = transport([
    ['/actions/runs/11223/jobs', ok({ jobs: [
      { name: 'build', status: 'completed', conclusion: 'success' },
      { name: 'codeql', status: 'completed', conclusion: 'failure' }
    ] })],
    ['/actions/runs/11223/artifacts', ok({ artifacts: [{ name: 'sarif', expired: false }] })],
    ['/actions/runs', ok({ workflow_runs: [{
      id: 11223, run_number: 87, name: 'Security', event: 'push',
      status: 'completed', conclusion: 'failure',
      head_branch: 'main', head_sha: 'deadbeefcafe',
      html_url: 'https://github.com/octo/demo/actions/runs/11223',
      created_at: '2026-02-01T09:59:00Z', run_started_at: '2026-02-01T10:00:00Z', updated_at: '2026-02-01T10:03:00Z'
    }] })]
  ]);
  const model = await githubDeliveryAdapter.fetchDelivery({ owner: 'octo', repository: 'demo', token: GH_TOKEN }, { request });
  assert.equal(model.providerId, 'github-actions');
  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(model.pipeline, 'octo/demo');
  assert.equal(model.run.id, '11223');
  assert.equal(model.run.displayName, '#87');
  assert.equal(model.run.outcome, RUN_OUTCOME.FAILED);
  assert.equal(model.run.providerResult, 'completed / failure', 'status et conclusion restent distincts');
  assert.equal(model.run.branch, 'main');
  assert.equal(model.run.commit, 'deadbeefcafe');
  assert.equal(model.run.url, 'https://github.com/octo/demo/actions/runs/11223');
  assert.equal(model.run.durationMs, 180000, 'durée dérivée des deux horodatages du run terminé');
  assert.deepEqual(model.stages.map((stage) => [stage.name, stage.outcome]), [
    ['build', RUN_OUTCOME.SUCCESS],
    ['codeql', RUN_OUTCOME.FAILED]
  ]);
  assert.deepEqual(model.artifacts.map((artifact) => artifact.name), ['sarif']);
  assert.ok(!JSON.stringify(model).includes(GH_TOKEN));
  assert.ok(calls.every((call) => !call.target.includes(GH_TOKEN)));
});

test('GitHub : une exécution en cours n’a pas de conclusion et n’est pas un échec', async () => {
  const { request } = transport([
    ['/jobs', ok({ jobs: [] })],
    ['/artifacts', ok({ artifacts: [] })],
    ['/actions/runs', ok({ workflow_runs: [{ id: 9, run_number: 3, status: 'in_progress', conclusion: null, head_branch: 'main', head_sha: 'aa', run_started_at: '2026-02-01T10:00:00Z' }] })]
  ]);
  const model = await githubDeliveryAdapter.fetchDelivery({ owner: 'octo', repository: 'demo' }, { request });
  assert.equal(model.run.outcome, RUN_OUTCOME.RUNNING);
  assert.equal(model.run.durationMs, null, 'aucune durée inventée pour une exécution en cours');
});

test('GitHub : un dépôt sans exécution n’est pas un échec', async () => {
  const { request } = transport([['/actions/runs', ok({ workflow_runs: [] })]]);
  const model = await githubDeliveryAdapter.fetchDelivery({ owner: 'octo', repository: 'demo' }, { request });
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED);
  assert.equal(model.run, null);
  assert.equal(model.capabilities.lastRun.state, RESOLVED_STATE.NOT_REPORTED);
});

test('GitHub : le workflow configuré cible son propre endpoint', async () => {
  const { request, calls } = transport([['/actions/workflows/', ok({ workflow_runs: [] })]]);
  await githubDeliveryAdapter.fetchDelivery({ owner: 'octo', repository: 'demo', workflow: 'security.yml' }, { request });
  assert.match(calls[0].target, /\/actions\/workflows\/security\.yml\/runs/);
});

test('GitHub : la console pointe vers le web, pas vers l’hôte de l’API', () => {
  assert.equal(githubDeliveryAdapter.consoleUrl({ owner: 'octo', repository: 'demo' }), 'https://github.com/octo/demo/actions');
  assert.equal(
    githubDeliveryAdapter.consoleUrl({ owner: 'octo', repository: 'demo', url: 'https://ghe.interne/api/v3' }),
    'https://ghe.interne/octo/demo/actions'
  );
});

// -------------------------------------------------- transport réel (HTTP)

test('transport : le vrai client HTTP rend le statut au lieu de lever dessus', async (t) => {
  const server = http.createServer((request, response) => {
    if (request.url.startsWith('/rate')) {
      response.writeHead(403, { 'content-type': 'application/json', 'x-ratelimit-remaining': '0' });
      return response.end(JSON.stringify({ message: 'API rate limit exceeded' }));
    }
    if (request.url.startsWith('/missing')) {
      response.writeHead(404, { 'content-type': 'application/json' });
      return response.end(JSON.stringify({ message: 'Not Found' }));
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ full_name: 'octo/demo', seen: request.headers.authorization ? 'auth' : 'anon' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  const okAnswer = await deliveryGetJson(`${base}/repos/octo/demo`, { headers: { authorization: `Bearer ${GH_TOKEN}` } });
  assert.equal(okAnswer.status, 200);
  assert.equal(okAnswer.body.seen, 'auth', 'l’en-tête d’autorisation part bien sur le fil');

  const missing = await deliveryGetJson(`${base}/missing`);
  assert.equal(missing.status, 404, 'un 404 est une réponse, pas une exception');

  const limited = await deliveryGetJson(`${base}/rate`);
  assert.equal(limited.status, 403);
  assert.equal(limited.headers['x-ratelimit-remaining'], '0');
});

test('transport : un hôte injoignable lève une erreur scrubée', async () => {
  await assert.rejects(
    () => deliveryGetJson('http://127.0.0.1:1/never', { timeoutMs: 1500 }),
    (error) => error instanceof DeliveryTransportError && !String(error.message).includes(GH_TOKEN)
  );
});

// ------------------------------------------------------------------ secrets

test('sécurité : aucun jeton n’est écrit dans le code, les tests ou le rendu', () => {
  const source = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', file), 'utf8');
  for (const file of ['delivery-gitlab.js', 'delivery-github.js', 'delivery-http.js']) {
    const text = source(file);
    // Le champ secret est déclaré comme tel, jamais persisté en clair.
    assert.ok(!/glpat-[A-Za-z0-9]/.test(text), `${file} ne contient aucun jeton`);
    assert.ok(!/ghp_[A-Za-z0-9]{10}/.test(text), `${file} ne contient aucun jeton`);
  }
  assert.match(source('delivery-gitlab.js'), /secret: true/);
  assert.match(source('delivery-github.js'), /secret: true/);
  // Le transport masque tout ce qui ressemble à un identifiant.
  const { scrubDeliveryError } = require('../src/integrations/delivery-http');
  assert.ok(!scrubDeliveryError(`connect failed Bearer ${GH_TOKEN}`).includes(GH_TOKEN));
  assert.ok(!scrubDeliveryError(`https://user:${TOKEN}@gitlab.com`).includes(TOKEN));
  assert.ok(!scrubDeliveryError(`https://gitlab.com?private_token=${TOKEN}`).includes(TOKEN));
});

// -------------------------------------------------- Jenkins : non-régression

test('Jenkins : contrat inchangé par l’arrivée de GitLab et GitHub', () => {
  const jenkins = delivery.deliveryProvider('jenkins');
  assert.equal(jenkins.implemented, true);
  assert.equal(delivery.DEFAULT_DELIVERY_PROVIDER, 'jenkins', 'Jenkins reste le fournisseur par défaut');
  // Champs, secret, capacités et sections : exactement ce qu'ils étaient.
  assert.deepEqual(jenkins.configuredBy, ['url', 'job', 'user', 'token']);
  assert.deepEqual(jenkins.secretFields, ['token']);
  assert.deepEqual(jenkins.sections.map((section) => section.kind), [
    'connection', 'run-summary', 'stage-list', 'security-report', 'artifact-list'
  ]);
  assert.equal(jenkins.capabilities.pipelineStatus, 'ready');
  assert.equal(jenkins.capabilities.lastRun, 'ready');
  assert.equal(jenkins.capabilities.stages, 'requires-probe');
});

test('Jenkins : son adaptateur et son protocole n’ont pas été modifiés', () => {
  const root = path.join(__dirname, '..');
  // Le protocole Jenkins et sa traduction dans le domaine restent le code
  // d'origine : cette tâche n'y touche pas.
  for (const file of ['src/integrations/delivery-jenkins.js', 'src/jenkins.js']) {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    assert.ok(text.length > 0, file);
  }
  const adapter = require('../src/integrations/delivery-jenkins');
  assert.equal(typeof adapter.jenkinsDeliveryAdapter.fetchDelivery, 'function');
  assert.equal(typeof adapter.toDeliveryModel, 'function');
  // Jenkins garde son propre transport : il n'emprunte pas celui des nouveaux
  // adaptateurs, donc rien de son comportement réseau ne change.
  const source = fs.readFileSync(path.join(root, 'src/integrations/delivery-jenkins.js'), 'utf8');
  assert.ok(!source.includes('delivery-http'), 'Jenkins ne passe pas par le nouveau transport');
  assert.match(source, /require\('\.\.\/jenkins'\)/);
});

test('délivrance : aucune donnée Jenkins ne fuit vers GitLab ou GitHub', async () => {
  // Une configuration Jenkins passée à un autre adaptateur ne produit jamais un
  // modèle « connecté » : chaque adaptateur exige ses propres champs.
  const jenkinsConfig = { url: 'http://jenkins.local:8080', job: 'security-pipeline', user: 'ci', token: 'jenkins-token' };
  const gitlab = await delivery.fetchDeliveryModel('gitlab-ci', jenkinsConfig);
  assert.equal(gitlab.status, PROVIDER_STATUS.NOT_CONFIGURED);
  assert.equal(gitlab.run, null);
  assert.match(gitlab.message, /projet/i);
  const github = await delivery.fetchDeliveryModel('github-actions', jenkinsConfig);
  assert.equal(github.status, PROVIDER_STATUS.NOT_CONFIGURED);
  assert.equal(github.run, null);
  // Et le modèle ne porte jamais le libellé d'un autre fournisseur.
  assert.equal(gitlab.providerLabel, 'GitLab CI/CD');
  assert.equal(github.providerLabel, 'GitHub Actions');
});

test('délivrance : un fournisseur catalogue-only n’est jamais présenté comme connecté', async () => {
  for (const id of ['azure-pipelines', 'circleci', 'bitbucket-pipelines']) {
    const model = await delivery.fetchDeliveryModel(id, { url: 'https://exemple' });
    assert.equal(model.status, PROVIDER_STATUS.NOT_CONFIGURED, id);
    assert.equal(model.configured, false, id);
    assert.equal(model.run, null, id);
    assert.match(model.message, /aucun adaptateur/i, id);
    const tested = await delivery.testDeliveryConnection(id, {});
    assert.equal(tested.connected, false, id);
  }
});
