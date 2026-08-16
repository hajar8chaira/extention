const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const {
  SonarError, normalizeHostUrl, sonarUrl, sonarRequest,
  checkServerStatus, waitForTask, fetchIssues, fetchHotspots, fetchRuleMetadata, ruleSecurityStandards
} = require('../src/sonarqube-api');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';

/** Starts a throwaway SonarQube stub bound to the loopback interface. */
async function startServer(handler) {
  const received = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    received.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), headers: request.headers });
    handler(url, request, response, received.length);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, received, hostUrl: `http://127.0.0.1:${server.address().port}` };
}

function json(response, payload, statusCode = 200) {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

test('normalise l’URL du serveur et refuse les protocoles non HTTP', () => {
  assert.equal(normalizeHostUrl('http://127.0.0.1:9000/'), 'http://127.0.0.1:9000');
  assert.equal(normalizeHostUrl(' https://sonar.example.com/sonar/ '), 'https://sonar.example.com/sonar');
  assert.throws(() => normalizeHostUrl(''), (error) => error.code === 'CONFIG_ERROR');
  assert.throws(() => normalizeHostUrl('ftp://host'), (error) => error.code === 'CONFIG_ERROR');
  assert.throws(() => normalizeHostUrl('pas-une-url'), (error) => error.code === 'CONFIG_ERROR');
});

test('construit les URL d’API sans jamais placer de valeur vide', () => {
  const url = sonarUrl('http://127.0.0.1:9000', 'api/issues/search', { componentKeys: 'demo', types: '', p: 2 });
  assert.equal(url.pathname, '/api/issues/search');
  assert.equal(url.searchParams.get('componentKeys'), 'demo');
  assert.equal(url.searchParams.has('types'), false);
  assert.equal(url.searchParams.get('p'), '2');
});

test('transmet le jeton uniquement dans l’en-tête Authorization', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, { status: 'UP', version: '25.1' }));
  t.after(() => server.close());
  await sonarRequest(hostUrl, 'api/system/status', { token: TOKEN });
  assert.equal(received[0].headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(JSON.stringify(received[0].query).includes(TOKEN), false);
  assert.equal(received[0].path.includes(TOKEN), false);
});

test('vérifie l’état du serveur et refuse un serveur en cours de démarrage', async (t) => {
  const states = ['UP', 'STARTING'];
  const { server, hostUrl } = await startServer((url, request, response, call) => json(response, { status: states[call - 1], version: '25.1' }));
  t.after(() => server.close());
  assert.deepEqual(await checkServerStatus(hostUrl), { status: 'UP', version: '25.1' });
  await assert.rejects(() => checkServerStatus(hostUrl), (error) => error.code === 'SERVER_UNAVAILABLE');
});

test('classe les erreurs d’authentification 401 et 403 sans révéler le jeton', async (t) => {
  const codes = [401, 403];
  const { server, hostUrl } = await startServer((url, request, response, call) => json(response, { errors: [{ msg: 'nope' }] }, codes[call - 1]));
  t.after(() => server.close());
  for (const _ of codes) {
    await assert.rejects(
      () => sonarRequest(hostUrl, 'api/issues/search', { token: TOKEN }),
      (error) => error.code === 'AUTH_ERROR' && !error.message.includes(TOKEN)
    );
  }
});

test('signale un serveur injoignable et une erreur interne distinctement', async (t) => {
  const { server, hostUrl } = await startServer((url, request, response) => json(response, {}, 503));
  t.after(() => server.close());
  await assert.rejects(() => sonarRequest(hostUrl, 'api/system/status'), (error) => error.code === 'SERVER_UNAVAILABLE');
  // Port fermé : aucune connexion possible.
  await assert.rejects(
    () => sonarRequest('http://127.0.0.1:1', 'api/system/status', { timeoutMs: 2000 }),
    (error) => error.code === 'SERVER_UNAVAILABLE'
  );
});

test('applique un timeout borné lorsque le serveur ne répond jamais', async (t) => {
  const { server, hostUrl } = await startServer(() => { /* volontairement sans réponse */ });
  t.after(() => server.close());
  await assert.rejects(
    () => sonarRequest(hostUrl, 'api/system/status', { timeoutMs: 150 }),
    (error) => error.code === 'TIMEOUT'
  );
});

test('attend la fin du traitement serveur puis renvoie SUCCESS', async (t) => {
  const statuses = ['PENDING', 'IN_PROGRESS', 'SUCCESS'];
  const { server, received, hostUrl } = await startServer((url, request, response, call) =>
    json(response, { task: { id: 'AY1', status: statuses[call - 1], analysisId: 'A42' } }));
  t.after(() => server.close());
  const result = await waitForTask(hostUrl, 'AY1', { token: TOKEN, pollIntervalMs: 5 });
  assert.equal(result.status, 'SUCCESS');
  assert.equal(result.analysisId, 'A42');
  assert.equal(received.length, 3);
  assert.equal(received[0].query.id, 'AY1');
});

test('propage FAILED et CANCELED comme des états distincts', async (t) => {
  const tasks = [
    { status: 'FAILED', errorMessage: 'quality profile missing' },
    { status: 'CANCELED' }
  ];
  const { server, hostUrl } = await startServer((url, request, response, call) => json(response, { task: tasks[call - 1] }));
  t.after(() => server.close());
  await assert.rejects(
    () => waitForTask(hostUrl, 'AY1', { pollIntervalMs: 5 }),
    (error) => error.code === 'FAILED' && error.message.includes('quality profile missing')
  );
  await assert.rejects(() => waitForTask(hostUrl, 'AY1', { pollIntervalMs: 5 }), (error) => error.code === 'CANCELED');
});

test('borne le polling et n’attend jamais indéfiniment', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, { task: { status: 'IN_PROGRESS' } }));
  t.after(() => server.close());
  // Le plancher volontaire de 1 s empêche qu’un timeout nul rende le polling inutile.
  await assert.rejects(
    () => waitForTask(hostUrl, 'AY1', { timeoutMs: 0, pollIntervalMs: 200 }),
    (error) => error.code === 'TIMEOUT'
  );
  assert.ok(received.length >= 1 && received.length <= 12, `polling borné, ${received.length} appel(s)`);
});

test('refuse de sonder une tâche sans identifiant', async () => {
  await assert.rejects(() => waitForTask('http://127.0.0.1:9000', ''), (error) => error.code === 'FAILED');
});

test('interrompt le polling dès que l’AbortSignal est déclenché', async (t) => {
  const { server, hostUrl } = await startServer((url, request, response) => json(response, { task: { status: 'IN_PROGRESS' } }));
  t.after(() => server.close());
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 30);
  await assert.rejects(
    () => waitForTask(hostUrl, 'AY1', { timeoutMs: 10000, pollIntervalMs: 15, signal: controller.signal }),
    (error) => error.code === 'CANCELED'
  );
});

test('interrompt une requête HTTP en cours sur annulation', async (t) => {
  const { server, hostUrl } = await startServer(() => { /* jamais de réponse */ });
  t.after(() => server.close());
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 25);
  await assert.rejects(
    () => sonarRequest(hostUrl, 'api/system/status', { timeoutMs: 10000, signal: controller.signal }),
    (error) => error.code === 'CANCELED'
  );
});

test('pagine la récupération des issues jusqu’au total annoncé', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => {
    const page = Number(url.searchParams.get('p'));
    const pageSize = Number(url.searchParams.get('ps'));
    const total = 5;
    const start = (page - 1) * pageSize;
    json(response, {
      total,
      issues: Array.from({ length: Math.max(0, Math.min(pageSize, total - start)) }, (_, index) => ({ key: `I${start + index}`, rule: 'js:S1', component: 'demo:a.js' })),
      components: [{ key: 'demo:a.js', path: 'a.js' }]
    });
  });
  t.after(() => server.close());
  const result = await fetchIssues(hostUrl, 'demo', { token: TOKEN, pageSize: 2 });
  assert.equal(result.issues.length, 5);
  assert.deepEqual(result.issues.map((issue) => issue.key), ['I0', 'I1', 'I2', 'I3', 'I4']);
  assert.equal(result.components.length, 1);
  assert.equal(received.length, 3);
  assert.equal(received[0].query.resolved, 'false');
  assert.equal(received[0].query.types, 'VULNERABILITY,BUG');
});

test('s’arrête proprement quand une page revient vide', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, { total: 99, issues: [] }));
  t.after(() => server.close());
  const result = await fetchIssues(hostUrl, 'demo', { pageSize: 10 });
  assert.equal(result.issues.length, 0);
  assert.equal(received.length, 1);
});

test('signale une pagination tronquée au-delà de la limite SonarQube', async (t) => {
  const { server, hostUrl } = await startServer((url, request, response) => json(response, {
    total: 12000,
    issues: Array.from({ length: 500 }, (_, index) => ({ key: `K${url.searchParams.get('p')}-${index}` }))
  }));
  t.after(() => server.close());
  const result = await fetchIssues(hostUrl, 'demo', { pageSize: 500 });
  assert.equal(result.truncated, true);
  assert.equal(result.issues.length, 10000);
});

test('récupère les security hotspots avec leur pagination propre', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, {
    paging: { pageIndex: 1, pageSize: 500, total: 1 },
    hotspots: [{ key: 'H1', ruleKey: 'js:S2076', component: 'demo:a.js', vulnerabilityProbability: 'HIGH' }],
    components: [{ key: 'demo:a.js', path: 'a.js' }]
  }));
  t.after(() => server.close());
  const result = await fetchHotspots(hostUrl, 'demo', { token: TOKEN });
  assert.equal(result.hotspots.length, 1);
  assert.equal(received[0].query.projectKey, 'demo');
  assert.equal(received[0].query.status, 'TO_REVIEW');
});

test('résout chaque règle via api/rules/show, une clé par appel', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, {
    rule: { key: url.searchParams.get('key'), name: 'règle', securityStandards: ['cwe:89', 'owaspTop10:a3'] }
  }));
  t.after(() => server.close());
  const rules = await fetchRuleMetadata(hostUrl, ['js:S1', 'js:S2', 'js:S1'], { token: TOKEN });
  assert.equal(rules.size, 2, 'les clés dupliquées ne sont demandées qu’une fois');
  assert.deepEqual(rules.get('js:S1').securityStandards, ['cwe:89', 'owaspTop10:a3']);
  assert.equal(received[0].path, '/api/rules/show');
  assert.deepEqual(received.map((entry) => entry.query.key).sort(), ['js:S1', 'js:S2']);
});

test('déduit le CWE depuis la description quand securityStandards est absent', async (t) => {
  // Comportement réel de SonarQube Community Build 26.x.
  const { server, hostUrl } = await startServer((url, request, response) => json(response, {
    rule: {
      key: 'javascript:S4790', name: 'Weak hashing', sysTags: ['cwe', 'former-hotspot'],
      descriptionSections: [{ key: 'root_cause', content: '<p>Voir <a>CWE-1240</a> et CWE-328.</p>' }]
    }
  }));
  t.after(() => server.close());
  const rules = await fetchRuleMetadata(hostUrl, ['javascript:S4790'], { token: TOKEN });
  assert.deepEqual(rules.get('javascript:S4790').securityStandards, ['cwe:1240', 'cwe:328']);
});

test('n’invente aucun CWE pour une règle non marquée cwe', () => {
  assert.deepEqual(ruleSecurityStandards({ sysTags: ['clumsy'], descriptionSections: [{ content: 'CWE-79 cité en passant' }] }), []);
  assert.deepEqual(ruleSecurityStandards({}), []);
  assert.deepEqual(ruleSecurityStandards({ securityStandards: ['cwe:22'] }), ['cwe:22']);
});

test('une règle introuvable n’interrompt pas la récupération des autres', async (t) => {
  const { server, hostUrl } = await startServer((url, request, response) => {
    if (url.searchParams.get('key') === 'js:absente') return json(response, { errors: [] }, 404);
    json(response, { rule: { key: url.searchParams.get('key'), name: 'ok' } });
  });
  t.after(() => server.close());
  const rules = await fetchRuleMetadata(hostUrl, ['js:absente', 'js:S1'], { token: TOKEN });
  assert.equal(rules.size, 1);
  assert.equal(rules.get('js:S1').name, 'ok');
});

test('un refus d’authentification interrompt la récupération des règles', async (t) => {
  const { server, hostUrl } = await startServer((url, request, response) => json(response, {}, 401));
  t.after(() => server.close());
  await assert.rejects(() => fetchRuleMetadata(hostUrl, ['js:S1'], { token: TOKEN }), (error) => error.code === 'AUTH_ERROR');
});

test('borne le nombre de règles résolues', async (t) => {
  const { server, received, hostUrl } = await startServer((url, request, response) => json(response, { rule: { key: url.searchParams.get('key') } }));
  t.after(() => server.close());
  await fetchRuleMetadata(hostUrl, Array.from({ length: 50 }, (_, index) => `js:S${index}`), { token: TOKEN, maxRules: 7 });
  assert.equal(received.length, 7);
});

test('ne demande aucune règle lorsque la liste est vide', async () => {
  const rules = await fetchRuleMetadata('http://127.0.0.1:1', [], {});
  assert.equal(rules.size, 0);
});

test('SonarError normalise un code inconnu vers FAILED', () => {
  assert.equal(new SonarError('N_IMPORTE_QUOI', 'test').code, 'FAILED');
  assert.equal(new SonarError('TIMEOUT', 'test').code, 'TIMEOUT');
});
