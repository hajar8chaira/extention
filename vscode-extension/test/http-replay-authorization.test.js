'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const {
  normalizeHar, normalizeHarEntry, replayScenario, replayAuthorization, replayOrigin,
  validateLocalUrl, validateCapturedUrl, isLocalScenarioHost, REPLAY_STATE
} = require('../src/http-scenarios');
const { validateHttpScenario } = require('../backend/contract');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const REMOTE = 'http://192.168.222.132:3000';
const scenarioFor = (url, method = 'GET', headers = {}) => ({ request: { url, method, headers }, response: {} });

// ------------------------------------------------------ IMPORT / CAPTURE

test('import : un HAR local et un HAR distant sont acceptés tous les deux', () => {
  const har = { log: { entries: [
    { request: { method: 'GET', url: 'http://127.0.0.1:3000/a', headers: [], queryString: [] }, response: { status: 200, headers: [], content: { text: '{}' } } },
    { request: { method: 'GET', url: `${REMOTE}/rest/products`, headers: [], queryString: [] }, response: { status: 200, headers: [], content: { text: '{}' } } },
    { request: { method: 'GET', url: 'https://preprod.interne.lan/api', headers: [], queryString: [] }, response: { status: 200, headers: [], content: { text: '{}' } } }
  ] } };
  const result = normalizeHar(har);
  assert.equal(result.scenarios.length, 3);
  assert.equal(result.rejected.length, 0);
  // La portée réelle est enregistrée, jamais affirmée « local » par défaut.
  assert.deepEqual(result.scenarios.map((entry) => entry.tags[1]), ['local', 'remote', 'remote']);
});

test('import : les protections structurelles et la rédaction sont intactes', () => {
  const entry = normalizeHarEntry({
    request: {
      method: 'POST', url: `${REMOTE}/rest/user/login`, queryString: [],
      headers: [{ name: 'Authorization', value: 'Bearer s3cr3t' }, { name: 'Cookie', value: 'token=abc' }, { name: 'Accept', value: 'application/json' }],
      postData: { text: '{"password":"p4ss"}' }
    },
    response: { status: 401, headers: [{ name: 'content-type', value: 'application/json' }], content: { text: '{}' } }
  }, 0);
  assert.equal(entry.request.headers.authorization, '[REDACTED]');
  assert.equal(entry.request.headers.cookie, '[REDACTED]');
  assert.equal(entry.request.headers.accept, 'application/json');
  assert.deepEqual(entry.request.sensitive_headers, ['authorization', 'cookie']);
  assert.equal(entry.response.statusCode, 401);
  assert.ok(entry.response.bodySha256);

  // Ce qui n'est pas une requête HTTP exploitable reste refusé.
  const refused = normalizeHar({ log: { entries: [
    { request: { method: 'GET', url: 'ftp://serveur/x', headers: [] }, response: { status: 200, headers: [], content: { text: '' } } },
    { request: { method: 'GET', url: 'pas-une-url', headers: [] }, response: { status: 200, headers: [], content: { text: '' } } },
    { request: { method: 'GET', url: '', headers: [] }, response: { status: 200, headers: [], content: { text: '' } } }
  ] } });
  assert.equal(refused.scenarios.length, 0);
  assert.equal(refused.rejected.length, 3);
  assert.throws(() => normalizeHar({ log: {} }), /log\.entries est absent/);
});

test('import : une capture Burp distante est stockable par le backend', () => {
  const remote = validateHttpScenario({ name: 'GET produits', source: 'burp', request: { method: 'GET', url: `${REMOTE}/rest/products` } });
  assert.equal(remote.scope, 'remote');
  assert.equal(remote.request.url, `${REMOTE}/rest/products`);
  const local = validateHttpScenario({ name: 'GET local', source: 'burp', request: { method: 'GET', url: 'http://127.0.0.1:3000/a' } });
  assert.equal(local.scope, 'local');
  for (const bad of ['ftp://serveur/x', 'pas-une-url']) {
    assert.throws(() => validateHttpScenario({ name: 'x', source: 'burp', request: { method: 'GET', url: bad } }));
  }
});

test('import : normaliser un HAR n’ouvre aucune connexion réseau', () => {
  const original = { httpRequest: http.request, httpGet: http.get };
  let calls = 0;
  http.request = () => { calls += 1; throw new Error('aucune requête ne doit partir d’un import'); };
  http.get = http.request;
  try {
    const result = normalizeHar({ log: { entries: [
      { request: { method: 'GET', url: `${REMOTE}/rest/products`, headers: [], queryString: [] }, response: { status: 200, headers: [], content: { text: '{}' } } }
    ] } });
    assert.equal(result.scenarios.length, 1);
    assert.equal(calls, 0, 'l’import est passif');
  } finally {
    http.request = original.httpRequest;
    http.get = original.httpGet;
  }
});

// ---------------------------------------------------------------- REPLAY

test('replay : une origine locale reste autorisée sans confirmation', () => {
  for (const url of ['http://127.0.0.1:3000/a', 'http://localhost:8080/a', 'http://[::1]:3000/a']) {
    const decision = replayAuthorization(scenarioFor(url));
    assert.equal(decision.state, REPLAY_STATE.ALLOWED, url);
    assert.equal(decision.scope, 'local', url);
  }
  assert.equal(isLocalScenarioHost('127.0.0.1'), true);
  assert.equal(isLocalScenarioHost('192.168.222.132'), false);
});

test('replay : une origine distante non confirmée exige une autorisation', () => {
  const decision = replayAuthorization(scenarioFor(`${REMOTE}/rest/products`));
  assert.equal(decision.state, REPLAY_STATE.AUTHORIZATION_REQUIRED);
  assert.equal(decision.scope, 'remote');
  assert.equal(decision.origin, REMOTE);
});

test('replay : l’autorisation est liée à l’origine exacte — schéma, hôte et port', () => {
  const authorizedOrigins = [REMOTE];
  assert.equal(replayAuthorization(scenarioFor(`${REMOTE}/rest/a`), { authorizedOrigins }).state, REPLAY_STATE.ALLOWED);
  // Un chemin différent sur la même origine reste autorisé…
  assert.equal(replayAuthorization(scenarioFor(`${REMOTE}/autre/chemin?x=1`), { authorizedOrigins }).state, REPLAY_STATE.ALLOWED);
  // …mais un autre port, un autre hôte ou un autre schéma redemandent.
  for (const url of ['http://192.168.222.132:8080/a', 'http://192.168.222.133:3000/a', 'https://192.168.222.132:3000/a']) {
    assert.equal(replayAuthorization(scenarioFor(url), { authorizedOrigins }).state, REPLAY_STATE.AUTHORIZATION_REQUIRED, url);
  }
  assert.equal(replayOrigin(`${REMOTE}/rest/products?a=1#x`), REMOTE, 'l’origine ignore chemin, requête et fragment');
});

test('replay : sans autorisation, aucune requête n’est envoyée', async () => {
  let reached = 0;
  const server = http.createServer((request, response) => { reached += 1; response.writeHead(200); response.end('{}'); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    // L'hôte est joignable, mais il est vu comme distant : sans autorisation la
    // requête ne part pas du tout.
    const remoteLooking = { request: { url: `http://192.168.222.132:${port}/a`, method: 'GET', headers: {} }, response: {} };
    // Le refus est immédiat et synchrone : rien n'est même mis en file.
    assert.throws(() => replayScenario(remoteLooking, { timeoutMs: 2000 }), /n’a pas été autorisée pour le replay HTTP/);
    assert.equal(reached, 0, 'aucune connexion ouverte');
  } finally {
    server.close();
  }
});

test('replay : local inchangé et distant confirmé envoient réellement la requête', async () => {
  const seen = [];
  const server = http.createServer((request, response) => {
    seen.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ ok: true, path: request.url }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const local = await replayScenario(scenarioFor(`http://127.0.0.1:${port}/local`), { timeoutMs: 5000 });
    assert.equal(local.statusCode, 200);

    const origin = `http://localhost:${port}`;
    const confirmed = await replayScenario(scenarioFor(`${origin}/confirme`), {
      timeoutMs: 5000, authorizedOrigins: [origin]
    });
    assert.equal(confirmed.statusCode, 200);
    assert.deepEqual(seen, ['/local', '/confirme']);
  } finally {
    server.close();
  }
});

test('replay : les règles sur les méthodes d’écriture sont conservées', () => {
  const authorizedOrigins = [REMOTE];
  assert.throws(
    () => replayScenario(scenarioFor(`${REMOTE}/a`, 'DELETE'), { authorizedOrigins }),
    /La méthode DELETE n’est pas autorisée/
  );
  for (const method of ['POST', 'PUT', 'PATCH']) {
    assert.throws(
      () => replayScenario(scenarioFor(`${REMOTE}/a`, method), { authorizedOrigins }),
      /exigent une confirmation interactive/, method
    );
  }
  // La méthode est vérifiée avant l'origine : une méthode interdite est refusée
  // même sur une origine locale.
  assert.throws(() => replayScenario(scenarioFor('http://127.0.0.1:3000/a', 'TRACE')), /TRACE/);
});

// ------------------------------------------------------- contrat exposé

test('contrat : les trois états de replay sont exposés au modèle', () => {
  assert.deepEqual(Object.values(REPLAY_STATE).sort(), ['allowed', 'authorization-required']);
  const local = replayAuthorization(scenarioFor('http://127.0.0.1:3000/a'));
  const remote = replayAuthorization(scenarioFor(`${REMOTE}/a`));
  const confirmed = replayAuthorization(scenarioFor(`${REMOTE}/a`), { authorizedOrigins: [REMOTE] });
  assert.deepEqual([local.state, remote.state, confirmed.state], ['allowed', 'authorization-required', 'allowed']);
  for (const decision of [local, remote, confirmed]) {
    assert.ok(decision.origin, 'chaque décision nomme son origine');
    assert.ok(['local', 'remote'].includes(decision.scope));
  }
});

test('contrat : l’autorisation de replay ne réutilise jamais celle de ZAP', () => {
  const extension = src('src/extension.js');
  const helper = extension.match(/function replayAuthorizedOrigins\(\)[\s\S]*?\n  \}/)[0];
  assert.match(helper, /dynamic\.replayAuthorizedOrigins/);
  assert.ok(!helper.includes('zap.remoteAuthorized'), 'le réglage ZAP n’est pas lu ici');
  assert.ok(!helper.includes('zap.targetMode'));
  // Le module de replay ignore complètement le vocabulaire ZAP.
  const scenarios = src('src/http-scenarios.js');
  assert.ok(!scenarios.includes('zap'), 'aucune notion de ZAP dans le contrat de replay');

  const manifest = JSON.parse(src('package.json'));
  const property = manifest.contributes.configuration.properties['securityCenter.dynamic.replayAuthorizedOrigins'];
  assert.equal(property.type, 'array');
  assert.deepEqual(property.default, []);
  assert.match(property.description, /Distinct de l’autorisation de scan ZAP/);
});

test('contrat : la confirmation est demandée par origine et persistée', () => {
  const extension = src('src/extension.js');
  const guard = extension.match(/async function authorizeReplayTarget\([\s\S]*?\n  \}/)[0];
  assert.match(guard, /modal: true/);
  assert.match(guard, /Je confirme être autorisé/);
  assert.match(guard, /decision\.origin/);
  assert.match(guard, /dynamic\.replayAuthorizedOrigins/);
  // Les quatre appels à replayScenario reçoivent les origines autorisées.
  const replayCalls = extension.match(/replayScenario\([\s\S]{0,400}?\)\s*;/g) || [];
  assert.equal(replayCalls.length, 4, 'quatre points de replay');
  for (const call of replayCalls) {
    assert.match(call, /authorizedOrigins: replayAuthorizedOrigins\(\)/, call.slice(0, 60));
  }
});

test('contrat : le validateur strictement local reste disponible', () => {
  assert.ok(validateLocalUrl('http://127.0.0.1:3000/x'));
  assert.throws(() => validateLocalUrl('http://192.168.222.132:3000/x'), /locales autorisées/);
  // Le validateur passif, lui, accepte l'origine distante mais pas n'importe quoi.
  assert.equal(validateCapturedUrl(`${REMOTE}/x`).origin, REMOTE);
  assert.throws(() => validateCapturedUrl('ftp://serveur/x'), /HTTP et HTTPS/);
});
