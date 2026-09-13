'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { sonarRequest, validateToken, checkServerStatus, SonarError } = require('../src/sonarqube-api');

const TOKEN = 'squ_ab12CD34ef56GH78ij90KL12mn34OP56qr78';
// Capturé sur le fil en lançant `curl -u "<TOKEN>:"` contre un serveur témoin :
// c'est littéralement ce que la commande de référence envoie.
const CURL_AUTHORIZATION = 'Basic c3F1X2FiMTJDRDM0ZWY1NkdINzhpajkwS0wxMm1uMzRPUDU2cXI3ODo=';

/** A stand-in SonarQube that records what it was actually asked. */
async function sonarServer(t, handler) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ method: request.method, url: request.url, authorization: request.headers.authorization, accept: request.headers.accept });
    handler(request, response, requests.length);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { requests, hostUrl: `http://127.0.0.1:${server.address().port}` };
}

const json = (payload, status = 200) => (request, response) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
};

// ------------------------------------------------------- l'en-tête envoyé

test('SonarQube : le jeton part en Basic, exactement comme « curl -u "TOKEN:" »', async (t) => {
  const sonar = await sonarServer(t, json({ valid: true }));
  await sonarRequest(sonar.hostUrl, 'api/authentication/validate', { token: TOKEN });
  const sent = sonar.requests[0];
  assert.equal(sent.method, 'GET');
  assert.equal(sent.url, '/api/authentication/validate');
  // Le défaut réel : « Bearer » n'existe qu'à partir de SonarQube 10.0. Un
  // serveur 9.9 l'ignore, la requête devient anonyme et le jeton est déclaré
  // refusé. Cette assertion échoue si le schéma repasse à Bearer.
  assert.equal(sent.authorization, CURL_AUTHORIZATION);
  assert.ok(!/^Bearer/i.test(sent.authorization), 'aucun schéma Bearer ne doit être envoyé à SonarQube');
  assert.equal(Buffer.from(sent.authorization.slice(6), 'base64').toString('utf8'), `${TOKEN}:`, 'jeton en nom d’utilisateur, mot de passe vide');
});

test('SonarQube : un jeton stocké avec des blancs parasites produit le même en-tête', async (t) => {
  const sonar = await sonarServer(t, json({ valid: true }));
  await sonarRequest(sonar.hostUrl, 'api/authentication/validate', { token: `  ${TOKEN}\n` });
  assert.equal(sonar.requests[0].authorization, CURL_AUTHORIZATION);
});

test('SonarQube : sans jeton, aucune identification n’est envoyée', async (t) => {
  const sonar = await sonarServer(t, json({ status: 'UP', version: '9.9.8.100196' }));
  const status = await checkServerStatus(sonar.hostUrl);
  assert.equal(sonar.requests[0].authorization, undefined, 'api/system/status est public et doit le rester');
  assert.deepEqual(status, { status: 'UP', version: '9.9.8.100196' });
});

test('SonarQube : un jeton remplacé est utilisé dès l’appel suivant', async (t) => {
  const sonar = await sonarServer(t, json({ valid: true }));
  await validateToken(sonar.hostUrl, TOKEN);
  await validateToken(sonar.hostUrl, 'squ_zz99YY88xx77WW66vv55UU44tt33SS22rr11');
  assert.equal(sonar.requests[0].authorization, CURL_AUTHORIZATION);
  assert.notEqual(sonar.requests[1].authorization, sonar.requests[0].authorization, 'aucun jeton n’est mis en cache entre deux appels');
  assert.equal(Buffer.from(sonar.requests[1].authorization.slice(6), 'base64').toString('utf8'), 'squ_zz99YY88xx77WW66vv55UU44tt33SS22rr11:');
});

// --------------------------------------------------------- verdicts rendus

test('SonarQube : un jeton accepté est rapporté valide', async (t) => {
  const sonar = await sonarServer(t, json({ valid: true }));
  assert.equal(await validateToken(sonar.hostUrl, TOKEN), true);
});

test('SonarQube : un refus HTTP 200 {valid:false} reste un refus honnête', async (t) => {
  // C'est exactement la réponse d'un 9.9 à une requête non identifiée : le
  // symptôme observé quand l'en-tête n'était pas compris.
  const sonar = await sonarServer(t, json({ valid: false }));
  assert.equal(await validateToken(sonar.hostUrl, TOKEN), false);
});

test('SonarQube : 401 et 403 sont des refus, pas des pannes', async (t) => {
  for (const status of [401, 403]) {
    const sonar = await sonarServer(t, json({ errors: [{ msg: 'Insufficient privileges' }] }, status));
    assert.equal(await validateToken(sonar.hostUrl, TOKEN), false, `HTTP ${status}`);
  }
});

test('SonarQube : une panne serveur ne se déguise jamais en jeton refusé', async (t) => {
  const sonar = await sonarServer(t, json({ errors: [] }, 500));
  await assert.rejects(
    () => validateToken(sonar.hostUrl, TOKEN),
    (error) => error instanceof SonarError && error.code === 'SERVER_UNAVAILABLE'
  );
});

test('SonarQube : un jeton absent est refusé sans appeler le serveur', async (t) => {
  const sonar = await sonarServer(t, json({ valid: true }));
  assert.equal(await validateToken(sonar.hostUrl, '   '), false);
  assert.equal(sonar.requests.length, 0);
});
