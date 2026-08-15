const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { normalizeHar, replayScenario, bodySha256, validateLocalUrl } = require('../src/http-scenarios');

test('importe un HAR local et masque les secrets HTTP', () => {
  const payload = { log: { entries: [{
    startedDateTime: '2026-08-12T10:00:00.000Z',
    request: {
      method: 'GET',
      url: 'http://127.0.0.1:3000/api/profile',
      headers: [{ name: 'Authorization', value: 'Bearer secret' }, { name: 'Accept', value: 'application/json' }]
    },
    response: {
      status: 200,
      headers: [{ name: 'Set-Cookie', value: 'session=secret' }],
      content: { text: '{"ok":true}' }
    }
  }] } };
  const result = normalizeHar(payload);
  assert.equal(result.scenarios.length, 1);
  assert.equal(result.scenarios[0].request.headers.authorization, '[REDACTED]');
  assert.deepEqual(result.scenarios[0].request.sensitive_headers, ['authorization']);
  assert.equal(result.scenarios[0].response.headers['set-cookie'], '[REDACTED]');
  assert.equal(result.scenarios[0].response.bodySha256, bodySha256('{"ok":true}'));
  assert.equal(result.scenarios[0].timestamp, '2026-08-12T10:00:00.000Z');
});

test('rejette les cibles HTTP externes pendant l’import', () => {
  const result = normalizeHar({ log: { entries: [{
    request: { method: 'GET', url: 'https://example.com', headers: [] },
    response: { status: 200, headers: [], content: { text: '' } }
  }] } });
  assert.equal(result.scenarios.length, 0);
  assert.equal(result.rejected.length, 1);
  assert.throws(() => validateLocalUrl('https://example.com'), /applications locales/);
});

test('rejoue une requête GET locale et compare la réponse', async (context) => {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"status":"ok"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => server.close());
  const address = server.address();
  const body = '{"status":"ok"}';
  const replay = await replayScenario({
    request: { method: 'GET', url: `http://127.0.0.1:${address.port}/health`, headers: { authorization: '[REDACTED]' } },
    response: { statusCode: 200, bodySha256: bodySha256(body) }
  });
  assert.equal(replay.statusCode, 200);
  assert.equal(replay.comparison.statusChanged, false);
  assert.equal(replay.comparison.bodyChanged, false);
});

test('refuse une méthode d’écriture sans autorisation auditée', () => {
  assert.throws(
    () => replayScenario({ request: { method: 'POST', url: 'http://127.0.0.1:3000/api/Feedbacks', body: '{}' } }),
    /autorisation auditée/
  );
});

test('refuse toujours DELETE même avec autorisation', () => {
  assert.throws(
    () => replayScenario({ request: { method: 'DELETE', url: 'http://127.0.0.1:3000/api/Users/1' } }, { allowWrite: true }),
    /n’est pas autorisée/
  );
});

test('rejoue un POST local uniquement après autorisation explicite', async (t) => {
  const received = {};
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      received.method = request.method;
      received.body = Buffer.concat(chunks).toString('utf8');
      response.writeHead(201, { 'content-type': 'application/json' });
      response.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const replay = await replayScenario({
    request: { method: 'POST', url: `http://127.0.0.1:${port}/items`, headers: { 'content-type': 'application/json' }, body: '{"name":"test"}' },
    response: { statusCode: 201, bodySha256: bodySha256('{"ok":true}') }
  }, { allowWrite: true, timeoutMs: 3000 });
  assert.equal(received.method, 'POST');
  assert.equal(received.body, '{"name":"test"}');
  assert.equal(replay.statusCode, 201);
});
