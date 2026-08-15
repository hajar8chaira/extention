const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { validateLocalTarget, dockerTargetUrl, routeExclusionRegex, zapConfig, dockerArgs, authenticateForZap, zapAuthEnv } = require('../src/zap');

test('autorise uniquement une cible HTTP locale', () => {
  assert.equal(validateLocalTarget('http://127.0.0.1:3000').port, '3000');
  assert.throws(() => validateLocalTarget('https://example.com'), /uniquement une cible locale/);
  assert.throws(() => validateLocalTarget('file:///etc/passwd'), /HTTP ou HTTPS/);
});

test('rend la cible locale accessible depuis le conteneur ZAP', () => {
  assert.equal(dockerTargetUrl('http://localhost:3000'), 'http://host.docker.internal:3000');
  const args = dockerArgs('http://127.0.0.1:3000', 'C:\\reports');
  assert.ok(args.includes('zaproxy/zap-stable'));
  assert.ok(args.includes('http://host.docker.internal:3000'));
  assert.ok(args.includes('C:\\reports:/zap/wrk:rw'));
});

test('exclut les routes sensibles avec la configuration native OUTOFSCOPE', () => {
  const regex = routeExclusionRegex('http://127.0.0.1:3000', '/logout');
  assert.match(regex, /host\\\.docker\\\.internal/);
  assert.match(regex, /logout/);
  const config = zapConfig(['/logout', '/api/admin'], 'http://127.0.0.1:3000');
  assert.equal(config.match(/OUTOFSCOPE/g).length, 2);
  const args = dockerArgs('http://127.0.0.1:3000', 'C:\\tmp', { excludedRoutes: ['/logout'] });
  assert.deepEqual(args.slice(-2), ['-c', 'security-center-zap.conf']);
});

test('construit séparément les scans actif et OpenAPI locaux', () => {
  const active = dockerArgs('http://localhost:3000', 'C:\\tmp', { mode: 'active' });
  assert.ok(active.includes('zap-full-scan.py'));
  assert.ok(active.includes('-m'));
  assert.ok(active.includes('-silent'));
  const api = dockerArgs('http://localhost:3000', 'C:\\tmp', { mode: 'openapi', openapi: 'http://127.0.0.1:3000/openapi.json' });
  assert.ok(api.includes('zap-api-scan.py'));
  assert.ok(api.includes('openapi'));
  assert.ok(api.includes('http://host.docker.internal:3000/openapi.json'));
});

test('interdit une spécification OpenAPI distante', () => {
  assert.throws(() => dockerArgs('http://localhost:3000', 'C:\\tmp', { mode: 'openapi', openapi: 'https://example.com/openapi.json' }), /introuvable/);
});

test('obtient un JWT local sans le placer dans les arguments Docker', async (t) => {
  const server = http.createServer((request, response) => {
    assert.equal(request.url, '/rest/user/login');
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ authentication: { token: 'jwt-secret-test' } }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const auth = { login: '/rest/user/login', usernameEnv: 'ZAP_USER_TEST', passwordEnv: 'ZAP_PASS_TEST', tokenPath: 'authentication.token', usernameField: 'email', passwordField: 'password', header: 'Authorization', prefix: 'Bearer' };
  const result = await authenticateForZap(`http://127.0.0.1:${port}`, auth, { ZAP_USER_TEST: 'dev@example.test', ZAP_PASS_TEST: 'password' });
  assert.deepEqual(result, { header: 'Authorization', value: 'Bearer jwt-secret-test' });
  assert.match(zapAuthEnv(result, `http://127.0.0.1:${port}`), /ZAP_AUTH_HEADER_VALUE=Bearer jwt-secret-test/);
  const args = dockerArgs(`http://127.0.0.1:${port}`, 'C:\\tmp', { mode: 'active', authEnvFile: 'C:\\tmp\\zap-auth.env' });
  assert.ok(args.includes('--env-file'));
  assert.doesNotMatch(args.join(' '), /jwt-secret-test/);
});

test('refuse un scan authentifié sans secrets dans l’environnement', () => {
  const auth = { login: '/login', usernameEnv: 'MISSING_USER', passwordEnv: 'MISSING_PASS' };
  assert.throws(() => authenticateForZap('http://127.0.0.1:3000', auth, {}), /définissez MISSING_USER et MISSING_PASS/);
});
