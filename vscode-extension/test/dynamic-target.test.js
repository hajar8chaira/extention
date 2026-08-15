const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { checkTargetReachability } = require('../src/dynamic-target');

test('détecte une cible dynamique accessible avec un HEAD léger', async (t) => {
  const server = http.createServer((request, response) => response.end());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  assert.equal((await checkTargetReachability(`http://127.0.0.1:${port}`)).state, 'online');
});

test('signale une cible dynamique inaccessible', async () => {
  const result = await checkTargetReachability('http://127.0.0.1:1', 250);
  assert.equal(result.state, 'unreachable');
});

test('conserve un état inconnu sans cible configurée', async () => {
  assert.deepEqual(await checkTargetReachability(''), { state: 'unknown' });
});
