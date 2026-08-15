const test = require('node:test');
const assert = require('node:assert/strict');
const { dockerCliArgs, requiresDocker } = require('../src/docker');

test('détecte si au moins un scanner exige Docker', () => {
  assert.equal(requiresDocker(['local', 'docker', 'local']), true);
  assert.equal(requiresDocker(['local', 'local', 'local']), false);
});

test('force le contexte Docker Desktop Linux sous Windows', () => {
  assert.deepEqual(dockerCliArgs(['run', '--rm'], 'win32'), ['--context', 'desktop-linux', 'run', '--rm']);
  assert.deepEqual(dockerCliArgs(['run', '--rm'], 'linux'), ['run', '--rm']);
});
