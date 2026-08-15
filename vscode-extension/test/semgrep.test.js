const test = require('node:test');
const assert = require('node:assert/strict');
const { localArgs, dockerArgs } = require('../src/semgrep');

test('construit une invocation locale avec une configuration explicite', () => {
  assert.deepEqual(localArgs('p/security-audit'), ['scan', '--config', 'p/security-audit', '--json', '--metrics=off', '.']);
});

test('monte le workspace en lecture de scan Docker', () => {
  const args = dockerArgs('C:\\repo', 'p/security-audit');
  assert.ok(args.includes('run'));
  assert.ok(args.includes('C:\\repo:/src'));
  assert.ok(args.includes('semgrep/semgrep'));
});

test('traduit les exclusions et règles Semgrep natives', () => {
  const args = localArgs(['p/security-audit', 'security-rules'], { files: ['dist/**'], rules: ['company.ignore-me'] });
  assert.equal(args.filter((item) => item === '--config').length, 2);
  assert.deepEqual(args.slice(args.indexOf('--exclude'), args.indexOf('--exclude') + 2), ['--exclude', 'dist/**']);
  assert.deepEqual(args.slice(args.indexOf('--exclude-rule'), args.indexOf('--exclude-rule') + 2), ['--exclude-rule', 'company.ignore-me']);
});

test('limite Semgrep aux fichiers modifiés en mode incrémental', () => {
  const args = dockerArgs('C:\\repo', 'security-rules/semgrep.yml', {}, ['src/app.ts', 'src/api.js']);
  assert.deepEqual(args.slice(-2), ['src/app.ts', 'src/api.js']);
  assert.ok(!args.includes('.'));
});
