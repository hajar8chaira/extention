const test = require('node:test');
const assert = require('node:assert/strict');
const { componentLicenses, matchesDeniedLicense, analyzeLicenses, renderLicenseReportHtml } = require('../src/license-compliance');

test('extrait les identifiants, noms et expressions CycloneDX', () => {
  const licenses = componentLicenses({ licenses: [
    { license: { id: 'MIT' } },
    { license: { name: 'Apache License 2.0' } },
    { expression: 'MIT OR Apache-2.0' }
  ] });
  assert.deepEqual(licenses, ['MIT', 'Apache License 2.0', 'MIT OR Apache-2.0']);
});

test('classe les licences autorisées, interdites et inconnues', () => {
  const report = analyzeLicenses({ components: [
    { name: 'safe', version: '1', licenses: [{ license: { id: 'MIT' } }] },
    { name: 'blocked', version: '2', licenses: [{ expression: 'GPL-3.0-only' }] },
    { name: 'unknown', version: '3' }
  ] }, ['GPL-3.0']);
  assert.deepEqual(report.counts, { allowed: 1, denied: 1, unknown: 1 });
  assert.equal(report.compliant, false);
  assert.equal(report.components[1].blockedBy[0], 'GPL-3.0-only');
});

test('ne confond pas GPL avec LGPL ou AGPL', () => {
  assert.equal(matchesDeniedLicense('GPL-3.0-only', 'GPL-3.0'), true);
  assert.equal(matchesDeniedLicense('MIT OR GPL-3.0-or-later', 'GPL-3.0'), true);
  assert.equal(matchesDeniedLicense('LGPL-3.0-only', 'GPL-3.0'), false);
  assert.equal(matchesDeniedLicense('AGPL-3.0-only', 'GPL-3.0'), false);
});

test('échappe les composants dans le rapport de licences', () => {
  const report = analyzeLicenses({ components: [{ name: '<script>', licenses: [] }] }, []);
  const html = renderLicenseReportHtml(report, 'nonce');
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /INCONNUE/);
});
