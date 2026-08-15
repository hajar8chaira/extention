'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { CACHE_KEY, createLocalScanCache, restoreLocalScanCache } = require('../src/local-scan-cache');

test('creates and restores the last scan for the same workspace', () => {
  const cache = createLocalScanCache('C:\\work\\app', [{ id: 'finding-1' }], [{ tool: 'Semgrep', status: 'completed' }], { scanStatus: 'completed' }, '2026-08-11T18:00:00.000Z');
  const restored = restoreLocalScanCache(cache, 'c:/work/app/');
  assert.equal(CACHE_KEY, 'securityCenter.lastScan.v1');
  assert.equal(restored.findings[0].id, 'finding-1');
  assert.equal(restored.scanners[0].tool, 'Semgrep');
  assert.equal(restored.dashboardOptions.scanStatus, 'completed');
});

test('does not restore a scan belonging to another workspace', () => {
  const cache = createLocalScanCache('C:\\work\\first', [], [], {});
  assert.equal(restoreLocalScanCache(cache, 'C:\\work\\second'), null);
});

test('rejects malformed or unsupported cache entries', () => {
  assert.equal(restoreLocalScanCache(null, 'C:\\work\\app'), null);
  assert.equal(restoreLocalScanCache({ version: 99 }, 'C:\\work\\app'), null);
});
