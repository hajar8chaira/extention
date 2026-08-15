const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanArgs, dockerArgs, supportedCallAnalysis } = require('../src/osv');
const { normalizeOsvOutput } = require('../src/findings');

test('configure OSV-Scanner v2 pour une analyse source JSON récursive', () => {
  assert.deepEqual(scanArgs('/src'), [
    'scan', 'source', '--format=json', '--verbosity=error',
    '--recursive', '--allow-no-lockfiles', '/src'
  ]);
  const args = dockerArgs('C:\\repo');
  assert.ok(args.includes('C:\\repo:/src:ro'));
  assert.ok(args.includes('ghcr.io/google/osv-scanner:latest'));
});

test('active la reachability uniquement pour un workspace Rust supporté', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-rust-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'crate'));
  fs.writeFileSync(path.join(root, 'crate', 'Cargo.lock'), 'version = 3\n');
  assert.equal(supportedCallAnalysis(root), 'rust');
  assert.ok(dockerArgs(root).includes('--call-analysis=rust'));
  assert.equal(supportedCallAnalysis(path.join(root, 'missing')), '');
});

test('normalise et regroupe les alias OSV d’une même vulnérabilité', () => {
  const payload = { results: [{
    source: { path: '/src/package-lock.json', type: 'lockfile' },
    packages: [{
      package: { name: 'demo', version: '1.0.0', ecosystem: 'npm' },
      vulnerabilities: [{
        id: 'GHSA-demo', aliases: ['CVE-2026-1234'],
        summary: 'Demo vulnerability',
        database_specific: { severity: 'HIGH' },
        affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }],
        references: [{ url: 'https://osv.dev/GHSA-demo' }]
      }, {
        id: 'CVE-2026-1234', aliases: ['GHSA-demo'],
        database_specific: { severity: 'HIGH' }
      }],
      groups: [{ ids: ['GHSA-demo', 'CVE-2026-1234'], experimentalAnalysis: { 'GHSA-demo': { called: true } } }]
    }]
  }] };
  const findings = normalizeOsvOutput(payload, 'C:\\repo');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'CVE-2026-1234');
  assert.equal(findings[0].packageName, 'demo');
  assert.equal(findings[0].fixedVersion, '1.0.1');
  assert.equal(findings[0].rawSeverity, 'HIGH');
  assert.equal(findings[0].reachable, true);
  assert.equal(findings[0].confidence, 'high');
  assert.equal(findings[0].absolutePath, 'C:\\repo\\package-lock.json');
});
