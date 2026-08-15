const test = require('node:test');
const assert = require('node:assert/strict');
const { scanArgs, dockerArgs, imageScanArgs, dockerImageArgs, sbomArgs, dockerSbomArgs, imageSbomArgs, dockerImageSbomArgs } = require('../src/trivy');
const { normalizeTrivyOutput } = require('../src/findings');

test('configure Trivy pour les CVE et mauvaises configurations', () => {
  const args = scanArgs('/workspace');
  assert.ok(args.includes('vuln,misconfig'));
  assert.ok(args.includes('json'));
  assert.ok(args.includes('/workspace'));
});

test('traduit les exclusions de fichiers vers Trivy', () => {
  const args = scanArgs('/workspace', ['vendor/**', 'dist/app.js']);
  assert.equal(args.filter((item) => item === '--skip-files').length, 2);
  assert.ok(args.includes('vendor/**'));
});

test('monte le projet en lecture seule et conserve le cache Trivy', () => {
  const args = dockerArgs('C:\\repo');
  assert.ok(args.includes('C:\\repo:/src:ro'));
  assert.ok(args.includes('security-center-trivy-cache:/root/.cache/trivy'));
  assert.ok(args.includes('aquasec/trivy:latest'));
});

test('peut analyser une image Docker en plus du système de fichiers', () => {
  assert.deepEqual(imageScanArgs('demo:latest').slice(0, 2), ['image', '--format']);
  const args = dockerImageArgs('demo:latest');
  assert.ok(args.includes('demo:latest'));
  assert.ok(args.includes('security-center-trivy-cache:/root/.cache/trivy'));
});

test('génère un SBOM CycloneDX depuis un montage en lecture seule', () => {
  assert.deepEqual(sbomArgs('/workspace'), ['fs', '--format', 'cyclonedx', '--scanners', 'vuln', '--quiet', '/workspace']);
  const args = dockerSbomArgs('C:\\repo');
  assert.ok(args.includes('C:\\repo:/src:ro'));
  assert.ok(args.includes('cyclonedx'));
  assert.ok(args.includes('security-center-trivy-cache:/root/.cache/trivy'));
});

test('peut générer le SBOM de l’image Docker configurée', () => {
  assert.deepEqual(imageSbomArgs('demo:latest').slice(0, 3), ['image', '--format', 'cyclonedx']);
  const args = dockerImageSbomArgs('demo:latest');
  assert.ok(args.includes('/var/run/docker.sock:/var/run/docker.sock'));
  assert.ok(args.includes('demo:latest'));
});

test('normalise les CVE et mauvaises configurations Trivy', () => {
  const payload = { Results: [{
    Target: 'package-lock.json',
    Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-0001', PkgName: 'demo', InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'HIGH', PrimaryURL: 'https://example.test/cve' }]
  }, {
    Target: 'Dockerfile',
    Misconfigurations: [{ ID: 'AVD-DS-0001', Title: 'Utilisateur root', Severity: 'MEDIUM', CauseMetadata: { Resource: 'Dockerfile', StartLine: 4, EndLine: 4 } }]
  }] };
  const findings = normalizeTrivyOutput(payload, '/workspace');
  assert.equal(findings.length, 2);
  assert.equal(findings[0].category, 'dependency');
  assert.equal(findings[0].severity, 'error');
  assert.equal(findings[0].packageName, 'demo');
  assert.equal(findings[0].installedVersion, '1.0.0');
  assert.equal(findings[0].fixedVersion, '1.0.1');
  assert.equal(findings[1].category, 'misconfiguration');
  assert.equal(findings[1].startLine, 3);
});
