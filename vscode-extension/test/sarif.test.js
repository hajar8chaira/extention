const test = require('node:test');
const assert = require('node:assert/strict');
const { sarifLevel, toSarif } = require('../src/sarif');
const { parseArgs } = require('../src/cli');

test('convertit les findings normalisés en SARIF 2.1.0', () => {
  const sarif = toSarif({ findings: [{ id: 'f1', tool: 'Semgrep', ruleId: 'company.eval', title: 'Eval dangereux', message: 'Éviter eval', rawSeverity: 'HIGH', file: 'src/app.js', line: 12, cwes: ['CWE-95'] }] });
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, 'semgrep/company.eval');
});

test('agrège Semgrep, Gitleaks, Trivy et OSV sans collision ni secret', () => {
  const findings = [
    { id: 's1', tool: 'Semgrep', ruleId: 'CVE-2026-1', title: 'Injection', message: 'Entrée non validée', rawSeverity: 'HIGH', file: 'src/app.js', line: 5, cwes: ['CWE-20'] },
    { id: 'g1', tool: 'Gitleaks', ruleId: 'generic-api-key', title: 'Secret détecté', message: 'Valeur masquée [REDACTED]', rawSeverity: 'CRITICAL', file: 'config.yml', line: 2, commit: 'abc123' },
    { id: 't1', tool: 'Trivy', ruleId: 'CVE-2026-1', title: 'Package vulnérable', rawSeverity: 'HIGH', file: 'package-lock.json', packageName: 'demo', installedVersion: '1.0.0', cves: ['CVE-2026-1'] },
    { id: 'o1', tool: 'OSV-Scanner', ruleId: 'CVE-2026-1', title: 'Advisory OSV', rawSeverity: 'MEDIUM', file: 'package-lock.json', packageName: 'demo', installedVersion: '1.0.0', cves: ['CVE-2026-1'], reachable: null }
  ];
  const sarif = toSarif({ findings });
  assert.equal(sarif.runs[0].results.length, 4);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 4);
  assert.deepEqual(new Set(sarif.runs[0].results.map((item) => item.properties.scanner)), new Set(['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner']));
  assert.ok(sarif.runs[0].results.every((item) => item.partialFingerprints.securityCenterFingerprint));
  assert.doesNotMatch(JSON.stringify(sarif), /AKIA[0-9A-Z]{16}/);
});

test('mappe les sévérités SARIF sans exagérer les faibles', () => {
  assert.equal(sarifLevel('CRITICAL'), 'error');
  assert.equal(sarifLevel('MEDIUM'), 'warning');
  assert.equal(sarifLevel('LOW'), 'note');
});

test('le CLI exige une identité et une justification pour ZAP offensif', () => {
  assert.throws(() => parseArgs(['--zap-authorized']), /exige --actor et --justification/);
  const args = parseArgs(['--tools', 'Semgrep,Trivy', '--zap-authorized', '--actor', 'ci', '--justification', 'application locale dédiée']);
  assert.deepEqual(args.tools, ['Semgrep', 'Trivy']);
});

test('le CLI valide le seuil de blocage headless', () => {
  assert.equal(parseArgs(['--fail-on', 'HIGH']).failOn, 'HIGH');
  assert.throws(() => parseArgs(['--fail-on', 'URGENT']), /sévérité inconnue/);
});

test('le CLI exige une base explicite pour le mode incrémental', () => {
  assert.throws(() => parseArgs(['--incremental']), /exige --base-ref/);
  assert.equal(parseArgs(['--incremental', '--base-ref', 'origin/main']).baseRef, 'origin/main');
});
