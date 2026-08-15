const test = require('node:test');
const assert = require('node:assert/strict');
const { setApiKey, authenticationHeaders, backendUrl, getBurpStatus, createAuditEvent, scanExportUrl } = require('../src/backend');

test('ajoute la clé API uniquement lorsqu’elle est configurée', () => {
  setApiKey('  secret-test  ');
  assert.deepEqual(authenticationHeaders(), { 'x-security-center-key': 'secret-test' });
  setApiKey('');
  assert.deepEqual(authenticationHeaders(), {});
});

test('construit les URLs du backend local', () => {
  assert.equal(backendUrl('http://127.0.0.1:8765/', 'health'), 'http://127.0.0.1:8765/health');
});

test('construit les endpoints des scénarios HTTP', () => {
  assert.equal(backendUrl('http://127.0.0.1:8765', 'api/v1/http-scenarios'), 'http://127.0.0.1:8765/api/v1/http-scenarios');
});

test('expose la lecture de l’état du connecteur Burp', () => {
  assert.equal(typeof getBurpStatus, 'function');
});

test('construit les URLs export de scan', () => {
  assert.equal(scanExportUrl('http://127.0.0.1:8765', 42, 'html'), 'http://127.0.0.1:8765/api/v1/scans/42/export.html');
  assert.throws(() => scanExportUrl('http://127.0.0.1:8765', 42, 'pdf'), /non pris en charge/);
});

test('expose la création d’événements d’audit sensibles', () => {
  assert.equal(typeof createAuditEvent, 'function');
});

const { normalizeScanToCamelCase } = require('../src/backend');

test('normalise les propriétés snake_case en camelCase pour scans et findings', () => {
  const rawScan = {
    scan_id: 101,
    result: {
      findings: [
        {
          raw_severity: 'HIGH',
          rule_id: 'semgrep-xss',
          start_line: 45,
          start_column: 8,
          help_uri: 'https://semgrep.dev/rules/xss',
          triage_status: 'accepted'
        }
      ]
    }
  };
  const normalized = normalizeScanToCamelCase(rawScan);
  const finding = normalized.result.findings[0];
  assert.equal(finding.rawSeverity, 'HIGH');
  assert.equal(finding.ruleId, 'semgrep-xss');
  assert.equal(finding.startLine, 45);
  assert.equal(finding.startColumn, 8);
  assert.equal(finding.helpUri, 'https://semgrep.dev/rules/xss');
  assert.equal(finding.triageStatus, 'accepted');
});
