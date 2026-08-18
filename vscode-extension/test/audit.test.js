const test = require('node:test');
const assert = require('node:assert/strict');
const { renderAuditLogHtml } = require('../src/audit');

test('affiche et échappe le journal d’audit', () => {
  const html = renderAuditLogHtml([{
    event_id: 1, created_at: '2026-08-10T10:00:00Z', scan_id: 14,
    finding_id: '<finding>', action: 'status:false_positive', actor: 'hajar', comment: '<script>alert(1)</script>'
  }], 'nonce');
  assert.match(html, /Journal d’audit/);
  assert.match(html, /false_positive/);
  assert.match(html, /hajar/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;/);
});

test('journal d’audit theme and VS Code class support', () => {
  const htmlLight = renderAuditLogHtml([], 'nonce', 'light');
  const htmlDark = renderAuditLogHtml([], 'nonce', 'dark');

  // Verify body theme classes are rendered correctly
  assert.match(htmlLight, /class="[^"]*theme-light[^"]*"/);
  assert.match(htmlDark, /class="[^"]*theme-dark[^"]*"/);

  // Verify filters-bar input controls consume theme-aware variables
  assert.match(htmlLight, /\.filters-bar input\[type="text"\]/);
  assert.match(htmlLight, /background:\s*var\(--sc-input-bg\)/);
  assert.match(htmlLight, /color:\s*var\(--sc-input-text\)/);
});

const { normalizeAuditEvent, sanitizeAuditEvent } = require('../src/audit-events');

test('existing ZAP authorization event preserved', () => {
  const event = {
    action: 'zap:active:authorized',
    actor: 'hajar',
    comment: 'Autorisé par le développeur'
  };
  const normalized = normalizeAuditEvent(event);
  assert.equal(normalized.category, 'DAST');
  assert.equal(normalized.result, 'AUTHORIZED');
});

test('triage change and accepted risk events mapped correctly', () => {
  const triageEvent = {
    action: 'finding.triage.changed',
    actor: 'hajar',
    comment: 'Triage de l\'alerte 123 pour confirmed',
    metadata: { status: 'confirmed' }
  };
  const riskEvent = {
    action: 'finding.risk.accepted',
    actor: 'hajar',
    comment: 'Risque accepté pour l\'alerte 123',
    metadata: { status: 'accepted' }
  };

  const normTriage = normalizeAuditEvent(triageEvent);
  const normRisk = normalizeAuditEvent(riskEvent);

  assert.equal(normTriage.category, 'TRIAGE');
  assert.equal(normTriage.result, 'SUCCESS');
  assert.equal(normRisk.category, 'TRIAGE');
  assert.equal(normRisk.result, 'ACCEPTED');
});

test('validated correction and AI rollback events mapped correctly', () => {
  const validatedEvent = {
    action: 'finding.fix.validated',
    actor: 'System',
    comment: 'Correction validée pour l\'alerte 123'
  };
  const rollbackEvent = {
    action: 'ai.rollback',
    actor: 'hajar',
    comment: 'Correction IA annulée'
  };

  const normVal = normalizeAuditEvent(validatedEvent);
  const normRollback = normalizeAuditEvent(rollbackEvent);

  assert.equal(normVal.category, 'TRIAGE');
  assert.equal(normVal.result, 'VALIDATED');
  assert.equal(normRollback.category, 'REMEDIATION');
  assert.equal(normRollback.result, 'ROLLBACK');
});

test('scanner failure and configuration changed events mapped correctly', () => {
  const failEvent = {
    action: 'scanner.run.failed',
    actor: 'System',
    comment: 'Échec de Semgrep'
  };
  const configEvent = {
    action: 'ai.configuration.changed',
    actor: 'hajar',
    comment: 'Modèles Ollama modifiés'
  };

  const normFail = normalizeAuditEvent(failEvent);
  const normConfig = normalizeAuditEvent(configEvent);

  assert.equal(normFail.category, 'SCANNER');
  assert.equal(normFail.result, 'FAILED');
  assert.equal(normConfig.category, 'CONFIGURATION');
  assert.equal(normConfig.result, 'SUCCESS');
});

test('sensitive values are redacted and not stored', () => {
  const event = {
    action: 'scanner.configuration.changed',
    actor: 'hajar',
    comment: 'Configuration modifiée',
    metadata: {
      api_key: 'sk-1234567890abcdef',
      password: 'my-super-secret-password',
      authorization: 'Bearer token123',
      safe_param: 'some-value'
    }
  };
  
  const sanitized = sanitizeAuditEvent(event);
  assert.equal(sanitized.metadata.api_key, '[REDACTED]');
  assert.equal(sanitized.metadata.password, '[REDACTED]');
  assert.equal(sanitized.metadata.authorization, '[REDACTED]');
  assert.equal(sanitized.metadata.safe_param, 'some-value');
});

test('policy changed only on actual difference: ignores reloads without differences', () => {
  const crypto = require('crypto');
  const { redactAuditValue } = require('../src/audit-events');
  
  const oldPolicy = { maxParallelScanners: 2, name: 'default' };
  const newPolicySame = { maxParallelScanners: 2, name: 'default' };
  const newPolicyDifferent = { maxParallelScanners: 4, name: 'default' };
  
  const hash1 = crypto.createHash('sha256').update(JSON.stringify(redactAuditValue(oldPolicy))).digest('hex');
  const hash2 = crypto.createHash('sha256').update(JSON.stringify(redactAuditValue(newPolicySame))).digest('hex');
  const hash3 = crypto.createHash('sha256').update(JSON.stringify(redactAuditValue(newPolicyDifferent))).digest('hex');
  
  assert.equal(hash1, hash2);
  assert.notEqual(hash1, hash3);
});
