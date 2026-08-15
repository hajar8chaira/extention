const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeAuditEvent, sanitizeAuditEvent } = require('../src/audit-events');

test('normalise les anciens événements ZAP et triage sans modifier leur action brute', () => {
  const zap = normalizeAuditEvent({ action: 'zap:active:authorized', actor: 'reviewer', scan_id: 0, finding_id: 'zap:local' });
  assert.equal(zap.action, 'zap:active:authorized');
  assert.equal(zap.category, 'DAST');
  assert.equal(zap.result, 'AUTHORIZED');
  assert.equal(zap.scan_id, null);
  const triage = normalizeAuditEvent({ action: 'status:validated', actor: 'reviewer' });
  assert.equal(triage.category, 'TRIAGE');
  assert.equal(triage.result, 'VALIDATED');
});

test('conserve un événement inconnu et masque récursivement les secrets', () => {
  const event = sanitizeAuditEvent({
    action: 'legacy:unknown', metadata: {
      authorization: 'Bearer secret', nested: { cookie: 'session=secret', safe: 'Semgrep' }, tokens: ['one']
    }
  });
  assert.equal(event.action, 'legacy:unknown');
  assert.equal(event.category, null);
  assert.equal(event.actor, 'Security Center');
  assert.equal(event.metadata.authorization, '[REDACTED]');
  assert.equal(event.metadata.nested.cookie, '[REDACTED]');
  assert.equal(event.metadata.nested.safe, 'Semgrep');
  assert.equal(event.metadata.tokens, '[REDACTED]');
});
