const test = require('node:test');
const assert = require('node:assert/strict');
const { findingKey, normalizeStatus, applyFindingStatuses, isActiveFinding, validatedAfterScan, retainValidatedFindings } = require('../src/triage');

test('restaure un statut à partir du fingerprint stable', () => {
  const finding = { id: 'id-temporaire', fingerprint: 'secret:file:10' };
  const [result] = applyFindingStatuses([finding], { 'secret:file:10': 'false_positive' });
  assert.equal(findingKey(finding), 'secret:file:10');
  assert.equal(result.triageStatus, 'false_positive');
  assert.equal(isActiveFinding(result), false);
});

test('utilise new pour un statut inconnu', () => {
  assert.equal(normalizeStatus('invalid'), 'new');
  const [result] = applyFindingStatuses([{ id: 'a' }], {});
  assert.equal(result.triageStatus, 'new');
  assert.equal(isActiveFinding(result), true);
});

test('masque uniquement les faux positifs et les résultats corrigés', () => {
  assert.equal(isActiveFinding({ triageStatus: 'confirmed' }), true);
  assert.equal(isActiveFinding({ triageStatus: 'accepted' }), true);
  assert.equal(isActiveFinding({ triageStatus: 'fixed' }), false);
  assert.equal(normalizeStatus('triaged'), 'triaged');
  assert.equal(normalizeStatus('probable'), 'probable');
  assert.equal(isActiveFinding({ triageStatus: 'validated' }), false);
});

test('valide une correction seulement si le même scanner termine et que l’alerte disparaît', () => {
  const previous = [
    { id: 'fixed-gone', tool: 'Semgrep', triageStatus: 'fixed' },
    { id: 'fixed-still', tool: 'Semgrep', triageStatus: 'fixed' },
    { id: 'zap-gone', tool: 'ZAP', triageStatus: 'fixed' },
    { id: 'confirmed-gone', tool: 'Semgrep', triageStatus: 'confirmed' }
  ];
  const current = [{ id: 'fixed-still', tool: 'Semgrep' }];
  const validated = validatedAfterScan(previous, current, [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'ZAP', status: 'cancelled' }
  ]);
  assert.deepEqual(validated.map((finding) => finding.id), ['fixed-gone']);
});

test('ne valide rien lorsque le scanner échoue', () => {
  const validated = validatedAfterScan(
    [{ id: 'fixed-gone', tool: 'Trivy', triageStatus: 'fixed' }],
    [],
    [{ tool: 'Trivy', status: 'failed' }]
  );
  assert.deepEqual(validated, []);
});

test('conserve une alerte disparue comme preuve validée dans la liste', () => {
  const result = retainValidatedFindings([{ id: 'still-present' }], [{ id: 'fixed-gone', tool: 'Semgrep', triageStatus: 'fixed', fixedBy: 'Ollama' }], '2026-08-12T09:30:00Z');
  assert.equal(result.length, 2);
  assert.equal(result[1].triageStatus, 'validated');
  assert.equal(result[1].fixedBy, 'Ollama');
  assert.equal(result[1].validatedAt, '2026-08-12T09:30:00Z');
  assert.equal(isActiveFinding(result[1]), false);
});
