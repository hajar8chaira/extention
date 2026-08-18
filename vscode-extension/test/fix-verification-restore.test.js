const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  VERIFICATION_STATE, VERIFICATION_REASON, FIX_SOURCE, VERIFIER,
  markFixApplied, applyVerification, verificationRecord, restoreVerificationOnFindings
} = require('../src/fix-verification');
const { findingKey } = require('../src/triage');

const semgrep = (extra = {}) => ({
  id: 'semgrep:js.sqli:src/db.js:42', tool: 'Semgrep', ruleId: 'js.sqli', category: 'security',
  file: 'src/db.js', startLine: 42, title: 'SQL injection', severity: 'high', ...extra
});
const gitleaks = (extra = {}) => ({
  id: 'gitleaks:aws-key:config.yml:7', tool: 'Gitleaks', ruleId: 'aws-access-key', category: 'secret',
  file: 'config.yml', startLine: 7, fingerprint: 'config.yml:aws-access-key:7', title: 'Cle AWS', ...extra
});
const trivyCve = (extra = {}) => ({
  id: 'trivy:CVE-2021-23337:lodash', tool: 'Trivy', ruleId: 'CVE-2021-23337', category: 'dependency',
  file: 'package-lock.json', title: 'lodash', ...extra
});
const zap = (extra = {}) => ({
  id: 'zap:40012', tool: 'ZAP', ruleId: '40012', category: 'dynamic',
  endpoint: 'http://127.0.0.1:3000/search', method: 'GET', parameter: 'q', title: 'XSS', ...extra
});

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/**
 * Produces what actually survives a restart: a triage status on the finding, and
 * a verification record that has been through JSON.
 */
function persistedPair(state, {
  finding = semgrep(), validator = VERIFIER.SAST_RESCAN,
  reason = VERIFICATION_REASON.ABSENT_AFTER_RESCAN, scanId = 21, retestId = null, detail = ''
} = {}) {
  const verified = applyVerification(markFixApplied(finding, { source: FIX_SOURCE.QUICK_FIX }), {
    state, validator, reason, at: '2026-08-17T12:00:00.000Z',
    evidence: { verifier: validator, tool: finding.tool, scanId, retestId, detail }
  });
  const record = JSON.parse(JSON.stringify(verificationRecord(verified)));
  return { verified, record, restoredFinding: { ...finding, triageStatus: verified.triageStatus } };
}

test('un finding VALIDATED retrouve toute sa preuve apres redemarrage', () => {
  const { record, restoredFinding } = persistedPair(VERIFICATION_STATE.VALIDATED);
  const [restored] = restoreVerificationOnFindings([restoredFinding], { [record.key]: record });
  assert.equal(restored.triageStatus, VERIFICATION_STATE.VALIDATED);
  assert.equal(restored.verification.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(restored.verification.validator, VERIFIER.SAST_RESCAN);
  assert.equal(restored.verification.reason, VERIFICATION_REASON.ABSENT_AFTER_RESCAN);
  assert.equal(restored.verification.at, '2026-08-17T12:00:00.000Z');
  assert.equal(restored.verification.evidence.scanId, 21);
  assert.equal(restored.verification.evidence.tool, 'Semgrep');
  assert.equal(restored.validatedAt, '2026-08-17T12:00:00.000Z');
  assert.equal(restored.verificationPending, false);
  assert.equal(restored.fixSource, FIX_SOURCE.QUICK_FIX);
});

test('chaque issue de verification survit au redemarrage', () => {
  const outcomes = [
    [VERIFICATION_STATE.STILL_PRESENT, VERIFICATION_REASON.PRESENT_AFTER_RESCAN],
    [VERIFICATION_STATE.VALIDATION_FAILED, VERIFICATION_REASON.SCANNER_UNAVAILABLE],
    [VERIFICATION_STATE.INCONCLUSIVE, VERIFICATION_REASON.SCANNER_INCOMPLETE],
    [VERIFICATION_STATE.REGRESSED, VERIFICATION_REASON.PRESENT_AFTER_RESCAN]
  ];
  for (const [state, reason] of outcomes) {
    const { record, restoredFinding } = persistedPair(state, { reason });
    const [restored] = restoreVerificationOnFindings([restoredFinding], { [record.key]: record });
    assert.equal(restored.triageStatus, state, state);
    assert.equal(restored.verification.state, state);
    assert.equal(restored.verification.reason, reason);
    assert.equal(restored.verificationPending, true, `${state} reste en attente`);
    assert.equal(restored.validatedAt, undefined, `${state} ne doit pas porter de date de validation`);
  }
});

test('une preuve de re-test DAST est restauree', () => {
  const { record, restoredFinding } = persistedPair(VERIFICATION_STATE.VALIDATED, {
    finding: zap(), validator: VERIFIER.DAST_RETEST,
    reason: VERIFICATION_REASON.RETEST_EVIDENCE_GONE, scanId: null, retestId: 'retest-42'
  });
  const [restored] = restoreVerificationOnFindings([restoredFinding], { [record.key]: record });
  assert.equal(restored.verification.evidence.retestId, 'retest-42');
  assert.equal(restored.verification.validator, VERIFIER.DAST_RETEST);
});

test('un enregistrement corrompu est ignore, sans planter ni inventer', () => {
  const malformed = [
    null, undefined, 'texte', 42, [],
    {}, { status: 'validated' }, { key: 'k' },
    { key: 'k', status: 'invente' }, { key: 'k', status: '' }, { key: 'k', status: null }
  ];
  for (const record of malformed) {
    const finding = { ...semgrep(), triageStatus: 'validated' };
    const [restored] = restoreVerificationOnFindings([finding], { [findingKey(finding)]: record });
    assert.equal(restored.verification, undefined, JSON.stringify(record));
    // Le statut n'est pas touche : la restauration echoue fermee, sans degrader.
    assert.equal(restored.triageStatus, 'validated');
  }
});

test('un enregistrement ne peut pas promouvoir un finding vers VALIDATED', () => {
  // Un cache trafique qui pretendrait qu'un finding ouvert a ete valide.
  const open = { ...semgrep(), triageStatus: 'new' };
  const forged = {
    key: findingKey(open), status: 'validated', validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: 'x', validatedAt: 'x', scanId: 1, tool: 'Semgrep'
  };
  const [restored] = restoreVerificationOnFindings([open], { [findingKey(open)]: forged });
  assert.equal(restored.triageStatus, 'new');
  assert.equal(restored.verification, undefined, 'aucune preuve ne doit etre attachee');
  assert.equal(restored.validatedAt, undefined);
});

test('un enregistrement en desaccord avec le statut est ecarte', () => {
  const applied = { ...semgrep(), triageStatus: 'fixed' };
  const stale = { key: findingKey(applied), status: 'validated', validator: VERIFIER.SAST_RESCAN, reason: 'r', at: 'x' };
  const [restored] = restoreVerificationOnFindings([applied], { [findingKey(applied)]: stale });
  assert.equal(restored.triageStatus, 'fixed');
  assert.equal(restored.verification, undefined);
});

test('un ancien finding sans metadonnees se charge normalement', () => {
  const legacy = [
    { ...semgrep(), triageStatus: 'fixed' },
    { ...gitleaks(), triageStatus: 'validated' },
    { ...trivyCve(), triageStatus: 'new' }
  ];
  assert.deepEqual(restoreVerificationOnFindings(legacy, {}), legacy, 'aucun champ ajoute');
  assert.deepEqual(restoreVerificationOnFindings(legacy, null), legacy);
  assert.deepEqual(restoreVerificationOnFindings(legacy, 'texte'), legacy);
  assert.deepEqual(restoreVerificationOnFindings(legacy, []), legacy);
});

test('des entrees invalides en tete ne cassent pas la restauration', () => {
  assert.deepEqual(restoreVerificationOnFindings(null, {}), []);
  assert.deepEqual(restoreVerificationOnFindings(undefined, {}), []);
  assert.deepEqual(restoreVerificationOnFindings('texte', {}), []);
});

test('la preuve restauree reste bornee', () => {
  const { record, restoredFinding } = persistedPair(VERIFICATION_STATE.VALIDATION_FAILED, {
    reason: VERIFICATION_REASON.VALIDATOR_ERROR, detail: 'x'.repeat(5000)
  });
  assert.ok(record.detail.length <= 200, 'borne avant ecriture');
  const [restored] = restoreVerificationOnFindings([restoredFinding], { [record.key]: record });
  assert.ok(restored.verification.evidence.detail.length <= 200, 'et apres relecture');
});

test('aucun materiau sensible ne subsiste dans l etat persiste', () => {
  const dirty = gitleaks({
    secret: 'AKIAQYLPMN5HG7RTZW3D', match: 'aws_key = AKIAQYLPMN5HG7RTZW3D',
    patch: '- aws_key = AKIAQYLPMN5HG7RTZW3D\n+ aws_key = env(AWS_KEY)',
    snippet: 'const password = "hunter2";',
    requestHeaders: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.charge', cookie: 'sid=abc123' },
    responseBody: '<html>corps sensible</html>',
    aiPrompt: 'Voici le code source complet du fichier'
  });
  const { record } = persistedPair(VERIFICATION_STATE.VALIDATED, { finding: dirty, validator: VERIFIER.SECRET_RESCAN });
  const blob = JSON.stringify(record);
  for (const forbidden of [
    'AKIAQYLPMN5HG7RTZW3D', 'hunter2', 'aws_key =', 'eyJhbGciOiJIUzI1NiJ9',
    'sid=abc123', 'corps sensible', 'code source complet', 'Bearer '
  ]) {
    assert.ok(!blob.includes(forbidden), `${forbidden} ne doit pas etre persiste`);
  }
  for (const key of ['secret', 'match', 'patch', 'snippet', 'requestHeaders', 'responseBody', 'aiPrompt']) {
    assert.ok(!Object.prototype.hasOwnProperty.call(record, key), `champ ${key} persiste`);
  }
});

test('l extension restaure la preuve aux deux points de reprise', () => {
  const source = extensionSource().split('\r').join('');
  // Au demarrage, depuis le cache local.
  assert.match(source, /restoreVerificationOnFindings\(\s*\n?\s*restoredProjection\.findings/);
  // Et apres un scan, quand les findings sont reconstruits.
  assert.match(source, /restoreVerificationOnFindings\(\s*\n?\s*retainValidatedFindings\(/);
  // Une seule cle de stockage, pas une seconde base.
  assert.equal((source.match(/const VERIFICATION_STATE_KEY = /g) || []).length, 1);
  assert.ok(!/workspaceState\.get\('securityCenter\.verification/.test(source), 'aucune cle concurrente');
});

test('la cle de verification est declaree avant son premier usage', () => {
  // Une const utilisee avant sa ligne de declaration leverait une ReferenceError
  // au demarrage de l extension, la ou plus aucun test ne la verrait.
  const source = extensionSource().split('\r').join('');
  const declaration = source.indexOf('const VERIFICATION_STATE_KEY = ');
  const firstUse = source.indexOf('VERIFICATION_STATE_KEY,', declaration + 1);
  assert.ok(declaration >= 0 && firstUse > declaration, 'declaration avant usage');
});
