const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  VERIFICATION_STATE, VERIFICATION_REASON, VERIFIER,
  verifyFindingFix, markFixApplied, interpretRescan
} = require('../src/fix-verification');

const semgrep = (extra = {}) => ({
  id: 'semgrep:js.sqli:src/db.js:42', tool: 'Semgrep', ruleId: 'js.sqli', category: 'security',
  file: 'src/db.js', startLine: 42, title: 'SQL injection', ...extra
});

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8').split('\r').join('');

// ======================= classification reelle des delais de scanner

test('la formulation reelle du timeout scanner est classee TIMEOUT', async () => {
  // Les scanners du produit ecrivent « a depasse N secondes » sans jamais dire
  // « delai » ni « timeout ». Observe sur un vrai echec Semgrep : le verdict
  // etait sur, mais classe comme une erreur de validateur.
  const messages = [
    'Le scan Semgrep a dépassé 300 secondes.',
    'Le scan Gitleaks a dépassé 240 secondes.',
    'Le scan ZAP a dépassé 600 secondes.',
    'Le scan a dépassé son délai.',
    'operation timed out',
    'ETIMEDOUT'
  ];
  for (const message of messages) {
    const result = await verifyFindingFix(markFixApplied(semgrep()), {
      runVerifier: async () => { throw new Error(message); }
    });
    assert.equal(result.reason, VERIFICATION_REASON.TIMEOUT, message);
    assert.equal(result.state, VERIFICATION_STATE.VALIDATION_FAILED);
  }
});

test('un timeout scanner ne produit jamais VALIDATED', async () => {
  const result = await verifyFindingFix(markFixApplied(semgrep()), {
    runVerifier: async () => { throw new Error('Le scan Semgrep a dépassé 300 secondes.'); }
  });
  assert.notEqual(result.state, VERIFICATION_STATE.VALIDATED);
  assert.notEqual(result.state, VERIFICATION_STATE.STILL_PRESENT);
  assert.match(result.evidence.detail, /dépassé/);
});

test('une annulation reste distincte d un depassement de delai', async () => {
  const cancelled = await verifyFindingFix(markFixApplied(semgrep()), {
    runVerifier: async () => { throw new Error('Scan Semgrep annulé.'); }
  });
  assert.equal(cancelled.reason, VERIFICATION_REASON.CANCELLED);
});

test('un scanner en echec ne peut pas valider par liste vide', async () => {
  // Le piege : un scanner qui plante rend zero finding, exactement comme un
  // scanner qui n en trouve plus. Seule la completion distingue les deux.
  const failed = await verifyFindingFix(markFixApplied(semgrep()), {
    runVerifier: async () => ({ findings: [], scannerStatuses: [{ tool: 'Semgrep', status: 'unavailable' }] })
  });
  assert.equal(failed.state, VERIFICATION_STATE.VALIDATION_FAILED);
  const incomplete = await verifyFindingFix(markFixApplied(semgrep()), {
    runVerifier: async () => ({ findings: [], scannerStatuses: [] })
  });
  assert.equal(incomplete.state, VERIFICATION_STATE.INCONCLUSIVE);
  // Et le seul cas qui valide reste une completion averee.
  const completed = await verifyFindingFix(markFixApplied(semgrep()), {
    runVerifier: async () => ({ findings: [], scannerStatuses: [{ tool: 'Semgrep', status: 'completed' }] })
  });
  assert.equal(completed.state, VERIFICATION_STATE.VALIDATED);
});

test('aucun statut de scanner inconnu ne vaut completion', () => {
  for (const status of ['running', 'pending', 'partial', 'error', '', undefined]) {
    const result = interpretRescan({
      finding: semgrep(), findings: [], scannerStatuses: [{ tool: 'Semgrep', status }]
    });
    assert.notEqual(result.outcome, VERIFICATION_STATE.VALIDATED, String(status));
  }
});

// ============================================= surete de l audit

test('l evenement d audit de verification ne transporte que des metadonnees', () => {
  const source = extensionSource();
  const run = source.slice(source.indexOf('async function runFixVerification'));
  const audit = run.slice(run.indexOf('createAuditEvent'), run.indexOf('if (!silent)'));
  const code = audit.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');

  // Chaque categorie que la charge d audit ne doit jamais porter.
  const forbidden = [
    'patch', 'replacement', 'originalText', 'proposedText', 'sourceText',
    'document.getText', 'getText()', 'stdout', 'stderr', 'payload',
    'body', 'authorization', 'Authorization', 'cookie', 'Cookie',
    'token', 'secret', 'password', 'prompt', 'generated.'
  ];
  for (const term of forbidden) {
    assert.ok(!code.includes(term), `l audit ne doit pas contenir « ${term} »`);
  }
  // Ce qu il porte effectivement : le verdict, sa raison, l identite du scan.
  assert.match(code, /action: `fix\.verification\.\$\{result\.state\}`/);
  assert.match(code, /validator: result\.validator/);
  assert.match(code, /reason: result\.reason/);
  assert.match(code, /scanId: result\.evidence\?\.scanId/);
});

test('le commentaire d audit est construit depuis les libelles, pas depuis les donnees', () => {
  const source = extensionSource();
  const run = source.slice(source.indexOf('async function runFixVerification'));
  const comment = run.slice(run.indexOf('comment: `'), run.indexOf('metadata: {'));
  // Seuls des libelles d etat et de raison entrent dans le commentaire.
  assert.match(comment, /VERIFICATION_LABELS\[result\.state\]/);
  assert.match(comment, /VERIFICATION_REASONS\[result\.reason\]/);
  assert.ok(!/finding\.(title|file|snippet|match|secret)/.test(comment));
});

test('la notification utilisateur n expose pas davantage que l audit', () => {
  const source = extensionSource();
  const run = source.slice(source.indexOf('async function runFixVerification'));
  const notify = run.slice(run.indexOf('if (!silent)'), run.indexOf('return verified;'));
  assert.match(notify, /VERIFICATION_LABELS\[result\.state\]/);
  assert.ok(!/evidence\.detail|stderr|payload/.test(notify), 'aucun detail brut affiche');
});
