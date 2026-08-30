const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildCompanionVisualModel, verificationFixState } = require('../src/live/companionMessages');
const { renderCompanionWidget } = require('../src/live/companionWidget');
const { VERIFICATION_STATE, markFixApplied, applyVerification, VERIFIER, VERIFICATION_REASON } = require('../src/fix-verification');

const modelFor = (fixState, extra = {}) => buildCompanionVisualModel({
  serviceState: 'clean', findings: [], file: 'routes/login.js',
  pipeline: { fixState, ...extra }
});

const finding = (triageStatus, extra = {}) => ({
  id: `semgrep:${triageStatus}`, tool: 'Semgrep', ruleId: 'js.sqli',
  file: 'src/db.js', startLine: 42, title: 'SQL injection', triageStatus, ...extra
});

// ============================================ mapping du cycle de vie

test('chaque etat du cycle produit sa presentation', () => {
  const expected = {
    [VERIFICATION_STATE.FIX_PROPOSED]: { mascot: 'watching', headline: /Correction disponible/ },
    [VERIFICATION_STATE.FIX_APPLIED]: { mascot: 'watching', headline: /Correction appliquée/ },
    [VERIFICATION_STATE.VALIDATING]: { mascot: 'thinking', headline: /Vérification de la correction/ },
    [VERIFICATION_STATE.VALIDATED]: { mascot: 'success', headline: /Correction vérifiée/ },
    [VERIFICATION_STATE.STILL_PRESENT]: { mascot: 'warning', headline: /toujours présent/ },
    [VERIFICATION_STATE.VALIDATION_FAILED]: { mascot: 'warning', headline: /Vérification impossible/ },
    [VERIFICATION_STATE.INCONCLUSIVE]: { mascot: 'warning', headline: /non concluante/ },
    [VERIFICATION_STATE.REGRESSED]: { mascot: 'critical', headline: /réapparu/ }
  };
  for (const [state, want] of Object.entries(expected)) {
    const model = modelFor(state);
    assert.equal(model.mascotState, want.mascot, `${state} : posture`);
    assert.match(model.message.headline, want.headline, `${state} : message`);
    assert.equal(model.message.kind, 'fix', `${state} : le message vient du cycle`);
  }
});

test('chaque etat du cycle se rend sur le widget', () => {
  for (const state of Object.values(VERIFICATION_STATE)) {
    if (state === VERIFICATION_STATE.OPEN) continue;
    const html = renderCompanionWidget(modelFor(state), { variant: 'full' });
    assert.match(html, /<img class="mascot mascot-[a-z]+/, `${state} rend une mascotte`);
    assert.ok(!html.includes('undefined'), `${state} ne rend aucun undefined`);
  }
});

// ============================================ aucune fausse reussite

test('une correction appliquee n est jamais presentee comme validee', () => {
  const applied = modelFor(VERIFICATION_STATE.FIX_APPLIED);
  // La posture ne doit pas etre celle du succes : un personnage qui celebre
  // au-dessus de « verifions que la vulnerabilite a disparu » est un faux signal.
  assert.notEqual(applied.mascotState, 'success');
  assert.equal(applied.mascotState, 'watching');
  // Et le texte dit explicitement que la verification reste a faire.
  assert.match(applied.message.detail, /vérif/i);
  for (const forbidden of [/vérifiée/i, /résolu/i, /sécurisé/i, /plus de problème/i]) {
    assert.ok(!forbidden.test(applied.message.headline + applied.message.detail),
      `« correction appliquée » ne doit pas affirmer ${forbidden}`);
  }
});

test('seul VALIDATED obtient la posture de succes', () => {
  const successStates = Object.values(VERIFICATION_STATE)
    .filter((state) => state !== VERIFICATION_STATE.OPEN)
    .filter((state) => modelFor(state).mascotState === 'success');
  assert.deepEqual(successStates, [VERIFICATION_STATE.VALIDATED]);
});

test('un echec technique ne devient jamais une reussite', () => {
  for (const state of [VERIFICATION_STATE.VALIDATION_FAILED, VERIFICATION_STATE.INCONCLUSIVE]) {
    const model = modelFor(state);
    assert.equal(model.mascotState, 'warning', state);
    assert.ok(!/vérifiée|résolu|✓/.test(model.message.headline), `${state} n affirme aucun succes`);
    // Et la raison est nommee, pas passee sous silence.
    assert.match(model.message.detail, /preuve/i, `${state} explique pourquoi`);
  }
});

test('une regression escalade au-dela d un simple avertissement', () => {
  const regressed = modelFor(VERIFICATION_STATE.REGRESSED);
  assert.equal(regressed.mascotState, 'critical');
  assert.match(regressed.message.detail, /validé/i, 'la validation precedente est rappelee');
  // Meme sans finding Live dans le fichier courant pour fournir une severite.
  assert.equal(regressed.mascotState, 'critical');
});

// ==================================== derivation depuis les findings

test('l etat rapporte est derive des statuts canoniques', () => {
  assert.equal(verificationFixState([finding(VERIFICATION_STATE.VALIDATED)]), VERIFICATION_STATE.VALIDATED);
  assert.equal(verificationFixState([finding(VERIFICATION_STATE.FIX_APPLIED)]), VERIFICATION_STATE.FIX_APPLIED);
  assert.equal(verificationFixState([]), '');
  assert.equal(verificationFixState(null), '');
  assert.equal(verificationFixState([finding('new'), finding('accepted')]), '');
});

test('la mauvaise nouvelle prime sur la bonne', () => {
  // Un compagnon qui annonce « vérifiée ✓ » alors qu un autre finding est revenu
  // dit vrai sur un finding et faux sur l etat de l espace de travail.
  const pairs = [
    [[VERIFICATION_STATE.VALIDATED, VERIFICATION_STATE.REGRESSED], VERIFICATION_STATE.REGRESSED],
    [[VERIFICATION_STATE.VALIDATED, VERIFICATION_STATE.STILL_PRESENT], VERIFICATION_STATE.STILL_PRESENT],
    [[VERIFICATION_STATE.VALIDATED, VERIFICATION_STATE.INCONCLUSIVE], VERIFICATION_STATE.INCONCLUSIVE],
    [[VERIFICATION_STATE.FIX_APPLIED, VERIFICATION_STATE.VALIDATED], VERIFICATION_STATE.FIX_APPLIED],
    [[VERIFICATION_STATE.STILL_PRESENT, VERIFICATION_STATE.REGRESSED], VERIFICATION_STATE.REGRESSED]
  ];
  for (const [statuses, want] of pairs) {
    assert.equal(verificationFixState(statuses.map((status) => finding(status))), want, statuses.join(' + '));
  }
});

test('le cycle reel de fix-verification traverse jusqu au compagnon', () => {
  // Pas de statut fabrique a la main : on passe par les fonctions du moteur.
  const applied = markFixApplied(finding('new'), { source: 'quick_fix' });
  assert.equal(verificationFixState([applied]), VERIFICATION_STATE.FIX_APPLIED);
  assert.notEqual(modelFor(verificationFixState([applied])).mascotState, 'success');

  const validated = applyVerification(applied, {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z'
  });
  assert.equal(verificationFixState([validated]), VERIFICATION_STATE.VALIDATED);
  assert.equal(modelFor(verificationFixState([validated])).mascotState, 'success');

  const stillPresent = applyVerification(applied, {
    state: VERIFICATION_STATE.STILL_PRESENT, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.PRESENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z'
  });
  assert.equal(modelFor(verificationFixState([stillPresent])).mascotState, 'warning');
});

// ============================================ une seule interpretation

test('le cycle n est interprete qu a un seul endroit', () => {
  const messages = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionMessages.js'), 'utf8');
  const extension = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // Les noms d etats sont importes, jamais retapes en litteraux.
  assert.match(messages, /const \{ VERIFICATION_STATE \} = require\('\.\.\/fix-verification'\)/);
  // extension.js ne recollapse plus le cycle a deux etats.
  assert.match(extension, /fixState: verificationFixState\(currentFindings\)/);
  assert.ok(!/triageStatus === 'validated' \? 'validated'/.test(extension),
    'extension.js ne doit plus interpreter le cycle lui-meme');
  // Et une seule table de presentation existe.
  assert.equal((messages.match(/const FIX_PRESENTATION = /g) || []).length, 1);
});

test('aucune donnee sensible ne traverse la presentation du cycle', () => {
  const model = buildCompanionVisualModel({
    serviceState: 'clean', findings: [], file: 'config.js',
    pipeline: {
      fixState: VERIFICATION_STATE.VALIDATED,
      // Des champs qu un finding pourrait porter : rien ne doit remonter.
      secret: 'AKIAQYLPMN5HG7RTZW3D', patch: 'const k = "AKIAQYLPMN5HG7RTZW3D";',
      stderr: 'gitleaks: leak detected in config.js'
    }
  });
  const blob = JSON.stringify(model);
  for (const forbidden of ['AKIAQYLPMN5HG7RTZW3D', 'const k =', 'gitleaks: leak']) {
    assert.ok(!blob.includes(forbidden), `${forbidden} ne doit pas atteindre le compagnon`);
  }
  const html = renderCompanionWidget(model, { variant: 'full' });
  assert.ok(!html.includes('AKIAQYLPMN5HG7RTZW3D'));
});

test('le compagnon ne declenche aucune correction', () => {
  const widget = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionWidget.js'), 'utf8');
  const messages = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionMessages.js'), 'utf8');
  for (const source of [widget, messages]) {
    assert.ok(!/verifyFindingFix\(|runFixVerification\(|applyVerification\(|generateAiFix/.test(source),
      'le compagnon rapporte le cycle, il ne l execute pas');
  }
});
