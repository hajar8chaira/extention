const chr13 = String.fromCharCode(13);
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  VERIFICATION_STATE, VERIFICATION_REASON, FIX_SOURCE, VERIFIER, STATE_LABELS, REASON_LABELS,
  verificationStrategyFor, verificationIdentity, interpretRescan, interpretRetest,
  verifyFindingFix, markFixApplied, markValidating, applyVerification,
  migrateLegacyStatus, detectRegressions, verificationRecord, restoreVerification
} = require('../src/fix-verification');
const { normalizeStatus, isActiveFinding, remediationCounters, applyFindingStatuses, findingKey } = require('../src/triage');

const semgrep = (extra = {}) => ({
  id: 'semgrep:js.sqli:src/db.js:42', tool: 'Semgrep', ruleId: 'js.sqli', category: 'security',
  file: 'src/db.js', startLine: 42, title: 'SQL injection', severity: 'high', ...extra
});
const gitleaks = (extra = {}) => ({
  id: 'gitleaks:aws-key:config.yml:7', tool: 'Gitleaks', ruleId: 'aws-access-key', category: 'secret',
  file: 'config.yml', startLine: 7, fingerprint: 'config.yml:aws-access-key:7', title: 'Clé AWS', ...extra
});
const trivyCve = (extra = {}) => ({
  id: 'trivy:CVE-2021-23337:lodash', tool: 'Trivy', ruleId: 'CVE-2021-23337', category: 'dependency',
  file: 'package-lock.json', title: 'lodash 4.17.20', ...extra
});
const trivyIac = (extra = {}) => ({
  id: 'trivy:AVD-DS-0002:Dockerfile', tool: 'Trivy', ruleId: 'AVD-DS-0002', category: 'misconfiguration',
  file: 'Dockerfile', title: 'Root user', ...extra
});
const zap = (extra = {}) => ({
  id: 'zap:40012', tool: 'ZAP', ruleId: '40012', category: 'dynamic',
  endpoint: 'http://127.0.0.1:3000/search', method: 'GET', parameter: 'q', title: 'XSS', ...extra
});

const completed = (tool) => [{ tool, status: 'completed' }];

// ================================================== dispatcher de stratégie

test('chaque famille de scanner reçoit son vérificateur', () => {
  assert.equal(verificationStrategyFor(semgrep()).verifier, VERIFIER.SAST_RESCAN);
  assert.equal(verificationStrategyFor({ tool: 'SonarQube' }).verifier, VERIFIER.SAST_RESCAN);
  assert.equal(verificationStrategyFor(gitleaks()).verifier, VERIFIER.SECRET_RESCAN);
  assert.equal(verificationStrategyFor(trivyCve()).verifier, VERIFIER.SCA_RESCAN);
  assert.equal(verificationStrategyFor({ tool: 'OSV-Scanner' }).verifier, VERIFIER.SCA_RESCAN);
  assert.equal(verificationStrategyFor({ tool: 'Snyk', category: 'dependency' }).verifier, VERIFIER.SCA_RESCAN);
  assert.equal(verificationStrategyFor(zap()).verifier, VERIFIER.DAST_RETEST);
});

test('Trivy et Snyk sont départagés par la catégorie, pas par l’outil', () => {
  assert.equal(verificationStrategyFor(trivyIac()).verifier, VERIFIER.IAC_RESCAN);
  assert.equal(verificationStrategyFor(trivyCve()).verifier, VERIFIER.SCA_RESCAN);
  assert.equal(verificationStrategyFor({ tool: 'Snyk', category: 'misconfiguration' }).verifier, VERIFIER.IAC_RESCAN);
});

test('un outil sans vérificateur sûr est nommé, pas deviné', () => {
  assert.equal(verificationStrategyFor({ tool: 'OutilInconnu' }).verifier, VERIFIER.NONE);
  assert.equal(verificationStrategyFor({}).verifier, VERIFIER.NONE);
  assert.equal(verificationStrategyFor(null).verifier, VERIFIER.NONE);
});

// ======================================================= identité stable

test('l’identité réutilise l’empreinte du scanner quand elle existe', () => {
  assert.equal(verificationIdentity(gitleaks()), 'config.yml:aws-access-key:7');
  // Deux findings au même titre mais à des endroits différents restent distincts.
  assert.notEqual(
    verificationIdentity(semgrep({ id: '', startLine: 42 })),
    verificationIdentity(semgrep({ id: '', startLine: 99 }))
  );
});

test('l’identité ne repose jamais sur le titre seul', () => {
  const before = semgrep({ id: '', title: 'SQL injection' });
  const reworded = semgrep({ id: '', title: 'Injection SQL détectée dans une requête' });
  assert.equal(verificationIdentity(before), verificationIdentity(reworded),
    'un scanner qui reformule son message ne doit pas ressembler à une correction');
});

test('l’identité DAST porte la route, la méthode et le paramètre', () => {
  const identity = verificationIdentity(zap({ id: '' }));
  assert.match(identity, /GET/);
  assert.match(identity, /\/search/);
  assert.match(identity, /q/);
  assert.notEqual(identity, verificationIdentity(zap({ id: '', method: 'POST' })));
  assert.notEqual(identity, verificationIdentity(zap({ id: '', parameter: 'autre' })));
});

// ============================================ appliquer n’est pas valider

test('appliquer une correction ne valide jamais', () => {
  for (const source of [FIX_SOURCE.QUICK_FIX, FIX_SOURCE.AI, FIX_SOURCE.MANUAL]) {
    const applied = markFixApplied(semgrep(), { source });
    assert.equal(applied.triageStatus, VERIFICATION_STATE.FIX_APPLIED);
    assert.notEqual(applied.triageStatus, VERIFICATION_STATE.VALIDATED);
    assert.equal(applied.verificationPending, true);
    assert.equal(applied.verification, null, 'aucune preuve n’existe encore');
    assert.equal(applied.fixSource, source);
  }
});

test('le libellé de la correction appliquée dit que la vérification manque', () => {
  assert.match(STATE_LABELS[VERIFICATION_STATE.FIX_APPLIED], /vérification en attente/);
  assert.match(STATE_LABELS[VERIFICATION_STATE.VALIDATED], /Validée/);
  assert.notEqual(STATE_LABELS[VERIFICATION_STATE.FIX_APPLIED], STATE_LABELS[VERIFICATION_STATE.VALIDATED]);
});

test('VALIDATING ne porte aucun verdict', () => {
  const validating = markValidating(markFixApplied(semgrep()));
  assert.equal(validating.triageStatus, VERIFICATION_STATE.VALIDATING);
  assert.equal(validating.verificationPending, true);
  assert.ok(validating.validationStartedAt);
});

// ================================================== lecture d’un rescan

test('le même finding absent après une analyse terminée vaut validation', () => {
  const result = interpretRescan({ finding: semgrep(), findings: [], scannerStatuses: completed('Semgrep') });
  assert.equal(result.outcome, VERIFICATION_STATE.VALIDATED);
  assert.equal(result.reason, VERIFICATION_REASON.ABSENT_AFTER_RESCAN);
});

test('le même finding toujours présent vaut échec de correction', () => {
  const result = interpretRescan({ finding: semgrep(), findings: [semgrep()], scannerStatuses: completed('Semgrep') });
  assert.equal(result.outcome, VERIFICATION_STATE.STILL_PRESENT);
});

test('un autre finding du même scanner ne vaut pas présence', () => {
  const other = semgrep({ id: 'semgrep:js.xss:src/ui.js:5', ruleId: 'js.xss', file: 'src/ui.js', startLine: 5 });
  const result = interpretRescan({ finding: semgrep(), findings: [other], scannerStatuses: completed('Semgrep') });
  assert.equal(result.outcome, VERIFICATION_STATE.VALIDATED, 'seul le même finding compte');
});

test('un scanner qui n’a pas tourné ne prouve pas une absence', () => {
  // Le piège central : « liste vide » et « scanner absent » se ressemblent.
  const result = interpretRescan({ finding: semgrep(), findings: [], scannerStatuses: [] });
  assert.equal(result.outcome, VERIFICATION_STATE.INCONCLUSIVE);
  assert.equal(result.reason, VERIFICATION_REASON.SCANNER_INCOMPLETE);
});

test('les échecs techniques ne deviennent ni validation ni présence', () => {
  const cases = [
    ['unavailable', VERIFICATION_REASON.SCANNER_UNAVAILABLE],
    ['not_installed', VERIFICATION_REASON.SCANNER_UNAVAILABLE],
    ['cancelled', VERIFICATION_REASON.CANCELLED],
    ['timeout', VERIFICATION_REASON.TIMEOUT]
  ];
  for (const [status, reason] of cases) {
    const result = interpretRescan({ finding: semgrep(), findings: [], scannerStatuses: [{ tool: 'Semgrep', status }] });
    assert.equal(result.outcome, VERIFICATION_STATE.VALIDATION_FAILED, status);
    assert.equal(result.reason, reason);
    assert.notEqual(result.outcome, VERIFICATION_STATE.VALIDATED);
    assert.notEqual(result.outcome, VERIFICATION_STATE.STILL_PRESENT);
  }
});

test('un scanner échoué pour un autre outil ne bloque pas la vérification', () => {
  const result = interpretRescan({
    finding: semgrep(), findings: [],
    scannerStatuses: [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Trivy', status: 'unavailable' }]
  });
  assert.equal(result.outcome, VERIFICATION_STATE.VALIDATED);
});

// ============================================= lecture d’un re-test DAST

test('le verdict DAST existant est traduit, pas recalculé', () => {
  assert.equal(interpretRetest({ state: 'VALIDATED', reason: 'evidence_gone' }).outcome, VERIFICATION_STATE.VALIDATED);
  assert.equal(interpretRetest({ state: 'STILL_PRESENT' }).outcome, VERIFICATION_STATE.STILL_PRESENT);
  assert.equal(interpretRetest({ state: 'INCONCLUSIVE' }).outcome, VERIFICATION_STATE.INCONCLUSIVE);
  // Tout verdict inconnu retombe sur non concluant, jamais sur validé.
  assert.equal(interpretRetest({ state: 'AUTRE' }).outcome, VERIFICATION_STATE.INCONCLUSIVE);
  assert.equal(interpretRetest(null).outcome, VERIFICATION_STATE.INCONCLUSIVE);
});

// =================================================== l’orchestrateur

test('l’orchestrateur mène une correction Quick Fix jusqu’à validée', async () => {
  const result = await verifyFindingFix(semgrep(), {
    runVerifier: async (strategy) => {
      assert.equal(strategy.verifier, VERIFIER.SAST_RESCAN);
      return { findings: [], scannerStatuses: completed('Semgrep'), scanId: 77 };
    }
  });
  assert.equal(result.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(result.validator, VERIFIER.SAST_RESCAN);
  assert.equal(result.evidence.scanId, 77);
  assert.equal(result.evidence.tool, 'Semgrep');
  assert.ok(result.at);
});

test('l’orchestrateur signale une correction qui n’a pas fonctionné', async () => {
  const result = await verifyFindingFix(semgrep(), {
    runVerifier: async () => ({ findings: [semgrep()], scannerStatuses: completed('Semgrep'), scanId: 78 })
  });
  assert.equal(result.state, VERIFICATION_STATE.STILL_PRESENT);
  assert.equal(result.reason, VERIFICATION_REASON.PRESENT_AFTER_RESCAN);
});

test('un vérificateur qui échoue ne produit jamais de validation', async () => {
  const result = await verifyFindingFix(semgrep(), {
    runVerifier: async () => { throw new Error('Semgrep a planté'); }
  });
  assert.equal(result.state, VERIFICATION_STATE.VALIDATION_FAILED);
  assert.equal(result.reason, VERIFICATION_REASON.VALIDATOR_ERROR);
  assert.match(result.evidence.detail, /planté/);
});

test('annulation et délai dépassé sont distingués', async () => {
  const cancelled = await verifyFindingFix(semgrep(), {
    runVerifier: async () => { throw new Error('Scan annulé.'); }
  });
  assert.equal(cancelled.reason, VERIFICATION_REASON.CANCELLED);
  const timedOut = await verifyFindingFix(semgrep(), {
    runVerifier: async () => { throw new Error('Le scan a dépassé son délai.'); }
  });
  assert.equal(timedOut.reason, VERIFICATION_REASON.TIMEOUT);
  // Une annulation après coup est vue même si le vérificateur a répondu.
  const lateCancel = await verifyFindingFix(semgrep(), {
    token: { isCancellationRequested: true },
    runVerifier: async () => ({ findings: [], scannerStatuses: completed('Semgrep') })
  });
  assert.equal(lateCancel.state, VERIFICATION_STATE.VALIDATION_FAILED);
  assert.equal(lateCancel.reason, VERIFICATION_REASON.CANCELLED);
});

test('un finding sans vérificateur est non concluant, pas validé', async () => {
  let called = false;
  const result = await verifyFindingFix({ tool: 'OutilInconnu', id: 'x' }, {
    runVerifier: async () => { called = true; return { findings: [], scannerStatuses: [] }; }
  });
  assert.equal(result.state, VERIFICATION_STATE.INCONCLUSIVE);
  assert.equal(result.reason, VERIFICATION_REASON.NO_VERIFIER);
  assert.equal(called, false, 'aucun vérificateur ne doit être lancé');
});

test('un vérificateur qui ne renvoie rien d’exploitable est une erreur', async () => {
  for (const raw of [null, undefined, 'texte', 42]) {
    const result = await verifyFindingFix(semgrep(), { runVerifier: async () => raw });
    assert.equal(result.state, VERIFICATION_STATE.VALIDATION_FAILED, String(raw));
    assert.equal(result.reason, VERIFICATION_REASON.VALIDATOR_ERROR);
  }
});

test('vérifier avant toute correction est refusé quand le contexte l’exige', async () => {
  const result = await verifyFindingFix(semgrep(), {
    requireFixApplied: true, fixApplied: false, runVerifier: async () => ({ findings: [] })
  });
  assert.equal(result.state, VERIFICATION_STATE.INCONCLUSIVE);
  assert.equal(result.reason, VERIFICATION_REASON.NOT_APPLIED);
});

test('l’orchestrateur DAST délègue au verdict de re-test existant', async () => {
  const result = await verifyFindingFix(zap(), {
    runVerifier: async (strategy) => {
      assert.equal(strategy.verifier, VERIFIER.DAST_RETEST);
      return { verdict: { state: 'VALIDATED', reason: 'evidence_gone' }, retestId: 'retest-1' };
    }
  });
  assert.equal(result.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(result.reason, VERIFICATION_REASON.RETEST_EVIDENCE_GONE);
  assert.equal(result.evidence.retestId, 'retest-1');
});

test('un 200 sans preuve ne valide pas un finding DAST', async () => {
  // Le verdict vient du moteur DAST ; un statut HTTP n'est pas un verdict.
  const result = await verifyFindingFix(zap(), {
    runVerifier: async () => ({ verdict: { state: 'STILL_PRESENT', reason: 'evidence_present' }, retestId: 'r2' })
  });
  assert.equal(result.state, VERIFICATION_STATE.STILL_PRESENT);
});

// ================================== application du résultat au finding

test('le résultat écrit le statut, la preuve et l’historique', () => {
  const applied = markFixApplied(semgrep(), { source: FIX_SOURCE.QUICK_FIX });
  const verified = applyVerification(applied, {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z',
    evidence: { verifier: VERIFIER.SAST_RESCAN, tool: 'Semgrep', scanId: 12, retestId: null, detail: '' }
  });
  assert.equal(verified.triageStatus, VERIFICATION_STATE.VALIDATED);
  assert.equal(verified.validatedAt, '2026-08-17T12:00:00.000Z');
  assert.equal(verified.verificationPending, false);
  assert.equal(verified.verification.validator, VERIFIER.SAST_RESCAN);
  assert.equal(verified.verificationHistory.length, 1);
});

test('un échec de vérification laisse la vérification en attente', () => {
  const verified = applyVerification(markFixApplied(semgrep()), {
    state: VERIFICATION_STATE.STILL_PRESENT, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.PRESENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z'
  });
  assert.equal(verified.verificationPending, true);
  assert.equal(verified.validatedAt, undefined, 'aucune date de validation sur un échec');
});

test('une décision humaine n’est pas écrasée par une vérification', () => {
  for (const status of ['false_positive', 'accepted']) {
    const decided = { ...semgrep(), triageStatus: status };
    const after = applyVerification(decided, { state: VERIFICATION_STATE.STILL_PRESENT, at: 'x' });
    assert.equal(after.triageStatus, status, `${status} doit survivre`);
  }
});

test('l’historique conserve les vérifications successives', () => {
  let finding = markFixApplied(semgrep());
  for (const state of [VERIFICATION_STATE.STILL_PRESENT, VERIFICATION_STATE.INCONCLUSIVE, VERIFICATION_STATE.VALIDATED]) {
    finding = applyVerification(finding, { state, validator: VERIFIER.SAST_RESCAN, reason: 'r', at: '2026-08-17T12:00:00.000Z' });
  }
  assert.equal(finding.verificationHistory.length, 3);
  assert.equal(finding.triageStatus, VERIFICATION_STATE.VALIDATED);
});

// ===================================== compatibilité avec l’existant

test('un ancien « fixed » ne devient pas silencieusement validé', () => {
  const migrated = migrateLegacyStatus('fixed');
  assert.equal(migrated.status, VERIFICATION_STATE.FIX_APPLIED);
  assert.equal(migrated.verificationPending, true);
  assert.notEqual(migrated.status, VERIFICATION_STATE.VALIDATED);
});

test('un « validated » existant garde son sens', () => {
  const migrated = migrateLegacyStatus('validated');
  assert.equal(migrated.status, VERIFICATION_STATE.VALIDATED);
  assert.equal(migrated.verificationPending, false);
});

test('les statuts existants restent acceptés par le modèle de triage', () => {
  for (const status of ['new', 'triaged', 'probable', 'confirmed', 'fixed', 'validated', 'false_positive', 'accepted']) {
    assert.equal(normalizeStatus(status), status, `${status} doit survivre`);
  }
});

test('les nouveaux états traversent le modèle de triage sans être écrasés', () => {
  for (const status of ['validating', 'still_present', 'validation_failed', 'inconclusive', 'regressed', 'fix_proposed']) {
    assert.equal(normalizeStatus(status), status);
  }
  // Et ils survivent au chemin de persistance existant.
  const finding = semgrep();
  const [restored] = applyFindingStatuses([finding], { [findingKey(finding)]: 'still_present' });
  assert.equal(restored.triageStatus, 'still_present');
});

test('un résultat de vérification non concluant reste une vulnérabilité active', () => {
  for (const status of ['validating', 'still_present', 'validation_failed', 'inconclusive', 'regressed']) {
    assert.equal(isActiveFinding({ triageStatus: status }), true, `${status} ne doit pas disparaître des compteurs actifs`);
  }
  assert.equal(isActiveFinding({ triageStatus: 'validated' }), false);
});

test('les compteurs ne confondent plus corrigé et validé', () => {
  const counters = remediationCounters([
    { triageStatus: 'fixed' }, { triageStatus: 'fixed' }, { triageStatus: 'validated' },
    { triageStatus: 'still_present' }, { triageStatus: 'inconclusive' },
    { triageStatus: 'validation_failed' }, { triageStatus: 'regressed' }
  ]);
  assert.equal(counters.fixApplied, 2);
  assert.equal(counters.validated, 1);
  assert.equal(counters.stillPresent, 1);
  assert.equal(counters.inconclusive, 2);
  assert.equal(counters.regressed, 1);
  assert.notEqual(counters.fixApplied, counters.validated);
});

// ==================================================== régression

test('un finding validé qui réapparaît est marqué réapparu', () => {
  const validated = applyVerification(markFixApplied(semgrep()), {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T10:00:00.000Z'
  });
  const [regressed] = detectRegressions([validated], [semgrep()], completed('Semgrep'));
  assert.equal(regressed.triageStatus, VERIFICATION_STATE.REGRESSED);
  // La preuve de la validation précédente est conservée, pas effacée.
  assert.equal(regressed.previousValidation.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(regressed.previousValidation.at, '2026-08-17T10:00:00.000Z');
  assert.equal(regressed.verificationHistory.length, 1);
});

test('aucune régression n’est déduite d’un scanner qui n’a pas tourné', () => {
  const validated = { ...semgrep(), triageStatus: 'validated', validatedAt: '2026-08-17T10:00:00.000Z' };
  assert.equal(detectRegressions([validated], [semgrep()], []).length, 0);
  assert.equal(detectRegressions([validated], [semgrep()], [{ tool: 'Semgrep', status: 'unavailable' }]).length, 0);
  assert.equal(detectRegressions([validated], [semgrep()], completed('Semgrep')).length, 1);
});

test('un finding jamais validé qui persiste n’est pas une régression', () => {
  const applied = markFixApplied(semgrep());
  assert.equal(detectRegressions([applied], [semgrep()], completed('Semgrep')).length, 0);
});

// ==================================================== persistance

test('l’enregistrement ne contient que des métadonnées', () => {
  const verified = applyVerification(markFixApplied(gitleaks(), { source: FIX_SOURCE.MANUAL }), {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SECRET_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z',
    evidence: { verifier: VERIFIER.SECRET_RESCAN, tool: 'Gitleaks', scanId: 5, retestId: null, detail: '' }
  });
  const record = verificationRecord(verified);
  assert.equal(record.status, VERIFICATION_STATE.VALIDATED);
  assert.equal(record.validator, VERIFIER.SECRET_RESCAN);
  assert.equal(record.scanId, 5);
  assert.equal(record.fixSource, FIX_SOURCE.MANUAL);
  assert.ok(record.validatedAt);
});

test('aucun secret ni contenu de patch n’entre dans l’enregistrement', () => {
  const verified = applyVerification(
    markFixApplied(gitleaks({
      secret: 'AKIAIOSFODNN7EXAMPLE', match: 'aws_key = AKIAIOSFODNN7EXAMPLE',
      patch: '- aws_key = AKIAIOSFODNN7EXAMPLE\n+ aws_key = env("AWS_KEY")'
    })),
    {
      state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SECRET_RESCAN, reason: 'r', at: 'x',
      evidence: { verifier: VERIFIER.SECRET_RESCAN, tool: 'Gitleaks', scanId: 5, detail: '' }
    }
  );
  const blob = JSON.stringify(verificationRecord(verified));
  assert.ok(!blob.includes('AKIAIOSFODNN7EXAMPLE'), 'aucun secret brut');
  assert.ok(!blob.includes('aws_key ='), 'aucun extrait de code');
  assert.ok(!blob.includes('patch'));
});

test('le détail d’une erreur est borné', () => {
  const verified = applyVerification(markFixApplied(semgrep()), {
    state: VERIFICATION_STATE.VALIDATION_FAILED, validator: VERIFIER.SAST_RESCAN, reason: 'r', at: 'x',
    evidence: { verifier: VERIFIER.SAST_RESCAN, tool: 'Semgrep', detail: 'x'.repeat(5000) }
  });
  assert.ok(verificationRecord(verified).detail.length <= 200);
});

test('l’état validé survit à un redémarrage', () => {
  const verified = applyVerification(markFixApplied(semgrep(), { source: FIX_SOURCE.AI }), {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z',
    evidence: { verifier: VERIFIER.SAST_RESCAN, tool: 'Semgrep', scanId: 9, detail: '' }
  });
  const record = JSON.parse(JSON.stringify(verificationRecord(verified)));
  const restored = restoreVerification(record);
  assert.equal(restored.status, VERIFICATION_STATE.VALIDATED);
  assert.equal(restored.validatedAt, '2026-08-17T12:00:00.000Z');
  assert.equal(restored.verification.validator, VERIFIER.SAST_RESCAN);
  assert.equal(restored.verification.evidence.scanId, 9);
  assert.equal(restored.fixSource, FIX_SOURCE.AI);
});

test('un enregistrement illisible est rejeté, pas réparé', () => {
  for (const raw of [null, {}, 'texte', { key: 'k', status: 'inventé' }, { status: 'validated' }]) {
    assert.equal(restoreVerification(raw), null, JSON.stringify(raw));
  }
});

test('chaque état et chaque raison ont un libellé', () => {
  for (const state of Object.values(VERIFICATION_STATE)) {
    assert.ok(STATE_LABELS[state], `libellé manquant pour ${state}`);
  }
  for (const reason of Object.values(VERIFICATION_REASON)) {
    assert.ok(REASON_LABELS[reason], `libellé manquant pour ${reason}`);
  }
});

// ============================================== rendu du détail de finding

const fs = require('fs');
const path = require('path');
const { renderFindingDetailsHtml } = require('../src/finding-details');

const renderDetails = (finding) => renderFindingDetailsHtml(finding, 'n', {});

test('un correctif appliqué n’est jamais présenté comme validé', () => {
  const html = renderDetails(markFixApplied(semgrep(), { source: FIX_SOURCE.QUICK_FIX }));
  assert.match(html, /vérification en attente/);
  assert.match(html, /aucun scanner ne l’a encore confirmé/);
  assert.ok(!html.includes('✓ Validée'), 'rien ne doit affirmer une validation');
  assert.match(html, /data-verify="1"/, 'l’action qui trancherait est proposée');
});

test('une validation affiche son vérificateur, sa date et son scan', () => {
  const validated = applyVerification(markFixApplied(semgrep(), { source: FIX_SOURCE.QUICK_FIX }), {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T12:00:00.000Z',
    evidence: { verifier: VERIFIER.SAST_RESCAN, tool: 'Semgrep', scanId: 31, detail: '' }
  });
  const html = renderDetails(validated);
  assert.match(html, /✓ Validée/);
  assert.match(html, /sast_rescan/);
  assert.match(html, /2026-08-17T12:00:00\.000Z/);
  assert.match(html, /31/);
  assert.match(html, /n’apparaît plus après une nouvelle analyse/);
  assert.match(html, /Quick Fix déterministe/);
  assert.ok(!/data-verify="1"/.test(html), 'rien à revérifier sur une validation');
});

test('chaque issue de vérification a son rendu', () => {
  const outcomes = {
    [VERIFICATION_STATE.STILL_PRESENT]: /✕ Toujours présente/,
    [VERIFICATION_STATE.INCONCLUSIVE]: /\? Non concluant/,
    [VERIFICATION_STATE.VALIDATION_FAILED]: /Vérification impossible/,
    [VERIFICATION_STATE.VALIDATING]: /Vérification en cours/,
    [VERIFICATION_STATE.REGRESSED]: /Réapparue après validation/
  };
  for (const [state, expected] of Object.entries(outcomes)) {
    const html = renderDetails(applyVerification(markFixApplied(semgrep()), {
      state, validator: VERIFIER.SAST_RESCAN, reason: VERIFICATION_REASON.PRESENT_AFTER_RESCAN, at: 'x'
    }));
    assert.match(html, expected, state);
    assert.match(html, /Relancer la vérification/, `${state} doit rester réessayable`);
  }
});

test('un patch IA garde son rollback accessible', () => {
  const html = renderDetails(applyVerification(markFixApplied(semgrep(), { source: FIX_SOURCE.AI, by: 'Ollama' }), {
    state: VERIFICATION_STATE.STILL_PRESENT, validator: VERIFIER.SAST_RESCAN, reason: 'r', at: 'x'
  }));
  assert.match(html, /data-rollback="1"/);
  assert.match(html, /Patch Ollama/);
});

test('aucun secret ni patch n’atteint la page de détail', () => {
  const html = renderDetails(applyVerification(
    markFixApplied(gitleaks({ secret: 'AKIAIOSFODNN7EXAMPLE' })),
    { state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SECRET_RESCAN, reason: 'r', at: 'x',
      evidence: { verifier: VERIFIER.SECRET_RESCAN, tool: 'Gitleaks', scanId: 1, detail: '' } }
  ));
  assert.ok(!html.includes('AKIAIOSFODNN7EXAMPLE'));
});

test('le détail échappe le contenu de la vérification', () => {
  const html = renderDetails(applyVerification(markFixApplied(semgrep()), {
    state: VERIFICATION_STATE.VALIDATION_FAILED, validator: '<script>alert(1)</script>',
    reason: 'r', at: 'x', evidence: { verifier: 'v', tool: 't', detail: '<img src=x onerror=alert(1)>' }
  }));
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('<img src=x onerror'));
});

// ================================================ garde-fous du câblage

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

test('les trois chemins de correction passent par le même cycle', () => {
  const source = extensionSource();
  // Quick Fix, IA et vérification manuelle appellent le même orchestrateur.
  assert.equal((source.match(/runFixVerification\(/g) || []).length, 4, 'une définition et trois appels');
  assert.match(source, /markFixApplied\(finding, \{ source: FIX_SOURCE\.QUICK_FIX/);
  assert.match(source, /markFixApplied\(finding, \{ source: FIX_SOURCE\.AI/);
  assert.match(source, /registerCommand\('securityCenter\.verifyFindingFix'/);
});

test('aucun chemin n’écrit « validated » sans passer par une vérification', () => {
  const source = extensionSource();
  // Le seul écrivain restant est validatedAfterScan, qui compare déjà des
  // empreintes après un scan terminé.
  const directWrites = source.match(/[^=!]=\s*'validated'/g) || [];
  assert.equal(directWrites.length, 1, 'un seul point d’écriture directe');
  assert.match(source, /for \(const finding of validatedFindings\) savedStatuses\[findingKey\(finding\)\] = 'validated'/);
  // Et plus aucun chemin ne marque « fixed » à la main.
  assert.ok(!/savedAiStatuses\[findingKey\(finding\)\] = 'fixed'/.test(source),
    'le chemin IA ne doit plus écrire le statut directement');
});

test('la régression est détectée après un scan', () => {
  const source = extensionSource();
  assert.match(source, /detectRegressions\(previousFindings, correlated\.findings, scanStatuses\)/);
  assert.match(source, /savedStatuses\[findingKey\(finding\)\] = VERIFICATION_STATE\.REGRESSED/);
  assert.match(source, /previousValidatedAt/, 'la validation précédente est conservée');
});

test('la vérification persiste des métadonnées et rien d’autre', () => {
  const source = extensionSource();
  const source_ = source.split(chr13).join('');
  const persist = source_.slice(source_.indexOf('async function persistVerification'));
  const body = persist.slice(0, persist.indexOf('\n  }\n'));
  assert.match(body, /verificationRecord\(finding\)/, 'la persistance passe par le projeteur');
  assert.ok(!/JSON\.stringify\(finding\)/.test(body), 'le finding complet n’est pas écrit');
});

test('l’audit de vérification ne consigne aucun contenu de patch', () => {
  const source = extensionSource();
  const source_ = source.split(chr13).join('');
  const run = source_.slice(source_.indexOf('async function runFixVerification'));
  const audit = run.slice(run.indexOf('createAuditEvent'), run.indexOf('if (!silent)'));
  assert.match(audit, /action: `fix\.verification\.\$\{result\.state\}`/);
  // Les commentaires parlent du correctif ; c'est le code qui ne doit pas le
  // transporter.
  const code = audit.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');
  assert.ok(!/patch|replacement|originalText|generated\./.test(code),
    'aucun extrait de correctif dans l’audit');
});

test('la vérification DAST réutilise le re-test existant', () => {
  const source = extensionSource();
  const source_ = source.split(chr13).join('');
  const verify = source_.slice(source_.indexOf('async function verifyDynamicFinding'));
  const body = verify.slice(0, verify.indexOf('\n  }\n'));
  assert.match(body, /replayScenario\(/);
  assert.match(body, /retestVerdict\(/);
  assert.ok(!/runZap|beginZapCampaign/.test(body), 'aucun scan ZAP complet');
});

test('le rescan de vérification se limite au scanner concerné', () => {
  const source = extensionSource();
  const run = source.slice(source.indexOf('async function runFixVerification'));
  assert.match(run.slice(0, 2500), /scanWorkspace', \[finding\.tool\]/);
});
