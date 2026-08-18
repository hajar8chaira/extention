const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { remediationCounters, isActiveFinding, findingKey } = require('../src/triage');
const {
  VERIFICATION_STATE, VERIFICATION_REASON, VERIFIER, FIX_SOURCE,
  markFixApplied, applyVerification, detectRegressions, verificationIdentity
} = require('../src/fix-verification');

const semgrep = (extra = {}) => ({
  id: 'semgrep:js.sqli:src/db.js:42', tool: 'Semgrep', ruleId: 'js.sqli', category: 'security',
  file: 'src/db.js', startLine: 42, title: 'SQL injection', severity: 'high', rawSeverity: 'HIGH', ...extra
});

const withStatus = (status, extra = {}) => ({ ...semgrep(extra), triageStatus: status });

const completed = (tool) => [{ tool, status: 'completed' }];

// Le dashboard n'affiche des resultats que pour un scan termine : sans cela
// currentFindings est vide et toutes les tuiles affichent zero.
const model = (findings) => buildDashboardModel(findings, completed('Semgrep'), { scanStatus: 'completed' });
const dashboardHtml = (findings) => renderDashboardHtml(model(findings), 'n', 'full', 'light');

/** Reads one activity tile out of the rendered overview. */
function tile(html, label) {
  const pattern = new RegExp(`<strong>(\\d+)</strong><span>${label}</span>`);
  const match = html.match(pattern);
  assert.ok(match, `tuile « ${label} » absente`);
  return Number(match[1]);
}

// ============================================ separation des compteurs

test('le dashboard distingue corrigee de validee', () => {
  const html = dashboardHtml([
    withStatus('fixed', { id: 'a' }), withStatus('fixed', { id: 'b' }),
    withStatus('validated', { id: 'c' })
  ]);
  assert.equal(tile(html, 'Corrigées'), 2);
  assert.equal(tile(html, 'Validées'), 1);
});

test('un correctif appliqué ne compte jamais comme validé', () => {
  const html = dashboardHtml([withStatus('fixed', { id: 'a' })]);
  assert.equal(tile(html, 'Corrigées'), 1);
  assert.equal(tile(html, 'Validées'), 0, 'appliquer nest pas valider');
});

test('un finding réapparu ne compte pas comme validé', () => {
  const html = dashboardHtml([
    withStatus('regressed', { id: 'a' }), withStatus('validated', { id: 'b' })
  ]);
  assert.equal(tile(html, 'Validées'), 1, 'seul le finding réellement validé compte');
  assert.equal(tile(html, 'Corrigées'), 0);
});

test('les issues non résolues n améliorent aucun compteur de remédiation', () => {
  const html = dashboardHtml([
    withStatus('still_present', { id: 'a' }),
    withStatus('validation_failed', { id: 'b' }),
    withStatus('inconclusive', { id: 'c' })
  ]);
  assert.equal(tile(html, 'Corrigées'), 0);
  assert.equal(tile(html, 'Validées'), 0);
});

test('les issues non résolues restent des vulnérabilités actives', () => {
  for (const status of ['still_present', 'validation_failed', 'inconclusive', 'regressed', 'validating']) {
    assert.equal(isActiveFinding({ triageStatus: status }), true, status);
  }
  const built = model([
    withStatus('still_present', { id: 'a' }), withStatus('regressed', { id: 'b' }),
    withStatus('validated', { id: 'c' })
  ]);
  // Deux restent a traiter ; la validee sort du decompte actif.
  assert.equal(built.findings.filter(isActiveFinding).length, 2);
});

test('le dashboard ne recompte pas : il lit le cycle de vie', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  assert.match(source, /remediationCounters\(dedupedCurrentFindings\)/);
  assert.match(source, /require\('\.\/triage'\)/);
  // La conflation d'origine a disparu du calcul de la tuile.
  assert.ok(!/currentResolvedCount/.test(source), 'ancien compteur agrege encore present');
  const conflations = source.match(/\['fixed', 'validated'\]\.includes\(finding\.triageStatus\)/g) || [];
  assert.equal(conflations.length, 0, 'aucune addition directe des deux statuts pour les compteurs');
});

test('les compteurs du dashboard et du cycle de vie concordent', () => {
  const findings = [
    withStatus('fixed', { id: 'a' }), withStatus('validated', { id: 'b' }),
    withStatus('regressed', { id: 'c' }), withStatus('still_present', { id: 'd' }),
    withStatus('accepted', { id: 'e' }), withStatus('new', { id: 'f' })
  ];
  const counters = remediationCounters(findings);
  const html = dashboardHtml(findings);
  assert.equal(tile(html, 'Corrigées'), counters.fixApplied);
  assert.equal(tile(html, 'Validées'), counters.validated);
  assert.equal(tile(html, 'Acceptées'), 1, 'les statuts existants ne bougent pas');
  assert.equal(tile(html, 'Nouvelles'), 1);
});

test('la tuile validée réutilise le langage visuel existant', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');
  const html = dashboardHtml([withStatus('validated', { id: 'a' })]);
  assert.match(html, /class="activity-stat validated"/, 'meme classe que les autres tuiles');
  assert.match(source, /\.activity-stat\.validated \{ border-color: var\(--vscode-charts-green\); \}/);
  // Aucune couleur codee en dur pour la nouvelle tuile.
  assert.ok(!/\.activity-stat\.validated \{[^}]*#[0-9a-f]{3,6}/i.test(source));
  assert.match(source, /grid-template-columns: repeat\(4,1fr\)/, 'la grille accueille la tuile');
});

// ==================================== cycle de régression de bout en bout

test('le cycle complet mène de validée à réapparue', () => {
  const original = semgrep();
  // 1. correction appliquee — pas encore validee
  const applied = markFixApplied(original, { source: FIX_SOURCE.QUICK_FIX });
  assert.equal(applied.triageStatus, VERIFICATION_STATE.FIX_APPLIED);
  // 2. verification reussie
  const validated = applyVerification(applied, {
    state: VERIFICATION_STATE.VALIDATED, validator: VERIFIER.SAST_RESCAN,
    reason: VERIFICATION_REASON.ABSENT_AFTER_RESCAN, at: '2026-08-17T10:00:00.000Z',
    evidence: { verifier: VERIFIER.SAST_RESCAN, tool: 'Semgrep', scanId: 5, detail: '' }
  });
  assert.equal(validated.triageStatus, VERIFICATION_STATE.VALIDATED);
  // 3. la meme vulnerabilite est reintroduite et le scanner se termine
  const [regressed] = detectRegressions([validated], [semgrep()], completed('Semgrep'));
  assert.equal(regressed.triageStatus, VERIFICATION_STATE.REGRESSED);
  // 4. la preuve de la validation precedente est conservee
  assert.equal(regressed.previousValidation.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(regressed.previousValidation.at, '2026-08-17T10:00:00.000Z');
  assert.equal(regressed.previousValidation.evidence.scanId, 5);
  assert.equal(regressed.verificationHistory.length, 1);
  // 5. le dashboard ne la compte plus comme validee
  const html = dashboardHtml([regressed]);
  assert.equal(tile(html, 'Validées'), 0);
  // 6. et elle redevient une vulnerabilite a traiter
  assert.equal(isActiveFinding(regressed), true);
});

test('aucun finding sans rapport ne devient réapparu par ressemblance de titre', () => {
  const validated = { ...semgrep(), triageStatus: 'validated', validatedAt: '2026-08-17T10:00:00.000Z' };
  // Meme titre, meme regle, mais un autre fichier et une autre ligne.
  const elsewhere = semgrep({ id: 'semgrep:js.sqli:src/api.js:9', file: 'src/api.js', startLine: 9 });
  assert.notEqual(verificationIdentity(validated), verificationIdentity(elsewhere));
  assert.equal(detectRegressions([validated], [elsewhere], completed('Semgrep')).length, 0);
  // Et un titre reformule au meme endroit reste bien le meme finding.
  const reworded = semgrep({ id: '', title: 'Injection SQL dans une requete' });
  const validatedNoId = { ...semgrep({ id: '' }), triageStatus: 'validated' };
  assert.equal(detectRegressions([validatedNoId], [reworded], completed('Semgrep')).length, 1);
});

test('la régression exige un scanner réellement terminé', () => {
  const validated = { ...semgrep(), triageStatus: 'validated', validatedAt: 'x' };
  for (const statuses of [[], [{ tool: 'Semgrep', status: 'unavailable' }], [{ tool: 'Semgrep', status: 'cancelled' }], [{ tool: 'Trivy', status: 'completed' }]]) {
    assert.equal(detectRegressions([validated], [semgrep()], statuses).length, 0, JSON.stringify(statuses));
  }
});

test('l extension enregistre la régression avec sa validation antérieure', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8').split('\r').join('');
  assert.match(source, /detectRegressions\(previousFindings, correlated\.findings, scanStatuses\)/);
  assert.match(source, /savedStatuses\[findingKey\(finding\)\] = VERIFICATION_STATE\.REGRESSED/);
  assert.match(source, /previousValidatedAt: previous\?\.validatedAt \|\| finding\.previousValidation\?\.at \|\| null/);
});
