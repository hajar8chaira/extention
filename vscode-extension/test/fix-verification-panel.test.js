'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  VERIFICATION_STATE, VERIFICATION_REASON, VERIFIER,
  verifyFindingFix, markFixApplied, applyVerification
} = require('../src/fix-verification');
const { renderFindingDetailsHtml } = require('../src/finding-details');
const { runDeclaredTests, declaredTestScript } = require('../src/ai/fix-verifier');

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/** Le finding reel du rapport : SonarQube, javascript:S4790, Gruntfile.js:75. */
const sonarFinding = (over = {}) => ({
  id: 'sonarqube:javascript:S4790:Gruntfile.js:75',
  fingerprint: 'sonarqube:javascript:S4790:Gruntfile.js:75',
  tool: 'SonarQube', ruleId: 'javascript:S4790', category: 'security',
  file: 'Gruntfile.js', absolutePath: '/w/Gruntfile.js', startLine: 75,
  title: 'Using weak hashing algorithms is security-sensitive',
  rawSeverity: 'HIGH', severity: 'HIGH', triageStatus: 'new', ...over
});

const completed = (tool = 'SonarQube') => [{ tool, status: 'completed', details: '140 résultat(s)' }];

// ===========================================================================
// Le scenario reel, de bout en bout
// ===========================================================================

test('verification : le re-scan SonarQube sans le finding produit VALIDATED', async () => {
  const finding = markFixApplied(sonarFinding(), { source: 'ai', by: 'Ollama' });
  const result = await verifyFindingFix(finding, {
    // Le re-scan a rendu 140 resultats, aucun n'etant ce finding.
    runVerifier: async () => ({ findings: [sonarFinding({ id: 'autre', fingerprint: 'autre' })], scannerStatuses: completed(), scanId: 42 })
  });
  assert.equal(result.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(result.reason, VERIFICATION_REASON.ABSENT_AFTER_RESCAN);
  assert.equal(result.validator, VERIFIER.SAST_RESCAN);
  assert.equal(result.evidence.tool, 'SonarQube', 'la preuve nomme le scanner reel');
  assert.equal(result.evidence.scanId, 42);
  assert.ok(result.at, 'un horodatage reel est enregistre');
});

test('verification : le finding porte ensuite un etat coherent, pas « Ouverte »', async () => {
  const applied = markFixApplied(sonarFinding(), { source: 'ai', by: 'Ollama' });
  const result = await verifyFindingFix(applied, {
    runVerifier: async () => ({ findings: [], scannerStatuses: completed(), scanId: 42 })
  });
  const verified = applyVerification(applied, result);
  assert.equal(verified.triageStatus, VERIFICATION_STATE.VALIDATED);
  assert.notEqual(verified.triageStatus, 'new');
  assert.equal(verified.verification.state, VERIFICATION_STATE.VALIDATED);
});

test('verification : la page de detail rendue avec le finding verifie n affiche plus « Ouverte »', async () => {
  const applied = markFixApplied(sonarFinding(), { source: 'ai', by: 'Ollama' });
  const result = await verifyFindingFix(applied, {
    runVerifier: async () => ({ findings: [], scannerStatuses: completed(), scanId: 42 })
  });
  const verified = applyVerification(applied, result);

  const stale = renderFindingDetailsHtml(sonarFinding(), 'n', { findings: [] });
  const fresh = renderFindingDetailsHtml(verified, 'n', { findings: [] });

  // Etat avant : c'est exactement ce que la page figee continuait d'afficher.
  assert.match(stale, /Ouverte/);
  // Etat apres : le verdict, sa raison et son verificateur.
  assert.match(fresh, /Validée/);
  assert.doesNotMatch(fresh, /<strong>Ouverte<\/strong>/);
  assert.match(fresh, /n’apparaît plus/, 'la raison réelle est affichée');
  assert.match(fresh, /Vérificateur/);
});

test('verification : le bouton « Vérifier » suit le cycle de vie', () => {
  const open = renderFindingDetailsHtml(sonarFinding(), 'n', { findings: [] });
  const applied = renderFindingDetailsHtml(markFixApplied(sonarFinding()), 'n', { findings: [] });
  const validated = renderFindingDetailsHtml(sonarFinding({ triageStatus: 'validated' }), 'n', { findings: [] });
  // Une correction appliquee attend sa verification : l'action reste offerte.
  assert.match(applied, /verifyFix/);
  assert.match(open, /verifyFix/);
  // Une fois validee, la page ne laisse pas un bouton desactive qui semble casse.
  const details = fs.readFileSync(path.join(__dirname, '..', 'src', 'finding-details.js'), 'utf8');
  assert.match(details, /const canVerify = finding\.triageStatus !== 'validated'/);
  assert.match(validated, /Validée/);
});

// ===========================================================================
// Le panneau ouvert doit se redessiner
// ===========================================================================

test('panneau : un changement d etat redessine la page de detail ouverte', () => {
  const source = extensionSource();
  // Le rendu est extrait, donc reutilisable apres coup.
  assert.match(source, /function renderFindingDetailsPanel\(finding, navigationContext = findingDetailsContext\)/);
  // `replaceFinding` — le point unique par lequel passe tout changement d'etat
  // de finding — redessine la page si elle montre ce finding.
  const replace = source.match(/function replaceFinding\(updated\)[\s\S]*?\n  \}/)[0];
  assert.match(replace, /findingKey\(findingDetailsFinding\) === key/);
  assert.match(replace, /renderFindingDetailsPanel\(updated\)/);
  // Et le snapshot capte a l'ouverture est remplace, pas conserve.
  assert.match(source, /function renderFindingDetailsPanel[\s\S]*?findingDetailsFinding = finding;/);
});

test('panneau : la page n est plus rendue une seule fois a l ouverture', () => {
  const source = extensionSource();
  const command = source.match(/registerCommand\('securityCenter\.showFindingDetails'[\s\S]*?\n  \}\)\);/)[0];
  // L'ouverture delegue au meme rendu que la mise a jour : une seule voie.
  assert.match(command, /renderFindingDetailsPanel\(finding, navigationContext\)/);
  assert.doesNotMatch(command, /webview\.html = renderFindingDetailsHtml/, 'plus de rendu unique en dur a l ouverture');
});

test('panneau : aucune reouverture requise et aucun rechargement d extension', () => {
  const source = extensionSource();
  const replace = source.match(/function replaceFinding\(updated\)[\s\S]*?\n  \}/)[0];
  for (const forbidden of ['reloadWindow', 'workbench.action.reloadWindow', 'dispose()', 'createWebviewPanel']) {
    assert.ok(!replace.includes(forbidden), `${forbidden} ne doit pas etre necessaire`);
  }
});

// ===========================================================================
// Les verdicts non valides restent non valides
// ===========================================================================

test('verification : un finding toujours present reste STILL_PRESENT', async () => {
  const applied = markFixApplied(sonarFinding());
  const result = await verifyFindingFix(applied, {
    runVerifier: async () => ({ findings: [sonarFinding()], scannerStatuses: completed(), scanId: 43 })
  });
  assert.equal(result.state, VERIFICATION_STATE.STILL_PRESENT);
  const verified = applyVerification(applied, result);
  assert.notEqual(verified.triageStatus, VERIFICATION_STATE.VALIDATED);
  assert.match(renderFindingDetailsHtml(verified, 'n', { findings: [] }), /Toujours présente/);
});

test('verification : un scanner en echec ne devient jamais VALIDATED', async () => {
  const applied = markFixApplied(sonarFinding());
  for (const scanners of [[{ tool: 'SonarQube', status: 'failed', error: 'serveur injoignable' }], [], [{ tool: 'SonarQube', status: 'cancelled' }]]) {
    const result = await verifyFindingFix(applied, { runVerifier: async () => ({ findings: [], scannerStatuses: scanners, scanId: null }) });
    assert.notEqual(result.state, VERIFICATION_STATE.VALIDATED, `statuts ${JSON.stringify(scanners)} ne valident pas`);
  }
});

// ===========================================================================
// Aucune seconde generation IA apres verification
// ===========================================================================

test('verification : aucune generation IA n est declenchee apres une verification reussie', () => {
  const source = extensionSource();
  const runFix = source.match(/async function runFixVerification\([\s\S]*?\n  \}/)[0];
  // La verification est un re-scan et une comparaison. Rien d'autre.
  for (const forbidden of ['generateAiFix', 'runTwoModelRemediation', 'runAdvancedRemediation', 'aiProvider', 'generateOllamaFix']) {
    assert.ok(!runFix.includes(forbidden), `la verification ne doit pas appeler ${forbidden}`);
  }
  // Et `securityCenter.generateAiFix` n'est invoque que par des actions
  // explicites de l'utilisateur, jamais par une retombee de verification.
  const invocations = source.match(/executeCommand\('securityCenter\.generateAiFix'[^)]*\)/g) || [];
  assert.ok(invocations.length > 0);
  for (const call of invocations) {
    const before = source.slice(Math.max(0, source.indexOf(call) - 400), source.indexOf(call));
    assert.ok(!/VERIFICATION_STATE\.VALIDATED|result\.state/.test(before), `invocation IA liee a une verification : ${call}`);
  }
});

// ===========================================================================
// spawn EINVAL
// ===========================================================================

test('spawn : le lanceur de tests n utilise pas la forme qui leve EINVAL', () => {
  const command = declaredTestScript(path.join(__dirname, '..'));
  assert.ok(command, 'ce projet declare un script test');
  if (process.platform === 'win32') {
    // `execFile('npm.cmd', …)` leve EINVAL *synchroniquement* depuis la
    // mitigation CVE-2024-27980 : c'est l'origine exacte du « spawn EINVAL »
    // observe apres l'application du patch.
    assert.notEqual(command.executable, 'npm.cmd');
    assert.match(command.executable, /cmd\.exe$/i);
    assert.deepEqual(command.args, ['/d', '/s', '/c', 'npm.cmd', 'test']);
  }
  assert.equal(command.label, 'npm test');
});

test('spawn : un echec de lancement ne remonte pas comme un echec Ollama', async () => {
  // Le vrai symptome : l'exception s'echappait de `runDeclaredTests` jusqu'au
  // catch de generateAiFix, qui la reclassait « Correction Ollama non appliquée »
  // alors que le patch etait deja applique ET verifie.
  const result = await runDeclaredTests(path.join(__dirname, '..'), 1000, () => {
    throw Object.assign(new Error('spawn EINVAL'), { code: 'EINVAL' });
  });
  assert.equal(result.status, 'skipped', 'un lanceur indisponible est « tests non exécutés »');
  assert.match(result.reason, /EINVAL/);
  assert.equal(result.command, 'npm test');
});

test('spawn : un echec de test reel reste un echec de test', async () => {
  const result = await runDeclaredTests(path.join(__dirname, '..'), 1000, (file, args, options, callback) => {
    callback(Object.assign(new Error('exit 1'), { code: 1 }), '', 'assertion failed');
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.exitCode, 1);
});

// ===========================================================================
// Historique des corrections appliquées
// ===========================================================================

const { renderPipelinePageHtml } = require('../src/pipeline-page');

const remediationModel = (findings) => ({ tab: 'remediation', scanId: '1', findings });
const remediationHtml = (findings) => renderPipelinePageHtml(remediationModel(findings), 'n');

const applied = (over = {}) => sonarFinding({
  triageStatus: 'fixed', fixSource: 'manual', fixedAt: '2026-08-22T08:00:00Z', ...over
});

test('corrections : une correction appliquée apparaît dans l’historique', () => {
  const html = remediationHtml([applied()]);
  assert.match(html, /Corrections appliquées/);
  assert.match(html, /Weak|Using weak hashing/);
  assert.match(html, /Correction appliquée — vérification en attente/);
  assert.match(html, /Correction manuelle/);
  // Un finding jamais corrigé n'entre pas dans l'historique.
  const untouched = remediationHtml([sonarFinding({ id: 'untouched', title: 'Jamais corrigé' })]);
  assert.doesNotMatch(untouched, /Jamais corrigé/);
  assert.match(untouched, /Aucune correction appliquée/);
});

test('corrections : une correction validée affiche VALIDATED et son vérificateur', () => {
  const html = remediationHtml([applied({
    triageStatus: 'validated', fixSource: 'ai',
    verification: { state: 'validated', reason: 'absent_after_rescan', validator: 'sast-rescan', at: '2026-08-22T10:05:00Z', evidence: { tool: 'SonarQube', scanId: 42 } }
  })]);
  assert.match(html, /Validée/);
  assert.match(html, /SonarQube/, 'le scanner vérificateur est nommé');
  assert.match(html, /n’apparaît plus/, 'le résultat réel est affiché');
  assert.match(html, /Correction IA \(Ollama\)/);
  assert.match(html, /42/, 'le scan de vérification est référencé');
});

test('corrections : les verdicts non validés restent visibles', () => {
  const cases = [
    ['still_present', /Toujours présente/],
    ['inconclusive', /Non concluant/],
    ['regressed', /Réapparue/],
    ['validation_failed', /Vérification impossible/]
  ];
  for (const [status, expected] of cases) {
    const html = remediationHtml([applied({ triageStatus: status, verification: { state: status, evidence: { tool: 'Semgrep' } } })]);
    assert.match(html, expected, `${status} doit rester visible`);
    assert.doesNotMatch(html, /Aucune correction appliquée/);
  }
});

test('corrections : l’identité source/scanner/fichier est préservée', () => {
  const html = remediationHtml([applied({ fixSource: 'quick-fix' })]);
  assert.match(html, /SonarQube/);
  assert.match(html, /javascript:S4790/);
  assert.match(html, /Gruntfile\.js:75/);
  assert.match(html, /Quick Fix déterministe/);
});

test('corrections : les métadonnées réellement stockées sont réutilisées', () => {
  const html = remediationHtml([applied({
    triageStatus: 'validated', fixSource: 'ai', aiSummary: 'Remplace md5 par sha256',
    verification: { state: 'validated', reason: 'absent_after_rescan', at: '2026-08-22T10:05:00Z', evidence: { tool: 'SonarQube', scanId: 42 } }
  })]);
  assert.match(html, /Remplace md5 par sha256/, 'le résumé déjà persisté est réutilisé');
  // Un champ absent n'est pas rendu vide : il disparaît.
  const sparse = remediationHtml([applied({ fixSource: '', fixedAt: '', triageStatus: 'fixed' })]);
  assert.doesNotMatch(sparse, /<dt>Source<\/dt>/);
  assert.doesNotMatch(sparse, /<dt>Appliquée le<\/dt>/);
});

test('corrections : aucun diff inventé quand aucun diff n’est conservé', () => {
  const html = remediationHtml([applied({ triageStatus: 'validated', fixSource: 'ai', verification: { state: 'validated', evidence: { tool: 'SonarQube' } } })]);
  const section = html.match(/Corrections appliquées[\s\S]*?<\/section>/)[0];
  // Security Center ne persiste pas de diff par finding : aucun bouton mort,
  // aucun avant/après fabriqué.
  assert.doesNotMatch(section, /data-remediation-diff/);
  assert.doesNotMatch(section, /Voir le diff/);
  assert.doesNotMatch(section, /crypto\.createHash/, 'aucun contenu de code inventé');
});

test('corrections : chaque action réutilise une commande existante', () => {
  const html = remediationHtml([applied({ triageStatus: 'validated' })]);
  for (const action of ['data-remediation-finding', 'data-remediation-code', 'data-remediation-verify']) {
    assert.ok(html.includes(action), `${action} doit être rendu`);
  }
  // Une correction déjà validée propose « Revérifier », pas un bouton désactivé.
  assert.match(html, /Revérifier/);
  assert.match(remediationHtml([applied()]), />Vérifier</);
  // Sans chemin absolu, pas de bouton « Ouvrir le code ».
  // Le script de la page cable tous les selecteurs : l'assertion porte sur le
  // balisage rendu, pas sur ce cablage defensif.
  const markupOf = (html) => html.slice(0, html.lastIndexOf('<script'));
  const noPath = markupOf(remediationHtml([applied({ absolutePath: '' })]));
  assert.ok(!noPath.includes('data-remediation-code'), 'aucun bouton mort sans fichier');
  assert.ok(markupOf(remediationHtml([applied()])).includes('data-remediation-code'), 'le bouton existe quand le fichier existe');
  // Les gestionnaires existent et pointent vers des commandes réelles.
  const extension = extensionSource();
  const handler = extension.match(/if \(message\?\.type === 'remediation'[\s\S]*?\n        \}/)[0];
  assert.match(handler, /securityCenter\.openFindingCode/);
  assert.match(handler, /securityCenter\.verifyFindingFix/);
  assert.match(handler, /securityCenter\.showFindingDetails/);
});

test('corrections : la nuance « validée » est explicitée', () => {
  const html = remediationHtml([applied({ triageStatus: 'validated' })]);
  assert.match(html, /n’était plus signalé par le scanner de vérification/);
  assert.match(html, /ne remplace pas un test fonctionnel/);
});

test('corrections : aucune seconde persistance ni second moteur de correction', () => {
  const page = fs.readFileSync(path.join(__dirname, '..', 'src', 'pipeline-page.js'), 'utf8');
  const tab = page.match(/function renderRemediationTab[\s\S]*?\n\}/)[0];
  // L'onglet lit le modèle existant, il n'écrit rien et ne corrige rien.
  for (const forbidden of ['workspaceState', 'update(', 'generateAiFix', 'runTwoModelRemediation', 'applyEdit']) {
    assert.ok(!tab.includes(forbidden), `${forbidden} ne doit pas apparaître dans l’onglet`);
  }
  assert.match(page, /function appliedCorrections\(findings = \[\]\)/);
});
