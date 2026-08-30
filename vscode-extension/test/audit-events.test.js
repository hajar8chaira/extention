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

// ===========================================================================
// Regression : vocabulaire d audit ferme (Checkpoint 6)
//
// Les noms d actions ont derive une fois : le producteur emettait
// `finding.fix.validated` pendant que les consommateurs mappaient encore
// `status:validated`. Resultat, des actions arrivaient dans le Journal sans
// libelle, sans categorie et sans resultat — et le MTTR etait mort sans que rien
// n echoue. Ce bloc ferme la boucle : le contrat est explicite, et le test
// echoue si une action emise n est pas comprise par ses consommateurs.
// ===========================================================================

const fsCk6 = require('node:fs');
const pathCk6 = require('node:path');
const {
  CATEGORY_MAP: CK6_CATEGORY_MAP, RESULT_MAP: CK6_RESULT_MAP,
  EMITTED_AUDIT_ACTIONS, normalizeAuditEvent: ck6Normalize, legacyCategory: ck6Category, legacyResult: ck6Result
} = require('../src/audit-events');
const { ACTION_LABELS: CK6_ACTION_LABELS, getReadableAction: ck6Readable } = require('../src/audit');
const { RESOLUTION_ACTIONS: CK6_RESOLUTION_ACTIONS } = require('../src/trends');
const { VERIFICATION_STATE: CK6_VERIFICATION_STATE } = require('../src/fix-verification');

const ck6Source = (file) => fsCk6.readFileSync(pathCk6.join(__dirname, '..', 'src', file), 'utf8');

test('vocabulaire d audit : chaque action emise est comprise par le Journal', () => {
  for (const action of EMITTED_AUDIT_ACTIONS) {
    assert.ok(CK6_CATEGORY_MAP[action], `${action} n a pas de categorie`);
    assert.ok(CK6_RESULT_MAP[action], `${action} n a pas de resultat`);
    assert.ok(CK6_ACTION_LABELS[action], `${action} n a pas de libelle lisible`);
    // Et rien ne doit retomber sur l affichage brut du nom technique.
    assert.notEqual(ck6Readable(action), action, `${action} s afficherait tel quel`);
  }
});

test('vocabulaire d audit : le contrat couvre les actions litterales du produit', () => {
  // Lecture ciblee de la SEULE source qui emet des evenements, pour ne pas
  // ramasser de faux positifs venant de la documentation ou des tests.
  const emitted = new Set(
    [...ck6Source('extension.js').matchAll(/action: '([a-z][a-z0-9.]*)'/g)].map((match) => match[1])
  );
  assert.ok(emitted.size > 10, 'l extraction doit trouver les actions litterales reelles');
  const contract = new Set(EMITTED_AUDIT_ACTIONS);
  const missing = [...emitted].filter((action) => !contract.has(action));
  assert.deepEqual(missing, [], `actions emises absentes du contrat : ${missing.join(', ')}`);
});

test('vocabulaire d audit : les familles dynamiques emises sont couvertes', () => {
  const source = ck6Source('extension.js');
  const contract = new Set(EMITTED_AUDIT_ACTIONS);
  // `fix.verification.${result.state}` : les neuf etats du cycle de vie.
  assert.match(source, /action: `fix\.verification\.\$\{result\.state\}`/);
  for (const state of Object.values(CK6_VERIFICATION_STATE)) {
    assert.ok(contract.has(`fix.verification.${state}`), `fix.verification.${state} doit etre au contrat`);
  }
  // Les ternaires du produit.
  for (const action of ['policy.gate.blocked', 'policy.gate.evaluated', 'scanner.retry', 'scanner.run.started']) {
    assert.match(source, new RegExp(`'${action.replace(/\./g, '\\.')}'`), `${action} doit etre emis`);
    assert.ok(contract.has(action), `${action} doit etre au contrat`);
  }
  // Les familles a prefixe restent resolues par les regles heritees.
  assert.match(source, /action: `zap:\$\{zapMode\}:authorized`/);
  assert.equal(ck6Category('zap:active:authorized'), 'DAST');
  assert.equal(ck6Result('zap:active:authorized'), 'AUTHORIZED');
  assert.equal(ck6Category('http-replay:post:completed'), 'HTTP');
});

test('vocabulaire d audit : les noms historiques restent compris', () => {
  // L historique deja stocke dans les backends existants ne doit pas devenir
  // illisible parce que le produit a renomme ses evenements.
  assert.equal(ck6Category('status:validated'), 'TRIAGE');
  assert.equal(ck6Result('status:validated'), 'VALIDATED');
  assert.equal(ck6Readable('status:validated'), 'Correction validée');
  assert.equal(ck6Category('zap:baseline:authorized'), 'DAST');
  const legacy = ck6Normalize({ action: 'status:fixed', actor: 'dev' });
  assert.equal(legacy.category, 'TRIAGE');
  assert.equal(legacy.result, 'SUCCESS');
});

test('vocabulaire d audit : compatible avec les actions de resolution du MTTR', () => {
  // Checkpoint 1 a ferme le vocabulaire cote Tendances. Les deux consommateurs
  // doivent parler du meme produit : toute action de resolution non historique
  // doit exister au contrat et etre rendue par le Journal.
  for (const action of CK6_RESOLUTION_ACTIONS) {
    if (action.startsWith('status:')) continue; // heritee, couverte plus haut
    assert.ok(EMITTED_AUDIT_ACTIONS.includes(action), `${action} doit etre au contrat d audit`);
    assert.ok(CK6_ACTION_LABELS[action], `${action} doit avoir un libelle`);
  }
});

test('vocabulaire d audit : un patch applique ne se lit jamais comme valide', () => {
  // La distinction que tout le cycle de vie protege doit survivre jusqu au
  // libelle affiche dans le Journal.
  assert.equal(CK6_RESULT_MAP['fix.verification.validated'], 'VALIDATED');
  assert.notEqual(CK6_RESULT_MAP['fix.verification.fixed'], 'VALIDATED');
  assert.notEqual(CK6_RESULT_MAP['fix.verification.still_present'], 'VALIDATED');
  assert.notEqual(CK6_RESULT_MAP['fix.verification.regressed'], 'VALIDATED');
  assert.match(CK6_ACTION_LABELS['fix.verification.fixed'], /attente/i);
});

test('vocabulaire d audit : la semantique des evenements est inchangee', () => {
  // Aucun nom d evenement n a ete modifie cote producteur pour arranger l UI.
  const source = ck6Source('extension.js');
  for (const action of ['finding.fixed', 'finding.fix.validated', 'ai.fix.applied', 'policy.changed']) {
    assert.match(source, new RegExp(`'${action.replace(/\./g, '\\.')}'`));
  }
  // La redaction reste appliquee telle quelle.
  const sanitized = ck6Normalize({ action: 'ai.fix.applied', actor: 'dev', metadata: { token: 'abc', model: 'qwen' } });
  assert.equal(sanitized.metadata.token, '[REDACTED]');
  assert.equal(sanitized.metadata.model, 'qwen');
});

// ===========================================================================
// Regression : le modele Jenkins n installe rien depuis le registre public
// ===========================================================================

test('Jenkinsfile : invoque le CLI local du depot, jamais un paquet npm publie', () => {
  const jenkinsfile = fsCk6.readFileSync(pathCk6.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
  // « security-center » n est pas publie : `npx --yes` irait chercher sur le
  // registre public ce qui occupe ce nom.
  assert.doesNotMatch(jenkinsfile, /npx\s+--yes\s+security-center/);
  assert.doesNotMatch(jenkinsfile, /npx[^\n]*security-center scan/);
  // Le meme chemin que le workflow GitHub deja fonctionnel.
  assert.match(jenkinsfile, /node vscode-extension\/src\/cli\.js scan/);
  const workflow = fsCk6.readFileSync(pathCk6.join(__dirname, '..', '..', '.github', 'workflows', 'security-center.yml'), 'utf8');
  assert.match(workflow, /node vscode-extension\/src\/cli\.js scan/, 'le workflow GitHub reste la reference');
});

test('Jenkinsfile : drapeaux, codes de sortie et archivage preserves', () => {
  const jenkinsfile = fsCk6.readFileSync(pathCk6.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
  for (const flag of ['--workspace "$WORKSPACE"', '--format json', '--output security-center-full-report.json', '--ci-report security-center-report.json', '--sbom', '--provenance']) {
    assert.ok(jenkinsfile.includes(flag), `le drapeau ${flag} doit etre preserve`);
  }
  // Lecture du code de sortie, pas interruption avant archivage.
  assert.match(jenkinsfile, /returnStatus: true/);
  assert.match(jenkinsfile, /env\.SC_EXIT/);
  // Semantique du Policy Gate inchangee : 2 = echec, 1 = BLOCK, 0 = accepte.
  assert.match(jenkinsfile, /env\.SC_EXIT == '2'/);
  assert.match(jenkinsfile, /env\.SC_EXIT == '1'/);
  assert.match(jenkinsfile, /env\.SC_EXIT == '0'/);
  // Archivage inconditionnel conserve.
  assert.match(jenkinsfile, /archiveArtifacts artifacts: 'security-center-report\.json', allowEmptyArchive: true, fingerprint: true/);
  assert.match(jenkinsfile, /always \{/);
  // Etapes inchangees.
  for (const stage of ['Checkout', 'Build & Test', 'Security Center', 'Policy Gate', 'Supply chain evidence', 'Deploy']) {
    assert.ok(jenkinsfile.includes(`stage('${stage}')`), `l etape ${stage} doit rester`);
  }
});
