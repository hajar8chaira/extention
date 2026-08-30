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

// ===========================================================================
// Regression : le consentement d ecriture du replay de verification (Checkpoint 4)
//
// `verifyDynamicFinding` s auto-accordait `allowWrite: true` en le derivant de
// la seule methode HTTP. Le garde-fou de `replayScenario` etait donc toujours
// satisfait, et une verification — y compris celle declenchee automatiquement
// apres un patch Ollama — pouvait envoyer un POST/PUT/PATCH sans consentement.
//
// Ces tests rejouent le contrat reel : la meme classification de methodes que
// le moteur de replay, le meme drapeau de session, et un vrai socket local qui
// compte ce qui part reellement sur le reseau.
// ===========================================================================

const http = require('http');
const { replayScenario, CONTROLLED_WRITE_METHODS, READ_METHODS } = require('../src/http-scenarios');

/**
 * Reproduit exactement la sequence du produit corrige :
 *   consentement -> puis seulement ensuite le replay.
 * `authorized` simule l etat de session `httpWriteReplayAuthorized` + la reponse
 * de la modale existante.
 */
async function verificationReplay({ method, url, authorized, onPrompt = () => {} }) {
  const upper = String(method).toUpperCase();
  let granted = true;
  if (CONTROLLED_WRITE_METHODS.has(upper)) {
    onPrompt(upper);
    granted = authorized === true;
  }
  if (!granted) throw new Error('Vérification annulée : replay en écriture non autorisé.');
  return replayScenario(
    { name: 'verif', request: { method: upper, url, headers: {}, body: '{}' }, response: {} },
    { allowWrite: CONTROLLED_WRITE_METHODS.has(upper), timeoutMs: 3000 }
  );
}

/** Un serveur local qui compte les requetes reellement recues. */
async function countingServer(t) {
  const received = [];
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      received.push(request.method);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { received, port: server.address().port };
}

test('consentement verif : la classification des methodes reste celle du moteur de replay', () => {
  // Aucun elargissement silencieux. DELETE n est dans aucun des deux ensembles :
  // il reste refuse par `replayScenario`, pas promu en methode d ecriture.
  assert.deepEqual([...READ_METHODS].sort(), ['GET', 'HEAD']);
  assert.deepEqual([...CONTROLLED_WRITE_METHODS].sort(), ['PATCH', 'POST', 'PUT']);
  assert.ok(!CONTROLLED_WRITE_METHODS.has('DELETE'));
  const source = extensionSource();
  assert.doesNotMatch(source, /allowWrite: \['POST', 'PUT', 'PATCH'\]\.includes\(method\), timeoutMs: 30000 \}\);\s*\n\s*return \{\s*\n\s*findingId/);
});

test('consentement verif : un GET se verifie sans demander d autorisation', async (t) => {
  const { received, port } = await countingServer(t);
  let prompted = 0;
  const replay = await verificationReplay({
    method: 'GET', url: `http://127.0.0.1:${port}/api/profile`,
    authorized: false, onPrompt: () => { prompted += 1; }
  });
  assert.equal(prompted, 0, 'un GET ne doit jamais declencher la demande d ecriture');
  assert.equal(replay.statusCode, 200);
  assert.deepEqual(received, ['GET'], 'le replay lecture doit bien avoir lieu');
});

for (const method of ['POST', 'PUT', 'PATCH']) {
  test(`consentement verif : ${method} sans autorisation n envoie rien`, async (t) => {
    const { received, port } = await countingServer(t);
    await assert.rejects(
      () => verificationReplay({ method, url: `http://127.0.0.1:${port}/api/items`, authorized: false }),
      /annul/i
    );
    assert.deepEqual(received, [], `aucune requete ${method} ne doit atteindre la cible`);
  });
}

test('consentement verif : une ecriture autorisee se rejoue normalement', async (t) => {
  const { received, port } = await countingServer(t);
  const replay = await verificationReplay({ method: 'POST', url: `http://127.0.0.1:${port}/api/items`, authorized: true });
  assert.equal(replay.statusCode, 200);
  assert.deepEqual(received, ['POST'], 'le comportement existant est preserve une fois autorise');
});

test('consentement verif : un refus ne valide jamais la correction', async () => {
  // Le refus remonte comme une exception « annulee » ; le cycle de vie existant
  // la traduit en VALIDATION_FAILED / CANCELLED. Aucun nouvel etat n est cree.
  const finding = { id: 'zap:sqli:POST:/api/items', tool: 'ZAP', category: 'dynamic', title: 'SQL Injection', endpoint: 'http://127.0.0.1:3000/api/items', method: 'POST' };
  const result = await verifyFindingFix(markFixApplied(finding), {
    runVerifier: async () => { throw new Error('Vérification annulée : replay en écriture non autorisé.'); }
  });
  assert.equal(result.state, VERIFICATION_STATE.VALIDATION_FAILED);
  assert.equal(result.reason, VERIFICATION_REASON.CANCELLED);
  assert.notEqual(result.state, VERIFICATION_STATE.VALIDATED);
  assert.equal(result.validator, VERIFIER.DAST_RETEST);
});

test('consentement verif : le chemin automatique Ollama ne contourne pas l autorisation', async (t) => {
  // Ollama applique un patch puis declenche `runFixVerification` sans nouvelle
  // interaction. Appliquer un patch ne doit pas valoir permission d ecrire.
  const { received, port } = await countingServer(t);
  const finding = { id: 'zap:sqli:POST:/api/items', tool: 'ZAP', category: 'dynamic', title: 'SQL Injection', endpoint: `http://127.0.0.1:${port}/api/items`, method: 'POST' };
  const aiApplied = markFixApplied(finding, { source: 'ai', by: 'Ollama' });
  const result = await verifyFindingFix(aiApplied, {
    // Le verificateur reel : consentement d abord, replay ensuite. Session non autorisee.
    runVerifier: async () => verificationReplay({ method: 'POST', url: `http://127.0.0.1:${port}/api/items`, authorized: false })
  });
  assert.deepEqual(received, [], 'aucune ecriture ne doit partir sur le chemin automatique');
  assert.equal(result.state, VERIFICATION_STATE.VALIDATION_FAILED);
  assert.notEqual(result.state, VERIFICATION_STATE.VALIDATED);
});

test('consentement verif : cablage reel dans verifyDynamicFinding', () => {
  const source = extensionSource();
  const body = source.match(/async function verifyDynamicFinding\([\s\S]*?\n  \}/);
  assert.ok(body, 'verifyDynamicFinding doit exister');
  // Le consentement est resolu AVANT le replay, dans cet ordre.
  const consentIndex = body[0].indexOf('authorizeVerificationWriteReplay');
  const replayIndex = body[0].indexOf('replayScenario(');
  assert.ok(consentIndex > -1, 'la verification doit passer par la porte de consentement');
  assert.ok(consentIndex < replayIndex, 'le consentement doit preceder le replay');
  assert.match(body[0], /if \(!writeAuthorized\) throw new Error\('Vérification annulée/);
  // Plus aucune auto-attribution de `allowWrite` depuis la seule methode.
  assert.doesNotMatch(body[0], /allowWrite: \['POST', 'PUT', 'PATCH'\]\.includes\(method\)/);
  // La porte reutilise l etat de session existant, sans en inventer un second.
  assert.match(source, /async function authorizeVerificationWriteReplay\(method\)[\s\S]*?if \(httpWriteReplayAuthorized\) return true;/);
  assert.match(source, /async function authorizeVerificationWriteReplay\(method\)[\s\S]*?httpWriteReplayAuthorized = true;/);
  assert.match(source, /CONTROLLED_WRITE_METHODS/);
});

test('consentement verif : les flux existants restent inchanges', () => {
  const source = extensionSource();
  // Replay manuel : meme drapeau de session, meme modale, meme audit.
  assert.match(source, /if \(!httpWriteReplayAuthorized\) \{[\s\S]*?'Autoriser pour cette session'[\s\S]*?httpWriteReplayAuthorized = true;/);
  assert.match(source, /action: `http-replay:\$\{method\.toLowerCase\(\)\}:authorized`/);
  // Re-test dynamique : sa propre confirmation modale par action, intacte.
  assert.match(source, /Une seule requête sera envoyée\. Aucun scan ZAP ne sera lancé\./);
  // Preflight ZAP : frontiere distincte, non consommee comme autorisation d ecriture.
  assert.match(source, /const zapPreflightRequired = zapRequestedForScan\(cfg, projectPolicy, requested\)/);
  assert.match(source, /async function resolveZapActiveScanConsent/);
  const gate = source.match(/async function authorizeVerificationWriteReplay\([\s\S]*?\n  \}/);
  assert.ok(gate);
  assert.doesNotMatch(gate[0], /zap|Zap|ZAP/, 'l autorisation ZAP ne doit jamais accorder une ecriture HTTP');
});
