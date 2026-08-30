const test = require('node:test');
const assert = require('node:assert/strict');

const {
  REDACTED, redactSecrets, redactOutgoingMessages,
  shannonEntropy, looksLikeSecretValue
} = require('../src/ai/secret-redaction');
const { buildMinimalContext, redactSecrets: builderRedact } = require('../src/ai/context-builder');
const { generateOllamaFix, repairOllamaFix, fixPrompt } = require('../src/ai/ollama-provider');

// Des secrets synthetiques : aucune valeur reelle n'entre dans ce fichier.
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
const GITHUB = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const OPENAI = 'sk-' + 'proj0A1b2C3d4E5f6G7h8I9j0K1l2M3n4';
const SLACK = 'xoxb-' + '123456789012-abcdefghijkl';
const GITLAB = 'glpat-' + 'A1b2C3d4E5f6G7h8I9j0';
const PRIVATE_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn1LhkgHqLPBjmSPvOwvDGXRhtBhTuHqXyz',
  'nT4dKLbYqUmA6zHrPoQwEcVbNmXjKlOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv',
  '-----END RSA PRIVATE KEY-----'
].join('\n');

const contains = (haystack, needle) => String(haystack).includes(needle);

// ============================================== identifiant sensible (existant)

test('un identifiant sensible reste redige (aucune regression)', () => {
  const out = redactSecrets('const apiKey = "super-secret-value";');
  assert.ok(!contains(out, 'super-secret-value'));
  assert.match(out, /\[REDACTED\]/);
  for (const line of ['const token = "abc";', 'const password = "hunter2";', 'password: hunter2', '"secret": "abc"']) {
    assert.match(redactSecrets(line), /\[REDACTED\]/, line);
  }
});

test('la fonction exposee par context-builder est bien la nouvelle', () => {
  // Les appelants existants importent redactSecrets depuis context-builder :
  // l'API publique ne change pas, seule l'implementation est partagee.
  assert.equal(builderRedact, redactSecrets);
});

// ======================================= identifiant inconnu, valeur reconnue

test('une cle AWS est redigee malgre un identifiant non liste', () => {
  const out = redactSecrets(`const awsAccessKeyId = "${AWS_KEY}";`);
  assert.ok(!contains(out, AWS_KEY), 'la valeur ne doit pas subsister');
  assert.match(out, /\[REDACTED\]/);
});

test('une cle AWS en YAML est redigee', () => {
  const out = redactSecrets(`aws_access_key_id: ${AWS_KEY}`);
  assert.ok(!contains(out, AWS_KEY));
  const secret = redactSecrets('aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.ok(!contains(secret, 'wJalrXUtnFEMI'));
});

test('les jetons a prefixe editeur sont reconnus par leur forme', () => {
  for (const [label, token] of [['GitHub', GITHUB], ['OpenAI', OPENAI], ['Slack', SLACK], ['GitLab', GITLAB]]) {
    const out = redactSecrets(`const x = "${token}";`);
    assert.ok(!contains(out, token), `${label} doit etre redige`);
  }
  // Et hors de toute affectation, en texte brut.
  assert.ok(!contains(redactSecrets(`le jeton ${GITHUB} a fuite`), GITHUB));
});

test('un identifiant totalement quelconque portant un secret est redige', () => {
  // Le coeur du probleme rapporte : le nom n'aide en rien.
  const out = redactSecrets(`const zzz = "${AWS_KEY}";`);
  assert.ok(!contains(out, AWS_KEY));
});

// ================================================ chaines de connexion

test('les mots de passe des chaines de connexion ne passent jamais', () => {
  const cases = [
    ['postgres://admin:superSecret123@database.internal/app', 'superSecret123'],
    ['postgresql://u:p4ssw0rd@host:5432/db', 'p4ssw0rd'],
    ['mysql://root:toor@127.0.0.1/app', 'toor'],
    ['mongodb://user:password@host/database', 'password'],
    ['redis://:hunter2@cache.internal:6379', 'hunter2'],
    ['amqp://guest:guest@rabbit/vhost', 'guest:guest']
  ];
  for (const [url, secret] of cases) {
    const out = redactSecrets(url);
    assert.ok(!contains(out, secret), `${url} laisse passer ${secret}`);
    assert.match(out, /\[REDACTED\]/, url);
  }
});

test('la structure utile de la chaine de connexion est preservee', () => {
  const out = redactSecrets('postgres://admin:superSecret@database.internal/app');
  assert.equal(out, 'postgres://[REDACTED]@database.internal/app');
  // Le modele voit encore qu il s agit d une base postgres, sur quel hote.
  assert.match(out, /^postgres:\/\//);
  assert.match(out, /database\.internal\/app$/);
});

test('une URL sans identifiants reste intacte', () => {
  const url = 'https://api.example.com/v1/users?page=2';
  assert.equal(redactSecrets(url), url);
  assert.equal(redactSecrets('const base = "https://example.com/api";'), 'const base = "https://example.com/api";');
});

test('les identifiants dans une URL HTTP sont retires', () => {
  assert.ok(!contains(redactSecrets('https://user:password@example.com'), 'password'));
  assert.ok(!contains(redactSecrets('https://someToken@example.com'), 'someToken'));
});

// ============================================== en-tetes d authentification

test('les en-tetes d authentification sont rediges en gardant leur schema', () => {
  const bearer = redactSecrets('Authorization: Bearer super-secret-token');
  assert.ok(!contains(bearer, 'super-secret-token'));
  assert.match(bearer, /Authorization: Bearer \[REDACTED\]/);

  const basic = redactSecrets('Authorization: Basic dXNlcjpwYXNzd29yZA==');
  assert.ok(!contains(basic, 'dXNlcjpwYXNzd29yZA'));

  const apiKey = redactSecrets('X-API-Key: 8f3a2b1c9d0e4f5a6b7c8d9e');
  assert.ok(!contains(apiKey, '8f3a2b1c9d0e4f5a6b7c8d9e'));
});

test('un jeton passe en parametre est redige', () => {
  for (const [text, secret] of [
    ['https://api.example.com/v1?access_token=abc123def456ghi789', 'abc123def456ghi789'],
    ['token=super-secret-value&page=2', 'super-secret-value'],
    ['client_secret=9f8e7d6c5b4a3210', '9f8e7d6c5b4a3210']
  ]) {
    assert.ok(!contains(redactSecrets(text), secret), text);
  }
});

// ============================================================ JWT

test('un JWT est redige', () => {
  const out = redactSecrets(`const session = "${JWT}";`);
  assert.ok(!contains(out, JWT));
  assert.ok(!contains(out, 'eyJhbGciOiJIUzI1NiJ'), 'aucun fragment de jeton');
  assert.ok(!contains(redactSecrets(`Authorization: Bearer ${JWT}`), JWT));
});

test('toute chaine pointee n est pas prise pour un JWT', () => {
  for (const safe of ['const version = "1.2.3";', 'require("lodash.merge.js")', 'const host = "a.b.c";', 'semver: 10.20.30']) {
    assert.equal(redactSecrets(safe), safe, safe);
  }
});

// ==================================================== cles privees

test('un bloc de cle privee est entierement remplace', () => {
  const out = redactSecrets(`const key = \`${PRIVATE_KEY}\`;`);
  assert.ok(!contains(out, 'MIIEowIBAAKCAQEA'), 'aucun fragment de cle');
  assert.ok(!contains(out, 'nT4dKLbYqUmA'), 'aucune ligne intermediaire');
  assert.match(out, /\[REDACTED\]_PRIVATE_KEY/);
});

test('une cle privee tronquee par la fenetre d extrait ne fuit pas non plus', () => {
  const truncated = PRIVATE_KEY.split('\n').slice(0, 2).join('\n');
  const out = redactSecrets(truncated);
  assert.ok(!contains(out, 'MIIEowIBAAKCAQEA'));
});

test('les autres formats de cle privee sont couverts', () => {
  for (const header of ['-----BEGIN PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----']) {
    const block = `${header}\nAAAAsecretbodyAAAA\n-----END PRIVATE KEY-----`;
    assert.ok(!contains(redactSecrets(block), 'AAAAsecretbodyAAAA'), header);
  }
});

// ============================================== faux positifs

test('le code normal traverse sans modification', () => {
  const safe = [
    'const greeting = "Hello world";',
    'const version = "1.2.3";',
    'const hash = "abcdef123456";',
    'const message = "Une phrase entiere avec des espaces";',
    'const path = "./src/components/Button.tsx";',
    'const query = "SELECT id, name FROM users WHERE id = ?";',
    'import { useState } from "react";',
    'const color = "#3fb950";',
    'export const MAX_RETRIES = 5;'
  ].join('\n');
  assert.equal(redactSecrets(safe), safe);
});

test('une reference d environnement est une correction, pas un secret', () => {
  const fixed = [
    'const apiKey = process.env.API_KEY;',
    'password: ${DB_PASSWORD}',
    'const token = import.meta.env.VITE_TOKEN;'
  ].join('\n');
  const out = redactSecrets(fixed);
  assert.ok(contains(out, 'process.env.API_KEY'), 'la solution ne doit pas etre effacee');
  assert.ok(contains(out, 'import.meta.env.VITE_TOKEN'));
});

test('l heuristique d entropie est bornee et explicable', () => {
  // Sous le seuil de longueur : jamais.
  assert.equal(looksLikeSecretValue('abcdef123456'), false);
  // Longue mais peu entropique : non.
  assert.equal(looksLikeSecretValue('aaaaaaaaaaaaaaaaaaaaaaaa'), false);
  // De la prose : non.
  assert.equal(looksLikeSecretValue('une phrase assez longue ici'), false);
  // Aleatoire et long : oui.
  assert.equal(looksLikeSecretValue('Xk7Pq2Mz9Rt4Nw8Vb3Ly6Hs1Jd5F'), true);
  assert.ok(shannonEntropy('aaaa') < shannonEntropy('Xk7Pq2Mz'));
});

// ================================== construction de contexte (couche 1)

test('le contexte construit ne contient aucun secret, meme sous un nom inconnu', () => {
  const source = [
    'const region = "eu-west-1";',
    `const awsAccessKeyId = "${AWS_KEY}";`,
    `const dbConn = "postgres://admin:superSecret123@db.internal/app";`,
    'module.exports = { region };'
  ].join('\n');
  const context = buildMinimalContext(
    { id: 'x', tool: 'Gitleaks', ruleId: 'r', title: 'Cle detectee', startLine: 1, absolutePath: 'C:/ws/config.js' },
    'C:/ws', source
  );
  const blob = JSON.stringify(context);
  assert.ok(!contains(blob, AWS_KEY), 'la cle AWS ne doit pas entrer dans le contexte');
  assert.ok(!contains(blob, 'superSecret123'), 'le mot de passe ne doit pas entrer dans le contexte');
  // Le contexte reste exploitable.
  assert.ok(contains(blob, 'eu-west-1'));
  assert.ok(contains(blob, 'postgres://'));
});

test('le bloc finding envoye au modele est redige lui aussi', () => {
  const context = buildMinimalContext(
    { id: `gitleaks:${AWS_KEY}`, tool: 'Gitleaks', ruleId: 'aws', title: `Cle ${AWS_KEY} trouvee`, startLine: 0, absolutePath: 'C:/ws/a.js' },
    'C:/ws', 'const a = 1;\n'
  );
  assert.ok(!contains(JSON.stringify(context.finding), AWS_KEY));
  // Et donc le prompt construit a partir de lui.
  assert.ok(!contains(fixPrompt(context), AWS_KEY));
});

// ============================ barriere finale avant Ollama (couche 2)

/** Capture l entree exacte du fournisseur sans jamais atteindre le reseau. */
function capturingFetch(captured) {
  return async (url, init) => {
    captured.url = String(url);
    captured.body = init.body;
    return {
      ok: true,
      json: async () => ({
        model: 'test', prompt_eval_count: 1, eval_count: 1,
        message: { content: JSON.stringify({ oldText: 'a', newText: 'b', summary: 's', securityReason: 'r', confidence: 0.9, assumptions: [], tests: [] }) }
      })
    };
  };
}

test('la barriere finale redige un secret injecte APRES la construction du contexte', async () => {
  // Le contexte est fabrique a la main pour contourner entierement la couche 1 :
  // c est exactement ce que ferait un futur chemin de prompt qui oublierait de
  // sanitiser ses entrees.
  const captured = {};
  const poisoned = {
    finding: { id: 'x', tool: 'Semgrep', ruleId: 'r', title: `fuite ${AWS_KEY}`, severity: 'HIGH', cwe: '' },
    file: 'a.js', excerptStartLine: 1, excerptEndLine: 3,
    excerpt: `1: const k = "${AWS_KEY}";\n2: const c = "postgres://admin:superSecret123@db/app";\n3: Authorization: Bearer ${JWT}`
  };
  await generateOllamaFix({
    baseUrl: 'http://127.0.0.1:11434', model: 'm', context: poisoned, fetchImpl: capturingFetch(captured)
  });
  assert.ok(captured.body, 'la requete doit avoir ete construite');
  assert.ok(!contains(captured.body, AWS_KEY), 'la cle AWS atteint le modele');
  assert.ok(!contains(captured.body, 'superSecret123'), 'le mot de passe atteint le modele');
  assert.ok(!contains(captured.body, JWT), 'le JWT atteint le modele');
  assert.ok(contains(captured.body, '[REDACTED]'), 'la redaction doit etre visible');
});

test('la barriere finale couvre aussi le chemin de reparation', async () => {
  // repairPrompt reinjecte la proposition refusee du modele, qui peut contenir
  // du code source recopie — un chemin que la couche 1 ne voit jamais.
  const captured = {};
  await repairOllamaFix({
    baseUrl: 'http://127.0.0.1:11434', model: 'm',
    context: { excerpt: 'const a = 1;' },
    rejectedPatch: `const k = "${AWS_KEY}";`,
    validationError: `valeur refusee: ${GITHUB}`,
    fetchImpl: capturingFetch(captured)
  });
  assert.ok(!contains(captured.body, AWS_KEY));
  assert.ok(!contains(captured.body, GITHUB));
});

test('la barriere finale laisse passer un contexte exploitable', async () => {
  const captured = {};
  await generateOllamaFix({
    baseUrl: 'http://127.0.0.1:11434', model: 'm',
    context: {
      finding: { id: 'x', tool: 'Semgrep', ruleId: 'js.sqli', title: 'SQL injection', severity: 'HIGH', cwe: 'CWE-89' },
      file: 'db.js', excerptStartLine: 1, excerptEndLine: 2,
      excerpt: '1: const q = "SELECT * FROM users WHERE id = " + id;\n2: db.query(q);'
    },
    fetchImpl: capturingFetch(captured)
  });
  // Le modele doit encore recevoir de quoi raisonner.
  assert.ok(contains(captured.body, 'SELECT * FROM users'));
  assert.ok(contains(captured.body, 'js.sqli'));
  assert.ok(contains(captured.body, 'db.query'));
  assert.ok(!contains(captured.body, '[REDACTED]'), 'aucune redaction inutile sur du code sain');
});

test('la barriere ne casse pas des messages sans contenu textuel', () => {
  assert.deepEqual(redactOutgoingMessages([]), []);
  assert.deepEqual(redactOutgoingMessages(null), []);
  assert.deepEqual(redactOutgoingMessages([{ role: 'user' }]), [{ role: 'user' }]);
  const [message] = redactOutgoingMessages([{ role: 'user', content: `k=${AWS_KEY}` }]);
  assert.ok(!contains(message.content, AWS_KEY));
  assert.equal(message.role, 'user');
});

test('la barriere est appelee au point d egress unique', () => {
  const fs = require('fs');
  const path = require('path');
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'ai', 'ollama-provider.js'), 'utf8');
  // L invariant n est pas « un seul appel » mais « aucun appel ne peut fuiter » :
  // CHAQUE envoi vers /api/chat doit passer par la barriere de redaction. La
  // tache assistant a ajoute un second point d egress ; le contrat vaut pour lui
  // exactement comme pour la remediation.
  const egress = source.match(/fetchImpl\(new URL\('\/api\/chat'/g) || [];
  assert.ok(egress.length >= 1, 'au moins un point d egress doit exister');
  const redactions = source.match(/redactOutgoingMessages\(messages\)/g) || [];
  assert.equal(redactions.length, egress.length, 'chaque appel /api/chat doit assainir ses messages');
  assert.equal((source.match(/messages: safeMessages/g) || []).length, egress.length);
  assert.ok(!/body: JSON\.stringify\(\{[^}]*messages \}\)/.test(source), 'aucun envoi de messages bruts');
});
