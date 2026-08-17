const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { generateSbomArtifact, describeSbom, readSbomArtifact } = require('../src/supply-chain/sbom');
const {
  detectLocalCosign, parseCosignVersion, cosignCandidates, resolveRunner, supportedModes, keylessSupport,
  generateKeyPair, signBlob, verifyBlob, scrubOutput, CosignError
} = require('../src/supply-chain/cosign');
const { generateProvenance, validateProvenance, PREDICATE_TYPE, STATEMENT_TYPE } = require('../src/supply-chain/provenance');
const { TOOLS } = require('../src/scanner-tool-manager');

const KEY_PASSWORD = 'un-mot-de-passe-solide';
const RUNNER = { mode: 'local', local: { path: '/usr/bin/cosign', version: '3.1.3' } };

function workspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'supply-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), content);
  }
  return root;
}

const CYCLONEDX = {
  bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:1234',
  components: [{ type: 'library', name: 'lodash', version: '4.17.11' }, { type: 'library', name: 'express', version: '4.17.1' }]
};

// -------------------------------------------------------------------- SBOM

test('décrit un document CycloneDX sans le reconstruire', () => {
  const described = describeSbom(CYCLONEDX);
  assert.equal(described.format, 'CycloneDX');
  assert.equal(described.specVersion, '1.5');
  assert.equal(described.componentCount, 2);
  assert.deepEqual(described.componentTypes, { library: 2 });
});

test('le SBOM devient un artefact daté, digéré et relu', async (t) => {
  const root = workspace(t);
  const artifact = await generateSbomArtifact({
    workspacePath: root, outputDirectory: path.join(root, 'out'),
    generate: async () => ({ payload: CYCLONEDX, mode: 'local' })
  });
  assert.equal(artifact.status, 'generated');
  assert.equal(artifact.componentCount, 2);
  assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(fs.existsSync(artifact.path));
  const reread = await readSbomArtifact(artifact);
  assert.equal(reread.digest, artifact.digest);
  assert.equal(reread.document.components.length, 2);
});

test('un échec de génération est décrit, pas propagé en exception', async (t) => {
  const root = workspace(t);
  const artifact = await generateSbomArtifact({
    workspacePath: root, generate: async () => { throw new Error('Trivy indisponible'); }
  });
  assert.equal(artifact.status, 'failed');
  assert.match(artifact.reason, /Trivy indisponible/);
});

// ------------------------------------------------------------------ Cosign

test('Cosign est un outil supply chain géré, pas un scanner', () => {
  assert.equal(TOOLS.cosign.label, 'Cosign');
  assert.equal(TOOLS.cosign.repo, 'sigstore/cosign');
  assert.equal(TOOLS.cosign.supplyChain, true);
  assert.deepEqual(TOOLS.cosign.versionArgs, ['version']);
  assert.ok(TOOLS.cosign.asset.test('cosign-windows-amd64.exe'));
  assert.ok(!TOOLS.cosign.asset.test('cosign-windows-amd64.exe.sigstore.json'));
  assert.ok(TOOLS.cosign.checksum.test('cosign_checksums.txt'));
});

test('détecte l’exécutable Cosign et sa version', async () => {
  assert.deepEqual(cosignCandidates('win32'), ['cosign.exe', 'cosign']);
  assert.equal(parseCosignVersion('GitVersion:    3.1.3'), '3.1.3');
  const detected = await detectLocalCosign({
    platform: 'linux', hasCommand: async () => '/usr/bin/cosign',
    exec: async () => ({ stdout: 'GitVersion: 3.1.3', stderr: '' })
  });
  assert.equal(detected.version, '3.1.3');
});

test('le mode Docker est refusé explicitement plutôt que simulé', async () => {
  assert.equal(supportedModes().docker, false);
  await assert.rejects(() => resolveRunner('docker', {}), (error) => error.code === 'UNSUPPORTED_MODE');
  assert.match(supportedModes().dockerReason, /clé privée/);
});

test('la signature keyless est annoncée comme non prise en charge', () => {
  assert.equal(keylessSupport().supported, false);
  assert.match(keylessSupport().reason, /OIDC/);
});

test('un CLI absent est signalé clairement', async () => {
  await assert.rejects(() => resolveRunner('auto', { detect: async () => null }), (error) => error.code === 'CLI_MISSING');
});

test('aucune signature sans confirmation explicite', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu' });
  await assert.rejects(
    () => signBlob({ filePath: path.join(root, 'a.txt'), keyPath: path.join(root, 'k'), password: KEY_PASSWORD, runner: RUNNER }),
    (error) => error.code === 'NOT_CONFIRMED'
  );
});

test('aucune génération de clé sans confirmation explicite', async (t) => {
  const root = workspace(t);
  await assert.rejects(
    () => generateKeyPair({ directory: root, password: KEY_PASSWORD, runner: RUNNER }),
    (error) => error.code === 'NOT_CONFIRMED'
  );
});

test('une clé existante n’est jamais écrasée', async (t) => {
  const root = workspace(t, { 'cosign.key': 'CLE EXISTANTE' });
  await assert.rejects(
    () => generateKeyPair({ directory: root, password: KEY_PASSWORD, confirmed: true, runner: RUNNER }),
    (error) => error.code === 'KEY_EXISTS'
  );
  assert.equal(fs.readFileSync(path.join(root, 'cosign.key'), 'utf8'), 'CLE EXISTANTE');
});

test('le mot de passe passe par l’environnement, jamais par argv', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu', 'cosign.key': 'k' });
  const calls = [];
  const exec = async (executable, args, options) => {
    calls.push({ executable, args, options });
    fs.writeFileSync(path.join(root, 'a.txt.sigstore.json'), 'bundle');
    return { stdout: '', stderr: '' };
  };
  const result = await signBlob({
    filePath: path.join(root, 'a.txt'), keyPath: path.join(root, 'cosign.key'),
    password: KEY_PASSWORD, confirmed: true, runner: RUNNER, exec
  });
  assert.equal(result.status, 'signed');
  assert.ok(!JSON.stringify(calls[0].args).includes(KEY_PASSWORD));
  assert.equal(calls[0].options.env.COSIGN_PASSWORD, KEY_PASSWORD);
  assert.ok(calls[0].args.includes('--yes'));
});

test('signer sans clé ou sans mot de passe est refusé', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu' });
  await assert.rejects(
    () => signBlob({ filePath: path.join(root, 'a.txt'), keyPath: '', password: KEY_PASSWORD, confirmed: true, runner: RUNNER }),
    (error) => error.code === 'KEY_MISSING'
  );
  fs.writeFileSync(path.join(root, 'cosign.key'), 'k');
  await assert.rejects(
    () => signBlob({ filePath: path.join(root, 'a.txt'), keyPath: path.join(root, 'cosign.key'), password: '', confirmed: true, runner: RUNNER }),
    (error) => error.code === 'PASSWORD_MISSING'
  );
});

test('une vérification réussie est un résultat structuré', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu', 'cosign.pub': 'p', 'a.txt.sigstore.json': 's' });
  const result = await verifyBlob({
    filePath: path.join(root, 'a.txt'), publicKeyPath: path.join(root, 'cosign.pub'),
    runner: RUNNER, exec: async () => ({ stdout: '', stderr: 'Verified OK' })
  });
  assert.equal(result.status, 'verified');
  assert.match(result.detail, /Verified OK/);
});

test('une vérification en échec est un résultat, pas une exception', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu', 'cosign.pub': 'p', 'a.txt.sigstore.json': 's' });
  const result = await verifyBlob({
    filePath: path.join(root, 'a.txt'), publicKeyPath: path.join(root, 'cosign.pub'), runner: RUNNER,
    exec: async () => { throw Object.assign(new Error('failed'), { stderr: 'signature verification failed' }); }
  });
  assert.equal(result.status, 'failed');
  assert.match(result.reason, /Cosign a échoué/);
});

test('l’annulation est propagée telle quelle', async (t) => {
  const root = workspace(t, { 'a.txt': 'contenu', 'cosign.key': 'k' });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => signBlob({
      filePath: path.join(root, 'a.txt'), keyPath: path.join(root, 'cosign.key'), password: KEY_PASSWORD,
      confirmed: true, runner: RUNNER, signal: controller.signal,
      exec: async () => { throw new Error('aborted'); }
    }),
    (error) => error.code === 'CANCELED'
  );
});

test('aucune matière de clé privée ne peut fuiter dans un message', () => {
  const leaked = '-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----';
  assert.ok(!scrubOutput(leaked).includes('AAAA'));
  assert.match(scrubOutput(leaked), /CLÉ MASQUÉE/);
  assert.ok(!scrubOutput(`COSIGN_PASSWORD=${KEY_PASSWORD}`).includes(KEY_PASSWORD));
});

// -------------------------------------------------------------- Provenance

test('la provenance porte le digest réel de l’artefact', async (t) => {
  const root = workspace(t, { 'sbom.json': JSON.stringify(CYCLONEDX) });
  const result = await generateProvenance({
    workspacePath: root, artifactPath: path.join(root, 'sbom.json'), git: null
  });
  assert.equal(result.status, 'generated');
  assert.match(result.artifactDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.statement.subject[0].name, 'sbom.json');
  assert.equal(result.statement.subject[0].digest.sha256, result.artifactDigest.replace('sha256:', ''));
});

test('la structure suit in-toto v1 et SLSA Provenance v1', async (t) => {
  const root = workspace(t, { 'artifact.bin': 'données' });
  const result = await generateProvenance({ workspacePath: root, artifactPath: path.join(root, 'artifact.bin'), git: null });
  assert.equal(result.statement._type, STATEMENT_TYPE);
  assert.equal(result.statement.predicateType, PREDICATE_TYPE);
  assert.deepEqual(validateProvenance(result.statement), { valid: true, problems: [] });
  // Aucune conformité SLSA n'est revendiquée : seule la structure l'est.
  assert.equal(result.slsaLevelClaimed, null);
  assert.match(result.conformance, /structure/);
});

test('le SBOM est rattaché à la provenance quand il existe', async (t) => {
  const root = workspace(t, { 'artifact.bin': 'données' });
  const result = await generateProvenance({
    workspacePath: root, artifactPath: path.join(root, 'artifact.bin'), git: null,
    sbom: { status: 'generated', digest: `sha256:${'a'.repeat(64)}`, path: '/tmp/sbom.json', componentCount: 2, format: 'CycloneDX' }
  });
  assert.equal(result.sbomLinked, true);
  const dependency = result.statement.predicate.buildDefinition.resolvedDependencies.find((entry) => entry.name === 'sbom');
  assert.equal(dependency.digest.sha256, 'a'.repeat(64));
  const byproduct = result.statement.predicate.runDetails.byproducts.find((entry) => entry.name === 'sbom');
  assert.equal(byproduct.annotations.componentCount, 2);
});

test('le résultat du policy gate est référencé dans la provenance', async (t) => {
  const root = workspace(t, { 'artifact.bin': 'données' });
  const result = await generateProvenance({
    workspacePath: root, artifactPath: path.join(root, 'artifact.bin'), git: null,
    policy: { status: 'PASS', violations: [], warnings: [], evaluatedAt: '2026-01-01T00:00:00.000Z' },
    scanners: [{ tool: 'Semgrep', status: 'completed' }]
  });
  assert.equal(result.policyStatus, 'PASS');
  const byproduct = result.statement.predicate.runDetails.byproducts.find((entry) => entry.name === 'policy-gate');
  assert.equal(byproduct.annotations.status, 'PASS');
  const scanners = result.statement.predicate.runDetails.byproducts.find((entry) => entry.name === 'scanners');
  assert.deepEqual(scanners.annotations.executed, ['Semgrep:completed']);
});

test('un dépôt Git alimente la provenance sans exposer d’identifiants', async (t) => {
  const root = workspace(t, { 'artifact.bin': 'données' });
  const result = await generateProvenance({
    workspacePath: root, artifactPath: path.join(root, 'artifact.bin'),
    git: { commit: 'abc123', repository: 'https://user:motdepasse@github.com/org/repo.git', branch: 'main' }
  });
  assert.equal(result.commit, 'abc123');
  assert.ok(!JSON.stringify(result.statement).includes('motdepasse'));
});

test('une provenance sans artefact lisible échoue proprement', async (t) => {
  const root = workspace(t);
  const result = await generateProvenance({ workspacePath: root, artifactPath: path.join(root, 'absent.bin'), git: null });
  assert.equal(result.status, 'failed');
  assert.match(result.reason, /introuvable/);
});

test('la validation structurelle détecte un document incomplet', () => {
  const check = validateProvenance({ _type: STATEMENT_TYPE, predicateType: PREDICATE_TYPE, subject: [{ name: 'x' }] });
  assert.equal(check.valid, false);
  assert.ok(check.problems.some((problem) => problem.includes('digest sha256')));
});

test('la provenance est déterministe hors identifiants d’exécution', async (t) => {
  const root = workspace(t, { 'artifact.bin': 'données' });
  const options = { workspacePath: root, artifactPath: path.join(root, 'artifact.bin'), git: null, finishedAt: '2026-01-01T00:00:00.000Z' };
  const first = await generateProvenance(options);
  const second = await generateProvenance(options);
  assert.equal(first.artifactDigest, second.artifactDigest);
  assert.deepEqual(first.statement.subject, second.statement.subject);
  assert.deepEqual(first.statement.predicate.buildDefinition, second.statement.predicate.buildDefinition);
});
