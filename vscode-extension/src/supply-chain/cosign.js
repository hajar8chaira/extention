'use strict';

/**
 * Cosign — supply-chain signing and verification.
 *
 * Cosign is not a vulnerability scanner: it never produces findings. It signs
 * and verifies the artefacts the pipeline produced.
 *
 * Execution modes, decided by what is actually safe rather than by symmetry
 * with the scanners:
 *   auto  → the local binary (managed install or PATH)
 *   local → the local binary
 *   docker→ deliberately unsupported. Signing in a container would mean
 *           mounting the private key and its password into that container;
 *           Security Center reports the mode as unsupported instead of
 *           offering an unsafe workflow.
 *
 * Key handling rules enforced here:
 *   - a key pair is never generated implicitly, only by an explicit call;
 *   - an existing key is never overwritten;
 *   - the password travels through the environment, never through argv;
 *   - no private key material is ever returned, logged or embedded anywhere.
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs/promises');
const path = require('path');

const execFileAsync = promisify(execFile);

// Sigstore bundle written next to the signed artefact. Cosign 3 made this the
// only supported output for blob signatures.
const BUNDLE_SUFFIX = '.sigstore.json';

const COSIGN_ERROR_CODES = Object.freeze({
  CLI_MISSING: 'CLI_MISSING',
  UNSUPPORTED_MODE: 'UNSUPPORTED_MODE',
  KEY_MISSING: 'KEY_MISSING',
  KEY_EXISTS: 'KEY_EXISTS',
  PASSWORD_MISSING: 'PASSWORD_MISSING',
  NOT_CONFIRMED: 'NOT_CONFIRMED',
  VERIFICATION_FAILED: 'VERIFICATION_FAILED',
  TIMEOUT: 'TIMEOUT',
  CANCELED: 'CANCELED',
  FAILED: 'FAILED'
});

class CosignError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CosignError';
    this.code = COSIGN_ERROR_CODES[code] ? code : 'FAILED';
  }
}

/** Removes anything that could carry key material out of a message. */
function scrubOutput(text) {
  return String(text || '')
    .replace(/-----BEGIN[\s\S]*?-----END[^-]*-----/g, '[CLÉ MASQUÉE]')
    .replace(/\b(COSIGN_PASSWORD|password)\s*[=:]\s*\S+/gi, '$1=***')
    .trim();
}

function cosignCandidates(platform = process.platform) {
  return platform === 'win32' ? ['cosign.exe', 'cosign'] : ['cosign'];
}

async function whichCommand(command, { exec = execFileAsync } = {}) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const { stdout } = await exec(detector, [command], { windowsHide: true });
    return String(stdout).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0] || '';
  } catch { return ''; }
}

function parseCosignVersion(text) {
  return String(text || '').match(/GitVersion:\s*v?([\w.-]+)/i)?.[1]
    || String(text || '').match(/\bv?(\d+\.\d+\.\d+[\w.-]*)\b/)?.[1]
    || '';
}

async function detectLocalCosign({ timeoutMs = 20000, platform = process.platform, exec = execFileAsync, hasCommand = whichCommand } = {}) {
  for (const candidate of cosignCandidates(platform)) {
    const resolved = await hasCommand(candidate);
    if (!resolved) continue;
    try {
      const { stdout, stderr } = await exec(resolved, ['version'], { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
      return { path: resolved, version: parseCosignVersion(`${stdout}\n${stderr}`) || 'inconnue' };
    } catch (error) {
      const version = parseCosignVersion(`${error.stdout || ''}\n${error.stderr || ''}`);
      if (version) return { path: resolved, version };
    }
  }
  return null;
}

/** Modes Security Center genuinely supports for Cosign. */
function supportedModes() {
  return {
    auto: true,
    local: true,
    docker: false,
    dockerReason: 'Le mode Docker exigerait de monter la clé privée et son mot de passe dans un conteneur. Security Center ne propose pas ce compromis.'
  };
}

async function resolveRunner(mode = 'auto', { platform = process.platform, detect = detectLocalCosign } = {}) {
  if (mode === 'docker') {
    throw new CosignError('UNSUPPORTED_MODE', supportedModes().dockerReason);
  }
  const local = await detect({ platform });
  if (!local) {
    throw new CosignError('CLI_MISSING', 'Cosign est introuvable. Installez-le depuis « Configuration des scanners » ou choisissez un autre mode.');
  }
  return { mode: 'local', local };
}

/**
 * Keyless signing needs an interactive OIDC flow and a public transparency log.
 * That is out of scope for the current local-first architecture, so it is
 * reported as unsupported rather than half-implemented.
 */
function keylessSupport() {
  return {
    supported: false,
    reason: 'La signature keyless exige un flux OIDC interactif et la publication dans un journal de transparence public. Security Center ne l’active pas dans son architecture locale actuelle.'
  };
}

async function fileExists(candidate) {
  try { await fs.access(candidate); return true; } catch { return false; }
}

async function runCosign(args, { runner, password = '', timeoutMs = 120000, signal, cwd, exec = execFileAsync }) {
  const env = { ...process.env };
  // The password only ever reaches the process through the environment.
  if (password) env.COSIGN_PASSWORD = password;
  else env.COSIGN_PASSWORD = '';
  try {
    const { stdout, stderr } = await exec(runner.local.path, args, {
      cwd, timeout: timeoutMs, windowsHide: true, maxBuffer: 16 * 1024 * 1024, signal, env
    });
    return { stdout: String(stdout || ''), stderr: scrubOutput(stderr) };
  } catch (error) {
    if (signal?.aborted) throw new CosignError('CANCELED', 'Opération Cosign annulée.');
    if (error.killed) throw new CosignError('TIMEOUT', `L’opération Cosign a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    const details = scrubOutput(`${error.stderr || ''}\n${error.stdout || ''}\n${error.message || ''}`);
    if (/incorrect password|decrypt|invalid password/i.test(details)) {
      throw new CosignError('PASSWORD_MISSING', 'Cosign n’a pas pu déchiffrer la clé privée : mot de passe incorrect.');
    }
    throw new CosignError('FAILED', `Cosign a échoué : ${details.split('\n').filter(Boolean).slice(-3).join(' ').slice(0, 400) || 'raison inconnue'}`);
  }
}

/**
 * Generates a key pair. Refuses to touch an existing key: overwriting signing
 * material is destructive and irreversible, so it is never done automatically.
 */
async function generateKeyPair({ directory, password, confirmed = false, timeoutMs = 60000, mode = 'auto', runner: providedRunner, exec = execFileAsync, signal } = {}) {
  if (!confirmed) throw new CosignError('NOT_CONFIRMED', 'La génération d’une paire de clés doit être confirmée explicitement.');
  if (!password) throw new CosignError('PASSWORD_MISSING', 'Un mot de passe est requis pour protéger la clé privée Cosign.');
  const target = path.resolve(directory);
  const privateKey = path.join(target, 'cosign.key');
  const publicKey = path.join(target, 'cosign.pub');
  if (await fileExists(privateKey)) {
    throw new CosignError('KEY_EXISTS', `Une clé Cosign existe déjà dans ${target}. Security Center n’écrase jamais une clé de signature.`);
  }
  const runner = providedRunner || await resolveRunner(mode, {});
  await fs.mkdir(target, { recursive: true });
  await runCosign(['generate-key-pair'], { runner, password, timeoutMs, cwd: target, exec, signal });
  if (!await fileExists(privateKey) || !await fileExists(publicKey)) {
    throw new CosignError('FAILED', 'Cosign n’a pas produit la paire de clés attendue.');
  }
  // The private key path is returned so the UI can show where it lives; its
  // content is never read by Security Center.
  await fs.chmod(privateKey, 0o600).catch(() => {});
  return { privateKeyPath: privateKey, publicKeyPath: publicKey, createdAt: new Date().toISOString() };
}

/**
 * Signs a file with a local key. `confirmed` is required by the API itself so
 * no code path can sign silently.
 */
async function signBlob({
  filePath, keyPath, password, confirmed = false, signaturePath = '',
  mode = 'auto', runner: providedRunner, timeoutMs = 120000, signal, exec = execFileAsync
} = {}) {
  if (!confirmed) throw new CosignError('NOT_CONFIRMED', 'La signature doit être confirmée explicitement par l’utilisateur.');
  const artifact = path.resolve(filePath);
  if (!await fileExists(artifact)) throw new CosignError('FAILED', `Artefact introuvable : ${artifact}`);
  if (!keyPath || !await fileExists(path.resolve(keyPath))) {
    throw new CosignError('KEY_MISSING', 'Aucune clé privée Cosign configurée. Générez ou sélectionnez une clé avant de signer.');
  }
  if (!password) throw new CosignError('PASSWORD_MISSING', 'Le mot de passe de la clé Cosign est requis.');
  const runner = providedRunner || await resolveRunner(mode, {});
  // Cosign 3 deprecated `--output-signature` and requires the Sigstore bundle,
  // which carries the signature and its verification material in one file.
  const bundle = signaturePath ? path.resolve(signaturePath) : `${artifact}${BUNDLE_SUFFIX}`;
  await runCosign([
    'sign-blob', '--key', path.resolve(keyPath), '--bundle', bundle,
    // Local-key signing stays local: Cosign 3 otherwise fetches a TUF signing
    // config and publishes the signature to the public transparency log and
    // timestamp authority. Security Center never sends a developer's artefact
    // digests to a public service without being asked to.
    '--use-signing-config=false', '--tlog-upload=false',
    '--yes', artifact
  ], { runner, password, timeoutMs, signal, exec, cwd: path.dirname(artifact) });
  if (!await fileExists(bundle)) throw new CosignError('FAILED', 'Cosign n’a produit aucune signature.');
  return {
    status: 'signed',
    artifact,
    signaturePath: bundle,
    signatureFormat: 'sigstore-bundle',
    // Recorded so the UI never implies public transparency-log inclusion.
    transparencyLog: false,
    keyType: 'local-key-pair',
    signedAt: new Date().toISOString(),
    cosignVersion: runner.local.version
  };
}

/** Verifies a signature. A failed verification is a result, not a crash. */
async function verifyBlob({
  filePath, publicKeyPath, signaturePath = '',
  mode = 'auto', runner: providedRunner, timeoutMs = 120000, signal, exec = execFileAsync
} = {}) {
  const artifact = path.resolve(filePath);
  const signature = signaturePath ? path.resolve(signaturePath) : `${artifact}${BUNDLE_SUFFIX}`;
  if (!publicKeyPath || !await fileExists(path.resolve(publicKeyPath))) {
    throw new CosignError('KEY_MISSING', 'Aucune clé publique Cosign disponible pour la vérification.');
  }
  if (!await fileExists(signature)) {
    throw new CosignError('FAILED', `Aucune signature trouvée pour ${path.basename(artifact)}.`);
  }
  const runner = providedRunner || await resolveRunner(mode, {});
  try {
    const result = await runCosign([
      'verify-blob', '--key', path.resolve(publicKeyPath), '--bundle', signature,
      // The counterpart of `--tlog-upload=false`: a locally signed artefact has
      // no transparency-log entry, so requiring one would fail every offline
      // verification. The signature itself is still fully verified.
      '--insecure-ignore-tlog=true', artifact
    ], { runner, timeoutMs, signal, exec, cwd: path.dirname(artifact) });
    return {
      status: 'verified',
      artifact,
      signaturePath: signature,
      verifiedAt: new Date().toISOString(),
      detail: scrubOutput(result.stderr || result.stdout) || 'Signature vérifiée.'
    };
  } catch (error) {
    if (error.code === 'CANCELED' || error.code === 'TIMEOUT') throw error;
    return {
      status: 'failed',
      artifact,
      signaturePath: signature,
      verifiedAt: new Date().toISOString(),
      reason: error.message
    };
  }
}

/** Signs a provenance/attestation document alongside its subject artefact. */
async function attestBlob({
  filePath, predicatePath, predicateType = 'slsaprovenance', keyPath, password, confirmed = false,
  outputPath = '', mode = 'auto', runner: providedRunner, timeoutMs = 120000, signal, exec = execFileAsync
} = {}) {
  if (!confirmed) throw new CosignError('NOT_CONFIRMED', 'L’attestation doit être confirmée explicitement par l’utilisateur.');
  if (!keyPath || !await fileExists(path.resolve(keyPath))) throw new CosignError('KEY_MISSING', 'Aucune clé privée Cosign configurée.');
  if (!password) throw new CosignError('PASSWORD_MISSING', 'Le mot de passe de la clé Cosign est requis.');
  const artifact = path.resolve(filePath);
  const predicate = path.resolve(predicatePath);
  if (!await fileExists(predicate)) throw new CosignError('FAILED', `Prédicat introuvable : ${predicate}`);
  const runner = providedRunner || await resolveRunner(mode, {});
  const output = outputPath ? path.resolve(outputPath) : `${artifact}.att.jsonl`;
  await runCosign([
    'attest-blob', '--key', path.resolve(keyPath), '--predicate', predicate,
    '--type', predicateType, '--output-attestation', output, '--yes', artifact
  ], { runner, password, timeoutMs, signal, exec, cwd: path.dirname(artifact) });
  return { status: 'attested', artifact, attestationPath: output, predicateType, attestedAt: new Date().toISOString() };
}

module.exports = {
  COSIGN_ERROR_CODES, CosignError, BUNDLE_SUFFIX,
  cosignCandidates, detectLocalCosign, parseCosignVersion, resolveRunner, supportedModes, keylessSupport,
  generateKeyPair, signBlob, verifyBlob, attestBlob, scrubOutput, whichCommand
};
