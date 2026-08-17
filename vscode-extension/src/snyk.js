const { execFile } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const path = require('path');
const { dockerCliArgs } = require('./docker');
const { SnykError, maskToken } = require('./snyk-api');

const execFileAsync = promisify(execFile);

// Official Snyk image. `snyk/snyk-cli` is deprecated by Snyk itself, and the
// language-specific tags of `snyk/snyk` bootstrap a package manager before the
// scan. `:linux` is the generic Ubuntu variant, so no community image and no
// unexpected `npm install` inside the analysed workspace.
const SNYK_IMAGE = 'snyk/snyk:linux';
const CONTAINER_SOURCE = '/project';
// Shell no-op handed to the image's `COMMAND` hook to neutralise its build
// bootstrap. Documented by Snyk as the way to override that step.
const DOCKER_BOOTSTRAP_NOOP = ':';

// Snyk graded capabilities. Open Source is the baseline every account has;
// Code and IaC depend on the plan, so they degrade instead of failing the scan.
const SNYK_CAPABILITIES = Object.freeze(['openSource', 'code', 'iac']);

function snykCandidates(platform = process.platform) {
  return platform === 'win32' ? ['snyk.exe', 'snyk.cmd', 'snyk'] : ['snyk'];
}

async function whichCommand(command, { exec = execFileAsync } = {}) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const { stdout } = await exec(detector, [command], { windowsHide: true });
    return String(stdout).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0] || '';
  } catch { return ''; }
}

/**
 * `npm i -g snyk` installs a `snyk.cmd` wrapper on Windows and Node refuses to
 * spawn batch files directly. The interpreter receives an argument array, so
 * `shell: true` stays unnecessary and arguments are never re-parsed.
 */
function localInvocation(resolvedPath, platform = process.platform) {
  if (platform === 'win32' && /\.(bat|cmd)$/i.test(resolvedPath)) {
    return { executable: process.env.COMSPEC || 'cmd.exe', prefixArgs: ['/d', '/s', '/c', resolvedPath] };
  }
  return { executable: resolvedPath, prefixArgs: [] };
}

/** `snyk --version` prints e.g. `1.1298.0 (standalone)`. */
function parseSnykVersion(text) {
  return String(text || '').match(/\b(\d+\.\d+\.\d+[\w.-]*)\b/)?.[1] || '';
}

async function detectLocalCli({ timeoutMs = 30000, platform = process.platform, exec = execFileAsync, hasCommand = whichCommand } = {}) {
  for (const candidate of snykCandidates(platform)) {
    const resolved = await hasCommand(candidate);
    if (!resolved) continue;
    const invocation = localInvocation(resolved, platform);
    try {
      const { stdout, stderr } = await exec(invocation.executable, [...invocation.prefixArgs, '--version'], {
        timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024
      });
      return { ...invocation, path: resolved, version: parseSnykVersion(`${stdout}\n${stderr}`) || 'inconnue' };
    } catch (error) {
      const version = parseSnykVersion(`${error.stdout || ''}\n${error.stderr || ''}`);
      if (version) return { ...invocation, path: resolved, version };
    }
  }
  return null;
}

/**
 * Security Center `auto → local → docker` policy, applied exactly once per
 * analysis so the `--version` probe never runs twice.
 */
async function resolveRunner(mode = 'auto', { platform = process.platform, detect = detectLocalCli, hasCommand = whichCommand } = {}) {
  const local = mode !== 'docker' ? await detect({ platform }) : null;
  if (local) return { mode: 'local', local };
  if (mode === 'local') {
    throw new SnykError('CLI_MISSING', 'Le CLI Snyk local est introuvable. Installez-le depuis « Configuration des scanners » ou choisissez le mode Docker.');
  }
  if (!await hasCommand('docker')) {
    throw new SnykError('DOCKER_MISSING', 'Ni le CLI Snyk local ni Docker ne sont disponibles.');
  }
  return { mode: 'docker', local: null };
}

/**
 * Snyk `--exclude` accepts directory and file *names*, never paths or globs.
 * Policy exclusions are glob patterns, so only the unambiguous name segments
 * are forwarded and everything else is silently ignored rather than sent as an
 * invalid argument.
 */
function excludeNames(exclusions = []) {
  const names = [];
  for (const pattern of exclusions) {
    for (const segment of String(pattern).split('/')) {
      const name = segment.trim();
      if (!name || name === '**' || name === '.' || name.includes('*') || name.includes('?')) continue;
      names.push(name);
    }
  }
  return [...new Set(names)];
}

function openSourceArgs({ exclusions = [], severityThreshold = '' } = {}) {
  const names = excludeNames(exclusions);
  return [
    'test', '--json', '--all-projects',
    ...(names.length ? [`--exclude=${names.join(',')}`] : []),
    ...(severityThreshold ? [`--severity-threshold=${severityThreshold}`] : [])
  ];
}

function codeArgs({ severityThreshold = '' } = {}) {
  return ['code', 'test', '--json', ...(severityThreshold ? [`--severity-threshold=${severityThreshold}`] : [])];
}

function iacArgs({ severityThreshold = '' } = {}) {
  return ['iac', 'test', '--json', ...(severityThreshold ? [`--severity-threshold=${severityThreshold}`] : [])];
}

/**
 * The workspace is mounted read-only: Snyk only ever reads manifests and source
 * files. No Docker socket, no extra privilege, and the token is passed by name
 * so its value never appears in argv.
 */
function dockerArgs(workspacePath, args, { image = SNYK_IMAGE, containerName = '' } = {}) {
  return dockerCliArgs([
    'run', '--rm',
    ...(containerName ? ['--name', containerName] : []),
    '-e', 'SNYK_TOKEN',
    '-e', 'SNYK_DISABLE_ANALYTICS',
    // The official image bootstraps the project before scanning: it runs
    // `npm install`, `mvn install` or `pip install` inside the working
    // directory. Security Center analyses a read-only copy of the developer's
    // workspace and must never trigger a build there, so the documented
    // `COMMAND` hook replaces that bootstrap with a shell no-op.
    '-e', `COMMAND=${DOCKER_BOOTSTRAP_NOOP}`,
    '-v', `${path.resolve(workspacePath)}:${CONTAINER_SOURCE}:ro`,
    '-w', CONTAINER_SOURCE,
    image,
    'snyk',
    ...args
  ]);
}

async function resolveInvocation(mode, workspacePath, args, { image = SNYK_IMAGE, platform, runner, containerName = '' } = {}) {
  const resolved = runner || await resolveRunner(mode, { platform });
  if (resolved.mode === 'local') {
    return {
      executable: resolved.local.executable,
      args: [...resolved.local.prefixArgs, ...args],
      cwd: path.resolve(workspacePath),
      mode: 'local',
      version: resolved.local.version
    };
  }
  return {
    executable: 'docker',
    args: dockerArgs(workspacePath, args, { image, containerName }),
    cwd: path.resolve(workspacePath),
    mode: 'docker',
    containerName
  };
}

/** Snyk credentials and telemetry are decided here, once, for every sub-scan. */
function snykEnvironment(token, baseEnv = process.env) {
  return {
    ...baseEnv,
    SNYK_TOKEN: String(token || ''),
    // Optional analytics are switched off: Security Center never sends the
    // analysed project's metadata anywhere the user did not ask for.
    SNYK_DISABLE_ANALYTICS: '1'
  };
}

/**
 * Maps Snyk's own wording onto a typed Security Center error. Snyk reports the
 * same conditions through the exit code, stderr, or a JSON body, so the text
 * rules live here once and every caller reuses them.
 */
function classifyMessage(details, { exitCode } = {}) {
  if (/missing api token|snyk auth|authentication (failed|error)|not authori[sz]ed|unauthori[sz]ed|\b401\b/i.test(details)) {
    return new SnykError('AUTH_ERROR', 'Snyk a refusé les identifiants. Vérifiez le jeton enregistré dans Security Center.');
  }
  if (/\b403\b|forbidden|insufficient permission/i.test(details)) {
    return new SnykError('AUTH_ERROR', 'Le jeton Snyk n’a pas les droits nécessaires sur cette organisation.');
  }
  if (/not supported|not enabled|not entitled|upgrade your plan|feature is not available|snyk code is not/i.test(details)) {
    return new SnykError('FEATURE_UNAVAILABLE', 'Cette capacité Snyk n’est pas disponible pour ce compte ou cette organisation.');
  }
  if (/enotfound|econnrefused|etimedout|eai_again|network|proxy/i.test(details)) {
    return new SnykError('NETWORK_ERROR', 'Snyk n’a pas pu joindre son service. Vérifiez la connexion réseau ou le proxy.');
  }
  // Snyk cannot resolve an npm project from the manifest alone: it needs the
  // installed tree or a lockfile. Reporting « aucune vulnérabilité » here would
  // be a false negative, so the actionable cause is stated instead.
  if (/missing node_modules|please run ['"]?npm install/i.test(details)) {
    return new SnykError('UNSUPPORTED', 'Snyk ne peut pas résoudre les dépendances : le projet n’a ni lockfile ni node_modules. Installez les dépendances ou versionnez le lockfile, puis relancez.');
  }
  if (exitCode === 3 || /no supported (target )?files|could not detect supported/i.test(details)) {
    return new SnykError('NO_PROJECTS', 'Aucun projet compatible Snyk n’a été détecté dans ce workspace.');
  }
  const summary = details.split('\n').map((line) => line.trim()).filter(Boolean).slice(-4).join(' ').slice(0, 400);
  return new SnykError('FAILED', `Snyk a échoué : ${summary || 'raison inconnue'}`);
}

/**
 * Turns raw CLI failure text into a typed Security Center error. Snyk exit
 * codes are meaningful: 0 = clean, 1 = issues found, 2 = error, 3 = nothing
 * supported to scan.
 */
function classifyFailure(error, { token = '', timeoutMs = 0, signal } = {}) {
  if (signal?.aborted) return new SnykError('CANCELED', 'Analyse Snyk annulée.');
  if (error?.killed) return new SnykError('TIMEOUT', `L’analyse Snyk a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
  if (error?.code === 'ENOENT') return new SnykError('CLI_MISSING', 'La commande Snyk est introuvable.');
  const details = maskToken(`${error?.stderr || ''}\n${error?.stdout || ''}\n${error?.message || ''}`, token);
  return classifyMessage(details, { exitCode: error?.exitCode });
}

/**
 * Snyk reports several failures as a *successful* process that prints
 * `{"ok": false, "error": "..."}`. Without this check a scan that never ran
 * would be indistinguishable from a project with no vulnerability at all.
 */
function snykPayloadError(payload) {
  const entries = (Array.isArray(payload) ? payload : [payload]).filter((entry) => entry && typeof entry === 'object');
  if (!entries.length) return '';
  const usable = entries.some((entry) => Array.isArray(entry.vulnerabilities)
    || Array.isArray(entry.infrastructureAsCodeIssues)
    || Array.isArray(entry.runs));
  if (usable) return '';
  const failed = entries.find((entry) => entry.error && entry.ok !== true);
  return failed ? String(failed.error) : '';
}

/** `docker run` leaves the container behind when its client is killed. */
async function removeContainer(containerName, { exec = execFileAsync } = {}) {
  if (!containerName) return;
  try { await exec('docker', dockerCliArgs(['rm', '-f', containerName]), { timeout: 15000, windowsHide: true }); }
  catch { /* Already gone: nothing to clean up. */ }
}

/**
 * Runs one Snyk sub-command and returns its parsed JSON.
 *
 * Snyk exits 1 as soon as it finds a single issue, so a non-zero status with
 * parsable JSON on stdout is a successful scan, not a failure.
 */
async function runSnykCommand(args, {
  workspacePath,
  mode = 'auto',
  token = '',
  timeoutMs = 600000,
  signal,
  image = SNYK_IMAGE,
  platform = process.platform,
  exec = execFileAsync,
  runner,
  env = process.env
}) {
  const containerName = (runner?.mode || mode) === 'local' ? '' : `security-center-snyk-${crypto.randomBytes(6).toString('hex')}`;
  const invocation = await resolveInvocation(mode, workspacePath, args, { image, platform, runner, containerName });
  const options = {
    cwd: invocation.cwd,
    timeout: timeoutMs,
    maxBuffer: 200 * 1024 * 1024,
    windowsHide: true,
    signal,
    env: snykEnvironment(token, env)
  };
  try {
    const { stdout, stderr } = await exec(invocation.executable, invocation.args, options);
    return { payload: acceptPayload(parseSnykJson(stdout, token), token), stderr: maskToken(stderr, token), mode: invocation.mode };
  } catch (error) {
    if (error instanceof SnykError) throw error;
    // Cancellation kills the Docker client; the container is removed explicitly
    // so no orphan survives the aborted scan.
    if (signal?.aborted && invocation.mode === 'docker') await removeContainer(invocation.containerName, { exec });
    if (error?.stdout && !signal?.aborted && !error?.killed) {
      try { return { payload: acceptPayload(parseSnykJson(error.stdout, token), token), stderr: maskToken(error.stderr, token), mode: invocation.mode }; }
      catch (payloadError) {
        // A typed error carried by the JSON body is the precise diagnosis and
        // wins over the generic process failure.
        if (payloadError instanceof SnykError && payloadError.code !== 'INVALID_RESPONSE') throw payloadError;
      }
    }
    throw classifyFailure(error, { token, timeoutMs, signal });
  }
}

/** Rejects a JSON body that reports a failure instead of results. */
function acceptPayload(payload, token = '') {
  const message = snykPayloadError(payload);
  if (message) throw classifyMessage(maskToken(message, token));
  return payload;
}

/**
 * Snyk prints JSON on stdout, sometimes preceded by progress lines and, with
 * `--all-projects`, as an array of per-project results. Both shapes are
 * normalised to an array here; the terminal output itself is never scraped.
 */
function parseSnykJson(stdout, token = '') {
  const text = String(stdout || '').trim();
  if (!text) throw new SnykError('INVALID_RESPONSE', 'Snyk n’a produit aucune sortie JSON.');
  const start = text.search(/[[{]/);
  if (start < 0) throw new SnykError('INVALID_RESPONSE', `Snyk n’a produit aucune sortie JSON exploitable : ${maskToken(text.slice(0, 200), token)}`);
  let parsed;
  try { parsed = JSON.parse(text.slice(start)); }
  catch { throw new SnykError('INVALID_RESPONSE', 'La sortie JSON de Snyk est illisible.'); }
  return parsed;
}

/** A capability result that failed without invalidating the whole Snyk scan. */
function degraded(error) {
  return {
    ran: false,
    available: error.code !== 'FEATURE_UNAVAILABLE' ? null : false,
    errorCode: error.code,
    error: error.message
  };
}

/**
 * Full Snyk analysis. Open Source is the load-bearing capability: Code and IaC
 * are additive, and their absence degrades the result instead of failing it.
 * Authentication, cancellation and timeouts stay fatal for the whole scan.
 */
async function runSnyk({
  workspacePath,
  mode = 'auto',
  token = '',
  includeOpenSource = true,
  includeCode = false,
  includeIaC = false,
  exclusions = [],
  severityThreshold = '',
  timeoutMs = 600000,
  signal,
  image = SNYK_IMAGE,
  platform = process.platform,
  exec = execFileAsync,
  runner: providedRunner,
  env = process.env
}) {
  if (!String(token || '').trim()) {
    throw new SnykError('AUTH_ERROR', 'Aucun jeton Snyk configuré. Utilisez « Security Center : configurer le jeton Snyk ».');
  }
  if (!includeOpenSource && !includeCode && !includeIaC) {
    throw new SnykError('CONFIG_ERROR', 'Aucune capacité Snyk activée. Activez au moins Snyk Open Source.');
  }
  const runner = providedRunner || await resolveRunner(mode, { platform });
  const shared = { workspacePath, mode, token, timeoutMs, signal, image, platform, exec, runner, env };
  const payload = {
    openSource: { ran: false, available: null, results: [], error: '', errorCode: '' },
    code: { ran: false, available: null, sarif: null, error: '', errorCode: '' },
    iac: { ran: false, available: null, results: [], error: '', errorCode: '' }
  };
  const warnings = [];

  if (includeOpenSource) {
    try {
      const result = await runSnykCommand(openSourceArgs({ exclusions, severityThreshold }), shared);
      payload.openSource = { ran: true, available: true, results: [result.payload].flat(), error: '', errorCode: '' };
    } catch (error) {
      // A workspace with no manifest is a legitimate outcome, not a failure.
      if (error.code === 'NO_PROJECTS') {
        payload.openSource = { ran: true, available: true, results: [], error: error.message, errorCode: error.code };
        warnings.push(error.message);
      } else if (['AUTH_ERROR', 'CANCELED', 'TIMEOUT', 'CLI_MISSING', 'DOCKER_MISSING'].includes(error.code)) {
        throw error;
      } else {
        payload.openSource = { ...degraded(error), results: [] };
        warnings.push(`Snyk Open Source : ${error.message}`);
      }
    }
  }

  for (const [capability, argsFor, key] of [['code', codeArgs, 'sarif'], ['iac', iacArgs, 'results']]) {
    if (capability === 'code' ? !includeCode : !includeIaC) continue;
    try {
      const result = await runSnykCommand(argsFor({ severityThreshold }), shared);
      payload[capability] = {
        ran: true,
        available: true,
        [key]: key === 'results' ? [result.payload].flat() : result.payload,
        error: '',
        errorCode: ''
      };
    } catch (error) {
      if (['CANCELED', 'TIMEOUT'].includes(error.code)) throw error;
      if (error.code === 'NO_PROJECTS') {
        payload[capability] = { ran: true, available: true, [key]: key === 'results' ? [] : null, error: error.message, errorCode: error.code };
        warnings.push(error.message);
        continue;
      }
      payload[capability] = { ...degraded(error), [key]: key === 'results' ? [] : null };
      warnings.push(`${capability === 'code' ? 'Snyk Code' : 'Snyk IaC'} : ${error.message}`);
    }
  }

  payload.capabilities = Object.fromEntries(SNYK_CAPABILITIES.map((capability) => {
    const source = capability === 'openSource' ? payload.openSource : payload[capability];
    return [capability, source.available];
  }));
  payload.warnings = warnings;
  payload.mode = runner.mode;
  payload.version = runner.local?.version || '';
  return { payload, stderr: warnings.join('\n'), mode: runner.mode };
}

module.exports = {
  SNYK_IMAGE, CONTAINER_SOURCE, SNYK_CAPABILITIES, DOCKER_BOOTSTRAP_NOOP,
  runSnyk, runSnykCommand, resolveRunner, resolveInvocation, detectLocalCli, snykCandidates, localInvocation,
  parseSnykVersion, parseSnykJson, acceptPayload, snykPayloadError, excludeNames, openSourceArgs, codeArgs, iacArgs,
  dockerArgs, snykEnvironment, classifyFailure, classifyMessage, removeContainer, whichCommand
};
