const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { dockerCliArgs } = require('./docker');
const sonarApi = require('./sonarqube-api');
const { SonarError, normalizeHostUrl } = require('./sonarqube-api');

const execFileAsync = promisify(execFile);

const SCANNER_IMAGE = 'sonarsource/sonar-scanner-cli:latest';
const CONTAINER_SOURCE = '/usr/src';
const CONTAINER_WORK = '/tmp/sonar-work';

// Noise that must never be analysed. Merged with the project policy exclusions.
const DEFAULT_EXCLUSIONS = Object.freeze([
  '**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/out/**',
  '**/coverage/**', '**/security-reports/**', '**/.runtime-python/**',
  '**/.codex-backups/**', '**/vendor/**', '**/.scannerwork/**',
  '**/*.min.js', '**/*.min.css', '**/*.map'
]);

function scannerCandidates(platform = process.platform) {
  return platform === 'win32'
    ? ['sonar-scanner.bat', 'sonar-scanner.cmd', 'sonar-scanner']
    : ['sonar-scanner'];
}

async function whichCommand(command) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const { stdout } = await execFileAsync(detector, [command], { windowsHide: true });
    return String(stdout).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0] || '';
  } catch { return ''; }
}

/**
 * SonarScanner ships as a .bat wrapper on Windows and Node refuses to spawn
 * batch files directly. The interpreter is invoked with an argument array so
 * `shell: true` stays unnecessary and arguments remain separated.
 */
function localInvocation(resolvedPath, platform = process.platform) {
  if (platform === 'win32' && /\.(bat|cmd)$/i.test(resolvedPath)) {
    return { executable: process.env.COMSPEC || 'cmd.exe', prefixArgs: ['/d', '/s', '/c', resolvedPath] };
  }
  return { executable: resolvedPath, prefixArgs: [] };
}

function parseScannerVersion(text) {
  return String(text || '').match(/SonarScanner\s+(?:CLI\s+)?v?([0-9][\w.-]*)/i)?.[1] || '';
}

async function detectLocalScanner({ timeoutMs = 30000, platform = process.platform } = {}) {
  for (const candidate of scannerCandidates(platform)) {
    const resolved = await whichCommand(candidate);
    if (!resolved) continue;
    const invocation = localInvocation(resolved, platform);
    try {
      const { stdout, stderr } = await execFileAsync(invocation.executable, [...invocation.prefixArgs, '--version'], {
        timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024
      });
      return { ...invocation, path: resolved, version: parseScannerVersion(`${stdout}\n${stderr}`) || 'inconnue' };
    } catch (error) {
      // Older CLIs print their banner then exit non-zero: accept the banner as proof.
      const version = parseScannerVersion(`${error.stdout || ''}\n${error.stderr || ''}`);
      if (version) return { ...invocation, path: resolved, version };
    }
  }
  return null;
}

/** Keeps only characters SonarQube accepts, and requires one non-digit. */
function sanitizeProjectKey(value) {
  const cleaned = String(value || '').trim()
    .replace(/[^A-Za-z0-9._:-]+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 400);
  return cleaned && /[A-Za-z_:.-]/.test(cleaned) ? cleaned : '';
}

/** `git@host:owner/repo.git` and `https://host/owner/repo` both become `owner_repo`. */
function projectKeyFromGitRemote(remoteUrl) {
  const match = String(remoteUrl || '').trim().match(/[:/]([^/:]+)\/([^/]+?)(?:\.git)?\/?$/);
  return match ? sanitizeProjectKey(`${match[1]}_${match[2]}`) : '';
}

async function readGitRemote(workspacePath) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', path.resolve(workspacePath), 'config', '--get', 'remote.origin.url'], {
      windowsHide: true, timeout: 5000
    });
    return stdout.trim();
  } catch { return ''; }
}

/** Shared `key=value` format of sonar-project.properties and report-task.txt. */
function parseScannerProperties(text) {
  const result = {};
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    result[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return result;
}

/**
 * Identity order: explicit setting, existing sonar-project.properties, Git
 * remote, then the folder name. The absolute workspace path is deliberately
 * never used as a permanent identity.
 */
function resolveProjectIdentity({ configuredKey = '', propertiesKey = '', gitRemote = '', workspacePath = '' } = {}) {
  const folder = path.basename(path.resolve(workspacePath || '.'));
  const projectKey = sanitizeProjectKey(configuredKey)
    || sanitizeProjectKey(propertiesKey)
    || projectKeyFromGitRemote(gitRemote)
    || sanitizeProjectKey(folder);
  if (!projectKey) {
    throw new SonarError('CONFIG_ERROR', 'Impossible de déterminer sonar.projectKey. Renseignez securityCenter.sonar.projectKey.');
  }
  return { projectKey, projectName: folder || projectKey };
}

function mergeExclusions(policyExclusions = []) {
  return [...new Set([...DEFAULT_EXCLUSIONS, ...policyExclusions.map((value) => String(value).trim()).filter(Boolean)])];
}

/**
 * When the developer already maintains a sonar-project.properties, only the
 * working directory is overridden so the repository is never modified.
 */
function analysisProperties({ projectKey, projectName, exclusions = [], workingDirectory, sources = '.', hasPropertiesFile = false }) {
  const shared = [`-Dsonar.working.directory=${workingDirectory}`, '-Dsonar.scm.disabled=true'];
  if (hasPropertiesFile) return shared;
  return [
    `-Dsonar.projectKey=${projectKey}`,
    `-Dsonar.projectName=${projectName}`,
    `-Dsonar.sources=${sources}`,
    '-Dsonar.sourceEncoding=UTF-8',
    ...(exclusions.length ? [`-Dsonar.exclusions=${exclusions.join(',')}`] : []),
    ...shared
  ];
}

/**
 * Inside the scanner container `127.0.0.1` is the container itself, so a local
 * SonarQube server has to be reached through the Docker host gateway. Remote
 * servers are left untouched.
 */
function dockerHostUrl(hostUrl) {
  const url = new URL(normalizeHostUrl(hostUrl));
  if (['127.0.0.1', 'localhost', '::1', '[::1]'].includes(url.hostname)) url.hostname = 'host.docker.internal';
  return url.toString().replace(/\/+$/, '');
}

function dockerArgs(workspacePath, properties, { envFile = '', workHostDirectory, image = SCANNER_IMAGE } = {}) {
  return dockerCliArgs([
    'run', '--rm',
    // Docker Desktop defines this alias already; Linux engines need it spelled out.
    '--add-host', 'host.docker.internal:host-gateway',
    ...(envFile ? ['--env-file', envFile] : []),
    '-v', `${path.resolve(workspacePath)}:${CONTAINER_SOURCE}:ro`,
    '-v', `${workHostDirectory}:${CONTAINER_WORK}:rw`,
    '-w', CONTAINER_SOURCE,
    image,
    ...properties
  ]);
}

/** Credentials go through an env-file (0600) so they never appear in argv. */
function sonarEnvFileContent(hostUrl, token) {
  for (const value of [hostUrl, token]) {
    if (/[\r\n]/.test(String(value || ''))) throw new SonarError('CONFIG_ERROR', 'Configuration SonarQube invalide.');
  }
  return `SONAR_HOST_URL=${hostUrl}\n${token ? `SONAR_TOKEN=${token}\n` : ''}`;
}

/** Last-resort scrubbing before any scanner output reaches a log or the UI. */
function maskToken(text, token = '') {
  let value = String(text || '');
  const secret = String(token || '');
  if (secret.length >= 8) value = value.split(secret).join('***');
  return value.replace(/\b(squ|sqp|sqa|sqk)_[A-Za-z0-9]{8,}/gi, '$1_***');
}

/**
 * Applies the Security Center `auto → local → docker` policy exactly once, so
 * the expensive `--version` probe never runs twice per analysis.
 */
async function resolveRunner(mode = 'auto', { platform = process.platform, detect = detectLocalScanner, hasCommand = whichCommand } = {}) {
  const local = mode !== 'docker' ? await detect({ platform }) : null;
  if (local) return { mode: 'local', local };
  if (mode === 'local') {
    throw new SonarError('CONFIG_ERROR', 'SonarScanner local est introuvable. Installez le CLI SonarScanner ou choisissez le mode Docker.');
  }
  if (!await hasCommand('docker')) {
    throw new SonarError('CONFIG_ERROR', 'Ni SonarScanner local ni Docker ne sont disponibles.');
  }
  return { mode: 'docker', local: null };
}

async function resolveInvocation(mode, workspacePath, properties, { envFile, workHostDirectory, image, platform, runner } = {}) {
  const resolved = runner || await resolveRunner(mode, { platform });
  if (resolved.mode === 'local') {
    return {
      executable: resolved.local.executable,
      args: [...resolved.local.prefixArgs, ...properties],
      cwd: path.resolve(workspacePath),
      mode: 'local',
      version: resolved.local.version
    };
  }
  return {
    executable: 'docker',
    args: dockerArgs(workspacePath, properties, { envFile, workHostDirectory, image }),
    cwd: path.resolve(workspacePath),
    mode: 'docker'
  };
}

async function runSonarQube({
  workspacePath,
  mode = 'auto',
  hostUrl = 'http://127.0.0.1:9000',
  projectKey = '',
  token = '',
  exclusions = [],
  includeCodeSmells = false,
  timeoutMs = 900000,
  taskTimeoutMs = 300000,
  pollIntervalMs = 2000,
  signal,
  image = SCANNER_IMAGE,
  api = sonarApi,
  gitRemote,
  platform = process.platform,
  exec = execFileAsync,
  runner: providedRunner
}) {
  const root = path.resolve(workspacePath);
  const normalizedHost = normalizeHostUrl(hostUrl);

  // Preflight: never start an analysis against a server that cannot receive it.
  const server = await api.checkServerStatus(normalizedHost, { timeoutMs: 10000, signal });
  if (!String(token || '').trim()) {
    throw new SonarError('AUTH_ERROR', 'Aucun jeton SonarQube configuré. Utilisez « Security Center: Configurer le jeton SonarQube ».');
  }

  let propertiesText = '';
  try { propertiesText = await fs.readFile(path.join(root, 'sonar-project.properties'), 'utf8'); }
  catch { /* Optional file: Security Center builds the properties itself. */ }
  const hasPropertiesFile = Boolean(propertiesText.trim());
  const identity = resolveProjectIdentity({
    configuredKey: projectKey,
    propertiesKey: parseScannerProperties(propertiesText)['sonar.projectKey'],
    gitRemote: gitRemote ?? await readGitRemote(root),
    workspacePath: root
  });

  // The working directory stays outside the repository so no scanner artefact
  // is ever written into the developer's project.
  const workDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-sonar-'));
  try {
    const runner = providedRunner || await resolveRunner(mode, { platform });
    // Docker sees the mounted path, the local CLI sees the host path. Either
    // way report-task.txt lands in `workDirectory` on the host.
    const properties = analysisProperties({
      ...identity,
      exclusions: mergeExclusions(exclusions),
      workingDirectory: runner.mode === 'docker' ? CONTAINER_WORK : workDirectory,
      hasPropertiesFile
    });
    // Only Docker needs the credentials on disk: the local CLI inherits them
    // from the process environment, so the token is never written there.
    let envFile = '';
    if (runner.mode === 'docker') {
      // The scanner reaches the server from inside the container; Security
      // Center keeps querying the API from the host with the configured URL.
      envFile = path.join(workDirectory, 'sonar.env');
      await fs.writeFile(envFile, sonarEnvFileContent(dockerHostUrl(normalizedHost), token), { encoding: 'utf8', mode: 0o600 });
    }
    const invocation = await resolveInvocation(mode, root, properties, {
      envFile, workHostDirectory: workDirectory, image, platform, runner
    });

    try {
      await exec(invocation.executable, invocation.args, {
        cwd: invocation.cwd,
        timeout: timeoutMs,
        maxBuffer: 50 * 1024 * 1024,
        windowsHide: true,
        signal,
        // Local mode receives credentials through the environment, never argv.
        env: invocation.mode === 'local'
          ? { ...process.env, SONAR_HOST_URL: normalizedHost, SONAR_TOKEN: token }
          : process.env
      });
    } catch (error) {
      if (signal?.aborted) throw new SonarError('CANCELED', 'Analyse SonarQube annulée.');
      if (error.killed) throw new SonarError('TIMEOUT', `L’analyse SonarScanner a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
      const details = maskToken(String(error.stderr || error.stdout || error.message || '').trim(), token);
      if (/not authorized|401|invalid token/i.test(details)) {
        throw new SonarError('AUTH_ERROR', 'SonarScanner a été refusé par le serveur. Vérifiez le jeton SonarQube.');
      }
      throw new SonarError('FAILED', `SonarScanner a échoué : ${details.split('\n').slice(-6).join(' ').slice(0, 500) || 'raison inconnue'}`);
    }

    let reportTask = {};
    try { reportTask = parseScannerProperties(await fs.readFile(path.join(workDirectory, 'report-task.txt'), 'utf8')); }
    catch { throw new SonarError('FAILED', 'SonarScanner n’a produit aucun report-task.txt exploitable.'); }

    const analysedKey = reportTask.projectKey || identity.projectKey;
    await api.waitForTask(normalizedHost, reportTask.ceTaskId, {
      token, timeoutMs: taskTimeoutMs, pollIntervalMs, signal
    });

    const types = includeCodeSmells ? ['VULNERABILITY', 'BUG', 'CODE_SMELL'] : ['VULNERABILITY', 'BUG'];
    const issueResult = await api.fetchIssues(normalizedHost, analysedKey, { token, types, signal });

    // Hotspots live on a separate endpoint and may be unavailable on older
    // servers: their absence degrades the result instead of failing the scan.
    const warnings = [];
    let hotspotResult = { hotspots: [], components: [], total: 0, truncated: false };
    try {
      hotspotResult = await api.fetchHotspots(normalizedHost, analysedKey, { token, signal });
    } catch (error) {
      if (error instanceof SonarError && error.code === 'CANCELED') throw error;
      if (signal?.aborted) throw new SonarError('CANCELED', 'Analyse SonarQube annulée.');
      warnings.push(`Security hotspots indisponibles : ${maskToken(error.message, token)}`);
    }

    const ruleKeys = [
      ...issueResult.issues.map((issue) => issue?.rule),
      ...hotspotResult.hotspots.map((hotspot) => hotspot?.ruleKey)
    ].filter(Boolean);
    let rules = new Map();
    try {
      rules = await api.fetchRuleMetadata(normalizedHost, ruleKeys, { token, signal });
    } catch (error) {
      if (error instanceof SonarError && error.code === 'CANCELED') throw error;
      if (signal?.aborted) throw new SonarError('CANCELED', 'Analyse SonarQube annulée.');
      warnings.push(`Métadonnées de règles indisponibles : ${maskToken(error.message, token)}`);
    }
    if (issueResult.truncated) warnings.push(`SonarQube a limité la pagination : ${issueResult.total} problème(s) au total.`);

    return {
      payload: {
        projectKey: analysedKey,
        serverUrl: normalizedHost,
        serverVersion: server.version,
        dashboardUrl: reportTask.dashboardUrl || '',
        issues: issueResult.issues,
        components: [...issueResult.components, ...hotspotResult.components],
        hotspots: hotspotResult.hotspots,
        rules: Object.fromEntries(rules),
        warnings
      },
      stderr: warnings.join('\n'),
      mode: invocation.mode
    };
  } finally {
    await fs.rm(workDirectory, { recursive: true, force: true });
  }
}

module.exports = {
  SCANNER_IMAGE, CONTAINER_SOURCE, CONTAINER_WORK, DEFAULT_EXCLUSIONS,
  runSonarQube, resolveRunner, resolveInvocation, detectLocalScanner, scannerCandidates, localInvocation,
  parseScannerVersion, sanitizeProjectKey, projectKeyFromGitRemote, readGitRemote,
  parseScannerProperties, resolveProjectIdentity, mergeExclusions, analysisProperties,
  dockerArgs, dockerHostUrl, sonarEnvFileContent, maskToken, whichCommand
};
