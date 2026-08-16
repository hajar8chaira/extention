const { execFile } = require('child_process');
const { promisify } = require('util');
const { dockerCliArgs } = require('./docker');

const execFileAsync = promisify(execFile);

// Mirrors docker-compose.sonarqube.yml exactly, so a server created here and a
// server created with the Compose file are the same container and the same
// named volumes. The Compose file lives outside the packaged extension, which
// is why the container is driven directly.
const SERVER_CONTAINER = 'security-center-sonarqube';
const SERVER_IMAGE = 'sonarqube:community';
const SERVER_URL = 'http://127.0.0.1:9000';
const SERVER_VOLUMES = Object.freeze([
  ['security-center-sonarqube-data', '/opt/sonarqube/data'],
  ['security-center-sonarqube-logs', '/opt/sonarqube/logs'],
  ['security-center-sonarqube-extensions', '/opt/sonarqube/extensions']
]);

const LOCAL_SERVER_STATES = Object.freeze({
  DOCKER_UNAVAILABLE: 'docker-unavailable',
  MISSING: 'missing',
  STOPPED: 'stopped',
  STARTING: 'starting',
  INITIALIZING: 'initializing',
  READY: 'ready',
  ERROR: 'error'
});

/**
 * Creation arguments. Bound to the loopback interface only, no privileged
 * flag, no Docker socket, no host filesystem mount, and named volumes so the
 * data survives a stop.
 */
function serverRunArgs({ image = SERVER_IMAGE, container = SERVER_CONTAINER } = {}) {
  return dockerCliArgs([
    'run', '-d',
    '--name', container,
    '-p', `127.0.0.1:9000:9000`,
    ...SERVER_VOLUMES.flatMap(([volume, mountPath]) => ['-v', `${volume}:${mountPath}`]),
    '-e', 'SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true',
    '--ulimit', 'nofile=65536:65536',
    '--restart', 'unless-stopped',
    image
  ]);
}

function serverStartArgs(container = SERVER_CONTAINER) {
  return dockerCliArgs(['start', container]);
}

/** Stop only. Never `rm`, never `down -v`: the volumes must survive. */
function serverStopArgs(container = SERVER_CONTAINER) {
  return dockerCliArgs(['stop', container]);
}

function serverInspectArgs(container = SERVER_CONTAINER) {
  return dockerCliArgs(['inspect', '--format', '{{.State.Status}}', container]);
}

/**
 * Status of the container Security Center manages, identified by its exact
 * name. No other container on the machine is ever inspected or stopped.
 */
async function inspectLocalServer({ exec = execFileAsync, container = SERVER_CONTAINER, timeoutMs = 10000 } = {}) {
  try {
    const { stdout } = await exec('docker', serverInspectArgs(container), { timeout: timeoutMs, windowsHide: true });
    return String(stdout || '').trim().toLowerCase() || null;
  } catch { return null; }
}

/**
 * A running container is not a ready SonarQube: the HTTP status decides.
 * `health` is the payload of the existing preflight, or null when unreachable.
 */
function localServerState({ dockerAvailable = true, containerStatus = null, health = null } = {}) {
  if (!dockerAvailable) return LOCAL_SERVER_STATES.DOCKER_UNAVAILABLE;
  if (!containerStatus) return LOCAL_SERVER_STATES.MISSING;
  if (['exited', 'created', 'paused', 'dead'].includes(containerStatus)) {
    return containerStatus === 'dead' ? LOCAL_SERVER_STATES.ERROR : LOCAL_SERVER_STATES.STOPPED;
  }
  if (containerStatus === 'restarting') return LOCAL_SERVER_STATES.STARTING;
  // Container is running: ask SonarQube itself.
  const status = String(health?.status || '').toUpperCase();
  if (status === 'UP') return LOCAL_SERVER_STATES.READY;
  if (['STARTING', 'DB_MIGRATION_NEEDED', 'DB_MIGRATION_RUNNING'].includes(status)) return LOCAL_SERVER_STATES.INITIALIZING;
  if (status === 'DOWN') return LOCAL_SERVER_STATES.ERROR;
  return LOCAL_SERVER_STATES.STARTING;
}

const LOCAL_SERVER_LABELS = Object.freeze({
  [LOCAL_SERVER_STATES.DOCKER_UNAVAILABLE]: 'Docker indisponible',
  [LOCAL_SERVER_STATES.MISSING]: 'Non installé',
  [LOCAL_SERVER_STATES.STOPPED]: 'Serveur local installé — arrêté',
  [LOCAL_SERVER_STATES.STARTING]: 'Démarrage…',
  [LOCAL_SERVER_STATES.INITIALIZING]: 'Initialisation…',
  [LOCAL_SERVER_STATES.READY]: 'Prêt',
  [LOCAL_SERVER_STATES.ERROR]: 'Erreur'
});

/**
 * Starts the managed server. An existing container is restarted, never
 * recreated, so no data is lost and no volume is touched.
 */
async function startLocalServer({ exec = execFileAsync, container = SERVER_CONTAINER, image = SERVER_IMAGE, timeoutMs = 180000 } = {}) {
  const status = await inspectLocalServer({ exec, container });
  if (status === 'running') return { action: 'already-running' };
  if (status) {
    await exec('docker', serverStartArgs(container), { timeout: timeoutMs, windowsHide: true });
    return { action: 'started' };
  }
  await exec('docker', serverRunArgs({ image, container }), { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
  return { action: 'created' };
}

async function stopLocalServer({ exec = execFileAsync, container = SERVER_CONTAINER, timeoutMs = 120000 } = {}) {
  const status = await inspectLocalServer({ exec, container });
  if (!status) return { action: 'missing' };
  if (status !== 'running') return { action: 'already-stopped' };
  await exec('docker', serverStopArgs(container), { timeout: timeoutMs, windowsHide: true });
  return { action: 'stopped' };
}

/**
 * Bounded wait for the server to actually answer. Never loops forever and
 * honours cancellation.
 */
async function waitForLocalServer({
  checkStatus,
  timeoutMs = 240000,
  pollIntervalMs = 5000,
  signal,
  onProgress = () => {},
  now = () => Date.now(),
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
} = {}) {
  const deadline = now() + Math.max(1000, timeoutMs);
  let last = null;
  for (;;) {
    if (signal?.aborted) return { state: LOCAL_SERVER_STATES.ERROR, reason: 'cancelled', health: last };
    try {
      last = await checkStatus();
      if (String(last?.status || '').toUpperCase() === 'UP') return { state: LOCAL_SERVER_STATES.READY, health: last };
      onProgress(LOCAL_SERVER_STATES.INITIALIZING);
    } catch {
      last = null;
      onProgress(LOCAL_SERVER_STATES.STARTING);
    }
    if (now() >= deadline) return { state: LOCAL_SERVER_STATES.ERROR, reason: 'timeout', health: last };
    await delay(pollIntervalMs);
  }
}

module.exports = {
  SERVER_CONTAINER, SERVER_IMAGE, SERVER_URL, SERVER_VOLUMES,
  LOCAL_SERVER_STATES, LOCAL_SERVER_LABELS,
  serverRunArgs, serverStartArgs, serverStopArgs, serverInspectArgs,
  inspectLocalServer, localServerState, startLocalServer, stopLocalServer, waitForLocalServer
};
