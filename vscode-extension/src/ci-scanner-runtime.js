'use strict';

/**
 * Security Center CI scanner runtime.
 *
 * On a CI execution node, Semgrep, Gitleaks, Trivy and OSV-Scanner run as
 * short-lived containers on the Docker daemon that node can reach: nothing is
 * installed on the node, nothing comes from a developer workstation, and the
 * project only chooses scanners in security-center.yml. Local VS Code scans do
 * not use this module.
 *
 * Workspace access comes from the daemon's own records, then is proven:
 *   - Jenkins directly on the node: the workspace is bind-mounted read-only at
 *     /src, as the local Docker mode already does.
 *   - Jenkins in a container managed by that same daemon: a host path cannot be
 *     derived from a container path, so the scanner container inherits the
 *     Jenkins container's volumes read-only (--volumes-from) and sees the
 *     workspace at its own path. Scanner output paths are mapped back to /src so
 *     the existing normalizers apply unchanged.
 * Before any scanner runs, a probe container reads a random marker file through
 * that exact mechanism. A workspace the scanners cannot see is an ERROR, never
 * an empty and falsely clean scan.
 */

const crypto = require('crypto');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const CONTAINER_SOURCE = '/src';
const RUNTIME_MODES = Object.freeze(['auto', 'container', 'host']);
const UNAVAILABLE = 'SCenter CI runtime unavailable';
const DOCKER_PREREQUISITE = 'One-time Jenkins node prerequisite: the user running the Jenkins agent must be able to run the docker CLI against a Docker daemon (docker CLI on the node, access to the daemon socket or DOCKER_HOST).';
// No privileged mode, no added capability, no Docker socket: a scanner reads
// the workspace and reports, nothing else.
const SECURITY_ARGS = Object.freeze(['--security-opt', 'no-new-privileges']);
// Files a container runtime bind-mounts from the container's own directory.
const CONTAINER_IDENTITY_MOUNTS = Object.freeze(['/etc/hostname', '/etc/hosts', '/etc/resolv.conf']);

class CiRuntimeError extends Error {
  constructor(message) { super(message); this.name = 'CiRuntimeError'; }
}

/**
 * `container` on a CI execution node, `host` otherwise. Jenkins exports
 * JENKINS_URL (when its URL is configured) and a BUILD_TAG starting with
 * "jenkins-" to every build; another CI opts in with --scanner-runtime
 * container or SCENTER_SCANNER_RUNTIME=container.
 */
function scannerRuntimeMode({ flag = '', env = process.env } = {}) {
  const requested = String(flag || env.SCENTER_SCANNER_RUNTIME || 'auto').trim().toLowerCase();
  if (!RUNTIME_MODES.includes(requested)) {
    throw new Error(`Scanner runtime inconnu « ${requested} » : utilisez ${RUNTIME_MODES.join(', ')}.`);
  }
  if (requested !== 'auto') return requested;
  return env.JENKINS_URL || String(env.BUILD_TAG || '').startsWith('jenkins-') ? 'container' : 'host';
}

function currentUser() {
  try { return os.userInfo().username || 'unknown'; } catch { return 'unknown'; }
}

/** Why `docker` failed, without echoing its output: no URL, host or secret reaches the log. */
function dockerFailureReason(error, timeoutMs) {
  const stderr = String(error?.stderr || '');
  if (error?.code === 'ENOENT') return 'the docker command is not installed on this node';
  if (error?.killed) return `docker did not answer within ${Math.round(timeoutMs / 1000)}s`;
  if (/permission denied/i.test(stderr)) return `permission denied on the Docker daemon for user ${currentUser()}`;
  if (/cannot connect to the docker daemon|is the docker daemon running|error during connect|connection refused|no such host/i.test(stderr)) return 'no Docker daemon is reachable';
  return `docker info failed${Number.isInteger(error?.code) ? ` (exit ${error.code})` : ''}`;
}

function unavailable(reason) {
  return new CiRuntimeError(`${UNAVAILABLE}: Docker is not accessible from this Jenkins execution node (${reason}). ${DOCKER_PREREQUISITE}`);
}

const shortId = (id) => String(id || '').slice(0, 12);

/** First meaningful line of a docker error, credentials in URLs removed. */
function firstLine(text) {
  const line = String(text || '').split('\n').map((item) => item.trim()).find(Boolean) || '';
  return line.replace(/\/\/[^/@\s]+@/g, '//').slice(0, 200);
}

/**
 * Container ids this process may be running in, from the kernel's own records:
 * the identity files a container runtime bind-mounts, and the cgroup path. A
 * host process that merely sees other containers' mounts matches neither.
 */
async function selfContainerSignals({ readFile, exists, hostname }) {
  const ids = [];
  try {
    for (const line of String(await readFile('/proc/self/mountinfo', 'utf8')).split('\n')) {
      const fields = line.split(' ');
      if (!CONTAINER_IDENTITY_MOUNTS.includes(fields[4])) continue;
      const match = /containers\/([0-9a-f]{64})\//.exec(fields[3] || '');
      if (match) ids.push(match[1]);
    }
  } catch { /* not Linux, or no procfs */ }
  try {
    for (const line of String(await readFile('/proc/self/cgroup', 'utf8')).split('\n')) {
      const match = /(?:^|\/)docker[-/]([0-9a-f]{64})/.exec(line);
      if (match) ids.push(match[1]);
    }
  } catch { /* not Linux, or no procfs */ }
  const name = String(hostname() || '').trim();
  return {
    ids: [...new Set(ids)],
    hostname: /^[0-9a-f]{12,64}$/.test(name) ? name : '',
    inContainer: ids.length > 0 || await exists('/.dockerenv')
  };
}

async function inspectContainer(exec, id, timeoutMs) {
  try {
    const { stdout } = await exec('docker', ['inspect', '--type', 'container', id], { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024, windowsHide: true });
    const [info] = JSON.parse(stdout);
    return info && typeof info.Id === 'string' ? info : null;
  } catch { return null; }
}

/** The daemon, and whether this process runs in a container that daemon manages. */
async function detectEnvironment({ exec, readFile, exists, hostname, timeoutMs }) {
  let version = '';
  try {
    const { stdout } = await exec('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true });
    version = String(stdout).trim();
  } catch (error) {
    throw unavailable(dockerFailureReason(error, timeoutMs));
  }
  if (!version) throw unavailable('docker info returned no server version');
  const signals = await selfContainerSignals({ readFile, exists, hostname });
  for (const id of signals.ids) {
    const info = await inspectContainer(exec, id, timeoutMs);
    if (info?.Id === id) return { kind: 'volumes-from', version, containerId: info.Id, mounts: info.Mounts || [] };
  }
  if (signals.hostname) {
    const info = await inspectContainer(exec, signals.hostname, timeoutMs);
    if (info?.Id.startsWith(signals.hostname) && info.Config?.Hostname === signals.hostname) {
      return { kind: 'volumes-from', version, containerId: info.Id, mounts: info.Mounts || [] };
    }
  }
  return { kind: 'host', version, inContainer: signals.inContainer };
}

function isWithin(child, parent) {
  const base = String(parent || '').replace(/\/+$/, '');
  return child === parent || child === base || child.startsWith(`${base}/`);
}

/** How scanner containers reach the workspace, never a guessed host path. */
function workspaceAccess(environment, workspacePath) {
  if (environment.kind !== 'volumes-from') {
    return { mechanism: 'bind mount', root: CONTAINER_SOURCE, args: ['-v', `${workspacePath}:${CONTAINER_SOURCE}:ro`] };
  }
  const covered = environment.mounts.some((mount) => typeof mount?.Destination === 'string' && isWithin(workspacePath, mount.Destination));
  if (!covered) {
    throw new CiRuntimeError(`${UNAVAILABLE}: Jenkins runs in container ${shortId(environment.containerId)} and the workspace ${workspacePath} is in that container's own filesystem, not on a Docker volume or bind mount, so scanner containers cannot read it. One-time Jenkins node prerequisite: keep Jenkins workspaces (JENKINS_HOME or the agent root directory) on a Docker volume or bind mount.`);
  }
  return {
    mechanism: `volumes of Jenkins container ${shortId(environment.containerId)}`,
    root: workspacePath,
    args: ['--volumes-from', `${environment.containerId}:ro`]
  };
}

/** Scanner output as if the workspace had been mounted at /src. */
function mapContainerPaths(value, root) {
  if (!root || root === CONTAINER_SOURCE) return value;
  const base = String(root).replace(/\/+$/, '');
  const prefix = `${base}/`;
  const visit = (item) => {
    if (typeof item === 'string') {
      if (item === base) return CONTAINER_SOURCE;
      return item.startsWith(prefix) ? `${CONTAINER_SOURCE}/${item.slice(prefix.length)}` : item;
    }
    if (Array.isArray(item)) return item.map(visit);
    if (item && typeof item === 'object') return Object.fromEntries(Object.entries(item).map(([key, entry]) => [key, visit(entry)]));
    return item;
  };
  return visit(value);
}

/** Proves that a scanner container sees this workspace through `access`. */
async function probeWorkspace({ exec, access, environment, image, workspacePath, writeFile, remove, timeoutMs }) {
  const token = crypto.randomBytes(16).toString('hex');
  const marker = `.security-center-runtime-probe-${token.slice(0, 12)}`;
  const hostFile = path.join(workspacePath, marker);
  await writeFile(hostFile, token);
  let seen = null;
  let detail = '';
  try {
    const { stdout } = await exec('docker', [
      'run', '--rm', ...SECURITY_ARGS, '--network', 'none', ...access.args,
      '--entrypoint', 'cat', image, `${access.root}/${marker}`
    ], { timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true });
    seen = String(stdout).trim();
  } catch (error) {
    if (error?.killed) {
      throw new CiRuntimeError(`${UNAVAILABLE}: the scanner image ${image} could not be started on this Jenkins execution node within ${Math.round(timeoutMs / 1000)}s (image pull or start timed out).`);
    }
    if (error?.code === 125 && /pull|manifest|unauthorized|denied|toomanyrequests|no such image|not found/i.test(String(error.stderr || ''))) {
      throw new CiRuntimeError(`${UNAVAILABLE}: this Jenkins execution node cannot pull the scanner image ${image} (${firstLine(error.stderr)}). One-time Jenkins node prerequisite: outbound access to the container registry, or the image preloaded on the node.`);
    }
    if (error?.code === 125) detail = ` (docker: ${firstLine(error.stderr)})`;
  } finally {
    await Promise.resolve(remove(hostFile, { force: true })).catch(() => {});
  }
  if (seen === token) return;
  if (environment.kind === 'volumes-from') {
    throw new CiRuntimeError(`${UNAVAILABLE}: scanner containers could not read the workspace ${workspacePath} through the ${access.mechanism}${detail}.`);
  }
  if (environment.inContainer) {
    throw new CiRuntimeError(`${UNAVAILABLE}: Jenkins runs inside a container that the reachable Docker daemon does not manage, and that daemon cannot read the workspace ${workspacePath}${detail}. One-time Jenkins node prerequisite: give the daemon the workspace at the same path (for example the same volume mounted at the same path), or run the build where the daemon manages the Jenkins container.`);
  }
  throw new CiRuntimeError(`${UNAVAILABLE}: the Docker daemon used by this Jenkins execution node cannot read the workspace ${workspacePath}${detail}. The docker CLI must reach the daemon of the machine that holds the workspace.`);
}

/**
 * One runtime per scan. Detection and the workspace probe run once, on the first
 * scanner that needs a container, and every scanner shares the outcome.
 */
function createCiScannerRuntime({
  workspacePath,
  exec = execFileAsync,
  readFile = fs.readFile,
  exists = (file) => fs.access(file).then(() => true, () => false),
  hostname = os.hostname,
  writeFile = fs.writeFile,
  remove = fs.rm,
  log = () => {},
  infoTimeoutMs = 20000,
  probeTimeoutMs = 15 * 60 * 1000
} = {}) {
  let ready = null;
  const started = new Set();

  async function prepare(image) {
    const environment = await detectEnvironment({ exec, readFile, exists, hostname, timeoutMs: infoTimeoutMs });
    const access = workspaceAccess(environment, workspacePath);
    log(`Docker ${environment.version}: scanners run as ephemeral containers, workspace read-only through ${access.mechanism}`);
    await probeWorkspace({ exec, access, environment, image, workspacePath, writeFile, remove, timeoutMs: probeTimeoutMs });
    return access;
  }

  function containerFor(access) {
    return {
      root: access.root,
      exec,
      runArgs(image, command, { workdir = '', volumes = [], env = {} } = {}) {
        const name = `security-center-${crypto.randomBytes(6).toString('hex')}`;
        started.add(name);
        return [
          'run', '--rm', '--name', name, ...SECURITY_ARGS, ...access.args, ...volumes,
          ...(workdir ? ['-w', workdir] : []),
          ...Object.entries(env).flatMap(([key, value]) => ['-e', `${key}=${value}`]),
          image, ...command
        ];
      },
      mapPaths: (payload) => mapContainerPaths(payload, access.root)
    };
  }

  return {
    workspacePath,
    /** The container context for one scanner, once the runtime is proven for this workspace. */
    async forScanner(image) {
      if (!ready) ready = prepare(image);
      return containerFor(await ready);
    },
    /** Removes any scanner container still present (timeout, abort); --rm handles the rest. */
    async cleanup() {
      const names = [...started];
      started.clear();
      await Promise.all(names.map((name) => Promise.resolve()
        .then(() => exec('docker', ['rm', '--force', name], { timeout: 30000, windowsHide: true }))
        .catch(() => {})));
    }
  };
}

module.exports = {
  CONTAINER_SOURCE, RUNTIME_MODES, SECURITY_ARGS, CiRuntimeError,
  scannerRuntimeMode, createCiScannerRuntime, detectEnvironment, workspaceAccess,
  mapContainerPaths, dockerFailureReason
};
