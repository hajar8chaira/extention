'use strict';

/**
 * The lifecycle of the Security Center backend.
 *
 * Before this module the backend was a container the user was expected to start
 * by hand: install Docker, clone the repository, run `docker compose -f
 * docker-compose.backend.yml up -d`. Nothing in that sentence belongs in a
 * Marketplace install, and everything downstream of it — history, trends, the
 * audit journal, Burp ingestion — was offline until the user performed it.
 *
 * The backend is now a service the extension owns. It ships inside the VSIX as
 * JavaScript, it runs on the Node runtime VS Code already provides, and this
 * module is the single place that decides where it is and whether it is up:
 *
 *   AUTO   — the default. Reuse a running backend, otherwise start one, wait
 *            for a real `/health`, and remember it.
 *   REMOTE — a backend an organization operates. Nothing is ever started.
 *   DOCKER — the compose file, kept for development and for reading a history
 *            written by the previous FastAPI backend. Never started either:
 *            the extension reports its state and stays out of its way.
 *
 * Three properties matter more than the routing:
 *
 *   ONE PROCESS. Every entry point goes through one shared promise, so Trends,
 *   Burp and History opening together start one backend, not three.
 *
 *   ONE PORT, HONESTLY RESOLVED. 8765 is a preference, not an assumption. A
 *   port held by another service is detected as such — `/health` has to name
 *   this service — and a free port is used instead.
 *
 *   NO SHARED PROCESS KILLED. The backend outlives the window that started it,
 *   because a second window may be using it. It stops on its own idle timeout.
 */

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const { DEFAULT_PORT, LOOPBACK_HOST, PROTOCOL_VERSION } = require('../backend/contract');
const { readLockFile, removeLockFile, writeDiscoveryFile, registerClient, unregisterClient } = require('../backend/discovery');
const {
  BACKEND_STATE, DEFAULT_BACKEND_URL, normalizeBackendUrl, probeBackend, describeBackend
} = require('./backend-config');

/** How the address of the backend is decided. */
const BACKEND_MODE = Object.freeze({
  AUTO: 'auto',
  REMOTE: 'remote',
  DOCKER: 'docker'
});

const BACKEND_MODE_LABELS = Object.freeze({
  [BACKEND_MODE.AUTO]: 'Auto',
  [BACKEND_MODE.REMOTE]: 'Remote',
  [BACKEND_MODE.DOCKER]: 'Docker (développement)'
});

/** What `resolveBackendMode` turned the mode into, once the environment is known. */
const RESOLVED_MODE = Object.freeze({
  LOCAL: 'local',
  REMOTE: 'remote',
  DOCKER: 'docker'
});

/**
 * Le cycle de vie du PROCESSUS, distinct de ce qu'un sondage a repondu.
 *
 * `BACKEND_STATE` decrit une reponse : ce que `/health` a dit, ou pourquoi il
 * n'a rien dit. Ce n'est pas la meme question que « ou en est le service ». Un
 * backend distant peut etre READY sans qu'aucun processus nous appartienne ; un
 * backend local peut etre STARTING alors qu'aucun sondage n'a encore abouti.
 * Melanger les deux est ce qui produisait des interfaces incapables de dire la
 * difference entre « pas encore demarre » et « en panne ».
 */
const BACKEND_LIFECYCLE = Object.freeze({
  STOPPED: 'stopped',
  STARTING: 'starting',
  READY: 'ready',
  DEGRADED: 'degraded',
  FAILED: 'failed',
  STOPPING: 'stopping'
});

/** Traduit le resultat d'un sondage en position dans le cycle de vie. */
function lifecycleFromState(state) {
  if (state === BACKEND_STATE.ONLINE) return BACKEND_LIFECYCLE.READY;
  if (state === BACKEND_STATE.STARTING) return BACKEND_LIFECYCLE.STARTING;
  if (state === BACKEND_STATE.ERROR) return BACKEND_LIFECYCLE.FAILED;
  // Quelque chose repond, mais pas de facon exploitable : le service existe,
  // il n'est pas utilisable. Ce n'est ni « arrete » ni « en panne de demarrage ».
  if ([BACKEND_STATE.INVALID_RESPONSE, BACKEND_STATE.AUTH_ERROR, BACKEND_STATE.TIMEOUT].includes(state)) {
    return BACKEND_LIFECYCLE.DEGRADED;
  }
  return BACKEND_LIFECYCLE.STOPPED;
}

const MODE_SETTING = 'backend.mode';
const REMOTE_URL_SETTING = 'backend.url';

/** The name of the data directory inside VS Code global storage. */
const DATA_DIRECTORY_NAME = 'backend-data';

/** How long a start is given to answer `/health` before it is called a timeout. */
const START_TIMEOUT_MS = 20000;
const HEALTH_POLL_INTERVAL_MS = 250;

function readSetting(configuration, key, fallback) {
  return typeof configuration?.get === 'function' ? configuration.get(key, fallback) : fallback;
}

/**
 * The configured mode, normalized.
 *
 * An unknown value resolves to AUTO rather than to an error: a settings file
 * with a typo in it must not leave the product without a backend.
 */
function resolveBackendMode(configuration) {
  const raw = String(readSetting(configuration, MODE_SETTING, BACKEND_MODE.AUTO) || '').trim().toLowerCase();
  return Object.values(BACKEND_MODE).includes(raw) ? raw : BACKEND_MODE.AUTO;
}

/** A free TCP port, obtained by binding one and letting the kernel choose. */
function findFreePort({ host = LOOPBACK_HOST } = {}) {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.on('error', reject);
    probe.listen(0, host, () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** Whether a port can be bound right now. Used to tell "free" from "taken by someone else". */
function isPortFree(port, { host = LOOPBACK_HOST } = {}) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.unref();
    probe.once('error', () => resolve(false));
    probe.listen(port, host, () => probe.close(() => resolve(true)));
  });
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

class BackendManager {
  /**
   * @param {object} options
   * @param {string} options.dataDir   Where the backend keeps its data. Outside the extension directory.
   * @param {Function} options.getConfiguration  Returns the VS Code configuration section.
   * @param {string} options.apiKey    Shared with the backend and with Burp; never logged.
   */
  constructor({
    dataDir,
    getConfiguration = () => ({}),
    apiKey = '',
    version = PROTOCOL_VERSION,
    serverPath = path.join(__dirname, '..', 'backend', 'server.js'),
    execPath = process.execPath,
    probe = probeBackend,
    spawnProcess = spawn,
    readLock = readLockFile,
    removeLock = removeLockFile,
    publishDiscovery = writeDiscoveryFile,
    joinClients = registerClient,
    leaveClients = unregisterClient,
    freePort = findFreePort,
    portFree = isPortFree,
    startTimeoutMs = START_TIMEOUT_MS,
    log = () => {}
  } = {}) {
    this.dataDir = dataDir;
    this.getConfiguration = getConfiguration;
    this.apiKey = apiKey;
    this.version = version;
    this.serverPath = serverPath;
    this.execPath = execPath;
    this.probe = probe;
    this.spawnProcess = spawnProcess;
    this.readLock = readLock;
    this.removeLock = removeLock;
    this.publishDiscovery = publishDiscovery;
    this.joinClients = joinClients;
    this.leaveClients = leaveClients;
    this.freePort = freePort;
    this.portFree = portFree;
    this.startTimeoutMs = startTimeoutMs;
    this.log = log;

    /** The single in-flight start. Its existence is the lock. */
    this.startPromise = null;
    /** The child this window started, when it started one. */
    this.child = null;
    /**
     * Vrai seulement si CE processus d'extension a engendre le backend.
     *
     * C'est ce qui autorise a l'arreter en sortant : un backend qu'on a trouve
     * deja demarre appartient a une autre fenetre, et le tuer lui retirerait son
     * historique en pleine session.
     */
    this.ownsProcess = false;
    this.lifecycle = BACKEND_LIFECYCLE.STOPPED;
    this.onLifecycleChange = null;
    this.lastStatus = describeBackend({ state: BACKEND_STATE.NOT_CONFIGURED });
    this.lastResolvedUrl = '';
  }

  /** Publie une transition de cycle de vie. Les repetitions ne sont pas des evenements. */
  setLifecycle(next, detail = '') {
    if (this.lifecycle === next) return next;
    const previous = this.lifecycle;
    this.lifecycle = next;
    this.log(`cycle de vie ${previous} -> ${next}${detail ? ` (${detail})` : ''}`);
    try { this.onLifecycleChange?.(next, previous); } catch { /* un observateur ne casse pas le service */ }
    return next;
  }

  getLifecycle() {
    return this.lifecycle;
  }

  setApiKey(apiKey) {
    this.apiKey = String(apiKey || '');
  }

  mode() {
    return resolveBackendMode(this.getConfiguration());
  }

  resolvedMode() {
    const mode = this.mode();
    if (mode === BACKEND_MODE.REMOTE) return RESOLVED_MODE.REMOTE;
    if (mode === BACKEND_MODE.DOCKER) return RESOLVED_MODE.DOCKER;
    return RESOLVED_MODE.LOCAL;
  }

  /**
   * The address to talk to, without contacting anything.
   *
   * In Remote mode this is the configured URL and nothing else. In Auto mode it
   * is the port a running backend published in its lock file, falling back to
   * the default — which is what makes a moved port invisible to every caller.
   */
  resolveBackendUrl() {
    const configuration = this.getConfiguration();
    if (this.mode() === BACKEND_MODE.REMOTE) {
      try { return normalizeBackendUrl(readSetting(configuration, REMOTE_URL_SETTING, '')); }
      catch { return ''; }
    }
    const lock = this.dataDir ? this.readLock(this.dataDir) : null;
    if (lock && lock.url) {
      try { return normalizeBackendUrl(lock.url); } catch { /* a damaged lock is a missing lock */ }
    }
    // The backend answers `/health` from the moment it binds, but writes its
    // lock a few instructions later. A caller landing in that window must not
    // be told the default port for a service this window just started on
    // another one — the address we last saw answering is the better answer.
    if (this.lastResolvedUrl) return this.lastResolvedUrl;
    // Docker publishes the default port; so does a local backend on a free machine.
    return DEFAULT_BACKEND_URL;
  }

  /** Probes whatever `resolveBackendUrl` names, and starts nothing. */
  async getBackendStatus() {
    const mode = this.mode();
    const url = this.resolveBackendUrl();
    if (!url) {
      return this.remember({
        ...describeBackend({
          state: BACKEND_STATE.NOT_CONFIGURED,
          message: 'Renseignez l’adresse du backend distant.'
        }),
        mode,
        resolvedMode: this.resolvedMode()
      });
    }
    const status = await this.probe(url);
    return this.remember({ ...status, mode, resolvedMode: this.resolvedMode() });
  }

  remember(status) {
    const enriched = Object.freeze({
      ...status,
      modeLabel: BACKEND_MODE_LABELS[status.mode] || status.mode,
      dataDir: this.dataDir || '',
      managed: status.resolvedMode === RESOLVED_MODE.LOCAL
    });
    this.lastStatus = enriched;
    // Le cycle de vie suit ce que le sondage vient d'etablir, sauf pendant un
    // demarrage ou un arret : ces deux phases sont pilotees, pas observees.
    if (![BACKEND_LIFECYCLE.STARTING, BACKEND_LIFECYCLE.STOPPING].includes(this.lifecycle)) {
      this.setLifecycle(lifecycleFromState(enriched.state));
    }
    if (enriched.online && enriched.url) {
      this.lastResolvedUrl = enriched.url;
      this.announce(enriched);
    }
    return enriched;
  }

  /**
   * Publishes the active backend for Burp and any other out-of-process component.
   *
   * Written on every transition to online, including in Remote mode: Burp must
   * follow the backend the extension is actually using, whichever it is.
   */
  announce(status) {
    if (!this.publishDiscovery) return;
    try {
      this.publishDiscovery({
        url: status.url, mode: status.mode, version: status.version || this.version, apiKey: this.apiKey
      });
    } catch (error) {
      this.log(`Backend : publication de l’adresse impossible — ${error.message}`);
    }
  }

  /**
   * THE entry point for every capability that needs the backend.
   *
   * Returns a status, never throws. In Auto mode it starts the backend if it is
   * not answering; in Remote and Docker mode it reports what it finds, because
   * starting someone else's service is not this extension's decision.
   */
  async ensureBackend() {
    const status = await this.getBackendStatus();
    if (status.online) return status;
    if (this.resolvedMode() !== RESOLVED_MODE.LOCAL) return status;
    if (status.state === BACKEND_STATE.AUTH_ERROR) return status;
    return this.startLocalBackend();
  }

  /**
   * Starts the local backend, once.
   *
   * Concurrent callers share the same promise: three panels opening at the same
   * moment produce one process. The promise is cleared when it settles, so a
   * later call can start a backend that has since stopped.
   */
  startLocalBackend() {
    if (this.startPromise) return this.startPromise;
    this.startPromise = this.performStart().finally(() => { this.startPromise = null; });
    return this.startPromise;
  }

  /** Le journal du service, dans le repertoire de donnees. Consultable par l'utilisateur. */
  logFilePath() {
    return this.dataDir ? path.join(this.dataDir, 'backend.log') : '';
  }

  /** Les dernieres lignes du journal, pour expliquer un demarrage qui a echoue. */
  readLogTail(lines_count = 12) {
    try {
      const text = fs.readFileSync(this.logFilePath(), 'utf8').trim();
      return text.split(/\r?\n/).slice(-lines_count).join('\n');
    } catch { return ''; }
  }

  async performStart() {
    this.setLifecycle(BACKEND_LIFECYCLE.STARTING);
    if (!this.dataDir) {
      return this.remember({
        ...describeBackend({ state: BACKEND_STATE.ERROR, message: 'Aucun emplacement de données n’est disponible.' }),
        mode: this.mode(), resolvedMode: this.resolvedMode()
      });
    }

    // Someone else may have started it between the probe and here.
    const running = await this.probeRunningBackend();
    if (running) return running;

    let port;
    try {
      port = await this.choosePort();
    } catch (error) {
      return this.failed(BACKEND_STATE.ERROR, `Aucun port disponible — ${error.message}`);
    }

    try {
      fs.mkdirSync(this.dataDir, { recursive: true });
    } catch (error) {
      return this.failed(BACKEND_STATE.ERROR, `Emplacement de données inaccessible — ${error.message}`);
    }

    // Ouvert en ajout : le journal d'un demarrage precedent reste lisible.
    let logFd = 'ignore';
    try { logFd = fs.openSync(this.logFilePath(), 'a'); } catch { logFd = 'ignore'; }

    let child;
    try {
      child = this.spawnProcess(this.execPath, [
        this.serverPath, '--port', String(port), '--data-dir', this.dataDir
      ], {
        // ELECTRON_RUN_AS_NODE turns the editor's own binary into the Node that
        // runs the service. It is why no Python, no Docker and no downloaded
        // executable is involved anywhere in this path.
        env: {
          ...process.env,
          ELECTRON_RUN_AS_NODE: '1',
          SECURITY_CENTER_API_KEY: this.apiKey,
          SECURITY_CENTER_VERSION: this.version
        },
        // Detached: the backend belongs to the machine, not to this window. A
        // second window closing must not take the history offline for the first.
        detached: true,
        // La sortie va dans un fichier, pas dans des tubes. Un processus detache
        // survit a la fenetre qui l'a lance : des tubes fermes par le depart du
        // parent le tueraient a la premiere ecriture, et le journal serait perdu
        // au moment ou l'on en a le plus besoin.
        stdio: ['ignore', logFd, logFd],
        windowsHide: true
      });
    } catch (error) {
      if (logFd !== 'ignore') { try { fs.closeSync(logFd); } catch { /* deja ferme */ } }
      return this.failed(BACKEND_STATE.ERROR, `Démarrage impossible — ${error.message}`);
    }
    if (logFd !== 'ignore') { try { fs.closeSync(logFd); } catch { /* le fils garde sa copie */ } }

    this.child = child;
    // Cette fenetre devient cliente du service : le registre decidera plus tard
    // qui a le droit de l'arreter.
    try { this.joinClients(this.dataDir); } catch { /* un registre absent n'empeche pas de servir */ }
    // Le backend engendre ici nous appartient : c'est ce qui autorisera a
    // l'arreter en quittant, et seulement celui-la.
    this.ownsProcess = true;
    let spawnError = '';
    child.on('error', (error) => { spawnError = spawnError || String(error.message || error); });
    // Un processus qui meurt sans qu'on le lui ait demande est un incident, pas
    // un etat stable : on le constate au lieu de continuer a annoncer READY.
    child.on('exit', (code, signal) => {
      if (this.child !== child) return;
      this.child = null;
      this.ownsProcess = false;
      if (this.lifecycle === BACKEND_LIFECYCLE.STOPPING) return;
      this.setLifecycle(BACKEND_LIFECYCLE.STOPPED, `processus termine (code ${code}, signal ${signal || 'aucun'})`);
    });
    if (typeof child.unref === 'function') child.unref();

    const url = `http://${LOOPBACK_HOST}:${port}`;
    const status = await this.waitForHealth(url);
    if (status.online) {
      this.setLifecycle(BACKEND_LIFECYCLE.READY, url);
      this.log(`Backend local démarré sur ${url}.`);
      return this.remember({ ...status, mode: this.mode(), resolvedMode: RESOLVED_MODE.LOCAL });
    }
    // Le service n'est pas venu. Ce que le processus a ecrit dans son journal est
    // la seule chose utile ici : elle voyage au lieu d'etre avalee.
    const detail = spawnError.trim() || this.readLogTail(6) || status.message;
    return this.failed(status.state, detail || 'Le backend local n’a pas répondu.');
  }

  /** Reuses a backend that is already answering, whether this window started it or not. */
  async probeRunningBackend() {
    const url = this.resolveBackendUrl();
    if (!url) return null;
    const status = await this.probe(url);
    if (!status.online) return null;
    return this.remember({ ...status, mode: this.mode(), resolvedMode: this.resolvedMode() });
  }

  /**
   * The port to start on.
   *
   * The default is preferred, so the address stays predictable. It is abandoned
   * only when something else holds it — at which point insisting would produce
   * `EADDRINUSE` and a backend that never starts.
   */
  async choosePort() {
    const lock = this.readLock(this.dataDir);
    if (lock && lock.port && await this.portFree(lock.port)) return lock.port;
    if (await this.portFree(DEFAULT_PORT)) return DEFAULT_PORT;
    this.log(`Port ${DEFAULT_PORT} occupé par un autre service : un port libre est choisi.`);
    return this.freePort();
  }

  /** Polls `/health` until the service names itself, or the start is declared failed. */
  async waitForHealth(url, { timeoutMs = this.startTimeoutMs } = {}) {
    const deadline = Date.now() + timeoutMs;
    let last = describeBackend({ state: BACKEND_STATE.TIMEOUT, url });
    while (Date.now() < deadline) {
      last = await this.probe(url);
      if (last.online) return last;
      if (last.state === BACKEND_STATE.INVALID_RESPONSE || last.state === BACKEND_STATE.AUTH_ERROR) return last;
      await delay(HEALTH_POLL_INTERVAL_MS);
    }
    return describeBackend({
      state: BACKEND_STATE.TIMEOUT, url,
      message: `Le backend local n’a pas répondu en ${Math.round(timeoutMs / 1000)} s.`
    });
  }

  failed(state, message) {
    // Un demarrage qui n'aboutit pas quitte STARTING : sans cela `remember`
    // laisserait le cycle de vie bloque sur « en cours » indefiniment.
    this.setLifecycle(lifecycleFromState(state) === BACKEND_LIFECYCLE.STOPPED
      ? BACKEND_LIFECYCLE.FAILED
      : lifecycleFromState(state), message);
    const status = this.remember({
      ...describeBackend({ state, url: this.resolveBackendUrl(), message }),
      mode: this.mode(),
      resolvedMode: this.resolvedMode()
    });
    this.log(`Backend : ${message}`);
    return status;
  }

  /**
   * Stops the local backend.
   *
   * Only ever the process named by the lock file, and only in local mode: a
   * remote backend is not ours to stop, and a Docker backend belongs to the
   * compose file that started it.
   */
  async stopLocalBackend() {
    if (this.resolvedMode() !== RESOLVED_MODE.LOCAL || !this.dataDir) return false;
    const lock = this.readLock(this.dataDir);
    const pid = lock ? Number(lock.pid) : Number(this.child && this.child.pid);
    if (!Number.isInteger(pid) || pid <= 0) return false;
    this.setLifecycle(BACKEND_LIFECYCLE.STOPPING);
    try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    this.removeLock(this.dataDir);
    this.child = null;
    this.ownsProcess = false;
    // The address is no longer ours to hand out: the next resolution starts
    // from the lock, or from the default, not from a service we just stopped.
    this.lastResolvedUrl = '';
    this.lastStatus = describeBackend({ state: BACKEND_STATE.OFFLINE, url: this.resolveBackendUrl() });
    this.setLifecycle(BACKEND_LIFECYCLE.STOPPED);
    return true;
  }

  /** Stop, then start. The address may change if the old port was taken meanwhile. */
  async restartLocalBackend() {
    await this.stopLocalBackend();
    // A listening socket is not released the instant the process is signalled.
    await delay(HEALTH_POLL_INTERVAL_MS);
    return this.startLocalBackend();
  }

  /**
   * What VS Code shutting down does: nothing to the process.
   *
   * Another window may be using it, and the backend stops itself after its idle
   * timeout. Killing a shared service because one of its clients closed is how
   * the second window loses its history mid-scan.
   */
  /**
   * Le depart de cette fenetre.
   *
   * On se retire du registre, et on n'arrete le service que si deux conditions
   * sont reunies : il nous appartient, et plus aucune autre fenetre ne s'est
   * declaree. Sans cela, fermer une fenetre couperait l'historique d'une autre
   * en pleine session. Si des fenetres restent, le service leur survit, et son
   * minuteur d'inactivite le fermera quand plus personne ne s'en servira.
   */
  dispose() {
    this.startPromise = null;
    let remaining = [];
    if (this.dataDir) {
      try { remaining = this.leaveClients(this.dataDir) || []; } catch { remaining = []; }
    }
    const shouldStop = this.ownsProcess && this.child && remaining.length === 0;
    if (shouldStop) {
      this.setLifecycle(BACKEND_LIFECYCLE.STOPPING, 'derniere fenetre');
      try { process.kill(this.child.pid, 'SIGTERM'); } catch { /* deja parti */ }
      if (this.dataDir) this.removeLock(this.dataDir);
      this.setLifecycle(BACKEND_LIFECYCLE.STOPPED);
    }
    this.ownsProcess = false;
    this.child = null;
    return shouldStop;
  }
}

/**
 * Le vocabulaire que le dashboard affiche, deduit de l'etat reel du backend.
 *
 * Le badge annoncait « online » des que l'appel reseau du demarrage aboutissait,
 * et « unknown » quand il echouait — c'est-a-dire qu'il decrivait le sort d'une
 * requete, pas l'etat du service. Un backend distant joignable etait annonce
 * « online » comme un service local, et un demarrage en cours etait indiscernable
 * d'une extension qui n'avait jamais rien tente.
 *
 * `unknown` reste possible, mais uniquement avant la premiere resolution : c'est
 * l'etat de l'interface qui n'a pas encore interroge le gestionnaire, jamais une
 * reponse a une question posee.
 */
const DASHBOARD_BACKEND_STATUS = Object.freeze({
  UNKNOWN: 'unknown',
  STARTING: 'starting',
  ONLINE: 'online',
  REMOTE: 'remote',
  OFFLINE: 'offline',
  ERROR: 'error'
});

function dashboardBackendStatus(status) {
  if (!status || !status.state) return DASHBOARD_BACKEND_STATUS.UNKNOWN;
  if (status.state === BACKEND_STATE.STARTING) return DASHBOARD_BACKEND_STATUS.STARTING;
  if (status.state === BACKEND_STATE.ONLINE) {
    // Un backend distant est en ligne, mais ce n'est pas le meme fait : il n'est
    // ni demarre ni arretable ici, et l'interface doit le dire.
    return status.resolvedMode === RESOLVED_MODE.REMOTE
      ? DASHBOARD_BACKEND_STATUS.REMOTE
      : DASHBOARD_BACKEND_STATUS.ONLINE;
  }
  if ([BACKEND_STATE.ERROR, BACKEND_STATE.INVALID_RESPONSE, BACKEND_STATE.AUTH_ERROR].includes(status.state)) {
    return DASHBOARD_BACKEND_STATUS.ERROR;
  }
  // OFFLINE, TIMEOUT, NOT_CONFIGURED : rien ne repond a l'adresse resolue.
  return DASHBOARD_BACKEND_STATUS.OFFLINE;
}

/** The data directory: inside global storage, which survives extension updates. */
function resolveDataDirectory(context) {
  const root = context?.globalStorageUri?.fsPath;
  return root ? path.join(root, DATA_DIRECTORY_NAME) : '';
}

/** A key for this installation. Generated once, kept in SecretStorage, never logged. */
function generateLocalApiKey() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  BACKEND_MODE, BACKEND_MODE_LABELS, RESOLVED_MODE, DASHBOARD_BACKEND_STATUS, dashboardBackendStatus, MODE_SETTING, REMOTE_URL_SETTING,
  DATA_DIRECTORY_NAME, START_TIMEOUT_MS,
  BackendManager, resolveBackendMode, resolveDataDirectory, generateLocalApiKey,
  BACKEND_LIFECYCLE, lifecycleFromState,
  findFreePort, isPortFree
};
