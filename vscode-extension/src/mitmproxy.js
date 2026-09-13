'use strict';

/**
 * mitmproxy — capture HTTP managée et headless.
 *
 * Burp reste le connecteur de ceux qui utilisent déjà Burp : il faut lancer Burp,
 * y charger le JAR, et c'est Burp qui pousse vers Security Center. mitmproxy
 * couvre l'autre besoin — capturer du trafic sans rien installer soi-même ni
 * ouvrir d'interface. Security Center installe le paquet officiel, démarre
 * `mitmdump` en arrière-plan sur un port libre, et son addon dépose chaque
 * échange sur le backend local.
 *
 * L'installation reprend le contrat déjà validé de Semgrep : environnement
 * Python isolé dans le stockage de l'extension, paquet officiel depuis PyPI,
 * rien hors de ce dossier, PATH du système jamais modifié.
 */

const fs = require('fs/promises');
const net = require('net');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

/** Le paquet officiel, publié par le projet mitmproxy sous licence MIT. */
const PACKAGE = 'mitmproxy';
const PYPI_METADATA = 'https://pypi.org/pypi/mitmproxy/json';

/**
 * États exposés à l'interface.
 *
 * `READY` et `CAPTURING` sont deux choses différentes : un proxy démarré que
 * personne ne traverse ne capture rien, et l'annoncer comme actif serait faux.
 */
const MITM_STATE = Object.freeze({
  NOT_INSTALLED: 'NOT_INSTALLED',
  READY: 'READY',
  STARTING: 'STARTING',
  CAPTURING: 'CAPTURING',
  STOPPED: 'STOPPED',
  FAILED: 'FAILED'
});

/**
 * Interception HTTPS : trois états, jamais confondus avec « le proxy tourne ».
 *
 * Le HTTP simple fonctionne dès le démarrage. Le HTTPS exige que le client fasse
 * confiance à l'autorité de certification que mitmproxy génère — sans cela le
 * client refuse la connexion, ce qui est le comportement correct.
 */
const HTTPS_STATE = Object.freeze({
  UNAVAILABLE: 'UNAVAILABLE',
  CERTIFICATE_REQUIRED: 'CERTIFICATE_REQUIRED',
  CERTIFICATE_GENERATED: 'CERTIFICATE_GENERATED'
});

/** Racine managée de l'outil, dans le stockage privé de l'extension. */
function mitmRoot(storagePath) {
  return path.join(storagePath, 'scanner-tools', 'mitmproxy');
}

function venvDirectory(storagePath) {
  return path.join(mitmRoot(storagePath), 'venv');
}

/** Répertoire de configuration de mitmproxy, y compris son autorité de certification. */
function confDirectory(storagePath) {
  return path.join(mitmRoot(storagePath), 'conf');
}

function managedExecutable(storagePath, command = 'mitmdump') {
  const binary = process.platform === 'win32' ? `${command}.exe` : command;
  return path.join(venvDirectory(storagePath), process.platform === 'win32' ? 'Scripts' : 'bin', binary);
}

function provenancePath(storagePath) {
  return path.join(mitmRoot(storagePath), 'provenance.json');
}

/** Le fichier d'autorité que le client doit approuver pour l'interception HTTPS. */
function certificateAuthorityPath(storagePath) {
  return path.join(confDirectory(storagePath), 'mitmproxy-ca-cert.cer');
}

async function exists(file) {
  try { await fs.access(file); return true; } catch { return false; }
}

/**
 * Version réellement installée, chaîne vide si l'outil ne répond pas.
 *
 * `mitmdump --version` écrit « Mitmproxy: 12.2.3 » suivi des versions de Python
 * et d'OpenSSL ; seule la première ligne nous concerne.
 */
async function installedVersion(executable, timeout = 30000) {
  try {
    const { stdout, stderr } = await execFileAsync(executable, ['--version'], { windowsHide: true, timeout, maxBuffer: 2 * 1024 * 1024 });
    const output = String(stdout || stderr);
    return output.match(/Mitmproxy:\s*([0-9][\w.]*)/i)?.[1] || '';
  } catch {
    return '';
  }
}

/** État d'installation, tel que la page le rend. */
async function detect(storagePath) {
  const executable = managedExecutable(storagePath);
  if (!await exists(executable)) return { installed: false, state: MITM_STATE.NOT_INSTALLED, executable: '', version: '' };
  const version = await installedVersion(executable);
  if (!version) return { installed: false, state: MITM_STATE.FAILED, executable, version: '' };
  return { installed: true, state: MITM_STATE.READY, executable, version };
}

/** Dernière version publiée sur PyPI, pour information. Jamais bloquante. */
async function latestPublishedVersion(downloadText) {
  try {
    const metadata = JSON.parse(await downloadText(PYPI_METADATA));
    return String(metadata?.info?.version || '');
  } catch {
    return '';
  }
}

/**
 * Installe mitmproxy dans un environnement Python isolé.
 *
 * pip vérifie lui-même l'empreinte de chaque artefact publié sur PyPI ; rien
 * n'est téléchargé d'ailleurs, et `--only-binary` évite d'exécuter le code de
 * construction d'un paquet source.
 */
async function install(storagePath, { onProgress = () => {}, signal, python = '' } = {}) {
  const interpreter = python || await findPython();
  if (!interpreter) {
    throw new Error('Python 3.12 ou plus récent est requis pour mitmproxy. Installez Python, puis relancez l’installation.');
  }
  const root = mitmRoot(storagePath);
  const venv = venvDirectory(storagePath);
  await fs.mkdir(root, { recursive: true });

  onProgress({ phase: 'prepare', message: 'Création de l’environnement Python isolé' });
  await run(interpreter, ['-m', 'venv', venv], { signal, timeout: 180000 });

  const venvPython = path.join(venv, process.platform === 'win32' ? 'Scripts' : 'bin', process.platform === 'win32' ? 'python.exe' : 'python');
  onProgress({ phase: 'install', message: `Installation de ${PACKAGE} depuis PyPI` });
  await run(venvPython, ['-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary', ':all:', PACKAGE], { signal, timeout: 900000 });

  const executable = managedExecutable(storagePath);
  if (!await exists(executable)) throw new Error('mitmproxy installé, mais mitmdump est introuvable dans l’environnement.');
  const version = await installedVersion(executable);
  if (!version) throw new Error('mitmproxy installé, mais « mitmdump --version » n’a rien renvoyé.');

  await fs.writeFile(provenancePath(storagePath), JSON.stringify({
    source: 'https://pypi.org/project/mitmproxy/',
    package: PACKAGE,
    version,
    license: 'MIT',
    python: interpreter,
    installedAt: new Date().toISOString()
  }, null, 2), 'utf8');

  onProgress({ phase: 'ready', message: `mitmproxy ${version} installé` });
  return { installed: true, state: MITM_STATE.READY, executable, version };
}

async function findPython() {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  for (const candidate of ['python', 'python3']) {
    try {
      const { stdout } = await execFileAsync(detector, [candidate], { windowsHide: true, timeout: 10000 });
      const found = stdout.trim().split(/\r?\n/)[0];
      if (found) return found;
    } catch { /* candidat suivant */ }
  }
  return '';
}

function run(executable, args, { signal, timeout }) {
  return execFileAsync(executable, args, { windowsHide: true, timeout, maxBuffer: 16 * 1024 * 1024, signal })
    .catch((error) => {
      if (signal?.aborted || error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
        throw Object.assign(new Error('Installation mitmproxy annulée.'), { cancelled: true });
      }
      const detail = String(error.stderr || error.message || '').trim().split(/\r?\n/).slice(-2).join(' ');
      throw new Error(detail || 'Installation mitmproxy impossible.');
    });
}

/**
 * Un port libre, relâché juste avant d'être annoncé.
 *
 * Le proxy n'est jamais épinglé sur 8080 : ce port est fréquemment occupé, et
 * un démarrage qui échoue pour cette raison n'est pas un défaut de l'outil.
 */
function freeLocalPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** Le port accepte-t-il une connexion ? C'est la seule preuve que le proxy écoute. */
function portAccepts(port, host = '127.0.0.1', timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (value) => { socket.destroy(); resolve(value); };
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
    socket.setTimeout(timeoutMs, () => done(false));
  });
}

/** Arguments de `mitmdump`. Aucune interface, aucun fichier hors du stockage. */
function mitmdumpArgs({ port, addon, confdir, host = '127.0.0.1' }) {
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`Port mitmproxy invalide : ${port}.`);
  if (!addon) throw new Error('L’addon Security Center est introuvable.');
  return [
    '--listen-host', host,
    '--listen-port', String(port),
    '-s', addon,
    '--set', `confdir=${confdir}`,
    // Sans cela mitmdump imprime chaque échange sur sa sortie : du trafic
    // complet, en clair, dans un journal que personne n'a demandé.
    '-q'
  ];
}

/**
 * Démarre le proxy et rend son adresse réelle.
 *
 * La promesse n'est tenue que lorsque le port accepte vraiment une connexion :
 * annoncer « prêt » sur la seule création du processus laisserait l'utilisateur
 * configurer un proxy qui n'écoute pas encore.
 */
async function startCapture(storagePath, {
  ingestUrl,
  apiKey = '',
  addonPath,
  host = '127.0.0.1',
  port = 0,
  maxBodyBytes = 65536,
  readyTimeoutMs = 30000,
  onExit = () => {},
  onLog = () => {},
  // Une détection que l'appelant vient de faire. Sans elle, chaque démarrage
  // relançait `mitmdump --version` une seconde fois — un démarrage de Python
  // de plus, inspecté par l'antivirus, pour une réponse déjà connue.
  detected: known = null
} = {}) {
  const detected = known?.installed && known.executable ? known : await detect(storagePath);
  if (!detected.installed) throw new Error('mitmproxy n’est pas installé.');
  if (!ingestUrl) throw new Error('L’adresse d’ingestion Security Center est requise.');
  if (!await exists(addonPath)) throw new Error(`L’addon Security Center est introuvable : ${addonPath}`);

  const confdir = confDirectory(storagePath);
  await fs.mkdir(confdir, { recursive: true });
  const listenPort = port > 0 ? port : await freeLocalPort();

  const child = spawn(detected.executable, mitmdumpArgs({ port: listenPort, addon: addonPath, confdir, host }), {
    windowsHide: true,
    env: {
      ...process.env,
      SECURITY_CENTER_INGEST_URL: ingestUrl,
      // La clé passe par l'environnement, jamais par la ligne de commande : les
      // arguments d'un processus sont lisibles par n'importe quel utilisateur
      // de la machine.
      SECURITY_CENTER_API_KEY: apiKey,
      SECURITY_CENTER_MAX_BODY: String(maxBodyBytes)
    }
  });

  let output = '';
  const capture = (chunk) => {
    const text = chunk.toString('utf8');
    output += text;
    onLog(text);
  };
  child.stdout?.on('data', capture);
  child.stderr?.on('data', capture);

  let exited = false;
  let exitError = '';
  child.on('exit', (code) => {
    exited = true;
    if (code !== 0) exitError = lastMeaningfulLine(output);
    onExit({ code, output });
  });
  child.on('error', (error) => { exited = true; exitError = error.message; });

  const deadline = Date.now() + readyTimeoutMs;
  while (Date.now() < deadline) {
    if (exited) {
      throw new Error(exitError
        ? `mitmdump s’est arrêté au démarrage : ${exitError}`
        : 'mitmdump s’est arrêté au démarrage.');
    }
    if (await portAccepts(listenPort, host)) {
      return {
        state: MITM_STATE.READY,
        pid: child.pid,
        host,
        port: listenPort,
        proxyUrl: `http://${host}:${listenPort}`,
        certificateAuthority: certificateAuthorityPath(storagePath),
        version: detected.version,
        startedAt: new Date().toISOString(),
        process: child
      };
    }
    await delay(250);
  }
  child.kill();
  throw new Error(`mitmdump n’a pas ouvert le port ${listenPort} en ${Math.round(readyTimeoutMs / 1000)} secondes.`);
}

function lastMeaningfulLine(output) {
  return String(output || '').split(/\r?\n/).map((line) => line.trim())
    .filter(Boolean).slice(-1)[0] || '';
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Arrête le proxy et attend que le port soit réellement rendu.
 *
 * Un processus tué n'est pas un port libéré : sans cette attente, un redémarrage
 * immédiat pouvait échouer sur un port encore occupé par le précédent.
 */
async function stopCapture(session, { timeoutMs = 10000 } = {}) {
  const child = session?.process;
  // Un processus tué par un signal garde `exitCode === null` et renseigne
  // `signalCode` : ne regarder que le premier faisait attendre le délai complet
  // puis déclarer l'arrêt manqué, alors que le proxy était bel et bien terminé.
  const finished = () => Boolean(child) && (child.exitCode !== null || child.signalCode !== null);
  if (!child || finished()) return { stopped: true, port: session?.port || 0 };
  child.kill();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (finished() && !await portAccepts(session.port, session.host || '127.0.0.1')) {
      return { stopped: true, port: session.port };
    }
    await delay(200);
  }
  // Dernier recours seulement : la terminaison douce a eu tout le temps voulu.
  try { child.kill('SIGKILL'); } catch { /* déjà mort */ }
  return { stopped: finished(), port: session.port };
}

/**
 * État de l'interception HTTPS, lu sur le disque et jamais supposé.
 *
 * Tant que le client n'a pas approuvé l'autorité, le HTTPS échoue côté client —
 * et c'est le comportement attendu. Le HTTP, lui, fonctionne sans rien.
 */
async function httpsState(storagePath) {
  const authority = certificateAuthorityPath(storagePath);
  if (!await exists(authority)) {
    return { state: HTTPS_STATE.CERTIFICATE_REQUIRED, certificateAuthority: '', available: false };
  }
  return { state: HTTPS_STATE.CERTIFICATE_GENERATED, certificateAuthority: authority, available: true };
}

// ------------------------------------------------------ navigateur de capture
//
// Un navigateur de capture n'appartient qu'à une capture. Chromium ne garde
// qu'une instance par répertoire de profil : lancé à nouveau sur le même profil,
// il transmet l'URL à l'instance déjà ouverte et ignore le nouveau
// `--proxy-server`. Avec un profil unique partagé, une deuxième capture — donc un
// nouveau port — envoyait son trafic vers le proxy de la précédente, déjà mort.
// D'où un profil par capture, et un navigateur fermé quand sa capture s'arrête.

/** Racine des profils de capture, dans le stockage managé de l'extension. */
function captureProfilesRoot(storagePath) {
  return path.join(mitmRoot(storagePath), 'capture-profiles');
}

/** Le profil d'une capture précise. L'identifiant est réduit à un nom de dossier sûr. */
function captureProfileDirectory(storagePath, captureId) {
  const safe = String(captureId || '').replace(/[^A-Za-z0-9_.-]/g, '-').replace(/^[.-]+/, '').slice(0, 96);
  if (!safe) throw new Error('Identifiant de capture invalide.');
  return path.join(captureProfilesRoot(storagePath), safe);
}

/**
 * Si un dossier est un profil de capture managé, et rien d'autre.
 *
 * C'est le garde-fou de toute suppression : seul un enfant direct de la racine
 * des profils de capture peut être effacé — jamais un profil de navigateur de
 * l'utilisateur, jamais la racine elle-même.
 */
function isManagedCaptureProfile(storagePath, directory) {
  if (!directory) return false;
  const comparable = (value) => {
    const resolved = path.resolve(value);
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  };
  const root = comparable(captureProfilesRoot(storagePath));
  const target = comparable(directory);
  return target !== root && path.dirname(target) === root;
}

/**
 * Arguments du navigateur de capture.
 *
 * - `--proxy-bypass-list=<-loopback>` : sans lui, Chromium ne fait jamais passer
 *   127.0.0.1 ni localhost par un proxy, et une cible locale n'était pas capturée.
 * - La cible n'est transmise que si c'est une vraie URL HTTP(S) : une valeur de
 *   réglage commençant par `--` serait sinon lue comme une option du navigateur.
 */
function captureBrowserArgs({ proxyUrl, profile, target = '' }) {
  if (!/^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}$/.test(String(proxyUrl || ''))) {
    throw new Error(`Adresse de proxy de capture invalide : ${proxyUrl}.`);
  }
  if (!profile) throw new Error('Profil de capture requis.');
  let url = '';
  try {
    const parsed = new URL(String(target || ''));
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') url = parsed.toString();
  } catch { /* cible absente ou invalide : le navigateur s'ouvre sans page */ }
  return [
    `--proxy-server=${proxyUrl}`,
    '--proxy-bypass-list=<-loopback>',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    ...(url ? [url] : [])
  ];
}

/**
 * Ferme le navigateur de capture que Security Center a lancé — et lui seul.
 *
 * Trois garde-fous :
 * - seul le processus lancé par l'extension est visé, jamais un nom d'image :
 *   le navigateur habituel de l'utilisateur n'est pas un descendant de ce
 *   processus, puisque son profil est différent ;
 * - un processus dont la sortie a déjà été observée n'est pas visé : son PID
 *   pourrait avoir été réattribué à un tout autre programme ;
 * - `taskkill` est appelé par son chemin système absolu, jamais via le PATH.
 */
async function closeCaptureBrowser(browser, {
  run = execFileAsync,
  platform = process.platform,
  timeoutMs = 5000
} = {}) {
  const child = browser?.process;
  if (!child || !Number.isInteger(child.pid)) return { closed: false, reason: 'aucun navigateur suivi' };
  if (browser.exited || child.exitCode !== null || child.signalCode !== null) {
    return { closed: true, reason: 'déjà fermé' };
  }
  try {
    if (platform === 'win32') {
      const taskkill = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe');
      // `/T` ferme l'arbre du processus lancé — ses rendus et son GPU —, et rien d'autre.
      await run(taskkill, ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: timeoutMs });
    } else {
      child.kill();
    }
    return { closed: true, reason: 'fermé' };
  } catch (error) {
    // `taskkill` échoue aussi quand le processus vient de se terminer seul.
    if (child.exitCode !== null || child.signalCode !== null) return { closed: true, reason: 'déjà fermé' };
    return { closed: false, reason: String(error?.message || error) };
  }
}

/** Efface le profil d'une capture terminée, si et seulement si c'est un profil managé. */
async function removeCaptureProfile(storagePath, directory) {
  if (!isManagedCaptureProfile(storagePath, directory)) return false;
  // Le navigateur peut tenir quelques fichiers un instant après sa fermeture.
  await fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 400 });
  return true;
}

module.exports = {
  PACKAGE,
  PYPI_METADATA,
  captureProfilesRoot,
  captureProfileDirectory,
  isManagedCaptureProfile,
  captureBrowserArgs,
  closeCaptureBrowser,
  removeCaptureProfile,
  MITM_STATE,
  HTTPS_STATE,
  mitmRoot,
  venvDirectory,
  confDirectory,
  managedExecutable,
  provenancePath,
  certificateAuthorityPath,
  installedVersion,
  detect,
  latestPublishedVersion,
  install,
  findPython,
  freeLocalPort,
  portAccepts,
  mitmdumpArgs,
  startCapture,
  stopCapture,
  httpsState
};
