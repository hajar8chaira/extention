const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { spawn } = require('child_process');
const { prepareZapBrowserIsolation, cleanupZapBrowserIsolation, sweepStaleZapRuns } = require('./zap-browser-isolation');

const DEFAULT_WINDOWS_HOME = 'C:\\Program Files\\ZAP\\Zed Attack Proxy';

/**
 * Les délais d'un scan ZAP local, une étape à la fois.
 *
 * Le scan héritait du délai générique des scanners — `securityCenter.scan.timeoutSeconds`,
 * 300 s — qui est taillé pour Semgrep ou Trivy : des analyses locales qui lisent
 * des fichiers. ZAP, lui, démarre une JVM, attend son API, puis parcourt une
 * application par le réseau. Sur une cible de LAN, les 300 s sont consommés
 * avant que le spider ait fini, et l'échec ne dit rien de l'application : il dit
 * seulement que le budget d'un autre outil s'est écoulé.
 *
 * Chaque étape reçoit donc le sien, mesuré sur ce qu'elle fait réellement, et
 * aucune n'est illimitée. `STALL_MS` est l'autre moitié de la réponse : une
 * étape qui progresse ne doit pas mourir sur son plafond, et une étape qui
 * n'avance plus ne doit pas occuper le plafond entier. C'est l'absence de
 * progression, pas la durée, qui caractérise un scan bloqué.
 */
const ZAP_LOCAL_TIMEOUTS = Object.freeze({
  /** Démarrage de la JVM, puis première réponse de l'API ZAP. */
  DAEMON_START_MS: 180000,
  /** Un appel d'API unitaire. */
  API_CALL_MS: 10000,
  /** Parcours de l'application. La plus longue étape d'un baseline. */
  SPIDER_MS: 900000,
  /** Vidage de la file d'analyse passive, une fois le parcours terminé. */
  PASSIVE_DRAIN_MS: 600000,
  /** Scan actif, seulement quand il est demandé. */
  ACTIVE_SCAN_MS: 1800000,
  /** Import d'une spécification OpenAPI. */
  OPENAPI_IMPORT_MS: 300000,
  /** Sans progression réelle pendant ce temps, l'étape est déclarée bloquée. */
  STALL_MS: 300000,
  /** Arrêt propre du démon avant de tuer le processus. */
  SHUTDOWN_MS: 15000,
  /** Délai laissé au processus pour sortir de lui-même après l'arrêt demandé. */
  SHUTDOWN_GRACE_MS: 5000
});

/** Le budget total d'un scan ZAP, celui que l'appelant doit accorder au moteur. */
const ZAP_SCAN_TIMEOUT_MS = 45 * 60 * 1000;

/**
 * La concurrence du scan actif, bornée.
 *
 * ZAP fixe par défaut ses fils par hôte au double des cœurs : 64 sur un poste à
 * 32 fils. La règle DOM XSS ouvre un navigateur piloté par fil. Mesuré sur
 * http://192.168.222.132:3000, cela a donné 64 geckodriver et 620 processus
 * Firefox, 29,9 Go en cinquante secondes : la mémoire du poste s'est épuisée et
 * la JVM de ZAP est morte vers 38 %. Huit fils gardent un scan actif parallèle
 * sans faire dépendre sa survie du nombre de cœurs de la machine.
 */
const ZAP_ACTIVE_SCAN_THREADS_PER_HOST = 8;

/**
 * Les pannes de démarrage que le produit sait nommer.
 *
 * Elles existent parce qu'« en attente de l'API ZAP » pendant trois minutes ne
 * décrit aucune de ces trois situations, et qu'aucune n'a le même remède.
 */
const ZAP_START_ERROR = Object.freeze({
  /** Le processus a démarré puis s'est arrêté avant d'ouvrir son API. */
  ZAP_PROCESS_EXITED: 'ZAP_PROCESS_EXITED',
  /** Le lancement lui-même a échoué : exécutable, JAR ou droits. */
  ZAP_START_FAILED: 'ZAP_START_FAILED',
  /** `java` est introuvable ou n'a pas pu être exécuté. */
  JAVA_START_FAILED: 'JAVA_START_FAILED'
});

/** Une panne de démarrage, avec son code et le diagnostic qui l'accompagne. */
class ZapStartError extends Error {
  constructor(code, message, diagnostics = null) {
    super(message);
    this.name = 'ZapStartError';
    this.code = code;
    this.diagnostics = diagnostics;
  }
}

/**
 * Les pannes d'API que le produit sait nommer pendant un scan.
 *
 * « fetch failed » ne disait ni quel appel avait échoué, ni si ZAP vivait
 * encore. Or un démon mort de faim, un port fermé et un sondage qui ne répond
 * pas trois fois de suite n'appellent pas la même correction.
 */
const ZAP_API_ERROR = Object.freeze({
  /** La connexion à l'API locale a échoué : refusée, réinitialisée, coupée. */
  ZAP_API_UNREACHABLE: 'ZAP_API_UNREACHABLE',
  /** L'API n'a pas répondu dans le temps accordé à l'appel. */
  ZAP_API_TIMEOUT: 'ZAP_API_TIMEOUT',
  /** L'API a répondu, mais par une erreur HTTP. */
  ZAP_API_HTTP_ERROR: 'ZAP_API_HTTP_ERROR',
  /** L'API a répondu en refusant la requête elle-même. */
  ZAP_API_REJECTED: 'ZAP_API_REJECTED',
  /** Le statut d'une étape reste illisible après les tentatives, démon vivant. */
  ZAP_STATUS_POLL_FAILED: 'ZAP_STATUS_POLL_FAILED',
  /** Le démon s'est arrêté pendant le scan. */
  ZAP_PROCESS_EXITED: 'ZAP_PROCESS_EXITED',
  /** Le démon s'est arrêté parce que la JVM n'a plus pu allouer de mémoire. */
  ZAP_OUT_OF_MEMORY: 'ZAP_OUT_OF_MEMORY'
});

/**
 * La politique de relecture d'un statut.
 *
 * Elle ne concerne que des lectures sans effet — `view/status`, `view/alerts` :
 * les relire ne lance rien deux fois. Une action (`ascan/action/scan`) n'est
 * jamais réessayée. Trois tentatives espacées de 1 s puis 2 s absorbent un
 * sondage perdu sans masquer une panne qui dure.
 */
const ZAP_STATUS_POLL_POLICY = Object.freeze({
  ATTEMPTS: 3,
  BACKOFF_MS: 1000,
  /** Le temps laissé à un démon qui meurt pour le dire, avant de conclure. */
  EXIT_GRACE_MS: 3000
});

/** Une panne d'API, avec son code, ses détails techniques et la sortie du démon. */
class ZapApiError extends Error {
  constructor(code, message, details = {}, diagnostics = null) {
    super(message);
    this.name = 'ZapApiError';
    this.code = code;
    this.details = details;
    this.diagnostics = diagnostics;
  }
}

/**
 * Retire des valeurs sensibles de tout texte destiné au journal.
 *
 * La clé d'API est générée par run et les identifiants de test peuvent passer par
 * l'environnement du démon : ni l'une ni les autres n'ont à se retrouver dans la
 * sortie « Security Center », que l'utilisateur copie et partage.
 */
function redactZapText(text, secrets = []) {
  let safe = String(text == null ? '' : text);
  for (const secret of secrets.filter((value) => typeof value === 'string' && value.length >= 4)) {
    safe = safe.split(secret).join('«redacted»');
  }
  return safe.replace(/api\.key=[^\s"']+/gi, 'api.key=«redacted»');
}

function detectLocalZap(configuredPath = '') {
  const candidates = [configuredPath, process.env.ZAP_PATH, path.join(DEFAULT_WINDOWS_HOME, 'zap.bat')].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) || '';
}

async function zapApi(baseUrl, apiKey, component, type, name, params = {}, timeoutMs = 10000) {
  const endpoint = `/JSON/${component}/${type}/${name}/`;
  const url = new URL(endpoint, baseUrl);
  url.searchParams.set('apikey', apiKey);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== '') url.searchParams.set(key, String(value));
  // Ce qui décrit l'appel, sans la clé : c'est ce que le journal peut montrer.
  const call = {
    operation: `${component}.${type}.${name}`,
    method: 'GET',
    endpoint,
    host: url.hostname,
    port: Number(url.port) || (url.protocol === 'https:' ? 443 : 80),
    timeoutMs,
    at: new Date().toISOString()
  };
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    const cause = error?.cause;
    const timedOut = error?.name === 'TimeoutError' || error?.name === 'AbortError';
    throw new ZapApiError(
      timedOut ? ZAP_API_ERROR.ZAP_API_TIMEOUT : ZAP_API_ERROR.ZAP_API_UNREACHABLE,
      timedOut
        ? `API ZAP ${name} : aucune réponse en ${Math.round(timeoutMs / 1000)} s.`
        : `API ZAP ${name} : connexion à l’API locale impossible.`,
      {
        ...call,
        error: redactZapText(error?.message, [apiKey]),
        errorName: error?.name || '',
        cause: cause ? {
          message: redactZapText(cause.message, [apiKey]),
          code: cause.code || '',
          errno: cause.errno ?? null,
          syscall: cause.syscall || '',
          address: cause.address || '',
          port: cause.port ?? null
        } : null
      }
    );
  }
  if (!response.ok) {
    const body = typeof response.text === 'function' ? await response.text().catch(() => '') : '';
    throw new ZapApiError(ZAP_API_ERROR.ZAP_API_HTTP_ERROR, `API ZAP ${name} : HTTP ${response.status}.`, {
      ...call, status: response.status, body: redactZapText(String(body).slice(0, 300), [apiKey])
    });
  }
  const payload = await response.json();
  if (payload.code === 'bad_request' || payload.code === 'internal_error') {
    throw new ZapApiError(ZAP_API_ERROR.ZAP_API_REJECTED, payload.message || `API ZAP ${name} refusée.`, {
      ...call, status: response.status, body: redactZapText(String(payload.message || payload.code).slice(0, 300), [apiKey])
    });
  }
  return payload;
}

async function waitForZap(baseUrl, apiKey, timeoutMs = ZAP_LOCAL_TIMEOUTS.DAEMON_START_MS, onWait) {
  const deadline = Date.now() + timeoutMs;
  const startedAt = Date.now();
  while (Date.now() < deadline) {
    try { return await zapApi(baseUrl, apiKey, 'core', 'view', 'version', {}, 3000); } catch {
      // L'attente est une étape en soi : sans elle, un démon lent est
      // indistinguable d'un scan figé.
      try { onWait?.(Math.round((Date.now() - startedAt) / 1000)); } catch { /* un écouteur ne casse jamais l'attente */ }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  throw new Error(`ZAP local n’a pas répondu sur ${baseUrl} en ${Math.round(timeoutMs / 1000)} secondes.`);
}

/**
 * Le lancement du démon, rendu observable.
 *
 * Le processus était lancé avec `stdio: 'ignore'` : quand ZAP s'arrêtait pendant
 * son démarrage — base de session verrouillée, JAR illisible, Java absent — il
 * l'écrivait sur sa sortie d'erreur, que personne ne lisait. Le seul symptôme
 * visible était une attente d'API de trois minutes sur un processus déjà mort.
 *
 * Les deux flux sont donc lus et conservés en anneau : les dernières lignes
 * suffisent à nommer la cause, et rien n'est accumulé sans limite. La clé d'API
 * et les identifiants sont retirés avant que quoi que ce soit sorte d'ici.
 */
const ZAP_OUTPUT_LINES = 40;

function attachZapDiagnostics(child, { command, args, cwd, secrets = [] }) {
  const diagnostics = {
    command,
    // Les arguments sont conservés assainis : ils portent `api.key=…`.
    args: args.map((argument) => redactZapText(argument, secrets)),
    cwd,
    pid: child.pid || null,
    spawnError: '',
    exitCode: null,
    exitSignal: null,
    stdout: [],
    stderr: []
  };
  const collect = (stream, bucket) => {
    if (!stream) return;
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      for (const line of redactZapText(chunk, secrets).split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        bucket.push(trimmed);
        if (bucket.length > ZAP_OUTPUT_LINES) bucket.shift();
      }
    });
    stream.on('error', () => { /* un flux coupé n'est pas une panne de scan */ });
  };
  collect(child.stdout, diagnostics.stdout);
  collect(child.stderr, diagnostics.stderr);
  child.once('error', (error) => { diagnostics.spawnError = redactZapText(error.message, secrets); });
  child.once('exit', (code, signal) => { diagnostics.exitCode = code; diagnostics.exitSignal = signal || null; });
  child.zapDiagnostics = diagnostics;
  return diagnostics;
}

function startLocalZap(zapPath, { port = 8090, apiKey, authResult, home = '', onDiagnostic } = {}, isolation = null) {
  // APPDATA, TEMP et TMP du run : le navigateur automatisé de ZAP télécharge et
  // crée ses profils dans le bac à sable du run, jamais dans le profil Windows.
  const env = { ...process.env, ...(isolation?.env || {}) };
  if (authResult) {
    env.ZAP_AUTH_HEADER = authResult.header;
    env.ZAP_AUTH_HEADER_VALUE = authResult.value;
    env.ZAP_AUTH_HEADER_SITE = '127.0.0.1';
  }
  // Its own home directory, never the user's.
  //
  // ZAP refuses to start when the home directory it was given is already in
  // use — « The home directory is already in use ». With the shared default,
  // two things broke: an open ZAP desktop made every Security Center run
  // impossible, and a daemon that had to be killed left the lock behind, so
  // every later run failed too until the user cleaned it by hand. A private
  // directory per run removes both, and keeps Security Center sessions out of
  // the user's own ZAP profile.
  const args = ['-daemon', '-host', '127.0.0.1', '-port', String(port), '-config', `api.key=${apiKey}`, '-config', 'api.addrs.addr.name=127.0.0.1', '-config', 'api.addrs.addr.regex=false', '-silent'];
  if (home) args.push('-dir', home);
  // Le profil Firefox de Security Center, celui qui fixe le répertoire de téléchargement.
  if (isolation?.configArgs?.length) args.push(...isolation.configArgs);
  const secrets = [apiKey, authResult?.value].filter(Boolean);
  const cwd = path.dirname(zapPath);
  let command = zapPath;
  let commandArgs = args;
  if (process.platform === 'win32' && /\.bat$/i.test(zapPath)) {
    const jar = fs.readdirSync(cwd).find((name) => /^zap-[\d.]+\.jar$/i.test(name));
    if (!jar) {
      throw new ZapStartError(ZAP_START_ERROR.ZAP_START_FAILED, `JAR ZAP introuvable dans ${cwd}.`, { command: 'java', cwd });
    }
    command = 'java';
    commandArgs = ['-Xmx1024m', '-jar', path.join(cwd, jar), ...args];
  }
  // Les deux flux sont lus : c'est la seule source de la cause réelle quand le
  // démon s'arrête pendant son démarrage.
  const child = spawn(command, commandArgs, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const diagnostics = attachZapDiagnostics(child, { command, args: commandArgs, cwd, secrets });
  try { onDiagnostic?.(diagnostics); } catch { /* un écouteur ne fait jamais échouer un lancement */ }
  return child;
}

/**
 * Attend l'API du démon, ou sa mort — le premier des deux qui arrive.
 *
 * L'attente était aveugle au processus : un démon mort depuis deux secondes était
 * interrogé pendant trois minutes, et la carte annonçait « Attente de l'API ZAP »
 * en cours sur un port que plus rien n'écoutait. La disparition du processus est
 * maintenant une réponse, et elle est immédiate.
 *
 * Les écouteurs et le minuteur sont retirés en sortie, quelle que soit l'issue :
 * une attente terminée ne doit rien laisser derrière elle.
 */
async function waitForZapDaemon({ baseUrl, apiKey, child, timeoutMs = ZAP_LOCAL_TIMEOUTS.DAEMON_START_MS, signal, onWait } = {}) {
  const diagnostics = child?.zapDiagnostics || null;
  const tail = () => {
    if (!diagnostics) return '';
    const lines = [...diagnostics.stderr, ...diagnostics.stdout].slice(-4);
    return lines.length ? ` Dernière sortie : ${lines.join(' | ')}` : '';
  };
  let died = null;
  let spawnFailure = null;
  const onExit = (code, sig) => { died = { code, signal: sig || null }; };
  const onError = (error) => { spawnFailure = error; };
  if (child) {
    child.once('exit', onExit);
    child.once('error', onError);
    // Un processus déjà sorti avant la pose de l'écouteur compte aussi.
    if (child.exitCode !== null || child.signalCode !== null) died = { code: child.exitCode, signal: child.signalCode };
  }
  const startedAt = Date.now();
  const deadline = startedAt + timeoutMs;
  try {
    while (Date.now() < deadline) {
      if (signal?.aborted) throw new Error('Scan ZAP annulé.');
      if (spawnFailure) {
        const javaMissing = /ENOENT/i.test(spawnFailure.message) && /^java/i.test(String(diagnostics?.command || ''));
        throw new ZapStartError(
          javaMissing ? ZAP_START_ERROR.JAVA_START_FAILED : ZAP_START_ERROR.ZAP_START_FAILED,
          javaMissing
            ? 'Java est introuvable : le démon ZAP local n’a pas pu être lancé. Installez Java 17 ou supérieur, ou utilisez le moteur Docker.'
            : `Le démon ZAP local n’a pas pu être lancé : ${spawnFailure.message}.`,
          diagnostics
        );
      }
      if (died) {
        throw new ZapStartError(
          ZAP_START_ERROR.ZAP_PROCESS_EXITED,
          `Le démon ZAP local s’est arrêté avant d’ouvrir son API (code ${died.code === null ? '—' : died.code}${died.signal ? `, signal ${died.signal}` : ''}).${tail()}`,
          diagnostics
        );
      }
      try {
        return await zapApi(baseUrl, apiKey, 'core', 'view', 'version', {}, 3000);
      } catch {
        try { onWait?.(Math.round((Date.now() - startedAt) / 1000)); } catch { /* un écouteur ne casse jamais l'attente */ }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    throw new ZapStartError(
      ZAP_START_ERROR.ZAP_START_FAILED,
      `ZAP local n’a pas répondu sur ${baseUrl} en ${Math.round(timeoutMs / 1000)} secondes.${tail()}`,
      diagnostics
    );
  } finally {
    child?.removeListener('exit', onExit);
    child?.removeListener('error', onError);
  }
}

/**
 * Waits for a ZAP component to finish, reporting its real progress.
 *
 * `spider/view/status` and `ascan/view/status` return a genuine 0-100 percentage.
 * That number used to be fetched and thrown away — only compared against 100 —
 * so the UI had no progress to show and would have had to invent one. It is now
 * handed to `onProgress` on every poll.
 *
 * The one-second sleep paces the polling of ZAP's own API; it never advances a
 * percentage by itself.
 */
/** Le nom d'une étape, tel qu'une raison d'échec le dit. */
const ZAP_READ_LABEL = Object.freeze({ spider: 'le spider', ascan: 'le scan actif', core: 'la collecte des alertes' });

/** La sortie d'un processus, ou `null` s'il vit encore. */
function exitedProcess(child) {
  if (!child || (child.exitCode === null || child.exitCode === undefined) && !child.signalCode) return null;
  return { code: child.exitCode ?? null, signal: child.signalCode || null };
}

/** Attend `ms`, ou la fermeture du processus si elle arrive avant. */
function waitForCloseOrDelay(child, ms) {
  return new Promise((resolve) => {
    let timer = null;
    const done = () => {
      clearTimeout(timer);
      child?.removeListener?.('close', done);
      resolve();
    };
    timer = setTimeout(done, ms);
    child?.once?.('close', done);
  });
}

/** Si quelque chose écoute encore sur ce port : la seule question que se pose un sondage perdu. */
function portListening(host, port, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (listening) => { socket.destroy(); resolve(listening); };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

/**
 * Le démon est mort : la raison vient de sa propre sortie.
 *
 * La JVM écrit « There is insufficient memory for the Java Runtime Environment »
 * et le chemin de son rapport de plantage avant de sortir. C'est ce qui sépare
 * une machine à court de mémoire d'un démon arrêté pour une autre cause.
 */
async function processDiedError(child, label, failures, lastSuccess) {
  // La sortie standard se vide après la fin du processus : on laisse le flux se fermer.
  await waitForCloseOrDelay(child, 1000);
  const diagnostics = child?.zapDiagnostics || null;
  const output = diagnostics ? [...diagnostics.stderr, ...diagnostics.stdout] : [];
  const memory = output.some((line) => /insufficient memory|OutOfMemoryError|os::commit_memory|Native memory allocation|errno=1455/i.test(line));
  const crashReport = (output.find((line) => /hs_err_pid\d+\.log/i.test(line)) || '').replace(/^#\s*/, '');
  const exit = exitedProcess(child) || { code: null, signal: null };
  const exitText = `code ${exit.code === null ? '—' : exit.code}${exit.signal ? `, signal ${exit.signal}` : ''}`;
  return new ZapApiError(
    memory ? ZAP_API_ERROR.ZAP_OUT_OF_MEMORY : ZAP_API_ERROR.ZAP_PROCESS_EXITED,
    memory
      ? `Le démon ZAP local s’est arrêté pendant ${label} : la JVM n’a plus pu allouer de mémoire (mémoire système insuffisante, ${exitText}).`
      : `Le démon ZAP local s’est arrêté pendant ${label} (${exitText}).`,
    { stage: label, processAlive: false, exitCode: exit.code, exitSignal: exit.signal, crashReport, lastSuccess, failures },
    diagnostics
  );
}

/**
 * Lit une vue ZAP en tolérant une perte passagère, jamais une panne qui dure.
 *
 * Réservé aux lectures sans effet. Entre deux tentatives, la vie du démon est
 * vérifiée : un processus mort conclut tout de suite, avec sa vraie raison. Après
 * la dernière tentative, le port dit s'il reste une API à qui parler.
 */
async function readZapView(baseUrl, apiKey, component, name, params = {}, {
  child = null,
  attempts = ZAP_STATUS_POLL_POLICY.ATTEMPTS,
  backoffMs = ZAP_STATUS_POLL_POLICY.BACKOFF_MS,
  exitGraceMs = ZAP_STATUS_POLL_POLICY.EXIT_GRACE_MS,
  timeoutMs = ZAP_LOCAL_TIMEOUTS.API_CALL_MS,
  signal,
  onRetry,
  lastSuccess = null
} = {}) {
  const label = ZAP_READ_LABEL[component] || component;
  const failures = [];
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await zapApi(baseUrl, apiKey, component, 'view', name, params, timeoutMs);
    } catch (error) {
      if (!(error instanceof ZapApiError)) throw error;
      const failure = { attempt, code: error.code, message: error.message, ...error.details };
      failures.push(failure);
      if (exitedProcess(child)) throw await processDiedError(child, label, failures, lastSuccess);
      // Une requête refusée par ZAP le restera : la relire n'y changerait rien.
      const permanent = error.code === ZAP_API_ERROR.ZAP_API_REJECTED
        || (error.code === ZAP_API_ERROR.ZAP_API_HTTP_ERROR && failure.status >= 400 && failure.status < 500);
      if (permanent) {
        error.details = { ...error.details, stage: label, attempts: attempt, lastSuccess, failures };
        throw error;
      }
      if (attempt < attempts) {
        try { onRetry?.({ attempt, attempts, failure }); } catch { /* un écouteur ne casse jamais un sondage */ }
        await waitForCloseOrDelay(child, backoffMs * 2 ** (attempt - 1));
        if (signal?.aborted) throw new Error('Scan ZAP annulé.');
        if (exitedProcess(child)) throw await processDiedError(child, label, failures, lastSuccess);
      }
    }
  }
  // Toutes les tentatives ont échoué. Un démon qui meurt met un instant à sortir.
  if (child && !exitedProcess(child)) await waitForCloseOrDelay(child, exitGraceMs);
  if (exitedProcess(child)) throw await processDiedError(child, label, failures, lastSuccess);
  const last = failures[failures.length - 1];
  const listening = await portListening(last.host, last.port);
  const details = {
    stage: label, attempts, processAlive: child ? true : null, portListening: listening, lastSuccess, failures
  };
  if (!listening) {
    throw new ZapApiError(
      ZAP_API_ERROR.ZAP_API_UNREACHABLE,
      child
        ? `Connexion perdue avec l’API ZAP locale pendant ${label} : le démon est en vie mais son port ${last.port} n’écoute plus.`
        : `Connexion perdue avec l’API ZAP locale pendant ${label} : plus rien n’écoute sur le port ${last.port}.`,
      details,
      child?.zapDiagnostics || null
    );
  }
  throw new ZapApiError(
    ZAP_API_ERROR.ZAP_STATUS_POLL_FAILED,
    `Le statut de ${label} n’a pas pu être lu après ${attempts} tentatives, alors que l’API ZAP locale reste ouverte.`,
    details,
    child?.zapDiagnostics || null
  );
}

/**
 * Borne la concurrence du scan actif avant son démarrage, puis la relit.
 *
 * Ce qui est journalisé est ce que ZAP applique, pas ce qu'on lui a demandé.
 * Le réglage n'est abaissé que s'il dépasse le plafond : un réglage déjà plus
 * sobre est respecté. Le réglage est une action — il n'est jamais réessayé.
 */
async function boundActiveScanConcurrency(baseUrl, apiKey, pollOptions = {}, diagnose = () => {}) {
  const threadsPerHost = () => readZapView(baseUrl, apiKey, 'ascan', 'optionThreadPerHost', {}, pollOptions)
    .then((value) => Number(value?.ThreadPerHost))
    .catch(() => NaN);
  const configured = await threadsPerHost();
  if (!Number.isFinite(configured) || configured > ZAP_ACTIVE_SCAN_THREADS_PER_HOST) {
    await zapApi(baseUrl, apiKey, 'ascan', 'action', 'setOptionThreadPerHost', { Integer: ZAP_ACTIVE_SCAN_THREADS_PER_HOST });
  }
  const applied = await threadsPerHost();
  const known = (value) => (Number.isFinite(value) ? value : 'inconnu');
  diagnose({ message: `scan actif : ${known(applied)} fil(s) par hôte (réglage initial ${known(configured)}, plafond ${ZAP_ACTIVE_SCAN_THREADS_PER_HOST})` });
  return { configured, applied };
}

async function waitForProgress(baseUrl, apiKey, component, scanId, timeoutMs, signal, onProgress, {
  stallMs = ZAP_LOCAL_TIMEOUTS.STALL_MS, child = null, attempts, backoffMs, exitGraceMs, onRetry
} = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastPercent = null;
  let lastChangeAt = Date.now();
  let lastSuccessAt = null;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error('Scan ZAP annulé.');
    // Une lecture de statut perdue n'arrête plus le scan : elle est relue, et
    // seule une panne confirmée — démon mort, port fermé, trois échecs — conclut.
    const result = await readZapView(baseUrl, apiKey, component, 'status', { scanId }, {
      child, attempts, backoffMs, exitGraceMs, signal, onRetry,
      lastSuccess: { operation: `${component}.view.status`, percent: lastPercent, at: lastSuccessAt }
    });
    lastSuccessAt = new Date().toISOString();
    const percent = Number(result.status);
    if (Number.isFinite(percent)) {
      const bounded = Math.max(0, Math.min(100, percent));
      onProgress?.(bounded);
      // Ce qui fait avancer l'horloge d'activité est un pourcentage qui change,
      // jamais le fait d'avoir interrogé ZAP une fois de plus.
      if (bounded !== lastPercent) { lastPercent = bounded; lastChangeAt = Date.now(); }
    }
    if (percent >= 100) return;
    // Une étape qui progresse va jusqu'à son plafond ; une étape immobile
    // s'arrête ici, et sa raison nomme le point où elle s'est arrêtée.
    if (Date.now() - lastChangeAt >= stallMs) {
      throw new Error(`L’étape ${component} du scan ZAP local n’a plus progressé depuis ${Math.round(stallMs / 1000)} secondes${lastPercent === null ? '' : ` (bloquée à ${lastPercent} %)`}.`);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`L’étape ${component} du scan ZAP local a dépassé ${Math.round(timeoutMs / 1000)} secondes${lastPercent === null ? '' : ` (arrêtée à ${lastPercent} %)`}.`);
}

/**
 * Waits for the passive-scan queue to drain.
 *
 * ZAP exposes `pscan/view/recordsToScan`, a count of records still queued. If the
 * running build does not answer that view, the queue state is simply unknown:
 * this returns `{ available: false }` and the caller must skip the passive stage
 * rather than display it as satisfied. A passive tick that was never observed is
 * never rendered as a completed one.
 */
async function waitForPassiveQueue(baseUrl, apiKey, timeoutMs, signal, onProgress, { stallMs = ZAP_LOCAL_TIMEOUTS.STALL_MS } = {}) {
  let initial = null;
  let lastRemaining = null;
  let lastChangeAt = Date.now();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error('Scan ZAP annulé.');
    let remaining;
    try {
      const result = await zapApi(baseUrl, apiKey, 'pscan', 'view', 'recordsToScan', {});
      remaining = Number(result.recordsToScan);
    } catch (error) {
      return { available: false, reason: error.message };
    }
    if (!Number.isFinite(remaining)) return { available: false, reason: 'recordsToScan non numérique' };
    if (initial === null) initial = remaining;
    // The percentage is derived from ZAP's own two numbers, not from elapsed time.
    const percent = initial > 0 ? Math.round(((initial - remaining) / initial) * 100) : 100;
    onProgress?.(Math.max(0, Math.min(100, percent)), remaining);
    if (remaining !== lastRemaining) { lastRemaining = remaining; lastChangeAt = Date.now(); }
    if (remaining <= 0) return { available: true, drained: true, records: initial };
    // Une file qui ne descend plus n'est pas une file qui travaille : le dire
    // tout de suite vaut mieux que d'attendre le plafond pour le même constat.
    if (Date.now() - lastChangeAt >= stallMs) {
      return { available: true, drained: false, records: initial, remaining, reason: `file passive immobile à ${remaining} enregistrement(s) depuis ${Math.round(stallMs / 1000)} secondes` };
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return { available: true, drained: false, records: initial, remaining: lastRemaining, reason: 'file passive non vidée dans le délai' };
}

function alertsToReport(alerts = []) {
  const groups = new Map();
  for (const item of alerts) {
    const key = String(item.alertRef || item.pluginId || item.alert || 'alert');
    if (!groups.has(key)) groups.set(key, {
      pluginid: key, alert: item.alert, name: item.name, riskcode: item.riskcode, confidence: item.confidence,
      cweid: item.cweid, desc: item.description || item.desc, solution: item.solution, reference: item.reference,
      otherinfo: item.other, instances: []
    });
    groups.get(key).instances.push({ uri: item.url, method: item.method, param: item.param, evidence: item.evidence, otherinfo: item.other });
  }
  return { site: [{ '@name': 'http://127.0.0.1', alerts: [...groups.values()] }] };
}

function openApiImportRequest(source, targetUrl) {
  if (path.isAbsolute(source)) {
    if (!fs.existsSync(source)) throw new Error(`Spécification OpenAPI locale introuvable : ${source}.`);
    return { action: 'importFile', params: { file: source, target: targetUrl } };
  }
  try {
    const url = new URL(source);
    if (!['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) throw new Error('remote');
    return { action: 'importUrl', params: { url: url.toString(), hostOverride: targetUrl } };
  } catch (error) {
    if (error.message === 'remote') throw new Error('La spécification OpenAPI distante est interdite.');
    if (!path.isAbsolute(source) || !fs.existsSync(source)) throw new Error(`Spécification OpenAPI locale introuvable : ${source}.`);
    return { action: 'importFile', params: { file: source, target: targetUrl } };
  }
}

/**
 * Runs a local ZAP scan, reporting its real lifecycle.
 *
 * `onLifecycle({ state, progress, detail })` is called only from data ZAP
 * actually returned. There is no timer-driven progress anywhere: every
 * percentage comes from `spider/view/status`, `ascan/view/status` or
 * `pscan/view/recordsToScan`.
 */


/**
 * A port nobody is listening on.
 *
 * The daemon used to be pinned to 8090, which is also the port ZAP's own
 * desktop application binds by default. With ZAP open — the very situation this
 * engine exists to avoid — the daemon could not bind, died immediately, and the
 * only symptom was « ZAP local ne répond pas sur http://127.0.0.1:8090 »: a
 * timeout blamed on ZAP rather than on the port already being taken.
 *
 * The OS picks the port by binding 0, and it is released before ZAP claims it.
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

/** Security Center's own ZAP home, never the user's. */
function zapHomeDirectory() {
  return path.join(os.tmpdir(), 'security-center-zap-home');
}

/**
 * Prepares the home directory the daemon will run in.
 *
 * It is stable rather than created per run: a brand-new home makes ZAP copy its
 * default configuration and migrate its database on every start, which took
 * longer than the startup window allowed. Reused, the daemon is answering in
 * about ten seconds.
 *
 * The stale lock is cleared here. ZAP refuses to start on a home that still
 * holds `.homelock` after a daemon was killed, and this directory belongs to
 * Security Center — removing its own leftover lock is safe, and the user's ZAP
 * profile is never touched.
 */
/**
 * Les verrous qu'un démon tué laisse derrière lui, dans le home de Security Center.
 *
 * `.homelock` était le seul retiré. Or la session et la base permanente de ZAP
 * sont des bases HSQLDB, et chacune pose son propre `.lck` dans `db/` et
 * `session/`. Un démon arrêté de force — fin de scan forcée, fenêtre fermée,
 * délai dépassé — les laisse en place ; au démarrage suivant, ZAP échoue sur
 * l'ouverture de sa base, s'arrête avant même d'écrire son journal, et n'ouvre
 * jamais son API. C'est exactement le démarrage qui « réussissait » puis attendait
 * une API qui ne viendrait pas.
 *
 * Ce répertoire appartient à Security Center, qui n'exécute qu'un démon à la
 * fois : retirer ses propres verrous abandonnés est sûr, et le profil ZAP de
 * l'utilisateur n'est jamais touché.
 */
async function clearStaleZapLocks(home) {
  const cleared = [];
  const candidates = [home, path.join(home, 'db'), path.join(home, 'session')];
  for (const directory of candidates) {
    const entries = await fsp.readdir(directory).catch(() => []);
    for (const entry of entries) {
      if (!/(^\.homelock$)|(\.lck$)/i.test(entry)) continue;
      const target = path.join(directory, entry);
      // Un verrou qu'on ne peut pas retirer est un verrou tenu par un processus
      // vivant : on le laisse, et le démarrage échouera avec sa vraie cause.
      const removed = await fsp.rm(target, { force: true }).then(() => true).catch(() => false);
      if (removed) cleared.push(path.relative(home, target) || entry);
    }
  }
  return cleared;
}

async function prepareZapHome({ onDiagnostic } = {}) {
  const home = zapHomeDirectory();
  await fsp.mkdir(home, { recursive: true });
  const cleared = await clearStaleZapLocks(home);
  if (cleared.length) {
    try { onDiagnostic?.({ clearedLocks: cleared }); } catch { /* un écouteur ne bloque jamais un démarrage */ }
  }
  return home;
}

/**
 * Arrête le démon, et s'assure qu'il est bien parti.
 *
 * L'arrêt reposait sur un seul appel : `core/action/shutdown`, et `kill()` en
 * secours uniquement si cet appel jetait. Un démon qui accepte la demande sans
 * sortir — le cas quand une étape le tient encore occupé — laissait donc un
 * processus Java vivant, avec son port et son home verrouillés pour le run
 * suivant. La sortie est maintenant attendue, puis forcée si elle ne vient pas.
 */
async function stopLocalZap(child, baseUrl, apiKey, { onStage } = {}) {
  const report = (detail) => { try { onStage?.(detail); } catch { /* un écouteur n'empêche jamais un arrêt */ } };
  report('Arrêt du démon demandé');
  const exited = child && child.exitCode === null && child.signalCode === null
    ? new Promise((resolve) => child.once('close', resolve))
    : Promise.resolve();
  try {
    await zapApi(baseUrl, apiKey, 'core', 'action', 'shutdown', {}, ZAP_LOCAL_TIMEOUTS.SHUTDOWN_MS);
  } catch {
    // L'API ne répond plus : il reste le processus.
    child?.kill();
  }
  if (!child) return { stopped: true, forced: false };
  const left = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), ZAP_LOCAL_TIMEOUTS.SHUTDOWN_GRACE_MS))
  ]);
  if (left) {
    report('Démon arrêté');
    return { stopped: true, forced: false };
  }
  // Le démon a accepté l'arrêt sans sortir : plus rien ne le fera partir seul,
  // et un ZAP orphelin garde son port et son verrou de home.
  child.kill();
  const afterKill = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), ZAP_LOCAL_TIMEOUTS.SHUTDOWN_GRACE_MS))
  ]);
  if (!afterKill) child.kill('SIGKILL');
  report('Démon arrêté de force');
  return { stopped: true, forced: true };
}

async function runLocalZap({ targetUrl, mode = 'baseline', localPath = '', timeoutMs = ZAP_SCAN_TIMEOUT_MS, signal, excludedRoutes = [], authResult, openapi = '', onLifecycle, onProcess, onDiagnostic }) {
  const report = (state, progress = null, detail = '', metrics = undefined) => {
    try { onLifecycle?.({ state, progress, detail, metrics }); } catch { /* a listener must never break a scan */ }
  };
  // Le diagnostic technique va au journal, pas aux étapes : il nomme la commande,
  // le PID et la sortie du démon, déjà débarrassés de tout secret.
  const diagnose = (info) => {
    try { onDiagnostic?.(info); } catch { /* un écouteur ne fait jamais échouer le scan */ }
  };
  const zapPath = detectLocalZap(localPath);
  if (!zapPath) throw new Error('ZAP local n’est pas installé. Utilisez le bouton Installer/configurer ZAP.');
  const apiKey = crypto.randomBytes(24).toString('hex');
  const port = await freeLocalPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const home = await prepareZapHome({
    onDiagnostic: (info) => diagnose({ message: `verrous abandonnés retirés du home ZAP : ${info.clearedLocks.join(', ')}` })
  });
  // Le mode réellement exécuté, dit par le moteur lui-même : c'est cette valeur
  // que le déroulé affiche, et non celle qu'une autre couche a pu retenir.
  report('MODE', null, mode, { });
  report('DAEMON_STARTING', null, `Démarrage du démon ZAP local sur le port ${port}`);
  // Le bac à sable du navigateur automatisé : téléchargements, profils et
  // fichiers temporaires de ce run, hors du profil Windows de l'utilisateur.
  const isolation = await prepareZapBrowserIsolation();
  const cleanupIsolation = async () => {
    const cleanup = await cleanupZapBrowserIsolation(isolation).catch((error) => ({ removed: false, reason: error.message }));
    diagnose({ message: cleanup.removed
      ? `bac à sable du navigateur supprimé (${cleanup.downloads} téléchargement(s) automatisé(s), ${cleanup.stoppedProcesses} processus arrêté(s))`
      : `bac à sable du navigateur non supprimé : ${cleanup.reason} — repris au prochain run` });
  };
  const staleRuns = await sweepStaleZapRuns({ keep: [isolation.runId] }).catch(() => []);
  if (staleRuns.length) diagnose({ message: `bacs à sable abandonnés supprimés : ${staleRuns.join(', ')}` });
  diagnose({ message: `téléchargements du navigateur automatisé isolés dans ${isolation.downloads}` });
  let child;
  try {
    child = startLocalZap(zapPath, { port, apiKey, authResult, home, onDiagnostic: (info) => diagnose({ launch: info }) }, isolation);
  } catch (error) {
    // Un lancement refusé est une panne nommée, pas une attente.
    diagnose({ message: `lancement refusé : ${error.message}` });
    await cleanupIsolation();
    throw error;
  }
  // Le démon est confié à l'appelant : si la fenêtre se ferme pendant le scan,
  // c'est le seul moyen d'arrêter un ZAP qui n'a plus personne pour l'arrêter.
  try { onProcess?.(child); } catch { /* un écouteur ne fait jamais échouer le scan */ }
  // Les sondages de statut connaissent le démon : ils peuvent distinguer une
  // lecture perdue d'un processus mort, et chaque nouvel essai est journalisé.
  const pollOptions = {
    child,
    onRetry: ({ attempt, attempts, failure }) => diagnose({
      message: `lecture ${failure.operation} échouée (tentative ${attempt}/${attempts}) : ${failure.code}${failure.cause?.code ? ` · ${failure.cause.code}` : ''}${failure.status ? ` · HTTP ${failure.status}` : ''} — nouvel essai`
    })
  };
  try {
    // L'attente de l'API est une étape distincte du démarrage, et elle court
    // contre la vie du processus : un démon mort répond tout de suite.
    report('API_WAIT', null, 'Attente de la réponse de l’API ZAP');
    await waitForZapDaemon({
      baseUrl, apiKey, child, signal, timeoutMs: ZAP_LOCAL_TIMEOUTS.DAEMON_START_MS,
      onWait: (seconds) => report('API_WAIT', null, `API ZAP pas encore disponible (${seconds} s)`)
    });
    report('API_WAIT', null, 'API ZAP disponible');
    // Le démarrage n'est terminé que maintenant : c'est la réponse de l'API qui
    // le prouve, jamais le retour de `spawn`.
    report('DAEMON_READY', null, `Démon ZAP prêt sur ${baseUrl}`, { pid: child.pid });
    await zapApi(baseUrl, apiKey, 'core', 'action', 'newSession', { name: `security-center-${Date.now()}`, overwrite: true });
    for (const route of excludedRoutes) {
      const target = new URL(targetUrl);
      const escaped = `${target.origin}${String(route).startsWith('/') ? route : `/${route}`}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      await zapApi(baseUrl, apiKey, 'core', 'action', 'excludeFromProxy', { regex: `^${escaped}(?:[/?#].*)?$` });
    }
    if (mode === 'openapi') {
      const request = openApiImportRequest(openapi, targetUrl);
      report('SPIDERING', null, 'Import OpenAPI');
      await zapApi(baseUrl, apiKey, 'openapi', 'action', request.action, request.params, Math.min(timeoutMs, ZAP_LOCAL_TIMEOUTS.OPENAPI_IMPORT_MS));
    } else {
      const spider = await zapApi(baseUrl, apiKey, 'spider', 'action', 'scan', { url: targetUrl, recurse: true, subtreeOnly: true, maxChildren: 0 });
      report('SPIDERING', 0);
      await waitForProgress(baseUrl, apiKey, 'spider', spider.scan, Math.min(timeoutMs, ZAP_LOCAL_TIMEOUTS.SPIDER_MS), signal,
        (percent) => report('SPIDERING', percent), pollOptions);
      // Ce que le parcours a réellement trouvé, demandé à ZAP plutôt que déduit.
      const discovered = await zapApi(baseUrl, apiKey, 'core', 'view', 'urls', { baseurl: targetUrl })
        .then((result) => (Array.isArray(result?.urls) ? result.urls.length : null))
        .catch(() => null);
      if (discovered !== null) report('SPIDERING', 100, `${discovered} URL découverte(s)`, { urls: discovered });
    }
    // The passive queue is only reported when ZAP answered for it.
    const passive = await waitForPassiveQueue(baseUrl, apiKey, Math.min(timeoutMs, ZAP_LOCAL_TIMEOUTS.PASSIVE_DRAIN_MS), signal,
      (percent, remaining) => report('PASSIVE_WAIT', percent, `${remaining} enregistrement(s) en file`, { recordsToScan: remaining }));
    if (!passive.available) report('PASSIVE_WAIT', null, `File passive indisponible : ${passive.reason}`);
    else if (!passive.drained) report('PASSIVE_WAIT', null, `File passive non vidée : ${passive.reason}`);
    if (mode === 'baseline') {
      // Le scan actif n'a pas eu lieu. Le taire le ferait passer pour réussi, et
      // laisserait croire que l'application a été testée activement.
      report('ACTIVE_SKIPPED', null, 'Mode baseline passif');
    } else {
      await boundActiveScanConcurrency(baseUrl, apiKey, pollOptions, diagnose);
      const active = await zapApi(baseUrl, apiKey, 'ascan', 'action', 'scan', { url: targetUrl, recurse: true, inScopeOnly: false });
      report('ACTIVE_SCANNING', 0);
      await waitForProgress(baseUrl, apiKey, 'ascan', active.scan, Math.min(timeoutMs, ZAP_LOCAL_TIMEOUTS.ACTIVE_SCAN_MS), signal,
        (percent) => report('ACTIVE_SCANNING', percent), pollOptions);
    }
    report('COLLECTING_RESULTS');
    const result = await readZapView(baseUrl, apiKey, 'core', 'alerts', { baseurl: targetUrl, start: 0, count: 10000 }, { ...pollOptions, signal });
    report('COLLECTING_RESULTS', 100, `${(result.alerts || []).length} alerte(s) collectée(s)`, { alerts: (result.alerts || []).length });
    return {
      payload: alertsToReport(result.alerts), stderr: '', mode: 'local',
      // What the run really observed, so the caller never has to guess.
      passiveQueue: passive
    };
  } finally {
    report('DAEMON_STOPPING', null, 'Arrêt du démon ZAP local');
    const stop = await stopLocalZap(child, baseUrl, apiKey).catch(() => ({ stopped: false, forced: false }));
    report('DAEMON_STOPPED', null, stop.forced ? 'Démon arrêté de force' : 'Démon arrêté');
    diagnose({ stopped: { forced: stop.forced, exitCode: child?.zapDiagnostics?.exitCode ?? null, exitSignal: child?.zapDiagnostics?.exitSignal ?? null } });
    // Terminé, échoué ou annulé : les téléchargements automatisés du run ne
    // survivent pas au démon.
    await cleanupIsolation();
  }
}

module.exports = {
  ZAP_LOCAL_TIMEOUTS, ZAP_SCAN_TIMEOUT_MS, ZAP_START_ERROR, ZapStartError,
  ZAP_API_ERROR, ZAP_STATUS_POLL_POLICY, ZapApiError, readZapView, portListening, ZAP_ACTIVE_SCAN_THREADS_PER_HOST,
  stopLocalZap, waitForZapDaemon, clearStaleZapLocks, redactZapText, attachZapDiagnostics,
  freeLocalPort,
  zapHomeDirectory,
  prepareZapHome, detectLocalZap, zapApi, waitForZap, startLocalZap, waitForProgress, waitForPassiveQueue, alertsToReport, openApiImportRequest, runLocalZap };
