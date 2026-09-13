const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const { dockerCliArgs } = require('./docker');
const { detectLocalZap, runLocalZap, ZAP_SCAN_TIMEOUT_MS, ZAP_LOCAL_TIMEOUTS } = require('./zap-local');
const { isLoopbackHost } = require('./dynamic-target');

const execFileAsync = promisify(execFile);

/**
 * Validates the URL ZAP is pointed at.
 *
 * `allowRemote` is opt-in and defaults to false, so every existing caller keeps
 * the loopback-only contract. It is turned on only once the user has chosen the
 * remote mode and confirmed being authorised to test that address.
 */
function validateZapTarget(targetUrl, { allowRemote = false } = {}) {
  let target;
  try {
    target = new URL(targetUrl);
  } catch {
    throw new Error('URL ZAP invalide.');
  }
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('ZAP accepte uniquement une URL HTTP ou HTTPS.');
  if (!allowRemote && !isLoopbackHost(target.hostname)) {
    throw new Error('Pour votre sécurité, le MVP ZAP autorise uniquement une cible locale.');
  }
  return target;
}

/** The loopback-only validator, unchanged for every caller that used it. */
function validateLocalTarget(targetUrl) {
  return validateZapTarget(targetUrl, { allowRemote: false });
}

/**
 * The address the ZAP container must dial.
 *
 * A loopback target has to become `host.docker.internal`: inside the container,
 * `127.0.0.1` is the container itself. A remote address is left exactly as the
 * user typed it — rewriting it would silently scan the wrong machine, which is
 * the one thing this function must never do.
 */
function dockerTargetUrl(targetUrl, { allowRemote = false } = {}) {
  const target = validateZapTarget(targetUrl, { allowRemote });
  if (!isLoopbackHost(target.hostname)) return target.toString().replace(/\/$/, '');
  target.hostname = 'host.docker.internal';
  return target.toString().replace(/\/$/, '');
}

function routeExclusionRegex(targetUrl, route, { allowRemote = false } = {}) {
  const target = dockerTargetUrl(targetUrl, { allowRemote }).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const normalized = String(route).trim().startsWith('/') ? String(route).trim() : `/${String(route).trim()}`;
  const escapedRoute = normalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return `^${target}${escapedRoute}(?:[/?#].*)?$`;
}

function zapConfig(excludedRoutes = [], targetUrl = 'http://127.0.0.1', { allowRemote = false } = {}) {
  const lines = ['# Security Center generated ZAP baseline configuration'];
  for (const route of excludedRoutes) lines.push(`*\tOUTOFSCOPE\t${routeExclusionRegex(targetUrl, route, { allowRemote })}`);
  return `${lines.join('\n')}\n`;
}

function resolveWorkspaceFile(workspacePath, configuredPath, label) {
  if (!configuredPath) return '';
  const root = path.resolve(workspacePath);
  const resolved = path.resolve(root, configuredPath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`${label} doit rester dans le workspace.`);
  }
  if (!require('fs').existsSync(resolved)) throw new Error(`${label} introuvable : ${configuredPath}.`);
  return resolved;
}

function containerWorkspacePath(workspacePath, filePath) {
  return `/src/${path.relative(path.resolve(workspacePath), filePath).split(path.sep).join('/')}`;
}

function dockerArgs(targetUrl, reportDirectory, options = {}) {
  const { excludedRoutes = [], mode = 'baseline', workspacePath = '', openapi = '', context = '', user = '', authEnvFile = '', allowRemote = false, containerName = '' } = options;
  if (!['baseline', 'active', 'openapi'].includes(mode)) throw new Error(`Mode ZAP inconnu : ${mode}.`);
  let scanScript = 'zap-baseline.py';
  let scanTarget = dockerTargetUrl(targetUrl, { allowRemote });
  if (mode === 'active') scanScript = 'zap-full-scan.py';
  if (mode === 'openapi') {
    scanScript = 'zap-api-scan.py';
    if (!openapi) throw new Error('Le mode ZAP OpenAPI exige zap.openapi dans security-center.yml.');
    try {
      scanTarget = dockerTargetUrl(openapi, { allowRemote });
    } catch {
      const specPath = resolveWorkspaceFile(workspacePath, openapi, 'La spécification OpenAPI');
      scanTarget = containerWorkspacePath(workspacePath, specPath);
    }
  }
  const args = [
    'run', '--rm',
    // Un conteneur nommé est un conteneur qu'on peut retrouver et arrêter.
    // Tuer le client Docker n'arrête pas le conteneur : sans ce nom, une
    // annulation laissait un scan poursuivre son trafic vers la cible.
    ...(containerName ? ['--name', containerName] : []),
    ...(authEnvFile ? ['--env-file', authEnvFile] : []),
    '-v', `${reportDirectory}:/zap/wrk:rw`,
    ...(workspacePath ? ['-v', `${path.resolve(workspacePath)}:/src:ro`] : []),
    'zaproxy/zap-stable',
    scanScript,
    '-t', scanTarget,
    ...(mode === 'openapi' ? ['-f', 'openapi'] : []),
    '-J', 'zap-report.json',
    '-I',
    '-z', '-silent'
  ];
  if (mode === 'baseline' || mode === 'active') args.push('-m', '2');
  if (excludedRoutes.length) args.push('-c', 'security-center-zap.conf');
  if (context) {
    const contextPath = resolveWorkspaceFile(workspacePath, context, 'Le contexte ZAP');
    args.push('-n', containerWorkspacePath(workspacePath, contextPath));
    if (user) args.push('-U', user);
  } else if (user) {
    throw new Error('zap.user exige également zap.context.');
  }
  return dockerCliArgs(args);
}

function valueAtPath(payload, configuredPath) {
  return String(configuredPath).split('.').filter(Boolean).reduce((value, key) => value?.[key], payload);
}

function resolveAuthLoginUrl(targetUrl, configuredLogin, { allowRemote = false } = {}) {
  const target = validateZapTarget(targetUrl, { allowRemote });
  const login = new URL(configuredLogin, target);
  validateZapTarget(login.toString(), { allowRemote });
  // Same-origin stays the rule in both modes: the login must belong to the very
  // target being scanned, never to another host.
  if (login.origin !== target.origin) throw new Error('zap.auth_login doit utiliser la même origine que la cible ZAP.');
  return login;
}

function authenticateForZap(targetUrl, auth, env = process.env, timeoutMs = 10000, { allowRemote = false } = {}) {
  if (!auth?.login) return Promise.resolve(null);
  const username = env[auth.usernameEnv];
  const password = env[auth.passwordEnv];
  if (!username || !password) {
    throw new Error(`Authentification ZAP impossible : définissez ${auth.usernameEnv} et ${auth.passwordEnv}.`);
  }
  const login = resolveAuthLoginUrl(targetUrl, auth.login, { allowRemote });
  const body = JSON.stringify({ [auth.usernameField]: username, [auth.passwordField]: password });
  const client = login.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.request(login, { method: 'POST', timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        if ((response.statusCode || 500) >= 400) return reject(new Error(`Login ZAP refusé avec HTTP ${response.statusCode}.`));
        try {
          const token = valueAtPath(JSON.parse(Buffer.concat(chunks).toString('utf8')), auth.tokenPath);
          if (typeof token !== 'string' || !token.trim()) throw new Error('jeton absent');
          resolve({ header: auth.header, value: `${auth.prefix ? `${auth.prefix} ` : ''}${token}` });
        } catch {
          reject(new Error(`Login ZAP réussi, mais aucun jeton n’existe dans ${auth.tokenPath}.`));
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('Le login ZAP a dépassé son délai.')));
    request.on('error', (error) => reject(new Error(`Login ZAP impossible : ${error.message}`)));
    request.end(body);
  });
}

function zapAuthEnv(authResult, targetUrl, { allowRemote = false } = {}) {
  if (!authResult) return '';
  for (const value of [authResult.header, authResult.value]) {
    if (/\r|\n/.test(value)) throw new Error('En-tête d’authentification ZAP invalide.');
  }
  return `ZAP_AUTH_HEADER=${authResult.header}\nZAP_AUTH_HEADER_VALUE=${authResult.value}\nZAP_AUTH_HEADER_SITE=${dockerTargetUrl(targetUrl, { allowRemote }).replace(/^https?:\/\//, '').split('/')[0]}\n`;
}

function checkTargetAvailable(targetUrl, timeoutMs = 5000, { allowRemote = false } = {}) {
  const target = validateZapTarget(targetUrl, { allowRemote });
  const client = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.get(target, { timeout: timeoutMs }, (response) => {
      response.resume();
      resolve(response.statusCode || 0);
    });
    request.on('timeout', () => request.destroy(new Error(`La cible ZAP ne répond pas après ${Math.round(timeoutMs / 1000)} secondes.`)));
    // The real reason is kept: « refused », « name not found » and « TLS
    // rejected » call for three different fixes, especially on a remote lab.
    request.on('error', (error) => reject(new Error(
      `La cible ZAP ${targetUrl} est inaccessible (${error.code || error.message}). Vérifiez qu’elle est démarrée et joignable depuis ce poste.`
    )));
  });
}

/** Supprime un conteneur ZAP qui aurait survécu à son client. Sans effet s'il n'existe plus. */
async function removeZapContainer(containerName) {
  if (!containerName) return false;
  try {
    await execFileAsync('docker', dockerCliArgs(['rm', '--force', containerName]), { timeout: 15000, windowsHide: true });
    return true;
  } catch {
    // Le conteneur s'est déjà retiré de lui-même (`--rm`), ou Docker n'est plus là.
    return false;
  }
}

async function runZap({ targetUrl, timeoutMs = ZAP_SCAN_TIMEOUT_MS, signal, excludedRoutes = [], mode = 'baseline', workspacePath = '', openapi = '', context = '', user = '', auth, authEnv = process.env, resolvedAuth = null, engine = 'auto', localPath = '', allowRemote = false, onLifecycle, onEngine, onAuthentication, onProcess, onContainer, onDiagnostic }) {
  validateZapTarget(targetUrl, { allowRemote });
  await checkTargetAvailable(targetUrl, 5000, { allowRemote });
  // A caller that already holds a credential — a Dynamic Security auth profile,
  // whose secret lives in SecretStorage — passes it here as a resolved
  // `{header, value}` pair, which is exactly what a login would have produced.
  // The rest of the path is unchanged: `zapAuthEnv` still rejects CRLF, the file
  // is still written 0600 into the temp directory, and the `finally` below still
  // deletes it. No parallel authentication engine, no new secret lifetime.
  const authResult = resolvedAuth || await authenticateForZap(targetUrl, auth, authEnv, 10000, { allowRemote });
  // Ce qui est dit est ce que ZAP recevra réellement : une session prouvée — un
  // profil validé, ou un login qui vient de rendre son jeton. Un login seulement
  // configuré n'en est pas une, et un login refusé a déjà levé ci-dessus.
  try { onAuthentication?.({ authenticated: Boolean(authResult) }); } catch { /* un écouteur ne fait jamais échouer le scan */ }
  const detectedLocalPath = detectLocalZap(localPath);
  // `auto` means « choose »: the local headless daemon when ZAP is installed,
  // the official Docker image otherwise. It used to behave exactly like `local`
  // and fail outright when no ZAP was installed, so the Docker engine — which
  // needs nothing installed — was only ever reachable by naming it explicitly.
  const resolvedEngine = engine === 'auto' ? (detectedLocalPath ? 'local' : 'docker') : engine;
  // Le moteur retenu est annoncé avant que quoi que ce soit démarre : la carte
  // dit « Local » ou « Docker » pendant le scan, et non après coup.
  try { onEngine?.(resolvedEngine); } catch { /* un écouteur ne fait jamais échouer le scan */ }
  const report = (state, progress = null, detail = '') => {
    try { onLifecycle?.({ state, progress, detail }); } catch { /* idem */ }
  };
  if (resolvedEngine !== 'docker') {
    if (!detectedLocalPath) throw new Error('ZAP local n’est pas détecté. Installez ZAP ou choisissez zap.mode: docker explicitement.');
    let localOpenapi = openapi;
    if (mode === 'openapi') {
      try { validateZapTarget(openapi, { allowRemote }); } catch { localOpenapi = resolveWorkspaceFile(workspacePath, openapi, 'La spécification OpenAPI'); }
    }
    return runLocalZap({ targetUrl, mode, localPath: detectedLocalPath, timeoutMs, signal, excludedRoutes, authResult, openapi: localOpenapi, onLifecycle, onProcess, onDiagnostic });
  }
  const reportDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-zap-'));
  const reportPath = path.join(reportDirectory, 'zap-report.json');
  // Le conteneur est nommé pour pouvoir être arrêté : `--rm` ne suffit pas
  // quand c'est le client qui meurt.
  const containerName = `security-center-zap-${process.pid}-${Date.now()}`;
  try { onContainer?.(containerName); } catch { /* un écouteur ne fait jamais échouer le scan */ }
  report('STARTING', null, 'Préparation du conteneur ZAP');
  try {
    const authEnvFile = authResult ? path.join(reportDirectory, 'zap-auth.env') : '';
    if (authEnvFile) await fs.writeFile(authEnvFile, zapAuthEnv(authResult, targetUrl, { allowRemote }), { encoding: 'utf8', mode: 0o600 });
    if (excludedRoutes.length) await fs.writeFile(path.join(reportDirectory, 'security-center-zap.conf'), zapConfig(excludedRoutes, targetUrl, { allowRemote }), 'utf8');
    // Le conteneur ne publie pas de pourcentage exploitable : l'étape est dite,
    // et aucune progression n'est inventée pour l'accompagner.
    report('MODE', null, mode);
    report('SPIDERING', null, `Docker · ${mode === 'active' ? 'zap-full-scan' : mode === 'openapi' ? 'zap-api-scan' : 'zap-baseline'}`);
    try {
      await execFileAsync('docker', dockerArgs(targetUrl, reportDirectory, { excludedRoutes, mode, workspacePath, openapi, context, user, authEnvFile, allowRemote, containerName }), {
        timeout: timeoutMs,
        maxBuffer: 20 * 1024 * 1024,
        windowsHide: true,
        signal
      });
    } catch (error) {
      if (signal?.aborted) throw new Error('Scan ZAP annulé.');
      try {
        const payload = JSON.parse(await fs.readFile(reportPath, 'utf8'));
        return { payload, stderr: error.stderr || '', mode: 'docker' };
      } catch {
        if (/unexpected EOF|500 Internal Server Error|dockerDesktopLinuxEngine/i.test(`${error.stderr || ''} ${error.message || ''}`)) {
          throw new Error('Docker Desktop a interrompu le conteneur ZAP. Redémarrez le moteur et vérifiez les ressources mémoire avant de relancer ZAP uniquement.');
        }
        if (error.killed) throw new Error(`Le scan ZAP a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
        throw new Error(error.stderr?.trim() || error.message || 'Échec du scan ZAP.');
      }
    }
    report('COLLECTING_RESULTS', null, 'Lecture du rapport ZAP');
    return { payload: JSON.parse(await fs.readFile(reportPath, 'utf8')), stderr: '', mode: 'docker' };
  } finally {
    // Terminé, échoué ou annulé : aucun conteneur ZAP ne reste derrière.
    await removeZapContainer(containerName);
    await fs.rm(reportDirectory, { recursive: true, force: true });
  }
}

module.exports = { ZAP_SCAN_TIMEOUT_MS, ZAP_LOCAL_TIMEOUTS, runZap, removeZapContainer, validateLocalTarget, validateZapTarget, dockerTargetUrl, routeExclusionRegex, zapConfig, resolveWorkspaceFile, containerWorkspacePath, dockerArgs, checkTargetAvailable, resolveAuthLoginUrl, authenticateForZap, zapAuthEnv, valueAtPath };
