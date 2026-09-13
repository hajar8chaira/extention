const http = require('http');
const https = require('https');

/**
 * The dynamic target: what ZAP is pointed at, and under which mode.
 *
 * Two modes, kept explicit rather than inferred:
 *
 *   LOCAL  — loopback only. Unchanged from the original behaviour, and still
 *            the default: an existing workspace keeps working untouched.
 *   REMOTE — a lab VM, a test server, a staging environment. Allowed only when
 *            the user has explicitly confirmed being authorised to test it.
 *
 * The confirmation is a guard rail, not proof of anything. It exists so that a
 * remote scan is never something that merely happened.
 */

const TARGET_MODE = Object.freeze({ LOCAL: 'local', REMOTE: 'remote' });

/** Reachability outcomes, each one telling the user what to fix. */
const TARGET_STATE = Object.freeze({
  UNKNOWN: 'unknown',
  ONLINE: 'online',
  UNREACHABLE: 'unreachable',
  TIMEOUT: 'timeout',
  DNS_ERROR: 'dns-error',
  TLS_ERROR: 'tls-error',
  REFUSED: 'refused'
});

const TARGET_STATE_LABELS = Object.freeze({
  [TARGET_STATE.UNKNOWN]: 'Non vérifiée',
  [TARGET_STATE.ONLINE]: 'Accessible',
  [TARGET_STATE.UNREACHABLE]: 'Inaccessible',
  [TARGET_STATE.TIMEOUT]: 'Délai dépassé',
  [TARGET_STATE.DNS_ERROR]: 'Nom introuvable',
  [TARGET_STATE.TLS_ERROR]: 'Erreur TLS',
  [TARGET_STATE.REFUSED]: 'Connexion refusée'
});

const LOOPBACK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '::1', '[::1]']);

function normalizeMode(value) {
  return String(value || '').toLowerCase() === TARGET_MODE.REMOTE ? TARGET_MODE.REMOTE : TARGET_MODE.LOCAL;
}

/** Whether a URL points at this machine. Hostname only — never a guess. */
function isLoopbackHost(hostname) {
  return LOOPBACK_HOSTS.includes(String(hostname || '').toLowerCase());
}

/**
 * The scope a URL really has, independent of the configured mode.
 *
 * Used to tell the user « this address is not local » before anything is saved,
 * and to keep the Docker rewrite away from remote hosts.
 */
function targetScope(value) {
  try {
    return isLoopbackHost(new URL(String(value || '').trim()).hostname) ? TARGET_MODE.LOCAL : TARGET_MODE.REMOTE;
  } catch {
    return TARGET_MODE.LOCAL;
  }
}

/**
 * Validates a dynamic target and returns its canonical form.
 *
 * `mode` defaults to LOCAL, so every existing caller keeps the original
 * loopback-only contract. REMOTE accepts a hostname or an IP — including a
 * private one, which is precisely the lab case — but never a scheme other than
 * HTTP(S), never a malformed URL and never credentials in the URL.
 */
function normalizeTargetUrl(value, { mode = TARGET_MODE.LOCAL } = {}) {
  const input = String(value || '').trim();
  if (!input) return '';
  let url;
  try { url = new URL(input); } catch { throw new Error('URL de cible invalide.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('La cible doit utiliser HTTP ou HTTPS.');
  if (url.username || url.password) {
    throw new Error('N’intégrez pas d’identifiants dans l’URL de la cible. Utilisez un profil d’authentification.');
  }
  if (!url.hostname) throw new Error('URL de cible invalide.');
  if (normalizeMode(mode) === TARGET_MODE.LOCAL && !isLoopbackHost(url.hostname)) {
    throw new Error('La cible dynamique doit être locale. Choisissez le mode « distant » pour tester un environnement autorisé.');
  }
  return url.toString().replace(/\/$/, '');
}

/**
 * Whether a scan may start against this target.
 *
 * A remote target with no explicit authorisation is refused here, before any
 * engine is launched: the confirmation is a precondition of the run, not a
 * dialog that can be dismissed on the way.
 */
function assertTargetAuthorized(value, { mode = TARGET_MODE.LOCAL, remoteAuthorized = false } = {}) {
  const resolved = normalizeMode(mode);
  const url = normalizeTargetUrl(value, { mode: resolved });
  if (!url) throw new Error('Aucune cible dynamique configurée.');
  if (resolved === TARGET_MODE.REMOTE && remoteAuthorized !== true) {
    throw new Error('Cible distante non autorisée : confirmez disposer de l’autorisation nécessaire avant de lancer une analyse dynamique.');
  }
  return url;
}

/** Maps a socket failure onto the state that names it. */
function stateFromError(error) {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  if (code === 'ETIMEDOUT' || /timeout/i.test(message)) return TARGET_STATE.TIMEOUT;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return TARGET_STATE.DNS_ERROR;
  if (code === 'ECONNREFUSED') return TARGET_STATE.REFUSED;
  if (/^(CERT_|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS)/.test(code) || /certificate|self.signed|ssl|tls/i.test(message)) {
    return TARGET_STATE.TLS_ERROR;
  }
  return TARGET_STATE.UNREACHABLE;
}

/**
 * Probes the target without scanning it.
 *
 * One HEAD request. It answers « can this be reached, and what did it say »,
 * which is what a developer needs before committing to a dynamic scan. It never
 * starts an engine and never follows a redirect elsewhere.
 */
async function checkTargetReachability(value, timeoutMs = 3000, { mode = TARGET_MODE.LOCAL } = {}) {
  let targetUrl;
  try { targetUrl = normalizeTargetUrl(value, { mode }); }
  catch (error) { return { state: TARGET_STATE.UNREACHABLE, error: error.message }; }
  if (!targetUrl) return { state: TARGET_STATE.UNKNOWN };
  const client = targetUrl.startsWith('https:') ? https : http;
  return new Promise((resolve) => {
    const request = client.request(targetUrl, { method: 'HEAD', timeout: timeoutMs }, (response) => {
      response.resume();
      resolve({ state: TARGET_STATE.ONLINE, statusCode: response.statusCode, scope: targetScope(targetUrl) });
    });
    request.once('timeout', () => request.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    request.once('error', (error) => resolve({
      state: stateFromError(error),
      error: error.message,
      scope: targetScope(targetUrl)
    }));
    request.end();
  });
}

module.exports = {
  TARGET_MODE,
  TARGET_STATE,
  TARGET_STATE_LABELS,
  LOOPBACK_HOSTS,
  normalizeMode,
  isLoopbackHost,
  targetScope,
  normalizeTargetUrl,
  assertTargetAuthorized,
  stateFromError,
  checkTargetReachability
};
