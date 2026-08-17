const https = require('https');

// Snyk's REST API is versioned by a dated query parameter. `/rest/self` is the
// cheapest authenticated endpoint: it answers with the identity behind the
// token, which is exactly what Security Center needs to say « jeton valide »
// without ever asking for organisation-wide permissions.
const SNYK_API_HOST = 'https://api.snyk.io';
const SNYK_API_VERSION = '2024-10-15';

const SNYK_ERROR_CODES = Object.freeze({
  AUTH_ERROR: 'AUTH_ERROR',
  CLI_MISSING: 'CLI_MISSING',
  DOCKER_MISSING: 'DOCKER_MISSING',
  CONFIG_ERROR: 'CONFIG_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  CANCELED: 'CANCELED',
  UNSUPPORTED: 'UNSUPPORTED',
  NO_PROJECTS: 'NO_PROJECTS',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  FEATURE_UNAVAILABLE: 'FEATURE_UNAVAILABLE',
  FAILED: 'FAILED'
});

class SnykError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SnykError';
    this.code = SNYK_ERROR_CODES[code] ? code : 'FAILED';
  }
}

/**
 * Last-resort scrubbing before any Snyk output reaches a log, a finding or the
 * webview. Snyk tokens are UUIDs, and the CLI echoes them in a few diagnostics,
 * so both the configured value and the generic shape are masked.
 */
function maskToken(text, token = '') {
  let value = String(text || '');
  const secret = String(token || '').trim();
  if (secret.length >= 8) value = value.split(secret).join('***');
  return value
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '***')
    .replace(/\b(SNYK_TOKEN|SNYK_CFG_API|api)\s*[=:]\s*\S+/gi, '$1=***');
}

/** Snyk tokens are UUID v4 API keys; anything else is rejected before storage. */
function looksLikeSnykToken(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

function abortError() {
  return new SnykError('CANCELED', 'Analyse Snyk annulée.');
}

/**
 * Authenticated Snyk REST call. The token travels only in the Authorization
 * header — never in the URL, never in a rejection message.
 */
function snykRequest(apiPath, { token = '', query = {}, timeoutMs = 15000, signal, apiHost = SNYK_API_HOST } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    let url;
    try {
      url = new URL(String(apiPath).replace(/^\/+/, ''), `${String(apiHost).replace(/\/+$/, '')}/`);
    } catch { return reject(new SnykError('CONFIG_ERROR', 'URL de l’API Snyk invalide.')); }
    url.searchParams.set('version', SNYK_API_VERSION);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
    const headers = { accept: 'application/vnd.api+json' };
    if (token) headers.authorization = `token ${token}`;
    const request = https.request(url, { method: 'GET', headers, timeout: timeoutMs }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const status = response.statusCode || 500;
        const text = Buffer.concat(chunks).toString('utf8');
        if (status === 401) return reject(new SnykError('AUTH_ERROR', 'Snyk a refusé le jeton (HTTP 401). Reconfigurez-le dans Security Center.'));
        if (status === 403) return reject(new SnykError('AUTH_ERROR', 'Le jeton Snyk n’a pas les droits nécessaires (HTTP 403).'));
        if (status >= 500) return reject(new SnykError('NETWORK_ERROR', `L’API Snyk a renvoyé une erreur interne (HTTP ${status}).`));
        if (status >= 400) return reject(new SnykError('FAILED', `L’API Snyk a répondu HTTP ${status}.`));
        try { resolve(text ? JSON.parse(text) : {}); }
        catch { reject(new SnykError('INVALID_RESPONSE', 'L’API Snyk a renvoyé une réponse JSON invalide.')); }
      });
    });
    const onAbort = () => request.destroy(abortError());
    signal?.addEventListener('abort', onAbort, { once: true });
    request.on('close', () => signal?.removeEventListener('abort', onAbort));
    request.on('timeout', () => request.destroy(new SnykError('TIMEOUT', `L’API Snyk ne répond pas après ${Math.round(timeoutMs / 1000)} secondes.`)));
    request.on('error', (error) => reject(error instanceof SnykError
      ? error
      : new SnykError('NETWORK_ERROR', 'L’API Snyk est injoignable. Vérifiez la connexion réseau.')));
    request.end();
  });
}

/**
 * Confirms the stored token is accepted. Returns `true`/`false` for a decided
 * answer and `null` when the verdict could not be established (network down),
 * so the UI never claims « jeton refusé » because the machine is offline.
 */
async function validateToken(token, { timeoutMs = 10000, signal, request = snykRequest } = {}) {
  if (!String(token || '').trim()) return false;
  try {
    await request('rest/self', { token, timeoutMs, signal });
    return true;
  } catch (error) {
    if (error instanceof SnykError && error.code === 'AUTH_ERROR') return false;
    if (error instanceof SnykError && error.code === 'CANCELED') throw error;
    return null;
  }
}

module.exports = {
  SNYK_API_HOST, SNYK_API_VERSION, SNYK_ERROR_CODES,
  SnykError, snykRequest, validateToken, maskToken, looksLikeSnykToken
};
