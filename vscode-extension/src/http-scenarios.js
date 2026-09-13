const crypto = require('crypto');
const http = require('http');
const https = require('https');

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']);
const MAX_BODY_LENGTH = 256 * 1024;
const READ_METHODS = new Set(['GET', 'HEAD']);
const CONTROLLED_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

const LOOPBACK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '::1']);

/** Replay decisions the model exposes, and the page will later render. */
const REPLAY_STATE = Object.freeze({
  ALLOWED: 'allowed',
  AUTHORIZATION_REQUIRED: 'authorization-required'
});

/**
 * A URL that can be recorded.
 *
 * Importing a HAR or receiving a Burp capture is passive: nothing is sent
 * anywhere. Refusing a remote address here rejected evidence about a test
 * environment the user is entitled to investigate, for no gain — the structural
 * checks, the redaction and the size limits are what protect this path, and
 * they are unchanged.
 */
function validateCapturedUrl(value) {
  let target;
  try {
    target = new URL(value);
  } catch {
    throw new Error('URL HTTP invalide.');
  }
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Seules les URL HTTP et HTTPS sont acceptées.');
  if (!target.hostname) throw new Error('URL HTTP invalide.');
  return target;
}

/** Whether a URL points at this machine. */
function isLocalScenarioHost(hostname) {
  return LOOPBACK_HOSTS.includes(String(hostname || '').toLowerCase().replace(/^\[|\]$/g, ''));
}

/**
 * The exact origin a replay would reach: scheme, host and port.
 *
 * Authorisation is granted against this string and nothing broader. Another
 * port on the same host is another origin, and needs its own confirmation.
 */
function replayOrigin(value) {
  const target = validateCapturedUrl(value);
  return target.origin;
}

/**
 * Whether this scenario may be sent, and why not when it may not.
 *
 * Local replay is unchanged and needs no confirmation. A remote origin must
 * have been confirmed for replay specifically — a ZAP scan authorisation is a
 * different decision about a different action, and is never read here.
 */
function replayAuthorization(scenario, { authorizedOrigins = [] } = {}) {
  const target = validateCapturedUrl(scenario?.request?.url);
  const origin = target.origin;
  const scope = isLocalScenarioHost(target.hostname) ? 'local' : 'remote';
  if (scope === 'local') return { state: REPLAY_STATE.ALLOWED, origin, scope };
  const authorized = (Array.isArray(authorizedOrigins) ? authorizedOrigins : [])
    .map((entry) => { try { return new URL(String(entry)).origin; } catch { return ''; } })
    .filter(Boolean);
  return {
    state: authorized.includes(origin) ? REPLAY_STATE.ALLOWED : REPLAY_STATE.AUTHORIZATION_REQUIRED,
    origin,
    scope
  };
}

/** Kept for callers that genuinely require a loopback address. */
function validateLocalUrl(value) {
  const target = validateCapturedUrl(value);
  if (!isLocalScenarioHost(target.hostname)) {
    throw new Error('Le replay MVP est limité aux applications locales autorisées.');
  }
  return target;
}

function normalizeHeaders(headers = []) {
  const normalized = {};
  const sensitiveHeaders = [];
  for (const header of headers) {
    const name = String(header.name || '').toLowerCase();
    if (!name) continue;
    if (SENSITIVE_HEADERS.has(name)) {
      normalized[name] = '[REDACTED]';
      sensitiveHeaders.push(name);
    } else {
      normalized[name] = String(header.value || '');
    }
  }
  return { headers: normalized, sensitiveHeaders };
}

function limitedBody(value) {
  const body = String(value || '');
  return body.length > MAX_BODY_LENGTH ? `${body.slice(0, MAX_BODY_LENGTH)}\n[TRUNCATED]` : body;
}

function bodySha256(body) {
  return crypto.createHash('sha256').update(String(body || '')).digest('hex');
}

function normalizeHarEntry(entry, index = 0) {
  const request = entry?.request || {};
  const response = entry?.response || {};
  const target = validateCapturedUrl(request.url);
  const requestHeaders = normalizeHeaders(request.headers);
  const responseHeaders = normalizeHeaders(response.headers);
  const responseBody = limitedBody(response.content?.text || '');
  return {
    name: `${request.method || 'GET'} ${target.pathname || '/'} #${index + 1}`,
    source: 'har',
    timestamp: entry.startedDateTime || '',
    request: {
      method: String(request.method || 'GET').toUpperCase(),
      url: target.toString(),
      headers: requestHeaders.headers,
      body: limitedBody(request.postData?.text || ''),
      sensitive_headers: requestHeaders.sensitiveHeaders
    },
    response: {
      statusCode: Number(response.status || 200),
      headers: responseHeaders.headers,
      body: responseBody,
      bodySha256: bodySha256(responseBody)
    },
    tags: ['imported', isLocalScenarioHost(target.hostname) ? 'local' : 'remote']
  };
}

function normalizeHar(payload) {
  const entries = payload?.log?.entries;
  if (!Array.isArray(entries)) throw new Error('Fichier HAR invalide : log.entries est absent.');
  const scenarios = [];
  const rejected = [];
  entries.forEach((entry, index) => {
    try {
      scenarios.push(normalizeHarEntry(entry, index));
    } catch (error) {
      rejected.push({ index, url: entry?.request?.url || '', error: error.message });
    }
  });
  return { scenarios, rejected };
}

function replayScenario(scenario, options = 30000) {
  const settings = typeof options === 'number' ? { timeoutMs: options } : (options || {});
  const timeoutMs = Number(settings.timeoutMs || 30000);
  const method = String(scenario?.request?.method || 'GET').toUpperCase();
  if (!READ_METHODS.has(method) && !CONTROLLED_WRITE_METHODS.has(method)) {
    throw new Error(`La méthode ${method} n’est pas autorisée pour le replay contrôlé.`);
  }
  if (CONTROLLED_WRITE_METHODS.has(method) && settings.allowWrite !== true) {
    throw new Error('Les méthodes POST/PUT/PATCH exigent une confirmation interactive et une autorisation auditée.');
  }
  const authorization = replayAuthorization(scenario, { authorizedOrigins: settings.authorizedOrigins });
  if (authorization.state !== REPLAY_STATE.ALLOWED) {
    throw new Error(`Replay refusé : l’origine distante ${authorization.origin} n’a pas été autorisée pour le replay HTTP.`);
  }
  const target = validateCapturedUrl(scenario.request.url);
  const transport = target.protocol === 'https:' ? https : http;
  const headers = Object.fromEntries(
    Object.entries(scenario.request.headers || {}).filter(([name, value]) => value !== '[REDACTED]' && !['host', 'content-length'].includes(name.toLowerCase()))
  );
  const requestBody = CONTROLLED_WRITE_METHODS.has(method) ? String(scenario.request.body || '') : '';
  if (Buffer.byteLength(requestBody) > MAX_BODY_LENGTH) throw new Error('Le corps de la requête dépasse la limite de 256 Kio.');
  if (requestBody) headers['content-length'] = Buffer.byteLength(requestBody);
  return new Promise((resolve, reject) => {
    const request = transport.request(target, { method, headers, timeout: timeoutMs }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const body = limitedBody(Buffer.concat(chunks).toString('utf8'));
        const digest = bodySha256(body);
        const original = scenario.response || {};
        resolve({
          replayedAt: new Date().toISOString(),
          statusCode: response.statusCode || 0,
          headers: response.headers,
          body,
          bodySha256: digest,
          comparison: {
            statusChanged: Number(original.statusCode || 0) !== Number(response.statusCode || 0),
            bodyChanged: Boolean(original.bodySha256) && original.bodySha256 !== digest,
            originalStatusCode: Number(original.statusCode || 0),
            originalBodySha256: original.bodySha256 || ''
          }
        });
      });
    });
    request.on('timeout', () => request.destroy(new Error('Le replay HTTP a dépassé le délai autorisé.')));
    request.on('error', reject);
    request.end(requestBody);
  });
}

module.exports = {
  validateLocalUrl, validateCapturedUrl, isLocalScenarioHost, replayOrigin, replayAuthorization,
  normalizeHeaders, bodySha256, normalizeHarEntry, normalizeHar, replayScenario,
  READ_METHODS, CONTROLLED_WRITE_METHODS, MAX_BODY_LENGTH, REPLAY_STATE, LOOPBACK_HOSTS
};
