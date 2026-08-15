const crypto = require('crypto');
const http = require('http');
const https = require('https');

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']);
const MAX_BODY_LENGTH = 256 * 1024;
const READ_METHODS = new Set(['GET', 'HEAD']);
const CONTROLLED_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

function validateLocalUrl(value) {
  let target;
  try {
    target = new URL(value);
  } catch {
    throw new Error('URL HTTP invalide.');
  }
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Seules les URL HTTP et HTTPS sont acceptées.');
  if (!['127.0.0.1', 'localhost', '::1'].includes(target.hostname)) {
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
  const target = validateLocalUrl(request.url);
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
    tags: ['imported', 'local']
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
  const target = validateLocalUrl(scenario.request.url);
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
  validateLocalUrl, normalizeHeaders, bodySha256, normalizeHarEntry, normalizeHar, replayScenario,
  READ_METHODS, CONTROLLED_WRITE_METHODS, MAX_BODY_LENGTH
};
