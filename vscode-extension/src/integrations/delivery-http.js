'use strict';

/**
 * The HTTP transport shared by the API-based delivery adapters.
 *
 * `integrations/http.js` collapses 401, 403, 404 and 429 into two error codes.
 * GitLab and GitHub need them apart: a project that exists but is not readable,
 * a project that does not exist, and an exhausted rate limit call for three
 * different sentences to the developer. So this transport reports the status
 * instead of throwing on it, and throws only when there is no HTTP answer at
 * all.
 *
 * It holds no vendor knowledge: no endpoint, no authentication scheme, no
 * status vocabulary. Those live in each adapter.
 *
 * The token never reaches this file's output. It travels in a header supplied
 * by the adapter, and every transport error is scrubbed before it is returned.
 */

const http = require('http');
const https = require('https');

/** No HTTP answer at all: DNS, refused socket, timeout, unreadable body. */
class DeliveryTransportError extends Error {
  constructor(message, code = 'OFFLINE') {
    super(message);
    this.name = 'DeliveryTransportError';
    this.code = code;
  }
}

/** Strips anything credential-shaped from a transport error before it is shown. */
function scrubDeliveryError(message) {
  return String(message || 'Erreur réseau.')
    .replace(/\/\/[^@/\s]+@/g, '//')
    .replace(/(Basic|Bearer|token)\s+[A-Za-z0-9+/=._-]+/gi, '$1 [REDACTED]')
    .replace(/([?&](?:private_token|access_token|token|password)=)[^&\s]+/gi, '$1[REDACTED]');
}

/**
 * Validates the base URL of a delivery platform.
 *
 * Credentials embedded in the URL are refused: they would be persisted in
 * workspace settings and echoed in every error message.
 */
function normalizeDeliveryBaseUrl(value, label = 'du service') {
  const text = String(value || '').trim();
  if (!text) throw new Error(`Renseignez l’URL ${label}.`);
  let url;
  try { url = new URL(text); } catch { throw new Error(`URL ${label} invalide.`); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Seules les URL HTTP et HTTPS sont acceptées.');
  if (url.username || url.password) {
    throw new Error('N’intégrez pas d’identifiants dans l’URL. Le jeton est conservé dans le SecretStorage de VS Code.');
  }
  url.hash = '';
  url.search = '';
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

/** Builds a URL from a base, a path and query parameters, encoding each part. */
function deliveryUrl(baseUrl, pathname, params = {}, label = 'du service') {
  const url = new URL(`${normalizeDeliveryBaseUrl(baseUrl, label)}/${String(pathname || '').replace(/^\/+/, '')}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value) !== '') url.searchParams.set(key, String(value));
  }
  return url.toString();
}

const MAX_BYTES = 2 * 1024 * 1024;

/**
 * Performs one GET and reports the answer, status included.
 *
 * Returns `{ status, headers, body }`; `body` is the parsed JSON, or `null`
 * when the payload was empty or not JSON — an adapter decides what a
 * non-JSON answer means for it. Redirects are refused rather than followed:
 * an authenticated request must not be replayed against another host.
 *
 * `request` replaces the transport entirely, which is what the tests use to
 * exercise real provider payloads without a network.
 */
async function deliveryGetJson(target, { headers = {}, timeoutMs = 10000, request = null } = {}) {
  if (typeof request === 'function') return request(target, { headers, timeoutMs });
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(target); } catch { return reject(new DeliveryTransportError('URL invalide.', 'INVALID_URL')); }
    const transport = url.protocol === 'https:' ? https : http;
    const call = transport.request(url, { method: 'GET', headers, timeout: timeoutMs }, (response) => {
      const status = response.statusCode || 500;
      if (status >= 300 && status < 400) {
        response.destroy();
        return reject(new DeliveryTransportError('Redirection refusée par Security Center.', 'REDIRECT'));
      }
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          response.destroy();
          reject(new DeliveryTransportError('Réponse trop volumineuse.', 'TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body = null;
        try { body = text ? JSON.parse(text) : null; } catch { body = null; }
        resolve({ status, headers: response.headers || {}, body });
      });
    });
    call.on('timeout', () => call.destroy(new DeliveryTransportError('Le service ne répond pas.', 'TIMEOUT')));
    call.on('error', (error) => {
      if (error instanceof DeliveryTransportError) return reject(error);
      const message = scrubDeliveryError(error.message);
      reject(new DeliveryTransportError(message, /timeout/i.test(String(error.message)) ? 'TIMEOUT' : 'OFFLINE'));
    });
    call.end();
  });
}

/** Milliseconds between two provider timestamps, or null when either is absent. */
function durationBetween(startedAt, finishedAt) {
  const start = Date.parse(String(startedAt || ''));
  const end = Date.parse(String(finishedAt || ''));
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  return end - start;
}

module.exports = {
  DeliveryTransportError,
  scrubDeliveryError,
  normalizeDeliveryBaseUrl,
  deliveryUrl,
  deliveryGetJson,
  durationBetween,
  MAX_BYTES
};
