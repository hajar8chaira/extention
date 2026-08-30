'use strict';

const http = require('http');
const https = require('https');

class IntegrationHttpError extends Error {
  constructor(message, code = 'ERROR') {
    super(message);
    this.name = 'IntegrationHttpError';
    this.code = code;
  }
}

/**
 * A transport failure caused by certificate verification rather than by the
 * network. Node reports these as ordinary socket errors, so the wording is all
 * there is to go on — but telling them apart matters: « unreachable » and « I
 * refused this certificate » have completely different remedies.
 */
const CERTIFICATE_SIGNATURE = /self.signed|certificate|cert_|unable to verify|ssl|tls/i;

function isCertificateError(error) {
  return CERTIFICATE_SIGNATURE.test(String(error?.message || error || ''));
}

function scrubIntegrationError(message) {
  return String(message || 'Erreur reseau.')
    .replace(/\/\/[^@/\s]+@/g, '//')
    .replace(/(Basic|Bearer)\s+[A-Za-z0-9+/=._-]+/gi, '$1 [REDACTED]')
    .replace(/([?&](?:token|password|api[-_]?key|secret)=)[^&\s]+/gi, '$1[REDACTED]');
}

function normalizeIntegrationUrl(value, name = 'Integration') {
  const text = String(value || '').trim();
  if (!text) throw new Error(`Renseignez l'URL ${name}.`);
  let url;
  try { url = new URL(text); } catch { throw new Error(`URL ${name} invalide.`); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Seules les URL HTTP et HTTPS sont acceptees.');
  if (url.username || url.password) throw new Error("N'integrez pas d'identifiants dans l'URL. Les secrets restent dans SecretStorage.");
  url.hash = '';
  url.search = '';
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

function joinUrl(baseUrl, pathname, params = {}) {
  const url = new URL(`${normalizeIntegrationUrl(baseUrl)}/${String(pathname || '').replace(/^\/+/, '')}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value) !== '') url.searchParams.set(key, String(value));
  }
  return url.toString();
}

/**
 * `tls` is the only way to relax certificate verification, and it relaxes it
 * for ONE request. There is no global switch, no environment variable and no
 * default: a caller that passes nothing gets Node's strict behaviour, exactly
 * as before this option existed.
 */
function requestText(target, { method = 'GET', headers = {}, body = null, timeoutMs = 10000, maxBytes = 1024 * 1024, tls = null } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(target); } catch { return reject(new IntegrationHttpError('URL integration invalide.', 'INVALID_URL')); }
    const transport = url.protocol === 'https:' ? https : http;
    const requestOptions = { method, headers, timeout: timeoutMs };
    if (url.protocol === 'https:' && tls && tls.allowSelfSigned === true) requestOptions.rejectUnauthorized = false;
    const request = transport.request(url, requestOptions, (response) => {
      const status = response.statusCode || 500;
      if (status >= 300 && status < 400) {
        response.destroy();
        return reject(new IntegrationHttpError('Redirection refusee par Security Center.', 'REDIRECT'));
      }
      if (status === 401 || status === 403) {
        response.destroy();
        return reject(new IntegrationHttpError('Authentification refusee par le service externe.', 'AUTH_ERROR'));
      }
      if (status >= 400) {
        response.destroy();
        return reject(new IntegrationHttpError(`Service externe HTTP ${status}.`, 'HTTP_ERROR'));
      }
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          response.destroy();
          reject(new IntegrationHttpError('Reponse externe trop volumineuse.', 'TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    request.on('timeout', () => request.destroy(new IntegrationHttpError('Le service externe ne repond pas.', 'TIMEOUT')));
    request.on('error', (error) => {
      if (error instanceof IntegrationHttpError) reject(error);
      else reject(new IntegrationHttpError(scrubIntegrationError(error.message), /timeout/i.test(error.message) ? 'TIMEOUT' : 'OFFLINE'));
    });
    if (body !== null && body !== undefined) request.write(body);
    request.end();
  });
}

async function requestJson(target, options = {}) {
  const text = await requestText(target, { ...options, headers: { accept: 'application/json', ...(options.headers || {}) } });
  try { return text ? JSON.parse(text) : {}; }
  catch { throw new IntegrationHttpError('Le service externe a renvoye une reponse non JSON.', 'MALFORMED'); }
}

module.exports = {
  IntegrationHttpError,
  isCertificateError,
  normalizeIntegrationUrl,
  joinUrl,
  requestJson,
  requestText,
  scrubIntegrationError
};
