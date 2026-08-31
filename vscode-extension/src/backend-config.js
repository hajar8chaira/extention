'use strict';

/**
 * The Security Center backend, as a configured dependency.
 *
 * The local backend is what persists scans, audit events and HTTP scenarios.
 * It is *optional*: the extension scans, renders and corrects without it. What
 * it is not is invisible — before this module its address existed as the string
 * `http://127.0.0.1:8765` repeated at every call site, and its absence surfaced
 * as a raw `connect ECONNREFUSED 127.0.0.1:8765` with nothing to configure.
 *
 * Three things live here and nowhere else:
 *
 *   - THE DEFAULT. One constant. A port changed here is changed everywhere.
 *   - THE RESOLUTION. Settings first, default second, always normalized.
 *   - THE STATE. `/health` answered, refused, timed out, or replied something
 *     that is not this backend — four different facts with four different
 *     remedies, none of them « 0 results ».
 *
 * `ECONNREFUSED` is not masked and not softened. Nothing listening is the
 * correct answer to a service that was never started; the honest rendering of
 * it is OFFLINE with the address that was tried, not a functional zero.
 *
 * What this module does *not* do is decide whether a backend should exist, or
 * bring one up. That is `backend-manager.js`, which owns the mode, the process
 * and the port. This file stays the vocabulary both of them speak.
 */

const { checkBackend } = require('./backend');

/** The address a local backend claims first. The manager publishes the real one. */
const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8765';

/** The setting that overrides it. Declared once, read through `resolveBackendUrl`. */
const BACKEND_URL_SETTING = 'backend.url';

/**
 * What a health probe established.
 *
 * `INVALID_RESPONSE` exists because a socket that accepts and answers is not
 * proof of this backend: a proxy, a dev server or another service on a reused
 * port all connect successfully. Only `/health` naming the service does.
 */
const BACKEND_STATE = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  STARTING: 'starting',
  ONLINE: 'online',
  OFFLINE: 'offline',
  TIMEOUT: 'timeout',
  INVALID_RESPONSE: 'invalid-response',
  AUTH_ERROR: 'auth-error',
  ERROR: 'error'
});

const BACKEND_STATE_LABELS = Object.freeze({
  [BACKEND_STATE.NOT_CONFIGURED]: 'Non configuré',
  [BACKEND_STATE.STARTING]: 'Démarrage',
  [BACKEND_STATE.ONLINE]: 'En ligne',
  [BACKEND_STATE.OFFLINE]: 'Hors ligne',
  [BACKEND_STATE.TIMEOUT]: 'Délai dépassé',
  [BACKEND_STATE.INVALID_RESPONSE]: 'Réponse inattendue',
  [BACKEND_STATE.AUTH_ERROR]: 'Clé d’API refusée',
  [BACKEND_STATE.ERROR]: 'Erreur'
});

/**
 * What the user has to do about each state. Never « retry harder ».
 *
 * OFFLINE no longer names a command to run. The local backend is started by the
 * extension itself, so a user reading this hint is either in Remote mode — where
 * the address is the thing to check — or looking at a start that failed, which
 * says so in its own message.
 */
const BACKEND_STATE_HINTS = Object.freeze({
  [BACKEND_STATE.NOT_CONFIGURED]: 'Renseignez l’adresse du backend Security Center.',
  [BACKEND_STATE.STARTING]: 'Initialisation du service local…',
  [BACKEND_STATE.ONLINE]: '',
  [BACKEND_STATE.OFFLINE]: 'Aucun service n’écoute à cette adresse. Réessayez, ou vérifiez l’adresse configurée.',
  [BACKEND_STATE.TIMEOUT]: 'L’adresse est joignable mais ne répond pas dans le délai imparti.',
  [BACKEND_STATE.INVALID_RESPONSE]: 'Un service répond à cette adresse, mais ce n’est pas le backend Security Center.',
  [BACKEND_STATE.AUTH_ERROR]: 'Le backend a refusé la clé d’API configurée.',
  [BACKEND_STATE.ERROR]: 'Le service local n’a pas pu démarrer. Consultez le journal Security Center.'
});

/**
 * The compose command, kept for the Docker mode only.
 *
 * It is a development and integration-testing path now, not something a
 * Marketplace user is ever asked to run: it is shown when the backend mode is
 * explicitly set to Docker, and nowhere else.
 */
const DOCKER_BACKEND_START_COMMAND = 'docker compose -f docker-compose.backend.yml up -d';

/**
 * Validates and normalizes a backend address.
 *
 * Credentials embedded in the URL are refused: they would end up in settings,
 * in logs and in every error message. The API key belongs in SecretStorage.
 */
function normalizeBackendUrl(value) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error('Renseignez l’adresse du backend Security Center.');
  let url;
  try { url = new URL(text); } catch { throw new Error('Adresse de backend invalide.'); }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Seules les adresses HTTP et HTTPS sont acceptées.');
  }
  if (url.username || url.password) {
    throw new Error('N’intégrez pas d’identifiants dans l’adresse. La clé d’API est conservée dans le SecretStorage de VS Code.');
  }
  url.hash = '';
  url.search = '';
  return url.toString().replace(/\/+$/, '');
}

/**
 * THE resolution point for the backend address.
 *
 * Every caller goes through here. `configuration` is a VS Code configuration
 * object, or anything exposing `get(key, fallback)` — which is what makes this
 * testable without the editor.
 */
function resolveBackendUrl(configuration) {
  const raw = typeof configuration?.get === 'function'
    ? configuration.get(BACKEND_URL_SETTING, DEFAULT_BACKEND_URL)
    : DEFAULT_BACKEND_URL;
  try {
    return normalizeBackendUrl(raw);
  } catch {
    // A malformed setting must not take the whole extension down with it: the
    // default answers, and the probe will report what actually happens.
    return DEFAULT_BACKEND_URL;
  }
}

function isDefaultBackendUrl(value) {
  try { return normalizeBackendUrl(value) === DEFAULT_BACKEND_URL; } catch { return false; }
}

/** Reads a transport failure into a state. */
function classifyBackendError(error) {
  const message = String(error?.message || error || '');
  if (/ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|socket hang up|ne répond pas/i.test(message)) {
    return BACKEND_STATE.OFFLINE;
  }
  if (/ETIMEDOUT|EAI_AGAIN|ENOTFOUND|timeout|délai/i.test(message)) return BACKEND_STATE.TIMEOUT;
  if (/HTTP 401|HTTP 403|Invalid or missing Security Center API key/i.test(message)) return BACKEND_STATE.AUTH_ERROR;
  if (/JSON invalide|invalid json|Unexpected token/i.test(message)) return BACKEND_STATE.INVALID_RESPONSE;
  return BACKEND_STATE.OFFLINE;
}

/** A backend that answered `/health` the way this backend answers it. */
function isHealthPayload(payload) {
  return Boolean(payload)
    && typeof payload === 'object'
    && String(payload.status || '').toLowerCase() === 'ok'
    && String(payload.service || '').toLowerCase().includes('security-center');
}

/**
 * Probes the backend and describes the outcome.
 *
 * Uses the application-level `/health` endpoint the backend already exposes,
 * not a bare TCP connect: a successful socket proves a listener, not this
 * service. Never throws — a dependency that is down must degrade its own
 * capability and nothing else.
 */
async function probeBackend(baseUrl, { check = checkBackend } = {}) {
  let target;
  try {
    target = normalizeBackendUrl(baseUrl);
  } catch (error) {
    return describeBackend({ state: BACKEND_STATE.NOT_CONFIGURED, url: String(baseUrl || ''), message: error.message });
  }
  try {
    const payload = await check(target);
    if (!isHealthPayload(payload)) {
      return describeBackend({
        state: BACKEND_STATE.INVALID_RESPONSE, url: target,
        message: 'La réponse ne correspond pas au backend Security Center.'
      });
    }
    return describeBackend({
      state: BACKEND_STATE.ONLINE, url: target,
      service: String(payload.service || ''), version: String(payload.version || '')
    });
  } catch (error) {
    return describeBackend({
      state: classifyBackendError(error), url: target, message: String(error?.message || '')
    });
  }
}

/** The shape every surface reads. `online` is the only affirmative. */
function describeBackend({ state, url = '', message = '', service = '', version = '' } = {}) {
  return Object.freeze({
    state,
    label: BACKEND_STATE_LABELS[state] || state,
    hint: BACKEND_STATE_HINTS[state] || '',
    url,
    service,
    version,
    message,
    online: state === BACKEND_STATE.ONLINE,
    // No command to copy. Where a local backend is expected, the extension
    // starts it; a state that persists is a fault to report, not a chore to
    // delegate to the user.
    startCommand: ''
  });
}

module.exports = {
  DEFAULT_BACKEND_URL,
  BACKEND_URL_SETTING,
  BACKEND_STATE,
  BACKEND_STATE_LABELS,
  BACKEND_STATE_HINTS,
  DOCKER_BACKEND_START_COMMAND,
  normalizeBackendUrl,
  resolveBackendUrl,
  isDefaultBackendUrl,
  classifyBackendError,
  isHealthPayload,
  probeBackend,
  describeBackend
};
