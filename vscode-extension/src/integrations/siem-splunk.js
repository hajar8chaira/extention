'use strict';

/**
 * Splunk Enterprise Security adapter.
 *
 * Splunk is neither Wazuh nor Elastic: there is no document index to read and
 * no detections endpoint to call. Everything is a *search*, submitted to the
 * management API as SPL and answered by the search runtime. Verified against
 * Splunk's current documentation before implementation:
 *
 *   - management API on the frontend's management port, e.g. `https://host:8089`;
 *   - `POST /services/search/jobs` with **form-encoded** parameters, not JSON;
 *   - `exec_mode=oneshot` runs the search and returns its results directly, so
 *     no job id, no polling and no result fetch are needed for a bounded read
 *     — the asynchronous SID lifecycle exists and is the right tool for long
 *     searches, but it would be dishonest complexity for a capped window;
 *   - `output_mode=json` and `count` shape and bound the answer;
 *   - `Authorization: Bearer <token>` for programmatic access.
 *
 * Enterprise Security's own model, also verified: notable events live in
 * `index=notable`, carry `urgency` as their severity vocabulary, and expose
 * MITRE mappings under `annotations.mitre_attack.*`.
 *
 * What this adapter refuses to claim: an asset inventory. Hosts appear in
 * notable events as `src`/`dest`, which is « machines that appeared in an
 * alert », not an estate. Splunk's authoritative source for that is the Assets
 * and Identities framework, which not every deployment populates, so `assets`
 * stays unavailable rather than approximated.
 */

const { isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson } = require('./http');
const {
  CONNECTION_STATUS, CAPABILITY_STATE, buildRuntimeSecurityModel,
  validateAgainstFields, normalizeSeverity
} = require('./siem-contract');

const ID = 'splunk';
const LABEL = 'Splunk Enterprise Security';

/** The search endpoint, in one place. */
const SEARCH_PATH = '/services/search/jobs';

/**
 * The notable index is Enterprise Security's own, documented store. It is a
 * product fact, not a deployment choice, which is why it is not a setting.
 */
const NOTABLE_INDEX = 'notable';

const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: 'url',
    label: 'Splunk management endpoint',
    placeholder: 'https://host:8089',
    required: true,
    hint: 'The REST management interface, usually port 8089 — not the web interface on 8000.'
  },
  {
    id: 'token',
    type: 'password',
    label: 'Authentication token',
    required: true,
    secret: true,
    hint: 'A Splunk authentication token with permission to search the notable index.'
  },
  {
    id: 'allowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed certificate',
    group: 'advanced',
    hint: 'Off by default. Enable only for an endpoint whose certificate you explicitly trust; certificate identity verification is relaxed for this connection only.'
  }
]);

/** Hard bounds. No search may exceed them, whatever the caller asks for. */
const LIMITS = Object.freeze({
  WINDOW: 100,
  MAX_WINDOW: 500,
  EARLIEST: '-24h',
  TIMEOUT_MS: 20000,
  MAX_BYTES: 1024 * 1024
});

const text = (value) => (value === null || value === undefined || typeof value === 'object' ? '' : String(value).trim());

function connectionFor(config = {}, secrets = {}) {
  return {
    url: text(config.url),
    token: String(secrets.token || ''),
    // A boolean is read as a boolean: any other value is not consent.
    allowSelfSigned: config.allowSelfSigned === true
  };
}

/**
 * The bounded notable search.
 *
 * `head` caps what the search runtime produces and `count` caps what the API
 * returns; both are set so neither the server nor the transport is asked for
 * an unbounded result. The time window is explicit for the same reason.
 */
function notableSearch({ limit = LIMITS.WINDOW } = {}) {
  const requested = Number(limit);
  const size = Math.min(Number.isFinite(requested) && requested > 0 ? requested : LIMITS.WINDOW, LIMITS.MAX_WINDOW);
  return { size, spl: `search index=${NOTABLE_INDEX} | head ${size}` };
}

/**
 * Request options for one search.
 *
 * Splunk's REST API takes form-encoded parameters, not JSON — a detail that
 * silently produces an empty result set if got wrong. The token travels in the
 * Authorization header and nowhere else.
 */
function searchRequest(connection, { spl, size, offset = 0 }) {
  const parameters = new URLSearchParams({
    search: spl,
    exec_mode: 'oneshot',
    output_mode: 'json',
    earliest_time: LIMITS.EARLIEST,
    count: String(size),
    offset: String(offset)
  });
  const options = {
    method: 'POST',
    timeoutMs: LIMITS.TIMEOUT_MS,
    maxBytes: LIMITS.MAX_BYTES,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Bearer ${connection.token}`
    },
    body: parameters.toString()
  };
  if (connection.allowSelfSigned) options.tls = { allowSelfSigned: true };
  return options;
}

/** Error classes worth telling apart, because each has a different fix. */
const FAILURE_MESSAGES = Object.freeze({
  'not-configured': 'Splunk is not configured.',
  'invalid-config': 'The Splunk management endpoint is not valid.',
  'auth-error': 'Splunk rejected this token, or it lacks permission to search notable events.',
  'tls-error': 'The Splunk certificate was rejected. Enable the self-signed option only if you trust this endpoint.',
  'not-found': 'The search endpoint was not found. Check that the URL points at the management interface, usually port 8089.',
  unreachable: 'Splunk is unreachable at this address.',
  timeout: 'Splunk did not answer in time.',
  malformed: 'Splunk returned an unexpected response.',
  'search-failed': 'The notable search failed on Splunk.'
});

function classifyFailure(error) {
  const code = String(error?.code || '');
  const raw = String(error?.message || '');
  if (code === 'AUTH_ERROR') return 'auth-error';
  if (code === 'TIMEOUT') return 'timeout';
  if (code === 'INVALID_URL') return 'invalid-config';
  if (code === 'MALFORMED' || code === 'TOO_LARGE') return 'malformed';
  if (code === 'HTTP_ERROR') return /\b404\b/.test(raw) ? 'not-found' : 'search-failed';
  if (code === 'OFFLINE') return isCertificateError({ message: raw }) ? 'tls-error' : 'unreachable';
  return 'search-failed';
}

function failure(code, relaxedTls = false) {
  return {
    ok: false,
    state: code === 'not-configured' ? CAPABILITY_STATE.REQUIRES_CONFIG : 'error',
    code,
    message: FAILURE_MESSAGES[code] || FAILURE_MESSAGES['search-failed'],
    relaxedTls: relaxedTls === true,
    alerts: []
  };
}

/**
 * MITRE techniques, from Enterprise Security's own annotations.
 *
 * Only the technique identifier is taken. Tactics, descriptions and platforms
 * are also annotated but describe the mapping rather than the technique, and
 * nothing is derived from a rule name or a search title.
 */
function techniquesFrom(row = {}) {
  // Splunk's JSON output flattens field names to dotted keys, but a deployment
  // that returns the annotation as a real object is read just as happily.
  const raw = row['annotations.mitre_attack.mitre_technique_id']
    ?? row['annotations.mitre_attack']?.mitre_technique_id
    ?? row?.annotations?.mitre_attack?.mitre_technique_id;
  const values = Array.isArray(raw) ? raw : raw === undefined || raw === null ? [] : [raw];
  return [...new Set(values.map((value) => text(value)).filter(Boolean))];
}

/**
 * One notable event → one normalized alert.
 *
 * `urgency` is Enterprise Security's documented severity vocabulary, so it maps
 * straight onto the shared one. Risk scores are deliberately not converted:
 * they are a different measurement with their own scale, and turning a number
 * into a severity would be inventing a judgement.
 */
function alertsFromNotables(rows = []) {
  return rows.map((row, index) => {
    const title = text(row.rule_name) || text(row.search_name);
    return {
      id: text(row.event_id) || `${text(row.search_name) || 'notable'}:${text(row._time) || index}`,
      timestamp: text(row._time),
      severity: normalizeSeverity(row.urgency),
      title: title || 'Runtime security alert',
      description: text(row.rule_description) || title,
      ruleId: text(row.search_name) || text(row.rule_id),
      source: ID,
      // `dest` is the machine the notable is about; `src` is where it came
      // from. Neither is invented when the notable carries neither.
      endpoint: text(row.dest) || text(row.src) || text(row.host),
      user: text(row.user) || text(row.src_user),
      mitreTechniques: techniquesFrom(row),
      rawReference: text(row.event_id),
      status: text(row.status_label) || text(row.status) || 'open'
    };
  });
}

function validateConfiguration(config = {}) {
  const base = validateAgainstFields(CONFIGURATION_FIELDS, config);
  if (!base.valid) return base;
  try { normalizeIntegrationUrl(config.url, LABEL); }
  catch (error) { return { valid: false, errors: [error.message] }; }
  return { valid: true, errors: [] };
}

async function runSearch(connection, search, request) {
  const baseUrl = normalizeIntegrationUrl(connection.url, LABEL);
  return request(joinUrl(baseUrl, SEARCH_PATH), searchRequest(connection, search));
}

/**
 * Does this deployment serve notable events?
 *
 * One bounded search, answered by Splunk rather than by configuration. A token
 * that exists proves nothing: a deployment without Enterprise Security, or a
 * token without access to the notable index, is a real state.
 */
async function probeAlerts(config = {}, secrets = {}, options = {}) {
  const connection = connectionFor(config, secrets);
  if (!connection.url || !connection.token) return failure('not-configured', connection.allowSelfSigned);
  const { request = requestJson } = options;
  try {
    // A one-row search is the cheapest question that still proves access to
    // the index rather than merely to the endpoint.
    await runSearch(connection, { spl: `search index=${NOTABLE_INDEX} | head 1`, size: 1 }, request);
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      relaxedTls: connection.allowSelfSigned
    };
  } catch (error) {
    return failure(classifyFailure(error), connection.allowSelfSigned);
  }
}

/**
 * One bounded window of recent notable events.
 *
 * `exec_mode=oneshot` means the search runs and answers in the same request:
 * no job id leaves this file, and the generic layer never learns that Splunk
 * has a search lifecycle at all.
 */
async function fetchAlerts(config = {}, secrets = {}, options = {}) {
  const connection = connectionFor(config, secrets);
  if (!connection.url || !connection.token) return failure('not-configured', connection.allowSelfSigned);
  const { request = requestJson, query = {} } = options;
  try {
    const payload = await runSearch(connection, notableSearch({ limit: query.limit }), request);
    const rows = Array.isArray(payload?.results) ? payload.results : [];
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      relaxedTls: connection.allowSelfSigned,
      alerts: alertsFromNotables(rows)
    };
  } catch (error) {
    return failure(classifyFailure(error), connection.allowSelfSigned);
  }
}

/** Connection state: can Splunk answer a notable search. */
async function fetchStatus(config = {}, secrets = {}, options = {}) {
  const connection = connectionFor(config, secrets);
  const lastSync = new Date().toISOString();
  if (!connection.url) {
    return buildRuntimeSecurityModel({ provider: ID, label: LABEL, configured: false, status: CONNECTION_STATUS.NOT_CONFIGURED });
  }

  let baseUrl = '';
  try { baseUrl = normalizeIntegrationUrl(connection.url, LABEL); }
  catch (error) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl: connection.url,
      status: CONNECTION_STATUS.INVALID_CONFIG, message: error.message, lastSync
    });
  }

  if (!connection.token) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: false,
      status: CONNECTION_STATUS.NOT_CONFIGURED, message: 'Jeton Splunk non configure.',
      lastSync, relaxedTls: connection.allowSelfSigned
    });
  }

  const probe = await probeAlerts(config, secrets, options);
  return buildRuntimeSecurityModel({
    provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
    status: probe.ok ? CONNECTION_STATUS.ONLINE
      : probe.code === 'auth-error' ? CONNECTION_STATUS.AUTH_ERROR
        : probe.code === 'timeout' ? CONNECTION_STATUS.TIMEOUT
          : probe.code === 'unreachable' || probe.code === 'tls-error' || probe.code === 'not-found' ? CONNECTION_STATUS.OFFLINE
            : CONNECTION_STATUS.ERROR,
    // The message comes from the table above, never from the raw transport
    // error — that is the classic place for a token to leak into a UI string.
    message: probe.ok ? '' : probe.message,
    lastSync, relaxedTls: connection.allowSelfSigned
  });
}

/** Test connection reaches the real provider — never a shortcut. */
async function testConnection(config = {}, secrets = {}, options = {}) {
  const validation = validateConfiguration(config);
  if (!validation.valid) {
    return { ok: false, status: CONNECTION_STATUS.INVALID_CONFIG, message: validation.errors.join(' ') };
  }
  const model = await fetchStatus(config, secrets, options);
  const ok = model.connectionStatus === CONNECTION_STATUS.ONLINE || model.connectionStatus === CONNECTION_STATUS.DEGRADED;
  return { ok, status: model.connectionStatus, message: model.message, model };
}

module.exports = {
  SEARCH_PATH,
  NOTABLE_INDEX,
  LIMITS,
  notableSearch,
  searchRequest,
  techniquesFrom,
  alertsFromNotables,
  classifyFailure,
  splunkAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Splunk ES notable events and risk analysis.',
    docsHint: 'Management endpoint and an authentication token able to search notable events.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * What this adapter can serve.
     *
     * Notable events and the MITRE annotations carried on them. `assets` is
     * absent on purpose: see the note at the top of this file. `incidents` is
     * absent too — a notable *is* the alert here, and claiming both would count
     * one record twice.
     */
    capabilities: Object.freeze({
      alerts: CAPABILITY_STATE.REQUIRES_CONFIG,
      mitre: CAPABILITY_STATE.REQUIRES_CONFIG,
      assets: CAPABILITY_STATE.UNAVAILABLE,
      vulnerabilities: CAPABILITY_STATE.UNAVAILABLE,
      sca: CAPABILITY_STATE.UNAVAILABLE,
      fim: CAPABILITY_STATE.UNAVAILABLE,
      incidents: CAPABILITY_STATE.UNAVAILABLE,
      rawEvents: CAPABILITY_STATE.UNAVAILABLE
    }),
    capabilityFetchers: Object.freeze({ fetchAlerts: Object.freeze(['alerts', 'mitre']) }),
    validateConfiguration,
    testConnection,
    fetchStatus,
    probeAlerts,
    fetchAlerts
  })
};
