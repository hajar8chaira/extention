'use strict';

/**
 * Elastic Security adapter.
 *
 * Elastic and Wazuh both involve a search engine, and that resemblance is a
 * trap. Wazuh's alerts are read from the Indexer directly, index pattern and
 * all; Elastic Security's are read through **Kibana**, whose Detections API
 * owns the alert index, the space routing and the permissions. This adapter
 * therefore talks to Kibana and never to Elasticsearch, and shares no query
 * builder, no index pattern and no field resolver with the Wazuh adapter.
 *
 * Verified against Elastic's published API before implementation:
 *
 *   - `POST /api/detection_engine/signals/search` accepts a body restricted to
 *     `query`, `aggs`, `size`, `sort`, `_source`, `fields`, `track_total_hits`
 *     and answers with the familiar `hits.hits` / `hits.total` shape.
 *   - There is no `from` and no `search_after` in that body, so there is no
 *     server-side pagination to offer. The adapter reads one bounded window and
 *     says so rather than pretending to page.
 *   - Alert documents carry `kibana.alert.*` fields; MITRE rides on
 *     `kibana.alert.rule.threat`.
 *
 * What this adapter deliberately does NOT claim: an asset inventory. Kibana
 * exposes no host-list API every deployment has, and aggregating `host.name`
 * out of alerts would describe « hosts that fired an alert », not an estate.
 * Calling that Assets would be the kind of half-truth this codebase keeps
 * removing, so the capability stays unavailable until a real source exists.
 */

const { IntegrationHttpError, isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson, scrubIntegrationError } = require('./http');
const {
  CONNECTION_STATUS, CAPABILITY_STATE, buildRuntimeSecurityModel, statusFromError,
  validateAgainstFields, normalizeSeverity
} = require('./siem-contract');

const ID = 'elastic';
const LABEL = 'Elastic Security';

/** The Detections API route this adapter uses, in one place. */
const ALERTS_PATH = '/api/detection_engine/signals/search';

/**
 * What Elastic Security needs.
 *
 * The endpoint is Kibana's, not Elasticsearch's — a frequent and expensive
 * confusion, so the label and hint say which one. API-key authentication is the
 * documented and recommended mechanism; basic auth exists in Elastic's docs but
 * is not implemented here rather than shipped untested.
 */
const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: 'url',
    label: 'Kibana endpoint',
    placeholder: 'https://host:5601',
    required: true,
    hint: 'Kibana, not Elasticsearch. Detection alerts are served by the Kibana Detections API.'
  },
  {
    id: 'apiKey',
    type: 'password',
    label: 'API key',
    required: true,
    secret: true,
    hint: 'A Kibana API key with read access to Security detection alerts.'
  },
  {
    id: 'space',
    type: 'text',
    label: 'Kibana space',
    group: 'advanced',
    hint: 'Optional. Only needed when detection alerts live outside the default space.'
  },
  {
    id: 'allowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed Kibana certificate',
    group: 'advanced',
    hint: 'Off by default. Enable only for an endpoint whose certificate you explicitly trust; certificate identity verification is relaxed for this connection only.'
  }
]);

/** One bounded read per refresh. No caller can ask for the whole index. */
const LIMITS = Object.freeze({ WINDOW: 100, MAX_WINDOW: 500, TIMEOUT_MS: 15000, MAX_BYTES: 1024 * 1024 });

const text = (value) => (value === null || value === undefined || typeof value === 'object' ? '' : String(value).trim());

/**
 * A Kibana space is a URL prefix, not a query parameter.
 *
 * The default space has no prefix at all, which is why an empty value must
 * produce an unprefixed path rather than `/s//api/...`.
 */
function spacePath(space, pathname) {
  const name = text(space);
  return name ? `/s/${encodeURIComponent(name)}${pathname}` : pathname;
}

function connectionFor(config = {}, secrets = {}) {
  return {
    url: text(config.url),
    apiKey: String(secrets.apiKey || ''),
    space: text(config.space),
    // A boolean is read as a boolean: any other value is not consent.
    allowSelfSigned: config.allowSelfSigned === true
  };
}

/**
 * Request options for one Kibana call.
 *
 * The key travels in the Authorization header and nowhere else — never a URL,
 * never a query parameter. `kbn-xsrf` is Kibana's convention for state-changing
 * requests; this search is a POST, so it is always sent.
 */
function requestOptionsFor(connection) {
  const options = {
    timeoutMs: LIMITS.TIMEOUT_MS,
    maxBytes: LIMITS.MAX_BYTES,
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'kbn-xsrf': 'true',
      authorization: `ApiKey ${connection.apiKey}`
    }
  };
  if (connection.allowSelfSigned) options.tls = { allowSelfSigned: true };
  return options;
}

/**
 * The alert query.
 *
 * `size` is capped here and nowhere else. Sorting is newest-first on the one
 * timestamp every alert document carries.
 */
function alertSearchBody({ limit = LIMITS.WINDOW } = {}) {
  const requested = Number(limit);
  const size = Math.min(Number.isFinite(requested) && requested > 0 ? requested : LIMITS.WINDOW, LIMITS.MAX_WINDOW);
  return {
    query: { match_all: {} },
    size,
    sort: [{ '@timestamp': { order: 'desc' } }],
    track_total_hits: true
  };
}

/** A probe asks the same question with no documents returned. */
function probeBody() {
  return { query: { match_all: {} }, size: 0, track_total_hits: true };
}

/**
 * MITRE techniques carried by the rule that fired.
 *
 * Elastic nests threats as `threat[].technique[]`, each with sub-techniques.
 * Identifiers and names are both taken because a deployment may populate
 * either; nothing is inferred when neither is present.
 */
function techniquesFrom(threat) {
  const entries = Array.isArray(threat) ? threat : threat ? [threat] : [];
  const found = [];
  for (const entry of entries) {
    const techniques = Array.isArray(entry?.technique) ? entry.technique : [];
    for (const technique of techniques) {
      const id = text(technique?.id);
      if (id) found.push(id);
      const subs = Array.isArray(technique?.subtechnique) ? technique.subtechnique : [];
      for (const sub of subs) {
        const subId = text(sub?.id);
        if (subId) found.push(subId);
      }
    }
  }
  return [...new Set(found)];
}

function readPath(source, path) {
  return String(path).split('.').reduce((value, segment) => (
    value === null || value === undefined ? undefined : value[segment]
  ), source);
}

/**
 * One Kibana alert document → one normalized alert.
 *
 * Every field is conditional: a document that does not carry a user, a host or
 * a technique produces a record without them rather than with a placeholder.
 */
function alertsFromKibana(hits = []) {
  return hits.map((hit) => {
    const document = hit?._source && typeof hit._source === 'object' ? hit._source : {};
    const ruleName = text(readPath(document, 'kibana.alert.rule.name'));
    const reason = text(readPath(document, 'kibana.alert.reason'));
    return {
      id: text(hit?._id),
      timestamp: text(document['@timestamp']),
      // Elastic's own vocabulary is low/medium/high/critical, which the shared
      // model already understands; nothing is re-scaled or re-scored here.
      severity: normalizeSeverity(readPath(document, 'kibana.alert.severity')),
      title: ruleName || 'Runtime security alert',
      description: reason || ruleName,
      ruleId: text(readPath(document, 'kibana.alert.rule.rule_id')) || text(readPath(document, 'kibana.alert.rule.uuid')),
      source: ID,
      endpoint: text(readPath(document, 'host.name')),
      user: text(readPath(document, 'user.name')),
      mitreTechniques: techniquesFrom(readPath(document, 'kibana.alert.rule.threat')),
      rawReference: text(hit?._id),
      status: text(readPath(document, 'kibana.alert.workflow_status'))
        || text(readPath(document, 'kibana.alert.status'))
        || 'open'
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

/** Error classes worth telling apart, because each has a different fix. */
const FAILURE_MESSAGES = Object.freeze({
  'not-configured': 'Elastic Security is not configured.',
  'invalid-config': 'The Kibana endpoint is not valid.',
  'auth-error': 'Kibana rejected this API key, or it lacks access to detection alerts.',
  'tls-error': 'The Kibana certificate was rejected. Enable the self-signed option only if you trust this endpoint.',
  'not-found': 'The Detections API was not found at this endpoint. Check that the URL points at Kibana, and at the right space.',
  'unreachable': 'Kibana is unreachable at this address.',
  timeout: 'Kibana did not answer in time.',
  malformed: 'Kibana returned an unexpected response.',
  'query-failed': 'The detection alert query failed on Kibana.'
});

function classifyFailure(error) {
  const code = String(error?.code || '');
  const raw = String(error?.message || '');
  if (code === 'AUTH_ERROR') return 'auth-error';
  if (code === 'TIMEOUT') return 'timeout';
  if (code === 'INVALID_URL') return 'invalid-config';
  if (code === 'MALFORMED' || code === 'TOO_LARGE') return 'malformed';
  if (code === 'HTTP_ERROR') return /\b404\b/.test(raw) ? 'not-found' : 'query-failed';
  if (code === 'OFFLINE') return isCertificateError({ message: raw }) ? 'tls-error' : 'unreachable';
  return 'query-failed';
}

function failure(code, relaxedTls = false) {
  return {
    ok: false,
    state: code === 'not-configured' ? CAPABILITY_STATE.REQUIRES_CONFIG : 'error',
    code,
    message: FAILURE_MESSAGES[code] || FAILURE_MESSAGES['query-failed'],
    relaxedTls: relaxedTls === true,
    alerts: []
  };
}

async function callDetections(connection, body, request) {
  const baseUrl = normalizeIntegrationUrl(connection.url, LABEL);
  return request(joinUrl(baseUrl, spacePath(connection.space, ALERTS_PATH)), {
    ...requestOptionsFor(connection),
    body: JSON.stringify(body)
  });
}

/**
 * Does this deployment serve detection alerts?
 *
 * One bounded question, answered by Kibana rather than by configuration: a key
 * that exists proves nothing, and a Kibana without the Security solution — or
 * with a key that cannot read alerts — is a real state, not a broken one.
 */
async function probeAlerts(config = {}, secrets = {}, options = {}) {
  const connection = connectionFor(config, secrets);
  if (!connection.url || !connection.apiKey) return failure('not-configured', connection.allowSelfSigned);
  const { request = requestJson } = options;
  try {
    const payload = await callDetections(connection, probeBody(), request);
    const total = payload?.hits?.total;
    const count = typeof total === 'number' ? total : Number(total?.value);
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      relaxedTls: connection.allowSelfSigned,
      total: Number.isFinite(count) ? count : null
    };
  } catch (error) {
    return failure(classifyFailure(error), connection.allowSelfSigned);
  }
}

/**
 * One bounded window of recent detection alerts.
 *
 * The Detections API accepts no `from` and no `search_after`, so there is no
 * server-side page to request. The window is read newest-first and the page
 * searches and filters within it, exactly as it does for any other provider
 * whose history is bounded.
 */
async function fetchAlerts(config = {}, secrets = {}, options = {}) {
  const connection = connectionFor(config, secrets);
  if (!connection.url || !connection.apiKey) return failure('not-configured', connection.allowSelfSigned);
  const { request = requestJson, query = {} } = options;
  try {
    const payload = await callDetections(connection, alertSearchBody({ limit: query.limit }), request);
    const hits = Array.isArray(payload?.hits?.hits) ? payload.hits.hits : [];
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      relaxedTls: connection.allowSelfSigned,
      alerts: alertsFromKibana(hits)
    };
  } catch (error) {
    return failure(classifyFailure(error), connection.allowSelfSigned);
  }
}

/**
 * Connection state.
 *
 * Elastic Security's health, for this integration, is « can Kibana answer for
 * detection alerts ». There is no asset inventory to report, so the model
 * carries none — an empty estate is not claimed, it is simply absent.
 */
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

  if (!connection.apiKey) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: false,
      status: CONNECTION_STATUS.NOT_CONFIGURED, message: 'Cle API Elastic non configuree.',
      lastSync, relaxedTls: connection.allowSelfSigned
    });
  }

  const probe = await probeAlerts(config, secrets, options);
  if (probe.ok) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
      status: CONNECTION_STATUS.ONLINE, lastSync, relaxedTls: connection.allowSelfSigned
    });
  }
  return buildRuntimeSecurityModel({
    provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
    status: probe.code === 'auth-error' ? CONNECTION_STATUS.AUTH_ERROR
      : probe.code === 'timeout' ? CONNECTION_STATUS.TIMEOUT
        : probe.code === 'unreachable' || probe.code === 'tls-error' ? CONNECTION_STATUS.OFFLINE
          : CONNECTION_STATUS.ERROR,
    // The message comes from the table above, never from the raw transport
    // error — that is the classic place for a key to leak into a UI string.
    message: scrubIntegrationError(probe.message),
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
  ALERTS_PATH,
  LIMITS,
  spacePath,
  alertSearchBody,
  probeBody,
  techniquesFrom,
  alertsFromKibana,
  classifyFailure,
  elasticAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Elastic SIEM detections and endpoint data.',
    docsHint: 'Kibana API key with read access to Security detection alerts.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * What this adapter can serve.
     *
     * Alerts and the MITRE techniques carried on them are the two capabilities
     * the Detections API genuinely backs. `assets` is absent on purpose: see
     * the note at the top of this file.
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
    /** Techniques ride on the alert documents, so they resolve together. */
    capabilityFetchers: Object.freeze({ fetchAlerts: Object.freeze(['alerts', 'mitre']) }),
    validateConfiguration,
    testConnection,
    fetchStatus,
    probeAlerts,
    fetchAlerts
  })
};
