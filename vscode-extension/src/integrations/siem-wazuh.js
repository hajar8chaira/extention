'use strict';

/**
 * Wazuh adapter.
 *
 * The network calls, the JWT exchange and the payload readers are the ones that
 * already worked — they are reused verbatim from `siem.js` rather than rewritten.
 * What is new is only the wrapper: Wazuh now answers the shared adapter contract,
 * so the Runtime Security page stops knowing that Wazuh exists.
 *
 * Configuration compatibility is a hard requirement: existing users keep
 * `securityCenter.wazuh.url` / `.username` and the same SecretStorage password.
 */

const { IntegrationHttpError, isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson, requestText, scrubIntegrationError } = require('./http');
const {
  CONNECTION_STATUS, CAPABILITY_STATE, buildRuntimeSecurityModel, statusFromError,
  validateAgainstFields, severityFromScale, normalizeEndpointStatus
} = require('./siem-contract');
const {
  INDEXER_ERROR, LIMITS, DATASET, createIndexerClient, candidatePaths, resolveFieldMap,
  missingRequiredFields, summaryQuery, searchQuery, alertSearchQuery, parseSummary, parseHits,
  indexerFailure, severityForLevel
} = require('./siem-indexer');
const { normalizeVulnerabilityRecord, normalizeVulnerabilityQuery } = require('./siem-vulnerabilities');

const ID = 'wazuh';
const LABEL = 'Wazuh';

/**
 * What Wazuh needs, declared rather than hardcoded in a form.
 * `secret: true` marks what must never leave SecretStorage.
 */
const CONFIGURATION_FIELDS = Object.freeze([
  { id: 'url', type: 'url', label: 'Wazuh API endpoint', placeholder: 'https://host:55000', required: true, hint: 'Manager API, usually port 55000.' },
  { id: 'username', type: 'text', label: 'Username', required: true },
  { id: 'password', type: 'password', label: 'Password', required: true, secret: true },
  // Independent of the Indexer option below, and off unless the user says so.
  // Many Manager deployments serve the API with their own CA-signed chain; the
  // ones that do not are a deliberate choice the user has to make explicitly.
  {
    id: 'allowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed Manager certificate',
    hint: 'Off by default. Enable only for a Manager whose certificate you explicitly trust; certificate identity verification is relaxed for this Manager connection only.'
  },

  // ---- Advanced: Wazuh Indexer -----------------------------------------
  // Optional on purpose. The Manager API alone is enough to connect and to read
  // agents and alerts, which is why none of these is required. Since Wazuh 4.8
  // the vulnerability state no longer comes from the Manager API — it lives in
  // the Indexer index `wazuh-states-vulnerabilities-*` — so this is the
  // connection that will unlock that capability. Nothing queries it yet.
  { id: 'indexerUrl', type: 'url', label: 'Indexer URL', placeholder: 'https://host:9200', group: 'advanced', hint: 'Optional. Enables vulnerability state and advanced runtime data.' },
  { id: 'indexerUsername', type: 'text', label: 'Indexer username', group: 'advanced' },
  { id: 'indexerPassword', type: 'password', label: 'Indexer password', group: 'advanced', secret: true },
  // Strict TLS is the default everywhere. This is the only way to relax it, it
  // is explicit, it is per-deployment, and it applies to Indexer requests only
  // — the Manager API path never reads it.
  {
    id: 'indexerAllowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed Indexer certificate',
    group: 'advanced',
    hint: 'Off by default. Only enable it for an Indexer whose certificate you trust: its identity is no longer verified.'
  }
]);

/**
 * Wazuh rule levels run 0-15.
 *
 * The thresholds live with the query builder so that a severity filter and a
 * severity badge can never disagree; this wrapper keeps the adapter's own
 * long-standing contract, including « anything not a positive number is INFO ».
 */
function wazuhLevelToSeverity(level) {
  const numeric = Number(level);
  if (!Number.isFinite(numeric) || numeric <= 0) return 'INFO';
  return severityForLevel(numeric);
}

/** Wazuh wraps collections in three different envelopes depending on route. */
function itemsOf(payload, fallbackKey) {
  if (Array.isArray(payload?.data?.affected_items)) return payload.data.affected_items;
  if (Array.isArray(payload?.data?.items)) return payload.data.items;
  if (Array.isArray(payload?.[fallbackKey])) return payload[fallbackKey];
  return [];
}

function extractMitreTechniques(rule = {}) {
  const mitre = rule.mitre || {};
  const values = [
    ...(Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : []),
    ...(Array.isArray(mitre.technique) ? mitre.technique : [])
  ];
  return [...new Set(values.map((item) => String(item || '').trim()).filter(Boolean))];
}

function endpointsFrom(payload) {
  return itemsOf(payload, 'agents').map((agent) => ({
    id: String(agent?.id || agent?.agent_id || ''),
    name: String(agent?.name || agent?.host || 'unknown-host'),
    hostname: String(agent?.host || agent?.name || ''),
    ip: String(agent?.ip || agent?.ip_address || ''),
    os: String(agent?.os?.name || agent?.os?.platform || agent?.os || ''),
    status: agent?.status,
    lastSeen: agent?.lastKeepAlive || agent?.last_seen || agent?.dateAdd || ''
  }));
}

function alertsFrom(payload) {
  return itemsOf(payload, 'alerts').map((alert, index) => {
    const rule = alert?.rule || {};
    const agent = alert?.agent || {};
    return {
      id: String(alert?.id || alert?._id || `${rule.id || 'rule'}:${alert?.timestamp || index}`),
      timestamp: alert?.timestamp || alert?.predecoder?.timestamp || '',
      severity: wazuhLevelToSeverity(rule.level),
      title: String(rule.description || alert?.title || 'Runtime security alert'),
      description: String(rule.description || alert?.full_log || ''),
      ruleId: String(rule.id || ''),
      source: ID,
      endpoint: String(agent.name || agent.host || alert?.host || ''),
      user: String(alert?.data?.srcuser || alert?.data?.dstuser || ''),
      mitreTechniques: extractMitreTechniques(rule),
      rawReference: String(alert?.id || alert?._id || ''),
      status: 'open'
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

/**
 * The Manager's own TLS decision, as request options.
 *
 * Returns nothing at all when the option is off, so the strict path stays
 * exactly the path it has always been. `=== true` is deliberate: a string, a
 * number or an object is not consent.
 */
function managerTlsOptions(config = {}) {
  return config.allowSelfSigned === true ? { tls: { allowSelfSigned: true } } : {};
}

/** Basic auth → short-lived JWT. The password never reaches a URL or a log. */
async function authenticate(baseUrl, username, password, { timeoutMs = 10000, requestTextImpl = requestText, tlsOptions = {} } = {}) {
  if (!username || !password) return '';
  const basic = Buffer.from(`${username}:${password}`).toString('base64');
  const body = await requestTextImpl(joinUrl(baseUrl, '/security/user/authenticate', { raw: 'true' }), {
    timeoutMs, headers: { authorization: `Basic ${basic}` }, ...tlsOptions
  });
  try {
    const parsed = JSON.parse(body);
    return parsed?.data?.token || parsed?.token || '';
  } catch {
    return String(body || '').trim();
  }
}

function notConfigured(baseUrl = '', message = '') {
  return buildRuntimeSecurityModel({
    provider: ID, label: LABEL, configured: Boolean(baseUrl), baseUrl,
    status: CONNECTION_STATUS.NOT_CONFIGURED, message
  });
}

/**
 * Reads the live state. A failure is a state, never an exception: Runtime
 * Security degrades on its own and nothing else in Security Center notices.
 */
async function fetchStatus(config = {}, secrets = {}, options = {}) {
  const {
    timeoutMs = 10000, request = requestJson, requestTextImpl = requestText
  } = options;
  const rawUrl = String(config.url || '').trim();
  if (!rawUrl) return notConfigured();

  let baseUrl = '';
  try { baseUrl = normalizeIntegrationUrl(rawUrl, LABEL); }
  catch (error) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl: rawUrl,
      status: CONNECTION_STATUS.INVALID_CONFIG, message: error.message, lastSync: new Date().toISOString()
    });
  }

  const username = String(config.username || '').trim();
  const password = String(secrets.password || '');
  const token = String(secrets.token || '');
  const credentialsConfigured = Boolean(token || (username && password));
  const lastSync = new Date().toISOString();
  if (!credentialsConfigured) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl,
      status: CONNECTION_STATUS.NOT_CONFIGURED,
      message: 'Identifiants Wazuh non configures.', lastSync, credentialsConfigured: false,
      relaxedTls: config.allowSelfSigned === true
    });
  }

  // The Manager's option, and nothing else: the Indexer's own flag lives in a
  // different field and is read by a different client.
  const tlsOptions = managerTlsOptions(config);
  try {
    const bearer = token || await authenticate(baseUrl, username, password, { timeoutMs, requestTextImpl, tlsOptions });
    const headers = bearer ? { authorization: `Bearer ${bearer}` } : {};
    // Two routes, both of which this API really has. Alert history is not one
    // of them: `analysisd` writes alerts to disk and they are shipped to the
    // Indexer, which is why they are fetched separately by `fetchAlerts()`.
    const [manager, rawAgents] = await Promise.all([
      request(joinUrl(baseUrl, '/manager/info'), { timeoutMs, headers, ...tlsOptions }),
      request(joinUrl(baseUrl, '/agents', { limit: 100 }), { timeoutMs, headers, ...tlsOptions })
    ]);
    const endpoints = endpointsFrom(rawAgents);
    const active = endpoints.filter((endpoint) => normalizeEndpointStatus(endpoint.status) === 'active').length;
    const degraded = endpoints.length > 0 && active < endpoints.length;
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured,
      status: degraded ? CONNECTION_STATUS.DEGRADED : CONNECTION_STATUS.ONLINE,
      version: String(manager?.data?.affected_items?.[0]?.version || manager?.data?.version || manager?.version || ''),
      endpoints,
      lastSync,
      relaxedTls: Boolean(tlsOptions.tls)
    });
  } catch (error) {
    return buildRuntimeSecurityModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured,
      status: statusFromError(error),
      // A rejected certificate is not « unreachable », and the raw Node wording
      // tells a user nothing they can act on. Naming the cause names the remedy.
      // A transport message reaches a user here, so it is scrubbed on the way
      // out as well as on the way in: URL credentials and Authorization values
      // are the two things that must never survive into a UI string.
      message: isCertificateError(error)
        ? `The ${LABEL} Manager certificate is not trusted. Enable the self-signed Manager option only if you trust this endpoint.`
        : scrubIntegrationError(error?.message || 'Wazuh est injoignable.'),
      lastSync,
      relaxedTls: Boolean(tlsOptions.tls)
    });
  }
}

/**
 * The Indexer connection for THIS deployment, assembled at call time.
 *
 * Nothing here is remembered between calls and nothing is defaulted to an
 * address: the user's configuration is the only source of truth, and an absent
 * URL simply means the capability is not configured.
 */
const ALERT_INDEX_MISSING = 'No Wazuh alert index was found on this Indexer.';
const ALERT_SCHEMA_UNSUPPORTED = 'The alert index does not expose a rule identifier field.';

function indexerConnection(config = {}, secrets = {}) {
  return {
    url: String(config.indexerUrl || '').trim(),
    username: String(config.indexerUsername || '').trim(),
    password: String(secrets.indexerPassword || ''),
    // A boolean is read as a boolean: any other value is not consent.
    allowSelfSigned: config.indexerAllowSelfSigned === true
  };
}

function vulnerabilityUnavailable(code, message = '', relaxedTls = false) {
  return {
    ok: false,
    state: code === INDEXER_ERROR.NOT_CONFIGURED ? CAPABILITY_STATE.REQUIRES_CONFIG : 'error',
    code,
    message: message || '',
    fieldMap: null,
    // Reported generically so no surface has to know what an Indexer is to
    // warn that this connection verifies less than the others.
    relaxedTls: relaxedTls === true
  };
}

/**
 * Does this deployment actually serve vulnerability state?
 *
 * Three questions, in order, and all three must be answered by the cluster:
 * can we authenticate, does an index of the family exist, and does it expose
 * enough of a schema to describe a vulnerability. Configuration alone answers
 * none of them, which is exactly why the capability cannot be promoted without
 * this call succeeding.
 *
 * An index that exists and holds no document is a *success*: an empty
 * deployment is a legitimate state, not a broken one.
 */
async function probeVulnerabilities(config = {}, secrets = {}, options = {}) {
  const connection = indexerConnection(config, secrets);
  if (!connection.url) return vulnerabilityUnavailable(INDEXER_ERROR.NOT_CONFIGURED);
  if (!connection.username && !connection.password) {
    return vulnerabilityUnavailable(INDEXER_ERROR.NOT_CONFIGURED);
  }

  let client;
  try {
    client = createIndexerClient({ ...connection, ...options });
  } catch (error) {
    const failure = indexerFailure(error);
    return vulnerabilityUnavailable(failure.code, failure.message, connection.allowSelfSigned);
  }

  try {
    // Bounded on purpose: only the candidate paths are asked about, never `*`.
    const capabilities = await client.fieldCaps(candidatePaths());
    const fieldMap = resolveFieldMap(capabilities);
    const indices = Array.isArray(capabilities?.indices) ? capabilities.indices.length : null;
    if (!Object.keys(fieldMap).length) {
      return vulnerabilityUnavailable(INDEXER_ERROR.INDEX_MISSING, '', connection.allowSelfSigned);
    }
    const missing = missingRequiredFields(fieldMap);
    if (missing.length) return vulnerabilityUnavailable(INDEXER_ERROR.UNSUPPORTED_SCHEMA, '', connection.allowSelfSigned);
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      fieldMap,
      indexCount: indices,
      relaxedTls: connection.allowSelfSigned
    };
  } catch (error) {
    const failure = indexerFailure(error);
    return vulnerabilityUnavailable(failure.code, failure.message, connection.allowSelfSigned);
  }
}

/**
 * One page of vulnerabilities plus the deployment-wide summary.
 *
 * Two cluster requests, whatever the number of agents: one aggregation for the
 * summary and the asset facets, one bounded search for the page. There is no
 * per-agent request because the Indexer already holds every agent's state.
 */
async function fetchVulnerabilities(config = {}, secrets = {}, options = {}) {
  const { fieldMap = null, query = {} } = options;
  const probe = fieldMap ? { ok: true, fieldMap } : await probeVulnerabilities(config, secrets, options);
  if (!probe.ok) return { ...probe, items: [], summary: null };

  const connection = indexerConnection(config, secrets);
  const normalized = normalizeVulnerabilityQuery(query, {
    defaultPageSize: LIMITS.DEFAULT_PAGE_SIZE, maxPageSize: LIMITS.MAX_PAGE_SIZE
  });
  let client;
  try {
    client = createIndexerClient({ ...connection, ...options });
  } catch (error) {
    return { ...indexerFailure(error), state: 'error', items: [], summary: null, relaxedTls: connection.allowSelfSigned };
  }

  try {
    const [summaryPayload, searchPayload] = await Promise.all([
      client.search(summaryQuery(probe.fieldMap, normalized)),
      client.search(searchQuery(probe.fieldMap, normalized))
    ]);
    const items = parseHits(searchPayload).map((hit, index) => normalizeVulnerabilityRecord(hit.source, probe.fieldMap, {
      provider: LABEL,
      providerFindingId: hit.id || String(index)
    }));
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      fieldMap: probe.fieldMap,
      summary: parseSummary(summaryPayload, probe.fieldMap),
      relaxedTls: connection.allowSelfSigned,
      items,
      page: normalized.page,
      pageSize: normalized.pageSize,
      total: parseSummary(searchPayload, probe.fieldMap).total
    };
  } catch (error) {
    const failure = indexerFailure(error);
    return { ok: false, state: 'error', code: failure.code, message: failure.message, items: [], summary: null, relaxedTls: connection.allowSelfSigned };
  }
}

/** One Indexer document → one normalized alert. Absent fields stay absent. */
function alertsFromIndexer(hits = [], fieldMap = {}) {
  const read = (source, key) => {
    const field = fieldMap[key];
    if (!field) return undefined;
    return String(field.path).split('.').reduce((value, segment) => (
      value === null || value === undefined ? undefined : value[segment]
    ), source);
  };
  const text = (value) => (value === null || value === undefined || typeof value === 'object' ? '' : String(value).trim());
  const list = (value) => (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value])
    .map((item) => text(item)).filter(Boolean);

  return hits.map((hit) => {
    const document = hit.source || {};
    const description = text(read(document, 'ruleDescription'));
    return {
      id: hit.id || '',
      timestamp: text(read(document, 'timestamp')),
      severity: wazuhLevelToSeverity(read(document, 'ruleLevel')),
      title: description || 'Runtime security alert',
      description: description || text(read(document, 'fullLog')),
      ruleId: text(read(document, 'ruleId')),
      source: ID,
      endpoint: text(read(document, 'assetName')) || text(read(document, 'assetId')),
      user: text(read(document, 'srcUser')) || text(read(document, 'dstUser')),
      mitreTechniques: [...new Set([...list(read(document, 'mitreIds')), ...list(read(document, 'mitreTechniques'))])],
      rawReference: hit.id || '',
      status: 'open'
    };
  });
}

/**
 * Does this deployment serve alert history?
 *
 * Same shape as the vulnerability probe, against a different index family and a
 * different candidate set — and answered by the cluster, not by configuration.
 */
async function probeAlerts(config = {}, secrets = {}, options = {}) {
  const connection = indexerConnection(config, secrets);
  if (!connection.url || (!connection.username && !connection.password)) {
    return vulnerabilityUnavailable(INDEXER_ERROR.NOT_CONFIGURED, '', connection.allowSelfSigned);
  }
  let client;
  try {
    client = createIndexerClient({ ...connection, ...options });
  } catch (error) {
    const failure = indexerFailure(error);
    return vulnerabilityUnavailable(failure.code, failure.message, connection.allowSelfSigned);
  }
  try {
    const capabilities = await client.fieldCaps(candidatePaths(DATASET.ALERTS), DATASET.ALERTS);
    const fieldMap = resolveFieldMap(capabilities, DATASET.ALERTS);
    if (!Object.keys(fieldMap).length) {
      return vulnerabilityUnavailable(INDEXER_ERROR.INDEX_MISSING, ALERT_INDEX_MISSING, connection.allowSelfSigned);
    }
    if (missingRequiredFields(fieldMap, DATASET.ALERTS).length) {
      return vulnerabilityUnavailable(INDEXER_ERROR.UNSUPPORTED_SCHEMA, ALERT_SCHEMA_UNSUPPORTED, connection.allowSelfSigned);
    }
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      fieldMap,
      relaxedTls: connection.allowSelfSigned
    };
  } catch (error) {
    const failure = indexerFailure(error);
    return vulnerabilityUnavailable(failure.code, failure.message, connection.allowSelfSigned);
  }
}

/**
 * One bounded window of recent alerts.
 *
 * A single search, sorted newest first, capped by the Indexer module. The page
 * then searches, filters and pages inside that window and says so — nothing
 * downloads an index.
 */
async function fetchAlerts(config = {}, secrets = {}, options = {}) {
  const probe = options.fieldMap ? { ok: true, fieldMap: options.fieldMap } : await probeAlerts(config, secrets, options);
  if (!probe.ok) return { ...probe, alerts: [] };

  const connection = indexerConnection(config, secrets);
  let client;
  try {
    client = createIndexerClient({ ...connection, ...options });
  } catch (error) {
    return { ...indexerFailure(error), state: 'error', alerts: [], relaxedTls: connection.allowSelfSigned };
  }
  try {
    const payload = await client.search(alertSearchQuery(probe.fieldMap, options.query || {}), DATASET.ALERTS);
    return {
      ok: true,
      state: CAPABILITY_STATE.READY,
      code: '',
      message: '',
      fieldMap: probe.fieldMap,
      relaxedTls: connection.allowSelfSigned,
      alerts: alertsFromIndexer(parseHits(payload), probe.fieldMap)
    };
  } catch (error) {
    const failure = indexerFailure(error);
    return { ok: false, state: 'error', code: failure.code, message: failure.message, alerts: [], relaxedTls: connection.allowSelfSigned };
  }
}

/** Test connection reaches the real provider — never a shortcut per provider. */
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
  wazuhAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Open-source XDR and SIEM platform.',
    docsHint: 'Manager API credentials with read access.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * Which capabilities each fetcher's outcome decides.
     *
     * MITRE techniques are read off the alert rules this adapter fetches, so a
     * working alert source is exactly what makes MITRE usable — and a failing
     * one is exactly what makes it unusable. That relationship is a fact about
     * Wazuh, not about SIEMs in general: another platform may serve techniques
     * from incidents, or from nothing at all. Declaring it here is what lets
     * generic orchestration stay ignorant of it.
     */
    capabilityFetchers: Object.freeze({
      fetchAlerts: Object.freeze(['alerts', 'mitre']),
      fetchVulnerabilities: Object.freeze(['vulnerabilities'])
    }),
    probeVulnerabilities,
    fetchVulnerabilities,
    probeAlerts,
    fetchAlerts,
    /**
     * What this adapter can serve TODAY.
     *
     * Only the three capabilities already backed by a real request are `ready`:
     * assets come from `/agents`. Alert history is not served by this API at
     * all — `analysisd` writes alerts to disk and they are shipped to the
     * search backend — so alerts, and the MITRE techniques read off their
     * rules, are proven by their own probe rather than declared here.
     *
     * `vulnerabilities` is deliberately `unavailable` rather than
     * `requires-config`: since Wazuh 4.8 the Manager API no longer serves
     * vulnerability state — it lives in the Indexer index
     * `wazuh-states-vulnerabilities-*` — and Security Center does not query it
     * yet. Declaring it available before the adapter exists would be exactly the
     * claim this contract is built to prevent.
     */
    capabilities: {
      // Alert history lives in the Indexer, so this capability needs the same
      // proof the others do: a successful probe, never a stored credential.
      alerts: CAPABILITY_STATE.REQUIRES_CONFIG,
      assets: CAPABILITY_STATE.READY,
      // Techniques are read off the alert rules, so MITRE lives and dies with
      // the alert source.
      mitre: CAPABILITY_STATE.REQUIRES_CONFIG,
      // Possible, not proven. The Indexer has to answer before this becomes
      // `ready`, and stored credentials are not an answer.
      vulnerabilities: CAPABILITY_STATE.REQUIRES_CONFIG,
      sca: CAPABILITY_STATE.UNAVAILABLE,
      fim: CAPABILITY_STATE.UNAVAILABLE,
      // Wazuh has no incident entity: offenses/incidents belong to other SIEMs.
      incidents: CAPABILITY_STATE.UNAVAILABLE,
      // Only a reference id is kept per alert, never the raw provider payload.
      rawEvents: CAPABILITY_STATE.UNAVAILABLE
    },
    validateConfiguration,
    testConnection,
    fetchStatus
  }),
  // Exported for the existing tests and for reuse by the registry.
  wazuhLevelToSeverity,
  extractMitreTechniques,
  endpointsFrom,
  alertsFrom,
  alertsFromIndexer,
  authenticate,
  severityFromScale
};
