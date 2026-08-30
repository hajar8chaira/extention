'use strict';

/**
 * Datadog, and nothing generic.
 *
 * Datadog is neither Prometheus nor Zabbix: hosts come from a paginated
 * inventory endpoint rather than a scrape-target list or a JSON-RPC call, and
 * metrics come from a timeseries query language of its own. Verified against
 * Datadog's current documentation before implementation:
 *
 *   - `GET /api/v1/hosts` lists the infrastructure, paginated by `start` and
 *     `count`, answering `host_list[]` with `host_name`, `up` and
 *     `last_reported_time`;
 *   - `GET /api/v1/query` takes `from`, `to` (Unix seconds) and `query`, and
 *     answers `series[]` of `{ metric, scope, pointlist: [[ts, value], …] }`;
 *   - authentication needs **two** credentials, `DD-API-KEY` and
 *     `DD-APPLICATION-KEY`. Datadog documents passing them as query parameters
 *     too; this adapter only ever sends headers, because a key in a URL is a
 *     key in a log.
 *
 * Datadog runs on several regional sites, so the API base is configuration
 * rather than a constant — and it is asked for as a URL rather than as a region
 * name, so no mapping table has to be invented or kept current.
 */

const { isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson } = require('./http');
const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON, SECTION_KIND,
  unavailableMetric, availableMetric, buildInfrastructureModel, validateAgainstFields
} = require('./observability-contract');

const ID = 'datadog';
const LABEL = 'Datadog';

const HOSTS_PATH = '/api/v1/hosts';
const QUERY_PATH = '/api/v1/query';

const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: 'url',
    label: 'Datadog API site',
    placeholder: 'https://api.datadoghq.com',
    required: true,
    hint: 'The API base for your Datadog site. EU, US3, US5, AP1 and government sites each have their own.'
  },
  {
    id: 'apiKey',
    type: 'password',
    label: 'API key',
    required: true,
    secret: true,
    hint: 'Sent as a request header, never stored in settings and never rendered back.'
  },
  {
    id: 'applicationKey',
    type: 'password',
    label: 'Application key',
    required: true,
    secret: true,
    hint: 'Required alongside the API key to read hosts and query metrics.'
  }
]);

/** Hard bounds. No read may exceed them, whatever the estate's size. */
const LIMITS = Object.freeze({
  HOSTS: 200,
  WINDOW_SECONDS: 300,
  TIMEOUT_MS: 15000,
  MAX_BYTES: 1024 * 1024
});

/**
 * The metric queries, per capability.
 *
 * These are the Datadog Agent's core host metrics. `transform` turns each
 * provider convention into the used-percentage the tile shows: idle time and
 * usable memory are both reported as the *free* share.
 *
 * Disk is the case worth reading twice. `system.disk.in_use` is a fraction per
 * device, and averaging fractions across devices of different sizes invents a
 * number — the mistake this domain has already made once. Datadog also reports
 * `system.disk.used` and `system.disk.total` in bytes, so the honest figure is
 * their weighted ratio, summed server-side before it ever arrives here.
 */
const METRIC_QUERIES = Object.freeze({
  [CAPABILITY.CPU]: Object.freeze({
    queries: Object.freeze([{ id: 'idle', expression: (host) => `avg:system.cpu.idle{host:${host}}` }]),
    combine: ({ idle }) => (idle === null ? null : 100 - idle),
    unit: '%'
  }),
  [CAPABILITY.MEMORY]: Object.freeze({
    // `pct_usable` is a fraction of 1, not a percentage.
    queries: Object.freeze([{ id: 'usable', expression: (host) => `avg:system.mem.pct_usable{host:${host}}` }]),
    combine: ({ usable }) => (usable === null ? null : (1 - usable) * 100),
    unit: '%'
  }),
  [CAPABILITY.DISK]: Object.freeze({
    queries: Object.freeze([
      { id: 'used', expression: (host) => `sum:system.disk.used{host:${host}}` },
      { id: 'total', expression: (host) => `sum:system.disk.total{host:${host}}` }
    ]),
    // Bytes over bytes: a weighted ratio, never an average of percentages.
    combine: ({ used, total }) => (used === null || total === null || !(total > 0) ? null : (used / total) * 100),
    unit: '%'
  }),
  [CAPABILITY.LOAD]: Object.freeze({
    queries: Object.freeze([{ id: 'load', expression: (host) => `avg:system.load.1{host:${host}}` }]),
    combine: ({ load }) => load,
    unit: ''
  })
});

const text = (value) => (value === null || value === undefined || typeof value === 'object' ? '' : String(value).trim());

function connectionFor(config = {}, secrets = {}) {
  return {
    url: text(config.url),
    apiKey: String(secrets.apiKey || ''),
    applicationKey: String(secrets.applicationKey || '')
  };
}

/**
 * Request options for one call.
 *
 * Both credentials travel as headers. Datadog documents a query-parameter form
 * as well; it is not used, because a URL is the one place a secret must never
 * appear.
 */
function requestOptionsFor(connection) {
  return {
    timeoutMs: LIMITS.TIMEOUT_MS,
    maxBytes: LIMITS.MAX_BYTES,
    headers: {
      'dd-api-key': connection.apiKey,
      'dd-application-key': connection.applicationKey
    }
  };
}

/** Error classes worth telling apart, because each has a different fix. */
const FAILURE_MESSAGES = Object.freeze({
  'not-configured': 'Datadog is not configured.',
  'invalid-config': 'The Datadog API site is not a valid URL.',
  'auth-error': 'Datadog rejected these keys, or they lack read access to hosts and metrics.',
  'tls-error': 'The Datadog certificate was rejected.',
  'not-found': 'The Datadog API was not found at this address. Check the site for your organisation.',
  unreachable: 'Datadog is unreachable at this address.',
  timeout: 'Datadog did not answer in time.',
  'rate-limited': 'Datadog is rate-limiting these requests. Try again shortly.',
  malformed: 'Datadog returned an unexpected response.',
  'query-failed': 'The Datadog query failed.'
});

function classifyFailure(error) {
  const code = String(error?.code || '');
  const raw = String(error?.message || '');
  if (code === 'AUTH_ERROR') return 'auth-error';
  if (code === 'TIMEOUT') return 'timeout';
  if (code === 'INVALID_URL') return 'invalid-config';
  if (code === 'MALFORMED' || code === 'TOO_LARGE') return 'malformed';
  if (code === 'HTTP_ERROR') {
    // Datadog answers 429 when an organisation exceeds its API allowance; that
    // is a « come back later », not a broken integration.
    if (/\b429\b/.test(raw)) return 'rate-limited';
    return /\b404\b/.test(raw) ? 'not-found' : 'query-failed';
  }
  if (code === 'OFFLINE') return isCertificateError({ message: raw }) ? 'tls-error' : 'unreachable';
  return 'query-failed';
}

const failureMessage = (code) => FAILURE_MESSAGES[code] || FAILURE_MESSAGES['query-failed'];

function connectionStatusFor(code) {
  if (code === 'auth-error') return PROVIDER_STATUS.AUTH_ERROR;
  if (code === 'timeout') return PROVIDER_STATUS.TIMEOUT;
  if (code === 'unreachable' || code === 'tls-error' || code === 'not-found') return PROVIDER_STATUS.OFFLINE;
  if (code === 'invalid-config') return PROVIDER_STATUS.QUERY_ERROR;
  return PROVIDER_STATUS.DEGRADED;
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

function entitiesFrom(payload) {
  const hosts = Array.isArray(payload?.host_list) ? payload.host_list : [];
  return hosts.map((host) => ({
    id: text(host?.name) || text(host?.host_name),
    name: text(host?.host_name) || text(host?.name),
    type: 'host',
    // `up` is a real boolean here; anything else is « not reported », which is
    // not the same as « down ».
    status: host?.up === true ? 'available' : host?.up === false ? 'unavailable' : '',
    endpoint: '',
    lastSeen: host?.last_reported_time ? new Date(Number(host.last_reported_time) * 1000).toISOString() : ''
  })).filter((entity) => entity.id);
}

function inventoryFrom(entities = []) {
  const total = entities.length;
  const signalled = entities.filter((entity) => entity.status === 'available' || entity.status === 'unavailable');
  if (!signalled.length) {
    return { known: true, up: null, total, display: `${total} host${total === 1 ? '' : 's'}` };
  }
  const up = entities.filter((entity) => entity.status === 'available').length;
  return { known: true, up, total, display: `${up}/${total} UP` };
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/**
 * The most recent point of a timeseries answer.
 *
 * Datadog returns `pointlist` oldest-first and may include trailing points with
 * a null value while a bucket is still filling; the latest *real* value is what
 * the tile should show, and an answer with no real value is no value.
 */
function latestPoint(payload) {
  const series = Array.isArray(payload?.series) ? payload.series : [];
  let latest = null;
  for (const entry of series) {
    const points = Array.isArray(entry?.pointlist) ? entry.pointlist : [];
    for (const point of points) {
      const raw = point?.[1];
      // `Number(null)` is `0`, and a null bucket is exactly what Datadog sends
      // for a gap. Rejecting it before the conversion is what stops a gap from
      // being displayed as a measurement of zero.
      if (raw === null || raw === undefined || raw === '') continue;
      const value = Number(raw);
      const stamp = Number(point?.[0]);
      if (!Number.isFinite(value) || !Number.isFinite(stamp)) continue;
      if (!latest || stamp >= latest.stamp) latest = { stamp, value };
    }
  }
  return latest ? latest.value : null;
}

function shapeMetric(value, unit) {
  if (value === null) return null;
  return unit === '%'
    ? availableMetric(value, `${Math.round(value)}%`)
    : availableMetric(value, String(Math.round(value * 100) / 100));
}

function validateConfiguration(config = {}) {
  const base = validateAgainstFields(CONFIGURATION_FIELDS, config);
  if (!base.valid) return base;
  try { normalizeIntegrationUrl(config.url, LABEL); }
  catch (error) { return { valid: false, errors: [error.message] }; }
  return { valid: true, errors: [] };
}

function selectEntity(ids, requested = '') {
  const wanted = text(requested);
  if (wanted && ids.includes(wanted)) return { entity: wanted, selectionRequired: false };
  if (ids.length === 1) return { entity: ids[0], selectionRequired: false };
  return { entity: '', selectionRequired: ids.length > 1 };
}

/**
 * Reads Datadog.
 *
 * The inventory proves the connection; each metric capability is then read on
 * its own so one failing query degrades only what it backs. A capability whose
 * query answered with no points is `unavailable` — the deployment does not
 * report it — while a query that failed is `error`. They are different facts.
 */
async function fetchStatus(config = {}, secrets = {}, options = {}) {
  const { request = requestJson, entity = '', now = Date.now() } = options;
  const connection = connectionFor(config, secrets);
  const lastChecked = new Date(now).toISOString();

  if (!connection.url || !connection.apiKey || !connection.applicationKey) {
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: Boolean(connection.url),
      status: PROVIDER_STATUS.NOT_CONFIGURED,
      message: connection.url ? failureMessage('not-configured') : '',
      credentialsConfigured: Boolean(connection.apiKey && connection.applicationKey)
    });
  }

  let baseUrl = '';
  try { baseUrl = normalizeIntegrationUrl(connection.url, LABEL); }
  catch (error) {
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: true, baseUrl: connection.url,
      status: PROVIDER_STATUS.QUERY_ERROR, message: error.message, lastChecked
    });
  }

  const requestOptions = requestOptionsFor(connection);

  // --- the inventory: this is what proves the connection -------------------
  let entities = [];
  try {
    const payload = await request(joinUrl(baseUrl, HOSTS_PATH, { start: 0, count: LIMITS.HOSTS }), requestOptions);
    entities = entitiesFrom(payload);
  } catch (error) {
    const code = classifyFailure(error);
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
      status: connectionStatusFor(code),
      // The message comes from the table, never from the raw error — that is
      // the classic place for a key to leak into a UI string.
      message: failureMessage(code),
      capabilities: { [CAPABILITY.HOST_INVENTORY]: RESOLVED_STATE.ERROR },
      failures: [{ capability: CAPABILITY.HOST_INVENTORY, code }],
      lastChecked
    });
  }

  const inventory = inventoryFrom(entities);
  const ids = entities.map((item) => item.id);
  const { entity: selectedEntity, selectionRequired } = selectEntity(ids, entity);
  const capabilities = { [CAPABILITY.HOST_INVENTORY]: RESOLVED_STATE.READY };
  const metrics = {};
  const failures = [];

  if (!selectedEntity) {
    // No host chosen and several offered: ask, never guess.
    for (const capability of Object.keys(METRIC_QUERIES)) {
      metrics[capability] = unavailableMetric(METRIC_REASON.ENTITY_NOT_SELECTED);
      capabilities[capability] = RESOLVED_STATE.READY;
    }
  } else {
    const to = Math.floor(now / 1000);
    const from = to - LIMITS.WINDOW_SECONDS;
    await Promise.all(Object.entries(METRIC_QUERIES).map(async ([capability, definition]) => {
      const readings = {};
      let failed = false;
      await Promise.all(definition.queries.map(async (query) => {
        try {
          const payload = await request(
            joinUrl(baseUrl, QUERY_PATH, { from, to, query: query.expression(selectedEntity) }),
            requestOptions
          );
          readings[query.id] = latestPoint(payload);
        } catch (error) {
          failed = true;
          failures.push({ capability, code: classifyFailure(error) });
        }
      }));

      if (failed) {
        metrics[capability] = unavailableMetric(METRIC_REASON.QUERY_FAILED);
        capabilities[capability] = RESOLVED_STATE.ERROR;
        return;
      }
      const combined = definition.combine(Object.fromEntries(
        definition.queries.map((query) => [query.id, readings[query.id] ?? null])
      ));
      const metric = shapeMetric(combined, definition.unit);
      metrics[capability] = metric || unavailableMetric(METRIC_REASON.NOT_EXPORTED);
      capabilities[capability] = metric ? RESOLVED_STATE.READY : RESOLVED_STATE.UNAVAILABLE;
    }));
  }

  const degraded = failures.length > 0 || selectionRequired
    || (Number.isFinite(inventory.up) && inventory.total > 0 && inventory.up < inventory.total);
  return buildInfrastructureModel({
    provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
    status: degraded ? PROVIDER_STATUS.DEGRADED : PROVIDER_STATUS.HEALTHY,
    message: selectionRequired
      ? 'Plusieurs hotes sont surveilles : choisissez celui a afficher.'
      : (failures.length ? 'Certaines lectures Datadog sont indisponibles.' : ''),
    entities, inventory,
    targets: { ...inventory, items: entities, selectedHost: selectedEntity },
    selectedEntity, selectionRequired,
    metrics, capabilities, failures, lastChecked
  });
}

/** Test connection reaches the real provider — never a shortcut. */
async function testConnection(config = {}, secrets = {}, options = {}) {
  const validation = validateConfiguration(config);
  if (!validation.valid) {
    return { ok: false, status: PROVIDER_STATUS.QUERY_ERROR, message: validation.errors.join(' ') };
  }
  const model = await fetchStatus(config, secrets, options);
  const ok = model.status === PROVIDER_STATUS.HEALTHY || model.status === PROVIDER_STATUS.DEGRADED;
  return { ok, status: model.status, message: model.message, model };
}

module.exports = {
  HOSTS_PATH,
  QUERY_PATH,
  LIMITS,
  METRIC_QUERIES,
  entitiesFrom,
  inventoryFrom,
  latestPoint,
  selectEntity,
  classifyFailure,
  datadogAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Datadog infrastructure hosts and host metrics.',
    docsHint: 'API site URL with an API key and an application key.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * The inventory is `ready`: reaching the API is what proves it. Every host
     * metric is `requires-probe`, because whether an agent reports a given
     * series is a fact about the deployment, not about the configuration.
     */
    capabilities: Object.freeze({
      [CAPABILITY.HOST_INVENTORY]: DECLARED_STATE.READY,
      [CAPABILITY.CPU]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.MEMORY]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.DISK]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.LOAD]: DECLARED_STATE.REQUIRES_PROBE
    }),
    sections: Object.freeze([
      Object.freeze({ id: 'hosts', kind: SECTION_KIND.ENTITY_INVENTORY, capability: CAPABILITY.HOST_INVENTORY, title: 'Infrastructure hosts' }),
      Object.freeze({
        id: 'host-health',
        kind: SECTION_KIND.METRIC_TILES,
        capability: Object.freeze([CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]),
        title: 'Host health'
      })
    ]),
    validateConfiguration,
    testConnection,
    fetchStatus
  })
};
