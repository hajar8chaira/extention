'use strict';

/**
 * Zabbix, and nothing generic.
 *
 * Zabbix is the test of whether this domain is really provider-neutral, because
 * it resembles Prometheus in almost no respect: one JSON-RPC endpoint instead
 * of REST routes, a bearer token instead of an optional one, numeric host ids
 * instead of `instance` labels, template-defined item keys instead of a metric
 * name space, and — the trap — **errors returned as HTTP 200 with a JSON-RPC
 * error object**, so a rejected token never reaches the transport's 401 path.
 *
 * Verified against Zabbix's published API before implementation:
 *
 *   - `POST <frontend>/api_jsonrpc.php`, JSON-RPC 2.0.
 *   - `Authorization: Bearer <token>`; the old JSON-RPC `auth` property is gone.
 *   - `host.get` returns `hostid`/`host`/`name`/`status`; there is no
 *     `available` on the host — availability lives on interfaces, fetched with
 *     `selectInterfaces`.
 *   - `item.get` returns `lastvalue` and `lastclock` alongside `units`, and
 *     supports `hostids`, `search` on `key_`, and `limit`.
 *
 * What this adapter refuses to invent: item keys. Which keys exist depends
 * entirely on the templates a site has linked, so the candidates below are
 * *searched* and only what the deployment actually returns is used. A host
 * monitored by a custom template simply has fewer capabilities — it is not
 * broken, and nothing is fabricated to fill the tiles.
 */

const { isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson } = require('./http');
const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON, SECTION_KIND,
  unavailableMetric, availableMetric, unknownInventory, buildInfrastructureModel, validateAgainstFields
} = require('./observability-contract');

const ID = 'zabbix';
const LABEL = 'Zabbix';

/** The single JSON-RPC entry point, in one place. */
const API_PATH = '/api_jsonrpc.php';

const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: 'url',
    label: 'Zabbix frontend URL',
    placeholder: 'https://host/zabbix',
    required: true,
    hint: 'The frontend address. The API entry point beneath it is added automatically.'
  },
  {
    id: 'apiToken',
    type: 'password',
    label: 'API token',
    required: true,
    secret: true,
    hint: 'Created under Users → API tokens. Sent as a bearer token, never stored in settings.'
  },
  {
    id: 'allowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed certificate',
    group: 'advanced',
    hint: 'Off by default. Enable only for a frontend whose certificate you explicitly trust; certificate identity verification is relaxed for this connection only.'
  }
]);

/** Hard bounds. No call may exceed them, whatever the deployment's size. */
const LIMITS = Object.freeze({ HOSTS: 200, ITEMS: 100, TIMEOUT_MS: 15000, MAX_BYTES: 1024 * 1024 });

/**
 * Candidate item keys per capability — *candidates*, matched against what the
 * host really has.
 *
 * These are the keys Zabbix's own agent templates define. A site that renamed
 * them, or that monitors by SNMP or a custom template, resolves fewer
 * capabilities rather than wrong ones. `invert` marks a key that reports the
 * free share where the tile shows the used one.
 */
const ITEM_CANDIDATES = Object.freeze({
  [CAPABILITY.CPU]: Object.freeze([
    { key: 'system.cpu.util', unit: '%' }
  ]),
  [CAPABILITY.MEMORY]: Object.freeze([
    { key: 'vm.memory.utilization', unit: '%' },
    { key: 'vm.memory.size[pavailable]', unit: '%', invert: true }
  ]),
  [CAPABILITY.LOAD]: Object.freeze([
    { key: 'system.cpu.load[all,avg1]', unit: '' },
    { key: 'system.cpu.load[percpu,avg1]', unit: '' }
  ]),
  [CAPABILITY.DISK]: Object.freeze([
    { key: 'vfs.fs.size', unit: '%', filesystem: true }
  ])
});

/** The key fragments `item.get` is asked to search for, and nothing else. */
function candidateSearchKeys() {
  return [...new Set(Object.values(ITEM_CANDIDATES).flatMap((entries) => entries.map((entry) => entry.key)))];
}

const text = (value) => (value === null || value === undefined || typeof value === 'object' ? '' : String(value).trim());

function connectionFor(config = {}, secrets = {}) {
  return {
    url: text(config.url),
    token: String(secrets.apiToken || ''),
    // A boolean is read as a boolean: any other value is not consent.
    allowSelfSigned: config.allowSelfSigned === true
  };
}

function requestOptionsFor(connection) {
  const options = {
    method: 'POST',
    timeoutMs: LIMITS.TIMEOUT_MS,
    maxBytes: LIMITS.MAX_BYTES,
    headers: {
      // Zabbix requires this exact content type for the JSON-RPC endpoint.
      'content-type': 'application/json-rpc',
      authorization: `Bearer ${connection.token}`
    }
  };
  if (connection.allowSelfSigned) options.tls = { allowSelfSigned: true };
  return options;
}

/** Error classes worth telling apart, because each has a different fix. */
const FAILURE_MESSAGES = Object.freeze({
  'not-configured': 'Zabbix is not configured.',
  'invalid-config': 'The Zabbix frontend URL is not valid.',
  'auth-error': 'Zabbix rejected this API token, or it lacks permission to read hosts.',
  'tls-error': 'The Zabbix certificate was rejected. Enable the self-signed option only if you trust this endpoint.',
  'not-found': 'The Zabbix API was not found at this address. Check that the URL points at the Zabbix frontend.',
  unreachable: 'Zabbix is unreachable at this address.',
  timeout: 'Zabbix did not answer in time.',
  malformed: 'Zabbix returned an unexpected response.',
  'api-error': 'The Zabbix API rejected the request.'
});

/**
 * A JSON-RPC failure carried in a 200 response.
 *
 * This is the shape a wrong token produces, so it must be read from the body:
 * relying on an HTTP status here would report a healthy provider that answers
 * nothing.
 */
class ZabbixApiError extends Error {
  constructor(payload = {}) {
    const detail = text(payload.data);
    super(text(payload.message) || 'Zabbix API error.');
    this.name = 'ZabbixApiError';
    this.rpcCode = Number(payload.code);
    this.detail = detail;
    // Zabbix says « Not authorised » / « re-login » for a rejected or expired
    // token, whatever the numeric code, so the wording is what identifies it.
    this.authFailure = /not authori[sz]ed|re-login|permission denied|session terminated/i.test(`${payload.message || ''} ${detail}`);
  }
}

function classifyFailure(error) {
  if (error instanceof ZabbixApiError) return error.authFailure ? 'auth-error' : 'api-error';
  const code = String(error?.code || '');
  const raw = String(error?.message || '');
  if (code === 'AUTH_ERROR') return 'auth-error';
  if (code === 'TIMEOUT') return 'timeout';
  if (code === 'INVALID_URL') return 'invalid-config';
  if (code === 'MALFORMED' || code === 'TOO_LARGE') return 'malformed';
  if (code === 'HTTP_ERROR') return /\b404\b/.test(raw) ? 'not-found' : 'api-error';
  if (code === 'OFFLINE') return isCertificateError({ message: raw }) ? 'tls-error' : 'unreachable';
  return 'api-error';
}

function failureMessage(code) {
  return FAILURE_MESSAGES[code] || FAILURE_MESSAGES['api-error'];
}

let requestId = 0;

/** One JSON-RPC call. The token travels in the header, never in the body. */
async function call(connection, method, params, request) {
  const baseUrl = normalizeIntegrationUrl(connection.url, LABEL);
  requestId += 1;
  const payload = await request(joinUrl(baseUrl, API_PATH), {
    ...requestOptionsFor(connection),
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id: requestId })
  });
  if (payload && typeof payload === 'object' && payload.error) throw new ZabbixApiError(payload.error);
  return payload?.result;
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/**
 * Availability, from wherever this version keeps it.
 *
 * Zabbix moved it off the host and onto the interfaces, and active-agent hosts
 * report it differently again. A host that offers no signal at all is not
 * « down » — it is unknown, and says so by contributing nothing to the count.
 */
function availabilityOf(host = {}) {
  const interfaces = Array.isArray(host.interfaces) ? host.interfaces : [];
  const signals = interfaces.map((entry) => text(entry?.available)).filter((value) => value !== '');
  const active = text(host.active_available);
  if (active !== '') signals.push(active);
  if (!signals.length) return '';
  if (signals.includes('1')) return 'available';
  if (signals.includes('2')) return 'unavailable';
  return '';
}

function entitiesFrom(hosts = []) {
  return hosts.map((host) => {
    const interfaces = Array.isArray(host.interfaces) ? host.interfaces : [];
    const primary = interfaces[0] || {};
    const endpoint = [text(primary.ip) || text(primary.dns), text(primary.port)].filter(Boolean).join(':');
    return {
      // Zabbix's numeric id is the query key; the human name is what is shown.
      id: text(host.hostid),
      name: text(host.name) || text(host.host) || text(host.hostid),
      type: 'host',
      status: availabilityOf(host),
      endpoint,
      lastSeen: ''
    };
  });
}

/**
 * The inventory.
 *
 * `up` is counted only from hosts that actually reported availability. When no
 * host does, the count is absent rather than zero — « nothing reported » and
 * « none available » are different statements.
 */
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
// Items → metrics
// ---------------------------------------------------------------------------

function numericValue(item) {
  const value = Number(item?.lastvalue);
  return Number.isFinite(value) ? value : null;
}

/** Items whose key starts with one of the candidates for this capability. */
function itemsFor(items, capability) {
  const candidates = ITEM_CANDIDATES[capability] || [];
  const matched = [];
  for (const candidate of candidates) {
    for (const item of items) {
      const key = text(item?.key_);
      if (!key) continue;
      const hit = candidate.filesystem ? key.startsWith(`${candidate.key}[`) : key === candidate.key;
      if (hit) matched.push({ item, candidate });
    }
    if (matched.length) break;
  }
  return matched;
}

/**
 * One capability's metric, from the items a host really has.
 *
 * Disk is the interesting case and the reason for `AMBIGUOUS`. Zabbix reports
 * `vfs.fs.size[<fs>,pused]` as a *percentage per filesystem* with no byte
 * sizes, so several of them cannot be weighted into one host figure; averaging
 * them would invent a number and picking one would be the arbitrary-selection
 * bug this domain already fixed once. One filesystem is answerable; several are
 * honestly declined.
 */
function metricFor(items, capability) {
  const matched = itemsFor(items, capability);
  if (!matched.length) return { metric: unavailableMetric(METRIC_REASON.NOT_EXPORTED), state: RESOLVED_STATE.UNAVAILABLE };
  if (matched.length > 1 && matched[0].candidate.filesystem) {
    return { metric: unavailableMetric(METRIC_REASON.AMBIGUOUS), state: RESOLVED_STATE.UNAVAILABLE };
  }

  const { item, candidate } = matched[0];
  const raw = numericValue(item);
  if (raw === null) return { metric: unavailableMetric(METRIC_REASON.NOT_EXPORTED), state: RESOLVED_STATE.UNAVAILABLE };

  const value = candidate.invert ? 100 - raw : raw;
  const unit = candidate.unit || text(item.units);
  const display = unit === '%'
    ? `${Math.round(value)}%`
    : String(Math.round(value * 100) / 100);
  return { metric: availableMetric(value, display), state: RESOLVED_STATE.READY };
}

// ---------------------------------------------------------------------------
// Entity selection — the rule this domain established and keeps
// ---------------------------------------------------------------------------

function selectEntity(ids, requested = '') {
  const wanted = text(requested);
  if (wanted && ids.includes(wanted)) return { entity: wanted, selectionRequired: false };
  if (ids.length === 1) return { entity: ids[0], selectionRequired: false };
  return { entity: '', selectionRequired: ids.length > 1 };
}

function validateConfiguration(config = {}) {
  const base = validateAgainstFields(CONFIGURATION_FIELDS, config);
  if (!base.valid) return base;
  try { normalizeIntegrationUrl(config.url, LABEL); }
  catch (error) { return { valid: false, errors: [error.message] }; }
  return { valid: true, errors: [] };
}

function connectionStatusFor(code) {
  if (code === 'auth-error') return PROVIDER_STATUS.AUTH_ERROR;
  if (code === 'timeout') return PROVIDER_STATUS.TIMEOUT;
  if (code === 'unreachable' || code === 'tls-error' || code === 'not-found') return PROVIDER_STATUS.OFFLINE;
  if (code === 'invalid-config') return PROVIDER_STATUS.QUERY_ERROR;
  return PROVIDER_STATUS.DEGRADED;
}

/**
 * Reads Zabbix.
 *
 * Two calls at most, whatever the size of the estate: the host inventory, then
 * one item read for the host on screen. The inventory failing is a connection
 * fact; the item read failing degrades only the capabilities it backs.
 */
async function fetchStatus(config = {}, secrets = {}, options = {}) {
  const { request = requestJson, entity = '' } = options;
  const connection = connectionFor(config, secrets);
  const lastChecked = new Date().toISOString();

  if (!connection.url || !connection.token) {
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: Boolean(connection.url),
      status: PROVIDER_STATUS.NOT_CONFIGURED,
      message: connection.url ? failureMessage('not-configured') : '',
      credentialsConfigured: Boolean(connection.token),
      relaxedTls: connection.allowSelfSigned
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

  // --- the inventory: this is what proves the connection -------------------
  let entities = [];
  try {
    const hosts = await call(connection, 'host.get', {
      output: ['hostid', 'host', 'name', 'status', 'active_available'],
      selectInterfaces: ['available', 'ip', 'dns', 'port'],
      limit: LIMITS.HOSTS
    }, request);
    entities = entitiesFrom(Array.isArray(hosts) ? hosts : []);
  } catch (error) {
    const code = classifyFailure(error);
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
      status: connectionStatusFor(code),
      // The message comes from the table, never from the raw error — that is
      // the classic place for a token to leak into a UI string.
      message: failureMessage(code),
      capabilities: { [CAPABILITY.HOST_INVENTORY]: RESOLVED_STATE.ERROR },
      failures: [{ capability: CAPABILITY.HOST_INVENTORY, code }],
      relaxedTls: connection.allowSelfSigned, lastChecked
    });
  }

  const inventory = inventoryFrom(entities);
  const ids = entities.map((item) => item.id).filter(Boolean);
  const { entity: selectedEntity, selectionRequired } = selectEntity(ids, entity);
  const capabilities = { [CAPABILITY.HOST_INVENTORY]: RESOLVED_STATE.READY };
  const metrics = {};
  const failures = [];
  const metricCapabilities = [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD];

  if (!selectedEntity) {
    // No host chosen and several offered: ask, never guess.
    for (const capability of metricCapabilities) {
      metrics[capability] = unavailableMetric(METRIC_REASON.ENTITY_NOT_SELECTED);
      capabilities[capability] = RESOLVED_STATE.READY;
    }
  } else {
    // --- one item read for the host on screen ------------------------------
    let items = [];
    let itemsFailed = false;
    try {
      const result = await call(connection, 'item.get', {
        output: ['itemid', 'key_', 'lastvalue', 'lastclock', 'units', 'value_type', 'name'],
        hostids: selectedEntity,
        search: { key_: candidateSearchKeys() },
        searchByAny: true,
        startSearch: true,
        limit: LIMITS.ITEMS
      }, request);
      items = Array.isArray(result) ? result : [];
    } catch (error) {
      itemsFailed = true;
      failures.push({ capability: 'items', code: classifyFailure(error) });
    }

    for (const capability of metricCapabilities) {
      if (itemsFailed) {
        metrics[capability] = unavailableMetric(METRIC_REASON.QUERY_FAILED);
        capabilities[capability] = RESOLVED_STATE.ERROR;
        continue;
      }
      const read = metricFor(items, capability);
      metrics[capability] = read.metric;
      capabilities[capability] = read.state;
    }
  }

  const degraded = failures.length > 0 || selectionRequired
    || (Number.isFinite(inventory.up) && inventory.total > 0 && inventory.up < inventory.total);
  return buildInfrastructureModel({
    provider: ID, label: LABEL, configured: true, baseUrl, credentialsConfigured: true,
    status: degraded ? PROVIDER_STATUS.DEGRADED : PROVIDER_STATUS.HEALTHY,
    message: selectionRequired
      ? 'Plusieurs hotes sont surveilles : choisissez celui a afficher.'
      : (failures.length ? 'Certaines lectures Zabbix sont indisponibles.' : ''),
    entities, inventory,
    targets: { ...inventory, items: entities, selectedHost: selectedEntity },
    selectedEntity, selectionRequired,
    metrics, capabilities, failures,
    relaxedTls: connection.allowSelfSigned, lastChecked
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
  API_PATH,
  LIMITS,
  ITEM_CANDIDATES,
  ZabbixApiError,
  candidateSearchKeys,
  availabilityOf,
  entitiesFrom,
  inventoryFrom,
  itemsFor,
  metricFor,
  selectEntity,
  classifyFailure,
  zabbixAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Zabbix host monitoring and item values.',
    docsHint: 'Zabbix frontend URL and an API token with read access to hosts.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * What this adapter can serve.
     *
     * The inventory is `ready`: reaching the API is what proves it. Every host
     * metric is `requires-probe`, because which item keys a host carries is
     * decided by the templates a site linked — a fact about the deployment,
     * not about the configuration.
     */
    capabilities: Object.freeze({
      [CAPABILITY.HOST_INVENTORY]: DECLARED_STATE.READY,
      [CAPABILITY.CPU]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.MEMORY]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.DISK]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.LOAD]: DECLARED_STATE.REQUIRES_PROBE
    }),
    /** Composed from the section kinds the page already draws. */
    sections: Object.freeze([
      Object.freeze({ id: 'hosts', kind: SECTION_KIND.ENTITY_INVENTORY, capability: CAPABILITY.HOST_INVENTORY, title: 'Monitored hosts' }),
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
