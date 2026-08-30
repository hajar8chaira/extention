'use strict';

/**
 * Prometheus, and nothing generic.
 *
 * Everything Prometheus-shaped lives here and nowhere else: the two HTTP
 * routes, the PromQL expressions, the `node_*` metric names, the `instance`
 * label as an entity identifier, the `mountpoint` pairing key, and the bearer
 * header. The Infrastructure page never learns any of it — it receives the
 * normalized model this adapter produces and a manifest of sections composed
 * from kinds the page already knows how to draw.
 *
 * The correctness rules established for this integration are preserved exactly
 * as they were, because each of them was a real defect once:
 *
 *   - a vector with one sample per host has no meaningful "first" element, so
 *     nothing is read positionally and no host is ever chosen silently;
 *   - filesystem size and free space are two independent queries whose result
 *     order does not correspond, so they are paired by {instance, mountpoint};
 *   - the target inventory is useful but never fatal;
 *   - a query that returns no series means the deployment does not export it —
 *     a Kubernetes-only or windows_exporter Prometheus is not broken;
 *   - a real zero is a measurement and stays a zero.
 */

const { IntegrationHttpError, joinUrl, normalizeIntegrationUrl, requestJson } = require('./http');
const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, METRIC_REASON, SECTION_KIND,
  unavailableMetric, availableMetric, unknownInventory, buildInfrastructureModel, validateAgainstFields
} = require('./observability-contract');

const ID = 'prometheus';
const LABEL = 'Prometheus';

/**
 * What Prometheus needs, declared rather than hardcoded in a form.
 * `secret: true` marks what must never leave SecretStorage.
 */
const CONFIGURATION_FIELDS = Object.freeze([
  { id: 'url', type: 'url', label: 'Prometheus endpoint', placeholder: 'http://host:9090', required: true, hint: 'HTTP API root, usually port 9090.' },
  {
    id: 'bearerToken',
    type: 'password',
    label: 'Bearer token',
    group: 'advanced',
    secret: true,
    hint: 'Optional. Sent as an Authorization header; never stored in settings and never rendered back.'
  },
  {
    id: 'allowSelfSigned',
    type: 'boolean',
    label: 'Allow self-signed certificate',
    group: 'advanced',
    hint: 'Off by default. Enable only for an endpoint whose certificate you explicitly trust; certificate identity verification is relaxed for this connection only.'
  }
]);

/** The PromQL this adapter runs. Nothing outside this file names a metric. */
const QUERIES = Object.freeze({
  cpu: '100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
  memoryTotal: 'node_memory_MemTotal_bytes',
  memoryAvailable: 'node_memory_MemAvailable_bytes',
  diskSize: 'node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}',
  diskAvailable: 'node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"}',
  load1: 'node_load1'
});

/** Which queries back which capability, so one failure degrades only its own. */
const CAPABILITY_QUERIES = Object.freeze({
  [CAPABILITY.CPU]: ['cpu'],
  [CAPABILITY.MEMORY]: ['memoryTotal', 'memoryAvailable'],
  [CAPABILITY.DISK]: ['diskSize', 'diskAvailable'],
  [CAPABILITY.LOAD]: ['load1']
});

const TIMEOUT_MS = 10000;

// ---------------------------------------------------------------------------
// Reading a vector: per entity, and per filesystem — never "the first one"
// ---------------------------------------------------------------------------

function sampleValue(series) {
  const number = Number(series?.value?.[1]);
  return Number.isFinite(number) ? number : null;
}

function vectorSeries(payload) {
  const result = payload?.data?.result;
  return Array.isArray(result) ? result : [];
}

/**
 * One value per entity.
 *
 * Series without an `instance` label cannot be attributed to a host, so they
 * are dropped rather than assigned to one. Guessing would be inventing an
 * attribution.
 */
function valuesByInstance(payload) {
  const values = new Map();
  for (const series of vectorSeries(payload)) {
    const instance = String(series?.metric?.instance || '').trim();
    const value = sampleValue(series);
    if (!instance || value === null) continue;
    if (!values.has(instance)) values.set(instance, value);
  }
  return values;
}

/** An unambiguous composite key: no separator can appear in an encoded value. */
function filesystemPairKey(instance, mountpoint) {
  return JSON.stringify([instance, mountpoint]);
}

function filesystemKey(metric = {}) {
  return String(metric.mountpoint || metric.device || '').trim();
}

/**
 * One value per entity AND filesystem.
 *
 * This is the pairing key that matters: size and available are two independent
 * queries, and Prometheus makes no promise that their result sets line up.
 */
function valuesByFilesystem(payload) {
  const values = new Map();
  for (const series of vectorSeries(payload)) {
    const instance = String(series?.metric?.instance || '').trim();
    const mountpoint = filesystemKey(series?.metric);
    const value = sampleValue(series);
    if (!instance || !mountpoint || value === null) continue;
    values.set(filesystemPairKey(instance, mountpoint), { instance, mountpoint, value });
  }
  return values;
}

/** Filesystems whose size AND available were both reported, for one entity. */
function pairedFilesystems(sizes, availables, host) {
  const paired = [];
  for (const [key, size] of sizes) {
    if (size.instance !== host) continue;
    const available = availables.get(key);
    if (!available) continue;
    if (!(size.value > 0)) continue;
    paired.push({ mountpoint: size.mountpoint, sizeBytes: size.value, availableBytes: available.value });
  }
  return paired.sort((left, right) => left.mountpoint.localeCompare(right.mountpoint));
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

function inventoryFrom(payload) {
  const active = Array.isArray(payload?.data?.activeTargets) ? payload.data.activeTargets : [];
  const total = active.length;
  const up = active.filter((target) => String(target?.health || '').toLowerCase() === 'up').length;
  const lastScrape = active.map((target) => target?.lastScrape || '').filter(Boolean).sort().pop() || '';
  return {
    // The provider answered: `0/0 UP` is a fact, and it is not « unavailable ».
    inventory: { known: true, up, total, display: `${up}/${total} UP`, lastScrape, lastScrapeAgeSeconds: secondsAgo(lastScrape) },
    entities: active.map((target) => ({
      id: String(target?.labels?.instance || ''),
      name: String(target?.labels?.job || target?.labels?.instance || target?.scrapePool || 'target'),
      type: 'host',
      status: String(target?.health || ''),
      endpoint: String(target?.scrapeUrl || ''),
      lastSeen: target?.lastScrape || ''
    }))
  };
}

function secondsAgo(value, now = Date.now()) {
  const time = Date.parse(value || '');
  if (!Number.isFinite(time)) return null;
  return Math.max(0, Math.round((now - time) / 1000));
}

// ---------------------------------------------------------------------------
// Entity selection
// ---------------------------------------------------------------------------

/**
 * Which entity the metrics describe.
 *
 * An explicit choice wins. A single known entity needs no choice. Several with
 * no choice made is answered by asking — never by taking the first one.
 */
function selectEntity(entities, requested = '') {
  const wanted = String(requested || '').trim();
  if (wanted && entities.includes(wanted)) return { entity: wanted, selectionRequired: false };
  if (entities.length === 1) return { entity: entities[0], selectionRequired: false };
  return { entity: '', selectionRequired: entities.length > 1 };
}

// ---------------------------------------------------------------------------
// Metric shaping
// ---------------------------------------------------------------------------

const pctMetric = (value) => (Number.isFinite(value) ? availableMetric(value, `${Math.round(value)}%`) : null);
const numericMetric = (value) => (Number.isFinite(value) ? availableMetric(value, String(Math.round(value * 100) / 100)) : null);
const bytesToGb = (value) => Number(value) / (1024 ** 3);

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

function connectionFor(config = {}, secrets = {}) {
  return {
    url: String(config.url || '').trim(),
    token: String(secrets.bearerToken || ''),
    // A boolean is read as a boolean: any other value is not consent.
    allowSelfSigned: config.allowSelfSigned === true
  };
}

function requestOptionsFor(connection, timeoutMs) {
  const options = { timeoutMs, headers: connection.token ? { authorization: `Bearer ${connection.token}` } : {} };
  if (connection.allowSelfSigned) options.tls = { allowSelfSigned: true };
  return options;
}

const CONNECTION_CODES = Object.freeze(['AUTH_ERROR', 'TIMEOUT', 'OFFLINE', 'INVALID_URL']);

function connectionStatusFor(code) {
  if (code === 'AUTH_ERROR') return PROVIDER_STATUS.AUTH_ERROR;
  if (code === 'TIMEOUT') return PROVIDER_STATUS.TIMEOUT;
  return PROVIDER_STATUS.OFFLINE;
}

function validateConfiguration(config = {}) {
  const base = validateAgainstFields(CONFIGURATION_FIELDS, config);
  if (!base.valid) return base;
  try { normalizeIntegrationUrl(config.url, LABEL); }
  catch (error) { return { valid: false, errors: [error.message] }; }
  return { valid: true, errors: [] };
}

/**
 * Reads Prometheus.
 *
 * Every request is attempted on its own and failures are collected rather than
 * thrown: the target inventory failing must not discard six metric answers, and
 * one unsupported metric must not hide the five that worked. The provider is
 * only reported unreachable when the failures say the provider itself is.
 */
async function fetchStatus(config = {}, secrets = {}, options = {}) {
  const { timeoutMs = TIMEOUT_MS, request = requestJson, entity = '' } = options;
  const connection = connectionFor(config, secrets);
  if (!connection.url) return buildInfrastructureModel({ provider: ID, label: LABEL, configured: false });

  let baseUrl = '';
  try { baseUrl = normalizeIntegrationUrl(connection.url, LABEL); }
  catch (error) {
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: true, baseUrl: connection.url,
      status: PROVIDER_STATUS.QUERY_ERROR, message: error.message, lastChecked: new Date().toISOString()
    });
  }

  const lastChecked = new Date().toISOString();
  const requestOptions = requestOptionsFor(connection, timeoutMs);
  const failures = [];

  // --- the target inventory: useful, never fatal ---------------------------
  let inventory = unknownInventory();
  let entities = [];
  try {
    const payload = await request(joinUrl(baseUrl, '/api/v1/targets', { state: 'active' }), requestOptions);
    const read = inventoryFrom(payload);
    inventory = read.inventory;
    entities = read.entities;
  } catch (error) {
    failures.push({ key: 'targets', capability: CAPABILITY.HOST_INVENTORY, code: error?.code || 'QUERY_ERROR' });
  }

  // --- the metric queries: each answers for itself -------------------------
  const payloads = {};
  await Promise.all(Object.entries(QUERIES).map(async ([key, query]) => {
    try {
      payloads[key] = await request(joinUrl(baseUrl, '/api/v1/query', { query }), requestOptions);
    } catch (error) {
      failures.push({ key, code: error?.code || 'QUERY_ERROR' });
    }
  }));

  // The provider is unreachable only when nothing at all could be read AND the
  // reason is a connection-level one. A Prometheus that answers but exports no
  // node metrics is online with unavailable capabilities, not offline.
  const attempted = Object.keys(QUERIES).length + 1;
  const connectionFailure = failures.find((failure) => CONNECTION_CODES.includes(failure.code));
  if (failures.length === attempted && connectionFailure) {
    return buildInfrastructureModel({
      provider: ID, label: LABEL, configured: true, baseUrl,
      status: connectionStatusFor(connectionFailure.code),
      message: connectionFailure.code === 'AUTH_ERROR' ? 'Prometheus a refuse ces identifiants.' : 'Prometheus est injoignable.',
      credentialsConfigured: Boolean(connection.token), relaxedTls: connection.allowSelfSigned,
      failures, lastChecked
    });
  }

  const cpuByHost = valuesByInstance(payloads.cpu);
  const memoryTotalByHost = valuesByInstance(payloads.memoryTotal);
  const memoryAvailableByHost = valuesByInstance(payloads.memoryAvailable);
  const load1ByHost = valuesByInstance(payloads.load1);
  const diskSizes = valuesByFilesystem(payloads.diskSize);
  const diskAvailables = valuesByFilesystem(payloads.diskAvailable);

  /*
   * Which hosts can be chosen — and which merely exist.
   *
   * A scrape target is not a host: Prometheus scrapes itself, and it scrapes
   * exporters that publish no `node_*` series at all. Offering those in the
   * host selector asks the user to choose between one machine and a list of
   * things that have no CPU, no memory and no disk to show — and, worse, makes
   * a single-exporter deployment look ambiguous, so nothing is selected and
   * every tile reads « Unavailable » while the data was there all along.
   *
   * So selection is over the hosts that the host-metric series actually name.
   * The inventory keeps every target — `2/2 UP` stays `2/2 UP` — because
   * « which targets are healthy » and « which host can I read metrics for » are
   * two different questions and only the second one is a choice.
   */
  const metricHosts = [...new Set([
    ...cpuByHost.keys(), ...memoryTotalByHost.keys(), ...memoryAvailableByHost.keys(), ...load1ByHost.keys(),
    ...[...diskSizes.values()].map((item) => item.instance),
    ...[...diskAvailables.values()].map((item) => item.instance)
  ])].sort();
  const inventoryHosts = entities.map((item) => item.id).filter(Boolean);
  for (const host of metricHosts) {
    if (!inventoryHosts.includes(host)) entities.push({ id: host, name: host, type: 'host', status: '' });
  }

  const { entity: selectedEntity, selectionRequired } = selectEntity(metricHosts, entity);
  const failed = new Set(failures.map((failure) => failure.key));
  /**
   * Why a metric has no value when no host is selected.
   *
   * Waiting for a choice and having nothing to read are different answers to
   * the user. Only the first one is `entity-not-selected`; with no host exposing
   * these series at all, the honest reason is that the deployment does not
   * export them — or that the query failed, if it did.
   */
  const unselectedReason = (key) => (selectionRequired
    ? METRIC_REASON.ENTITY_NOT_SELECTED
    : (failed.has(key) ? METRIC_REASON.QUERY_FAILED : METRIC_REASON.NOT_EXPORTED));
  const readFor = (map, key) => {
    if (!selectedEntity) return { value: null, reason: unselectedReason(key) };
    const value = map.has(selectedEntity) ? map.get(selectedEntity) : null;
    return { value, reason: value === null ? (failed.has(key) ? METRIC_REASON.QUERY_FAILED : METRIC_REASON.NOT_EXPORTED) : '' };
  };

  const cpu = readFor(cpuByHost, 'cpu');
  const load = readFor(load1ByHost, 'load1');
  const memoryTotal = readFor(memoryTotalByHost, 'memoryTotal');
  const memoryAvailable = readFor(memoryAvailableByHost, 'memoryAvailable');

  // Memory needs BOTH halves from the same entity, or it has no answer.
  const memoryTotalGb = memoryTotal.value === null ? null : bytesToGb(memoryTotal.value);
  const memoryUsedGb = memoryTotal.value === null || memoryAvailable.value === null
    ? null : bytesToGb(memoryTotal.value - memoryAvailable.value);

  // Disk is summed over filesystems whose size and available were BOTH reported
  // for this entity and this mountpoint. Nothing is divided across entities or
  // across filesystems.
  const filesystems = selectedEntity ? pairedFilesystems(diskSizes, diskAvailables, selectedEntity) : [];
  const diskSizeBytes = filesystems.reduce((total, item) => total + item.sizeBytes, 0);
  const diskAvailableBytes = filesystems.reduce((total, item) => total + item.availableBytes, 0);
  const diskPercent = filesystems.length && diskSizeBytes > 0
    ? ((diskSizeBytes - diskAvailableBytes) / diskSizeBytes) * 100
    : null;

  const metrics = {
    [CAPABILITY.CPU]: pctMetric(cpu.value) || unavailableMetric(cpu.reason || METRIC_REASON.NOT_EXPORTED),
    [CAPABILITY.MEMORY]: Number.isFinite(memoryUsedGb) && Number.isFinite(memoryTotalGb) && memoryTotalGb > 0
      ? {
        available: true,
        value: (memoryUsedGb / memoryTotalGb) * 100,
        usedGb: memoryUsedGb,
        totalGb: memoryTotalGb,
        reason: '',
        display: `${Math.round(memoryUsedGb * 10) / 10} GB / ${Math.round(memoryTotalGb * 10) / 10} GB`
      }
      : unavailableMetric(memoryTotal.reason || memoryAvailable.reason || METRIC_REASON.NOT_EXPORTED),
    [CAPABILITY.DISK]: pctMetric(diskPercent) || unavailableMetric(
      !selectedEntity ? (selectionRequired ? METRIC_REASON.ENTITY_NOT_SELECTED : unselectedReason('diskSize'))
        : (failed.has('diskSize') || failed.has('diskAvailable') ? METRIC_REASON.QUERY_FAILED : METRIC_REASON.NOT_EXPORTED)
    ),
    [CAPABILITY.LOAD]: numericMetric(load.value) || unavailableMetric(load.reason || METRIC_REASON.NOT_EXPORTED)
  };

  // Capability evidence, proven one capability at a time. A query that answered
  // with no series says the deployment does not export it; a query that failed
  // says something went wrong. They are not the same outcome.
  const capabilities = { [CAPABILITY.HOST_INVENTORY]: inventory.known ? RESOLVED_STATE.READY : RESOLVED_STATE.ERROR };
  for (const [capability, keys] of Object.entries(CAPABILITY_QUERIES)) {
    if (keys.some((key) => failed.has(key))) capabilities[capability] = RESOLVED_STATE.ERROR;
    else if (metrics[capability]?.available) capabilities[capability] = RESOLVED_STATE.READY;
    else if (metrics[capability]?.reason === METRIC_REASON.ENTITY_NOT_SELECTED) capabilities[capability] = RESOLVED_STATE.READY;
    else capabilities[capability] = RESOLVED_STATE.UNAVAILABLE;
  }

  const degraded = failures.length > 0 || selectionRequired
    || (inventory.known && inventory.total > 0 && inventory.up < inventory.total);
  return buildInfrastructureModel({
    provider: ID, label: LABEL, configured: true, baseUrl,
    status: degraded ? PROVIDER_STATUS.DEGRADED : PROVIDER_STATUS.HEALTHY,
    message: selectionRequired
      ? 'Plusieurs hotes sont surveilles : choisissez celui a afficher.'
      : (failures.length ? 'Certaines lectures Prometheus sont indisponibles.' : ''),
    credentialsConfigured: Boolean(connection.token),
    relaxedTls: connection.allowSelfSigned,
    entities, inventory, targets: { ...inventory, items: entities, selectedHost: selectedEntity },
    // The inventory lists every target; only hosts with metrics are offered.
    selectableEntities: metricHosts,
    selectedEntity, selectionRequired,
    metrics, capabilities, failures, filesystems, lastChecked
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
  QUERIES,
  valuesByInstance,
  valuesByFilesystem,
  pairedFilesystems,
  selectEntity,
  inventoryFrom,
  secondsAgo,
  prometheusAdapter: Object.freeze({
    id: ID,
    label: LABEL,
    summary: 'Prometheus HTTP API and exporter metrics.',
    docsHint: 'HTTP API endpoint, optionally behind a bearer token.',
    configurationFields: CONFIGURATION_FIELDS,
    getConfigurationSchema: () => CONFIGURATION_FIELDS,
    /**
     * What this adapter can serve.
     *
     * The inventory is `ready`: reaching the HTTP API is what proves it. Every
     * host metric is `requires-probe`, because whether a deployment exports
     * `node_*` series is a fact about that deployment — a Kubernetes-only or
     * windows_exporter Prometheus is perfectly healthy and simply has none.
     */
    capabilities: Object.freeze({
      [CAPABILITY.HOST_INVENTORY]: DECLARED_STATE.READY,
      [CAPABILITY.CPU]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.MEMORY]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.DISK]: DECLARED_STATE.REQUIRES_PROBE,
      [CAPABILITY.LOAD]: DECLARED_STATE.REQUIRES_PROBE
    }),
    /** How this provider's dashboard is composed, from kinds the page knows. */
    sections: Object.freeze([
      Object.freeze({ id: 'inventory', kind: SECTION_KIND.ENTITY_INVENTORY, capability: CAPABILITY.HOST_INVENTORY, title: 'Targets' }),
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
