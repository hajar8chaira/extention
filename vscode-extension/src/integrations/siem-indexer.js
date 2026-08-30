'use strict';

/**
 * The Wazuh Indexer, and nothing generic.
 *
 * Since Wazuh 4.8 the Manager API no longer serves vulnerability state: it
 * lives in an OpenSearch index written by the vulnerability detector. That is a
 * Wazuh implementation detail, so everything about it — the index pattern, the
 * candidate field paths, the OpenSearch query bodies — stays in this file,
 * below the adapter boundary. The Runtime Security page never learns that an
 * OpenSearch cluster exists.
 *
 * Two rules shape the design:
 *
 *   1. Nothing about a deployment is known in advance. The address, the
 *      credentials, the agents, the indices and even the available fields come
 *      from the connected cluster at runtime. A field is used only after the
 *      cluster says it exists.
 *
 *   2. A missing optional field is omitted, never replaced. Wazuh versions
 *      differ, and a deployment that cannot supply a CVSS score has not scored
 *      the vulnerability at zero.
 */

const { IntegrationHttpError, isCertificateError, joinUrl, normalizeIntegrationUrl, requestJson } = require('./http');

/**
 * The vulnerability state index family, in one place.
 *
 * Wazuh writes one index per cluster/date; the wildcard is the documented way
 * to address the family. Never spread this literal around the codebase, and
 * never let another provider inherit it.
 */
const VULNERABILITY_INDEX_PATTERN = 'wazuh-states-vulnerabilities-*';

/**
 * The alert index family.
 *
 * The Manager API has never served alert history: `analysisd` writes alerts to
 * disk and they are shipped to the Indexer, which is where the Wazuh Dashboard
 * reads them from too. Wazuh writes one index per day (`wazuh-alerts-4.x-…`),
 * so the family is addressed by its documented wildcard — and, like every other
 * assumption here, its existence is confirmed at runtime before it is used.
 */
const ALERT_INDEX_PATTERN = 'wazuh-alerts-*';

/**
 * Candidate paths per logical field — *candidates*, verified against the live
 * mapping before any of them is used.
 *
 * Order matters: the first path the cluster confirms wins. Several entries
 * exist where Wazuh versions genuinely differ; a single entry means one
 * documented path, still verified rather than assumed.
 */
const VULNERABILITY_FIELD_CANDIDATES = Object.freeze({
  cve: ['vulnerability.id'],
  severity: ['vulnerability.severity'],
  cvssScore: ['vulnerability.score.base', 'vulnerability.cvss.base_score'],
  cvssVersion: ['vulnerability.score.version', 'vulnerability.cvss.version'],
  description: ['vulnerability.description'],
  detectedAt: ['vulnerability.detected_at'],
  publishedAt: ['vulnerability.published_at'],
  references: ['vulnerability.reference'],
  underEvaluation: ['vulnerability.under_evaluation'],
  category: ['vulnerability.category'],
  packageName: ['package.name'],
  packageVersion: ['package.version'],
  packageArchitecture: ['package.architecture'],
  packageType: ['package.type'],
  packageCondition: ['package.condition'],
  assetId: ['agent.id'],
  assetName: ['agent.name'],
  assetIp: ['agent.ip'],
  osName: ['host.os.name'],
  osVersion: ['host.os.version'],
  osFull: ['host.os.full'],
  indexedAt: ['@timestamp']
});

/**
 * Alert fields, same rules: candidates, confirmed before use, omitted when the
 * deployment does not define them.
 */
const ALERT_FIELD_CANDIDATES = Object.freeze({
  timestamp: ['@timestamp', 'timestamp'],
  ruleId: ['rule.id'],
  ruleLevel: ['rule.level'],
  ruleDescription: ['rule.description'],
  ruleGroups: ['rule.groups'],
  mitreIds: ['rule.mitre.id'],
  mitreTechniques: ['rule.mitre.technique'],
  assetId: ['agent.id'],
  assetName: ['agent.name'],
  assetIp: ['agent.ip'],
  srcUser: ['data.srcuser'],
  dstUser: ['data.dstuser'],
  fullLog: ['full_log'],
  location: ['location'],
  decoder: ['decoder.name']
});

/**
 * Without a vulnerability identifier there is no vulnerability to show; without
 * a rule id there is no alert to show. Every other field is a bonus the
 * deployment may or may not provide.
 */
const REQUIRED_FIELDS = Object.freeze(['cve']);
const ALERT_REQUIRED_FIELDS = Object.freeze(['ruleId']);

/**
 * A dataset is « which index family, which candidate fields, what is
 * indispensable ». Everything below takes one, so alerts and vulnerabilities
 * share every mechanism without sharing a query.
 */
const DATASET = Object.freeze({
  VULNERABILITIES: Object.freeze({
    id: 'vulnerabilities',
    indexPattern: VULNERABILITY_INDEX_PATTERN,
    candidates: VULNERABILITY_FIELD_CANDIDATES,
    required: REQUIRED_FIELDS
  }),
  ALERTS: Object.freeze({
    id: 'alerts',
    indexPattern: ALERT_INDEX_PATTERN,
    candidates: ALERT_FIELD_CANDIDATES,
    required: ALERT_REQUIRED_FIELDS
  })
});

/**
 * Wazuh rule levels run 0-15. These bounds are the single definition of how a
 * level becomes a severity — used both to read a document and to build a
 * severity filter, so the list and its filter can never disagree.
 */
const SEVERITY_LEVELS = Object.freeze([
  { severity: 'CRITICAL', min: 12 },
  { severity: 'HIGH', min: 8 },
  { severity: 'MEDIUM', min: 4 },
  { severity: 'LOW', min: 1 },
  { severity: 'INFO', min: 0 }
]);

function severityForLevel(level) {
  const numeric = Number(level);
  if (!Number.isFinite(numeric)) return 'INFO';
  return (SEVERITY_LEVELS.find((entry) => numeric >= entry.min) || { severity: 'INFO' }).severity;
}

/** The inclusive level window one severity covers, for a range filter. */
function levelRangeFor(severity) {
  const wanted = String(severity || '').toUpperCase();
  const index = SEVERITY_LEVELS.findIndex((entry) => entry.severity === wanted);
  if (index < 0) return null;
  const range = { gte: SEVERITY_LEVELS[index].min };
  if (index > 0) range.lt = SEVERITY_LEVELS[index - 1].min;
  return range;
}

/** Hard bounds. No query may exceed them, whatever the caller asks for. */
const LIMITS = Object.freeze({
  DEFAULT_PAGE_SIZE: 10,
  MAX_PAGE_SIZE: 50,
  MAX_RESULT_WINDOW: 1000,
  MAX_FACET_VALUES: 100,
  MAX_SEARCH_LENGTH: 64,
  // The alert window read on each refresh. Bounded on purpose: the page filters
  // and pages within what the provider returned, and says so.
  ALERT_WINDOW: 100,
  MAX_ALERT_WINDOW: 500,
  TIMEOUT_MS: 15000,
  MAX_BYTES: 1024 * 1024
});

/** Error classes worth telling apart, because each has a different fix. */
const INDEXER_ERROR = Object.freeze({
  NOT_CONFIGURED: 'not-configured',
  INVALID_CONFIG: 'invalid-config',
  AUTH_ERROR: 'auth-error',
  TLS_ERROR: 'tls-error',
  UNREACHABLE: 'unreachable',
  TIMEOUT: 'timeout',
  INDEX_MISSING: 'index-missing',
  UNSUPPORTED_SCHEMA: 'unsupported-schema',
  MALFORMED: 'malformed',
  QUERY_FAILED: 'query-failed'
});

const INDEXER_ERROR_MESSAGES = Object.freeze({
  [INDEXER_ERROR.NOT_CONFIGURED]: 'Wazuh Indexer is not configured.',
  [INDEXER_ERROR.INVALID_CONFIG]: 'The Wazuh Indexer URL is not valid.',
  [INDEXER_ERROR.AUTH_ERROR]: 'The Wazuh Indexer rejected these credentials.',
  [INDEXER_ERROR.TLS_ERROR]: 'The Wazuh Indexer certificate was rejected. Enable the self-signed option only if you trust this endpoint.',
  [INDEXER_ERROR.UNREACHABLE]: 'The Wazuh Indexer is unreachable at this address.',
  [INDEXER_ERROR.TIMEOUT]: 'The Wazuh Indexer did not answer in time.',
  [INDEXER_ERROR.INDEX_MISSING]: 'No Wazuh vulnerability state index was found on this Indexer.',
  [INDEXER_ERROR.UNSUPPORTED_SCHEMA]: 'The vulnerability index does not expose a vulnerability identifier field.',
  [INDEXER_ERROR.MALFORMED]: 'The Wazuh Indexer returned an unexpected response.',
  [INDEXER_ERROR.QUERY_FAILED]: 'The vulnerability query failed on the Wazuh Indexer.'
});

/**
 * Turns a transport failure into one of the classes above.
 *
 * The message that reaches a user comes from the table, never from the raw
 * error: transport errors are the classic place for a credential or a full URL
 * to leak into a UI string.
 */
function classifyIndexerError(error) {
  const code = String(error?.code || '');
  const raw = String(error?.message || '');
  if (code === 'AUTH_ERROR') return INDEXER_ERROR.AUTH_ERROR;
  if (code === 'TIMEOUT') return INDEXER_ERROR.TIMEOUT;
  if (code === 'INVALID_URL') return INDEXER_ERROR.INVALID_CONFIG;
  if (code === 'MALFORMED' || code === 'TOO_LARGE') return INDEXER_ERROR.MALFORMED;
  if (code === 'HTTP_ERROR') return /\b404\b/.test(raw) ? INDEXER_ERROR.INDEX_MISSING : INDEXER_ERROR.QUERY_FAILED;
  if (code === 'OFFLINE') return isCertificateError({ message: raw }) ? INDEXER_ERROR.TLS_ERROR : INDEXER_ERROR.UNREACHABLE;
  return INDEXER_ERROR.QUERY_FAILED;
}

function indexerFailure(error) {
  const code = classifyIndexerError(error);
  return { ok: false, code, message: INDEXER_ERROR_MESSAGES[code] };
}

/**
 * A client bound to one deployment's Indexer.
 *
 * The credentials are turned into an Authorization header here and nowhere
 * else — never a `https://user:pass@host` URL, never a query parameter, never a
 * log line. The relaxed-TLS flag is passed per request and applies to this
 * client's requests only; the Manager API path never sees it.
 */
function createIndexerClient({
  url = '', username = '', password = '', allowSelfSigned = false,
  timeoutMs = LIMITS.TIMEOUT_MS, request = requestJson
} = {}) {
  const rawUrl = String(url || '').trim();
  if (!rawUrl) throw new IntegrationHttpError('URL Indexer absente.', 'INVALID_URL');
  const baseUrl = normalizeIntegrationUrl(rawUrl, 'Wazuh Indexer');
  const headers = { 'content-type': 'application/json' };
  if (username || password) {
    headers.authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  }
  const tls = allowSelfSigned === true ? { allowSelfSigned: true } : null;
  const options = { timeoutMs, maxBytes: LIMITS.MAX_BYTES, tls };

  return {
    baseUrl,
    /**
     * Field capabilities for the candidate paths only — never `fields=*`.
     *
     * This one call answers both questions the probe has: whether an index of
     * the family exists at all (it reports the indices it matched) and which of
     * the candidate fields that index actually defines.
     */
    async fieldCaps(fields = [], dataset = DATASET.VULNERABILITIES) {
      return request(joinUrl(baseUrl, `/${dataset.indexPattern}/_field_caps`, { fields: fields.join(','), ignore_unavailable: 'true' }),
        { ...options, headers });
    },
    /** One bounded search. The body is built by this module, never by a caller. */
    async search(body = {}, dataset = DATASET.VULNERABILITIES) {
      return request(joinUrl(baseUrl, `/${dataset.indexPattern}/_search`, { ignore_unavailable: 'true' }),
        { ...options, method: 'POST', headers, body: JSON.stringify(body) });
    }
  };
}

/** Every path worth asking `_field_caps` about, including keyword sub-fields. */
function candidatePaths(dataset = DATASET.VULNERABILITIES) {
  const paths = new Set();
  for (const candidates of Object.values(dataset.candidates)) {
    for (const path of candidates) {
      paths.add(path);
      paths.add(`${path}.keyword`);
    }
  }
  return [...paths];
}

const AGGREGATABLE_TYPES = new Set(['keyword', 'boolean', 'byte', 'short', 'integer', 'long', 'float', 'half_float', 'scaled_float', 'double', 'date', 'ip']);

/** Flattens one `_field_caps` entry into { type, aggregatable, searchable }. */
function capabilityOf(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const types = Object.entries(entry);
  if (!types.length) return null;
  // A field can be indexed under several types across indices; prefer the one
  // that can be aggregated, since that is what decides the facets.
  const preferred = types.find(([, value]) => value?.aggregatable === true) || types[0];
  const [type, value] = preferred;
  return {
    type: String(value?.type || type || ''),
    aggregatable: value?.aggregatable === true,
    searchable: value?.searchable !== false
  };
}

/**
 * The runtime field map for ONE deployment.
 *
 * Only keys the cluster confirmed appear. `queryPath` is what filters and
 * aggregations must target — a `text` field with a `keyword` sub-field is
 * displayed from the base path and queried through the sub-field, which is the
 * difference between a working asset filter and a silently empty one.
 */
function resolveFieldMap(fieldCaps = {}, dataset = DATASET.VULNERABILITIES) {
  const fields = fieldCaps && typeof fieldCaps.fields === 'object' && fieldCaps.fields ? fieldCaps.fields : {};
  const resolved = {};
  for (const [key, candidates] of Object.entries(dataset.candidates)) {
    for (const path of candidates) {
      const base = capabilityOf(fields[path]);
      if (!base) continue;
      const keyword = capabilityOf(fields[`${path}.keyword`]);
      const queryable = base.aggregatable ? base : (keyword?.aggregatable ? keyword : null);
      resolved[key] = {
        path,
        type: base.type,
        queryPath: queryable === keyword ? `${path}.keyword` : path,
        aggregatable: Boolean(queryable),
        searchable: base.searchable
      };
      break;
    }
  }
  return resolved;
}

function missingRequiredFields(fieldMap = {}, dataset = DATASET.VULNERABILITIES) {
  return dataset.required.filter((key) => !fieldMap[key]);
}

/** Escapes the wildcard metacharacters so a search term stays a search term. */
function escapeWildcard(value) {
  return String(value).replace(/([*?\\])/g, '\\$1');
}

function boundedSearchTerm(value) {
  return String(value || '').trim().slice(0, LIMITS.MAX_SEARCH_LENGTH);
}

/** A contains-match on one field, whatever its indexed type. */
function containsClause(field, term) {
  if (!field) return null;
  const escaped = escapeWildcard(term);
  if (field.type === 'text') return { match_phrase: { [field.path]: term } };
  return { wildcard: { [field.queryPath]: { value: `*${escaped}*`, case_insensitive: true } } };
}

/**
 * The filter clauses for one query.
 *
 * A filter whose field the deployment does not expose is dropped rather than
 * guessed: filtering on something that does not exist would silently return
 * nothing and look like « no vulnerabilities ».
 */
function filterClauses(fieldMap, query = {}) {
  const filters = [];
  const term = (field, value) => {
    if (!field || !value) return;
    filters.push({ term: { [field.queryPath]: value } });
  };
  term(fieldMap.severity, query.severity);
  term(fieldMap.assetName && fieldMap.assetName.aggregatable ? fieldMap.assetName : fieldMap.assetId, query.asset);

  const should = [];
  const cve = boundedSearchTerm(query.cve);
  if (cve) {
    const clause = containsClause(fieldMap.cve, cve);
    if (clause) filters.push(clause);
  }
  const pkg = boundedSearchTerm(query.package);
  if (pkg) {
    const clause = containsClause(fieldMap.packageName, pkg);
    if (clause) filters.push(clause);
  }
  const search = boundedSearchTerm(query.search);
  if (search) {
    for (const key of ['cve', 'packageName', 'description', 'assetName']) {
      const clause = containsClause(fieldMap[key], search);
      if (clause) should.push(clause);
    }
  }
  const bool = {};
  if (filters.length) bool.filter = filters;
  if (should.length) { bool.should = should; bool.minimum_should_match = 1; }
  return Object.keys(bool).length ? { bool } : { match_all: {} };
}

/**
 * The deployment-wide summary, as ONE aggregation request.
 *
 * `size: 0` means no document is transferred: the severity distribution and the
 * affected-asset count are computed by the cluster. There is no per-agent loop
 * because there is no reason for one.
 */
function summaryQuery(fieldMap, query = {}) {
  const aggs = {};
  if (fieldMap.severity?.aggregatable) {
    aggs.severity = { terms: { field: fieldMap.severity.queryPath, size: 16 } };
  }
  const assetField = fieldMap.assetName?.aggregatable ? fieldMap.assetName : (fieldMap.assetId?.aggregatable ? fieldMap.assetId : null);
  if (assetField) {
    aggs.affectedAssets = { cardinality: { field: assetField.queryPath } };
    aggs.assetFacets = { terms: { field: assetField.queryPath, size: LIMITS.MAX_FACET_VALUES } };
  }
  const body = { size: 0, track_total_hits: true, query: filterClauses(fieldMap, query) };
  if (Object.keys(aggs).length) body.aggs = aggs;
  return body;
}

/** One bounded page. `from + size` can never exceed the result window. */
function searchQuery(fieldMap, query = {}) {
  const size = Math.min(Math.max(Number(query.pageSize) || LIMITS.DEFAULT_PAGE_SIZE, 1), LIMITS.MAX_PAGE_SIZE);
  const page = Math.max(Number(query.page) || 1, 1);
  const maxPage = Math.max(1, Math.floor(LIMITS.MAX_RESULT_WINDOW / size));
  const from = (Math.min(page, maxPage) - 1) * size;
  const body = {
    from,
    size,
    track_total_hits: true,
    query: filterClauses(fieldMap, query)
  };
  // Sorting only on a field the deployment actually exposes and can sort on.
  const sortField = fieldMap.detectedAt?.aggregatable ? fieldMap.detectedAt : (fieldMap.indexedAt?.aggregatable ? fieldMap.indexedAt : null);
  if (sortField) body.sort = [{ [sortField.queryPath]: { order: 'desc' } }];
  return body;
}

/**
 * The alert filter clauses.
 *
 * Severity is not a field in this index — Wazuh stores a numeric rule level —
 * so a severity filter becomes the range that level maps to. Building it from
 * the same table the reader uses is what keeps a filtered list consistent with
 * the badge shown on each row.
 */
function alertFilterClauses(fieldMap, query = {}) {
  const filters = [];
  const term = (field, value) => {
    if (!field || !value) return;
    filters.push({ term: { [field.queryPath]: value } });
  };
  term(fieldMap.assetName && fieldMap.assetName.aggregatable ? fieldMap.assetName : fieldMap.assetId, query.asset);
  term(fieldMap.ruleId, query.rule);

  if (query.severity && fieldMap.ruleLevel) {
    const range = levelRangeFor(query.severity);
    if (range) filters.push({ range: { [fieldMap.ruleLevel.queryPath]: range } });
  }

  const should = [];
  const search = boundedSearchTerm(query.search);
  if (search) {
    for (const key of ['ruleDescription', 'assetName', 'ruleId', 'srcUser', 'fullLog']) {
      const clause = containsClause(fieldMap[key], search);
      if (clause) should.push(clause);
    }
  }
  const bool = {};
  if (filters.length) bool.filter = filters;
  if (should.length) { bool.should = should; bool.minimum_should_match = 1; }
  return Object.keys(bool).length ? { bool } : { match_all: {} };
}

/**
 * One bounded window of the most recent alerts.
 *
 * `size` is capped here and nowhere else, so no caller can ask the cluster for
 * the whole index. Sorting is applied only on a field the deployment actually
 * exposes.
 */
function alertSearchQuery(fieldMap, query = {}) {
  // A non-positive or unreadable limit is an absent limit, not a request for
  // one document: clamping it upwards would silently hide most of the window.
  const requested = Number(query.limit);
  const size = Math.min(Number.isFinite(requested) && requested > 0 ? requested : LIMITS.ALERT_WINDOW, LIMITS.MAX_ALERT_WINDOW);
  const body = { from: 0, size, track_total_hits: true, query: alertFilterClauses(fieldMap, query) };
  const sortField = fieldMap.timestamp?.aggregatable ? fieldMap.timestamp : null;
  if (sortField) body.sort = [{ [sortField.queryPath]: { order: 'desc' } }];
  return body;
}

/** `hits.total` is an object on modern clusters and a number on old ones. */
function totalHits(payload) {
  const total = payload?.hits?.total;
  if (typeof total === 'number') return total;
  const value = Number(total?.value);
  return Number.isFinite(value) ? value : 0;
}

function bucketList(aggregation) {
  return Array.isArray(aggregation?.buckets) ? aggregation.buckets : [];
}

/**
 * Reads the aggregation response.
 *
 * A metric the mapping could not support is `null`, not `0`: « the cluster was
 * not asked » and « the cluster answered none » must not render the same.
 */
function parseSummary(payload = {}, fieldMap = {}) {
  const aggregations = payload?.aggregations || {};
  const severity = fieldMap.severity?.aggregatable
    ? bucketList(aggregations.severity).map((bucket) => ({ value: String(bucket.key ?? ''), count: Number(bucket.doc_count) || 0 }))
    : null;
  const affectedAssets = aggregations.affectedAssets && Number.isFinite(Number(aggregations.affectedAssets.value))
    ? Number(aggregations.affectedAssets.value)
    : null;
  const assets = aggregations.assetFacets
    ? bucketList(aggregations.assetFacets).map((bucket) => ({ value: String(bucket.key ?? ''), count: Number(bucket.doc_count) || 0 }))
    : [];
  return { total: totalHits(payload), severity, affectedAssets, assets };
}

function parseHits(payload = {}) {
  const hits = Array.isArray(payload?.hits?.hits) ? payload.hits.hits : [];
  return hits.map((hit) => ({ id: String(hit?._id || ''), source: hit?._source && typeof hit._source === 'object' ? hit._source : {} }));
}

module.exports = {
  VULNERABILITY_INDEX_PATTERN,
  ALERT_INDEX_PATTERN,
  DATASET,
  SEVERITY_LEVELS,
  severityForLevel,
  levelRangeFor,
  FIELD_CANDIDATES: VULNERABILITY_FIELD_CANDIDATES,
  VULNERABILITY_FIELD_CANDIDATES,
  ALERT_FIELD_CANDIDATES,
  REQUIRED_FIELDS,
  ALERT_REQUIRED_FIELDS,
  alertFilterClauses,
  alertSearchQuery,
  LIMITS,
  INDEXER_ERROR,
  INDEXER_ERROR_MESSAGES,
  classifyIndexerError,
  indexerFailure,
  createIndexerClient,
  candidatePaths,
  resolveFieldMap,
  missingRequiredFields,
  filterClauses,
  summaryQuery,
  searchQuery,
  parseSummary,
  parseHits,
  totalHits
};
