'use strict';

/**
 * API inventory and dynamic coverage.
 *
 * Builds a canonical endpoint list from what was actually observed — Burp capture,
 * ZAP findings, a HAR import, an OpenAPI import — and states, per endpoint, how
 * far dynamic testing really went.
 *
 * The distinction this module exists to protect: **appearing in proxy traffic is
 * not being tested**. A request that crossed Burp proves the endpoint exists and
 * responds. It proves nothing about whether a security test was ever aimed at it.
 * Coverage therefore has ordered states, and the weakest one is the default.
 *
 * Normalization is deliberately conservative. `/users/123` and `/users/456` are
 * the same route; `/products/shoes` and `/products/hats` are not obviously so. A
 * segment is collapsed into a parameter only on strong evidence — a numeric id, a
 * UUID, a long hex digest — or when several distinct values were genuinely seen at
 * the same position. Everything else stays separate: an inventory that merges too
 * eagerly hides endpoints, which is the opposite of its purpose.
 */

/**
 * `dashboard` is required lazily, inside the functions that need it.
 *
 * The dashboard renders these sections, so a top-level require would close a
 * cycle — and Node resolves a cycle by handing back half-initialised exports,
 * which made `associationFor` and `endpointPath` `undefined` at load time. The
 * failure was invisible in isolation and only appeared through the page.
 */
function dashboardApi() {
  return require('./dashboard');
}

/**
 * How far testing went, weakest first. The order is the semantics: when two
 * pieces of evidence disagree, the stronger one wins, and nothing is ever
 * upgraded by a source that does not warrant it.
 */
const COVERAGE_STATE = Object.freeze({
  NOT_TESTED: 'NOT_TESTED',
  OBSERVED: 'OBSERVED',
  PASSIVELY_ANALYZED: 'PASSIVELY_ANALYZED',
  REPLAYED: 'REPLAYED',
  ACTIVELY_TESTED: 'ACTIVELY_TESTED'
});

const COVERAGE_RANK = Object.freeze({
  NOT_TESTED: 0, OBSERVED: 1, PASSIVELY_ANALYZED: 2, REPLAYED: 3, ACTIVELY_TESTED: 4
});

/** Where an endpoint became known. Several may apply to the same endpoint. */
const ENDPOINT_SOURCE = Object.freeze({
  BURP: 'BURP', ZAP: 'ZAP', HAR: 'HAR', OPENAPI: 'OPENAPI', REPLAY: 'REPLAY'
});

/** Confidence that a collapsed segment really is a parameter. */
const NORMALIZATION_CONFIDENCE = Object.freeze({ HIGH: 'HIGH', OBSERVED: 'OBSERVED', NONE: 'NONE' });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONG_HEX = /^[0-9a-f]{24,}$/i;
const NUMERIC = /^\d+$/;
/** A ULID or similar: long, uppercase-ish, and mixing letters with digits. */
const OPAQUE_ID = /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{16,}$/;

/**
 * Whether a path segment is a dynamic identifier on its own evidence.
 *
 * Only shapes that are identifiers by convention qualify. A word, a slug or a
 * file name never does, however many times it appears.
 */
function looksLikeIdentifier(segment) {
  const value = String(segment || '');
  if (!value) return false;
  if (NUMERIC.test(value)) return true;
  if (UUID.test(value)) return true;
  if (LONG_HEX.test(value)) return true;
  // A dotted name is a file, not an id: `report.pdf` must stay itself.
  if (value.includes('.')) return false;
  return OPAQUE_ID.test(value);
}

/**
 * Templates a path, collapsing only segments that are identifiers by shape.
 *
 * Returns the template and the confidence: `HIGH` when something was collapsed on
 * its own evidence, `NONE` when the path was left untouched.
 */
function templatePath(pathname) {
  const raw = String(pathname || '/');
  const segments = raw.split('/');
  let collapsed = 0;
  const templated = segments.map((segment, index) => {
    if (!segment) return segment;
    if (!looksLikeIdentifier(segment)) return segment;
    collapsed += 1;
    // Named after the preceding segment when there is one: `/users/{id}` reads
    // better than `/users/{param1}` and survives a reordering of the inventory.
    const parent = segments[index - 1];
    return parent && /^[a-z][\w-]*$/i.test(parent) ? '{id}' : '{param}';
  }).join('/');
  return {
    template: templated || '/',
    confidence: collapsed ? NORMALIZATION_CONFIDENCE.HIGH : NORMALIZATION_CONFIDENCE.NONE,
    collapsed
  };
}

/**
 * Second-pass templating from real observations.
 *
 * Two concrete paths that differ in exactly one segment, where that segment took
 * several distinct values, describe one route with a parameter — even when the
 * values are not identifier-shaped. Requiring a *difference in exactly one
 * position* is what keeps `/a/x` and `/b/y` apart.
 */
function templateFromObservations(paths) {
  const groups = new Map();
  const concrete = [...new Set(paths.map((value) => String(value || '/')))];
  for (const pathname of concrete) {
    const segments = pathname.split('/');
    for (let index = 0; index < segments.length; index += 1) {
      if (!segments[index]) continue;
      const key = `${segments.length}:${index}:${segments.map((segment, position) => (position === index ? '*' : segment)).join('/')}`;
      if (!groups.has(key)) groups.set(key, { index, segments, values: new Set() });
      groups.get(key).values.add(segments[index]);
    }
  }
  const templates = new Map();
  for (const group of groups.values()) {
    // Three distinct values at one position is strong evidence. Two is not: an
    // API with exactly `/status/up` and `/status/down` is two endpoints.
    if (group.values.size < 3) continue;
    const parent = group.segments[group.index - 1];
    // A parameter needs a collection to belong to. Without a parent segment,
    // `/a`, `/b` and `/c` are three top-level endpoints, not one route with a
    // parameter — collapsing them would erase three real endpoints.
    if (!parent) continue;
    const template = group.segments
      .map((segment, position) => (position === group.index ? (parent && /^[a-z][\w-]*$/i.test(parent) ? '{id}' : '{param}') : segment))
      .join('/');
    for (const value of group.values) {
      const concretePath = group.segments.map((segment, position) => (position === group.index ? value : segment)).join('/');
      templates.set(concretePath, template);
    }
  }
  return templates;
}

function endpointKey(method, template) {
  return `${String(method || 'GET').toUpperCase()} ${template}`;
}

function hostOf(url) {
  try { return new URL(String(url)).host; } catch { return ''; }
}

function queryKeysOf(url) {
  try { return [...new URL(String(url)).searchParams.keys()].map((key) => key.toLowerCase()).sort(); }
  catch { return []; }
}

/**
 * Whether a transaction carried authentication.
 *
 * Read from the sanitized headers: the *presence* of an Authorization or Cookie
 * header is the signal, and the value is never needed — nor available, since the
 * sanitizer already replaced it.
 */
function isAuthenticated(transaction) {
  if (transaction?.authenticated === true) return true;
  const headers = transaction?.request?.headers || {};
  return Object.keys(headers).some((name) => /^(authorization|cookie|x-api-key|x-auth-token)$/i.test(name));
}

/**
 * Builds the inventory.
 *
 * `transactions` are canonical `DynamicTransaction` objects (or raw scenarios —
 * both shapes are read). `findings` are the normalized findings; they are matched
 * to endpoints through the existing association engine, never re-derived here.
 * `activeTested` and `replayed` name endpoint keys the caller can prove.
 */
function buildApiInventory({
  transactions = [], findings = [], openapiEndpoints = [],
  activelyTested = [], replayed = [], passivelyAnalyzed = []
} = {}) {
  // Every list is defended: a caller passing `null` for a source it does not have
  // is normal, and must not crash an inventory.
  const observations = (Array.isArray(transactions) ? transactions : [])
    .map((item) => normalizeObservation(item)).filter(Boolean);
  // Second pass needs the concrete paths, per method, so `/a/{id}` from GET does
  // not template a POST path that was never observed that way.
  const byMethod = new Map();
  for (const observation of observations) {
    if (!byMethod.has(observation.method)) byMethod.set(observation.method, []);
    byMethod.get(observation.method).push(observation.pathname);
  }
  const observedTemplates = new Map();
  for (const [method, paths] of byMethod) {
    for (const [concrete, template] of templateFromObservations(paths)) {
      observedTemplates.set(`${method} ${concrete}`, template);
    }
  }

  const endpoints = new Map();
  const upsert = (method, template, patch) => {
    const key = endpointKey(method, template);
    const current = endpoints.get(key) || {
      key, method: String(method).toUpperCase(), template,
      host: '', concretePaths: new Set(), queryParameters: new Set(), contentTypes: new Set(),
      sources: new Set(), authenticatedRequests: 0, requestCount: 0,
      firstSeen: null, lastSeen: null, lastStatusCode: null,
      findingIds: new Set(), coverage: COVERAGE_STATE.NOT_TESTED,
      normalization: NORMALIZATION_CONFIDENCE.NONE
    };
    endpoints.set(key, patch(current) || current);
    return endpoints.get(key);
  };

  for (const observation of observations) {
    const shapeTemplate = templatePath(observation.pathname);
    const observedTemplate = observedTemplates.get(`${observation.method} ${observation.pathname}`);
    // Shape evidence is stronger than co-occurrence: a numeric id is an id even
    // if it was only seen once.
    const template = shapeTemplate.confidence === NORMALIZATION_CONFIDENCE.HIGH
      ? shapeTemplate.template
      : (observedTemplate || observation.pathname);
    const normalization = shapeTemplate.confidence === NORMALIZATION_CONFIDENCE.HIGH
      ? NORMALIZATION_CONFIDENCE.HIGH
      : (observedTemplate ? NORMALIZATION_CONFIDENCE.OBSERVED : NORMALIZATION_CONFIDENCE.NONE);
    upsert(observation.method, template, (endpoint) => {
      endpoint.host = endpoint.host || observation.host;
      endpoint.concretePaths.add(observation.pathname);
      for (const key of observation.queryKeys) endpoint.queryParameters.add(key);
      if (observation.contentType) endpoint.contentTypes.add(observation.contentType);
      endpoint.sources.add(observation.source);
      endpoint.requestCount += 1;
      if (observation.authenticated) endpoint.authenticatedRequests += 1;
      if (observation.timestamp) {
        if (!endpoint.firstSeen || observation.timestamp < endpoint.firstSeen) endpoint.firstSeen = observation.timestamp;
        if (!endpoint.lastSeen || observation.timestamp > endpoint.lastSeen) endpoint.lastSeen = observation.timestamp;
      }
      if (observation.status !== null) endpoint.lastStatusCode = observation.status;
      endpoint.normalization = normalization === NORMALIZATION_CONFIDENCE.HIGH ? NORMALIZATION_CONFIDENCE.HIGH : endpoint.normalization === NORMALIZATION_CONFIDENCE.HIGH ? endpoint.normalization : normalization;
      // Crossing a proxy establishes existence, nothing more.
      endpoint.coverage = strongest(endpoint.coverage, COVERAGE_STATE.OBSERVED);
      return endpoint;
    });
  }

  // OpenAPI declares endpoints that may never have been reached. They enter the
  // inventory as NOT_TESTED so « never reached » is visible instead of absent.
  for (const declared of Array.isArray(openapiEndpoints) ? openapiEndpoints : []) {
    const method = String(declared?.method || 'GET').toUpperCase();
    const pathname = String(declared?.path || declared?.template || '/');
    upsert(method, pathname, (endpoint) => {
      endpoint.sources.add(ENDPOINT_SOURCE.OPENAPI);
      if (declared?.host) endpoint.host = endpoint.host || String(declared.host);
      return endpoint;
    });
  }

  // Findings attach through the existing association engine only.
  for (const endpoint of endpoints.values()) {
    for (const finding of Array.isArray(findings) ? findings : []) {
      if (!matchesEndpoint(endpoint, finding)) continue;
      endpoint.findingIds.add(String(finding.id || finding.ruleId || ''));
      if (String(finding.tool || '').toUpperCase() === 'ZAP') endpoint.sources.add(ENDPOINT_SOURCE.ZAP);
    }
  }

  // Caller-proven evidence, applied last so it can only raise coverage.
  applyEvidence(endpoints, passivelyAnalyzed, COVERAGE_STATE.PASSIVELY_ANALYZED);
  applyEvidence(endpoints, replayed, COVERAGE_STATE.REPLAYED, ENDPOINT_SOURCE.REPLAY);
  applyEvidence(endpoints, activelyTested, COVERAGE_STATE.ACTIVELY_TESTED, ENDPOINT_SOURCE.ZAP);

  return [...endpoints.values()]
    .map((endpoint) => ({
      key: endpoint.key,
      method: endpoint.method,
      host: endpoint.host,
      template: endpoint.template,
      concretePaths: [...endpoint.concretePaths].sort(),
      queryParameters: [...endpoint.queryParameters].sort(),
      contentTypes: [...endpoint.contentTypes].sort(),
      sources: [...endpoint.sources].sort(),
      authenticated: endpoint.authenticatedRequests > 0,
      authenticatedRequests: endpoint.authenticatedRequests,
      requestCount: endpoint.requestCount,
      firstSeen: endpoint.firstSeen,
      lastSeen: endpoint.lastSeen,
      lastStatusCode: endpoint.lastStatusCode,
      findingIds: [...endpoint.findingIds].filter(Boolean).sort(),
      findingCount: [...endpoint.findingIds].filter(Boolean).length,
      coverage: endpoint.coverage,
      normalization: endpoint.normalization
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

/** Raises the coverage of the named endpoints, never lowers it. */
function applyEvidence(endpoints, keys, state, source = null) {
  for (const key of keys || []) {
    const endpoint = endpoints.get(String(key));
    if (!endpoint) continue;
    endpoint.coverage = strongest(endpoint.coverage, state);
    if (source) endpoint.sources.add(source);
  }
}

function strongest(left, right) {
  return (COVERAGE_RANK[right] ?? 0) > (COVERAGE_RANK[left] ?? 0) ? right : left;
}

/** Reads both the canonical transaction shape and a raw captured scenario. */
function normalizeObservation(item) {
  const request = item?.request || {};
  const url = String(item?.url || request.url || '');
  if (!url) return null;
  const method = String(item?.method || request.method || 'GET').toUpperCase();
  const pathname = item?.endpoint && String(item.endpoint).startsWith('/')
    ? String(item.endpoint)
    : dashboardApi().endpointPath(url);
  const response = item?.response || {};
  const status = Number.isFinite(Number(response.status ?? response.statusCode))
    ? Number(response.status ?? response.statusCode) : null;
  return {
    method,
    pathname: pathname || '/',
    host: hostOf(url),
    queryKeys: queryKeysOf(url),
    contentType: String(response.contentType || response.headers?.['content-type'] || '').split(';')[0].trim(),
    source: sourceOf(item),
    authenticated: isAuthenticated(item),
    timestamp: item?.timestamp || null,
    status
  };
}

function sourceOf(item) {
  const raw = String(item?.source || '').toLowerCase();
  if (raw.includes('zap')) return ENDPOINT_SOURCE.ZAP;
  if (raw.includes('har')) return ENDPOINT_SOURCE.HAR;
  if (raw.includes('replay')) return ENDPOINT_SOURCE.REPLAY;
  return ENDPOINT_SOURCE.BURP;
}

/**
 * Whether a finding belongs to an endpoint.
 *
 * Reuses the existing association engine on each concrete path the endpoint was
 * observed at, and accepts only EXACT or STRONG. A PROBABLE association is not
 * enough to claim an endpoint « has findings » in an inventory.
 */
function matchesEndpoint(endpoint, finding) {
  if (!finding?.endpoint) return false;
  const method = String(finding.method || '').toUpperCase();
  if (method && method !== 'HTTP' && method !== endpoint.method) return false;
  const paths = endpoint.concretePaths.size ? [...endpoint.concretePaths] : [endpoint.template];
  const { associationFor, ASSOCIATION_CONFIDENCE } = dashboardApi();
  return paths.some((pathname) => {
    const association = associationFor(
      { request: { url: `http://${endpoint.host || '127.0.0.1'}${pathname}`, method: endpoint.method } },
      finding
    );
    return association.confidence === ASSOCIATION_CONFIDENCE.EXACT
      || association.confidence === ASSOCIATION_CONFIDENCE.STRONG;
  });
}

/**
 * Coverage summary.
 *
 * `tested` counts only endpoints that were actually subjected to a test — passive
 * analysis, a replay or an active scan. An observed endpoint is explicitly *not*
 * tested, and the percentage says so.
 */
function summarizeCoverage(inventory = []) {
  const counts = Object.fromEntries(Object.keys(COVERAGE_RANK).map((state) => [state, 0]));
  const methods = new Set();
  let authenticated = 0;
  let withFindings = 0;
  for (const endpoint of inventory) {
    counts[endpoint.coverage] = (counts[endpoint.coverage] || 0) + 1;
    methods.add(endpoint.method);
    if (endpoint.authenticated) authenticated += 1;
    if (endpoint.findingCount) withFindings += 1;
  }
  const total = inventory.length;
  const tested = counts.PASSIVELY_ANALYZED + counts.REPLAYED + counts.ACTIVELY_TESTED;
  const observed = total - counts.NOT_TESTED;
  return {
    total,
    observed,
    tested,
    untested: total - tested,
    notReached: counts.NOT_TESTED,
    passivelyAnalyzed: counts.PASSIVELY_ANALYZED,
    replayed: counts.REPLAYED,
    activelyTested: counts.ACTIVELY_TESTED,
    authenticated,
    withFindings,
    methods: [...methods].sort(),
    byState: counts,
    // Share of endpoints a security test was actually aimed at. Zero endpoints
    // means zero coverage, not a vacuous 100 %.
    coveragePercent: total ? Math.round((tested / total) * 100) : 0,
    activeCoveragePercent: total ? Math.round((counts.ACTIVELY_TESTED / total) * 100) : 0
  };
}

/** Human wording, so a surface never has to invent it. */
const COVERAGE_LABELS = Object.freeze({
  NOT_TESTED: 'Non atteint',
  OBSERVED: 'Observé — non testé',
  PASSIVELY_ANALYZED: 'Analysé passivement',
  REPLAYED: 'Rejoué',
  ACTIVELY_TESTED: 'Testé activement'
});

module.exports = {
  COVERAGE_STATE, COVERAGE_RANK, COVERAGE_LABELS, ENDPOINT_SOURCE, NORMALIZATION_CONFIDENCE,
  looksLikeIdentifier, templatePath, templateFromObservations, endpointKey,
  buildApiInventory, summarizeCoverage, isAuthenticated, matchesEndpoint, strongest
};
