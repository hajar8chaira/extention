'use strict';

/**
 * Alert querying for the Runtime Security domain.
 *
 * Everything here works on the alerts the adapter already returned — no
 * provider request, no re-fetch, no inference. Filtering, faceting and
 * pagination are pure functions so the rules can be tested without an editor
 * and without a SIEM.
 *
 * Two field-name conventions coexist on purpose. The normalized alert model
 * (`siem-contract.normalizeAlert`) says `endpoint` and `description`; the older
 * page fixtures and the dashboard card say `host` and `summary`. Reading both
 * is what lets the real Wazuh payload display correctly without breaking any
 * existing caller.
 */

const SEVERITY_ORDER = Object.freeze(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const DEFAULT_PAGE_SIZE = 10;

const text = (value) => String(value ?? '').trim();

/** The asset an alert is about, whichever convention produced it. */
function alertEndpoint(alert = {}) {
  return text(alert.endpoint) || text(alert.host);
}

/** The alert body, whichever convention produced it. */
function alertDescription(alert = {}) {
  return text(alert.description) || text(alert.summary);
}

function alertSeverity(alert = {}) {
  return text(alert.severity).toUpperCase();
}

/**
 * A stable identity for one alert.
 *
 * The provider id is preferred; the rule/timestamp pair is the fallback for
 * payloads that carry no id. The index is the last resort so that two
 * otherwise identical alerts never collapse into one row.
 */
function alertKey(alert = {}, index = 0) {
  return text(alert.id) || text(alert.rawReference) || `${text(alert.ruleId) || 'rule'}:${text(alert.timestamp) || index}`;
}

/** A query is always complete and always in range — callers may send anything. */
function normalizeAlertQuery(query = {}) {
  const page = Number.parseInt(query.page, 10);
  return {
    search: text(query.search),
    severity: text(query.severity).toUpperCase(),
    agent: text(query.agent),
    rule: text(query.rule),
    page: Number.isFinite(page) && page > 0 ? page : 1,
    alert: text(query.alert)
  };
}

function isFiltered(query) {
  const normalized = normalizeAlertQuery(query);
  return Boolean(normalized.search || normalized.severity || normalized.agent || normalized.rule);
}

/**
 * The values a filter can actually take, read from the alerts in hand.
 *
 * Offering a filter for something the provider never returned would promise a
 * result that cannot exist, so every option here is backed by at least one alert.
 */
function alertFacets(alerts = []) {
  const severities = new Map();
  const agents = new Map();
  const rules = new Map();
  for (const alert of alerts) {
    const severity = alertSeverity(alert);
    if (severity) severities.set(severity, (severities.get(severity) || 0) + 1);
    const endpoint = alertEndpoint(alert);
    if (endpoint) agents.set(endpoint, (agents.get(endpoint) || 0) + 1);
    const rule = text(alert.ruleId);
    if (rule) rules.set(rule, (rules.get(rule) || 0) + 1);
  }
  const entries = (map) => [...map.entries()].map(([value, count]) => ({ value, count }));
  return {
    severities: entries(severities).sort((left, right) => SEVERITY_ORDER.indexOf(left.value) - SEVERITY_ORDER.indexOf(right.value)),
    agents: entries(agents).sort((left, right) => left.value.localeCompare(right.value)),
    rules: entries(rules).sort((left, right) => left.value.localeCompare(right.value, undefined, { numeric: true }))
  };
}

/**
 * Free text matches the fields a human would read: title, description, rule,
 * asset, user and technique. It never matches on an id the user cannot see.
 */
function matchesSearch(alert, needle) {
  if (!needle) return true;
  const haystack = [
    text(alert.title), alertDescription(alert), text(alert.ruleId),
    alertEndpoint(alert), text(alert.user), (alert.mitreTechniques || []).join(' ')
  ].join(' ').toLowerCase();
  return haystack.includes(needle.toLowerCase());
}

function filterAlerts(alerts = [], query = {}) {
  const normalized = normalizeAlertQuery(query);
  return alerts.filter((alert) => (
    matchesSearch(alert, normalized.search)
    && (!normalized.severity || alertSeverity(alert) === normalized.severity)
    && (!normalized.agent || alertEndpoint(alert) === normalized.agent)
    && (!normalized.rule || text(alert.ruleId) === normalized.rule)
  ));
}

/**
 * Bounded loading: a page of a filtered set, clamped so a stale page number
 * from a previous filter can never produce an empty screen.
 */
function paginateAlerts(alerts = [], query = {}, pageSize = DEFAULT_PAGE_SIZE) {
  const size = Number.isFinite(pageSize) && pageSize > 0 ? pageSize : DEFAULT_PAGE_SIZE;
  const total = alerts.length;
  const pageCount = Math.max(1, Math.ceil(total / size));
  const page = Math.min(Math.max(normalizeAlertQuery(query).page, 1), pageCount);
  const start = (page - 1) * size;
  const items = alerts.slice(start, start + size);
  return {
    items, page, pageCount, total, pageSize: size,
    from: total ? start + 1 : 0,
    to: start + items.length
  };
}

/** The alert a detail view is about, by key. Never by position. */
function findAlert(alerts = [], key = '') {
  const wanted = text(key);
  if (!wanted) return null;
  return alerts.find((alert, index) => alertKey(alert, index) === wanted) || null;
}

/**
 * The investigation facts, conditionally.
 *
 * A field the provider did not supply is absent, not filled with a placeholder
 * and never reconstructed from something else: an empty user field means Wazuh
 * sent no user, which is information in itself.
 */
function alertDetailFields(alert = {}, runtime = {}) {
  const fields = [];
  const add = (label, value) => { if (text(value)) fields.push({ label, value: text(value) }); };
  add('Severity', alertSeverity(alert));
  add('Status', alert.status);
  add('Detected at', alert.timestamp);
  add('Provider', runtime.label || (runtime.provider && runtime.provider.label) || alert.source);
  add('Rule ID', alert.ruleId);
  add('Agent / asset', alertEndpoint(alert));
  add('User', alert.user);
  if ((alert.mitreTechniques || []).length) fields.push({ label: 'MITRE techniques', value: alert.mitreTechniques.join(', ') });
  add('Raw reference', alert.rawReference);
  return fields;
}

module.exports = {
  SEVERITY_ORDER,
  DEFAULT_PAGE_SIZE,
  alertEndpoint,
  alertDescription,
  alertSeverity,
  alertKey,
  normalizeAlertQuery,
  isFiltered,
  alertFacets,
  filterAlerts,
  paginateAlerts,
  findAlert,
  alertDetailFields
};
