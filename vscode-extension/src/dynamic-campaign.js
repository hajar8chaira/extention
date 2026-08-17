'use strict';

/**
 * Dynamic Security campaign identity.
 *
 * A campaign is one dynamic execution: a ZAP run, or a Burp capture session. It
 * exists so that a transaction, a finding and a lifecycle state can be attributed
 * to *the run that produced them* instead of floating in a global bag.
 *
 * Three rules shape this module:
 *
 *   - It invents nothing. A lifecycle state is recorded only when the execution
 *     layer reports it, and a progress percentage only when ZAP returned one. A
 *     stage that was never observed stays absent, not « 0% » and not « done ».
 *
 *   - It persists metadata only. Request and response bodies never enter a
 *     campaign; headers and parameters pass through the single existing
 *     sanitizer. The full sanitized detail is rebuilt on demand elsewhere.
 *
 *   - It is pure. No `vscode`, no clock of its own beyond an injectable one, no
 *     I/O. Persistence is the caller's existing local scan cache, which already
 *     round-trips `dashboardOptions` — this module adds no second store.
 */

const { SENSITIVE_HTTP_NAME, sanitizeHttpValue } = require('./dashboard');

/**
 * Lifecycle states.
 *
 * `PASSIVE_WAIT` is only ever entered when the passive-scan queue was actually
 * queried. ZAP exposes `pscan/view/recordsToScan`; when that call is unavailable
 * the state is skipped entirely rather than displayed as satisfied.
 */
const CAMPAIGN_STATUS = Object.freeze({
  STARTING: 'STARTING',
  SPIDERING: 'SPIDERING',
  PASSIVE_WAIT: 'PASSIVE_WAIT',
  ACTIVE_SCANNING: 'ACTIVE_SCANNING',
  COLLECTING_RESULTS: 'COLLECTING_RESULTS',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  CANCELLED: 'CANCELLED',
  FAILED: 'FAILED'
});

/** Once a campaign reaches one of these, its lifecycle is closed. */
const TERMINAL_STATUSES = Object.freeze([
  CAMPAIGN_STATUS.COMPLETED, CAMPAIGN_STATUS.PARTIAL,
  CAMPAIGN_STATUS.CANCELLED, CAMPAIGN_STATUS.FAILED
]);

const CAMPAIGN_SOURCES = Object.freeze(['zap', 'burp', 'replay']);

/** Connector states for a Burp session. `disconnected` never means « capturing ». */
const CAPTURE_STATE = Object.freeze({
  LIVE: 'live', HISTORICAL: 'historical', NEVER_CONNECTED: 'never_connected'
});

/** The bucket for data that predates campaign identity. Never a real campaign. */
const LEGACY_CAMPAIGN_ID = 'legacy-unattributed';

function isoNow(now) {
  return new Date(typeof now === 'function' ? now() : (now ?? Date.now())).toISOString();
}

/**
 * A campaign identifier.
 *
 * Sortable by construction (the timestamp leads) and collision-resistant through
 * the random suffix, so two runs started in the same millisecond stay distinct.
 */
function campaignId(source, { now = Date.now, random = () => Math.random().toString(16).slice(2, 10) } = {}) {
  const stamp = isoNow(now).replace(/[-:.]/g, '').replace('T', '-').slice(0, 15);
  return `${source}-${stamp}-${random()}`;
}

/**
 * A new campaign, in its initial state.
 *
 * `auth.status` starts as `unknown` on purpose: configuring credentials is not
 * evidence that authentication worked. Only the execution layer may promote it.
 */
function createCampaign({
  source, target = '', mode = '', auth = null, id = '', now = Date.now, random
} = {}) {
  if (!CAMPAIGN_SOURCES.includes(source)) throw new Error(`Source de campagne inconnue : ${source}.`);
  const startedAt = isoNow(now);
  return {
    id: id || campaignId(source, { now, random }),
    source,
    target: String(target || ''),
    mode: String(mode || ''),
    startedAt,
    completedAt: null,
    status: CAMPAIGN_STATUS.STARTING,
    auth: { mode: auth?.mode || 'anonymous', status: auth?.status || 'unknown' },
    lifecycle: [{ state: CAMPAIGN_STATUS.STARTING, at: startedAt, progress: null, detail: '' }],
    transactions: [],
    findingIds: [],
    statistics: { transactions: 0, uniqueEndpoints: 0, findings: 0 }
  };
}

/**
 * Records a lifecycle observation.
 *
 * Returns a new campaign. Refuses to reopen a finished one, and only appends an
 * entry when something actually changed — a progress poll that reports the same
 * percentage is not an event.
 */
function applyProgress(campaign, { state, progress = null, detail = '', now = Date.now } = {}) {
  if (!campaign) throw new Error('Campagne absente.');
  if (!Object.values(CAMPAIGN_STATUS).includes(state)) throw new Error(`État de campagne inconnu : ${state}.`);
  if (TERMINAL_STATUSES.includes(campaign.status)) return campaign;
  // A percentage is kept only when it really is one. `null` means « ZAP did not
  // say », which must never be rendered as zero.
  const percent = Number.isFinite(Number(progress)) && progress !== null && progress !== ''
    ? Math.max(0, Math.min(100, Math.round(Number(progress))))
    : null;
  const last = campaign.lifecycle[campaign.lifecycle.length - 1];
  if (last && last.state === state && last.progress === percent && last.detail === detail) return campaign;
  return {
    ...campaign,
    status: state,
    lifecycle: [...campaign.lifecycle, { state, at: isoNow(now), progress: percent, detail: String(detail || '') }]
  };
}

/**
 * Closes a campaign with its outcome and what it produced.
 *
 * `findingIds` and `transactions` are what this run is answerable for; nothing
 * else may later claim to belong to it.
 */
function completeCampaign(campaign, {
  status = CAMPAIGN_STATUS.COMPLETED, findingIds = [], transactions = null, auth = null, now = Date.now
} = {}) {
  if (!TERMINAL_STATUSES.includes(status)) throw new Error(`Issue de campagne invalide : ${status}.`);
  const finalTransactions = transactions ? [...transactions] : campaign.transactions;
  return {
    ...campaign,
    status,
    completedAt: isoNow(now),
    lifecycle: [...campaign.lifecycle, { state: status, at: isoNow(now), progress: null, detail: '' }],
    findingIds: [...new Set(findingIds.filter(Boolean))],
    transactions: finalTransactions,
    auth: auth ? { ...campaign.auth, ...auth } : campaign.auth,
    statistics: {
      transactions: finalTransactions.length,
      uniqueEndpoints: new Set(finalTransactions.map((item) => `${item.method} ${item.endpoint}`)).size,
      findings: new Set(findingIds.filter(Boolean)).size
    }
  };
}

/** The most advanced real percentage observed for a state, or null. */
function progressFor(campaign, state) {
  const entries = (campaign?.lifecycle || []).filter((entry) => entry.state === state && entry.progress !== null);
  return entries.length ? entries[entries.length - 1].progress : null;
}

/** Whether a state was actually observed. Absence is not failure — it is silence. */
function observed(campaign, state) {
  return (campaign?.lifecycle || []).some((entry) => entry.state === state);
}

/**
 * A captured HTTP exchange, reduced to safe metadata.
 *
 * Bodies are deliberately absent: a campaign is an index, not an archive, and
 * persisting request bodies is how credentials end up on disk. Header and
 * parameter values go through the one existing sanitizer.
 */
function toTransaction(scenario, { campaignId: id, source = '', index = 0 } = {}) {
  const request = scenario?.request || {};
  const response = scenario?.response || {};
  const rawUrl = String(request.url || '');
  let endpoint = rawUrl;
  let query = {};
  // The stored URL is sanitized too. Redacting only the parsed query map while
  // persisting the original URL would keep the secret on disk in the field most
  // likely to be displayed.
  let url = rawUrl;
  try {
    const parsed = new URL(rawUrl);
    endpoint = parsed.pathname.replace(/\/+$/, '') || '/';
    for (const [name, value] of parsed.searchParams) query[name] = sanitizeHttpValue(name, value);
    for (const name of [...parsed.searchParams.keys()]) {
      if (SENSITIVE_HTTP_NAME.test(name)) parsed.searchParams.set(name, '[REDACTED]');
    }
    url = parsed.toString();
  } catch {
    endpoint = rawUrl.split('?')[0].replace(/\/+$/, '') || rawUrl || '/';
  }
  const method = String(request.method || 'GET').toUpperCase();
  const durationMs = Number(scenario?.durationMs ?? scenario?.duration ?? response.durationMs ?? response.time ?? 0);
  const contentType = response.headers?.['content-type'] || response.headers?.['Content-Type']
    || response.mimeType || response.content?.mimeType || '';
  return {
    id: `${id}:${index}:${method}:${endpoint}`,
    campaignId: id,
    source: String(scenario?.source || source || 'capture'),
    // An absent timestamp stays null. The backend genuinely does not always
    // provide one, and « Not available » is the honest rendering of that.
    timestamp: scenario?.timestamp || scenario?.startedDateTime || null,
    method,
    url,
    endpoint,
    request: {
      headers: Object.fromEntries(Object.entries(request.headers || {}).map(([name, value]) => [name, sanitizeHttpValue(name, value)])),
      query,
      parameterNames: parameterNames(request),
      hasBody: Boolean(request.body)
    },
    response: {
      status: response.statusCode ?? response.status ?? null,
      contentType: String(contentType || ''),
      durationMs: durationMs > 0 ? durationMs : null,
      headers: Object.fromEntries(Object.entries(response.headers || {}).map(([name, value]) => [name, sanitizeHttpValue(name, value)]))
    },
    authenticated: Boolean(scenario?.authenticated),
    association: { findingIds: [], confidence: null },
    replay: null,
    retest: null
  };
}

/** Parameter names only — never their values, which may be credentials. */
function parameterNames(request) {
  const names = new Set();
  for (const parameter of request.parameters || []) if (parameter?.name) names.add(String(parameter.name));
  const body = String(request.body || '');
  if (body && /^[\w.[\]%+-]+=/.test(body)) {
    for (const pair of body.split('&')) {
      const name = pair.split('=')[0];
      if (name) names.add(decodeURIComponent(name));
    }
  } else if (body) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) for (const key of Object.keys(parsed)) names.add(key);
    } catch { /* an unreadable body contributes no name */ }
  }
  return [...names];
}

/**
 * Records an association on a transaction.
 *
 * The confidence comes from the existing association engine and is copied, never
 * recomputed here. Belonging to the same campaign is not evidence and never
 * raises a tier.
 */
function withAssociation(transaction, { findingIds = [], confidence = null } = {}) {
  return { ...transaction, association: { findingIds: [...new Set(findingIds.filter(Boolean))], confidence: confidence || null } };
}

/**
 * A Burp capture session state.
 *
 * Connector connectivity and captured history are separate facts. A disconnected
 * connector with stored requests is a *historical* session — describing it as
 * live would present old evidence as current traffic.
 */
function captureSessionFrom(status, { campaign = null } = {}) {
  const connected = status?.connected === true;
  const received = Number(status?.received_requests ?? status?.receivedRequests ?? 0) || 0;
  const lastSeen = status?.last_seen || status?.lastSeen || null;
  const state = connected ? CAPTURE_STATE.LIVE
    : (received > 0 || lastSeen) ? CAPTURE_STATE.HISTORICAL
      : CAPTURE_STATE.NEVER_CONNECTED;
  return {
    connected,
    state,
    // Only a live connector has a *current* session.
    currentSessionId: connected ? campaign?.id || null : null,
    lastSessionId: !connected && campaign ? campaign.id : null,
    lastSeen,
    receivedRequests: received,
    connector: String(status?.connector || ''),
    // The backend may hold requests without ever giving a timestamp. Saying so
    // is better than inventing one.
    lastSeenKnown: Boolean(lastSeen)
  };
}

/**
 * Restores a persisted campaign.
 *
 * Anything unrecognisable returns `null` rather than a half-built object, so a
 * cache written by an older version can never crash a page or masquerade as a
 * valid run.
 */
function restoreCampaign(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (!raw.id || !CAMPAIGN_SOURCES.includes(raw.source)) return null;
  if (!Object.values(CAMPAIGN_STATUS).includes(raw.status)) return null;
  const transactions = Array.isArray(raw.transactions) ? raw.transactions.filter((item) => item && item.id) : [];
  return {
    id: String(raw.id),
    source: raw.source,
    target: String(raw.target || ''),
    mode: String(raw.mode || ''),
    startedAt: raw.startedAt || null,
    completedAt: raw.completedAt || null,
    status: raw.status,
    auth: { mode: raw.auth?.mode || 'anonymous', status: raw.auth?.status || 'unknown' },
    lifecycle: Array.isArray(raw.lifecycle)
      ? raw.lifecycle.filter((entry) => entry && Object.values(CAMPAIGN_STATUS).includes(entry.state))
        .map((entry) => ({
          state: entry.state, at: entry.at || null,
          progress: Number.isFinite(entry.progress) ? entry.progress : null,
          detail: String(entry.detail || '')
        }))
      : [],
    transactions,
    findingIds: Array.isArray(raw.findingIds) ? raw.findingIds.filter(Boolean).map(String) : [],
    statistics: {
      transactions: Number(raw.statistics?.transactions) || transactions.length,
      uniqueEndpoints: Number(raw.statistics?.uniqueEndpoints) || 0,
      findings: Number(raw.statistics?.findings) || 0
    },
    restored: true
  };
}

/**
 * The bucket for transactions and findings that predate campaign identity.
 *
 * Explicitly not a campaign: no lifecycle, no target claim, no timing. It exists
 * so old cached data keeps being shown without being attributed to a run that
 * cannot be proven to have produced it.
 */
function legacyBucket(transactionCount = 0) {
  return {
    id: LEGACY_CAMPAIGN_ID,
    source: 'legacy',
    legacy: true,
    status: 'UNATTRIBUTED',
    target: '',
    startedAt: null,
    completedAt: null,
    lifecycle: [],
    transactions: [],
    findingIds: [],
    statistics: { transactions: Number(transactionCount) || 0, uniqueEndpoints: 0, findings: 0 }
  };
}

/** Whether persisted dynamic data carries campaign identity at all. */
function hasCampaignIdentity(options) {
  return Boolean(options?.dynamicCampaign?.id) && !options.dynamicCampaign.legacy;
}

module.exports = {
  CAMPAIGN_STATUS, TERMINAL_STATUSES, CAMPAIGN_SOURCES, CAPTURE_STATE, LEGACY_CAMPAIGN_ID,
  campaignId, createCampaign, applyProgress, completeCampaign, progressFor, observed,
  toTransaction, parameterNames, withAssociation, captureSessionFrom,
  restoreCampaign, legacyBucket, hasCampaignIdentity, SENSITIVE_HTTP_NAME
};
