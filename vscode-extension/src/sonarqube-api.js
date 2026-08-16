const http = require('http');
const https = require('https');

const MAX_PAGE_SIZE = 500;
// SonarQube refuses paginated queries beyond 10000 results.
const MAX_TOTAL_RESULTS = 10000;
// api/rules/show resolves one rule per call, so requests are issued in small
// concurrent batches rather than one large query.
const RULE_BATCH_SIZE = 5;

const SONAR_ERROR_CODES = Object.freeze({
  AUTH_ERROR: 'AUTH_ERROR',
  SERVER_UNAVAILABLE: 'SERVER_UNAVAILABLE',
  TIMEOUT: 'TIMEOUT',
  FAILED: 'FAILED',
  CANCELED: 'CANCELED',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  CONFIG_ERROR: 'CONFIG_ERROR'
});

class SonarError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SonarError';
    this.code = SONAR_ERROR_CODES[code] ? code : 'FAILED';
  }
}

function normalizeHostUrl(value) {
  const input = String(value || '').trim();
  if (!input) throw new SonarError('CONFIG_ERROR', 'Aucune URL de serveur SonarQube configurée.');
  let url;
  try { url = new URL(input); } catch { throw new SonarError('CONFIG_ERROR', 'URL SonarQube invalide.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new SonarError('CONFIG_ERROR', 'Le serveur SonarQube doit utiliser HTTP ou HTTPS.');
  return url.toString().replace(/\/+$/, '');
}

function sonarUrl(hostUrl, apiPath, query = {}) {
  const url = new URL(String(apiPath).replace(/^\/+/, ''), `${normalizeHostUrl(hostUrl)}/`);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    url.searchParams.set(key, String(value));
  }
  return url;
}

function abortError() {
  return new SonarError('CANCELED', 'Analyse SonarQube annulée.');
}

function delay(durationMs, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const timer = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, durationMs);
    function onAbort() { clearTimeout(timer); reject(abortError()); }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Performs an authenticated SonarQube API call.
 * The token is only ever sent as an Authorization header: it never reaches the
 * query string, and no rejection message repeats a credential value.
 */
function sonarRequest(hostUrl, apiPath, { token = '', query = {}, timeoutMs = 15000, signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    let url;
    try { url = sonarUrl(hostUrl, apiPath, query); } catch (error) { return reject(error); }
    const transport = url.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json' };
    if (token) headers.authorization = `Bearer ${token}`;
    const request = transport.request(url, { method: 'GET', headers, timeout: timeoutMs }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const status = response.statusCode || 500;
        const text = Buffer.concat(chunks).toString('utf8');
        if (status === 401) return reject(new SonarError('AUTH_ERROR', 'SonarQube a refusé le jeton (HTTP 401). Reconfigurez le jeton dans Security Center.'));
        if (status === 403) return reject(new SonarError('AUTH_ERROR', 'Le jeton SonarQube n’a pas les droits nécessaires sur ce projet (HTTP 403).'));
        if (status === 404) return reject(new SonarError('FAILED', `SonarQube ne connaît pas la ressource demandée (HTTP 404 sur ${url.pathname}).`));
        if (status >= 500) return reject(new SonarError('SERVER_UNAVAILABLE', `Le serveur SonarQube a renvoyé une erreur interne (HTTP ${status}).`));
        if (status >= 400) return reject(new SonarError('FAILED', `SonarQube a répondu HTTP ${status} sur ${url.pathname}.`));
        try { resolve(text ? JSON.parse(text) : {}); }
        catch { reject(new SonarError('INVALID_RESPONSE', 'SonarQube a renvoyé une réponse JSON invalide.')); }
      });
    });
    const onAbort = () => request.destroy(abortError());
    signal?.addEventListener('abort', onAbort, { once: true });
    request.on('close', () => signal?.removeEventListener('abort', onAbort));
    request.on('timeout', () => request.destroy(new SonarError('TIMEOUT', `Le serveur SonarQube ne répond pas après ${Math.round(timeoutMs / 1000)} secondes.`)));
    request.on('error', (error) => reject(error instanceof SonarError
      ? error
      : new SonarError('SERVER_UNAVAILABLE', `Le serveur SonarQube ${url.origin} est injoignable.`)));
    request.end();
  });
}

/** Lightweight preflight. `api/system/status` is public, so it works before a token exists. */
async function checkServerStatus(hostUrl, { timeoutMs = 10000, signal } = {}) {
  const payload = await sonarRequest(hostUrl, 'api/system/status', { timeoutMs, signal });
  const status = String(payload?.status || '').toUpperCase();
  if (status !== 'UP') {
    throw new SonarError('SERVER_UNAVAILABLE', `Le serveur SonarQube n’est pas prêt (état ${status || 'inconnu'}). Attendez la fin du démarrage.`);
  }
  return { status, version: String(payload?.version || '') };
}

/**
 * Confirms the stored token is accepted by the server. SonarQube answers
 * `{valid:false}` with HTTP 200 for a rejected token, so a false result is a
 * genuine authentication failure rather than a transport problem.
 */
async function validateToken(hostUrl, token, { timeoutMs = 10000, signal } = {}) {
  if (!String(token || '').trim()) return false;
  try {
    const payload = await sonarRequest(hostUrl, 'api/authentication/validate', { token, timeoutMs, signal });
    return payload?.valid === true;
  } catch (error) {
    if (error instanceof SonarError && error.code === 'AUTH_ERROR') return false;
    throw error;
  }
}

/**
 * A finished sonar-scanner process only means the report was submitted. The
 * Compute Engine still has to process it, so we poll the task until it settles.
 */
async function waitForTask(hostUrl, taskId, { token = '', timeoutMs = 300000, pollIntervalMs = 2000, signal, requestTimeoutMs = 15000 } = {}) {
  if (!String(taskId || '').trim()) throw new SonarError('FAILED', 'SonarScanner n’a pas fourni d’identifiant de tâche serveur.');
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  for (;;) {
    if (signal?.aborted) throw abortError();
    const payload = await sonarRequest(hostUrl, 'api/ce/task', { token, query: { id: taskId }, timeoutMs: requestTimeoutMs, signal });
    const task = payload?.task || {};
    const status = String(task.status || '').toUpperCase();
    if (status === 'SUCCESS') return { status, analysisId: String(task.analysisId || ''), componentKey: String(task.componentKey || '') };
    if (status === 'FAILED') throw new SonarError('FAILED', `Le traitement SonarQube a échoué : ${task.errorMessage || 'raison non communiquée par le serveur'}.`);
    if (status === 'CANCELED') throw new SonarError('CANCELED', 'Le traitement SonarQube a été annulé côté serveur.');
    if (Date.now() >= deadline) {
      throw new SonarError('TIMEOUT', `Le traitement SonarQube n’est pas terminé après ${Math.round(timeoutMs / 1000)} secondes (dernier état : ${status || 'inconnu'}).`);
    }
    await delay(pollIntervalMs, signal);
  }
}

function pagedTotal(payload, fallback) {
  const total = Number(payload?.total ?? payload?.paging?.total ?? fallback);
  return Number.isFinite(total) ? total : fallback;
}

async function fetchPaged(hostUrl, apiPath, { token, query = {}, collection, timeoutMs, signal, pageSize = MAX_PAGE_SIZE }) {
  const size = Math.max(1, Math.min(Number(pageSize) || MAX_PAGE_SIZE, MAX_PAGE_SIZE));
  const items = [];
  const components = new Map();
  let page = 1;
  for (;;) {
    if (signal?.aborted) throw abortError();
    const payload = await sonarRequest(hostUrl, apiPath, { token, query: { ...query, ps: size, p: page }, timeoutMs, signal });
    for (const component of payload?.components || []) {
      if (component?.key) components.set(component.key, component);
    }
    const batch = Array.isArray(payload?.[collection]) ? payload[collection] : [];
    items.push(...batch);
    const total = pagedTotal(payload, items.length);
    const reachable = Math.min(total, MAX_TOTAL_RESULTS);
    if (!batch.length || items.length >= reachable || page * size >= reachable) {
      return { items, components: [...components.values()], total, truncated: total > reachable };
    }
    page += 1;
  }
}

const DEFAULT_ISSUE_TYPES = Object.freeze(['VULNERABILITY', 'BUG']);

async function fetchIssues(hostUrl, projectKey, { token = '', types = DEFAULT_ISSUE_TYPES, timeoutMs = 30000, signal, pageSize = MAX_PAGE_SIZE } = {}) {
  const selected = [...new Set((types || []).map((type) => String(type).toUpperCase()).filter(Boolean))];
  const result = await fetchPaged(hostUrl, 'api/issues/search', {
    token,
    query: { componentKeys: projectKey, resolved: 'false', ...(selected.length ? { types: selected.join(',') } : {}) },
    collection: 'issues',
    timeoutMs,
    signal,
    pageSize
  });
  return { issues: result.items, components: result.components, total: result.total, truncated: result.truncated };
}

/**
 * Security hotspots live in a dedicated endpoint since SonarQube 8.x. They are
 * the most security-relevant output, so they are fetched separately.
 */
async function fetchHotspots(hostUrl, projectKey, { token = '', timeoutMs = 30000, signal, pageSize = MAX_PAGE_SIZE } = {}) {
  const result = await fetchPaged(hostUrl, 'api/hotspots/search', {
    token,
    query: { projectKey, status: 'TO_REVIEW' },
    collection: 'hotspots',
    timeoutMs,
    signal,
    pageSize
  });
  return { hotspots: result.items, components: result.components, total: result.total, truncated: result.truncated };
}

/**
 * Normalises the CWE mapping of a rule.
 *
 * Older servers expose it as `securityStandards: ["cwe:79", ...]`. SonarQube
 * Community Build 26.x drops that field and only states the CWE inside the
 * rule description, flagging the rule with the `cwe` system tag. Both shapes
 * are folded into the `cwe:<id>` form so callers stay version-agnostic.
 */
function ruleSecurityStandards(rule) {
  const declared = Array.isArray(rule?.securityStandards) ? rule.securityStandards : [];
  if (declared.length) return declared;
  const sysTags = Array.isArray(rule?.sysTags) ? rule.sysTags : [];
  if (!sysTags.includes('cwe')) return [];
  const described = JSON.stringify(rule?.descriptionSections || rule?.htmlDesc || '');
  return [...new Set(described.match(/CWE-\d+/g) || [])].map((value) => `cwe:${value.slice(4)}`);
}

/**
 * Rule metadata carries the CWE mapping that the issue payload omits.
 *
 * `api/rules/search` cannot filter on a list of keys — `rule_keys` is silently
 * ignored and `rule_key` accepts a single value — so each distinct rule is
 * resolved through `api/rules/show`, in small concurrent batches.
 */
async function fetchRuleMetadata(hostUrl, ruleKeys, { token = '', timeoutMs = 30000, signal, maxRules = 300 } = {}) {
  const keys = [...new Set((ruleKeys || []).map((key) => String(key).trim()).filter(Boolean))].slice(0, maxRules);
  const rules = new Map();
  for (let index = 0; index < keys.length; index += RULE_BATCH_SIZE) {
    if (signal?.aborted) throw abortError();
    const batch = keys.slice(index, index + RULE_BATCH_SIZE);
    const payloads = await Promise.all(batch.map(async (key) => {
      try {
        const payload = await sonarRequest(hostUrl, 'api/rules/show', {
          token, query: { key }, timeoutMs, signal
        });
        return payload?.rule || null;
      } catch (error) {
        // A single unknown rule must not sink the whole metadata pass.
        if (error instanceof SonarError && ['CANCELED', 'AUTH_ERROR'].includes(error.code)) throw error;
        return null;
      }
    }));
    for (const rule of payloads) {
      if (!rule?.key) continue;
      rules.set(rule.key, {
        key: rule.key,
        name: String(rule.name || ''),
        type: String(rule.type || ''),
        sysTags: Array.isArray(rule.sysTags) ? rule.sysTags : [],
        securityStandards: ruleSecurityStandards(rule)
      });
    }
  }
  return rules;
}

module.exports = {
  MAX_PAGE_SIZE, MAX_TOTAL_RESULTS, RULE_BATCH_SIZE, DEFAULT_ISSUE_TYPES, SONAR_ERROR_CODES,
  SonarError, normalizeHostUrl, sonarUrl, sonarRequest, delay, ruleSecurityStandards,
  checkServerStatus, validateToken, waitForTask, fetchPaged, fetchIssues, fetchHotspots, fetchRuleMetadata
};
