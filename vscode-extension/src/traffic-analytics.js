'use strict';

/**
 * Analyse du trafic HTTP capturé.
 *
 * Tout ce que ce module rend est **dérivé** de ce qui a réellement été observé
 * dans les échanges : aucun jugement, aucune vulnérabilité inventée à partir
 * d'une requête. Une observation de sécurité n'apparaît ici que si elle se lit
 * directement dans les en-têtes ou le code de réponse, ou si elle renvoie à un
 * finding déjà produit par un scanner.
 *
 * Le modèle est commun à Burp, HAR et mitmproxy : c'est le champ `source` qui
 * les distingue, et rien d'autre.
 */

const SENSITIVE_REQUEST_HEADERS = Object.freeze(['authorization', 'cookie', 'proxy-authorization', 'x-api-key']);

/** Les sources de capture que le modèle sait rendre, dans l'ordre d'affichage. */
const TRAFFIC_SOURCES = Object.freeze(['mitmproxy', 'burp', 'har', 'zap', 'manual']);

/**
 * En-têtes de réponse dont l'absence est un fait observable.
 *
 * Ce n'est pas une note de sécurité : c'est le constat qu'un en-tête n'a pas été
 * vu sur cette réponse. La qualification, elle, appartient aux scanners.
 */
const OBSERVED_SECURITY_HEADERS = Object.freeze([
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options'
]);

function lower(value) {
  return String(value === undefined || value === null ? '' : value).toLowerCase();
}

function parseUrl(value) {
  try { return new URL(String(value)); } catch { return null; }
}

/** Chemin normalisé, sans requête ni barre finale. */
function trafficPath(url) {
  const parsed = parseUrl(url);
  if (parsed) return parsed.pathname.replace(/\/+$/, '') || '/';
  return String(url || '').split('?')[0].replace(/\/+$/, '') || '/';
}

function trafficHost(url) {
  const parsed = parseUrl(url);
  return parsed ? parsed.host : '';
}

function statusOf(scenario) {
  const value = Number(scenario?.response?.statusCode ?? scenario?.response?.status ?? 0);
  return Number.isFinite(value) && value >= 100 && value <= 599 ? value : 0;
}

function methodOf(scenario) {
  return String(scenario?.request?.method || 'GET').toUpperCase();
}

function sourceOf(scenario) {
  const source = lower(scenario?.source);
  return TRAFFIC_SOURCES.includes(source) ? source : 'manual';
}

function contentTypeOf(scenario) {
  const headers = scenario?.response?.headers || {};
  const raw = headers['content-type'] || headers['Content-Type'] || '';
  return String(raw).split(';')[0].trim().toLowerCase();
}

function durationOf(scenario) {
  const value = Number(scenario?.capture?.duration_ms ?? scenario?.capture?.durationMs ?? NaN);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function timestampOf(scenario) {
  const raw = scenario?.timestamp || scenario?.captured_at || scenario?.capturedAt || '';
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : '';
}

/**
 * Une requête porte-t-elle une authentification observable ?
 *
 * Seule la présence d'un en-tête d'authentification compte — la liste des
 * en-têtes sensibles est conservée à la capture, précisément parce que leur
 * valeur, elle, ne l'est pas. Aucune conclusion n'est tirée de l'absence.
 */
function authenticationOf(scenario) {
  const declared = (scenario?.request?.sensitive_headers || []).map(lower);
  const present = Object.keys(scenario?.request?.headers || {}).map(lower);
  const observed = SENSITIVE_REQUEST_HEADERS.filter((header) => declared.includes(header) || present.includes(header));
  const tagged = (scenario?.tags || []).some((tag) => lower(tag) === 'authenticated');
  if (!observed.length && !tagged) return { authenticated: false, evidence: [], label: 'Aucune authentification observée' };
  const labels = {
    authorization: 'En-tête Authorization observé',
    cookie: 'Cookie de session observé',
    'proxy-authorization': 'En-tête Proxy-Authorization observé',
    'x-api-key': 'Clé d’API observée'
  };
  const evidence = observed.map((header) => labels[header] || `En-tête ${header} observé`);
  return {
    authenticated: true,
    evidence: evidence.length ? evidence : ['Requête marquée authentifiée à la capture'],
    label: evidence[0] || 'Requête authentifiée'
  };
}

/**
 * Observations lisibles directement dans l'échange.
 *
 * Rien ici n'est une vulnérabilité : ce sont des faits. Les findings, eux,
 * viennent des scanners et sont rattachés par `linkedFindings`.
 */
function observationsOf(scenario) {
  const observations = [];
  const authentication = authenticationOf(scenario);
  if (authentication.authenticated) {
    for (const evidence of authentication.evidence) observations.push({ kind: 'authentication', label: evidence });
  }
  const status = statusOf(scenario);
  if (status >= 500) observations.push({ kind: 'server-error', label: `Réponse d’erreur serveur ${status}` });
  else if (status >= 400) observations.push({ kind: 'client-error', label: `Réponse d’erreur ${status}` });

  const responseHeaders = Object.keys(scenario?.response?.headers || {}).map(lower);
  // L'absence n'est constatée que sur une réponse HTML : un en-tête de politique
  // de navigateur n'a pas de sens sur une image ou un flux JSON.
  if (contentTypeOf(scenario).includes('html')) {
    for (const header of OBSERVED_SECURITY_HEADERS) {
      if (!responseHeaders.includes(header)) {
        observations.push({ kind: 'missing-header', label: `En-tête ${header} absent de la réponse` });
      }
    }
  }
  return observations;
}

/** Clé d'agrégation d'un endpoint : méthode + hôte + chemin. */
function endpointKey(scenario) {
  return `${methodOf(scenario)} ${trafficHost(scenario?.request?.url)}${trafficPath(scenario?.request?.url)}`;
}

/**
 * Inventaire des endpoints observés.
 *
 * `linkFindings` reçoit un scénario et rend les findings qui lui sont rattachés ;
 * l'appelant fournit la fonction déjà utilisée par le reste de l'application,
 * pour qu'il n'existe qu'une seule règle de corrélation.
 */
function endpointInventory(scenarios = [], { linkFindings = () => [] } = {}) {
  const inventory = new Map();
  for (const scenario of Array.isArray(scenarios) ? scenarios : []) {
    if (!scenario?.request?.url) continue;
    const key = endpointKey(scenario);
    const timestamp = timestampOf(scenario);
    const entry = inventory.get(key) || {
      key,
      method: methodOf(scenario),
      host: trafficHost(scenario.request.url),
      path: trafficPath(scenario.request.url),
      observations: 0,
      latestStatus: 0,
      authenticated: false,
      contentType: '',
      sources: [],
      findingIds: [],
      firstSeen: '',
      lastSeen: ''
    };
    entry.observations += 1;
    const status = statusOf(scenario);
    if (status) entry.latestStatus = status;
    if (authenticationOf(scenario).authenticated) entry.authenticated = true;
    const contentType = contentTypeOf(scenario);
    if (contentType) entry.contentType = contentType;
    const source = sourceOf(scenario);
    if (!entry.sources.includes(source)) entry.sources.push(source);
    for (const finding of linkFindings(scenario) || []) {
      const id = String(finding?.id ?? finding ?? '');
      if (id && !entry.findingIds.includes(id)) entry.findingIds.push(id);
    }
    if (timestamp) {
      if (!entry.firstSeen || timestamp < entry.firstSeen) entry.firstSeen = timestamp;
      if (!entry.lastSeen || timestamp > entry.lastSeen) entry.lastSeen = timestamp;
    }
    inventory.set(key, entry);
  }
  return [...inventory.values()].sort((left, right) => right.observations - left.observations || left.key.localeCompare(right.key));
}

/** Résumé de session : uniquement des comptages de ce qui a été observé. */
function sessionSummary(scenarios = [], { linkFindings = () => [] } = {}) {
  const list = (Array.isArray(scenarios) ? scenarios : []).filter((scenario) => scenario?.request?.url);
  const hosts = new Set();
  const methods = {};
  const statusClasses = {};
  const sources = {};
  const findingIds = new Set();
  let authenticatedRequests = 0;
  let errorResponses = 0;
  let first = '';
  let last = '';

  for (const scenario of list) {
    hosts.add(trafficHost(scenario.request.url));
    const method = methodOf(scenario);
    methods[method] = (methods[method] || 0) + 1;
    const status = statusOf(scenario);
    if (status) {
      const family = `${Math.floor(status / 100)}xx`;
      statusClasses[family] = (statusClasses[family] || 0) + 1;
      if (status >= 400) errorResponses += 1;
    }
    const source = sourceOf(scenario);
    sources[source] = (sources[source] || 0) + 1;
    if (authenticationOf(scenario).authenticated) authenticatedRequests += 1;
    for (const finding of linkFindings(scenario) || []) {
      const id = String(finding?.id ?? finding ?? '');
      if (id) findingIds.add(id);
    }
    const timestamp = timestampOf(scenario);
    if (timestamp) {
      if (!first || timestamp < first) first = timestamp;
      if (!last || timestamp > last) last = timestamp;
    }
  }

  const endpoints = endpointInventory(list, { linkFindings });
  return {
    totalRequests: list.length,
    uniqueEndpoints: endpoints.length,
    uniqueHosts: hosts.size,
    authenticatedRequests,
    authenticatedEndpoints: endpoints.filter((endpoint) => endpoint.authenticated).length,
    linkedFindings: findingIds.size,
    errorResponses,
    methods,
    statusClasses,
    sources,
    firstSeen: first,
    lastSeen: last,
    // Une durée n'est rendue que si les deux bornes existent réellement.
    durationMs: first && last ? Math.max(0, Date.parse(last) - Date.parse(first)) : null
  };
}

const MAX_PREVIEW_LENGTH = 4000;

/** Corps tronqué et, quand c'est sûr, remis en forme pour être lisible. */
function previewBody(body, contentType = '') {
  const text = String(body === undefined || body === null ? '' : body);
  if (!text) return { text: '', truncated: false, formatted: false, length: 0 };
  let formatted = false;
  let rendered = text;
  if (lower(contentType).includes('json') && text.length <= MAX_PREVIEW_LENGTH) {
    try { rendered = JSON.stringify(JSON.parse(text), null, 2); formatted = true; } catch { /* laissé brut */ }
  }
  const truncated = rendered.length > MAX_PREVIEW_LENGTH;
  return {
    text: truncated ? `${rendered.slice(0, MAX_PREVIEW_LENGTH)}\n[TRONQUÉ]` : rendered,
    truncated,
    formatted,
    length: text.length
  };
}

/** Un nom de paramètre qui annonce un secret. */
const SENSITIVE_PARAMETER = /(token|key|secret|password|passwd|auth|session|signature)/i;

/** Paramètres de requête, valeurs masquées lorsque le nom trahit un secret. */
function queryParameters(url) {
  const parsed = parseUrl(url);
  if (!parsed) return [];
  return [...parsed.searchParams.entries()].map(([name, value]) => ({
    name,
    value: SENSITIVE_PARAMETER.test(name) ? '[REDACTED]' : value
  }));
}

/**
 * L'URL telle qu'elle peut être affichée.
 *
 * Les en-têtes sensibles sont masqués à la capture, mais un jeton passé en
 * paramètre d'URL, lui, traversait le modèle jusqu'au tableau et jusqu'à la
 * liste des tests récents. Il est masqué ici, une fois, pour toutes les sources.
 */
function displayUrl(url) {
  const text = String(url === undefined || url === null ? '' : url);
  const parsed = parseUrl(text);
  if (parsed) {
    let changed = false;
    for (const [name] of [...parsed.searchParams.entries()]) {
      if (SENSITIVE_PARAMETER.test(name)) { parsed.searchParams.set(name, '[REDACTED]'); changed = true; }
    }
    // `searchParams` réencode tout ce qu'il touche : l'URL d'origine est rendue
    // telle quelle quand elle ne contient aucun secret.
    return changed ? decodeURIComponent(parsed.toString()) : text;
  }
  // Le nom d'un scénario — « GET /chemin?token=… » — n'est pas une URL absolue,
  // et portait pourtant le même secret jusqu'à l'écran.
  const separator = text.indexOf('?');
  if (separator < 0) return text;
  const query = text.slice(separator + 1).split('&').map((pair) => {
    const name = pair.split('=')[0];
    return SENSITIVE_PARAMETER.test(name) && pair.includes('=') ? `${name}=[REDACTED]` : pair;
  }).join('&');
  return `${text.slice(0, separator)}?${query}`;
}

/**
 * Détail complet d'un échange, prêt à être rendu.
 *
 * Les en-têtes arrivent déjà rédigés depuis la capture ; ce module ne les
 * dé-rédige jamais et se contente de les présenter.
 */
function requestDetails(scenario, { findings = [] } = {}) {
  if (!scenario?.request?.url) return null;
  const contentType = contentTypeOf(scenario);
  const requestContentType = lower((scenario.request.headers || {})['content-type'] || '');
  const authentication = authenticationOf(scenario);
  return {
    method: methodOf(scenario),
    url: displayUrl(scenario.request.url),
    host: trafficHost(scenario.request.url),
    path: trafficPath(scenario.request.url),
    status: statusOf(scenario),
    source: sourceOf(scenario),
    timestamp: timestampOf(scenario),
    durationMs: durationOf(scenario),
    contentType,
    requestHeaders: scenario.request.headers || {},
    requestBody: previewBody(scenario.request.body, requestContentType),
    responseHeaders: scenario.response?.headers || {},
    responseBody: previewBody(scenario.response?.body, contentType),
    queryParameters: queryParameters(scenario.request.url),
    authentication,
    observations: observationsOf(scenario),
    linkedFindings: (findings || []).map((finding) => ({
      id: String(finding?.id || ''),
      title: String(finding?.title || ''),
      severity: String(finding?.rawSeverity || finding?.severity || ''),
      tool: String(finding?.tool || '')
    })).filter((finding) => finding.id),
    sizes: {
      request: Number(scenario?.capture?.request_size ?? scenario?.capture?.requestSize ?? 0) || 0,
      response: Number(scenario?.capture?.response_size ?? scenario?.capture?.responseSize ?? 0) || 0
    }
  };
}

module.exports = {
  TRAFFIC_SOURCES,
  SENSITIVE_REQUEST_HEADERS,
  OBSERVED_SECURITY_HEADERS,
  MAX_PREVIEW_LENGTH,
  trafficPath,
  trafficHost,
  statusOf,
  methodOf,
  sourceOf,
  contentTypeOf,
  durationOf,
  timestampOf,
  authenticationOf,
  observationsOf,
  endpointKey,
  endpointInventory,
  sessionSummary,
  previewBody,
  queryParameters,
  displayUrl,
  SENSITIVE_PARAMETER,
  requestDetails
};
