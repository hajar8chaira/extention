'use strict';

/**
 * The wire contract of the Security Center local backend.
 *
 * This file exists so that the service and its clients agree on one definition
 * of every value that travels between them: the name the service answers with,
 * the statuses a finding may take, the shape an audit event must have before it
 * is written down. It is required by the server, by the extension and by the
 * tests — never duplicated in any of them.
 *
 * It replaces the pydantic models of the previous FastAPI implementation. The
 * validation rules are the same rules, deliberately: a status outside the
 * vocabulary is refused, `false_positive` and `accepted` still demand a written
 * justification, an HTTP scenario still points at a local target only, and
 * sensitive keys are still redacted before an audit event reaches disk.
 */

/** The name `/health` answers with. A client that reads anything else is not talking to us. */
const SERVICE_NAME = 'security-center-backend';

/** The contract version. Bumped when a route changes shape, not when the extension ships. */
const PROTOCOL_VERSION = '1.0.0';

/** The port the local backend claims first. A free port is chosen when it is taken. */
const DEFAULT_PORT = 8765;

/** The interface the local backend binds. Never 0.0.0.0: a scan history is not a network service. */
const LOOPBACK_HOST = '127.0.0.1';

/** Hosts an HTTP scenario is allowed to name. Replay is a local capability. */
const ALLOWED_SCENARIO_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '::1', 'host.docker.internal']);

/** The triage vocabulary. A finding is in exactly one of these states. */
const FINDING_STATUSES = Object.freeze([
  'new', 'triaged', 'probable', 'confirmed', 'fixed', 'validated', 'false_positive', 'accepted'
]);

/** The two statuses that close a finding without fixing it, and therefore owe an explanation. */
const STATUSES_REQUIRING_JUSTIFICATION = Object.freeze(['false_positive', 'accepted']);

const SCENARIO_SOURCES = Object.freeze(['har', 'burp', 'zap', 'manual']);

/** Keys whose value never reaches the audit journal in clear text. */
const SENSITIVE_KEYS = Object.freeze([
  'authorization', 'cookie', 'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'private_key'
]);

/** A request rejected by validation. The service turns it into an HTTP 422. */
class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 422;
  }
}

/** A request that named something that does not exist. */
class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
    this.statusCode = 404;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** Query limits are clamped, never trusted: a limit of 1e9 is a denial of service, not a preference. */
function clampLimit(value, fallback, maximum) {
  const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(parsed, maximum));
}

function requireText(value, field, { maxLength = 1000, minLength = 1 } = {}) {
  const text = String(value === undefined || value === null ? '' : value).trim();
  if (text.length < minLength) throw new ValidationError(`${field} is required`);
  if (text.length > maxLength) throw new ValidationError(`${field} exceeds ${maxLength} characters`);
  return text;
}

/**
 * Replaces the value of every sensitive key, at any depth, with a marker.
 *
 * Applied on the way in rather than on the way out: a secret that is never
 * written cannot leak from a file that is later copied, exported or attached
 * to a bug report.
 */
function redactAuditMetadata(value, key = '') {
  const normalizedKey = String(key).toLowerCase().replace(/-/g, '_');
  if (SENSITIVE_KEYS.some((sensitive) => normalizedKey.includes(sensitive))) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((item) => redactAuditMetadata(item));
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactAuditMetadata(item, name)]));
  }
  return value;
}

/** A scan as the extension sends it. Findings keep the keys they arrive with. */
function validateScanResult(payload) {
  if (!isPlainObject(payload)) throw new ValidationError('A scan result object is required');
  const workspace = requireText(payload.workspace, 'workspace', { maxLength: 4096 });
  if (!Array.isArray(payload.findings)) throw new ValidationError('findings must be a list');
  if (!Array.isArray(payload.scanners)) throw new ValidationError('scanners must be a list');
  const correlations = payload.correlations === undefined ? [] : payload.correlations;
  if (!Array.isArray(correlations)) throw new ValidationError('correlations must be a list');
  const finishedAt = payload.finished_at || payload.finishedAt;
  return {
    workspace,
    findings: payload.findings,
    scanners: payload.scanners,
    correlations,
    finished_at: finishedAt ? new Date(finishedAt).toISOString() : new Date().toISOString()
  };
}

function validateStatusUpdate(payload) {
  if (!isPlainObject(payload)) throw new ValidationError('A status update object is required');
  const status = String(payload.status === undefined ? '' : payload.status);
  if (!FINDING_STATUSES.includes(status)) {
    throw new ValidationError(`status must be one of: ${FINDING_STATUSES.join(', ')}`);
  }
  const comment = String(payload.comment === undefined || payload.comment === null ? '' : payload.comment);
  if (comment.length > 1000) throw new ValidationError('comment exceeds 1000 characters');
  if (STATUSES_REQUIRING_JUSTIFICATION.includes(status) && !comment.trim()) {
    throw new ValidationError('A justification is required for false_positive and accepted');
  }
  return {
    status,
    actor: String(payload.actor === undefined || payload.actor === null ? '' : payload.actor).trim() || 'local-user',
    comment
  };
}

function validateAuditEvent(payload) {
  if (!isPlainObject(payload)) throw new ValidationError('An audit event object is required');
  const action = requireText(payload.action, 'action', { maxLength: 100 });
  const comment = String(payload.comment === undefined || payload.comment === null ? '' : payload.comment);
  if (comment.length > 1000) throw new ValidationError('comment exceeds 1000 characters');
  // An authorization is a decision someone made. Recording it without the reason
  // makes the journal a list of events instead of a chain of accountability.
  if (action.endsWith(':authorized') && !comment.trim()) {
    throw new ValidationError('A justification is required for authorization events');
  }
  const optional = (value, maxLength) => {
    if (value === undefined || value === null || value === '') return null;
    return requireText(value, 'field', { maxLength });
  };
  const scanId = Number(payload.scan_id);
  return {
    scan_id: Number.isFinite(scanId) && scanId >= 0 ? scanId : null,
    finding_id: optional(payload.finding_id, 500),
    action,
    actor: String(payload.actor === undefined || payload.actor === null ? '' : payload.actor).trim() || 'Security Center',
    comment,
    category: optional(payload.category, 50),
    actor_type: optional(payload.actor_type, 50),
    result: optional(payload.result, 50),
    project: optional(payload.project, 500),
    resource: optional(payload.resource, 1000),
    resource_type: optional(payload.resource_type, 50),
    reason: optional(payload.reason, 1000),
    metadata: redactAuditMetadata(isPlainObject(payload.metadata) ? payload.metadata : {})
  };
}

function validateHttpScenario(payload) {
  if (!isPlainObject(payload)) throw new ValidationError('An HTTP scenario object is required');
  const name = requireText(payload.name, 'name', { maxLength: 200 });
  const source = String(payload.source === undefined ? '' : payload.source);
  if (!SCENARIO_SOURCES.includes(source)) {
    throw new ValidationError(`source must be one of: ${SCENARIO_SOURCES.join(', ')}`);
  }
  const request = isPlainObject(payload.request) ? payload.request : null;
  if (!request) throw new ValidationError('request is required');
  const url = String(request.url === undefined ? '' : request.url);
  let parsed;
  try { parsed = new URL(url); } catch { throw new ValidationError('request.url is not a valid URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new ValidationError('Only HTTP and HTTPS requests are supported');
  }
  if (!ALLOWED_SCENARIO_HOSTS.includes(parsed.hostname.replace(/^\[|\]$/g, ''))) {
    throw new ValidationError('Only local HTTP targets are accepted');
  }
  const response = isPlainObject(payload.response) ? payload.response : null;
  if (response) {
    const statusCode = Number(response.statusCode === undefined ? response.status_code : response.statusCode);
    if (!Number.isFinite(statusCode) || statusCode < 100 || statusCode > 599) {
      throw new ValidationError('response.statusCode must be an HTTP status code');
    }
  }
  return {
    name,
    source,
    request: {
      method: String(request.method === undefined ? 'GET' : request.method),
      url,
      headers: isPlainObject(request.headers) ? request.headers : {},
      body: String(request.body === undefined || request.body === null ? '' : request.body),
      sensitive_headers: Array.isArray(request.sensitive_headers) ? request.sensitive_headers : []
    },
    response: response ? {
      statusCode: Number(response.statusCode === undefined ? response.status_code : response.statusCode),
      headers: isPlainObject(response.headers) ? response.headers : {},
      body: String(response.body === undefined || response.body === null ? '' : response.body),
      bodySha256: String(response.bodySha256 || response.body_sha256 || '')
    } : null,
    tags: Array.isArray(payload.tags) ? payload.tags : []
  };
}

/** What `/health` answers: enough for a client to be sure of the service, its version and its data. */
function healthPayload({ version = PROTOCOL_VERSION, port = DEFAULT_PORT, dataDir = '', startedAt = '' } = {}) {
  return {
    service: SERVICE_NAME,
    status: 'ok',
    version,
    runtime: 'node',
    pid: process.pid,
    port,
    data_dir: dataDir,
    started_at: startedAt
  };
}

module.exports = {
  SERVICE_NAME, PROTOCOL_VERSION, DEFAULT_PORT, LOOPBACK_HOST, ALLOWED_SCENARIO_HOSTS,
  FINDING_STATUSES, STATUSES_REQUIRING_JUSTIFICATION, SCENARIO_SOURCES, SENSITIVE_KEYS,
  ValidationError, NotFoundError,
  clampLimit, redactAuditMetadata, validateScanResult, validateStatusUpdate,
  validateAuditEvent, validateHttpScenario, healthPayload
};
