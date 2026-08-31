'use strict';

/**
 * The HTTP surface of the Security Center local backend.
 *
 * Route for route, this is the FastAPI application it replaces: same paths,
 * same methods, same response shapes, same API-key middleware. The extension
 * client was not modified to accommodate it — that is the point. What changed
 * is the runtime underneath: Node instead of Python, so the service ships in
 * the VSIX and starts from the editor rather than from a container.
 *
 * The server binds the loopback interface only, and never any other. A scan
 * history, an audit journal and captured HTTP traffic are the three things in
 * this product that must not become reachable from the network by accident.
 */

const http = require('node:http');

const {
  SERVICE_NAME, PROTOCOL_VERSION, DEFAULT_PORT, LOOPBACK_HOST,
  ValidationError, NotFoundError,
  clampLimit, healthPayload, validateAuditEvent, validateHttpScenario,
  validateScanResult, validateStatusUpdate
} = require('./contract');

const MAX_BODY_BYTES = 32 * 1024 * 1024;

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (character) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]
  ));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new ValidationError('Request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) return resolve(undefined);
      try { resolve(JSON.parse(text)); }
      catch { reject(new ValidationError('Request body is not valid JSON')); }
    });
    request.on('error', reject);
  });
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload === undefined ? null : payload);
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store'
  });
  response.end(body);
}

function renderScanHtml(stored) {
  const rows = stored.result.findings.map((finding) => (
    '<tr>'
    + `<td>${escapeHtml(finding.tool)}</td>`
    + `<td>${escapeHtml(finding.rawSeverity || finding.raw_severity)}</td>`
    + `<td>${escapeHtml(finding.title)}</td>`
    + `<td>${escapeHtml(finding.file)}:${Number(finding.startLine === undefined ? finding.start_line : finding.startLine) + 1}</td>`
    + `<td>${escapeHtml(finding.triageStatus || 'new')}</td>`
    + '</tr>'
  )).join('') || '<tr><td colspan="5">Aucun résultat</td></tr>';
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Security Center — scan ${stored.scan_id}</title>
<style>body{font:14px system-ui;margin:32px;color:#1f2328}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d7de;padding:8px;text-align:left}th{background:#f6f8fa}</style>
</head><body><h1>Rapport Security Center</h1>
<p>Scan #${stored.scan_id} — ${escapeHtml(stored.result.workspace)} — ${escapeHtml(stored.result.finished_at)}</p>
<p>${stored.result.findings.length} résultat(s), ${stored.result.correlations.length} corrélation(s).</p>
<table><thead><tr><th>Outil</th><th>Sévérité</th><th>Résultat</th><th>Emplacement</th><th>Statut</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;
}

/**
 * Builds the request handler.
 *
 * `onActivity` is called for every served request: it is what lets the process
 * know it is still needed, and shut itself down when it is not.
 */
function createRequestHandler({ store, apiKey = '', version = PROTOCOL_VERSION, port = DEFAULT_PORT, startedAt = new Date().toISOString(), onActivity = () => {} } = {}) {
  const burp = { lastSeen: null };

  async function route(request, url) {
    const method = request.method || 'GET';
    const pathname = url.pathname.replace(/\/+$/, '') || '/';

    if (method === 'GET' && (pathname === '/health' || pathname === '/')) {
      // `port` may be a function: when the caller asked the kernel to choose,
      // the real port is only known after `listen`, and `/health` is the place
      // clients read it from.
      const boundPort = typeof port === 'function' ? port() : port;
      return { status: 200, body: healthPayload({ version, port: boundPort, dataDir: store.dataDir, startedAt }) };
    }

    if (method === 'POST' && pathname === '/api/v1/scans/results') {
      const result = validateScanResult(await readBody(request));
      const scanId = store.save(result);
      return { status: 201, body: { scan_id: scanId, result } };
    }

    if (method === 'GET' && pathname === '/api/v1/scans/latest') {
      return { status: 200, body: store.latest() };
    }

    if (method === 'GET' && pathname === '/api/v1/scans') {
      return { status: 200, body: store.listScans(clampLimit(url.searchParams.get('limit'), 50, 200)) };
    }

    const exportMatch = pathname.match(/^\/api\/v1\/scans\/([^/]+)\/export\.(json|html)$/);
    if (method === 'GET' && exportMatch) {
      const stored = store.requireScan(decodeURIComponent(exportMatch[1]));
      if (exportMatch[2] === 'json') return { status: 200, body: stored };
      return {
        status: 200,
        html: renderScanHtml(stored),
        headers: { 'content-disposition': `attachment; filename="security-center-scan-${stored.scan_id}.html"` }
      };
    }

    const statusMatch = pathname.match(/^\/api\/v1\/scans\/([^/]+)\/findings\/(.+)\/status$/);
    if (method === 'PATCH' && statusMatch) {
      const update = validateStatusUpdate(await readBody(request));
      const stored = store.updateFindingStatus(
        decodeURIComponent(statusMatch[1]), decodeURIComponent(statusMatch[2]),
        update.status, update.actor, update.comment
      );
      if (!stored) throw new NotFoundError('Scan or finding not found');
      return { status: 200, body: stored };
    }

    const scanMatch = pathname.match(/^\/api\/v1\/scans\/([^/]+)$/);
    if (method === 'GET' && scanMatch) {
      return { status: 200, body: store.requireScan(decodeURIComponent(scanMatch[1])) };
    }

    if (method === 'GET' && pathname === '/api/v1/audit-events') {
      return { status: 200, body: store.listAuditEvents(clampLimit(url.searchParams.get('limit'), 200, 1000)) };
    }

    if (method === 'POST' && pathname === '/api/v1/audit-events') {
      return { status: 201, body: store.createAuditEvent(validateAuditEvent(await readBody(request))) };
    }

    if (method === 'GET' && pathname === '/api/v1/dashboard') {
      const stored = store.latest();
      if (!stored) return { status: 200, body: { scan_id: null, workspace: '', total: 0, by_tool: {}, by_severity: {}, scanners: [], finished_at: null, metadata: {} } };
      const byTool = {};
      const bySeverity = {};
      for (const finding of stored.result.findings) {
        byTool[finding.tool] = (byTool[finding.tool] || 0) + 1;
        const severity = finding.rawSeverity || finding.raw_severity || '';
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;
      }
      return {
        status: 200,
        body: {
          scan_id: stored.scan_id,
          workspace: stored.result.workspace,
          total: stored.result.findings.length,
          by_tool: byTool,
          by_severity: bySeverity,
          scanners: stored.result.scanners,
          finished_at: stored.result.finished_at,
          metadata: {
            correlations: stored.result.correlations.length,
            high_confidence_correlations: stored.result.correlations.filter((item) => item.confidence === 'high').length
          }
        }
      };
    }

    if (method === 'POST' && pathname === '/api/v1/http-scenarios') {
      return { status: 201, body: store.saveHttpScenario(validateHttpScenario(await readBody(request))) };
    }

    if (method === 'GET' && pathname === '/api/v1/http-scenarios') {
      return { status: 200, body: store.listHttpScenarios(clampLimit(url.searchParams.get('limit'), 100, 500)) };
    }

    if (method === 'POST' && pathname === '/api/v1/integrations/burp/requests') {
      const scenario = validateHttpScenario(await readBody(request));
      return { status: 201, body: store.saveHttpScenario({ ...scenario, source: 'burp' }) };
    }

    if (method === 'GET' && pathname === '/api/v1/integrations/burp/status') {
      const scenarios = store.listHttpScenarios(500);
      const connected = Boolean(burp.lastSeen) && (Date.now() - burp.lastSeen) < 15000;
      return {
        status: 200,
        body: {
          status: 'ready',
          connector: 'security-center-burp',
          connected,
          last_seen: burp.lastSeen ? new Date(burp.lastSeen).toISOString() : null,
          received_requests: scenarios.filter((scenario) => scenario.source === 'burp').length
        }
      };
    }

    if (method === 'POST' && pathname === '/api/v1/integrations/burp/heartbeat') {
      burp.lastSeen = Date.now();
      return { status: 200, body: { status: 'connected', last_seen: new Date(burp.lastSeen).toISOString() } };
    }

    throw Object.assign(new Error('Not found'), { statusCode: 404 });
  }

  return async function handler(request, response) {
    onActivity();
    let url;
    try {
      url = new URL(request.url || '/', `http://${LOOPBACK_HOST}`);
    } catch {
      return sendJson(response, 400, { detail: 'Invalid request URL' });
    }

    // `/health` stays open: a probe that needs the key cannot tell "wrong key"
    // from "wrong service", and the payload it returns names nothing private.
    if (apiKey && url.pathname.startsWith('/api/v1/')) {
      const supplied = Buffer.from(String(request.headers['x-security-center-key'] || ''), 'utf8');
      const expected = Buffer.from(apiKey, 'utf8');
      const valid = supplied.length === expected.length && require('node:crypto').timingSafeEqual(supplied, expected);
      if (!valid) return sendJson(response, 401, { detail: 'Invalid or missing Security Center API key' });
    }

    try {
      const outcome = await route(request, url);
      if (outcome.html !== undefined) {
        response.writeHead(outcome.status, {
          'content-type': 'text/html; charset=utf-8',
          'content-length': Buffer.byteLength(outcome.html),
          ...(outcome.headers || {})
        });
        return response.end(outcome.html);
      }
      return sendJson(response, outcome.status, outcome.body);
    } catch (error) {
      const statusCode = Number(error && error.statusCode) || 500;
      // The message describes the request, never the environment: no paths, no
      // keys, no stack. A 500 is a bug to read in the log, not in the client.
      const detail = statusCode >= 500 ? 'Internal backend error' : String(error.message || 'Request rejected');
      if (statusCode >= 500) process.emitWarning(`security-center-backend: ${error && error.stack ? error.stack : error}`);
      return sendJson(response, statusCode, { detail });
    }
  };
}

/** The server, bound to loopback and to nothing else. */
function createBackendServer(options = {}) {
  const server = http.createServer(createRequestHandler(options));
  server.keepAliveTimeout = 5000;
  return server;
}

module.exports = { createRequestHandler, createBackendServer, renderScanHtml, SERVICE_NAME };
