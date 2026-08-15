const http = require('http');
const https = require('https');
let configuredApiKey = '';

function setApiKey(apiKey) {
  configuredApiKey = String(apiKey || '').trim();
}

function authenticationHeaders() {
  return configuredApiKey ? { 'x-security-center-key': configuredApiKey } : {};
}

function requestJson(method, target, payload, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const transport = url.protocol === 'https:' ? https : http;
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const request = transport.request(url, {
      method,
      headers: { ...authenticationHeaders(), ...(body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}) },
      timeout: timeoutMs
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if ((response.statusCode || 500) >= 400) return reject(new Error(`Backend HTTP ${response.statusCode}: ${text}`));
        try { resolve(text ? JSON.parse(text) : {}); }
        catch { reject(new Error('Le backend a renvoyé un JSON invalide.')); }
      });
    });
    request.on('timeout', () => request.destroy(new Error('Le backend local ne répond pas.')));
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

function backendUrl(baseUrl, path) {
  return new URL(path, `${String(baseUrl).replace(/\/+$/, '')}/`).toString();
}

function requestText(target, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.get(url, { timeout: timeoutMs, headers: authenticationHeaders() }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const body = Buffer.concat(chunks);
        if ((response.statusCode || 500) >= 400) return reject(new Error(`Backend HTTP ${response.statusCode}: ${body.toString('utf8')}`));
        resolve(body);
      });
    });
    request.on('timeout', () => request.destroy(new Error('Le backend local ne rÃ©pond pas.')));
    request.on('error', reject);
  });
}

function checkBackend(baseUrl) {
  return requestJson('GET', backendUrl(baseUrl, 'health'));
}

async function saveScanResult(baseUrl, result) {
  const storedScan = await requestJson('POST', backendUrl(baseUrl, 'api/v1/scans/results'), result, 10000);
  return normalizeScanToCamelCase(storedScan);
}

function saveHttpScenario(baseUrl, scenario) {
  return requestJson('POST', backendUrl(baseUrl, 'api/v1/http-scenarios'), scenario, 10000);
}

function listHttpScenarios(baseUrl) {
  return requestJson('GET', backendUrl(baseUrl, 'api/v1/http-scenarios'), undefined, 10000);
}

function getBurpStatus(baseUrl) {
  return requestJson('GET', backendUrl(baseUrl, 'api/v1/integrations/burp/status'), undefined, 10000);
}

async function listScans(baseUrl, limit = 50) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 200));
  const scans = await requestJson('GET', backendUrl(baseUrl, `api/v1/scans?limit=${safeLimit}`), undefined, 10000);
  return Array.isArray(scans) ? scans.map(normalizeScanToCamelCase) : scans;
}

function normalizeFindingToCamelCase(f) {
  if (!f) return f;
  return {
    ...f,
    ruleId: f.ruleId ?? f.rule_id,
    rawSeverity: f.rawSeverity ?? f.raw_severity,
    startLine: f.startLine ?? f.start_line,
    startColumn: f.startColumn ?? f.start_column,
    endLine: f.endLine ?? f.end_line,
    endColumn: f.endColumn ?? f.end_column,
    helpUri: f.helpUri ?? f.help_uri,
    triageStatus: f.triageStatus ?? f.triage_status,
    triageActor: f.triageActor ?? f.triage_actor,
    triageComment: f.triageComment ?? f.triage_comment,
    triageUpdatedAt: f.triageUpdatedAt ?? f.triage_updated_at
  };
}

function normalizeScanToCamelCase(s) {
  if (!s) return s;
  const result = s.result || {};
  const findings = result.findings || s.findings || [];
  const scanners = result.scanners || s.scanners || [];
  
  const normalizedFindings = findings.map(normalizeFindingToCamelCase);
  
  return {
    ...s,
    findings: normalizedFindings,
    scanners: scanners,
    result: {
      ...result,
      findings: normalizedFindings,
      scanners: scanners
    }
  };
}

async function getScan(baseUrl, scanId) {
  const rawScan = await requestJson('GET', backendUrl(baseUrl, `api/v1/scans/${encodeURIComponent(scanId)}`), undefined, 10000);
  return normalizeScanToCamelCase(rawScan);
}

async function updateFindingStatus(baseUrl, scanId, findingId, status, actor = 'local-user', comment = '') {
  const rawScan = await requestJson('PATCH', backendUrl(baseUrl, `api/v1/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/status`), { status, actor, comment }, 10000);
  return normalizeScanToCamelCase(rawScan);
}

function listAuditEvents(baseUrl, limit = 200) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 200, 1000));
  return requestJson('GET', backendUrl(baseUrl, `api/v1/audit-events?limit=${safeLimit}`), undefined, 10000);
}

function createAuditEvent(baseUrl, event) {
  const { sanitizeAuditEvent } = require('./audit-events');
  return requestJson('POST', backendUrl(baseUrl, 'api/v1/audit-events'), sanitizeAuditEvent(event), 10000);
}

function scanExportUrl(baseUrl, scanId, format = 'json') {
  if (!['json', 'html'].includes(format)) throw new Error('Format d’export non pris en charge.');
  return backendUrl(baseUrl, `api/v1/scans/${encodeURIComponent(scanId)}/export.${format}`);
}

module.exports = {
  setApiKey, authenticationHeaders, backendUrl, checkBackend, requestJson, requestText, saveScanResult, saveHttpScenario,
  listHttpScenarios, getBurpStatus, listScans, getScan, updateFindingStatus, listAuditEvents, createAuditEvent, scanExportUrl,
  normalizeFindingToCamelCase, normalizeScanToCamelCase
};
