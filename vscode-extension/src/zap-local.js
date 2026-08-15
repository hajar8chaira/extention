const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const DEFAULT_WINDOWS_HOME = 'C:\\Program Files\\ZAP\\Zed Attack Proxy';

function detectLocalZap(configuredPath = '') {
  const candidates = [configuredPath, process.env.ZAP_PATH, path.join(DEFAULT_WINDOWS_HOME, 'zap.bat')].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) || '';
}

async function zapApi(baseUrl, apiKey, component, type, name, params = {}, timeoutMs = 10000) {
  const url = new URL(`/JSON/${component}/${type}/${name}/`, baseUrl);
  url.searchParams.set('apikey', apiKey);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== '') url.searchParams.set(key, String(value));
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`API ZAP ${name} : HTTP ${response.status}.`);
  const payload = await response.json();
  if (payload.code === 'bad_request' || payload.code === 'internal_error') throw new Error(payload.message || `API ZAP ${name} refusée.`);
  return payload;
}

async function waitForZap(baseUrl, apiKey, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { return await zapApi(baseUrl, apiKey, 'core', 'view', 'version', {}, 3000); } catch { await new Promise((resolve) => setTimeout(resolve, 1000)); }
  }
  throw new Error(`ZAP local ne répond pas sur ${baseUrl}.`);
}

function startLocalZap(zapPath, { port = 8090, apiKey, authResult } = {}) {
  const env = { ...process.env };
  if (authResult) {
    env.ZAP_AUTH_HEADER = authResult.header;
    env.ZAP_AUTH_HEADER_VALUE = authResult.value;
    env.ZAP_AUTH_HEADER_SITE = '127.0.0.1';
  }
  const args = ['-daemon', '-host', '127.0.0.1', '-port', String(port), '-config', `api.key=${apiKey}`, '-config', 'api.addrs.addr.name=127.0.0.1', '-config', 'api.addrs.addr.regex=false', '-silent'];
  if (process.platform === 'win32' && /\.bat$/i.test(zapPath)) {
    const jar = fs.readdirSync(path.dirname(zapPath)).find((name) => /^zap-[\d.]+\.jar$/i.test(name));
    if (!jar) throw new Error(`JAR ZAP introuvable dans ${path.dirname(zapPath)}.`);
    return spawn('java', ['-Xmx1024m', '-jar', path.join(path.dirname(zapPath), jar), ...args], { cwd: path.dirname(zapPath), env, windowsHide: true, stdio: 'ignore' });
  }
  return spawn(zapPath, args, { cwd: path.dirname(zapPath), env, windowsHide: true, stdio: 'ignore' });
}

async function waitForProgress(baseUrl, apiKey, component, scanId, timeoutMs, signal) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error('Scan ZAP annulé.');
    const result = await zapApi(baseUrl, apiKey, component, 'view', 'status', { scanId });
    if (Number(result.status) >= 100) return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`Le scan ZAP local a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
}

function alertsToReport(alerts = []) {
  const groups = new Map();
  for (const item of alerts) {
    const key = String(item.alertRef || item.pluginId || item.alert || 'alert');
    if (!groups.has(key)) groups.set(key, {
      pluginid: key, alert: item.alert, name: item.name, riskcode: item.riskcode, confidence: item.confidence,
      cweid: item.cweid, desc: item.description || item.desc, solution: item.solution, reference: item.reference,
      otherinfo: item.other, instances: []
    });
    groups.get(key).instances.push({ uri: item.url, method: item.method, param: item.param, evidence: item.evidence, otherinfo: item.other });
  }
  return { site: [{ '@name': 'http://127.0.0.1', alerts: [...groups.values()] }] };
}

function openApiImportRequest(source, targetUrl) {
  if (path.isAbsolute(source)) {
    if (!fs.existsSync(source)) throw new Error(`Spécification OpenAPI locale introuvable : ${source}.`);
    return { action: 'importFile', params: { file: source, target: targetUrl } };
  }
  try {
    const url = new URL(source);
    if (!['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) throw new Error('remote');
    return { action: 'importUrl', params: { url: url.toString(), hostOverride: targetUrl } };
  } catch (error) {
    if (error.message === 'remote') throw new Error('La spécification OpenAPI distante est interdite.');
    if (!path.isAbsolute(source) || !fs.existsSync(source)) throw new Error(`Spécification OpenAPI locale introuvable : ${source}.`);
    return { action: 'importFile', params: { file: source, target: targetUrl } };
  }
}

async function runLocalZap({ targetUrl, mode = 'baseline', localPath = '', timeoutMs = 600000, signal, excludedRoutes = [], authResult, openapi = '' }) {
  const zapPath = detectLocalZap(localPath);
  if (!zapPath) throw new Error('ZAP local n’est pas installé. Utilisez le bouton Installer/configurer ZAP.');
  const apiKey = crypto.randomBytes(24).toString('hex');
  const baseUrl = 'http://127.0.0.1:8090';
  const child = startLocalZap(zapPath, { port: 8090, apiKey, authResult });
  try {
    await waitForZap(baseUrl, apiKey);
    await zapApi(baseUrl, apiKey, 'core', 'action', 'newSession', { name: `security-center-${Date.now()}`, overwrite: true });
    for (const route of excludedRoutes) {
      const target = new URL(targetUrl);
      const escaped = `${target.origin}${String(route).startsWith('/') ? route : `/${route}`}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      await zapApi(baseUrl, apiKey, 'core', 'action', 'excludeFromProxy', { regex: `^${escaped}(?:[/?#].*)?$` });
    }
    if (mode === 'openapi') {
      const request = openApiImportRequest(openapi, targetUrl);
      await zapApi(baseUrl, apiKey, 'openapi', 'action', request.action, request.params, Math.min(timeoutMs, 120000));
    } else {
      const spider = await zapApi(baseUrl, apiKey, 'spider', 'action', 'scan', { url: targetUrl, recurse: true, subtreeOnly: true, maxChildren: 0 });
      await waitForProgress(baseUrl, apiKey, 'spider', spider.scan, Math.min(timeoutMs, 180000), signal);
    }
    if (mode !== 'baseline') {
      const active = await zapApi(baseUrl, apiKey, 'ascan', 'action', 'scan', { url: targetUrl, recurse: true, inScopeOnly: false });
      await waitForProgress(baseUrl, apiKey, 'ascan', active.scan, timeoutMs, signal);
    }
    const result = await zapApi(baseUrl, apiKey, 'core', 'view', 'alerts', { baseurl: targetUrl, start: 0, count: 10000 });
    return { payload: alertsToReport(result.alerts), stderr: '', mode: 'local' };
  } finally {
    try { await zapApi(baseUrl, apiKey, 'core', 'action', 'shutdown', {}, 5000); } catch { child.kill(); }
  }
}

module.exports = { detectLocalZap, zapApi, waitForZap, startLocalZap, waitForProgress, alertsToReport, openApiImportRequest, runLocalZap };
