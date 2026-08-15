const http = require('http');
const https = require('https');

function normalizeTargetUrl(value) {
  const input = String(value || '').trim();
  if (!input) return '';
  const url = new URL(input);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('La cible doit utiliser HTTP ou HTTPS.');
  if (!['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) throw new Error('La cible dynamique doit être locale.');
  return url.toString().replace(/\/$/, '');
}

async function checkTargetReachability(value, timeoutMs = 3000) {
  let targetUrl;
  try { targetUrl = normalizeTargetUrl(value); } catch (error) { return { state: 'unreachable', error: error.message }; }
  if (!targetUrl) return { state: 'unknown' };
  const client = targetUrl.startsWith('https:') ? https : http;
  return new Promise((resolve) => {
    const request = client.request(targetUrl, { method: 'HEAD', timeout: timeoutMs }, (response) => {
      response.resume();
      resolve({ state: 'online', statusCode: response.statusCode });
    });
    request.once('timeout', () => request.destroy(new Error('timeout')));
    request.once('error', (error) => resolve({ state: 'unreachable', error: error.message }));
    request.end();
  });
}

module.exports = { normalizeTargetUrl, checkTargetReachability };
