'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  PROMETHEUS_STATUS,
  fetchPrometheusStatus,
  targetsFrom,
  normalizePrometheusUrl
} = require('../src/integrations/observability');
const { RUNTIME_STATUS, AGENT_STATUS, normalizeAgentStatus, agentSummary } = require('../src/integrations/siem');
// Wazuh's own client lives in its adapter, and is exercised by the Wazuh
// suites. The registry keeps only what every provider shares.
const { wazuhAdapter, wazuhLevelToSeverity, extractMitreTechniques } = require('../src/integrations/siem-wazuh');
const { IntegrationHttpError } = require('../src/integrations/http');
const { renderIntegrationPageHtml } = require('../src/integrations-page');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const manifest = require('../package.json');

const vector = (value, metric = { instance: 'ubuntu-runtime:9100' }) => ({
  status: 'success',
  data: { resultType: 'vector', result: [{ metric, value: [1755600000, String(value)] }] }
});

// Les series de systeme de fichiers portent toujours un point de montage :
// c'est la cle qui permet d'apparier taille et espace libre sans les melanger.
const fsVector = (value, mountpoint = '/', instance = 'ubuntu-runtime:9100') => ({
  status: 'success',
  data: { resultType: 'vector', result: [{ metric: { instance, mountpoint }, value: [1755600000, String(value)] }] }
});

const targetsPayload = () => ({
  data: {
    activeTargets: [
      { health: 'up', labels: { instance: 'ubuntu-runtime:9100' }, lastScrape: new Date(Date.now() - 8000).toISOString() },
      { health: 'up', labels: { instance: 'api-runtime:9100' }, lastScrape: new Date(Date.now() - 9000).toISOString() }
    ]
  }
});

test('Prometheus normalizes health, targets and node exporter metrics', async () => {
  // Deux cibles sont surveillees : le fournisseur ne choisit pas pour l'utilisateur,
  // donc l'hote a lire est explicite.
  const status = await fetchPrometheusStatus({
    baseUrl: 'http://prometheus.local:9090/',
    host: 'ubuntu-runtime:9100',
    request: async (url) => {
      if (url.includes('/targets')) return targetsPayload();
      if (url.includes('node_cpu_seconds_total')) return vector(21);
      if (url.includes('MemTotal')) return vector(9.7 * 1024 ** 3);
      if (url.includes('MemAvailable')) return vector(6.3 * 1024 ** 3);
      if (url.includes('filesystem_size')) return fsVector(1000);
      if (url.includes('filesystem_avail')) return fsVector(880);
      if (url.includes('node_load1')) return vector(0.42);
      throw new Error('unexpected query');
    }
  });
  assert.equal(status.status, PROMETHEUS_STATUS.HEALTHY);
  assert.equal(status.targets.up, 2);
  assert.equal(status.targets.total, 2);
  assert.equal(status.metrics.cpu.display, '21%');
  assert.equal(status.metrics.memory.display, '3.4 GB / 9.7 GB');
  assert.equal(status.metrics.disk.display, '12%');
  assert.equal(status.metrics.load1.display, '0.42');
  assert.equal(status.selectedHost, 'ubuntu-runtime:9100');
  assert.equal(status.hostSelectionRequired, false);
  // Les deux cibles restent inventoriees, mais une seule publie des series
  // d hote : c est elle, et elle seule, qui peut etre choisie.
  assert.deepEqual([...status.targets.items].map((item) => item.id).sort(), ['api-runtime:9100', 'ubuntu-runtime:9100']);
  assert.deepEqual([...status.hosts].sort(), ['ubuntu-runtime:9100']);
});

test('Prometheus metric failures stay unavailable and never become zero', async () => {
  const status = await fetchPrometheusStatus({
    baseUrl: 'http://prometheus.local:9090',
    host: 'ubuntu-runtime:9100',
    request: async (url) => {
      if (url.includes('/targets')) return targetsPayload();
      if (url.includes('node_cpu_seconds_total')) return vector(0);
      throw new IntegrationHttpError('query failed', 'QUERY_ERROR');
    }
  });
  assert.equal(status.status, PROMETHEUS_STATUS.DEGRADED);
  assert.equal(status.metrics.cpu.available, true);
  assert.equal(status.metrics.cpu.display, '0%', 'a real returned zero is rendered');
  assert.equal(status.metrics.memory.available, false);
  assert.equal(status.metrics.memory.display, 'Unavailable');
  assert.equal(status.metrics.disk.display, 'Unavailable');
});

test('Prometheus maps timeout, auth and offline states distinctly', async () => {
  for (const [code, expected] of [
    ['TIMEOUT', PROMETHEUS_STATUS.TIMEOUT],
    ['AUTH_ERROR', PROMETHEUS_STATUS.AUTH_ERROR],
    ['OFFLINE', PROMETHEUS_STATUS.OFFLINE]
  ]) {
    const status = await fetchPrometheusStatus({
      baseUrl: 'http://prometheus.local:9090',
      request: async () => { throw new IntegrationHttpError('network', code); }
    });
    assert.equal(status.status, expected);
  }
});

test('Prometheus rejects credentials embedded in URLs', () => {
  assert.throws(() => normalizePrometheusUrl('http://user:pass@prometheus.local:9090'), /identifiants/);
  assert.equal(normalizePrometheusUrl('http://prometheus.local:9090/path?token=x#frag'), 'http://prometheus.local:9090/path');
});

test('targets normalization handles down targets without faking success', () => {
  const targets = targetsFrom({ data: { activeTargets: [{ health: 'up' }, { health: 'down' }] } });
  assert.equal(targets.up, 1);
  assert.equal(targets.total, 2);
  assert.equal(targets.display, '1/2 UP');
});

test('Wazuh severity and MITRE extraction stay with the adapter', () => {
  assert.equal(wazuhLevelToSeverity(15), 'CRITICAL');
  assert.equal(wazuhLevelToSeverity(12), 'CRITICAL');
  assert.equal(wazuhLevelToSeverity(9), 'HIGH');
  assert.equal(wazuhLevelToSeverity(5), 'MEDIUM');
  assert.equal(wazuhLevelToSeverity(2), 'LOW');
  assert.equal(wazuhLevelToSeverity(0), 'INFO');
  assert.equal(wazuhLevelToSeverity('bogus'), 'INFO');
  assert.deepEqual(extractMitreTechniques({ mitre: { id: ['T1110'], technique: ['Brute Force'] } }), ['T1110', 'Brute Force']);
  assert.deepEqual(extractMitreTechniques({}), []);
});

test('the SIEM registry keeps only what every provider shares', () => {
  // Le client Wazuh a quitte le registre : plus de second exemplaire.
  const registry = fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', 'siem.js'), 'utf8');
  for (const leaked of ['/manager/info', '/agents', 'authenticateWazuh', 'agentsFromWazuh', 'alertsFromWazuh', 'wazuhLevelToSeverity']) {
    assert.ok(!registry.includes(leaked), `${leaked} ne doit plus vivre dans le registre`);
  }
  // Ce qui reste est generique et utilisable par n importe quel fournisseur.
  assert.equal(normalizeAgentStatus('never_connected'), AGENT_STATUS.NEVER_CONNECTED);
  assert.deepEqual(agentSummary([{ status: AGENT_STATUS.ACTIVE }, { status: AGENT_STATUS.DISCONNECTED }]),
    { total: 2, active: 1, disconnected: 1, neverConnected: 0 });
  // Et l adaptateur, lui, sait toujours parler a son API.
  assert.equal(typeof wazuhAdapter.fetchStatus, 'function');
});

test('Integrations page always exposes unconfigured Prometheus and Wazuh without fake zeros', () => {
  const html = renderIntegrationPageHtml({}, 'n', 'light');
  assert.match(html, /data-provider="prometheus"/);
  assert.match(html, /data-provider="wazuh"/);
  assert.match(html, /CI \/ Delivery/);
  assert.match(html, /Observability/);
  assert.match(html, /SIEM \/ Runtime Security/);
  assert.match(html, /Team notifications/);
  assert.match(html, /Prometheus URL/);
  assert.match(html, /Wazuh API URL/);
  assert.match(html, /Test connection/);
  assert.match(html, /Cancel/);
  assert.match(html, /Metrics, targets and infrastructure observability/);
  assert.match(html, /Agents, runtime alerts, rules and MITRE ATT&amp;CK context/);
  assert.doesNotMatch(html, /<strong>0<\/strong>/, 'not-configured providers must not look like real zero data');
  assert.doesNotMatch(html, /password[^<]*secret-password|Bearer |Basic /i);
});

test('Prometheus and Runtime detail pages are generic Security Center views', () => {
  const prometheus = renderIntegrationPageHtml({ view: 'prometheus', prometheus: { configured: true, status: PROMETHEUS_STATUS.HEALTHY, targets: { display: '2/2 UP', lastScrapeAgeSeconds: 8 }, selectedHost: 'ubuntu-runtime', metrics: { cpu: { available: true, display: '21%' }, memory: { available: true, display: '3.4 GB / 9.7 GB' }, disk: { available: true, display: '12%' }, load1: { available: true, display: '0.42' } } } }, 'n', 'dark');
  assert.match(prometheus, /Infrastructure/);
  assert.doesNotMatch(prometheus, /Grafana/);
  const runtime = renderIntegrationPageHtml({ view: 'runtime', runtime: { configured: true, status: RUNTIME_STATUS.ONLINE, label: 'Wazuh', agentSummary: { active: 1, total: 1, disconnected: 0, neverConnected: 0 }, alertSummary: { critical: 1, high: 0, medium: 0 }, agents: [{ name: 'ubuntu-runtime', os: 'Ubuntu 22.04', status: 'active', ip: '10.0.0.5', lastSeen: '10 sec ago' }], alerts: [{ severity: 'CRITICAL', title: 'SSH brute-force attempt', host: 'ubuntu-runtime', ruleId: '5710', mitreTechniques: ['T1110'] }] } }, 'n', 'light');
  assert.match(runtime, /Runtime Security/);
  assert.doesNotMatch(runtime, /Wazuh Dashboard/);
});

test('unconfigured detail pages show setup state instead of zero runtime metrics', () => {
  const prometheus = renderIntegrationPageHtml({ view: 'prometheus' }, 'n', 'light');
  assert.match(prometheus, /Prometheus is not configured/);
  assert.match(prometheus, /Unavailable/);
  assert.match(prometheus, /Prometheus URL/);
  const runtime = renderIntegrationPageHtml({ view: 'runtime' }, 'n', 'light');
  assert.match(runtime, /Manager status/);
  assert.match(runtime, /Unavailable/);
  assert.match(runtime, /Wazuh API URL/);
  assert.doesNotMatch(runtime, /<strong>0<\/strong>/);
});

test('dashboard enterprise summary is optional and uses provided normalized facts only', () => {
  const empty = renderDashboardHtml(buildDashboardModel([], []), 'n', 'full', 'light');
  assert.doesNotMatch(empty, /Enterprise Security/);
  const model = buildDashboardModel([], [], {
    enterprise: {
      prometheus: { configured: true, status: 'healthy', metrics: { cpu: { display: '21%' }, memory: { display: '35%' } } },
      runtime: { configured: true, status: 'online', label: 'Wazuh', alertSummary: { critical: 2, high: 5 } },
      delivery: { configured: true, state: 'SUCCESS', build: { number: 42 } }
    }
  });
  const html = renderDashboardHtml(model, 'n', 'full', 'light');
  assert.match(html, /Security Domains/);
  assert.match(html, /CPU 21% · RAM 35%/);
  assert.match(html, /Wazuh · 2 Critical · 5 High/);
});

test('dashboard enterprise summary is visible before provider configuration and routes contextual actions', () => {
  const model = buildDashboardModel([], [], {
    enterprise: {
      prometheus: { configured: false, status: 'not-configured' },
      runtime: { configured: false, status: 'not-configured', label: 'Wazuh' },
      delivery: { configured: false }
    }
  });
  const html = renderDashboardHtml(model, 'n', 'full', 'light');
  assert.match(html, /Security Domains/);
  assert.match(html, /Application Security/);
  assert.match(html, /Delivery Security/);
  assert.match(html, /Infrastructure/);
  assert.match(html, /AI Companion/);
  assert.match(html, /Connect observability/);
  assert.match(html, /Connect a SIEM provider/);
  assert.doesNotMatch(html, /Wazuh · Not configured|Prometheus · Not configured/);
  assert.match(html, /data-command="securityCenter.configureObservability"/);
  assert.match(html, /data-command="securityCenter.configureSiem"/);
  assert.doesNotMatch(html, /CPU 0|RAM 0/);
});

test('Integrations routing is connected through the real shell command and webview actions', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /registerCommand\('securityCenter\.configureTeamIntegrations'[\s\S]{0,120}openIntegrationsPage\(\)/);
  assert.match(source, /createWebviewPanel\('securityCenter\.integrations'/);
  assert.match(source, /renderIntegrationPageHtml\(/);
  assert.match(source, /message\.action === 'viewPrometheus'[\s\S]{0,80}integrationsView = 'prometheus'/);
  assert.match(source, /message\.action === 'viewRuntime'[\s\S]{0,80}integrationsView = 'runtime'/);
  assert.match(source, /message\.action === 'savePrometheusConfig'[\s\S]{0,420}refreshPrometheusStatus\(\)/);
  assert.match(source, /message\.action === 'saveWazuhConfig'[\s\S]{0,420}refreshRuntimeSecurityStatus\(\)/);
  assert.match(source, /'securityCenter\.configurePrometheus'/);
  assert.match(source, /registerCommand\('securityCenter\.configureSiem'/);
  assert.match(source, /'securityCenter\.openRuntimeSecurity'/);
  assert.match(source, /registerCommand\('securityCenter\.openInfrastructure'/);
});

test('enterprise credentials use SecretStorage and are not manifest settings', () => {
  const properties = Object.keys(manifest.contributes.configuration.properties);
  assert.ok(properties.includes('securityCenter.prometheus.url'));
  assert.ok(properties.includes('securityCenter.wazuh.url'));
  assert.ok(properties.includes('securityCenter.wazuh.username'));
  assert.ok(!properties.some((key) => /prometheus.*(token|password|secret)|wazuh.*(token|password|secret)/i.test(key)));
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // Idem : la persistance des secrets vit dans le service provider-neutre.
  assert.match(source, /secrets: context\.secrets/);
  const shared = fs.readFileSync(path.join(__dirname, '..', 'src', 'integrations', 'provider-configuration.js'), 'utf8');
  assert.match(shared, /secrets\.store\(secretKeyFor\(adapter\.id, field\.id\)/);
  assert.match(shared, /secrets\.get\(secretKeyFor\(adapter\.id, field\.id\)/);
  assert.doesNotMatch(source, /update\('wazuh\.(password|token|secret)'/);
});

test('no new external animation or dashboard dependency is introduced for integrations', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.deepEqual(packageJson.dependencies || {}, {});
  assert.ok(!packageJson.contributes.commands.some((entry) => /grafana/i.test(entry.command) || /grafana/i.test(entry.title)));
  assert.ok(!packageJson.activationEvents.some((entry) => /grafana/i.test(entry)));
});
