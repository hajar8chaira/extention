'use strict';

const { compactIcon, renderSecurityCenterShell } = require('./security-center-shell');
const { PROMETHEUS_STATUS, buildPrometheusStatus, displaySecondsAgo } = require('./integrations/observability');
const { RUNTIME_STATUS, buildRuntimeSecurityStatus } = require('./integrations/siem');
const { DELIVERY_PROVIDERS, PROVIDER_STATUS } = require('./integrations/delivery');
const { renderProviderForm } = require('./delivery-provider-view');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]
  ));
}

function statusTone(status) {
  const value = String(status || '').toLowerCase();
  if (['healthy', 'online', 'connected', 'success'].includes(value)) return 'ok';
  if (['degraded', 'query-error', 'timeout', 'running', 'unstable'].includes(value)) return 'warn';
  if (['offline', 'auth-error', 'error', 'failed'].includes(value)) return 'bad';
  return 'muted';
}

function statusLabel(status) {
  return ({
    [PROMETHEUS_STATUS.NOT_CONFIGURED]: 'Not configured',
    [PROMETHEUS_STATUS.HEALTHY]: 'Connected',
    [PROMETHEUS_STATUS.DEGRADED]: 'Degraded',
    [PROMETHEUS_STATUS.OFFLINE]: 'Unavailable',
    [PROMETHEUS_STATUS.QUERY_ERROR]: 'Invalid URL',
    [PROMETHEUS_STATUS.AUTH_ERROR]: 'Authentication required',
    [PROMETHEUS_STATUS.TIMEOUT]: 'Unavailable',
    [RUNTIME_STATUS.NOT_CONFIGURED]: 'Not configured',
    [RUNTIME_STATUS.ONLINE]: 'Connected',
    [RUNTIME_STATUS.DEGRADED]: 'Degraded',
    [RUNTIME_STATUS.OFFLINE]: 'Unavailable',
    [RUNTIME_STATUS.AUTH_ERROR]: 'Authentication required',
    [RUNTIME_STATUS.TIMEOUT]: 'Unavailable',
    [RUNTIME_STATUS.ERROR]: 'Error'
  })[status] || String(status || 'Unknown');
}

function deliverySummary(delivery = {}) {
  if (!delivery?.configured || delivery.status === PROVIDER_STATUS.NOT_CONFIGURED) {
    return { status: 'not-configured', label: 'Not configured', tone: 'muted', line: 'Optional CI/CD connector' };
  }
  if (delivery.status === PROVIDER_STATUS.HEALTHY) {
    return {
      status: 'healthy',
      label: 'Connected',
      tone: 'ok',
      line: delivery.run?.displayName || delivery.run?.id
        ? `Run ${delivery.run.displayName || delivery.run.id} · ${delivery.run.outcome || 'reported'}`
        : 'Provider responded'
    };
  }
  if ([PROVIDER_STATUS.OFFLINE, PROVIDER_STATUS.AUTH_ERROR, PROVIDER_STATUS.ERROR].includes(delivery.status)) {
    return { status: 'failed', label: 'Attention', tone: 'bad', line: delivery.message || 'Delivery provider unavailable' };
  }
  return { status: 'degraded', label: 'Connected', tone: 'warn', line: delivery.message || 'Delivery state available' };
}

function metricTile(label, metric) {
  const text = metric?.available ? metric.display : 'Unavailable';
  return `<div class="metric-tile"><span>${escapeHtml(label)}</span><strong>${escapeHtml(text)}</strong></div>`;
}

function providerMark(icon, label) {
  return `<span class="provider-mark" aria-hidden="true">${compactIcon(icon)}<small>${escapeHtml(label)}</small></span>`;
}

function capabilityList(items) {
  return `<div class="capabilities">${items.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}</div>`;
}

function endpointLabel(baseUrl) {
  return String(baseUrl || '').trim() || 'Not configured';
}

function renderPrometheusCard(prometheus) {
  const status = prometheus || buildPrometheusStatus();
  const configured = Boolean(status.configured);
  const body = configured
    ? `<div class="metric-grid">
      ${metricTile('CPU', status.metrics.cpu)}
      ${metricTile('RAM', status.metrics.memory)}
      ${metricTile('Disk', status.metrics.disk)}
      ${metricTile('Load', status.metrics.load1)}
    </div>
    <div class="integration-facts">
      <span>Targets: <strong>${escapeHtml(status.targets.display)}</strong></span>
      <span>Endpoint: <strong>${escapeHtml(endpointLabel(status.baseUrl))}</strong></span>
      <span>Last scrape: <strong>${escapeHtml(displaySecondsAgo(status.targets.lastScrapeAgeSeconds))}</strong></span>
    </div>`
    : `<p class="integration-purpose">Metrics, targets and infrastructure observability.</p>
    ${capabilityList(['Targets UP/DOWN', 'CPU', 'RAM', 'Disk', 'Load', 'Last scrape'])}
    <div class="integration-facts"><span>Endpoint: <strong>Not configured</strong></span></div>`;
  return `<article class="integration-card ${statusTone(status.status)}" data-provider="prometheus">
    <div class="integration-card-head">
      <div class="provider-title">${providerMark('chart', 'P')}<div><h3>Observability</h3><p>Provider: ${escapeHtml(status.label || 'Not configured')}</p></div></div>
      <span class="state-chip ${statusTone(status.status)}">● ${escapeHtml(statusLabel(status.status))}</span>
    </div>
    ${body}
    ${status.message ? `<p class="provider-message">${escapeHtml(status.message)}</p>` : ''}
    <div class="actions">
      ${configured ? '<button data-action="viewPrometheus">Open Prometheus</button>' : '<button data-action="revealPrometheusConfig">Configure</button>'}
      <button class="secondary" data-action="testPrometheus">Test connection</button>
      ${configured ? '<button class="secondary" data-action="revealPrometheusConfig">Configure</button>' : ''}
    </div>
  </article>`;
}

function renderWazuhCard(runtime) {
  const status = runtime || buildRuntimeSecurityStatus();
  const configured = Boolean(status.configured);
  const recent = status.alerts[0];
  const body = configured
    ? `<div class="metric-grid">
      <div class="metric-tile"><span>Agents</span><strong>${escapeHtml(String(status.agentSummary.active))} / ${escapeHtml(String(status.agentSummary.total))}</strong></div>
      <div class="metric-tile critical"><span>Critical</span><strong>${escapeHtml(String(status.alertSummary.critical))}</strong></div>
      <div class="metric-tile high"><span>High</span><strong>${escapeHtml(String(status.alertSummary.high))}</strong></div>
      <div class="metric-tile"><span>Medium</span><strong>${escapeHtml(String(status.alertSummary.medium))}</strong></div>
      <div class="metric-tile"><span>Low</span><strong>${escapeHtml(String(status.alertSummary.low || 0))}</strong></div>
    </div>
    <div class="integration-facts">
      <span>Endpoint: <strong>${escapeHtml(endpointLabel(status.baseUrl))}</strong></span>
      <span>Disconnected: <strong>${escapeHtml(String(status.agentSummary.disconnected))}</strong></span>
      <span>Never connected: <strong>${escapeHtml(String(status.agentSummary.neverConnected))}</strong></span>
    </div>
    ${recent ? `<div class="recent-alert"><span>${escapeHtml(recent.severity)}</span><strong>${escapeHtml(recent.title)}</strong><small>${escapeHtml(recent.host || 'Unknown host')}</small></div>` : '<div class="recent-alert muted">No recent runtime alerts returned by the SIEM provider.</div>'}`
    : `<p class="integration-purpose">Agents, runtime alerts, rules and MITRE ATT&amp;CK context.</p>
    ${capabilityList(['Manager status', 'Agents', 'Runtime alerts', 'Rule IDs', 'MITRE ATT&CK'])}
    <div class="integration-facts"><span>Endpoint: <strong>Not configured</strong></span></div>`;
  return `<article class="integration-card ${statusTone(status.status)}" data-provider="wazuh">
    <div class="integration-card-head">
      <div class="provider-title">${providerMark('shield', 'W')}<div><h3>Wazuh</h3><p>SIEM / Runtime Security</p></div></div>
      <span class="state-chip ${statusTone(status.status)}">● ${escapeHtml(statusLabel(status.status))}</span>
    </div>
    ${body}
    ${status.message ? `<p class="provider-message">${escapeHtml(status.message)}</p>` : ''}
    <div class="actions">
      ${configured ? '<button data-action="viewRuntime">Open Runtime Security</button>' : '<button data-action="revealWazuhConfig">Configure</button>'}
      <button class="secondary" data-action="testWazuh">Test connection</button>
      ${configured ? '<button class="secondary" data-action="revealWazuhConfig">Configure</button>' : ''}
    </div>
  </article>`;
}

function renderDeliveryProviderCard(provider, delivery, selectedProvider) {
  const active = delivery?.providerId === provider.id && delivery?.configured;
  const selected = selectedProvider === provider.id;
  const summary = active
    ? deliverySummary(delivery)
    : provider.implemented
      ? { label: 'Implemented', tone: 'muted', line: provider.summary || 'Provider adapter available.' }
      : { label: 'Catalogue only', tone: 'muted', line: 'Provider referenced, adapter unavailable in this version.' };
  const run = active && delivery.run ? (delivery.run.displayName || delivery.run.id || 'Reported') : 'Unavailable';
  const report = active && delivery.securityReport?.reported ? 'Reported' : 'Not reported';
  return `<article class="integration-card ${summary.tone}${selected ? ' selected' : ''}" data-provider="${escapeHtml(provider.id)}">
    <div class="integration-card-head">
      <div class="provider-title">${providerMark('cube', provider.label.slice(0, 1))}<div><h3>${escapeHtml(provider.label)}</h3><p>${provider.implemented ? 'CI/CD adapter implemented' : 'CI/CD catalogue reference'}</p></div></div>
      <span class="state-chip ${summary.tone}">● ${escapeHtml(summary.label)}</span>
    </div>
    <div class="integration-facts">
      <span>Pipeline: <strong>${escapeHtml(active ? (delivery.pipeline || 'Not reported') : 'Not configured')}</strong></span>
      <span>Run: <strong>${escapeHtml(run)}</strong></span>
      <span>Security report: <strong>${escapeHtml(report)}</strong></span>
    </div>
    <p class="provider-message">${escapeHtml(summary.line)}</p>
    <div class="actions">
      <button data-command="securityCenter.openSecurityDelivery">Open delivery</button>
      ${provider.implemented
        ? `<button class="secondary" data-action="selectDeliveryProvider" data-provider-id="${escapeHtml(provider.id)}">${active || selected ? 'Configure' : 'Select'}</button>`
        : `<button class="secondary" data-action="selectDeliveryProvider" data-provider-id="${escapeHtml(provider.id)}">View status</button>`}
      ${active ? '<button class="secondary" data-action="disconnectDelivery">Disconnect</button>' : ''}
    </div>
  </article>`;
}

function renderDeliveryConfiguration(model) {
  const providers = model.deliveryProviders || DELIVERY_PROVIDERS;
  const selected = model.deliverySelectedProvider || model.delivery?.providerId || 'jenkins';
  const provider = providers.find((entry) => entry.id === selected) || providers[0] || null;
  return `<section id="delivery-config" class="config-card delivery-config"${model.openConfig === 'delivery' ? '' : ' hidden'}>
    <div class="config-head"><h3>Security Delivery / CI-CD</h3><span>Provider configuration</span></div>
    <label>CI/CD provider
      <select id="delivery-provider">
        ${providers.map((entry) => `<option value="${escapeHtml(entry.id)}"${entry.id === selected ? ' selected' : ''}>${escapeHtml(entry.label)}${entry.implemented ? '' : ' — catalogue only'}</option>`).join('')}
      </select>
    </label>
    ${renderProviderForm(provider, {
      configuration: model.deliveryProviderValues || {},
      secretsConfigured: model.deliverySecretsConfigured || {}
    })}
    <div class="actions"><button class="secondary" data-action="cancelConfig">Cancel</button></div>
  </section>`;
}

function renderPrometheusForm(prometheus, open = false) {
  return `<section id="prometheus-config" class="config-card"${open ? '' : ' hidden'}>
    <div class="config-head"><h3>Connect Prometheus</h3><span>Optional observability provider</span></div>
    <label>Prometheus URL
      <input id="prometheus-url" type="url" spellcheck="false" autocomplete="off" placeholder="http://host:9090" value="${escapeHtml(prometheus?.baseUrl || '')}">
    </label>
    <small>Security Center reads a small Node Exporter metric subset from the Prometheus API.</small>
    <div class="actions"><button data-action="savePrometheusConfig">Save</button><button class="secondary" data-action="testPrometheusConfig">Test connection</button><button class="secondary" data-action="cancelConfig">Cancel</button></div>
  </section>`;
}

function renderWazuhForm(runtime, open = false) {
  return `<section id="wazuh-config" class="config-card"${open ? '' : ' hidden'}>
    <div class="config-head"><h3>Connect Wazuh</h3><span>Generic SIEM / Runtime Security provider</span></div>
    <label>Wazuh API URL
      <input id="wazuh-url" type="url" spellcheck="false" autocomplete="off" placeholder="https://host:55000" value="${escapeHtml(runtime?.baseUrl || '')}">
    </label>
    <label>Username
      <input id="wazuh-user" type="text" spellcheck="false" autocomplete="off" placeholder="wazuh" value="${escapeHtml(runtime?.username || '')}">
    </label>
    <label>Password / API credential
      <input id="wazuh-password" type="password" autocomplete="off" placeholder="${runtime?.credentialsConfigured ? 'Leave empty to keep the stored credential' : 'Stored in VS Code SecretStorage'}">
    </label>
    <small>${runtime?.credentialsConfigured ? 'Credential configured in SecretStorage.' : 'Credential is never rendered back into this webview.'}</small>
    <div class="actions"><button data-action="saveWazuhConfig">Save</button><button class="secondary" data-action="testWazuhConfig">Test connection</button><button class="secondary" data-action="cancelConfig">Cancel</button></div>
  </section>`;
}

function renderTeamIntegrations(team = {}) {
  return `<section class="integration-section">
    <div class="section-title"><h2>Team notifications</h2><span>Existing notification connectors</span></div>
    <div class="team-grid">
      <article class="team-card">${providerMark('pulse', 'S')}<div><strong>Slack</strong><span>${team.slackEnabled ? 'Enabled' : 'Optional'}</span></div><button class="secondary" data-action="configureSlack">Configure</button></article>
      <article class="team-card">${providerMark('compare', 'J')}<div><strong>Jira</strong><span>${team.jiraEnabled ? 'Enabled' : 'Optional'}</span></div><button class="secondary" data-action="configureJira">Configure</button></article>
    </div>
  </section>`;
}

/**
 * The Security Center backend, as the user sees it.
 *
 * Nothing on this card asks for a Docker path, a compose file or a container
 * name: in the standard mode there is no container, and the only thing the user
 * can usefully act on is the mode and — in Remote mode — the address. The
 * resolved address is shown rather than the configured one, because in Auto
 * mode the port is chosen at start time and the two can differ.
 */
function renderBackendCard(backend = {}) {
  const state = String(backend.state || 'not-configured');
  const tone = backend.online ? 'ok' : ['starting'].includes(state) ? 'warn' : 'bad';
  const label = backend.label || statusLabel(state);
  const detail = backend.online
    ? 'Persistance, historique, tendances et ingestion Burp'
    : escapeHtml(backend.hint || backend.message || 'Service indisponible');
  return `<article class="integration-card ${tone}" data-card="backend">
    <div class="card-head">${providerMark('server', 'Backend')}<span class="state-chip ${tone}">● ${escapeHtml(label)}</span></div>
    <div><strong>Security Center Backend</strong><span class="card-line">${detail}</span></div>
    <dl class="backend-facts">
      <div><dt>Mode</dt><dd>${escapeHtml(backend.modeLabel || backend.mode || 'Auto')}</dd></div>
      <div><dt>Resolved mode</dt><dd>${escapeHtml(backend.resolvedMode || 'local')}</dd></div>
      <div><dt>Address</dt><dd>${escapeHtml(endpointLabel(backend.url))}</dd></div>
      <div><dt>Version</dt><dd>${escapeHtml(backend.version || 'Unavailable')}</dd></div>
    </dl>
    ${capabilityList(['Scan history', 'Trends / MTTR', 'Audit journal', 'Burp ingestion'])}
    <div class="actions">
      <button data-action="testBackend">Test connection</button>
      ${backend.managed ? '<button class="secondary" data-action="restartBackend">Restart backend</button>' : ''}
      <button class="secondary" data-action="revealBackendConfig">Advanced configuration</button>
    </div>
  </article>`;
}

/** The advanced form. Closed by default: the standard mode needs no configuration. */
function renderBackendForm(backend = {}, open = false) {
  const mode = String(backend.mode || 'auto');
  const option = (value, label, hint) => `<label class="radio-row">
    <input type="radio" name="backend-mode" value="${value}"${mode === value ? ' checked' : ''}>
    <span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(hint)}</small></span>
  </label>`;
  return `<details class="config-card" data-config="backend"${open ? ' open' : ''}>
    <summary>Security Center Backend — advanced configuration</summary>
    <div class="config-grid">
      ${option('auto', 'Auto / Local', 'Le service local est démarré par l’extension. Aucune installation requise.')}
      ${option('remote', 'Remote', 'Un backend opéré par votre organisation. L’extension ne démarre rien.')}
      ${option('docker', 'Docker (développement)', 'docker-compose.backend.yml, pour le développement et les tests.')}
      <label>Remote URL
        <input type="url" id="backend-url" value="${escapeHtml(backend.remoteUrl || '')}" placeholder="https://security.company.internal">
      </label>
      <small class="config-note">Les données locales sont conservées dans le stockage global de VS Code : une mise à jour de l’extension ne supprime pas l’historique.</small>
    </div>
    <div class="actions">
      <button data-action="saveBackendConfig">Save</button>
      <button class="secondary" data-action="resetBackendConfig">Reset to defaults</button>
    </div>
  </details>`;
}

function renderOverview(model) {
  const deliveryProviders = model.deliveryProviders || DELIVERY_PROVIDERS;
  const deliverySelectedProvider = model.deliverySelectedProvider || model.delivery?.providerId || 'jenkins';
  return `<section class="integration-section">
    <div class="section-title"><h2>Security Center Backend</h2><span>Service local géré par l’extension</span></div>
    <div class="integration-grid">${renderBackendCard(model.backend)}</div>
  </section>
  <section class="integration-section">
    <div class="section-title"><h2>CI / Delivery</h2><span>Security Delivery / CI-CD providers</span></div>
    <div class="integration-grid">${deliveryProviders.map((provider) => renderDeliveryProviderCard(provider, model.delivery, deliverySelectedProvider)).join('')}</div>
  </section>
  <section class="integration-section">
    <div class="section-title"><h2>Observability</h2><span>Infrastructure facts from external metrics</span></div>
    <div class="integration-grid">${renderPrometheusCard(model.prometheus)}</div>
  </section>
  <section class="integration-section">
    <div class="section-title"><h2>SIEM / Runtime Security</h2><span>Normalized provider model; Wazuh is the first adapter</span></div>
    <div class="integration-grid">${renderWazuhCard(model.runtime)}</div>
  </section>
  ${renderBackendForm(model.backend, model.openConfig === 'backend')}
  ${renderPrometheusForm(model.prometheus, model.openConfig === 'prometheus')}
  ${renderWazuhForm(model.runtime, model.openConfig === 'wazuh')}
  ${renderDeliveryConfiguration(model)}
  ${renderTeamIntegrations(model.team)}`;
}

function renderPrometheusDetail(prometheus) {
  const status = prometheus || buildPrometheusStatus();
  const configured = Boolean(status.configured);
  return `<section class="detail-page">
    <div class="detail-hero"><div><h2>Infrastructure</h2><span>Prometheus</span></div><span class="state-chip ${statusTone(status.status)}">● ${escapeHtml(statusLabel(status.status))}</span></div>
    <h3>${escapeHtml(configured ? (status.selectedHost || 'No runtime host selected') : 'Prometheus is not configured')}</h3>
    <div class="detail-grid">
      ${metricTile('CPU', status.metrics.cpu)}
      ${metricTile('Memory', status.metrics.memory)}
      ${metricTile('Disk', status.metrics.disk)}
      ${metricTile('Load', status.metrics.load1)}
      <div class="metric-tile"><span>Targets</span><strong>${escapeHtml(status.targets.display)}</strong></div>
      <div class="metric-tile"><span>Last scrape</span><strong>${escapeHtml(displaySecondsAgo(status.targets.lastScrapeAgeSeconds))}</strong></div>
    </div>
    <div class="actions"><button class="secondary" data-action="showOverview">Back to integrations</button>${configured ? '<button data-action="testPrometheus">Refresh metrics</button>' : '<button data-action="revealPrometheusConfig">Configure</button>'}</div>
    ${renderPrometheusForm(status, !configured)}
  </section>`;
}

function renderRuntimeDetail(runtime) {
  const status = runtime || buildRuntimeSecurityStatus();
  const configured = Boolean(status.configured);
  const count = (value) => configured ? String(value) : 'Unavailable';
  const agents = status.agents.map((agent) => `<article class="runtime-row">
    <div><strong>${escapeHtml(agent.name)}</strong><span>${escapeHtml(agent.os || 'OS unavailable')}</span></div>
    <span class="state-chip ${statusTone(agent.status === 'active' ? 'online' : 'degraded')}">● ${escapeHtml(agent.status)}</span>
    <span>${escapeHtml(agent.ip || 'No IP')}</span><span>${escapeHtml(agent.lastSeen || 'Last seen unavailable')}</span>
  </article>`).join('') || '<div class="empty">No agents returned by the SIEM provider.</div>';
  const alerts = status.alerts.map((alert) => `<article class="alert-row ${escapeHtml(String(alert.severity).toLowerCase())}">
    <span>${escapeHtml(alert.severity)}</span>
    <div><strong>${escapeHtml(alert.title)}</strong><small>${escapeHtml(alert.host || 'Unknown host')} · Rule ${escapeHtml(alert.ruleId || 'Unavailable')}${alert.mitreTechniques.length ? ` · MITRE ${escapeHtml(alert.mitreTechniques.join(', '))}` : ''}</small></div>
    <time>${escapeHtml(alert.timestamp || 'Timestamp unavailable')}</time>
  </article>`).join('') || '<div class="empty">No recent runtime alerts returned by the SIEM provider.</div>';
  return `<section class="detail-page">
    <div class="detail-hero"><div><h2>Runtime Security</h2><span>Provider: ${escapeHtml(status.label)}</span></div><span class="state-chip ${statusTone(status.status)}">● ${escapeHtml(statusLabel(status.status))}</span></div>
    <div class="detail-grid">
      <div class="metric-tile"><span>Manager status</span><strong>${escapeHtml(configured ? statusLabel(status.status) : 'Unavailable')}</strong></div>
      <div class="metric-tile"><span>Agents active</span><strong>${escapeHtml(count(status.agentSummary.active))}</strong></div>
      <div class="metric-tile"><span>Disconnected</span><strong>${escapeHtml(count(status.agentSummary.disconnected))}</strong></div>
      <div class="metric-tile"><span>Never connected</span><strong>${escapeHtml(count(status.agentSummary.neverConnected))}</strong></div>
      <div class="metric-tile critical"><span>Critical</span><strong>${escapeHtml(count(status.alertSummary.critical))}</strong></div>
      <div class="metric-tile high"><span>High</span><strong>${escapeHtml(count(status.alertSummary.high))}</strong></div>
      <div class="metric-tile"><span>Medium</span><strong>${escapeHtml(count(status.alertSummary.medium))}</strong></div>
      <div class="metric-tile"><span>Low</span><strong>${escapeHtml(count(status.alertSummary.low || 0))}</strong></div>
    </div>
    <h3>Agents</h3><div class="runtime-list">${agents}</div>
    <h3>Recent alerts</h3><div class="runtime-list">${alerts}</div>
    <div class="actions"><button class="secondary" data-action="showOverview">Back to integrations</button>${configured ? '<button data-action="testWazuh">Refresh runtime security</button>' : '<button data-action="revealWazuhConfig">Configure</button>'}</div>
    ${renderWazuhForm(status, !configured)}
  </section>`;
}

function integrationsCss() {
  return `
  .integration-section{display:grid;gap:10px;margin-bottom:18px}
  .section-title{display:flex;justify-content:space-between;align-items:end;gap:12px}
  .section-title h2{margin:0;font-size:11px;letter-spacing:.8px;text-transform:uppercase;color:var(--sc-muted)}
  .section-title span{font-size:10px;color:var(--sc-muted)}
  .integration-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .integration-card,.config-card,.team-card,.detail-page{border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:15px}
  .integration-card{display:grid;gap:12px;border-top:2px solid var(--sc-border)}
  .integration-card.selected{box-shadow:0 0 0 2px color-mix(in srgb,var(--sc-primary) 30%,transparent),var(--sc-shadow-sm)}
  .integration-card.ok{border-top-color:var(--sc-success)}
  .integration-card.warn{border-top-color:var(--sc-warning)}
  .backend-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 12px;margin:0}
  .backend-facts div{display:grid;gap:2px;min-width:0}
  .backend-facts dt{font-size:10px;letter-spacing:.4px;text-transform:uppercase;color:var(--sc-muted)}
  .backend-facts dd{margin:0;font-size:11px;overflow-wrap:anywhere}
  .radio-row{display:flex;gap:8px;align-items:start;font-size:11px}
  .radio-row span{display:grid;gap:2px}
  .radio-row small{color:var(--sc-muted)}
  .config-note{color:var(--sc-muted);font-size:10px}
  .integration-card.bad{border-top-color:var(--sc-danger)}
  .integration-card-head,.detail-hero,.config-head{display:flex;justify-content:space-between;align-items:start;gap:12px}
  .provider-title{display:grid;grid-template-columns:34px minmax(0,1fr);align-items:center;gap:10px;min-width:0}
  .provider-mark{display:grid;place-items:center;position:relative;width:34px;height:34px;border-radius:10px;color:var(--sc-primary);background:linear-gradient(135deg,var(--sc-primary-soft),var(--sc-surface));border:1px solid color-mix(in srgb,var(--sc-primary) 24%,var(--sc-border));box-shadow:0 8px 18px color-mix(in srgb,var(--sc-primary) 14%,transparent)}
  .provider-mark .compact-icon{width:18px;height:18px}.provider-mark small{position:absolute;right:4px;bottom:2px;font-size:7px;font-weight:900;color:var(--sc-primary)}
  h2,h3{margin:0;color:var(--sc-text)}
  .integration-card h3{font-size:15px}
  .integration-card p,.provider-message,.integration-purpose,.integration-facts span,.team-card span,small{margin:0;color:var(--sc-muted);font-size:11px;line-height:1.45}
  .capabilities{display:flex;flex-wrap:wrap;gap:6px}.capabilities span{padding:4px 8px;border-radius:999px;color:var(--sc-primary);background:var(--sc-primary-soft);font-size:9px;font-weight:800}
  .state-chip{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;border-radius:999px;padding:4px 9px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.45px;color:var(--sc-muted);background:var(--sc-surface-soft)}
  .state-chip.ok{color:var(--sc-success);background:var(--sc-success-bg)}
  .state-chip.warn{color:var(--sc-warning);background:var(--sc-warning-bg)}
  .state-chip.bad{color:var(--sc-danger);background:var(--sc-danger-bg)}
  .metric-grid,.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(108px,1fr));gap:8px}
  .metric-tile{display:grid;gap:5px;min-width:0;padding:10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface-soft)}
  .metric-tile span{font-size:9px;font-weight:800;letter-spacing:.5px;text-transform:uppercase;color:var(--sc-muted)}
  .metric-tile strong{font-size:15px;overflow-wrap:anywhere}
  .metric-tile.critical strong,.alert-row.critical>span{color:var(--sc-critical)}
  .metric-tile.high strong,.alert-row.high>span{color:var(--sc-high)}
  .integration-facts{display:grid;gap:6px}
  .integration-facts span{display:flex;justify-content:space-between;gap:12px}
  .recent-alert{display:grid;gap:3px;padding:10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface)}
  .recent-alert span{font-size:9px;font-weight:800;color:var(--sc-danger)}
  .recent-alert strong{font-size:12px}.recent-alert small{color:var(--sc-muted)}
  .actions{display:flex;flex-wrap:wrap;gap:8px}
  button{font:700 11px var(--vscode-font-family);border:1px solid var(--sc-primary);border-radius:var(--sc-radius-md);padding:7px 12px;cursor:pointer;color:var(--sc-primary-text,var(--vscode-button-foreground));background:var(--sc-primary)}
  button.secondary{color:var(--sc-text);border-color:var(--sc-border);background:var(--sc-surface)}
  button:hover{background:var(--sc-primary-hover)}button.secondary:hover{background:var(--sc-surface-soft)}
  .config-card{display:grid;gap:11px;margin-bottom:18px}.config-card[hidden]{display:none}
  label{display:grid;gap:5px;font-size:11px;font-weight:700;color:var(--sc-text)}
  input,select{min-width:0;padding:8px 10px;border-radius:var(--sc-radius-md);border:1px solid var(--sc-input-border,var(--sc-border));color:var(--sc-input-text,var(--sc-text));background:var(--sc-input-bg,var(--sc-surface))}
  .delivery-config .card{box-shadow:none;margin:0;padding:0;border:0;background:transparent}
  .delivery-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px}
  .field{margin-top:11px;display:flex;flex-direction:column;gap:5px;min-width:0}
  .field label{display:flex;align-items:center;gap:8px}
  .field input[type="checkbox"]{width:15px;height:15px;min-width:15px;padding:0}
  .field small,summary{font-size:10px;color:var(--sc-muted)}
  .team-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
  .team-card{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:12px}.team-card div{display:grid;gap:4px}
  .detail-page{display:grid;gap:14px}.detail-hero{padding-bottom:12px;border-bottom:1px solid var(--sc-border)}
  .runtime-list{display:grid;gap:8px}.runtime-row,.alert-row{display:grid;grid-template-columns:minmax(0,1fr) auto auto auto;gap:12px;align-items:center;padding:10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface)}
  .runtime-row div,.alert-row div{min-width:0}.runtime-row strong,.alert-row strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .runtime-row span,.alert-row small,.alert-row time{color:var(--sc-muted);font-size:10.5px}
  .alert-row>span{font-size:9px;font-weight:900;text-transform:uppercase}
  .empty{padding:12px;border:1px dashed var(--sc-border);border-radius:var(--sc-radius-md);color:var(--sc-muted);background:var(--sc-surface-soft)}
  @media(max-width:780px){.section-title,.integration-card-head,.detail-hero,.config-head{align-items:start;flex-direction:column}.runtime-row,.alert-row{grid-template-columns:1fr}.integration-facts span{display:block}}`;
}

function renderIntegrationPageHtml(model = {}, nonce = '', theme = 'light') {
  const view = model.view === 'prometheus' || model.view === 'runtime' ? model.view : 'overview';
  const prometheus = model.prometheus || buildPrometheusStatus();
  const runtime = model.runtime || buildRuntimeSecurityStatus();
  const deliveryFields = (model.deliveryProviderDefinition?.configurationFields || []).map((field) => ({
    id: field.id, type: field.type, secret: Boolean(field.secret)
  }));
  const content = view === 'prometheus'
    ? renderPrometheusDetail(prometheus)
    : view === 'runtime'
      ? renderRuntimeDetail(runtime)
      : renderOverview({ ...model, prometheus, runtime });
  return renderSecurityCenterShell({
    surface: 'integrations',
    brandLogoUri: model.brandLogoUri || '',
    cspSource: model.cspSource || '',
    nonce,
    theme,
    title: 'Integrations',
    subtitle: 'Optional enterprise connectors for CI, observability and runtime security',
    headerActions: '<button data-action="refresh">Refresh</button>',
    content,
    styles: integrationsCss(),
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();
      const value=id=>{const el=document.getElementById(id);return el?el.value.trim():'';};
      const deliveryFields=${JSON.stringify(deliveryFields)};
      const deliveryProvider=()=>{const el=document.getElementById('delivery-provider');return el?el.value:'';};
      const deliveryConfig=()=>Object.fromEntries(deliveryFields.map(entry=>{
        const el=document.getElementById('delivery-'+entry.id);
        return [entry.id,entry.type==='boolean'?Boolean(el&&el.checked):(el?el.value.trim():'')];
      }));
      const backendConfig=()=>({mode:(document.querySelector('input[name="backend-mode"]:checked')||{}).value||'auto',url:value('backend-url')});
      const prometheusConfig=()=>({url:value('prometheus-url')});
      const wazuhConfig=()=>({url:value('wazuh-url'),username:value('wazuh-user'),password:value('wazuh-password')});
      const reveal=id=>{const el=document.getElementById(id);if(el){el.hidden=false;el.scrollIntoView({block:'nearest'});const input=el.querySelector('input');if(input)input.focus();}};
      document.querySelectorAll('[data-command]:not(.sc-nav-item)').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
      document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{
        const action=b.dataset.action;
        if(action==='selectDeliveryProvider')return vscode.postMessage({type:'action',action,provider:b.dataset.providerId});
        if(action==='revealBackendConfig'){const el=document.querySelector('[data-config="backend"]');if(el){el.open=true;el.scrollIntoView({block:'nearest'});}return;}
        if(action==='saveBackendConfig')return vscode.postMessage({type:'action',action,config:backendConfig()});
        if(action==='revealPrometheusConfig')return reveal('prometheus-config');
        if(action==='revealWazuhConfig')return reveal('wazuh-config');
        if(action==='cancelConfig'){document.querySelectorAll('.config-card').forEach(el=>el.hidden=true);return;}
        if(action==='deliverySave'||action==='deliveryTest')return vscode.postMessage({type:'action',action,provider:deliveryProvider(),config:deliveryConfig()});
        if(action==='disconnectDelivery')return vscode.postMessage({type:'action',action});
        if(action==='savePrometheusConfig'||action==='testPrometheusConfig')return vscode.postMessage({type:'action',action,config:prometheusConfig()});
        if(action==='saveWazuhConfig'||action==='testWazuhConfig')return vscode.postMessage({type:'action',action,config:wazuhConfig()});
        vscode.postMessage({type:'action',action});
      });
      const deliverySelect=document.getElementById('delivery-provider');
      if(deliverySelect)deliverySelect.onchange=()=>vscode.postMessage({type:'action',action:'selectDeliveryProvider',provider:deliveryProvider()});`
  });
}

module.exports = {
  renderBackendCard,
  renderBackendForm,
  renderIntegrationPageHtml,
  renderPrometheusCard,
  renderWazuhCard,
  renderDeliveryProviderCard,
  renderPrometheusDetail,
  renderRuntimeDetail,
  deliverySummary,
  statusTone,
  statusLabel,
  escapeHtml
};
