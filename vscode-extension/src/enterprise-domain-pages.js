'use strict';

const { compactIcon, renderSecurityCenterShell } = require('./security-center-shell');
const {
  PROMETHEUS_STATUS, buildPrometheusStatus, displaySecondsAgo,
  OBSERVABILITY_PROVIDERS, observabilityProvider, observabilityAdapter,
  isSupportedObservabilityProvider, supportedObservabilityProviders, plannedObservabilityProviders,
  resolveCapabilities: resolveObservabilityCapabilities, visibleSections: visibleObservabilitySections,
  CAPABILITY: OBSERVABILITY_CAPABILITY, RESOLVED_STATE: OBSERVABILITY_STATE
} = require('./integrations/observability');
const {
  RUNTIME_STATUS, buildRuntimeSecurityStatus,
  siemProvider, isSupportedSiemProvider, supportedSiemProviders, plannedSiemProviders, SIEM_PROVIDERS
} = require('./integrations/siem');
const { CONFIG_GROUP, FIELD_TYPE: CONFIG_FIELD_TYPE, fieldsInGroup } = require('./integrations/siem-contract');
const {
  RUNTIME_CAPABILITY_STATE, RUNTIME_CAPABILITY_LABELS, CAPABILITY_TABS,
  capabilityVisible, capabilityOffered, runtimeNavigation
} = require('./integrations/siem-navigation');
const {
  normalizeVulnerabilityQuery, isVulnerabilityFiltered, severityCounts,
  vulnerabilityKey, vulnerabilityDetailSections
} = require('./integrations/siem-vulnerabilities');
const {
  alertEndpoint, alertDescription, alertKey, normalizeAlertQuery, isFiltered,
  alertFacets, filterAlerts, paginateAlerts, findAlert, alertDetailFields
} = require('./integrations/siem-alerts');
const { isTrustedWebviewAssetUri } = require('./scanner-presentation');

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
    [PROMETHEUS_STATUS.HEALTHY]: 'Healthy',
    [PROMETHEUS_STATUS.DEGRADED]: 'Degraded',
    [PROMETHEUS_STATUS.OFFLINE]: 'Unavailable',
    [PROMETHEUS_STATUS.QUERY_ERROR]: 'Invalid URL',
    [PROMETHEUS_STATUS.AUTH_ERROR]: 'Authentication required',
    [PROMETHEUS_STATUS.TIMEOUT]: 'Timeout',
    [RUNTIME_STATUS.NOT_CONFIGURED]: 'Not configured',
    [RUNTIME_STATUS.ONLINE]: 'Online',
    [RUNTIME_STATUS.DEGRADED]: 'Degraded',
    [RUNTIME_STATUS.OFFLINE]: 'Offline',
    [RUNTIME_STATUS.AUTH_ERROR]: 'Authentication failed',
    [RUNTIME_STATUS.TIMEOUT]: 'Timeout',
    [RUNTIME_STATUS.ERROR]: 'Error'
  })[status] || String(status || 'Unknown');
}

function safeProviderLabel(status, fallback) {
  return status?.configured ? String(status.label || fallback) : '';
}

function actionStateMessage(state) {
  if (!state || !state.message) return '';
  return `<p class="domain-action-state ${escapeHtml(state.tone || 'muted')}" role="status">${escapeHtml(state.message)}</p>`;
}

function metricTile(label, value, tone = '') {
  return `<div class="domain-metric ${escapeHtml(tone)}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function providerLogoUri(provider, assets = {}) {
  const logos = assets?.providerLogoUris && typeof assets.providerLogoUris === 'object'
    ? assets.providerLogoUris
    : {};
  const key = String(provider?.icon || provider?.id || '');
  const uri = logos[key] || logos[provider?.id] || logos[provider?.icon] || '';
  return isTrustedWebviewAssetUri(uri, assets) ? uri : '';
}

function providerLogo(provider, assets = {}, className = 'provider-mark') {
  const uri = providerLogoUri(provider, assets);
  const label = escapeHtml(provider?.label || 'Provider');
  if (!uri) return `<span class="${escapeHtml(className)} provider-mark-fallback" aria-hidden="true">${escapeHtml(String(provider?.label || '?').slice(0, 1).toUpperCase())}</span>`;
  return `<span class="${escapeHtml(className)}"><img class="provider-logo" src="${escapeHtml(uri)}" alt="${label} logo" loading="lazy"></span>`;
}

function domainHeader({ eyebrow, title, provider = '', status = '', subtitle = '', icon = 'shield', meta = '' }) {
  return `<section class="domain-hero">
    <div class="domain-watermark" aria-hidden="true">${compactIcon('shield')}${compactIcon('pulse')}</div>
    <div class="domain-hero-copy">
      <span class="domain-eyebrow">${escapeHtml(eyebrow)}</span>
      <h2>${escapeHtml(title)}</h2>
      ${subtitle ? `<p>${escapeHtml(subtitle)}</p>` : ''}
    </div>
    <div class="domain-hero-status">
      <span class="domain-icon">${compactIcon(icon)}</span>
      ${provider ? `<span>Provider</span><strong>${escapeHtml(provider)}</strong>` : '<span>Provider</span><strong>None</strong>'}
      ${status ? `<em class="${escapeHtml(statusTone(status))}">● ${escapeHtml(statusLabel(status))}</em>` : ''}
      ${meta ? `<small class="domain-hero-meta">${escapeHtml(meta)}</small>` : ''}
    </div>
  </section>`;
}

/**
 * The provider catalogue.
 *
 * Runtime Security is a multi-SIEM domain, so every platform it is built to
 * integrate is listed. Selecting one shows that provider's real connection
 * form. What differs is only what can be *done*: a provider with no adapter is
 * never offered Test or Save, because nothing could honour them.
 */
function runtimeProviderChooser(providers, selectedId, assets = {}) {
  const options = providers.map((provider) => `<label class="provider-option${provider.id === selectedId ? ' selected' : ''}">
      <input type="radio" name="runtime-provider-choice" value="${escapeHtml(provider.id)}"${provider.id === selectedId ? ' checked' : ''}>
      ${providerLogo(provider, assets)}
      <span class="provider-copy"><span class="provider-name">${escapeHtml(provider.label)}</span>
      <span class="provider-note">${escapeHtml(provider.summary || '')}</span></span>
    </label>`).join('');
  return `<div class="provider-catalogue">
      <span class="field-label">SIEM provider</span>
      <p class="field-hint">Choose the platform Security Center reads runtime detections from.</p>
      ${options}
      <input type="hidden" id="runtime-provider" value="${escapeHtml(selectedId)}">
    </div>`;
}

/**
 * One input, from its declared schema. A secret is never given a value.
 *
 * `idPrefix` is what lets two domains render the same schema machinery on two
 * pages without their DOM ids colliding. Nothing else about the renderer knows
 * which domain it is serving.
 */
function runtimeField(field, values = {}, secretsConfigured = {}, idPrefix = 'runtime-') {
  const id = `${idPrefix}${field.id}`;
  const optional = field.required ? '' : '<span class="field-optional">Optional</span>';
  const hint = field.hint ? `<small>${escapeHtml(field.hint)}</small>` : '';
  // A decision, not a value: it renders as a checkbox and submits true/false,
  // so « unticked » is an answer rather than an empty string.
  if (field.type === CONFIG_FIELD_TYPE.BOOLEAN) {
    return `<label class="config-field field-toggle">
      <input id="${escapeHtml(id)}" type="checkbox"${values[field.id] === true ? ' checked' : ''}>
      <span>${escapeHtml(field.label)}</span>
      ${hint}
    </label>`;
  }
  if (field.secret) {
    const stored = secretsConfigured[field.id] === true;
    return `<label class="config-field">${escapeHtml(field.label)}${optional}
      <input id="${escapeHtml(id)}" type="password" autocomplete="off" placeholder="${stored ? 'Leave empty to keep the stored credential' : 'Stored in VS Code SecretStorage'}">
      ${hint}
    </label>`;
  }
  return `<label class="config-field">${escapeHtml(field.label)}${optional}
      <input id="${escapeHtml(id)}" type="${field.type === 'url' ? 'url' : 'text'}" spellcheck="false" autocomplete="off"${field.placeholder ? ` placeholder="${escapeHtml(field.placeholder)}"` : ''} value="${escapeHtml(values[field.id] || '')}">
      ${hint}
    </label>`;
}

function runtimeConfigForm(runtime, open = true, actionState = null, providers = [], assets = {}) {
  const catalogue = providers.length ? providers : SIEM_PROVIDERS;
  const selectedId = catalogue.some((provider) => provider.id === runtime?.provider)
    ? runtime.provider
    : (catalogue[0]?.id || '');
  const provider = catalogue.find((entry) => entry.id === selectedId) || null;
  const fields = provider?.configurationFields || [];
  // Legacy callers pass `baseUrl`/`username`; the schema-driven form reads a
  // values map. Both are accepted so no existing surface has to change.
  const values = runtime?.values || { url: runtime?.baseUrl || '', username: runtime?.username || '' };
  // Only booleans reach the webview: which secrets exist, never their values.
  const secretsConfigured = runtime?.secretsConfigured
    || (runtime?.credentialsConfigured ? { password: true } : {});
  const primary = fieldsInGroup(fields, CONFIG_GROUP.PRIMARY);
  const advanced = fieldsInGroup(fields, CONFIG_GROUP.ADVANCED);
  const anySecretStored = Object.values(secretsConfigured).some(Boolean);
  const connectable = provider ? provider.implemented !== false : true;

  // Two panes of one card, not two cards: choosing a provider on the left and
  // configuring it on the right is a single task, and the page has the width to
  // show both at once instead of stacking a ten-row list above a form.
  return `<section class="domain-card setup-card config-workspace-card"${open ? '' : ' hidden'}>
    <div class="domain-card-head"><div><h3>Connect your SIEM</h3><p>Connect your existing security platform to bring runtime detections, incidents and infrastructure context into Security Center.</p></div></div>
    <div class="config-workspace">
      <div class="config-pane config-pane-catalogue">
        ${runtimeProviderChooser(catalogue, selectedId, assets)}
      </div>
      <div class="config-pane config-pane-form">
        <div class="config-provider-head">
          ${provider ? providerLogo(provider, assets, 'provider-head-mark') : ''}
          <div class="provider-head-copy">
            <span class="field-label">Configuration</span>
            <h4>${provider ? escapeHtml(provider.label) : 'Provider configuration'}</h4>
            <p>${provider ? escapeHtml(provider.summary || `Connection details for ${provider.label}.`) : 'Select a provider to configure it.'}</p>
            <small>${provider ? escapeHtml(`Connection details for ${provider.label}.`) : ''}</small>
          </div>
        </div>
        <div class="config-field-group">
          <span class="config-section-title">Connection</span>
          ${primary.map((field) => runtimeField(field, values, secretsConfigured)).join('')}
        </div>
        ${advanced.length ? `<div class="config-advanced">
          <button type="button" class="config-advanced-toggle" data-action="toggleAdvanced" aria-expanded="false">
            <span>Advanced</span>
            <small>Optional provider fields</small>
          </button>
          <div class="config-advanced-body" hidden>${advanced.map((field) => runtimeField(field, values, secretsConfigured)).join('')}</div>
        </div>` : ''}
        <small>${anySecretStored ? 'Credential configured in SecretStorage.' : 'Credential is never rendered back into this webview.'}</small>
        ${actionStateMessage(actionState)}
        <div class="domain-actions">
          ${connectable
            ? `<button data-action="testRuntimeConfig">Test connection</button>
          <button data-action="saveRuntimeConfig">Save configuration</button>`
            : `<p class="provider-message">Security Center does not integrate ${escapeHtml(provider.label)} yet. Its connection requirements will be published with its adapter — nothing here is configured, tested or stored for it.</p>`}
          <button class="secondary" data-action="cancelConfig">Cancel</button>
        </div>
      </div>
    </div>
  </section>`;
}

function runtimeSetup(runtime, actionState, assets = {}) {
  return `<div class="domain-layout single wide">
    ${runtimeConfigForm(runtime, true, actionState, [], assets)}
  </div>`;
}

function agentRows(runtime, limit = 0) {
  const agents = limit > 0 ? runtime.agents.slice(0, limit) : runtime.agents;
  return agents.map((agent) => `<article class="asset-row">
    <div><strong>${escapeHtml(agent.name || 'unknown-host')}</strong><span>${escapeHtml(agent.os || 'OS unavailable')}</span></div>
    <em class="${escapeHtml(statusTone(agent.status === 'active' ? 'online' : 'degraded'))}">● ${escapeHtml(agent.status || 'unknown')}</em>
    <span>${escapeHtml(agent.ip || 'No IP')}</span>
    <span>Last seen: ${escapeHtml(agent.lastSeen || 'Unavailable')}</span>
  </article>`).join('') || '<div class="empty-state">No monitored assets returned by the SIEM provider.</div>';
}

/**
 * One alert row.
 *
 * `list` lets a filtered or paginated subset be rendered while the detail index
 * still refers to the provider's own ordering, so the quick preview keeps
 * working on any page without a second copy of the detail markup.
 */
function alertRows(runtime, limit = 0, list = null) {
  const alerts = list || (limit > 0 ? runtime.alerts.slice(0, limit) : runtime.alerts);
  return alerts.map((alert) => {
    const index = runtime.alerts.indexOf(alert);
    const key = alertKey(alert, index);
    return `<article class="alert-row ${escapeHtml(String(alert.severity || '').toLowerCase())}" data-alert-index="${index}">
    <span>${escapeHtml(alert.severity || 'UNKNOWN')}</span>
    <div><strong>${escapeHtml(alert.title || 'Runtime security alert')}</strong><small>${escapeHtml(alertEndpoint(alert) || 'Unknown host')} · Rule ${escapeHtml(alert.ruleId || 'Unavailable')}${alert.mitreTechniques?.length ? ` · MITRE ${escapeHtml(alert.mitreTechniques.join(', '))}` : ''}</small></div>
    <time>${escapeHtml(alert.timestamp || 'Timestamp unavailable')}</time>
    <div class="row-actions">
      <button class="secondary icon-action" data-alert-index="${index}" aria-label="Preview runtime alert">${compactIcon('report')}</button>
      <button class="secondary" data-alert-open="${escapeHtml(key)}">Investigate</button>
    </div>
  </article>`;
  }).join('') || '<div class="empty-state">No recent runtime alerts returned by the SIEM provider.</div>';
}

function runtimeAlertDetails(runtime) {
  return runtime.alerts.map((alert, index) => `<section class="alert-detail" data-alert-detail="${index}" hidden>
    <div class="detail-head"><span class="${escapeHtml(String(alert.severity || '').toLowerCase())}">${escapeHtml(alert.severity || 'UNKNOWN')}</span><button class="secondary icon-action" data-close-alert>${compactIcon('compare')}</button></div>
    <h3>${escapeHtml(alert.title || 'Runtime security alert')}</h3>
    <p>${escapeHtml(alertDescription(alert) || 'No normalized summary returned by the provider.')}</p>
    <dl>
      <div><dt>Provider</dt><dd>${escapeHtml(runtime.label || 'SIEM')}</dd></div>
      <div><dt>Host / Agent</dt><dd>${escapeHtml(alertEndpoint(alert) || alert.agentId || 'Unavailable')}</dd></div>
      <div><dt>Rule ID</dt><dd>${escapeHtml(alert.ruleId || 'Unavailable')}</dd></div>
      <div><dt>Category</dt><dd>${escapeHtml(alert.category || 'Unavailable')}</dd></div>
      <div><dt>MITRE techniques</dt><dd>${escapeHtml(alert.mitreTechniques?.length ? alert.mitreTechniques.join(', ') : 'Unavailable')}</dd></div>
      <div><dt>Timestamp</dt><dd>${escapeHtml(alert.timestamp || 'Unavailable')}</dd></div>
      <div><dt>Status</dt><dd>${escapeHtml(alert.status || 'open')}</dd></div>
    </dl>
  </section>`).join('');
}

const VULNERABILITIES_CAPABILITY = 'vulnerabilities';
const ALERTS_CAPABILITY = 'alerts';
const ASSETS_CAPABILITY = 'assets';
const MITRE_CAPABILITY = 'mitre';

const SEVERITY_WEIGHT = Object.freeze({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 });

const OVERVIEW_ALERTS = 5;
const OVERVIEW_ASSETS = 5;

/** How a resolved capability reads: available, degraded, or still to set up. */
function capabilityTone(state) {
  if (state === RUNTIME_CAPABILITY_STATE.READY) return 'ok';
  if (state === RUNTIME_CAPABILITY_STATE.ERROR) return 'bad';
  return 'warn';
}

/**
 * Per-capability health.
 *
 * The point of listing capabilities separately is that they fail separately:
 * the provider API can answer while one capability is degraded, and the rest of
 * the domain must keep working. Capabilities the provider does not offer are
 * not listed at all — a disabled row advertises an intention, it informs no one.
 */
function capabilityHealth(runtime, capabilities) {
  const rows = [`<div class="capability-row"><span>${escapeHtml(runtime.label || 'SIEM')} API</span><em class="${escapeHtml(statusTone(runtime.status))}">${escapeHtml(statusLabel(runtime.status))}</em></div>`];
  for (const tab of CAPABILITY_TABS) {
    if (!capabilityVisible(capabilities, tab.capability)) continue;
    const state = capabilities[tab.capability];
    rows.push(`<div class="capability-row"><span>${escapeHtml(tab.label)}</span><em class="${escapeHtml(capabilityTone(state))}">${escapeHtml(RUNTIME_CAPABILITY_LABELS[state] || state)}</em></div>`);
  }
  return `<div class="capability-list">${rows.join('')}</div>`;
}

/** The local navigation. Its entries are the resolved capabilities, nothing else. */
function runtimeTabsNav(tabs, activeTab) {
  return `<nav class="tabs" aria-label="Runtime Security sections">${tabs.map((tab) => `<button data-tab="${escapeHtml(tab.id)}"${tab.id === activeTab ? ' aria-current="true"' : ''}>${escapeHtml(tab.label)}</button>`).join('')}</nav>`;
}

/**
 * Why a section shows nothing. Never a zero: a provider that could not be asked
 * has not answered « none », it has not answered at all.
 */
function capabilityNotice(runtime, state, subject) {
  if (state === RUNTIME_CAPABILITY_STATE.ERROR) {
    return `<p class="provider-message bad">${escapeHtml(runtime.message || `${subject} could not be read from the provider. The stored configuration is preserved.`)}</p>`;
  }
  return `<p class="provider-message">${escapeHtml(`${subject} require additional provider setup.`)}</p>`;
}

/** MITRE techniques carried by the normalized alerts — nothing inferred. */
function mitreTechniques(runtime) {
  const observed = new Map();
  for (const alert of runtime.alerts || []) {
    for (const raw of alert.mitreTechniques || []) {
      const technique = String(raw || '').trim();
      if (!technique) continue;
      const entry = observed.get(technique) || { technique, count: 0, hosts: new Set(), rules: new Set(), severity: '' };
      entry.count += 1;
      if (alert.host) entry.hosts.add(String(alert.host));
      if (alert.ruleId) entry.rules.add(String(alert.ruleId));
      const severity = String(alert.severity || '').toUpperCase();
      if (!entry.severity || (SEVERITY_WEIGHT[severity] || 0) > (SEVERITY_WEIGHT[entry.severity] || 0)) entry.severity = severity;
      observed.set(technique, entry);
    }
  }
  return [...observed.values()].sort((left, right) => right.count - left.count);
}

function runtimeLastSync(runtime) {
  return runtime.lastChecked ? displaySecondsAgo((Date.now() - Date.parse(runtime.lastChecked)) / 1000) : 'Unavailable';
}

/** The connection card: identity, state, per-capability health, actions. */
function runtimeConnection(runtime, actionState, openConfig, capabilities, assets = {}) {
  const configuredButUnavailable = runtime.configured && runtime.status !== RUNTIME_STATUS.ONLINE && runtime.status !== RUNTIME_STATUS.DEGRADED;
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Connection</h3><p>Provider-backed runtime-security state.</p></div><span class="state-chip ${statusTone(runtime.status)}">● ${escapeHtml(statusLabel(runtime.status))}</span></div>
      <div class="identity-grid">
        ${metricTile('Provider', runtime.label || 'SIEM')}
        ${metricTile('Connection', statusLabel(runtime.status), statusTone(runtime.status))}
        ${metricTile('Last sync', runtimeLastSync(runtime))}
        ${metricTile('Credentials', runtime.credentialsConfigured ? 'Configured' : 'Not configured')}
      </div>
      ${capabilityHealth(runtime, capabilities)}
      ${relaxedTlsWarning(runtime, 'Provider API')}
      ${configuredButUnavailable ? `<p class="provider-message bad">${escapeHtml(runtime.message || 'Provider is unavailable. Existing configuration is preserved.')}</p>` : ''}
      ${actionStateMessage(actionState)}
      <div class="domain-actions">
        <button data-action="refreshRuntime">Refresh</button>
        <button class="secondary" data-action="openIntegrations">Open integration settings</button>
        ${runtime.configured ? '<button class="secondary" data-action="disconnectRuntime">Disconnect provider</button>' : ''}
      </div>
      ${runtimeConfigForm(runtime, openConfig, actionState, [], assets)}
    </section>`;
}

/**
 * Overview: what the provider already told us, and where to go next.
 *
 * Only resolved capabilities get a card, and nothing here asks the provider for
 * anything the adapter did not already return.
 */
function runtimeOverview(runtime, capabilities) {
  const alertsState = capabilities[ALERTS_CAPABILITY];
  const assetsState = capabilities[ASSETS_CAPABILITY];
  const mitreState = capabilities[MITRE_CAPABILITY];
  const techniques = mitreTechniques(runtime);
  const alertsCard = !capabilityVisible(capabilities, ALERTS_CAPABILITY) ? '' : `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Alert summary</h3><p>Normalized severities from the SIEM provider.</p></div></div>
      ${alertsState === RUNTIME_CAPABILITY_STATE.READY ? `<div class="summary-grid">
        ${metricTile('Critical', String(runtime.alertSummary.critical), 'critical')}
        ${metricTile('High', String(runtime.alertSummary.high), 'high')}
        ${metricTile('Medium', String(runtime.alertSummary.medium), 'medium')}
        ${metricTile('Low', String(runtime.alertSummary.low || 0), 'low')}
      </div>` : capabilityNotice(runtime, alertsState, 'Alert counts')}
    </section>`;
  const assetsCard = !capabilityVisible(capabilities, ASSETS_CAPABILITY) ? '' : `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Monitored assets / agents</h3><p>Runtime hosts known by the configured provider.</p></div>${runtime.agents.length > OVERVIEW_ASSETS ? '<button class="secondary" data-tab="assets">View all →</button>' : ''}</div>
      ${assetsState === RUNTIME_CAPABILITY_STATE.READY ? `<div class="summary-grid">
        ${metricTile('Active', String(runtime.agentSummary.active), 'ok')}
        ${metricTile('Disconnected', String(runtime.agentSummary.disconnected || 0), 'warn')}
        ${metricTile('Total', String(runtime.agentSummary.total))}
      </div>
      <div class="asset-list">${agentRows(runtime, OVERVIEW_ASSETS)}</div>` : capabilityNotice(runtime, assetsState, 'Monitored assets')}
    </section>`;
  const mitreCard = !capabilityVisible(capabilities, MITRE_CAPABILITY) ? '' : `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>MITRE ATT&amp;CK</h3><p>Techniques carried by the alert rules the provider returned.</p></div>${techniques.length ? '<button class="secondary" data-tab="mitre">View all →</button>' : ''}</div>
      ${mitreState === RUNTIME_CAPABILITY_STATE.READY ? `<div class="summary-grid">
        ${metricTile('Observed techniques', String(techniques.length))}
        ${metricTile('Alerts carrying a technique', String((runtime.alerts || []).filter((alert) => alert.mitreTechniques?.length).length))}
      </div>
      ${techniques.length ? `<div class="mitre-list">${techniques.slice(0, 3).map(mitreRow).join('')}</div>` : '<div class="empty-state">No MITRE technique was attached to the alerts returned by the provider.</div>'}` : capabilityNotice(runtime, mitreState, 'MITRE techniques')}
    </section>`;
  const recentCard = !capabilityVisible(capabilities, ALERTS_CAPABILITY) ? '' : `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Recent alerts</h3><p>Click an alert to inspect the normalized details.</p></div>${runtime.alerts.length > OVERVIEW_ALERTS ? '<button class="secondary" data-tab="alerts">View all →</button>' : ''}</div>
      <div class="alert-list">${alertRows(runtime, OVERVIEW_ALERTS)}</div>${runtimeAlertDetails(runtime)}
    </section>`;
  return `${alertsCard}${assetsCard}${mitreCard}${recentCard}${capabilitySetupCard(runtime, capabilities)}`;
}

/** One filter control, rendered only when the provider supplied values for it. */
function alertFilter(id, label, options, selected) {
  if (!options.length) return '';
  return `<label class="filter-field">${escapeHtml(label)}
      <select id="alerts-${escapeHtml(id)}" data-alerts-filter>
        <option value="">All</option>
        ${options.map((option) => `<option value="${escapeHtml(option.value)}"${option.value === selected ? ' selected' : ''}>${escapeHtml(`${option.value} (${option.count})`)}</option>`).join('')}
      </select>
    </label>`;
}

/**
 * The alert toolbar.
 *
 * Every option comes from the alerts in hand, so no filter can promise a result
 * the provider never returned.
 */
function alertToolbar(runtime, query) {
  const facets = alertFacets(runtime.alerts || []);
  return `<div class="alerts-toolbar">
      <label class="filter-field filter-search">Search
        <input id="alerts-search" type="search" spellcheck="false" autocomplete="off" placeholder="Title, rule, asset, user or technique" value="${escapeHtml(query.search)}" data-alerts-search>
      </label>
      ${alertFilter('severity', 'Severity', facets.severities, query.severity)}
      ${alertFilter('agent', 'Asset / agent', facets.agents, query.agent)}
      ${alertFilter('rule', 'Rule', facets.rules, query.rule)}
      <button class="secondary" data-alerts-clear${isFiltered(query) ? '' : ' disabled'}>Clear filters</button>
    </div>`;
}

/** Bounded loading: which slice of the filtered set is on screen, and how to move. */
function alertPager(page) {
  if (page.pageCount <= 1) return '';
  return `<div class="pager">
      <button class="secondary" data-alerts-page="${page.page - 1}"${page.page <= 1 ? ' disabled' : ''}>Previous</button>
      <span>Page ${escapeHtml(String(page.page))} of ${escapeHtml(String(page.pageCount))}</span>
      <button class="secondary" data-alerts-page="${page.page + 1}"${page.page >= page.pageCount ? ' disabled' : ''}>Next</button>
    </div>`;
}

/**
 * The full investigation view.
 *
 * Same shape as the Security Center finding details: a facts grid, then the
 * narrative blocks. Every fact is one the provider actually sent — a field it
 * omitted is absent rather than filled with a placeholder, because « Wazuh sent
 * no user » and « the user is unknown » are not the same statement.
 */
function runtimeAlertInvestigation(runtime, alert) {
  const fields = alertDetailFields(alert, runtime);
  const description = alertDescription(alert);
  return `<section class="domain-card span-2 investigation">
      <div class="domain-card-head">
        <div><span class="state-chip ${escapeHtml(String(alert.severity || '').toLowerCase())}">${escapeHtml(alert.severity || 'UNKNOWN')}</span><h3>${escapeHtml(alert.title || 'Runtime security alert')}</h3><p>Alert investigation · ${escapeHtml(runtime.label || 'SIEM')}</p></div>
        <button class="secondary" data-alert-open="">← Back to alerts</button>
      </div>
      <div class="detail-grid detail-block">
        ${fields.map((field) => `<div class="detail-label">${escapeHtml(field.label)}</div><div>${escapeHtml(field.value)}</div>`).join('')}
      </div>
      <h4>Description</h4>
      <div class="detail-block">${description ? escapeHtml(description) : '<span class="muted">The provider returned no description for this alert.</span>'}</div>
      <h4>Provider metadata</h4>
      <div class="detail-block">${alert.rawReference
        ? escapeHtml(`Reference ${alert.rawReference} in ${runtime.label || 'the provider'}.`)
        : '<span class="muted">The provider returned no additional metadata for this alert.</span>'}
      </div>
    </section>`;
}

/**
 * Alerts: search, filters, bounded pages, and two levels of detail.
 *
 * The quick preview stays what it was — a light side sheet reachable from any
 * row. The investigation view is a destination, so it replaces the list rather
 * than floating over it.
 */
function runtimeAlerts(runtime, capabilities, rawQuery = {}) {
  const state = capabilities[ALERTS_CAPABILITY];
  const query = normalizeAlertQuery(rawQuery);
  const opened = findAlert(runtime.alerts || [], query.alert);
  if (opened) return runtimeAlertInvestigation(runtime, opened);

  const filtered = filterAlerts(runtime.alerts || [], query);
  const page = paginateAlerts(filtered, query);
  const emptyList = (runtime.alerts || []).length === 0
    ? '<div class="empty-state">No recent runtime alerts returned by the SIEM provider.</div>'
    : '<div class="empty-state">No alert matches these filters.</div>';
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Alerts</h3><p>Normalized detections returned by the provider. Preview an alert inline, or open the full investigation.</p></div></div>
      ${state === RUNTIME_CAPABILITY_STATE.READY ? `<div class="summary-grid">
        ${metricTile('Critical', String(runtime.alertSummary.critical), 'critical')}
        ${metricTile('High', String(runtime.alertSummary.high), 'high')}
        ${metricTile('Medium', String(runtime.alertSummary.medium), 'medium')}
        ${metricTile('Low', String(runtime.alertSummary.low || 0), 'low')}
      </div>` : capabilityNotice(runtime, state, 'Alert counts')}
      ${alertToolbar(runtime, query)}
      <p class="alerts-meta">${escapeHtml(page.total
        ? `Showing ${page.from}–${page.to} of ${page.total} alert${page.total > 1 ? 's' : ''} returned by ${runtime.label || 'the provider'} at the last refresh.`
        : 'No alert to show for the current filters.')}</p>
      <div class="alert-list">${page.items.length ? alertRows(runtime, 0, page.items) : emptyList}</div>
      ${alertPager(page)}
      ${runtimeAlertDetails(runtime)}
    </section>`;
}

/** Assets. Only fields the adapter already normalizes — nothing invented. */
function runtimeAssets(runtime, capabilities) {
  const state = capabilities[ASSETS_CAPABILITY];
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Assets</h3><p>Runtime hosts known by the configured provider.</p></div></div>
      ${state === RUNTIME_CAPABILITY_STATE.READY ? `<div class="summary-grid">
        ${metricTile('Active', String(runtime.agentSummary.active), 'ok')}
        ${metricTile('Disconnected', String(runtime.agentSummary.disconnected || 0), 'warn')}
        ${metricTile('Never connected', String(runtime.agentSummary.neverConnected || 0))}
        ${metricTile('Total', String(runtime.agentSummary.total))}
      </div>` : capabilityNotice(runtime, state, 'Monitored assets')}
      <div class="asset-list">${agentRows(runtime)}</div>
    </section>`;
}

function mitreRow(entry) {
  return `<article class="mitre-row">
    <span class="${escapeHtml(String(entry.severity || '').toLowerCase())}">${escapeHtml(entry.technique)}</span>
    <div><strong>${escapeHtml(`${entry.count} alert${entry.count > 1 ? 's' : ''}`)}</strong><small>${escapeHtml([...entry.hosts].join(', ') || 'Host unavailable')}${entry.rules.size ? ` · Rule ${escapeHtml([...entry.rules].join(', '))}` : ''}</small></div>
  </article>`;
}

/** MITRE. Techniques read from the alert rules themselves — never inferred. */
function runtimeMitre(runtime, capabilities) {
  const state = capabilities[MITRE_CAPABILITY];
  const techniques = mitreTechniques(runtime);
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>MITRE ATT&amp;CK</h3><p>Techniques attached to the alert rules the provider returned. Nothing is inferred from titles, CVEs or package names.</p></div></div>
      ${state === RUNTIME_CAPABILITY_STATE.READY
        ? `<div class="summary-grid">${metricTile('Observed techniques', String(techniques.length))}</div>
      ${techniques.length ? `<div class="mitre-list">${techniques.map(mitreRow).join('')}</div>` : '<div class="empty-state">No MITRE technique was attached to the alerts returned by the provider.</div>'}`
        : capabilityNotice(runtime, state, 'MITRE techniques')}
    </section>`;
}

/**
 * A capability the provider offers but that has never been proven usable.
 *
 * It gets an invitation, not a tab: the difference between « set this up » and
 * « this works » is the whole point of the capability model.
 */
function capabilitySetupCard(runtime, capabilities) {
  const pending = CAPABILITY_TABS.filter((tab) => (
    capabilityOffered(capabilities, tab.capability) && !capabilityVisible(capabilities, tab.capability)
  ));
  if (!pending.length) return '';
  const names = pending.map((tab) => tab.label).join(', ');
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Additional data sources</h3><p>${escapeHtml(`${names} require access to this provider's search backend. Configure it to enable ${pending.length > 1 ? 'these sections' : 'this section'}. Everything the provider's management API serves keeps working without it.`)}</p></div></div>
      <div class="domain-actions"><button class="secondary" data-action="showConfig">Configure provider</button></div>
    </section>`;
}

/**
 * A visible, permanent statement that ONE connection verifies less than usual.
 *
 * Each connection states its own relaxation and gets its own sentence. Merging
 * them would produce a warning that is true of something and silent about
 * which — and a user who cannot tell which endpoint is unverified has not
 * really been warned.
 */
function relaxedTlsWarning(source, scope) {
  if (!source || source.relaxedTls !== true) return '';
  return `<p class="provider-message warn" role="status">⚠ ${escapeHtml(`${scope} TLS verification relaxed`)} — ${escapeHtml(`Self-signed certificate acceptance is enabled for the ${scope.toLowerCase()} connection only.`)}</p>`;
}

/** One filter control over runtime facets. No option is written by this file. */
function facetFilter(id, label, options, selected) {
  if (!options || !options.length) return '';
  return `<label class="filter-field">${escapeHtml(label)}
      <select id="vulns-${escapeHtml(id)}" data-vulns-filter>
        <option value="">All</option>
        ${options.map((option) => `<option value="${escapeHtml(option.value)}"${option.value === selected ? ' selected' : ''}>${escapeHtml(option.count === undefined ? option.value : `${option.value} (${option.count})`)}</option>`).join('')}
      </select>
    </label>`;
}

function vulnerabilityToolbar(data, query) {
  const summary = data.summary || {};
  return `<div class="alerts-toolbar">
      <label class="filter-field filter-search">Search
        <input id="vulns-search" type="search" spellcheck="false" autocomplete="off" placeholder="CVE, package or description" value="${escapeHtml(query.search)}" data-vulns-search>
      </label>
      ${facetFilter('severity', 'Severity', summary.severity, query.severity)}
      ${facetFilter('asset', 'Asset / agent', summary.assets, query.asset)}
      <label class="filter-field">CVE
        <input id="vulns-cve" type="search" spellcheck="false" autocomplete="off" value="${escapeHtml(query.cve)}" data-vulns-search>
      </label>
      <label class="filter-field">Package
        <input id="vulns-package" type="search" spellcheck="false" autocomplete="off" value="${escapeHtml(query.package)}" data-vulns-search>
      </label>
      <button class="secondary" data-vulns-clear${isVulnerabilityFiltered(query) ? '' : ' disabled'}>Clear filters</button>
    </div>`;
}

/**
 * The summary cards.
 *
 * A distribution the provider could not compute is absent, not four zeros: an
 * unanswered question and an answer of « none » are different facts.
 */
function vulnerabilitySummary(data) {
  const summary = data.summary || {};
  const counts = severityCounts(summary.severity);
  const tiles = [];
  if (counts) {
    tiles.push(metricTile('Critical', String(counts.CRITICAL), 'critical'));
    tiles.push(metricTile('High', String(counts.HIGH), 'high'));
    tiles.push(metricTile('Medium', String(counts.MEDIUM), 'medium'));
    tiles.push(metricTile('Low', String(counts.LOW), 'low'));
  }
  if (Number.isFinite(summary.total)) tiles.push(metricTile('Total records', String(summary.total)));
  if (Number.isFinite(summary.affectedAssets)) tiles.push(metricTile('Affected assets', String(summary.affectedAssets)));
  return tiles.length ? `<div class="summary-grid">${tiles.join('')}</div>` : '';
}

function vulnerabilityRows(items) {
  return items.map((record, index) => {
    const key = vulnerabilityKey(record, index);
    const facts = [record.package, record.packageVersion, record.asset]
      .filter(Boolean).map((value) => escapeHtml(value)).join(' · ');
    return `<article class="alert-row ${escapeHtml(String(record.uiSeverity || '').toLowerCase())}">
    <span>${escapeHtml(record.severity || record.uiSeverity || '')}</span>
    <div><strong>${escapeHtml(record.cve || record.title || 'Vulnerability')}</strong><small>${facts}</small></div>
    <time>${escapeHtml(Number.isFinite(record.cvssScore) ? `CVSS ${record.cvssScore}` : '')}</time>
    <div class="row-actions"><button class="secondary" data-vuln-open="${escapeHtml(key)}">Investigate</button></div>
  </article>`;
  }).join('');
}

/** Server-side paging: the page numbers come from the provider's own total. */
function vulnerabilityPager(data, query) {
  const total = Number(data.total);
  if (!Number.isFinite(total) || total <= query.pageSize) return '';
  const pageCount = Math.max(1, Math.ceil(total / query.pageSize));
  const page = Math.min(query.page, pageCount);
  return `<div class="pager">
      <button class="secondary" data-vulns-page="${page - 1}"${page <= 1 ? ' disabled' : ''}>Previous</button>
      <span>Page ${escapeHtml(String(page))} of ${escapeHtml(String(pageCount))}</span>
      <button class="secondary" data-vulns-page="${page + 1}"${page >= pageCount ? ' disabled' : ''}>Next</button>
    </div>`;
}

/** The investigation view: only sections the record could actually fill. */
function vulnerabilityInvestigation(runtime, record) {
  const sections = vulnerabilityDetailSections(record);
  return `<section class="domain-card span-2 investigation">
      <div class="domain-card-head">
        <div>${record.severity ? `<span class="state-chip ${escapeHtml(String(record.uiSeverity || '').toLowerCase())}">${escapeHtml(record.severity)}</span>` : ''}<h3>${escapeHtml(record.cve || record.title || 'Vulnerability')}</h3><p>Vulnerability investigation · ${escapeHtml(runtime.label || 'Provider')}</p></div>
        <button class="secondary" data-vuln-open="">← Back to vulnerabilities</button>
      </div>
      ${sections.map((section) => `<h4>${escapeHtml(section.title)}</h4>
      <div class="detail-grid detail-block">${section.fields.map((field) => `<div class="detail-label">${escapeHtml(field.label)}</div><div>${escapeHtml(field.value)}</div>`).join('')}</div>`).join('')}
      ${record.description ? `<h4>Description</h4><div class="detail-block">${escapeHtml(record.description)}</div>` : ''}
      ${record.references?.length ? `<h4>References</h4><div class="detail-block"><ul class="plain-list">${record.references.map((reference) => `<li>${escapeHtml(reference)}</li>`).join('')}</ul></div>` : ''}
    </section>`;
}

/**
 * Vulnerabilities.
 *
 * Six outcomes, deliberately distinguishable, because each has a different
 * cause and a different fix: never configured, probe failed, query failed,
 * filtered to nothing, genuinely empty, and populated. Only one of them is
 * allowed to look like « no vulnerabilities ».
 */
function runtimeVulnerabilities(runtime, capabilities, rawQuery = {}, data = null) {
  const state = capabilities[VULNERABILITIES_CAPABILITY];
  const query = normalizeVulnerabilityQuery(rawQuery);
  const payload = data || {};

  if (state !== RUNTIME_CAPABILITY_STATE.READY || payload.ok === false) {
    return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Vulnerability detection</h3><p>Provider-backed vulnerability state.</p></div><span class="state-chip bad">● ${escapeHtml(RUNTIME_CAPABILITY_LABELS[state] || 'Error')}</span></div>
      <p class="provider-message bad">${escapeHtml(payload.message || 'Vulnerability data could not be read from the provider.')}</p>
      ${relaxedTlsWarning(payload, 'Vulnerability data source')}
      <div class="domain-actions"><button class="secondary" data-action="showConfig">Review provider configuration</button></div>
    </section>`;
  }

  const items = Array.isArray(payload.items) ? payload.items : [];
  const opened = query.vulnerability
    ? items.find((record, index) => vulnerabilityKey(record, index) === query.vulnerability)
    : null;
  if (opened) return vulnerabilityInvestigation(runtime, opened);

  const emptyMessage = isVulnerabilityFiltered(query)
    ? 'No vulnerability matches these filters.'
    : `No active vulnerabilities were returned by ${runtime.label || 'the provider'}.`;
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>Vulnerabilities</h3><p>Deployment-wide vulnerability state, read from the provider.</p></div></div>
      ${relaxedTlsWarning(payload, 'Vulnerability data source')}
      ${vulnerabilitySummary(payload)}
      ${vulnerabilityToolbar(payload, query)}
      <div class="alert-list">${items.length ? vulnerabilityRows(items) : `<div class="empty-state">${escapeHtml(emptyMessage)}</div>`}</div>
      ${vulnerabilityPager(payload, query)}
    </section>`;
}

/**
 * The operational shell: connection, local navigation, active section.
 *
 * The panel is chosen by tab id and the tab list comes from resolved
 * capabilities — so a capability that becomes available brings its tab with it,
 * and one that fails takes down only its own section.
 */
function runtimeData(runtime, actionState, openConfig = false, navigation = null, alertsQuery = {}, vulnerabilities = null, vulnerabilitiesQuery = {}, assets = {}) {
  const nav = navigation || runtimeNavigation(siemProvider(runtime.provider), runtime, '');
  const body = nav.tab === ALERTS_CAPABILITY ? runtimeAlerts(runtime, nav.capabilities, alertsQuery)
    : nav.tab === ASSETS_CAPABILITY ? runtimeAssets(runtime, nav.capabilities)
      : nav.tab === MITRE_CAPABILITY ? runtimeMitre(runtime, nav.capabilities)
        : nav.tab === VULNERABILITIES_CAPABILITY ? runtimeVulnerabilities(runtime, nav.capabilities, vulnerabilitiesQuery, vulnerabilities)
          : runtimeOverview(runtime, nav.capabilities);
  return `<div class="domain-layout">
    ${runtimeConnection(runtime, actionState, openConfig, nav.capabilities, assets)}
    <div class="span-2">${runtimeTabsNav(nav.tabs, nav.tab)}</div>
    ${body}
  </div>`;
}

/**
 * The observability catalogue. Same contract as the SIEM chooser: only adapters
 * that exist are selectable, planned ones are listed and inert. A one-entry
 * dropdown was what made an entire domain read as a single tool.
 */
function observabilityProviderChooser(providers, selectedId, assets = {}) {
  const options = providers.map((provider) => `<label class="provider-option${provider.id === selectedId ? ' selected' : ''}">
      <input type="radio" name="observability-provider-choice" value="${escapeHtml(provider.id)}"${provider.id === selectedId ? ' checked' : ''}>
      ${providerLogo(provider, assets)}
      <span class="provider-copy"><span class="provider-name">${escapeHtml(provider.label)}</span>
      <span class="provider-note">${escapeHtml(provider.summary || '')}</span></span>
    </label>`).join('');
  return `<div class="provider-catalogue">
      <span class="field-label">Observability provider</span>
      <p class="field-hint">Choose the metrics platform Security Center reads infrastructure context from.</p>
      ${options}
      <input type="hidden" id="observability-provider" value="${escapeHtml(selectedId)}">
    </div>`;
}

function observabilityConfigForm(prometheus, open = true, actionState = null, providers = [], assets = {}) {
  const catalogue = providers.length ? providers : OBSERVABILITY_PROVIDERS;
  const selectedId = catalogue.some((provider) => provider.id === prometheus?.provider)
    ? prometheus.provider
    : (catalogue.find((provider) => provider.implemented)?.id || catalogue[0]?.id || '');
  const provider = catalogue.find((entry) => entry.id === selectedId) || null;
  const fields = provider?.configurationFields || [];
  // Legacy callers pass `baseUrl`; the schema-driven form reads a values map.
  // Both are accepted so no existing surface has to change — but `{}` is truthy,
  // so `values || fallback` silently rendered an EMPTY endpoint for any caller
  // holding a `baseUrl` and an empty map. An empty input is then saved as an
  // empty value, and the form rejects its own field as missing. The two sources
  // are merged instead, the explicit map winning field by field.
  const legacyValues = prometheus?.baseUrl ? { url: prometheus.baseUrl } : {};
  const values = { ...legacyValues, ...(prometheus?.values || {}) };
  const secretsConfigured = prometheus?.secretsConfigured
    || (prometheus?.credentialsConfigured ? { bearerToken: true } : {});
  const primary = fieldsInGroup(fields, CONFIG_GROUP.PRIMARY);
  const advanced = fieldsInGroup(fields, CONFIG_GROUP.ADVANCED);
  const anySecretStored = Object.values(secretsConfigured).some(Boolean);
  const connectable = provider ? provider.implemented !== false : false;

  return `<section class="domain-card setup-card config-workspace-card"${open ? '' : ' hidden'}>
    <div class="domain-card-head"><div><h3>Connect observability</h3><p>Connect an existing metrics backend to display host health inside Security Center.</p></div></div>
    <div class="config-workspace">
      <div class="config-pane config-pane-catalogue">
        ${observabilityProviderChooser(catalogue, selectedId, assets)}
      </div>
      <div class="config-pane config-pane-form">
        <div class="config-provider-head">
          ${provider ? providerLogo(provider, assets, 'provider-head-mark') : ''}
          <div class="provider-head-copy">
            <span class="field-label">Configuration</span>
            <h4>${provider ? escapeHtml(provider.label) : 'Provider configuration'}</h4>
            <p>${provider ? escapeHtml(provider.summary || `Connection details for ${provider.label}.`) : 'Select a provider to configure it.'}</p>
            <small>${provider ? escapeHtml(`Connection details for ${provider.label}.`) : ''}</small>
          </div>
        </div>
        ${primary.map((field) => runtimeField(field, values, secretsConfigured, 'observability-')).join('')}
        ${advanced.length ? `<div class="config-advanced">
          <button type="button" class="config-advanced-toggle" data-action="toggleAdvanced" aria-expanded="false">Advanced</button>
          <div class="config-advanced-body" hidden>${advanced.map((field) => runtimeField(field, values, secretsConfigured, 'observability-')).join('')}</div>
        </div>` : ''}
        <small>${anySecretStored ? 'Credential configured in SecretStorage.' : 'Security Center reads the metrics provider API directly. Unavailable metrics stay unavailable, never zero.'}</small>
        ${actionStateMessage(actionState)}
        <div class="domain-actions">
          ${connectable
            ? `<button data-action="testInfrastructureConfig">Test connection</button>
          <button data-action="saveInfrastructureConfig">Save configuration</button>`
            : `<p class="provider-message">Security Center does not integrate ${escapeHtml(provider?.label || 'this backend')} yet. Its connection requirements will be published with its adapter — nothing here is configured, tested or stored for it.</p>`}
          <button class="secondary" data-action="cancelConfig">Cancel</button>
        </div>
      </div>
    </div>
  </section>`;
}

function infrastructureSetup(prometheus, actionState, assets = {}) {
  return `<div class="domain-layout single wide">${observabilityConfigForm(prometheus, true, actionState, [], assets)}</div>`;
}

/**
 * One inventory entity, read from the contract it is actually delivered in.
 *
 * Adapters answer the normalized entity — `{ id, name, status, endpoint,
 * lastSeen }`. The historical `targetsFrom()` helper answers the same facts
 * under the older names `{ instance, health, lastScrape }`. This row read only
 * the older ones, so every adapter-supplied entity arrived with its identifier,
 * its health and its scrape time under keys nobody looked at, and each row drew
 * « UNKNOWN / Instance unavailable / Last scrape: Unavailable » while the
 * inventory summary — built from the very same payload — read `2/2 UP`.
 *
 * Both shapes are accepted, the contract first. Nothing is invented: a field
 * absent from both stays absent, and an unreadable status stays unknown rather
 * than becoming healthy.
 */
function inventoryEntity(entity = {}) {
  const identifier = String(entity.id || entity.instance || '').trim();
  const status = String(entity.status || entity.health || '').trim();
  const lastSeen = entity.lastSeen || entity.lastScrape || '';
  return {
    name: String(entity.name || '').trim(),
    identifier,
    endpoint: String(entity.endpoint || '').trim(),
    status,
    // « Up » and « available » are the two words this domain's adapters use for
    // a reachable entity. Anything else — including nothing — is not healthy.
    healthy: ['up', 'available'].includes(status.toLowerCase()),
    lastSeen
  };
}

function targetRows(model) {
  const items = Array.isArray(model.targets?.items) && model.targets.items.length
    ? model.targets.items
    : (Array.isArray(model.entities) ? model.entities : []);
  return items.map(inventoryEntity).map((entity) => `<article class="asset-row">
    <div><strong>${escapeHtml(entity.name || 'Monitored target')}</strong><span>${escapeHtml(entity.endpoint)}</span></div>
    <em class="${entity.healthy ? 'ok' : 'bad'}">● ${escapeHtml((entity.status || 'unknown').toUpperCase())}</em>
    <span>${escapeHtml(entity.identifier || 'Instance unavailable')}</span>
    <span>Last scrape: ${escapeHtml(entity.lastSeen ? displaySecondsAgo((Date.now() - Date.parse(entity.lastSeen)) / 1000) : 'Unavailable')}</span>
  </article>`).join('') || '<div class="empty-state">No targets returned by the observability provider.</div>';
}

/** What the host card is describing, without ever naming a host it did not read. */
function hostHealthSubtitle(prometheus) {
  if (prometheus.selectedHost) return prometheus.selectedHost;
  if (prometheus.hostSelectionRequired) return 'Select a host to read its metrics';
  // The provider may monitor plenty and expose host metrics for none of it.
  // Saying « no host reported » there would contradict the inventory shown
  // just above; the honest statement is about the metrics, not the inventory.
  if ((prometheus.entities || []).length) return 'No monitored entity exposes host metrics';
  return 'No monitored host reported by the provider';
}

/**
 * The host selector.
 *
 * It exists only when the provider reported more than one host — the choice is
 * the user's, and with a single host there is nothing to choose.
 */
function hostSelector(prometheus) {
  const hosts = Array.isArray(prometheus.hosts) ? prometheus.hosts : [];
  if (hosts.length < 2) return '';
  return `<label class="filter-field">Host
      <select id="observability-host" data-observability-host>
        <option value=""${prometheus.selectedHost ? '' : ' selected'}>Select a host…</option>
        ${hosts.map((host) => `<option value="${escapeHtml(host)}"${host === prometheus.selectedHost ? ' selected' : ''}>${escapeHtml(host)}</option>`).join('')}
      </select>
    </label>`;
}

/** Human wording for a capability, from the contract's vocabulary alone. */
const CAPABILITY_LABELS = Object.freeze({
  hostInventory: 'Host inventory', cpu: 'CPU', memory: 'Memory', disk: 'Disk', load: 'Load'
});

function capabilityLabel(capability) {
  return CAPABILITY_LABELS[capability] || capability;
}

/**
 * One section, drawn by KIND.
 *
 * The renderer implements kinds; adapters compose dashboards out of them. That
 * is what keeps provider names out of this file: a backend that shows hosts,
 * services and problems composes three sections from the same closed set, and
 * nothing here has to learn its name.
 */
function infrastructureSection(section, model, resolved) {
  const capabilities = Array.isArray(section.capability) ? section.capability : [section.capability];
  if (section.kind === 'entity-inventory') {
    return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>${escapeHtml(section.title || 'Inventory')}</h3><p>Entities reported by the configured provider.</p></div>${hostSelector(model)}</div>
      ${model.selectionRequired ? '<p class="provider-message">Several monitored hosts were returned. Choose one to read its metrics — Security Center will not pick one for you.</p>' : ''}
      <div class="asset-list">${targetRows(model)}</div>
    </section>`;
  }
  if (section.kind === 'metric-tiles') {
    const tiles = capabilities.map((capability) => {
      const metric = model.metrics?.[capability] || model.metrics?.[`${capability}1`];
      return metricTile(capabilityLabel(capability), metric?.available ? metric.display : 'Unavailable');
    }).join('');
    return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>${escapeHtml(section.title || 'Metrics')}</h3><p>${escapeHtml(hostHealthSubtitle(model))}</p></div></div>
      <div class="summary-grid">${tiles}</div>
    </section>`;
  }
  // status-list
  return `<section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>${escapeHtml(section.title || 'Status')}</h3></div></div>
      <div class="capability-list">${capabilities.map((capability) => `<div class="capability-row"><span>${escapeHtml(capabilityLabel(capability))}</span><em class="${escapeHtml(resolved[capability] === 'ready' ? 'ok' : resolved[capability] === 'error' ? 'bad' : 'warn')}">${escapeHtml(resolved[capability] || 'unknown')}</em></div>`).join('')}</div>
    </section>`;
}

/** Per-capability health, so one failing query never reads as a dead provider. */
function observabilityCapabilityHealth(model, resolved) {
  const rows = [`<div class="capability-row"><span>${escapeHtml(model.label || 'Provider')}</span><em class="${escapeHtml(statusTone(model.status))}">${escapeHtml(statusLabel(model.status))}</em></div>`];
  for (const [capability, state] of Object.entries(resolved)) {
    if (state === OBSERVABILITY_STATE.UNAVAILABLE && !model.configured) continue;
    const tone = state === OBSERVABILITY_STATE.READY ? 'ok' : state === OBSERVABILITY_STATE.ERROR ? 'bad' : 'warn';
    const label = state === OBSERVABILITY_STATE.READY ? 'Available'
      : state === OBSERVABILITY_STATE.ERROR ? 'Error'
        : state === OBSERVABILITY_STATE.UNAVAILABLE ? 'Not exported' : 'Setup required';
    rows.push(`<div class="capability-row"><span>${escapeHtml(capabilityLabel(capability))}</span><em class="${tone}">${escapeHtml(label)}</em></div>`);
  }
  return `<div class="capability-list">${rows.join('')}</div>`;
}

function infrastructureData(prometheus, actionState, openConfig = false, assets = {}) {
  const configuredButUnavailable = prometheus.configured
    && prometheus.status !== PROMETHEUS_STATUS.HEALTHY && prometheus.status !== PROMETHEUS_STATUS.DEGRADED;
  const adapter = observabilityAdapter(prometheus.provider);
  // Resolved from what the provider proved, never from the fact it is configured.
  // Evidence comes from the provider's own reading. A model built without one —
  // an older caller, a fixture — still states a fact per metric: an available
  // value is itself the proof, and an absent one is not promoted.
  const evidence = Object.keys(prometheus.capabilities || {}).length
    ? prometheus.capabilities
    : Object.fromEntries(Object.values(OBSERVABILITY_CAPABILITY)
      .map((capability) => {
        const metric = prometheus.metrics?.[capability] || prometheus.metrics?.[`${capability}1`];
        if (capability === OBSERVABILITY_CAPABILITY.HOST_INVENTORY) {
          return [capability, prometheus.targets?.known === false ? OBSERVABILITY_STATE.ERROR : OBSERVABILITY_STATE.READY];
        }
        return [capability, metric?.available ? OBSERVABILITY_STATE.READY : OBSERVABILITY_STATE.UNAVAILABLE];
      }));
  const resolved = resolveObservabilityCapabilities(adapter, {
    configured: Boolean(prometheus.configured),
    evidence
  });
  // A configured provider shows its sections even when a capability turned out
  // to be unavailable: « CPU — Unavailable » is the honest answer, and hiding
  // the tile would hide the fact. Nothing is shown before configuration.
  // The manifest is the adapter's, but a model may carry its own — which is how
  // a provider composes a different dashboard out of the same section kinds
  // without this file ever learning its name.
  const manifest = Array.isArray(prometheus.sections) && prometheus.sections.length
    ? prometheus.sections
    : (adapter?.sections || []);
  const sections = (prometheus.configured ? manifest : visibleObservabilitySections({ sections: manifest }, resolved))
    .map((section) => infrastructureSection(section, prometheus, resolved))
    .join('');

  return `<div class="domain-layout">
    <section class="domain-card span-2">
      <div class="domain-card-head"><div><h3>System health</h3><p>Security Center reads a focused metrics subset for developer operations.</p></div><span class="state-chip ${statusTone(prometheus.status)}">● ${escapeHtml(statusLabel(prometheus.status))}</span></div>
      <div class="identity-grid">
        ${metricTile('Provider', prometheus.label || 'Observability')}
        ${metricTile('Status', statusLabel(prometheus.status), statusTone(prometheus.status))}
        ${metricTile('Inventory', prometheus.targets?.display || 'Unavailable')}
        ${metricTile('Last scrape', displaySecondsAgo(prometheus.targets?.lastScrapeAgeSeconds))}
      </div>
      ${observabilityCapabilityHealth(prometheus, resolved)}
      ${relaxedTlsWarning(prometheus, 'Provider API')}
      ${configuredButUnavailable ? `<p class="provider-message bad">${escapeHtml(prometheus.message || 'Provider is unavailable. Existing configuration is preserved.')}</p>` : ''}
      ${actionStateMessage(actionState)}
      <div class="domain-actions">
        <button data-action="refreshInfrastructure">Refresh</button>
        <button class="secondary" data-action="showConfig">Configure</button>
        <button class="secondary" data-action="openIntegrations">Open integration settings</button>
      </div>
      ${observabilityConfigForm(prometheus, openConfig, actionState, [], assets)}
    </section>
    ${sections}
  </div>`;
}

function domainCss() {
  return `
  /* Catalogue de fournisseurs SIEM. Memes jetons que le reste du systeme
     visuel : aucune couleur ni aucun rayon n'est introduit ici. */
  .field-toggle{grid-template-columns:18px minmax(0,1fr);align-items:start;gap:4px 8px;padding:9px 10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface)}
  .field-toggle input{width:auto;margin:1px 0 0;justify-self:start}
  .field-toggle small{grid-column:2}
  .field-optional{margin-left:6px;color:var(--sc-muted);font-size:9px;font-weight:700;letter-spacing:.4px;text-transform:uppercase}
  .config-provider-head{display:grid;grid-template-columns:38px minmax(0,1fr);gap:8px 11px;align-items:center;padding-bottom:2px}
  .provider-head-copy{display:grid;gap:3px;min-width:0}
  .config-provider-head h4{margin:0;color:var(--sc-text);font-size:18px;font-weight:800;letter-spacing:0}
  .config-provider-head p{max-width:680px}
  .config-provider-head small{color:var(--sc-muted)}
  .config-section-title{color:var(--sc-muted);font-size:9px;font-weight:900;letter-spacing:.7px;text-transform:uppercase}
  .config-field-group{display:grid;gap:10px}
  .config-field input{width:100%}
  .config-advanced{display:grid;gap:10px;padding:13px 14px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface-soft)}
  .config-advanced-toggle{display:grid;gap:2px;width:100%;padding:0 0 9px;border:0;border-bottom:1px solid var(--sc-border);background:transparent;color:var(--sc-text);text-align:left;font:800 11px var(--vscode-font-family);cursor:pointer}
  .config-advanced-toggle span{color:var(--sc-primary);font-size:11px}
  .config-advanced-toggle small{color:var(--sc-muted);font-size:10px;font-weight:600}
  .config-advanced-body{display:grid;gap:10px}
  .config-advanced-body[hidden]{display:none}
  /* Un seul plan de travail : le catalogue choisit, le formulaire configure.
     Les deux colonnes partagent la carte et sont separees par un filet, pas par
     un vide — la relation « fournisseur -> configuration » doit rester lisible. */
  .setup-card.config-workspace-card{width:min(100%,1320px);max-width:1320px;margin:0 auto}
  .config-workspace{display:grid;grid-template-columns:minmax(0,34fr) minmax(0,66fr);gap:0;align-items:start}
  .config-pane{display:grid;gap:9px;min-width:0}
  .config-pane-catalogue{align-content:start;overflow:visible;padding-right:18px}
  .config-pane-form{gap:13px;padding-left:22px;border-left:1px solid var(--sc-border)}
  .config-pane-form .field-label{color:var(--sc-muted);font-size:9px;font-weight:900;letter-spacing:.7px;text-transform:uppercase}
  .config-pane-form .field-hint{margin:0 0 2px;color:var(--sc-muted);font-size:11px}
  .config-pane-form .domain-actions{justify-content:flex-end;align-items:center;margin-top:2px;padding-top:10px;border-top:1px solid var(--sc-border)}
  .config-pane-form .domain-actions button{flex:0 0 auto}
  .config-pane-form .provider-message{flex:1 1 100%}
  /* Sous une certaine largeur la colonne de droite deviendrait illisible :
     on empile, fournisseur d'abord, sans jamais deborder horizontalement. */
  @media(max-width:900px){
    .config-workspace{grid-template-columns:minmax(0,1fr)}
    .config-pane-catalogue{overflow:visible;padding-right:0}
    .config-pane-form{padding-left:0;padding-top:16px;border-left:0;border-top:1px solid var(--sc-border)}
  }
  .provider-catalogue{display:grid;gap:6px;margin-bottom:4px}
  .provider-catalogue .field-label{color:var(--sc-muted);font-size:9px;font-weight:900;letter-spacing:.7px;text-transform:uppercase}
  .provider-catalogue .field-hint{margin:0 0 2px;color:var(--sc-muted);font-size:11px}
  .provider-option{display:grid;grid-template-columns:18px 30px minmax(0,1fr) auto;align-items:center;gap:1px 9px;min-height:50px;padding:7px 10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface);cursor:pointer;transition:border-color .12s ease,background-color .12s ease}
  .provider-option:hover{border-color:color-mix(in srgb,var(--sc-primary) 30%,var(--sc-border));background:var(--sc-surface-soft)}
  .provider-option input{margin:0}
  .provider-option.selected{border-color:var(--sc-primary);background:var(--sc-primary-soft)}
  .provider-copy{display:grid;gap:2px;min-width:0}
  .provider-option .provider-name{color:var(--sc-text);font-size:11.5px;font-weight:700;line-height:1.3}
  .provider-option .provider-note{color:var(--sc-muted);font-size:10px;line-height:1.35;overflow:hidden;text-overflow:ellipsis}
  .provider-mark,.provider-head-mark{display:grid;place-items:center;overflow:hidden;flex:none;border:1px solid var(--sc-border);background:var(--sc-surface-soft)}
  .provider-mark{width:28px;height:28px;border-radius:8px}
  .provider-head-mark{width:38px;height:38px;border-radius:10px}
  .provider-logo{display:block;max-width:72%;max-height:72%;object-fit:contain}
  .provider-mark-fallback{color:var(--sc-muted);font-size:12px;font-weight:900}
  .provider-badge{padding:2px 8px;border-radius:999px;font-size:9px;font-weight:900;letter-spacing:.5px;text-transform:uppercase}
  .provider-badge.supported{color:var(--sc-success);background:color-mix(in srgb,var(--sc-success) 14%,transparent)}
  .provider-badge.planned{color:var(--sc-muted);background:var(--sc-surface-soft)}
  .provider-planned{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:2px 10px;padding:10px 12px;border:1px dashed var(--sc-border);border-radius:var(--sc-radius-md);opacity:.75}
  .provider-planned-title{color:var(--sc-muted);font-size:9px;font-weight:900;letter-spacing:.7px;text-transform:uppercase}
  .provider-planned-list{grid-column:1;color:var(--sc-muted);font-size:10.5px}
  .provider-planned .provider-badge{grid-row:1/span 2}
  .domain-hero{position:relative;overflow:hidden;display:flex;justify-content:space-between;gap:18px;margin-bottom:18px;padding:22px;border:1px solid var(--sc-border);border-radius:18px;background:linear-gradient(135deg,color-mix(in srgb,var(--sc-primary) 9%,var(--sc-surface)),var(--sc-surface));box-shadow:var(--sc-shadow-sm)}
  .domain-watermark{position:absolute;right:24px;bottom:-20px;display:flex;gap:18px;opacity:.035;pointer-events:none;color:var(--sc-primary);transform:scale(5)}
  .domain-hero-copy,.domain-hero-status{position:relative;z-index:1}.domain-eyebrow{display:block;margin-bottom:6px;color:var(--sc-primary);font-size:10px;font-weight:900;letter-spacing:.9px;text-transform:uppercase}
  .domain-hero h2{margin:0;color:var(--sc-text);font-size:28px;letter-spacing:0}.domain-hero p{max-width:620px;margin:8px 0 0;color:var(--sc-muted);font-size:12px;line-height:1.55}
  .domain-hero-status{display:grid;min-width:172px;align-content:center;justify-items:start;gap:4px;padding:12px 14px;border:1px solid var(--sc-border);border-radius:14px;background:color-mix(in srgb,var(--sc-surface) 82%,transparent)}
  .domain-icon{display:grid;place-items:center;width:34px;height:34px;margin-bottom:4px;border-radius:11px;color:var(--sc-primary);background:var(--sc-primary-soft)}.domain-hero-status span{color:var(--sc-muted);font-size:9px;font-weight:900;text-transform:uppercase;letter-spacing:.7px}.domain-hero-status strong{font-size:13px}.domain-hero-status em,.state-chip,.asset-row em{font-style:normal;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.5px}
  .ok{color:var(--sc-success)}.warn{color:var(--sc-warning)}.bad{color:var(--sc-danger)}.muted{color:var(--sc-muted)}.critical{color:var(--sc-critical)}.high{color:var(--sc-high)}.medium{color:var(--sc-medium)}.low{color:var(--sc-low)}
  .domain-layout{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.domain-layout.single{grid-template-columns:minmax(0,760px)}.domain-layout.single.wide{grid-template-columns:minmax(0,1fr)}.span-2{grid-column:1/-1}
  .domain-card{position:relative;overflow:hidden;display:grid;gap:13px;padding:17px;border:1px solid var(--sc-border);border-radius:16px;background:var(--sc-surface);box-shadow:var(--sc-shadow-sm)}
  .domain-card::after{content:'';position:absolute;right:-36px;top:-44px;width:160px;height:160px;border-radius:999px;border:1px solid color-mix(in srgb,var(--sc-primary) 16%,transparent);opacity:.25;pointer-events:none}
  .domain-card-head{display:flex;justify-content:space-between;gap:12px;align-items:start}.domain-card h3{margin:0;font-size:15px}.domain-card p,.domain-card small{margin:0;color:var(--sc-muted);font-size:11px;line-height:1.5}
  .state-chip{display:inline-flex;white-space:nowrap;padding:5px 9px;border-radius:999px;background:var(--sc-surface-soft)}
  .identity-grid,.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:9px}.domain-metric{display:grid;gap:5px;min-width:0;padding:12px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft)}
  .domain-metric span{color:var(--sc-muted);font-size:9px;font-weight:900;letter-spacing:.55px;text-transform:uppercase}.domain-metric strong{font-size:18px;overflow-wrap:anywhere}
  .asset-list,.alert-list{display:grid;gap:8px}.asset-row,.alert-row{display:grid;grid-template-columns:minmax(0,1fr) auto auto auto;gap:12px;align-items:center;padding:11px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft)}
  .asset-row strong,.asset-row span,.alert-row strong,.alert-row small{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.asset-row span,.alert-row small,.alert-row time{color:var(--sc-muted);font-size:10.5px}.alert-row>span{font-size:10px;font-weight:900}
  .icon-action{display:grid;place-items:center;width:30px;height:30px;padding:0}.icon-action .compact-icon{width:15px;height:15px}
  .alert-detail{position:fixed;right:18px;top:72px;z-index:20;display:grid;gap:11px;width:min(420px,calc(100vw - 36px));max-height:calc(100vh - 98px);overflow:auto;padding:18px;border:1px solid var(--sc-border);border-radius:16px;background:var(--sc-surface);box-shadow:0 24px 70px color-mix(in srgb,var(--sc-text) 20%,transparent)}.alert-detail[hidden]{display:none}.detail-head{display:flex;justify-content:space-between;align-items:center}.alert-detail dl{display:grid;gap:8px;margin:0}.alert-detail dl div{display:grid;grid-template-columns:120px minmax(0,1fr);gap:10px}.alert-detail dt{color:var(--sc-muted);font-size:10px;font-weight:900;text-transform:uppercase}.alert-detail dd{margin:0;overflow-wrap:anywhere}
  /* Navigation locale : meme motif segmente que la page Pipeline, memes jetons. */
  .tabs{display:flex;flex-wrap:wrap;gap:4px;padding-bottom:8px;border-bottom:1px solid var(--sc-border)}
  .tabs button{padding:6px 12px;border:0;border-bottom:2px solid transparent;border-radius:0;color:var(--sc-muted);background:transparent;font:600 11px var(--vscode-font-family);cursor:pointer;transition:color .15s ease,border-color .15s ease}
  .tabs button:hover{color:var(--sc-text)}
  .tabs button[aria-current=true]{color:var(--sc-primary);border-bottom-color:var(--sc-primary);font-weight:800}
  .tabs button:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:1px}
  /* Sante par capacite : chacune tombe seule, donc chacune se lit seule. */
  .capability-list{display:grid;gap:6px}
  .capability-row{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:8px 11px;border:1px solid var(--sc-border);border-radius:10px;background:var(--sc-surface-soft)}
  .capability-row span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--sc-text);font-size:11px;font-weight:700}
  .capability-row em{font-style:normal;font-size:10px;font-weight:900;letter-spacing:.5px;text-transform:uppercase}
  /* Barre de filtres et pagination : memes jetons, aucun nouveau vocabulaire. */
  .alerts-toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:end}
  /* gap n agit que sur une grille : sans display, l etiquette et son controle
     se collent et le selecteur passe inapercu la ou la barre de filtres ne le
     blockifie pas deja. */
  .filter-field{display:grid;gap:4px;font-size:9px;font-weight:900;letter-spacing:.5px;text-transform:uppercase;color:var(--sc-muted)}
  .filter-field select,.filter-field input{font:600 11px var(--vscode-font-family)}
  .filter-search{flex:1 1 220px}
  .alerts-toolbar button{align-self:end}
  .alerts-toolbar button[disabled]{opacity:.5;cursor:default}
  .alerts-meta{margin:0;color:var(--sc-muted);font-size:10.5px}
  .pager{display:flex;gap:10px;align-items:center;justify-content:flex-end}
  .pager span{color:var(--sc-muted);font-size:10.5px}
  .pager button[disabled]{opacity:.5;cursor:default}
  .row-actions{display:flex;gap:6px;align-items:center}
  /* Vue d investigation : meme motif que le detail de finding — grille de faits
     puis blocs de contenu. */
  .investigation h4{margin:6px 0 0;font-size:11px;font-weight:900;letter-spacing:.5px;text-transform:uppercase;color:var(--sc-muted)}
  .investigation .domain-card-head h3{margin-top:6px}
  .detail-grid{display:grid;grid-template-columns:minmax(120px,180px) minmax(0,1fr);gap:8px 14px}
  .detail-block{padding:12px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft);font-size:11.5px;line-height:1.55;overflow-wrap:anywhere}
  .detail-label{color:var(--sc-muted);font-weight:800}
  .plain-list{margin:0;padding-left:16px;display:grid;gap:4px}
  .provider-message.warn{border-color:color-mix(in srgb,var(--sc-warning) 45%,var(--sc-border));color:var(--sc-text)}
  .mitre-list{display:grid;gap:8px}
  .mitre-row{display:grid;grid-template-columns:auto minmax(0,1fr);gap:12px;align-items:center;padding:11px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft)}
  .mitre-row>span{font-size:11px;font-weight:900}
  .mitre-row strong,.mitre-row small{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .mitre-row small{color:var(--sc-muted);font-size:10.5px}
  .domain-hero-meta{color:var(--sc-muted);font-size:10px;font-weight:700}
  .domain-actions{display:flex;flex-wrap:wrap;gap:8px}button{font:800 11px var(--vscode-font-family);border:1px solid var(--sc-primary);border-radius:10px;padding:8px 12px;cursor:pointer;color:var(--sc-primary-text,var(--vscode-button-foreground));background:var(--sc-primary)}button.secondary{color:var(--sc-text);border-color:var(--sc-border);background:var(--sc-surface)}
  .setup-card{max-width:760px}label{display:grid;gap:6px;font-size:11px;font-weight:800;color:var(--sc-text)}input,select{min-width:0;padding:9px 11px;border-radius:10px;border:1px solid var(--sc-input-border,var(--sc-border));color:var(--sc-input-text,var(--sc-text));background:var(--sc-input-bg,var(--sc-surface))}.setup-card[hidden],.domain-card[hidden]{display:none}
  .domain-action-state{padding:10px 12px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft)}.provider-message{padding:10px 12px;border:1px solid var(--sc-border);border-radius:12px;background:var(--sc-surface-soft)}.empty-state{padding:12px;border:1px dashed var(--sc-border);border-radius:12px;color:var(--sc-muted);background:var(--sc-surface-soft)}
  @media(max-width:560px){.config-pane-form .domain-actions{justify-content:stretch}.config-pane-form .domain-actions button{flex:1 1 160px}}
  @media(max-width:860px){.domain-hero{flex-direction:column}.domain-layout{grid-template-columns:1fr}.asset-row,.alert-row{grid-template-columns:1fr}.alert-detail dl div{grid-template-columns:1fr}}`;
}

function pageScript(kind) {
  const prefix = kind === 'runtime' ? 'Runtime' : 'Infrastructure';
  const configFn = kind === 'runtime'
    // Le fournisseur vient du catalogue : seuls les adaptateurs reellement
    // disponibles ont un bouton radio, donc rien d'autre ne peut etre soumis.
    // Les champs viennent du schema du fournisseur : le script collecte tout ce
    // que le formulaire a reellement rendu plutot qu'une liste figee.
    ? "const provider=()=>{const c=document.querySelector('input[name=\"runtime-provider-choice\"]:checked');return c?c.value:value('runtime-provider');};const config=()=>{const out={provider:provider()};document.querySelectorAll('.setup-card input[id^=\"runtime-\"]').forEach(function(el){const key=el.id.slice('runtime-'.length);if(!key||key==='provider')return;out[key]=el.type==='checkbox'?el.checked:el.value.trim();});return out;};"
    // Le fournisseur vient du catalogue : seuls les adaptateurs disponibles ont
    // un bouton radio, donc rien d'autre ne peut etre soumis.
    : "const provider=()=>{const c=document.querySelector('input[name=\"observability-provider-choice\"]:checked');return c?c.value:value('observability-provider');};const config=()=>{const out={provider:provider()};document.querySelectorAll('.setup-card input[id^=\"observability-\"]').forEach(function(el){const key=el.id.slice('observability-'.length);if(!key||key==='provider')return;out[key]=el.type==='checkbox'?el.checked:el.value.trim();});return out;};";
  return `const vscode=window.__scShellApi||acquireVsCodeApi();
    const value=id=>{const el=document.getElementById(id);return el?el.value.trim():'';};
    ${configFn}
    const showConfig=()=>{document.querySelectorAll('.setup-card').forEach(el=>{el.hidden=false;const input=el.querySelector('input,select');if(input)input.focus();});};
    document.querySelectorAll('[data-command]:not(.sc-nav-item)').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
    document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{
      const action=b.dataset.action;
      if(action==='toggleAdvanced'){
        const body=b.parentElement.querySelector('.config-advanced-body');
        if(body){const open=body.hidden;body.hidden=!open;b.setAttribute('aria-expanded',open?'true':'false');}
        return;
      }
      if(action==='showConfig')return showConfig();
      if(action==='cancelConfig'){document.querySelectorAll('.setup-card').forEach(el=>el.hidden=true);return;}
      if(action==='openIntegrations')return vscode.postMessage({type:'action',action});
      if(action==='save${prefix}Config'||action==='test${prefix}Config')return vscode.postMessage({type:'action',action,config:config()});
      vscode.postMessage({type:'action',action});
    });
    document.querySelectorAll('input[name="observability-provider-choice"]').forEach(function(radio){
      radio.addEventListener('change',function(){vscode.postMessage({type:'action',action:'selectObservabilityProvider',config:{provider:radio.value}});});
    });
    document.querySelectorAll('input[name="runtime-provider-choice"]').forEach(function(radio){
      radio.addEventListener('change',function(){vscode.postMessage({type:'action',action:'selectRuntimeProvider',config:{provider:radio.value}});});
    });
    document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'tab',tab:b.dataset.tab}));
    document.querySelectorAll('[data-observability-host]').forEach(el=>el.addEventListener('change',()=>vscode.postMessage({type:'action',action:'selectInfrastructureHost',config:{host:el.value}})));
    const alertsQuery=()=>({search:value('alerts-search'),severity:value('alerts-severity'),agent:value('alerts-agent'),rule:value('alerts-rule')});
    const postAlerts=extra=>vscode.postMessage({type:'alerts',query:Object.assign(alertsQuery(),extra||{})});
    document.querySelectorAll('[data-alerts-filter]').forEach(el=>el.addEventListener('change',()=>postAlerts({page:1})));
    const alertSearch=document.querySelector('[data-alerts-search]');
    if(alertSearch){alertSearch.addEventListener('change',()=>postAlerts({page:1}));alertSearch.addEventListener('keydown',e=>{if(e.key==='Enter')postAlerts({page:1});});}
    document.querySelectorAll('[data-alerts-page]').forEach(b=>b.onclick=()=>postAlerts({page:b.dataset.alertsPage}));
    document.querySelectorAll('[data-alerts-clear]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'alerts',query:{}}));
    document.querySelectorAll('[data-alert-open]').forEach(b=>b.onclick=e=>{e.stopPropagation();postAlerts({alert:b.dataset.alertOpen,page:1});});
    const vulnsQuery=()=>({search:value('vulns-search'),severity:value('vulns-severity'),asset:value('vulns-asset'),cve:value('vulns-cve'),package:value('vulns-package')});
    const postVulns=extra=>vscode.postMessage({type:'vulns',query:Object.assign(vulnsQuery(),extra||{})});
    document.querySelectorAll('[data-vulns-filter]').forEach(el=>el.addEventListener('change',()=>postVulns({page:1})));
    document.querySelectorAll('[data-vulns-search]').forEach(el=>{el.addEventListener('change',()=>postVulns({page:1}));el.addEventListener('keydown',e=>{if(e.key==='Enter')postVulns({page:1});});});
    document.querySelectorAll('[data-vulns-page]').forEach(b=>b.onclick=()=>postVulns({page:b.dataset.vulnsPage}));
    document.querySelectorAll('[data-vulns-clear]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'vulns',query:{}}));
    document.querySelectorAll('[data-vuln-open]').forEach(b=>b.onclick=e=>{e.stopPropagation();postVulns({vulnerability:b.dataset.vulnOpen,page:1});});
    document.querySelectorAll('[data-alert-index]').forEach(item=>item.addEventListener('click',()=>{const detail=document.querySelector('[data-alert-detail="'+item.dataset.alertIndex+'"]');if(detail)detail.hidden=false;}));
    document.querySelectorAll('[data-close-alert]').forEach(item=>item.addEventListener('click',()=>{const detail=item.closest('.alert-detail');if(detail)detail.hidden=true;}));`;
}

function renderRuntimeSecurityPageHtml(model = {}, nonce = '', theme = 'light', assets = {}) {
  const runtime = model.runtime || buildRuntimeSecurityStatus();
  // The label comes from the provider's own metadata; the generic page has no
  // vendor to fall back on.
  const provider = safeProviderLabel(runtime, siemProvider(runtime.provider)?.label || '');
  const configured = Boolean(runtime.configured);
  // Navigation is resolved once, from the provider's capabilities: the header,
  // the tabs and the active panel all describe the same resolved state.
  // Runtime evidence, when a probe produced any. Without it nothing is
  // promoted — which is what keeps a secondary data source from being believed
  // on the strength of its configuration alone.
  const nav = runtimeNavigation(siemProvider(runtime.provider), runtime, model.tab, model.capabilityEvidence || {});
  const content = `${domainHeader({
    eyebrow: 'Runtime Security',
    title: 'Runtime Security',
    provider,
    status: runtime.status,
    icon: 'shield',
    meta: configured ? `Last sync: ${runtimeLastSync(runtime)}` : '',
    subtitle: configured
      ? 'Normalized SIEM alerts, monitored assets and investigation context.'
      : 'SIEM provider not configured. Connect your SIEM to bring runtime-security alerts into Security Center.'
  })}${configured
    ? runtimeData(runtime, model.actionState, model.openConfig, nav, model.alertsQuery, model.vulnerabilities, model.vulnerabilitiesQuery, assets)
    : runtimeSetup(runtime, model.actionState, assets)}`;
  return renderSecurityCenterShell({
    surface: 'runtime',
    nonce,
    theme,
    title: 'Runtime Security',
    subtitle: configured ? `Provider: ${provider}` : 'SIEM provider not configured',
    headerActions: configured
      ? '<button data-action="refreshRuntime">Refresh</button><button class="secondary" data-action="showConfig">Settings</button>'
      : '',
    content,
    styles: domainCss(),
    script: pageScript('runtime'),
    csp: `default-src 'none'; img-src ${assets?.cspSource || "'self'"}; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';`
  });
}

function renderInfrastructurePageHtml(model = {}, nonce = '', theme = 'light', assets = {}) {
  const prometheus = model.prometheus || buildPrometheusStatus();
  const provider = safeProviderLabel(prometheus, 'Prometheus');
  const configured = Boolean(prometheus.configured);
  const content = `${domainHeader({
    eyebrow: 'Infrastructure',
    title: 'Infrastructure',
    provider,
    status: prometheus.status,
    icon: 'chart',
    subtitle: configured
      ? 'Operational observability signals from the configured metrics provider.'
      : 'Observability provider not configured. Connect an existing metrics backend to display host health inside Security Center.'
  })}${configured ? infrastructureData(prometheus, model.actionState, model.openConfig, assets) : infrastructureSetup(prometheus, model.actionState, assets)}`;
  return renderSecurityCenterShell({
    surface: 'infrastructure',
    nonce,
    theme,
    title: 'Infrastructure',
    subtitle: configured ? `Provider: ${provider}` : 'Observability provider not configured',
    headerActions: configured ? '<button data-action="refreshInfrastructure">Refresh</button>' : '',
    content,
    styles: domainCss(),
    script: pageScript('infrastructure'),
    csp: `default-src 'none'; img-src ${assets?.cspSource || "'self'"}; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';`
  });
}

module.exports = {
  renderRuntimeSecurityPageHtml,
  renderInfrastructurePageHtml,
  domainCss,
  statusLabel,
  statusTone
};
