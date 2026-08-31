'use strict';

/**
 * The generic Security Delivery renderer.
 *
 * Draws the delivery page from the normalized model alone. It contains no
 * provider name, no endpoint, no vendor vocabulary and no conditional on
 * `providerId`: every label it shows either comes from the model or belongs to
 * the domain. A new adapter therefore gets a page without this file changing —
 * which is the property the tests assert.
 *
 * Two rules it holds to, inherited from Runtime Security and Infrastructure:
 *
 *   - A capability with no answer renders its reason, never a fabricated value
 *     and never a failure. « Not reported » and « failed » are different words
 *     on this page because they are different facts.
 *   - A field marked `secret` in a provider schema is never rendered back. Its
 *     value does not reach the HTML, only whether one is configured.
 */

const {
  PROVIDER_STATUS, CAPABILITY, RESOLVED_STATE, RUN_OUTCOME, RUN_OUTCOME_LABELS, SECTION_KIND,
  CONFIG_GROUP, fieldsInGroup
} = require('./integrations/delivery-contract');
const { renderSecurityCenterShell } = require('./security-center-shell');
const { isTrustedWebviewAssetUri } = require('./scanner-presentation');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

/** Visual weight of a provider state. Domain vocabulary, not vendor wording. */
const STATUS_CLASS = Object.freeze({
  [PROVIDER_STATUS.HEALTHY]: 'ok',
  [PROVIDER_STATUS.DEGRADED]: 'warn',
  [PROVIDER_STATUS.NOT_CONFIGURED]: 'muted',
  [PROVIDER_STATUS.OFFLINE]: 'bad',
  [PROVIDER_STATUS.AUTH_ERROR]: 'bad',
  [PROVIDER_STATUS.ERROR]: 'bad'
});

const OUTCOME_CLASS = Object.freeze({
  [RUN_OUTCOME.SUCCESS]: 'ok',
  [RUN_OUTCOME.RUNNING]: 'warn',
  [RUN_OUTCOME.UNSTABLE]: 'warn',
  [RUN_OUTCOME.FAILED]: 'bad',
  [RUN_OUTCOME.ABORTED]: 'bad',
  [RUN_OUTCOME.NOT_STARTED]: 'muted',
  [RUN_OUTCOME.NOT_REPORTED]: 'muted'
});

const CAPABILITY_LABELS = Object.freeze({
  [CAPABILITY.PIPELINE_STATUS]: 'État du pipeline',
  [CAPABILITY.LAST_RUN]: 'Dernière exécution',
  [CAPABILITY.STAGES]: 'Étapes',
  [CAPABILITY.ARTIFACTS]: 'Artefacts',
  [CAPABILITY.DEPLOYMENT_STATUS]: 'Déploiement'
});

const RESOLVED_LABELS = Object.freeze({
  [RESOLVED_STATE.READY]: 'Disponible',
  [RESOLVED_STATE.REQUIRES_CONFIG]: 'À configurer',
  [RESOLVED_STATE.NOT_REPORTED]: 'Non rapporté',
  [RESOLVED_STATE.UNAVAILABLE]: 'Indisponible',
  [RESOLVED_STATE.ERROR]: 'Erreur'
});

const PAGE_STATUS_LABELS = Object.freeze({
  [PROVIDER_STATUS.HEALTHY]: 'Healthy',
  [PROVIDER_STATUS.DEGRADED]: 'Degraded',
  [PROVIDER_STATUS.OFFLINE]: 'Offline',
  [PROVIDER_STATUS.NOT_CONFIGURED]: 'Not configured',
  [PROVIDER_STATUS.AUTH_ERROR]: 'Authentication error',
  [PROVIDER_STATUS.ERROR]: 'Error'
});

/** « Non fourni » is the honest rendering of a field the provider omitted. */
function value(raw) {
  const text = String(raw ?? '').trim();
  return text ? escapeHtml(text) : '<span class="muted">Non fourni</span>';
}

function row(label, rendered) {
  return `<div class="row"><span>${escapeHtml(label)}</span><span>${rendered}</span></div>`;
}

function formatDuration(durationMs) {
  if (durationMs == null || !Number.isFinite(Number(durationMs))) return '';
  const seconds = Math.round(Number(durationMs) / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${String(seconds % 60).padStart(2, '0')} s`;
}

/** Provider identity and connection state. */
function renderConnectionSection(model, section) {
  const stateClass = STATUS_CLASS[model.status] || 'muted';
  const logo = model.providerLogoUri
    ? `<span class="provider-logo" aria-hidden="true"><img src="${escapeHtml(model.providerLogoUri)}" alt="" loading="lazy"></span>`
    : '';
  const detail = model.message ? `<p class="muted">${escapeHtml(model.message)}</p>` : '';
  return `<section class="card ${stateClass}" data-section="connection">
<div class="card-head"><h3 class="provider-title">${logo}<span>${escapeHtml(section.title)}</span></h3>
<span class="state">${escapeHtml(model.statusLabel)}</span></div>
${row('Fournisseur', value(model.providerLabel))}
${row('Serveur', value(model.target))}
${row('Pipeline', value(model.pipeline))}
${row('Authentification', model.credentialsConfigured ? 'Jeton conservé par le SecretStorage' : '<span class="muted">Aucun jeton enregistré</span>')}
${detail}
<div class="actions">
<button data-action="deliveryConfigure">Configurer le fournisseur</button>
<button class="secondary" data-action="deliveryTest">Tester la connexion</button>
${model.consoleUrl ? '<button class="secondary" data-action="deliveryOpenConsole">Ouvrir la console du fournisseur</button>' : ''}
</div></section>`;
}

function withResolvedProviderAsset(model = {}, assets = {}) {
  const logos = assets?.providerLogoUris && typeof assets.providerLogoUris === 'object'
    ? assets.providerLogoUris
    : {};
  const candidate = logos[model.providerId] || '';
  const providerLogoUri = isTrustedWebviewAssetUri(candidate, assets) ? String(candidate) : '';
  return { ...model, providerLogoUri };
}

/**
 * The last run.
 *
 * When there is none, the section says which of « not started » or « not
 * reported » applies. It never renders a failure for a run that does not exist.
 */
function renderRunSection(model, section) {
  const capability = model.capabilities?.[CAPABILITY.LAST_RUN] || {};
  if (!model.run) {
    return `<section class="card muted" data-section="run-summary">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3>
<span class="state">${escapeHtml(RESOLVED_LABELS[capability.state] || RESOLVED_LABELS[RESOLVED_STATE.NOT_REPORTED])}</span></div>
<p class="muted">${escapeHtml(capability.reason || 'Aucune exécution rapportée par le fournisseur.')}</p>
<p class="muted">Une absence d’exécution n’est pas un échec : aucun verdict n’est attribué.</p></section>`;
  }
  const run = model.run;
  const outcomeClass = OUTCOME_CLASS[run.outcome] || 'muted';
  const duration = formatDuration(run.durationMs);
  return `<section class="card ${outcomeClass}" data-section="run-summary">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3>
<span class="state">${escapeHtml(RUN_OUTCOME_LABELS[run.outcome] || run.outcome)}</span></div>
${row('Identifiant', value(run.displayName || run.id))}
${row('Résultat rapporté', value(run.providerResult))}
${row('Démarrée le', value(run.startedAt))}
${row('Durée', duration ? escapeHtml(duration) : '<span class="muted">Non fournie</span>')}
${row('Branche', value(run.branch))}
${row('Commit', value(run.commit))}
</section>`;
}

/** A capability-driven list section: stages, artefacts. */
function renderListSection(model, section, { capability, items, emptyHint }) {
  const resolved = model.capabilities?.[capability] || {};
  const entries = Array.isArray(items) ? items : [];
  if (!entries.length) {
    return `<section class="card muted" data-section="${escapeHtml(section.kind)}">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3>
<span class="state">${escapeHtml(RESOLVED_LABELS[resolved.state] || RESOLVED_LABELS[RESOLVED_STATE.NOT_REPORTED])}</span></div>
<p class="muted">${escapeHtml(resolved.reason || emptyHint)}</p></section>`;
  }
  const rows = entries.map((entry) => `<li><span>${escapeHtml(entry.name || entry.label || '')}</span>${entry.path ? `<small>${escapeHtml(entry.path)}</small>` : ''}${entry.outcome ? `<span class="state">${escapeHtml(RUN_OUTCOME_LABELS[entry.outcome] || entry.outcome)}</span>` : ''}</li>`).join('');
  return `<section class="card" data-section="${escapeHtml(section.kind)}">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3><span class="state">${entries.length}</span></div>
<ul class="delivery-list">${rows}</ul></section>`;
}

/** The archived security verdict, when the provider published one. */
function renderSecurityReportSection(model, section) {
  const report = model.securityReport;
  if (!report || !report.reported) {
    return `<section class="card muted" data-section="security-report">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3><span class="state">Non rapporté</span></div>
<p class="muted">${escapeHtml(report?.reason || 'Cette exécution n’a publié aucun rapport de sécurité. Son verdict de sécurité est inconnu.')}</p>
<p class="muted">Un verdict inconnu n’est pas un verdict favorable.</p></section>`;
  }
  if (report.inconsistent) {
    return `<section class="card warn" data-section="security-report">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3><span class="state">Non attribuable</span></div>
<p class="muted">Le rapport publié ne correspond pas au commit de cette exécution : son verdict n’est pas attribué.</p></section>`;
  }
  const policy = report.policy || {};
  return `<section class="card ${policy.passed === false ? 'bad' : 'ok'}" data-section="security-report">
<div class="card-head"><h3>${escapeHtml(section.title)}</h3>
<span class="state">${policy.passed === false ? 'Politique non respectée' : 'Politique respectée'}</span></div>
${row('Décision', value(policy.decision || (policy.passed === false ? 'blocked' : 'passed')))}
${row('Motif', value(policy.reason))}
</section>`;
}

/**
 * Renders every section the adapter declared, in its order.
 *
 * The dispatch is on section KIND — a closed vocabulary of the domain — never
 * on the provider. An adapter that declares no section renders nothing rather
 * than falling back to someone else's layout.
 */
function renderDeliverySections(model = {}) {
  const sections = Array.isArray(model.sections) ? model.sections : [];
  return sections.map((section) => {
    switch (section.kind) {
      case SECTION_KIND.CONNECTION:
        return renderConnectionSection(model, section);
      case SECTION_KIND.RUN_SUMMARY:
        return renderRunSection(model, section);
      case SECTION_KIND.STAGE_LIST:
        return renderListSection(model, section, {
          capability: CAPABILITY.STAGES,
          items: model.stages,
          emptyHint: 'Le fournisseur n’expose pas les étapes de cette exécution.'
        });
      case SECTION_KIND.ARTIFACT_LIST:
        return renderListSection(model, section, {
          capability: CAPABILITY.ARTIFACTS,
          items: model.artifacts,
          emptyHint: 'Aucun artefact rapporté par cette exécution.'
        });
      case SECTION_KIND.SECURITY_REPORT:
        return renderSecurityReportSection(model, section);
      default:
        return '';
    }
  }).join('');
}

/**
 * The provider selector.
 *
 * A catalogue-only provider is listed but carries no form and no Test/Save
 * action: with no schema there is nothing to draw, which is the intended
 * outcome rather than a limitation to work around.
 */
function renderProviderSelector(providers = [], selectedId = '') {
  const options = providers.map((provider) => {
    const selected = provider.id === selectedId ? ' selected' : '';
    const suffix = provider.implemented ? '' : ' — adaptateur indisponible';
    return `<option value="${escapeHtml(provider.id)}"${selected}>${escapeHtml(provider.label)}${escapeHtml(suffix)}</option>`;
  }).join('');
  return `<section class="card" data-section="provider-selector">
<div class="card-head"><h3>Fournisseur CI/CD</h3></div>
<label for="delivery-provider">Plateforme de livraison</label>
<select id="delivery-provider" data-action="deliverySelectProvider">${options}</select>
</section>`;
}

/**
 * The configuration form of the selected provider.
 *
 * Built entirely from the declared schema. A secret field renders an empty
 * input and a note about what is already stored — its value is never emitted.
 */
function renderProviderForm(provider, { configuration = {}, secretsConfigured = {} } = {}) {
  if (!provider) return '';
  if (!provider.implemented || !provider.configurationFields.length) {
    return `<section class="card muted" data-section="provider-form">
<div class="card-head"><h3>${escapeHtml(provider.label)}</h3><span class="state">Référencé</span></div>
<p class="muted">Ce fournisseur est référencé mais aucun adaptateur n’est encore disponible.</p></section>`;
  }
  const field = (entry) => {
    if (entry.type === 'boolean') {
      const checked = configuration[entry.id] === true ? ' checked' : '';
      return `<div class="field"><label><input type="checkbox" id="delivery-${escapeHtml(entry.id)}"${checked}> ${escapeHtml(entry.label)}</label>${entry.hint ? `<small>${escapeHtml(entry.hint)}</small>` : ''}</div>`;
    }
    // A secret is never written back into the document: only the fact that one
    // is stored, as a placeholder.
    const stored = entry.secret ? Boolean(secretsConfigured[entry.id]) : false;
    const attrValue = entry.secret ? '' : escapeHtml(configuration[entry.id] ?? '');
    const placeholder = entry.secret && stored
      ? 'Laisser vide pour conserver la valeur enregistrée'
      : escapeHtml(entry.placeholder || '');
    return `<div class="field"><label for="delivery-${escapeHtml(entry.id)}">${escapeHtml(entry.label)}${entry.required ? ' *' : ''}</label>
<input id="delivery-${escapeHtml(entry.id)}" type="${escapeHtml(entry.type === 'password' ? 'password' : entry.type === 'url' ? 'url' : 'text')}" autocomplete="off" spellcheck="false"${attrValue ? ` value="${attrValue}"` : ''} placeholder="${placeholder}">
${entry.hint ? `<small>${escapeHtml(entry.hint)}</small>` : ''}</div>`;
  };
  const primary = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.PRIMARY).map(field).join('');
  const advanced = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.ADVANCED).map(field).join('');
  return `<section class="card" data-section="provider-form">
<div class="card-head"><h3>${escapeHtml(provider.label)}</h3></div>
<div class="delivery-fields">${primary}</div>
${advanced ? `<details class="advanced"><summary>Avancé</summary><div class="delivery-fields">${advanced}</div></details>` : ''}
<div class="actions">
<button data-action="deliverySave">Enregistrer la configuration</button>
<button class="secondary" data-action="deliveryTest">Tester la connexion</button>
</div></section>`;
}

function deliveryPageCss() {
  return `
  .delivery-head{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:13px}
  .delivery-head-tile{border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:13px;display:grid;gap:5px}
  .delivery-head-tile span{color:var(--sc-muted);font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.6px}
  .delivery-head-tile strong{font-size:14px;color:var(--sc-text);overflow-wrap:anywhere}
  .card{border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:15px;margin-bottom:13px}
  .card.ok{border-top:2px solid var(--sc-success)}
  .card.warn{border-top:2px solid var(--sc-warning)}
  .card.bad{border-top:2px solid var(--sc-danger)}
  .card.muted{border-top:2px solid var(--sc-border)}
  .card-head{display:flex;justify-content:space-between;gap:12px;align-items:baseline;margin-bottom:9px}
  h3{margin:0;font-size:14px;font-weight:700;color:var(--sc-text)}
  .provider-title{display:inline-flex;align-items:center;gap:8px;min-width:0}
  .provider-title span{min-width:0;overflow-wrap:anywhere}
  .provider-logo{display:grid;place-items:center;flex:none;width:30px;height:30px;border:1px solid var(--sc-border);border-radius:8px;background:var(--sc-surface-soft);overflow:hidden}
  .provider-logo img{display:block;max-width:72%;max-height:72%;object-fit:contain}
  .state{flex:none;padding:3px 9px;border-radius:999px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;color:var(--sc-muted);background:var(--sc-surface-soft)}
  .card.ok>.card-head .state{color:var(--sc-success);background:var(--sc-success-bg)}
  .card.warn>.card-head .state{color:var(--sc-warning);background:var(--sc-warning-bg)}
  .card.bad>.card-head .state{color:var(--sc-danger);background:var(--sc-danger-bg)}
  .muted{color:var(--sc-muted)}
  .row{display:grid;grid-template-columns:minmax(120px,190px) minmax(0,1fr);gap:10px;padding:6px 0;border-top:1px solid var(--sc-border)}
  .row>span:first-child{color:var(--sc-muted);font-size:11px}
  .row>span:last-child{min-width:0;overflow-wrap:anywhere;font-size:11px}
  code{font-family:var(--vscode-editor-font-family,monospace);font-size:11px;padding:1px 5px;border-radius:var(--sc-radius-sm);background:var(--sc-surface-soft);overflow-wrap:anywhere}
  .delivery-list{list-style:none;padding:0;margin:8px 0 0;display:grid;gap:7px}
  .delivery-list li{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;padding:8px 10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface-soft)}
  .delivery-list small{grid-column:1/-1;color:var(--sc-muted)}
  .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}
  button{font:600 11px var(--vscode-font-family);border:1px solid var(--sc-primary);border-radius:var(--sc-radius-md);padding:7px 12px;cursor:pointer;color:var(--sc-primary-text);background:var(--sc-primary)}
  button:hover{background:var(--sc-primary-hover)}
  button.secondary{color:var(--sc-text);border-color:var(--sc-border);background:var(--sc-surface)}
  button.secondary:hover{background:var(--sc-surface-soft)}
  select,input{font:inherit;font-size:11px;min-width:0;padding:8px 10px;border-radius:var(--sc-radius-md);color:var(--sc-input-text);background:var(--sc-input-bg);border:1px solid var(--sc-input-border)}
  select:focus,input:focus{outline:none;border-color:var(--sc-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--sc-primary) 22%,transparent)}
  label{display:grid;gap:5px;font-size:11px;font-weight:700;color:var(--sc-text)}
  .delivery-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0 16px}
  .field{margin-top:13px;display:flex;flex-direction:column;gap:5px;min-width:0}
  .field label{display:flex;align-items:center;gap:8px}
  .field input[type="checkbox"]{width:15px;height:15px;min-width:15px;padding:0}
  .field small,summary{font-size:10px;color:var(--sc-muted)}
  .advanced{margin-top:10px}
  @media(max-width:640px){.row{grid-template-columns:1fr}.card-head{align-items:start;flex-direction:column}.delivery-fields{grid-template-columns:1fr}}`;
}

function renderDeliveryProviderPageHtml({
  model = {},
  providers = [],
  selectedProvider = '',
  selectedProviderDefinition = null,
  configuration = {},
  secretsConfigured = {}
} = {}, nonce = '', theme = 'light', assets = {}) {
  const cspSource = assets?.cspSource || '';
  const resolvedModel = withResolvedProviderAsset(model, assets);
  const selected = selectedProvider || resolvedModel.providerId || '';
  const provider = selectedProviderDefinition || providers.find((entry) => entry.id === selected) || null;
  const statusLabel = PAGE_STATUS_LABELS[resolvedModel.status] || resolvedModel.statusLabel || resolvedModel.status || 'Unknown';
  const providerLabel = resolvedModel.providerLabel || provider?.label || 'None';
  const fields = provider?.configurationFields || [];
  const fieldSchema = JSON.stringify(fields.map((field) => ({ id: field.id, type: field.type, secret: Boolean(field.secret) })));
  const canDisconnect = Boolean(resolvedModel.configured);
  const content = `
  <section class="delivery-head" aria-label="Delivery provider summary">
    <div class="delivery-head-tile"><span>Provider</span><strong>${escapeHtml(providerLabel || 'None')}</strong></div>
    <div class="delivery-head-tile"><span>Status</span><strong>${escapeHtml(statusLabel)}</strong></div>
  </section>
  ${renderProviderSelector(providers, selected)}
  ${renderProviderForm(provider, { configuration, secretsConfigured })}
  ${renderDeliverySections(resolvedModel) || `<section class="card muted"><div class="card-head"><h3>Security Delivery</h3><span class="state">${escapeHtml(statusLabel)}</span></div><p class="muted">${escapeHtml(resolvedModel.message || 'Select an implemented CI/CD provider to read delivery evidence.')}</p></section>`}`;

  return renderSecurityCenterShell({
    surface: 'delivery',
    nonce,
    theme,
    title: 'Security Delivery',
    subtitle: `Provider: ${escapeHtml(providerLabel || 'None')} · Status: ${escapeHtml(statusLabel)}`,
    headerActions: `<button data-action="deliveryRefresh">Refresh</button><button class="secondary" data-action="deliveryConfigure">Configure</button><button class="secondary" data-action="deliveryOpenSettings">Open integration settings</button>${canDisconnect ? '<button class="secondary" data-action="deliveryDisconnect">Disconnect provider</button>' : ''}`,
    content,
    contextRail: '',
    styles: deliveryPageCss(),
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();
  const fields=${fieldSchema};
  const field=id=>document.getElementById('delivery-'+id);
  const selected=()=>{const el=document.getElementById('delivery-provider');return el?el.value:'';};
  const config=()=>Object.fromEntries(fields.map(entry=>{
    const el=field(entry.id);
    return [entry.id,entry.type==='boolean'?Boolean(el&&el.checked):(el?el.value.trim():'')];
  }));
  const reveal=()=>{const el=document.querySelector('[data-section="provider-form"]');if(el){el.scrollIntoView({block:'nearest'});const input=el.querySelector('input,select');if(input)input.focus();}};
  document.querySelectorAll('[data-command]:not(.sc-nav-item)').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{
    const action=b.dataset.action;
    if(action==='deliveryConfigure'){reveal();return;}
    if(action==='deliverySelectProvider')return;
    if(action==='deliverySave'||action==='deliveryTest')return vscode.postMessage({type:'delivery',action,provider:selected(),config:config()});
    vscode.postMessage({type:'delivery',action,provider:selected()});
  });
  const providerSelect=document.getElementById('delivery-provider');
  if(providerSelect)providerSelect.onchange=()=>vscode.postMessage({type:'delivery',action:'deliverySelectProvider',provider:selected()});`,
    csp: `default-src 'none'; img-src ${cspSource || "'self'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`,
    brandLogoUri: assets?.brandLogoUri || ''
  });
}

module.exports = {
  renderDeliverySections,
  renderProviderSelector,
  renderProviderForm,
  renderDeliveryProviderPageHtml,
  renderConnectionSection,
  renderRunSection,
  renderListSection,
  renderSecurityReportSection,
  STATUS_CLASS,
  OUTCOME_CLASS,
  CAPABILITY_LABELS,
  RESOLVED_LABELS,
  PAGE_STATUS_LABELS,
  formatDuration,
  escapeHtml
};
