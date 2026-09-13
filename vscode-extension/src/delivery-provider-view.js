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

function formatTimestamp(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('fr-FR');
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

function providerLogoUri(provider, assets = {}) {
  const logos = assets?.providerLogoUris && typeof assets.providerLogoUris === 'object'
    ? assets.providerLogoUris
    : {};
  const candidate = logos[provider?.id] || logos[provider?.icon] || '';
  return isTrustedWebviewAssetUri(candidate, assets) ? String(candidate) : '';
}

function providerLogo(provider, assets = {}, className = 'provider-card-logo') {
  const uri = providerLogoUri(provider, assets);
  const label = escapeHtml(provider?.label || 'Provider');
  if (!uri) return `<span class="${escapeHtml(className)} provider-card-logo-fallback" aria-hidden="true">${escapeHtml(String(provider?.label || '?').slice(0, 1).toUpperCase())}</span>`;
  return `<span class="${escapeHtml(className)}"><img src="${escapeHtml(uri)}" alt="${label} logo" loading="lazy"></span>`;
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
${model.deployment ? row('Déploiement', value(model.deployment.reason ? `${model.deployment.status} — ${model.deployment.reason}` : model.deployment.status)) : ''}
${model.deployment?.healthCheck ? row('Health check', value(model.deployment.healthCheck.detail ? `${model.deployment.healthCheck.status} — ${model.deployment.healthCheck.detail}` : model.deployment.healthCheck.status)) : ''}
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
<p class="muted">Un verdict inconnu n’est pas un verdict favorable.</p>
${report?.ciEngine ? `<p class="muted" data-ci-engine="${escapeHtml(String(report.ciEngine.state || '').toLowerCase())}">${escapeHtml(report.ciEngine.label)}${report.ciEngine.reason ? ` — ${escapeHtml(report.ciEngine.reason)}` : ''}</p>` : ''}</section>`;
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
${report.verdict?.status ? row('Verdict CI', value(`${report.verdict.status} (code ${report.verdict.exitCode})`)) : ''}
${report.ciEngine ? row('CI Engine', value(report.ciEngine.version ? `${report.ciEngine.label} — ${report.ciEngine.version}${report.ciEngine.commit ? ` (build ${report.ciEngine.commit.slice(0, 12)})` : ''}` : `${report.ciEngine.label}${report.ciEngine.reason ? ` — ${report.ciEngine.reason}` : ''}`)) : ''}
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

/** États d'une carte du hub. Chacun décrit ce qui est réellement su. */
const HUB_STATE = Object.freeze({
  UNAVAILABLE: 'unavailable',
  UNCONFIGURED: 'unconfigured',
  CONFIGURED: 'configured',
  ACTIVE: 'active'
});

/**
 * L'état de chaque fournisseur pour le hub, sans rien inventer.
 *
 * Seul le fournisseur actif a été interrogé : lui seul porte un statut de
 * connexion réel. Un autre fournisseur configuré est annoncé « configuré », pas
 * « connecté » — l'affirmer sans appel serait une invention.
 */
function providerHubEntries(providers = [], { model = {}, activeProviderId = '', configurations = {} } = {}) {
  return providers.map((provider) => {
    const configuration = configurations[provider.id] || {};
    const configured = Object.values(configuration).some((entry) => String(entry ?? '').trim() !== '');
    const active = Boolean(provider.implemented) && provider.id === activeProviderId;
    const state = !provider.implemented ? HUB_STATE.UNAVAILABLE
      : active ? HUB_STATE.ACTIVE
        : configured ? HUB_STATE.CONFIGURED
          : HUB_STATE.UNCONFIGURED;
    return {
      id: provider.id,
      label: provider.label,
      summary: provider.summary || '',
      implemented: Boolean(provider.implemented),
      state,
      // Le libellé de pipeline/projet/dépôt configuré, quand il en existe un.
      pipeline: active ? (model.pipeline || '') : String(configuration.job || configuration.project || configuration.repository || ''),
      status: active ? (PAGE_STATUS_LABELS[model.status] || model.statusLabel || '') : '',
      statusClass: active ? (STATUS_CLASS[model.status] || 'muted') : '',
      lastSync: active ? formatTimestamp(model.fetchedAt) : '',
    };
  });
}

/**
 * Le hub : ce que Security Delivery montre en premier.
 *
 * Une carte ne porte que ce qui aide à décider : le fournisseur, son état, ce
 * qui est configuré, et l'action qui suit. La configuration, la connexion et les
 * preuves de livraison vivent désormais dans l'espace dédié du fournisseur —
 * elles étaient auparavant répétées trois fois sur la même page.
 */
function renderProviderHub(entries = [], assets = {}) {
  const implementedEntries = entries.filter((entry) => entry.state !== HUB_STATE.UNAVAILABLE);
  const unavailableEntries = entries.filter((entry) => entry.state === HUB_STATE.UNAVAILABLE);
  const implementedCards = implementedEntries.map((entry) => {
    const logo = providerLogo({ id: entry.id, label: entry.label }, assets, 'hub-card-logo');
    if (entry.state === HUB_STATE.UNCONFIGURED) {
      return `<article class="hub-card" data-provider-card="${escapeHtml(entry.id)}">
<div class="hub-card-head">${logo}<h3>${escapeHtml(entry.label)}</h3><span class="state muted">Non configuré</span></div>
<p class="hub-description">${escapeHtml(entry.summary)}</p>
<div class="hub-actions"><button class="secondary" data-action="deliveryConfigureSelected" data-provider="${escapeHtml(entry.id)}">Configurer</button></div></article>`;
    }
    const facts = [
      entry.pipeline ? `<div><span>Pipeline</span><strong>${escapeHtml(entry.pipeline)}</strong></div>` : '',
      entry.lastSync ? `<div><span>Dernière synchro</span><strong>${escapeHtml(entry.lastSync)}</strong></div>` : ''
    ].filter(Boolean).join('');
    const stateLabel = entry.state === HUB_STATE.ACTIVE ? (entry.status || 'Connecté') : 'Configuré';
    return `<article class="hub-card ${escapeHtml(entry.statusClass || '')}" data-provider-card="${escapeHtml(entry.id)}">
<div class="hub-card-head">${logo}<h3>${escapeHtml(entry.label)}</h3><span class="state">${escapeHtml(stateLabel)}</span></div>
<p class="hub-description">${escapeHtml(entry.summary)}</p>
${facts ? `<div class="hub-facts">${facts}</div>` : ''}
<div class="hub-actions"><button data-action="deliveryOpenWorkspace" data-provider="${escapeHtml(entry.id)}">Ouvrir</button><button class="secondary" data-action="deliveryConfigureSelected" data-provider="${escapeHtml(entry.id)}">Configurer</button></div></article>`;
  }).join('');
  const unavailableRows = unavailableEntries.map((entry) => {
    const logo = providerLogo({ id: entry.id, label: entry.label }, assets, 'hub-row-logo');
    return `<article class="hub-provider-row unavailable" data-provider-card="${escapeHtml(entry.id)}">
<div class="hub-provider-main">${logo}<div><h3>${escapeHtml(entry.label)}</h3><p>${escapeHtml(entry.summary)}</p></div></div>
<span class="state muted">Non disponible</span></article>`;
  }).join('');
  return `<section class="hub" aria-label="Fournisseurs CI/CD">
<section class="hub-section" aria-labelledby="delivery-available-title">
<div class="hub-section-head"><h2 id="delivery-available-title">CONNECTED / AVAILABLE</h2><span>${implementedEntries.length} providers</span></div>
<div class="hub-available-grid">${implementedCards}</div>
</section>
<section class="hub-section hub-section-other" aria-labelledby="delivery-other-title">
<div class="hub-section-head"><h2 id="delivery-other-title">OTHER PROVIDERS</h2><span>Adapter not available yet</span></div>
<div class="hub-provider-list">${unavailableRows}</div>
</section>
</section>`;
}

/**
 * L'espace dédié d'un fournisseur.
 *
 * Les sections rendues sont celles que l'adaptateur déclare, avec son propre
 * vocabulaire. Rien n'est ajouté : une donnée qu'aucun adaptateur ne rapporte
 * aujourd'hui — un historique d'exécutions, par exemple — n'a pas de section.
 */
function renderProviderWorkspace(model = {}, provider = null, { assets = {}, configuring = false, configuration = {}, secretsConfigured = {}, canDisconnect = false, workspacePanels = '' } = {}) {
  const statusLabel = PAGE_STATUS_LABELS[model.status] || model.statusLabel || model.status || 'Inconnu';
  const logo = providerLogo({ id: model.providerId || provider?.id, label: model.providerLabel || provider?.label }, assets, 'hub-card-logo');
  const header = `<section class="workspace-head ${escapeHtml(STATUS_CLASS[model.status] || 'muted')}" aria-label="État du fournisseur">
<div class="workspace-identity">${logo}<div><h2>${escapeHtml(model.providerLabel || provider?.label || 'Fournisseur')}</h2><p>${escapeHtml(model.target || 'Cible non configurée')}</p></div></div>
<div class="workspace-facts">
<div><span>Connexion</span><strong>${escapeHtml(statusLabel)}</strong></div>
<div><span>Pipeline</span><strong>${escapeHtml(model.pipeline || 'Non configuré')}</strong></div>
<div><span>Dernière synchro</span><strong>${escapeHtml(formatTimestamp(model.fetchedAt) || 'Jamais')}</strong></div>
</div></section>`;

  const actions = `<div class="workspace-actions">
<button data-action="deliveryRefresh">Actualiser</button>
${model.consoleUrl ? `<button class="secondary" data-action="deliveryOpenConsole">Ouvrir la console du fournisseur</button>` : ''}
<button class="secondary" data-action="deliveryConfigureSelected" data-provider="${escapeHtml(model.providerId || provider?.id || '')}">Configurer</button>
<button class="quiet-action" data-action="deliveryBackToHub">← Security Delivery</button>
</div>`;

  const form = configuring && provider
    ? renderProviderForm(provider, { configuration, secretsConfigured, assets, canDisconnect })
    : '';

  // Panels the caller adds to this workspace, rendered as given: the renderer
  // hosts them without knowing which provider they belong to.
  return `${header}${actions}${form}${workspacePanels || ''}${renderWorkspaceSections(model)}`;
}

/**
 * Les sections de l'espace dédié, dans le vocabulaire du fournisseur.
 *
 * La connexion n'y figure plus : elle est déjà dans l'en-tête, et la répéter
 * était l'une des trois duplications de l'ancienne page.
 */
function renderWorkspaceSections(model = {}) {
  const sections = Array.isArray(model.sections) ? model.sections : [];
  return sections.map((section) => {
    switch (section.kind) {
      case SECTION_KIND.CONNECTION:
        return '';
      case SECTION_KIND.RUN_SUMMARY:
        // Le titre vient de l'adaptateur : c'est lui qui porte le vocabulaire
        // natif du fournisseur — « Dernier pipeline » pour GitLab, « Jobs » pour
        // GitHub. Le renderer générique n'en connaît aucun.
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
function renderProviderSelector(providers = [], selectedId = '', assets = {}) {
  const options = providers.map((provider) => {
    const selected = provider.id === selectedId ? ' selected' : '';
    const suffix = provider.implemented ? '' : ' — adaptateur indisponible';
    return `<option value="${escapeHtml(provider.id)}"${selected}>${escapeHtml(provider.label)}${escapeHtml(suffix)}</option>`;
  }).join('');
  const cards = providers.map((provider) => {
    const selected = provider.id === selectedId;
    const unavailable = provider.implemented === false;
    const state = unavailable ? 'Adapter not available yet' : 'Implemented adapter';
    const attrs = unavailable
      ? ' disabled aria-disabled="true"'
      : ` data-provider-id="${escapeHtml(provider.id)}"`;
    return `<button type="button" class="provider-option${selected ? ' selected' : ''}${unavailable ? ' unavailable' : ''}"${attrs}>
      ${providerLogo(provider, assets)}
      <span class="provider-option-copy">
        <span class="provider-name">${escapeHtml(provider.label)}</span>
        <span class="provider-note">${escapeHtml(provider.summary || '')}</span>
        <span class="provider-state">${escapeHtml(state)}</span>
      </span>
    </button>`;
  }).join('');
  return `<section class="provider-catalogue-card" data-section="provider-selector">
<div class="catalogue-head"><span class="field-label">CI/CD provider</span><p>Choose the delivery system Security Center reads pipeline evidence from.</p></div>
<div class="provider-options">${cards}</div>
<label class="sr-only" for="delivery-provider">Delivery provider</label>
<select id="delivery-provider" data-action="deliverySelectProvider" aria-hidden="true" tabindex="-1">${options}</select>
</section>`;
}

/**
 * The configuration form of the selected provider.
 *
 * Built entirely from the declared schema. A secret field renders an empty
 * input and a note about what is already stored — its value is never emitted.
 */
function renderProviderForm(provider, { configuration = {}, secretsConfigured = {}, assets = {}, canDisconnect = false } = {}) {
  if (!provider) return '';
  if (!provider.implemented || !provider.configurationFields.length) {
    return `<section class="delivery-config-panel unavailable" data-section="provider-form">
<div class="config-provider-head">
${providerLogo(provider, assets, 'provider-head-logo')}
<div><span class="field-label">Catalogue-only provider</span><h3>${escapeHtml(provider.label)}</h3><p>${escapeHtml(provider.summary || '')}</p></div>
</div>
<div class="provider-unavailable">
  <strong>Adapter not available yet</strong>
  <p>Ce fournisseur est référencé mais aucun adaptateur n’est encore disponible. Security Center cannot test, save or read delivery evidence from it in this version.</p>
</div>
</section>`;
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
      : (entry.secret ? 'Stored in VS Code SecretStorage' : escapeHtml(entry.placeholder || ''));
    return `<div class="field${entry.secret ? ' secret-field' : ''}"><label for="delivery-${escapeHtml(entry.id)}">${escapeHtml(entry.label)}${entry.required ? ' *' : ''}</label>
<input id="delivery-${escapeHtml(entry.id)}" type="${escapeHtml(entry.type === 'password' ? 'password' : entry.type === 'url' ? 'url' : 'text')}" autocomplete="off" spellcheck="false"${attrValue ? ` value="${attrValue}"` : ''} placeholder="${placeholder}">
${entry.secret
  ? `<small class="${stored ? 'secret-stored' : 'secret-empty'}">${stored ? 'Stored in VS Code SecretStorage. Leave empty to keep it.' : 'Stored in VS Code SecretStorage. The value is never rendered back.'}</small>`
  : ''}
${entry.hint ? `<small>${escapeHtml(entry.hint)}</small>` : ''}</div>`;
  };
  const primaryFields = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.PRIMARY).filter((entry) => !entry.secret);
  const credentialFields = provider.configurationFields.filter((entry) => entry.secret);
  const advancedFields = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.ADVANCED).filter((entry) => !entry.secret);
  const primary = primaryFields.map(field).join('');
  const credentials = credentialFields.map(field).join('');
  const advanced = advancedFields.map(field).join('');
  return `<section class="delivery-config-panel" data-section="provider-form">
<div class="config-provider-head">
${providerLogo(provider, assets, 'provider-head-logo')}
<div class="provider-head-copy"><span class="field-label">Configuration</span><h3>${escapeHtml(provider.label)}</h3><p>${escapeHtml(provider.summary || `Connection details for ${provider.label}.`)}</p></div>
</div>
<div class="config-section">
  <span class="config-section-title">Connection</span>
  <div class="delivery-fields">${primary}</div>
</div>
${credentials ? `<div class="config-section credentials-section">
  <span class="config-section-title">Credentials</span>
  <div class="delivery-fields">${credentials}</div>
</div>` : ''}
${advanced ? `<details class="advanced"><summary><span>Advanced</span><small>Optional provider fields</small></summary><div class="delivery-fields">${advanced}</div></details>` : ''}
<div class="actions">
<button data-action="deliverySave">Save configuration</button>
<button class="secondary" data-action="deliveryTest">Test connection</button>
<button class="secondary" data-action="deliveryRefresh">Cancel</button>
${canDisconnect ? '<button class="secondary danger-action" data-action="deliveryDisconnect">Disconnect</button>' : ''}
</div></section>`;
}

function deliveryPageCss() {
  return `
  /* --------------------------------------------------- hub des fournisseurs
     Des cartes compactes : le fournisseur, son état, ce qui est configuré, et
     l'action qui suit. Tout le reste appartient à son espace dédié. */
  .hub{display:grid;gap:14px;margin-bottom:12px}
  .hub-section{display:grid;gap:7px}
  .hub-section-head{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:0 1px}
  .hub-section-head h2{margin:0;color:var(--sc-muted);font-size:10px;font-weight:850;letter-spacing:.75px;text-transform:uppercase}
  .hub-section-head span{color:var(--sc-muted);font-size:10px;font-weight:750}
  .hub-available-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;align-items:start}
  .hub-card{display:grid;gap:7px;padding:11px 12px;border:1px solid var(--sc-border);border-radius:10px;background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);min-width:0;align-content:start}
  .hub-card.ok{border-left:3px solid color-mix(in srgb,var(--sc-success) 46%,var(--sc-border))}
  .hub-card.bad{border-left:3px solid color-mix(in srgb,var(--sc-critical) 42%,var(--sc-border))}
  .hub-card.warn{border-left:3px solid color-mix(in srgb,var(--sc-primary) 42%,var(--sc-border))}
  .hub-card-head{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:9px;align-items:center;min-width:0}
  .hub-card-head h3{margin:0;font-size:13px;font-weight:800;color:var(--sc-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .hub-description{margin:0;color:var(--sc-muted);font-size:10.5px;line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .hub-card-logo{width:30px;height:30px;border:1px solid color-mix(in srgb,var(--sc-border) 82%,var(--sc-primary) 18%);border-radius:8px;display:grid;place-items:center;background:color-mix(in srgb,var(--sc-surface) 94%,var(--sc-primary) 6%);overflow:hidden}
  .hub-card-logo img{width:22px;height:22px;object-fit:contain}
  .hub-card-logo-fallback{font-weight:800;color:var(--sc-primary)}
  .hub-facts{display:flex;flex-wrap:wrap;gap:5px 12px;padding-top:2px}
  .hub-facts>div{display:grid;gap:1px;min-width:0}
  .hub-facts span{display:block;color:var(--sc-muted);font-size:8.5px;font-weight:850;letter-spacing:.45px;text-transform:uppercase}
  .hub-facts strong{display:block;font-size:11px;font-weight:800;color:var(--sc-text);overflow-wrap:anywhere}
  .hub-actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:2px;align-items:center}
  .hub-actions button{width:auto;min-height:28px;padding:5px 10px;border-radius:7px;font-size:10.5px;font-weight:750;line-height:1.1}
  .hub-actions button:not(.secondary){background:color-mix(in srgb,var(--sc-primary) 88%,var(--sc-surface) 12%);border-color:color-mix(in srgb,var(--sc-primary) 82%,var(--sc-border) 18%)}
  .hub-actions button:not(.secondary):hover{background:var(--sc-primary)}
  .hub-provider-list{display:grid;gap:6px;padding:8px;border:1px solid color-mix(in srgb,var(--sc-border) 72%,transparent);border-radius:10px;background:color-mix(in srgb,var(--sc-surface) 70%,transparent)}
  .hub-provider-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;min-width:0;padding:7px 9px;border:1px solid color-mix(in srgb,var(--sc-border) 72%,transparent);border-radius:8px;background:color-mix(in srgb,var(--sc-surface-soft) 58%,var(--sc-surface) 42%)}
  .hub-provider-main{display:grid;grid-template-columns:26px minmax(0,1fr);gap:9px;align-items:center;min-width:0}
  .hub-provider-main h3{margin:0;font-size:12px;font-weight:780;color:color-mix(in srgb,var(--sc-text) 82%,var(--sc-muted) 18%);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .hub-provider-main p{margin:2px 0 0;color:var(--sc-muted);font-size:10px;line-height:1.3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .hub-row-logo{width:26px;height:26px;border:1px solid color-mix(in srgb,var(--sc-border) 86%,transparent);border-radius:7px;display:grid;place-items:center;background:var(--sc-surface);overflow:hidden}
  .hub-row-logo img{width:19px;height:19px;object-fit:contain;opacity:.72}
  .hub-row-logo.provider-card-logo-fallback{font-size:11px;font-weight:800;color:var(--sc-muted)}
  @media(max-width:980px){.hub-available-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
  @media(max-width:640px){.hub-available-grid{grid-template-columns:1fr}.hub-provider-row{grid-template-columns:1fr}.hub-provider-row>.state{width:max-content}}

  /* ------------------------------------------------ espace dédié d'un fournisseur */
  .workspace-head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;align-items:center;padding:14px;margin-bottom:11px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm)}
  .workspace-head.ok{border-left:3px solid color-mix(in srgb,var(--sc-success) 46%,var(--sc-border))}
  .workspace-head.bad{border-left:3px solid color-mix(in srgb,var(--sc-critical) 42%,var(--sc-border))}
  .workspace-head.warn{border-left:3px solid color-mix(in srgb,var(--sc-primary) 42%,var(--sc-border))}
  .workspace-identity{display:grid;grid-template-columns:auto minmax(0,1fr);gap:11px;align-items:center;min-width:0}
  .workspace-identity h2{margin:0;font-size:18px;font-weight:800;letter-spacing:-.2px}
  .workspace-identity p{margin:2px 0 0;color:var(--sc-muted);font-size:11.5px;overflow-wrap:anywhere}
  .workspace-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:8px}
  .workspace-facts>div{padding:7px 10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:color-mix(in srgb,var(--sc-surface) 96%,var(--sc-primary) 4%);min-width:0}
  .workspace-facts span{display:block;color:var(--sc-muted);font-size:9px;font-weight:850;letter-spacing:.45px;text-transform:uppercase}
  .workspace-facts strong{display:block;margin-top:3px;font-size:13.5px;font-weight:800;color:var(--sc-text);overflow-wrap:anywhere}
  .workspace-actions{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px}
  .workspace-actions button{width:auto;min-height:0;padding:6px 12px;font-size:12px}
  @media (max-width:640px){.workspace-head{grid-template-columns:1fr}}

  .delivery-head{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:13px}
  .delivery-head-tile{border:1px solid var(--sc-border);border-left:3px solid color-mix(in srgb,var(--sc-primary) 44%,var(--sc-border));border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:12px 13px;display:grid;gap:5px;min-width:0}
  .delivery-head-tile span{color:var(--sc-muted);font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.6px}
  .delivery-head-tile strong{font-size:14px;color:var(--sc-text);overflow-wrap:anywhere}
  .delivery-workspace{display:grid;grid-template-columns:minmax(260px,.72fr) minmax(0,1.28fr);gap:13px;align-items:start;margin-bottom:13px}
  .provider-catalogue-card,.delivery-config-panel{border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:14px}
  .catalogue-head{display:grid;gap:4px;margin-bottom:10px}.catalogue-head p{margin:0;color:var(--sc-muted);font-size:11px;line-height:1.45}
  .field-label,.config-section-title{display:block;color:var(--sc-primary);font-size:9.5px;font-weight:850;letter-spacing:.7px;text-transform:uppercase}
  .provider-options{display:grid;gap:8px}
  .provider-option{width:100%;display:grid;grid-template-columns:38px minmax(0,1fr);gap:10px;align-items:center;padding:10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);color:var(--sc-text);background:color-mix(in srgb,var(--sc-surface) 96%,var(--sc-primary) 4%);text-align:left}
  .provider-option:hover:not(:disabled){border-color:color-mix(in srgb,var(--sc-primary) 42%,var(--sc-border));background:var(--sc-primary-soft)}
  .provider-option.selected{border-color:color-mix(in srgb,var(--sc-primary) 62%,var(--sc-border));box-shadow:0 0 0 1px color-mix(in srgb,var(--sc-primary) 18%,transparent);background:color-mix(in srgb,var(--sc-surface) 88%,var(--sc-primary) 12%)}
  .provider-option.unavailable{cursor:not-allowed;opacity:.72;background:var(--sc-surface)}
  .provider-card-logo,.provider-head-logo{display:grid;place-items:center;flex:none;border:1px solid color-mix(in srgb,var(--sc-border) 82%,var(--sc-primary) 18%);border-radius:9px;background:var(--sc-surface);overflow:hidden}
  .provider-card-logo{width:36px;height:36px}.provider-head-logo{width:42px;height:42px}
  .provider-card-logo img,.provider-head-logo img{display:block;max-width:74%;max-height:74%;object-fit:contain}
  .provider-card-logo-fallback{font-weight:850;color:var(--sc-primary)}
  .provider-option-copy{display:grid;gap:2px;min-width:0}.provider-name{font-size:12px;font-weight:800;color:var(--sc-text)}
  .provider-note{font-size:10px;color:var(--sc-muted);line-height:1.35;overflow-wrap:anywhere}.provider-state{font-size:9px;font-weight:800;color:var(--sc-muted);text-transform:uppercase;letter-spacing:.45px}
  .provider-option:not(.unavailable) .provider-state{color:var(--sc-success)}
  #delivery-provider{position:absolute;inline-size:1px;block-size:1px;opacity:0;pointer-events:none}
  .config-provider-head{display:grid;grid-template-columns:auto minmax(0,1fr);gap:11px;align-items:start;margin-bottom:13px}
  .provider-head-copy{display:grid;gap:3px}.provider-head-copy p{margin:0;color:var(--sc-muted);font-size:11px;line-height:1.45}
  .delivery-config-panel h3{margin:0;font-size:16px}.config-section{display:grid;gap:8px;margin-top:12px}
  .credentials-section{padding-top:11px;border-top:1px solid var(--sc-border)}
  .provider-unavailable{display:grid;gap:5px;padding:12px;border:1px solid color-mix(in srgb,var(--sc-warning) 32%,var(--sc-border));border-radius:var(--sc-radius-md);background:var(--sc-warning-bg)}
  .provider-unavailable strong{color:var(--sc-warning)}.provider-unavailable p{margin:0;color:var(--sc-text);font-size:11px;line-height:1.45}
  .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
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
  button.danger-action{color:var(--sc-danger);border-color:color-mix(in srgb,var(--sc-danger) 34%,var(--sc-border));background:color-mix(in srgb,var(--sc-danger) 8%,var(--sc-surface))}
  button.danger-action:hover{background:color-mix(in srgb,var(--sc-danger) 12%,var(--sc-surface))}
  button:disabled{cursor:not-allowed}
  select,input{font:inherit;font-size:11px;min-width:0;padding:8px 10px;border-radius:var(--sc-radius-md);color:var(--sc-input-text);background:var(--sc-input-bg);border:1px solid var(--sc-input-border)}
  select:focus,input:focus{outline:none;border-color:var(--sc-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--sc-primary) 22%,transparent)}
  label{display:grid;gap:5px;font-size:11px;font-weight:700;color:var(--sc-text)}
  .delivery-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0 16px}
  .field{margin-top:13px;display:flex;flex-direction:column;gap:5px;min-width:0}
  .field label{display:flex;align-items:center;gap:8px}
  .field input[type="checkbox"]{width:15px;height:15px;min-width:15px;padding:0}
  .field small,summary{font-size:10px;color:var(--sc-muted)}
  .secret-stored{color:var(--sc-success)!important}.secret-empty{color:var(--sc-muted)}
  .advanced{margin-top:12px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);padding:0;background:color-mix(in srgb,var(--sc-surface) 96%,var(--sc-primary) 4%)}
  .advanced summary{display:flex;justify-content:space-between;gap:12px;align-items:center;cursor:pointer;padding:9px 10px;font-weight:800;color:var(--sc-text)}
  .advanced summary small{font-weight:600;color:var(--sc-muted)}.advanced .delivery-fields{padding:0 10px 10px}
  .workspace-panel{margin-top:12px}
  .panel-status{list-style:none;margin:12px 0 0;padding:0;display:grid;gap:6px}
  .panel-step{display:flex;flex-wrap:wrap;gap:6px;align-items:baseline;padding:7px 10px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md)}
  .panel-step small{flex-basis:100%;color:var(--sc-muted)}
  .panel-step.ready span{color:var(--sc-success);font-weight:700}.panel-step.failed span{color:var(--sc-danger,#c62828);font-weight:700}
  .panel-step.skipped span,.panel-step.pending span{color:var(--sc-muted)}
  .panel-checked{display:block;margin-top:6px;color:var(--sc-muted)}
  @media(max-width:980px){.delivery-workspace{grid-template-columns:1fr}}
  @media(max-width:640px){.row{grid-template-columns:1fr}.card-head{align-items:start;flex-direction:column}.delivery-fields{grid-template-columns:1fr}}`;
}

function renderDeliveryProviderPageHtml({
  model = {},
  providers = [],
  selectedProvider = '',
  selectedProviderDefinition = null,
  configuration = {},
  secretsConfigured = {},
  // Purement présentationnel : quelle vue est affichée, et si le formulaire est
  // ouvert. Aucun contrat d'adaptateur ni identifiant de commande n'en dépend.
  view = 'hub',
  configuring = false,
  activeProvider = '',
  configurations = {},
  workspacePanels = ''
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
  // Maître/détail : le hub liste les fournisseurs, l'espace dédié en montre un
  // seul. Une même page ne mélange plus sélection, configuration, connexion et
  // preuves de livraison.
  const workspaceView = view === 'provider' && provider?.implemented;
  const content = workspaceView
    ? renderProviderWorkspace(resolvedModel, provider, { assets, configuring, configuration, secretsConfigured, canDisconnect, workspacePanels })
    : `${renderProviderHub(providerHubEntries(providers, { model: resolvedModel, activeProviderId: activeProvider, configurations }), assets)}
  ${configuring && provider?.implemented ? `<section class="delivery-workspace" aria-label="Configuration du fournisseur">${renderProviderForm(provider, { configuration, secretsConfigured, assets, canDisconnect })}</section>` : ''}`;

  return renderSecurityCenterShell({
    surface: 'delivery',
    nonce,
    theme,
    title: 'Security Delivery',
    subtitle: workspaceView
      ? `${escapeHtml(providerLabel)} · ${escapeHtml(statusLabel)}`
      : 'Fournisseurs CI/CD, configuration et espaces dédiés',
    headerActions: workspaceView
      ? `<button data-action="deliveryTest">Tester la connexion</button><button class="secondary" data-action="deliveryOpenSettings">Paramètres d’intégration</button>${canDisconnect ? '<button class="secondary" data-action="deliveryDisconnect">Déconnecter</button>' : ''}`
      : `<button data-action="deliveryRefresh">Actualiser</button><button class="secondary" data-action="deliveryOpenSettings">Paramètres d’intégration</button>`,
    content,
    contextRail: '',
    styles: deliveryPageCss(),
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();
  const fields=${fieldSchema};
  const field=id=>document.getElementById('delivery-'+id);
  const selected=()=>{const el=document.getElementById('delivery-provider');return el?el.value:'';};
  const selectProvider=id=>{const el=document.getElementById('delivery-provider');if(el)el.value=id;vscode.postMessage({type:'delivery',action:'deliverySelectProvider',provider:id});};
  const config=()=>Object.fromEntries(fields.map(entry=>{
    const el=field(entry.id);
    return [entry.id,entry.type==='boolean'?Boolean(el&&el.checked):(el?el.value.trim():'')];
  }));
  const reveal=()=>{const el=document.querySelector('[data-section="provider-form"]');if(el){el.scrollIntoView({block:'nearest'});const input=el.querySelector('input,select');if(input)input.focus();}};
  document.querySelectorAll('[data-command]:not(.sc-nav-item)').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  document.querySelectorAll('.provider-option[data-provider-id]').forEach(b=>b.onclick=()=>selectProvider(b.dataset.providerId));
  document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{
    const action=b.dataset.action;
    if(action==='deliveryConfigure'){reveal();return;}
    if(action==='deliverySelectProvider')return;
    if(action==='deliveryOpenWorkspace'||action==='deliveryConfigureSelected')return vscode.postMessage({type:'delivery',action,provider:b.dataset.provider||selected()});
    if(action==='deliveryBackToHub')return vscode.postMessage({type:'delivery',action});
    const panel=b.closest('[data-panel]');
    if(panel)return vscode.postMessage({type:'delivery',action,panel:panel.dataset.panel,values:Object.fromEntries([...panel.querySelectorAll('[data-panel-field]')].map(el=>[el.dataset.panelField,el.value.trim()]))});
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
  renderProviderHub,
  renderProviderWorkspace,
  providerHubEntries,
  HUB_STATE,
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
