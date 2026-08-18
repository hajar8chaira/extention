'use strict';

/**
 * Dynamic Security workspace — the integration layer.
 *
 * Joins the P1 modules to the product: it turns the canonical transactions, the
 * ZAP campaign lifecycle, the Burp session and the retest records into one model,
 * renders the sections the Dynamic Security page embeds, and defines exactly what
 * gets persisted.
 *
 * It computes no security logic of its own. The inventory comes from
 * `dynamic-inventory`, the verdicts from `dynamic-retest`, the profiles from
 * `dynamic-auth`, the association from `dashboard`. This file decides *what
 * counts as evidence* and *what is safe to write down* — nothing else.
 *
 * The evidence rule is the delicate part. A completed ZAP scan does not prove
 * anything about a particular endpoint: coverage is raised per endpoint, from an
 * alert ZAP actually reported against it, and never from a global status.
 */

const { buildApiInventory, summarizeCoverage, COVERAGE_STATE, COVERAGE_LABELS, ENDPOINT_SOURCE } = require('./dynamic-inventory');
const { RETEST_STATE, RETEST_LABELS, REASON_LABELS } = require('./dynamic-retest');
const { AUTH_STATUS, AUTH_STATUS_LABELS, authenticatedCoverageClaim, publicProfile } = require('./dynamic-auth');
const { CAPTURE_STATE } = require('./dynamic-campaign');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

/**
 * ZAP plugin id ranges, used to tell a passive alert from an active one.
 *
 * ZAP numbers its passive scanners in the 10000s and its active scanners in the
 * 40000s and 90000s. This is a convention of the tool, not a guarantee, so an
 * unrecognised id yields the *weaker* state rather than the stronger one.
 */
const ZAP_ACTIVE_RANGES = Object.freeze([[40000, 49999], [90000, 99999]]);
const ZAP_PASSIVE_RANGES = Object.freeze([[10000, 19999], [2, 9999]]);

function inRanges(value, ranges) {
  const id = Number(value);
  if (!Number.isFinite(id)) return false;
  return ranges.some(([low, high]) => id >= low && id <= high);
}

/**
 * Endpoint-level coverage evidence, derived from what really happened.
 *
 * Returns endpoint keys per state. A key only appears when there is evidence for
 * that endpoint specifically — this is what stops a finished global scan from
 * marking an entire inventory as actively tested.
 */
function coverageEvidenceFrom({ findings = [], replayRecords = [], campaign = null } = {}) {
  const activelyTested = new Set();
  const passivelyAnalyzed = new Set();
  const replayed = new Set();

  for (const finding of Array.isArray(findings) ? findings : []) {
    if (String(finding?.tool || '').toUpperCase() !== 'ZAP') continue;
    const key = endpointKeyOf(finding.method, finding.endpoint);
    if (!key) continue;
    // An alert is proof ZAP looked at this endpoint. Which kind of look it was
    // comes from the plugin family, and an unknown family counts as passive.
    if (inRanges(finding.ruleId, ZAP_ACTIVE_RANGES)) activelyTested.add(key);
    else if (inRanges(finding.ruleId, ZAP_PASSIVE_RANGES)) passivelyAnalyzed.add(key);
    else passivelyAnalyzed.add(key);
  }

  for (const record of Array.isArray(replayRecords) ? replayRecords : []) {
    const key = endpointKeyOf(record?.method, record?.endpoint || record?.url);
    if (key) replayed.add(key);
  }

  return {
    activelyTested: [...activelyTested].sort(),
    passivelyAnalyzed: [...passivelyAnalyzed].sort(),
    replayed: [...replayed].sort(),
    // Recorded so the UI can explain *why* coverage is what it is, and say when
    // no endpoint-level evidence existed at all.
    zapRan: Boolean(campaign && campaign.source === 'zap' && campaign.completedAt),
    endpointLevelEvidence: activelyTested.size + passivelyAnalyzed.size > 0
  };
}

/**
 * The endpoint key a finding or replay refers to.
 *
 * Uses the same shape as the inventory keys, including the identifier templating,
 * so evidence lands on the endpoint the inventory actually holds.
 */
function endpointKeyOf(method, endpoint) {
  const { templatePath } = require('./dynamic-inventory');
  const { endpointPath } = require('./dashboard');
  if (!endpoint) return '';
  const verb = String(method || '').toUpperCase();
  // A finding whose method ZAP never reported cannot be attributed to one verb.
  if (!verb || verb === 'HTTP') return '';
  return `${verb} ${templatePath(endpointPath(endpoint)).template}`;
}

/**
 * The whole Dynamic Security workspace model.
 *
 * Pure: everything it needs is passed in. `transactions` are canonical
 * `DynamicTransaction` objects — the raw scenario shape is accepted too, but the
 * canonical one is what the product feeds it.
 */
function buildDynamicWorkspace({
  transactions = [], findings = [], campaign = null, burpSession = null,
  openapiEndpoints = [], replayRecords = [], retests = [], authProfile = null,
  authValidated = false, targetUrl = ''
} = {}) {
  const evidence = coverageEvidenceFrom({ findings, replayRecords, campaign });
  const inventory = buildApiInventory({
    transactions, findings, openapiEndpoints,
    activelyTested: evidence.activelyTested,
    passivelyAnalyzed: evidence.passivelyAnalyzed,
    replayed: evidence.replayed
  });
  const coverage = summarizeCoverage(inventory);
  const protectedReached = inventory.filter((endpoint) => endpoint.authenticated
    && endpoint.coverage !== COVERAGE_STATE.NOT_TESTED).length;
  return {
    targetUrl: String(targetUrl || ''),
    campaignId: campaign?.id || null,
    campaignStatus: campaign?.status || null,
    campaignRestored: campaign?.restored === true,
    burpSession,
    inventory,
    coverage,
    evidence,
    // `coverageEvaluated` is false when nothing was ever analysed. The UI must
    // say « non évaluée » rather than « 0 testé », which reads as a result.
    coverageEvaluated: inventory.length > 0,
    auth: authProfile ? publicProfile(authProfile) : null,
    authClaim: authenticatedCoverageClaim({
      profile: authProfile, validated: authValidated, protectedEndpointsReached: protectedReached
    }),
    retests: (Array.isArray(retests) ? retests : []).map((record) => ({
      findingId: String(record?.findingId || ''),
      endpoint: String(record?.endpoint || ''),
      method: String(record?.method || ''),
      title: String(record?.title || ''),
      state: RETEST_STATE[record?.state] ? record.state : RETEST_STATE.FOUND,
      reason: String(record?.verdict?.reason || record?.reason || ''),
      at: record?.verdict?.evidence?.at || null,
      previousStatus: record?.verdict?.evidence?.previous?.status ?? null,
      replayStatus: record?.verdict?.comparison?.status?.replay ?? null,
      comparison: record?.verdict?.comparison || null
    }))
  };
}

/**
 * What gets persisted, and nothing more.
 *
 * Auth metadata only — never a secret, never a header value. Response previews
 * are dropped from retest comparisons before writing: a preview is for looking at
 * once, not for storing in a workspace cache that gets copied around.
 */
function dynamicWorkspaceState(model) {
  return {
    campaignId: model?.campaignId || null,
    savedAt: new Date().toISOString(),
    inventory: (model?.inventory || []).map((endpoint) => ({
      key: endpoint.key, method: endpoint.method, host: endpoint.host, template: endpoint.template,
      concretePaths: endpoint.concretePaths, queryParameters: endpoint.queryParameters,
      contentTypes: endpoint.contentTypes, sources: endpoint.sources,
      authenticated: endpoint.authenticated, authenticatedRequests: endpoint.authenticatedRequests,
      requestCount: endpoint.requestCount, firstSeen: endpoint.firstSeen, lastSeen: endpoint.lastSeen,
      lastStatusCode: endpoint.lastStatusCode, findingIds: endpoint.findingIds,
      findingCount: endpoint.findingCount, coverage: endpoint.coverage, normalization: endpoint.normalization
    })),
    targetUrl: model?.targetUrl || '',
    campaignStatus: model?.campaignStatus || null,
    coverage: model?.coverage || null,
    evidence: model?.evidence || null,
    // Metadata only: id, kind, header name, status. The secret stays in
    // SecretStorage and `publicProfile` already guarantees it is absent.
    auth: model?.auth || null,
    retests: (model?.retests || []).map((record) => ({
      findingId: record.findingId, endpoint: record.endpoint, method: record.method,
      title: record.title, state: record.state, reason: record.reason, at: record.at,
      previousStatus: record.previousStatus, replayStatus: record.replayStatus
      // `comparison` is deliberately not persisted: it carries previews.
    }))
  };
}

/**
 * Restores persisted state.
 *
 * Marks itself `restored` so no surface can present an old inventory as live
 * capture. An unrecognisable payload returns `null` rather than a half object.
 */
function restoreDynamicWorkspaceState(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (!Array.isArray(raw.inventory)) return null;
  // Each entry is completed to the shape the renderer reads. A cache written by
  // an older version — or truncated — must render as an incomplete row, not
  // throw halfway through the page.
  const inventory = raw.inventory
    .filter((endpoint) => endpoint && endpoint.key)
    .map((endpoint) => ({
      ...endpoint,
      method: String(endpoint.method || ''),
      template: String(endpoint.template || endpoint.key || ''),
      concretePaths: Array.isArray(endpoint.concretePaths) ? endpoint.concretePaths : [],
      queryParameters: Array.isArray(endpoint.queryParameters) ? endpoint.queryParameters : [],
      contentTypes: Array.isArray(endpoint.contentTypes) ? endpoint.contentTypes : [],
      sources: Array.isArray(endpoint.sources) ? endpoint.sources : [],
      findingIds: Array.isArray(endpoint.findingIds) ? endpoint.findingIds : [],
      findingCount: Number.isFinite(endpoint.findingCount) ? endpoint.findingCount : 0,
      requestCount: Number.isFinite(endpoint.requestCount) ? endpoint.requestCount : 0,
      authenticated: endpoint.authenticated === true,
      coverage: COVERAGE_STATE[endpoint.coverage] ? endpoint.coverage : COVERAGE_STATE.NOT_TESTED
    }));
  const auth = raw.auth && typeof raw.auth === 'object' ? raw.auth : null;
  return {
    targetUrl: String(raw.targetUrl || ''),
    campaignId: raw.campaignId || null,
    campaignStatus: raw.campaignStatus || null,
    campaignRestored: true,
    burpSession: null,
    savedAt: raw.savedAt || null,
    inventory,
    // Recomputed from the restored inventory rather than trusted from the cache:
    // it is a pure projection of endpoints we just validated, so it cannot
    // reintroduce a coverage number the endpoints do not support.
    coverage: summarizeCoverage(inventory),
    evidence: raw.evidence && typeof raw.evidence === 'object' ? raw.evidence : null,
    coverageEvaluated: inventory.length > 0,
    auth,
    // A restored profile is metadata about a past run. Its validation is not
    // reasserted here, so no restored state can claim an authenticated scan.
    authClaim: authenticatedCoverageClaim({
      profile: auth, validated: false,
      protectedEndpointsReached: inventory.filter((endpoint) => endpoint.authenticated
        && endpoint.coverage !== COVERAGE_STATE.NOT_TESTED).length
    }),
    retests: (Array.isArray(raw.retests) ? raw.retests : [])
      .filter((record) => record && record.findingId)
      .map((record) => ({ ...record, comparison: null })),
    restored: true
  };
}

// ---------------------------------------------------------------- rendering

function metric(label, value, hint = '') {
  return `<div class="dyn-metric"><span>${escapeHtml(label)}</span><strong>${value}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</div>`;
}

/** A value the product does not have is named, never rendered as zero. */
function known(value, { suffix = '' } = {}) {
  return Number.isFinite(value) ? `${value}${suffix}` : '<span class="dyn-muted">Non évalué</span>';
}

function renderOverview(model) {
  const coverage = model.coverage;
  const evaluated = model.coverageEvaluated;
  return `<section class="dynamic-section" id="dyn-overview">
      <div class="dynamic-section-head"><h2>Vue d’ensemble</h2>
      ${model.campaignRestored ? '<span class="status">Dernière campagne enregistrée</span>' : model.campaignId ? '<span class="status">Campagne en cours</span>' : ''}</div>
      ${model.restored ? `<p class="dyn-restored">État restauré depuis le dernier scan enregistré${model.savedAt ? ` (${escapeHtml(model.savedAt)})` : ''}. Ce n’est pas une mesure en direct : relancez une analyse pour réévaluer la couverture.</p>` : ''}
      <dl class="dyn-facts">
        <div><dt>Cible</dt><dd>${model.targetUrl ? escapeHtml(model.targetUrl) : '<span class="dyn-muted">Aucune cible configurée</span>'}</dd></div>
        <div><dt>Campagne</dt><dd>${model.campaignId ? `<code>${escapeHtml(model.campaignId)}</code>${model.campaignStatus ? ` · ${escapeHtml(model.campaignStatus)}` : ''}` : '<span class="dyn-muted">Aucune campagne dynamique</span>'}</dd></div>
      </dl>
      <div class="dyn-metrics">
        ${metric('Endpoints découverts', evaluated ? coverage.total : known(NaN))}
        ${metric('Observés', evaluated ? coverage.observed : known(NaN))}
        ${metric('Testés', evaluated ? coverage.tested : known(NaN))}
        ${metric('Testés activement', evaluated ? coverage.activelyTested : known(NaN))}
        ${metric('Authentifiés', evaluated ? coverage.authenticated : known(NaN))}
        ${metric('Avec findings', evaluated ? coverage.withFindings : known(NaN))}
        ${metric('Couverture', evaluated ? `${coverage.coveragePercent} %` : known(NaN), evaluated ? 'part des endpoints réellement testés' : '')}
      </div>
      ${evaluated ? '' : '<p class="dyn-empty">Aucun endpoint découvert : lancez une analyse ZAP ou capturez du trafic avec Burp pour alimenter l’inventaire.</p>'}
    </section>`;
}

function renderInventory(model) {
  if (!model.inventory.length) {
    return `<section class="dynamic-section" id="dyn-inventory"><div class="dynamic-section-head"><h2>Inventaire d’API</h2></div>
      <p class="dyn-empty">Aucun endpoint découvert. L’inventaire se construit à partir du trafic capturé, des alertes ZAP, d’un import HAR ou d’une spécification OpenAPI.</p></section>`;
  }
  const rows = model.inventory.map((endpoint, index) => `<tr data-endpoint-index="${index}"
      data-method="${escapeHtml(endpoint.method)}" data-coverage="${escapeHtml(endpoint.coverage)}"
      data-auth="${endpoint.authenticated ? '1' : '0'}" data-findings="${endpoint.findingCount ? '1' : '0'}"
      data-sources="${escapeHtml(endpoint.sources.join(','))}"
      data-search="${escapeHtml(`${endpoint.method} ${endpoint.template} ${endpoint.sources.join(' ')}`.toLowerCase())}">
      <td><span class="dyn-method">${escapeHtml(endpoint.method)}</span></td>
      <td><code>${escapeHtml(endpoint.template)}</code>${endpoint.normalization === 'HIGH' ? '<small class="dyn-muted"> route normalisée</small>' : ''}</td>
      <td>${endpoint.concretePaths.length || '<span class="dyn-muted">—</span>'}</td>
      <td>${escapeHtml(endpoint.sources.join(', ')) || '<span class="dyn-muted">—</span>'}</td>
      <td>${endpoint.authenticated ? 'Oui' : '<span class="dyn-muted">Non</span>'}</td>
      <td><span class="dyn-coverage dyn-${escapeHtml(endpoint.coverage.toLowerCase())}">${escapeHtml(COVERAGE_LABELS[endpoint.coverage] || endpoint.coverage)}</span></td>
      <td>${endpoint.findingCount || '<span class="dyn-muted">0</span>'}</td>
      <td>${endpoint.lastStatusCode ?? '<span class="dyn-muted">—</span>'}</td>
      <td>${endpoint.lastSeen ? escapeHtml(new Date(endpoint.lastSeen).toLocaleString('fr-FR')) : '<span class="dyn-muted">—</span>'}</td>
    </tr>`).join('');
  return `<section class="dynamic-section" id="dyn-inventory">
      <div class="dynamic-section-head"><h2>Inventaire d’API</h2><span class="status">${model.inventory.length} endpoint(s)</span></div>
      <div class="dyn-filters">
        <input type="search" id="dyn-search" placeholder="Rechercher une route…" aria-label="Rechercher un endpoint">
        <select id="dyn-filter-method" aria-label="Filtrer par méthode"><option value="">Toutes les méthodes</option>${[...new Set(model.inventory.map((endpoint) => endpoint.method))].sort().map((method) => `<option value="${escapeHtml(method)}">${escapeHtml(method)}</option>`).join('')}</select>
        <select id="dyn-filter-coverage" aria-label="Filtrer par couverture"><option value="">Toute couverture</option>${Object.keys(COVERAGE_LABELS).map((state) => `<option value="${escapeHtml(state)}">${escapeHtml(COVERAGE_LABELS[state])}</option>`).join('')}</select>
        <select id="dyn-filter-source" aria-label="Filtrer par source"><option value="">Toutes les sources</option>${Object.values(ENDPOINT_SOURCE).map((source) => `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`).join('')}</select>
        <label><input type="checkbox" id="dyn-filter-auth"> Authentifiés</label>
        <label><input type="checkbox" id="dyn-filter-findings"> Avec findings</label>
      </div>
      <div class="dyn-table-scroll"><table class="dyn-table"><thead><tr>
        <th>Méthode</th><th>Route</th><th>Chemins</th><th>Sources</th><th>Auth</th><th>Couverture</th><th>Findings</th><th>Statut</th><th>Dernière vue</th>
      </tr></thead><tbody id="dyn-inventory-body">${rows}</tbody></table></div>
      <p class="dyn-empty" id="dyn-inventory-empty" hidden>Aucun endpoint ne correspond aux filtres.</p>
    </section>`;
}

function renderCoverage(model) {
  const coverage = model.coverage;
  if (!model.coverageEvaluated) {
    return `<section class="dynamic-section" id="dyn-coverage"><div class="dynamic-section-head"><h2>Couverture dynamique</h2><span class="status">Non évaluée</span></div>
      <p class="dyn-empty">Aucune couverture n’a été évaluée : il n’y a pas encore d’endpoint découvert.</p></section>`;
  }
  const claim = model.authClaim;
  return `<section class="dynamic-section" id="dyn-coverage">
      <div class="dynamic-section-head"><h2>Couverture dynamique</h2><span class="status">${coverage.coveragePercent} % testés</span></div>
      <div class="dyn-metrics">
        ${metric('Observés — non testés', coverage.byState.OBSERVED)}
        ${metric('Analysés passivement', coverage.passivelyAnalyzed)}
        ${metric('Rejoués', coverage.replayed)}
        ${metric('Testés activement', coverage.activelyTested)}
        ${metric('Jamais atteints', coverage.notReached)}
      </div>
      <p class="dyn-note">Apparaître dans le trafic d’un proxy établit qu’un endpoint existe, pas qu’un test de sécurité l’a visé. « Observé » n’est donc jamais compté comme testé.</p>
      ${model.evidence && !model.evidence.endpointLevelEvidence && model.evidence.zapRan
    ? '<p class="dyn-note">Une analyse ZAP a été exécutée mais n’a produit aucune preuve par endpoint : la couverture reste à l’état le plus faible plutôt que d’être présumée.</p>' : ''}
      <h3 class="dyn-subhead">Couverture authentifiée</h3>
      <dl class="dyn-facts">
        <div><dt>Identifiants configurés</dt><dd>${model.auth?.secretConfigured ? 'Oui' : '<span class="dyn-muted">Non</span>'}</dd></div>
        <div><dt>Session validée</dt><dd>${model.auth?.status === AUTH_STATUS.VALID ? 'Oui' : '<span class="dyn-muted">Non</span>'}</dd></div>
        <div><dt>Endpoints protégés testés</dt><dd>${coverage.authenticated}</dd></div>
        <div><dt>Scan authentifié</dt><dd>${claim.authenticated ? 'Oui' : '<span class="dyn-muted">Non revendiqué</span>'}</dd></div>
      </dl>
      <p class="dyn-note">${escapeHtml(claim.reason)}</p>
    </section>`;
}

function renderAuthentication(model) {
  const auth = model.auth;
  return `<section class="dynamic-section" id="dyn-auth">
      <div class="dynamic-section-head"><h2>Authentification</h2>
      <span class="status">${escapeHtml(auth ? auth.statusLabel : AUTH_STATUS_LABELS.NOT_CONFIGURED)}</span></div>
      ${auth ? `<dl class="dyn-facts">
        <div><dt>Profil</dt><dd>${escapeHtml(auth.label)} <code>${escapeHtml(auth.id)}</code></dd></div>
        <div><dt>Type</dt><dd>${escapeHtml(auth.kind)}${auth.header ? ` · en-tête <code>${escapeHtml(auth.header)}</code>` : ''}</dd></div>
        <div><dt>Secret</dt><dd>${auth.secretConfigured ? `Conservé dans le SecretStorage · ${escapeHtml(auth.maskedValue || 'configuré')}` : '<span class="dyn-muted">Aucun secret enregistré</span>'}</dd></div>
        <div><dt>Dernière validation</dt><dd>${auth.lastValidatedAt ? escapeHtml(new Date(auth.lastValidatedAt).toLocaleString('fr-FR')) : '<span class="dyn-muted">Jamais validée</span>'}</dd></div>
      </dl>
      <p class="dyn-note">Le secret n’est jamais réaffiché, ni écrit dans les réglages, l’historique, le cache ou un rapport.</p>`
    : '<p class="dyn-empty">Aucun profil d’authentification. Un scan dynamique sans profil est anonyme et n’atteindra pas les endpoints protégés.</p>'}
      <div class="dynamic-actions">
        <button class="secondary" data-command="securityCenter.configureDynamicAuth">${auth ? 'Modifier le profil' : 'Créer un profil'}</button>
        ${auth ? '<button class="secondary" data-command="securityCenter.validateDynamicAuth">Valider la session</button>' : ''}
        ${auth ? '<button class="quiet-action" data-command="securityCenter.removeDynamicAuth">Supprimer le profil</button>' : ''}
      </div>
    </section>`;
}

function renderRetests(model) {
  if (!model.retests.length) {
    return `<section class="dynamic-section" id="dyn-retests"><div class="dynamic-section-head"><h2>Re-tests</h2></div>
      <p class="dyn-empty">Aucun re-test. Depuis un finding dynamique, « Re-tester ce finding » rejoue la requête d’origine et compare la condition de sécurité.</p></section>`;
  }
  const rows = model.retests.map((record) => `<tr>
      <td><span class="dyn-method">${escapeHtml(record.method || '—')}</span></td>
      <td><code>${escapeHtml(record.endpoint)}</code><br><small>${escapeHtml(record.title)}</small></td>
      <td><span class="dyn-retest dyn-${escapeHtml(record.state.toLowerCase())}">${escapeHtml(RETEST_LABELS[record.state] || record.state)}</span></td>
      <td>${escapeHtml(REASON_LABELS[record.reason] || record.reason || '—')}</td>
      <td>${record.previousStatus ?? '<span class="dyn-muted">—</span>'} → ${record.replayStatus ?? '<span class="dyn-muted">—</span>'}</td>
      <td>${record.at ? escapeHtml(new Date(record.at).toLocaleString('fr-FR')) : '<span class="dyn-muted">—</span>'}</td>
    </tr>`).join('');
  return `<section class="dynamic-section" id="dyn-retests">
      <div class="dynamic-section-head"><h2>Re-tests</h2><span class="status">${model.retests.length}</span></div>
      <div class="dyn-table-scroll"><table class="dyn-table"><thead><tr>
        <th>Méthode</th><th>Endpoint</th><th>Résultat</th><th>Raison</th><th>Statut avant → après</th><th>Date</th>
      </tr></thead><tbody>${rows}</tbody></table></div>
      <p class="dyn-note">Un code HTTP ne vaut jamais verdict : une validation exige que la condition de sécurité propre au finding ait cessé d’être vraie.</p>
    </section>`;
}

/** The Burp session, stated as live or historical — never ambiguous. */
function renderBurpSession(model) {
  const session = model.burpSession;
  if (!session) return '';
  const live = session.state === CAPTURE_STATE.LIVE;
  return `<section class="dynamic-section" id="dyn-burp-session">
      <div class="dynamic-section-head"><h2>Session de capture Burp</h2>
      <span class="status">${live ? '● Capture en direct' : session.state === CAPTURE_STATE.HISTORICAL ? '○ Dernier relevé — pas du trafic en direct' : '○ Jamais connecté'}</span></div>
      <dl class="dyn-facts">
        <div><dt>Session</dt><dd>${session.currentSessionId ? `<code>${escapeHtml(session.currentSessionId)}</code>` : session.lastSessionId ? `<code>${escapeHtml(session.lastSessionId)}</code> <small>(terminée)</small>` : '<span class="dyn-muted">Aucune</span>'}</dd></div>
        <div><dt>Connecteur</dt><dd>${escapeHtml(session.connector || '—')}</dd></div>
        <div><dt>Dernier signal</dt><dd>${session.lastSeenKnown ? escapeHtml(new Date(session.lastSeen).toLocaleString('fr-FR')) : '<span class="dyn-muted">Non fourni par le connecteur</span>'}</dd></div>
        <div><dt>Requêtes reçues</dt><dd>${session.receivedRequests}</dd></div>
      </dl>
      ${live ? '' : '<p class="dyn-note">Le connecteur Burp ne permet pas de démarrer ou d’arrêter une capture depuis Security Center : Burp reste la source d’interception.</p>'}
    </section>`;
}

/** All sections, in the order the page embeds them. */
function renderDynamicSections(model) {
  if (!model) return '';
  return [
    renderOverview(model),
    renderBurpSession(model),
    renderInventory(model),
    renderCoverage(model),
    renderAuthentication(model),
    renderRetests(model)
  ].filter(Boolean).join('\n');
}

/**
 * Styles for the sections.
 *
 * Only theme variables, with the same tokens the rest of the page uses. No fixed
 * background: a hardcoded dark panel is exactly what breaks the light theme.
 */
function dynamicSectionsCss() {
  return `
    .dyn-facts { margin: 8px 0 0; }
    .dyn-facts > div { display: grid; grid-template-columns: 210px 1fr; gap: 8px; padding: 5px 0; border-top: 1px solid var(--vscode-widget-border); }
    .dyn-facts dt { color: var(--vscode-descriptionForeground); }
    .dyn-facts dd { margin: 0; }
    .dyn-metrics { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 0; }
    .dyn-metric { flex: 1 1 130px; padding: 9px 11px; border: 1px solid var(--vscode-widget-border); border-radius: 5px; }
    .dyn-metric span { display: block; color: var(--vscode-descriptionForeground); font-size: 12px; }
    .dyn-metric strong { display: block; font-size: 20px; }
    .dyn-metric small { color: var(--vscode-descriptionForeground); }
    .dyn-muted, .dyn-note, .dyn-empty { color: var(--vscode-descriptionForeground); }
    .dyn-note, .dyn-empty { margin: 10px 0 0; font-size: 12px; line-height: 1.5; }
    .dyn-restored { margin: 0 0 12px; padding: 8px 10px; font-size: 12px; line-height: 1.5;
      color: var(--vscode-descriptionForeground);
      border-left: 3px solid var(--vscode-editorWarning-foreground, var(--vscode-widget-border));
      background: var(--vscode-textBlockQuote-background, transparent); }
    .dyn-subhead { margin: 16px 0 4px; font-size: 13px; }
    .dyn-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 10px 0; }
    .dyn-filters input[type=search], .dyn-filters select { font: inherit; padding: 4px 7px; border: 1px solid var(--vscode-widget-border); border-radius: 4px; color: var(--vscode-input-foreground); background: var(--vscode-input-background); }
    .dyn-filters label { display: flex; align-items: center; gap: 5px; color: var(--vscode-descriptionForeground); font-size: 12px; }
    .dyn-table-scroll { overflow-x: auto; }
    .dyn-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .dyn-table th { text-align: left; padding: 6px 8px; color: var(--vscode-descriptionForeground); font-weight: 600; border-bottom: 1px solid var(--vscode-widget-border); white-space: nowrap; }
    .dyn-table td { padding: 6px 8px; border-bottom: 1px solid var(--vscode-widget-border); vertical-align: top; }
    .dyn-table tbody tr:hover { background: var(--vscode-list-hoverBackground); cursor: pointer; }
    .dyn-method { font-weight: 700; font-size: 11px; letter-spacing: .03em; }
    .dyn-coverage, .dyn-retest { font-size: 11px; font-weight: 600; white-space: nowrap; }
    .dyn-actively_tested, .dyn-validated { color: var(--vscode-testing-iconPassed, #3fa66a); }
    .dyn-replayed, .dyn-passively_analyzed, .dyn-inconclusive { color: var(--vscode-editorWarning-foreground, #d0a215); }
    .dyn-not_tested, .dyn-observed { color: var(--vscode-descriptionForeground); }
    .dyn-still_present { color: var(--vscode-editorError-foreground, #e05252); }
    @media (max-width: 700px) { .dyn-facts > div { grid-template-columns: 1fr; } }`;
}

/**
 * Client-side filtering for the inventory table.
 *
 * Filtering in the page avoids a round trip and a full re-render for every
 * keystroke; the data is already there. Nothing here fetches or computes state.
 */
function dynamicSectionsScript() {
  return `
  (function(){
    const body = document.getElementById('dyn-inventory-body');
    if (!body) return;
    const search = document.getElementById('dyn-search');
    const method = document.getElementById('dyn-filter-method');
    const coverage = document.getElementById('dyn-filter-coverage');
    const source = document.getElementById('dyn-filter-source');
    const auth = document.getElementById('dyn-filter-auth');
    const findings = document.getElementById('dyn-filter-findings');
    const empty = document.getElementById('dyn-inventory-empty');
    const apply = () => {
      const term = (search.value || '').trim().toLowerCase();
      let visible = 0;
      for (const row of body.querySelectorAll('tr')) {
        const show = (!term || row.dataset.search.includes(term))
          && (!method.value || row.dataset.method === method.value)
          && (!coverage.value || row.dataset.coverage === coverage.value)
          && (!source.value || (row.dataset.sources || '').split(',').includes(source.value))
          && (!auth.checked || row.dataset.auth === '1')
          && (!findings.checked || row.dataset.findings === '1');
        row.hidden = !show;
        if (show) visible += 1;
      }
      if (empty) empty.hidden = visible > 0;
    };
    for (const control of [search, method, coverage, source, auth, findings]) {
      control.addEventListener(control === search ? 'input' : 'change', apply);
    }
    for (const row of body.querySelectorAll('tr')) {
      row.addEventListener('click', () => vscode.postMessage({ type: 'dynamicEndpoint', index: Number(row.dataset.endpointIndex) }));
    }
  })();`;
}

module.exports = {
  ZAP_ACTIVE_RANGES, ZAP_PASSIVE_RANGES,
  coverageEvidenceFrom, endpointKeyOf, buildDynamicWorkspace,
  dynamicWorkspaceState, restoreDynamicWorkspaceState,
  renderDynamicSections, renderOverview, renderInventory, renderCoverage,
  renderAuthentication, renderRetests, renderBurpSession,
  dynamicSectionsCss, dynamicSectionsScript, escapeHtml
};
