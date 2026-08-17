'use strict';

/**
 * The Security Pipeline page.
 *
 * A dedicated surface, deliberately separate from the dashboard (which keeps
 * showing findings) and from « Configuration des scanners » (which keeps owning
 * installation and modes). It answers the decision questions: what was found,
 * who found it, is it reachable, what should be fixed first, does the policy
 * allow the release, and what supply-chain evidence exists.
 *
 * Every state rendered here comes from a real pipeline result. No stage is ever
 * animated or filled in optimistically.
 */

const { dataAvailability } = require('./pipeline');
const { renderCompanionWidget, companionWidgetCss } = require('./live/companionWidget');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

const STATE_LABELS = Object.freeze({
  not_configured: 'Non configurée',
  ready: 'Prête',
  running: 'En cours',
  passed: 'OK',
  warning: 'Attention',
  blocked: 'Bloquée',
  skipped: 'Ignorée',
  failed: 'Échec'
});

const REACHABILITY_LABELS = Object.freeze({
  not_evaluated: 'Non évaluée',
  present: 'Présente',
  imported: 'Importée',
  statically_reachable: 'Atteignable statiquement',
  dynamically_confirmed: 'Confirmée dynamiquement',
  not_reachable: 'Non atteignable',
  unknown: 'Indéterminée'
});

const REACHABILITY_STATUS_LABELS = Object.freeze({
  REACHABLE: 'Atteignable',
  POTENTIALLY_REACHABLE: 'Potentiellement atteignable',
  NOT_REACHABLE: 'Non atteignable',
  UNKNOWN: 'Indéterminée'
});

const PRIORITY_CODE_LABELS = Object.freeze({ P0: 'Critique', P1: 'Élevée', P2: 'Moyenne', P3: 'Faible' });

const CORRELATION_LABELS = Object.freeze({
  sca: 'Dépendance', sast: 'Code', iac: 'Configuration', 'dast-sast': 'Runtime ↔ Code'
});

const TIER_LABELS = Object.freeze({
  confirmed: 'Confirmée par plusieurs scanners', probable: 'Corrélation probable', candidate: 'Corrélation candidate'
});

/** Wording for each gate verdict. None of them is « OK ». */
const POLICY_STATE_LABELS = Object.freeze({
  NOT_CONFIGURED: 'Non configuré', PASS: 'PASS', WARN: 'WARN', BLOCK: 'BLOCK', ERROR: 'Configuration invalide'
});

const TABS = Object.freeze([
  ['pipeline', 'Pipeline'],
  ['correlations', 'Corrélations'],
  ['reachability', 'Reachability'],
  ['priorities', 'Priorités'],
  ['policy', 'Policy Gate'],
  ['supply-chain', 'Supply Chain']
]);

/**
 * Availability for one tab. The extension normally supplies it; when it does
 * not, the page derives it with the same rules rather than silently rendering
 * an empty list.
 */
function availabilityFor(model, section, { summary, records, expected }) {
  return model.availability?.[section] || dataAvailability({
    summary, records, expected, intelligence: model.intelligence
  });
}

/**
 * Empty state for a detail tab. Each case says something different, and
 * « données perdues » is never rendered as « aucun résultat ».
 */
function renderAvailability(availability, { notExecuted, noResults }) {
  const state = availability?.state;
  if (state === 'ERROR') {
    return `<section class="banner bad"><strong>Analyse impossible</strong><p>${escapeHtml(availability.reason || 'Security Intelligence a échoué pour ce scan.')}</p></section>`;
  }
  if (state === 'MISSING_PERSISTED_DATA') {
    return `<section class="banner warn"><strong>Détail indisponible pour ce scan</strong><p>${escapeHtml(availability.reason)} Relancez une analyse pour reconstituer le détail.</p></section>`;
  }
  if (state === 'NOT_EXECUTED') {
    return `<section class="banner muted-state"><strong>Analyse non exécutée</strong><p>${escapeHtml(notExecuted)}</p></section>`;
  }
  if (state === 'NO_RESULTS') {
    return `<section class="banner muted-state"><strong>Analyse exécutée — aucun résultat</strong><p>${escapeHtml(noResults)}</p></section>`;
  }
  return '';
}

/** Which scan the page is showing. Same value on every tab, by construction. */
function renderScanFooter(model) {
  if (!model.scanId) return '';
  const date = model.finishedAt ? new Date(model.finishedAt) : null;
  const stamp = date && !Number.isNaN(date.getTime())
    ? date.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '';
  return `<p class="footnote scan-footer">Scan : <code>${escapeHtml(model.scanId)}</code>${stamp ? ` · ${escapeHtml(stamp)}` : ''}${model.restored ? ' · restauré depuis le dernier scan enregistré' : ''}</p>`;
}

function stateClass(state) {
  if (['passed'].includes(state)) return 'ok';
  if (['warning', 'running'].includes(state)) return 'warn';
  if (['blocked', 'failed'].includes(state)) return 'bad';
  return 'muted-state';
}

/** Gate verdict → the page's colour vocabulary. */
function policyClass(status) {
  return { PASS: 'ok', WARN: 'warn', BLOCK: 'bad', ERROR: 'bad' }[status] || 'muted-state';
}

function renderStage(stage) {
  return `<li class="stage ${escapeHtml(stateClass(stage.state))}" data-stage="${escapeHtml(stage.id)}" tabindex="0" role="button" aria-label="${escapeHtml(stage.label)} — ${escapeHtml(STATE_LABELS[stage.state] || stage.state)}">
      <div class="stage-head"><span class="stage-name">${escapeHtml(stage.label)}</span><span class="stage-state">${escapeHtml(STATE_LABELS[stage.state] || stage.state)}</span></div>
      <p class="stage-detail">${escapeHtml(stage.detail || '')}</p>
    </li>`;
}

/**
 * The Policy Gate summary shown on the Pipeline tab.
 *
 * Five distinct states, each with its own wording and its own next action. An
 * absent or invalid policy is never dressed up as a pass.
 */
function renderPolicyBanner(model) {
  const policy = model.policy;
  const status = policy?.status || (policy ? 'NOT_CONFIGURED' : '');
  if (status === 'ERROR') {
    return `<section class="banner bad"><strong>Policy Gate — configuration invalide</strong>
      <p>${escapeHtml(policy.error || 'La politique projet n’a pas pu être lue.')}</p>
      <p>Aucune livraison n’est autorisée sur cette base : le gate n’a pas pu être évalué.</p>
      <div class="actions"><button data-tab="policy">Corriger la politique</button><button class="secondary" data-action="openPolicyYaml">Ouvrir security-center.yml</button></div></section>`;
  }
  if (!policy || !policy.configured) {
    return `<section class="banner muted-state"><strong>Policy Gate — NON CONFIGURÉ</strong>
      <p>Aucune règle de gate trouvée dans <code>security-center.yml</code>. Security Center ne peut donc ni autoriser ni bloquer une livraison.</p>
      <div class="actions"><button data-tab="policy">Configurer la politique</button></div></section>`;
  }
  const violations = policy.violations || [];
  const warnings = policy.warnings || [];
  return `<section class="banner ${escapeHtml(policyClass(status))}">
      <strong>Policy Gate — ${escapeHtml(POLICY_STATE_LABELS[status] || status)}</strong>
      <p>${escapeHtml(policy.summary || '')}</p>
      <p class="muted">${violations.length} violation(s) bloquante(s) · ${warnings.length} avertissement(s)</p>
      ${violations.length ? `<ul class="violations">${violations.slice(0, 3).map((violation) => `<li><span class="violation-rule">${escapeHtml(violation.rule || violation.code)}</span> ${escapeHtml(violation.message)}${violation.file ? `<code>${escapeHtml(violation.file)}${violation.line ? `:${violation.line}` : ''}</code>` : ''}</li>`).join('')}</ul>` : ''}
      <div class="actions"><button data-tab="policy">${violations.length ? 'Voir les violations' : 'Détail de la politique'}</button></div>
    </section>`;
}

function renderPipelineTab(model) {
  const stages = model.stages || [];
  const intelligenceFailed = model.intelligence?.status === 'failed';
  const groups = [
    ['Analyse', stages.filter((stage) => stage.kind === 'scan')],
    ['Security intelligence', stages.filter((stage) => stage.kind === 'intelligence')],
    ['Décision', stages.filter((stage) => stage.kind === 'decision')],
    ['Preuves supply chain', stages.filter((stage) => stage.kind === 'artifact')]
  ];
  const banner = renderPolicyBanner(model);
  // A failed intelligence run is stated plainly, and the scanner results above
  // it are explicitly described as still valid.
  const intelligenceBanner = intelligenceFailed
    ? `<section class="banner bad"><strong>Security Intelligence indisponible</strong><p>${escapeHtml(model.intelligence.error || '')} — les résultats des scanners restent affichés et n’ont pas été modifiés. La corrélation, l’atteignabilité et la priorisation ne sont pas disponibles pour ce scan.</p></section>`
    : '';
  return `${intelligenceBanner}${banner}
    ${groups.map(([title, items]) => items.length
      ? `<h3 class="section-title">${escapeHtml(title)}</h3><ol class="stages">${items.map(renderStage).join('')}</ol>`
      : '').join('')}
    ${model.scanId ? renderScanFooter(model) : '<p class="footnote">Aucune analyse enregistrée. Lancez une analyse du workspace pour alimenter le pipeline.</p>'}`;
}

/**
 * One violation or warning, with everything that explains why it matters.
 *
 * Every fact rendered here is read from the gate result. Nothing is inferred,
 * and a signal the engines did not produce is simply not shown rather than
 * displayed as « unknown » or as a default.
 */
function renderViolation(item, index) {
  const facts = [
    item.severity ? ['Sévérité', item.severity] : null,
    Number.isFinite(item.priority) ? ['Priorité', `${item.priority}/100${item.priorityCode ? ` · ${PRIORITY_CODE_LABELS[item.priorityCode] || item.priorityCode}` : ''}`] : null,
    item.reachability ? ['Atteignabilité', REACHABILITY_LABELS[item.reachability] || item.reachability] : null,
    item.correlationTier ? ['Corrélation', TIER_LABELS[item.correlationTier] || item.correlationTier] : null,
    item.sources?.length ? ['Détecté par', item.sources.join(' + ')] : null,
    item.file ? ['Fichier', `${item.file}${item.line ? `:${item.line}` : ''}`] : null,
    item.rule ? ['Règle violée', item.rule] : null
  ].filter(Boolean);
  return `<article class="card ${item.code === 'severity-warning' || item.code === 'priority-warning' || String(item.code).includes('artifact-not') ? 'warn' : 'bad'}">
      <div class="card-head">
        <div><span class="chip">${escapeHtml(index)}</span><h3>${escapeHtml(item.title || item.message)}</h3>
        ${item.title ? `<small>${escapeHtml(item.message)}</small>` : ''}</div>
      </div>
      <dl>${facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd${label === 'Fichier' ? ' class="path"' : ''}>${escapeHtml(value)}</dd></div>`).join('')}</dl>
    </article>`;
}

/** A checkbox that states its effect in plain language, not in YAML. */
function checkbox(name, checked, label, hint = '') {
  return `<label class="option"><input type="checkbox" data-policy-field="${escapeHtml(name)}"${checked ? ' checked' : ''}>
      <span><strong>${escapeHtml(label)}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</span></label>`;
}

function numberField(name, value, label, hint) {
  return `<label class="option number"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(hint)}</small></span>
      <input type="number" min="0" max="100" step="1" data-policy-field="${escapeHtml(name)}" value="${Number.isInteger(value) ? value : ''}" placeholder="aucun">
    </label>`;
}

/**
 * The Policy Gate tab: the verdict, why it was reached, and the editor for the
 * rules that produced it.
 *
 * The form only exposes rules the engine can actually evaluate, so a saved
 * policy can never promise a control Security Center would not apply.
 */
function renderPolicyTab(model) {
  const policy = model.policy;
  const config = model.policyConfig || {};
  const gate = config.gate || {};
  const supplyChain = config.supplyChain || {};
  const evaluation = model.policyEvaluation || {};
  const status = policy?.status || 'NOT_CONFIGURED';
  const violations = policy?.violations || [];
  const warnings = policy?.warnings || [];
  const busy = model.busy ? 'disabled' : '';

  const verdict = config.error
    ? `<section class="banner bad"><strong>Configuration invalide</strong><p>${escapeHtml(config.error)}</p>
        <p>Le gate n’a pas été évalué : une politique illisible n’autorise rien.</p></section>`
    : `<section class="banner ${escapeHtml(policyClass(status))}">
        <strong>${escapeHtml(POLICY_STATE_LABELS[status] || status)}</strong>
        <p>${escapeHtml(policy?.summary || 'Aucune évaluation disponible pour ce scan.')}</p>
        ${policy?.configured ? `<div class="summary-row">
          <div class="summary-tile ${violations.length ? 'bad' : ''}"><strong>${violations.length}</strong><span>Violation(s) bloquante(s)</span></div>
          <div class="summary-tile ${warnings.length ? 'warn' : ''}"><strong>${warnings.length}</strong><span>Avertissement(s)</span></div>
          <div class="summary-tile"><strong>${policy.counts?.evaluatedFindings ?? 0}</strong><span>Résultat(s) évalué(s)</span></div>
        </div>` : ''}
      </section>`;

  // Which scan this verdict belongs to, and whether the policy has moved since.
  const provenance = `<article class="card compact">
      <div class="card-head"><div><h3>Évaluation</h3><small>Le verdict appartient au même scan que les findings, les corrélations et les priorités.</small></div></div>
      <dl>
        <div><dt>Scan</dt><dd>${model.scanId ? `<code>${escapeHtml(model.scanId)}</code>` : '<span class="muted">Aucune analyse enregistrée</span>'}</dd></div>
        <div><dt>Dernière évaluation</dt><dd>${policy?.evaluatedAt ? escapeHtml(new Date(policy.evaluatedAt).toLocaleString('fr-FR')) : '<span class="muted">Jamais</span>'}</dd></div>
        <div><dt>Politique appliquée</dt><dd>${evaluation.policyChangedSinceScan
          ? '<span class="muted">Politique <strong>au moment du scan</strong> — le fichier a été modifié depuis. Ré-évaluez pour appliquer la politique actuelle.</span>'
          : 'Politique actuelle du projet'}</dd></div>
        ${evaluation.reevaluatedAt ? `<div><dt>Ré-évaluation manuelle</dt><dd>${escapeHtml(new Date(evaluation.reevaluatedAt).toLocaleString('fr-FR'))} — sans relancer les scanners</dd></div>` : ''}
        <div><dt>Fichier</dt><dd class="path">${escapeHtml(config.filePath || 'security-center.yml (absent)')}</dd></div>
      </dl>
      <div class="actions">
        <button data-action="reevaluatePolicy" ${busy} ${model.scanId ? '' : 'disabled'}>Ré-évaluer la politique</button>
        <button class="secondary" data-command="securityCenter.scanWorkspace" ${busy}>Relancer une analyse complète</button>
      </div>
      ${model.scanId ? '' : '<p class="footnote">La ré-évaluation a besoin d’un scan terminé : elle rejoue uniquement le moteur de politique sur ses résultats.</p>'}
    </article>`;

  const rules = policy?.rules?.length
    ? `<article class="card compact"><div class="card-head"><div><h3>Règles appliquées</h3><small>Ce que la politique demande, tel que le moteur l’a évalué</small></div></div>
        <ul class="violations">${policy.rules.map((rule) => `<li>${escapeHtml(rule.label)} <span class="violation-rule">${escapeHtml(rule.key)}</span></li>`).join('')}</ul></article>`
    : '';

  const details = policy?.configured ? `
    ${violations.length ? `<h3 class="section-title">${violations.length} violation(s) bloquante(s)</h3>${violations.map((item, index) => renderViolation(item, index + 1)).join('')}` : ''}
    ${warnings.length ? `<h3 class="section-title">${warnings.length} avertissement(s)</h3>${warnings.map((item, index) => renderViolation(item, index + 1)).join('')}` : ''}
    ${!violations.length && !warnings.length ? '<section class="banner ok"><strong>Aucune violation</strong><p>Toutes les règles configurées sont respectées par ce scan.</p></section>' : ''}` : '';

  const saved = model.policySaveResult
    ? model.policySaveResult.ok
      ? `<section class="banner ok"><strong>Politique enregistrée</strong><p>${escapeHtml(model.policySaveResult.message || '')}</p></section>`
      : `<section class="banner bad"><strong>Enregistrement refusé</strong><p>${escapeHtml(model.policySaveResult.message || '')}</p><p>Le fichier n’a pas été modifié.</p></section>`
    : '';

  const form = `<article class="card" id="policy-form">
      <div class="card-head"><div><h3>Configurer le Policy Gate</h3><small>Sans écrire de YAML. Seules les règles que Security Center sait évaluer sont proposées.</small></div></div>
      <h4 class="section-title">Bloquer la livraison quand</h4>
      ${checkbox('failCritical', gate.failOnSeverity?.includes('CRITICAL') || gate.failOnSeverity?.includes('HIGH') || gate.failOnSeverity?.includes('MEDIUM'), 'Des vulnérabilités critiques existent', 'gate.fail_on_severity')}
      ${checkbox('failHigh', gate.failOnSeverity?.includes('HIGH') || gate.failOnSeverity?.includes('MEDIUM'), 'Des vulnérabilités élevées existent', 'Inclut aussi les critiques : le seuil signifie « cette sévérité ou plus grave ».')}
      ${checkbox('failMedium', gate.failOnSeverity?.includes('MEDIUM'), 'Des vulnérabilités moyennes existent', 'Inclut aussi les élevées et les critiques.')}
      ${checkbox('blockSecrets', gate.blockSecrets, 'Des secrets exposés existent', 'gate.block_secrets')}
      ${numberField('priorityThreshold', gate.priorityThreshold, 'Seuil de priorité bloquant', 'Un résultat dont le score de priorité atteint cette valeur bloque la livraison. Laisser vide pour ne pas utiliser la priorité.')}
      <h4 class="section-title">Signaler sans bloquer</h4>
      ${checkbox('warnHigh', gate.warnOnSeverity?.includes('HIGH') || gate.warnOnSeverity?.includes('MEDIUM'), 'Vulnérabilités élevées', 'gate.warn_on_severity')}
      ${checkbox('warnMedium', gate.warnOnSeverity?.includes('MEDIUM'), 'Vulnérabilités moyennes', 'Inclut aussi les élevées.')}
      ${numberField('warnPriorityThreshold', gate.warnPriorityThreshold, 'Seuil de priorité signalé', 'Signale les résultats atteignant ce score sans bloquer.')}
      <h4 class="section-title">Preuves exigées</h4>
      ${checkbox('requireSbom', gate.requireSbom, 'Un SBOM doit avoir été généré', 'gate.require_sbom')}
      ${checkbox('requireProvenance', supplyChain.requireProvenance, 'Une provenance doit avoir été générée', 'supply_chain.require_provenance')}
      ${checkbox('requireSignature', supplyChain.requireSignature, 'Une signature vérifiée est exigée', 'supply_chain.require_signature')}
      <p class="footnote">Une preuve exigée dont l’étape n’a pas été exécutée produit un avertissement, jamais un PASS.</p>
      <div class="actions">
        <button data-action="savePolicy" ${busy}>Enregistrer la politique</button>
        ${config.configured ? '' : `<button class="secondary" data-action="createStarterPolicy" ${busy}>Créer une politique de départ</button>`}
        <button class="secondary" data-action="openPolicyYaml">Avancé — ouvrir security-center.yml</button>
      </div>
    </article>`;

  return `${saved}${verdict}${provenance}${rules}${form}${details}${renderScanFooter(model)}`;
}

/** One correlated vulnerability, with every source scanner kept visible. */
function renderCluster(cluster, index) {
  return `<article class="card cluster" data-cluster="${escapeHtml(cluster.id)}">
      <div class="card-head">
        <div>
          <span class="chip">${escapeHtml(CORRELATION_LABELS[cluster.type] || cluster.type)}</span>
          <h3>${escapeHtml(cluster.title || cluster.identity?.identifier || cluster.identity?.file || 'Vulnérabilité corrélée')}</h3>
          <small>Groupe <code>${escapeHtml(cluster.id)}</code> · ${cluster.findingCount ?? cluster.count} finding(s) · ${escapeHtml(cluster.severity || '')}</small>
        </div>
        <span class="confidence ${escapeHtml(cluster.confidence)}">${escapeHtml(cluster.tierLabel || cluster.confidence)}<small class="muted"> · confiance ${escapeHtml(cluster.confidence)}</small></span>
      </div>
      <dl>
        <div><dt>Détectée par</dt><dd>${cluster.tools.map((tool) => `<span class="tool-chip">✓ ${escapeHtml(tool)}</span>`).join('')}</dd></div>
        ${cluster.primaryTool ? `<div><dt>Finding canonique</dt><dd>${escapeHtml(cluster.primaryTool)} <span class="muted">(les ${cluster.findingCount ?? cluster.count} résultats d’origine restent consultables)</span></dd></div>` : ''}
        ${cluster.identity?.package ? `<div><dt>Paquet</dt><dd><code>${escapeHtml(cluster.identity.package)}${cluster.identity.version ? `@${escapeHtml(cluster.identity.version)}` : ''}</code></dd></div>` : ''}
        ${cluster.identity?.file ? `<div><dt>Fichier</dt><dd><code>${escapeHtml(cluster.identity.file)}${cluster.identity.line ? `:${cluster.identity.line}` : ''}</code></dd></div>` : ''}
        ${cluster.identity?.endpoint ? `<div><dt>Endpoint</dt><dd><code>${escapeHtml(cluster.identity.method || 'HTTP')} ${escapeHtml(cluster.identity.endpoint)}</code></dd></div>` : ''}
        ${cluster.identity?.resource ? `<div><dt>Ressource</dt><dd><code>${escapeHtml(cluster.identity.resource)}</code></dd></div>` : ''}
      </dl>
      <div class="reasons"><span class="reasons-title">Pourquoi ces résultats sont corrélés</span><ul>${cluster.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul></div>
      <div class="sources"><span class="reasons-title">Preuves d’origine conservées</span><ul>${cluster.sources.map((source, sourceIndex) => `<li><button class="link" data-cluster-index="${index}" data-source-index="${sourceIndex}"><strong>${escapeHtml(source.tool)}</strong> ${escapeHtml(source.ruleId || '')} ${source.file ? `<code>${escapeHtml(source.file)}${source.line ? `:${source.line}` : ''}</code>` : ''}${source.endpoint ? `<code>${escapeHtml(source.endpoint)}</code>` : ''}</button></li>`).join('')}</ul></div>
    </article>`;
}

function renderCorrelationsTab(model) {
  const clusters = model.clusters || [];
  const empty = renderAvailability(availabilityFor(model, 'correlations', {
    summary: model.correlation, records: clusters, expected: model.correlation?.total
  }), {
    notExecuted: 'Lancez une analyse pour rechercher des recoupements entre scanners.',
    noResults: 'Aucun résultat n’a été confirmé par plusieurs scanners lors de cette analyse.'
  });
  if (empty) return `${empty}${renderScanFooter(model)}`;
  const summary = model.correlation || {};
  const tiers = summary.byTier || {};
  const grouped = [
    ['confirmed', 'Confirmées', 'Plusieurs scanners s’accordent sur une preuve forte'],
    ['probable', 'Probables', 'Preuves concordantes, un élément reste non vérifié'],
    ['candidate', 'Candidates', 'Rapprochement plausible mais non prouvé — aucun poids dans la priorité']
  ];
  return `<section class="summary-row">
      <div class="summary-tile ${tiers.confirmed ? 'bad' : ''}"><strong>${tiers.confirmed || 0}</strong><span>Confirmées</span></div>
      <div class="summary-tile ${tiers.probable ? 'warn' : ''}"><strong>${tiers.probable || 0}</strong><span>Probables</span></div>
      <div class="summary-tile"><strong>${tiers.candidate || 0}</strong><span>Candidates</span></div>
      <div class="summary-tile"><strong>${escapeHtml(summary.routeMapAvailable ? 'Oui' : 'Non')}</strong><span>routes reconnues</span></div>
    </section>
    <p class="footnote">Seules les corrélations <strong>confirmées</strong> sont décrites comme « confirmées par plusieurs scanners ». Une candidate est une hypothèse : elle est affichée pour jugement, sans influence sur la priorité.</p>
    ${!summary.routeMapAvailable ? '<p class="footnote">Aucune route HTTP n’a pu être lue dans ce workspace : les corrélations runtime ↔ code ne sont pas établies pour ce projet.</p>' : ''}
    ${grouped.map(([tier, label, hint]) => {
      const section = clusters.filter((cluster) => (cluster.tier || 'candidate') === tier);
      if (!section.length) return '';
      return `<h3 class="section-title">${escapeHtml(label)} — ${section.length}<small class="muted"> · ${escapeHtml(hint)}</small></h3>${section.map(renderCluster).join('')}`;
    }).join('')}
    ${renderScanFooter(model)}`;
}

function renderReachabilityTab(model) {
  const summary = model.reachability;
  const empty = renderAvailability(availabilityFor(model, 'reachability', {
    summary, records: (model.findings || []).filter((finding) => finding.reachability),
    expected: summary ? Object.values(summary.counts || {}).reduce((total, value) => total + value, 0) : null
  }), {
    notExecuted: 'Lancez une analyse pour évaluer l’atteignabilité.',
    noResults: 'Aucun résultat n’était éligible à une évaluation d’atteignabilité.'
  });
  if (empty) return `${empty}${renderScanFooter(model)}`;
  const findings = (model.findings || []).filter((finding) => finding.reachability && finding.reachability.state !== 'not_evaluated');
  const order = ['dynamically_confirmed', 'statically_reachable', 'imported', 'present', 'unknown', 'not_reachable'];
  const statusOrder = ['REACHABLE', 'POTENTIALLY_REACHABLE', 'UNKNOWN', 'NOT_REACHABLE'];
  const sorted = [...findings].sort((left, right) => order.indexOf(left.reachability.state) - order.indexOf(right.reachability.state));
  const runtime = summary.runtime || { observed: 0, applicationEndpoints: 0, staticAssets: 0, sources: [] };
  const runtimeFindings = (model.findings || []).filter((finding) => finding.runtime?.observed);
  return `<h3 class="section-title">Code Reachability<small class="muted"> · dépendances, fichiers et routes applicatives</small></h3>
    <section class="summary-row">
      ${statusOrder.filter((status) => summary.statusCounts?.[status]).map((status) => `<div class="summary-tile ${status === 'REACHABLE' ? 'bad' : status === 'POTENTIALLY_REACHABLE' ? 'warn' : ''}"><strong>${summary.statusCounts[status]}</strong><span>${escapeHtml(REACHABILITY_STATUS_LABELS[status])}</span></div>`).join('')}
    </section>
    ${runtime.observed ? `<h3 class="section-title">Runtime Observed<small class="muted"> · trafic réellement émis par ${escapeHtml(runtime.sources.join(', ') || 'un scanner dynamique')}</small></h3>
    <section class="summary-row">
      <div class="summary-tile ${runtime.applicationEndpoints ? 'warn' : ''}"><strong>${runtime.applicationEndpoints}</strong><span>Endpoints applicatifs</span></div>
      <div class="summary-tile"><strong>${runtime.staticAssets}</strong><span>Ressources statiques</span></div>
    </section>
    <p class="footnote">Une observation runtime prouve qu’une requête a été envoyée et vue. Ce n’est pas une atteignabilité de code : une réponse sur un CSS ou un favicon ne dit rien du chemin applicatif.</p>
    ${runtimeFindings.slice(0, 25).map((finding) => `<article class="card compact">
      <div class="card-head"><div><h3>${escapeHtml(finding.title)}</h3><small>${escapeHtml(finding.tool)}${finding.runtime.staticAsset ? ' · ressource statique' : ''}</small></div><span class="reach">${escapeHtml(finding.runtime.source)}</span></div>
      <dl><div><dt>Requête</dt><dd class="path">${escapeHtml(finding.runtime.method || 'HTTP')} ${escapeHtml(finding.runtime.url)}</dd></div>
      ${finding.runtime.parameter ? `<div><dt>Paramètre</dt><dd>${escapeHtml(finding.runtime.parameter)}</dd></div>` : ''}
      ${finding.runtime.evidence ? `<div><dt>Preuve</dt><dd class="path">${escapeHtml(finding.runtime.evidence)}</dd></div>` : ''}</dl>
    </article>`).join('')}` : ''}
    <h3 class="section-title">Détail par résultat</h3>
    ${!summary.analysed ? '<p class="footnote">L’analyse des imports n’a pas pu être exécutée : aucune conclusion d’atteignabilité n’est tirée. Rien n’est déclaré « non atteignable » sur cette base.</p>'
      : `<p class="footnote">${summary.scannedFiles} fichier(s) analysé(s), ${summary.entryPoints} point(s) d’entrée identifié(s). Security Center ne calcule pas de graphe d’appel complet : « atteignable statiquement » signifie que le composant est importé par un point d’entrée.</p>`}
    ${sorted.slice(0, 60).map((finding) => `<article class="card compact">
      <div class="card-head"><div><h3>${escapeHtml(finding.title)}</h3><small>${escapeHtml(finding.tool)} · ${escapeHtml(finding.package || finding.file || finding.endpoint || '')}</small></div><span class="reach ${escapeHtml(finding.reachability.state)}">${escapeHtml(REACHABILITY_STATUS_LABELS[finding.reachability.status] || finding.reachability.status)}<small class="muted"> · confiance ${escapeHtml(finding.reachability.confidence)}</small></span></div>
      <p class="stage-detail">${escapeHtml(finding.reachability.reason)}</p>
      ${finding.reachability.evidence?.length ? `<ul class="evidence">${finding.reachability.evidence.slice(0, 4).map((item) => `<li><span class="chip">${escapeHtml(item.type)}</span> ${item.file ? `<code>${escapeHtml(item.file)}${item.line ? `:${item.line}` : ''}</code>` : ''} ${escapeHtml(item.detail || '')}</li>`).join('')}</ul>` : ''}
    </article>`).join('')}
    ${sorted.length > 60 ? `<p class="footnote">${sorted.length} résultats évalués — les 60 plus significatifs sont affichés.</p>` : ''}
    ${renderScanFooter(model)}`;
}

function renderPrioritiesTab(model) {
  const summary = model.priority;
  const empty = renderAvailability(availabilityFor(model, 'priorities', {
    summary, records: (model.findings || []).filter((finding) => finding.priority),
    expected: summary ? Object.values(summary.distribution || {}).reduce((total, value) => total + value, 0) : null
  }), {
    notExecuted: 'Lancez une analyse pour calculer les priorités.',
    noResults: 'Aucun résultat à prioriser pour ce scan.'
  });
  if (empty) return `${empty}${renderScanFooter(model)}`;
  const scored = [...(model.findings || [])]
    .filter((finding) => finding.priority)
    .sort((left, right) => right.priority.score - left.priority.score);
  const ranked = scored.slice(0, 40);
  const distribution = summary.distribution || {};
  return `<section class="summary-row">
      <div class="summary-tile bad"><strong>${distribution.P0 || 0}</strong><span>P0 Critique</span></div>
      <div class="summary-tile warn"><strong>${distribution.P1 || 0}</strong><span>P1 Élevée</span></div>
      <div class="summary-tile"><strong>${distribution.P2 || 0}</strong><span>P2 Moyenne</span></div>
      <div class="summary-tile"><strong>${distribution.P3 || 0}</strong><span>P3 Faible</span></div>
    </section>
    <p class="footnote">Le score est déterministe et entièrement expliqué : chaque point provient d’un signal nommé ci-dessous.</p>
    ${ranked.map((finding, index) => `<article class="card priority-card">
      <div class="card-head">
        <div><h3>${escapeHtml(finding.title)}</h3><small>${escapeHtml(finding.tool)} · ${escapeHtml(finding.file || finding.package || finding.endpoint || '')}${finding.line ? `:${finding.line}` : ''}</small></div>
        <span class="score ${escapeHtml(finding.priority.level)}"><span class="priority-code">${escapeHtml(finding.priority.code)}</span> ${finding.priority.score}<small>/100</small></span>
      </div>
      <dl>
        <div><dt>Sévérité</dt><dd>${escapeHtml(finding.severity || '')}</dd></div>
        <div><dt>Atteignabilité</dt><dd>${escapeHtml(REACHABILITY_STATUS_LABELS[finding.reachability?.status] || 'Indéterminée')}</dd></div>
        <div><dt>Corrélation</dt><dd>${finding.correlation
          ? `<strong>${escapeHtml(finding.correlation.tier === 'confirmed' ? 'Confirmée' : finding.correlation.tier === 'probable' ? 'Probable' : 'Candidate')}</strong> — ${(finding.correlation.tools || []).map((tool) => `<span class="tool-chip">${escapeHtml(tool)}</span>`).join('')}`
          : '<span class="muted">Aucune</span>'}</dd></div>
        ${finding.runtime?.observed ? `<div><dt>Observé à l’exécution</dt><dd>${escapeHtml(finding.runtime.source)} — ${escapeHtml(finding.runtime.method || 'HTTP')} ${escapeHtml(finding.runtime.url)}${finding.runtime.staticAsset ? ' <span class="muted">(ressource statique)</span>' : ''}</dd></div>` : ''}
      </dl>
      <div class="reasons"><span class="reasons-title">${escapeHtml(finding.priority.code)} ${escapeHtml(PRIORITY_CODE_LABELS[finding.priority.code] || finding.priority.label)} — pourquoi</span><ul>${finding.priority.reasons.map((reason) => `<li>${reason.points >= 0 ? '✓' : '−'} ${escapeHtml(reason.label)} <span class="points">${reason.points >= 0 ? '+' : ''}${reason.points}</span></li>`).join('')}</ul></div>
      <div class="actions"><button class="secondary" data-finding-index="${index}">Voir le détail du finding</button></div>
    </article>`).join('')}
    ${scored.length > ranked.length ? `<p class="footnote">${scored.length} résultats priorisés — les ${ranked.length} plus prioritaires sont affichés.</p>` : ''}
    ${renderScanFooter(model)}`;
}

function renderArtifactCard(title, artifact, { actions = '', description = '' }) {
  const state = !artifact ? 'not_configured'
    : ['generated', 'verified', 'signed'].includes(artifact.status) ? 'passed'
      : artifact.status === 'cancelled' ? 'skipped' : 'failed';
  const rows = [];
  if (artifact?.status === 'generated' && artifact.componentCount !== undefined) {
    rows.push(['Format', `${artifact.format || ''} ${artifact.specVersion || ''}`.trim() || 'Inconnu']);
    rows.push(['Composants', String(artifact.componentCount ?? 0)]);
  }
  if (artifact?.artifactDigest) rows.push(['Digest de l’artefact', artifact.artifactDigest]);
  if (artifact?.digest && !artifact.artifactDigest) rows.push(['Digest', artifact.digest]);
  if (artifact?.sbomLinked !== undefined) rows.push(['SBOM rattaché', artifact.sbomLinked ? 'Oui' : 'Non']);
  if (artifact?.policyStatus) rows.push(['Policy Gate', artifact.policyStatus]);
  if (artifact?.conformance) rows.push(['Conformité', artifact.conformance]);
  if (artifact?.generatedAt) rows.push(['Généré le', artifact.generatedAt]);
  if (artifact?.signedAt) rows.push(['Signé le', artifact.signedAt]);
  if (artifact?.verifiedAt) rows.push(['Vérifié le', artifact.verifiedAt]);
  if (artifact?.path) rows.push(['Fichier', artifact.path]);
  if (artifact?.signaturePath) rows.push(['Signature', artifact.signaturePath]);
  if (artifact?.reason) rows.push(['Raison', artifact.reason]);
  return `<article class="card artifact ${escapeHtml(stateClass(state))}">
      <div class="card-head"><div><h3>${escapeHtml(title)}</h3><small>${escapeHtml(description)}</small></div><span class="stage-state">${escapeHtml(STATE_LABELS[state])}</span></div>
      ${rows.length ? `<dl>${rows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd class="path">${escapeHtml(value)}</dd></div>`).join('')}</dl>` : ''}
      ${actions ? `<div class="actions">${actions}</div>` : ''}
    </article>`;
}

function renderSupplyChainTab(model) {
  const artifacts = model.artifacts || {};
  const cosign = model.cosign || {};
  const busy = model.busy ? 'disabled' : '';
  const signingAvailable = cosign.installed && cosign.keyConfigured;
  // Signing an artefact that the policy blocked is refused by default: the
  // button is only offered when the gate did not block.
  const gateBlocked = model.policy?.status === 'BLOCK';
  return `${renderArtifactCard('SBOM', artifacts.sbom, {
      description: 'Inventaire des composants, généré par Trivy au format CycloneDX',
      actions: `<button data-action="generateSbom" ${busy}>Générer le SBOM</button>${artifacts.sbom?.status === 'generated' ? '<button class="secondary" data-action="openSbom">Ouvrir le fichier</button>' : ''}`
    })}
    ${renderArtifactCard('Provenance', artifacts.provenance, {
      description: 'Statement in-toto v1 avec prédicat SLSA Provenance v1 — structure compatible, aucun niveau SLSA revendiqué',
      actions: `<button data-action="generateProvenance" ${busy}>Générer la provenance</button>${artifacts.provenance?.status === 'generated' ? '<button class="secondary" data-action="openProvenance">Ouvrir le fichier</button>' : ''}`
    })}
    ${renderArtifactCard('Signature', artifacts.signing, {
      description: 'Signature Cosign d’un artefact local',
      actions: `${gateBlocked
        ? '<span class="inline-note">Signature indisponible : la politique projet a bloqué ce scan.</span>'
        : `<button data-action="signArtifact" ${busy} ${signingAvailable ? '' : 'disabled'}>Signer un artefact</button>`}<button class="secondary" data-action="verifySignature" ${busy} ${cosign.installed ? '' : 'disabled'}>Vérifier une signature</button>`
    })}
    <article class="card">
      <div class="card-head"><div><h3>Cosign</h3><small>Outil de signature supply chain — ne produit aucune vulnérabilité</small></div><span class="stage-state">${escapeHtml(cosign.installed ? 'Installé' : 'Non installé')}</span></div>
      <dl>
        <div><dt>Version</dt><dd>${escapeHtml(cosign.version || 'Non détectée')}</dd></div>
        <div><dt>Emplacement</dt><dd class="path">${escapeHtml(cosign.path || 'Aucun')}</dd></div>
        <div><dt>Modes pris en charge</dt><dd>Auto, Local${cosign.dockerReason ? ' <span class="muted">(Docker non pris en charge)</span>' : ''}</dd></div>
        <div><dt>Clé de signature</dt><dd>${cosign.keyConfigured ? `Configurée <span class="muted">(clé publique : ${escapeHtml(cosign.publicKeyPath || 'inconnue')})</span>` : '<span class="muted">Aucune clé configurée</span>'}</dd></div>
        <div><dt>Mot de passe de la clé</dt><dd>${cosign.passwordConfigured ? 'Conservé dans VS Code SecretStorage' : '<span class="muted">Non configuré</span>'}</dd></div>
        <div><dt>Signature keyless</dt><dd><span class="muted">${escapeHtml(cosign.keylessReason || 'Non prise en charge')}</span></dd></div>
      </dl>
      ${cosign.dockerReason ? `<p class="footnote">${escapeHtml(cosign.dockerReason)}</p>` : ''}
      <div class="actions">${cosign.installed ? '' : `<button data-action="installCosign" ${busy}>Installer Cosign</button>`}<button class="secondary" data-action="configureCosignKey" ${busy}>${cosign.keyConfigured ? 'Remplacer la clé' : 'Configurer une clé'}</button><button class="secondary" data-action="refresh" ${busy}>Revérifier</button></div>
    </article>`;
}

function renderPipelinePageHtml(model = {}, nonce = '', theme = 'light') {
  const activeTab = TABS.some(([id]) => id === model.tab) ? model.tab : 'pipeline';
  // COMPACT mode: a presence, not an assistant. This page has its own decision
  // story to tell, so the companion stays small and only speaks when the state
  // it reports actually warrants it. Same shared model as the Live Security page.
  const companion = renderCompanionWidget(model.companion, {
    variant: 'compact', enabled: model.companionEnabled !== false
  });
  const body = activeTab === 'correlations' ? renderCorrelationsTab(model)
    : activeTab === 'reachability' ? renderReachabilityTab(model)
      : activeTab === 'priorities' ? renderPrioritiesTab(model)
        : activeTab === 'policy' ? renderPolicyTab(model)
          : activeTab === 'supply-chain' ? renderSupplyChainTab(model)
            : renderPipelineTab(model);
  return `<!doctype html><html data-theme="${escapeHtml(theme)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>
    :root{color-scheme:light;--bg:#f7f8fb;--card:#fff;--text:#26344a;--muted:#687386;--border:#d8deea;--accent:#5577d8;--ok:#2f9e62;--warn:#c58a19;--bad:#d9534f}html[data-theme=dark]{color-scheme:dark;--bg:#181818;--card:#222;--text:#ddd;--muted:#aaa;--border:#444;--accent:#7aa2ff;--ok:#75ce91;--warn:#e0ad4f;--bad:#ff7b72}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13px var(--vscode-font-family,Segoe UI);padding:28px}.wrap{max-width:1120px;margin:auto}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:18px}h1{font-size:28px;margin:0 0 7px}h3{font-size:15px;margin:0}p{color:var(--muted);margin:4px 0;line-height:1.5}.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px}.tabs button{background:transparent;color:var(--muted);border:1px solid transparent;border-radius:6px;padding:7px 13px;font:inherit;cursor:pointer}.tabs button[aria-current=true]{background:var(--card);border-color:var(--border);color:var(--text);font-weight:700}.section-title{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:22px 0 10px}.stages{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;margin:0;padding:0}.stage{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--muted);border-radius:8px;padding:13px;cursor:pointer}.stage:focus-visible{outline:2px solid var(--vscode-focusBorder,var(--accent));outline-offset:2px}.stage.ok{border-left-color:var(--ok)}.stage.warn{border-left-color:var(--warn)}.stage.bad{border-left-color:var(--bad)}.stage-head{display:flex;justify-content:space-between;gap:10px;align-items:baseline}.stage-name{font-weight:700}.stage-state{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.stage.ok .stage-state{color:var(--ok)}.stage.warn .stage-state{color:var(--warn)}.stage.bad .stage-state{color:var(--bad)}.stage-detail{font-size:12px;margin:6px 0 0}.banner{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--muted);border-radius:8px;padding:15px;margin-bottom:16px}.banner.ok{border-left-color:var(--ok)}.banner.warn{border-left-color:var(--warn)}.banner.bad{border-left-color:var(--bad)}.violations{margin:10px 0 0;padding-left:18px}.violations li{margin:5px 0;color:var(--text)}.violations.warn li{color:var(--muted)}.violation-rule{font-family:var(--vscode-editor-font-family,monospace);font-size:11px;background:color-mix(in srgb,var(--accent) 12%,var(--card));padding:1px 5px;border-radius:3px;margin-right:6px}.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px}.card.ok{border-left:3px solid var(--ok)}.card.warn{border-left:3px solid var(--warn)}.card.bad{border-left:3px solid var(--bad)}.card-head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.card-head small{color:var(--muted);display:block;margin-top:3px}.chip{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,var(--card));padding:2px 7px;border-radius:99px;margin-bottom:5px}.tool-chip{display:inline-block;border:1px solid var(--border);border-radius:99px;padding:2px 9px;margin:0 5px 4px 0;font-weight:600}.confidence{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}.confidence.high{color:var(--ok)}.confidence.medium{color:var(--warn)}.confidence.low{color:var(--muted)}dl{margin:13px 0}dl>div{display:grid;grid-template-columns:170px 1fr;padding:6px 0;border-top:1px solid var(--border)}dt{color:var(--muted)}dd{margin:0}.path{overflow-wrap:anywhere;font-family:var(--vscode-editor-font-family,monospace);font-size:12px}.reasons,.sources{margin-top:12px}.reasons-title{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700}.reasons ul,.sources ul,.evidence{margin:6px 0 0;padding-left:18px}.reasons li,.sources li,.evidence li{margin:4px 0}.points{color:var(--muted);font-family:var(--vscode-editor-font-family,monospace)}.summary-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.summary-tile{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;min-width:110px}.summary-tile strong{display:block;font-size:22px}.summary-tile span{color:var(--muted);font-size:12px}.summary-tile.bad strong{color:var(--bad)}.summary-tile.warn strong{color:var(--warn)}.score{font-size:26px;font-weight:800;white-space:nowrap}.priority-code{display:inline-block;font-size:12px;font-weight:800;letter-spacing:.04em;border:1px solid currentColor;border-radius:4px;padding:1px 6px;vertical-align:middle;margin-right:5px}.score small{font-size:12px;font-weight:400;color:var(--muted)}.score.critical{color:var(--bad)}.score.high{color:var(--warn)}.reach{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);white-space:nowrap}.reach.dynamically_confirmed{color:var(--bad)}.reach.statically_reachable{color:var(--warn)}.reach.not_reachable{color:var(--ok)}code{font-family:var(--vscode-editor-font-family,monospace);font-size:12px;background:color-mix(in srgb,var(--text) 7%,var(--card));padding:1px 5px;border-radius:3px}button{border:0;border-radius:4px;padding:8px 12px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}button.secondary{background:var(--vscode-button-secondaryBackground,#e8eaf0);color:var(--vscode-button-secondaryForeground,var(--text))}button.link{background:none;color:var(--accent);padding:0;text-align:left}button:disabled{opacity:.55;cursor:not-allowed}button:focus-visible{outline:2px solid var(--vscode-focusBorder,var(--accent));outline-offset:2px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}.footnote{font-size:12px;margin-top:14px}.muted,.muted-state{color:var(--muted)}.inline-note{color:var(--muted);font-size:12px;align-self:center}.compact dl{margin:8px 0}h4.section-title{margin:18px 0 8px}.option{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-top:1px solid var(--border);cursor:pointer}.option:first-of-type{border-top:0}.option input[type=checkbox]{margin:2px 0 0;width:15px;height:15px;accent-color:var(--accent);flex:none}.option small{display:block;color:var(--muted);margin-top:2px}.option.number{justify-content:space-between;align-items:center;cursor:default}.option.number input{width:88px;padding:5px 7px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);font:inherit}@media(max-width:760px){body{padding:16px}.hero{display:block}dl>div{grid-template-columns:1fr}}
  ${companion ? companionWidgetCss() : ''}
  </style></head><body><main class="wrap">
  <header class="hero"><div><h1>Security Pipeline</h1><p>De la détection à la décision : corrélation, atteignabilité, priorité, politique projet et preuves supply chain.</p></div><div class="actions"><button data-command="securityCenter.scanWorkspace">Relancer l’analyse</button><button class="secondary" data-command="securityCenter.openDashboard">← Dashboard</button></div></header>
  <nav class="tabs">${TABS.map(([id, label]) => `<button data-tab="${escapeHtml(id)}"${id === activeTab ? ' aria-current="true"' : ''}>${escapeHtml(label)}</button>`).join('')}</nav>
  <section>${body}</section>
  </main>${companion}
  <script nonce="${nonce}">const vscode=acquireVsCodeApi();
  document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'tab',tab:b.dataset.tab}));
  document.querySelectorAll('[data-command]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  // The gate form is read at submit time, so the page keeps no state of its own:
  // the checkboxes are a view of security-center.yml, never a second copy of it.
  const policySelection=()=>{const s={};document.querySelectorAll('[data-policy-field]').forEach(i=>{s[i.dataset.policyField]=i.type==='checkbox'?i.checked:(i.value.trim()===''?null:Number(i.value));});return s;};
  document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'action',action:b.dataset.action,selection:b.dataset.action==='savePolicy'?policySelection():undefined}));
  document.querySelectorAll('[data-stage]').forEach(el=>{el.onclick=()=>vscode.postMessage({type:'stage',stage:el.dataset.stage});el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();vscode.postMessage({type:'stage',stage:el.dataset.stage});}};});
  document.querySelectorAll('[data-finding-index]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'finding',index:Number(b.dataset.findingIndex)}));
  document.querySelectorAll('[data-cluster-index]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'clusterSource',cluster:Number(b.dataset.clusterIndex),source:Number(b.dataset.sourceIndex)}));
  </script></body></html>`;
}

module.exports = {
  renderPipelinePageHtml, renderPipelineTab, renderCorrelationsTab, renderReachabilityTab,
  renderPrioritiesTab, renderPolicyTab, renderPolicyBanner, renderViolation,
  renderSupplyChainTab, renderStage, renderCluster, renderArtifactCard,
  renderAvailability, renderScanFooter,
  STATE_LABELS, REACHABILITY_LABELS, REACHABILITY_STATUS_LABELS, PRIORITY_CODE_LABELS,
  CORRELATION_LABELS, TIER_LABELS, POLICY_STATE_LABELS, TABS, stateClass, policyClass, escapeHtml
};
