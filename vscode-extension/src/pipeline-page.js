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
const { STATE_LABELS: VERIFICATION_LABELS, REASON_LABELS: VERIFICATION_REASONS } = require('./fix-verification');
const { renderCompanionWidget, companionWidgetCss } = require('./live/companionWidget');
const { renderSecurityCenterShell } = require('./security-center-shell');
const { buildAssistantCardModel, renderAssistantCard, assistantCardCss, assistantCardScript } = require('./companion-assistant-card');
const { scannerLogoUri } = require('./scanner-presentation');

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
  ['supply-chain', 'Supply Chain'],
  ['remediation', 'Corrections']
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
function getStatusBadge(state) {
  const badgeMap = {
    passed: { label: '✓ OK', cssClass: 'status-success' },
    running: { label: '● RUNNING', cssClass: 'status-running' },
    warning: { label: '! WARNING', cssClass: 'status-warning' },
    blocked: { label: '× FAILED', cssClass: 'status-error' },
    failed: { label: '× FAILED', cssClass: 'status-error' },
    not_configured: { label: '— NOT CONFIGURÉ', cssClass: 'status-neutral' },
    skipped: { label: '○ SKIPPED', cssClass: 'status-skipped' }
  };
  const badge = badgeMap[state] || { label: String(state).toUpperCase(), cssClass: 'status-neutral' };
  const stateLabel = STATE_LABELS[state] || state;
  return `<span class="status-badge ${badge.cssClass}" title="${escapeHtml(stateLabel)}">${escapeHtml(badge.label)} <small class="state-label-text" style="display: none;">${escapeHtml(stateLabel)}</small></span>`;
}

function renderToolBadge(tool, assets = {}, className = 'tool-chip') {
  const uri = scannerLogoUri(tool, assets);
  return `<span class="${escapeHtml(className)}" title="${escapeHtml(tool)}">
      ${uri ? `<img class="tool-logo-img" src="${escapeHtml(uri)}" alt="${escapeHtml(tool)} logo" loading="lazy">` : ''}
      <span>${escapeHtml(tool)}</span>
    </span>`;
}

function renderScanCard(stage, assets = {}) {
  const toolBadges = Array.isArray(stage.tools) && stage.tools.length
    ? stage.tools.map((tool) => renderToolBadge(tool, assets)).join('')
    : '';
  return `<div class="pipeline-card ${escapeHtml(stateClass(stage.state))}" data-stage="${escapeHtml(stage.id)}" tabindex="0" role="button" aria-label="${escapeHtml(stage.label)} — ${escapeHtml(STATE_LABELS[stage.state] || stage.state)}">
      <div class="card-top">
        <span class="card-icon" aria-hidden="true">◇</span>
        <span class="card-title">${escapeHtml(stage.label)}</span>
        ${getStatusBadge(stage.state)}
      </div>
      ${toolBadges ? `<div class="card-tools">${toolBadges}</div>` : ''}
      <p class="card-detail">${escapeHtml(stage.detail || 'Aucun résultat')}</p>
    </div>`;
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
  
  const labelMap = {
    PASS: 'Policy Gate — PASS (Livraison autorisée)',
    WARN: 'Policy Gate — WARN (Livraison autorisée avec avertissements)',
    BLOCK: 'Policy Gate — BLOCK (Livraison bloquée)',
    NOT_CONFIGURED: 'Policy Gate — NON CONFIGURÉ',
    ERROR: 'Policy Gate — ERROR (Configuration invalide)'
  };
  const titleText = labelMap[status] || `Policy Gate — ${status}`;

  if (status === 'ERROR') {
    return `<div class="policy-callout status-error" data-stage="policy" tabindex="0" role="button" aria-label="${escapeHtml(titleText)}">
      <div class="policy-callout-header">
        <div class="policy-callout-title">${escapeHtml(titleText)}</div>
      </div>
      <p>${escapeHtml(policy.error || 'La politique projet n’a pas pu être lue.')}</p>
      <p>Aucune livraison n’est autorisée sur cette base : le gate n’a pas pu être évalué.</p>
      <div class="actions">
        <button data-tab="policy">Corriger la politique</button>
        <button class="secondary" data-action="openPolicyYaml">Ouvrir security-center.yml</button>
      </div>
    </div>`;
  }
  if (!policy || !policy.configured) {
    return `<div class="policy-callout status-neutral" data-stage="policy" tabindex="0" role="button" aria-label="${escapeHtml(titleText)}">
      <div class="policy-callout-header">
        <div class="policy-callout-title">${escapeHtml(titleText)}</div>
      </div>
      <p>Aucune règle de gate trouvée dans <code>security-center.yml</code>. Security Center ne peut donc ni autoriser ni bloquer une livraison.</p>
      <div class="actions">
        <button data-tab="policy">Configurer la politique</button>
      </div>
    </div>`;
  }
  const violations = policy.violations || [];
  const warnings = policy.warnings || [];
  return `<div class="policy-callout ${escapeHtml(policyClass(status))}" data-stage="policy" tabindex="0" role="button" aria-label="${escapeHtml(titleText)}">
      <div class="policy-callout-header">
        <div class="policy-callout-title">${escapeHtml(titleText)}</div>
        <span class="policy-callout-stats">${violations.length} violation(s) bloquante(s) · ${warnings.length} avertissement(s)</span>
      </div>
      <p>${escapeHtml(policy.summary || '')}</p>
      ${violations.length ? `<ul class="violations">${violations.slice(0, 3).map((violation) => `<li><span class="violation-rule">${escapeHtml(violation.rule || violation.code)}</span> ${escapeHtml(violation.message)}${violation.file ? `<code>${escapeHtml(violation.file)}${violation.line ? `:${violation.line}` : ''}</code>` : ''}</li>`).join('')}</ul>` : ''}
      <div class="actions">
        <button data-tab="policy">${violations.length ? 'Voir les violations' : 'Détail de la politique'}</button>
      </div>
    </div>`;
}

function renderVisualPipelineFlowHtml(model, stages, assets = {}) {
  const scans = stages.filter((stage) => stage.kind === 'scan');
  const intelligenceFailed = model.intelligence?.status === 'failed';
  
  // 1. PROJECT status
  const isAnyScanRunning = scans.some(s => s.state === 'running');
  const projectStatus = isAnyScanRunning ? 'running' : (model.scanId ? 'passed' : 'neutral');

  // 2. DETECTION state
  const anyScanRunning = scans.some(s => s.state === 'running');
  const allScanFailed = scans.length > 0 && scans.every(s => s.state === 'failed');
  const anyScanBlocked = scans.some(s => s.state === 'blocked');
  const anyScanWarning = scans.some(s => s.state === 'warning');
  const anyScanPassed = scans.some(s => s.state === 'passed');
  
  let detectionState = 'not_configured';
  if (anyScanRunning) {
    detectionState = 'running';
  } else if (anyScanBlocked) {
    detectionState = 'blocked';
  } else if (allScanFailed) {
    detectionState = 'failed';
  } else if (anyScanWarning) {
    detectionState = 'warning';
  } else if (anyScanPassed) {
    detectionState = 'passed';
  } else if (scans.some(s => s.state !== 'not_configured')) {
    detectionState = 'passed';
  }

  // Micro scanners list
  const scannerStatuses = [];
  const allTools = ['Gitleaks', 'Semgrep', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP'];
  for (const tool of allTools) {
    const scanStatus = model.scanners?.find(s => s.tool.toLowerCase() === tool.toLowerCase())?.status;
    const isRunning = scans.some(s => s.state === 'running' && s.tools?.includes(tool));
    const isFailed = scans.some(s => s.state === 'failed' && s.tools?.includes(tool));
    const isPassed = scans.some(s => (s.state === 'passed' || s.state === 'warning' || s.state === 'blocked') && s.tools?.includes(tool));
    
    let symbol = '○';
    let cssClass = 'status-waiting';
    if (isRunning || scanStatus === 'running') {
      symbol = '◉';
      cssClass = 'status-running';
    } else if (scanStatus === 'completed' || isPassed) {
      symbol = '✓';
      cssClass = 'status-completed';
    } else if (scanStatus === 'failed' || isFailed) {
      symbol = '×';
      cssClass = 'status-failed';
    }
    scannerStatuses.push({ name: tool, symbol, cssClass, logoUri: scannerLogoUri(tool, assets) });
  }

  // 3. SECURITY INTELLIGENCE state
  const intelStages = stages.filter(s => s.kind === 'intelligence');
  const isIntelFailed = intelligenceFailed || (intelStages.length > 0 && intelStages.every(s => s.state === 'failed'));
  const isIntelRunning = intelStages.some(s => s.state === 'running');
  const isIntelSkipped = intelStages.length > 0 && intelStages.every(s => s.state === 'skipped' || s.state === 'not_configured');
  const anyIntelWarning = intelStages.some(s => s.state === 'warning');
  const anyIntelPassed = intelStages.some(s => s.state === 'passed');
  
  let intelState = 'not_configured';
  if (isIntelFailed) {
    intelState = 'failed';
  } else if (isIntelRunning) {
    intelState = 'running';
  } else if (isIntelSkipped) {
    intelState = 'skipped';
  } else if (anyIntelWarning) {
    intelState = 'warning';
  } else if (anyIntelPassed) {
    intelState = 'passed';
  }

  function getSubitemIndicator(state) {
    if (state === 'passed' || state === 'warning') return '✓';
    if (state === 'running') return '◉';
    if (state === 'failed') return '×';
    return '○';
  }

  // 4. POLICY GATE state
  const policyStage = stages.find(s => s.id === 'policy');
  const policyState = policyStage ? policyStage.state : 'not_configured';

  // 5. FINAL DESTINATION state
  let destLabel = 'DELIVERY';
  let destState = 'not_configured';
  let destDetail = 'En attente du gate';
  
  if (policyState === 'blocked') {
    destLabel = 'LIVRAISON BLOQUÉE';
    destState = 'blocked';
    destDetail = 'Pipeline bloqué';
  } else if (policyState === 'passed' || policyState === 'warning') {
    const artifactStages = stages.filter(s => s.kind === 'artifact');
    const anyArtifactRunning = artifactStages.some(s => s.state === 'running');
    const anyArtifactPassed = artifactStages.some(s => s.state === 'passed');
    
    if (anyArtifactRunning) {
      destLabel = 'SUPPLY CHAIN';
      destState = 'running';
      destDetail = 'Preuves en cours...';
    } else if (anyArtifactPassed) {
      destLabel = 'SUPPLY CHAIN PRÊTE';
      destState = 'passed';
      destDetail = 'Preuves générées';
    } else {
      destLabel = 'READY / POLICY PASSED';
      destState = 'passed';
      destDetail = 'Gate validé';
    }
  } else if (policyState === 'running') {
    destLabel = 'DELIVERY';
    destState = 'running';
    destDetail = 'Évaluation du gate...';
  }

  // 6. Connectors (lines) status
  // Line 1: PROJECT -> DETECTION
  let line1Status = 'connector-neutral';
  if (projectStatus === 'passed') {
    if (detectionState === 'running') {
      line1Status = 'connector-active';
    } else if (detectionState === 'passed' || detectionState === 'warning' || detectionState === 'blocked' || detectionState === 'failed') {
      line1Status = 'connector-completed';
    }
  } else if (projectStatus === 'running') {
    line1Status = 'connector-active';
  }

  // Line 2: DETECTION -> SECURITY INTELLIGENCE
  let line2Status = 'connector-neutral';
  if (detectionState === 'passed' || detectionState === 'warning') {
    if (intelState === 'running') {
      line2Status = 'connector-active';
    } else if (intelState === 'passed' || intelState === 'warning') {
      line2Status = 'connector-completed';
    } else if (intelState === 'failed' || intelState === 'skipped') {
      line2Status = 'connector-interrupted';
    }
  } else if (detectionState === 'blocked' || detectionState === 'failed') {
    line2Status = 'connector-interrupted';
  }

  // Line 3: SECURITY INTELLIGENCE -> POLICY GATE
  let line3Status = 'connector-neutral';
  if (intelState === 'passed' || intelState === 'warning') {
    if (policyState === 'running') {
      line3Status = 'connector-active';
    } else if (policyState === 'passed' || policyState === 'warning' || policyState === 'blocked' || policyState === 'failed') {
      line3Status = 'connector-completed';
    }
  } else if (intelState === 'failed' || intelState === 'skipped') {
    line3Status = 'connector-neutral';
  }

  // Line 4: POLICY GATE -> FINAL DESTINATION
  let line4Status = 'connector-neutral';
  if (policyState === 'passed' || policyState === 'warning') {
    if (destState === 'running') {
      line4Status = 'connector-active';
    } else if (destState === 'passed') {
      line4Status = 'connector-completed';
    }
  } else if (policyState === 'blocked' || policyState === 'failed') {
    line4Status = 'connector-interrupted';
  }

  return `
    <div class="visual-pipeline-flow">
      <!-- PROJECT NODE -->
      <div class="flow-node node-project ${escapeHtml(projectStatus)}" data-stage="project" tabindex="0" role="button" aria-label="Project Status — ${escapeHtml(projectStatus)}">
        <div class="node-ring"></div>
        <div class="node-content">
          <div class="node-label">PROJECT</div>
          <div class="node-sub">Source</div>
        </div>
      </div>
      
      <div class="flow-line ${escapeHtml(line1Status)}">
        <div class="flow-pulse"></div>
      </div>

      <!-- DETECTION NODE -->
      <div class="flow-node node-detection ${escapeHtml(detectionState)}" data-stage="secrets" tabindex="0" role="button" aria-label="Detection Status — ${escapeHtml(detectionState)}">
        <div class="node-ring"></div>
        <div class="node-content">
          <div class="node-label">DETECTION</div>
          <div class="node-sub">Security Scanners</div>
          <div class="node-scanners-micro">
            ${scannerStatuses.map(s => `<span class="micro-scanner ${escapeHtml(s.cssClass)}" title="${escapeHtml(s.name)}">${s.logoUri ? `<img class="micro-scanner-logo" src="${escapeHtml(s.logoUri)}" alt="${escapeHtml(s.name)} logo" loading="lazy">` : `<span>${escapeHtml(s.name[0])}</span>`}<small>${escapeHtml(s.symbol)}</small></span>`).join('')}
          </div>
        </div>
      </div>

      <div class="flow-line ${escapeHtml(line2Status)}">
        <div class="flow-pulse"></div>
      </div>

      <!-- INTELLIGENCE NODE -->
      <div class="flow-node node-intel ${escapeHtml(intelState)}" data-stage="correlation" tabindex="0" role="button" aria-label="Intelligence Status — ${escapeHtml(intelState)}">
        <div class="node-ring"></div>
        <div class="node-content">
          <div class="node-label">SECURITY INTEL</div>
          <div class="node-sub">${intelState === 'failed' || intelState === 'skipped' ? 'UNAVAILABLE ×' : 'Intelligence'}</div>
          ${intelState !== 'failed' && intelState !== 'skipped' ? `
          <div class="intel-micro-list">
            <div><span>◇ Correlation</span> <span class="indicator">${escapeHtml(getSubitemIndicator(stages.find(s => s.id === 'correlation')?.state))}</span></div>
            <div><span>◇ Reachability</span> <span class="indicator">${escapeHtml(getSubitemIndicator(stages.find(s => s.id === 'reachability')?.state))}</span></div>
            <div><span>◇ Prioritisation</span> <span class="indicator">${escapeHtml(getSubitemIndicator(stages.find(s => s.id === 'priority')?.state))}</span></div>
          </div>
          ` : ''}
        </div>
      </div>

      <div class="flow-line ${escapeHtml(line3Status)}">
        <div class="flow-pulse"></div>
      </div>

      <!-- POLICY GATE NODE -->
      <div class="flow-node node-policy ${escapeHtml(policyState)}" data-stage="policy" tabindex="0" role="button" aria-label="Policy Gate Status — ${escapeHtml(policyState)}">
        <div class="node-ring"></div>
        <div class="node-content">
          <div class="node-label">POLICY GATE</div>
          <div class="node-sub">${policyState === 'blocked' ? 'BLOCKED ×' : policyState === 'passed' || policyState === 'warning' ? 'PASS ✓' : policyState === 'running' ? 'EVALUATING ●' : 'NOT CONFIGURED'}</div>
        </div>
      </div>

      <div class="flow-line ${escapeHtml(line4Status)}">
        <div class="flow-pulse"></div>
      </div>

      <!-- FINAL DESTINATION -->
      <div class="flow-node node-destination ${escapeHtml(destState)}" data-stage="signing" tabindex="0" role="button" aria-label="Delivery Destination — ${escapeHtml(destLabel)}">
        <div class="node-ring"></div>
        <div class="node-content">
          <div class="node-label">${escapeHtml(destLabel)}</div>
          <div class="node-sub">${escapeHtml(destDetail)}</div>
        </div>
      </div>
    </div>
  `;
}

function renderPipelineTab(model, assets = {}) {
  const stages = model.stages || [];
  const intelligenceFailed = model.intelligence?.status === 'failed';
  
  const scans = stages.filter((stage) => stage.kind === 'scan');
  const intelligenceItems = stages.filter((stage) => stage.kind === 'intelligence');
  const artifacts = stages.filter((stage) => stage.kind === 'artifact');

  const policyBanner = renderPolicyBanner(model);
  
  const intelligenceBanner = intelligenceFailed
    ? `<div class="policy-callout status-error" style="margin-bottom: 20px;">
        <div class="policy-callout-header">
          <div class="policy-callout-title">⚠️ Security Intelligence indisponible</div>
        </div>
        <p>${escapeHtml(model.intelligence.error || '')} — les résultats des scanners restent affichés et n’ont pas été modifiés. La corrélation, l’atteignabilité et la priorisation ne sont pas disponibles pour ce scan.</p>
      </div>`
    : '';

  if (!stages.length) {
    return `<p class="footnote">Aucune analyse enregistrée. Lancez une analyse du workspace pour alimenter le pipeline.</p>`;
  }

  return `${intelligenceBanner}
    ${renderVisualPipelineFlowHtml(model, stages, assets)}
    <div class="pipeline-flow">
      <!-- Section 1: ANALYSE -->
      <section class="flow-section">
        <h3 class="flow-section-title">1. ANALYSE</h3>
        <div class="pipeline-grid">
          ${scans.map((stage) => renderScanCard(stage, assets)).join('')}
        </div>
      </section>

      <div class="flow-connector">↓</div>

      <!-- Section 2: SECURITY INTELLIGENCE -->
      <section class="flow-section">
        <h3 class="flow-section-title">2. SECURITY INTELLIGENCE</h3>
        <div class="intelligence-container ${intelligenceFailed ? 'failed' : ''}">
          <div class="intelligence-row">
            ${intelligenceItems.map(stage => `
              <div class="intel-subcard ${escapeHtml(stateClass(stage.state))}" data-stage="${escapeHtml(stage.id)}" tabindex="0" role="button" aria-label="${escapeHtml(stage.label)} — ${escapeHtml(STATE_LABELS[stage.state] || stage.state)}">
                <div class="intel-subcard-head">
                  <span class="intel-subcard-title">${escapeHtml(stage.label)}</span>
                  ${getStatusBadge(stage.state)}
                </div>
                <p class="intel-subcard-detail">${escapeHtml(stage.detail || '')}</p>
              </div>
            `).join('')}
          </div>
        </div>
      </section>

      <div class="flow-connector">↓</div>

      <!-- Section 3: DECISION -->
      <section class="flow-section">
        <h3 class="flow-section-title">3. DÉCISION</h3>
        ${policyBanner}
      </section>

      <div class="flow-connector">↓</div>

      <!-- Section 4: SUPPLY CHAIN -->
      <section class="flow-section">
        <h3 class="flow-section-title">4. PREUVES SUPPLY CHAIN</h3>
        <div class="supply-chain-grid">
          ${artifacts.map(stage => `
            <div class="supply-card ${escapeHtml(stateClass(stage.state))}" data-stage="${escapeHtml(stage.id)}" tabindex="0" role="button" aria-label="${escapeHtml(stage.label)} — ${escapeHtml(STATE_LABELS[stage.state] || stage.state)}">
              <div class="supply-card-header">
                <span class="supply-card-title">${escapeHtml(stage.label)}</span>
                ${getStatusBadge(stage.state)}
              </div>
              <p class="supply-card-detail">${escapeHtml(stage.detail || '')}</p>
            </div>
          `).join('')}
        </div>
      </section>
    </div>
    
    ${model.scanId ? renderScanFooter(model) : ''}`;
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

/**
 * Corrections appliquées.
 *
 * Reads what the fix lifecycle already stores on each finding — no second
 * persistence, no second correction engine. A finding qualifies when it carries
 * a fix source, an applied timestamp or a verification verdict.
 *
 * Deliberately absent: a before/after diff. Security Center persists the
 * rollback text for the *last* patch only, in memory; there is no per-finding
 * diff to reuse, so none is shown and no « Voir le diff » button is offered
 * rather than rendering one that would be dead for every historical entry.
 */
const REMEDIATION_STATES = Object.freeze(['fixed', 'validating', 'validated', 'still_present', 'validation_failed', 'inconclusive', 'regressed']);

const FIX_SOURCE_LABELS = Object.freeze({
  ai: 'Correction IA (Ollama)',
  'quick-fix': 'Quick Fix déterministe',
  quickfix: 'Quick Fix déterministe',
  manual: 'Correction manuelle'
});

const REMEDIATION_TONE = Object.freeze({
  validated: 'ok', still_present: 'bad', regressed: 'bad',
  validation_failed: 'warn', inconclusive: 'warn', fixed: 'muted', validating: 'muted'
});

function appliedCorrections(findings = []) {
  return findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => finding && (finding.fixSource || finding.fixedAt || finding.verification
      || REMEDIATION_STATES.includes(String(finding.triageStatus || ''))))
    .sort((left, right) => String(right.finding.fixedAt || right.finding.verification?.at || '')
      .localeCompare(String(left.finding.fixedAt || left.finding.verification?.at || '')));
}

function localTime(value) {
  if (!value) return '';
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toLocaleString('fr-FR') : '';
}

function remediationRow({ finding, index }) {
  const status = String(finding.triageStatus || '');
  const verification = finding.verification || null;
  const location = [finding.file || finding.endpoint || '', finding.startLine ? `:${finding.startLine}` : ''].join('');
  // Chaque ligne n'affiche que ce qui existe reellement.
  const facts = [
    ['Source', FIX_SOURCE_LABELS[String(finding.fixSource || '').toLowerCase()] || (finding.fixSource ? String(finding.fixSource) : '')],
    ['Appliquée le', localTime(finding.fixedAt)],
    ['Vérificateur', verification?.evidence?.tool || verification?.validator || ''],
    ['Vérifiée le', localTime(verification?.at)],
    ['Résultat', verification?.reason ? (VERIFICATION_REASONS[verification.reason] || verification.reason) : ''],
    ['Scan de vérification', verification?.evidence?.scanId != null ? String(verification.evidence.scanId) : ''],
    ['Résumé du modèle', finding.aiSummary || '']
  ].filter(([, value]) => String(value || '').trim());
  return `<article class="card compact remediation-entry">
      <div class="card-head">
        <div><strong>${escapeHtml(finding.title || 'Finding')}</strong><small>${escapeHtml(finding.tool || '')}${finding.ruleId ? ` · ${escapeHtml(finding.ruleId)}` : ''}${location ? ` · ${escapeHtml(location)}` : ''}</small></div>
        <span class="state-chip ${escapeHtml(REMEDIATION_TONE[status] || 'muted')}">${escapeHtml(VERIFICATION_LABELS[status] || status || '—')}</span>
      </div>
      <dl class="remediation-facts">${facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>
      <div class="actions">
        <button class="secondary" data-remediation-finding="${index}">Voir le finding</button>
        ${finding.absolutePath ? `<button class="secondary" data-remediation-code="${index}">Ouvrir le code</button>` : ''}
        <button class="secondary" data-remediation-verify="${index}">${status === 'validated' ? 'Revérifier' : 'Vérifier'}</button>
      </div>
    </article>`;
}

function renderRemediationTab(model) {
  const entries = appliedCorrections(model.findings || []);
  return `<section class="tab-panel">
    <div class="section-heading"><span>Corrections appliquées</span></div>
    <p class="tab-intro">Ce que Security Center a réellement appliqué et vérifié, dans l’ordre le plus récent d’abord.</p>
    <p class="remediation-caveat">« Validée » signifie que le finding d’origine n’était plus signalé par le scanner de vérification concerné. Cela ne remplace pas un test fonctionnel.</p>
    ${entries.length
      ? `<div class="card-grid">${entries.map(remediationRow).join('')}</div>`
      : '<div class="empty-state">Aucune correction appliquée pour l’instant. Une correction apparaît ici dès qu’un patch est appliqué à un finding.</div>'}
  </section>`;
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

/**
 * Le rail de contexte de Security Pipeline.
 *
 * Chaque nombre vient d'un resume que le pipeline a REELLEMENT produit :
 * `model.correlation` (correlation-v2), `model.reachability` (reachability),
 * `model.priority` (prioritization) et `model.policy` (policy-gate). Le rail ne
 * recalcule rien, ne repondere rien et n'affiche aucune carte dont les faits
 * manquent — un resume absent fait disparaitre sa carte, il ne devient pas zero.
 */
function renderPipelineRail(model, assistantCard) {
  const cards = [];

  // Etat du dernier passage. `scanId` et `finishedAt` sont persistes par le
  // pipeline ; « restaure » dit que les donnees viennent du workspaceState.
  if (model.scanId || model.finishedAt) {
    const intelligenceFailed = model.intelligence?.status === 'failed';
    cards.push(`<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>Dernier passage</strong>
        <span class="rail-pill ${intelligenceFailed ? 'bad' : 'ok'}">${intelligenceFailed ? '✕ Partiel' : '✓ Terminé'}</span></div>
      <div class="rail-facts">
        ${model.scanId ? `<div class="rail-fact"><span>Scan</span><strong title="${escapeHtml(String(model.scanId))}">${escapeHtml(String(model.scanId))}</strong></div>` : ''}
        ${model.finishedAt ? `<div class="rail-fact"><span>Terminé</span><strong>${escapeHtml(new Date(model.finishedAt).toLocaleString('fr-FR'))}</strong></div>` : ''}
        <div class="rail-fact"><span>Findings</span><strong>${escapeHtml(String((model.findings || []).length))}</strong></div>
        ${model.restored ? '<div class="rail-fact"><span>Source</span><strong>Restauré</strong></div>' : ''}
      </div>
    </section>`);
  }

  // Correlation : total, confirmes et outils contributeurs. Les outils sont
  // comptes sur les clusters reellement presents, pas devines.
  const correlation = model.correlation;
  if (correlation && Number.isFinite(Number(correlation.total))) {
    const tools = new Set();
    for (const cluster of model.clusters || []) {
      for (const source of cluster.sources || []) if (source.tool) tools.add(source.tool);
    }
    cards.push(`<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>Corrélation</strong></div>
      <div class="rail-facts">
        <div class="rail-fact"><span>Groupes</span><strong>${escapeHtml(String(correlation.total))}</strong></div>
        ${Number.isFinite(Number(correlation.confirmed)) ? `<div class="rail-fact"><span>Confirmés</span><strong class="tone-ok">${escapeHtml(String(correlation.confirmed))}</strong></div>` : ''}
        ${correlation.byTier ? `<div class="rail-fact"><span>Probables</span><strong>${escapeHtml(String(correlation.byTier.probable || 0))}</strong></div>` : ''}
        ${tools.size ? `<div class="rail-fact"><span>Outils</span><strong>${escapeHtml(String(tools.size))}</strong></div>` : ''}
      </div>
      <button class="rail-link secondary" data-tab="correlations">Voir les corrélations →</button>
    </section>`);
  }

  // Atteignabilite. `analysed: false` est un fait a montrer, pas un zero.
  const reachability = model.reachability;
  if (reachability) {
    const counts = reachability.counts || {};
    cards.push(`<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>Atteignabilité</strong>
        <span class="rail-pill ${reachability.analysed ? 'ok' : 'bad'}">${reachability.analysed ? '✓ Analysée' : '✕ Non analysée'}</span></div>
      <div class="rail-facts">
        ${Object.entries(counts).slice(0, 4).map(([key, value]) => `<div class="rail-fact"><span>${escapeHtml(REACHABILITY_LABELS[key] || key)}</span><strong>${escapeHtml(String(value))}</strong></div>`).join('')}
        ${Number.isFinite(Number(reachability.scannedFiles)) ? `<div class="rail-fact"><span>Fichiers analysés</span><strong>${escapeHtml(String(reachability.scannedFiles))}</strong></div>` : ''}
      </div>
      <button class="rail-link secondary" data-tab="reachability">Voir l’atteignabilité →</button>
    </section>`);
  }

  // Priorisation : le score le plus haut et la distribution P0..P3, tels que
  // l'algorithme existant les a produits. Aucun recalcul dans la presentation.
  const priority = model.priority;
  if (priority && priority.distribution) {
    const distribution = priority.distribution;
    cards.push(`<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>Priorisation</strong>
        ${Number.isFinite(Number(priority.highest)) ? `<span class="rail-pill">Max ${escapeHtml(String(priority.highest))}</span>` : ''}</div>
      <div class="rail-facts">
        ${['P0', 'P1', 'P2', 'P3'].map((code) => `<div class="rail-fact"><span>${code}</span><strong class="${code === 'P0' ? 'tone-bad' : code === 'P1' ? 'tone-warn' : ''}">${escapeHtml(String(distribution[code] || 0))}</strong></div>`).join('')}
      </div>
      <button class="rail-link secondary" data-tab="priorities">Voir les priorités →</button>
    </section>`);
  }

  // Policy Gate : le verdict existant, plus le decompte de ses regles. Une
  // politique non configuree le dit, et propose l'action de configuration.
  const policy = model.policy;
  if (policy) {
    const status = String(policy.status || '').toUpperCase();
    const configured = policy.configured !== false && status !== 'NOT_CONFIGURED';
    const tone = status === 'PASS' ? 'ok' : status === 'WARN' ? 'warn' : status === 'BLOCK' || status === 'ERROR' ? 'bad' : 'muted';
    const glyph = { ok: '✓', warn: '!', bad: '✕', muted: '·' }[tone];
    cards.push(`<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>Policy Gate</strong>
        <span class="rail-pill ${tone}">${glyph} ${escapeHtml(POLICY_STATE_LABELS[status] || status || 'Inconnu')}</span></div>
      ${configured ? `<div class="rail-facts">
        <div class="rail-fact"><span>Blocages</span><strong class="tone-bad">${escapeHtml(String((policy.violations || []).length))}</strong></div>
        <div class="rail-fact"><span>Avertissements</span><strong class="tone-warn">${escapeHtml(String((policy.warnings || []).length))}</strong></div>
        ${Number.isFinite(Number(policy.counts?.evaluatedFindings)) ? `<div class="rail-fact"><span>Évalués</span><strong>${escapeHtml(String(policy.counts.evaluatedFindings))}</strong></div>` : ''}
      </div>` : '<p class="rail-note">Aucune politique projet n’est configurée : le gate ne rend aucun verdict.</p>'}
      <button class="rail-link secondary" data-command="securityCenter.openProjectPolicy">${configured ? 'Ouvrir la politique →' : 'Configurer la politique →'}</button>
    </section>`);
  }

  return `${assistantCard}${cards.join('')}`;
}

/** Le style du rail, en tokens partages — aucune couleur en dur. */
function pipelineRailCss() {
  return `
    .rail-card{display:grid;gap:9px}
    .rail-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
    .rail-head strong{font-size:11.5px;color:var(--sc-text)}
    .rail-pill{flex:none;padding:3px 8px;border-radius:999px;font-size:8.5px;font-weight:800;letter-spacing:.4px;text-transform:uppercase;color:var(--sc-text-secondary);background:var(--sc-surface-secondary);white-space:nowrap}
    .rail-pill.ok{color:var(--sc-success);background:var(--sc-success-bg)}
    .rail-pill.warn{color:var(--sc-warning);background:var(--sc-warning-bg)}
    .rail-pill.bad{color:var(--sc-danger);background:var(--sc-danger-bg)}
    .rail-facts{display:grid;gap:6px}
    .rail-fact{display:flex;justify-content:space-between;align-items:baseline;gap:9px;min-width:0}
    .rail-fact span{flex:none;color:var(--sc-text-secondary);font-size:10px}
    .rail-fact strong{min-width:0;font-size:10.5px;color:var(--sc-text);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .rail-note{margin:0;color:var(--sc-text-secondary);font-size:10px;line-height:1.45}
    .rail-link{width:100%;margin-top:2px;padding:6px 9px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md,8px);
      color:var(--sc-text);background:var(--sc-surface);font:600 10px var(--vscode-font-family);cursor:pointer;text-align:center}
    .rail-link:hover{background:var(--sc-surface-secondary)}
    .rail-link:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:1px}
    .tone-ok{color:var(--sc-success)}.tone-warn{color:var(--sc-warning)}.tone-bad{color:var(--sc-danger)}`;
}

function renderPipelinePageHtml(model = {}, nonce = '', theme = 'light', assets = {}) {
  const companionImageUri = typeof assets === 'string' ? assets : assets?.companionImageUri || '';
  const cspSource = typeof assets === 'object' ? assets?.cspSource || '' : '';
  const activeTab = TABS.some(([id]) => id === model.tab) ? model.tab : 'pipeline';
  // COMPACT mode: a presence, not an assistant. This page has its own decision
  // story to tell, so the companion stays small and only speaks when the state
  // it reports actually warrants it. Same shared model as the Live Security page.
  // L'assistant du rail parle de la porte de politique telle que le pipeline
  // vient de la rendre — jamais d'un verdict recalcule ici. Sans verdict connu,
  // il ne s'affiche pas.
  const assistantCard = renderAssistantCard(buildAssistantCardModel({
    surface: 'pipeline',
    companion: model.companionEnabled === false ? null : model.companion,
    pipeline: { policyStatus: model.policy?.status || '' },
    enabled: model.companionEnabled !== false
  }), { mascotImageUri: companionImageUri });
  // Une seule mascotte par surface : la carte remplace le widget flottant
  // lorsqu'elle a quelque chose a dire, et lui rend la place sinon.
  const companion = assistantCard ? '' : renderCompanionWidget(model.companion, {
    variant: 'compact', enabled: model.companionEnabled !== false, imageUri: companionImageUri
  });
  const contextRail = renderPipelineRail(model, assistantCard);
  const body = activeTab === 'correlations' ? renderCorrelationsTab(model)
    : activeTab === 'reachability' ? renderReachabilityTab(model)
      : activeTab === 'priorities' ? renderPrioritiesTab(model)
        : activeTab === 'policy' ? renderPolicyTab(model)
          : activeTab === 'supply-chain' ? renderSupplyChainTab(model)
            : activeTab === 'remediation' ? renderRemediationTab(model)
            : renderPipelineTab(model, assets);
  return renderSecurityCenterShell({
    surface: 'pipeline',
    nonce,
    theme,
    title: 'Security Pipeline',
    subtitle: 'De la détection à la décision : corrélation, atteignabilité, priorité, politique projet et preuves supply chain',
    headerActions: `<button data-command="securityCenter.scanWorkspace">Relancer l’analyse</button>`,
    content: `<nav class="tabs">${TABS.map(([id, label]) => `<button data-tab="${escapeHtml(id)}"${id === activeTab ? ' aria-current="true"' : ''}>${escapeHtml(label)}</button>`).join('')}</nav>
  <section>${body}</section>`,
    // Le companion garde son modele et son rendu : il change seulement de place,
    // du coin de la page vers le rail de contexte du cadre.
    contextRail: `${contextRail}${companion}`,
    styles: `
    ${assistantCard ? assistantCardCss() : ''}
    ${pipelineRailCss()}

    body {
      --bg: var(--sc-bg);
      --card: var(--sc-surface);
      --text: var(--sc-text);
      --muted: var(--sc-text-secondary);
      --border: var(--sc-border);
      --accent: var(--sc-primary);
      
      --ok: #28a745;
      --warn: #d29922;
      --bad: #d94b40;
      --ok-bg: rgba(40, 167, 69, 0.06);
      --warn-bg: rgba(210, 153, 34, 0.06);
      --bad-bg: rgba(217, 75, 64, 0.06);
      --running-bg: rgba(70, 123, 215, 0.06);
      --running: #467bd7;
      
      --ok-glow: rgba(40, 167, 69, 0.15);
      --warn-glow: rgba(210, 153, 34, 0.15);
      --bad-glow: rgba(217, 75, 64, 0.15);
      --accent-glow: rgba(70, 123, 215, 0.2);
    }
    
    body.theme-dark {
      --ok: #4ca866;
      --warn: #e3c036;
      --bad: #d94b40;
      --ok-bg: rgba(76, 168, 102, 0.12);
      --warn-bg: rgba(227, 192, 54, 0.12);
      --bad-bg: rgba(217, 75, 64, 0.12);
      --running-bg: rgba(0, 122, 204, 0.12);
      --running: #007acc;
      
      --ok-glow: rgba(76, 168, 102, 0.25);
      --warn-glow: rgba(227, 192, 54, 0.25);
      --bad-glow: rgba(217, 75, 64, 0.25);
      --accent-glow: rgba(0, 122, 204, 0.3);
    }

    /* Keyframes for futuristic flow visualization */
    @keyframes pulse-horizontal {
      0% { left: 0%; opacity: 0; }
      10% { opacity: 1; }
      90% { opacity: 1; }
      100% { left: 100%; opacity: 0; }
    }
    @keyframes pulse-vertical {
      0% { top: 0%; opacity: 0; }
      10% { opacity: 1; }
      90% { opacity: 1; }
      100% { top: 100%; opacity: 0; }
    }
    @keyframes node-glow {
      0% { box-shadow: 0 0 4px var(--accent-glow); }
      50% { box-shadow: 0 0 12px var(--accent-glow); }
      100% { box-shadow: 0 0 4px var(--accent-glow); }
    }
    @keyframes border-pulse {
      0% { border-color: var(--border); }
      50% { border-color: var(--accent); }
      100% { border-color: var(--border); }
    }

    /* Visual Pipeline Flow styles */
    .visual-pipeline-flow {
      display: grid;
      grid-template-columns: minmax(118px,1fr) minmax(24px,44px) minmax(150px,1.2fr) minmax(24px,44px) minmax(160px,1.25fr) minmax(24px,44px) minmax(132px,1fr) minmax(24px,44px) minmax(132px,1fr);
      align-items: center;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 24px;
      gap: 0;
      overflow: hidden;
    }
    
    .flow-node {
      position: relative;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      min-width: 0;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
      gap: 4px;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .flow-node:hover {
      border-color: var(--accent);
    }
    .flow-node:focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    
    .flow-node.not_configured {
      opacity: 0.65;
    }
    
    .node-ring {
      position: absolute;
      top: -3px;
      left: -3px;
      right: -3px;
      bottom: -3px;
      border-radius: 10px;
      border: 2px solid transparent;
      z-index: 1;
      pointer-events: none;
    }
    .flow-node.passed .node-ring { border-color: var(--ok); box-shadow: 0 0 6px var(--ok-glow); }
    .flow-node.warning .node-ring { border-color: var(--warn); box-shadow: 0 0 6px var(--warn-glow); }
    .flow-node.blocked .node-ring, .flow-node.failed .node-ring { border-color: var(--bad); box-shadow: 0 0 6px var(--bad-glow); }
    .flow-node.running .node-ring {
      border-color: var(--accent);
      animation: node-glow 2s ease-in-out infinite;
    }
    .flow-node.running {
      animation: border-pulse 2s ease-in-out infinite;
    }
    
    .node-content {
      position: relative;
      z-index: 2;
      width: 100%;
    }
    
    .node-label {
      font-weight: 700;
      font-size: 11px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text);
    }
    
    .node-sub {
      font-size: 10px;
      color: var(--muted);
      margin-top: 1px;
    }
    
    /* Connectors */
    .flow-line {
      align-self: center;
      height: 2px;
      background: var(--border);
      position: relative;
      min-width: 24px;
    }
    .flow-line.connector-completed {
      background: var(--ok);
    }
    .flow-line.connector-interrupted {
      background: var(--bad);
    }
    .flow-line.connector-active {
      background: var(--accent);
    }
    
    .flow-pulse {
      display: none;
      width: 6px;
      height: 6px;
      background: var(--accent);
      border-radius: 50%;
      position: absolute;
      top: -2px;
      box-shadow: 0 0 8px var(--accent);
    }
    
    .flow-line.connector-active .flow-pulse {
      display: block;
      animation: pulse-horizontal 2s linear infinite;
    }
    
    /* Micro Scanners List */
    .node-scanners-micro {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      margin-top: 5px;
      border-top: 1px solid var(--border);
      padding-top: 5px;
    }
    .micro-scanner {
      display: inline-flex;
      align-items: center;
      justify-content:center;
      gap:3px;
      min-width:22px;
      height:18px;
      font-size: 8px;
      font-weight: 700;
      padding: 0 4px;
      border-radius: 2px;
      border: 1px solid var(--border);
      background: var(--card);
    }
    .micro-scanner small{font-size:8px;line-height:1}
    .micro-scanner-logo{width:12px;height:12px;object-fit:contain;display:block}
    .micro-scanner.status-completed {
      color: var(--ok);
      border-color: var(--ok);
    }
    .micro-scanner.status-running {
      color: var(--accent);
      border-color: var(--accent);
    }
    .micro-scanner.status-failed {
      color: var(--bad);
      border-color: var(--bad);
    }
    .micro-scanner.status-waiting {
      color: var(--muted);
      border-color: var(--border);
    }
    
    /* Micro Intel List */
    .intel-micro-list {
      display: flex;
      flex-direction: column;
      gap: 1px;
      margin-top: 5px;
      border-top: 1px solid var(--border);
      padding-top: 5px;
      font-size: 8px;
      color: var(--muted);
    }
    .intel-micro-list > div {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .intel-micro-list .indicator {
      font-weight: 700;
    }

    /* Responsive pipeline visual flow overrides */
    @media (max-width: 1050px) {
      .visual-pipeline-flow {
        grid-template-columns: minmax(0,1fr);
        align-items: stretch;
        width: 100%;
        padding: 12px;
      }
      .flow-node {
        width: 100%;
        min-height: 70px;
      }
      .flow-line {
        justify-self:center;
        width: 2px;
        height: 24px;
        min-height: 24px;
        margin: 4px 0;
        flex-grow: 0;
      }
      .flow-pulse {
        top: 0;
        left: -2px;
      }
      .flow-line.connector-active .flow-pulse {
        animation: pulse-vertical 2s linear infinite;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      .flow-pulse, .flow-node.running .node-ring, .flow-node.running {
        animation: none !important;
      }
      .flow-pulse {
        display: none !important;
      }
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--vscode-font-family, Segoe UI, -apple-system, sans-serif);
      font-size: 13px;
      line-height: 1.4;
      padding: 24px;
    }
    .wrap {
      max-width: 1120px;
      margin: auto;
    }
    
    .hero {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
      margin-bottom: 16px;
    }
    .hero h1 {
      font-size: 22px;
      font-weight: 600;
      margin: 0 0 4px 0;
    }
    .hero p {
      margin: 0;
      font-size: 12px;
      color: var(--muted);
    }
    .hero .actions {
      display: flex;
      gap: 8px;
    }
    
    /* Segmented tab navigation */
    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .tabs button {
      background: transparent;
      color: var(--muted);
      border: none;
      border-bottom: 2px solid transparent;
      border-radius: 0;
      padding: 6px 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .tabs button:hover {
      color: var(--text);
    }
    .tabs button[aria-current=true] {
      color: var(--accent);
      border-bottom-color: var(--accent);
      font-weight: 600;
    }
    
    /* Flow sections styles */
    .pipeline-flow {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    
    .flow-section {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    
    .flow-section-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 0 0 16px 0;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    
    .flow-connector {
      text-align: center;
      font-size: 20px;
      font-weight: bold;
      color: var(--border);
      margin: -4px 0;
      user-select: none;
    }
    
    /* Responsive grids */
    .pipeline-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 178px), 1fr));
      gap: 12px;
      width:100%;
      min-width:0;
    }
    
    .pipeline-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-width:0;
      min-height: 118px;
      transition: all 0.15s ease;
    }
    .pipeline-card:hover {
      border-color: var(--accent);
      box-shadow: 0 2px 8px rgba(0,0,0,0.04);
      transform: translateY(-1px);
    }
    .pipeline-card:focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    .card-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap:7px;
      margin-bottom: 8px;
      min-width:0;
    }
    .card-icon {
      font-size: 14px;
      color: var(--muted);
      margin-right: 4px;
    }
    .card-title {
      font-weight: 600;
      font-size: 13px;
      flex:1 1 auto;
      min-width:0;
      overflow-wrap:anywhere;
    }
    .card-tools {
      display:flex;
      flex-wrap:wrap;
      gap:5px;
      margin-bottom: 8px;
      min-width:0;
    }
    .tool-chip {
      display:inline-flex;
      align-items:center;
      gap:5px;
      max-width:100%;
      min-width:0;
      padding:3px 6px;
      border:1px solid var(--border);
      border-radius:5px;
      background:var(--bg);
      color:var(--muted);
      font-size:10px;
      font-weight:700;
      line-height:1.2;
    }
    .tool-chip span{min-width:0;overflow-wrap:anywhere}
    .tool-logo-img{display:block;width:14px;height:14px;object-fit:contain;flex:none}
    .status-badge{flex:none}
    .card-detail {
      font-size: 11px;
      color: var(--muted);
      margin: 0;
      overflow-wrap:anywhere;
    }
    
    /* Status Badge component */
    .status-badge {
      display: inline-flex;
      align-items: center;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .status-success {
      background: var(--ok-bg);
      color: var(--ok);
    }
    .status-running {
      background: var(--running-bg);
      color: var(--running);
    }
    .status-warning {
      background: var(--warn-bg);
      color: var(--warn);
    }
    .status-error {
      background: var(--bad-bg);
      color: var(--bad);
    }
    .status-neutral {
      background: rgba(120, 120, 120, 0.08);
      color: var(--muted);
    }
    .status-skipped {
      background: rgba(120, 120, 120, 0.08);
      color: var(--muted);
    }
    
    /* Security Intelligence Section */
    .intelligence-container {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      background: linear-gradient(180deg,color-mix(in srgb,var(--sc-primary) 5%,var(--card)),var(--card));
    }
    .intelligence-container.failed {
      border-color: var(--bad);
      background: var(--bad-bg);
    }
    .intelligence-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 190px), 1fr));
      gap: 12px;
    }
    
    .intel-subcard {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      min-width:0;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .intel-subcard-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:4px}
    .intel-subcard:hover {
      border-color: var(--accent);
    }
    .intel-subcard-title {
      font-weight: 600;
      font-size: 13px;
    }
    .intel-subcard-detail {
      font-size: 11px;
      color: var(--muted);
      margin: 0;
      overflow-wrap:anywhere;
    }
    
    /* Policy Callout Banner */
    .policy-callout {
      border: 1px solid var(--border);
      border-left: 4px solid var(--muted);
      border-radius: 6px;
      padding: 16px;
      background: var(--card);
    }
    .policy-callout.ok {
      border-left-color: var(--ok);
      background: var(--ok-bg);
    }
    .policy-callout.warn {
      border-left-color: var(--warn);
      background: var(--warn-bg);
    }
    .policy-callout.bad, .policy-callout.status-error {
      border-left-color: var(--bad);
      background: var(--bad-bg);
    }
    .policy-callout.status-neutral {
      border-left-color: var(--border);
      background: rgba(120, 120, 120, 0.02);
    }
    
    .policy-callout-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .policy-callout-title {
      font-weight: 700;
      font-size: 14px;
    }
    .policy-callout-stats {
      font-size: 11px;
      color: var(--muted);
    }
    
    /* Supply Chain Section */
    .supply-chain-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
    }
    .supply-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .supply-card:hover {
      border-color: var(--accent);
    }
    .supply-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .supply-card-title {
      font-weight: 600;
      font-size: 13px;
    }
    .supply-card-detail {
      font-size: 11px;
      color: var(--muted);
      margin: 0;
    }
    
    /* Existing card, banner, detail elements preserved for detail tabs */
    .section-title { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:22px 0 10px }
    .stages { list-style:none; display:grid; grid-template-columns:repeat(auto-fill,minmax(230px,1fr)); gap:12px; margin:0; padding:0 }
    .stage { background:var(--card); border:1px solid var(--border); border-left:3px solid var(--muted); border-radius:8px; padding:13px; cursor:pointer }
    .stage:focus-visible { outline:2px solid var(--vscode-focusBorder,var(--accent)); outline-offset:2px }
    .stage.ok { border-left-color:var(--ok) }
    .stage.warn { border-left-color:var(--warn) }
    .stage.bad { border-left-color:var(--bad) }
    .stage-head { display:flex; justify-content:space-between; gap:10px; align-items:baseline }
    .stage-name { font-weight:700 }
    .stage-state { font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; letter-spacing:.04em }
    .stage.ok .stage-state { color:var(--ok) }
    .stage.warn .stage-state { color:var(--warn) }
    .stage.bad .stage-state { color:var(--bad) }
    .stage-detail { font-size:12px; margin:6px 0 0 }
    
    .banner { background:var(--card); border:1px solid var(--border); border-left:3px solid var(--muted); border-radius:8px; padding:15px; margin-bottom:16px }
    .banner.ok { border-left-color:var(--ok) }
    .banner.warn { border-left-color:var(--warn) }
    .banner.bad { border-left-color:var(--bad) }
    
    .violations { margin:10px 0 0; padding-left:18px }
    .violations li { margin:5px 0; color:var(--text) }
    .violations.warn li { color:var(--muted) }
    .violation-rule { font-family:var(--vscode-editor-font-family,monospace); font-size:11px; background:color-mix(in srgb,var(--accent) 12%,var(--card)); padding:1px 5px; border-radius:3px; margin-right:6px }
    
    .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:12px }
    .card.ok { border-left:3px solid var(--ok) }
    .card.warn { border-left:3px solid var(--warn) }
    .card.bad { border-left:3px solid var(--bad) }
    .card-head { display:flex; justify-content:space-between; gap:14px; align-items:flex-start }
    .card-head small { color:var(--muted); display:block; margin-top:3px }
    
    .chip { display:inline-block; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; color:var(--accent); background:color-mix(in srgb,var(--accent) 12%,var(--card)); padding:2px 7px; border-radius:99px; margin-bottom:5px }
    .tool-chip { display:inline-block; border:1px solid var(--border); border-radius:99px; padding:2px 9px; margin:0 5px 4px 0; font-weight:600 }
    
    .confidence { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; white-space:nowrap }
    .confidence.high { color:var(--ok) }
    .confidence.medium { color:var(--warn) }
    .confidence.low { color:var(--muted) }
    
    dl { margin:13px 0 }
    dl>div { display:grid; grid-template-columns:170px 1fr; padding:6px 0; border-top:1px solid var(--border) }
    dt { color:var(--muted) }
    dd { margin:0 }
    .path { overflow-wrap:anywhere; font-family:var(--vscode-editor-font-family,monospace); font-size:12px }
    
    .reasons, .sources { margin-top:12px }
    .reasons-title { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); font-weight:700 }
    .reasons ul, .sources ul, .evidence { margin:6px 0 0; padding-left:18px }
    .reasons li, .sources li, .evidence li { margin:4px 0 }
    .points { color:var(--muted); font-family:var(--vscode-editor-font-family,monospace) }
    
    .summary-row { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px }
    .summary-tile { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:12px 16px; min-width:110px }
    .summary-tile strong { display:block; font-size:22px }
    .summary-tile span { color:var(--muted); font-size:12px }
    .summary-tile.bad strong { color:var(--bad) }
    .summary-tile.warn strong { color:var(--warn) }
    
    .score { font-size:26px; font-weight:800; white-space:nowrap }
    .priority-code { display:inline-block; font-size:12px; font-weight:800; letter-spacing:.04em; border:1px solid currentColor; border-radius:4px; padding:1px 6px; vertical-align:middle; margin-right:5px }
    .score small { font-size:12px; font-weight:400; color:var(--muted) }
    .score.critical { color:var(--bad) }
    .score.high { color:var(--warn) }
    
    .reach { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); white-space:nowrap }
    .reach.dynamically_confirmed { color:var(--bad)}
    .reach.statically_reachable { color:var(--warn) }
    .reach.not_reachable { color:var(--ok) }
    
    code { font-family:var(--vscode-editor-font-family,monospace); font-size:12px; background:color-mix(in srgb,var(--text) 7%,var(--card)); padding:1px 5px; border-radius:3px }
    
    button { border:0; border-radius:4px; padding:8px 12px; background:var(--accent); color:#fff; font:inherit; cursor:pointer }
    button.secondary { background:var(--vscode-button-secondaryBackground,#e8eaf0); color:var(--vscode-button-secondaryForeground,var(--text)) }
    button.link { background:none; color:var(--accent); padding:0; text-align:left }
    button:disabled { opacity:.55; cursor:not-allowed }
    button:focus-visible { outline:2px solid var(--vscode-focusBorder,var(--accent)); outline-offset:2px }
    .actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:13px }
    .footnote { font-size:12px; margin-top:14px }
    .muted, .muted-state { color:var(--muted) }
    .inline-note { color:var(--muted); font-size:12px; align-self:center }
    .compact dl { margin:8px 0 }
    h4.section-title { margin:18px 0 8px }
    .option { display:flex; gap:10px; align-items:flex-start; padding:8px 0; border-top:1px solid var(--border); cursor:pointer }
    .option:first-of-type { border-top:0 }
    .option input[type=checkbox] { margin:2px 0 0; width:15px; height:15px; accent-color:var(--accent); flex:none }
    .option small { display:block; color:var(--muted); margin-top:2px }
    .option.number { justify-content:space-between; align-items:center; cursor:default }
    .option.number input { width:88px; padding:5px 7px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); font:inherit }
    @media(max-width:760px){body{padding:16px}.hero{display:block}dl>div{grid-template-columns:1fr}}
    ${companion ? companionWidgetCss() : ''}`,
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();
  document.addEventListener('click', (e) => {
    const companionClick = e.target.closest('.sc-widget-mascot') || e.target.closest('.sc-widget-bubble');
    if (companionClick) {
      vscode.postMessage({ type: 'companion' });
    }
  });
  document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'tab',tab:b.dataset.tab}));
  // Le rail navigue par le meme message d'onglet que les barres du haut : les
  // deux chemins arrivent sur le seul handler existant, sans route en double.
  // La carte d'assistant apporte son propre relais : l'exclure ici evite que le
  // meme clic parte deux fois.
  document.querySelectorAll('[data-command]:not(.sc-nav-item):not(.sc-assistant [data-command])').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  // The gate form is read at submit time, so the page keeps no state of its own:
  // the checkboxes are a view of security-center.yml, never a second copy of it.
  const policySelection=()=>{const s={};document.querySelectorAll('[data-policy-field]').forEach(i=>{s[i.dataset.policyField]=i.type==='checkbox'?i.checked:(i.value.trim()===''?null:Number(i.value));});return s;};
  document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'action',action:b.dataset.action,selection:b.dataset.action==='savePolicy'?policySelection():undefined}));
  document.querySelectorAll('[data-stage]').forEach(el=>{el.onclick=()=>vscode.postMessage({type:'stage',stage:el.dataset.stage});el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();vscode.postMessage({type:'stage',stage:el.dataset.stage});}};});
  document.querySelectorAll('[data-finding-index]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'finding',index:Number(b.dataset.findingIndex)}));
  document.querySelectorAll('[data-remediation-finding]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'remediation',action:'finding',index:Number(b.dataset.remediationFinding)}));
  document.querySelectorAll('[data-remediation-code]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'remediation',action:'code',index:Number(b.dataset.remediationCode)}));
  document.querySelectorAll('[data-remediation-verify]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'remediation',action:'verify',index:Number(b.dataset.remediationVerify)}));
  document.querySelectorAll('[data-cluster-index]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'clusterSource',cluster:Number(b.dataset.clusterIndex),source:Number(b.dataset.sourceIndex)}));
  ${assistantCard ? assistantCardScript() : ''}`,
    csp: `default-src 'none'; img-src ${cspSource || "'self'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`
  });
}

module.exports = {
  renderPipelinePageHtml, renderPipelineRail, pipelineRailCss, renderPipelineTab, renderCorrelationsTab, renderReachabilityTab,
  renderPrioritiesTab, renderPolicyTab, renderPolicyBanner, renderViolation,
  renderSupplyChainTab, renderStage, renderCluster, renderArtifactCard,
  renderAvailability, renderScanFooter,
  STATE_LABELS, REACHABILITY_LABELS, REACHABILITY_STATUS_LABELS, PRIORITY_CODE_LABELS,
  CORRELATION_LABELS, TIER_LABELS, POLICY_STATE_LABELS, TABS, stateClass, policyClass, escapeHtml
};
