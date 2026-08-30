'use strict';

const { renderSecurityCenterShell } = require('./security-center-shell');

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

const INACTIVE = new Set(['false_positive', 'fixed', 'validated', 'accepted']);

/**
 * The audit actions that prove a finding was actually resolved.
 *
 * Exact names, never a prefix match. `fix.verification.*` covers nine lifecycle
 * states and only `validated` is a resolution: `fix.verification.fixed` means a
 * patch was applied and verification is still pending, and counting it would
 * measure « time to patch » while calling it MTTR.
 *
 * `finding.risk.accepted` is deliberately absent for the same reason: accepting
 * a risk closes a discussion, not a vulnerability.
 *
 * The legacy `status:` names are kept so history recorded by earlier versions
 * keeps contributing to the average instead of silently dropping out.
 */
const RESOLUTION_ACTIONS = new Set([
  // Emitted today by the extension.
  'finding.fixed',
  'finding.fix.validated',
  'fix.verification.validated',
  // Emitted by earlier versions; still present in existing backends.
  'status:fixed',
  'status:validated'
]);

function buildTrendReport(scans, auditEvents, days = 90, now = new Date()) {
  const cutoff = new Date(now.getTime() - days * 86400000);
  const ordered = [...scans].filter((scan) => new Date(scan.result.finished_at) >= cutoff)
    .sort((a, b) => new Date(a.result.finished_at) - new Date(b.result.finished_at));
  
  // Get standard/full completed tools across all scans in the period
  let maxToolsSize = -1;
  let targetTools = new Set();
  
  ordered.forEach(scan => {
    const scanners = scan.result.scanners || [];
    const completed = new Set(scanners.filter(s => s.status === 'completed').map(s => s.tool));
    if (completed.size > maxToolsSize) {
      maxToolsSize = completed.size;
      targetTools = completed;
    }
  });
  
  const isScanComparable = (scan) => {
    const scanners = scan.result.scanners || [];
    const hasFailedOrCancelled = scanners.some(s => s.status === 'failed' || s.status === 'cancelled');
    if (hasFailedOrCancelled) return false;
    
    const completed = new Set(scanners.filter(s => s.status === 'completed').map(s => s.tool));
    if (completed.size !== targetTools.size) return false;
    for (const tool of targetTools) {
      if (!completed.has(tool)) return false;
    }
    return true;
  };

  const points = ordered.map((scan) => {
    const active = scan.result.findings.filter((finding) => !INACTIVE.has(finding.triageStatus));
    return {
      scanId: scan.scan_id,
      date: scan.result.finished_at,
      total: scan.result.findings.length,
      active: active.length,
      critical: active.filter((finding) => String(finding.rawSeverity).toUpperCase() === 'CRITICAL').length,
      high: active.filter((finding) => ['HIGH', 'ERROR'].includes(String(finding.rawSeverity).toUpperCase())).length,
      medium: active.filter((finding) => ['MEDIUM', 'WARNING'].includes(String(finding.rawSeverity).toUpperCase())).length,
      low: active.filter((finding) => !['CRITICAL', 'HIGH', 'ERROR', 'MEDIUM', 'WARNING'].includes(String(finding.rawSeverity).toUpperCase())).length,
      scanners: scan.result.scanners || [],
      isComparable: isScanComparable(scan)
    };
  });

  for (let i = 0; i < points.length; i++) {
    const curr = points[i];
    if (!curr.isComparable) {
      curr.trend = { display: 'N/A Non comparable', color: 'muted', tooltip: 'Non comparable : couverture de scanners incomplète ou échec' };
      continue;
    }
    
    let prev = null;
    for (let j = i - 1; j >= 0; j--) {
      if (points[j].isComparable) {
        prev = points[j];
        break;
      }
    }
    
    if (!prev) {
      curr.trend = { display: '—', color: 'muted', tooltip: 'Premier snapshot comparable de la période' };
      continue;
    }
    
    const prevActive = prev.active;
    const currActive = curr.active;
    
    if (prevActive === 0 && currActive === 0) {
      curr.trend = { display: '→ 0 % Stable', color: 'neutral', tooltip: 'Stable (0 alerte)' };
      continue;
    }
    
    if (prevActive === 0) {
      curr.trend = { display: '↑ 100.0 % Dégradation', color: 'bad', tooltip: `Dégradation : augmentation de ${currActive} alertes` };
      continue;
    }
    
    const diff = currActive - prevActive;
    const pct = Math.abs((diff / prevActive) * 100).toFixed(1);
    
    if (diff > 0) {
      curr.trend = { display: `↑ ${pct} % Dégradation`, color: 'bad', tooltip: `Dégradation : augmentation de ${diff} alertes` };
    } else if (diff < 0) {
      curr.trend = { display: `↓ ${pct} % Amélioration`, color: 'good', tooltip: `Amélioration : diminution de ${Math.abs(diff)} alertes` };
    } else {
      curr.trend = { display: '→ 0 % Stable', color: 'neutral', tooltip: 'Stable (aucune modification)' };
    }
  }

  const firstSeen = new Map();
  for (const scan of ordered) {
    const seenAt = new Date(scan.result.finished_at);
    for (const finding of scan.result.findings) {
      // Indexed under both identities on purpose. A scanner that supplies a
      // fingerprint (Gitleaks, SonarQube, Snyk) is stored under it, but an audit
      // event carries `finding_id` — looking up only one of the two makes every
      // fingerprinted finding unresolvable and silently removes it from the MTTR.
      for (const identity of [finding.fingerprint, finding.id]) {
        if (identity && !firstSeen.has(identity)) firstSeen.set(identity, seenAt);
      }
    }
  }

  const resolvedIdentities = new Set();
  const resolutionHours = [];
  for (const event of [...auditEvents].sort((a, b) => new Date(a.created_at) - new Date(b.created_at))) {
    if (!RESOLUTION_ACTIONS.has(event.action) || resolvedIdentities.has(event.finding_id)) continue;
    const started = firstSeen.get(event.finding_id);
    if (!started) continue;
    resolutionHours.push(Math.max(0, (new Date(event.created_at) - started) / 3600000));
    resolvedIdentities.add(event.finding_id);
  }

  const mttrHours = resolutionHours.length ? resolutionHours.reduce((sum, value) => sum + value, 0) / resolutionHours.length : null;
  const latest = points.at(-1) || { active: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const previous = points.at(-2);
  
  return { days, points, latest, change: previous ? latest.active - previous.active : null, mttrHours, resolvedCount: resolutionHours.length };
}

/**
 * @param backendError message d'erreur REEL du backend, ou chaine vide.
 *   Les tendances viennent de l'historique des scans du backend : quand il ne
 *   repond pas, la page s'ouvre quand meme et le dit. Aucune serie n'est
 *   fabriquee — les compteurs restent ceux d'un rapport vide.
 */
function renderTrendReportHtml(reports, nonce, selectedTheme = 'light', backendError = '') {
  let reportsObj = reports;
  if (reports && (reports.points || reports.latest)) {
    reportsObj = { 7: reports, 30: reports, 90: reports };
  }
  const defaultReport = reportsObj[7] || { latest: { active: 0, critical: 0, high: 0, medium: 0, low: 0 }, change: null, mttrHours: null, resolvedCount: 0, points: [] };
  const initialActive = defaultReport.latest.active;
  const initialCritical = defaultReport.latest.critical;
  const initialCritHigh = defaultReport.latest.critical + defaultReport.latest.high;

  let initialMttr = '—';
  let initialMttrSub = 'Temps moyen de résolution';
  if (defaultReport.mttrHours !== null) {
    initialMttr = defaultReport.mttrHours < 24 ? `${defaultReport.mttrHours.toFixed(1)} h` : `${(defaultReport.mttrHours / 24).toFixed(1)} j`;
  } else {
    initialMttrSub = 'Aucune correction validée';
  }

  const sortedPoints = [...defaultReport.points].reverse();
  const recentScansPts = sortedPoints.slice(0, 5);
  const initialRecentScans = recentScansPts.length === 0
    ? '<li class="recent-scan-item" style="color: var(--vscode-descriptionForeground)">Aucune analyse enregistrée.</li>'
    : recentScansPts.map(pt => {
        const trend = pt.trend || { display: '—', color: 'muted', tooltip: '' };
        return `
          <li class="recent-scan-item ${pt.isComparable ? '' : 'non-comparable'}">
            <span class="recent-scan-dot ${pt.isComparable ? 'comparable' : 'non-comparable-dot'}"></span>
            <div class="recent-scan-details">
              <div class="recent-scan-meta">
                <span class="recent-scan-date">Scan #${pt.scanId} — ${escapeHtml(new Date(pt.date).toLocaleString('fr-FR'))}</span>
                <span class="recent-scan-status-badge ${pt.isComparable ? 'status-ok' : 'status-warn'}">
                  ${pt.isComparable ? 'Complet' : 'Partiel / Échec'}
                </span>
              </div>
              <div class="recent-scan-findings-summary">
                <strong class="findings-count">${pt.active} alertes actives</strong>
                <span class="severity-bullets">
                  <span class="sev-bullet crit">${pt.critical} Crit.</span> · 
                  <span class="sev-bullet high">${pt.high} High</span> · 
                  <span class="sev-bullet med">${pt.medium} Med.</span> · 
                  <span class="sev-bullet low">${pt.low} Low</span>
                </span>
              </div>
              <div class="recent-scan-trend-row">
                Tendance : <span class="trend-text ${trend.color}" title="${escapeHtml(trend.tooltip)}">${escapeHtml(trend.display)}</span>
              </div>
            </div>
          </li>
        `;
      }).join('');

  const initialRows = defaultReport.points.length === 0
    ? '<tr><td colspan="8" style="text-align: center; color: var(--vscode-descriptionForeground)">Aucun scan dans cette période.</td></tr>'
    : defaultReport.points.map(pt => {
      const trend = pt.trend || { display: '—', color: 'muted', tooltip: '' };
      return `
        <tr>
          <td>#${pt.scanId}</td>
          <td>${escapeHtml(new Date(pt.date).toLocaleString('fr-FR'))}</td>
          <td>${pt.active}</td>
          <td>${pt.critical}</td>
          <td>${pt.high}</td>
          <td>${pt.medium}</td>
          <td>${pt.low}</td>
          <td class="trend-cell ${trend.color}" title="${escapeHtml(trend.tooltip)}">${escapeHtml(trend.display)}</td>
        </tr>
      `;
    }).join('');

  const getChartSummary = (pts) => {
    if (pts.length === 0) return '0 snapshot • aucune analyse';
    const count = pts.length;
    const lastDate = new Date(pts[pts.length - 1].date);
    const pad = (n) => String(n).padStart(2, '0');
    const dateStr = `${pad(lastDate.getDate())}/${pad(lastDate.getMonth() + 1)}/${lastDate.getFullYear()} ${pad(lastDate.getHours())}:${pad(lastDate.getMinutes())}`;
    return `${count} snapshot${count > 1 ? 's' : ''} • dernière analyse ${dateStr}`;
  };

  const initialSummary = getChartSummary(defaultReport.points);

  const content = `
  ${backendError ? `<section class="backend-banner" role="alert"><strong>Tendances indisponibles</strong><p>${escapeHtml(backendError)}</p><p class="backend-hint">L’historique des scans provient du backend. Tant qu’il ne répond pas, aucune tendance ne peut être calculée : rien n’est estimé à sa place.</p></section>` : ''}
  <!-- KPI cards -->
  <div class="cards">
    <div class="card card-active">
      <div class="kpi-icon-container">
        <svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 0c-.2 0-.3.1-.4.2l-6 2c-.3.1-.5.4-.5.7v3.5c0 4.1 2.9 8.1 6.6 9.5.2.1.4.1.6 0 3.7-1.4 6.6-5.4 6.6-9.5V2.9c0-.3-.2-.6-.5-.7l-6-2c-.1-.1-.2-.2-.4-.2zm0 1.5l5 1.7v3.2c0 3.2-2.2 6.4-5 7.6-2.8-1.2-5-4.4-5-7.6V3.2l5-1.7z"/></svg>
      </div>
      <div class="kpi-content">
        <strong id="kpi-active-val">${initialActive}</strong>
        <small>Alertes actives</small>
        <div class="kpi-subtext">Total à traiter sur le projet</div>
      </div>
    </div>
    <div class="card card-critical">
      <div class="kpi-icon-container">
        <svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.146.146 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.163.163 0 0 1-.054.06.116.116 0 0 1-.066.017H1.146a.115.115 0 0 1-.066-.017.163.163 0 0 1-.054-.06.176.176 0 0 1 .002-.183L7.884 2.073a.147.147 0 0 1 .054-.057zm1.044 8.047a.5.5 0 0 0-.964 0l-.333 3a.5.5 0 1 0 .964 0l.333-3zM8 12a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/></svg>
      </div>
      <div class="kpi-content">
        <strong id="kpi-critical-val">${initialCritical}</strong>
        <small>Failles critiques</small>
        <div class="kpi-subtext">Priorité de remédiation absolue</div>
      </div>
    </div>
    <div class="card card-crithigh">
      <div class="kpi-icon-container">
        <svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M7.002 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0L7.1 4.995z"/></svg>
      </div>
      <div class="kpi-content">
        <strong id="kpi-critical-high-val">${initialCritHigh}</strong>
        <small>Critiques + Hautes</small>
        <div class="kpi-subtext">Bloquants pour la mise en production</div>
      </div>
    </div>
    <div class="card card-mttr">
      <div class="kpi-icon-container">
        <svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7 9V3.5a.5.5 0 0 1 .5-.5z"/></svg>
      </div>
      <div class="kpi-content">
        <strong id="kpi-mttr-val">${initialMttr}</strong>
        <small>Délai de correction (MTTR)</small>
        <div class="kpi-subtext" id="kpi-mttr-sub">${initialMttrSub}</div>
      </div>
    </div>
  </div>

  <!-- SVG Chart Workspace -->
  <section class="workspace-section">
    <h2>Évolution des vulnérabilités</h2>
    <div class="chart-summary-bar" id="chart-summary-text">${initialSummary}</div>

    <div class="comparability-warning" id="comparability-warning" style="display: none;"></div>

    <!-- Legend toggles -->
    <div class="trend-legend">
      <button class="legend-btn active" data-series="total"><span class="legend-color" style="background: var(--trend-total);"></span>Total</button>
      <button class="legend-btn active" data-series="critical"><span class="legend-color" style="background: var(--trend-critical);"></span>Critical</button>
      <button class="legend-btn active" data-series="high"><span class="legend-color" style="background: var(--trend-high);"></span>High</button>
      <button class="legend-btn" data-series="medium"><span class="legend-color" style="background: var(--trend-medium);"></span>Medium</button>
      <button class="legend-btn" data-series="low"><span class="legend-color" style="background: var(--trend-low);"></span>Low</button>
      <span class="legend-info"><span class="legend-color" style="background: transparent; border: 1.5px dashed var(--vscode-descriptionForeground, #a0a0a0); box-sizing: border-box; width: 10px; height: 10px;"></span>Non comparable</span>
    </div>

    <!-- Chart container with SVG -->
    <div class="trend-chart-wrapper" id="chart-wrapper">
      <svg class="trend-chart" id="svg-chart" viewBox="0 0 900 400" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="trend-tooltip" id="tooltip"></div>
    </div>

    <!-- Brush timeline for dense histories -->
    <div class="brush-container" id="brush-container" style="display: none;">
      <svg class="brush-svg" id="brush-svg" viewBox="0 0 900 50" preserveAspectRatio="xMidYMid meet"></svg>
    </div>

    <!-- Chart footer summary + compact activity -->
    <div class="chart-footer" id="chart-footer">
      <div class="footer-metrics-grid" id="chart-footer-metrics"></div>
      <div class="footer-recent-activity">
        <h3 class="footer-section-title">Activité récente</h3>
        <ul class="recent-scans-list" id="recent-activity-list">
          ${initialRecentScans}
        </ul>
      </div>
    </div>
  </section>

  <!-- Collapsible raw table -->
  <details class="raw-history-details" id="history-details">
    <summary>Historique de la période</summary>
    <div class="raw-history-content">
      <table>
        <thead>
          <tr>
            <th>Scan</th>
            <th>Date</th>
            <th>Actives</th>
            <th>Critiques</th>
            <th>Hautes</th>
            <th>Moyennes</th>
            <th>Faibles</th>
            <th>Tendance <span class="help-icon" title="Variation du nombre d’alertes actives par rapport au snapshot précédent.">ⓘ</span></th>
          </tr>
        </thead>
        <tbody id="raw-scans-tbody">
          ${initialRows}
        </tbody>
      </table>
    </div>
  </details>`;

  return renderSecurityCenterShell({
    surface: 'trends',
    nonce,
    theme: selectedTheme,
    title: 'Tendances de sécurité',
    subtitle: "Analyse de l'évolution des vulnérabilités dans le temps",
    headerActions: `      <div class="period-selector">
        <button class="period-btn active" data-days="7">7 jours</button>
        <button class="period-btn" data-days="30">30 jours</button>
        <button class="period-btn" data-days="90">90 jours</button>
      </div>`,
    content,
    styles: `
    
    body {
      --page-background: var(--sc-bg);
      --card-background: var(--sc-surface);
      --vscode-foreground: var(--sc-text);
      --vscode-descriptionForeground: var(--sc-text-secondary);
      --vscode-panel-border: var(--sc-border);
      
      --trend-total: var(--vscode-charts-blue, #4F7DF3);
      --trend-critical: var(--vscode-charts-red, #E5534B);
      --trend-high: var(--vscode-charts-orange, #F59E42);
      --trend-medium: var(--vscode-charts-purple, #8B5CF6);
      --trend-low: var(--vscode-charts-green, #45B36B);
    }

    .trend-report-wrapper { background: var(--page-background); color: var(--vscode-foreground); }
    

    .backend-banner { margin: 0 0 18px; padding: 13px 15px; border: 1px solid var(--sc-warning, #d29922); border-left: 3px solid var(--sc-warning, #d29922); border-radius: 8px; background: var(--sc-warning-bg, rgba(210,153,34,.08)); }
    .backend-banner strong { display: block; font-size: 13px; }
    .backend-banner p { margin: 5px 0 0; font-size: 11px; color: var(--vscode-descriptionForeground); }
    .backend-banner .backend-hint { opacity: .85; }
    .page-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .brand-header {
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .brand-title {
      display: flex;
      align-items: center;
      gap: 8px;
      border-right: 1px solid var(--vscode-panel-border);
      padding-right: 20px;
    }
    .brand-logo {
      color: var(--trend-total);
    }
    .brand-name-group {
      display: flex;
      flex-direction: column;
      line-height: 1.1;
    }
    .brand-name {
      font-weight: 700;
      font-size: 15px;
      color: var(--vscode-foreground);
    }
    .brand-sub {
      font-size: 10px;
      color: var(--vscode-descriptionForeground);
    }
    .page-title-group h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 600;
      color: var(--vscode-foreground);
    }
    .page-subtitle {
      margin: 2px 0 0 0;
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
    }
    .header-actions {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .back {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: 0;
      border-radius: 5px;
      padding: 9px 13px;
      cursor: pointer;
      font-family: inherit;
    }
    .back:hover {
      background: var(--vscode-button-secondaryHoverBackground);
    }

    /* Period selector styles */
    .period-selector {
      display: inline-flex;
      background: var(--vscode-button-secondaryBackground, var(--vscode-panel-border));
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
    }
    .period-btn {
      background: transparent;
      border: 0;
      color: var(--vscode-foreground);
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 13px;
      cursor: pointer;
      font-family: inherit;
      transition: background 0.15s, color 0.15s;
    }
    .period-btn.active {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }

    /* KPI Row Cards */
    .cards {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin: 24px 0;
    }
    .card {
      display: flex;
      flex-direction: row;
      align-items: flex-start;
      gap: 16px;
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.03);
    }
    .kpi-icon-container {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .card-active .kpi-icon-container {
      background: rgba(79, 125, 243, 0.15);
      color: var(--trend-total);
    }
    .card-critical .kpi-icon-container {
      background: rgba(229, 83, 75, 0.15);
      color: var(--trend-critical);
    }
    .card-crithigh .kpi-icon-container {
      background: rgba(245, 158, 66, 0.15);
      color: var(--trend-high);
    }
    .card-mttr .kpi-icon-container {
      background: rgba(69, 179, 107, 0.15);
      color: var(--trend-low);
    }
    .kpi-content {
      display: flex;
      flex-direction: column;
      flex-grow: 1;
    }
    .kpi-content small {
      color: var(--vscode-descriptionForeground);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      margin-bottom: 4px;
    }
    .card strong {
      font-size: 26px;
      font-weight: 700;
      line-height: 1.2;
      margin-bottom: 6px;
      color: var(--vscode-foreground);
    }
    .kpi-subtext {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      border-top: 1px dashed var(--vscode-panel-border);
      padding-top: 6px;
      margin-top: 4px;
    }

    /* Visual Trends Workspace Area */
    .workspace-section {
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.02);
      margin-bottom: 24px;
    }
    .workspace-section h2 {
      margin-top: 0;
      margin-bottom: 4px;
      font-size: 16px;
      font-weight: 600;
    }
    .chart-summary-bar {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 16px;
      font-weight: 400;
    }
    .comparability-warning {
      background: var(--vscode-editor-inactiveSelectionBackground, rgba(200, 200, 200, 0.08));
      border-left: 3px solid var(--vscode-charts-orange, #F59E42);
      padding: 8px 12px;
      font-size: 12px;
      margin-bottom: 16px;
      border-radius: 4px;
      color: var(--vscode-foreground);
    }

    /* Chart styles */
    .trend-chart-wrapper {
      position: relative;
      width: 100%;
      height: 400px;
      margin-bottom: 8px;
    }
    @media (min-width: 769px) {
      .trend-chart-wrapper {
        height: 480px;
      }
    }
    .trend-chart {
      width: 100%;
      height: 100%;
      overflow: visible;
      cursor: crosshair;
    }
    .grid-line {
      stroke: var(--vscode-panel-border);
      stroke-width: 1;
      stroke-dasharray: 3, 3;
      opacity: 0.6;
    }
    .axis-line {
      stroke: var(--vscode-panel-border);
      stroke-width: 1;
    }
    .axis-text {
      fill: var(--vscode-descriptionForeground);
      font-size: 10px;
      font-family: var(--vscode-font-family);
    }
    .axis-text-y {
      font-family: var(--vscode-font-family);
    }
    .chart-path {
      fill: none;
      stroke-width: 2.5;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .chart-area {
      stroke: none;
    }
    .chart-point {
      stroke-width: 2;
      transition: r 0.15s ease, stroke-width 0.15s ease;
    }
    circle[stroke-dasharray="3,2"] {
      r: 4.5px !important;
      fill: transparent !important;
      stroke: var(--vscode-descriptionForeground, #a0a0a0) !important;
      stroke-width: 1.5 !important;
      stroke-dasharray: 3,2 !important;
      pointer-events: auto;
    }
    .chart-point.highlighted {
      r: 5.5;
      stroke-width: 2;
    }
    .chart-crosshair {
      stroke: var(--trend-total);
      stroke-width: 1;
      stroke-dasharray: 4, 3;
      opacity: 0.4;
      pointer-events: none;
    }
    .data-label {
      font-family: var(--vscode-font-family);
      pointer-events: none;
      user-select: none;
    }

    /* Chart summary footer */
    .chart-footer {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
      padding-top: 24px;
      border-top: 1px solid var(--vscode-panel-border);
      margin-top: 16px;
    }
    @media (max-width: 768px) {
      .chart-footer {
        grid-template-columns: 1fr;
        gap: 16px;
      }
    }
    .footer-metrics-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
    }
    @media (max-width: 900px) {
      .footer-metrics-grid {
        grid-template-columns: repeat(3, 1fr);
      }
    }
    @media (max-width: 480px) {
      .footer-metrics-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
    .chart-footer-item {
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 12px;
      background: rgba(120, 120, 120, 0.02);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
    }
    .chart-footer-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--vscode-descriptionForeground);
      font-weight: 600;
    }
    .chart-footer-value {
      font-size: 15px;
      font-weight: 700;
      color: var(--vscode-foreground);
      line-height: 1.2;
    }
    .chart-footer-value.good { color: var(--trend-low); }
    .chart-footer-value.bad { color: var(--trend-critical); }
    .chart-footer-value.neutral { color: var(--vscode-foreground); }

    .footer-recent-activity {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .footer-section-title {
      margin: 0 0 4px 0;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--vscode-descriptionForeground);
    }
    .recent-scans-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .recent-scan-compact {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: var(--vscode-foreground);
      padding: 4px 0;
      border-bottom: 1px solid var(--vscode-panel-border, rgba(120,120,120,0.05));
    }
    .recent-scan-compact:last-child {
      border-bottom: none;
    }
    .recent-scan-time {
      color: var(--vscode-descriptionForeground);
      font-family: var(--vscode-editor-font-family, monospace);
      white-space: nowrap;
      min-width: 75px;
    }
    .recent-scan-bullet {
      font-size: 10px;
    }
    .recent-scan-title {
      flex-grow: 1;
      font-weight: 500;
    }
    .recent-scan-count {
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
      white-space: nowrap;
    }

    /* Brush timeline */
    .brush-container {
      position: relative;
      width: 100%;
      height: 50px;
      margin-top: 8px;
      margin-bottom: 12px;
    }
    .brush-svg {
      width: 100%;
      height: 100%;
    }
    .brush-bg {
      fill: var(--vscode-panel-border);
      opacity: 0.15;
    }
    .brush-path {
      fill: none;
      stroke: var(--trend-total);
      stroke-width: 1.5;
      opacity: 0.5;
    }
    .brush-viewport {
      fill: var(--trend-total);
      fill-opacity: 0.12;
      stroke: var(--trend-total);
      stroke-width: 1;
      cursor: move;
    }
    .brush-handle {
      fill: var(--trend-total);
      cursor: ew-resize;
      opacity: 0.8;
    }
    .brush-overlay-left, .brush-overlay-right {
      fill: var(--vscode-editor-background, #1e1e1e);
      opacity: 0.5;
      pointer-events: none;
    }
    .brush-label {
      fill: var(--vscode-descriptionForeground);
      font-size: 9px;
      font-family: var(--vscode-font-family);
    }

    /* Tooltip */
    .trend-tooltip {
      position: absolute;
      background: var(--vscode-notifications-background, var(--vscode-editor-background));
      border: 1px solid var(--vscode-notifications-border, var(--vscode-panel-border));
      color: var(--vscode-notifications-foreground, var(--vscode-foreground));
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 11px;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.15s;
      box-shadow: 0 4px 8px rgba(0,0,0,0.15);
      z-index: 10;
      white-space: nowrap;
      min-width: 150px;
    }
    html.theme-light .trend-tooltip {
      background: #ffffff;
      border: 1px solid #d1d5db;
      color: #1f2937;
      box-shadow: 0 4px 12px rgba(0,0,0,0.12);
    }
    html.theme-dark .trend-tooltip {
      background: var(--vscode-editorWidget-background, #252526);
      border: 1px solid var(--vscode-widget-border, #454545);
      color: var(--vscode-editorWidget-foreground, #cccccc);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .trend-tooltip strong {
      display: block;
      margin-bottom: 4px;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 2px;
      font-size: 11px;
    }
    .tooltip-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin: 2px 0;
    }
    .tooltip-row span {
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .tooltip-color {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }

    /* Legend style */
    .trend-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 24px;
      justify-content: center;
      align-items: center;
    }
    .legend-info {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 500;
      color: var(--vscode-descriptionForeground);
    }
    .legend-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: var(--vscode-button-secondaryBackground, rgba(120,120,120,0.1));
      color: var(--vscode-descriptionForeground);
      border: 1px solid var(--vscode-panel-border, transparent);
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.2s ease;
    }
    .legend-btn .legend-color {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      transition: transform 0.2s ease;
    }
    .legend-btn.active {
      color: var(--vscode-foreground);
      border-color: currentColor;
      background: var(--card-background);
      box-shadow: 0 2px 6px rgba(0,0,0,0.08);
      font-weight: 600;
    }
    .legend-btn.active[data-series="total"] { color: var(--trend-total); }
    .legend-btn.active[data-series="critical"] { color: var(--trend-critical); }
    .legend-btn.active[data-series="high"] { color: var(--trend-high); }
    .legend-btn.active[data-series="medium"] { color: var(--trend-medium); }
    .legend-btn.active[data-series="low"] { color: var(--trend-low); }
    .legend-btn:hover {
      opacity: 0.95;
      transform: translateY(-1px);
    }

    /* Table collapsible Details */
    .raw-history-details {
      margin-top: 20px;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      background: var(--card-background);
    }
    .raw-history-details summary {
      padding: 12px 16px;
      font-weight: 500;
      cursor: pointer;
      outline: none;
      user-select: none;
      font-size: 14px;
      color: var(--vscode-foreground);
    }
    .raw-history-details[open] summary {
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .raw-history-content {
      padding: 16px;
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--vscode-panel-border);
      text-align: left;
      font-size: 13px;
    }
    th {
      font-weight: 500;
      color: var(--vscode-descriptionForeground);
    }
    tr:last-child td {
      border-bottom: 0;
    }

    /* Trend cell styling */
    .trend-cell {
      font-weight: 500;
    }
    .trend-cell.bad {
      color: var(--trend-critical);
    }
    .trend-cell.good {
      color: var(--trend-low);
    }
    .trend-cell.neutral {
      color: var(--vscode-foreground);
    }
    .trend-cell.muted {
      color: var(--vscode-descriptionForeground);
    }

    .help-icon {
      cursor: help;
      color: var(--vscode-descriptionForeground);
      margin-left: 4px;
      font-size: 12px;
    }

    @media (max-width: 768px) {
      .cards {
        grid-template-columns: repeat(2, 1fr);
      }
      .page-head {
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
      }
      .brand-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
      }
      .brand-title {
        border-right: none;
        padding-right: 0;
      }
      .trend-chart-wrapper {
        height: 280px;
      }
      .brush-container {
        height: 40px;
      }
    }
    @media (max-width: 480px) {
      .cards {
        grid-template-columns: 1fr;
      }
      .trend-chart-wrapper {
        height: 220px;
      }
      .chart-footer-value {
        font-size: 12px;
      }
    }

    .sc-topbar-actions .period-selector { margin: 0; }`,
    script: `    const vscode = window.__scShellApi || acquireVsCodeApi();
    
    // Loaded reports mapped by days
    const reports = ${JSON.stringify(reportsObj)};
    let currentPeriod = 7;
    let activeSeries = {
      total: true,
      critical: true,
      high: true,
      medium: false,
      low: false
    };
    let pinnedPointIndex = null;
    let brushRange = null; // { startFrac, endFrac } 0-1 fraction of full time domain

    // Series colors
    const colors = {
      total: 'var(--trend-total)',
      critical: 'var(--trend-critical)',
      high: 'var(--trend-high)',
      medium: 'var(--trend-medium)',
      low: 'var(--trend-low)'
    };
    const colorsFallback = {
      total: '#4F7DF3',
      critical: '#E5534B',
      high: '#F59E42',
      medium: '#8B5CF6',
      low: '#45B36B'
    };

    // Setup selector buttons
    document.querySelectorAll('.period-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentPeriod = parseInt(btn.getAttribute('data-days'), 10);
        updateUI();
      });
    });

    // Setup legend toggles
    document.querySelectorAll('.legend-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const seriesName = btn.getAttribute('data-series');
        activeSeries[seriesName] = !activeSeries[seriesName];
        btn.classList.toggle('active', activeSeries[seriesName]);
        renderChart();
      });
    });

    function formatMttr(mttrHours, resolvedCount) {
      if (mttrHours === null) return '—';
      const label = mttrHours < 24 ? mttrHours.toFixed(1) + ' h' : (mttrHours / 24).toFixed(1) + ' j';
      return label;
    }

    function getChartSummary(pts) {
      if (pts.length === 0) return '0 snapshot • aucune analyse';
      const count = pts.length;
      const lastDate = new Date(pts[pts.length - 1].date);
      const pad = (n) => String(n).padStart(2, '0');
      const dateStr = pad(lastDate.getDate()) + '/' + pad(lastDate.getMonth() + 1) + '/' + lastDate.getFullYear() + ' ' + pad(lastDate.getHours()) + ':' + pad(lastDate.getMinutes());
      return count + ' snapshot' + (count > 1 ? 's' : '') + ' • dernière analyse ' + dateStr;
    }

    function updateUI() {
      brushRange = null; // Reset brush when changing period
      const report = reports[currentPeriod];
      if (!report) return;

      // Update KPIs
      document.getElementById('kpi-active-val').innerText = report.latest.active;
      document.getElementById('kpi-critical-val').innerText = report.latest.critical || 0;
      document.getElementById('kpi-critical-high-val').innerText = (report.latest.critical || 0) + (report.latest.high || 0);
      
      const mttrVal = report.mttrHours;
      if (mttrVal !== null) {
        document.getElementById('kpi-mttr-val').innerText = formatMttr(mttrVal, report.resolvedCount);
        document.getElementById('kpi-mttr-sub').innerText = 'Temps moyen de résolution';
      } else {
        document.getElementById('kpi-mttr-val').innerText = '—';
        document.getElementById('kpi-mttr-sub').innerText = 'Aucune correction validée';
      }

      // Update summary above chart
      document.getElementById('chart-summary-text').innerText = getChartSummary(report.points);

      // Recent activity (max 5) - compact format
      const listContainer = document.getElementById('recent-activity-list');
      listContainer.innerHTML = '';
      
      const sortedPoints = [...report.points].reverse();
      const recentScans = sortedPoints.slice(0, 5);

      if (recentScans.length === 0) {
        listContainer.innerHTML = '<li class="recent-scan-compact" style="color: var(--vscode-descriptionForeground)">Aucune analyse enregistrée.</li>';
      } else {
        recentScans.forEach(pt => {
          const d = new Date(pt.date);
          const pad = (n) => String(n).padStart(2, '0');
          const dateStr = pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
          const statusText = pt.isComparable ? 'terminé' : 'partiel';
          const dotColor = pt.isComparable ? 'var(--trend-total, #4F7DF3)' : 'var(--trend-high, #F59E42)';
          const findingsText = pt.active + ' findings';

          const li = document.createElement('li');
          li.className = 'recent-scan-compact';
          
          li.innerHTML = '<span class="recent-scan-time">' + dateStr + '</span>' +
                         '<span class="recent-scan-bullet" style="color: ' + dotColor + '">●</span>' +
                         '<span class="recent-scan-title">Scan #' + pt.scanId + ' ' + statusText + '</span>' +
                         '<span class="recent-scan-count">' + findingsText + '</span>';
          listContainer.appendChild(li);
        });
      }

      // Raw history table
      const tbody = document.getElementById('raw-scans-tbody');
      tbody.innerHTML = '';
      
      if (report.points.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--vscode-descriptionForeground)">Aucun scan dans cette période.</td></tr>';
      } else {
        report.points.forEach(pt => {
          const tr = document.createElement('tr');
          
          const scanTd = document.createElement('td');
          scanTd.innerText = '#' + pt.scanId;
          
          const dateTd = document.createElement('td');
          dateTd.innerText = new Date(pt.date).toLocaleString('fr-FR');
          
          const activeTd = document.createElement('td');
          activeTd.innerText = pt.active;
          
          const critTd = document.createElement('td');
          critTd.innerText = pt.critical;
          
          const highTd = document.createElement('td');
          highTd.innerText = pt.high;

          const medTd = document.createElement('td');
          medTd.innerText = pt.medium;

          const lowTd = document.createElement('td');
          lowTd.innerText = pt.low;
          
          const trendTd = document.createElement('td');
          const trend = pt.trend || { display: '—', color: 'muted', tooltip: '' };
          trendTd.className = 'trend-cell ' + trend.color;
          trendTd.title = trend.tooltip;
          trendTd.innerText = trend.display;
          
          tr.appendChild(scanTd);
          tr.appendChild(dateTd);
          tr.appendChild(activeTd);
          tr.appendChild(critTd);
          tr.appendChild(highTd);
          tr.appendChild(medTd);
          tr.appendChild(lowTd);
          tr.appendChild(trendTd);
          
          tbody.appendChild(tr);
        });
      }

      renderChart();
    }

    // Helper: get series value from a point
    function getSeriesVal(pt, seriesName) {
      if (seriesName === 'total') return pt.active;
      return pt[seriesName] || 0;
    }

    // Helper: compute nice rounded Y ticks
    function niceYTicks(maxVal, count) {
      if (maxVal <= 0) maxVal = 10;
      const rawStep = maxVal / (count - 1);
      const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
      const niceCandidates = [1, 2, 2.5, 5, 10];
      let niceStep = magnitude;
      for (const c of niceCandidates) {
        if (c * magnitude >= rawStep) { niceStep = c * magnitude; break; }
      }
      const ticks = [];
      for (let i = 0; i < count; i++) {
        ticks.push(Math.round(niceStep * i));
      }
      return ticks;
    }

    // Helper: generate adaptive X-axis time labels
    function generateXLabels(minT, maxT, targetCount) {
      if (targetCount < 2) targetCount = 2;
      const span = maxT - minT;
      if (span <= 0) return [minT];
      const step = span / (targetCount - 1);
      const labels = [];
      for (let i = 0; i < targetCount; i++) {
        labels.push(Math.round(minT + step * i));
      }
      return labels;
    }

    // Helper: format date for X-axis
    function formatXLabel(timestamp, spanMs) {
      const d = new Date(timestamp);
      const pad = (n) => String(n).padStart(2, '0');
      if (spanMs < 86400000) {
        return pad(d.getHours()) + ':' + pad(d.getMinutes());
      } else if (spanMs <= 7 * 86400000) {
        return pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
      } else {
        const months = ['janv', 'fév', 'mars', 'avr', 'mai', 'juin', 'juil', 'août', 'sept', 'oct', 'nov', 'déc'];
        return d.getDate() + ' ' + months[d.getMonth()];
      }
    }

    // Find previous comparable point for a given index in the points array
    function findPrevComparable(allPoints, idx) {
      for (let j = idx - 1; j >= 0; j--) {
        if (allPoints[j].isComparable) return allPoints[j];
      }
      return null;
    }

    // Compute chart footer summary
    function updateChartFooter(allPoints) {
      const footer = document.getElementById('chart-footer-metrics');
      footer.innerHTML = '';
      if (allPoints.length === 0) return;

      const latest = allPoints[allPoints.length - 1];
      const prevComp = latest.isComparable ? findPrevComparable(allPoints, allPoints.length - 1) : null;

      function calculateChange(currVal, prevVal) {
        const diff = currVal - prevVal;
        if (prevVal === 0) {
          return { diff, pct: diff > 0 ? '+100.0 %' : '0.0 %' };
        }
        const pct = (diff / prevVal) * 100;
        const sign = diff > 0 ? '+' : '';
        return { diff, pct: sign + pct.toFixed(1) + ' %' };
      }

      const items = [];
      items.push({ label: 'Actuel', value: String(latest.active), sub: '', cls: '' });
      if (prevComp) {
        items.push({ label: 'Précédent comparable', value: String(prevComp.active), sub: '', cls: '' });
        
        const varCalc = calculateChange(latest.active, prevComp.active);
        items.push({ 
          label: 'Variation', 
          value: (varCalc.diff > 0 ? '+' : '') + varCalc.diff, 
          sub: varCalc.pct,
          cls: varCalc.diff > 0 ? 'bad' : (varCalc.diff < 0 ? 'good' : 'neutral') 
        });

        const critCalc = calculateChange(latest.critical, prevComp.critical);
        items.push({ 
          label: 'Δ Critiques', 
          value: (critCalc.diff > 0 ? '+' : '') + critCalc.diff, 
          sub: critCalc.pct,
          cls: critCalc.diff > 0 ? 'bad' : (critCalc.diff < 0 ? 'good' : 'neutral') 
        });

        const highCalc = calculateChange(latest.high, prevComp.high);
        items.push({ 
          label: 'Δ Hautes', 
          value: (highCalc.diff > 0 ? '+' : '') + highCalc.diff, 
          sub: highCalc.pct,
          cls: highCalc.diff > 0 ? 'bad' : (highCalc.diff < 0 ? 'good' : 'neutral') 
        });
      } else {
        items.push({ label: 'Précédent comparable', value: '—', sub: '', cls: '' });
      }

      items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'chart-footer-item';
        let subHtml = '';
        if (item.sub) {
          subHtml = '<span class="chart-footer-value-pct">' + item.sub + '</span>';
        }
        div.innerHTML = '<span class="chart-footer-label">' + item.label + '</span><span class="chart-footer-value ' + item.cls + '">' + item.value + '</span>' + subHtml;
        footer.appendChild(div);
      });
    }

    function renderChart() {
      const svg = document.getElementById('svg-chart');
      svg.innerHTML = '';
      pinnedPointIndex = null;
      
      const report = reports[currentPeriod];
      if (!report || report.points.length === 0) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', '450');
        text.setAttribute('y', '200');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', 'var(--vscode-descriptionForeground)');
        text.setAttribute('font-size', '14');
        text.textContent = 'Aucune donnée disponible pour cette période';
        svg.appendChild(text);
        document.getElementById('chart-footer-metrics').innerHTML = '';
        document.getElementById('brush-container').style.display = 'none';
        return;
      }

      const allPoints = report.points;
      const width = 900;
      const height = 400;
      const padLeft = 65;
      const padRight = 25;
      const padTop = 25;
      const padBottom = 50;
      const plotWidth = width - padLeft - padRight;
      const plotHeight = height - padTop - padBottom;

      // Full time domain
      const allTimestamps = allPoints.map(p => new Date(p.date).getTime());
      const fullMinT = Math.min(...allTimestamps);
      const fullMaxT = Math.max(...allTimestamps);
      const fullSpan = fullMaxT - fullMinT;

      // Determine visible range from brush
      let viewMinT = fullMinT;
      let viewMaxT = fullMaxT;
      if (brushRange && fullSpan > 0) {
        viewMinT = fullMinT + brushRange.startFrac * fullSpan;
        viewMaxT = fullMinT + brushRange.endFrac * fullSpan;
      }

      // Filter points visible in the view window (with small margin)
      const viewMargin = (viewMaxT - viewMinT) * 0.02;
      const visiblePoints = allPoints.filter(pt => {
        const t = new Date(pt.date).getTime();
        return t >= viewMinT - viewMargin && t <= viewMaxT + viewMargin;
      });

      if (visiblePoints.length === 0) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', '450');
        text.setAttribute('y', '200');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', 'var(--vscode-descriptionForeground)');
        text.setAttribute('font-size', '13');
        text.textContent = 'Aucun scan dans la plage sélectionnée';
        svg.appendChild(text);
        return;
      }

      // Check comparability counts to show warning banner
      const compWarning = document.getElementById('comparability-warning');
      const comparableCount = allPoints.filter(p => p.isComparable).length;
      if (comparableCount === 1 && allPoints.length > 1) {
        compWarning.style.display = 'block';
        compWarning.innerText = '1 snapshot comparable sur ' + allPoints.length + ' — davantage de scans complets sont nécessaires pour calculer une tendance fiable.';
      } else if (comparableCount === 0 && allPoints.length > 0) {
        compWarning.style.display = 'block';
        compWarning.innerText = '0 snapshot comparable sur ' + allPoints.length + ' — davantage de scans complets sont nécessaires pour calculer une tendance fiable.';
      } else {
        compWarning.style.display = 'none';
      }

      // Compute maxY from visible points
      let maxY = 0;
      const seriesList = ['total', 'critical', 'high', 'medium', 'low'];
      visiblePoints.forEach(pt => {
        seriesList.forEach(s => {
          if (activeSeries[s]) {
            const v = getSeriesVal(pt, s);
            if (v > maxY) maxY = v;
          }
        });
      });
      if (maxY === 0) maxY = 10;

      // Nice Y-axis ticks
      const yTicks = niceYTicks(maxY, 6);
      const yMax = yTicks[yTicks.length - 1] || maxY;

      // Draw Y grid + labels
      yTicks.forEach(val => {
        const y = padTop + plotHeight - (val / yMax) * plotHeight;
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', padLeft.toString());
        line.setAttribute('y1', y.toFixed(1));
        line.setAttribute('x2', (width - padRight).toString());
        line.setAttribute('y2', y.toFixed(1));
        line.setAttribute('class', 'grid-line');
        svg.appendChild(line);

        const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        txt.setAttribute('x', (padLeft - 10).toString());
        txt.setAttribute('y', (y + 3.5).toFixed(1));
        txt.setAttribute('text-anchor', 'end');
        txt.setAttribute('class', 'axis-text');
        txt.textContent = val.toString();
        svg.appendChild(txt);
      });

      // Axes
      const xAxis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      xAxis.setAttribute('x1', padLeft.toString());
      xAxis.setAttribute('y1', (padTop + plotHeight).toString());
      xAxis.setAttribute('x2', (width - padRight).toString());
      xAxis.setAttribute('y2', (padTop + plotHeight).toString());
      xAxis.setAttribute('class', 'axis-line');
      svg.appendChild(xAxis);

      const yAxisLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      yAxisLine.setAttribute('x1', padLeft.toString());
      yAxisLine.setAttribute('y1', padTop.toString());
      yAxisLine.setAttribute('x2', padLeft.toString());
      yAxisLine.setAttribute('y2', (padTop + plotHeight).toString());
      yAxisLine.setAttribute('class', 'axis-line');
      svg.appendChild(yAxisLine);

      // Y-axis Label
      const yLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      yLabel.setAttribute('x', (-padTop - plotHeight / 2).toString());
      yLabel.setAttribute('y', '18');
      yLabel.setAttribute('transform', 'rotate(-90)');
      yLabel.setAttribute('text-anchor', 'middle');
      yLabel.setAttribute('class', 'axis-text-y');
      yLabel.setAttribute('fill', 'var(--vscode-descriptionForeground)');
      yLabel.setAttribute('font-size', '10px');
      yLabel.setAttribute('font-weight', '600');
      yLabel.textContent = 'Nombre de vulnérabilités';
      svg.appendChild(yLabel);

      // Map visible points to X positions using real timestamps
      const viewSpan = viewMaxT - viewMinT;
      const chartPoints = visiblePoints.map((pt, i) => {
        const t = new Date(pt.date).getTime();
        const x = viewSpan === 0 ? padLeft + plotWidth / 2 : padLeft + ((t - viewMinT) / viewSpan) * plotWidth;
        const origIdx = allPoints.indexOf(pt);
        return { x, pt, index: i, origIndex: origIdx };
      });

      // Adaptive X-axis labels (~5-7)
      const wrapperEl = document.getElementById('chart-wrapper');
      const wrapperWidth = wrapperEl ? wrapperEl.offsetWidth : 900;
      const targetLabels = wrapperWidth < 500 ? 4 : (wrapperWidth < 700 ? 5 : 7);
      const xLabelTimes = generateXLabels(viewMinT, viewMaxT, targetLabels);

      xLabelTimes.forEach(t => {
        const x = viewSpan === 0 ? padLeft + plotWidth / 2 : padLeft + ((t - viewMinT) / viewSpan) * plotWidth;
        if (x < padLeft - 5 || x > width - padRight + 5) return;
        
        const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        txt.setAttribute('x', x.toFixed(1));
        txt.setAttribute('y', (padTop + plotHeight + 15).toString());
        txt.setAttribute('text-anchor', 'middle');
        txt.setAttribute('class', 'axis-text');

        const d = new Date(t);
        const pad = (n) => String(n).padStart(2, '0');
        const dateStr = pad(d.getDate()) + '/' + pad(d.getMonth() + 1);
        const timeStr = pad(d.getHours()) + ':' + pad(d.getMinutes());

        const tspanDate = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
        tspanDate.setAttribute('x', x.toFixed(1));
        tspanDate.setAttribute('dy', '0');
        tspanDate.textContent = dateStr;
        
        const tspanTime = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
        tspanTime.setAttribute('x', x.toFixed(1));
        tspanTime.setAttribute('dy', '11');
        tspanTime.textContent = timeStr;

        txt.appendChild(tspanDate);
        txt.appendChild(tspanTime);
        svg.appendChild(txt);
      });

      // Gradient definition for Total area
      if (activeSeries.total) {
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const grad = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        grad.setAttribute('id', 'total-area-grad');
        grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0'); grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop1.setAttribute('offset', '0%'); stop1.setAttribute('stop-color', colorsFallback.total); stop1.setAttribute('stop-opacity', '0.18');
        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop2.setAttribute('offset', '100%'); stop2.setAttribute('stop-color', colorsFallback.total); stop2.setAttribute('stop-opacity', '0.02');
        grad.appendChild(stop1); grad.appendChild(stop2); defs.appendChild(grad); svg.appendChild(defs);
      }

      // Helper: determine if we should render static data label for a point
      function shouldShowLabel(cp, seriesName, pathCoords) {
        if (!cp.pt.isComparable) return false;
        const idx = pathCoords.findIndex(c => c.x === cp.x);
        if (idx === -1) return false;
        
        // Always label first and last comparable points
        if (idx === 0 || idx === pathCoords.length - 1) return true;
        
        // If density is low, label all points
        if (pathCoords.length <= 12) return true;
        
        // Local peak/trough
        const val = pathCoords[idx].val;
        const prevVal = pathCoords[idx - 1].val;
        const nextVal = pathCoords[idx + 1].val;
        if (val > prevVal && val > nextVal) return true;
        if (val < prevVal && val < nextVal) return true;
        
        return false;
      }

      // Draw series: lines (comparable only) + area + points
      seriesList.forEach(seriesName => {
        if (!activeSeries[seriesName]) return;

        // Build path from comparable points only
        const pathCoords = chartPoints
          .filter(cp => cp.pt.isComparable)
          .map(cp => {
            const val = getSeriesVal(cp.pt, seriesName);
            const y = padTop + plotHeight - (val / yMax) * plotHeight;
            return { x: cp.x, y, val };
          });

        let bezierD = '';
        if (pathCoords.length >= 2) {
          bezierD = 'M ' + pathCoords[0].x.toFixed(1) + ' ' + pathCoords[0].y.toFixed(1);
          for (let i = 0; i < pathCoords.length - 1; i++) {
            const p0 = pathCoords[i];
            const p1 = pathCoords[i + 1];
            const cpX1 = p0.x + (p1.x - p0.x) / 3;
            const cpY1 = p0.y;
            const cpX2 = p0.x + 2 * (p1.x - p0.x) / 3;
            const cpY2 = p1.y;
            bezierD += ' C ' + cpX1.toFixed(1) + ' ' + cpY1.toFixed(1) + ', ' + cpX2.toFixed(1) + ' ' + cpY2.toFixed(1) + ', ' + p1.x.toFixed(1) + ' ' + p1.y.toFixed(1);
          }
        }

        // Area fill under Total
        if (seriesName === 'total' && pathCoords.length >= 2) {
          const areaD = bezierD + ' L ' + pathCoords[pathCoords.length - 1].x.toFixed(1) + ' ' + (padTop + plotHeight) +
                        ' L ' + pathCoords[0].x.toFixed(1) + ' ' + (padTop + plotHeight) + ' Z';
          const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          area.setAttribute('d', areaD);
          area.setAttribute('class', 'chart-area');
          area.setAttribute('fill', 'url(#total-area-grad)');
          svg.appendChild(area);
        }

        // Line path
        if (pathCoords.length >= 2) {
          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          path.setAttribute('d', bezierD);
          path.setAttribute('class', 'chart-path');
          path.setAttribute('data-series', seriesName);
          path.setAttribute('stroke', colors[seriesName]);
          svg.appendChild(path);
        }

        // Draw points (comparable only)
        chartPoints.forEach(cp => {
          if (!cp.pt.isComparable) return;
          const val = getSeriesVal(cp.pt, seriesName);
          const y = padTop + plotHeight - (val / yMax) * plotHeight;

          const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          circle.setAttribute('cx', cp.x.toFixed(1));
          circle.setAttribute('cy', y.toFixed(1));
          circle.setAttribute('class', 'chart-point');
          circle.setAttribute('data-index', cp.index.toString());
          circle.setAttribute('data-series', seriesName);
          circle.setAttribute('r', '4');
          circle.setAttribute('fill', 'var(--card-background)');
          circle.setAttribute('stroke', colors[seriesName]);
          circle.setAttribute('stroke-width', '2');
          svg.appendChild(circle);

          // Data label
          if (shouldShowLabel(cp, seriesName, pathCoords)) {
            const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            txt.setAttribute('x', cp.x.toFixed(1));
            txt.setAttribute('y', (y - 8).toFixed(1));
            txt.setAttribute('text-anchor', 'middle');
            txt.setAttribute('fill', colors[seriesName]);
            txt.setAttribute('font-size', '9px');
            txt.setAttribute('font-weight', 'bold');
            txt.setAttribute('class', 'data-label');
            txt.textContent = val.toString();
            svg.appendChild(txt);
          }
        });
      });

      // Draw non-comparable points as unique gray markers (only once per scan, at active/total height)
      chartPoints.forEach(cp => {
        if (cp.pt.isComparable) return;
        const val = getSeriesVal(cp.pt, 'total');
        const y = padTop + plotHeight - (val / yMax) * plotHeight;

        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', cp.x.toFixed(1));
        circle.setAttribute('cy', y.toFixed(1));
        circle.setAttribute('class', 'chart-point');
        circle.setAttribute('data-index', cp.index.toString());
        circle.setAttribute('data-series', 'total');
        circle.setAttribute('r', '4.5');
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', 'var(--vscode-descriptionForeground, #a0a0a0)');
        circle.setAttribute('stroke-width', '1.5');
        circle.setAttribute('stroke-dasharray', '3,2');
        svg.appendChild(circle);
      });

      // Crosshair line (hidden by default)
      const hoverLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      hoverLine.setAttribute('x1', '0'); hoverLine.setAttribute('y1', padTop.toString());
      hoverLine.setAttribute('x2', '0'); hoverLine.setAttribute('y2', (padTop + plotHeight).toString());
      hoverLine.setAttribute('class', 'chart-crosshair');
      hoverLine.setAttribute('style', 'display: none;');
      svg.appendChild(hoverLine);

      // --- Tooltip and hover interaction ---
      const wrapper = document.getElementById('chart-wrapper');
      const tooltip = document.getElementById('tooltip');

      function buildTooltipHtml(cp) {
        const pt = cp.pt;
        const dateStr = new Date(pt.date).toLocaleString('fr-FR');
        let html = '<strong>' + dateStr + '</strong>';
        html += '<div class="tooltip-row"><span><span class="tooltip-color" style="background:' + colors.total + '"></span>Total actives</span><strong>' + pt.active + '</strong></div>';
        html += '<div class="tooltip-row"><span><span class="tooltip-color" style="background:' + colors.critical + '"></span>Critiques</span><strong>' + pt.critical + '</strong></div>';
        html += '<div class="tooltip-row"><span><span class="tooltip-color" style="background:' + colors.high + '"></span>Hautes</span><strong>' + pt.high + '</strong></div>';
        html += '<div class="tooltip-row"><span><span class="tooltip-color" style="background:' + colors.medium + '"></span>Moyennes</span><strong>' + pt.medium + '</strong></div>';
        html += '<div class="tooltip-row"><span><span class="tooltip-color" style="background:' + colors.low + '"></span>Faibles</span><strong>' + pt.low + '</strong></div>';

        if (pt.isComparable) {
          const prev = findPrevComparable(allPoints, cp.origIndex);
          if (prev) {
            const diff = pt.active - prev.active;
            const sign = diff > 0 ? '+' : '';
            const cls = diff > 0 ? 'bad' : (diff < 0 ? 'good' : 'neutral');
            html += '<div style="border-top: 1px solid var(--vscode-panel-border); margin-top: 4px; padding-top: 4px; font-size: 10px;">';
            html += '<span class="trend-text ' + cls + '">' + sign + diff + ' vs précédent comparable</span>';
            html += '</div>';
          } else {
            html += '<div style="border-top: 1px solid var(--vscode-panel-border); margin-top: 4px; padding-top: 4px; font-size: 10px; color: var(--vscode-descriptionForeground);">Premier snapshot comparable</div>';
          }
        } else {
          html += '<div style="color: var(--vscode-charts-orange, #F59E42); border-top: 1px dashed var(--vscode-panel-border); margin-top: 4px; padding-top: 4px; font-size: 10px; font-weight: 500;">⚠ Non comparable — exclu de la tendance comparable</div>';
        }
        return html;
      }

      function showTooltipAt(cp) {
        tooltip.innerHTML = buildTooltipHtml(cp);
        tooltip.style.opacity = '1';
        tooltip.style.pointerEvents = 'auto';

        const wrapperRect = wrapper.getBoundingClientRect();
        const svgRect = svg.getBoundingClientRect();
        const xPx = (cp.x / width) * svgRect.width;
        let leftPos = xPx - tooltip.offsetWidth / 2;
        leftPos = Math.max(4, Math.min(leftPos, wrapperRect.width - tooltip.offsetWidth - 4));
        tooltip.style.left = leftPos + 'px';

        const yVal = getSeriesVal(cp.pt, 'total');
        const ySvg = padTop + plotHeight - (yVal / yMax) * plotHeight;
        const yPx = (ySvg / height) * svgRect.height;
        if (yPx - tooltip.offsetHeight - 14 > 0) {
          tooltip.style.top = (yPx - tooltip.offsetHeight - 14) + 'px';
        } else {
          tooltip.style.top = (yPx + 14) + 'px';
        }
      }

      function highlightPoint(idx) {
        hoverLine.setAttribute('style', 'display: block;');
        const cp = chartPoints[idx];
        if (!cp) return;
        hoverLine.setAttribute('x1', cp.x.toFixed(1));
        hoverLine.setAttribute('x2', cp.x.toFixed(1));
        document.querySelectorAll('.chart-point').forEach(c => {
          const isHighlighted = parseInt(c.getAttribute('data-index'), 10) === idx;
          c.classList.toggle('highlighted', isHighlighted);
          if (isHighlighted) {
            const seriesName = c.getAttribute('data-series');
            if (c.getAttribute('stroke-dasharray') !== '3,2') {
              c.setAttribute('fill', colorsFallback[seriesName] || colors[seriesName]);
              c.setAttribute('r', '5.5');
            }
          } else {
            if (c.getAttribute('stroke-dasharray') !== '3,2') {
              c.setAttribute('fill', 'var(--card-background)');
              c.setAttribute('r', '4');
            }
          }
        });
      }

      function hideTooltip() {
        if (pinnedPointIndex !== null) return;
        hoverLine.setAttribute('style', 'display: none;');
        document.querySelectorAll('.chart-point').forEach(c => {
          c.classList.remove('highlighted');
          if (c.getAttribute('stroke-dasharray') !== '3,2') {
            c.setAttribute('fill', 'var(--card-background)');
            c.setAttribute('r', '4');
          }
        });
        tooltip.style.opacity = '0';
        tooltip.style.pointerEvents = 'none';
      }

      function findNearestPoint(e) {
        const rect = svg.getBoundingClientRect();
        const localX = ((e.clientX - rect.left) / rect.width) * width;
        let nearest = null;
        let bestDist = Infinity;
        chartPoints.forEach(cp => {
          const d = Math.abs(cp.x - localX);
          if (d < bestDist) { bestDist = d; nearest = cp; }
        });
        return (nearest && bestDist < 60) ? nearest : null;
      }

      svg.addEventListener('mousemove', (e) => {
        if (pinnedPointIndex !== null) return;
        const cp = findNearestPoint(e);
        if (cp) {
          highlightPoint(cp.index);
          showTooltipAt(cp);
        } else {
          hideTooltip();
        }
      });

      svg.addEventListener('mouseleave', () => {
        hideTooltip();
      });

      svg.addEventListener('click', (e) => {
        const cp = findNearestPoint(e);
        if (!cp) {
          pinnedPointIndex = null;
          hideTooltip();
          return;
        }
        if (pinnedPointIndex === cp.index) {
          pinnedPointIndex = null;
          hideTooltip();
        } else {
          pinnedPointIndex = cp.index;
          highlightPoint(cp.index);
          showTooltipAt(cp);
        }
      });

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && pinnedPointIndex !== null) {
          pinnedPointIndex = null;
          hideTooltip();
        }
      });

      document.addEventListener('click', (e) => {
        if (pinnedPointIndex !== null && !wrapper.contains(e.target)) {
          pinnedPointIndex = null;
          hideTooltip();
        }
      });

      updateChartFooter(allPoints);
      updateChartSummary(allPoints);
      renderBrush(allPoints);
    }

    function updateChartSummary(pts) {
      if (pts.length === 0) {
        document.getElementById('chart-summary-text').innerText = '0 snapshot • aucune analyse';
        return;
      }
      const count = pts.length;
      const pad = (n) => String(n).padStart(2, '0');
      const first = new Date(pts[0].date);
      const last = new Date(pts[pts.length - 1].date);
      const fmtDate = (d) => pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + '/' + d.getFullYear();
      const fmtFull = (d) => fmtDate(d) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());

      let text = count + ' snapshot' + (count > 1 ? 's' : '') + ' • ';
      text += fmtDate(first) + ' → ' + fmtDate(last) + ' • ';
      text += 'dernière analyse ' + fmtFull(last);
      document.getElementById('chart-summary-text').innerText = text;
    }

    function renderBrush(allPoints) {
      const brushContainer = document.getElementById('brush-container');
      const brushSvg = document.getElementById('brush-svg');

      if (allPoints.length < 8) {
        brushContainer.style.display = 'none';
        brushRange = null;
        return;
      }
      brushContainer.style.display = 'block';
      brushSvg.innerHTML = '';

      const bW = 900, bH = 50, bPadL = 65, bPadR = 25, bPadT = 4, bPadB = 4;
      const bPlotW = bW - bPadL - bPadR;
      const bPlotH = bH - bPadT - bPadB;

      // Background
      const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      bgRect.setAttribute('x', bPadL.toString()); bgRect.setAttribute('y', bPadT.toString());
      bgRect.setAttribute('width', bPlotW.toString()); bgRect.setAttribute('height', bPlotH.toString());
      bgRect.setAttribute('class', 'brush-bg');
      brushSvg.appendChild(bgRect);

      // Mini line + area under mini line
      const allTs = allPoints.map(p => new Date(p.date).getTime());
      const bMinT = Math.min(...allTs);
      const bMaxT = Math.max(...allTs);
      const bSpan = bMaxT - bMinT;
      let bMaxY = 0;
      allPoints.forEach(p => { if (p.active > bMaxY) bMaxY = p.active; });
      if (bMaxY === 0) bMaxY = 10;

      const comparablePs = allPoints.filter(p => p.isComparable);
      if (comparablePs.length > 1) {
        let d = '';
        comparablePs.forEach((p, i) => {
          const t = new Date(p.date).getTime();
          const x = bPadL + ((t - bMinT) / bSpan) * bPlotW;
          const y = bPadT + bPlotH - (p.active / bMaxY) * bPlotH;
          d += (i === 0 ? 'M ' : ' L ') + x.toFixed(1) + ' ' + y.toFixed(1);
        });
        
        // Brush total area definition
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const grad = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        grad.setAttribute('id', 'brush-area-grad');
        grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0'); grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop1.setAttribute('offset', '0%'); stop1.setAttribute('stop-color', colorsFallback.total); stop1.setAttribute('stop-opacity', '0.12');
        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop2.setAttribute('offset', '100%'); stop2.setAttribute('stop-color', colorsFallback.total); stop2.setAttribute('stop-opacity', '0.01');
        grad.appendChild(stop1); grad.appendChild(stop2); defs.appendChild(grad); brushSvg.appendChild(defs);

        const areaD = d + ' L ' + (bPadL + ((new Date(comparablePs[comparablePs.length - 1].date).getTime() - bMinT) / bSpan) * bPlotW).toFixed(1) + ' ' + (bPadT + bPlotH) +
                      ' L ' + (bPadL + ((new Date(comparablePs[0].date).getTime() - bMinT) / bSpan) * bPlotW).toFixed(1) + ' ' + (bPadT + bPlotH) + ' Z';
        const miniArea = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        miniArea.setAttribute('d', areaD);
        miniArea.setAttribute('fill', 'url(#brush-area-grad)');
        brushSvg.appendChild(miniArea);

        const miniPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        miniPath.setAttribute('d', d);
        miniPath.setAttribute('class', 'brush-path');
        brushSvg.appendChild(miniPath);
      }

      // Viewport rectangle
      const startFrac = brushRange ? brushRange.startFrac : 0;
      const endFrac = brushRange ? brushRange.endFrac : 1;
      const vpX = bPadL + startFrac * bPlotW;
      const vpW = (endFrac - startFrac) * bPlotW;

      // Overlays (dimmed areas outside viewport)
      const overlayLeft = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      overlayLeft.setAttribute('x', bPadL.toString()); overlayLeft.setAttribute('y', bPadT.toString());
      overlayLeft.setAttribute('width', Math.max(0, vpX - bPadL).toFixed(1)); overlayLeft.setAttribute('height', bPlotH.toString());
      overlayLeft.setAttribute('class', 'brush-overlay-left');
      brushSvg.appendChild(overlayLeft);

      const overlayRight = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      overlayRight.setAttribute('x', (vpX + vpW).toFixed(1)); overlayRight.setAttribute('y', bPadT.toString());
      overlayRight.setAttribute('width', Math.max(0, bPadL + bPlotW - vpX - vpW).toFixed(1)); overlayRight.setAttribute('height', bPlotH.toString());
      overlayRight.setAttribute('class', 'brush-overlay-right');
      brushSvg.appendChild(overlayRight);

      // Viewport rect
      const vpRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      vpRect.setAttribute('x', vpX.toFixed(1)); vpRect.setAttribute('y', bPadT.toString());
      vpRect.setAttribute('width', Math.max(10, vpW).toFixed(1)); vpRect.setAttribute('height', bPlotH.toString());
      vpRect.setAttribute('class', 'brush-viewport');
      vpRect.setAttribute('id', 'brush-vp');
      brushSvg.appendChild(vpRect);

      // Drag handles
      const handleW = 6;
      const leftHandle = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      leftHandle.setAttribute('x', (vpX - handleW / 2).toFixed(1)); leftHandle.setAttribute('y', (bPadT + 2).toString());
      leftHandle.setAttribute('width', handleW.toString()); leftHandle.setAttribute('height', (bPlotH - 4).toString());
      leftHandle.setAttribute('rx', '2'); leftHandle.setAttribute('class', 'brush-handle brush-handle-left');
      brushSvg.appendChild(leftHandle);

      const rightHandle = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rightHandle.setAttribute('x', (vpX + vpW - handleW / 2).toFixed(1)); rightHandle.setAttribute('y', (bPadT + 2).toString());
      rightHandle.setAttribute('width', handleW.toString()); rightHandle.setAttribute('height', (bPlotH - 4).toString());
      rightHandle.setAttribute('rx', '2'); rightHandle.setAttribute('class', 'brush-handle brush-handle-right');
      brushSvg.appendChild(rightHandle);

      // Brush interaction
      let dragMode = null; // 'move', 'left', 'right'
      let dragStartX = 0;
      let dragStartFracs = { s: startFrac, e: endFrac };

      function brushPointerDown(mode, e) {
        e.preventDefault();
        e.stopPropagation();
        dragMode = mode;
        dragStartX = e.clientX;
        dragStartFracs = { s: brushRange ? brushRange.startFrac : 0, e: brushRange ? brushRange.endFrac : 1 };
        document.addEventListener('pointermove', brushPointerMove);
        document.addEventListener('pointerup', brushPointerUp);
      }

      function brushPointerMove(e) {
        if (!dragMode) return;
        const brushRect = brushSvg.getBoundingClientRect();
        const dx = e.clientX - dragStartX;
        const dFrac = dx / (brushRect.width * (bPlotW / bW));
        const minWidth = 0.05;

        let newS = dragStartFracs.s;
        let newE = dragStartFracs.e;

        if (dragMode === 'move') {
          const span = newE - newS;
          newS = Math.max(0, Math.min(1 - span, dragStartFracs.s + dFrac));
          newE = newS + span;
        } else if (dragMode === 'left') {
          newS = Math.max(0, Math.min(dragStartFracs.e - minWidth, dragStartFracs.s + dFrac));
        } else if (dragMode === 'right') {
          newE = Math.min(1, Math.max(dragStartFracs.s + minWidth, dragStartFracs.e + dFrac));
        }

        brushRange = { startFrac: newS, endFrac: newE };
        renderChart();
      }

      function brushPointerUp() {
        dragMode = null;
        document.removeEventListener('pointermove', brushPointerMove);
        document.removeEventListener('pointerup', brushPointerUp);
      }

      vpRect.addEventListener('pointerdown', (e) => brushPointerDown('move', e));
      leftHandle.addEventListener('pointerdown', (e) => brushPointerDown('left', e));
      rightHandle.addEventListener('pointerdown', (e) => brushPointerDown('right', e));

      // Double-click brush to reset
      brushSvg.addEventListener('dblclick', () => {
        brushRange = null;
        renderChart();
      });
    }
    updateUI();`,
    csp: `default-src 'none'; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';`
  });
}

module.exports = { RESOLUTION_ACTIONS, buildTrendReport, renderTrendReportHtml };
