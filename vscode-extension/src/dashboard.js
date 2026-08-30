const { renderCompanionWidget, companionWidgetCss } = require('./live/companionWidget');
const { renderDynamicSections, dynamicSectionsCss, dynamicSectionsScript } = require('./dynamic-workspace');
const { remediationCounters } = require('./triage');
const { renderInternalSidebar, renderSecurityCenterAtmosphere, pageAtmosphereKind, compactIcon, shellLayoutCss } = require('./security-center-shell');
const { buildAssistantCardModel, renderAssistantCard, renderAssistantHeroCard, renderAssistantPanelCard, assistantCardCss, assistantCardScript } = require('./companion-assistant-card');
const { scannerPresentation, scannerLogoUri, scannerIdForTool } = require('./scanner-presentation');
const { isTerminalScannerStatus, successfulScannerCount, finishedScannerCount } = require('./security-snapshot');

function countBy(items, selector) {
  const counts = {};
  for (const item of items) {
    const key = selector(item) || 'UNKNOWN';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function calculateRiskScore(findings) {
  const weights = { CRITICAL: 15, HIGH: 8, ERROR: 8, MEDIUM: 3, WARNING: 3, LOW: 1, INFO: 0, INFORMATION: 0 };
  return Math.min(100, findings.reduce((total, finding) => total + (weights[String(finding.rawSeverity).toUpperCase()] || 0), 0));
}

function riskLevel(score) {
  if (score >= 75) return 'critique';
  if (score >= 45) return 'élevé';
  if (score >= 20) return 'modéré';
  return 'faible';
}

/**
 * The correlation model Security Center *shows*.
 *
 * One engine decides what a correlation is, and it is the same one the Security
 * Pipeline reports: Correlation V2. Its clusters are already attached to every
 * finding by `mergeIntelligence` (`correlationClusters`), and the local scan
 * cache persists them alongside the findings — so this reads intelligence that
 * has already been computed and never re-runs correlation from a render path.
 *
 * Legacy V1 keeps running untouched for the backend record and for the source
 * attribution on dynamic finding cards, which depend on its own `endpoint-source`
 * vocabulary. It simply no longer decides the number on screen.
 */
function visibleCorrelationClusters(findings = [], options = {}) {
  // An explicitly supplied set wins, so a restored scan can hand over exactly
  // the clusters it persisted rather than relying on the findings carrying them.
  if (Array.isArray(options.correlationClusters)) return options.correlationClusters;
  const byId = new Map();
  for (const finding of findings) {
    for (const cluster of finding?.correlationClusters || []) {
      if (cluster?.id && !byId.has(cluster.id)) byId.set(cluster.id, cluster);
    }
  }
  return [...byId.values()];
}

function buildDashboardModel(findings = [], scanners = [], options = {}) {
  // Legacy V1 output. Still produced, still persisted, still read by the source
  // attribution below — but no longer the visible correlation summary.
  const legacyCorrelations = Array.isArray(options.correlations) ? options.correlations : [];
  const correlations = visibleCorrelationClusters(findings, options);
  const activeFindings = findings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus));
  const currentRunFindings = Array.isArray(options.currentRunFindings)
    ? options.currentRunFindings
    : scanners.flatMap((scanner) => Array.isArray(scanner.currentRun?.findings) ? scanner.currentRun.findings : []);
  const riskScore = calculateRiskScore(activeFindings);
  return {
    findings,
    workspacePostureFindings: findings,
    currentRunFindings,
    total: findings.length,
    activeTotal: activeFindings.length,
    byTool: countBy(findings, (finding) => finding.tool),
    bySeverity: countBy(findings, (finding) => finding.rawSeverity),
    byContext: countBy(findings, (finding) => finding.sourceContext || 'non classé'),
    byStatus: countBy(findings, (finding) => finding.triageStatus || 'new'),
    correlations,
    // V2 clusters use the same `high`/`medium`/`low` confidence vocabulary as V1,
    // so the « Confiance élevée » card reads the new source without any change.
    correlationCounts: countBy(correlations, (correlation) => correlation.confidence),
    // Preserved for the dynamic source attribution, which relies on V1 types.
    legacyCorrelations,
    riskScore,
    riskLevel: riskLevel(riskScore),
    productionPriority: activeFindings.filter((finding) => finding.sourceContext === 'production' && ['CRITICAL', 'HIGH'].includes(String(finding.rawSeverity).toUpperCase())).length,
    runtimeFindings: activeFindings.filter((finding) => finding.sourceContext === 'runtime').length,
    successfulScanners: successfulScannerCount(scanners),
    completedScanners: successfulScannerCount(scanners),
    finishedScanners: finishedScannerCount(scanners),
    httpScenarioCount: Number(options.httpScenarioCount || 0),
    httpScenarios: Array.isArray(options.httpScenarios) ? options.httpScenarios : [],
    burpConnected: Boolean(options.burpConnected),
    burpStatus: options.burpStatus && typeof options.burpStatus === 'object' ? options.burpStatus : {},
    burpEndpoint: options.burpEndpoint || '',
    dynamicTargetUrl: options.dynamicTargetUrl || '',
    dynamicTargetState: options.dynamicTargetState || 'unknown',
    // How the target state was established, and when. Never fabricated.
    dynamicTargetEvidence: options.dynamicTargetEvidence || null,
    // Modèle de l'espace de travail dynamique (inventaire, couverture, auth,
    // re-tests). Construit ailleurs : la page ne fait que l'afficher.
    dynamicWorkspace: options.dynamicWorkspace || null,
    scanDurationMs: Number(options.scanDurationMs || 0),
    scanStartedAt: options.scanStartedAt || '',
    scanners,
    // Scanners knowingly turned off in the configuration. They are reported as
    // « Désactivé » and never as a scanner that ran and found nothing.
    disabledScanners: (Array.isArray(options.disabledScanners) ? options.disabledScanners : [])
      .filter((tool) => tool && !scanners.some((scanner) => scanner.tool === tool)),
    workspace: options.workspace || 'Aucun workspace',
    scanStatus: options.scanStatus || 'idle',
    backendStatus: options.backendStatus || 'unknown',
    policyResult: options.policyResult || null,
    snapshotAvailable: Boolean(options.snapshotAvailable),
    activeExecution: options.activeExecution || null,
    lastExecution: options.lastExecution || null,
    executionType: options.executionType || '',
    scanHistory: Array.isArray(options.scanHistory) ? options.scanHistory : [],
    mttrHours: Number.isFinite(options.mttrHours) ? options.mttrHours : null,
    enterprise: options.enterprise && typeof options.enterprise === 'object' ? options.enterprise : null
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function summarizeScannerError(value) {
  const error = String(value || '').trim();
  if (!error) return 'Le scanner a échoué sans fournir de cause exploitable.';
  if (/SonarQube .*injoignable|serveur SonarQube .*injoignable|SERVER_UNAVAILABLE/i.test(error)) {
    return 'SonarQube inaccessible. Démarrez le serveur configuré ou corrigez l’URL SonarQube, puis relancez ce scanner.';
  }
  if (/unexpected EOF|error waiting for container|docker API|dockerDesktopLinuxEngine|daemon is running/i.test(error)) {
    return 'Docker Desktop a interrompu la connexion avec son moteur Linux. Redémarrez Docker Desktop, attendez que le moteur soit prêt, puis relancez ce scanner.';
  }
  if (/d[ée]pass[ée].*d[ée]lai|maximal|timed?\s*out|timeout/i.test(error)) {
    return 'Le scanner a dépassé le délai maximal autorisé. Essayez le scan rapide ou relancez uniquement ce scanner.';
  }
  if (/inaccessible|ECONNREFUSED|connection refused/i.test(error)) {
    return 'La cible locale est inaccessible. Démarrez l’application cible puis réessayez.';
  }
  if (/HTTP 401|login.*refus/i.test(error)) {
    return 'L’authentification a été refusée. Vérifiez le compte configuré pour ce scanner.';
  }
  return error.length > 260 ? `${error.slice(0, 257)}…` : error;
}

function renderRows(values, emptyLabel) {
  const rows = Object.entries(values);
  if (!rows.length) return `<div class="empty">${escapeHtml(emptyLabel)}</div>`;
  return rows.map(([label, count]) => `<div class="row"><span>${escapeHtml(label)}</span><strong>${count}</strong></div>`).join('');
}

function semanticClass(label) {
  const value = String(label).toLowerCase();
  if (['critical', 'error', 'high', 'production', 'confirmed'].includes(value)) return 'danger';
  if (['medium', 'warning', 'runtime', 'new'].includes(value)) return 'warning';
  if (['low', 'information', 'info', 'test', 'false_positive', 'fixed'].includes(value)) return 'info';
  return 'neutral';
}

function renderMetricRows(values, emptyLabel) {
  const rows = Object.entries(values).sort((a, b) => b[1] - a[1]);
  if (!rows.length) return `<div class="empty">${escapeHtml(emptyLabel)}</div>`;
  const max = Math.max(...rows.map(([, count]) => count), 1);
  return rows.map(([label, count]) => `<div class="metric">
    <div class="metric-label"><span><i class="dot ${semanticClass(label)}"></i>${escapeHtml(label)}</span><strong>${count}</strong></div>
    <progress class="${semanticClass(label)}" max="${max}" value="${count}">${count}</progress>
  </div>`).join('');
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs) || durationMs < 0) return '';
  const totalSeconds = Math.round(durationMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes ? `${minutes} min ${seconds} s` : `${seconds} s`;
}

function actionButton(command, label, icon, primary = false) {
  return `<button class="${primary ? 'primary' : 'secondary'}" data-command="${escapeHtml(command)}">${compactIcon(icon)}<span>${escapeHtml(label)}</span></button>`;
}

function renderScannerLogoHtml(tool, status = '', assets = {}) {
  const presentation = scannerPresentation(tool);
  const uri = scannerLogoUri(tool, assets);
  const statusClass = status ? ` ${escapeHtml(status)}` : '';
  if (uri) {
    return `<span class="scanner-logo${statusClass}" data-scanner-logo="${escapeHtml(presentation.id)}"><img class="scanner-logo-img" src="${escapeHtml(uri)}" alt="${escapeHtml(presentation.label)} logo" loading="lazy"></span>`;
  }
  return `<span class="scanner-logo fallback${statusClass}" data-scanner-logo="${escapeHtml(presentation.id)}">${compactIcon(presentation.fallbackIcon)}</span>`;
}

function scannerStatusLabel(status) {
  return ({
    completed: 'COMPLETED',
    failed: 'FAILED',
    running: 'RUNNING',
    refreshing: 'RUNNING',
    pending: 'WAITING',
    cancelled: 'CANCELLED',
    skipped: 'SKIPPED',
    disabled: 'NOT CONFIGURED'
  })[status] || String(status || 'WAITING').toUpperCase();
}

function scannerCategoryLabel(tool) {
  const category = scannerPresentation(tool).category || '';
  return category.replace(/\//g, ' / ');
}

function currentScannerFindings(scanner, allFindings) {
  if (!scanner || scanner.status !== 'completed') return [];
  if (Array.isArray(scanner.currentRun?.findings)) return scanner.currentRun.findings;
  return allFindings.filter((finding) => finding.tool === scanner.tool);
}

function currentScannerResultCount(scanner, allFindings) {
  if (!scanner || scanner.status !== 'completed') return null;
  const count = Number(scanner.currentRun?.resultCount);
  if (Number.isFinite(count)) return count;
  return currentScannerFindings(scanner, allFindings).length;
}

function scannerResultSummary(scanner, allFindings) {
  if (!scanner) return 'No current execution';
  if (scanner.status === 'failed') return summarizeScannerError(scanner.error || scanner.details);
  if (scanner.status === 'cancelled') return 'Cancelled before producing current results';
  if (scanner.status === 'running' || scanner.status === 'refreshing') return 'Analysis in progress';
  if (scanner.status === 'pending') return 'Waiting for current execution';
  if (scanner.status !== 'completed') return 'No current result';
  const count = currentScannerResultCount(scanner, allFindings);
  const word = scanner.tool === 'Gitleaks'
    ? (count === 1 ? 'secret' : 'secrets')
    : scanner.tool === 'OSV-Scanner'
      ? (count === 1 ? 'vulnerability' : 'vulnerabilities')
      : count === 1 ? 'finding' : 'findings';
  return `${count} ${word}`;
}

function deduplicateByFingerprint(findings) {
  const seen = new Set();
  const result = [];
  for (const finding of findings) {
    const key = finding.fingerprint || finding.id || JSON.stringify(finding);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }
  return result;
}

function getConsolidatedFindingsForHistoryEntry(entry) {
  if (entry?.dashboardOptions?.snapshotResultSets) {
    const resultSets = entry.dashboardOptions.snapshotResultSets;
    const findings = [];
    for (const tool of Object.keys(resultSets)) {
      const set = resultSets[tool];
      if (set && Array.isArray(set.findings)) {
        findings.push(...set.findings);
      }
    }
    return findings;
  }
  return entry?.findings || [];
}

function historyActiveFindings(entry) {
  const consolidated = getConsolidatedFindingsForHistoryEntry(entry);
  const deduped = deduplicateByFingerprint(consolidated);
  return deduped.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus || 'new'));
}

function formatSingleDateAdapted(date, minDate, maxDate) {
  const diffMs = maxDate.getTime() - minDate.getTime();
  const diffDays = diffMs / (1000 * 60 * 60 * 24);
  
  const isSameDay = minDate.getDate() === maxDate.getDate() &&
                    minDate.getMonth() === maxDate.getMonth() &&
                    minDate.getFullYear() === maxDate.getFullYear();

  if (isSameDay) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
  } else if (diffDays <= 7) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${day}/${month} ${hours}:${minutes}`;
  } else {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  }
}

function formatDateAdapted(dates) {
  if (dates.length === 0) return '';
  const date = dates[0];
  const today = new Date();
  const isToday = date.getDate() === today.getDate() &&
                  date.getMonth() === today.getMonth() &&
                  date.getFullYear() === today.getFullYear();
  if (isToday) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
  } else {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${day}/${month} ${hours}:${minutes}`;
  }
}

function getYScale(maxValue) {
  if (maxValue <= 0) maxValue = 1;
  const targetSteps = 4;
  const rawStep = maxValue / targetSteps;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
  const ratio = rawStep / (magnitude || 1);
  let step;
  if (ratio <= 1) step = magnitude;
  else if (ratio <= 2) step = magnitude * 2;
  else if (ratio <= 5) step = magnitude * 5;
  else step = magnitude * 10;
  
  if (step <= 0) step = 1;
  
  const ticks = [];
  for (let i = 0; i <= targetSteps + 2; i++) {
    const val = i * step;
    ticks.push(val);
    if (val >= maxValue) break;
  }
  return {
    ticks,
    maxVal: ticks[ticks.length - 1]
  };
}

function generateActivityChart(historyPointsData) {
  const N = historyPointsData.length;
  if (N === 0) {
    return `<div class="history-chart-empty">—</div>`;
  }

  const width = 500;
  const height = 220;
  const paddingLeft = 40;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 38;
  const chartWidth = width - paddingLeft - paddingRight;
  const chartHeight = height - paddingTop - paddingBottom;

  const timestamps = historyPointsData.map(p => new Date(p.savedAt).getTime());
  const activeCounts = historyPointsData.map(p => historyActiveFindings(p).length);
  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const timeRange = maxTime - minTime;

  const maxActive = Math.max(...activeCounts, 1);
  const { ticks, maxVal } = getYScale(maxActive);

  const points = historyPointsData.map((entry, index) => {
    const time = new Date(entry.savedAt).getTime();
    const activeFindings = historyActiveFindings(entry);
    const active = activeFindings.length;
    
    let x;
    if (N === 1) {
      x = paddingLeft + chartWidth / 2;
    } else {
      x = timeRange > 0
        ? paddingLeft + ((time - minTime) / timeRange) * chartWidth
        : paddingLeft + (index / (N - 1)) * chartWidth;
    }
      
    const y = paddingTop + chartHeight - (active / maxVal) * chartHeight;

    const critical = activeFindings.filter(f => ['critical', 'error'].includes(String(f.rawSeverity || f.severity || '').toUpperCase())).length;
    const high = activeFindings.filter(f => String(f.rawSeverity || f.severity || '').toUpperCase() === 'HIGH').length;
    const medium = activeFindings.filter(f => ['medium', 'warning'].includes(String(f.rawSeverity || f.severity || '').toUpperCase())).length;
    const low = activeFindings.filter(f => ['low', 'info', 'information'].includes(String(f.rawSeverity || f.severity || '').toUpperCase())).length;
    
    const consolidated = getConsolidatedFindingsForHistoryEntry(entry);
    const total = deduplicateByFingerprint(consolidated).length;

    return {
      x,
      y,
      entry,
      active,
      total,
      critical,
      high,
      medium,
      low
    };
  });

  const gridLinesHtml = ticks.map(tick => {
    const y = paddingTop + chartHeight - (tick / maxVal) * chartHeight;
    return `
      <line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" class="chart-grid-line" />
      <text x="${paddingLeft - 10}" y="${y + 4}" class="chart-y-axis-label" text-anchor="end">${tick}</text>
    `;
  }).join('');

  const vertLinesHtml = points.map(p => {
    return `<line x1="${p.x.toFixed(2)}" y1="${paddingTop}" x2="${p.x.toFixed(2)}" y2="${(paddingTop + chartHeight).toFixed(2)}" class="chart-grid-line vertical" />`;
  }).join('');

  let pathHtml = '';
  if (N >= 2) {
    const getBezierPath = (pts) => {
      let d = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[i];
        const p1 = pts[i + 1];
        const cpX1 = p0.x + (p1.x - p0.x) / 3;
        const cpY1 = p0.y;
        const cpX2 = p0.x + 2 * (p1.x - p0.x) / 3;
        const cpY2 = p1.y;
        d += ` C ${cpX1.toFixed(2)} ${cpY1.toFixed(2)}, ${cpX2.toFixed(2)} ${cpY2.toFixed(2)}, ${p1.x.toFixed(2)} ${p1.y.toFixed(2)}`;
      }
      return d;
    };
    const bezierD = getBezierPath(points);
    const areaD = `${bezierD} L ${points[points.length - 1].x.toFixed(2)} ${(paddingTop + chartHeight).toFixed(2)} L ${points[0].x.toFixed(2)} ${(paddingTop + chartHeight).toFixed(2)} Z`;
    
    pathHtml = `
      <path d="${areaD}" fill="url(#chart-area-gradient)" />
      <path d="${bezierD}" class="chart-line" />
    `;
  }

  const diffDays = timeRange / (1000 * 60 * 60 * 24);
  const isSameDay = new Date(minTime).toDateString() === new Date(maxTime).toDateString();

  // Create a label-selection strategy to prevent overlaps
  const selectedIndexes = new Set();
  selectedIndexes.add(0);
  selectedIndexes.add(N - 1);

  if (N > 1) {
    if (N <= 4) {
      for (let i = 1; i < N - 1; i++) {
        selectedIndexes.add(i);
      }
    } else if (N <= 8) {
      const step = Math.floor(N / 3) || 1;
      for (let i = step; i < N - 1; i += step) {
        selectedIndexes.add(i);
      }
    } else {
      const countToSelect = 5;
      const step = (N - 1) / (countToSelect - 1);
      for (let i = 1; i < countToSelect - 1; i++) {
        const idx = Math.round(i * step);
        if (idx > 0 && idx < N - 1) {
          selectedIndexes.add(idx);
        }
      }
    }
  }

  const labelsHtmlList = [];
  let lastLabelX = -9999;
  const minLabelSpacing = 65;

  for (let i = 0; i < N; i++) {
    if (!selectedIndexes.has(i)) continue;
    const p = points[i];
    
    // Check if we render the label
    let shouldRender = false;
    if (i === 0) {
      shouldRender = true;
    } else if (i === N - 1) {
      // If the last label overlaps with the previous one, drop the previous one
      if (p.x - lastLabelX < minLabelSpacing && labelsHtmlList.length > 1) {
        labelsHtmlList.pop();
      }
      shouldRender = true;
    } else {
      // Intermediate label
      if (p.x - lastLabelX >= minLabelSpacing && (points[N - 1].x - p.x >= minLabelSpacing)) {
        shouldRender = true;
      }
    }

    if (shouldRender) {
      const date = new Date(p.entry.savedAt);
      let labelContent = '';
      if (isSameDay) {
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        labelContent = `<tspan x="${p.x.toFixed(2)}" dy="4">${hours}:${minutes}</tspan>`;
      } else if (diffDays <= 7) {
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        labelContent = `
          <tspan x="${p.x.toFixed(2)}" dy="-6">${day}/${month}</tspan>
          <tspan x="${p.x.toFixed(2)}" dy="13">${hours}:${minutes}</tspan>
        `;
      } else {
        const day = String(date.getDate()).padStart(2, '0');
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const monthStr = months[date.getMonth()];
        labelContent = `<tspan x="${p.x.toFixed(2)}" dy="4">${day} ${monthStr}</tspan>`;
      }
      
      labelsHtmlList.push(`<text x="${p.x.toFixed(2)}" y="${height - 20}" class="chart-axis-label" text-anchor="middle">${labelContent}</text>`);
      lastLabelX = p.x;
    }
  }

  const formatTooltipTimestamp = (date) => {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
  };

  const circles = points.map(p => {
    const date = new Date(p.entry.savedAt);
    const dateStr = formatTooltipTimestamp(date);
    return `<circle cx="${p.x.toFixed(2)}" cy="${p.y.toFixed(2)}" r="4.5" class="chart-dot" 
      data-date="${escapeHtml(dateStr)}"
      data-total="${p.total}"
      data-active="${p.active}"
      data-critical="${p.critical}"
      data-high="${p.high}"
      data-medium="${p.medium}"
      data-low="${p.low}"
    />`;
  }).join('');

  return `
    <div class="activity-chart-wrapper">
      <svg class="activity-chart" viewBox="0 0 500 220" role="img" aria-label="Évolution des alertes actives">
        <defs>
          <linearGradient id="chart-area-gradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--vscode-charts-blue, #58a6ff)" stop-opacity="0.18"/>
            <stop offset="100%" stop-color="var(--vscode-charts-blue, #58a6ff)" stop-opacity="0.00"/>
          </linearGradient>
        </defs>
        ${gridLinesHtml}
        ${vertLinesHtml}
        ${pathHtml}
        ${circles}
        ${labelsHtmlList.join('')}
      </svg>
      <div id="activity-chart-tooltip" class="activity-tooltip" style="opacity: 0; display: none;"></div>
    </div>
  `;
}

function severityCount(findings, severities) {
  return findings.filter((finding) => severities.includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
}

function endpointPath(value) {
  try { return new URL(String(value)).pathname.replace(/\/+$/, '') || '/'; }
  catch { return String(value || '').split('?')[0].replace(/\/+$/, '') || '/'; }
}

function isUsefulHttpScenario(scenario) {
  const pathname = endpointPath(scenario.request?.url).toLowerCase();
  if (/\.(?:css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i.test(pathname)) return false;
  if (pathname === '/socket.io' || pathname.startsWith('/socket.io/')) return false;
  return ['/api/', '/rest/', '/graphql', '/ftp/', '/b2b/', '/profile'].some((prefix) =>
    pathname === prefix.replace(/\/$/, '') || pathname.startsWith(prefix));
}

/**
 * Association confidence between a captured HTTP transaction and a finding.
 *
 * Deliberately evidence-based. A shared hostname, a shared target or a shared CWE
 * proves nothing and never links anything here — only the normalized path, the
 * HTTP method and the exercised parameter do.
 *
 *   EXACT    same path, same method, and the finding's parameter really appears
 *            in this transaction's query or body
 *   STRONG   same path and same method
 *   PROBABLE same path, but the scanner reported no method for the finding, so
 *            the match cannot be proven — presented as possible, not confirmed
 *   null     no evidence; not linked
 *
 * `ZAP_UNKNOWN_METHOD` matters: the normalizer stores the literal `'HTTP'` when
 * ZAP reports no method for an alert instance. Compared for equality against a
 * real `GET`, that sentinel silently dropped legitimate links, so it is treated
 * as « unknown » rather than as a method name.
 */
const ZAP_UNKNOWN_METHOD = 'HTTP';

const ASSOCIATION_CONFIDENCE = Object.freeze({
  EXACT: 'EXACT', STRONG: 'STRONG', PROBABLE: 'PROBABLE', WEAK: 'WEAK'
});

/** Wording per tier. Only EXACT and STRONG are stated as established links. */
const ASSOCIATION_LABELS = Object.freeze({
  EXACT: 'Association exacte — paramètre confirmé',
  STRONG: 'Association établie — même endpoint et même méthode',
  PROBABLE: 'Association possible — non prouvée : le scanner n’a pas fourni la méthode',
  WEAK: 'Association possible — non prouvée'
});

/** Parameter names this transaction actually exercises, from query and body. */
function transactionParameters(scenario) {
  const names = new Set();
  const request = scenario?.request || {};
  try {
    for (const key of new URL(String(request.url)).searchParams.keys()) names.add(key.toLowerCase());
  } catch { /* a relative or malformed URL simply contributes no query parameter */ }
  for (const parameter of request.parameters || []) {
    if (parameter?.name) names.add(String(parameter.name).toLowerCase());
  }
  const body = String(request.body || '');
  if (body) {
    // Only the shapes we can read without guessing: form encoding and flat JSON.
    if (/^[\w.[\]%+-]+=/.test(body)) {
      for (const pair of body.split('&')) {
        const name = pair.split('=')[0];
        if (name) names.add(decodeURIComponent(name).toLowerCase());
      }
    } else {
      try {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          for (const key of Object.keys(parsed)) names.add(key.toLowerCase());
        }
      } catch { /* an unreadable body contributes no parameter */ }
    }
  }
  return names;
}

/**
 * How strongly a finding belongs to a transaction, with the reasons.
 * Returns `{ confidence: null }` when there is no evidence at all.
 */
function associationFor(scenario, finding) {
  if (!finding?.endpoint) return { confidence: null, reasons: [] };
  const path = endpointPath(scenario?.request?.url);
  const findingPath = endpointPath(finding.endpoint);
  if (findingPath !== path) return { confidence: null, reasons: [] };

  const method = String(scenario?.request?.method || '').toUpperCase();
  const findingMethod = String(finding.method || '').toUpperCase();
  const methodKnown = findingMethod && findingMethod !== ZAP_UNKNOWN_METHOD;
  const reasons = [`Chemin identique : ${path}`];

  // A method the scanner did report and that disagrees is a hard rejection: this
  // is what stops `GET /foo` from inheriting a finding about `POST /api/login`.
  if (methodKnown && method && findingMethod !== method) return { confidence: null, reasons: [] };

  if (!methodKnown) {
    reasons.push('Méthode non fournie par le scanner pour ce finding');
    return { confidence: ASSOCIATION_CONFIDENCE.PROBABLE, reasons };
  }
  reasons.push(`Méthode identique : ${findingMethod}`);

  const parameter = String(finding.parameter || '').toLowerCase();
  if (parameter && transactionParameters(scenario).has(parameter)) {
    reasons.push(`Paramètre « ${finding.parameter} » réellement présent dans cette requête`);
    return { confidence: ASSOCIATION_CONFIDENCE.EXACT, reasons };
  }
  if (parameter) reasons.push(`Paramètre « ${finding.parameter} » absent de cette requête`);
  return { confidence: ASSOCIATION_CONFIDENCE.STRONG, reasons };
}

/** Findings associated with a transaction, each carrying its confidence tier. */
function linkedFindingsWithConfidence(scenario, findings) {
  return (findings || [])
    .map((finding) => ({ finding, ...associationFor(scenario, finding) }))
    .filter((entry) => entry.confidence);
}

/**
 * The historical helper: the findings themselves. Kept so existing callers are
 * unchanged, now including the ones a sentinel method used to hide.
 */
function linkedFindingsForScenario(scenario, findings) {
  return linkedFindingsWithConfidence(scenario, findings).map((entry) => entry.finding);
}

function sourceCorrelationForFinding(finding, findings = [], correlations = []) {
  const findingIndex = findings.indexOf(finding);
  if (finding.absolutePath && (finding.file || finding.startLine)) {
    return { label: 'Likely source', finding, index: findingIndex, confidence: 'high' };
  }
  const matches = correlations
    .filter((correlation) => correlation.findingIds?.includes(finding.id))
    .sort((left, right) => (left.confidence === 'high' ? 0 : 1) - (right.confidence === 'high' ? 0 : 1));
  for (const correlation of matches) {
    const sourceFinding = findings.find((candidate) => candidate.id !== finding.id
      && correlation.findingIds.includes(candidate.id)
      && candidate.absolutePath
      && (candidate.file || candidate.startLine));
    if (!sourceFinding) continue;
    const reliable = correlation.type === 'endpoint-source' && correlation.confidence === 'high';
    return { label: reliable ? 'Likely source' : 'Possible source', finding: sourceFinding, index: findings.indexOf(sourceFinding), confidence: reliable ? 'high' : 'medium' };
  }
  return null;
}

const SENSITIVE_HTTP_NAME = /authorization|cookie|token|secret|api[-_]?key|password|passwd|session/i;

function sanitizeHttpValue(name, value) {
  return SENSITIVE_HTTP_NAME.test(String(name || '')) ? '[REDACTED]' : String(value ?? '');
}

function safeHttpParameters(scenario) {
  const parameters = [];
  try {
    const url = new URL(String(scenario.request?.url || ''));
    for (const [name, value] of url.searchParams) parameters.push({ location: 'query', name, value: sanitizeHttpValue(name, value) });
  } catch { /* URL partielle */ }
  const body = String(scenario.request?.body || '');
  if (body && body.length <= 64 * 1024) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [name, value] of Object.entries(parsed)) parameters.push({ location: 'body', name, value: sanitizeHttpValue(name, typeof value === 'object' ? JSON.stringify(value) : value) });
      }
    } catch {
      try {
        for (const [name, value] of new URLSearchParams(body)) parameters.push({ location: 'body', name, value: sanitizeHttpValue(name, value) });
      } catch { /* corps non structuré */ }
    }
  }
  return parameters.slice(0, 50);
}

function buildSafeHttpPreview(scenario, findings = []) {
  const request = scenario?.request || {};
  const response = scenario?.response || {};
  const headers = Object.entries(request.headers || {}).map(([name, value]) => ({ name, value: sanitizeHttpValue(name, value) }));
  // Each association carries its confidence and the evidence behind it, so a
  // match that could not be proven is never presented as a confirmed link.
  const linked = linkedFindingsWithConfidence(scenario, findings).map(({ finding, confidence, reasons }) => ({
    index: findings.indexOf(finding), severity: String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase(),
    title: finding.title || finding.ruleId || 'Finding', source: finding.tool || 'Security Center',
    confidence,
    confidenceLabel: ASSOCIATION_LABELS[confidence] || '',
    proven: confidence === ASSOCIATION_CONFIDENCE.EXACT || confidence === ASSOCIATION_CONFIDENCE.STRONG,
    reasons
  }));
  const body = String(response.body || response.content?.text || '');
  const safeBody = body && !SENSITIVE_HTTP_NAME.test(body) ? body.slice(0, 2000) : body ? '[REDACTED: potentially sensitive response]' : '';
  const durationMs = Number(scenario.durationMs ?? scenario.duration ?? response.durationMs ?? response.time ?? 0);
  const contentType = response.headers?.['content-type'] || response.headers?.['Content-Type'] || response.mimeType || response.content?.mimeType || 'Unknown';
  let path = String(request.url || '');
  let safeUrl = path;
  try {
    const parsed = new URL(path);
    for (const [name] of parsed.searchParams) if (SENSITIVE_HTTP_NAME.test(name)) parsed.searchParams.set(name, '[REDACTED]');
    path = `${parsed.pathname || '/'}${parsed.search || ''}`;
    safeUrl = parsed.toString();
  } catch { /* URL partielle */ }
  const responseHeaders = Object.entries(response.headers || {}).map(([name, value]) => ({ name, value: sanitizeHttpValue(name, value) }));
  let requestBody = String(request.body || '');
  if (requestBody) {
    try {
      const parsed = JSON.parse(requestBody);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        requestBody = JSON.stringify(Object.fromEntries(Object.entries(parsed).map(([name, value]) => [name, sanitizeHttpValue(name, typeof value === 'object' ? JSON.stringify(value) : value)])), null, 2);
      } else if (SENSITIVE_HTTP_NAME.test(requestBody)) requestBody = '[REDACTED: potentially sensitive request]';
    } catch { requestBody = SENSITIVE_HTTP_NAME.test(requestBody) ? '[REDACTED: potentially sensitive request]' : requestBody; }
  }
  return {
    method: String(request.method || 'HTTP').toUpperCase(), url: safeUrl, path,
    timestamp: scenario.timestamp || scenario.capturedAt || scenario.startedDateTime || scenario.createdAt || '',
    source: String(scenario.source || 'capture').toUpperCase(), duration: durationMs > 0 ? formatDuration(durationMs) : 'Not available',
    headers, parameters: safeHttpParameters(scenario), requestBody: requestBody.slice(0, 4000), statusCode: Number(response.statusCode || response.status || 0), responseHeaders,
    responseType: String(contentType), responsePreview: safeBody, linkedFindings: linked,
    safeRequest: `${String(request.method || 'HTTP').toUpperCase()} ${path}\n${headers.map((header) => `${header.name}: ${header.value}`).join('\n')}`.trim()
  };
}

function renderPipeline(scanners, scanStatus, durationMs, findings = []) {
  if (!scanners.length) return '<div class="empty">Le pipeline apparaîtra au lancement d’une analyse.</div>';
  const allFinished = scanners.every((scanner) => ['completed', 'failed', 'cancelled'].includes(scanner.status));
  const hasFailure = scanners.some((scanner) => scanner.status === 'failed');
  const hasCancellation = scanners.some((scanner) => scanner.status === 'cancelled');
  const endStatus = allFinished ? (hasFailure || hasCancellation ? 'failed' : 'completed') : 'pending';
  const stage = (label, status, subtitle = '', scannerFindings = null) => {
    const interactive = Array.isArray(scannerFindings);
    const hasExplicitCount = interactive && Object.prototype.hasOwnProperty.call(scannerFindings, 'resultCount');
    const findingCount = hasExplicitCount ? scannerFindings.resultCount : Array.isArray(scannerFindings) ? scannerFindings.length : null;
    const countLabel = findingCount === null ? '— finding(s)' : `${findingCount} finding(s)`;
    const severityRank = (value) => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, WARNING: 2, LOW: 1, INFO: 0 }[String(value || '').toUpperCase()] || 0);
    const priority = interactive
      ? [...scannerFindings].sort((left, right) => severityRank(right.rawSeverity || right.severity) - severityRank(left.rawSeverity || left.severity)).slice(0, 5)
      : [];
    const tooltipId = interactive ? `pipeline-${String(label).toLowerCase().replace(/[^a-z0-9]+/g, '-')}-findings` : '';
    const popover = interactive ? `<div id="${tooltipId}" class="pipeline-popover" role="tooltip">
      <strong>${escapeHtml(label)} · ${escapeHtml(countLabel)}</strong>
      ${priority.length ? priority.map((finding) => `<span><b>${escapeHtml(String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase())}</b> ${escapeHtml(finding.title || finding.ruleId || 'Finding')}</span>`).join('') : `<span>${['running', 'refreshing'].includes(status) ? 'Analysis in progress' : status === 'pending' ? 'No current result for this execution yet.' : status === 'failed' ? 'Scanner failed. No previous result is used as the current result.' : status === 'cancelled' ? 'Scanner cancelled before producing a current result.' : 'Aucun finding pour ce scanner.'}</span>`}
      ${scannerFindings.length > priority.length ? `<small>+ ${scannerFindings.length - priority.length} autre(s)</small>` : ''}
      ${status === 'failed' ? `<button class="pipeline-retry" data-retry-scanner="${escapeHtml(label)}">Relancer ${escapeHtml(label)}</button>` : ''}
    </div>` : '';
    return `<div class="pipeline-stage${interactive ? ' interactive' : ''}"${interactive ? ` tabindex="0" aria-describedby="${tooltipId}" aria-label="Aperçu des findings ${escapeHtml(label)}"` : ''}>
    <div class="pipeline-dot ${status}">${status === 'completed' ? '✓' : status === 'cancelled' ? '×' : status === 'failed' ? '!' : ['running', 'refreshing'].includes(status) ? '<span class="pipeline-spinner" aria-hidden="true">↻</span>' : '○'}</div>
    <strong>${escapeHtml(label)}</strong>
    <small>${escapeHtml(subtitle || status)}</small>
    ${popover}
  </div>`;
  };
  const terminal = ['completed', 'partial', 'cancelled', 'failed'].includes(scanStatus);
  const parts = [stage('Start', 'completed', terminal ? 'Terminé' : 'Démarré')];
  for (const scanner of scanners) {
    const connectorStatus = ['running', 'refreshing', 'completed', 'failed', 'cancelled'].includes(scanner.status) ? 'active' : 'pending';
    parts.push(`<div class="pipeline-line ${connectorStatus}"></div>`);
    const scannerSubtitle = ['running', 'refreshing'].includes(scanner.status)
      ? (scanner.previousValidResult ? 'En cours · résultat précédent conservé' : 'En cours')
      : scanner.status === 'completed' ? (scanner.durationMs ? formatDuration(scanner.durationMs) : 'Terminé')
      : scanner.status === 'failed' ? 'Échec · relance disponible'
      : scanner.status === 'cancelled' ? 'Annulé · relance disponible'
      : 'En attente';
    const currentFindings = Array.isArray(scanner.currentRun?.findings)
      ? [...scanner.currentRun.findings]
      : scanner.status === 'completed'
        ? findings.filter((finding) => finding.tool === scanner.tool)
        : [];
    currentFindings.resultCount = scanner.status === 'completed'
      ? Number(scanner.currentRun?.resultCount ?? currentFindings.length)
      : null;
    parts.push(stage(scanner.tool, scanner.status, scannerSubtitle, currentFindings));
  }
  parts.push(`<div class="pipeline-line ${allFinished ? 'active' : 'pending'}"></div>`);
  const endSubtitle = !allFinished ? 'En attente' : hasCancellation ? `Scan partiel • ${formatDuration(durationMs)}` : hasFailure ? `Terminé avec erreur • ${formatDuration(durationMs)}` : formatDuration(durationMs);
  parts.push(stage('End', endStatus, endSubtitle));
  return `<div class="pipeline-scroll"><div class="pipeline">${parts.join('')}</div></div>`;
}

function renderDonutChart(values, label) {
  const entries = Object.entries(values).filter(([, count]) => count > 0).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  if (!total) return '<div class="empty">Aucun résultat</div>';
  let offset = 0;
  const segments = entries.map(([name, count], index) => {
    const percent = count / total * 100;
    const segment = `<circle class="donut-segment chart-${index % 6}" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="${percent} ${100 - percent}" stroke-dashoffset="${-offset}"></circle>`;
    offset += percent;
    return segment;
  }).join('');
  const legend = entries.map(([name, count], index) => `<div class="donut-legend-row"><span class="donut-swatch chart-${index % 6}"></span><span>${escapeHtml(name)}</span><strong>${count}</strong></div>`).join('');
  return `<div class="donut-card"><div class="donut-wrap"><svg viewBox="0 0 100 100" role="img" aria-label="${escapeHtml(label)}"><circle class="donut-track" cx="50" cy="50" r="42"></circle>${segments}</svg><div class="donut-total"><strong>${total}</strong><span>total</span></div></div><div class="donut-legend">${legend}</div></div>`;
}

/**
 * Les quatre paliers de severite, dans l'ordre du plus grave au moins grave.
 * L'ordre est celui de la lecture, pas celui des donnees : une repartition qui
 * commence par « low » se lit a l'envers.
 */
const SEVERITY_SLICES = Object.freeze([
  ['critical', 'Critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low']
]);

/**
 * La repartition par severite, dessinee avec les couleurs de severite plutot
 * qu'avec la palette generique des graphiques : une part « critical » qui n'est
 * pas rouge serait une couleur qui ment sur une gravite.
 *
 * Les comptes viennent de l'appelant. Cette fonction dessine, elle ne compte
 * pas, n'agrege pas et n'estime aucun pourcentage manquant : un palier absent
 * des donnees est simplement absent du dessin.
 */
function renderSeverityDonut(counts) {
  const entries = SEVERITY_SLICES
    .map(([key, label]) => ({ key, label, count: Number(counts[key] || 0) }))
    .filter((entry) => entry.count > 0);
  const total = entries.reduce((sum, entry) => sum + entry.count, 0);
  if (!total) return '<div class="empty">Aucune alerte active a repartir.</div>';
  let offset = 0;
  const segments = entries.map((entry) => {
    const percent = entry.count / total * 100;
    const segment = `<circle class="sev-segment sev-${entry.key}" cx="50" cy="50" r="40" pathLength="100" stroke-dasharray="${percent.toFixed(2)} ${(100 - percent).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"><title>${escapeHtml(entry.label)} : ${entry.count}</title></circle>`;
    offset += percent;
    return segment;
  }).join('');
  const legend = entries.map((entry) => `<div class="sev-legend-row"><span class="sev-swatch sev-${entry.key}"></span><span class="sev-name">${escapeHtml(entry.label)}</span><strong>${entry.count}</strong><small>${Math.round(entry.count / total * 100)} %</small></div>`).join('');
  return `<div class="sev-donut"><div class="sev-ring"><svg viewBox="0 0 100 100" role="img" aria-label="Repartition des alertes actives par severite"><circle class="sev-track" cx="50" cy="50" r="40"></circle>${segments}</svg><div class="sev-total"><strong>${total}</strong><span>actives</span></div></div><div class="sev-legend">${legend}</div></div>`;
}

/**
 * Les fichiers et endpoints les plus exposes, tels que la liste deja affichee
 * les decrit.
 *
 * C'est un regroupement d'un tableau deja en memoire, pas une nouvelle analyse :
 * aucun scan n'est declenche, rien n'est persiste, aucune severite n'est
 * recalculee. Un finding sans emplacement n'est pas invente : il est ignore.
 */
function topRiskyTargets(findings, limit = 5) {
  const rank = { CRITICAL: 4, ERROR: 4, HIGH: 3, MEDIUM: 2, WARNING: 2, LOW: 1 };
  const buckets = new Map();
  for (const finding of findings) {
    const target = finding.file || finding.endpoint || '';
    if (!target) continue;
    const severity = String(finding.rawSeverity || finding.severity || '').toUpperCase();
    const entry = buckets.get(target) || { target, count: 0, severity: '', rank: 0 };
    entry.count += 1;
    if ((rank[severity] || 0) > entry.rank) {
      entry.rank = rank[severity] || 0;
      entry.severity = severity;
    }
    buckets.set(target, entry);
  }
  return [...buckets.values()]
    .sort((left, right) => right.rank - left.rank || right.count - left.count)
    .slice(0, limit);
}

/**
 * Severite -> palier semantique. `semanticClass` ne distingue que trois tons et
 * confondait « medium » avec « high » ; les cartes de severite en demandent
 * quatre, car un « medium » peint comme un « high » est une couleur qui exagere.
 */
function severityTone(value) {
  const severity = String(value || '').toUpperCase();
  if (['CRITICAL', 'ERROR'].includes(severity)) return 'critical';
  if (severity === 'HIGH') return 'high';
  if (['MEDIUM', 'WARNING'].includes(severity)) return 'medium';
  if (['LOW', 'INFO', 'INFORMATION'].includes(severity)) return 'low';
  return 'neutral';
}

/**
 * Les evenements du cycle de vie d'une correction, tels que le finding les
 * porte deja.
 *
 * Un evenement n'existe ici que s'il a une date reelle dans le modele. Il n'y a
 * volontairement aucune ligne « Alerte detectee » generique : seuls certains
 * scanners datent leur detection, et inventer cette date pour les autres
 * donnerait une chronologie fausse. Un cycle incomplet s'affiche incomplet.
 */
function verificationTimeline(finding) {
  if (!finding) return [];
  const events = [];
  const push = (at, label, tone) => {
    const time = Date.parse(at || '');
    if (Number.isFinite(time)) events.push({ at, time, label, tone });
  };
  push(finding.createdAt, 'Alerte signalée par le scanner', 'neutral');
  push(finding.fixedAt, finding.fixSource ? `Correction appliquée (${finding.fixSource})` : 'Correction appliquée', 'medium');
  push(finding.validationStartedAt, 'Vérification lancée', 'neutral');
  for (const entry of Array.isArray(finding.verificationHistory) ? finding.verificationHistory : []) {
    if (!entry?.state) continue;
    push(entry.at, VERIFICATION_EVENT_LABELS[entry.state] || entry.state, entry.state === 'validated' ? 'low' : 'critical');
  }
  if (!finding.verificationHistory?.length && finding.verification?.state) {
    push(finding.verification.at, VERIFICATION_EVENT_LABELS[finding.verification.state] || finding.verification.state,
      finding.verification.state === 'validated' ? 'low' : 'critical');
  }
  return events.sort((left, right) => left.time - right.time);
}

/** Verdicts du cycle unifie, dits avec les mots du cycle et pas ceux du code. */
const VERIFICATION_EVENT_LABELS = Object.freeze({
  fix_proposed: 'Correction proposée', fixed: 'Correction appliquée', validating: 'Vérification en cours',
  validated: 'Disparition confirmée par re-scan', still_present: 'Toujours présente après vérification',
  validation_failed: 'Vérification impossible', inconclusive: 'Vérification non concluante',
  regressed: 'Réapparue après validation'
});

/** Le dernier segment d'un chemin : ce que l'oeil cherche en premier. */
function targetLabel(value) {
  const text = String(value);
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : text;
}

/**
 * Les surfaces hebergees par le cadre applicatif partage.
 *
 * `sidebar` (la vue etroite de la barre d'activite) et `history` (un scan
 * archive, ouvert en lecture seule) restent hors cadre : la premiere n'a pas la
 * largeur d'une navigation, la seconde n'est pas une page de l'application
 * courante. Toutes les autres ouvrent desormais la meme coquille.
 */
const SHELLED_SURFACES = new Set(['full', 'findings', 'scans', 'dynamic', 'analytics', 'burp-settings', 'scanner-details']);

/** Titre et sous-titre de la barre superieure, par page. */
const SURFACE_TITLES = {
  full: ['Dashboard', ''],
  findings: ['Findings', 'Alertes, triage et corrections'],
  scans: ['Scans', 'État, résultats et exécution des scanners'],
  dynamic: ['Dynamic Security', 'Cible, tests dynamiques, findings et trafic HTTP capturé'],
  analytics: ['Analytics', 'Répartition des alertes et signaux de sécurité'],
  'burp-settings': ['Paramètres Burp', 'État du connecteur et de la capture sécurisée'],
  'scanner-details': ['Scanner Details', 'Résultats détaillés du scanner sélectionné']
};

function renderDashboardHtml(model, nonce, surface = 'full', selectedTheme = 'light', uiState = {}, assets = {}) {
  const companionImageUri = typeof assets === 'string' ? assets : assets?.companionImageUri || '';
  const cspSource = typeof assets === 'object' ? assets?.cspSource || '' : '';
  const renderScannerLogo = (tool, status = '') => renderScannerLogoHtml(tool, status, assets);
  const scannerId = (tool) => scannerIdForTool(tool);
  const renderZapPreflightModal = (preflight = {}) => {
    const modeLabel = preflight.mode === 'openapi' ? 'OpenAPI active' : 'Active DAST';
    return `<div class="sc-modal-overlay sc-modal-backdrop" role="presentation">
      <section class="sc-zap-preflight" role="dialog" aria-modal="true" aria-labelledby="zap-preflight-title" aria-describedby="zap-preflight-copy" data-zap-preflight-id="${escapeHtml(preflight.id || '')}" tabindex="-1">
        <div class="sc-zap-modal-head">
          <div class="sc-zap-modal-logo">${renderScannerLogo('ZAP', 'running')}</div>
          <div>
            <span>Dynamic Security · ZAP</span>
            <h2 id="zap-preflight-title">Autoriser l’analyse ZAP active ?</h2>
          </div>
          <button class="sc-modal-close" type="button" data-zap-preflight-decision="cancel" aria-label="Cancel analysis">×</button>
        </div>
        <p id="zap-preflight-copy" class="sc-zap-modal-copy">ZAP will send active security-test requests to this target. Active testing can send attack-like requests to the application.</p>
        <div class="sc-zap-target">
          <span>Target · ${escapeHtml(modeLabel)}</span>
          <code>${escapeHtml(preflight.target || 'http://127.0.0.1:3000')}</code>
        </div>
        <div class="sc-zap-warning"><strong>Authorized targets only</strong><span>Only continue if you own this application or are authorized to test it.</span></div>
        <div class="sc-zap-modal-actions">
          <button class="secondary" type="button" data-zap-preflight-decision="passive">Use passive scan</button>
          <button class="primary" type="button" data-zap-preflight-decision="active">Authorize active scan</button>
          <button class="quiet-action" type="button" data-zap-preflight-decision="cancel">Cancel analysis</button>
        </div>
      </section>
    </div>`;
  };
  const zapPreflightModal = uiState?.zapPreflight ? renderZapPreflightModal(uiState.zapPreflight) : '';
  const inShell = SHELLED_SURFACES.has(surface);
  const modalRoot = `<div id="security-center-modal-root">${zapPreflightModal}</div>`;
  const statusLabels = { new: 'Nouvelle', triaged: 'Triée', probable: 'Probable', confirmed: 'Confirmée', fixed: 'Corrigée — validation en attente', validated: 'Validée par re-scan', false_positive: 'Faux positif', accepted: 'Risque accepté',
    // Verification outcomes. Without these a row would print its raw slug.
    fix_proposed: 'Correction proposée', validating: 'Vérification en cours',
    still_present: 'Toujours présente après vérification', validation_failed: 'Vérification impossible',
    inconclusive: 'Vérification non concluante', regressed: 'Réapparue après validation' };
  const completedTools = new Set(model.scanners.filter((scanner) => scanner.status === 'completed').map((scanner) => scanner.tool));
  const scanResultsTrusted = model.scanStatus === 'completed' || model.snapshotAvailable;
  const partialResultsAvailable = ['partial', 'cancelled'].includes(model.scanStatus) && completedTools.size > 0;
  const resultsAvailable = scanResultsTrusted || partialResultsAvailable;
  const currentExecutionActive = model.scanStatus !== 'idle'
    && !['completed', 'partial', 'cancelled', 'failed'].includes(model.scanStatus)
    && (model.activeExecution || model.scanners.some((scanner) => scanner.currentRun));
  const completedCurrentRunFindings = deduplicateByFingerprint(model.currentRunFindings || []);
  const optionTags = (values) => Object.keys(values).sort().map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
  const scannerOptionTags = (values) => Object.keys(values).sort().map((tool) => `<option value="${escapeHtml(scannerId(tool))}">${escapeHtml(scannerPresentation(tool).label)}</option>`).join('');
  const reachabilityFor = (finding) => {
    const status = finding.reachability?.status || finding.reachability?.state;
    if (status) return String(status);
    if (finding.reachable === true) return 'REACHABLE';
    if (finding.reachable === false) return 'NOT_REACHABLE';
    return 'UNKNOWN';
  };
  const reachabilityLabel = (value) => ({
    REACHABLE: 'Reachable',
    POTENTIALLY_REACHABLE: 'Potentially reachable',
    NOT_REACHABLE: 'Not reachable',
    UNKNOWN: 'Unknown',
    dynamically_confirmed: 'Dynamically confirmed',
    statically_reachable: 'Statically reachable',
    imported: 'Imported',
    present: 'Present',
    not_reachable: 'Not reachable',
    unknown: 'Unknown'
  })[value] || String(value || 'Unknown');
  const factBadge = (type, label) => `<span class="fact-badge ${escapeHtml(type)}">${escapeHtml(label)}</span>`;
  const findingCards = model.findings.length
    ? model.findings.map((finding, index) => {
        const severity = String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase();
        const context = finding.sourceContext || 'non classé';
        const status = finding.triageStatus || 'new';
        const location = finding.endpoint || finding.file || 'Emplacement non fourni';
        const line = Number.isFinite(Number(finding.startLine)) && Number(finding.startLine) >= 0 ? `:${Number(finding.startLine) + 1}` : '';
        const presentation = scannerPresentation(finding.tool);
        const stableScannerId = scannerId(finding.tool);
        const reachability = reachabilityFor(finding);
        const confidence = finding.confidence || finding.reachability?.confidence || finding.priority?.confidence || 'unknown';
        const searchable = [finding.title, finding.tool, presentation.label, severity, context, status, location, finding.ruleId, finding.cwe, reachability, confidence]
          .filter(Boolean).join(' ').toLowerCase();
        return `<article class="finding-card" tabindex="0"
          data-search="${escapeHtml(searchable)}"
          data-tool="${escapeHtml(finding.tool)}"
          data-tool-id="${escapeHtml(stableScannerId)}"
          data-tool-label="${escapeHtml(presentation.label)}"
          data-severity="${escapeHtml(severity)}"
          data-status="${escapeHtml(status)}"
          data-context="${escapeHtml(context)}"
          data-reachability="${escapeHtml(reachability)}"
          data-reachability-label="${escapeHtml(reachabilityLabel(reachability))}"
          data-title="${escapeHtml(finding.title || 'Security finding')}"
          data-location="${escapeHtml(location)}${escapeHtml(line)}"
          data-rule="${escapeHtml(finding.ruleId || finding.cwe || 'Rule unavailable')}"
          data-confidence="${escapeHtml(confidence)}"
          data-description="${escapeHtml(finding.description || finding.developerSummary || 'No short description was provided by the scanner.')}">
          <div class="finding-accent ${semanticClass(severity)}"></div>
          <div class="finding-source">
            ${renderScannerLogo(finding.tool, status)}
            <span>${escapeHtml(presentation.label)}</span>
          </div>
          <div class="finding-main">
            <div class="finding-top">
              <span class="severity-badge ${semanticClass(severity)}">${escapeHtml(severity)}</span>
              ${factBadge('status', statusLabels[status] || status)}
              ${factBadge('context', context)}
              ${factBadge('reachability', reachabilityLabel(reachability))}
              ${finding.staleFromPreviousScan ? '<span class="triage-badge">Données du scan précédent</span>' : ''}
            </div>
            <strong class="finding-title">${escapeHtml(finding.title || 'Security finding')}</strong>
            <span class="finding-location">${escapeHtml(location)}${escapeHtml(line)}</span>
            <small>${escapeHtml(finding.ruleId || finding.cwe || 'Rule unavailable')} · Confidence ${escapeHtml(confidence)}</small>
          </div>
          <div class="finding-state">
            <span>${escapeHtml(statusLabels[status] || status)}</span>
            <small>${escapeHtml(reachabilityLabel(reachability))}</small>
          </div>
          <div class="finding-card-actions">
            ${finding.absolutePath ? `<button class="finding-code" data-finding-code-index="${index}" title="Ouvrir le fichier à la ligne concernée">Ouvrir le code</button>` : ''}
            <button class="finding-open" data-finding-index="${index}" title="Afficher toutes les preuves et recommandations">Investigate →</button>
          </div>
        </article>`;
      }).join('')
    : '<div class="empty">Aucune vulnérabilité à afficher. Lancez une analyse du workspace.</div>';
  const currentFindings = currentExecutionActive
    ? completedCurrentRunFindings
    : resultsAvailable
      ? model.findings.filter((finding) => !finding.staleFromPreviousScan && (model.snapshotAvailable || scanResultsTrusted || completedTools.has(finding.tool)))
      : [];
  const priorityFindings = currentFindings
    .filter((finding) => !finding.staleFromPreviousScan
      && !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus)
      && ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase()))
    .slice(0, 3)
    .map((finding) => {
      const severity = String(finding.rawSeverity || finding.severity || 'HIGH').toUpperCase();
      return `<article class="priority-finding ${semanticClass(severity)}"><span class="priority-marker"></span><div><span class="priority-severity">${escapeHtml(severity)}</span><strong>${escapeHtml(finding.title || 'Alerte de sécurité')}</strong><span>${escapeHtml(finding.tool || 'Scanner')} • ${escapeHtml(finding.endpoint || finding.file || 'Emplacement non fourni')}</span></div><button class="finding-open" data-finding-index="${model.findings.indexOf(finding)}">Examiner →</button></article>`;
    })
    .join('') || `<div class="empty">${resultsAvailable ? 'Aucune alerte HIGH ou CRITICAL dans les scanners terminés.' : 'Les priorités seront calculées après au moins un scanner terminé.'}</div>`;
  const dedupedCurrentFindings = deduplicateByFingerprint(currentFindings);
  const currentActiveFindings = dedupedCurrentFindings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus));
  const currentCriticalCount = currentActiveFindings.filter((finding) => ['CRITICAL', 'ERROR'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  const currentHighCount = currentActiveFindings.filter((finding) => String(finding.rawSeverity || finding.severity || '').toUpperCase() === 'HIGH').length;
  const currentProductionPriority = currentActiveFindings.filter((finding) => finding.sourceContext === 'production' && ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  const currentNewCount = dedupedCurrentFindings.filter((finding) => (finding.triageStatus || 'new') === 'new').length;
  // « Corrigee » and « validee » are not the same claim: the first says a patch
  // was applied, the second says a scanner confirmed the issue is gone. They were
  // summed into one tile, which made an unverified fix look like a result.
  // The split comes from the lifecycle itself rather than from a second count.
  const remediation = remediationCounters(dedupedCurrentFindings);
  const currentAcceptedCount = dedupedCurrentFindings.filter((finding) => finding.triageStatus === 'accepted').length;
  const priorityFindingCount = currentActiveFindings.filter((finding) => ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  
  const historyEntries = model.scanHistory
    .filter((entry) => entry && entry.savedAt)
    .sort((left, right) => new Date(right.savedAt) - new Date(left.savedAt));
    
  const maxPoints = 7;
  const historyPointsData = [...model.scanHistory]
    .filter((entry) => entry && entry.savedAt)
    .sort((a, b) => new Date(a.savedAt) - new Date(b.savedAt))
    .slice(-maxPoints);

  const historyChart = generateActivityChart(historyPointsData);

  let trendTop = '—';
  let trendBottom = '';
  const N = historyPointsData.length;
  if (N >= 2) {
    const firstVal = historyActiveFindings(historyPointsData[0]).length;
    const lastVal = historyActiveFindings(historyPointsData[N - 1]).length;
    if (firstVal === 0) {
      trendTop = '—';
    } else {
      const change = ((lastVal - firstVal) / firstVal) * 100;
      const roundedChange = Math.round(change);
      trendTop = `${roundedChange >= 0 ? '+' : ''}${roundedChange} %`;
    }
    trendBottom = `sur ${N} scans`;
  } else {
    trendTop = '—';
    trendBottom = `sur ${N} scan${N > 1 ? 's' : ''}`;
  }

  // MTTR Calculation with precise resolution priority rules
  const sortedScansForMttr = [...model.scanHistory]
    .filter((entry) => entry && entry.savedAt)
    .sort((a, b) => new Date(a.savedAt) - new Date(b.savedAt));

  const firstSeen = new Map();
  for (const scan of sortedScansForMttr) {
    const scanTime = new Date(scan.savedAt).getTime();
    const scanFindings = getConsolidatedFindingsForHistoryEntry(scan);
    const dedupedScanFindings = deduplicateByFingerprint(scanFindings);
    for (const finding of dedupedScanFindings) {
      const key = finding.fingerprint || finding.id;
      if (!key) continue;
      if (!firstSeen.has(key)) {
        firstSeen.set(key, scanTime);
      }
    }
  }

  // Also seed with current findings
  for (const finding of currentFindings) {
    const key = finding.fingerprint || finding.id;
    if (!key) continue;
    if (!firstSeen.has(key)) {
      firstSeen.set(key, Date.now());
    }
  }

  const lastSeenScanIndexMap = new Map();
  for (let i = 0; i < sortedScansForMttr.length; i++) {
    const scan = sortedScansForMttr[i];
    const scanFindings = getConsolidatedFindingsForHistoryEntry(scan);
    const dedupedScanFindings = deduplicateByFingerprint(scanFindings);
    for (const finding of dedupedScanFindings) {
      const key = finding.fingerprint || finding.id;
      if (!key) continue;
      lastSeenScanIndexMap.set(key, i);
    }
  }

  const getFindingResolutionTime = (finding, scans) => {
    if (finding.validatedAt) {
      const t = Date.parse(finding.validatedAt);
      if (Number.isFinite(t)) return t;
    }
    if (finding.fixedAt) {
      const t = Date.parse(finding.fixedAt);
      if (Number.isFinite(t)) return t;
    }
    const key = finding.fingerprint || finding.id;
    const lastSeenScanIdx = lastSeenScanIndexMap.get(key);
    if (lastSeenScanIdx !== undefined) {
      for (let i = lastSeenScanIdx + 1; i < scans.length; i++) {
        const scanAfter = scans[i];
        const scanner = (scanAfter.scanners || []).find(s => s.tool === finding.tool);
        if (scanner && scanner.status === 'completed') {
          const scanFindings = getConsolidatedFindingsForHistoryEntry(scanAfter);
          const isAbsent = !scanFindings.some(f => (f.fingerprint || f.id) === key);
          if (isAbsent) {
            const t = Date.parse(scanAfter.savedAt);
            if (Number.isFinite(t)) return t;
          }
        }
      }
    }
    return null;
  };

  const allFindingsMap = new Map();
  // Gather from history
  for (const scan of sortedScansForMttr) {
    const scanFindings = getConsolidatedFindingsForHistoryEntry(scan);
    const dedupedScanFindings = deduplicateByFingerprint(scanFindings);
    for (const finding of dedupedScanFindings) {
      const key = finding.fingerprint || finding.id;
      if (!key) continue;
      allFindingsMap.set(key, finding);
    }
  }
  // Gather from current findings
  for (const finding of currentFindings) {
    const key = finding.fingerprint || finding.id;
    if (!key) continue;
    allFindingsMap.set(key, finding);
  }

  const resolvedKeys = new Set();
  const durations = [];
  const isResolvedStatus = (status) => ['fixed', 'validated'].includes(status);

  const isAbsentInCurrentForCompletedScanner = (key, tool) => {
    const scanner = model.scanners.find(s => s.tool === tool);
    if (scanner && scanner.status === 'completed') {
      const isAbsent = !currentFindings.some(f => (f.fingerprint || f.id) === key);
      return isAbsent;
    }
    return false;
  };

  const hasDisappearedInHistory = (key, tool) => {
    const lastSeenIdx = lastSeenScanIndexMap.get(key);
    if (lastSeenIdx !== undefined) {
      for (let i = lastSeenIdx + 1; i < sortedScansForMttr.length; i++) {
        const scanAfter = sortedScansForMttr[i];
        const scanner = (scanAfter.scanners || []).find(s => s.tool === tool);
        if (scanner && scanner.status === 'completed') {
          const scanFindings = getConsolidatedFindingsForHistoryEntry(scanAfter);
          const isAbsent = !scanFindings.some(f => (f.fingerprint || f.id) === key);
          if (isAbsent) return true;
        }
      }
    }
    return false;
  };

  for (const [key, finding] of allFindingsMap.entries()) {
    const disappearedInHistory = hasDisappearedInHistory(key, finding.tool);
    const disappearedInCurrent = isAbsentInCurrentForCompletedScanner(key, finding.tool);
    const isResolved = isResolvedStatus(finding.triageStatus) || disappearedInHistory || disappearedInCurrent;
    
    if (isResolved && !resolvedKeys.has(key)) {
      const firstTime = firstSeen.get(key);
      if (firstTime) {
        let resolveTime = null;
        if (finding.validatedAt) {
          const t = Date.parse(finding.validatedAt);
          if (Number.isFinite(t)) resolveTime = t;
        }
        if (resolveTime === null && finding.fixedAt) {
          const t = Date.parse(finding.fixedAt);
          if (Number.isFinite(t)) resolveTime = t;
        }
        if (resolveTime === null) {
          if (disappearedInHistory) {
            resolveTime = getFindingResolutionTime(finding, sortedScansForMttr);
          } else if (disappearedInCurrent) {
            resolveTime = Date.now();
          }
        }

        if (resolveTime !== null && resolveTime >= firstTime) {
          durations.push(resolveTime - firstTime);
          resolvedKeys.add(key);
        }
      }
    }
  }

  let mttrTop = '—';
  let mttrBottom = 'Aucune correction validée';
  if (durations.length > 0) {
    const averageMs = durations.reduce((sum, val) => sum + val, 0) / durations.length;
    const totalMinutes = Math.round(averageMs / (1000 * 60));
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    mttrTop = hours ? `${hours} h ${minutes} min` : `${minutes} min`;
    mttrBottom = 'findings validés';
  }

  const trendLabel = trendTop;
  const mttrLabel = mttrTop;
  const prioritySummary = {
    critical: severityCount(currentActiveFindings, ['CRITICAL', 'ERROR']),
    high: severityCount(currentActiveFindings, ['HIGH']),
    medium: severityCount(currentActiveFindings, ['MEDIUM', 'WARNING']),
    low: severityCount(currentActiveFindings, ['LOW', 'INFO', 'INFORMATION'])
  };
  const recentScanRows = historyEntries.slice(0, 3).map((entry) => {
    const status = String(entry.dashboardOptions?.scanStatus || 'unknown');
    const date = new Date(entry.savedAt).toLocaleString('fr-FR');
    return `<div class="recent-scan"><span class="recent-state ${semanticClass(status)}"></span><strong>${escapeHtml(entry.dashboardOptions?.executionType === 'incremental' ? 'Scan rapide' : 'Scan')}</strong><time>${escapeHtml(date)}</time><span class="recent-status">${escapeHtml(status)}</span></div>`;
  }).join('') || '<div class="empty">Aucune analyse enregistrée.</div>';
  const burpScenarios = model.httpScenarios.filter((scenario) => scenario.source === 'burp');
  const trafficScenarios = model.httpScenarios.slice(0, 250);
  const trafficRows = trafficScenarios.length
    ? trafficScenarios.map((scenario, index) => {
      const method = String(scenario.request?.method || 'HTTP').toUpperCase();
      const url = String(scenario.request?.url || '');
      let endpoint = url;
      try { const parsed = new URL(url); endpoint = `${parsed.pathname || '/'}${parsed.search || ''}`; } catch { /* URL déjà partielle */ }
      const statusCode = Number(scenario.response?.statusCode || scenario.response?.status || 0);
      const source = String(scenario.source || 'capture').toUpperCase();
      const linked = linkedFindingsForScenario(scenario, model.findings);
      const sensitiveHeaders = (scenario.request?.sensitive_headers || []).map((header) => String(header).toLowerCase());
      const authenticated = sensitiveHeaders.some((header) => ['authorization', 'cookie', 'proxy-authorization', 'x-api-key'].includes(header))
        || (scenario.tags || []).some((tag) => String(tag).toLowerCase() === 'authenticated');
      const timestampValue = scenario.timestamp || scenario.capturedAt || scenario.startedDateTime || scenario.createdAt || '';
      const timestamp = timestampValue ? new Date(timestampValue).toLocaleString('fr-FR') : 'Not available';
      const search = `${method} ${endpoint} ${source} ${statusCode}`.toLowerCase();
      return `<button class="traffic-row" data-traffic-index="${index}" data-method="${escapeHtml(method)}" data-authenticated="${authenticated}" data-findings="${linked.length}" data-search="${escapeHtml(search)}" data-endpoint="${escapeHtml(endpoint)}" data-status="${statusCode || '—'}" data-source="${escapeHtml(source)}" data-timestamp="${escapeHtml(timestamp)}">
        <span class="method">${escapeHtml(method)}</span><strong>${escapeHtml(endpoint || '/')}</strong><span>${statusCode || '—'}</span><span>${escapeHtml(source)}</span><span>${linked.length}</span><time>${escapeHtml(timestamp)}</time>
      </button>`;
    }).join('')
    : '<div class="empty">Aucune requête Burp/HAR capturée.</div>';
  const inactiveStatuses = new Set(['false_positive', 'fixed', 'validated', 'accepted']);
  const dynamicFindings = model.findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => {
      const tool = String(finding.tool || '').toLowerCase();
      const context = String(finding.sourceContext || finding.context || '').toLowerCase();
      const source = String(finding.source || finding.evidenceSource || '').toLowerCase();
      return !inactiveStatuses.has(finding.triageStatus)
        && ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())
        && (tool === 'zap' || tool === 'burp' || context === 'runtime' || context === 'dynamic' || source.includes('replay'));
    })
    .sort((left, right) => {
      const rank = { CRITICAL: 0, ERROR: 0, HIGH: 1 };
      return (rank[String(left.finding.rawSeverity || left.finding.severity || '').toUpperCase()] ?? 2)
        - (rank[String(right.finding.rawSeverity || right.finding.severity || '').toUpperCase()] ?? 2);
    });
  const dynamicFindingRows = dynamicFindings
    .slice(0, 5)
    .map(({ finding, index }) => {
      const severity = String(finding.rawSeverity || finding.severity || 'HIGH').toUpperCase();
      const endpoint = finding.endpoint || finding.url || finding.route || finding.file || 'Endpoint non fourni';
      const method = finding.method ? `${String(finding.method).toUpperCase()} ` : '';
      const matchingBurpScenario = burpScenarios.find((scenario) => linkedFindingsForScenario(scenario, [finding]).length > 0);
      // Source attribution stays on V1 on purpose: it is keyed on the V1
      // `endpoint-source` type and on pairwise correlations. Switching it to V2
      // would silently downgrade every « Likely source » to « Possible source ».
      const correlations = model.legacyCorrelations.filter((correlation) => correlation.findingIds?.includes(finding.id));
      const sources = [...new Set([
        finding.tool,
        ...(finding.correlatedTools || []),
        ...correlations.flatMap((correlation) => correlation.tools || []),
        ...(matchingBurpScenario ? ['Burp'] : [])
      ].filter(Boolean))];
      const sourceLabel = sources.length > 1 ? sources.join(' + ') : sources[0] || 'Dynamic';
      const correlationLabel = sources.length > 1 ? `<span class="dynamic-correlation">${sources.length} sources</span>` : '';
      const status = finding.triageStatus || 'new';
      const sourceCorrelation = sourceCorrelationForFinding(finding, model.findings, model.legacyCorrelations);
      const sourceLocation = sourceCorrelation
        ? `${sourceCorrelation.finding.file || sourceCorrelation.finding.absolutePath}${sourceCorrelation.finding.startLine ? `:${sourceCorrelation.finding.startLine}` : ''}`
        : '';
      const sourceEvidence = sourceCorrelation ? `<div class="dynamic-source ${sourceCorrelation.confidence}"><span>${sourceCorrelation.label}</span><code>${escapeHtml(sourceLocation)}</code><button class="quiet-action" data-finding-code-index="${sourceCorrelation.index}">Ouvrir le code</button></div>` : '';
      return `<article class="dynamic-finding-row">
        <span class="dynamic-severity ${semanticClass(severity)}">${escapeHtml(severity)}</span>
        <div class="dynamic-finding-copy"><strong>${escapeHtml(finding.title || finding.ruleId || 'Alerte dynamique')}</strong><small>${escapeHtml(method + endpoint)}</small><span>${escapeHtml(sourceLabel)}${correlationLabel}</span>${sourceEvidence}</div>
        <span class="triage-badge">${escapeHtml(statusLabels[status] || status)}</span>
        <button class="quiet-action" data-finding-index="${index}">Investigate</button>
      </article>`;
    })
    .join('') || '<div class="empty">Aucun finding dynamique HIGH ou CRITICAL actif.</div>';
  const recentDynamicRows = model.httpScenarios.slice(0, 8).map((scenario) => `<div class="dynamic-row"><div><strong>${escapeHtml(scenario.name || `${scenario.request?.method || 'HTTP'} ${endpointPath(scenario.request?.url)}`)}</strong><small>${escapeHtml(scenario.request?.method || 'HTTP')} • ${escapeHtml(scenario.request?.url || 'URL non fournie')} • ${escapeHtml(scenario.source || 'capture')}</small></div></div>`).join('') || '<div class="empty">Aucun test dynamique récent.</div>';
  const scannerRows = model.scanners.length
    ? model.scanners.map((scanner) => {
      const count = currentScannerResultCount(scanner, currentFindings);
      const duration = scanner.status === 'completed' && scanner.durationMs ? formatDuration(scanner.durationMs) : '—';
      const completedAt = scanner.completedAt ? new Date(scanner.completedAt).toLocaleString('fr-FR') : '—';
      const resultSummary = scannerResultSummary(scanner, currentFindings);
      const failedActions = scanner.status === 'failed'
        ? `<div class="scan-row-actions"><button class="secondary" data-retry-scanner="${escapeHtml(scanner.tool)}">Retry</button><button class="secondary" data-command="securityCenter.openScannerSetup">Configure</button></div>`
        : '';
      const details = scanner.status === 'failed' && scanner.error
        ? `<small class="scan-row-error">${escapeHtml(summarizeScannerError(scanner.error))}</small>`
        : scanner.details
          ? `<small>${escapeHtml(scanner.details)}</small>`
          : '';
      return `<article class="scanner scan-scanner-row overview-scanner ${escapeHtml(scanner.status)}" data-scanner-id="${escapeHtml(scannerId(scanner.tool))}">
        ${renderScannerLogo(scanner.tool, scanner.status)}
        <div class="scanner-identity"><strong>${escapeHtml(scannerPresentation(scanner.tool).label)}</strong><small>${escapeHtml(scannerCategoryLabel(scanner.tool))}</small>${details}</div>
        <span class="scanner-result-summary ${escapeHtml(scanner.status)}">${escapeHtml(resultSummary)}</span>
        <span class="scanner-value"><strong>${count === null ? '—' : count}</strong><small>current run</small></span>
        <span class="scanner-value"><strong>${escapeHtml(duration)}</strong><small>duration</small></span>
        <time>${escapeHtml(completedAt)}</time>
        <span class="scan-status-chip ${escapeHtml(scanner.status)}">${escapeHtml(scannerStatusLabel(scanner.status))}</span>
        ${failedActions}
        <button class="scanner-chevron" data-scanner-id="${escapeHtml(scannerId(scanner.tool))}" data-scanner="${escapeHtml(scanner.tool)}" aria-label="Voir les détails de ${escapeHtml(scanner.tool)}">›</button>
      </article>`;
    }).join('')
    : '<div class="empty">Aucun scanner exécuté</div>';
  const disabledScannerRows = model.disabledScanners.map((tool) => `<article class="scanner scan-scanner-row overview-scanner disabled" data-scanner-id="${escapeHtml(scannerId(tool))}">
        ${renderScannerLogo(tool, 'disabled')}
        <div class="scanner-identity"><strong>${escapeHtml(scannerPresentation(tool).label)}</strong><small>${escapeHtml(scannerCategoryLabel(tool))}</small><small>Désactivé · Non inclus dans cette analyse</small></div>
        <span class="scanner-result-summary disabled">No current execution</span>
        <span class="scanner-value"><strong>—</strong><small>current run</small></span>
        <span class="scanner-value"><strong>—</strong><small>duration</small></span>
        <time>—</time>
        <span class="scan-status-chip disabled">NOT CONFIGURED</span>
        <button class="scanner-chevron" data-command="securityCenter.openScannerSetup" data-scanner-id="${escapeHtml(scannerId(tool))}" aria-label="Configurer ${escapeHtml(tool)}">›</button>
      </article>`).join('');
  const overviewScannerRows = model.scanners.length
    ? model.scanners.map((scanner) => {
      const scannerRunFindings = Array.isArray(scanner.currentRun?.findings) ? scanner.currentRun.findings : [];
      const count = scanner.status === 'completed'
        ? Number(scanner.currentRun?.resultCount ?? currentFindings.filter((finding) => finding.tool === scanner.tool).length)
        : null;
      const presentation = scannerPresentation(scanner.tool);
      const description = presentation.description;
      const completedAt = scanner.completedAt ? new Date(scanner.completedAt).toLocaleString('fr-FR') : '—';
      const duration = scanner.status === 'completed' && scanner.durationMs ? formatDuration(scanner.durationMs) : '—';
      const statusLabel = scanner.status === 'completed' ? 'Prêt' : scanner.status === 'running' || scanner.status === 'refreshing' ? 'En cours' : scanner.status === 'failed' ? 'Échec' : 'En attente';
      return `<div class="overview-scanner">
        ${renderScannerLogo(scanner.tool, scanner.status)}
        <div class="scanner-identity"><strong>${escapeHtml(scanner.tool)}</strong><small>${escapeHtml(description)}</small></div>
        <span class="scanner-ready ${escapeHtml(scanner.status)}">${escapeHtml(statusLabel)}</span>
        <span class="scanner-value"><strong>${count === null ? '—' : count}</strong><small>alertes${scannerRunFindings.length && scanner.status === 'completed' ? ' run' : ''}</small></span>
        <span class="scanner-value"><strong>${escapeHtml(duration)}</strong><small>durée</small></span>
        <time>${escapeHtml(completedAt)}</time>
        <button class="scanner-chevron" data-scanner-id="${escapeHtml(scannerId(scanner.tool))}" data-scanner="${escapeHtml(scanner.tool)}" aria-label="Voir les détails de ${escapeHtml(scanner.tool)}">›</button>
      </div>`;
    }).join('')
    : '<div class="empty">Aucun scanner exécuté.</div>';
  // No finding count and no duration: these scanners never ran.
  const overviewDisabledRows = model.disabledScanners.map((tool) => {
    const presentation = scannerPresentation(tool);
    const description = presentation.description;
    return `<div class="overview-scanner disabled">
        ${renderScannerLogo(tool, 'disabled')}
        <div class="scanner-identity"><strong>${escapeHtml(tool)}</strong><small>${escapeHtml(description)}</small></div>
        <span class="scanner-ready disabled">Désactivé</span>
        <span class="scanner-value"><strong>—</strong><small>alertes</small></span>
        <span class="scanner-value"><strong>—</strong><small>durée</small></span>
        <time>—</time>
        <button class="scanner-chevron" data-command="securityCenter.openScannerSetup" data-scanner-id="${escapeHtml(scannerId(tool))}" aria-label="Configurer ${escapeHtml(tool)}">›</button>
      </div>`;
  }).join('');
  const correlationRows = model.correlations.length
    ? model.correlations.map((correlation) => `<div class="correlation">
        <strong>${escapeHtml(correlation.title)}</strong>
        <span>${escapeHtml(correlation.tools.join(' + '))} • confiance ${escapeHtml(correlation.confidence)}</span>
        <small>${escapeHtml(Array.isArray(correlation.reasons) ? correlation.reasons.join(' · ') : correlation.reason)}</small>
      </div>`).join('')
    : '<div class="empty">Aucune correspondance multi-outils</div>';
  const terminalStatuses = ['completed', 'partial', 'cancelled', 'failed'];
  const statusClass = model.scanStatus === 'completed' ? 'completed' : ['failed', 'cancelled', 'partial'].includes(model.scanStatus) ? 'failed' : 'running';
  const scanRunning = model.scanStatus !== 'idle' && !terminalStatuses.includes(model.scanStatus);
  const hasScanned = model.scanners.length > 0 || model.total > 0 || terminalStatuses.includes(model.scanStatus);
  const finishedCount = Number.isFinite(Number(model.finishedScanners))
    ? Number(model.finishedScanners)
    : model.scanners.filter(isTerminalScannerStatus).length;
  const successfulCount = Number.isFinite(Number(model.successfulScanners))
    ? Number(model.successfulScanners)
    : model.scanners.filter((scanner) => scanner.status === 'completed').length;
  const failedTools = model.scanners.filter((scanner) => scanner.status === 'failed').map((scanner) => scanner.tool);
  const failedScanners = model.scanners.filter((scanner) => scanner.status === 'failed');
  const cancelledTools = model.scanners.filter((scanner) => scanner.status === 'cancelled').map((scanner) => scanner.tool);
  const scanStatusLabel = model.scanStatus === 'cancelled'
    ? `Scan partiel — ${finishedCount}/${model.scanners.length} scanners terminés${cancelledTools.length ? ` — ${cancelledTools.join(', ')} annulé${cancelledTools.length > 1 ? 's' : ''}` : ''}`
    : model.scanStatus === 'partial' ? `Scan partiel — ${finishedCount}/${model.scanners.length} scanners terminés${failedScanners.length ? ` — ${successfulCount}/${model.scanners.length} réussis` : ''}` : model.scanStatus;
  const scanLabel = scanRunning ? 'Analyse en cours…' : hasScanned ? '↻ Relancer' : '▶ Lancer';
  const fullHeaderAction = surface === 'full'
    ? `<button class="header-scan" data-command="securityCenter.scanWorkspace" ${scanRunning ? 'disabled' : ''}>${scanLabel}</button>`
    : '';
  const policyBanner = scanResultsTrusted && model.policyResult
    ? `<div class="policy-banner ${model.policyResult.passed ? 'pass' : 'fail'}"><strong>${model.policyResult.passed ? 'Politique projet respectée' : 'Politique projet non respectée'}</strong><span>${escapeHtml(model.policyResult.passed ? `${model.policyResult.activeCount} alerte(s) comptée(s), aucun critère bloquant.${model.policyResult.ignoredByToolThreshold ? ` ${model.policyResult.ignoredByToolThreshold} alerte(s) visible(s) sous le seuil propre à leur outil.` : ''}` : model.policyResult.reasons.join(' ; '))}</span></div>`
    : '';
  const criticalCount = currentCriticalCount;
  const highCount = currentHighCount;
  const newCount = currentNewCount;
  const fixAppliedCount = remediation.fixApplied;
  const validatedCount = remediation.validated;
  const acceptedCount = currentAcceptedCount;
  const operationalState = failedTools.length || (scanResultsTrusted && model.policyResult?.passed === false) ? 'danger' : model.scanStatus === 'completed' ? 'success' : 'neutral';
  const operationalTitle = failedTools.length
    ? `Scan partiel — ${failedTools.join(', ')} en échec`
    : scanResultsTrusted && model.policyResult?.passed === false ? 'Livraison bloquée par la politique de sécurité' : model.scanStatus === 'completed' ? 'Analyse terminée' : 'État de l’analyse';
  const operationalDetails = [criticalCount ? `${criticalCount} alerte(s) critique(s)` : '', `${currentProductionPriority} priorité(s) production`, scanResultsTrusted && model.policyResult?.passed === false ? 'Politique non respectée' : scanResultsTrusted && model.policyResult?.passed === true ? 'Politique respectée' : ''].filter(Boolean).join(' • ');
  // A presence, not a widget: a small floating mascot in the corner, on every
  // page surface that has room for one. It consumes the very same shared model
  // the Live Security page renders — the dashboard computes no companion state,
  // no message and no count.
  //
  // It floats rather than sitting inside `.operational-banner`: that banner is
  // hidden by `body.surface-full > .operational-banner`, so a companion placed
  // inside it would have been invisible on the full dashboard. The sidebar keeps
  // none — it is a narrow strip and the tree below it needs the space.
  const COMPANION_SURFACES = ['full', 'findings', 'scans', 'dynamic', 'analytics'];
  // Une seule mascotte par surface. La carte d'assistant du rail porte desormais
  // le personnage sur les pages ou elle s'affiche ; le widget flottant n'y est
  // donc plus dessine. Il reste la presence par defaut partout ou la carte n'a
  // aucun fait reel a rapporter. `assistantCard` est calcule plus bas, avec le
  // reste du rail : cette variable est resolue apres lui.
  const companionWidgetFor = (assistantCard) => (COMPANION_SURFACES.includes(surface) && !assistantCard
    ? renderCompanionWidget(model.companion, { variant: 'compact', enabled: model.companionEnabled !== false, interactive: true })
    : '');
  const failureDiagnostics = surface === 'full' && failedScanners.length
    ? `<section class="failure-diagnostics"><div><span class="failure-kicker">⚠ Scan incomplet</span><strong>${finishedCount}/${model.scanners.length} scanners terminés · ${successfulCount}/${model.scanners.length} réussis</strong><p>${failedScanners.map((scanner) => `${escapeHtml(scanner.tool)} : ${escapeHtml(summarizeScannerError(scanner.error))}`).join(' • ')}</p></div><div class="failure-actions"><button class="secondary" data-command="securityCenter.scanSelected">Réessayer</button><button class="quiet-action" data-command="securityCenter.showLogs">Journal →</button></div></section>`
    : '';
  const currentRiskScore = calculateRiskScore(currentActiveFindings);
  const displayedRiskScore = resultsAvailable ? currentRiskScore : 0;
  const displayedRiskLevel = currentExecutionActive
    ? (completedCurrentRunFindings.length ? `${riskLevel(currentRiskScore)} (run partiel)` : 'en recalcul')
    : scanRunning && !model.snapshotAvailable ? 'en recalcul' : partialResultsAvailable && !model.snapshotAvailable ? `${riskLevel(currentRiskScore)} (partiel)` : scanResultsTrusted ? riskLevel(currentRiskScore) : 'non évalué';
  const riskExplanation = currentExecutionActive
    ? (currentActiveFindings.length
      ? 'Score partiel calculé uniquement avec les scanners déjà terminés dans le run courant.'
      : 'Run courant en attente du premier scanner terminé : aucun ancien résultat n’est compté ici.')
    : scanRunning && model.snapshotAvailable
      ? `La posture workspace reste visible depuis le snapshot consolidé pendant l’actualisation ${escapeHtml(model.executionType || 'partielle')}.`
      : scanRunning
        ? 'Calcul en attente du premier résultat exploitable.'
        : partialResultsAvailable
          ? `Score partiel calculé uniquement avec ${completedTools.size} scanner(s) terminé(s). Un outil en échec n’est jamais interprété comme zéro alerte.`
          : scanResultsTrusted
            ? 'Score calculé à partir des résultats valides les plus récents de chaque scanner.'
            : 'Aucun scanner n’a terminé avec des résultats exploitables. Le risque courant ne peut pas être évalué.';
  const activeFindingsCardLabel = currentExecutionActive ? 'Alertes actives du run' : 'Alertes actives';
  const scanResultsCardLabel = currentExecutionActive ? 'Résultats du run courant' : 'Résultats du scan';
  const riskClass = displayedRiskScore >= 80 ? 'critical' : displayedRiskScore >= 55 ? 'high' : displayedRiskScore >= 25 ? 'medium' : 'low';
  const zapScanner = model.scanners.find((scanner) => scanner.tool === 'ZAP');
  const zapPolicy = model.policyResult?.policy;
  const effectiveZapMode = zapScanner?.mode || (zapPolicy?.zapOpenapi ? 'openapi' : zapPolicy?.zapActive ? 'active' : 'baseline');
  const zapMode = effectiveZapMode === 'openapi' ? 'OpenAPI actif' : effectiveZapMode === 'active' ? 'Actif' : 'Passif baseline';
  const zapAuthenticated = zapScanner?.authenticated ?? Boolean(zapPolicy?.zapAuth?.login || zapPolicy?.zapContext);
  const zapAuth = zapAuthenticated ? 'Authentifié' : 'Non authentifié';
  const zapAuthenticationFailed = zapScanner?.status === 'failed'
    && /authentification|login.*(?:refus|401)|http\s*401/i.test(String(zapScanner?.error || ''));
  const zapFindingCount = model.findings.filter((finding) => finding.tool === 'ZAP').length;
  const zapTestedUrls = new Set(model.findings.filter((finding) => finding.tool === 'ZAP' && finding.endpoint).map((finding) => finding.endpoint)).size;
  const burpUniqueEndpoints = new Set(burpScenarios.map((scenario) => endpointPath(scenario.request?.url))).size;
  const burpLinkedFindings = new Set(burpScenarios.flatMap((scenario) => linkedFindingsForScenario(scenario, model.findings))).size;
  const burpLastSeen = model.burpStatus.last_seen ? new Date(model.burpStatus.last_seen).toLocaleString('fr-FR') : 'Not available';
  const burpStoredRequests = Number.isFinite(Number(model.burpStatus.received_requests)) ? Number(model.burpStatus.received_requests) : burpScenarios.length;
  const zapState = !zapScanner ? 'jamais exécuté' : zapScanner.status;
  const targetUrl = model.dynamicTargetUrl || model.findings.find((finding) => finding.tool === 'ZAP' && finding.endpoint)?.endpoint || model.httpScenarios.find((scenario) => scenario.request?.url)?.request?.url || '';
  let targetOrigin = '';
  try { targetOrigin = new URL(targetUrl).origin; } catch { targetOrigin = targetUrl; }
  const targetState = model.dynamicTargetState || 'unknown';
  const targetStatus = targetState === 'online' ? '● En ligne' : targetState === 'unreachable' ? '⚠ Cible inaccessible' : 'Inconnue / non vérifiée';
  // The badge says how it knows. « En ligne » with no evidence would be a claim
  // without a source, and « non vérifiée » beside a finished scan was a
  // contradiction.
  const targetEvidence = model.dynamicTargetEvidence;
  const targetEvidenceLabel = targetEvidence
    ? `${targetEvidence.source === 'zap-scan' ? 'Confirmée par l’analyse ZAP' : 'Vérifiée directement'} le ${new Date(targetEvidence.at).toLocaleString('fr-FR')}`
    : '';
  const zapCurrentCount = currentScannerResultCount(zapScanner, currentFindings);
  const zapDuration = zapScanner?.durationMs ? formatDuration(zapScanner.durationMs) : '';
  const zapLastScan = zapScanner?.completedAt ? new Date(zapScanner.completedAt).toLocaleString('fr-FR') : '';
  const zapCard = surface === 'scans'
    ? `<section class="zap-card zap-execution-card ${escapeHtml(zapScanner?.status || 'idle')}">
      <div class="zap-execution-head">
        <span class="zap-kicker">Dynamic Security</span>
        <div class="zap-title-row">${renderScannerLogo('ZAP', zapScanner?.status || 'pending')}<div><h4>ZAP</h4><p>${escapeHtml(zapMode)}</p></div></div>
      </div>
      <div class="zap-execution-grid">
        <div class="zap-execution-fact"><span>Findings</span><strong>${zapCurrentCount === null ? '—' : escapeHtml(zapCurrentCount)}</strong><small>${zapScanner?.status === 'completed' ? 'current run' : escapeHtml(scannerResultSummary(zapScanner, currentFindings))}</small></div>
        <div class="zap-execution-fact"><span>Scan mode</span><strong>${escapeHtml(zapAuth)}</strong><small>${escapeHtml(zapMode)}</small></div>
        ${zapDuration ? `<div class="zap-execution-fact"><span>Last scan</span><strong>${escapeHtml(zapDuration)}</strong>${zapLastScan ? `<small>${escapeHtml(zapLastScan)}</small>` : ''}</div>` : ''}
        ${targetOrigin ? `<div class="zap-execution-fact target"><span>Target</span><strong>${escapeHtml(targetOrigin)}</strong>${targetEvidenceLabel ? `<small>${escapeHtml(targetEvidenceLabel)}</small>` : ''}</div>` : ''}
      </div>
      ${zapScanner?.error ? `<p class="zap-execution-error">${escapeHtml(summarizeScannerError(zapScanner.error))}</p>` : ''}
      <div class="zap-meta"><span class="scan-status-chip ${escapeHtml(zapScanner?.status || 'pending')}">${escapeHtml(scannerStatusLabel(zapScanner?.status || 'pending'))}</span><button class="secondary" data-command="securityCenter.scanZap">Relancer ZAP</button><button class="secondary" data-command="securityCenter.configureZapCredentials">Compte ZAP</button><button class="secondary" data-command="securityCenter.configureZap">Configurer</button></div>
    </section>`
    : `<section class="zap-card ${escapeHtml(zapScanner?.status || 'idle')}"><div><span class="zap-kicker">Analyse dynamique</span><h4>ZAP — ${escapeHtml(zapMode)}</h4><p>${escapeHtml(zapScanner?.error ? summarizeScannerError(zapScanner.error) : `${zapFindingCount} alerte(s) runtime • ${zapAuth}`)}</p></div><div class="zap-meta"><span class="status ${escapeHtml(zapScanner?.status || 'pending')}">${escapeHtml(zapState)}</span><button class="secondary" data-command="securityCenter.scanZap">Relancer ZAP uniquement</button><button class="secondary" data-command="securityCenter.configureZapCredentials">Compte ZAP</button><button class="secondary" data-command="securityCenter.configureZap">Installer / configurer ZAP</button></div></section>`;
  const scanSuccessCount = model.scanners.filter((scanner) => scanner.status === 'completed').length;
  const scanWaitingCount = model.scanners.filter((scanner) => ['pending', 'running', 'refreshing'].includes(scanner.status)).length;
  const scansCurrentFindingTotal = model.scanners.reduce((sum, scanner) => {
    const count = currentScannerResultCount(scanner, currentFindings);
    return count === null ? sum : sum + count;
  }, 0);
  const scansExecutionSummary = surface === 'scans'
    ? `<section class="scan-execution-summary" aria-label="Résumé d'exécution des scanners">
        <div class="scan-summary-copy"><span>Execution and scanner health</span><strong>${escapeHtml(finishedCount)}/${escapeHtml(model.scanners.length)} scanners terminés</strong></div>
        <div class="scan-summary-metrics">
          <div class="scan-summary-stat success"><span>Successful</span><strong>${scanSuccessCount}</strong></div>
          <div class="scan-summary-stat failed"><span>Failed</span><strong>${failedScanners.length}</strong></div>
          <div class="scan-summary-stat waiting"><span>Waiting</span><strong>${scanWaitingCount}</strong></div>
          <div class="scan-summary-stat total"><span>Total findings</span><strong>${scansCurrentFindingTotal}</strong></div>
          <div class="scan-summary-stat dynamic"><span>Dynamic</span><strong>${zapCurrentCount === null ? '—' : zapCurrentCount}</strong></div>
        </div>
      </section>`
    : '';
  // Le chrono et le bouton de theme existent en un seul exemplaire dans le
  // document : les deux en-tetes se les partagent, jamais ne les dupliquent.
  const initialThemeIcon = selectedTheme === 'dark' ? '☀' : '☾';
  const initialThemeLabel = selectedTheme === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre';
  const themeToggleButton = `<button id="theme-toggle" class="theme-toggle" title="${initialThemeLabel}" aria-label="${initialThemeLabel}"><span class="theme-toggle-icon" aria-hidden="true">${initialThemeIcon}</span></button>`;
  const scanChronoBadge = scanRunning
    ? `<span id="scan-chrono" class="scan-chrono" data-started-at="${escapeHtml(model.scanStartedAt)}" data-elapsed="${model.scanDurationMs}">◷ ${escapeHtml(formatDuration(model.scanDurationMs))}</span>`
    : '';
  const backendTone = model.backendStatus === 'online' ? 'online' : ['offline', 'error', 'unreachable'].includes(String(model.backendStatus)) ? 'offline' : 'unknown';
  // Le dashboard complet porte deja son nom dans la barre laterale interne : le
  // haut de page nomme la vue, pas le produit. Les autres surfaces gardent leur
  // en-tete d'origine, inchange.
  // Une seule barre superieure pour toutes les pages hebergees. Le nom du
  // produit vit dans le rail de navigation : le repeter au-dessus de chaque page
  // etait le signe visuel que l'on venait d'ouvrir une autre application.
  const [surfaceTitle, surfaceSubtitle] = SURFACE_TITLES[surface] || ['Security Center', ''];
  const shellSubtitle = surface === 'full'
    ? `Vue de sécurité du workspace <span class="sc-topbar-workspace">${escapeHtml(model.workspace)}</span>`
    : surface === 'scanner-details' && model.activeScanner
      ? escapeHtml(String(model.activeScanner))
      : escapeHtml(surfaceSubtitle);
  const headerBar = inShell
    ? `<header class="sc-topbar">
      <div class="sc-topbar-title"><h1>${escapeHtml(surfaceTitle)}</h1><p>${shellSubtitle}</p></div>
      <div class="header-actions">${themeToggleButton}${scanChronoBadge}${fullHeaderAction}<div class="header-status"><span class="status-pill ${statusClass}">${escapeHtml(scanStatusLabel)}</span><span class="backend ${backendTone}">Backend ${escapeHtml(model.backendStatus)}</span></div></div>
    </header>`
    : `<div class="header"><div><h2>Security Center</h2><div class="workspace">${escapeHtml(model.workspace)}</div></div><div class="header-actions">${themeToggleButton}${scanChronoBadge}${fullHeaderAction}<div class="header-status"><span class="status-pill ${statusClass}">${escapeHtml(scanStatusLabel)}</span><span class="backend">Backend ${escapeHtml(model.backendStatus)}</span></div></div></div>`;

  // Zones les plus exposees : un regroupement de `currentActiveFindings`, la
  // liste que la page affiche deja. Aucune analyse supplementaire.
  const riskyTargets = topRiskyTargets(currentActiveFindings);
  const riskyTargetRows = riskyTargets.length
    ? riskyTargets.map((entry) => `<div class="risky-target"><span class="risky-dot ${severityTone(entry.severity)}"></span><div class="risky-copy"><strong>${escapeHtml(targetLabel(entry.target))}</strong><small>${escapeHtml(entry.target)}</small></div><span class="risky-severity ${severityTone(entry.severity)}">${escapeHtml(entry.severity || '—')}</span><span class="risky-count">${entry.count}</span></div>`).join('')
    : `<div class="empty">${resultsAvailable ? 'Aucune alerte active rattachée à un fichier ou un endpoint.' : 'Les zones exposées apparaîtront après un premier scanner terminé.'}</div>`;

  const overviewTripleRow = `<div class="overview-triple">
    <section class="overview-panel"><div class="overview-panel-head"><strong>Alertes par sévérité</strong><button data-command="securityCenter.openFindingsPage">Voir tout →</button></div>${renderSeverityDonut(prioritySummary)}</section>
    <section class="overview-panel"><div class="overview-panel-head"><strong>Dernières analyses</strong><button data-command="securityCenter.showScanHistoryPage">Voir tout l'historique →</button></div><div class="recent-scans">${recentScanRows}</div></section>
    <section class="overview-panel"><div class="overview-panel-head"><strong>Zones les plus exposées</strong><button data-command="securityCenter.openFindingsPage">Findings →</button></div><div class="risky-targets">${riskyTargetRows}</div></section>
  </div>`;

  const enterprise = model.enterprise && typeof model.enterprise === 'object' ? model.enterprise : null;
  const enterpriseTone = (status) => {
    const value = String(status || '').toLowerCase();
    if (['healthy', 'online', 'success'].includes(value)) return 'ok';
    if (['degraded', 'query-error', 'timeout', 'running', 'unstable'].includes(value)) return 'warn';
    if (['offline', 'auth-error', 'error', 'failed'].includes(value)) return 'bad';
    return 'muted';
  };
  const delivery = enterprise?.delivery || {};
  const prometheus = enterprise?.prometheus || {};
  const runtime = enterprise?.runtime || {};
  const deliveryState = delivery.state === 'SUCCESS' ? 'success' : delivery.state === 'ERROR' || delivery.state === 'FAILED' ? 'error' : delivery.configured ? 'degraded' : 'not-configured';
  const COMPANION_STATE_LABELS = { idle: 'En veille', analyzing: 'Analyse en cours', clean: 'Aucun problème', findings: 'Problèmes détectés', degraded: 'Mode réduit', disabled: 'Désactivé', error: 'Erreur' };
  const companionVisual = model.companionEnabled === false ? null : model.companion;
  const companionStateLabel = model.companionEnabled === false ? 'Disabled' : model.companion ? (COMPANION_STATE_LABELS[model.companion.state] || String(model.companion.state || 'Active')) : 'Not reporting';
  const appTone = criticalCount || highCount ? 'bad' : model.total ? 'warn' : 'ok';
  const appState = criticalCount ? 'At risk' : highCount ? 'Attention' : model.total ? 'Review' : 'Healthy';
  const deliveryLabel = delivery.configured
    ? (delivery.build?.number ? `Jenkins build #${delivery.build.number} · ${delivery.state}` : `Jenkins · ${delivery.state || 'Connected'}`)
    : 'Jenkins not configured';
  const infrastructureLabel = prometheus.configured
    ? `Prometheus · CPU ${prometheus.metrics?.cpu?.display || 'Unavailable'} · RAM ${prometheus.metrics?.memory?.display || 'Unavailable'}`
    : 'Connect observability';
  const runtimeLabel = runtime.configured
    ? `${runtime.label || 'SIEM'} · ${runtime.alertSummary?.critical || 0} Critical · ${runtime.alertSummary?.high || 0} High`
    : 'Connect a SIEM provider';
  const companionTone = model.companionEnabled === false ? 'muted' : model.companion?.state === 'error' ? 'bad' : model.companion?.state === 'degraded' ? 'warn' : 'ok';
  const domainCard = ({ title, icon, tone, status, metric, detail, command, action }) => `<article class="domain-card ${escapeHtml(tone)}">
    <div class="domain-card-head"><span class="domain-icon">${compactIcon(icon)}</span><strong><i class="enterprise-dot ${escapeHtml(tone)}"></i>${escapeHtml(status)}</strong></div>
    <div class="domain-card-body"><span>${escapeHtml(title)}</span><strong>${escapeHtml(metric)}</strong><p>${escapeHtml(detail)}</p></div>
    <button class="domain-cta" data-command="${escapeHtml(command)}">${escapeHtml(action)} →</button>
  </article>`;
  const enterpriseSummary = `<section class="overview-panel enterprise-summary">
    <div class="overview-panel-head"><strong>Security Domains</strong><button data-command="securityCenter.configureTeamIntegrations">Manage providers →</button></div>
    <div class="enterprise-domain-grid">
      ${domainCard({ title: 'Application Security', icon: 'shield', tone: appTone, status: appState, metric: `${model.activeTotal} active findings`, detail: `${criticalCount} Critical · ${highCount} High`, command: 'securityCenter.openFindingsPage', action: 'View findings' })}
      ${domainCard({ title: 'Runtime Security', icon: 'pulse', tone: enterpriseTone(runtime.status), status: runtime.configured ? String(runtime.status || 'Configured') : 'Not configured', metric: runtime.configured ? (runtime.label || 'SIEM') : 'SIEM provider', detail: runtimeLabel, command: runtime.configured ? 'securityCenter.openRuntimeSecurity' : 'securityCenter.configureSiem', action: runtime.configured ? 'Open runtime' : 'Configure' })}
      ${domainCard({ title: 'Delivery Security', icon: 'play', tone: enterpriseTone(deliveryState), status: delivery.configured ? String(delivery.state || 'Connected') : 'Not configured', metric: 'Jenkins', detail: deliveryLabel, command: 'securityCenter.openSecurityDelivery', action: 'View delivery' })}
      ${domainCard({ title: 'Infrastructure', icon: 'cube', tone: enterpriseTone(prometheus.status), status: prometheus.configured ? String(prometheus.status || 'Configured') : 'Not configured', metric: prometheus.configured ? (prometheus.label || 'Observability') : 'Observability', detail: infrastructureLabel, command: prometheus.configured ? 'securityCenter.openInfrastructure' : 'securityCenter.configureObservability', action: prometheus.configured ? 'Open infrastructure' : 'Configure' })}
      ${domainCard({ title: 'AI Companion', icon: 'shield', tone: companionTone, status: companionStateLabel, metric: model.companionEnabled === false ? 'Disabled' : 'Active context', detail: companionVisual ? (companionVisual.shortMessage || 'Security context is available') : 'Open Live Security for context', command: 'securityCenter.openLiveSecurityPage', action: 'Open Companion' })}
    </div>
  </section>`;
  const severityHeroMetrics = [
    ['Critical', criticalCount, 'critical'],
    ['High', highCount, 'high'],
    ['Medium', prioritySummary.medium, 'medium'],
    ['Low', prioritySummary.low, 'low']
  ].map(([label, value, tone]) => `<div class="overview-kpi hero-metric ${tone}"><span class="hero-metric-label"><i class="hero-metric-dot ${tone}"></i>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  const scannerTotal = model.scanners.length;
  const scannerCoveragePercent = scannerTotal > 0 ? Math.round(model.completedScanners / scannerTotal * 100) : 0;
  const scannerCoverageLabel = scannerTotal > 0
    ? `${model.completedScanners} completed${failedTools.length ? ` · ${failedTools.length} failed` : ''}`
    : 'No scanners configured';
  const operationsHeroMetrics = `<div class="overview-kpi hero-metric production"><span class="hero-metric-label">${compactIcon('play')}Production</span><strong>${escapeHtml(currentProductionPriority)}</strong><small>priority findings</small></div>
    <div class="overview-kpi hero-metric scanners"><div class="scanner-coverage-head"><span class="hero-metric-label">${compactIcon('pulse')}Scanner coverage</span><b>${scannerCoveragePercent}%</b></div><strong>${escapeHtml(`${model.completedScanners} / ${scannerTotal}`)}</strong><div class="scanner-coverage-bar" aria-hidden="true"><span style="width: ${scannerCoveragePercent}%"></span></div><small>${escapeHtml(scannerCoverageLabel)}</small></div>`;
  const heroMetrics = `<div class="hero-metric-panel">
    <div class="posture-header"><span>Security posture</span><strong>${escapeHtml(model.activeTotal)} active</strong></div>
    <div class="hero-metric-group hero-severity-grid">${severityHeroMetrics}</div>
    <div class="hero-metric-group hero-operations-grid">${operationsHeroMetrics}</div>
  </div>`;
  const securityCenterHero = `<section class="overview-summary security-center-hero">
    <div class="security-hero-motif" aria-hidden="true">
      <span></span><span></span><span></span>
      <svg viewBox="0 0 420 220" focusable="false"><path d="M18 168 C90 90 126 184 198 94 S328 90 398 34"></path><path d="M42 48 H138 L184 92 H286 L350 154"></path><circle cx="42" cy="48" r="4"></circle><circle cx="184" cy="92" r="4"></circle><circle cx="350" cy="154" r="4"></circle></svg>
    </div>
    <div class="hero security-hero-copy ${riskClass}">
      <div class="security-product-mark">
        <div class="security-shield">${compactIcon('shield')}</div>
        <div class="risk-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="risk-track" cx="50" cy="50" r="42"></circle><circle class="risk-progress" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="${displayedRiskScore} 100"></circle></svg><strong>${displayedRiskScore}</strong></div>
      </div>
      <div class="risk-copy">
        <div class="security-product-badge">DevSecOps Security</div>
        <h2>Security Center</h2>
        <p class="security-workspace">Vue de sécurité du workspace <strong>${escapeHtml(model.workspace)}</strong></p>
        <span class="risk-explanation">Surveillez, analysez et corrigez les risques de sécurité en continu.</span>
        <span class="risk-calculation-note">${riskExplanation}</span>
        <div class="risk-label"><i class="risk-status-dot"></i>Risque ${escapeHtml(displayedRiskLevel)}</div>
      </div>
    </div>
    <div class="overview-kpis security-hero-metrics">${heroMetrics}</div>
  </section>`;

  // Le compagnon du rail lit le meme modele visuel partage que la page Live
  // Security et que la mascotte flottante. Il ne compose aucun message, ne
  // compte aucun finding et n'apparait pas du tout quand le moteur n'a rien a
  // dire : une carte d'assistant sans etat serait un assistant invente.
  const companionLine = companionVisual ? String(companionVisual.shortMessage || companionVisual.message?.headline || '') : '';
  const companionFile = companionVisual ? String(companionVisual.currentFile || '') : '';
  const companionSeverity = companionVisual ? String(companionVisual.liveHighestSeverity || '') : '';
  const companionFacts = companionVisual
    ? [
      companionFile ? `<div class="sc-rail-fact"><span>Fichier courant</span><strong title="${escapeHtml(companionFile)}">${escapeHtml(targetLabel(companionFile))}</strong></div>` : '',
      `<div class="sc-rail-fact"><span>Problèmes Live</span><strong>${Number(companionVisual.liveFindingCount) || 0}</strong></div>`,
      companionSeverity ? `<div class="sc-rail-fact"><span>Sévérité la plus haute</span><strong class="sc-rail-sev ${severityTone(companionSeverity)}">${escapeHtml(String(companionSeverity).toUpperCase())}</strong></div>` : ''
    ].filter(Boolean).join('')
    : '';
  const companionCard = companionVisual
    ? `<section class="sc-rail-card sc-rail-live">
      <div class="sc-rail-head"><strong>Live Security Companion</strong><span class="sc-companion-state ${escapeHtml(String(companionVisual.state || 'idle'))}">${escapeHtml(COMPANION_STATE_LABELS[companionVisual.state] || String(companionVisual.state || 'idle'))}</span></div>
      ${companionLine ? `<p class="sc-companion-line">${escapeHtml(companionLine)}</p>` : ''}
      <div class="sc-rail-facts">${companionFacts}</div>
      <button class="sc-rail-link" data-command="securityCenter.openLiveSecurityPage">Voir les détails →</button>
    </section>`
    : '';
  // Chaque action cite une commande deja enregistree et deja autorisee par la
  // frontiere de confiance du webview. Aucun raccourci n'execute de logique ici.
  const quickActionsCard = `<section class="sc-rail-card">
    <div class="sc-rail-head"><strong>Actions rapides</strong></div>
    <div class="sc-rail-actions">
      <button class="sc-rail-action primary" data-command="securityCenter.scanWorkspace" ${scanRunning ? 'disabled' : ''}><span class="sc-rail-action-icon">▷</span><span>${scanRunning ? 'Analyse en cours…' : hasScanned ? 'Relancer l’analyse' : 'Lancer l’analyse'}</span></button>
      <button class="sc-rail-action" data-command="securityCenter.openFindingsPage"><span class="sc-rail-action-icon">◉</span><span>Examiner les findings</span>${currentActiveFindings.length ? `<small>${currentActiveFindings.length}</small>` : ''}</button>
      <button class="sc-rail-action" data-command="securityCenter.verifyFindingFix"><span class="sc-rail-action-icon">✓</span><span>Vérifier une correction</span></button>
      <button class="sc-rail-action" data-command="securityCenter.openSecurityPipeline"><span class="sc-rail-action-icon">↗</span><span>Ouvrir le pipeline</span></button>
    </div>
  </section>`;

  // Cycle unifie de verification. Chaque compteur vient d'un statut reellement
  // porte par un finding : « appliquee », « validee » et « toujours presente »
  // restent trois faits distincts, jamais additionnes en un seul « corrige ».
  const validatingCount = dedupedCurrentFindings.filter((finding) => finding.triageStatus === 'validating').length;
  const verificationTiles = [
    ['Appliquées', remediation.fixApplied, 'medium'],
    ['En vérification', validatingCount, 'neutral'],
    ['Validées', remediation.validated, 'low'],
    ['Toujours présentes', remediation.stillPresent, 'critical'],
    ['Non concluantes', remediation.inconclusive, 'high'],
    ['Réapparues', remediation.regressed, 'critical']
  ];
  // Le finding dont la verification est la plus recente : c'est celui sur lequel
  // le developpeur vient d'agir.
  const lastVerified = dedupedCurrentFindings
    .filter((finding) => Number.isFinite(Date.parse(finding.verification?.at || finding.fixedAt || '')))
    .sort((left, right) => Date.parse(right.verification?.at || right.fixedAt) - Date.parse(left.verification?.at || left.fixedAt))[0] || null;
  const lastVerifiedState = lastVerified ? String(lastVerified.verification?.state || lastVerified.triageStatus || '') : '';
  const verifyBody = lastVerified
    ? `<div class="verify-latest ${severityTone(lastVerified.rawSeverity || lastVerified.severity)}">
      <span class="verify-state ${escapeHtml(lastVerifiedState)}">${escapeHtml(statusLabels[lastVerifiedState] || lastVerifiedState || 'État inconnu')}</span>
      <strong>${escapeHtml(lastVerified.title || 'Alerte de sécurité')}</strong>
      <small>${escapeHtml(lastVerified.file || lastVerified.endpoint || 'Emplacement non fourni')}</small>
      ${lastVerified.verification?.validator ? `<span class="verify-meta">Vérifié par ${escapeHtml(lastVerified.verification.validator)}${lastVerified.verification.reason ? ` — ${escapeHtml(lastVerified.verification.reason)}` : ''}</span>` : ''}
    </div>`
    : '<div class="empty">Aucune correction n’a encore été appliquée ni vérifiée.</div>';
  const fixVerifyCard = `<section class="overview-panel"><div class="overview-panel-head"><strong>Fix &amp; Verify</strong><button data-command="securityCenter.verifyFindingFix">Vérifier une correction →</button></div>
    <div class="verify-tiles">${verificationTiles.map(([label, value, tone]) => `<div class="verify-tile ${tone}"><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`).join('')}</div>
    ${verifyBody}
  </section>`;

  // Chronologie : uniquement les evenements dates par le modele du finding
  // ci-dessus. Aucune etape n'est comblee pour faire joli.
  const timelineEvents = verificationTimeline(lastVerified);
  const activityTimelineCard = `<section class="overview-panel"><div class="overview-panel-head"><strong>Chronologie de vérification</strong><button data-command="securityCenter.showAuditLog">Journal d'audit →</button></div>
    ${timelineEvents.length
      ? `<ol class="verify-timeline">${timelineEvents.map((event) => `<li class="verify-event ${event.tone}"><span class="verify-dot"></span><div><strong>${escapeHtml(event.label)}</strong><time>${escapeHtml(new Date(event.at).toLocaleString('fr-FR'))}</time></div></li>`).join('')}</ol>`
      : `<div class="empty">${lastVerified ? 'Aucun horodatage de cycle de vie sur cette alerte.' : 'La chronologie apparaîtra dès qu’une correction aura été appliquée.'}</div>`}
  </section>`;
  const overviewLowerRow = `<div class="overview-lower">${fixVerifyCard}${activityTimelineCard}</div>`;

  // Le bandeau compact de la page Findings compte exactement la liste qu'elle
  // affiche — `model.findings` — et rien d'autre. Reutiliser les compteurs de
  // l'apercu (dedupliques, limites aux scanners termines) aurait donne un total
  // different de celui du tableau juste en dessous.
  const findingsSummary = [
    ['Total', model.findings.length, 'total'],
    ['Critical', severityCount(model.findings, ['CRITICAL', 'ERROR']), 'critical'],
    ['High', severityCount(model.findings, ['HIGH']), 'high'],
    ['Medium', severityCount(model.findings, ['MEDIUM', 'WARNING']), 'medium'],
    ['Low', severityCount(model.findings, ['LOW', 'INFO', 'INFORMATION']), 'low']
  ].map(([label, value, tone]) => `<div class="findings-stat ${tone}"><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`).join('');
  const reachabilityOptions = [...new Set(model.findings.map(reachabilityFor))]
    .sort()
    .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(reachabilityLabel(value))}</option>`)
    .join('');

  // La carte d'assistant, en tete du rail. Elle ne calcule aucun fait : elle
  // recoit la liste de findings que cette page affiche deja, l'etat du scan tel
  // que le modele le porte, et le modele visuel partage du companion. Quand rien
  // de reel n'est disponible, `buildAssistantCardModel` rend `null` et la carte
  // n'apparait pas — le rail garde ses cartes existantes, inchangees.
  const assistantModel = buildAssistantCardModel({
    surface,
    companion: companionVisual,
    findings: currentActiveFindings,
    scan: { status: model.scanStatus, completed: finishedCount, successful: successfulCount, total: model.scanners.length },
    scanners: model.scanners,
    posture: {
      label: currentExecutionActive ? 'Current run' : 'Workspace posture',
      findingCount: currentActiveFindings.length,
      scope: currentExecutionActive ? 'current-run' : 'workspace-posture'
    }
  });
  const assistantOptions = { mascotImageUri: companionImageUri };
  const assistantCard = renderAssistantCard(assistantModel, assistantOptions);
  const assistantHeroCard = renderAssistantHeroCard(assistantModel, assistantOptions);
  const assistantPanelCard = renderAssistantPanelCard(assistantModel);
  const companionPresence = companionWidgetFor(assistantCard);
  const fullShellOpen = inShell ? `<div class="sc-app-shell">${renderInternalSidebar(surface)}<main class="sc-main" data-page-kind="${escapeHtml(pageAtmosphereKind(surface))}">${renderSecurityCenterAtmosphere(surface)}` : '';
  const fullShellClose = inShell ? `</main><aside class="sc-companion-rail" aria-label="Contexte Security Center">
    ${assistantHeroCard}
    ${assistantCard ? '' : companionCard}
    ${quickActionsCard}
    ${assistantPanelCard}
    <section class="sc-rail-card sc-context-card"><div class="sc-rail-head"><strong>État de l'analyse</strong><span class="sc-rail-pill ${statusClass}">${escapeHtml(model.scanStatus)}</span></div><span>${escapeHtml(scanStatusLabel)}</span><small>${escapeHtml(finishedCount)}/${escapeHtml(model.scanners.length)} scanners terminés</small></section>
    <section class="sc-rail-card sc-context-card"><div class="sc-rail-head"><strong>Backend</strong><span class="sc-rail-pill ${backendTone}">${escapeHtml(model.backendStatus)}</span></div><span>${escapeHtml(operationalTitle)}</span></section>
  </aside></div>` : '';
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource || "'self'"}; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style nonce="${nonce}">
    * { box-sizing: border-box; }
    body {
      --sc-bg: var(--vscode-sideBar-background);
      --sc-surface: var(--vscode-editor-background);
      --sc-surface-soft: var(--vscode-editor-inactiveSelectionBackground);
      --sc-border: var(--vscode-widget-border);
      --sc-text: var(--vscode-foreground);
      --sc-muted: var(--vscode-descriptionForeground);
      --sc-primary: var(--vscode-button-background);
      --sc-primary-hover: var(--vscode-button-hoverBackground);
      --sc-primary-soft: color-mix(in srgb, var(--sc-primary) 12%, var(--sc-surface));
      --sc-critical: var(--vscode-charts-red, #d92d20);
      --sc-high: var(--vscode-charts-orange, #f97316);
      --sc-medium: var(--vscode-charts-yellow, #ca8a04);
      --sc-low: var(--vscode-charts-green, #16a34a);
      --sc-success: var(--vscode-testing-iconPassed, #16a34a);
      --sc-warning: var(--vscode-editorWarning-foreground, #ca8a04);
      --sc-radius-sm: 6px;
      --sc-radius-md: 8px;
      --sc-radius-lg: 12px;
      --sc-shadow-sm: 0 10px 28px var(--vscode-widget-shadow, rgba(15, 23, 42, .10));
      color: var(--sc-text);
      font-family: var(--vscode-font-family);
      padding: 16px;
      margin: 0 auto;
      max-width: 1200px;
      background: var(--sc-bg);
      color-scheme: light;
    }
    body.theme-light {
      --vscode-foreground: #424750;
      --vscode-descriptionForeground: #707782;
      --vscode-sideBar-background: #f7f8fa;
      --vscode-editor-background: #ffffff;
      --vscode-editor-inactiveSelectionBackground: #edf0f4;
      --vscode-widget-border: #d9dde3;
      --vscode-focusBorder: #467bd7;
      --vscode-button-background: #467bd7;
      --vscode-button-foreground: #ffffff;
      --vscode-button-hoverBackground: #376bc2;
      --vscode-button-secondaryBackground: #e9ebef;
      --vscode-button-secondaryForeground: #4e5560;
      --vscode-button-secondaryHoverBackground: #dde1e7;
      --vscode-input-background: #ffffff;
      --vscode-input-foreground: #353a42;
      --vscode-input-border: #cfd4dc;
      --vscode-textLink-foreground: #356cc8;
      --vscode-progressBar-background: #467bd7;
      --vscode-editorWidget-background: #ffffff;
      --vscode-editorWidget-foreground: #424750;
      --vscode-list-hoverBackground: #f1f3f6;
      --vscode-list-hoverForeground: #353a42;
      --vscode-list-activeSelectionBackground: #e4ebf8;
      --vscode-list-activeSelectionForeground: #2f3540;
      --vscode-widget-shadow: rgba(35, 42, 52, .18);
      --sc-bg: #f6f7fb;
      --sc-surface: #ffffff;
      --sc-surface-soft: #f1f4fb;
      --sc-border: #dde3ee;
      --sc-text: #172033;
      --sc-muted: #687386;
      --sc-primary: #5b5fef;
      --sc-primary-hover: #484bd6;
      --sc-primary-soft: #eef0ff;
      --sc-shadow-sm: 0 12px 30px rgba(32, 40, 72, .08);
      color-scheme: light;
    }
    body.theme-dark {
      --sc-bg: color-mix(in srgb, var(--vscode-sideBar-background) 82%, #0b1020 18%);
      --sc-surface: var(--vscode-editor-background);
      --sc-surface-soft: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 70%, var(--vscode-editor-background));
      --sc-border: var(--vscode-widget-border);
      --sc-text: var(--vscode-foreground);
      --sc-muted: var(--vscode-descriptionForeground);
      --sc-primary: var(--vscode-button-background);
      --sc-primary-hover: var(--vscode-button-hoverBackground);
      --sc-primary-soft: color-mix(in srgb, var(--vscode-button-background) 18%, var(--vscode-editor-background));
      color-scheme: dark;
    }
    body.surface-full, body.sc-shelled { max-width: none; min-height: 100vh; padding: 0; margin: 0; overflow-x: hidden; }
    h2, h3 { margin: 0; }
    h2 { font-size: 23px; letter-spacing: -.4px; }
    h3 { font-size: 11px; letter-spacing: .8px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin: 22px 0 10px; }
    .header { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; margin-bottom: 16px; padding-bottom: 13px; border-bottom: 2px solid color-mix(in srgb, var(--sc-primary) 78%, #ff2da8 22%); }
    body.surface-full .header { position: sticky; top: 0; z-index: 6; align-items: center; margin: -24px -24px 18px; padding: 14px 24px; border-bottom: 1px solid var(--sc-border); background: color-mix(in srgb, var(--sc-surface) 94%, transparent); backdrop-filter: blur(12px); }
    body.surface-full .header h2 { font-size: 18px; letter-spacing: 0; }
    .header-actions { display: flex; align-items: flex-start; gap: 8px; }
    .theme-toggle { display: inline-grid; place-items: center; width: 30px; height: 30px; padding: 0; color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); font-size: 14px; line-height: 1; text-align: center; }
    .theme-toggle-icon { display: block; line-height: 1; }
    .header-status { display: flex; flex-direction: column; align-items: flex-end; gap: 5px; }
    .header-scan { width: auto; min-width: 88px; padding: 5px 10px; text-align: center; color: var(--vscode-button-foreground); background: var(--vscode-button-background); font-size: 10px; }
    .header-scan:hover { background: var(--vscode-button-hoverBackground); }
    .scan-chrono { display: inline-flex; align-items: center; gap: 5px; min-width: 78px; padding: 5px 9px; border: 1px solid var(--vscode-widget-border); border-radius: 999px; color: var(--vscode-foreground); background: var(--vscode-editor-background); font: 600 10px var(--vscode-font-family); }
    .backend { color: var(--vscode-descriptionForeground); font-size: 10px; }
    .workspace { color: var(--vscode-descriptionForeground); overflow-wrap: anywhere; margin-top: 5px; }
    ${shellLayoutCss()}
    body.surface-full .sc-main > .operational-banner,
    body.surface-full .sc-main > .policy-banner,
    body.surface-full .sc-main > .zap-card,
    body.surface-full .sc-main > .cards { display: none !important; }
    .status-pill, .status { border-radius: 999px; padding: 4px 8px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; }
    .status-pill.completed, .status.completed { color: #75d99f; background: rgba(46,160,87,.16); }
    .status-pill.failed, .status.failed { color: #ff7b72; background: rgba(248,81,73,.16); }
    .status-pill.running, .status.running { color: #79c0ff; background: rgba(56,139,253,.16); }
    .status.pending { color: var(--vscode-descriptionForeground); background: var(--vscode-editor-inactiveSelectionBackground); }
    .operational-banner { display: grid; grid-template-columns: auto 1fr; gap: 10px; align-items: center; border: 1px solid var(--vscode-widget-border); border-radius: 9px; padding: 11px 13px; margin-bottom: 12px; }
    .operational-banner.danger { border-color: rgba(255,59,48,.75); background: rgba(255,59,48,.13); }
    .operational-banner.success { border-color: rgba(46,160,67,.55); background: rgba(46,160,67,.09); }
    .operational-icon { font-size: 19px; font-weight: 900; color: var(--vscode-descriptionForeground); }
    .operational-banner.danger .operational-icon, .operational-banner.danger strong { color: #ff453a; }
    .operational-copy strong, .operational-copy span { display: block; }
    .operational-copy strong { font-size: 13px; }
    .operational-copy span { margin-top: 3px; color: var(--vscode-descriptionForeground); font-size: 10px; }
    .failure-diagnostics { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 14px; align-items: center; margin: 10px 0 14px; padding: 13px 15px; border: 1px solid rgba(255,159,10,.6); border-radius: 9px; background: rgba(255,159,10,.07); }
    .failure-diagnostics strong { display: block; margin-top: 4px; font-size: 14px; }
    .failure-kicker { color: #ffb340; font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: .7px; }
    .failure-diagnostics p { margin: 6px 0 0; color: var(--vscode-descriptionForeground); font-size: 10px; line-height: 1.45; }
    .failure-actions { display: flex; align-items: center; gap: 7px; }
    .failure-actions button { width: auto; }
    .quiet-action { color: var(--vscode-textLink-foreground); background: transparent; border-color: transparent; }
    .sidebar-open { width: 100%; margin: 10px 0; }
    body.surface-sidebar > h3,
    body.surface-sidebar .policy-banner,
    body.surface-sidebar .zap-card,
    body.surface-sidebar .cards,
    body.surface-sidebar .findings-panel,
    body.surface-sidebar .scanner,
    body.surface-sidebar .analytics-grid,
    body.surface-sidebar .metric,
    body.surface-sidebar .correlation,
    body.surface-sidebar .http-summary,
    body.surface-sidebar .burp-requests,
    body.surface-sidebar .http-help,
    body.surface-sidebar .http-details,
    body.surface-sidebar .http-actions,
    body.surface-sidebar .workflow,
    body.surface-sidebar .page-findings,
    body.surface-sidebar .page-scans,
    body.surface-sidebar .page-dynamic,
    body.surface-sidebar .page-analytics,
    body.surface-sidebar .page-burp-settings { display: none !important; }
    body.surface-sidebar > .operational-banner,
    body.surface-sidebar > .hero,
    body.surface-sidebar > .pipeline-panel,
    body.surface-sidebar > h3.sidebar-keep,
    body.surface-sidebar > .page-navigation { display: none !important; }
    body.surface-sidebar .action-sections { display: grid !important; grid-template-columns: 1fr; gap: 9px; }
    body.surface-sidebar .action-group { padding: 10px; }
    body.surface-sidebar .action-group-buttons { display: grid; grid-template-columns: 1fr; gap: 7px; }
    body.surface-sidebar .action-group-buttons button { width: 100%; text-align: left; }
    body.surface-history .header-scan,
    body.surface-history .action-sections,
    body.surface-history .http-actions,
    body.surface-history .finding-card-actions,
    body.surface-history .zap-meta button { display: none !important; }
    body.surface-findings .page-scans, body.surface-findings .page-dynamic, body.surface-findings .page-analytics, body.surface-findings .page-burp-settings,
    body.surface-scans .page-findings, body.surface-scans .page-dynamic, body.surface-scans .page-analytics, body.surface-scans .page-burp-settings,
    body.surface-dynamic .page-findings, body.surface-dynamic .page-scans, body.surface-dynamic .page-analytics, body.surface-dynamic .page-burp-settings,
    body.surface-analytics .page-findings, body.surface-analytics .page-scans, body.surface-analytics .page-dynamic, body.surface-analytics .page-burp-settings,
    body.surface-burp-settings .page-findings, body.surface-burp-settings .page-scans, body.surface-burp-settings .page-dynamic, body.surface-burp-settings .page-analytics { display: none !important; }
    body.surface-findings .hero, body.surface-findings .policy-banner, body.surface-findings .pipeline-panel, body.surface-findings .zap-card, body.surface-findings .cards,
    body.surface-scans .hero, body.surface-scans .policy-banner, body.surface-scans .cards,
    body.surface-dynamic .hero, body.surface-dynamic .policy-banner, body.surface-dynamic .pipeline-panel, body.surface-dynamic .cards,
    body.surface-analytics .hero, body.surface-analytics .policy-banner, body.surface-analytics .pipeline-panel, body.surface-analytics .zap-card, body.surface-analytics .cards { display: none !important; }
    body.surface-full .page-findings, body.surface-full .page-scans, body.surface-full .page-dynamic, body.surface-full .page-analytics, body.surface-full .page-burp-settings { display: none !important; }
    body.surface-burp-settings .hero, body.surface-burp-settings .policy-banner, body.surface-burp-settings .pipeline-panel, body.surface-burp-settings .zap-card, body.surface-burp-settings .cards { display: none !important; }
    body.surface-full > .operational-banner, body.surface-full > .policy-banner, body.surface-full > .zap-card, body.surface-full > .cards { display: none !important; }
    .page-navigation { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 7px; margin: 12px 0; }
    .page-navigation button { text-align: center; }
    body.surface-dynamic .sc-main > .operational-banner, body.surface-dynamic .sc-main > .zap-card { display: none !important; }
    #security-center-modal-root:empty { display: none; }
    .sc-modal-overlay,
    .sc-modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: rgba(20, 24, 45, .34);
      backdrop-filter: blur(3px);
      pointer-events: auto;
    }
    body.sc-modal-open { overflow: hidden; }
    .sc-zap-preflight {
      width: min(600px, calc(100vw - 48px));
      max-height: calc(100vh - 48px);
      overflow-y: auto;
      display: grid;
      gap: 16px;
      padding: 20px;
      border: 1px solid color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border));
      border-radius: 18px;
      color: var(--sc-text);
      background: color-mix(in srgb, var(--sc-surface) 97%, var(--sc-primary) 3%);
      box-shadow: 0 24px 70px rgba(15, 23, 42, .28), 0 0 0 1px color-mix(in srgb, var(--sc-primary) 10%, transparent);
    }
    .sc-zap-modal-head { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 12px; align-items: start; }
    .sc-zap-modal-logo .scanner-logo { width: 44px; height: 44px; border-radius: 14px; }
    .sc-zap-modal-head span { display: block; margin-bottom: 4px; color: var(--sc-primary); font-size: 10px; font-weight: 800; letter-spacing: .7px; text-transform: uppercase; }
    .sc-zap-modal-head h2 { margin: 0; color: var(--sc-text); font-size: 20px; letter-spacing: 0; }
    .sc-modal-close { width: 30px; min-width: 30px; height: 30px; padding: 0; border-radius: 999px; color: var(--sc-muted); background: transparent; border-color: transparent; font-size: 18px; line-height: 1; }
    .sc-modal-close:hover { color: var(--sc-text); background: var(--sc-surface-soft); }
    .sc-zap-modal-copy { margin: 0; color: var(--sc-muted); font-size: 13px; line-height: 1.55; }
    .sc-zap-target {
      display: grid;
      gap: 7px;
      padding: 12px 14px;
      border: 1px solid color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border));
      border-radius: 12px;
      background: var(--sc-surface-soft);
    }
    .sc-zap-target span { color: var(--sc-muted); font-size: 10px; font-weight: 800; letter-spacing: .6px; text-transform: uppercase; }
    .sc-zap-target code { color: var(--sc-text); background: transparent; font-size: 12px; overflow-wrap: anywhere; }
    .sc-zap-warning { display: grid; gap: 3px; padding: 11px 13px; border: 1px solid rgba(255,159,10,.34); border-radius: 12px; background: rgba(255,159,10,.08); }
    .sc-zap-warning strong { color: var(--sc-warning); font-size: 12px; }
    .sc-zap-warning span { color: var(--sc-muted); font-size: 12px; line-height: 1.45; }
    .sc-zap-modal-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 9px; }
    .sc-zap-modal-actions button { width: auto; min-height: 34px; padding-inline: 13px; }
    .sc-zap-modal-actions .primary { color: #fff; background: var(--sc-primary); border-color: var(--sc-primary); }
    .sc-zap-modal-actions .primary:hover { background: var(--sc-primary-hover); }
    .sc-zap-modal-actions .secondary { color: var(--sc-primary); background: var(--sc-surface); border-color: color-mix(in srgb, var(--sc-primary) 36%, var(--sc-border)); }
    .sc-zap-modal-actions .quiet-action { color: var(--sc-muted); }
    .sc-zap-modal-actions button:focus-visible, .sc-modal-close:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
    .dynamic-page-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin: 6px 0 16px; padding-bottom: 12px; border-bottom: 1px solid var(--vscode-widget-border); }
    .dynamic-page-header h1 { margin: 0; font-size: 22px; }
    .dynamic-page-header p { margin: 5px 0 0; color: var(--vscode-descriptionForeground); font-size: 11px; }
    .dynamic-section { margin: 0 0 10px; padding: 12px 14px; border: 1px solid var(--vscode-widget-border); border-radius: 6px; background: var(--vscode-editor-background); }
    .dynamic-section-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 10px; }
    .dynamic-section-head h2 { font-size: 12px; letter-spacing: .2px; }
    .dynamic-section-head span { color: var(--vscode-descriptionForeground); font-size: 10px; }
    .dynamic-status-grid { display: grid; gap: 10px; }
    .dynamic-status-copy strong, .dynamic-status-copy span, .dynamic-status-copy small { display: block; }
    .dynamic-status-copy span { margin-top: 4px; color: var(--vscode-descriptionForeground); overflow-wrap: anywhere; }
    .dynamic-status-copy small { margin-top: 5px; color: var(--vscode-descriptionForeground); }
    .dynamic-actions { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
    .dynamic-purpose { margin: -5px 0 10px; color: var(--vscode-descriptionForeground); font-size: 10px; }
    .dynamic-facts { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 7px 14px; }
    .dynamic-fact span, .dynamic-fact strong { display: block; }
    .dynamic-fact span { color: var(--vscode-descriptionForeground); font-size: 9px; text-transform: uppercase; letter-spacing: .4px; }
    .dynamic-fact strong { margin-top: 2px; font-size: 11px; overflow-wrap: anywhere; }
    .dynamic-settings { margin-left: auto; padding-inline: 8px; }
    .dynamic-actions button { width: auto; }
    .dynamic-list { display: grid; gap: 0; }
    .dynamic-row { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 10px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--vscode-widget-border); }
    .dynamic-row:last-child { border-bottom: 0; }
    .dynamic-row strong, .dynamic-row small { display: block; overflow-wrap: anywhere; }
    .dynamic-row small { margin-top: 3px; color: var(--vscode-descriptionForeground); }
    .dynamic-row button { width: auto; }
    .dynamic-finding-row { display: grid; grid-template-columns: auto minmax(0,1fr) auto auto; gap: 10px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--vscode-widget-border); }
    .dynamic-finding-row:last-child { border-bottom: 0; }
    .dynamic-severity { min-width: 54px; font-size: 9px; font-weight: 800; letter-spacing: .5px; }
    .dynamic-severity.danger { color: var(--vscode-errorForeground); }
    .dynamic-finding-copy strong, .dynamic-finding-copy small, .dynamic-finding-copy span { display: block; overflow-wrap: anywhere; }
    .dynamic-finding-copy small, .dynamic-finding-copy span { margin-top: 2px; color: var(--vscode-descriptionForeground); font-size: 9px; }
    .dynamic-correlation { display: inline !important; margin-left: 6px !important; color: var(--vscode-textLink-foreground) !important; }
    .dynamic-source { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin-top: 5px; font-size: 11px; color: var(--vscode-descriptionForeground); }
    .dynamic-source span { font-weight: 700; color: var(--vscode-foreground); }
    .dynamic-source.medium span { color: var(--vscode-descriptionForeground); }
    .dynamic-source code { padding: 1px 4px; border-radius: 3px; background: var(--vscode-textCodeBlock-background, var(--vscode-editor-inactiveSelectionBackground)); color: var(--vscode-textLink-foreground); overflow-wrap: anywhere; }
    .dynamic-source button { padding: 2px 5px; font-size: 10px; }
    .settings-list { display: grid; border: 1px solid var(--vscode-widget-border); border-radius: 6px; overflow: hidden; }
    .settings-row { display: grid; grid-template-columns: minmax(130px, .45fr) minmax(0, 1fr); gap: 12px; padding: 9px 11px; border-bottom: 1px solid var(--vscode-widget-border); }
    .settings-row:last-child { border-bottom: 0; }
    .settings-row span { color: var(--vscode-descriptionForeground); }
    .settings-row strong, .settings-row code { overflow-wrap: anywhere; }
    .dynamic-finding-row button { width: auto; }
    .traffic-controls { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 9px; }
    .traffic-controls input { min-width: 210px; flex: 1; }
    .traffic-filter { width: auto; padding: 5px 9px; }
    .traffic-filter.active { color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
    .traffic-layout { display: grid; grid-template-columns: minmax(0, 3fr) minmax(320px, 2fr); gap: 12px; min-width: 0; }
    .traffic-table { min-width: 650px; }
    .traffic-scroll { overflow: auto; border: 1px solid var(--vscode-widget-border); border-radius: 5px; }
    .traffic-head, .traffic-row { display: grid; grid-template-columns: 65px minmax(210px,1fr) 65px 80px 65px 145px; gap: 8px; align-items: center; width: 100%; padding: 7px 9px; text-align: left; }
    .traffic-head { color: var(--vscode-descriptionForeground); background: var(--vscode-editor-inactiveSelectionBackground); font-size: 9px; font-weight: 700; text-transform: uppercase; }
    .traffic-row { color: var(--vscode-foreground); background: transparent; border: 0; border-top: 1px solid var(--vscode-widget-border); border-radius: 0; font-size: 10px; }
    .traffic-row:hover { background: var(--vscode-list-hoverBackground, var(--vscode-editor-inactiveSelectionBackground)); }
    .traffic-row.selected { color: var(--vscode-list-activeSelectionForeground, var(--vscode-foreground)); background: var(--vscode-list-activeSelectionBackground, var(--vscode-editor-inactiveSelectionBackground)); outline: 1px solid var(--vscode-focusBorder); outline-offset: -1px; }
    .traffic-row:focus-visible, .traffic-filter:focus-visible, .dynamic-actions button:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: 1px; }
    .traffic-row strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .traffic-row[hidden] { display: none; }
    .traffic-preview { padding: 11px; border: 1px solid var(--vscode-widget-border); border-radius: 5px; background: var(--vscode-editor-background); align-self: start; }
    .traffic-preview h3 { margin: 0 0 8px; }
    .traffic-preview strong, .traffic-preview span { display: block; overflow-wrap: anywhere; }
    .traffic-preview span { margin-top: 5px; color: var(--vscode-descriptionForeground); font-size: 9px; }
    .traffic-preview h4 { margin: 12px 0 5px; font-size: 10px; }
    .traffic-preview dl { display: grid; grid-template-columns: auto minmax(0,1fr); gap: 4px 8px; margin: 5px 0; font-size: 9px; }
    .traffic-preview dt { color: var(--vscode-descriptionForeground); }
    .traffic-preview dd { margin: 0; overflow-wrap: anywhere; }
    .traffic-preview pre { max-height: 150px; overflow: auto; white-space: pre-wrap; word-break: break-word; padding: 7px; background: var(--vscode-textCodeBlock-background, var(--vscode-editor-inactiveSelectionBackground)); font-size: 9px; }
    .traffic-preview details { margin-top: 8px; }
    .traffic-preview summary { cursor: pointer; font-size: 9px; color: var(--vscode-textLink-foreground); }
    .traffic-finding { display: grid; grid-template-columns: 48px minmax(0,1fr) 64px auto; gap: 6px; align-items: center; margin-top: 5px; }
    .traffic-finding > strong { color: var(--vscode-errorForeground); font-size: 9px; }
    .traffic-finding > small { color: var(--vscode-descriptionForeground); overflow: hidden; text-overflow: ellipsis; }
    .traffic-actions { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 9px; }
    .traffic-actions button { width: auto; padding: 4px 7px; }
    .traffic-empty-filter { padding: 14px; color: var(--vscode-descriptionForeground); font-style: italic; }
    @media (max-width: 900px) { .traffic-layout { grid-template-columns: 1fr; } .traffic-preview { position: static; } }
    @media (max-width: 560px) { .dynamic-page-header, .dynamic-section-head { align-items: stretch; flex-direction: column; } .dynamic-facts { grid-template-columns: 1fr; } .dynamic-finding-row { grid-template-columns: auto minmax(0,1fr); } .dynamic-finding-row > .triage-badge, .dynamic-finding-row > button { grid-column: 2; justify-self: start; } .settings-row { grid-template-columns: 1fr; gap: 3px; } .traffic-controls input { min-width: 100%; } }
    @media (min-width: 760px) { .dynamic-status-grid { grid-template-columns: repeat(2, minmax(0,1fr)); } }
    .overview-pages { display: grid; gap: 9px; margin: 14px 0; }
    .overview-link { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 10px; align-items: center; padding: 12px; border: 1px solid var(--vscode-widget-border); border-radius: 9px; background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 48%, transparent); }
    .overview-link strong, .overview-link span { display: block; }
    .overview-link span { margin-top: 3px; color: var(--vscode-descriptionForeground); font-size: 10px; }
    .overview-link button, .priority-finding button { width: auto; }
    .priority-findings { display: grid; gap: 7px; margin-bottom: 14px; }
    .priority-finding { display: grid; grid-template-columns: 8px minmax(0,1fr) auto; gap: 10px; align-items: center; padding: 12px; border: 1px solid var(--vscode-widget-border); border-radius: 8px; background: color-mix(in srgb, var(--vscode-editor-background) 88%, transparent); }
    .priority-marker { width: 8px; height: 8px; border-radius: 50%; background: #8b949e; box-shadow: 0 0 0 4px rgba(139,148,158,.10); }
    .priority-finding.danger .priority-marker { background: #ff453a; box-shadow: 0 0 0 4px rgba(255,69,58,.12); }
    .priority-finding.warning .priority-marker { background: #ff9f0a; box-shadow: 0 0 0 4px rgba(255,159,10,.12); }
    .priority-severity { color: #ff7b72 !important; font-size: 9px !important; font-weight: 800; letter-spacing: .7px; text-transform: uppercase; }
    .priority-finding strong, .priority-finding span { display: block; }
    .priority-finding span { margin-top: 4px; color: var(--vscode-descriptionForeground); font-size: 10px; overflow-wrap: anywhere; }
    .history-readonly { margin: 0 0 12px; padding: 10px 13px; border: 1px solid var(--vscode-focusBorder); border-radius: 8px; color: var(--vscode-descriptionForeground); }
    .hero { display: grid; grid-template-columns: 94px 1fr; align-items: center; gap: 18px; border: 1px solid var(--vscode-widget-border); background: transparent; border-radius: 12px; padding: 16px; margin-bottom: 10px; }
    body.surface-full .hero { border: 0; border-radius: 0; padding: 16px 18px; margin: 0; background: transparent; }
    .hero.critical { border-color: rgba(255,59,48,.8); background: linear-gradient(135deg, rgba(255,59,48,.20), rgba(255,59,48,.04)); }
    .hero.high { border-color: rgba(255,149,0,.7); background: rgba(255,149,0,.10); }
    .hero.medium { border-color: rgba(255,204,0,.65); background: rgba(255,204,0,.08); }
    .hero.low { border-color: rgba(46,160,67,.55); background: rgba(46,160,67,.07); }
    .risk-ring { width: 86px; aspect-ratio: 1; display: grid; place-items: center; position: relative; }
    .risk-ring svg { position: absolute; inset: 0; width: 100%; height: 100%; transform: rotate(-90deg); }
    .risk-track, .risk-progress { fill: none; stroke-width: 9; }
    .risk-track { stroke: rgba(139,148,158,.18); } .risk-progress { stroke: #3fb950; stroke-linecap: round; }
    .critical .risk-progress { stroke: #ff3b30; } .high .risk-progress { stroke: #ff9500; } .medium .risk-progress { stroke: #ffcc00; }
    .risk-ring strong { position: relative; font-size: 25px; color: var(--vscode-foreground); }
    .risk-copy strong, .risk-copy span { display: block; }
    .risk-label { text-transform: uppercase; font-size: 14px; font-weight: 800; letter-spacing: .8px; }
    .critical .risk-label { color: #ff453a; } .high .risk-label { color: #ff9f0a; } .medium .risk-label { color: #ffd60a; } .low .risk-label { color: #75d99f; }
    .risk-explanation { margin-top: 6px; color: var(--vscode-descriptionForeground); font-size: 10px; line-height: 1.45; }
    .cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .card { background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 82%, transparent); border: 1px solid var(--vscode-widget-border); border-radius: 8px; padding: 11px; min-height: 69px; }
    .card strong { display: block; font-size: 23px; }
    .card span { color: var(--vscode-descriptionForeground); font-size: 10px; text-transform: uppercase; letter-spacing: .4px; }
    .overview-kpis { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); border: 1px solid var(--vscode-widget-border); border-radius: 10px; overflow: hidden; margin: 12px 0 16px; }
    .overview-summary { display: grid; border: 1px solid var(--vscode-widget-border); border-radius: 12px; overflow: hidden; margin: 12px 0 18px; background: var(--vscode-editor-background); }
    .overview-summary .overview-kpis { border: 0; border-radius: 0; margin: 0; }
    .overview-kpi { padding: 14px; background: color-mix(in srgb, var(--vscode-editor-background) 76%, transparent); border-right: 1px solid var(--vscode-widget-border); }
    .overview-kpi:last-child { border-right: 0; }
    .overview-kpi strong, .overview-kpi span, .overview-kpi small { display: block; }
    .overview-kpi strong { font-size: 25px; line-height: 1; }
    .overview-kpi span { margin-top: 7px; color: var(--vscode-descriptionForeground); font-size: 9px; font-weight: 800; letter-spacing: .6px; text-transform: uppercase; }
    .overview-kpi small { margin-top: 5px; color: var(--vscode-descriptionForeground); font-size: 9px; }
    .overview-kpi.critical strong { color: #ff453a; } .overview-kpi.high strong { color: #ff9f0a; }
    .overview-split { display: grid; gap: 12px; margin: 14px 0; }
    .overview-panel { border: 1px solid var(--vscode-widget-border); border-radius: 10px; padding: 14px; background: color-mix(in srgb, var(--vscode-editor-background) 74%, transparent); }
    .overview-panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .overview-panel-head strong { font-size: 11px; letter-spacing: .7px; text-transform: uppercase; }
    .overview-panel-head button { width: auto; padding: 4px 7px; color: var(--vscode-textLink-foreground); background: transparent; border-color: transparent; }
    .compact-icon { width: 17px; height: 17px; flex: 0 0 auto; fill: none; stroke: currentColor; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }
    .overview-scanner { display: grid; grid-template-columns: 30px minmax(120px,1fr) auto auto auto minmax(95px,.8fr) 24px; align-items: center; gap: 9px; padding: 9px 2px; border-bottom: 1px solid var(--vscode-widget-border); font-size: 10px; }
    .overview-scanner:last-child { border-bottom: 0; }
    .scanner-logo { width: 36px; height: 36px; display: grid; place-items: center; border: 1px solid var(--vscode-widget-border); border-radius: 8px; color: var(--vscode-button-background); background: var(--vscode-button-foreground); overflow: hidden; }
    .scanner-logo-img { display: block; width: 28px; height: 28px; object-fit: contain; }
    .scanner-logo[data-scanner-logo="semgrep"] .scanner-logo-img,
    .scanner-logo[data-scanner-logo="osv"] .scanner-logo-img { width: 30px; height: 22px; }
    .scanner-logo[data-scanner-logo="zap"] .scanner-logo-img { width: 29px; height: 29px; }
    .scanner-logo.completed { border-color: color-mix(in srgb, var(--vscode-testing-iconPassed) 45%, var(--vscode-widget-border)); }
    .scanner-logo.failed { border-color: color-mix(in srgb, var(--vscode-testing-iconFailed) 45%, var(--vscode-widget-border)); }
    .scanner-logo.disabled, .scanner-index.disabled { opacity: .55; }
    .overview-scanner.disabled, .scanner.disabled { opacity: .78; }
    .status.disabled, .scanner-ready.disabled { color: var(--vscode-descriptionForeground); }
    .scanner-identity strong, .scanner-identity small, .scanner-value strong, .scanner-value small { display: block; }
    .scanner-identity small, .scanner-value small, .overview-scanner time { color: var(--vscode-descriptionForeground); }
    .scanner-identity small { margin-top: 2px; line-height: 1.25; }
    .scanner-ready { padding: 3px 7px; border-radius: 999px; color: var(--vscode-descriptionForeground); background: var(--vscode-editor-inactiveSelectionBackground); font-size: 9px; font-weight: 700; }
    .scanner-ready.completed { color: var(--vscode-testing-iconPassed); background: color-mix(in srgb, var(--vscode-testing-iconPassed) 12%, var(--vscode-editor-background)); }
    .scanner-ready.failed { color: var(--vscode-testing-iconFailed); }
    .scanner-value { min-width: 44px; text-align: right; }
    .scanner-value small { margin-top: 1px; }
    .overview-scanner time { text-align: right; line-height: 1.3; }
    .scanner-chevron { width: 24px; padding: 3px; color: var(--vscode-textLink-foreground); background: transparent; border-color: transparent; text-align: center; font-size: 16px; }
    .scanner-health { width: 19px; height: 19px; display: grid; place-items: center; border-radius: 50%; }
    .scanner-health.completed { color: #75d99f; background: rgba(46,160,87,.14); } .scanner-health.failed { color: #ff7b72; background: rgba(248,81,73,.14); }
    .activity-bars { display: grid; grid-template-columns: repeat(3, 1fr); align-items: end; gap: 10px; min-height: 104px; padding-top: 8px; }
    .activity-stat { display: grid; align-content: end; gap: 6px; text-align: center; height: 100%; }
    .activity-bar { width: 100%; min-height: 5px; border-radius: 5px 5px 2px 2px; background: #58a6ff; opacity: .82; }
    .activity-stat.resolved .activity-bar { background: #3fb950; } .activity-stat.accepted .activity-bar { background: #a371f7; }
    .activity-stat strong { font-size: 18px; } .activity-stat span { color: var(--vscode-descriptionForeground); font-size: 9px; text-transform: uppercase; }
    .activity-overview { display: grid; gap: 12px; }
    .activity-summary { display: grid; grid-template-columns: repeat(4,1fr); gap: 8px; }
    .activity-summary .activity-stat { min-height: 42px; align-content: center; border-top: 3px solid var(--vscode-charts-blue); }
    .activity-summary .activity-stat.resolved { border-color: var(--vscode-charts-yellow); }
    .activity-summary .activity-stat.validated { border-color: var(--vscode-charts-green); }
    .activity-summary .activity-stat.accepted { border-color: var(--vscode-charts-purple); }
    .activity-chart-wrapper {
      min-height: 110px;
      padding: 8px 0;
      border-top: 1px dashed var(--vscode-widget-border);
      border-bottom: 1px dashed var(--vscode-widget-border);
      position: relative;
    }
    .activity-chart {
      width: 100%;
      height: 140px;
      overflow: visible;
    }
    .activity-chart .chart-line {
      fill: none;
      stroke: var(--vscode-charts-blue, #58a6ff);
      stroke-width: 2.5;
      stroke-linecap: round;
      stroke-linejoin: round;
      vector-effect: non-scaling-stroke;
      filter: drop-shadow(0px 2px 4px rgba(88, 166, 255, 0.20));
    }
    .activity-chart .chart-grid-line {
      stroke: var(--vscode-widget-border, rgba(128, 128, 128, 0.15));
      stroke-width: 1;
      stroke-dasharray: 3 3;
    }
    .activity-chart .chart-grid-line.vertical {
      stroke-width: 0.5;
      stroke-dasharray: 2 4;
      opacity: 0.6;
    }
    .activity-chart .chart-y-axis-label {
      font-size: 10px;
      fill: var(--vscode-descriptionForeground);
      font-weight: 500;
      dominant-baseline: middle;
    }
    .activity-chart .chart-dot {
      fill: var(--vscode-editor-background);
      stroke: var(--vscode-charts-blue, #58a6ff);
      stroke-width: 2;
      r: 4;
      cursor: pointer;
      transition: r 0.1s ease, fill 0.1s ease, stroke-width 0.1s ease;
    }
    .activity-chart .chart-dot:hover {
      r: 6;
      fill: var(--vscode-charts-blue, #58a6ff);
      stroke-width: 2;
    }
    .chart-axis-label {
      font-size: 9.5px;
      fill: var(--vscode-descriptionForeground);
      font-weight: 500;
    }
    .activity-tooltip {
      position: absolute;
      background: var(--vscode-editorWidget-background, #1f242c);
      color: var(--vscode-editorWidget-foreground, #cccccc);
      border: 1px solid var(--vscode-widget-border, #30363d);
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 11px;
      box-shadow: 0 4px 10px rgba(0,0,0,0.15);
      z-index: 20;
      pointer-events: none;
      display: none;
      width: max-content;
      min-width: 170px;
      font-family: var(--vscode-font-family);
      line-height: 1.4;
    }
    .tooltip-timestamp {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--vscode-editorWidget-foreground, #ffffff);
      border-bottom: 1px solid var(--vscode-widget-border, #30363d);
      padding-bottom: 4px;
    }
    .tooltip-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 4px;
    }
    .tooltip-row.total-row {
      font-weight: 600;
      margin-bottom: 6px;
    }
    .tooltip-severity {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .tooltip-dot {
      display: inline-block;
      width: 6px;
      height: 6px;
      border-radius: 50%;
    }
    .tooltip-dot.critical { background-color: var(--vscode-charts-red, #f85149); }
    .tooltip-dot.high { background-color: var(--vscode-charts-orange, #f0883e); }
    .tooltip-dot.medium { background-color: var(--vscode-charts-yellow, #d29922); }
    .tooltip-dot.low { background-color: var(--vscode-charts-green, #3fb950); }
    .history-chart-empty { display: grid; place-items: center; height: 104px; color: var(--vscode-descriptionForeground); }
    .activity-footer {
      display: flex;
      justify-content: space-between;
      align-items: stretch;
      margin-top: 14px;
      padding-top: 10px;
      border-top: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.25));
    }
    .activity-col {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
    }
    .activity-col:last-of-type {
      align-items: flex-start;
      padding-left: 14px;
    }
    .activity-divider {
      width: 1px;
      background: var(--vscode-widget-border, rgba(128,128,128,0.25));
      margin: 2px 0;
    }
    .activity-col-title {
      font-size: 8.5px;
      font-weight: 700;
      color: var(--vscode-descriptionForeground);
      text-transform: uppercase;
      letter-spacing: .6px;
      margin-bottom: 4px;
    }
    .activity-col-val {
      font-size: 20px;
      font-weight: 650;
      color: var(--vscode-foreground);
      line-height: 1.15;
      margin-bottom: 2px;
    }
    .activity-col-sub {
      font-size: 9px;
      color: var(--vscode-descriptionForeground);
    }
    .overview-bottom { display: grid; gap: 12px; margin: 0 0 20px; }
    .priority-summary-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 8px; }
    .priority-summary-item { padding: 9px 4px; text-align: center; }
    .priority-summary-item strong, .priority-summary-item span { display: block; }
    .priority-summary-item strong { font-size: 20px; }
    .priority-summary-item span { margin-top: 4px; color: var(--vscode-descriptionForeground); font-size: 8px; font-weight: 700; text-transform: uppercase; }
    .priority-summary-item.critical strong { color: var(--vscode-testing-iconFailed); }
    .priority-summary-item.high strong { color: var(--vscode-charts-orange); }
    .priority-summary-item.medium strong { color: var(--vscode-charts-yellow); }
    .priority-summary-item.low strong { color: var(--vscode-charts-blue); }
    .recent-scans { display: grid; }
    .recent-scan { display: grid; grid-template-columns: 10px minmax(100px,1fr) auto auto; align-items: center; gap: 8px; padding: 8px 0; border-bottom: 1px solid var(--vscode-widget-border); font-size: 9px; }
    .recent-scan:last-child { border-bottom: 0; }
    .recent-scan time, .recent-status { color: var(--vscode-descriptionForeground); }
    .recent-state { width: 7px; height: 7px; border-radius: 50%; background: var(--vscode-descriptionForeground); }
    .recent-state.info { background: var(--vscode-charts-blue); }
    .recent-state.warning { background: var(--vscode-charts-yellow); }
    .recent-state.danger { background: var(--vscode-testing-iconFailed); }
    .row { display: flex; justify-content: space-between; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--vscode-widget-border); }
    .row small { display: block; margin-top: 2px; color: var(--vscode-descriptionForeground); }
    .completed { color: var(--vscode-testing-iconPassed); }
    .failed { color: var(--vscode-testing-iconFailed); }
    .running { color: var(--vscode-progressBar-background); }
    .pending { color: var(--vscode-descriptionForeground); }
    .empty { color: var(--vscode-descriptionForeground); font-style: italic; }
    .scanner { display: grid; grid-template-columns: 27px 1fr auto; align-items: center; gap: 9px; padding: 7px 0; }
    .scanner-index { width: 25px; height: 25px; display: grid; place-items: center; border-radius: 50%; border: 1px solid var(--vscode-widget-border); font-size: 11px; font-weight: 700; }
    .scanner-index.completed { color: #75d99f; border-color: rgba(46,160,87,.65); background: rgba(46,160,87,.12); }
    .scanner-index.failed { color: #ff7b72; border-color: rgba(248,81,73,.65); }
    .scanner-copy small { display: block; color: var(--vscode-descriptionForeground); margin-top: 2px; }
    .scanner-copy .scanner-error { color: #ff7b72; line-height: 1.4; overflow-wrap: anywhere; }
    .metric { margin-bottom: 9px; }
    .metric-label { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }
    .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; background: #8b949e; }
    .dot.danger { background: #ff7b72; } .dot.warning { background: #d29922; } .dot.info { background: #58a6ff; }
    progress { width: 100%; height: 6px; border: 0; border-radius: 5px; overflow: hidden; display: block; }
    progress::-webkit-progress-bar { background: var(--vscode-editor-inactiveSelectionBackground); }
    progress::-webkit-progress-value { background: #8b949e; border-radius: 5px; }
    progress.danger::-webkit-progress-value { background: #ff7b72; } progress.warning::-webkit-progress-value { background: #d29922; } progress.info::-webkit-progress-value { background: #58a6ff; }
    .correlation { border: 1px solid var(--vscode-widget-border); border-left: 3px solid #d29922; background: rgba(210,153,34,.06); border-radius: 6px; padding: 9px; margin-bottom: 8px; }
    .correlation span, .correlation small { display: block; margin-top: 4px; color: var(--vscode-descriptionForeground); }
    button { width: 100%; border: 1px solid var(--vscode-button-border, transparent); border-radius: 6px; padding: 8px 10px; cursor: pointer; font-family: inherit; font-weight: 600; text-align: left; }
    button.primary { color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
    button.primary:hover { background: var(--vscode-button-hoverBackground); }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:disabled { cursor: not-allowed; opacity: .48; }
    .http-actions { display: grid; grid-template-columns: 1fr; gap: 7px; margin: 9px 0; }
    .action-sections { display: grid; gap: 10px; }
    .action-group { border: 1px solid var(--vscode-widget-border); border-radius: 9px; padding: 10px; background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 48%, transparent); }
    .action-group-title { margin-bottom: 8px; color: var(--vscode-descriptionForeground); font-size: 10px; font-weight: 800; letter-spacing: .6px; text-transform: uppercase; }
    .action-group-buttons { display: grid; gap: 7px; }
    .action-group-buttons button { display: flex; align-items: center; gap: 8px; }
    .action-group.frequent { border-color: rgba(56,139,253,.45); }
    .http-help { margin: 8px 0; padding: 9px; border-left: 3px solid #58a6ff; background: rgba(56,139,253,.07); color: var(--vscode-descriptionForeground); font-size: 11px; line-height: 1.45; }
    .http-details { margin: 9px 0; border: 1px solid var(--vscode-widget-border); border-radius: 7px; padding: 9px; background: var(--vscode-editor-background); font-size: 11px; line-height: 1.5; }
    .http-details summary { cursor: pointer; font-weight: 700; color: var(--vscode-textLink-foreground); }
    .http-details ol { margin: 8px 0 0; padding-left: 20px; }
    .workflow { display: grid; gap: 7px; }
    .workflow-step { display: grid; grid-template-columns: 25px 1fr; gap: 8px; align-items: start; border: 1px solid var(--vscode-widget-border); border-radius: 6px; padding: 8px; background: rgba(56,139,253,.04); }
    .workflow-number { display: grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; color: #79c0ff; background: rgba(56,139,253,.16); font-weight: 700; font-size: 11px; }
    .workflow-step strong, .workflow-step small { display: block; }
    .workflow-step small { color: var(--vscode-descriptionForeground); margin-top: 3px; line-height: 1.35; }
    .http-summary { border: 1px solid rgba(56,139,253,.4); border-radius: 8px; padding: 10px; background: linear-gradient(135deg, rgba(56,139,253,.12), rgba(163,113,247,.06)); }
    .http-summary strong { font-size: 21px; display: block; }
    .http-summary span { color: var(--vscode-descriptionForeground); font-size: 11px; }
    .http-summary .burp-connection { display: block; margin-top: 7px; font-weight: 700; }
    .burp-connection.connected { color: var(--vscode-testing-iconPassed); }
    .burp-connection.disconnected { color: var(--vscode-testing-iconQueued, var(--vscode-descriptionForeground)); }
    .burp-requests { display: grid; gap: 7px; margin: 9px 0; }
    .burp-request { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 9px; border: 1px solid var(--vscode-widget-border); border-radius: 7px; padding: 9px; background: var(--vscode-editor-background); }
    .burp-request .method { padding: 3px 6px; border-radius: 5px; color: #79c0ff; background: rgba(56,139,253,.16); font-size: 9px; font-weight: 800; }
    .burp-request strong, .burp-request small { display: block; overflow-wrap: anywhere; }
    .burp-request small { margin-top: 3px; color: var(--vscode-descriptionForeground); }
    .burp-state { color: #75d99f; font-size: 9px; text-transform: uppercase; font-weight: 700; }
    .page-findings { position: relative; display: grid; gap: 14px; }
    .findings-hero { position: relative; overflow: hidden; display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; padding: 18px; border: 1px solid var(--sc-border); border-radius: 18px; background: linear-gradient(135deg, color-mix(in srgb, var(--sc-primary) 8%, var(--sc-surface)), var(--sc-surface)); box-shadow: var(--sc-shadow-sm); }
    .findings-watermark { position: absolute; right: 38px; bottom: -12px; display: flex; gap: 18px; opacity: .035; transform: scale(5); color: var(--sc-primary); pointer-events: none; }
    .findings-eyebrow { color: var(--sc-primary); font-size: 10px; font-weight: 900; letter-spacing: .9px; text-transform: uppercase; }
    .findings-hero h2 { margin: 4px 0 0; color: var(--sc-text); font-size: 28px; letter-spacing: 0; }
    .findings-hero p { max-width: 680px; margin: 7px 0 0; color: var(--sc-muted); font-size: 12px; line-height: 1.55; }
    .findings-panel { border: 1px solid var(--sc-border); border-radius: 18px; padding: 14px; background: var(--sc-surface); box-shadow: var(--sc-shadow-sm); }
    .finding-filters { display: grid; grid-template-columns: 1fr; gap: 9px; margin-bottom: 11px; }
    .finding-filters label { display: grid; gap: 5px; min-width: 0; color: var(--sc-muted); font-size: 9px; font-weight: 900; letter-spacing: .6px; text-transform: uppercase; }
    .finding-filters input, .finding-filters select { width: 100%; min-height: 34px; color: var(--vscode-input-foreground); background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, var(--sc-border)); border-radius: 10px; padding: 8px 10px; font-family: inherit; text-transform: none; letter-spacing: 0; }
    .finding-filters .quiet-action { align-self: end; min-height: 34px; border-radius: 10px; }
    .finding-filter-meta { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 12px; }
    .filter-chips { display: flex; flex-wrap: wrap; gap: 6px; min-height: 24px; }
    .filter-chip { display: inline-flex; align-items: center; gap: 5px; padding: 5px 8px; border: 1px solid color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border)); border-radius: 999px; color: var(--sc-primary); background: var(--sc-primary-soft); font-size: 10px; font-weight: 800; }
    .filter-chip button { width: 16px; height: 16px; display: grid; place-items: center; padding: 0; border: 0; border-radius: 50%; color: inherit; background: transparent; cursor: pointer; }
    .finding-list { display: grid; gap: 10px; max-height: 760px; overflow-y: auto; padding-right: 4px; }
    .finding-layout { display: grid; gap: 14px; }
    .finding-preview { display: none; position: sticky; top: 12px; align-self: start; border: 1px solid var(--sc-border); border-radius: 16px; padding: 16px; background: var(--sc-surface); box-shadow: var(--sc-shadow-sm); }
    .finding-preview-label { color: var(--sc-primary); font-size: 10px; font-weight: 900; letter-spacing: .7px; text-transform: uppercase; }
    .finding-preview h4 { margin: 10px 0; color: var(--sc-text); font-size: 18px; line-height: 1.32; overflow-wrap: anywhere; }
    .preview-source { display: flex; justify-content: space-between; gap: 8px; align-items: center; margin-top: 10px; }
    .preview-source span, .preview-source strong { display: inline-flex; align-items: center; border-radius: 999px; font-size: 10px; font-weight: 900; text-transform: uppercase; }
    .preview-source span { color: var(--sc-muted); }
    .preview-source strong { padding: 5px 8px; color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 10%, transparent); }
    .finding-preview dl { display: grid; gap: 8px; margin: 12px 0; }
    .finding-preview dl div { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 8px; }
    .finding-preview dt { color: var(--sc-muted); font-size: 9px; font-weight: 900; letter-spacing: .55px; text-transform: uppercase; }
    .finding-preview dd { margin: 0; overflow-wrap: anywhere; }
    .finding-preview p { color: var(--sc-muted); font-size: 12px; line-height: 1.5; }
    .preview-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .finding-card { position: relative; display: grid; grid-template-columns: 4px auto minmax(0,1fr); gap: 12px; align-items: center; border: 1px solid var(--sc-border); border-radius: 14px; padding: 12px 12px 12px 0; background: var(--sc-surface); transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease; }
    .finding-card.hidden { display: none; }
    .finding-card:hover, .finding-card:focus-visible { border-color: color-mix(in srgb, var(--sc-primary) 55%, var(--sc-border)); box-shadow: 0 10px 24px color-mix(in srgb, var(--sc-primary) 10%, transparent); transform: translateY(-1px); outline: none; }
    .finding-card.selected { border-color: var(--sc-primary); box-shadow: 0 0 0 1px color-mix(in srgb, var(--sc-primary) 30%, transparent), 0 12px 28px color-mix(in srgb, var(--sc-primary) 14%, transparent); }
    .finding-accent { border-radius: 0 5px 5px 0; background: #8b949e; }
    .finding-accent.danger { background: var(--sc-critical); } .finding-accent.warning { background: var(--sc-high); } .finding-accent.info { background: var(--sc-low); }
    .finding-source { display: grid; justify-items: center; gap: 5px; width: 58px; color: var(--sc-muted); font-size: 9px; font-weight: 900; text-transform: uppercase; }
    .finding-source .scanner-logo { width: 38px; height: 38px; border-radius: 12px; }
    .finding-source .scanner-logo-img { width: 26px; height: 26px; }
    .finding-main { min-width: 0; }
    .finding-top { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 7px; }
    .severity-badge, .tool-badge, .context-badge, .triage-badge, .fact-badge { border-radius: 999px; padding: 3px 7px; font-size: 9px; font-weight: 800; text-transform: uppercase; }
    .severity-badge { padding: 4px 9px; font-size: 10px; border: 1px solid currentColor; }
    .severity-badge { color: #c9d1d9; background: rgba(139,148,158,.18); }
    .severity-badge.danger { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 11%, transparent); }
    .severity-badge.warning { color: var(--sc-high); background: color-mix(in srgb, var(--sc-high) 12%, transparent); }
    .severity-badge.info { color: var(--sc-low); background: color-mix(in srgb, var(--sc-low) 13%, transparent); }
    .tool-badge { color: #d2a8ff; background: rgba(163,113,247,.15); }
    .context-badge, .triage-badge, .fact-badge { color: var(--sc-muted); background: var(--sc-surface-soft); }
    .finding-title, .finding-location, .finding-main small { display: block; overflow-wrap: anywhere; }
    .finding-title { color: var(--sc-text); font-size: 13px; line-height: 1.35; }
    .finding-location { margin-top: 5px; color: var(--sc-primary); font-size: 11px; }
    .finding-main small { margin-top: 4px; color: var(--sc-muted); }
    .finding-state { display: grid; gap: 4px; min-width: 118px; color: var(--sc-text); font-size: 10px; font-weight: 900; text-transform: uppercase; }
    .finding-state small { color: var(--sc-muted); font-weight: 700; text-transform: none; }
    .finding-card-actions { display: flex; flex-wrap: wrap; gap: 6px; justify-self: end; }
    .finding-open, .finding-code { width: auto; padding: 6px 9px; border-radius: 9px; background: transparent; border-color: var(--sc-border); font-size: 10px; font-weight: 900; }
    .finding-open { color: var(--sc-primary); background: var(--sc-primary-soft); border-color: color-mix(in srgb, var(--sc-primary) 28%, var(--sc-border)); }
    .finding-code { color: var(--sc-success); }
    .findings-summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 9px; margin: 0; }
    .findings-stat { padding: 10px 12px; border: 1px solid var(--sc-border); border-left: 3px solid var(--sc-border); border-radius: var(--sc-radius-md); background: var(--sc-surface); }
    .findings-stat strong, .findings-stat span { display: block; }
    .findings-stat strong { color: var(--sc-text); font-size: 19px; font-weight: 700; line-height: 1.1; }
    .findings-stat span { margin-top: 3px; color: var(--sc-muted); font-size: 9.5px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; }
    .findings-stat.critical { border-left-color: var(--sc-critical); }
    .findings-stat.high { border-left-color: var(--sc-high); }
    .findings-stat.medium { border-left-color: var(--sc-medium); }
    .findings-stat.low { border-left-color: var(--sc-low); }
    .findings-stat.total { border-left-color: var(--sc-primary); }
    body.surface-findings .finding-list { max-height: none; }
    body.surface-findings .finding-card-actions { flex-wrap: nowrap; }
    @media (max-width: 980px) { .findings-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
    @media (max-width: 760px) { .finding-card { grid-template-columns: 4px auto minmax(0,1fr); } .finding-state, .finding-card-actions { grid-column: 3; justify-self: start; } .finding-card-actions { flex-wrap: wrap; } }
    @media (max-width: 680px) { .findings-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .finding-preview dl div { grid-template-columns: 1fr; } }
    .findings-count { margin: 0 0 8px; color: var(--vscode-descriptionForeground); font-size: 10px; }
    .pipeline-panel { border: 1px solid var(--vscode-widget-border); border-radius: 10px; padding: 13px; background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 62%, transparent); }
    .zap-card { display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center; margin: 10px 0; padding: 13px; border: 1px solid rgba(163,113,247,.48); border-radius: 10px; background: linear-gradient(135deg, rgba(163,113,247,.12), rgba(56,139,253,.05)); }
    .zap-card.failed { border-color: rgba(248,81,73,.68); background: rgba(248,81,73,.09); }
    .zap-card.completed { border-color: rgba(63,185,80,.55); background: rgba(46,160,67,.08); }
    .zap-card h4 { margin: 4px 0; font-size: 14px; }
    .zap-card p { margin: 0; color: var(--vscode-descriptionForeground); font-size: 10px; overflow-wrap: anywhere; }
    .zap-kicker { color: #d2a8ff; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: .6px; }
    .zap-meta { display: grid; justify-items: end; gap: 8px; }
    .policy-banner { display: grid; gap: 4px; margin: 12px 0; padding: 11px 13px; border: 1px solid; border-radius: 8px; }
    .policy-banner span { color: var(--vscode-descriptionForeground); font-size: 11px; }
    .policy-banner.pass { border-color: rgba(63,185,80,.55); background: rgba(46,160,67,.10); }
    .policy-banner.fail { border-color: rgba(248,81,73,.55); background: rgba(248,81,73,.10); }
    .pipeline-scroll { overflow-x: auto; padding: 5px 2px 10px; scrollbar-width: thin; scrollbar-color: #b9c0ca #edf0f4; }
    .pipeline-scroll::-webkit-scrollbar { height: 10px; }
    .pipeline-scroll::-webkit-scrollbar-track { background: #edf0f4; border-radius: 999px; }
    .pipeline-scroll::-webkit-scrollbar-thumb { background: #b9c0ca; border: 2px solid #edf0f4; border-radius: 999px; }
    .pipeline-scroll::-webkit-scrollbar-thumb:hover { background: #969faa; }
    body.theme-dark .pipeline-scroll { scrollbar-color: var(--vscode-scrollbarSlider-background, #555) transparent; }
    body.theme-dark .pipeline-scroll::-webkit-scrollbar-track { background: transparent; }
    body.theme-dark .pipeline-scroll::-webkit-scrollbar-thumb { background: var(--vscode-scrollbarSlider-background, #555); border-color: transparent; }
    body.theme-dark .pipeline-scroll::-webkit-scrollbar-thumb:hover { background: var(--vscode-scrollbarSlider-hoverBackground, #777); }
    .pipeline { min-width: 690px; display: flex; align-items: flex-start; }
    .pipeline-stage { flex: 0 0 92px; text-align: center; min-width: 76px; }
    .pipeline-stage.interactive { position: relative; overflow: visible; border-radius: 7px; outline-offset: 3px; cursor: default; }
    .pipeline-stage.interactive:focus-visible { outline: 2px solid var(--vscode-focusBorder); }
    .pipeline-stage strong, .pipeline-stage small { display: block; }
    .pipeline-stage strong { margin-top: 7px; font-size: 11px; }
    .pipeline-stage small { margin-top: 3px; color: var(--vscode-descriptionForeground); font-size: 9px; }
    .pipeline-dot { width: 32px; height: 32px; margin: 0 auto; display: grid; place-items: center; border-radius: 50%; border: 2px solid var(--vscode-widget-border); background: var(--vscode-sideBar-background); font-weight: 800; }
    .pipeline-dot.completed { color: #3fb950; border-color: rgba(63,185,80,.6); background: rgba(46,160,87,.14); }
    .pipeline-dot.running, .pipeline-dot.refreshing { color: #58a6ff; border-color: rgba(56,139,253,.75); background: rgba(56,139,253,.17); box-shadow: 0 0 0 5px rgba(56,139,253,.08); }
    .pipeline-dot.running, .pipeline-dot.refreshing { position: relative; animation: scanner-float 1.55s ease-in-out infinite; }
    .pipeline-spinner { display: inline-block; line-height: 1; animation: scanner-spin .85s linear infinite; }
    .pipeline-popover { position: fixed; z-index: 1000; left: 0; top: 0; width: min(310px, calc(100vw - 24px)); max-height: min(230px, calc(100vh - 24px)); overflow: auto; transform: translate(-50%, -4px); visibility: hidden; opacity: 0; pointer-events: none; padding: 10px; border: 1px solid var(--vscode-widget-border); border-radius: 8px; text-align: left; color: var(--vscode-editorWidget-foreground, var(--vscode-foreground)); background: var(--vscode-editorWidget-background, var(--vscode-editor-background)); box-shadow: 0 5px 16px var(--vscode-widget-shadow); transition: opacity .14s ease, transform .14s ease, visibility 0s linear .14s; }
    .pipeline-popover strong, .pipeline-popover span, .pipeline-popover small { display: block; }
    .pipeline-popover span { margin-top: 7px; line-height: 1.35; }
    .pipeline-popover b { margin-right: 5px; font-size: 9px; }
    .pipeline-stage.interactive:hover .pipeline-popover, .pipeline-stage.interactive:focus-visible .pipeline-popover { visibility: visible; opacity: 1; pointer-events: auto; transform: translate(-50%, 0); transition-delay: .12s, .12s, 0s; }
    .pipeline-dot.running::after, .pipeline-dot.refreshing::after { content: ''; position: absolute; inset: -7px; border: 2px solid rgba(56,139,253,.42); border-radius: 50%; animation: scanner-pop 1.55s ease-out infinite; pointer-events: none; }
    @keyframes scanner-float { 0%, 100% { transform: translateY(0) scale(1); } 50% { transform: translateY(-5px) scale(1.06); } }
    @keyframes scanner-spin { to { transform: rotate(360deg); } }
    @keyframes scanner-pop { 0% { transform: scale(.72); opacity: .8; } 70%, 100% { transform: scale(1.28); opacity: 0; } }
    @media (prefers-reduced-motion: reduce) { .pipeline-dot.running, .pipeline-dot.refreshing, .pipeline-dot.running::after, .pipeline-dot.refreshing::after, .pipeline-spinner { animation: none; } .pipeline-popover { transition: none; } }
    .pipeline-dot.failed { color: #ff7b72; border-color: rgba(248,81,73,.75); background: rgba(248,81,73,.14); }
    .pipeline-dot.cancelled { color: #d29922; border-color: rgba(210,153,34,.75); background: rgba(210,153,34,.14); }
    .pipeline-retry { margin-top: 9px; width: 100%; padding: 6px 8px; color: var(--vscode-button-foreground); background: var(--vscode-button-background); border: 0; border-radius: 4px; cursor: pointer; }
    .pipeline-line { flex: 1; min-width: 38px; height: 2px; margin-top: 15px; background: var(--vscode-widget-border); }
    .pipeline-line.active { background: linear-gradient(90deg, #3fb950, #58a6ff); }
    .analytics-grid { display: grid; gap: 10px; }
    .analytics-panel { border: 1px solid var(--vscode-widget-border); border-radius: 10px; padding: 12px; background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 40%, transparent); }
    .analytics-panel h3 { margin-top: 0; }
    .donut-card { display: grid; grid-template-columns: 118px 1fr; align-items: center; gap: 12px; }
    .donut-wrap { position: relative; width: 112px; height: 112px; }
    .donut-wrap svg { width: 100%; height: 100%; transform: rotate(-90deg); }
    .donut-track, .donut-segment { fill: none; stroke-width: 14; }
    .donut-track { stroke: var(--vscode-editor-inactiveSelectionBackground); }
    .donut-segment { stroke-linecap: butt; }
    .chart-0 { stroke: #ff453a; background: #ff453a; } .chart-1 { stroke: #ff9f0a; background: #ff9f0a; } .chart-2 { stroke: #ffd60a; background: #ffd60a; } .chart-3 { stroke: #58a6ff; background: #58a6ff; } .chart-4 { stroke: #a371f7; background: #a371f7; } .chart-5 { stroke: #3fb950; background: #3fb950; }
    .donut-total { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
    .donut-total strong, .donut-total span { display: block; }
    .donut-total strong { font-size: 21px; } .donut-total span { color: var(--vscode-descriptionForeground); font-size: 9px; text-transform: uppercase; }
    .donut-legend { display: grid; gap: 5px; min-width: 0; }
    .donut-legend-row { display: grid; grid-template-columns: 8px minmax(0, 1fr) auto; align-items: center; gap: 6px; font-size: 10px; }
    .donut-legend-row span:nth-child(2) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .donut-swatch { width: 8px; height: 8px; border-radius: 2px; }

    /* La coquille du dashboard complet occupe toute la largeur de l'onglet : le
       cadrage est fait par .sc-app-shell, qui doit pouvoir placer sa colonne
       de navigation contre le bord. Un max-width pose sur le body laissait une
       bande vide a droite du rail et decalait la barre laterale interne.
       Le padding appartient a .sc-main, pas au body. */
    body.surface-full, body.sc-shelled {
      width: 100%;
      max-width: none;
      padding: 0;
      font-family: var(--vscode-font-family), Inter, "Segoe UI", system-ui, sans-serif;
    }
    /* Aucune regle h2 ici : le dashboard complet n'en affiche plus qu'aux
       intitules de groupe de la navigation, que .sc-nav-group h2 habille.
       Une regle body.surface-full h2 les emportait par specificite et rendait
       « OVERVIEW » ou « ANALYZE » plus gros qu'un titre de carte. */
    body.sc-shelled .workspace { margin-top: 4px; font-size: 13px; opacity: .65; }
    /* ================================================= dashboard complet
       Tout ce bloc est de la presentation. Il repeint les sections que le
       dashboard rendait deja, en passant par les jetons --sc-* : aucune regle
       ici ne decide de ce qui est affiche, seulement de son apparence. */
    body.surface-full, body.sc-shelled { background: var(--sc-bg); }

    /* ------------------------------------------------------------ topbar */
    .sc-topbar { position: sticky; top: 0; z-index: 5; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 16px; min-width: 0; margin: 0 0 20px; padding: 14px 18px; border: 1px solid color-mix(in srgb, var(--sc-primary) 12%, var(--sc-border)); border-radius: var(--sc-radius-lg); background: color-mix(in srgb, var(--sc-surface) 96%, transparent); box-shadow: 0 10px 26px color-mix(in srgb, var(--sc-primary) 7%, transparent), var(--sc-shadow-sm); backdrop-filter: blur(12px); isolation: isolate; }
    .sc-topbar-title { min-width: 0; }
    .sc-topbar-title h1 { margin: 0; color: var(--sc-text); font-size: 19px; font-weight: 700; letter-spacing: 0; overflow-wrap: anywhere; }
    .sc-topbar-title p { margin: 3px 0 0; color: var(--sc-muted); font-size: 11px; line-height: 1.4; overflow-wrap: anywhere; }
    .sc-topbar-actions, .header-actions { min-width: 0; }
    .sc-topbar-workspace { color: var(--sc-text); font-weight: 600; }
    body.surface-full .header-actions { align-items: center; gap: 8px; }
    body.surface-full .header-status { flex-direction: row; align-items: center; gap: 8px; }
    body.surface-full .theme-toggle { border: 1px solid var(--sc-border); border-radius: 999px; color: var(--sc-muted); background: var(--sc-surface); font-weight: 700; box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 8%, transparent); transition: transform .14s ease, color .12s ease, border-color .12s ease, background-color .12s ease, box-shadow .14s ease; }
    body.surface-full .theme-toggle:hover { transform: translateY(-1px); color: var(--sc-primary); border-color: color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border)); background: var(--sc-primary-soft); box-shadow: 0 8px 18px color-mix(in srgb, var(--sc-primary) 10%, transparent); }
    body.surface-full .theme-toggle:active { transform: translateY(0); }
    body.surface-full .header-scan { min-width: 0; padding: 7px 14px; border: 0; border-radius: 999px; color: var(--vscode-button-foreground); background: var(--sc-primary); font-size: 10.5px; font-weight: 700; }
    body.surface-full .header-scan:hover:not(:disabled) { background: var(--sc-primary-hover); }
    body.surface-full .scan-chrono { border-color: var(--sc-border); color: var(--sc-text); background: var(--sc-surface); }
    body.surface-full .backend { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border: 1px solid var(--sc-border); border-radius: 999px; color: var(--sc-muted); background: var(--sc-surface); font-size: 10px; font-weight: 600; }
    body.surface-full .backend::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
    body.surface-full .backend.online { color: var(--sc-success); border-color: color-mix(in srgb, var(--sc-success) 30%, var(--sc-border)); }
    body.surface-full .backend.offline { color: var(--sc-critical); border-color: color-mix(in srgb, var(--sc-critical) 30%, var(--sc-border)); }
    body.surface-full .status-pill { border-radius: 999px; font-size: 9.5px; font-weight: 700; }
    body.surface-full .status-pill.completed { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 12%, var(--sc-surface)); }
    body.surface-full .status-pill.failed { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    body.surface-full .status-pill.running { color: var(--sc-primary); background: var(--sc-primary-soft); }

    /* ------------------------------------------------- titres de section */
    body.surface-full h3 { margin: 22px 0 10px; color: var(--sc-muted); font-size: 10px; font-weight: 800; letter-spacing: .9px; }
    body.surface-full .quiet-action { color: var(--sc-primary); }

    /* -------------------------------------------- Security Center hero */
    body.surface-full .security-center-hero { position: relative; display: grid; grid-template-columns: minmax(390px, 1.04fr) minmax(350px, .96fr); gap: 20px; align-items: center; margin: 4px 0 20px; padding: clamp(20px, 2vw, 26px); border: 1px solid color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border)); border-radius: 22px; overflow: hidden; background: radial-gradient(circle at 16% 40%, color-mix(in srgb, var(--sc-primary) 14%, transparent), transparent 25%), radial-gradient(circle at 44% -18%, color-mix(in srgb, var(--sc-low) 7%, transparent), transparent 34%), linear-gradient(135deg, color-mix(in srgb, var(--sc-primary) 7%, var(--sc-surface)), var(--sc-surface) 60%); box-shadow: 0 18px 42px color-mix(in srgb, var(--sc-primary) 10%, transparent), var(--sc-shadow-sm); font-family: var(--vscode-font-family), "Segoe UI", Inter, system-ui, sans-serif; }
    body.surface-full .security-center-hero::before { content: ''; position: absolute; inset: 12px auto auto 16px; width: 230px; height: 230px; border: 1px solid color-mix(in srgb, var(--sc-primary) 12%, transparent); border-radius: 40px; opacity: .28; transform: rotate(12deg); pointer-events: none; }
    body.surface-full .security-center-hero::after { content: ''; position: absolute; left: 4%; right: 44%; bottom: 18px; height: 86px; opacity: .12; pointer-events: none; background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--sc-primary) 42%, transparent), transparent), repeating-linear-gradient(90deg, color-mix(in srgb, var(--sc-primary) 26%, transparent) 0 1px, transparent 1px 30px); mask-image: linear-gradient(90deg, transparent, rgb(0 0 0) 18%, rgb(0 0 0) 82%, transparent); }
    .security-hero-motif { position: absolute; inset: 0; pointer-events: none; opacity: .28; overflow: hidden; }
    .security-hero-motif svg { position: absolute; left: 74px; top: 16px; width: min(39%, 360px); height: auto; color: var(--sc-primary); opacity: .18; }
    .security-hero-motif path { fill: none; stroke: currentColor; stroke-width: 1.15; stroke-linecap: round; stroke-dasharray: 5 13; }
    .security-hero-motif circle { fill: currentColor; fill-opacity: .72; }
    .security-hero-motif span { position: absolute; width: 5px; height: 5px; border-radius: 50%; background: color-mix(in srgb, var(--sc-primary) 52%, transparent); box-shadow: 0 0 0 6px color-mix(in srgb, var(--sc-primary) 8%, transparent); }
    .security-hero-motif span:nth-child(1) { left: 42px; top: 44px; }
    .security-hero-motif span:nth-child(2) { left: 34%; bottom: 38px; }
    .security-hero-motif span:nth-child(3) { left: 28%; top: 26px; }
    body.surface-full .overview-kpis { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 0; border: 0; border-radius: 0; overflow: visible; background: transparent; }
    body.surface-full .security-hero-metrics { display: block; align-self: center; min-width: 0; }
    body.surface-full .hero-metric-panel { position: relative; display: grid; gap: 13px; min-height: 0; padding: 16px; border: 1px solid color-mix(in srgb, var(--sc-primary) 18%, var(--sc-border)); border-radius: 18px; background: color-mix(in srgb, var(--sc-surface) 92%, transparent); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 7%, transparent), 0 14px 28px color-mix(in srgb, var(--sc-primary) 8%, transparent); backdrop-filter: blur(10px); overflow: hidden; }
    body.surface-full .hero-metric-panel::before { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, color-mix(in srgb, var(--sc-primary) 6%, transparent), transparent 38%), radial-gradient(circle at 100% 0, color-mix(in srgb, var(--sc-low) 7%, transparent), transparent 28%); pointer-events: none; }
    body.surface-full .posture-header { position: relative; z-index: 1; display: flex; align-items: center; justify-content: space-between; gap: 12px; min-width: 0; }
    body.surface-full .posture-header span { color: var(--sc-muted); font-size: 11px; font-weight: 800; letter-spacing: .7px; text-transform: uppercase; }
    body.surface-full .posture-header strong { flex: none; padding: 4px 9px; border: 1px solid color-mix(in srgb, var(--sc-primary) 18%, var(--sc-border)); border-radius: 999px; color: var(--sc-text); background: color-mix(in srgb, var(--sc-primary) 7%, var(--sc-surface)); font-size: 11px; font-weight: 800; letter-spacing: .4px; text-transform: uppercase; font-variant-numeric: tabular-nums; }
    body.surface-full .hero-metric-group { position: relative; z-index: 1; display: grid; min-width: 0; }
    body.surface-full .hero-severity-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; padding: 2px 0 14px; border-bottom: 1px solid color-mix(in srgb, var(--sc-border) 72%, transparent); }
    body.surface-full .hero-operations-grid { grid-template-columns: minmax(128px, .82fr) minmax(190px, 1.18fr); gap: 0; padding-top: 1px; }
    body.surface-full .overview-kpi { position: relative; display: flex; flex-direction: column; justify-content: flex-start; gap: 7px; min-width: 0; padding: 0; border: 0; border-radius: 0; background: transparent; box-shadow: none; overflow: hidden; }
    body.surface-full .hero-operations-grid .overview-kpi + .overview-kpi { padding-left: 16px; border-left: 1px solid color-mix(in srgb, var(--sc-border) 66%, transparent); }
    body.surface-full .hero-metric-label { display: inline-flex; align-items: center; gap: 6px; min-width: 0; margin: 0; color: var(--sc-muted); font-size: 11px; font-weight: 800; letter-spacing: .55px; text-transform: uppercase; white-space: nowrap; }
    body.surface-full .hero-metric-label .compact-icon { flex: none; width: 13px; height: 13px; color: var(--sc-primary); stroke-width: 2; }
    body.surface-full .hero-metric-dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--sc-primary); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sc-primary) 10%, transparent); }
    body.surface-full .hero-metric-dot.critical { background: var(--sc-critical); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sc-critical) 10%, transparent); }
    body.surface-full .hero-metric-dot.high { background: var(--sc-high); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sc-high) 12%, transparent); }
    body.surface-full .hero-metric-dot.medium { background: var(--sc-medium); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sc-medium) 12%, transparent); }
    body.surface-full .hero-metric-dot.low { background: var(--sc-low); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sc-low) 12%, transparent); }
    body.surface-full .overview-kpi > strong { margin: 0; color: var(--sc-text); font-size: clamp(26px, 2.1vw, 34px); font-weight: 800; line-height: .98; font-variant-numeric: tabular-nums; }
    body.surface-full .overview-kpi.critical > strong { color: var(--sc-critical); }
    body.surface-full .overview-kpi.high > strong { color: var(--sc-high); }
    body.surface-full .overview-kpi.medium > strong { color: var(--sc-medium); }
    body.surface-full .overview-kpi.low > strong { color: var(--sc-low); }
    body.surface-full .overview-kpi > small { margin: 0; color: var(--sc-muted); font-size: 12px; line-height: 1.35; }
    body.surface-full .scanner-coverage-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-width: 0; }
    body.surface-full .scanner-coverage-head b { flex: none; color: var(--sc-text); font-size: 12px; font-weight: 800; font-variant-numeric: tabular-nums; }
    body.surface-full .scanner-coverage-bar { position: relative; height: 8px; margin-top: 1px; border-radius: 999px; background: color-mix(in srgb, var(--sc-border) 58%, transparent); overflow: hidden; }
    body.surface-full .scanner-coverage-bar span { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--sc-primary), color-mix(in srgb, var(--sc-primary) 70%, var(--sc-low))); }

    body.surface-full .hero { display: grid; grid-template-columns: minmax(126px, 154px) minmax(0, 1fr); gap: clamp(16px, 2vw, 24px); align-items: center; min-height: 0; margin: 0; padding: 0; border: 0; border-radius: 0; background: transparent; box-shadow: none; }
    .security-hero-copy, .security-hero-metrics { position: relative; z-index: 1; }
    .security-product-mark { position: relative; display: grid; place-items: center; width: clamp(124px, 11vw, 150px); aspect-ratio: 1; isolation: isolate; }
    .security-product-mark::before { content: ''; position: absolute; inset: 6px; border: 1px solid color-mix(in srgb, var(--sc-primary) 14%, transparent); border-radius: 50%; box-shadow: 0 0 0 14px color-mix(in srgb, var(--sc-primary) 4%, transparent), inset 0 0 34px color-mix(in srgb, var(--sc-primary) 8%, transparent); }
    .security-product-mark::after { content: ''; position: absolute; left: 24%; right: 24%; bottom: 7px; height: 13px; border-radius: 50%; background: color-mix(in srgb, var(--sc-primary) 20%, transparent); filter: blur(10px); opacity: .64; }
    .security-shield { display: grid; place-items: center; width: clamp(100px, 9vw, 124px); height: clamp(100px, 9vw, 124px); border: 1px solid color-mix(in srgb, var(--sc-primary) 28%, var(--sc-border)); border-radius: 28px; color: var(--sc-primary); background: linear-gradient(145deg, color-mix(in srgb, var(--sc-primary) 14%, var(--sc-surface)), color-mix(in srgb, var(--sc-surface) 94%, var(--sc-primary))); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 10%, transparent), 0 14px 28px color-mix(in srgb, var(--sc-primary) 15%, transparent); z-index: 1; }
    .security-shield .compact-icon { width: clamp(52px, 4.8vw, 66px); height: clamp(52px, 4.8vw, 66px); stroke-width: 1.55; }
    body.surface-full .risk-ring { position: absolute; right: 0; bottom: 0; z-index: 2; width: 68px; padding: 5px; border: 1px solid color-mix(in srgb, var(--sc-primary) 24%, var(--sc-border)); border-radius: 50%; background: color-mix(in srgb, var(--sc-surface) 94%, transparent); box-shadow: 0 8px 20px color-mix(in srgb, var(--sc-primary) 12%, transparent); }
    body.surface-full .risk-ring strong { color: var(--sc-text); font-size: 21px; font-weight: 850; line-height: 1; font-variant-numeric: tabular-nums; }
    body.surface-full .risk-track, body.surface-full .risk-progress { stroke-width: 8.5; }
    body.surface-full .risk-track { stroke: color-mix(in srgb, var(--sc-border) 70%, transparent); }
    body.surface-full .risk-progress { stroke: var(--sc-low); filter: drop-shadow(0 0 5px color-mix(in srgb, var(--sc-low) 34%, transparent)); }
    body.surface-full .hero.critical .risk-progress { stroke: var(--sc-critical); }
    body.surface-full .hero.high .risk-progress { stroke: var(--sc-high); }
    body.surface-full .hero.medium .risk-progress { stroke: var(--sc-medium); }
    body.surface-full .risk-copy h2 { margin: 6px 0 0; color: var(--sc-text); font-size: clamp(32px, 2.4vw, 42px); font-weight: 800; line-height: 1.04; letter-spacing: 0; }
    .security-product-badge { display: inline-flex; width: fit-content; padding: 5px 10px; border: 1px solid color-mix(in srgb, var(--sc-primary) 26%, var(--sc-border)); border-radius: 999px; color: var(--sc-primary); background: var(--sc-primary-soft); font-size: 10px; font-weight: 900; letter-spacing: .6px; text-transform: uppercase; }
    .security-workspace { margin: 9px 0 0; color: var(--sc-muted); font-size: clamp(14px, 1.05vw, 16px); line-height: 1.4; overflow-wrap: anywhere; }
    .security-workspace strong { color: var(--sc-text); font-weight: 800; }
    body.surface-full .risk-label { display: inline-flex; align-items: center; gap: 7px; width: fit-content; margin-top: 11px; padding: 5px 9px; border: 1px solid color-mix(in srgb, currentColor 24%, var(--sc-border)); border-radius: 999px; background: color-mix(in srgb, currentColor 8%, var(--sc-surface)); font-size: 12.5px; font-weight: 800; letter-spacing: .3px; text-transform: none; }
    body.surface-full .risk-status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 4px color-mix(in srgb, currentColor 12%, transparent); }
    body.surface-full .hero.critical .risk-label { color: var(--sc-critical); }
    body.surface-full .hero.high .risk-label { color: var(--sc-high); }
    body.surface-full .hero.medium .risk-label { color: var(--sc-medium); }
    body.surface-full .hero.low .risk-label { color: var(--sc-low); }
    body.surface-full .risk-explanation { display: block; max-width: 500px; margin-top: 8px; color: var(--sc-muted); font-size: clamp(13px, .95vw, 14.5px); line-height: 1.48; }
    .risk-calculation-note { display: block; max-width: 500px; margin-top: 6px; color: var(--sc-muted); font-size: 10.5px; line-height: 1.42; }

    /* --------------------------------------------------- cartes generiques */
    body.surface-full .overview-panel,
    body.surface-full .pipeline-panel { padding: 18px 20px; border: 1px solid color-mix(in srgb, var(--sc-primary) 12%, var(--sc-border)); border-radius: 16px; background: linear-gradient(145deg, color-mix(in srgb, var(--sc-primary) 2%, transparent), transparent 36%), var(--sc-surface); background-clip: padding-box; box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 7%, transparent), 0 12px 30px color-mix(in srgb, var(--sc-primary) 6%, transparent), var(--sc-shadow-sm); backdrop-filter: blur(6px); transition: transform .16s ease, border-color .16s ease, box-shadow .16s ease; }
    body.surface-full .overview-panel:hover,
    body.surface-full .pipeline-panel:hover { transform: translateY(-1px); border-color: color-mix(in srgb, var(--sc-primary) 20%, var(--sc-border)); box-shadow: 0 16px 34px color-mix(in srgb, var(--sc-primary) 8%, transparent), var(--sc-shadow-sm); }
    body.surface-full .overview-panel-head { position: relative; min-height: 30px; margin-bottom: 14px; padding-bottom: 10px; border-bottom: 0; }
    body.surface-full .overview-panel-head::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 1px; background: linear-gradient(90deg, color-mix(in srgb, var(--sc-primary) 30%, transparent), color-mix(in srgb, var(--sc-primary) 7%, transparent), transparent 78%); pointer-events: none; }
    body.surface-full .overview-panel-head strong { color: var(--sc-text); font-size: 12px; font-weight: 800; letter-spacing: 0; text-transform: none; }
    body.surface-full .overview-panel-head button { width: auto; padding: 4px 9px; border: 0; border-radius: var(--sc-radius-sm); color: var(--sc-primary); background: transparent; font-size: 10px; font-weight: 800; transition: transform .16s ease, background-color .12s ease, color .12s ease; }
    body.surface-full .overview-panel-head button:hover { transform: translateX(2px); background: var(--sc-primary-soft); }
    body.surface-full .empty { color: var(--sc-muted); font-size: 10.5px; }

    /* --------------------------------- rangee severite / analyses / zones */
    body.surface-full .overview-triple { display: grid; grid-template-columns: minmax(260px, .9fr) minmax(280px, 1fr) minmax(320px, 1.1fr); gap: 16px; margin-bottom: 22px; align-items: stretch; }
    body.surface-full .overview-triple > .overview-panel { display: flex; flex-direction: column; height: 100%; min-height: 246px; min-width: 0; }
    body.surface-full .overview-triple > .overview-panel > :not(.overview-panel-head) { flex: 1; min-height: 0; }

    .sev-donut { display: grid; grid-template-columns: 118px minmax(0, 1fr); gap: 16px; align-items: center; }
    .sev-ring { position: relative; width: 116px; aspect-ratio: 1; display: grid; place-items: center; }
    .sev-ring svg { position: absolute; inset: 0; width: 100%; height: 100%; transform: rotate(-90deg); }
    .sev-track, .sev-segment { fill: none; stroke-width: 13; }
    .sev-track { stroke: color-mix(in srgb, var(--sc-border) 75%, transparent); }
    .sev-segment { stroke-linecap: butt; }
    .sev-segment.sev-critical { stroke: var(--sc-critical); }
    .sev-segment.sev-high { stroke: var(--sc-high); }
    .sev-segment.sev-medium { stroke: var(--sc-medium); }
    .sev-segment.sev-low { stroke: var(--sc-low); }
    .sev-total { position: relative; display: grid; justify-items: center; line-height: 1.1; }
    .sev-total strong { color: var(--sc-text); font-size: 22px; font-variant-numeric: tabular-nums; }
    .sev-total span { color: var(--sc-muted); font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
    .sev-legend { display: grid; gap: 7px; min-width: 0; }
    .sev-legend-row { display: grid; grid-template-columns: 9px minmax(0, 1fr) auto auto; align-items: center; gap: 8px; font-size: 10.5px; }
    .sev-swatch { width: 9px; height: 9px; border-radius: 3px; background: var(--sc-border); }
    .sev-swatch.sev-critical { background: var(--sc-critical); }
    .sev-swatch.sev-high { background: var(--sc-high); }
    .sev-swatch.sev-medium { background: var(--sc-medium); }
    .sev-swatch.sev-low { background: var(--sc-low); }
    .sev-legend-row .sev-name { color: var(--sc-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sev-legend-row strong { color: var(--sc-text); font-variant-numeric: tabular-nums; }
    .sev-legend-row small { min-width: 34px; color: var(--sc-muted); text-align: right; font-variant-numeric: tabular-nums; }

    body.surface-full .recent-scans { display: grid; gap: 0; max-height: 214px; overflow: auto; padding-right: 4px; scrollbar-gutter: stable; scrollbar-width: thin; scrollbar-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)) transparent; }
    body.surface-full .recent-scans::-webkit-scrollbar,
    body.surface-full .risky-targets::-webkit-scrollbar,
    body.surface-full .overview-split > .overview-panel:first-child::-webkit-scrollbar { width: 6px; height: 6px; }
    body.surface-full .recent-scans::-webkit-scrollbar-track,
    body.surface-full .risky-targets::-webkit-scrollbar-track,
    body.surface-full .overview-split > .overview-panel:first-child::-webkit-scrollbar-track { background: transparent; }
    body.surface-full .recent-scans::-webkit-scrollbar-thumb,
    body.surface-full .risky-targets::-webkit-scrollbar-thumb,
    body.surface-full .overview-split > .overview-panel:first-child::-webkit-scrollbar-thumb { border-radius: 999px; background: color-mix(in srgb, var(--sc-primary) 24%, var(--sc-border)); }
    body.surface-full .recent-scans::-webkit-scrollbar-thumb:hover,
    body.surface-full .risky-targets::-webkit-scrollbar-thumb:hover,
    body.surface-full .overview-split > .overview-panel:first-child::-webkit-scrollbar-thumb:hover { background: color-mix(in srgb, var(--sc-primary) 38%, var(--sc-border)); }
    body.surface-full .recent-scan { grid-template-columns: 8px minmax(0, 1fr) auto; grid-template-areas: 'dot name status' 'dot time status'; gap: 3px 12px; padding: 11px 10px; border: 0; border-bottom: 1px solid color-mix(in srgb, var(--sc-border) 54%, transparent); border-radius: 0; font-size: 10.5px; }
    body.surface-full .recent-scan:last-child { border-bottom: 0; }
    body.surface-full .recent-scan:hover { background: color-mix(in srgb, var(--sc-primary) 4%, var(--sc-surface)); }
    body.surface-full .recent-scan .recent-state { grid-area: dot; width: 8px; height: 8px; }
    body.surface-full .recent-scan strong { grid-area: name; color: var(--sc-text); font-size: 11px; }
    body.surface-full .recent-scan time { grid-area: time; color: var(--sc-muted); font-size: 9.5px; }
    body.surface-full .recent-status { grid-area: status; align-self: center; padding: 3px 9px; border-radius: 999px; color: var(--sc-muted); background: var(--sc-surface-soft); font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; }
    body.surface-full .recent-state { background: var(--sc-muted); }
    body.surface-full .recent-state.info { background: var(--sc-low); }
    body.surface-full .recent-state.warning { background: var(--sc-medium); }
    body.surface-full .recent-state.danger { background: var(--sc-critical); }

    .risky-targets { display: grid; gap: 0; max-height: 214px; overflow: auto; padding-right: 4px; scrollbar-gutter: stable; scrollbar-width: thin; scrollbar-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)) transparent; }
    .risky-target { display: grid; grid-template-columns: 8px minmax(0, 1fr) auto minmax(24px, auto); align-items: center; gap: 12px; padding: 11px 10px; border-bottom: 1px solid color-mix(in srgb, var(--sc-border) 54%, transparent); border-radius: 0; transition: background-color .14s ease; }
    .risky-target:last-child { border-bottom: 0; }
    .risky-target:hover { background: color-mix(in srgb, var(--sc-primary) 4%, var(--sc-surface)); }
    .risky-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--sc-muted); }
    .risky-dot.critical { background: var(--sc-critical); }
    .risky-dot.high { background: var(--sc-high); }
    .risky-dot.medium { background: var(--sc-medium); }
    .risky-dot.low { background: var(--sc-low); }
    .risky-copy { min-width: 0; }
    .risky-copy strong, .risky-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .risky-copy strong { color: var(--sc-text); font-size: 11.5px; font-family: var(--vscode-editor-font-family, monospace); }
    .risky-copy small { margin-top: 3px; color: var(--sc-muted); font-size: 9px; direction: rtl; text-align: left; }
    .risky-severity { padding: 3px 8px; border-radius: 999px; font-size: 8.5px; font-weight: 800; letter-spacing: .4px; color: var(--sc-muted); background: var(--sc-surface-soft); }
    .risky-severity.critical { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    .risky-severity.high { color: var(--sc-high); background: color-mix(in srgb, var(--sc-high) 14%, var(--sc-surface)); }
    .risky-severity.medium { color: var(--sc-medium); background: color-mix(in srgb, var(--sc-medium) 16%, var(--sc-surface)); }
    .risky-severity.low { color: var(--sc-low); background: color-mix(in srgb, var(--sc-low) 14%, var(--sc-surface)); }
    .risky-count { min-width: 20px; color: var(--sc-text); font-size: 12px; font-weight: 700; text-align: right; font-variant-numeric: tabular-nums; }

    /* ------------------------------------------------------------ pipeline */
    body.surface-full .pipeline-panel { margin-bottom: 22px; padding: 16px 14px 10px; }
    body.surface-full .pipeline { min-width: 640px; }
    body.surface-full .pipeline-stage { flex-basis: 82px; min-width: 72px; }
    body.surface-full .pipeline-stage strong { margin-top: 8px; color: var(--sc-text); font-size: 10.5px; }
    body.surface-full .pipeline-stage small { color: var(--sc-muted); font-size: 9px; }
    body.surface-full .pipeline-dot { width: 30px; height: 30px; border: 1.5px solid var(--sc-border); background: var(--sc-surface); font-size: 12px; }
    body.surface-full .pipeline-dot.completed { color: var(--sc-success); border-color: color-mix(in srgb, var(--sc-success) 45%, var(--sc-border)); background: color-mix(in srgb, var(--sc-success) 10%, var(--sc-surface)); }
    body.surface-full .pipeline-dot.running, body.surface-full .pipeline-dot.refreshing { color: var(--sc-primary); border-color: color-mix(in srgb, var(--sc-primary) 55%, var(--sc-border)); background: var(--sc-primary-soft); box-shadow: 0 0 0 5px color-mix(in srgb, var(--sc-primary) 9%, transparent); }
    body.surface-full .pipeline-dot.running::after, body.surface-full .pipeline-dot.refreshing::after { border-color: color-mix(in srgb, var(--sc-primary) 38%, transparent); }
    body.surface-full .pipeline-dot.failed { color: var(--sc-critical); border-color: color-mix(in srgb, var(--sc-critical) 50%, var(--sc-border)); background: color-mix(in srgb, var(--sc-critical) 10%, var(--sc-surface)); }
    body.surface-full .pipeline-dot.cancelled { color: var(--sc-medium); border-color: color-mix(in srgb, var(--sc-medium) 50%, var(--sc-border)); background: color-mix(in srgb, var(--sc-medium) 10%, var(--sc-surface)); }
    body.surface-full .pipeline-line { min-width: 28px; height: 2px; margin-top: 14px; border-radius: 2px; background: color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border)); }
    body.surface-full .pipeline-line.active { background: color-mix(in srgb, var(--sc-primary) 55%, var(--sc-border)); }
    body.surface-full .pipeline-popover { border-color: var(--sc-border); border-radius: var(--sc-radius-md); background: var(--sc-surface); box-shadow: var(--sc-shadow-sm); }
    body.surface-full .pipeline-retry { border-radius: var(--sc-radius-sm); background: var(--sc-primary); }

    /* ------------------------------------------------ scanners + activite */
    body.surface-full .overview-split { grid-template-columns: minmax(430px, 1.5fr) minmax(320px, .95fr); gap: 18px; margin: 0 0 22px; align-items: start; }
    body.surface-full .overview-split > .overview-panel { min-width: 0; }
    body.surface-full .overview-split > .overview-panel:first-child { max-height: 560px; overflow: auto; scrollbar-width: thin; scrollbar-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)) transparent; }
    body.surface-full .overview-split > .overview-panel:nth-child(2) { max-height: 560px; overflow: hidden; }
    body.surface-full .overview-scanner { grid-template-columns: 42px minmax(140px, 1.5fr) auto 54px 56px minmax(96px, .8fr) 22px; min-height: 50px; padding: 7px 6px; border-bottom: 1px solid color-mix(in srgb, var(--sc-border) 65%, transparent); border-radius: var(--sc-radius-md); font-size: 10.5px; transition: background-color .12s ease; }
    body.surface-full .overview-scanner:hover { color: var(--sc-text); background: var(--sc-surface-soft); }
    body.surface-full .scanner-logo { width: 38px; height: 38px; border: 1px solid var(--sc-border); color: var(--vscode-button-background); background: var(--vscode-button-foreground); }
    body.surface-full .scanner-logo.completed { border-color: color-mix(in srgb, var(--sc-success) 35%, var(--sc-border)); }
    body.surface-full .scanner-logo.failed { border-color: color-mix(in srgb, var(--sc-critical) 35%, var(--sc-border)); }
    body.surface-full .scanner-identity strong { color: var(--sc-text); font-size: 11px; }
    body.surface-full .scanner-identity small, body.surface-full .scanner-value small, body.surface-full .overview-scanner time { color: var(--sc-muted); font-size: 9px; }
    body.surface-full .scanner-ready { padding: 3px 9px; color: var(--sc-muted); background: var(--sc-surface-soft); font-size: 8.5px; font-weight: 800; letter-spacing: .4px; }
    body.surface-full .scanner-ready.completed { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 12%, var(--sc-surface)); }
    body.surface-full .scanner-ready.failed { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    body.surface-full .scanner-value strong { color: var(--sc-text); font-variant-numeric: tabular-nums; }
    body.surface-full .scanner-chevron { color: var(--sc-muted); }
    body.surface-full .overview-scanner:hover .scanner-chevron { color: var(--sc-primary); }

    body.surface-full .enterprise-summary { margin: 0 0 22px; }
    body.surface-full .enterprise-domain-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(188px, 1fr)); gap: 14px; margin-top: 14px; align-items: stretch; }
    body.surface-full .domain-card { position: relative; display: flex; flex-direction: column; gap: 14px; min-height: 178px; padding: 16px; border: 1px solid color-mix(in srgb, var(--sc-primary) 10%, var(--sc-border)); border-radius: 16px; background: linear-gradient(180deg, color-mix(in srgb, var(--sc-primary) 2%, transparent), transparent 42%), var(--sc-surface); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 6%, transparent), var(--sc-shadow-sm); overflow: hidden; transition: transform .14s ease, border-color .14s ease, box-shadow .14s ease; }
    body.surface-full .domain-card::before { content: ''; position: absolute; inset: 0 0 auto; height: 3px; background: color-mix(in srgb, var(--sc-primary) 52%, var(--sc-border)); box-shadow: 0 5px 14px color-mix(in srgb, var(--sc-primary) 12%, transparent); }
    body.surface-full .domain-card.ok::before { background: var(--sc-success); box-shadow: 0 5px 14px color-mix(in srgb, var(--sc-success) 13%, transparent); }
    body.surface-full .domain-card.warn::before { background: var(--sc-medium); box-shadow: 0 5px 14px color-mix(in srgb, var(--sc-medium) 14%, transparent); }
    body.surface-full .domain-card.bad::before { background: var(--sc-critical); box-shadow: 0 5px 14px color-mix(in srgb, var(--sc-critical) 13%, transparent); }
    body.surface-full .domain-card.muted::before { background: color-mix(in srgb, var(--sc-muted) 50%, var(--sc-border)); }
    body.surface-full .domain-card:hover { transform: translateY(-1px); border-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 7%, transparent), 0 16px 34px color-mix(in srgb, var(--sc-primary) 10%, transparent); }
    body.surface-full .domain-card-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
    body.surface-full .domain-icon { display: grid; place-items: center; width: 36px; height: 36px; border: 1px solid color-mix(in srgb, var(--sc-primary) 24%, var(--sc-border)); border-radius: 12px; color: var(--sc-primary); background: var(--sc-primary-soft); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 10%, transparent); }
    body.surface-full .domain-card.ok .domain-icon { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 10%, var(--sc-surface)); border-color: color-mix(in srgb, var(--sc-success) 28%, var(--sc-border)); }
    body.surface-full .domain-card.warn .domain-icon { color: var(--sc-medium); background: color-mix(in srgb, var(--sc-medium) 12%, var(--sc-surface)); border-color: color-mix(in srgb, var(--sc-medium) 30%, var(--sc-border)); }
    body.surface-full .domain-card.bad .domain-icon { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 10%, var(--sc-surface)); border-color: color-mix(in srgb, var(--sc-critical) 30%, var(--sc-border)); }
    body.surface-full .domain-card.muted .domain-icon { color: var(--sc-muted); background: var(--sc-surface-soft); border-color: var(--sc-border); }
    body.surface-full .domain-icon .compact-icon { width: 18px; height: 18px; stroke-width: 1.9; }
    body.surface-full .domain-card-head strong { display: inline-flex; align-items: center; gap: 6px; max-width: 62%; padding: 3px 7px; border: 1px solid color-mix(in srgb, var(--sc-border) 68%, transparent); border-radius: 999px; color: var(--sc-muted); background: color-mix(in srgb, var(--sc-surface-soft) 62%, transparent); font-size: 9px; font-weight: 900; text-transform: uppercase; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    body.surface-full .domain-card-body > span { display: block; color: var(--sc-muted); font-size: 9px; font-weight: 900; letter-spacing: .65px; text-transform: uppercase; }
    body.surface-full .domain-card-body { min-width: 0; }
    body.surface-full .domain-card-body strong { display: block; margin-top: 8px; color: var(--sc-text); font-size: 18px; line-height: 1.15; overflow-wrap: anywhere; }
    body.surface-full .domain-card-body p { margin: 7px 0 0; color: var(--sc-muted); font-size: 11px; line-height: 1.4; }
    body.surface-full .domain-card button { align-self: flex-start; margin-top: auto; min-height: 32px; padding: 7px 12px; border: 1px solid color-mix(in srgb, var(--sc-primary) 32%, var(--sc-border)); border-radius: 10px; color: var(--sc-primary); background: var(--sc-primary-soft); font-size: 10px; font-weight: 900; cursor: pointer; transition: transform .14s ease, background-color .12s ease, border-color .12s ease; }
    body.surface-full .domain-card button:active { transform: translateY(1px); }
    body.surface-full .domain-card:hover .domain-cta { transform: translateX(2px); border-color: color-mix(in srgb, var(--sc-primary) 46%, var(--sc-border)); background: color-mix(in srgb, var(--sc-primary) 17%, var(--sc-surface)); }
    body.surface-full .enterprise-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--sc-muted); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-muted) 14%, transparent); }
    body.surface-full .enterprise-dot.ok { background: var(--sc-success); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-success) 16%, transparent); }
    body.surface-full .enterprise-dot.warn { background: var(--sc-medium); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-medium) 16%, transparent); }
    body.surface-full .enterprise-dot.bad { background: var(--sc-critical); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-critical) 16%, transparent); }

    body.surface-full .activity-summary { gap: 9px; }
    body.surface-full .activity-summary .activity-stat { min-height: 52px; padding: 9px 4px; border-top: 0; border-radius: var(--sc-radius-md); background: var(--sc-surface-soft); }
    body.surface-full .activity-stat strong { color: var(--sc-text); font-size: 19px; font-variant-numeric: tabular-nums; }
    body.surface-full .activity-stat span { color: var(--sc-muted); font-size: 8.5px; font-weight: 700; letter-spacing: .3px; }
    /* « Corrigee », « validee » et « acceptee » restent trois etats distincts :
       une couleur commune laisserait croire a un seul resultat. */
    body.surface-full .activity-summary .activity-stat.resolved strong { color: var(--sc-medium); }
    body.surface-full .activity-summary .activity-stat.validated strong { color: var(--sc-success); }
    body.surface-full .activity-summary .activity-stat.accepted strong { color: var(--sc-muted); }
    body.surface-full .activity-footer { border-top: 1px solid var(--sc-border); }
    body.surface-full .activity-col-title { color: var(--sc-muted); }
    body.surface-full .activity-col-val { color: var(--sc-text); }

    /* --------------------------------------------------- alertes prioritaires */
    body.surface-full .priority-findings { gap: 8px; margin-bottom: 24px; }
    body.surface-full .priority-finding { min-height: 52px; padding: 11px 13px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-lg); background: var(--sc-surface); box-shadow: var(--sc-shadow-sm); transition: border-color .12s ease, background-color .12s ease; }
    body.surface-full .priority-finding:hover { border-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)); background: var(--sc-surface); }
    body.surface-full .priority-finding strong { color: var(--sc-text); font-size: 11.5px; }
    body.surface-full .priority-finding span { color: var(--sc-muted); }
    body.surface-full .priority-severity { display: inline-block; margin-bottom: 4px; padding: 2px 7px; border-radius: 999px; font-size: 8.5px; font-weight: 800; letter-spacing: .4px; }
    body.surface-full .priority-finding.danger .priority-severity { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    body.surface-full .priority-finding.warning .priority-severity { color: var(--sc-high); background: color-mix(in srgb, var(--sc-high) 14%, var(--sc-surface)); }
    body.surface-full .priority-finding .finding-open { padding: 6px 11px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); color: var(--sc-primary); background: var(--sc-surface); font-size: 10px; }
    body.surface-full .priority-finding .finding-open:hover { border-color: color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border)); background: var(--sc-primary-soft); }

    /* -------------------------------------------- fix & verify / chronologie */
    body.surface-full .overview-lower { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, .9fr); gap: 14px; margin-bottom: 26px; align-items: start; }
    .verify-tiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-bottom: 13px; }
    .verify-tile { padding: 9px 10px; border: 1px solid color-mix(in srgb, var(--sc-primary) 7%, var(--sc-border)); border-radius: var(--sc-radius-md); background: linear-gradient(180deg, color-mix(in srgb, var(--sc-surface) 74%, transparent), var(--sc-surface-soft)); }
    .verify-tile strong, .verify-tile span { display: block; }
    .verify-tile strong { color: var(--sc-text); font-size: 17px; line-height: 1; font-variant-numeric: tabular-nums; }
    .verify-tile span { margin-top: 5px; color: var(--sc-muted); font-size: 8.5px; font-weight: 700; letter-spacing: .3px; text-transform: uppercase; }
    .verify-tile.critical strong { color: var(--sc-critical); }
    .verify-tile.high strong { color: var(--sc-high); }
    .verify-tile.medium strong { color: var(--sc-medium); }
    .verify-tile.low strong { color: var(--sc-low); }
    .verify-latest { padding: 12px; border: 1px solid var(--sc-border); border-left: 3px solid var(--sc-border); border-radius: var(--sc-radius-md); background: var(--sc-surface); }
    .verify-latest.critical { border-left-color: var(--sc-critical); }
    .verify-latest.high { border-left-color: var(--sc-high); }
    .verify-latest.medium { border-left-color: var(--sc-medium); }
    .verify-latest.low { border-left-color: var(--sc-low); }
    .verify-latest strong, .verify-latest small, .verify-meta { display: block; overflow-wrap: anywhere; }
    .verify-latest strong { margin-top: 7px; color: var(--sc-text); font-size: 11.5px; line-height: 1.35; }
    .verify-latest small { margin-top: 4px; color: var(--sc-muted); font-size: 10px; font-family: var(--vscode-editor-font-family, monospace); }
    .verify-meta { margin-top: 7px; color: var(--sc-muted); font-size: 9.5px; }
    .verify-state { display: inline-block; padding: 3px 9px; border-radius: 999px; color: var(--sc-muted); background: var(--sc-surface-soft); font-size: 8.5px; font-weight: 800; letter-spacing: .3px; text-transform: uppercase; }
    .verify-state.validated { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 12%, var(--sc-surface)); }
    .verify-state.fixed, .verify-state.validating { color: var(--sc-medium); background: color-mix(in srgb, var(--sc-medium) 15%, var(--sc-surface)); }
    .verify-state.still_present, .verify-state.regressed { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    .verify-state.inconclusive, .verify-state.validation_failed { color: var(--sc-high); background: color-mix(in srgb, var(--sc-high) 14%, var(--sc-surface)); }
    .verify-timeline { display: grid; gap: 0; margin: 0; padding: 0; list-style: none; }
    .verify-event { position: relative; display: grid; grid-template-columns: 18px minmax(0, 1fr); align-items: start; gap: 9px; padding: 0 0 14px; }
    .verify-event:last-child { padding-bottom: 0; }
    .verify-event::before { content: ''; position: absolute; top: 14px; bottom: 0; left: 5px; width: 1px; background: var(--sc-border); }
    .verify-event:last-child::before { display: none; }
    .verify-dot { position: relative; z-index: 1; width: 9px; height: 9px; margin-top: 4px; border-radius: 50%; background: var(--sc-muted); box-shadow: 0 0 0 3px var(--sc-surface); }
    .verify-event.critical .verify-dot { background: var(--sc-critical); }
    .verify-event.high .verify-dot { background: var(--sc-high); }
    .verify-event.medium .verify-dot { background: var(--sc-medium); }
    .verify-event.low .verify-dot { background: var(--sc-low); }
    .verify-event strong, .verify-event time { display: block; }
    .verify-event strong { color: var(--sc-text); font-size: 10.5px; font-weight: 600; line-height: 1.35; }
    .verify-event time { margin-top: 2px; color: var(--sc-muted); font-size: 9px; }

    /* ------------------------------------------------------- rail droit */
    .sc-rail-card { padding: 14px; border: 1px solid color-mix(in srgb, var(--sc-primary) 10%, var(--sc-border)); border-radius: var(--sc-radius-lg); background: linear-gradient(145deg, color-mix(in srgb, var(--sc-primary) 2%, transparent), transparent 40%), var(--sc-surface); box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 6%, transparent), var(--sc-shadow-sm); }
    .sc-rail-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px 8px; margin-bottom: 10px; }
    .sc-rail-head strong { color: var(--sc-text); font-size: 11px; font-weight: 700; }
    .sc-rail-pill, .sc-companion-state { flex: none; max-width: 100%; padding: 3px 8px; border-radius: 999px; color: var(--sc-muted); background: var(--sc-surface-soft); font-size: 8px; font-weight: 700; letter-spacing: .3px; text-transform: uppercase; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-rail-pill.completed, .sc-rail-pill.online { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 12%, var(--sc-surface)); }
    .sc-rail-pill.failed, .sc-rail-pill.offline { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    .sc-rail-pill.running { color: var(--sc-primary); background: var(--sc-primary-soft); }
    .sc-companion-state.clean { color: var(--sc-success); background: color-mix(in srgb, var(--sc-success) 12%, var(--sc-surface)); }
    .sc-companion-state.findings, .sc-companion-state.error { color: var(--sc-critical); background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface)); }
    .sc-companion-state.analyzing { color: var(--sc-primary); background: var(--sc-primary-soft); }
    .sc-rail-live { border-color: color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border)); background: radial-gradient(circle at 90% 0, color-mix(in srgb, var(--sc-primary) 13%, transparent), transparent 38%), linear-gradient(180deg, var(--sc-primary-soft), var(--sc-surface) 58%); }
    .sc-companion-line { margin: 0 0 11px; color: var(--sc-text); font-size: 10.5px; line-height: 1.5; }
    .sc-rail-facts { display: grid; gap: 7px; }
    .sc-rail-fact { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; font-size: 10px; }
    .sc-rail-fact span { color: var(--sc-muted); }
    .sc-rail-fact strong { min-width: 0; color: var(--sc-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-rail-sev.critical { color: var(--sc-critical); }
    .sc-rail-sev.high { color: var(--sc-high); }
    .sc-rail-sev.medium { color: var(--sc-medium); }
    .sc-rail-sev.low { color: var(--sc-low); }
    .sc-rail-link { width: 100%; margin-top: 12px; padding: 7px 10px; border: 1px solid color-mix(in srgb, var(--sc-primary) 26%, var(--sc-border)); border-radius: var(--sc-radius-md); color: var(--sc-primary); background: var(--sc-surface); font-size: 10px; font-weight: 700; text-align: center; transition: transform .14s ease, background-color .12s ease, border-color .12s ease; }
    .sc-rail-link:hover { transform: translateY(-1px); background: var(--sc-primary-soft); }
    .sc-rail-link:active { transform: translateY(0); }
    .sc-rail-actions { display: grid; gap: 5px; }
    .sc-rail-action { display: grid; grid-template-columns: 16px minmax(0, 1fr) auto; align-items: center; gap: 8px; width: 100%; min-height: 28px; padding: 6px 8px; border: 1px solid transparent; border-radius: var(--sc-radius-sm); color: var(--sc-text); background: var(--sc-surface); font-size: 10.5px; font-weight: 600; text-align: left; transition: transform .14s ease, background-color .12s ease, border-color .12s ease, color .12s ease; }
    .sc-rail-action span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-rail-action-icon { display: grid; place-items: center; width: 16px; height: 16px; color: var(--sc-primary); font-size: 10px; }
    .sc-rail-action small { justify-self: end; min-width: 18px; padding: 1px 6px; border-radius: 999px; color: var(--sc-primary); background: var(--sc-primary-soft); font-size: 9px; font-weight: 800; text-align: center; }
    .sc-rail-action:hover:not(:disabled) { transform: translateY(-1px); color: var(--sc-primary); border-color: color-mix(in srgb, var(--sc-primary) 30%, var(--sc-border)); background: var(--sc-primary-soft); }
    .sc-rail-action:active:not(:disabled) { transform: translateY(0); }
    .sc-rail-action.primary { color: var(--vscode-button-foreground); border-color: transparent; background: var(--sc-primary); }
    .sc-rail-action.primary .sc-rail-action-icon { color: currentColor; }
    .sc-rail-action.primary:hover:not(:disabled) { color: var(--vscode-button-foreground); background: var(--sc-primary-hover); }
    .sc-companion-rail .sc-context-card { padding: 14px; box-shadow: var(--sc-shadow-sm); }
    .sc-companion-rail .sc-context-card span { margin-top: 0; color: var(--sc-muted); font-size: 10px; }
    .sc-companion-rail .sc-context-card small { margin-top: 7px; color: var(--sc-muted); font-weight: 600; }

    /* ------------------------------------------------------------ divers */
    body.surface-full .policy-banner { border-radius: var(--sc-radius-lg); }
    body.surface-full .failure-diagnostics { border-radius: var(--sc-radius-lg); }
    body.surface-full button { transition: background-color .12s ease, border-color .12s ease, color .12s ease; }
    body.surface-full button:focus-visible,
    body.surface-full [tabindex]:focus-visible { outline: 2px solid var(--sc-primary); outline-offset: 2px; }
    body.surface-full code,
    body.surface-full pre,
    body.surface-full .finding-location,
    body.surface-full .dynamic-source code,
    body.surface-full .traffic-row strong { font-family: var(--vscode-editor-font-family, monospace); }
    /* ------------------------------------------------------------ scans */
    body.surface-scans .sc-topbar {
      background: color-mix(in srgb, var(--sc-surface) 96%, transparent);
    }
    body.surface-scans .operational-banner,
    body.surface-scans .pipeline-panel,
    body.surface-scans .zap-execution-card,
    body.surface-scans .page-scans,
    body.surface-scans .scan-execution-summary {
      border: 1px solid color-mix(in srgb, var(--sc-primary) 14%, var(--sc-border));
      border-radius: 17px;
      background: color-mix(in srgb, var(--sc-surface) 97%, transparent);
      box-shadow: 0 18px 42px color-mix(in srgb, var(--sc-primary) 9%, transparent), var(--sc-shadow-sm);
      backdrop-filter: blur(8px);
    }
    body.surface-scans .operational-banner { margin-bottom: 14px; }
    body.surface-scans .scan-execution-summary {
      display: grid;
      grid-template-columns: minmax(180px, .62fr) minmax(0, 1.38fr);
      gap: 14px;
      align-items: center;
      margin: 0 0 14px;
      padding: 14px 16px;
    }
    body.surface-scans .scan-summary-copy span,
    body.surface-scans .scan-summary-stat span,
    body.surface-scans .scan-section-head span {
      display: block;
      color: var(--sc-primary);
      font-size: 9px;
      font-weight: 900;
      letter-spacing: .7px;
      text-transform: uppercase;
    }
    body.surface-scans .scan-summary-copy strong {
      display: block;
      margin-top: 5px;
      color: var(--sc-text);
      font-size: 15px;
    }
    body.surface-scans .scan-summary-metrics {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
    }
    body.surface-scans .scan-summary-stat {
      padding: 10px 11px;
      border: 1px solid var(--sc-border);
      border-left: 3px solid var(--sc-primary);
      border-radius: var(--sc-radius-md);
      background: var(--sc-surface-soft);
    }
    body.surface-scans .scan-summary-stat strong {
      display: block;
      margin-top: 4px;
      color: var(--sc-text);
      font-size: 22px;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }
    body.surface-scans .scan-summary-stat.success { border-left-color: var(--sc-success); }
    body.surface-scans .scan-summary-stat.failed { border-left-color: var(--sc-critical); }
    body.surface-scans .scan-summary-stat.waiting { border-left-color: var(--sc-muted); }
    body.surface-scans .scan-summary-stat.dynamic { border-left-color: var(--sc-primary); }
    body.surface-scans .scans-section-title,
    body.surface-scans .page-scans h3 {
      margin: 0;
      color: var(--sc-text);
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: none;
    }
    body.surface-scans .scans-section-title {
      margin: 14px 0 8px;
    }
    body.surface-scans .pipeline-panel {
      padding: 16px 14px 12px;
      margin-bottom: 14px;
    }
    body.surface-scans .pipeline-scroll {
      scrollbar-width: thin;
      scrollbar-color: color-mix(in srgb, var(--sc-primary) 25%, transparent) transparent;
    }
    body.surface-scans .pipeline-scroll::-webkit-scrollbar { height: 7px; }
    body.surface-scans .pipeline-scroll::-webkit-scrollbar-track { background: transparent; }
    body.surface-scans .pipeline-scroll::-webkit-scrollbar-thumb {
      border-radius: 999px;
      background: color-mix(in srgb, var(--sc-primary) 25%, transparent);
    }
    body.surface-scans .pipeline-scroll::-webkit-scrollbar-thumb:hover {
      background: color-mix(in srgb, var(--sc-primary) 42%, transparent);
    }
    body.surface-scans .pipeline {
      min-width: 0;
      width: 100%;
    }
    body.surface-scans .pipeline-stage { flex: 0 1 92px; }
    body.surface-scans .pipeline-stage strong { color: var(--sc-text); }
    body.surface-scans .pipeline-stage small { color: var(--sc-muted); }
    body.surface-scans .pipeline-line {
      min-width: 22px;
      border-radius: 2px;
      background: color-mix(in srgb, var(--sc-primary) 20%, var(--sc-border));
    }
    body.surface-scans .pipeline-line.active {
      background: color-mix(in srgb, var(--sc-primary) 42%, var(--sc-border));
    }
    body.surface-scans .pipeline-dot {
      border-color: var(--sc-border);
      background: var(--sc-surface);
    }
    body.surface-scans .pipeline-dot.completed {
      color: var(--sc-success);
      border-color: color-mix(in srgb, var(--sc-success) 50%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-success) 11%, var(--sc-surface));
    }
    body.surface-scans .pipeline-dot.failed {
      color: var(--sc-critical);
      border-color: color-mix(in srgb, var(--sc-critical) 58%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-critical) 12%, var(--sc-surface));
    }
    body.surface-scans .pipeline-dot.running,
    body.surface-scans .pipeline-dot.refreshing {
      color: var(--sc-primary);
      border-color: color-mix(in srgb, var(--sc-primary) 58%, var(--sc-border));
      background: var(--sc-primary-soft);
    }
    body.surface-scans .pipeline-popover {
      border-color: color-mix(in srgb, var(--sc-primary) 14%, var(--sc-border));
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
    }
    body.surface-scans .zap-execution-card {
      grid-template-columns: minmax(170px, .55fr) minmax(0, 1fr) auto;
      gap: 16px;
      align-items: center;
      margin: 14px 0;
      padding: 15px 16px;
    }
    body.surface-scans .zap-execution-card.completed {
      border-color: color-mix(in srgb, var(--sc-success) 28%, var(--sc-border));
    }
    body.surface-scans .zap-execution-card.failed {
      border-color: color-mix(in srgb, var(--sc-critical) 34%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-critical) 5%, var(--sc-surface));
    }
    body.surface-scans .zap-title-row {
      display: flex;
      align-items: center;
      gap: 11px;
      margin-top: 7px;
    }
    body.surface-scans .zap-title-row h4,
    body.surface-scans .zap-title-row p {
      margin: 0;
    }
    body.surface-scans .zap-title-row h4 {
      color: var(--sc-text);
      font-size: 16px;
    }
    body.surface-scans .zap-title-row p {
      margin-top: 2px;
      color: var(--sc-muted);
      font-size: 10px;
    }
    body.surface-scans .zap-execution-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      min-width: 0;
    }
    body.surface-scans .zap-execution-fact {
      min-width: 0;
      padding: 9px 10px;
      border: 1px solid var(--sc-border);
      border-radius: var(--sc-radius-md);
      background: var(--sc-surface-soft);
    }
    body.surface-scans .zap-execution-fact.target {
      grid-column: span 2;
    }
    body.surface-scans .zap-execution-fact span,
    body.surface-scans .zap-execution-fact strong,
    body.surface-scans .zap-execution-fact small {
      display: block;
      overflow-wrap: anywhere;
    }
    body.surface-scans .zap-execution-fact span {
      color: var(--sc-muted);
      font-size: 9px;
      font-weight: 800;
      letter-spacing: .55px;
      text-transform: uppercase;
    }
    body.surface-scans .zap-execution-fact strong {
      margin-top: 4px;
      color: var(--sc-text);
      font-size: 14px;
      font-variant-numeric: tabular-nums;
    }
    body.surface-scans .zap-execution-fact small,
    body.surface-scans .zap-execution-error {
      margin-top: 3px;
      color: var(--sc-muted);
      font-size: 9px;
    }
    body.surface-scans .zap-execution-error {
      grid-column: 1 / -1;
      margin: 0;
      color: var(--sc-critical);
    }
    body.surface-scans .zap-meta {
      justify-items: end;
      align-self: stretch;
      align-content: center;
      gap: 7px;
    }
    body.surface-scans .zap-meta button,
    body.surface-scans .scan-row-actions button {
      width: auto;
      min-height: 28px;
      padding: 6px 9px;
      border-radius: var(--sc-radius-sm);
      color: var(--sc-primary);
      border-color: color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border));
      background: var(--sc-primary-soft);
      font-size: 10px;
      font-weight: 800;
    }
    body.surface-scans .page-scans {
      display: grid;
      gap: 0;
      padding: 15px 16px;
      margin-top: 14px;
    }
    body.surface-scans .scan-section-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 11px;
      padding-bottom: 11px;
      border-bottom: 1px solid color-mix(in srgb, var(--sc-primary) 12%, var(--sc-border));
    }
    body.surface-scans .scan-section-head small {
      color: var(--sc-muted);
      font-size: 10px;
    }
    body.surface-scans .scan-scanner-list {
      display: grid;
      gap: 8px;
    }
    body.surface-scans .scan-scanner-row {
      grid-template-columns: 42px minmax(150px, 1.15fr) minmax(160px, 1fr) 70px 70px minmax(118px, .72fr) auto auto 24px;
      min-height: 64px;
      padding: 10px 11px;
      border: 1px solid color-mix(in srgb, var(--sc-border) 78%, transparent);
      border-radius: var(--sc-radius-lg);
      background: var(--sc-surface);
      box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 5%, transparent);
      transition: transform .14s ease, border-color .14s ease, background-color .14s ease, box-shadow .14s ease;
    }
    body.surface-scans .scan-scanner-row:hover {
      transform: translateY(-1px);
      border-color: color-mix(in srgb, var(--sc-primary) 26%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-primary) 4%, var(--sc-surface));
      box-shadow: 0 12px 26px color-mix(in srgb, var(--sc-primary) 7%, transparent);
    }
    body.surface-scans .scan-scanner-row.disabled:hover {
      transform: none;
      border-color: var(--sc-border);
      box-shadow: inset 0 1px 0 color-mix(in srgb, var(--sc-primary) 5%, transparent);
    }
    body.surface-scans .scanner-logo {
      width: 38px;
      height: 38px;
      border-color: var(--sc-border);
      background: var(--sc-surface-soft);
    }
    body.surface-scans .scanner-identity strong {
      color: var(--sc-text);
      font-size: 12px;
    }
    body.surface-scans .scanner-identity small {
      color: var(--sc-muted);
      font-size: 9.5px;
      line-height: 1.35;
    }
    body.surface-scans .scan-row-error {
      color: var(--sc-critical) !important;
    }
    body.surface-scans .scanner-result-summary {
      color: var(--sc-text);
      font-size: 11px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    body.surface-scans .scanner-result-summary.failed {
      color: var(--sc-critical);
    }
    body.surface-scans .scanner-value {
      min-width: 0;
      text-align: left;
    }
    body.surface-scans .scanner-value strong {
      color: var(--sc-text);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
    }
    body.surface-scans .scanner-value small,
    body.surface-scans .overview-scanner time {
      color: var(--sc-muted);
      font-size: 9px;
    }
    body.surface-scans .scan-status-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 24px;
      padding: 4px 9px;
      border: 1px solid var(--sc-border);
      border-radius: 999px;
      color: var(--sc-muted);
      background: var(--sc-surface-soft);
      font-size: 8.5px;
      font-weight: 900;
      letter-spacing: .45px;
      text-transform: uppercase;
      white-space: nowrap;
    }
    body.surface-scans .scan-status-chip.completed {
      color: var(--sc-success);
      border-color: color-mix(in srgb, var(--sc-success) 28%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-success) 11%, var(--sc-surface));
    }
    body.surface-scans .scan-status-chip.failed {
      color: var(--sc-critical);
      border-color: color-mix(in srgb, var(--sc-critical) 32%, var(--sc-border));
      background: color-mix(in srgb, var(--sc-critical) 11%, var(--sc-surface));
    }
    body.surface-scans .scan-status-chip.running,
    body.surface-scans .scan-status-chip.refreshing {
      color: var(--sc-primary);
      border-color: color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border));
      background: var(--sc-primary-soft);
    }
    body.surface-scans .scan-row-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      justify-content: flex-end;
    }
    body.surface-scans .scanner-chevron {
      color: var(--sc-muted);
      opacity: .72;
      transition: color .14s ease, opacity .14s ease, transform .14s ease;
    }
    body.surface-scans .scan-scanner-row:hover .scanner-chevron {
      color: var(--sc-primary);
      opacity: 1;
      transform: translateX(1px);
    }
    @media (max-width: 1100px) {
      body.surface-scans .scan-execution-summary,
      body.surface-scans .zap-execution-card { grid-template-columns: 1fr; }
      body.surface-scans .scan-summary-metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      body.surface-scans .pipeline { min-width: 760px; }
      body.surface-scans .zap-meta { justify-items: start; }
      body.surface-scans .scan-scanner-row {
        grid-template-columns: 42px minmax(150px, 1fr) minmax(140px, 1fr) auto 24px;
      }
      body.surface-scans .scan-scanner-row .scanner-value,
      body.surface-scans .scan-scanner-row time,
      body.surface-scans .scan-row-actions {
        grid-column: 2 / -2;
      }
      body.surface-scans .scan-row-actions { justify-content: flex-start; }
    }
    @media (max-width: 680px) {
      body.surface-scans .scan-summary-metrics,
      body.surface-scans .zap-execution-grid { grid-template-columns: 1fr; }
      body.surface-scans .zap-execution-fact.target { grid-column: auto; }
      body.surface-scans .scan-scanner-row {
        grid-template-columns: 38px minmax(0, 1fr) auto;
        align-items: start;
      }
      body.surface-scans .scan-scanner-row .scanner-result-summary,
      body.surface-scans .scan-scanner-row .scanner-value,
      body.surface-scans .scan-scanner-row time,
      body.surface-scans .scan-row-actions {
        grid-column: 2 / -1;
      }
      body.surface-scans .scan-status-chip { grid-column: 3; grid-row: 1; }
      body.surface-scans .scanner-chevron { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      body.surface-scans .scan-scanner-row,
      body.surface-scans .scanner-chevron { transition: none; }
      body.surface-scans .scan-scanner-row:hover,
      body.surface-scans .scan-scanner-row:hover .scanner-chevron { transform: none; }
    }
    body.surface-sidebar { padding: 12px; }
    body.surface-sidebar h2 { font-size: 20px; font-weight: 650; }
    body.surface-sidebar .workspace { font-size: 12px; }
    body.surface-sidebar .action-group { padding: 9px; border-radius: 8px; }
    body.surface-sidebar .action-group-title { margin-bottom: 6px; font-size: 9px; }
    body.surface-sidebar .action-group-buttons { gap: 5px; }
    body.surface-sidebar .action-group-buttons button { padding: 7px 9px; font-size: 11px; }
    @media (max-width: 1200px) {
      body.surface-full .security-center-hero { grid-template-columns: 1fr; }
      body.surface-full .security-hero-copy { grid-template-columns: minmax(126px, 150px) minmax(0, 1fr); }
      body.surface-full .overview-triple { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      body.surface-full .enterprise-domain-grid { grid-template-columns: repeat(3, minmax(188px, 1fr)); }
    }
    @media (max-width: 980px) {
      .sc-topbar { padding: 13px 16px; }
      body.surface-full .hero-metric-panel { min-height: 0; }
      body.surface-full .hero-severity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      body.surface-full .hero-operations-grid { grid-template-columns: 1fr; gap: 14px; }
      body.surface-full .hero-operations-grid .overview-kpi + .overview-kpi { padding: 14px 0 0; border-left: 0; border-top: 1px solid color-mix(in srgb, var(--sc-border) 66%, transparent); }
      body.surface-full .overview-split { grid-template-columns: 1fr; }
      body.surface-full .overview-split > .overview-panel:first-child,
      body.surface-full .overview-split > .overview-panel:nth-child(2) { max-height: none; overflow: visible; }
      body.surface-full .overview-triple { grid-template-columns: 1fr; }
      body.surface-full .overview-triple > .overview-panel { min-height: 0; }
      body.surface-full .overview-lower { grid-template-columns: 1fr; }
      body.surface-full .enterprise-domain-grid { grid-template-columns: repeat(2, minmax(188px, 1fr)); }
    }
    @media (max-width: 680px) {
      .sc-main { padding: 16px; }
      .sc-topbar { grid-template-columns: 1fr; align-items: stretch; gap: 11px; margin: 0 0 16px; padding: 12px 14px; }
      .sc-topbar-actions { justify-content: flex-start; }
      .header-actions { flex-wrap: wrap; }
      body.surface-full .security-center-hero { padding: 16px; border-radius: 18px; }
      body.surface-full .hero { grid-template-columns: 1fr; justify-items: start; }
      .security-product-mark { width: 128px; }
      .security-shield { width: 104px; height: 104px; border-radius: 28px; }
      .security-shield .compact-icon { width: 54px; height: 54px; }
      body.surface-full .risk-ring { width: 62px; }
      body.surface-full .hero-metric-panel { padding: 14px; }
      body.surface-full .posture-header { align-items: flex-start; flex-direction: column; gap: 8px; }
      body.surface-full .hero-severity-grid { grid-template-columns: 1fr; gap: 10px; }
      body.surface-full .overview-kpi > strong { font-size: 30px; }
      body.surface-full .enterprise-domain-grid { grid-template-columns: 1fr; }
      body.surface-full .overview-scanner { grid-template-columns: 28px minmax(110px, 1fr) auto 48px 22px; }
      body.surface-full .overview-scanner .scanner-value:nth-of-type(4), body.surface-full .overview-scanner time { display: none; }
      .finding-card-header { grid-template-columns: auto minmax(0, 1fr) auto; }
      .finding-card-meta, .finding-card-file-line { grid-column: 2 / -1; }
      .sev-donut { grid-template-columns: 1fr; justify-items: center; }
      .verify-tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      body.surface-full .recent-scan { grid-template-columns: 8px minmax(0, 1fr); grid-template-areas: 'dot name' 'dot time'; }
      body.surface-full .recent-status { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      body.surface-full button,
      body.surface-full .overview-scanner,
      body.surface-full .overview-panel,
      body.surface-full .pipeline-panel,
      body.surface-full .overview-panel-head button,
      body.surface-full .risky-target,
      body.surface-full .domain-card,
      body.surface-full .domain-cta,
      body.surface-full .scanner-finding-card,
      body.surface-full .expand-chevron { transition: none; }
      body.surface-full .overview-panel:hover,
      body.surface-full .pipeline-panel:hover,
      body.surface-full .overview-panel-head button:hover,
      body.surface-full .domain-card:hover,
      body.surface-full .domain-card:hover .domain-cta,
      body.surface-full .scanner-finding-card:hover { transform: none; }
    }
    @media (min-width: 760px) {
      body { padding: 28px; }
      .cards { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .http-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .action-sections { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .action-group-buttons { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .analytics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .findings-hero { grid-template-columns: minmax(320px, .9fr) minmax(520px, 1.1fr); align-items: center; }
      .finding-filters { grid-template-columns: minmax(240px, 2fr) repeat(5, minmax(124px, 1fr)) auto; align-items: end; }
      .finding-card { grid-template-columns: 4px auto minmax(0, 1fr) auto auto; align-items: center; }
      .finding-card-actions { grid-column: 5; grid-row: 1; justify-self: end; }
      .finding-layout { grid-template-columns: minmax(0, 1.55fr) minmax(270px, .75fr); align-items: start; }
      .finding-preview { display: block; }
      .workflow { grid-template-columns: repeat(5, minmax(0, 1fr)); }
      .workflow-step { grid-template-columns: 1fr; min-height: 130px; }
      .workflow-number { margin-bottom: 5px; }
      .overview-kpis { grid-template-columns: repeat(4, minmax(0,1fr)); }
    }
    ${model.dynamicWorkspace ? dynamicSectionsCss() : ''}
    ${companionPresence ? companionWidgetCss() : ''}
    ${assistantCard ? assistantCardCss() : ''}
    /* Scanner Details UI */
    .page-scanner-details {
      padding: 0;
      color: var(--sc-text);
    }
    .scanner-detail-hero {
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-columns: minmax(0,1fr) auto;
      gap: 18px;
      align-items: center;
      margin-bottom: 18px;
      padding: 22px;
      border: 1px solid var(--sc-border);
      border-radius: 18px;
      background: linear-gradient(135deg, color-mix(in srgb, var(--sc-primary) 8%, var(--sc-surface)), var(--sc-surface));
      box-shadow: var(--sc-shadow-sm);
    }
    .scanner-detail-watermark {
      position: absolute;
      right: 26px;
      bottom: -18px;
      display: flex;
      gap: 18px;
      opacity: .035;
      color: var(--sc-primary);
      transform: scale(5);
      pointer-events: none;
    }
    .scanner-header-identity {
      display: flex;
      align-items: center;
      gap: 14px;
      position: relative;
      z-index: 1;
    }
    .scanner-header-identity .scanner-logo {
      width: 58px;
      height: 58px;
      border-radius: 16px;
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
    }
    .scanner-header-identity .scanner-logo-img {
      width: 42px;
      height: 42px;
    }
    .scanner-header-identity .scanner-logo[data-scanner-logo="semgrep"] .scanner-logo-img,
    .scanner-header-identity .scanner-logo[data-scanner-logo="osv"] .scanner-logo-img {
      width: 38px;
      height: 26px;
    }
    .scanner-header-desc {
      margin: 4px 0 0;
      color: var(--sc-muted);
      font-size: 13px;
    }
    .scanner-eyebrow {
      color: var(--sc-primary);
      font-size: 10px;
      font-weight: 900;
      letter-spacing: .8px;
      text-transform: uppercase;
    }
    .scanner-header-identity h1 {
      margin: 3px 0 0;
      color: var(--sc-text);
      font-size: 28px;
      letter-spacing: 0;
    }
    .scanner-hero-status {
      position: relative;
      z-index: 1;
      display: grid;
      justify-items: end;
      gap: 4px;
      min-width: 150px;
      padding: 12px;
      border: 1px solid var(--sc-border);
      border-radius: 14px;
      background: color-mix(in srgb, var(--sc-surface) 84%, transparent);
    }
    .scanner-hero-status strong {
      font-size: 28px;
      line-height: 1;
    }
    .scanner-hero-status small {
      color: var(--sc-muted);
      font-size: 10px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .scanner-meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(128px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }
    .meta-item {
      padding: 12px;
      border: 1px solid var(--sc-border);
      border-radius: 12px;
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
    }
    .meta-item span {
      display: block;
      font-size: 11px;
      color: var(--sc-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }
    .meta-item strong {
      font-size: 14px;
      color: var(--sc-text);
    }
    .scan-identity-bar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 24px;
      padding: 10px 12px;
      background: var(--sc-surface-soft);
      border: 1px solid var(--sc-border);
      border-left: 3px solid var(--sc-primary);
      border-radius: 12px;
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
    }
    .scanner-state-card {
      padding: 24px;
      border: 1px solid var(--sc-border);
      border-radius: 16px;
      text-align: center;
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
      margin: 20px 0;
    }
    .scanner-state-card.failed {
      border-color: var(--vscode-inputValidation-errorBorder, #ff7b72);
      background: color-mix(in srgb, var(--vscode-inputValidation-errorBackground, #ff7b72) 10%, transparent);
    }
    .scanner-state-card h3 {
      margin-top: 0;
      color: var(--vscode-errorForeground, #ff7b72);
    }
    .scanner-error-details {
      font-family: var(--vscode-editor-font-family, monospace);
      background: rgba(0,0,0,0.2);
      padding: 10px;
      border-radius: 4px;
      text-align: left;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .scanner-state-card.success {
      border-color: var(--vscode-testing-iconPassed, #3fb950);
      color: var(--vscode-testing-iconPassed, #3fb950);
    }
    .scanner-kpi-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .kpi-card {
      min-width: 120px;
      padding: 12px;
      border: 1px solid var(--sc-border);
      border-radius: 12px;
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
      display: flex;
      flex-direction: column;
      align-items: center;
      border-left: 4px solid var(--vscode-widget-border);
    }
    .kpi-card.critical { border-left-color: var(--sc-critical); }
    .kpi-card.high { border-left-color: var(--sc-high); }
    .kpi-card.medium { border-left-color: var(--sc-medium); }
    .kpi-card.low { border-left-color: var(--sc-low); }
    .kpi-card.sonar-category { border-left-color: var(--sc-primary); }
    .kpi-card strong {
      font-size: 20px;
      line-height: 1.2;
    }
    .kpi-card span {
      font-size: 11px;
      color: var(--sc-muted);
      margin-top: 2px;
    }
    .scanner-filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      padding: 12px;
      border: 1px solid var(--sc-border);
      border-radius: 14px;
      background: var(--sc-surface);
      box-shadow: var(--sc-shadow-sm);
    }
    .scanner-filter-bar .filter-group {
      flex: 1 1 200px;
      display: flex;
      gap: 8px;
    }
    .scanner-filter-bar .filter-group.select-group {
      flex: 1 1 300px;
    }
    .scanner-filter-bar .filter-group.input-group {
      flex: 2 1 400px;
    }
    .scanner-filter-bar input, .scanner-filter-bar select {
      flex: 1 1 auto;
      padding: 6px 10px;
      border: 1px solid var(--vscode-input-border, var(--sc-border));
      border-radius: 10px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
    }
    .scanner-tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--vscode-widget-border);
      padding-bottom: 1px;
    }
    .scanner-tabs .tab-button {
      padding: 8px 16px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      font-size: 13px;
    }
    .scanner-tabs .tab-button:hover {
      color: var(--vscode-foreground);
    }
    .scanner-tabs .tab-button.active {
      color: var(--vscode-foreground);
      border-bottom-color: var(--vscode-focusBorder);
      font-weight: bold;
    }
    .scanner-findings-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .scanner-finding-card {
      border: 1px solid var(--sc-border);
      border-radius: 12px;
      background: var(--sc-surface);
      overflow: hidden;
      transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease;
    }
    .scanner-finding-card:hover {
      transform: translateY(-1px);
      border-color: color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border));
      box-shadow: 0 10px 24px color-mix(in srgb, var(--sc-primary) 10%, transparent);
    }
    .scanner-finding-card.expanded {
      border-color: color-mix(in srgb, var(--sc-primary) 42%, var(--sc-border));
    }
    .finding-card-header {
      display: grid;
      grid-template-columns: auto minmax(180px, 1fr) minmax(120px, .75fr) minmax(130px, .8fr) auto;
      align-items: center;
      padding: 10px 14px;
      cursor: pointer;
      gap: 12px;
      user-select: none;
      min-width: 0;
    }
    .finding-card-header:hover {
      background: var(--sc-surface-soft);
    }
    .finding-card-title {
      min-width: 0;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-size: 13px;
    }
    .finding-card-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      min-width: 0;
    }
    .finding-card-meta small {
      max-width: 100%;
      padding: 3px 7px;
      border-radius: 999px;
      color: var(--sc-muted);
      background: var(--sc-surface-soft);
      font-size: 9px;
      font-weight: 700;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .finding-card-file-line {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      font-family: var(--vscode-editor-font-family, monospace);
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .expand-chevron {
      font-size: 10px;
      transition: transform 0.2s ease;
      color: var(--vscode-descriptionForeground);
    }
    .scanner-finding-card.expanded .expand-chevron {
      transform: rotate(180deg);
    }
    .finding-card-details {
      display: none;
      padding: 0;
      border-top: 1px solid var(--sc-border);
      background: linear-gradient(180deg, color-mix(in srgb, var(--sc-primary) 3%, var(--sc-surface)), var(--sc-surface));
    }
    .scanner-finding-card.expanded .finding-card-details {
      display: block;
    }
    .detail-body {
      margin: 0;
    }
    .evidence-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      padding: 14px;
    }
    .detail-row {
      min-width: 0;
      margin: 0;
      padding: 11px 12px;
      border: 1px solid var(--sc-border);
      border-radius: 12px;
      background: color-mix(in srgb, var(--sc-surface) 86%, transparent);
    }
    .detail-row span {
      display: block;
      font-size: 11px;
      text-transform: uppercase;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 3px;
      font-weight: 800;
      letter-spacing: .45px;
    }
    .detail-row code, .detail-row pre {
      font-family: var(--vscode-editor-font-family, monospace);
      background: var(--vscode-textCodeBlock-background, var(--sc-surface-soft));
      border-radius: 6px;
      overflow-wrap: anywhere;
    }
    .detail-row code {
      display: inline-block;
      max-width: 100%;
      padding: 3px 6px;
      font-size: 12px;
    }
    .detail-row pre {
      padding: 8px 12px;
      overflow-x: auto;
      margin: 4px 0 0;
    }
    .detail-row p {
      margin: 4px 0 0;
      font-size: 13px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }
    .detail-row.code-snippet pre {
      border-left: 3px solid var(--vscode-focusBorder);
    }
    .masked-secret {
      letter-spacing: 2px;
      color: var(--vscode-errorForeground, #ff7b72);
      font-weight: bold;
    }
    .dataflow-steps ol {
      margin: 4px 0 0;
      padding-left: 20px;
      font-size: 12px;
      line-height: 1.5;
    }
    .dataflow-steps li {
      margin-bottom: 4px;
    }
    .scanner-finding-card .finding-card-actions, .zap-actions-row {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0;
      border-top: 1px solid var(--sc-border);
      padding: 12px 14px;
      background: color-mix(in srgb, var(--sc-surface) 92%, transparent);
    }
    .scanner-finding-card .finding-card-actions button, .zap-actions-row button {
      min-height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 800;
    }
    .zap-actions-row {
      border-top: none;
      justify-content: flex-start;
      padding: 0;
      margin-top: 16px;
    }
    .severity-badge {
      display: inline-block;
      padding: 2px 6px;
      font-size: 10px;
      font-weight: bold;
      text-transform: uppercase;
      border-radius: 4px;
      text-align: center;
      min-width: 60px;
    }
    .severity-badge.error {
      background: #cf222e;
      color: #ffffff;
    }
    .severity-badge.warning {
      background: #d29922;
      color: #000000;
    }
    .severity-badge.information {
      background: #58a6ff;
      color: #ffffff;
    }

    /* Page visibility override for scanner-details */
    body.surface-scanner-details .page-findings,
    body.surface-scanner-details .page-scans,
    body.surface-scanner-details .page-dynamic,
    body.surface-scanner-details .page-analytics,
    body.surface-scanner-details .page-burp-settings,
    body.surface-scanner-details .overview-split,
    body.surface-scanner-details .overview-summary,
    body.surface-scanner-details .hero,
    body.surface-scanner-details .policy-banner,
    body.surface-scanner-details .pipeline-panel,
    body.surface-scanner-details .zap-card,
    body.surface-scanner-details .cards { display: none !important; }

    body:not(.surface-scanner-details) .page-scanner-details { display: none !important; }

    /* Responsive adjustments */
    @media (max-width: 768px) {
      .scanner-meta-grid {
        grid-template-columns: repeat(3, 1fr);
      }
    }
    @media (max-width: 480px) {
      .scanner-meta-grid {
        grid-template-columns: 1fr;
      }
      .scanner-kpi-summary {
        flex-direction: column;
        align-items: stretch;
      }
      .kpi-card {
        flex: 1 1 auto;
      }
      .scanner-filter-bar {
        flex-direction: column;
      }
      .scanner-filter-bar .filter-group {
        flex: 1 1 auto;
        flex-direction: column;
      }
    }
  </style>
</head>
<body class="surface-${escapeHtml(surface)}${inShell ? ' sc-shelled' : ''}${zapPreflightModal ? ' sc-modal-open' : ''} theme-${selectedTheme === 'dark' ? 'dark' : 'light'}">
  ${fullShellOpen}
  ${headerBar}
  ${surface === 'history' ? '<div class="history-readonly"><strong>Scan historique — lecture seule</strong><br>Cette vue indépendante ne remplace pas le scan actuellement affiché.</div>' : ''}
  <div class="operational-banner ${operationalState}"><span class="operational-icon">${operationalState === 'danger' ? '!' : operationalState === 'success' ? '✓' : 'i'}</span><div class="operational-copy"><strong>${escapeHtml(operationalTitle)}</strong><span>${escapeHtml(operationalDetails)}</span></div></div>
  ${failureDiagnostics}
  ${surface === 'full' ? `${securityCenterHero}${enterpriseSummary}${overviewTripleRow}` : `<div class="hero ${riskClass}"><div class="risk-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="risk-track" cx="50" cy="50" r="42"></circle><circle class="risk-progress" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="${displayedRiskScore} 100"></circle></svg><strong>${displayedRiskScore}</strong></div><div class="risk-copy"><div class="risk-label">Risque ${escapeHtml(displayedRiskLevel)}</div><span class="risk-explanation">${riskExplanation}</span></div></div>`}
  ${policyBanner}
  ${scansExecutionSummary}
  <h3 class="sidebar-keep scans-section-title">Pipeline d’analyse</h3>
  <div class="pipeline-panel">${renderPipeline(model.scanners, model.scanStatus, model.scanDurationMs, model.findings.filter((finding) => !finding.staleFromPreviousScan))}</div>
  ${surface === 'full' ? `<div class="overview-split"><section class="overview-panel"><div class="overview-panel-head"><strong>Scanners</strong><button data-command="securityCenter.openScansPage">Voir les détails →</button></div>${overviewScannerRows}${overviewDisabledRows}</section><section class="overview-panel"><div class="overview-panel-head"><strong>Activité de sécurité</strong><button data-command="securityCenter.showTrends">Tendances →</button></div><div class="activity-overview"><div class="activity-summary"><div class="activity-stat"><strong>${newCount}</strong><span>Nouvelles</span></div><div class="activity-stat resolved"><strong>${fixAppliedCount}</strong><span>Corrigées</span></div><div class="activity-stat validated"><strong>${validatedCount}</strong><span>Validées</span></div><div class="activity-stat accepted"><strong>${acceptedCount}</strong><span>Acceptées</span></div></div>${historyChart}<div class="activity-footer"><div class="activity-col"><span class="activity-col-title">Tendance globale</span><strong class="activity-col-val">${escapeHtml(trendTop)}</strong><span class="activity-col-sub">${escapeHtml(trendBottom)}</span></div><div class="activity-divider"></div><div class="activity-col"><span class="activity-col-title">Temps moyen de correction</span><strong class="activity-col-val">${escapeHtml(mttrTop)}</strong><span class="activity-col-sub">${escapeHtml(mttrBottom)}</span></div></div></div></section></div>` : ''}
  ${zapCard}
  <div class="cards">
    <div class="card"><strong>${currentActiveFindings.length}</strong><span>${escapeHtml(activeFindingsCardLabel)}</span></div>
    <div class="card"><strong>${currentFindings.length}</strong><span>${escapeHtml(scanResultsCardLabel)}</span></div>
    <div class="card"><strong>${currentProductionPriority}</strong><span>Priorités production</span></div>
    <div class="card"><strong>${finishedCount}/${model.scanners.length}</strong><span>Scanners terminés</span></div>
    <div class="card"><strong>${resultsAvailable ? currentActiveFindings.filter((finding) => finding.sourceContext === 'runtime').length : 0}</strong><span>Alertes runtime</span></div>
    <div class="card"><strong>${resultsAvailable ? model.correlations.length : 0}</strong><span>Corrélations</span></div>
    <div class="card"><strong>${resultsAvailable ? model.correlationCounts.high || 0 : 0}</strong><span>Confiance élevée</span></div>
  </div>
  ${surface === 'full' ? `<h3>Priority Findings ${resultsAvailable ? `<button class="quiet-action" data-command="securityCenter.openFindingsPage">Voir les ${priorityFindingCount} priorité${priorityFindingCount > 1 ? 's' : ''} →</button>` : ''}</h3><div class="priority-findings">${priorityFindings}</div>${overviewLowerRow}` : ''}
  <section class="page-findings">
    <section class="findings-hero">
      <div class="findings-watermark" aria-hidden="true">${compactIcon('shield')}${compactIcon('pulse')}</div>
      <div><span class="findings-eyebrow">Application Security</span><h2>Findings</h2><p>Prioritize, investigate and remediate security issues with the real scanner evidence already collected.</p></div>
      <div class="findings-summary">${findingsSummary}</div>
    </section>
    <section class="findings-panel" aria-label="Findings investigation workspace">
      <h3>Vulnérabilités détaillées</h3>
      <div class="finding-filters">
        <label class="filter-search"><span>Search</span><input id="finding-search" type="search" placeholder="Search findings, files, rules, CWE..."></label>
        <label><span>Scanner</span><select id="finding-tool"><option value="">Tous les outils</option>${scannerOptionTags(model.byTool)}</select></label>
        <label><span>Severity</span><select id="finding-severity"><option value="">All severities</option>${optionTags(model.bySeverity)}</select></label>
        <label><span>Status</span><select id="finding-status"><option value="">All statuses</option>${optionTags(model.byStatus)}</select></label>
        <label><span>Environment</span><select id="finding-context"><option value="">All contexts</option>${optionTags(model.byContext)}</select></label>
        <label><span>Reachability</span><select id="finding-reachability"><option value="">All reachability</option>${reachabilityOptions}</select></label>
        <button id="finding-clear-filters" class="quiet-action" type="button">Clear</button>
      </div>
      <div class="finding-filter-meta"><div id="finding-filter-chips" class="filter-chips" aria-live="polite"></div><div class="findings-count"><strong id="visible-findings">${model.findings.length}</strong> / ${model.findings.length} finding(s)</div></div>
      <div class="finding-layout">
        <div class="finding-list" role="list">${findingCards}</div>
        <aside class="finding-preview" aria-live="polite">
          <div class="finding-preview-label">Investigation Preview</div>
          <div class="preview-source"><span id="preview-scanner">Select a finding</span><strong id="preview-severity">—</strong></div>
          <h4 id="preview-title">Select a finding</h4>
          <dl>
            <div><dt>File / target</dt><dd id="preview-location">The file or endpoint appears here.</dd></div>
            <div><dt>Rule</dt><dd id="preview-rule">Rule unavailable</dd></div>
            <div><dt>Reachability</dt><dd id="preview-reachability">Unknown</dd></div>
            <div><dt>Confidence</dt><dd id="preview-confidence">Unknown</dd></div>
            <div><dt>Environment</dt><dd id="preview-context">Unclassified</dd></div>
            <div><dt>Status</dt><dd id="preview-status">New</dd></div>
          </dl>
          <p id="preview-description">Use Investigate to open the full evidence, remediation and verification workspace.</p>
          <div class="preview-actions">
            <button id="preview-code" class="finding-code" type="button" hidden>Open code</button>
            <button id="preview-details" class="finding-open" type="button" disabled>View full details</button>
            <button class="secondary" data-command="securityCenter.verifyFindingFix" type="button">Fix & Verify</button>
          </div>
        </aside>
      </div>
    </section>
  </section>
  <section class="page-scans">${surface === 'scans' ? `<div class="scan-section-head"><div><span>Scanner execution</span><h3>Scanners</h3></div><small>${escapeHtml(model.scanners.length + model.disabledScanners.length)} configured source(s)</small></div><div class="scan-scanner-list">${scannerRows}${disabledScannerRows}</div>` : ''}</section>
  <section class="page-analytics"><div class="analytics-grid"><section class="analytics-panel"><h3>Répartition par outil</h3>${renderDonutChart(model.byTool, 'Répartition des alertes par outil')}</section><section class="analytics-panel"><h3>Répartition par sévérité</h3>${renderDonutChart(model.bySeverity, 'Répartition des alertes par sévérité')}</section></div>
  <h3>Par contexte</h3>${renderMetricRows(model.byContext, 'Aucun résultat')}
  <h3>Suivi de correction</h3>${renderMetricRows(model.byStatus, 'Aucun statut')}
  <h3>Corrélations multi-outils</h3>${correlationRows}</section>
  <section class="page-dynamic">
    <section class="dynamic-section dynamic-target"><div class="dynamic-section-head"><h2>Cible</h2><span class="target-state ${escapeHtml(targetState)}">${escapeHtml(targetStatus)}</span></div><div class="dynamic-status-copy"><strong>${escapeHtml(targetOrigin || 'Aucune cible configurée')}</strong>${targetState === 'unreachable' ? '<span>Démarrez l’application avant de lancer une analyse dynamique.</span>' : targetState === 'unknown' && targetOrigin ? '<span>La cible n’a pas encore été vérifiée.</span>' : targetEvidenceLabel ? `<span>${escapeHtml(targetEvidenceLabel)}</span>` : ''}</div><div class="dynamic-actions"><button class="secondary" data-command="securityCenter.checkDynamicTarget" ${targetOrigin ? '' : 'disabled'}>Vérifier</button><button class="secondary" data-command="securityCenter.changeDynamicTarget">Modifier la cible</button></div></section>
    <div class="dynamic-status-grid">
      <section class="dynamic-section"><div class="dynamic-section-head"><h2>ZAP</h2><span class="status ${escapeHtml(zapScanner?.status || 'pending')}">${escapeHtml(zapState)}</span></div><p class="dynamic-purpose">Analyse dynamique automatisée</p><div class="dynamic-facts"><div class="dynamic-fact"><span>Dernière analyse</span><strong>${zapScanner ? escapeHtml(zapState) : 'Jamais exécutée'}</strong></div><div class="dynamic-fact"><span>URL testées</span><strong>${zapTestedUrls || 'Non disponible'}</strong></div><div class="dynamic-fact"><span>Findings</span><strong>${zapFindingCount}</strong></div><div class="dynamic-fact"><span>Durée</span><strong>${zapScanner?.durationMs ? escapeHtml(formatDuration(zapScanner.durationMs)) : 'Non disponible'}</strong></div></div>${zapScanner?.error ? `<div class="dynamic-status-copy" role="alert"><span>${escapeHtml(summarizeScannerError(zapScanner.error))}</span></div>` : ''}<div class="dynamic-actions">${zapAuthenticationFailed ? '<button class="primary" data-command="securityCenter.configureZapCredentials">Configurer le compte ZAP</button><button class="quiet-action" data-command="securityCenter.configureZap">Paramètres ZAP</button>' : zapScanner?.status === 'failed' ? '<button class="primary" data-command="securityCenter.configureZap">Configurer ZAP</button>' : `<button class="primary" data-command="securityCenter.scanZap" ${zapScanner?.status === 'running' ? 'disabled aria-busy="true"' : ''}>${zapScanner?.status === 'running' ? 'Analyse ZAP en cours…' : 'Lancer ZAP'}</button>`}<button class="quiet-action anchor-action" data-target="dynamic-findings">Voir les findings</button></div></section>
      <section class="dynamic-section"><div class="dynamic-section-head"><h2>Burp</h2><span class="burp-connection ${model.burpConnected ? 'connected' : 'disconnected'}">${model.burpConnected ? '● Connecté' : '○ Déconnecté'}</span></div><p class="dynamic-purpose">Capture et investigation du trafic HTTP</p><div class="dynamic-facts"><div class="dynamic-fact"><span>Requêtes capturées</span><strong>${burpScenarios.length}</strong></div><div class="dynamic-fact"><span>Endpoints uniques</span><strong>${burpUniqueEndpoints || 'Aucun'}</strong></div><div class="dynamic-fact"><span>Findings liés</span><strong>${burpLinkedFindings}</strong></div></div><div class="dynamic-actions"><button class="secondary" data-command="securityCenter.openBurpSettingsPage">Paramètres</button></div></section>
    </div>
    <section id="dynamic-findings" class="dynamic-section"><div class="dynamic-section-head"><h2>Findings dynamiques</h2><span>${dynamicFindings.length} prioritaire(s)</span></div><div class="dynamic-list">${dynamicFindingRows}</div><div class="dynamic-actions"><button class="quiet-action" data-command="securityCenter.openFindingsPage">Voir tous les findings dynamiques →</button></div></section>
    <section id="http-traffic" class="dynamic-section dynamic-traffic"><div class="dynamic-section-head"><h2>Trafic HTTP</h2><span><strong id="visible-traffic">${trafficScenarios.length}</strong> / ${model.httpScenarios.length} requête(s)</span></div>
      <div class="traffic-controls"><input id="traffic-search" type="search" placeholder="Rechercher un endpoint ou chemin…" aria-label="Rechercher dans le trafic HTTP"><button class="traffic-filter active" data-traffic-filter="all">Toutes</button><button class="traffic-filter" data-traffic-filter="GET">GET</button><button class="traffic-filter" data-traffic-filter="POST">POST</button><button class="traffic-filter" data-traffic-filter="authenticated">Authentifiées</button><button class="traffic-filter" data-traffic-filter="findings">Avec findings</button></div>
      <div class="traffic-layout"><div class="traffic-scroll"><div class="traffic-table"><div class="traffic-head"><span>Méthode</span><span>Endpoint</span><span>Statut</span><span>Source</span><span>Findings</span><span>Horodatage</span></div>${trafficRows}<div id="traffic-empty-filter" class="traffic-empty-filter" hidden>Aucune requête ne correspond aux filtres.</div></div></div><aside class="traffic-preview" aria-live="polite" aria-busy="false"><h3>Détails de la requête</h3><div id="traffic-preview-content"><strong>Sélectionnez une requête</strong><span>Les détails assainis seront chargés à la demande.</span></div></aside></div>
    </section>
    <section class="dynamic-section"><div class="dynamic-section-head"><h2>Tests dynamiques récents</h2><span>${model.httpScenarios.length} scénario(s)</span></div><div class="dynamic-list">${recentDynamicRows}</div></section>
  </section>
  <section class="page-burp-settings">
    <section class="dynamic-section"><div class="dynamic-section-head"><h2>Connecteur</h2><span class="burp-connection ${model.burpConnected ? 'connected' : 'disconnected'}">${model.burpConnected ? '● Connecté' : '○ Déconnecté'}</span></div><div class="settings-list">
      <div class="settings-row"><span>État du connecteur</span><strong>${escapeHtml(model.burpStatus.status || (model.burpConnected ? 'ready' : 'unavailable'))}</strong></div>
      <div class="settings-row"><span>Endpoint</span><code>${escapeHtml(model.burpEndpoint || 'Non configuré')}</code></div>
      <div class="settings-row"><span>Dernier signal</span><strong>${escapeHtml(burpLastSeen)}</strong></div>
      <div class="settings-row"><span>État de la capture</span><strong>${model.burpConnected ? 'Connecteur actif' : 'Aucun signal'}</strong></div>
      <div class="settings-row"><span>Masquage des secrets</span><strong>Activé</strong></div>
      <div class="settings-row"><span>Requêtes enregistrées</span><strong>${burpStoredRequests}</strong></div>
    </div><div class="dynamic-actions"><button class="primary" data-command="securityCenter.testBurpConnection">Tester la connexion</button><button class="secondary" data-command="securityCenter.importHttpCapture">Importer un HAR</button></div></section>
    <section class="dynamic-section"><div class="dynamic-section-head"><h2>Avancé</h2><span>Optionnel</span></div><div class="settings-list"><div class="settings-row"><span>Connecteur</span><code>${escapeHtml(model.burpStatus.connector || 'security-center-burp')}</code></div><div class="settings-row"><span>Contrôle de connexion</span><strong>Géré dans Burp ; la déconnexion et la reconnexion automatiques ne sont pas prises en charge.</strong></div></div><div class="dynamic-actions"><button class="secondary" data-command="securityCenter.configureBurp">Guide d’installation et informations techniques</button></div></section>
    ${renderDynamicSections(model.dynamicWorkspace)}
  </section>

  <section class="page-scanner-details">
    ${renderScannerDetailsPage(model, selectedTheme, assets)}
  </section>

  ${fullShellClose}
  ${modalRoot}
  <script nonce="${nonce}">
    // acquireVsCodeApi() leve au second appel dans un meme webview. Cette page
    // n'est pas hebergee par le cadre partage : c'est donc elle qui publie
    // l'instance sur window.__scShellApi, comme le fait shellNavScript pour les
    // autres pages. Sans cette publication, le script de la carte d'assistant —
    // injecte plus bas des qu'un scan a produit un resultat — reacquiert l'API,
    // leve, et interrompt TOUT le reste du script : le garde-fou ZAP perdait
    // ainsi ses deux boutons.
    const vscode = window.__scShellApi || (window.__scShellApi = acquireVsCodeApi());
    const themeToggle = document.getElementById('theme-toggle');
    const scanChrono = document.getElementById('scan-chrono');
    if (scanChrono) {
      const startedAt = Date.parse(scanChrono.dataset.startedAt || '');
      const fallbackStartedAt = Date.now() - Number(scanChrono.dataset.elapsed || 0);
      const origin = Number.isFinite(startedAt) ? startedAt : fallbackStartedAt;
      const updateChrono = () => {
        const total = Math.max(0, Math.floor((Date.now() - origin) / 1000));
        const hours = Math.floor(total / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        const seconds = total % 60;
        scanChrono.textContent = '◷ ' + (hours ? String(hours).padStart(2, '0') + ':' : '') + String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
        scanChrono.title = 'Durée écoulée du scan';
      };
      updateChrono();
      window.setInterval(updateChrono, 1000);
    }
    const updateThemeToggle = () => {
      const dark = document.body.classList.contains('theme-dark');
      themeToggle.textContent = dark ? '☀' : '☾';
      themeToggle.setAttribute('aria-label', dark ? 'Passer au thème clair' : 'Passer au thème sombre');
      themeToggle.title = dark ? 'Passer au thème clair' : 'Passer au thème sombre';
    };
    updateThemeToggle();
    themeToggle.addEventListener('click', () => {
      const dark = !document.body.classList.contains('theme-dark');
      document.body.classList.toggle('theme-dark', dark);
      document.body.classList.toggle('theme-light', !dark);
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
      vscode.postMessage({ type: 'themeChanged', theme: dark ? 'dark' : 'light' });
      updateThemeToggle();
    });
    // La carte d'assistant apporte son propre relais : l'exclure ici evite que
    // le meme clic parte deux fois.
    document.querySelectorAll('[data-command]:not(.sc-assistant [data-command])').forEach((button) => {
      button.addEventListener('click', () => vscode.postMessage({ type: 'command', command: button.dataset.command }));
    });
    const zapPreflight = document.querySelector('[data-zap-preflight-id]');
    if (zapPreflight) {
      const zapReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      const resolveZapPreflight = (decision) => {
        if (zapPreflight.dataset.resolved === 'true') return;
        zapPreflight.dataset.resolved = 'true';
        zapPreflight.querySelectorAll('[data-zap-preflight-decision]').forEach((button) => { button.disabled = true; });
        zapReturnFocus?.focus?.();
        vscode.postMessage({ type: 'zapPreflightResolved', id: zapPreflight.dataset.zapPreflightId, decision });
      };
      zapPreflight.querySelectorAll('[data-zap-preflight-decision]').forEach((button) => {
        button.addEventListener('click', () => resolveZapPreflight(button.dataset.zapPreflightDecision || 'cancel'));
      });
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          resolveZapPreflight('cancel');
          return;
        }
        if (event.key === 'Tab') {
          const focusables = [...zapPreflight.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
            .filter((item) => !item.disabled && item.offsetParent !== null);
          if (!focusables.length) return;
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }
      });
      const firstDecision = zapPreflight.querySelector('[data-zap-preflight-decision="passive"]');
      firstDecision?.focus?.();
    }
    ${assistantCard ? assistantCardScript() : ''}
    ${model.dynamicWorkspace ? dynamicSectionsScript() : ''}
    document.addEventListener('click', (e) => {
      const companionClick = e.target.closest('.sc-widget-mascot') || e.target.closest('.sc-widget-bubble');
      if (companionClick) {
        vscode.postMessage({ type: 'companion' });
      }
    });
    document.querySelectorAll('.scanner-chevron[data-scanner-id]').forEach((button) => {
      button.addEventListener('click', (event) => {
        event.stopPropagation();
        vscode.postMessage({ type: 'openScannerDetails', scannerId: button.dataset.scannerId, scanner: button.dataset.scanner });
      });
    });
    document.querySelectorAll('.overview-scanner:not(.disabled)').forEach((row) => {
      row.style.cursor = 'pointer';
      row.addEventListener('click', (event) => {
        if (event.target.closest('button')) return;
        const button = row.querySelector('.scanner-chevron');
        if (button?.dataset.scannerId) vscode.postMessage({ type: 'openScannerDetails', scannerId: button.dataset.scannerId, scanner: button.dataset.scanner });
      });
    });

    let activeSubTab = '';
    const filterScannerFindings = () => {
      const query = (document.getElementById('scanner-search')?.value || '').toLowerCase().trim();
      const severity = document.getElementById('scanner-filter-severity')?.value || '';
      const status = document.getElementById('scanner-filter-status')?.value || '';
      const filePath = (document.getElementById('scanner-filter-filepath')?.value || '').toLowerCase().trim();
      const ruleCwe = (document.getElementById('scanner-filter-rulecwe')?.value || '').toLowerCase().trim();

      let visibleCount = 0;
      const cards = document.querySelectorAll('.scanner-finding-card');
      cards.forEach((card) => {
        const cardSeverity = card.dataset.severity;
        const cardStatus = card.dataset.status;
        const cardFile = (card.dataset.file || '').toLowerCase();
        const cardRule = (card.dataset.rule || '').toLowerCase();
        const cardCwe = (card.dataset.cwe || '').toLowerCase();
        const cardSnykCapability = card.dataset.snykCapability;
        const cardCategory = card.dataset.category;
        const isContainer = card.dataset.isContainer === 'true';
        const searchText = (card.dataset.search || '').toLowerCase();

        const matchesQuery = !query || searchText.includes(query);
        const matchesSeverity = !severity || cardSeverity === severity;
        const matchesStatus = !status || cardStatus === status;
        const matchesFile = !filePath || cardFile.includes(filePath);
        const matchesRuleCwe = !ruleCwe || cardRule.includes(ruleCwe) || cardCwe.includes(ruleCwe);

        let matchesTab = true;
        if (activeSubTab === 'trivy-dependencies') {
          matchesTab = cardCategory === 'dependency' && !isContainer;
        } else if (activeSubTab === 'trivy-iac') {
          matchesTab = cardCategory === 'misconfiguration';
        } else if (activeSubTab === 'trivy-container') {
          matchesTab = cardCategory === 'dependency' && isContainer;
        } else if (activeSubTab === 'trivy-licenses') {
          matchesTab = false;
        } else if (activeSubTab === 'snyk-oss') {
          matchesTab = cardSnykCapability === 'openSource';
        } else if (activeSubTab === 'snyk-code') {
          matchesTab = cardSnykCapability === 'code';
        } else if (activeSubTab === 'snyk-iac') {
          matchesTab = cardSnykCapability === 'iac';
        }

        const visible = matchesQuery && matchesSeverity && matchesStatus && matchesFile && matchesRuleCwe && matchesTab;
        card.style.display = visible ? 'block' : 'none';
        if (visible) visibleCount += 1;
      });

      const countEl = document.getElementById('scanner-visible-count');
      if (countEl) countEl.textContent = String(visibleCount);
    };

    const scannerSearch = document.getElementById('scanner-search');
    const filterSeverity = document.getElementById('scanner-filter-severity');
    const filterStatus = document.getElementById('scanner-filter-status');
    const filterFilepath = document.getElementById('scanner-filter-filepath');
    const filterRulecwe = document.getElementById('scanner-filter-rulecwe');

    if (scannerSearch) scannerSearch.addEventListener('input', filterScannerFindings);
    if (filterSeverity) filterSeverity.addEventListener('change', filterScannerFindings);
    if (filterStatus) filterStatus.addEventListener('change', filterScannerFindings);
    if (filterFilepath) filterFilepath.addEventListener('input', filterScannerFindings);
    if (filterRulecwe) filterRulecwe.addEventListener('input', filterScannerFindings);

    const trivyTabs = document.getElementById('trivy-tabs');
    if (trivyTabs) activeSubTab = 'trivy-dependencies';
    const snykTabs = document.getElementById('snyk-tabs');
    if (snykTabs) activeSubTab = 'snyk-oss';

    document.querySelectorAll('.tab-button').forEach((btn) => {
      btn.addEventListener('click', () => {
        const parent = btn.closest('.scanner-tabs');
        if (parent) {
          parent.querySelectorAll('.tab-button').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          activeSubTab = btn.dataset.tab;
          filterScannerFindings();
        }
      });
    });

    document.querySelectorAll('.scanner-finding-card .finding-card-header').forEach((header) => {
      header.addEventListener('click', () => {
        const card = header.closest('.finding-card');
        if (card) card.classList.toggle('expanded');
      });
    });

    const pageScannerDetails = document.querySelector('.page-scanner-details');
    if (pageScannerDetails) {
      pageScannerDetails.addEventListener('click', (event) => {
        const button = event.target.closest('button');
        if (!button) return;
        
        const findingIndex = button.dataset.findingIndex;
        if (findingIndex !== undefined) {
          const idx = Number(findingIndex);
          if (button.classList.contains('action-open-details')) {
            vscode.postMessage({ type: 'finding', index: idx });
          } else if (button.classList.contains('action-open-file')) {
            vscode.postMessage({ type: 'findingCode', index: idx });
          } else if (button.classList.contains('action-apply-fix')) {
            vscode.postMessage({ type: 'applyFindingFix', index: idx });
          }
        }

        const scenarioIndex = button.dataset.scenarioIndex;
        if (scenarioIndex !== undefined) {
          const idx = Number(scenarioIndex);
          if (button.classList.contains('action-open-request')) {
            vscode.postMessage({ type: 'openFullHttpRequest', index: idx });
          } else if (button.classList.contains('action-replay-traffic')) {
            vscode.postMessage({ type: 'replayHttpTraffic', index: idx });
          }
        }
      });
      filterScannerFindings();
    }
    document.querySelectorAll('[data-retry-scanner]').forEach((button) => {
      button.addEventListener('click', (event) => {
        event.stopPropagation();
        vscode.postMessage({ type: 'retryScanner', tool: button.dataset.retryScanner });
      });
    });
    const placePipelinePopover = (stage) => {
      const popover = stage.querySelector('.pipeline-popover');
      if (!popover) return;
      const stageRect = stage.getBoundingClientRect();
      const margin = 12;
      const halfWidth = Math.min(155, Math.max(0, (window.innerWidth - (margin * 2)) / 2));
      const center = Math.min(window.innerWidth - margin - halfWidth, Math.max(margin + halfWidth, stageRect.left + (stageRect.width / 2)));
      popover.style.left = center + 'px';
      const popoverHeight = Math.min(230, popover.scrollHeight || 230);
      const top = Math.min(window.innerHeight - margin - popoverHeight, stageRect.bottom + 10);
      popover.style.top = Math.max(margin, top) + 'px';
    };
    document.querySelectorAll('.pipeline-stage.interactive').forEach((stage) => {
      stage.addEventListener('mouseenter', () => placePipelinePopover(stage));
      stage.addEventListener('focusin', () => placePipelinePopover(stage));
    });
    document.querySelectorAll('.anchor-action').forEach((button) => button.addEventListener('click', () => {
      document.getElementById(button.dataset.target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
    const trafficRows = [...document.querySelectorAll('.traffic-row')];
    const trafficSearch = document.getElementById('traffic-search');
    const trafficFilters = [...document.querySelectorAll('.traffic-filter')];
    const visibleTraffic = document.getElementById('visible-traffic');
    const emptyTrafficFilter = document.getElementById('traffic-empty-filter');
    let activeTrafficFilter = 'all';
    const selectTraffic = (row) => {
      trafficRows.forEach((item) => item.classList.toggle('selected', item === row));
      const preview = document.getElementById('traffic-preview-content');
      const previewPanel = preview?.closest('.traffic-preview');
      previewPanel?.setAttribute('aria-busy', 'true');
      if (preview) preview.innerHTML = '<strong>Chargement de la requête assainie…</strong><span>Les valeurs sensibles restent masquées.</span>';
      vscode.postMessage({ type: 'httpTrafficDetails', index: Number(row.dataset.trafficIndex) });
    };
    const filterTraffic = () => {
      const query = (trafficSearch?.value || '').trim().toLowerCase();
      let count = 0;
      trafficRows.forEach((row) => {
        const matchesFilter = activeTrafficFilter === 'all'
          || row.dataset.method === activeTrafficFilter
          || (activeTrafficFilter === 'authenticated' && row.dataset.authenticated === 'true')
          || (activeTrafficFilter === 'findings' && Number(row.dataset.findings) > 0);
        const show = matchesFilter && (!query || row.dataset.search.includes(query));
        row.hidden = !show;
        if (show) count += 1;
      });
      if (visibleTraffic) visibleTraffic.textContent = String(count);
      if (emptyTrafficFilter) emptyTrafficFilter.hidden = count !== 0;
    };
    trafficFilters.forEach((button) => button.addEventListener('click', () => {
      activeTrafficFilter = button.dataset.trafficFilter;
      trafficFilters.forEach((item) => item.classList.toggle('active', item === button));
      filterTraffic();
    }));
    trafficSearch?.addEventListener('input', filterTraffic);
    trafficRows.forEach((row) => {
      row.addEventListener('click', () => selectTraffic(row));
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectTraffic(row); return; }
        if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
        event.preventDefault();
        const visibleRows = trafficRows.filter((item) => !item.hidden);
        const index = visibleRows.indexOf(row);
        const next = visibleRows[index + (event.key === 'ArrowDown' ? 1 : -1)];
        next?.focus();
      });
    });
    window.addEventListener('message', (event) => {
      if (event.data?.command === 'setTheme') {
        const theme = event.data.theme === 'dark' ? 'dark' : 'light';
        document.body.classList.toggle('theme-dark', theme === 'dark');
        document.body.classList.toggle('theme-light', theme !== 'dark');
        document.documentElement.setAttribute('data-theme', theme);
        updateThemeToggle();
        return;
      }
      if (event.data?.type !== 'httpTrafficDetails') return;
      const detail = event.data.detail || {};
      const preview = document.getElementById('traffic-preview-content');
      if (!preview) return;
      preview.closest('.traffic-preview')?.setAttribute('aria-busy', 'false');
      preview.replaceChildren();
      const add = (tag, text, className = '') => { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; preview.appendChild(node); return node; };
      add('h4', 'Request');
      const request = document.createElement('dl');
      [['Method', detail.method], ['URL/path', detail.path || detail.url], ['Timestamp', detail.timestamp || 'Not available'], ['Source', detail.source], ['Duration', detail.duration]].forEach(([name, value]) => { const dt = document.createElement('dt'); dt.textContent = name; const dd = document.createElement('dd'); dd.textContent = value; request.append(dt, dd); });
      preview.appendChild(request);
      const technical = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Request headers and parameters'; technical.appendChild(summary);
      const headers = add.bind(null);
      const headerTitle = document.createElement('h4'); headerTitle.textContent = 'Request headers'; technical.appendChild(headerTitle);
      const headerPre = document.createElement('pre'); headerPre.textContent = (detail.headers || []).map((item) => item.name + ': ' + item.value).join('\\n') || 'None'; technical.appendChild(headerPre);
      const parameterTitle = document.createElement('h4'); parameterTitle.textContent = 'Parameters'; technical.appendChild(parameterTitle);
      const parameterPre = document.createElement('pre'); parameterPre.textContent = (detail.parameters || []).map((item) => item.location + ' • ' + item.name + '=' + item.value).join('\\n') || 'None'; technical.appendChild(parameterPre); preview.appendChild(technical);
      add('h4', 'Response');
      const response = document.createElement('dl');
      [['Status', detail.statusCode || '—'], ['Type', detail.responseType], ['Duration', detail.duration]].forEach(([name, value]) => { const dt = document.createElement('dt'); dt.textContent = name; const dd = document.createElement('dd'); dd.textContent = value; response.append(dt, dd); }); preview.appendChild(response);
      if (detail.responsePreview) { const bodyDetails = document.createElement('details'); const bodySummary = document.createElement('summary'); bodySummary.textContent = 'Safe response preview'; const body = document.createElement('pre'); body.textContent = detail.responsePreview; bodyDetails.append(bodySummary, body); preview.appendChild(bodyDetails); }
      const linkedFindings = detail.linkedFindings || [];
      add('h4', linkedFindings.length + ' finding(s) lié(s)');
      linkedFindings.slice(0, 3).forEach((finding) => { const row = document.createElement('div'); row.className = 'traffic-finding'; const severity = document.createElement('strong'); severity.textContent = finding.severity; const title = document.createElement('span'); title.textContent = finding.title; const source = document.createElement('small'); source.textContent = finding.source || 'Security Center'; const open = document.createElement('button'); open.className = 'quiet-action'; open.textContent = 'Ouvrir →'; open.addEventListener('click', () => vscode.postMessage({ type: 'findingFromTraffic', findingIndex: finding.index, trafficIndex: Number(document.querySelector('.traffic-row.selected')?.dataset.trafficIndex) })); row.append(severity, title, source, open); preview.appendChild(row); });
      if (linkedFindings.length > 3) { const all = document.createElement('button'); all.className = 'quiet-action'; all.textContent = 'Voir les ' + linkedFindings.length + ' findings →'; all.addEventListener('click', () => vscode.postMessage({ type: 'command', command: 'securityCenter.openFindingsPage' })); preview.appendChild(all); }
      const actions = document.createElement('div'); actions.className = 'traffic-actions'; const full = document.createElement('button'); full.className = 'secondary'; full.textContent = 'Ouvrir la requête complète'; full.addEventListener('click', () => vscode.postMessage({ type: 'openFullHttpRequest', index: Number(document.querySelector('.traffic-row.selected')?.dataset.trafficIndex) })); const copy = document.createElement('button'); copy.className = 'secondary'; copy.textContent = 'Copier la requête assainie'; copy.addEventListener('click', () => navigator.clipboard.writeText(detail.safeRequest || '')); const replay = document.createElement('button'); replay.className = 'primary'; replay.textContent = 'Rejouer la requête'; replay.disabled = !['GET', 'HEAD', 'POST', 'PUT', 'PATCH'].includes(detail.method); replay.addEventListener('click', () => vscode.postMessage({ type: 'replayHttpTraffic', index: Number(document.querySelector('.traffic-row.selected')?.dataset.trafficIndex) })); actions.append(full, copy, replay); preview.appendChild(actions);
    });
    document.querySelectorAll('[data-finding-index]').forEach((button) => {
      button.addEventListener('click', () => vscode.postMessage({ type: 'finding', index: Number(button.dataset.findingIndex) }));
    });
    document.querySelectorAll('[data-finding-code-index]').forEach((button) => {
      button.addEventListener('click', () => vscode.postMessage({ type: 'findingCode', index: Number(button.dataset.findingCodeIndex) }));
    });
    const findingCards = [...document.querySelectorAll('.page-findings .finding-card')];
    const previewTitle = document.getElementById('preview-title');
    const previewLocation = document.getElementById('preview-location');
    const previewRule = document.getElementById('preview-rule');
    const previewScanner = document.getElementById('preview-scanner');
    const previewSeverity = document.getElementById('preview-severity');
    const previewReachability = document.getElementById('preview-reachability');
    const previewConfidence = document.getElementById('preview-confidence');
    const previewContext = document.getElementById('preview-context');
    const previewStatus = document.getElementById('preview-status');
    const previewDescription = document.getElementById('preview-description');
    const previewDetails = document.getElementById('preview-details');
    const previewCode = document.getElementById('preview-code');
    const selectFinding = (card) => {
      findingCards.forEach((item) => item.classList.toggle('selected', item === card));
      if (previewScanner) previewScanner.textContent = card.dataset.toolLabel || card.dataset.tool || 'Scanner';
      if (previewSeverity) previewSeverity.textContent = card.dataset.severity || 'UNKNOWN';
      if (previewTitle) previewTitle.textContent = card.dataset.title || 'Security finding';
      if (previewLocation) previewLocation.textContent = card.dataset.location || 'Location unavailable';
      if (previewRule) previewRule.textContent = card.dataset.rule || 'Rule unavailable';
      if (previewReachability) previewReachability.textContent = card.dataset.reachabilityLabel || card.dataset.reachability || 'UNKNOWN';
      if (previewConfidence) previewConfidence.textContent = card.dataset.confidence || 'unknown';
      if (previewContext) previewContext.textContent = card.dataset.context || 'unclassified';
      if (previewStatus) previewStatus.textContent = card.dataset.status || 'new';
      if (previewDescription) previewDescription.textContent = card.dataset.description || 'No short description was provided by the scanner.';
      if (previewDetails) { previewDetails.disabled = false; previewDetails.dataset.findingIndex = card.querySelector('[data-finding-index]')?.dataset.findingIndex || ''; }
      if (previewCode) {
        const codeIndex = card.querySelector('[data-finding-code-index]')?.dataset.findingCodeIndex;
        previewCode.hidden = codeIndex === undefined;
        previewCode.dataset.findingCodeIndex = codeIndex || '';
      }
    };
    findingCards.forEach((card) => {
      card.addEventListener('click', (event) => { if (!event.target.closest('button')) selectFinding(card); });
      card.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectFinding(card); } });
    });
    const firstVisibleFinding = findingCards.find((card) => !card.classList.contains('hidden'));
    if (firstVisibleFinding) selectFinding(firstVisibleFinding);
    const search = document.getElementById('finding-search');
    const tool = document.getElementById('finding-tool');
    const severity = document.getElementById('finding-severity');
    const status = document.getElementById('finding-status');
    const contextFilter = document.getElementById('finding-context');
    const reachabilityFilter = document.getElementById('finding-reachability');
    const clearFindingFilters = document.getElementById('finding-clear-filters');
    const findingFilterChips = document.getElementById('finding-filter-chips');
    const visible = document.getElementById('visible-findings');
    previewDetails?.addEventListener('click', () => {
      const index = Number(previewDetails.dataset.findingIndex);
      if (Number.isInteger(index)) vscode.postMessage({ type: 'finding', index });
    });
    previewCode?.addEventListener('click', () => {
      const index = Number(previewCode.dataset.findingCodeIndex);
      if (Number.isInteger(index)) vscode.postMessage({ type: 'findingCode', index });
    });
    const renderFindingFilterChips = () => {
      if (!findingFilterChips) return;
      findingFilterChips.replaceChildren();
      const chips = [
        search?.value ? ['search', 'Search: ' + search.value, search] : null,
        tool?.value ? ['scanner', 'Scanner: ' + (tool.selectedOptions[0]?.textContent || tool.value), tool] : null,
        severity?.value ? ['severity', 'Severity: ' + severity.value, severity] : null,
        status?.value ? ['status', 'Status: ' + status.value, status] : null,
        contextFilter?.value ? ['context', 'Environment: ' + contextFilter.value, contextFilter] : null,
        reachabilityFilter?.value ? ['reachability', 'Reachability: ' + (reachabilityFilter.selectedOptions[0]?.textContent || reachabilityFilter.value), reachabilityFilter] : null
      ].filter(Boolean);
      chips.forEach(([, label, control]) => {
        const chip = document.createElement('span');
        chip.className = 'filter-chip';
        const text = document.createElement('span');
        text.textContent = label;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.setAttribute('aria-label', 'Remove ' + label);
        remove.textContent = '×';
        remove.addEventListener('click', () => { control.value = ''; filterFindings(); });
        chip.append(text, remove);
        findingFilterChips.appendChild(chip);
      });
    };
    const filterFindings = () => {
      const query = (search?.value || '').trim().toLowerCase();
      let count = 0;
      let firstVisible = null;
      for (const card of findingCards) {
        const show = (!query || card.dataset.search.includes(query))
          && (!tool?.value || card.dataset.toolId === tool.value)
          && (!severity?.value || card.dataset.severity === severity.value)
          && (!status?.value || card.dataset.status === status.value)
          && (!contextFilter?.value || card.dataset.context === contextFilter.value)
          && (!reachabilityFilter?.value || card.dataset.reachability === reachabilityFilter.value);
        card.classList.toggle('hidden', !show);
        if (show) { count += 1; if (!firstVisible) firstVisible = card; }
      }
      if (visible) visible.textContent = String(count);
      renderFindingFilterChips();
      if (firstVisible && !findingCards.some((card) => card.classList.contains('selected') && !card.classList.contains('hidden'))) selectFinding(firstVisible);
    };
    [search, tool, severity, status, contextFilter, reachabilityFilter].forEach((control) => control?.addEventListener('input', filterFindings));
    [tool, severity, status, contextFilter, reachabilityFilter].forEach((control) => control?.addEventListener('change', filterFindings));
    clearFindingFilters?.addEventListener('click', () => {
      [search, tool, severity, status, contextFilter, reachabilityFilter].forEach((control) => { if (control) control.value = ''; });
      filterFindings();
    });
    filterFindings();

    // Handle tooltips and hovers on the security activity chart
    const chartDots = document.querySelectorAll('.chart-dot');
    const tooltip = document.getElementById('activity-chart-tooltip');
    
    chartDots.forEach((dot) => {
      dot.addEventListener('mouseenter', () => {
        const date = dot.getAttribute('data-date');
        const total = dot.getAttribute('data-total');
        const active = dot.getAttribute('data-active');
        const critical = dot.getAttribute('data-critical');
        const high = dot.getAttribute('data-high');
        const medium = dot.getAttribute('data-medium');
        const low = dot.getAttribute('data-low');
        
        let severityHtml = '';
        if (Number(critical) > 0) {
          severityHtml += '<div class="tooltip-row"><span class="tooltip-severity"><span class="tooltip-dot critical"></span>Critical</span><strong>' + critical + '</strong></div>';
        }
        if (Number(high) > 0) {
          severityHtml += '<div class="tooltip-row"><span class="tooltip-severity"><span class="tooltip-dot high"></span>High</span><strong>' + high + '</strong></div>';
        }
        if (Number(medium) > 0) {
          severityHtml += '<div class="tooltip-row"><span class="tooltip-severity"><span class="tooltip-dot medium"></span>Medium</span><strong>' + medium + '</strong></div>';
        }
        if (Number(low) > 0) {
          severityHtml += '<div class="tooltip-row"><span class="tooltip-severity"><span class="tooltip-dot low"></span>Low</span><strong>' + low + '</strong></div>';
        }

        const wrapper = dot.closest('.activity-chart-wrapper');
        const wrapperRect = wrapper.getBoundingClientRect();
        const dotRect = dot.getBoundingClientRect();

        let x = dotRect.left - wrapperRect.left + dotRect.width / 2;
        let y = dotRect.top - wrapperRect.top;

        tooltip.innerHTML = '<span class="tooltip-timestamp">' + date + '</span>' +
          '<div class="tooltip-row total-row">' +
            '<span class="tooltip-label">Total findings</span>' +
            '<strong>' + total + '</strong>' +
          '</div>' +
          severityHtml;

        tooltip.style.display = 'block';

        const tooltipRect = tooltip.getBoundingClientRect();

        let left = x - tooltipRect.width / 2;
        let top = y - tooltipRect.height - 12;

        // Clamp horizontally
        left = Math.max(8, Math.min(left, wrapper.clientWidth - tooltipRect.width - 8));

        // If top < 8
        if (top < 8) {
          top = y + dotRect.height + 12;
        }

        // Clamp vertically
        top = Math.max(8, Math.min(top, wrapper.clientHeight - tooltipRect.height - 8));

        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
        tooltip.style.opacity = '1';
      });
      
      dot.addEventListener('mouseleave', () => {
        tooltip.style.opacity = '0';
        tooltip.style.display = 'none';
      });
    });
  </script>
  ${companionPresence}
</body>
</html>`;
}

const SCANNER_CATEGORIES = Object.freeze({
  Semgrep: "Analyse statique du code (SAST)",
  Gitleaks: "Détection de secrets",
  Trivy: "Analyse de dépendances et configurations (SCA/IaC)",
  'OSV-Scanner': "Analyse de vulnérabilités open-source (SCA)",
  SonarQube: "Analyse de qualité et sécurité du code",
  Snyk: "Analyse de sécurité multi-facettes (SCA/SAST/IaC)",
  ZAP: "Analyse dynamique automatisée (DAST)"
});

function renderScannerDetailsPage(model, selectedTheme, assets = {}) {
  const scannerName = model.activeScanner || '';
  if (!scannerName) {
    return `<div class="empty">Sélectionnez un scanner pour voir les résultats.</div>`;
  }
  const scannerObj = model.scanners.find(s => s.tool === scannerName);
  const isDisabled = model.disabledScanners.includes(scannerName);
  const presentation = scannerPresentation(scannerName);
  const activeScannerId = scannerIdForTool(scannerName);
  const description = presentation.description;
  const category = SCANNER_CATEGORIES[scannerName] || "Analyse de sécurité";

  const scannerFindings = scannerObj?.status === 'completed'
    ? (Array.isArray(scannerObj.currentRun?.findings) ? scannerObj.currentRun.findings : model.findings.filter(f => f.tool === scannerName))
    : [];
  const currentResultCount = scannerObj?.status === 'completed'
    ? Number(scannerObj.currentRun?.resultCount ?? scannerFindings.length)
    : null;

  let state = 'not_run';
  let errorMsg = '';
  if (scannerObj) {
    if (scannerObj.status === 'completed') {
      state = currentResultCount > 0 ? 'has_findings' : 'zero_findings';
    } else if (scannerObj.status === 'failed' || scannerObj.status === 'cancelled') {
      state = 'failed';
      errorMsg = scannerObj.error || scannerObj.details || 'Échec sans détails';
    } else if (scannerObj.status === 'running' || scannerObj.status === 'refreshing') {
      state = 'running';
    } else if (scannerObj.status === 'pending') {
      state = 'pending';
    }
  } else if (isDisabled) {
    state = 'not_run';
  }

  let html = `
  <header class="scanner-detail-hero" data-active-scanner-id="${escapeHtml(activeScannerId)}" data-active-scanner="${escapeHtml(scannerName)}">
    <div class="scanner-detail-watermark" aria-hidden="true">${compactIcon('shield')}${compactIcon('pulse')}</div>
    <div class="scanner-header-identity">
      ${renderScannerLogoHtml(scannerName, scannerObj?.status || '', assets)}
      <div>
        <span class="scanner-eyebrow">${escapeHtml(presentation.category)}</span>
        <h1>${escapeHtml(presentation.label)}</h1>
        <p class="scanner-header-desc">${escapeHtml(description || category)}</p>
      </div>
    </div>
    <aside class="scanner-hero-status">
      <span class="state-chip ${escapeHtml(scannerObj?.status || 'not-run')}">${scannerObj ? escapeHtml(scannerObj.status.toUpperCase()) : isDisabled ? 'NOT CONFIGURED' : 'NOT RUN'}</span>
      <strong>${currentResultCount === null ? '—' : currentResultCount}</strong>
      <small>current-run findings</small>
    </aside>
  </header>
  
  <div class="scanner-meta-grid">
    <div class="meta-item">
      <span>Statut</span>
      <strong>${scannerObj ? escapeHtml(scannerObj.status.toUpperCase()) : 'NON EXÉCUTÉ'}</strong>
    </div>
    <div class="meta-item">
      <span>Dernier scan</span>
      <strong>${scannerObj && scannerObj.status === 'completed' && scannerObj.completedAt ? escapeHtml(new Date(scannerObj.completedAt).toLocaleString('fr-FR')) : '—'}</strong>
    </div>
    <div class="meta-item">
      <span>Durée</span>
      <strong>${scannerObj && scannerObj.status === 'completed' && scannerObj.durationMs ? escapeHtml(formatDuration(scannerObj.durationMs)) : '—'}</strong>
    </div>
    <div class="meta-item">
      <span>Findings</span>
      <strong>${currentResultCount === null ? '—' : currentResultCount}</strong>
    </div>
    <div class="meta-item">
      <span>Version</span>
      <strong>Non disponible</strong>
    </div>
    <div class="meta-item">
      <span>Mode</span>
      <strong>Non disponible</strong>
    </div>
  </div>

  <div class="scan-identity-bar">
    <span><strong>Scan :</strong> ${model.scanStartedAt ? `local-execution-${model.scanStartedAt}` : 'non disponible'}</span>
    <span><strong>Date :</strong> ${model.scanStartedAt ? new Date(model.scanStartedAt).toLocaleString('fr-FR') : 'non disponible'}</span>
    <span><strong>Branch :</strong> Non disponible</span>
  </div>
  `;

  if (state === 'failed') {
    return html + `
    <div class="scanner-state-card failed">
      <h3>Scan failed</h3>
      <p class="scanner-error-details">${escapeHtml(summarizeScannerError(errorMsg))}</p>
      <button class="primary" data-command="securityCenter.openScannerSetup">Open scanner configuration</button>
    </div>`;
  }

  if (state === 'not_run') {
    return html + `
    <div class="scanner-state-card not-run">
      <p>No result available for this scanner in the selected scan.</p>
    </div>`;
  }

  if (state === 'pending') {
    return html + `
    <div class="scanner-state-card not-run">
      <p>No current result is available for this scanner yet.</p>
    </div>`;
  }

  if (state === 'running') {
    return html + `
    <div class="scanner-state-card running">
      <p>Analysis in progress</p>
    </div>`;
  }

  if (state === 'zero_findings') {
    return html + `
    <div class="scanner-state-card success">
      <p>✓ No findings detected by ${escapeHtml(scannerName)} in the current scanner run.</p>
    </div>`;
  }

  const criticalCount = scannerFindings.filter(f => String(f.rawSeverity).toUpperCase() === 'CRITICAL').length;
  const highCount = scannerFindings.filter(f => String(f.rawSeverity).toUpperCase() === 'HIGH').length;
  const mediumCount = scannerFindings.filter(f => String(f.rawSeverity).toUpperCase() === 'MEDIUM').length;
  const lowCount = scannerFindings.filter(f => String(f.rawSeverity).toUpperCase() === 'LOW').length;

  html += `
  <div class="scanner-kpi-summary">
    <div class="kpi-card critical">
      <strong>${criticalCount}</strong>
      <span>Critical</span>
    </div>
    <div class="kpi-card high">
      <strong>${highCount}</strong>
      <span>High</span>
    </div>
    <div class="kpi-card medium">
      <strong>${mediumCount}</strong>
      <span>Medium</span>
    </div>
    <div class="kpi-card low">
      <strong>${lowCount}</strong>
      <span>Low</span>
    </div>
  `;

  if (scannerName === 'SonarQube') {
    const securityCount = scannerFindings.filter(f => f.category === 'security' || f.category === 'security-hotspot').length;
    const reliabilityCount = scannerFindings.filter(f => f.category === 'reliability').length;
    const maintainabilityCount = scannerFindings.filter(f => f.category === 'maintainability').length;

    html += `
    <div class="kpi-card sonar-category">
      <strong>${securityCount}</strong>
      <span>Security</span>
    </div>
    <div class="kpi-card sonar-category">
      <strong>${reliabilityCount}</strong>
      <span>Reliability</span>
    </div>
    <div class="kpi-card sonar-category">
      <strong>${maintainabilityCount}</strong>
      <span>Maintainability</span>
    </div>
    `;
  }

  html += `</div>`;

  html += `
  <div class="scanner-filter-bar">
    <div class="filter-group">
      <input type="search" id="scanner-search" placeholder="Rechercher (règle, CWE, description, fichier...)">
    </div>
    <div class="filter-group select-group">
      <select id="scanner-filter-severity">
        <option value="">Toutes les sévérités</option>
        <option value="error">Critical / High</option>
        <option value="warning">Medium</option>
        <option value="information">Low</option>
      </select>
      <select id="scanner-filter-status">
        <option value="">Tous les statuts</option>
        <option value="new">New</option>
        <option value="false_positive">False Positive</option>
        <option value="fixed">Fixed</option>
        <option value="validated">Validated</option>
        <option value="accepted">Accepted</option>
      </select>
    </div>
    <div class="filter-group input-group">
      <input type="text" id="scanner-filter-filepath" placeholder="Filtrer par fichier...">
      <input type="text" id="scanner-filter-rulecwe" placeholder="Règle ou CWE...">
    </div>
  </div>
  <div class="findings-count">
    <strong id="scanner-visible-count">${currentResultCount}</strong> vulnérabilité(s) affichée(s)
  </div>
  `;

  if (scannerName === 'Trivy') {
    html += `
    <div class="scanner-tabs" id="trivy-tabs">
      <button class="tab-button active" data-tab="trivy-dependencies">Dependencies</button>
      <button class="tab-button" data-tab="trivy-iac">IaC / Misconfigurations</button>
      <button class="tab-button" data-tab="trivy-container">Container</button>
      <button class="tab-button" data-tab="trivy-licenses">Licenses</button>
    </div>
    `;
  } else if (scannerName === 'Snyk') {
    html += `
    <div class="scanner-tabs" id="snyk-tabs">
      <button class="tab-button active" data-tab="snyk-oss">Open Source</button>
      <button class="tab-button" data-tab="snyk-code">Code</button>
      <button class="tab-button" data-tab="snyk-iac">IaC</button>
    </div>
    `;
  }

  html += `<div class="scanner-findings-list">`;
  scannerFindings.forEach((finding, index) => {
    const overallIndex = model.findings.findIndex(f => f.id === finding.id);
    const isContainer = finding.target && (finding.target.includes(':') || !finding.target.includes('.') || finding.target.includes('image'));
    const lineLabel = Number.isFinite(Number(finding.startLine)) ? `:${Number(finding.startLine) + 1}` : '';
    const locationLabel = finding.file ? `${finding.file}${lineLabel}` : finding.endpoint || finding.target || 'Unavailable';
    const metaBits = [
      finding.ruleId ? `Rule ${finding.ruleId}` : '',
      finding.cwe ? finding.cwe : '',
      finding.packageName ? `Package ${finding.packageName}` : '',
      finding.triageStatus ? `Status ${finding.triageStatus}` : ''
    ].filter(Boolean);

    html += `
    <div class="finding-card scanner-finding-card"
         data-severity="${escapeHtml(finding.severity)}"
         data-status="${escapeHtml(finding.triageStatus || 'new')}"
         data-file="${escapeHtml(finding.file || '')}"
         data-rule="${escapeHtml(finding.ruleId || '')}"
         data-cwe="${escapeHtml(finding.cwe || '')}"
         data-snyk-capability="${escapeHtml(finding.snykCapability || '')}"
         data-category="${escapeHtml(finding.category || '')}"
         data-is-container="${isContainer}"
         data-search="${escapeHtml(finding.title || '')} ${escapeHtml(finding.description || '')} ${escapeHtml(finding.ruleId || '')} ${escapeHtml(finding.file || '')}">
      
      <div class="finding-card-header">
        <span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.rawSeverity || finding.severity)}</span>
        <span class="finding-card-title" title="${escapeHtml(finding.title || 'Security finding')}">${escapeHtml(finding.title || 'Security finding')}</span>
        <span class="finding-card-meta">${metaBits.slice(0, 2).map((item) => `<small title="${escapeHtml(item)}">${escapeHtml(item)}</small>`).join('')}</span>
        <span class="finding-card-file-line" title="${escapeHtml(locationLabel)}">${escapeHtml(locationLabel)}</span>
        <span class="expand-chevron" aria-hidden="true">⌄</span>
      </div>
      
      <div class="finding-card-details">
        <div class="detail-body evidence-grid">
          ${renderScannerSpecificDetails(finding, scannerName, model)}
        </div>
        <div class="finding-card-actions">
          <button class="secondary action-open-file" data-finding-index="${overallIndex}">Open code</button>
          <button class="secondary action-open-details" data-finding-index="${overallIndex}">View details →</button>
          ${finding.autofix ? `<button class="primary action-apply-fix" data-finding-index="${overallIndex}">Fix &amp; Verify</button>` : ''}
        </div>
      </div>
    </div>
    `;
  });
  html += `</div>`;

  return html;
}

function renderScannerSpecificDetails(finding, scannerName, model) {
  let html = '';
  
  if (scannerName === 'Semgrep') {
    html += `
    <div class="detail-row"><span>Règle ID</span><code>${escapeHtml(finding.ruleId)}</code></div>
    ${finding.cwe ? `<div class="detail-row"><span>CWE</span><code>${escapeHtml(finding.cwe)}</code></div>` : ''}
    <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}:${finding.startColumn + 1}</code></div>
    <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
    ${finding.originalText ? `<div class="detail-row code-snippet"><span>Extrait</span><pre><code>${escapeHtml(finding.originalText)}</code></pre></div>` : ''}
    <div class="detail-row"><span>Statut</span><strong>${escapeHtml(finding.triageStatus || 'new')}</strong></div>
    `;
  }
  
  else if (scannerName === 'Gitleaks') {
    html += `
    <div class="detail-row"><span>Type de secret / Règle</span><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}</code></div>
    <div class="detail-row"><span>Fingerprint</span><code>${finding.fingerprint ? escapeHtml(finding.fingerprint.slice(0, 8) + '…') : '—'}</code></div>
    <div class="detail-row"><span>Valeur secrète</span><code class="masked-secret">•••••••• (Masqué)</code></div>
    <div class="detail-row"><span>Statut</span><strong>${escapeHtml(finding.triageStatus || 'new')}</strong></div>
    `;
  }
  
  else if (scannerName === 'Trivy') {
    if (finding.category === 'dependency') {
      html += `
      <div class="detail-row"><span>CVE / Advisory</span><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="detail-row"><span>Package</span><code>${escapeHtml(finding.packageName)}</code></div>
      <div class="detail-row"><span>Version installée</span><code>${escapeHtml(finding.installedVersion)}</code></div>
      <div class="detail-row"><span>Version corrigée</span><code>${escapeHtml(finding.fixedVersion || 'Non spécifiée')}</code></div>
      <div class="detail-row"><span>CVSS Score</span><strong>Non disponible (Non exposé par le modèle)</strong></div>
      <div class="detail-row"><span>Dependency Path</span><strong>Non disponible (Non exposé par le modèle)</strong></div>
      <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
      `;
    } else {
      html += `
      <div class="detail-row"><span>Ressource</span><code>${escapeHtml(finding.target || finding.file)}</code></div>
      <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}</code></div>
      <div class="detail-row"><span>Misconfiguration</span><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="detail-row"><span>Titre</span><p>${escapeHtml(finding.title)}</p></div>
      <div class="detail-row"><span>Recommandation</span><p>${escapeHtml(finding.solution || 'Non spécifiée')}</p></div>
      <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
      `;
    }
  }
  
  else if (scannerName === 'OSV-Scanner') {
    html += `
    <div class="detail-row"><span>Advisory / CVE</span><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="detail-row"><span>Package</span><code>${escapeHtml(finding.packageName)}</code></div>
    <div class="detail-row"><span>Version actuelle</span><code>${escapeHtml(finding.installedVersion)}</code></div>
    <div class="detail-row"><span>Version corrigée</span><code>${escapeHtml(finding.fixedVersion || 'Aucune')}</code></div>
    <div class="detail-row"><span>Plage affectée</span><strong>Non disponible (Non exposé par le modèle)</strong></div>
    <div class="detail-row"><span>Manifeste</span><code>${escapeHtml(finding.file)}</code></div>
    ${finding.reachable !== null ? `<div class="detail-row"><span>Reachable</span><strong>${finding.reachable ? 'Oui (Haute priorité)' : 'Non (Basse priorité)'}</strong></div>` : ''}
    <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
    `;
  }
  
  else if (scannerName === 'SonarQube') {
    html += `
    <div class="detail-row"><span>Titre</span><p>${escapeHtml(finding.title)}</p></div>
    <div class="detail-row"><span>Règle</span><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="detail-row"><span>Type</span><code>${escapeHtml(finding.issueType || finding.category)}</code></div>
    <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}</code></div>
    <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
    <div class="detail-row"><span>Statut Sonar</span><strong>${escapeHtml(finding.sonarStatus || 'Non spécifié')}</strong></div>
    `;
  }
  
  else if (scannerName === 'Snyk') {
    if (finding.snykCapability === 'openSource') {
      html += `
      <div class="detail-row"><span>Package</span><code>${escapeHtml(finding.packageName)}</code></div>
      <div class="detail-row"><span>Version</span><code>${escapeHtml(finding.installedVersion)}</code></div>
      <div class="detail-row"><span>CVE</span><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="detail-row"><span>Upgrade Path</span><code>${finding.upgradePath ? escapeHtml(finding.upgradePath.join(' → ')) : '—'}</code></div>
      <div class="detail-row"><span>Fixed In</span><code>${finding.fixedVersion ? escapeHtml(finding.fixedVersion) : '—'}</code></div>
      <div class="detail-row"><span>CVSS Score</span><strong>${finding.cvssScore !== null ? escapeHtml(finding.cvssScore) : 'Non disponible'}</strong></div>
      <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
      `;
    } else if (finding.snykCapability === 'code') {
      html += `
      <div class="detail-row"><span>Règle</span><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}</code></div>
      <div class="detail-row"><span>CWE</span><code>${escapeHtml(finding.cwe || 'Non spécifiée')}</code></div>
      <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
      `;
      if (finding.dataFlow && finding.dataFlow.length > 0) {
        html += `
        <div class="detail-row dataflow-steps">
          <span>Dataflow</span>
          <ol>
            ${finding.dataFlow.map(step => `<li><code>${escapeHtml(step.file)}:${step.line}</code> ${escapeHtml(step.message || '')}</li>`).join('')}
          </ol>
        </div>
        `;
      }
    } else if (finding.snykCapability === 'iac') {
      html += `
      <div class="detail-row"><span>Ressource</span><code>${escapeHtml(finding.resource || '—')}</code></div>
      <div class="detail-row"><span>Emplacement</span><code>${escapeHtml(finding.file)}:${finding.startLine + 1}</code></div>
      <div class="detail-row"><span>Public ID</span><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="detail-row"><span>Impact</span><p>${escapeHtml(finding.impact || 'Non spécifié')}</p></div>
      <div class="detail-row"><span>Remédiation</span><p>${escapeHtml(finding.solution || 'Non spécifiée')}</p></div>
      <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
      `;
    }
  }
  
  else if (scannerName === 'ZAP') {
    const scenarioIndex = model.httpScenarios.findIndex((scenario) => linkedFindingsForScenario(scenario, [finding]).length > 0);
    html += `
    <div class="detail-row"><span>Alerte</span><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="detail-row"><span>Méthode HTTP</span><strong>${escapeHtml(finding.method || 'HTTP')}</strong></div>
    <div class="detail-row"><span>Endpoint</span><code>${escapeHtml(finding.endpoint || '')}</code></div>
    ${finding.parameter ? `<div class="detail-row"><span>Paramètre</span><code>${escapeHtml(finding.parameter)}</code></div>` : ''}
    <div class="detail-row"><span>Confiance</span><strong>${escapeHtml(finding.confidence)}</strong></div>
    ${finding.cwe ? `<div class="detail-row"><span>CWE</span><code>${escapeHtml(finding.cwe)}</code></div>` : ''}
    <div class="detail-row"><span>Runtime Observed</span><strong>Oui (runtime context)</strong></div>
    ${finding.evidence ? `<div class="detail-row"><span>Evidence</span><pre><code>${escapeHtml(finding.evidence)}</code></pre></div>` : ''}
    <div class="detail-row"><span>Description</span><p>${escapeHtml(finding.description)}</p></div>
    <div class="detail-row"><span>Solution</span><p>${escapeHtml(finding.solution)}</p></div>
    
    <div class="zap-actions-row">
      <button class="secondary" data-command="securityCenter.openDynamicPage">Open Dynamic Security →</button>
      ${scenarioIndex !== -1 ? `
        <button class="secondary action-open-request" data-scenario-index="${scenarioIndex}">Open request</button>
        <button class="secondary action-replay-traffic" data-scenario-index="${scenarioIndex}">Replay</button>
      ` : ''}
    </div>
    `;
  }
  
  return html;
}

module.exports = { SENSITIVE_HTTP_NAME, sanitizeHttpValue, buildDashboardModel, calculateRiskScore, riskLevel, countBy, escapeHtml, summarizeScannerError, renderDashboardHtml, endpointPath, isUsefulHttpScenario, linkedFindingsForScenario, linkedFindingsWithConfidence, associationFor, transactionParameters, ASSOCIATION_CONFIDENCE, ZAP_UNKNOWN_METHOD, sourceCorrelationForFinding, buildSafeHttpPreview };
