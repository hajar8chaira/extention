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

function buildDashboardModel(findings = [], scanners = [], options = {}) {
  const correlations = Array.isArray(options.correlations) ? options.correlations : [];
  const activeFindings = findings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus));
  const riskScore = calculateRiskScore(activeFindings);
  return {
    findings,
    total: findings.length,
    activeTotal: activeFindings.length,
    byTool: countBy(findings, (finding) => finding.tool),
    bySeverity: countBy(findings, (finding) => finding.rawSeverity),
    byContext: countBy(findings, (finding) => finding.sourceContext || 'non classé'),
    byStatus: countBy(findings, (finding) => finding.triageStatus || 'new'),
    correlations,
    correlationCounts: countBy(correlations, (correlation) => correlation.confidence),
    riskScore,
    riskLevel: riskLevel(riskScore),
    productionPriority: activeFindings.filter((finding) => finding.sourceContext === 'production' && ['CRITICAL', 'HIGH'].includes(String(finding.rawSeverity).toUpperCase())).length,
    runtimeFindings: activeFindings.filter((finding) => finding.sourceContext === 'runtime').length,
    completedScanners: scanners.filter((scanner) => scanner.status === 'completed').length,
    httpScenarioCount: Number(options.httpScenarioCount || 0),
    httpScenarios: Array.isArray(options.httpScenarios) ? options.httpScenarios : [],
    burpConnected: Boolean(options.burpConnected),
    burpStatus: options.burpStatus && typeof options.burpStatus === 'object' ? options.burpStatus : {},
    burpEndpoint: options.burpEndpoint || '',
    dynamicTargetUrl: options.dynamicTargetUrl || '',
    dynamicTargetState: options.dynamicTargetState || 'unknown',
    scanDurationMs: Number(options.scanDurationMs || 0),
    scanStartedAt: options.scanStartedAt || '',
    scanners,
    workspace: options.workspace || 'Aucun workspace',
    scanStatus: options.scanStatus || 'idle',
    backendStatus: options.backendStatus || 'unknown',
    policyResult: options.policyResult || null,
    snapshotAvailable: Boolean(options.snapshotAvailable),
    activeExecution: options.activeExecution || null,
    lastExecution: options.lastExecution || null,
    executionType: options.executionType || ''
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

function linkedFindingsForScenario(scenario, findings) {
  const path = endpointPath(scenario.request?.url);
  const method = String(scenario.request?.method || '').toUpperCase();
  return (findings || []).filter((finding) => finding.endpoint
    && endpointPath(finding.endpoint) === path
    && (!finding.method || !method || String(finding.method).toUpperCase() === method));
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
  const linked = linkedFindingsForScenario(scenario, findings).map((finding) => ({
    index: findings.indexOf(finding), severity: String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase(), title: finding.title || finding.ruleId || 'Finding', source: finding.tool || 'Security Center'
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
    const severityRank = (value) => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, WARNING: 2, LOW: 1, INFO: 0 }[String(value || '').toUpperCase()] || 0);
    const priority = interactive
      ? [...scannerFindings].sort((left, right) => severityRank(right.rawSeverity || right.severity) - severityRank(left.rawSeverity || left.severity)).slice(0, 5)
      : [];
    const tooltipId = interactive ? `pipeline-${String(label).toLowerCase().replace(/[^a-z0-9]+/g, '-')}-findings` : '';
    const popover = interactive ? `<div id="${tooltipId}" class="pipeline-popover" role="tooltip">
      <strong>${escapeHtml(label)} · ${scannerFindings.length} finding(s)</strong>
      ${priority.length ? priority.map((finding) => `<span><b>${escapeHtml(String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase())}</b> ${escapeHtml(finding.title || finding.ruleId || 'Finding')}</span>`).join('') : `<span>${['running', 'refreshing'].includes(status) ? 'Analyse en cours…' : status === 'failed' ? 'Le scanner a échoué. Les anciens résultats valides restent conservés.' : 'Aucun finding pour ce scanner.'}</span>`}
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
    parts.push(stage(scanner.tool, scanner.status, scannerSubtitle, findings.filter((finding) => finding.tool === scanner.tool)));
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

function renderDashboardHtml(model, nonce, surface = 'full', selectedTheme = 'light', uiState = {}) {
  const statusLabels = { new: 'Nouvelle', triaged: 'Triée', probable: 'Probable', confirmed: 'Confirmée', fixed: 'Corrigée — validation en attente', validated: 'Validée par re-scan', false_positive: 'Faux positif', accepted: 'Risque accepté' };
  const completedTools = new Set(model.scanners.filter((scanner) => scanner.status === 'completed').map((scanner) => scanner.tool));
  const scanResultsTrusted = model.scanStatus === 'completed' || model.snapshotAvailable;
  const partialResultsAvailable = ['partial', 'cancelled'].includes(model.scanStatus) && completedTools.size > 0;
  const resultsAvailable = scanResultsTrusted || partialResultsAvailable;
  const optionTags = (values) => Object.keys(values).sort().map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
  const findingCards = model.findings.length
    ? model.findings.map((finding, index) => {
        const severity = String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase();
        const context = finding.sourceContext || 'non classé';
        const status = finding.triageStatus || 'new';
        const location = finding.endpoint || finding.file || 'Emplacement non fourni';
        const line = finding.startLine > 0 ? `:${finding.startLine + 1}` : '';
        const searchable = [finding.title, finding.tool, severity, context, status, location, finding.ruleId, finding.cwe]
          .filter(Boolean).join(' ').toLowerCase();
        return `<article class="finding-card" tabindex="0" data-search="${escapeHtml(searchable)}" data-tool="${escapeHtml(finding.tool)}" data-severity="${escapeHtml(severity)}" data-status="${escapeHtml(status)}" data-title="${escapeHtml(finding.title)}" data-location="${escapeHtml(location)}${escapeHtml(line)}" data-rule="${escapeHtml(finding.ruleId || finding.cwe || 'Règle non renseignée')}">
          <div class="finding-accent ${semanticClass(severity)}"></div>
          <div class="finding-main">
            <div class="finding-top">
              <span class="severity-badge ${semanticClass(severity)}">${escapeHtml(severity)}</span>
              <span class="tool-badge">${escapeHtml(finding.tool)}</span>
              <span class="context-badge">${escapeHtml(context)}</span>
              <span class="triage-badge">${escapeHtml(statusLabels[status] || status)}</span>
              ${finding.staleFromPreviousScan ? '<span class="triage-badge">Données du scan précédent</span>' : ''}
            </div>
            <strong class="finding-title">${escapeHtml(finding.title)}</strong>
            <span class="finding-location">${escapeHtml(location)}${escapeHtml(line)}</span>
            <small>${escapeHtml(finding.ruleId || finding.cwe || 'Règle non renseignée')}</small>
          </div>
          <div class="finding-card-actions">
            ${finding.absolutePath ? `<button class="finding-code" data-finding-code-index="${index}" title="Ouvrir le fichier à la ligne concernée">Ouvrir le code</button>` : ''}
            <button class="finding-open" data-finding-index="${index}" title="Afficher toutes les preuves et recommandations">Voir les détails →</button>
          </div>
        </article>`;
      }).join('')
    : '<div class="empty">Aucune vulnérabilité à afficher. Lancez une analyse du workspace.</div>';
  const currentFindings = resultsAvailable
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
  const currentActiveFindings = currentFindings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus));
  const currentCriticalCount = currentActiveFindings.filter((finding) => ['CRITICAL', 'ERROR'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  const currentHighCount = currentActiveFindings.filter((finding) => String(finding.rawSeverity || finding.severity || '').toUpperCase() === 'HIGH').length;
  const currentProductionPriority = currentActiveFindings.filter((finding) => finding.sourceContext === 'production' && ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
  const currentNewCount = currentFindings.filter((finding) => (finding.triageStatus || 'new') === 'new').length;
  const currentResolvedCount = currentFindings.filter((finding) => ['fixed', 'validated'].includes(finding.triageStatus)).length;
  const currentAcceptedCount = currentFindings.filter((finding) => finding.triageStatus === 'accepted').length;
  const priorityFindingCount = currentActiveFindings.filter((finding) => ['CRITICAL', 'ERROR', 'HIGH'].includes(String(finding.rawSeverity || finding.severity || '').toUpperCase())).length;
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
      const correlations = model.correlations.filter((correlation) => correlation.findingIds?.includes(finding.id));
      const sources = [...new Set([
        finding.tool,
        ...(finding.correlatedTools || []),
        ...correlations.flatMap((correlation) => correlation.tools || []),
        ...(matchingBurpScenario ? ['Burp'] : [])
      ].filter(Boolean))];
      const sourceLabel = sources.length > 1 ? sources.join(' + ') : sources[0] || 'Dynamic';
      const correlationLabel = sources.length > 1 ? `<span class="dynamic-correlation">${sources.length} sources</span>` : '';
      const status = finding.triageStatus || 'new';
      const sourceCorrelation = sourceCorrelationForFinding(finding, model.findings, model.correlations);
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
    ? model.scanners.map((scanner, index) => `<div class="scanner">
        <div class="scanner-index ${scanner.status}">${scanner.status === 'completed' ? '✓' : scanner.status === 'failed' ? '!' : index + 1}</div>
        <div class="scanner-copy"><strong>${escapeHtml(scanner.tool)}</strong>${scanner.details ? `<small>${escapeHtml(scanner.details)}</small>` : ''}${scanner.error ? `<small class="scanner-error">${escapeHtml(summarizeScannerError(scanner.error))}</small>` : ''}</div>
        <span class="status ${scanner.status}">${escapeHtml(scanner.status)}</span>
      </div>`).join('')
    : '<div class="empty">Aucun scanner exécuté</div>';
  const overviewScannerRows = model.scanners.length
    ? model.scanners.map((scanner) => {
      const count = currentFindings.filter((finding) => finding.tool === scanner.tool).length;
      const provenance = scanner.sourceExecutionId ? `scan ${scanner.sourceExecutionId}${scanner.completedAt ? ` · ${new Date(scanner.completedAt).toLocaleString('fr-FR')}` : ''}` : '';
      const refreshNote = scanner.lastRefreshStatus && scanner.lastRefreshStatus !== 'completed' ? ` · dernière actualisation ${escapeHtml(scanner.lastRefreshStatus)}` : '';
      return `<div class="overview-scanner"><span class="scanner-health ${escapeHtml(scanner.status)}">${scanner.status === 'completed' ? '✓' : scanner.status === 'failed' ? '!' : scanner.status === 'refreshing' ? '↻' : '•'}</span><strong>${escapeHtml(scanner.tool)}</strong><span>${count} alerte(s)</span><small>${scanner.status === 'refreshing' ? 'Actualisation en cours' : scanner.durationMs ? formatDuration(scanner.durationMs) : escapeHtml(scanner.status)}${provenance ? ` · ${escapeHtml(provenance)}` : ''}${refreshNote}</small></div>`;
    }).join('')
    : '<div class="empty">Aucun scanner exécuté.</div>';
  const correlationRows = model.correlations.length
    ? model.correlations.map((correlation) => `<div class="correlation">
        <strong>${escapeHtml(correlation.title)}</strong>
        <span>${escapeHtml(correlation.tools.join(' + '))} • confiance ${escapeHtml(correlation.confidence)}</span>
        <small>${escapeHtml(correlation.reason)}</small>
      </div>`).join('')
    : '<div class="empty">Aucune correspondance multi-outils</div>';
  const terminalStatuses = ['completed', 'partial', 'cancelled', 'failed'];
  const statusClass = model.scanStatus === 'completed' ? 'completed' : ['failed', 'cancelled', 'partial'].includes(model.scanStatus) ? 'failed' : 'running';
  const scanRunning = model.scanStatus !== 'idle' && !terminalStatuses.includes(model.scanStatus);
  const hasScanned = model.scanners.length > 0 || model.total > 0 || terminalStatuses.includes(model.scanStatus);
  const completedCount = model.scanners.filter((scanner) => scanner.status === 'completed' || scanner.previousValidResult).length;
  const failedTools = model.scanners.filter((scanner) => scanner.status === 'failed' && !scanner.previousValidResult).map((scanner) => scanner.tool);
  const failedScanners = model.scanners.filter((scanner) => scanner.status === 'failed');
  const cancelledTools = model.scanners.filter((scanner) => scanner.status === 'cancelled').map((scanner) => scanner.tool);
  const scanStatusLabel = model.scanStatus === 'cancelled'
    ? `Scan partiel — ${completedCount}/${model.scanners.length} scanners terminés${cancelledTools.length ? ` — ${cancelledTools.join(', ')} annulé${cancelledTools.length > 1 ? 's' : ''}` : ''}`
    : model.scanStatus === 'partial' ? `Scan partiel — ${completedCount}/${model.scanners.length} scanners terminés` : model.scanStatus;
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
  const resolvedCount = currentResolvedCount;
  const acceptedCount = currentAcceptedCount;
  const operationalState = failedTools.length || (scanResultsTrusted && model.policyResult?.passed === false) ? 'danger' : model.scanStatus === 'completed' ? 'success' : 'neutral';
  const operationalTitle = failedTools.length
    ? `Scan partiel — ${failedTools.join(', ')} en échec`
    : scanResultsTrusted && model.policyResult?.passed === false ? 'Livraison bloquée par la politique de sécurité' : model.scanStatus === 'completed' ? 'Analyse terminée' : 'État de l’analyse';
  const operationalDetails = [criticalCount ? `${criticalCount} alerte(s) critique(s)` : '', `${currentProductionPriority} priorité(s) production`, scanResultsTrusted && model.policyResult?.passed === false ? 'Politique non respectée' : scanResultsTrusted && model.policyResult?.passed === true ? 'Politique respectée' : ''].filter(Boolean).join(' • ');
  const failureDiagnostics = surface === 'full' && failedScanners.length
    ? `<section class="failure-diagnostics"><div><span class="failure-kicker">⚠ Scan incomplet</span><strong>${completedCount}/${model.scanners.length} scanners terminés</strong><p>${failedScanners.map((scanner) => `${escapeHtml(scanner.tool)} : ${escapeHtml(summarizeScannerError(scanner.error))}`).join(' • ')}</p></div><div class="failure-actions"><button class="secondary" data-command="securityCenter.scanSelected">Réessayer</button><button class="quiet-action" data-command="securityCenter.showLogs">Journal →</button></div></section>`
    : '';
  const currentRiskScore = calculateRiskScore(currentActiveFindings);
  const displayedRiskScore = resultsAvailable ? currentRiskScore : 0;
  const displayedRiskLevel = scanRunning && !model.snapshotAvailable ? 'en recalcul' : partialResultsAvailable && !model.snapshotAvailable ? `${riskLevel(currentRiskScore)} (partiel)` : scanResultsTrusted ? riskLevel(currentRiskScore) : 'non évalué';
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
  const zapCard = `<section class="zap-card ${escapeHtml(zapScanner?.status || 'idle')}"><div><span class="zap-kicker">Analyse dynamique</span><h4>ZAP — ${escapeHtml(zapMode)}</h4><p>${escapeHtml(zapScanner?.error ? summarizeScannerError(zapScanner.error) : `${zapFindingCount} alerte(s) runtime • ${zapAuth}`)}</p></div><div class="zap-meta"><span class="status ${escapeHtml(zapScanner?.status || 'pending')}">${escapeHtml(zapState)}</span><button class="secondary" data-command="securityCenter.scanZap">Relancer ZAP uniquement</button><button class="secondary" data-command="securityCenter.configureZapCredentials">Compte ZAP</button><button class="secondary" data-command="securityCenter.configureZap">Installer / configurer ZAP</button></div></section>`;
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style nonce="${nonce}">
    * { box-sizing: border-box; }
    body { color: var(--vscode-foreground); font-family: var(--vscode-font-family); padding: 16px; margin: 0 auto; max-width: 1200px; background: var(--vscode-sideBar-background); color-scheme: light; }
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
      color-scheme: light;
    }
    body.theme-dark { color-scheme: dark; }
    h2, h3 { margin: 0; }
    h2 { font-size: 23px; letter-spacing: -.4px; }
    h3 { font-size: 11px; letter-spacing: .8px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin: 22px 0 10px; }
    .header { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; margin-bottom: 16px; padding-bottom: 13px; border-bottom: 2px solid color-mix(in srgb, var(--vscode-button-background) 78%, #ff2da8 22%); }
    .header-actions { display: flex; align-items: flex-start; gap: 8px; }
    .theme-toggle { width: auto; padding: 5px 9px; color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); font-size: 10px; text-align: center; }
    .header-status { display: flex; flex-direction: column; align-items: flex-end; gap: 5px; }
    .header-scan { width: auto; min-width: 88px; padding: 5px 10px; text-align: center; color: var(--vscode-button-foreground); background: var(--vscode-button-background); font-size: 10px; }
    .header-scan:hover { background: var(--vscode-button-hoverBackground); }
    .scan-chrono { display: inline-flex; align-items: center; gap: 5px; min-width: 78px; padding: 5px 9px; border: 1px solid var(--vscode-widget-border); border-radius: 999px; color: var(--vscode-foreground); background: var(--vscode-editor-background); font: 600 10px var(--vscode-font-family); }
    .backend { color: var(--vscode-descriptionForeground); font-size: 10px; }
    .workspace { color: var(--vscode-descriptionForeground); overflow-wrap: anywhere; margin-top: 5px; }
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
    body.surface-dynamic > .operational-banner, body.surface-dynamic > .zap-card { display: none !important; }
    .dynamic-page-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin: 6px 0 16px; padding-bottom: 12px; border-bottom: 1px solid var(--vscode-widget-border); }
    .dynamic-page-header h1 { margin: 0; font-size: 22px; }
    .dynamic-page-header p { margin: 5px 0 0; color: var(--vscode-descriptionForeground); font-size: 11px; }
    .dynamic-section { margin: 0 0 10px; padding: 12px 14px; border: 1px solid var(--vscode-widget-border); border-radius: 6px; background: var(--vscode-editor-background); }
    .zap-confirmation-backdrop { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; padding: 18px; background: color-mix(in srgb, var(--vscode-editor-background) 72%, transparent); }
    .zap-confirmation { width: min(520px, 100%); padding: 18px; border: 1px solid var(--vscode-focusBorder); border-radius: 8px; color: var(--vscode-foreground); background: var(--vscode-editor-background); box-shadow: 0 8px 28px var(--vscode-widget-shadow, rgba(0,0,0,.25)); }
    .zap-confirmation-head { display: flex; gap: 12px; align-items: flex-start; }
    .zap-confirmation-icon { flex: 0 0 auto; color: var(--vscode-editorWarning-foreground); font-size: 22px; line-height: 1; }
    .zap-confirmation h2 { margin: 0; font-size: 15px; }
    .zap-confirmation p { margin: 7px 0 0; color: var(--vscode-descriptionForeground); line-height: 1.5; }
    .zap-confirmation-target { margin-top: 14px; padding: 9px 11px; border: 1px solid var(--vscode-input-border, var(--vscode-widget-border)); border-left: 3px solid var(--vscode-focusBorder); border-radius: 4px; color: var(--vscode-input-foreground); background: var(--vscode-input-background); }
    .zap-confirmation-target span, .zap-confirmation-target code { display: block; }
    .zap-confirmation-target span { margin-bottom: 4px; color: var(--vscode-descriptionForeground); font-size: 10px; }
    .zap-confirmation-target code { padding: 0; overflow-wrap: anywhere; color: var(--vscode-input-foreground); background: transparent; }
    .zap-confirmation .dynamic-actions { justify-content: flex-end; margin-top: 18px; }
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
    .overview-scanner { display: grid; grid-template-columns: 22px minmax(90px,1fr) auto 65px; align-items: center; gap: 8px; padding: 8px 0; border-bottom: 1px solid var(--vscode-widget-border); font-size: 10px; }
    .overview-scanner:last-child { border-bottom: 0; }
    .overview-scanner > span, .overview-scanner > small { color: var(--vscode-descriptionForeground); }
    .scanner-health { width: 19px; height: 19px; display: grid; place-items: center; border-radius: 50%; }
    .scanner-health.completed { color: #75d99f; background: rgba(46,160,87,.14); } .scanner-health.failed { color: #ff7b72; background: rgba(248,81,73,.14); }
    .activity-bars { display: grid; grid-template-columns: repeat(3, 1fr); align-items: end; gap: 10px; min-height: 104px; padding-top: 8px; }
    .activity-stat { display: grid; align-content: end; gap: 6px; text-align: center; height: 100%; }
    .activity-bar { width: 100%; min-height: 5px; border-radius: 5px 5px 2px 2px; background: #58a6ff; opacity: .82; }
    .activity-stat.resolved .activity-bar { background: #3fb950; } .activity-stat.accepted .activity-bar { background: #a371f7; }
    .activity-stat strong { font-size: 18px; } .activity-stat span { color: var(--vscode-descriptionForeground); font-size: 9px; text-transform: uppercase; }
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
    .findings-panel { border: 1px solid var(--vscode-widget-border); border-radius: 10px; padding: 12px; background: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 48%, transparent); }
    .finding-filters { display: grid; grid-template-columns: 1fr; gap: 7px; margin-bottom: 11px; }
    .finding-filters input, .finding-filters select { width: 100%; color: var(--vscode-input-foreground); background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, var(--vscode-widget-border)); border-radius: 6px; padding: 8px; font-family: inherit; }
    .finding-list { display: grid; gap: 8px; max-height: 720px; overflow-y: auto; padding-right: 3px; }
    .finding-layout { display: grid; gap: 10px; }
    .finding-preview { display: none; position: sticky; top: 12px; align-self: start; border: 1px solid var(--vscode-widget-border); border-radius: 9px; padding: 14px; background: var(--vscode-editor-background); }
    .finding-preview-label { color: var(--vscode-descriptionForeground); font-size: 9px; font-weight: 800; letter-spacing: .6px; text-transform: uppercase; }
    .finding-preview h4 { margin: 8px 0; font-size: 15px; line-height: 1.35; }
    .finding-preview span, .finding-preview small { display: block; overflow-wrap: anywhere; }
    .finding-preview span { color: var(--vscode-textLink-foreground); font-size: 11px; }
    .finding-preview small { margin-top: 8px; color: var(--vscode-descriptionForeground); }
    .finding-card { position: relative; display: grid; grid-template-columns: 4px 1fr; gap: 11px; border: 1px solid var(--vscode-widget-border); border-radius: 8px; padding: 10px 10px 10px 0; background: var(--vscode-editor-background); }
    .finding-card.hidden { display: none; }
    .finding-card.selected { border-color: var(--vscode-focusBorder); box-shadow: 0 0 0 1px var(--vscode-focusBorder); }
    .finding-accent { border-radius: 0 5px 5px 0; background: #8b949e; }
    .finding-accent.danger { background: #ff7b72; } .finding-accent.warning { background: #d29922; } .finding-accent.info { background: #58a6ff; }
    .finding-main { min-width: 0; }
    .finding-top { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 7px; }
    .severity-badge, .tool-badge, .context-badge, .triage-badge { border-radius: 999px; padding: 3px 7px; font-size: 9px; font-weight: 700; text-transform: uppercase; }
    .severity-badge { padding: 4px 9px; font-size: 10px; border: 1px solid currentColor; }
    .severity-badge { color: #c9d1d9; background: rgba(139,148,158,.18); }
    .severity-badge.danger { color: #ff453a; background: rgba(255,59,48,.17); }
    .severity-badge.warning { color: #e3b341; background: rgba(210,153,34,.16); }
    .severity-badge.info { color: #79c0ff; background: rgba(56,139,253,.16); }
    .tool-badge { color: #d2a8ff; background: rgba(163,113,247,.15); }
    .context-badge, .triage-badge { color: var(--vscode-descriptionForeground); background: var(--vscode-editor-inactiveSelectionBackground); }
    .finding-title, .finding-location, .finding-main small { display: block; overflow-wrap: anywhere; }
    .finding-title { font-size: 12px; line-height: 1.35; }
    .finding-location { margin-top: 5px; color: #79c0ff; font-size: 10px; }
    .finding-main small { margin-top: 4px; color: var(--vscode-descriptionForeground); }
    .finding-card-actions { grid-column: 2; display: flex; flex-wrap: wrap; gap: 6px; justify-self: start; }
    .finding-open, .finding-code { width: auto; padding: 5px 8px; background: transparent; border-color: var(--vscode-widget-border); font-size: 10px; }
    .finding-open { color: var(--vscode-textLink-foreground); }
    .finding-code { color: #75d99f; }
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

    /* Advanced compact dashboard presentation. This layer changes layout only. */
    body.surface-full {
      width: 100%;
      max-width: 1280px;
      padding: 24px clamp(20px, 3vw, 28px) 32px;
      font-family: var(--vscode-font-family);
    }
    body.surface-full h2 { font-size: 26px; font-weight: 650; line-height: 1.18; letter-spacing: -.45px; }
    body.surface-full .workspace { margin-top: 4px; font-size: 13px; opacity: .65; }
    body.surface-full h3,
    body.surface-full .overview-panel-head strong {
      font-size: 11px;
      font-weight: 650;
      letter-spacing: .6px;
    }
    body.surface-full .header { margin-bottom: 16px; padding-bottom: 12px; border-bottom-width: 1px; }
    body.surface-full .overview-summary {
      grid-template-columns: minmax(310px, .9fr) minmax(540px, 1.55fr);
      align-items: stretch;
      margin: 12px 0 24px;
      border-radius: 10px;
      background: var(--vscode-editor-background);
    }
    body.surface-full .hero {
      grid-template-columns: 82px minmax(0, 1fr);
      gap: 16px;
      min-height: 126px;
      padding: 16px 18px;
      border-right: 1px solid var(--vscode-widget-border);
      background: var(--vscode-editor-background);
    }
    body.surface-full .hero.critical,
    body.surface-full .hero.high,
    body.surface-full .hero.medium,
    body.surface-full .hero.low { background: var(--vscode-editor-background); }
    body.surface-full .risk-ring { width: 78px; }
    body.surface-full .risk-ring strong { font-size: 24px; }
    body.surface-full .risk-track,
    body.surface-full .risk-progress { stroke-width: 8; }
    body.surface-full .risk-label { font-size: 12px; font-weight: 700; letter-spacing: .6px; }
    body.surface-full .risk-explanation { max-width: 390px; font-size: 10.5px; }
    body.surface-full .overview-kpis { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    body.surface-full .overview-kpi { display: grid; align-content: center; min-width: 0; padding: 16px; background: var(--vscode-editor-background); }
    body.surface-full .overview-kpi strong { font-size: 25px; }
    body.surface-full .overview-kpi span { font-size: 10px; }
    body.surface-full .overview-kpi small { font-size: 10.5px; line-height: 1.35; }
    body.surface-full .pipeline-panel,
    body.surface-full .overview-panel,
    body.surface-full .priority-finding {
      border-radius: 9px;
      background: var(--vscode-editor-background);
      box-shadow: none;
    }
    body.surface-full .pipeline-panel { padding: 12px 10px 8px; }
    body.surface-full .pipeline { min-width: 660px; }
    body.surface-full .pipeline-stage { flex-basis: 84px; }
    body.surface-full .pipeline-dot { width: 32px; height: 32px; background: var(--vscode-editor-background); }
    body.surface-full .pipeline-line { min-width: 30px; }
    body.surface-full .pipeline-line.active { background: var(--vscode-testing-iconPassed, var(--vscode-progressBar-background)); }
    body.surface-full .overview-split { grid-template-columns: minmax(0, 1.15fr) minmax(310px, .85fr); gap: 16px; margin: 16px 0 24px; }
    body.surface-full .overview-panel { padding: 14px 16px; }
    body.surface-full .overview-scanner {
      grid-template-columns: 22px minmax(120px, 1fr) auto minmax(82px, auto);
      min-height: 54px;
      padding: 8px 2px;
      font-size: 10.5px;
      transition: background-color .12s ease;
    }
    body.surface-full .overview-scanner:hover {
      color: var(--vscode-list-hoverForeground, var(--vscode-foreground));
      background: var(--vscode-list-hoverBackground, var(--vscode-editor-inactiveSelectionBackground));
    }
    body.surface-full .scanner-health { width: 20px; height: 20px; }
    body.surface-full .activity-bars { min-height: 124px; }
    body.surface-full .activity-stat strong { font-size: 22px; }
    body.surface-full .activity-stat span { font-size: 10px; }
    body.surface-full .priority-findings { gap: 6px; margin-bottom: 24px; }
    body.surface-full .priority-finding { min-height: 54px; padding: 9px 11px; }
    body.surface-full .priority-finding:hover { background: var(--vscode-list-hoverBackground, var(--vscode-editor-inactiveSelectionBackground)); }
    body.surface-full button { transition: background-color .12s ease, border-color .12s ease, color .12s ease; }
    body.surface-full code,
    body.surface-full pre,
    body.surface-full .finding-location,
    body.surface-full .dynamic-source code,
    body.surface-full .traffic-row strong { font-family: var(--vscode-editor-font-family, monospace); }
    body.surface-sidebar { padding: 12px; }
    body.surface-sidebar h2 { font-size: 20px; font-weight: 650; }
    body.surface-sidebar .workspace { font-size: 12px; }
    body.surface-sidebar .action-group { padding: 9px; border-radius: 8px; }
    body.surface-sidebar .action-group-title { margin-bottom: 6px; font-size: 9px; }
    body.surface-sidebar .action-group-buttons { gap: 5px; }
    body.surface-sidebar .action-group-buttons button { padding: 7px 9px; font-size: 11px; }
    @media (max-width: 980px) {
      body.surface-full .overview-summary { grid-template-columns: 1fr; }
      body.surface-full .hero { border-right: 0; border-bottom: 1px solid var(--vscode-widget-border); }
      body.surface-full .overview-split { grid-template-columns: 1fr; }
    }
    @media (max-width: 680px) {
      body.surface-full { padding-inline: 16px; }
      body.surface-full .header { align-items: stretch; flex-direction: column; }
      body.surface-full .header-actions { flex-wrap: wrap; }
      body.surface-full .overview-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      body.surface-full .overview-kpi:nth-child(2) { border-right: 0; }
      body.surface-full .overview-kpi:nth-child(-n+2) { border-bottom: 1px solid var(--vscode-widget-border); }
      body.surface-full .hero { grid-template-columns: 72px minmax(0, 1fr); }
      body.surface-full .risk-ring { width: 68px; }
      body.surface-full .overview-scanner { grid-template-columns: 22px minmax(100px, 1fr) auto; }
      body.surface-full .overview-scanner small { grid-column: 2 / -1; }
    }
    @media (prefers-reduced-motion: reduce) {
      body.surface-full button,
      body.surface-full .overview-scanner { transition: none; }
    }
    @media (min-width: 760px) {
      body { padding: 28px; }
      .cards { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .http-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .action-sections { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .action-group-buttons { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .analytics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .finding-filters { grid-template-columns: minmax(240px, 2fr) repeat(3, minmax(130px, 1fr)); }
      .finding-card { grid-template-columns: 4px 1fr auto; align-items: center; }
      .finding-card-actions { grid-column: 3; grid-row: 1; justify-self: end; }
      .finding-layout { grid-template-columns: minmax(0, 1.7fr) minmax(240px, .8fr); align-items: start; }
      .finding-preview { display: block; }
      .workflow { grid-template-columns: repeat(5, minmax(0, 1fr)); }
      .workflow-step { grid-template-columns: 1fr; min-height: 130px; }
      .workflow-number { margin-bottom: 5px; }
      .overview-kpis { grid-template-columns: repeat(4, minmax(0,1fr)); }
      .overview-summary { grid-template-columns: minmax(320px, 1.2fr) minmax(560px, 2.8fr); align-items: stretch; }
      .overview-summary .hero { border-right: 1px solid var(--vscode-widget-border); }
      .overview-split { grid-template-columns: minmax(0,1.2fr) minmax(280px,.8fr); }
    }
  </style>
</head>
<body class="surface-${escapeHtml(surface)} theme-${selectedTheme === 'dark' ? 'dark' : 'light'}">
  <div class="header"><div><h2>Security Center</h2><div class="workspace">${escapeHtml(model.workspace)}</div></div><div class="header-actions"><button id="theme-toggle" class="theme-toggle" title="Changer le thème de Security Center">◐ Sombre</button>${scanRunning ? `<span id="scan-chrono" class="scan-chrono" data-started-at="${escapeHtml(model.scanStartedAt)}" data-elapsed="${model.scanDurationMs}">◷ ${escapeHtml(formatDuration(model.scanDurationMs))}</span>` : ''}${fullHeaderAction}<div class="header-status"><span class="status-pill ${statusClass}">${escapeHtml(scanStatusLabel)}</span><span class="backend">Backend ${escapeHtml(model.backendStatus)}</span></div></div></div>
  ${surface === 'history' ? '<div class="history-readonly"><strong>Scan historique — lecture seule</strong><br>Cette vue indépendante ne remplace pas le scan actuellement affiché.</div>' : ''}
  <div class="operational-banner ${operationalState}"><span class="operational-icon">${operationalState === 'danger' ? '!' : operationalState === 'success' ? '✓' : 'i'}</span><div class="operational-copy"><strong>${escapeHtml(operationalTitle)}</strong><span>${escapeHtml(operationalDetails)}</span></div></div>
  ${surface === 'sidebar' ? '<button class="primary sidebar-open" data-command="securityCenter.openDashboard">Ouvrir le dashboard complet</button>' : ''}
  ${surface === 'sidebar' ? `<div class="page-navigation"><button class="secondary" data-command="securityCenter.openFindingsPage">Findings</button><button class="secondary" data-command="securityCenter.openScansPage">Scans</button><button class="secondary" data-command="securityCenter.openAnalyticsPage">Analytics</button></div>` : ''}
  ${failureDiagnostics}
  ${surface === 'full' ? '<div class="overview-summary">' : ''}<div class="hero ${riskClass}"><div class="risk-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="risk-track" cx="50" cy="50" r="42"></circle><circle class="risk-progress" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="${displayedRiskScore} 100"></circle></svg><strong>${displayedRiskScore}</strong></div><div class="risk-copy"><div class="risk-label">Risque ${escapeHtml(displayedRiskLevel)}</div><span class="risk-explanation">${scanRunning && model.snapshotAvailable ? `Score conservé depuis le snapshot consolidé pendant l’actualisation ${escapeHtml(model.executionType || 'partielle')}.` : scanRunning ? 'Calcul en attente du premier résultat exploitable.' : partialResultsAvailable ? `Score partiel calculé uniquement avec ${completedTools.size} scanner(s) terminé(s). Un outil en échec n’est jamais interprété comme zéro alerte.` : scanResultsTrusted ? 'Score calculé à partir des résultats valides les plus récents de chaque scanner.' : 'Aucun scanner n’a terminé avec des résultats exploitables. Le risque courant ne peut pas être évalué.'}</span></div></div>
  ${surface === 'full' ? `<div class="overview-kpis"><div class="overview-kpi critical"><strong>${criticalCount}</strong><span>Critical</span><small>Exigent une attention immédiate</small></div><div class="overview-kpi high"><strong>${highCount}</strong><span>High</span><small>Priorité de correction élevée</small></div><div class="overview-kpi"><strong>${currentProductionPriority}</strong><span>Production</span><small>${newCount} nouvelle(s) au total</small></div><div class="overview-kpi"><strong>${model.completedScanners}/${model.scanners.length}</strong><span>Scanners</span><small>${failedTools.length ? `${failedTools.join(', ')} en échec` : 'Tous les scanners ont réussi'}</small></div></div></div>` : ''}
  ${policyBanner}
  <h3 class="sidebar-keep">Pipeline d’analyse</h3>
  <div class="pipeline-panel">${renderPipeline(model.scanners, model.scanStatus, model.scanDurationMs, model.findings.filter((finding) => !finding.staleFromPreviousScan))}</div>
  ${surface === 'full' ? `<div class="overview-split"><section class="overview-panel"><div class="overview-panel-head"><strong>Scanners</strong><button data-command="securityCenter.openScansPage">Voir les détails →</button></div>${overviewScannerRows}</section><section class="overview-panel"><div class="overview-panel-head"><strong>Activité de sécurité</strong><button data-command="securityCenter.showTrends">Tendances →</button></div><div class="activity-bars"><div class="activity-stat"><div class="activity-bar" style="height:${Math.max(8, Math.min(82, newCount * 2))}px"></div><strong>${newCount}</strong><span>Nouvelles</span></div><div class="activity-stat resolved"><div class="activity-bar" style="height:${Math.max(8, Math.min(82, resolvedCount * 5))}px"></div><strong>${resolvedCount}</strong><span>Corrigées</span></div><div class="activity-stat accepted"><div class="activity-bar" style="height:${Math.max(8, Math.min(82, acceptedCount * 5))}px"></div><strong>${acceptedCount}</strong><span>Acceptées</span></div></div></section></div>` : ''}
  ${zapCard}
  <div class="cards">
    <div class="card"><strong>${currentActiveFindings.length}</strong><span>Alertes actives</span></div>
    <div class="card"><strong>${currentFindings.length}</strong><span>Résultats du scan</span></div>
    <div class="card"><strong>${currentProductionPriority}</strong><span>Priorités production</span></div>
    <div class="card"><strong>${model.completedScanners}/${model.scanners.length}</strong><span>Scanners terminés</span></div>
    <div class="card"><strong>${resultsAvailable ? currentActiveFindings.filter((finding) => finding.sourceContext === 'runtime').length : 0}</strong><span>Alertes runtime</span></div>
    <div class="card"><strong>${resultsAvailable ? model.correlations.length : 0}</strong><span>Corrélations</span></div>
    <div class="card"><strong>${resultsAvailable ? model.correlationCounts.high || 0 : 0}</strong><span>Confiance élevée</span></div>
  </div>
  ${surface === 'full' ? `<h3>Priority Findings ${resultsAvailable ? `<button class="quiet-action" data-command="securityCenter.openFindingsPage">Voir les ${priorityFindingCount} priorité${priorityFindingCount > 1 ? 's' : ''} →</button>` : ''}</h3><div class="priority-findings">${priorityFindings}</div>` : ''}
  ${surface === 'sidebar' ? `<h3 class="sidebar-keep">Actions</h3>
  <div class="action-sections">
    <section class="action-group frequent"><div class="action-group-title">Analyse fréquente</div><div class="action-group-buttons"><button class="primary" data-command="securityCenter.scanWorkspace">Relancer l’analyse</button><button class="secondary" data-command="securityCenter.scanIncremental">Scan rapide des fichiers modifiés</button><button class="secondary" data-command="securityCenter.compareScans">Comparer les scans</button></div></section>
    <section class="action-group"><div class="action-group-title">Investigation</div><div class="action-group-buttons"><button class="secondary" data-command="securityCenter.openDynamicPage">Ouvrir Dynamic Security</button><button class="secondary" data-command="securityCenter.showScanHistoryPage">Ouvrir l’historique des scans</button><button class="secondary" data-command="securityCenter.showAuditLog">Ouvrir le journal d’audit</button><button class="secondary" data-command="securityCenter.showTrends">Tendances et MTTR</button></div></section>
    <section class="action-group"><div class="action-group-title">Rapports</div><div class="action-group-buttons"><button class="secondary" data-command="securityCenter.generateSbom">Exporter le SBOM</button><button class="secondary" data-command="securityCenter.checkLicenses">Contrôler les licences</button></div></section>
    <section class="action-group"><div class="action-group-title">Configuration et protection</div><div class="action-group-buttons"><button class="secondary" data-command="securityCenter.openScannerSetup">Scanners locaux</button><button class="secondary" data-command="securityCenter.openProjectPolicy">Politique projet</button><button class="secondary" data-command="securityCenter.configureOllama">Ollama local</button><button class="secondary" data-command="securityCenter.rollbackAiFix">Rollback IA</button><button class="secondary" data-command="securityCenter.configureBackendApiKey">Clé API backend</button><button class="secondary" data-command="securityCenter.configureTeamIntegrations">Slack / Jira</button><button class="secondary" data-command="securityCenter.installPreCommitHook">Protection pre-commit</button></div></section>
  </div>` : ''}
  <section class="page-findings"><header class="dynamic-page-header"><div><h1>Findings</h1><p>Alertes, preuves, triage et corrections.</p></div><button class="quiet-action" data-command="securityCenter.openDashboard">← Dashboard</button></header><h3>Vulnérabilités détaillées</h3>
  <section class="findings-panel">
    <div class="finding-filters">
      <input id="finding-search" type="search" placeholder="Rechercher une vulnérabilité, un fichier, une CVE/CWE…">
      <select id="finding-tool"><option value="">Tous les outils</option>${optionTags(model.byTool)}</select>
      <select id="finding-severity"><option value="">Toutes les sévérités</option>${optionTags(model.bySeverity)}</select>
      <select id="finding-status"><option value="">Tous les statuts</option>${optionTags(model.byStatus)}</select>
    </div>
    <div class="findings-count"><strong id="visible-findings">${model.findings.length}</strong> vulnérabilité(s) affichée(s)</div>
    <div class="finding-layout"><div class="finding-list">${findingCards}</div><aside class="finding-preview" aria-live="polite"><div class="finding-preview-label">Aperçu de l’alerte</div><h4 id="preview-title">Sélectionnez une vulnérabilité</h4><span id="preview-location">Le fichier ou l’endpoint apparaîtra ici.</span><small id="preview-rule">Utilisez « Voir les détails » pour ouvrir toutes les preuves et recommandations.</small></aside></div>
  </section></section>
  <section class="page-scans"><header class="dynamic-page-header"><div><h1>Scans</h1><p>État, résultats et exécution des scanners.</p></div><button class="quiet-action" data-command="securityCenter.openDashboard">← Dashboard</button></header><h3>Scanners</h3>${scannerRows}</section>
  <section class="page-analytics"><header class="dynamic-page-header"><div><h1>Analytics</h1><p>Répartition des alertes et signaux de sécurité.</p></div><button class="quiet-action" data-command="securityCenter.openDashboard">← Dashboard</button></header><div class="analytics-grid"><section class="analytics-panel"><h3>Répartition par outil</h3>${renderDonutChart(model.byTool, 'Répartition des alertes par outil')}</section><section class="analytics-panel"><h3>Répartition par sévérité</h3>${renderDonutChart(model.bySeverity, 'Répartition des alertes par sévérité')}</section></div>
  <h3>Par contexte</h3>${renderMetricRows(model.byContext, 'Aucun résultat')}
  <h3>Suivi de correction</h3>${renderMetricRows(model.byStatus, 'Aucun statut')}
  <h3>Corrélations multi-outils</h3>${correlationRows}</section>
  <section class="page-dynamic">
    <header class="dynamic-page-header"><div><h1>Dynamic Security</h1><p>Cible, tests dynamiques, findings et trafic HTTP capturé.</p></div><button class="quiet-action" data-command="securityCenter.openDashboard">← Dashboard</button></header>
    <section class="dynamic-section dynamic-target"><div class="dynamic-section-head"><h2>Cible</h2><span class="target-state ${escapeHtml(targetState)}">${escapeHtml(targetStatus)}</span></div><div class="dynamic-status-copy"><strong>${escapeHtml(targetOrigin || 'Aucune cible configurée')}</strong>${targetState === 'unreachable' ? '<span>Démarrez l’application avant de lancer une analyse dynamique.</span>' : targetState === 'unknown' && targetOrigin ? '<span>La cible n’a pas encore été vérifiée.</span>' : ''}</div><div class="dynamic-actions"><button class="secondary" data-command="securityCenter.checkDynamicTarget" ${targetOrigin ? '' : 'disabled'}>Vérifier</button><button class="secondary" data-command="securityCenter.changeDynamicTarget">Modifier la cible</button></div></section>
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
  ${surface !== 'history' && uiState.zapConfirmationVisible ? `<div class="zap-confirmation-backdrop"><section class="zap-confirmation" role="alertdialog" aria-modal="true" aria-labelledby="zap-confirmation-title" aria-describedby="zap-confirmation-copy"><div class="zap-confirmation-head"><span class="zap-confirmation-icon" aria-hidden="true">!</span><div><h2 id="zap-confirmation-title">Autoriser l'analyse ZAP ${escapeHtml(uiState.zapConfirmation?.mode || 'active')} ?</h2><p id="zap-confirmation-copy">ZAP va envoyer des requêtes de test à la cible locale. Continuez uniquement si vous êtes autorisé à tester cette application.</p></div></div>${uiState.zapConfirmation?.target ? `<div class="zap-confirmation-target"><span>Cible</span><code>${escapeHtml(uiState.zapConfirmation.target)}</code></div>` : ''}<p>Si vous refusez, Security Center utilisera le scan passif baseline.</p><div class="dynamic-actions"><button class="secondary" data-zap-cancel>Utiliser le scan passif</button><button class="primary" data-zap-confirm>Autoriser le scan local</button></div></section></div>` : ''}
  <section class="page-burp-settings">
    <header class="dynamic-page-header"><div><h1>Paramètres Burp</h1><p>État du connecteur et de la capture sécurisée.</p></div><div><button class="quiet-action" data-command="securityCenter.openDynamicPage">← Sécurité dynamique</button><button class="quiet-action" data-command="securityCenter.openDashboard">Dashboard</button></div></header>
    <section class="dynamic-section"><div class="dynamic-section-head"><h2>Connecteur</h2><span class="burp-connection ${model.burpConnected ? 'connected' : 'disconnected'}">${model.burpConnected ? '● Connecté' : '○ Déconnecté'}</span></div><div class="settings-list">
      <div class="settings-row"><span>État du connecteur</span><strong>${escapeHtml(model.burpStatus.status || (model.burpConnected ? 'ready' : 'unavailable'))}</strong></div>
      <div class="settings-row"><span>Endpoint</span><code>${escapeHtml(model.burpEndpoint || 'Non configuré')}</code></div>
      <div class="settings-row"><span>Dernier signal</span><strong>${escapeHtml(burpLastSeen)}</strong></div>
      <div class="settings-row"><span>État de la capture</span><strong>${model.burpConnected ? 'Connecteur actif' : 'Aucun signal'}</strong></div>
      <div class="settings-row"><span>Masquage des secrets</span><strong>Activé</strong></div>
      <div class="settings-row"><span>Requêtes enregistrées</span><strong>${burpStoredRequests}</strong></div>
    </div><div class="dynamic-actions"><button class="primary" data-command="securityCenter.testBurpConnection">Tester la connexion</button><button class="secondary" data-command="securityCenter.importHttpCapture">Importer un HAR</button></div></section>
    <section class="dynamic-section"><div class="dynamic-section-head"><h2>Avancé</h2><span>Optionnel</span></div><div class="settings-list"><div class="settings-row"><span>Connecteur</span><code>${escapeHtml(model.burpStatus.connector || 'security-center-burp')}</code></div><div class="settings-row"><span>Contrôle de connexion</span><strong>Géré dans Burp ; la déconnexion et la reconnexion automatiques ne sont pas prises en charge.</strong></div></div><div class="dynamic-actions"><button class="secondary" data-command="securityCenter.configureBurp">Guide d’installation et informations techniques</button></div></section>
  </section>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
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
    const updateThemeToggle = () => { themeToggle.textContent = document.body.classList.contains('theme-dark') ? '☀ Clair' : '◐ Sombre'; };
    updateThemeToggle();
    themeToggle.addEventListener('click', () => {
      const dark = !document.body.classList.contains('theme-dark');
      document.body.classList.toggle('theme-dark', dark);
      document.body.classList.toggle('theme-light', !dark);
      vscode.postMessage({ type: 'themeChanged', theme: dark ? 'dark' : 'light' });
      updateThemeToggle();
    });
    document.querySelectorAll('[data-command]').forEach((button) => {
      button.addEventListener('click', () => vscode.postMessage({ type: 'command', command: button.dataset.command }));
    });
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
    document.querySelectorAll('[data-zap-cancel]').forEach((button) => button.addEventListener('click', () => vscode.postMessage({ type: 'cancelZapScan' })));
    document.querySelectorAll('[data-zap-confirm]').forEach((button) => button.addEventListener('click', () => vscode.postMessage({ type: 'confirmZapScan' })));
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
    const findingCards = [...document.querySelectorAll('.finding-card')];
    const previewTitle = document.getElementById('preview-title');
    const previewLocation = document.getElementById('preview-location');
    const previewRule = document.getElementById('preview-rule');
    const selectFinding = (card) => {
      findingCards.forEach((item) => item.classList.toggle('selected', item === card));
      previewTitle.textContent = card.dataset.title;
      previewLocation.textContent = card.dataset.location;
      previewRule.textContent = card.dataset.severity + ' • ' + card.dataset.tool + ' • ' + card.dataset.rule;
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
    const visible = document.getElementById('visible-findings');
    const filterFindings = () => {
      const query = search.value.trim().toLowerCase();
      let count = 0;
      for (const card of findingCards) {
        const show = (!query || card.dataset.search.includes(query))
          && (!tool.value || card.dataset.tool === tool.value)
          && (!severity.value || card.dataset.severity === severity.value)
          && (!status.value || card.dataset.status === status.value);
        card.classList.toggle('hidden', !show);
        if (show) count += 1;
      }
      visible.textContent = String(count);
    };
    [search, tool, severity, status].forEach((control) => control?.addEventListener('input', filterFindings));
  </script>
</body>
</html>`;
}

module.exports = { buildDashboardModel, calculateRiskScore, riskLevel, countBy, escapeHtml, summarizeScannerError, renderDashboardHtml, endpointPath, isUsefulHttpScenario, linkedFindingsForScenario, sourceCorrelationForFinding, buildSafeHttpPreview };
