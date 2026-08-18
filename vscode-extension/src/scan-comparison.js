const { themeOverridesCss } = require('./theme-controller');

/**
 * Stable identity of a finding across scans.
 *
 * The scanner fingerprint is preferred, then the normalized id. The composite
 * fallback matters: both used to be able to come back `undefined`, and every
 * identity-less finding then collided with every other one — two unrelated
 * results would have looked like the same finding persisting. Real findings
 * always carry an id, so this only ever fires on malformed input, which is
 * exactly when a silent collision would be hardest to notice.
 */
function findingIdentity(finding) {
  if (finding.fingerprint) return String(finding.fingerprint);
  if (finding.id) return String(finding.id);
  return [
    finding.tool || '', finding.ruleId || '', finding.file || finding.endpoint || '',
    finding.startLine ?? '', finding.parameter || ''
  ].join('|');
}

function completedTools(result) {
  return new Set((result.scanners || [])
    .filter((scanner) => scanner.status === 'completed')
    .map((scanner) => scanner.tool));
}

function countBy(items, selector) {
  const counts = {};
  for (const item of items) {
    const key = selector(item) || 'UNKNOWN';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function compareScans(baseline, current) {
  const baselineTools = completedTools(baseline.result);
  const currentTools = completedTools(current.result);
  const comparableTools = [...baselineTools].filter((tool) => currentTools.has(tool)).sort();
  const allTools = new Set([...baselineTools, ...currentTools, ...(baseline.result.scanners || []).map((s) => s.tool), ...(current.result.scanners || []).map((s) => s.tool)]);
  const excludedTools = [...allTools].filter((tool) => !comparableTools.includes(tool)).sort();
  const baselineFindings = (baseline.result.findings || []).filter((finding) => comparableTools.includes(finding.tool));
  const currentFindings = (current.result.findings || []).filter((finding) => comparableTools.includes(finding.tool));
  const baselineById = new Map(baselineFindings.map((finding) => [findingIdentity(finding), finding]));
  const currentById = new Map(currentFindings.map((finding) => [findingIdentity(finding), finding]));
  const added = currentFindings.filter((finding) => !baselineById.has(findingIdentity(finding)));
  const resolved = baselineFindings.filter((finding) => !currentById.has(findingIdentity(finding)));
  const persistent = currentFindings.filter((finding) => baselineById.has(findingIdentity(finding)));
  
  const severityChanged = persistent.filter((finding) => {
    const oldFinding = baselineById.get(findingIdentity(finding));
    return oldFinding && String(oldFinding.rawSeverity).toUpperCase() !== String(finding.rawSeverity).toUpperCase();
  });
  const unchanged = persistent.filter((finding) => {
    const oldFinding = baselineById.get(findingIdentity(finding));
    return oldFinding && String(oldFinding.rawSeverity).toUpperCase() === String(finding.rawSeverity).toUpperCase();
  });

  /**
   * A regression: a finding the baseline had already dealt with, back again.
   *
   * « Dealt with » means the baseline carried an explicit triage verdict —
   * `validated` (a re-scan confirmed the fix), `fixed` (awaiting that re-scan) or
   * `false_positive` / `accepted` (judged not to require action). A finding that
   * was merely absent from the baseline is NEW, not regressed: never having been
   * seen is not the same as having been resolved.
   *
   * Detected on the stable identity, never on the title.
   */
  const RESOLVED_STATUSES = ['validated', 'fixed', 'false_positive', 'accepted'];
  const regressed = currentFindings.filter((finding) => {
    const previous = baselineById.get(findingIdentity(finding));
    if (!previous) return false;
    if (!RESOLVED_STATUSES.includes(String(previous.triageStatus || ''))) return false;
    // Still closed in the current scan? Then nothing regressed — the verdict
    // simply carried over.
    return !RESOLVED_STATUSES.includes(String(finding.triageStatus || ''));
  });
  const regressedIdentities = new Set(regressed.map((finding) => findingIdentity(finding)));

  const perTool = comparableTools.map((tool) => ({
    tool,
    before: baselineFindings.filter((finding) => finding.tool === tool).length,
    after: currentFindings.filter((finding) => finding.tool === tool).length,
    added: added.filter((finding) => finding.tool === tool).length,
    resolved: resolved.filter((finding) => finding.tool === tool).length,
    persistent: persistent.filter((finding) => finding.tool === tool).length,
    regressed: regressed.filter((finding) => finding.tool === tool).length
  }));
  return {
    baselineId: baseline.scan_id,
    currentId: current.scan_id,
    comparableTools,
    excludedTools,
    added,
    resolved,
    persistent,
    regressed,
    regressedIdentities: [...regressedIdentities],
    severityChanged,
    unchanged,
    perTool,
    beforeBySeverity: countBy(baselineFindings, (finding) => finding.rawSeverity),
    afterBySeverity: countBy(currentFindings, (finding) => finding.rawSeverity),
    baselineCount: baselineFindings.length,
    currentCount: currentFindings.length
  };
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function renderScanComparisonHtml(scans, nonce, selectedTheme = 'light') {
  return `<!doctype html>
<html lang="fr" class="theme-${selectedTheme === 'dark' ? 'dark' : 'light'}">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <style nonce="${nonce}">
    ${themeOverridesCss()}



    body {
      --page-background: var(--sc-bg);
      --card-background: var(--sc-surface);
      --vscode-foreground: var(--sc-text);
      --vscode-descriptionForeground: var(--sc-text-secondary);
      --vscode-panel-border: var(--sc-border);
    }

    html, body {
      background: var(--page-background);
      color: var(--vscode-foreground);
      font-family: var(--vscode-font-family);
      margin: 0;
      padding: 0;
      min-height: 100vh;
    }

    body {
      padding: 24px;
      max-width: 1200px;
      margin: auto;
      box-sizing: border-box;
    }

    /* Page Header */
    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .page-header h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 600;
      color: var(--vscode-foreground);
    }
    .page-header p {
      margin: 4px 0 0;
      font-size: 13px;
      color: var(--vscode-descriptionForeground);
    }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground, #5f6368);
      color: var(--vscode-button-secondaryForeground, #ffffff);
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 6px;
      padding: 8px 14px;
      cursor: pointer;
      font-family: inherit;
      font-weight: 500;
      transition: background 0.15s;
    }
    .btn-secondary:hover {
      background: var(--vscode-button-secondaryHoverBackground, #4f5357);
    }
    .btn-primary {
      background: var(--vscode-button-background, #007acc);
      color: var(--vscode-button-foreground, #ffffff);
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 6px;
      padding: 10px 24px;
      cursor: pointer;
      font-family: inherit;
      font-weight: 600;
      font-size: 13px;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn-primary:hover:not(:disabled) {
      background: var(--vscode-button-hoverBackground, #0062a3);
    }
    .btn-primary:disabled {
      background: var(--vscode-button-secondaryBackground, #3a3d41);
      color: var(--vscode-button-secondaryForeground, #969696);
      opacity: 0.65;
      cursor: not-allowed;
      border-color: transparent;
    }

    /* Selection Cards Row */
    .selection-cards {
      display: flex;
      align-items: stretch;
      gap: 24px;
      margin-bottom: 24px;
    }
    .selection-card {
      flex: 1;
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 16px 20px;
      position: relative;
      transition: all 0.2s ease;
      box-shadow: 0 2px 4px rgba(0,0,0,0.02);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    #selection-card-A::after {
      content: 'VS';
      position: absolute;
      right: -25px;
      top: 50%;
      transform: translateY(-50%) translateX(50%);
      font-size: 11px;
      font-weight: 700;
      color: var(--vscode-descriptionForeground);
      background: var(--page-background);
      border: 1px solid var(--vscode-panel-border);
      width: 26px;
      height: 26px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
      z-index: 10;
    }
    .selection-card.selected-A {
      border-left: 4px solid var(--vscode-charts-blue, #007acc);
      box-shadow: 0 2px 8px rgba(0, 122, 204, 0.1);
    }
    .selection-card.selected-B {
      border-left: 4px solid var(--vscode-charts-green, #4ca866);
      box-shadow: 0 2px 8px rgba(76, 168, 102, 0.1);
    }
    .selection-card-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--vscode-descriptionForeground);
    }
    .selection-card-empty {
      font-style: italic;
      color: var(--vscode-descriptionForeground);
      font-size: 13px;
      margin-top: 8px;
      padding: 12px 0;
    }
    .selection-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 13px;
      margin-top: 8px;
      color: var(--vscode-foreground);
    }
    .selection-card-id {
      font-size: 18px;
      font-weight: 700;
      color: var(--vscode-foreground);
    }
    .btn-deselect {
      position: absolute;
      top: 14px;
      right: 14px;
      background: transparent;
      color: var(--vscode-descriptionForeground);
      border: 1px solid var(--vscode-panel-border);
      cursor: pointer;
      font-size: 11px;
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: 500;
      transition: all 0.15s;
    }
    .btn-deselect:hover {
      background: rgba(120, 120, 120, 0.08);
      color: var(--vscode-foreground);
    }

    /* Action bar */
    .compare-action-bar {
      display: flex;
      justify-content: center;
      margin-bottom: 24px;
    }

    /* Scans Browser List Workspace */
    .workspace-section {
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .workspace-section h2 {
      margin-top: 0;
      margin-bottom: 16px;
      font-size: 16px;
      font-weight: 600;
      color: var(--vscode-foreground);
    }

    /* Warning Banner style */
    .warning-banner {
      background: var(--vscode-inputValidation-warningBackground, #5a4d2b);
      color: var(--vscode-inputValidation-warningForeground, #ffffff);
      border: 1px solid var(--vscode-inputValidation-warningBorder, #d29922);
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    /* Filter Bar */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: center;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 16px;
    }
    .filter-bar input, .filter-bar select {
      background: var(--sc-input-bg);
      color: var(--sc-input-text);
      border: 1px solid var(--sc-input-border);
      border-radius: 6px;
      padding: 8px 12px;
      font-family: inherit;
      font-size: 13px;
      box-sizing: border-box;
    }
    .filter-bar select option {
      background-color: var(--sc-input-bg);
      color: var(--sc-input-text);
    }
    .filter-bar input::placeholder {
      color: var(--sc-input-placeholder);
    }
    .filter-bar input:focus, .filter-bar select:focus {
      outline: none;
      border-color: var(--sc-primary);
    }
    .filter-bar input[type="text"] {
      flex-grow: 2;
      min-width: 250px;
    }
    .filter-bar select {
      min-width: 160px;
      cursor: pointer;
    }
    .checkbox-label {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      cursor: pointer;
      user-select: none;
      color: var(--vscode-foreground);
      font-weight: 500;
    }

    /* Scans Table */
    .scans-table-wrapper {
      overflow-x: auto;
    }
    .scans-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .scans-table th, .scans-table td {
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--vscode-panel-border);
      color: var(--vscode-foreground);
    }
    .scans-table th {
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
      background: rgba(120, 120, 120, 0.02);
    }
    .scans-row {
      cursor: pointer;
      transition: background 0.15s;
    }
    .scans-row:hover {
      background: rgba(120, 120, 120, 0.06);
    }
    .scans-row.selected-A {
      background: rgba(0, 122, 204, 0.08);
      font-weight: 600;
    }
    .scans-row.selected-B {
      background: rgba(76, 168, 102, 0.08);
      font-weight: 600;
    }
    .scans-row.selected-A td:first-child {
      box-shadow: inset 4px 0 0 0 var(--vscode-charts-blue, #007acc);
    }
    .scans-row.selected-B td:first-child {
      box-shadow: inset 4px 0 0 0 var(--vscode-charts-green, #4ca866);
    }
    
    /* Selection labels */
    .selection-label-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      font-size: 11px;
      font-weight: 700;
      color: #ffffff;
    }
    .selection-label-badge.label-A {
      background: var(--vscode-charts-blue, #007acc);
    }
    .selection-label-badge.label-B {
      background: var(--vscode-charts-green, #4ca866);
    }

    /* Badges */
    .status-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid transparent;
      cursor: help;
    }
    .status-badge.comparable {
      background: rgba(76, 168, 102, 0.12);
      color: var(--vscode-testing-iconPassed, #2e7d32);
      border-color: rgba(76, 168, 102, 0.3);
    }
    .status-badge.partiel {
      background: rgba(227, 192, 54, 0.12);
      color: var(--vscode-testing-iconQueued, #b78103);
      border-color: rgba(227, 192, 54, 0.3);
    }
    .status-badge.incomparable {
      background: rgba(120, 120, 120, 0.12);
      color: var(--vscode-descriptionForeground, #5f6368);
      border-color: rgba(120, 120, 120, 0.3);
    }

    /* Severity bullets */
    .sev-bullet {
      font-weight: 600;
    }
    .sev-bullet.crit { color: var(--vscode-charts-red, #e05151); }
    .sev-bullet.high { color: var(--vscode-charts-orange, #e38936); }
    
    /* Row toggle details */
    .btn-toggle-row {
      background: transparent;
      border: 0;
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      font-size: 11px;
      padding: 6px;
      border-radius: 4px;
    }
    .btn-toggle-row:hover {
      background: rgba(120, 120, 120, 0.1);
      color: var(--vscode-foreground);
    }
    .scans-row-details {
      display: none;
      background: rgba(120, 120, 120, 0.02);
    }
    .scans-row-details.expanded {
      display: table-row;
    }
    .details-content {
      padding: 14px 18px;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
      font-size: 13px;
    }
    .details-col-title {
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--vscode-foreground);
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 4px;
    }
    .details-item {
      margin: 4px 0;
      color: var(--vscode-foreground);
    }

    /* Comparison Area */
    .comparison-output-container {
      display: none;
    }
    .workspace-section {
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .workspace-section h2 {
      margin-top: 0;
      margin-bottom: 16px;
      font-size: 16px;
      font-weight: 500;
    }

    /* Warning Banner style */
    .warning-banner {
      background: var(--vscode-inputValidation-warningBackground, #5a4d2b);
      color: var(--vscode-inputValidation-warningForeground, #ffffff);
      border: 1px solid var(--vscode-inputValidation-warningBorder, #d29922);
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    /* Filter Bar */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
      border-bottom: 1px dashed var(--vscode-panel-border);
      padding-bottom: 16px;
    }
    .filter-bar input, .filter-bar select {
      background: var(--sc-input-bg);
      color: var(--sc-input-text);
      border: 1px solid var(--sc-input-border);
      border-radius: 4px;
      padding: 6px 10px;
      font-family: inherit;
      font-size: 13px;
    }
    .filter-bar select option {
      background-color: var(--sc-input-bg);
      color: var(--sc-input-text);
    }
    .filter-bar input::placeholder {
      color: var(--sc-input-placeholder);
    }
    .filter-bar input:focus, .filter-bar select:focus {
      outline: none;
      border-color: var(--sc-primary);
    }
    .filter-bar input[type="text"] {
      flex-grow: 1;
      min-width: 200px;
    }
    .checkbox-label {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      cursor: pointer;
      user-select: none;
    }

    /* Scans Table */
    .scans-table-wrapper {
      overflow-x: auto;
    }
    .scans-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .scans-table th, .scans-table td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .scans-table th {
      font-weight: 500;
      color: var(--vscode-descriptionForeground);
    }
    .scans-row {
      cursor: pointer;
      transition: background 0.15s;
    }
    .scans-row:hover {
      background: rgba(120, 120, 120, 0.05);
    }
    .scans-row.selected-A {
      background: rgba(0, 122, 204, 0.08);
    }
    .scans-row.selected-B {
      background: rgba(76, 168, 102, 0.08);
    }
    
    /* Selection labels */
    .selection-label-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      font-size: 11px;
      font-weight: 700;
      color: #fff;
    }
    .selection-label-badge.label-A {
      background: var(--vscode-charts-blue, #007acc);
    }
    .selection-label-badge.label-B {
      background: var(--vscode-charts-green, #4ca866);
    }

    /* Badges */
    .status-badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 500;
    }
    .status-badge.comparable {
      background: rgba(76, 168, 102, 0.15);
      color: var(--vscode-testing-iconPassed, #4ca866);
    }
    .status-badge.partiel {
      background: rgba(227, 192, 54, 0.15);
      color: var(--vscode-testing-iconQueued, #e3c036);
    }
    .status-badge.incomparable {
      background: rgba(160, 160, 160, 0.15);
      color: var(--vscode-descriptionForeground, #a0a0a0);
    }

    /* Severity bullets */
    .sev-bullet {
      font-weight: 500;
    }
    .sev-bullet.crit { color: var(--vscode-charts-red, #e05151); }
    .sev-bullet.high { color: var(--vscode-charts-orange, #e38936); }
    
    /* Row toggle details */
    .btn-toggle-row {
      background: transparent;
      border: 0;
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      font-size: 10px;
      padding: 4px;
    }
    .scans-row-details {
      display: none;
      background: rgba(120, 120, 120, 0.02);
    }
    .scans-row-details.expanded {
      display: table-row;
    }
    .details-content {
      padding: 12px 16px;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      font-size: 12px;
    }
    .details-col-title {
      font-size: 11px;
      padding: 6px;
      border-radius: 4px;
    }
    .btn-toggle-row:hover {
      background: rgba(120, 120, 120, 0.1);
      color: var(--vscode-foreground);
    }
    .scans-row-details {
      display: none;
      background: rgba(120, 120, 120, 0.02);
    }
    .scans-row-details.expanded {
      display: table-row;
    }
    .details-content {
      padding: 14px 18px;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
      font-size: 13px;
    }
    .details-col-title {
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--vscode-foreground);
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 4px;
    }
    .details-item {
      margin: 4px 0;
      color: var(--vscode-foreground);
    }

    /* Comparison Area */
    .comparison-output-container {
      display: none;
    }
    .comparison-output-container.active {
      display: block;
    }

    /* Summary Metric Rows */
    .metrics-summary-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    .metric-card {
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.02);
      transition: transform 0.2s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
    }
    .metric-card strong {
      font-size: 28px;
      font-weight: 700;
      display: block;
      color: var(--vscode-foreground);
    }
    .metric-card.good strong { color: var(--vscode-testing-iconPassed, #4ca866); }
    .metric-card.bad strong { color: var(--vscode-errorForeground, #d94b40); }
    .metric-card small {
      color: var(--vscode-descriptionForeground);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
      display: block;
    }

    .status-summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .status-summary-card {
      border: 1px solid var(--vscode-panel-border);
      background: var(--card-background);
      border-radius: 8px;
      padding: 12px 16px;
      text-align: left;
      box-shadow: 0 1px 3px rgba(0,0,0,0.01);
    }
    .status-summary-card small {
      display: block;
      font-size: 11px;
      font-weight: 500;
      color: var(--vscode-descriptionForeground);
      text-transform: uppercase;
      margin-bottom: 4px;
    }
    .status-summary-card strong {
      font-size: 22px;
      font-weight: 700;
      color: var(--vscode-foreground);
    }
    .status-summary-card.resolved strong { color: var(--vscode-testing-iconPassed, #4ca866); }
    .status-summary-card.new strong { color: var(--vscode-errorForeground, #d94b40); }
    .status-summary-card.unchanged strong { color: var(--vscode-foreground); }
    .status-summary-card.sevchanged strong { color: var(--vscode-charts-orange, #e38936); }

    /* Tables in Output */
    .output-grid-two-columns {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 24px;
    }
    .compact-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .compact-table th, .compact-table td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--vscode-panel-border);
      text-align: left;
    }
    .trend-badge {
      font-weight: 600;
      font-size: 12px;
    }
    .trend-badge.bad { color: var(--vscode-errorForeground, #d94b40); }
    .trend-badge.good { color: var(--vscode-testing-iconPassed, #4ca866); }
    .trend-badge.neutral { color: var(--vscode-foreground); }

    /* Tabs Nav */
    .tabs-nav {
      display: flex;
      border-bottom: 1px solid var(--vscode-panel-border);
      gap: 4px;
      margin-bottom: 16px;
    }
    .tab-btn {
      background: transparent;
      border: 0;
      color: var(--vscode-descriptionForeground);
      padding: 8px 16px;
      cursor: pointer;
      font-family: inherit;
      font-size: 13px;
      border-bottom: 2px solid transparent;
      transition: color 0.15s, border-color 0.15s;
    }
    .tab-btn:hover {
      color: var(--vscode-foreground);
    }
    .tab-btn.active {
      color: var(--vscode-foreground);
      border-color: var(--vscode-button-background);
      font-weight: 600;
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }

    /* Finding Row styling */
    .findings-list-wrapper {
      max-height: 450px;
      overflow-y: auto;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
    }
    .finding-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 14px;
      border-bottom: 1px solid var(--vscode-panel-border);
      gap: 16px;
      font-size: 13px;
    }
    .finding-row:last-child {
      border-bottom: 0;
    }
    .finding-info {
      flex-grow: 1;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .finding-meta {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .finding-sev-tag {
      font-weight: 700;
      font-size: 10px;
      text-transform: uppercase;
      padding: 1px 4px;
      border-radius: 3px;
    }
    .finding-sev-tag.CRITICAL { background: rgba(224, 81, 81, 0.15); color: #e05151; }
    .finding-sev-tag.HIGH { background: rgba(227, 137, 54, 0.15); color: #e38936; }
    .finding-sev-tag.MEDIUM { background: rgba(227, 192, 54, 0.15); color: #e3c036; }
    .finding-sev-tag.LOW { background: rgba(74, 144, 226, 0.15); color: #4a90e2; }
    
    .finding-title {
      font-weight: 500;
      color: var(--vscode-foreground);
    }
    .finding-file {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      font-family: var(--vscode-editor-font-family, monospace);
    }
    .finding-actions {
      display: flex;
      gap: 8px;
    }
    .btn-action-small {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: 0;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 11px;
      cursor: pointer;
      font-family: inherit;
    }
    .btn-action-small:hover {
      background: var(--vscode-button-secondaryHoverBackground);
    }
    .empty-findings {
      padding: 24px;
      text-align: center;
      color: var(--vscode-descriptionForeground);
      font-style: italic;
      background: var(--card-background);
    }

    /* Category list items */
    .category-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      border-bottom: 1px dashed var(--vscode-panel-border);
    }
    .category-item:last-child {
      border-bottom: 0;
    }

    /* Timeline style */
    .timeline-wrapper {
      display: flex;
      flex-direction: row;
      align-items: center;
      justify-content: center;
      margin: 20px 0;
      gap: 16px;
      background: var(--card-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.01);
    }
    .timeline-node {
      border: 1px solid var(--vscode-panel-border);
      background: var(--page-background);
      border-radius: 6px;
      padding: 12px 20px;
      text-align: center;
      font-size: 13px;
      min-width: 180px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }
    .timeline-arrow {
      width: 40px;
      height: 2px;
      background: var(--vscode-panel-border);
      position: relative;
    }
    .timeline-arrow::after {
      content: '';
      position: absolute;
      right: -2px;
      top: -3px;
      width: 0;
      height: 0;
      border-top: 4px solid transparent;
      border-bottom: 4px solid transparent;
      border-left: 6px solid var(--vscode-panel-border);
    }
    .timeline-elapsed {
      font-size: 11px;
      color: var(--vscode-foreground);
      font-weight: 600;
      background: rgba(120, 120, 120, 0.08);
      padding: 4px 10px;
      border-radius: 12px;
    }

    /* Raw details collapsible */
    .raw-details-summary {
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      background: var(--card-background);
      margin-top: 24px;
    }
    .raw-details-summary summary {
      padding: 10px 14px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      outline: none;
    }
    .raw-details-content {
      padding: 14px;
      border-top: 1px solid var(--vscode-panel-border);
      overflow-x: auto;
    }
    .raw-details-content pre {
      margin: 0;
      font-size: 11px;
      font-family: var(--vscode-editor-font-family, monospace);
      color: var(--vscode-descriptionForeground);
    }

    /* Responsive */
    @media (max-width: 768px) {
      .selection-cards {
        flex-direction: column;
        gap: 32px;
      }
      #selection-card-A::after {
        right: 50%;
        top: auto;
        bottom: -29px;
        transform: translateY(50%) translateX(50%);
      }
      .output-grid-two-columns {
        grid-template-columns: 1fr;
      }
      .metrics-summary-row, .status-summary-grid {
        grid-template-columns: repeat(2, 1fr);
      }
      .finding-row {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
      }
      .finding-actions {
        width: 100%;
        justify-content: flex-end;
      }
      .filter-bar {
        flex-direction: column;
        align-items: stretch;
      }
      .filter-bar input[type="text"], .filter-bar select, .checkbox-label {
        width: 100%;
        box-sizing: border-box;
      }
      .details-content {
        grid-template-columns: 1fr;
        gap: 12px;
      }
      .timeline-wrapper {
        flex-direction: column;
        gap: 8px;
      }
      .timeline-arrow {
        width: 2px;
        height: 24px;
      }
      .timeline-arrow::after {
        right: auto;
        left: -3px;
        bottom: -4px;
        top: auto;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid var(--vscode-panel-border);
      }
    }
  </style>
</head>
<body class="theme-${selectedTheme === 'dark' ? 'dark' : 'light'}">
  <!-- Page Header -->
  <header class="page-header">
    <div>
      <h1>Comparer les scans</h1>
      <p>Comparez deux états de sécurité du projet.</p>
    </div>
    <button class="btn-secondary" id="btn-back-dashboard">← Dashboard</button>
  </header>

  <!-- Selection Cards -->
  <section class="selection-cards">
    <!-- Card A -->
    <div class="selection-card" id="selection-card-A">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <div class="selection-card-title" style="margin: 0;">Scan A — Avant</div>
        <span class="selection-label-badge label-A">A</span>
      </div>
      <div class="selection-card-empty" id="card-A-empty">Aucun scan sélectionné (référence)</div>
      <div class="selection-card-details" id="card-A-details" style="display: none;">
        <div class="selection-card-id" id="card-A-id" style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">Scan #—</div>
        <div id="card-A-date" style="margin-bottom: 4px;">Date : —</div>
        <div id="card-A-findings" style="margin-bottom: 4px;">— alertes</div>
        <div id="card-A-severity" style="margin-bottom: 4px;">— critiques / — hautes</div>
        <div id="card-A-scanners" style="margin-bottom: 4px;">Couverture : —</div>
        <div id="card-A-quality">Qualité : —</div>
      </div>
      <button class="btn-deselect" id="btn-deselect-A" style="display: none;">Désélectionner</button>
    </div>

    <!-- Card B -->
    <div class="selection-card" id="selection-card-B">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <div class="selection-card-title" style="margin: 0;">Scan B — Après</div>
        <span class="selection-label-badge label-B">B</span>
      </div>
      <div class="selection-card-empty" id="card-B-empty">Aucun scan sélectionné (comparé)</div>
      <div class="selection-card-details" id="card-B-details" style="display: none;">
        <div class="selection-card-id" id="card-B-id" style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">Scan #—</div>
        <div id="card-B-date" style="margin-bottom: 4px;">Date : —</div>
        <div id="card-B-findings" style="margin-bottom: 4px;">— alertes</div>
        <div id="card-B-severity" style="margin-bottom: 4px;">— critiques / — hautes</div>
        <div id="card-B-scanners" style="margin-bottom: 4px;">Couverture : —</div>
        <div id="card-B-quality">Qualité : —</div>
      </div>
      <button class="btn-deselect" id="btn-deselect-B" style="display: none;">Désélectionner</button>
    </div>
  </section>

  <!-- Compare Action Button -->
  <div class="compare-action-bar">
    <button class="btn-primary" id="btn-compare-scans" disabled>Comparer les scans</button>
  </div>

  <!-- Warning Banner -->
  <div class="warning-banner" id="warning-banner-toast"></div>

  <!-- Available Scans Workspace -->
  <section class="workspace-section">
    <h2>Historique des scans disponibles</h2>
    
    <!-- Filter bar -->
    <div class="filter-bar" data-debug-theme-fix="scan-comparison-v3">
      <input type="text" id="search-scan-input" placeholder="Rechercher par ID ou nom de projet...">
      
      <select id="filter-status-select">
        <option value="ALL">Tous les statuts</option>
        <option value="Completed">Complets uniquement</option>
        <option value="Partial">Partiels</option>
      </select>
      
      <select id="sort-order-select">
        <option value="newest">Plus récent en premier</option>
        <option value="oldest">Plus ancien en premier</option>
      </select>

      <label class="checkbox-label">
        <input type="checkbox" id="comparable-only-checkbox">
        Comparable uniquement
      </label>
    </div>

    <!-- Scans Table -->
    <div class="scans-table-wrapper">
      <table class="scans-table">
        <thead>
          <tr>
            <th style="width: 80px; text-align: center;">Sélection</th>
            <th>Scan</th>
            <th>Date / Heure</th>
            <th>Alertes</th>
            <th>Critical / High</th>
            <th>Couverture scanners</th>
            <th>Qualité</th>
            <th style="width: 60px; text-align: center;">Détails</th>
          </tr>
        </thead>
        <tbody id="scans-table-tbody">
          <!-- Rows inserted via script -->
        </tbody>
      </table>
    </div>
  </section>

  <!-- Comparison Output -->
  <section class="comparison-output-container" id="comparison-result-area">
    <div class="workspace-section">
      <h2 id="comparison-report-header">Rapport de comparaison : Scan #A → Scan #B</h2>
      
      <!-- Metrics KPI row -->
      <div class="metrics-summary-row">
        <div class="metric-card" id="metric-before">
          <strong id="metric-before-val">0</strong>
          <small>Avant (A)</small>
        </div>
        <div class="metric-card" id="metric-after">
          <strong id="metric-after-val">0</strong>
          <small>Après (B)</small>
        </div>
        <div class="metric-card" id="metric-diff">
          <strong id="metric-diff-val">0</strong>
          <small>Différence absolue</small>
        </div>
        <div class="metric-card" id="metric-pct">
          <strong id="metric-pct-val">0 %</strong>
          <small>Évolution</small>
        </div>
      </div>

      <!-- Quick stats summary counts -->
      <div class="status-summary-grid">
        <div class="status-summary-card resolved">
          <small>Résolues</small>
          <strong id="stat-count-resolved">0</strong>
        </div>
        <div class="status-summary-card new">
          <small>Nouvelles</small>
          <strong id="stat-count-new">0</strong>
        </div>
        <div class="status-summary-card unchanged">
          <small>Inchangées</small>
          <strong id="stat-count-unchanged">0</strong>
        </div>
        <div class="status-summary-card sevchanged">
          <small>Sévérité modifiée</small>
          <strong id="stat-count-sevchanged">0</strong>
        </div>
      </div>

      <!-- Severity and Scanner comparison columns -->
      <div class="output-grid-two-columns">
        <!-- Severity Comp -->
        <div>
          <h3>Évolution par sévérité</h3>
          <table class="compact-table">
            <thead>
              <tr>
                <th>Sévérité</th>
                <th>Avant</th>
                <th>Après</th>
                <th>Évolution</th>
              </tr>
            </thead>
            <tbody id="severity-comp-tbody">
              <!-- Severity rows -->
            </tbody>
          </table>
        </div>

        <!-- Scanner Comp -->
        <div>
          <h3>Évolution par outil</h3>
          <table class="compact-table">
            <thead>
              <tr>
                <th>Scanner</th>
                <th>Avant</th>
                <th>Après</th>
                <th>Évolution</th>
              </tr>
            </thead>
            <tbody id="scanner-comp-tbody">
              <!-- Scanner rows -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Category Breakdown -->
      <div style="margin-bottom: 24px;">
        <h3>Répartition par catégorie</h3>
        <div style="border: 1px solid var(--vscode-panel-border); border-radius: 6px; background: var(--card-background);" id="category-breakdown-list">
          <!-- Categories list -->
        </div>
      </div>

      <!-- Timeline visual -->
      <div>
        <h3>Ligne temporelle</h3>
        <div class="timeline-wrapper">
          <div class="timeline-node">
            <strong id="timeline-A-title">Scan #A</strong>
            <div style="font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px;" id="timeline-A-time">—</div>
          </div>
          <div class="timeline-arrow"></div>
          <div class="timeline-elapsed" id="timeline-elapsed-text">Écart : —</div>
          <div class="timeline-arrow"></div>
          <div class="timeline-node">
            <strong id="timeline-B-title">Scan #B</strong>
            <div style="font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px;" id="timeline-B-time">—</div>
          </div>
        </div>
      </div>

      <!-- Findings Diff tab list -->
      <div style="margin-top: 30px;">
        <h3>Détail des alertes comparées</h3>
        <div class="tabs-nav">
          <button class="tab-btn active" data-tab="tab-new" id="tab-btn-new">Nouvelles (<span id="tab-count-new">0</span>)</button>
          <button class="tab-btn" data-tab="tab-resolved" id="tab-btn-resolved">Disparues (<span id="tab-count-resolved">0</span>)</button>
          <button class="tab-btn" data-tab="tab-persistent" id="tab-btn-persistent">Persistantes (<span id="tab-count-persistent">0</span>)</button>
          <button class="tab-btn" data-tab="tab-sevchanged" id="tab-btn-sevchanged">Sévérité modifiée (<span id="tab-count-sevchanged">0</span>)</button>
        </div>

        <div class="tab-content active" id="tab-new">
          <div class="findings-list-wrapper" id="list-new-findings"></div>
        </div>
        <div class="tab-content" id="tab-resolved">
          <div class="findings-list-wrapper" id="list-resolved-findings"></div>
        </div>
        <div class="tab-content" id="tab-persistent">
          <div class="findings-list-wrapper" id="list-persistent-findings"></div>
        </div>
        <div class="tab-content" id="tab-sevchanged">
          <div class="findings-list-wrapper" id="list-sevchanged-findings"></div>
        </div>
      </div>

      <!-- Technical details -->
      <details class="raw-details-summary">
        <summary>Détails techniques de comparaison</summary>
        <div class="raw-details-content" style="font-size: 13px; padding: 14px;">
          <div style="margin-bottom: 8px;"><strong>Outils comparés :</strong> <span id="raw-comparable-tools">—</span></div>
          <div><strong>Outils exclus (non complétés dans les deux scans) :</strong> <span id="raw-excluded-tools">—</span></div>
        </div>
      </details>
    </div>
  </section>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    // Safe date formatting helper to prevent RangeError: Invalid time value
    function formatDate(dateVal) {
      if (!dateVal) return '—';
      const d = new Date(dateVal);
      if (isNaN(d.getTime())) return '—';
      return d.toLocaleString('fr-FR');
    }
    
    // Scans data payload (Base64 decoded for safety against early script tag termination)
    const scansBase64 = "${Buffer.from(JSON.stringify(scans)).toString('base64')}";
    const rawScans = JSON.parse(atob(scansBase64));
    
    // State
    let scanAId = null;
    let scanBId = null;
    let expandedScanId = null;
    let activeComparison = null;

    // Determine targetTools from scans completed list
    let maxToolsSize = -1;
    let targetTools = new Set();
    rawScans.forEach(s => {
      const scanners = s.result?.scanners || [];
      const completed = new Set(scanners.filter(x => x.status === 'completed').map(x => x.tool));
      if (completed.size > maxToolsSize) {
        maxToolsSize = completed.size;
        targetTools = completed;
      }
    });

    const checkScanComparability = (s) => {
      const scanners = s.result?.scanners || [];
      const hasFailedOrCancelled = scanners.some(x => x.status === 'failed' || x.status === 'cancelled');
      const completed = new Set(scanners.filter(x => x.status === 'completed').map(x => x.tool));
      
      if (completed.size === 0) return 'incomparable';
      
      const matchesTarget = completed.size === targetTools.size && [...targetTools].every(t => completed.has(t));
      if (matchesTarget && !hasFailedOrCancelled) {
        return 'comparable';
      }
      return 'partiel';
    };

    // Enrich scans list
    const scansList = rawScans.map(s => {
      const scanners = s.result?.scanners || [];
      const active = s.result?.findings?.filter(f => !['false_positive', 'fixed', 'validated', 'accepted'].includes(f.triageStatus)) || [];
      const quality = checkScanComparability(s);
      
      return {
        scan_id: s.scan_id,
        finished_at: s.result?.finished_at || s.finished_at,
        findingsCount: s.result?.findings?.length || 0,
        activeCount: active.length,
        criticalCount: active.filter(f => String(f.rawSeverity).toUpperCase() === 'CRITICAL').length,
        highCount: active.filter(f => ['HIGH', 'ERROR'].includes(String(f.rawSeverity).toUpperCase())).length,
        scanners: scanners,
        quality: quality,
        raw: s
      };
    });

    // Handle back dashboard
    document.getElementById('btn-back-dashboard').addEventListener('click', () => {
      vscode.postMessage({ command: 'openDashboard' });
    });

    // Handle Selection deselect buttons
    document.getElementById('btn-deselect-A').addEventListener('click', (e) => {
      e.stopPropagation();
      scanAId = null;
      updateSelectionUI();
    });
    document.getElementById('btn-deselect-B').addEventListener('click', (e) => {
      e.stopPropagation();
      scanBId = null;
      updateSelectionUI();
    });

    // Handle Compare button trigger
    document.getElementById('btn-compare-scans').addEventListener('click', () => {
      if (scanAId !== null && scanBId !== null) {
        vscode.postMessage({
          command: 'compare',
          baselineId: scanAId,
          currentId: scanBId
        });
      }
    });

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');
      });
    });

    // Sorting and filter listeners
    document.getElementById('search-scan-input').addEventListener('input', renderScansList);
    document.getElementById('filter-status-select').addEventListener('change', renderScansList);
    document.getElementById('sort-order-select').addEventListener('change', renderScansList);
    document.getElementById('comparable-only-checkbox').addEventListener('change', renderScansList);

    function showWarning(message) {
      const banner = document.getElementById('warning-banner-toast');
      banner.innerText = message;
      banner.style.display = 'block';
      setTimeout(() => { banner.style.display = 'none'; }, 4000);
    }

    function toggleRowDetails(scanId, e) {
      e.stopPropagation();
      expandedScanId = expandedScanId === scanId ? null : scanId;
      renderScansList();
    }

    function selectScan(scanId) {
      // If already A or B, deselect it
      if (scanAId === scanId) {
        scanAId = null;
        updateSelectionUI();
        return;
      }
      if (scanBId === scanId) {
        scanBId = null;
        updateSelectionUI();
        return;
      }

      // If A is free, assign it
      if (scanAId === null) {
        scanAId = scanId;
      } else if (scanBId === null) {
        // If B is free, assign it
        scanBId = scanId;
      } else {
        // Both selected: show warning banner
        showWarning("Vous avez déjà sélectionné deux scans. Veuillez en désélectionner un pour faire un nouveau choix.");
      }
      updateSelectionUI();
    }

    function updateSelectionUI() {
      // Update Card A
      const cardA = scansList.find(s => s.scan_id === scanAId);
      if (cardA) {
        document.getElementById('card-A-empty').style.display = 'none';
        document.getElementById('card-A-details').style.display = 'block';
        document.getElementById('btn-deselect-A').style.display = 'block';
        document.getElementById('card-A-id').innerText = 'Scan #' + cardA.scan_id;
        document.getElementById('card-A-date').innerText = 'Date : ' + formatDate(cardA.finished_at);
        document.getElementById('card-A-findings').innerText = cardA.findingsCount + ' alertes (' + cardA.activeCount + ' actives)';
        document.getElementById('card-A-severity').innerHTML = 'Sévérité : <span class="sev-bullet crit">' + cardA.criticalCount + ' critiques</span>, <span class="sev-bullet high">' + cardA.highCount + ' hautes</span>';
        
        const completedA = cardA.scanners.filter(x => x.status === 'completed').length;
        document.getElementById('card-A-scanners').innerText = 'Couverture : ' + completedA + '/' + cardA.scanners.length + ' scanners complétés';
        
        let qualHtml = '';
        if (cardA.quality === 'comparable') {
          qualHtml = '<span class="status-badge comparable" title="État suffisamment complet pour une comparaison fiable.">✓ Comparable</span>';
        } else if (cardA.quality === 'partiel') {
          qualHtml = '<span class="status-badge partiel" title="Tous les scanners attendus n\\\'ont pas été exécutés.">⚠ Partiel</span>';
        } else {
          qualHtml = '<span class="status-badge incomparable" title="Le scan contient une couverture insuffisante ou un échec.">✗ Incomplet</span>';
        }
        document.getElementById('card-A-quality').innerHTML = 'Qualité : ' + qualHtml;
      } else {
        document.getElementById('card-A-empty').style.display = 'block';
        document.getElementById('card-A-details').style.display = 'none';
        document.getElementById('btn-deselect-A').style.display = 'none';
      }

      // Update Card B
      const cardB = scansList.find(s => s.scan_id === scanBId);
      if (cardB) {
        document.getElementById('card-B-empty').style.display = 'none';
        document.getElementById('card-B-details').style.display = 'block';
        document.getElementById('btn-deselect-B').style.display = 'block';
        document.getElementById('card-B-id').innerText = 'Scan #' + cardB.scan_id;
        document.getElementById('card-B-date').innerText = 'Date : ' + formatDate(cardB.finished_at);
        document.getElementById('card-B-findings').innerText = cardB.findingsCount + ' alertes (' + cardB.activeCount + ' actives)';
        document.getElementById('card-B-severity').innerHTML = 'Sévérité : <span class="sev-bullet crit">' + cardB.criticalCount + ' critiques</span>, <span class="sev-bullet high">' + cardB.highCount + ' hautes</span>';
        
        const completedB = cardB.scanners.filter(x => x.status === 'completed').length;
        document.getElementById('card-B-scanners').innerText = 'Couverture : ' + completedB + '/' + cardB.scanners.length + ' scanners complétés';
        
        let qualHtml = '';
        if (cardB.quality === 'comparable') {
          qualHtml = '<span class="status-badge comparable" title="État suffisamment complet pour une comparaison fiable.">✓ Comparable</span>';
        } else if (cardB.quality === 'partiel') {
          qualHtml = '<span class="status-badge partiel" title="Tous les scanners attendus n\\\'ont pas été exécutés.">⚠ Partiel</span>';
        } else {
          qualHtml = '<span class="status-badge incomparable" title="Le scan contient une couverture insuffisante ou un échec.">✗ Incomplet</span>';
        }
        document.getElementById('card-B-quality').innerHTML = 'Qualité : ' + qualHtml;
      } else {
        document.getElementById('card-B-empty').style.display = 'block';
        document.getElementById('card-B-details').style.display = 'none';
        document.getElementById('btn-deselect-B').style.display = 'none';
      }

      // Enable/disable compare button
      const compareBtn = document.getElementById('btn-compare-scans');
      if (scanAId !== null && scanBId !== null) {
        compareBtn.disabled = false;
        compareBtn.innerText = 'Comparer #' + scanAId + ' → #' + scanBId;
      } else {
        compareBtn.disabled = true;
        compareBtn.innerText = 'Comparer les scans';
      }

      renderScansList();
    }

    function renderScansList() {
      const tbody = document.getElementById('scans-table-tbody');
      tbody.innerHTML = '';

      if (scansList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--vscode-descriptionForeground); padding: 24px;">Aucun scan disponible pour ce projet.</td></tr>';
        return;
      }

      const query = document.getElementById('search-scan-input').value.toLowerCase();
      const statusFilter = document.getElementById('filter-status-select').value;
      const comparableOnly = document.getElementById('comparable-only-checkbox').checked;
      const sortOrder = document.getElementById('sort-order-select').value;

      // Filter
      let filtered = scansList.filter(s => {
        // Search query match
        const matchesQuery = String(s.scan_id).includes(query) || 
                             formatDate(s.finished_at).toLowerCase().includes(query) ||
                             (s.raw.workspace && s.raw.workspace.toLowerCase().includes(query));
        if (!matchesQuery) return false;

        // Status match
        if (statusFilter === 'Completed') {
          // completed scans have no failed or cancelled tools
          const hasFailedOrCancelled = s.scanners.some(x => x.status === 'failed' || x.status === 'cancelled');
          if (hasFailedOrCancelled) return false;
        } else if (statusFilter === 'Partial') {
          const hasFailedOrCancelled = s.scanners.some(x => x.status === 'failed' || x.status === 'cancelled');
          if (!hasFailedOrCancelled) return false;
        }

        // Comparable match
        if (comparableOnly && s.quality !== 'comparable') return false;

        return true;
      });

      // Sort
      filtered.sort((a, b) => {
        const timeA = new Date(a.finished_at).getTime();
        const timeB = new Date(b.finished_at).getTime();
        return sortOrder === 'newest' ? timeB - timeA : timeA - timeB;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--vscode-descriptionForeground); padding: 24px;">Aucun scan disponible correspondant aux critères.</td></tr>';
        return;
      }

      filtered.forEach(s => {
        const tr = document.createElement('tr');
        tr.className = 'scans-row';
        if (s.scan_id === scanAId) tr.classList.add('selected-A');
        if (s.scan_id === scanBId) tr.classList.add('selected-B');
        
        tr.addEventListener('click', () => selectScan(s.scan_id));

        // Checkbox / Badge state cell
        const selectTd = document.createElement('td');
        selectTd.style.textAlign = 'center';
        if (s.scan_id === scanAId) {
          selectTd.innerHTML = '<span class="selection-label-badge label-A">A</span>';
        } else if (s.scan_id === scanBId) {
          selectTd.innerHTML = '<span class="selection-label-badge label-B">B</span>';
        } else {
          selectTd.innerHTML = '<input type="checkbox" style="pointer-events: none;">';
        }

        // Scan ID cell
        const idTd = document.createElement('td');
        idTd.innerText = '#' + s.scan_id;

        // Date/Time cell
        const dateTd = document.createElement('td');
        dateTd.innerText = formatDate(s.finished_at);

        // Alert count cell
        const countTd = document.createElement('td');
        countTd.innerText = s.findingsCount + ' (' + s.activeCount + ' active(s))';

        // Severity count cell
        const sevTd = document.createElement('td');
        sevTd.innerHTML = '<span class="sev-bullet crit">' + s.criticalCount + ' Crit.</span> · ' +
                           '<span class="sev-bullet high">' + s.highCount + ' High</span>';

        // Scanners count cell
        const scannersTd = document.createElement('td');
        const completedScanners = s.scanners.filter(x => x.status === 'completed');
        scannersTd.innerText = completedScanners.length + ' / ' + s.scanners.length;
        if (s.scanners.length > 0) {
          scannersTd.title = completedScanners.length + ' scanner' + (completedScanners.length > 1 ? 's' : '') + ' exécuté' + (completedScanners.length > 1 ? 's' : '') + ' sur ' + s.scanners.length + ' attendu' + (s.scanners.length > 1 ? 's' : '');
        }

        // Quality badge cell
        const qualTd = document.createElement('td');
        if (s.quality === 'comparable') {
          qualTd.innerHTML = '<span class="status-badge comparable" title="État suffisamment complet pour une comparaison fiable.">✓ Comparable</span>';
        } else if (s.quality === 'partiel') {
          qualTd.innerHTML = '<span class="status-badge partiel" title="Tous les scanners attendus n\\\'ont pas été exécutés.">⚠ Partiel</span>';
        } else {
          qualTd.innerHTML = '<span class="status-badge incomparable" title="Le scan contient une couverture insuffisante ou un échec.">✗ Incomplet</span>';
        }

        // Expand arrow cell
        const expandTd = document.createElement('td');
        expandTd.style.textAlign = 'center';
        const expandBtn = document.createElement('button');
        expandBtn.className = 'btn-toggle-row';
        expandBtn.innerHTML = s.scan_id === expandedScanId ? '▼' : '▶';
        expandBtn.addEventListener('click', (e) => toggleRowDetails(s.scan_id, e));
        expandTd.appendChild(expandBtn);

        tr.appendChild(selectTd);
        tr.appendChild(idTd);
        tr.appendChild(dateTd);
        tr.appendChild(countTd);
        tr.appendChild(sevTd);
        tr.appendChild(scannersTd);
        tr.appendChild(qualTd);
        tr.appendChild(expandTd);

        tbody.appendChild(tr);

        // Render expanded row details
        if (s.scan_id === expandedScanId) {
          const detTr = document.createElement('tr');
          detTr.className = 'scans-row-details expanded';
          
          const detTd = document.createElement('td');
          detTd.colSpan = 8;
          
          const content = document.createElement('div');
          content.className = 'details-content';
          
          // Scanner status col
          const col1 = document.createElement('div');
          col1.innerHTML = '<div class="details-col-title">Scanner(s)</div>';
          s.scanners.forEach(sc => {
            col1.innerHTML += '<div class="details-item">' + sc.tool + ' : ' + sc.status + '</div>';
          });
          if (s.scanners.length === 0) col1.innerHTML += '<div class="details-item" style="color: var(--vscode-descriptionForeground)">Aucun scanner</div>';
          
          // Severity count col
          const col2 = document.createElement('div');
          col2.innerHTML = '<div class="details-col-title">Gravité des alertes</div>';
          const activeFindings = s.raw.result?.findings?.filter(f => !['false_positive', 'fixed', 'validated', 'accepted'].includes(f.triageStatus)) || [];
          const crit = activeFindings.filter(f => String(f.rawSeverity).toUpperCase() === 'CRITICAL').length;
          const high = activeFindings.filter(f => ['HIGH', 'ERROR'].includes(String(f.rawSeverity).toUpperCase())).length;
          const med = activeFindings.filter(f => ['MEDIUM', 'WARNING'].includes(String(f.rawSeverity).toUpperCase())).length;
          const low = activeFindings.filter(f => !['CRITICAL', 'HIGH', 'ERROR', 'MEDIUM', 'WARNING'].includes(String(f.rawSeverity).toUpperCase())).length;
          col2.innerHTML += '<div class="details-item">Critical : ' + crit + '</div>';
          col2.innerHTML += '<div class="details-item">High : ' + high + '</div>';
          col2.innerHTML += '<div class="details-item">Medium : ' + med + '</div>';
          col2.innerHTML += '<div class="details-item">Low : ' + low + '</div>';

          // Execution info col
          const col3 = document.createElement('div');
          col3.innerHTML = '<div class="details-col-title">Informations d’exécution</div>';
          col3.innerHTML += '<div class="details-item">Workspace : ' + (s.raw.workspace || 'n/a') + '</div>';
          const started = s.raw.result?.started_at || s.raw.started_at;
          const finished = s.raw.result?.finished_at || s.raw.finished_at;
          if (started && finished) {
            const dur = Math.round((new Date(finished) - new Date(started)) / 1000);
            col3.innerHTML += '<div class="details-item">Durée : ' + dur + ' s</div>';
          }
          if (s.raw.git_commit) {
            col3.innerHTML += '<div class="details-item">Commit : ' + s.raw.git_commit.slice(0, 7) + '</div>';
          }

          content.appendChild(col1);
          content.appendChild(col2);
          content.appendChild(col3);
          detTd.appendChild(content);
          detTr.appendChild(detTd);
          tbody.appendChild(detTr);
        }
      });
    }

    // Classify finding for category breakdown
    function getFindingCategory(f) {
      const tool = String(f.tool || '').toUpperCase();
      if (tool === 'GITLEAKS') return 'Secrets';
      if (tool === 'OSV') return 'Dependencies';
      if (tool === 'ZAP' || tool === 'BURP') return 'Dynamic Security';
      if (tool === 'SEMGREP') return 'Code';
      if (tool === 'SONARQUBE') return 'Code';
      // Snyk covers three domains at once, so the capability recorded on the
      // finding decides its category rather than the scanner name.
      if (tool === 'SNYK') {
        if (f.snykCapability === 'openSource') return 'Dependencies';
        if (f.snykCapability === 'iac') return 'IaC / Cloud';
        return 'Code';
      }
      if (tool === 'TRIVY') {
        if (f.imageName || f.dockerImage) return 'Containers';
        if (String(f.ruleId || '').includes('AVD-') || String(f.title || '').includes('Misconfig')) return 'IaC / Cloud';
        return 'Dependencies';
      }
      return 'Code';
    }

    // Helper: format severity tags
    function getSevTag(sev) {
      const upper = String(sev || '').toUpperCase();
      return '<span class="finding-sev-tag ' + upper + '">' + escapeHtml(upper) + '</span>';
    }

    // Helper: render findings lists in tabs
    function drawFindingsList(containerId, findings, emptyText) {
      const container = document.getElementById(containerId);
      container.innerHTML = '';
      
      if (findings.length === 0) {
        container.innerHTML = '<div class="empty-findings">' + escapeHtml(emptyText) + '</div>';
        return;
      }

      findings.slice(0, 100).forEach(f => {
        const row = document.createElement('div');
        row.className = 'finding-row';

        const info = document.createElement('div');
        info.className = 'finding-info';

        const meta = document.createElement('div');
        meta.className = 'finding-meta';
        meta.innerHTML = getSevTag(f.rawSeverity) + ' · <span>' + escapeHtml(f.tool) + '</span>';

        const title = document.createElement('div');
        title.className = 'finding-title';
        title.innerText = f.title;

        const file = document.createElement('div');
        file.className = 'finding-file';
        file.innerText = f.file || f.endpoint || f.packageName || '';

        info.appendChild(meta);
        info.appendChild(title);
        info.appendChild(file);

        const actions = document.createElement('div');
        actions.className = 'finding-actions';

        const btnInspect = document.createElement('button');
        btnInspect.className = 'btn-action-small';
        btnInspect.innerText = 'Inspect';
        btnInspect.addEventListener('click', () => {
          vscode.postMessage({ command: 'showFindingDetails', finding: f });
        });

        const btnOpenCode = document.createElement('button');
        btnOpenCode.className = 'btn-action-small';
        btnOpenCode.innerText = 'Code';
        btnOpenCode.addEventListener('click', () => {
          vscode.postMessage({ command: 'openFindingCode', finding: f });
        });

        actions.appendChild(btnInspect);
        actions.appendChild(btnOpenCode);

        row.appendChild(info);
        row.appendChild(actions);
        container.appendChild(row);
      });

      if (findings.length > 100) {
        const moreDiv = document.createElement('div');
        moreDiv.style.padding = '10px';
        moreDiv.style.textAlign = 'center';
        moreDiv.style.fontSize = '12px';
        moreDiv.style.color = 'var(--vscode-descriptionForeground)';
        moreDiv.innerText = 'Et ' + (findings.length - 100) + ' autres alertes (affichage limité aux 100 premières).';
        container.appendChild(moreDiv);
      }
    }

    // Helper: calculate severity delta
    function getSeverityDeltaHtml(before, after) {
      const diff = after - before;
      if (diff < 0) {
        return '<span class="trend-badge good">↓' + Math.abs(diff) + '</span>';
      } else if (diff > 0) {
        return '<span class="trend-badge bad">↑' + diff + '</span>';
      }
      return '<span class="trend-badge neutral">→ 0</span>';
    }

    // Receive message from extension
    window.addEventListener('message', event => {
      const message = event.data;
      if (message.command === 'comparisonResult') {
        const comp = message.comparison;
        activeComparison = comp;
        
        // Show output area
        const resultArea = document.getElementById('comparison-result-area');
        resultArea.classList.add('active');

        // Scroll to comparison output area smoothly
        resultArea.scrollIntoView({ behavior: 'smooth' });

        // Update title
        document.getElementById('comparison-report-header').innerText = 'Rapport de comparaison : Scan #' + comp.baselineId + ' → Scan #' + comp.currentId;

        // Get details
        const scanA = scansList.find(s => s.scan_id === comp.baselineId);
        const scanB = scansList.find(s => s.scan_id === comp.currentId);

        // Update KPIs
        const countA = comp.baselineCount;
        const countB = comp.currentCount;
        const diffAbs = countB - countA;
        const diffPct = countA === 0 ? (countB > 0 ? 100 : 0) : ((diffAbs / countA) * 100);

        document.getElementById('metric-before-val').innerText = countA;
        document.getElementById('metric-after-val').innerText = countB;
        
        const diffCard = document.getElementById('metric-diff');
        diffCard.className = 'metric-card';
        if (diffAbs < 0) {
          document.getElementById('metric-diff-val').innerText = diffAbs;
          diffCard.classList.add('good');
        } else if (diffAbs > 0) {
          document.getElementById('metric-diff-val').innerText = '+' + diffAbs;
          diffCard.classList.add('bad');
        } else {
          document.getElementById('metric-diff-val').innerText = '0';
        }

        const pctCard = document.getElementById('metric-pct');
        pctCard.className = 'metric-card';
        const pctStr = (diffAbs >= 0 ? '+' : '') + diffPct.toFixed(1) + ' %';
        document.getElementById('metric-pct-val').innerText = pctStr;
        if (diffAbs < 0) pctCard.classList.add('good');
        if (diffAbs > 0) pctCard.classList.add('bad');

        // Update Quick counts
        document.getElementById('stat-count-resolved').innerText = comp.resolved.length;
        document.getElementById('stat-count-new').innerText = comp.added.length;
        document.getElementById('stat-count-unchanged').innerText = comp.unchanged?.length || 0;
        document.getElementById('stat-count-sevchanged').innerText = comp.severityChanged?.length || 0;

        // Render Severity table
        const sevTbody = document.getElementById('severity-comp-tbody');
        sevTbody.innerHTML = '';
        const sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        sevs.forEach(sev => {
          const beforeCount = comp.beforeBySeverity[sev] || 0;
          const afterCount = comp.afterBySeverity[sev] || 0;
          const tr = document.createElement('tr');
          tr.innerHTML = '<td><strong>' + sev + '</strong></td>' +
                         '<td>' + beforeCount + '</td>' +
                         '<td>' + afterCount + '</td>' +
                         '<td>' + getSeverityDeltaHtml(beforeCount, afterCount) + '</td>';
          sevTbody.appendChild(tr);
        });

        // Render Scanners table
        const scanTbody = document.getElementById('scanner-comp-tbody');
        scanTbody.innerHTML = '';
        comp.perTool.forEach(row => {
          const tr = document.createElement('tr');
          const diff = row.after - row.before;
          const diffStr = diff > 0 ? '+' + diff : String(diff);
          const trendClass = diff < 0 ? 'good' : (diff > 0 ? 'bad' : 'neutral');
          const trendSym = diff < 0 ? '↓' : (diff > 0 ? '↑' : '→ ');
          tr.innerHTML = '<td><strong>' + escapeHtml(row.tool) + '</strong></td>' +
                         '<td>' + row.before + '</td>' +
                         '<td>' + row.after + '</td>' +
                         '<td><span class="trend-badge ' + trendClass + '">' + trendSym + Math.abs(diff) + '</span></td>';
          scanTbody.appendChild(tr);
        });
        // Render excluded non-comparable tools
        comp.excludedTools.forEach(toolName => {
          const tr = document.createElement('tr');
          tr.innerHTML = '<td><strong>' + escapeHtml(toolName) + '</strong></td>' +
                         '<td colspan="3" style="font-style: italic; color: var(--vscode-descriptionForeground);">Non comparable (scanner manquant ou échec)</td>';
          scanTbody.appendChild(tr);
        });

        // Category Breakdown classification
        const catBreakdown = document.getElementById('category-breakdown-list');
        catBreakdown.innerHTML = '';
        const catMap = {
          'Code': { before: 0, after: 0 },
          'Secrets': { before: 0, after: 0 },
          'Dependencies': { before: 0, after: 0 },
          'IaC / Cloud': { before: 0, after: 0 },
          'Containers': { before: 0, after: 0 },
          'Dynamic Security': { before: 0, after: 0 }
        };

        // Populate baseline categories
        if (scanA && scanA.raw.result?.findings) {
          scanA.raw.result.findings.forEach(f => {
            const cat = getFindingCategory(f);
            if (catMap[cat]) catMap[cat].before++;
          });
        }
        // Populate current categories
        if (scanB && scanB.raw.result?.findings) {
          scanB.raw.result.findings.forEach(f => {
            const cat = getFindingCategory(f);
            if (catMap[cat]) catMap[cat].after++;
          });
        }

        // Render categories that contain data
        let hasCategoriesData = false;
        Object.keys(catMap).forEach(cat => {
          const before = catMap[cat].before;
          const after = catMap[cat].after;
          if (before > 0 || after > 0) {
            hasCategoriesData = true;
            const item = document.createElement('div');
            item.className = 'category-item';
            item.innerHTML = '<span><strong>' + cat + '</strong></span>' +
                             '<span>' + before + ' → ' + after + ' (' + getSeverityDeltaHtml(before, after) + ')</span>';
            catBreakdown.appendChild(item);
          }
        });
        if (!hasCategoriesData) {
          catBreakdown.innerHTML = '<div class="empty-findings">Aucune catégorie renseignée.</div>';
        }

        // Timeline populate
        document.getElementById('timeline-A-title').innerText = 'Scan #' + comp.baselineId;
        document.getElementById('timeline-A-time').innerText = scanA ? formatDate(scanA.finished_at) : '—';
        document.getElementById('timeline-B-title').innerText = 'Scan #' + comp.currentId;
        document.getElementById('timeline-B-time').innerText = scanB ? formatDate(scanB.finished_at) : '—';
        if (scanA && scanB) {
          const elapsedSecs = Math.max(0, Math.round((new Date(scanB.finished_at) - new Date(scanA.finished_at)) / 1000));
          let elapsedStr = elapsedSecs + ' s';
          if (elapsedSecs > 60) {
            const mins = Math.floor(elapsedSecs / 60);
            elapsedStr = mins + ' m ' + (elapsedSecs % 60) + ' s';
            if (mins > 60) {
              const hrs = Math.floor(mins / 60);
              elapsedStr = hrs + ' h ' + (mins % 60) + ' m';
              if (hrs > 24) {
                elapsedStr = Math.floor(hrs / 24) + ' j ' + (hrs % 24) + ' h';
              }
            }
          }
          document.getElementById('timeline-elapsed-text').innerText = 'Écart : ' + elapsedStr;
        } else {
          document.getElementById('timeline-elapsed-text').innerText = 'Écart : —';
        }

        // Draw tab counts and findings lists
        document.getElementById('tab-count-new').innerText = comp.added.length;
        document.getElementById('tab-count-resolved').innerText = comp.resolved.length;
        document.getElementById('tab-count-persistent').innerText = comp.persistent.length;
        document.getElementById('tab-count-sevchanged').innerText = comp.severityChanged?.length || 0;

        drawFindingsList('list-new-findings', comp.added, 'Aucune nouvelle alerte.');
        drawFindingsList('list-resolved-findings', comp.resolved, 'Aucune alerte disparue.');
        drawFindingsList('list-persistent-findings', comp.persistent, 'Aucune alerte persistante.');
        drawFindingsList('list-sevchanged-findings', comp.severityChanged || [], 'Aucune alerte avec sévérité modifiée.');

        document.getElementById('raw-comparable-tools').innerText = comp.comparableTools.join(', ') || 'Aucun';
        document.getElementById('raw-excluded-tools').innerText = comp.excludedTools.join(', ') || 'Aucun';
      }
    });

    // Auto-preselect default scans A and B
    function preselectDefaultScans() {
      // Find the two most recent comparable scans
      const comparables = scansList.filter(s => s.quality === 'comparable');
      if (comparables.length >= 2) {
        // Sort descending
        comparables.sort((a, b) => {
          const timeA = a.finished_at ? new Date(a.finished_at).getTime() : 0;
          const timeB = b.finished_at ? new Date(b.finished_at).getTime() : 0;
          return (isNaN(timeB) ? 0 : timeB) - (isNaN(timeA) ? 0 : timeA);
        });
        scanBId = comparables[0].scan_id;
        scanAId = comparables[1].scan_id;
        updateSelectionUI();
        
        // Immediately compare on startup!
        vscode.postMessage({
          command: 'compare',
          baselineId: scanAId,
          currentId: scanBId
        });
      } else {
        updateSelectionUI();
      }
    }

    preselectDefaultScans();
  </script>
</body>
</html>`;
}

module.exports = { findingIdentity, completedTools, compareScans, renderScanComparisonHtml };
