'use strict';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

const ACTION_LABELS = {
  'finding.triage.changed': 'Triage modifié',
  'finding.risk.accepted': 'Risque accepté',
  'finding.fixed': 'Alerte résolue',
  'finding.fix.validated': 'Correction validée',
  'ai.fix.requested': 'Correction IA demandée',
  'ai.fix.applied': 'Correction IA appliquée',
  'ai.rollback': 'Rollback IA exécuté',
  'scanner.run.started': 'Scan démarré',
  'scanner.run.completed': 'Scan complété',
  'scanner.run.failed': 'Échec scanner',
  'scanner.retry': 'Retry scanner lancé',
  'policy.changed': 'Politique modifiée',
  'scanner.configuration.changed': 'Configuration modifiée',
  'ai.configuration.changed': 'Configuration IA modifiée'
};

function getReadableAction(action) {
  if (ACTION_LABELS[action]) return ACTION_LABELS[action];
  if (action.startsWith('status:')) {
    const status = action.substring(7);
    const labels = {
      validated: 'Correction validée',
      accepted: 'Risque accepté',
      false_positive: 'Faux positif',
      confirmed: 'Alerte confirmée',
      triaged: 'Alerte triée',
      new: 'Nouvelle alerte'
    };
    return labels[status] || `Triage : ${status}`;
  }
  if (action.startsWith('zap:')) {
    const mode = action.substring(4).replace(':authorized', '');
    return `ZAP ${mode} scan authorized`;
  }
  if (action.startsWith('http-replay:')) {
    const method = action.split(':')[1]?.toUpperCase() || 'HTTP';
    if (action.endsWith(':authorized')) return `Replay ${method} autorisé`;
    if (action.endsWith(':completed')) return `Replay ${method} complété`;
  }
  return action;
}

function renderAuditLogHtml(events, nonce) {
  const eventsJson = JSON.stringify(events.map(e => ({
    ...e,
    readableAction: getReadableAction(e.action)
  }))).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');

  const rows = events.length ? events.map((e) => {
    const dateStr = new Date(e.created_at).toLocaleString('fr-FR');
    const refStr = e.finding_id 
      ? `<span style="font-family:monospace; font-size:11px;">${escapeHtml(e.finding_id)}</span>` 
      : (e.scan_id ? `Scan #${e.scan_id}` : 'Global');

    const catClass = (e.category || '').toLowerCase() || 
                     (e.action.startsWith('status:') || e.action.startsWith('finding.triage') ? 'triage' : 
                      e.action.startsWith('ai.') ? 'remediation' : 
                      e.action.startsWith('scanner.') ? 'scanner' : '');
    const actionBadge = `<span class="action-badge ${catClass}" title="${escapeHtml(e.action)}">${escapeHtml(getReadableAction(e.action))}</span>`;

    return `<tr class="audit-row" onclick="toggleDetails(this)">
      <td>${escapeHtml(dateStr)}</td>
      <td>${refStr}</td>
      <td>${actionBadge}</td>
      <td>${escapeHtml(e.actor)}</td>
      <td style="word-break: break-word;">${escapeHtml(e.comment || '—')}</td>
    </tr>
    <tr class="details-row" style="display: none;">
      <td colspan="5" class="details-cell">
        <div class="metadata-box">
          <strong>Action technique :</strong> <code>${escapeHtml(e.action)}</code>
          ${e.category ? `<br><strong>Catégorie :</strong> <code>${escapeHtml(e.category)}</code>` : ''}
          ${e.result ? `<br><strong>Résultat :</strong> <code>${escapeHtml(e.result)}</code>` : ''}
          ${e.metadata && Object.keys(e.metadata).length > 0 ? `<br><strong>Métadonnées détaillées :</strong><pre>${escapeHtml(JSON.stringify(e.metadata, null, 2))}</pre>` : ''}
        </div>
      </td>
    </tr>`;
  }).join('') : '';

  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <style nonce="${nonce}">
    :root {
      --page-background: var(--vscode-editor-background, #f3f4f6);
      --card-background: var(--vscode-sideBar-background, var(--vscode-editor-background, #ffffff));
      --vscode-foreground: var(--vscode-foreground, #424750);
      --vscode-descriptionForeground: var(--vscode-descriptionForeground, #707782);
      --vscode-panel-border: var(--vscode-panel-border, #d9dde5);
      --vscode-button-background: var(--vscode-button-background, #4b78cf);
      --vscode-button-foreground: var(--vscode-button-foreground, #ffffff);
      --vscode-button-hoverBackground: var(--vscode-button-hoverBackground, #3f69ba);
    }

    body.theme-dark {
      --page-background: var(--vscode-editor-background, #1e1e1e);
      --card-background: var(--vscode-sideBar-background, #252526);
      --vscode-foreground: var(--vscode-foreground, #cccccc);
      --vscode-descriptionForeground: var(--vscode-descriptionForeground, #858585);
      --vscode-panel-border: var(--vscode-panel-border, #454545);
    }

    body {
      font-family: var(--vscode-font-family, system-ui, -apple-system, sans-serif);
      color: var(--vscode-foreground);
      background: var(--page-background);
      margin: 0;
      padding: 24px;
      box-sizing: border-box;
    }

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding-bottom: 16px;
    }

    .page-header h1 {
      margin: 0 0 4px 0;
      font-size: 22px;
      font-weight: 600;
    }

    .page-header p {
      margin: 0;
      font-size: 13px;
      color: var(--vscode-descriptionForeground);
    }

    .btn-secondary {
      background: var(--vscode-button-secondaryBackground, var(--vscode-panel-border));
      color: var(--vscode-button-secondaryForeground, var(--vscode-foreground));
      border: 1px solid var(--vscode-panel-border);
      padding: 6px 12px;
      font-size: 13px;
      border-radius: 4px;
      cursor: pointer;
      font-family: inherit;
      transition: background 0.15s;
    }

    .btn-secondary:hover {
      background: var(--vscode-button-secondaryHoverBackground, var(--vscode-panel-border));
    }

    /* KPI Summary Cards */
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .summary-card {
      background: var(--card-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      padding: 16px;
      text-align: left;
      box-shadow: 0 2px 4px rgba(0,0,0,0.02);
      transition: transform 0.2s ease;
    }

    .summary-card:hover {
      transform: translateY(-2px);
    }

    .summary-card strong {
      display: block;
      font-size: 28px;
      font-weight: 700;
      color: var(--vscode-foreground);
      margin-bottom: 4px;
    }

    .summary-card small {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Filters Bar */
    .filters-bar {
      background: var(--card-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }

    .filter-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      flex-grow: 1;
      min-width: 140px;
    }

    .filter-item.search {
      flex-grow: 2;
      min-width: 200px;
    }

    .filter-item label {
      font-size: 11px;
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .filters-bar input[type="text"], .filters-bar select {
      background: var(--vscode-input-background, var(--page-background));
      color: var(--vscode-input-foreground, var(--vscode-foreground));
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      padding: 6px 10px;
      font-size: 13px;
      border-radius: 4px;
      font-family: inherit;
      outline: none;
    }

    .filters-bar input[type="text"]:focus, .filters-bar select:focus {
      border-color: var(--vscode-focusBorder, #4b78cf);
    }

    /* Audit Log Table */
    .table-container {
      background: var(--card-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 4px rgba(0,0,0,0.02);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }

    th {
      background: var(--card-background);
      border-bottom: 2px solid var(--vscode-panel-border);
      padding: 12px 16px;
      font-size: 12px;
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
      text-transform: uppercase;
    }

    td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      font-size: 13px;
      vertical-align: top;
      color: var(--vscode-foreground);
    }

    .audit-row {
      cursor: pointer;
      transition: background 0.15s;
    }

    .audit-row:hover {
      background: rgba(120, 120, 120, 0.05);
    }

    .action-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(120, 120, 120, 0.1);
    }

    .action-badge.triage { background: rgba(75, 120, 207, 0.12); color: var(--vscode-button-background); }
    .action-badge.remediation { background: rgba(76, 168, 102, 0.12); color: var(--vscode-testing-iconPassed, #4ca866); }
    .action-badge.scanner { background: rgba(227, 137, 54, 0.12); color: var(--vscode-charts-orange, #e38936); }
    .action-badge.configuration { background: rgba(160, 160, 160, 0.12); color: var(--vscode-descriptionForeground); }

    .details-row {
      background: rgba(120, 120, 120, 0.02);
    }

    .details-cell {
      padding: 16px 24px;
      border-bottom: 1px solid var(--vscode-panel-border);
    }

    .metadata-box {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 11px;
      background: rgba(120, 120, 120, 0.04);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      padding: 12px;
      margin-top: 8px;
      overflow-x: auto;
      color: var(--vscode-descriptionForeground);
    }

    .metadata-box pre {
      margin: 4px 0 0 0;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .empty-state {
      padding: 32px;
      text-align: center;
      color: var(--vscode-descriptionForeground);
      font-style: italic;
    }

    @media (max-width: 768px) {
      .filters-bar {
        flex-direction: column;
        align-items: stretch;
      }
      .filter-item {
        width: 100%;
      }
    }
  </style>
</head>
<body class="theme-light">
  <!-- Page Header -->
  <header class="page-header">
    <div>
      <h1>Journal d’audit</h1>
      <p>Historique des actions de sécurité et des changements de configuration sur le projet.</p>
    </div>
    <button class="btn-secondary" id="btn-back-dashboard">← Dashboard</button>
  </header>

  <!-- Summary Cards -->
  <section class="summary-cards">
    <div class="summary-card">
      <strong id="kpi-today">0</strong>
      <small>Aujourd'hui</small>
    </div>
    <div class="summary-card">
      <strong id="kpi-triage">0</strong>
      <small>Changements de triage</small>
    </div>
    <div class="summary-card">
      <strong id="kpi-fixes">0</strong>
      <small>Corrections validées</small>
    </div>
    <div class="summary-card">
      <strong id="kpi-failures">0</strong>
      <small>Échecs scanner</small>
    </div>
    <div class="summary-card">
      <strong id="kpi-rollbacks">0</strong>
      <small>Rollbacks IA</small>
    </div>
  </section>

  <!-- Filters Bar -->
  <section class="filters-bar">
    <div class="filter-item search">
      <label for="filter-search">Recherche</label>
      <input type="text" id="filter-search" placeholder="Scan, alerte, auteur ou justification...">
    </div>
    <div class="filter-item">
      <label for="filter-date">Date</label>
      <select id="filter-date">
        <option value="all">Tous les événements</option>
        <option value="7">7 derniers jours</option>
        <option value="30">30 derniers jours</option>
        <option value="90">90 derniers jours</option>
      </select>
    </div>
    <div class="filter-item">
      <label for="filter-action">Type d’action</label>
      <select id="filter-action">
        <option value="all">Toutes les actions</option>
      </select>
    </div>
    <div class="filter-item">
      <label for="filter-scanner">Scanner</label>
      <select id="filter-scanner">
        <option value="all">Tous les scanners</option>
      </select>
    </div>
    <div class="filter-item">
      <label for="filter-actor">Acteur</label>
      <select id="filter-actor">
        <option value="all">Tous les acteurs</option>
      </select>
    </div>
  </section>

  <!-- Table View -->
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Date</th>
          <th>Scan / Alerte</th>
          <th>Action</th>
          <th>Acteur</th>
          <th>Justification / Commentaire</th>
        </tr>
      </thead>
      <tbody id="audit-tbody">
        ${rows || '<tr><td colspan="5" class="empty-state">Aucun événement d’audit.</td></tr>'}
      </tbody>
    </table>
    <div id="audit-empty" class="empty-state" style="display: none;">
      Aucun événement ne correspond aux filtres actifs.
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const events = ${eventsJson};

    // Initialize theme
    window.addEventListener('message', event => {
      const message = event.data;
      if (message.command === 'setTheme') {
        document.body.className = 'theme-' + message.theme;
      }
    });

    // Back to Dashboard
    document.getElementById('btn-back-dashboard').onclick = () => {
      vscode.postMessage({ command: 'openDashboard' });
    };

    // Calculate filter list dropdowns
    function populateDropdowns() {
      const actions = new Set();
      const scanners = new Set();
      const actors = new Set();

      events.forEach(e => {
        if (e.action) actions.add(e.action);
        if (e.actor) actors.add(e.actor);
        
        // Extract scanner name if tool is mentioned in metadata
        if (e.metadata && e.metadata.tool) {
          scanners.add(e.metadata.tool);
        } else if (e.action.startsWith('zap:')) {
          scanners.add('ZAP');
        } else if (e.action.includes('Semgrep')) {
          scanners.add('Semgrep');
        } else if (e.action.includes('Gitleaks')) {
          scanners.add('Gitleaks');
        } else if (e.action.includes('Trivy')) {
          scanners.add('Trivy');
        } else if (e.action.includes('OSV')) {
          scanners.add('OSV-Scanner');
        } else if (e.action.includes('SonarQube')) {
          scanners.add('SonarQube');
        } else if (e.action.includes('Snyk')) {
          scanners.add('Snyk');
        }
      });

      const actionSelect = document.getElementById('filter-action');
      [...actions].sort().forEach(act => {
        const readable = getActionLabel(act);
        const opt = document.createElement('option');
        opt.value = act;
        opt.textContent = readable;
        actionSelect.appendChild(opt);
      });

      const scannerSelect = document.getElementById('filter-scanner');
      [...scanners].sort().forEach(sc => {
        const opt = document.createElement('option');
        opt.value = sc;
        opt.textContent = sc;
        scannerSelect.appendChild(opt);
      });

      const actorSelect = document.getElementById('filter-actor');
      [...actors].sort().forEach(ac => {
        const opt = document.createElement('option');
        opt.value = ac;
        opt.textContent = ac;
        actorSelect.appendChild(opt);
      });
    }

    function getActionLabel(action) {
      if (ACTION_LABELS[action]) return ACTION_LABELS[action];
      if (action.startsWith('status:')) {
        return 'Triage: ' + action.substring(7);
      }
      return action;
    }

    const ACTION_LABELS = ${JSON.stringify(ACTION_LABELS)};

    // Category mapping for badge colors
    function getCategoryClass(category, action) {
      if (category) return category.toLowerCase();
      if (action.startsWith('status:') || action.startsWith('finding.triage')) return 'triage';
      if (action.startsWith('ai.')) return 'remediation';
      if (action.startsWith('scanner.')) return 'scanner';
      return '';
    }

    // Toggle details row
    function toggleDetails(row) {
      const next = row.nextElementSibling;
      if (next && next.classList.contains('details-row')) {
        next.style.display = next.style.display === 'none' ? 'table-row' : 'none';
      }
    }

    // Refresh UI
    function render() {
      const search = document.getElementById('filter-search').value.toLowerCase().trim();
      const dateVal = document.getElementById('filter-date').value;
      const actionVal = document.getElementById('filter-action').value;
      const scannerVal = document.getElementById('filter-scanner').value;
      const actorVal = document.getElementById('filter-actor').value;

      const now = new Date();
      let filtered = events.filter(e => {
        // Search filter
        if (search) {
          const scanIdStr = e.scan_id ? '#' + e.scan_id : '';
          const findingIdStr = e.finding_id ? e.finding_id.toLowerCase() : '';
          const commentStr = e.comment ? e.comment.toLowerCase() : '';
          const actionStr = e.readableAction ? e.readableAction.toLowerCase() : '';
          const actorStr = e.actor ? e.actor.toLowerCase() : '';
          const matches = scanIdStr.includes(search) || 
                          findingIdStr.includes(search) || 
                          commentStr.includes(search) || 
                          actionStr.includes(search) || 
                          actorStr.includes(search);
          if (!matches) return false;
        }

        // Date filter
        if (dateVal !== 'all') {
          const cutoff = new Date(now.getTime() - Number(dateVal) * 24 * 3600 * 1000);
          if (new Date(e.created_at) < cutoff) return false;
        }

        // Action filter
        if (actionVal !== 'all' && e.action !== actionVal) return false;

        // Actor filter
        if (actorVal !== 'all' && e.actor !== actorVal) return false;

        // Scanner filter
        if (scannerVal !== 'all') {
          let matchesScanner = false;
          if (e.metadata && e.metadata.tool === scannerVal) {
            matchesScanner = true;
          } else if (e.action.startsWith('zap:') && scannerVal === 'ZAP') {
            matchesScanner = true;
          } else if (e.action.includes('Semgrep') && scannerVal === 'Semgrep') {
            matchesScanner = true;
          } else if (e.action.includes('Gitleaks') && scannerVal === 'Gitleaks') {
            matchesScanner = true;
          } else if (e.action.includes('Trivy') && scannerVal === 'Trivy') {
            matchesScanner = true;
          } else if (e.action.includes('OSV') && scannerVal === 'OSV-Scanner') {
            matchesScanner = true;
          } else if (e.action.includes('SonarQube') && scannerVal === 'SonarQube') {
            matchesScanner = true;
          } else if (e.action.includes('Snyk') && scannerVal === 'Snyk') {
            matchesScanner = true;
          }
          if (!matchesScanner) return false;
        }

        return true;
      });

      // Update KPI Statistics
      calculateKpis(filtered);

      const tbody = document.getElementById('audit-tbody');
      tbody.innerHTML = '';

      if (filtered.length === 0) {
        document.getElementById('audit-empty').style.display = 'block';
        return;
      }
      document.getElementById('audit-empty').style.display = 'none';

      filtered.forEach(e => {
        const tr = document.createElement('tr');
        tr.className = 'audit-row';
        tr.onclick = () => toggleDetails(tr);

        const dateStr = new Date(e.created_at).toLocaleString('fr-FR');
        const refStr = e.finding_id 
          ? '<span style="font-family:monospace; font-size:11px;">' + escapeHtml(e.finding_id) + '</span>' 
          : (e.scan_id ? 'Scan #' + e.scan_id : 'Global');

        const catClass = getCategoryClass(e.category, e.action);
        const actionBadge = '<span class="action-badge ' + catClass + '" title="' + escapeHtml(e.action) + '">' + escapeHtml(e.readableAction) + '</span>';

        tr.innerHTML = '<td>' + escapeHtml(dateStr) + '</td>' +
                       '<td>' + refStr + '</td>' +
                       '<td>' + actionBadge + '</td>' +
                       '<td>' + escapeHtml(e.actor) + '</td>' +
                       '<td style="word-break: break-word;">' + escapeHtml(e.comment || '—') + '</td>';

        const detailsTr = document.createElement('tr');
        detailsTr.className = 'details-row';
        detailsTr.style.display = 'none';

        let metaHtml = '';
        if (e.metadata && Object.keys(e.metadata).length > 0) {
          metaHtml = '<br><strong>Métadonnées détaillées :</strong><pre>' + escapeHtml(JSON.stringify(e.metadata, null, 2)) + '</pre>';
        }

        detailsTr.innerHTML = '<td colspan="5" class="details-cell">' +
                              '<div class="metadata-box">' +
                              '<strong>Action technique :</strong> <code>' + escapeHtml(e.action) + '</code>' +
                              (e.category ? '<br><strong>Catégorie :</strong> <code>' + escapeHtml(e.category) + '</code>' : '') +
                              (e.result ? '<br><strong>Résultat :</strong> <code>' + escapeHtml(e.result) + '</code>' : '') +
                              metaHtml +
                              '</div>' +
                              '</td>';

        tbody.appendChild(tr);
        tbody.appendChild(detailsTr);
      });
    }

    function calculateKpis(eventList) {
      const today = new Date();
      today.setHours(0,0,0,0);

      let countToday = 0;
      let countTriage = 0;
      let countFixes = 0;
      let countFailures = 0;
      let countRollbacks = 0;

      eventList.forEach(e => {
        const d = new Date(e.created_at);
        if (d >= today) countToday++;

        if (e.action.startsWith('status:') || e.action.startsWith('finding.triage') || e.action.startsWith('finding.risk')) {
          countTriage++;
        }
        if (e.action === 'finding.fix.validated' || e.action === 'status:validated') {
          countFixes++;
        }
        if (e.action === 'scanner.run.failed') {
          countFailures++;
        }
        if (e.action === 'ai.rollback') {
          countRollbacks++;
        }
      });

      document.getElementById('kpi-today').innerText = countToday;
      document.getElementById('kpi-triage').innerText = countTriage;
      document.getElementById('kpi-fixes').innerText = countFixes;
      document.getElementById('kpi-failures').innerText = countFailures;
      document.getElementById('kpi-rollbacks').innerText = countRollbacks;
    }

    function escapeHtml(text) {
      return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // Attach listeners
    document.getElementById('filter-search').oninput = render;
    document.getElementById('filter-date').onchange = render;
    document.getElementById('filter-action').onchange = render;
    document.getElementById('filter-scanner').onchange = render;
    document.getElementById('filter-actor').onchange = render;

    // Boot
    populateDropdowns();
    render();
  </script>
</body>
</html>
`;
}

module.exports = { renderAuditLogHtml };
