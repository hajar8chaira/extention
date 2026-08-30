'use strict';

/**
 * Le lanceur compact de la barre d'activite.
 *
 * Avant ce module, la vue etroite de la barre d'activite rendait le document du
 * dashboard complet avec `surface === 'sidebar'` : le meme HTML, le meme script,
 * et un catalogue de navigation (Investigation, Pipeline, Rapports,
 * Configuration…) qui reproduisait la navigation interne de Security Center.
 * Ouvrir l'application affichait donc DEUX navigations cote a cote.
 *
 * La responsabilite est desormais separee :
 *
 *   barre d'activite  = lanceur + etat + trois actions
 *   Security Center   = la navigation complete de l'application
 *
 * Ce fichier ne contient AUCUNE logique metier : il ne calcule pas de risque, ne
 * lit aucun scanner, n'appelle aucun backend. Il recoit le modele deja construit
 * par le dashboard et le met en page. Chaque bouton cite une commande qui existe
 * deja ; aucune n'est creee ici.
 */

const { themeOverridesCss } = require('./theme-controller');
const { compactIcon, escapeHtml, shellTokensCss } = require('./security-center-shell');
const { renderMascotSvg, mascotCss, mascotVisualFor } = require('./live/companionMascot');

/**
 * Le nom du projet, jamais son chemin absolu. Un chemin de workspace revele
 * l'arborescence du poste du developpeur et n'apporte rien dans 250px.
 */
function projectName(workspace) {
  const value = String(workspace ?? '').trim();
  if (!value) return '';
  const segments = value.replace(/[\\/]+$/, '').split(/[\\/]/);
  return segments[segments.length - 1] || value;
}

/** Les quatre etats de scan, tels que le modele les nomme deja. */
const SCAN_STATE = Object.freeze({
  completed: { label: 'Analyse terminée', tone: 'ok', code: 'COMPLETED' },
  partial: { label: 'Analyse partielle', tone: 'warn', code: 'PARTIAL' },
  running: { label: 'Analyse en cours', tone: 'busy', code: 'RUNNING' },
  failed: { label: 'Analyse en échec', tone: 'bad', code: 'FAILED' },
  idle: { label: 'Aucune analyse', tone: 'muted', code: 'IDLE' }
});
const TERMINAL_SCANNER_STATUSES = new Set(['completed', 'failed', 'cancelled', 'skipped', 'not_configured', 'disabled', 'unavailable', 'error']);

function scannerFinished(scanner) {
  return TERMINAL_SCANNER_STATUSES.has(String(scanner?.status || '').toLowerCase().replace(/[\s-]+/g, '_'));
}

/**
 * L'etat affiche vient du modele, pas d'une seconde interpretation.
 *
 * `scanStatus` est la source ; « partial » est deduit du seul fait deja present
 * dans le modele — des scanners termines, mais pas tous. Rien n'est invente : un
 * statut inconnu retombe sur `idle` plutot que d'afficher une reussite.
 */
function scanState(model) {
  const status = String(model.scanStatus || 'idle').toLowerCase();
  const total = (model.scanners || []).length;
  const completed = Number(model.successfulScanners ?? model.completedScanners ?? 0);
  const failed = (model.scanners || []).filter((scanner) => scanner.status === 'failed').length;
  if (status === 'running') return SCAN_STATE.running;
  if (status === 'failed' || (total > 0 && failed === total)) return SCAN_STATE.failed;
  if (status === 'completed') return total > 0 && completed < total ? SCAN_STATE.partial : SCAN_STATE.completed;
  return SCAN_STATE[status] || SCAN_STATE.idle;
}

/**
 * L'etat du compagnon Live, tel que le moteur partage l'a produit. Le lanceur
 * ne calcule rien depuis les scanners : il affiche uniquement le statut Live,
 * le compteur Live courant et le fichier/projet reellement transmis.
 */
function liveState(model) {
  const project = projectName(model.workspace);
  if (model.companionEnabled === false) {
    return {
      tone: 'muted', label: 'Live Security inactive', active: false,
      headline: 'Live Security is off.', detail: 'Open Live Security to enable file monitoring.',
      count: null, visual: 'sleeping', target: project
    };
  }
  const companion = model.companion;
  if (!companion) {
    return {
      tone: 'muted', label: 'Live Security inactive', active: false,
      headline: 'Live Security is not reporting yet.', detail: 'Open Live Security to inspect the current file.',
      count: null, visual: 'idle', target: project
    };
  }
  const file = baseName(companion.currentFile || companion.file || '');
  const byState = {
    findings: { tone: 'warn', label: 'Attention', headline: 'Live issues detected.', detail: 'Review the current file warnings.' },
    analyzing: { tone: 'busy', label: 'Analyzing', headline: file ? `Checking ${file}.` : 'Checking the current file.', detail: 'Analysis is in progress.' },
    clean: { tone: 'ok', label: 'Active', headline: file ? `Watching ${file}.` : 'Watching your workspace.', detail: 'No live issues detected.' },
    degraded: { tone: 'warn', label: 'Degraded', headline: 'Live Security is in reduced mode.', detail: 'A scanner or live signal needs attention.' },
    disabled: { tone: 'muted', label: 'Off', headline: 'Live Security is off.', detail: 'Open Live Security to enable monitoring.' },
    error: { tone: 'bad', label: 'Error', headline: 'Live analysis is unavailable.', detail: 'Open Live Security for details.' },
    idle: { tone: 'ok', label: 'Active', headline: file ? `Watching ${file}.` : 'Watching your workspace.', detail: 'No live issues detected.' }
  };
  const resolved = byState[companion.state] || byState.idle;
  const count = Number.isFinite(Number(companion.liveFindingCount)) ? Number(companion.liveFindingCount) : null;
  const severity = String(companion.liveHighestSeverity || '').toUpperCase();
  return {
    ...resolved,
    active: !['disabled', 'error'].includes(companion.state),
    // Un compteur reel, jamais un placeholder : absent du modele, il disparait.
    count,
    visual: companion.mascotState || mascotVisualFor(companion.state, { severity }),
    target: file || project,
    severity
  };
}

function baseName(value) {
  return String(value || '').replaceAll('\\', '/').split('/').filter(Boolean).pop() || '';
}

/**
 * Une pastille d'etat. Le glyphe double la couleur : l'information d'etat ne
 * doit jamais dependre de la couleur seule.
 */
function statusPill(tone, label, code = '') {
  const glyph = { ok: '✓', warn: '!', bad: '✕', busy: '◌', muted: '○' }[tone] || '○';
  return `<p class="state-pill ${escapeHtml(tone)}" role="status">
      <span class="state-glyph" aria-hidden="true">${glyph}</span>
      <span class="state-label">${escapeHtml(label)}</span>
      ${code ? `<span class="state-code">${escapeHtml(code)}</span>` : ''}
    </p>`;
}

/**
 * Le backend, uniquement quand son etat est connu.
 *
 * `unknown` ne rend rien : un champ indisponible disparait plutot que d'afficher
 * une valeur inventee. `checking` n'est pas non plus « hors ligne » — le dire
 * serait un diagnostic que le modele n'a pas encore rendu.
 */
function backendPill(status) {
  if (status === 'online') return statusPill('ok', 'Backend en ligne');
  if (status === 'offline') return statusPill('bad', 'Backend hors ligne');
  if (status === 'checking') return statusPill('busy', 'Vérification du backend');
  return '';
}

/** Les trois actions du lanceur. Chaque commande existe deja et est enregistree. */
const QUICK_ACTIONS = Object.freeze([
  ['securityCenter.scanWorkspace', 'Relancer l’analyse', 'play'],
  ['securityCenter.scanIncremental', 'Scan rapide des fichiers modifiés', 'code'],
  ['securityCenter.openLiveSecurityPage', 'Live Security', 'pulse']
]);

function launcherCss() {
  return `
    ${themeOverridesCss()}
    ${shellTokensCss()}
    ${mascotCss()}
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 13px 12px 18px;
      color: var(--sc-text);
      background: var(--sc-bg);
      font: 12px var(--vscode-font-family);
      /* La sidebar VS Code est redimensionnable : rien n'est fige en pixels,
         et aucun contenu ne peut deborder horizontalement. */
      overflow-x: hidden;
    }
    .launcher { display: grid; gap: 14px; min-width: 0; }
    .launcher section { min-width: 0; }
    h2 {
      margin: 0 0 7px;
      color: var(--sc-muted);
      font-size: 9px;
      font-weight: 800;
      letter-spacing: .7px;
      text-transform: uppercase;
    }

    /* ---------------------------------------------------------- identite */
    .brand { display: flex; align-items: center; gap: 9px; min-width: 0; }
    .brand-mark {
      display: grid;
      place-items: center;
      flex: none;
      width: 28px;
      height: 28px;
      border-radius: var(--sc-radius-md);
      color: var(--sc-primary-text);
      background: linear-gradient(135deg, var(--sc-primary), var(--sc-primary-hover));
    }
    .brand-mark .compact-icon { width: 16px; height: 16px; }
    .brand-copy { min-width: 0; }
    .brand-copy strong { display: block; font-size: 12.5px; line-height: 1.2; }
    .brand-copy small {
      display: block;
      color: var(--sc-muted);
      font-size: 8px;
      font-weight: 800;
      letter-spacing: 1.1px;
    }

    /* ------------------------------------------------------------- etat */
    .project {
      display: grid;
      gap: 7px;
      padding: 11px;
      border: 1px solid var(--sc-border);
      border-radius: var(--sc-radius-lg);
      background: var(--sc-surface);
    }
    .project-name {
      margin: 0;
      min-width: 0;
      font-size: 12px;
      font-weight: 700;
      /* Un nom de projet tres long s'abrege au lieu d'elargir la vue. */
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .state-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      /* Une pastille se replie plutot que de deborder quand la vue retrecit. */
      flex-wrap: wrap;
      margin: 0;
      font-size: 10px;
    }
    .state-glyph { flex: none; font-weight: 900; }
    .state-label { min-width: 0; font-weight: 700; }
    .state-code {
      flex: none;
      padding: 2px 6px;
      border-radius: 999px;
      color: var(--sc-muted);
      background: var(--sc-surface-soft);
      font-size: 8px;
      font-weight: 800;
      letter-spacing: .5px;
    }
    .state-pill.ok .state-glyph, .state-pill.ok .state-label { color: var(--sc-success); }
    .state-pill.warn .state-glyph, .state-pill.warn .state-label { color: var(--sc-warning); }
    .state-pill.bad .state-glyph, .state-pill.bad .state-label { color: var(--sc-danger); }
    .state-pill.busy .state-glyph, .state-pill.busy .state-label { color: var(--sc-primary); }
    .state-pill.muted .state-glyph, .state-pill.muted .state-label { color: var(--sc-muted); }
    .state-detail { margin: 0; color: var(--sc-text-secondary); font-size: 10px; overflow-wrap: anywhere; }

    /* -------------------------------------------------------- action principale */
    .cta {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
      padding: 11px 12px;
      border: 0;
      border-radius: var(--sc-radius-md);
      color: var(--sc-primary-text);
      background: var(--sc-primary);
      font: 700 12px var(--vscode-font-family);
      cursor: pointer;
      transition: background-color .12s ease;
    }
    .cta:hover { background: var(--sc-primary-hover); }
    .cta:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
    .cta-arrow { flex: none; font-size: 13px; line-height: 1; }

    /* ------------------------------------------------------------ posture */
    .stats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .stat {
      display: grid;
      gap: 1px;
      padding: 9px 10px;
      border: 1px solid var(--sc-border);
      border-left-width: 3px;
      border-radius: var(--sc-radius-md);
      background: var(--sc-surface);
      min-width: 0;
    }
    .stat strong { font-size: 17px; line-height: 1.1; }
    .stat span { color: var(--sc-muted); font-size: 9px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; }
    .stat.critical { border-left-color: var(--sc-critical); }
    .stat.critical strong { color: var(--sc-critical); }
    .stat.high { border-left-color: var(--sc-high); }
    .stat.high strong { color: var(--sc-high); }
    .posture-total { margin: 8px 0 0; color: var(--sc-text-secondary); font-size: 10px; }

    /* ------------------------------------------------------ actions rapides */
    .quick-actions { display: grid; gap: 6px; }
    .quick-action {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      padding: 8px 10px;
      border: 1px solid var(--sc-border);
      border-radius: var(--sc-radius-md);
      color: var(--sc-text);
      background: var(--sc-surface);
      font: 600 11px var(--vscode-font-family);
      text-align: left;
      cursor: pointer;
      min-width: 0;
    }
    .quick-action .compact-icon { flex: none; width: 14px; height: 14px; color: var(--sc-primary); }
    .quick-action span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .quick-action:hover { border-color: var(--sc-primary); background: var(--sc-primary-soft); }
    .quick-action:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 1px; }

    /* ------------------------------------------------------- live companion */
    .live {
      display: grid;
      gap: 9px;
      padding: 11px;
      border: 1px solid color-mix(in srgb, var(--sc-primary) 24%, var(--sc-border));
      border-radius: var(--sc-radius-lg);
      background: linear-gradient(160deg, color-mix(in srgb, var(--sc-primary) 9%, var(--sc-surface)), var(--sc-surface));
      box-shadow: var(--sc-shadow-sm);
    }
    .live-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .live h2 { margin: 0; color: var(--sc-text); }
    .live-status { display: inline-flex; align-items: center; gap: 4px; min-width: 0; color: var(--sc-muted); font-size: 8px; font-weight: 900; letter-spacing: .5px; text-transform: uppercase; }
    .live-status::before { content: ''; flex: none; width: 6px; height: 6px; border-radius: 50%; background: var(--sc-success); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-success) 18%, transparent); }
    .live-status.warn::before { background: var(--sc-warning); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-warning) 18%, transparent); }
    .live-status.bad::before { background: var(--sc-danger); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-danger) 18%, transparent); }
    .live-status.busy::before { background: var(--sc-primary); box-shadow: 0 0 0 3px color-mix(in srgb, var(--sc-primary) 18%, transparent); }
    .live-status.muted::before { background: var(--sc-muted); box-shadow: none; }
    .live-companion-mini { display: grid; grid-template-columns: 58px minmax(0, 1fr); align-items: center; gap: 9px; min-width: 0; }
    .live-mascot { position: relative; display: grid; place-items: center; min-width: 0; line-height: 0; }
    .live-mascot::before { content: ''; position: absolute; width: 46px; height: 46px; border-radius: 999px; background: radial-gradient(circle, color-mix(in srgb, var(--sc-primary) 22%, transparent), transparent 68%); filter: blur(2px); opacity: .72; }
    .live-mascot .mascot { position: relative; width: 54px; height: 68px; max-width: 100%; filter: drop-shadow(0 8px 14px color-mix(in srgb, var(--sc-text) 14%, transparent)) drop-shadow(0 0 13px color-mix(in srgb, var(--sc-primary) 22%, transparent)); }
    .live-copy { min-width: 0; display: grid; gap: 3px; }
    .live-title { margin: 0; color: var(--sc-text); font-size: 11px; font-weight: 800; line-height: 1.25; overflow-wrap: anywhere; }
    .live-detail { margin: 0; color: var(--sc-muted); font-size: 9.5px; line-height: 1.35; overflow-wrap: anywhere; }
    .live-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
    .live-chip { min-width: 0; padding: 6px 7px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); background: color-mix(in srgb, var(--sc-surface) 78%, transparent); }
    .live-chip strong, .live-chip span { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .live-chip strong { color: var(--sc-text); font-size: 10.5px; font-variant-numeric: tabular-nums; }
    .live-chip span { margin-top: 1px; color: var(--sc-muted); font-size: 8px; font-weight: 800; letter-spacing: .35px; text-transform: uppercase; }
    .live-link {
      justify-self: stretch;
      min-height: 28px;
      padding: 6px 9px;
      border: 1px solid color-mix(in srgb, var(--sc-primary) 28%, var(--sc-border));
      border-radius: var(--sc-radius-md);
      color: var(--sc-primary);
      background: color-mix(in srgb, var(--sc-primary) 8%, var(--sc-surface));
      font: 800 10.5px var(--vscode-font-family);
      cursor: pointer;
    }
    .live-link:hover { color: var(--sc-primary-hover); border-color: var(--sc-primary); background: var(--sc-primary-soft); }
    .live-link:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }

    /* Sous ~260px la vue reste lisible : les deux mini-cartes s'empilent. */
    @media (max-width: 259px) {
      .stats { grid-template-columns: minmax(0, 1fr); }
      .live-companion-mini { grid-template-columns: 48px minmax(0, 1fr); }
      .live-mascot .mascot { width: 46px; height: 58px; }
      .live-meta { grid-template-columns: minmax(0, 1fr); }
    }
    @media (prefers-reduced-motion: reduce) {
      * { transition: none !important; }
      .live .mascot { animation: none !important; }
    }`;
}

/**
 * Rend le lanceur compact.
 *
 * @param model le modele deja construit par `buildDashboardModel`, enrichi au
 *   rendu de `companion` / `companionEnabled` — exactement ce que les autres
 *   surfaces recoivent. Le lanceur n'en derive aucune valeur nouvelle.
 */
function renderSidebarLauncherHtml(model = {}, nonce = '', theme = 'light', uiState = {}, assets = {}) {
  const appliedTheme = theme === 'dark' ? 'dark' : 'light';
  const project = projectName(model.workspace);
  const state = scanState(model);
  const scannerList = model.scanners || [];
  const scanners = scannerList.length;
  const completed = Number(model.finishedScanners || scannerList.filter(scannerFinished).length || model.completedScanners || 0);
  const severity = model.bySeverity || {};
  const criticalCount = Number(severity.CRITICAL || 0);
  const highCount = Number(severity.HIGH || 0);
  const activeTotal = Number(model.activeTotal || 0);
  const backend = String(model.backendStatus || 'unknown').toLowerCase();
  const live = liveState(model);
  const mascotImageUri = assets.companionImageUri || assets.mascotImageUri || '';
  const cspSource = assets.cspSource || "'none'";

  return `<!doctype html>
<html lang="fr" data-theme="${appliedTheme}">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>${launcherCss()}</style>
</head>
<body class="theme-${appliedTheme}">
  <div class="launcher">
    <header class="brand">
      <span class="brand-mark" aria-hidden="true">${compactIcon('shield')}</span>
      <span class="brand-copy"><strong>Security Center</strong><small>DEVSECOPS</small></span>
    </header>

    <section class="project" aria-label="État du workspace">
      ${project ? `<p class="project-name" title="${escapeHtml(project)}">${escapeHtml(project)}</p>` : ''}
      ${statusPill(state.tone, state.label, state.code)}
      ${scanners ? `<p class="state-detail">${completed}/${scanners} scanner(s) terminé(s)</p>` : ''}
      ${backendPill(backend)}
    </section>

    <button class="cta" data-open-security-center aria-label="Ouvrir Security Center">
      Ouvrir Security Center<span class="cta-arrow" aria-hidden="true">→</span>
    </button>

    <section aria-label="Posture de sécurité">
      <h2>Posture de sécurité</h2>
      <div class="stats">
        <div class="stat critical"><strong>${criticalCount}</strong><span>Critical</span></div>
        <div class="stat high"><strong>${highCount}</strong><span>High</span></div>
      </div>
      <p class="posture-total">${activeTotal} alerte(s) active(s)</p>
    </section>

    <section aria-label="Actions rapides">
      <h2>Actions rapides</h2>
      <div class="quick-actions">
        ${QUICK_ACTIONS.map(([command, label, icon]) => `<button class="quick-action" data-command="${escapeHtml(command)}" aria-label="${escapeHtml(label)}">${compactIcon(icon)}<span>${escapeHtml(label)}</span></button>`).join('')}
      </div>
    </section>

    <section class="live" aria-label="Live Companion">
      <div class="live-head">
        <h2>Live Companion</h2>
        <span class="live-status ${escapeHtml(live.tone)}">${escapeHtml(live.active ? 'Active' : 'Off')}</span>
      </div>
      <div class="live-companion-mini">
        <span class="live-mascot" aria-hidden="true">${renderMascotSvg(live.visual, 'Security Companion', { size: 'compact', src: mascotImageUri })}</span>
        <div class="live-copy">
          <p class="live-title">${escapeHtml(live.headline)}</p>
          <p class="live-detail">${escapeHtml(live.detail)}</p>
        </div>
      </div>
      <div class="live-meta" aria-label="Live Security context">
        ${live.count === null ? '' : `<div class="live-chip"><strong>${escapeHtml(live.count)}</strong><span>Live issues</span></div>`}
        ${live.target ? `<div class="live-chip"><strong title="${escapeHtml(live.target)}">${escapeHtml(live.target)}</strong><span>${live.target === project ? 'Workspace' : 'Current file'}</span></div>` : ''}
      </div>
      <button class="live-link" data-command="securityCenter.openLiveSecurityPage">Open Live Security →</button>
    </section>
  </div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    // Le CTA ne cite pas la commande lui-meme : l'extension decide, elle ouvre
    // ou revele le dashboard existant PUIS replie la barre laterale native.
    document.querySelector('[data-open-security-center]')
      .addEventListener('click', () => vscode.postMessage({ type: 'openSecurityCenter' }));
    document.querySelectorAll('[data-command]').forEach((button) => {
      button.addEventListener('click', () => vscode.postMessage({ type: 'command', command: button.dataset.command }));
    });
    // Les deux messages du garde-fou ZAP existent deja cote extension.
  </script>
</body>
</html>`;
}

module.exports = {
  renderSidebarLauncherHtml,
  projectName,
  scanState,
  liveState,
  QUICK_ACTIONS,
  SCAN_STATE
};
