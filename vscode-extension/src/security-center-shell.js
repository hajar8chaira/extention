'use strict';

/**
 * L'enveloppe applicative unique de Security Center.
 *
 * Avant ce module, seul le dashboard portait la navigation interne : chaque
 * autre page (Findings, Scans, Historique, Pipeline, Delivery, Audit,
 * Tendances…) ouvrait un document autonome, avec son propre en-tete « Security
 * Center », son propre lien « ← Dashboard » et sa propre mise en page. Ouvrir
 * une page revenait donc a quitter l'application.
 *
 * Ce fichier ne contient AUCUNE logique metier : ni modele, ni commande, ni
 * calcul. Il expose seulement le cadre (barre laterale, zone centrale, rail de
 * contexte), les tokens de mise en page partages et le script minimal qui
 * relaie un clic de navigation vers une commande DEJA enregistree. Les pages
 * gardent leur contenu, leurs donnees et leurs handlers.
 */

const { themeOverridesCss } = require('./theme-controller');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]
  ));
}

/**
 * Les pictogrammes de la navigation. Identiques a ceux du dashboard : ils y
 * vivaient, ils sont remontes ici pour que toutes les surfaces dessinent le
 * meme rail plutot que deux jeux d'icones divergents.
 */
function compactIcon(name) {
  const paths = {
    code: '<path d="M8 4 3 9l5 5M12 4l5 5-5 5M11 2 9 16"/>',
    key: '<circle cx="6" cy="8" r="3"/><path d="m9 8 7 0m-2 0v3m-3-3v2"/>',
    cube: '<path d="m9 2 7 4v8l-7 4-7-4V6zM2 6l7 4 7-4M9 10v8"/>',
    shield: '<path d="M9 2 16 5v5c0 4-3 6-7 8-4-2-7-4-7-8V5zM6 10l2 2 4-5"/>',
    pulse: '<path d="M2 10h3l2-5 3 10 2-5h4"/>',
    play: '<path d="m6 4 9 5-9 5z"/>',
    history: '<path d="M3 5v4h4M4 8a6 6 0 1 1 2 5M9 6v4l3 2"/>',
    chart: '<path d="M3 15V9m5 6V4m5 11V7m4 8H1"/>',
    report: '<path d="M4 2h8l3 3v11H4zM12 2v4h4M7 9h5m-5 3h5"/>',
    settings: '<circle cx="9" cy="9" r="3"/><path d="M9 1v2m0 12v2M1 9h2m12 0h2M3 3l2 2m8 8 2 2M15 3l-2 2M5 13l-2 2"/>',
    compare: '<path d="M3 5h11m-3-3 3 3-3 3M15 13H4m3-3-3 3 3 3"/>'
  };
  return `<svg class="compact-icon" viewBox="0 0 18 18" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
}

/**
 * Identite de page → commande de navigation mise en avant.
 *
 * Ce n'est pas un routeur : rien n'est resolu ici, aucune page n'est ouverte
 * depuis cette table. Elle dit seulement quel element du rail doit porter
 * l'etat courant quand une surface se dessine. L'ouverture reste faite par les
 * commandes existantes.
 */
const SURFACE_NAV_COMMAND = {
  full: 'securityCenter.openDashboard',
  findings: 'securityCenter.openFindingsPage',
  'finding-details': 'securityCenter.openFindingsPage',
  scans: 'securityCenter.openScansPage',
  'scanner-details': 'securityCenter.openScansPage',
  'scan-history': 'securityCenter.showScanHistoryPage',
  // La comparaison est une operation de l'historique des scans : elle n'ajoute
  // pas d'entree au rail, elle allume la section a laquelle elle appartient.
  'compare-scans': 'securityCenter.showScanHistoryPage',
  dynamic: 'securityCenter.openDynamicPage',
  'burp-settings': 'securityCenter.openDynamicPage',
  runtime: 'securityCenter.openRuntimeSecurity',
  infrastructure: 'securityCenter.openInfrastructure',
  analytics: 'securityCenter.openAnalyticsPage',
  live: 'securityCenter.openLiveSecurityPage',
  pipeline: 'securityCenter.openSecurityPipeline',
  delivery: 'securityCenter.openSecurityDelivery',
  audit: 'securityCenter.showAuditLog',
  trends: 'securityCenter.showTrends',
  licenses: 'securityCenter.checkLicenses',
  'scanner-setup': 'securityCenter.openScannerSetup',
  policy: 'securityCenter.openProjectPolicy',
  integrations: 'securityCenter.configureTeamIntegrations'
};

/**
 * Le rail de navigation, groupe par intention. Chaque entree nomme une commande
 * qui existe deja et qui est deja enregistree : rien n'est invente ici.
 */
const NAV_GROUPS = [
  ['Overview', [
    ['Dashboard', 'securityCenter.openDashboard', 'shield']
  ]],
  ['Analyze', [
    ['Findings', 'securityCenter.openFindingsPage', 'report'],
    ['Scans', 'securityCenter.openScansPage', 'pulse'],
    // La page d'historique, pas la QuickPick : depuis le rail, « Scan History »
    // doit ouvrir une surface a l'interieur de l'application.
    ['Scan History', 'securityCenter.showScanHistoryPage', 'history'],
    ['Dynamic Security', 'securityCenter.openDynamicPage', 'chart'],
    ['Runtime Security', 'securityCenter.openRuntimeSecurity', 'shield'],
    ['Infrastructure', 'securityCenter.openInfrastructure', 'pulse'],
    ['Analytics', 'securityCenter.openAnalyticsPage', 'chart']
  ]],
  ['Improve', [
    ['Fix & Verify', 'securityCenter.verifyFindingFix', 'compare'],
    ['Live Security', 'securityCenter.openLiveSecurityPage', 'pulse'],
    ['Ollama / AI', 'securityCenter.configureOllama', 'hubot']
  ]],
  ['Deliver', [
    ['Security Pipeline', 'securityCenter.openSecurityPipeline', 'shield'],
    ['Security Delivery', 'securityCenter.openSecurityDelivery', 'cube']
  ]],
  ['Report', [
    ['Audit Journal', 'securityCenter.showAuditLog', 'report'],
    ['Trends & MTTR', 'securityCenter.showTrends', 'chart'],
    ['SBOM', 'securityCenter.generateSbom', 'cube'],
    ['Licenses', 'securityCenter.checkLicenses', 'key']
  ]],
  ['Configuration', [
    ['Scanner Configuration', 'securityCenter.openScannerSetup', 'settings'],
    ['Project Policy', 'securityCenter.openProjectPolicy', 'shield'],
    ['Integrations', 'securityCenter.configureTeamIntegrations', 'compare']
  ]]
];

/** Toutes les commandes citees par le rail, pour la frontiere de confiance. */
function navCommands() {
  return NAV_GROUPS.flatMap(([, items]) => items.map(([, command]) => command)).filter(Boolean);
}

/**
 * @param asLinks rend les items en liens `command:` au lieu de boutons.
 *   Certaines pages n'ont aucune raison d'executer du script — la conformite
 *   des licences est un rapport en lecture seule. Plutot que d'activer les
 *   scripts pour obtenir une navigation, on utilise les URI de commande, que
 *   l'hote restreint a une liste explicite. La page reste sans script.
 */
function renderInternalSidebar(surface, { asLinks = false, brandLogoUri = '' } = {}) {
  const activeCommand = SURFACE_NAV_COMMAND[surface] || null;
  // Le hibou n'est rendu que si une URI de webview a ete resolue ET que la page
  // autorise les images dans sa CSP. Les pages de rapport (licences, journal
  // d'audit) sont volontairement servies sous `default-src 'none'` : elles
  // gardent le bouclier plutot que d'elargir leur CSP pour une decoration.
  const brandMark = brandLogoUri
    ? `<img class="sc-nav-logo" src="${escapeHtml(brandLogoUri)}" alt="" width="28" height="28" decoding="async">`
    : compactIcon('shield');
  return `<aside class="sc-internal-nav" aria-label="Navigation Secenter">
    <div class="sc-nav-brand"><span class="sc-nav-mark">${brandMark}</span><div><strong>Secenter</strong><small>Security Center</small></div></div>
    <nav class="sc-nav-groups">
      ${NAV_GROUPS.map(([group, items]) => `<section class="sc-nav-group"><h2>${escapeHtml(group)}</h2>${items.map(([label, command, icon]) => {
        const active = command && command === activeCommand ? ' active' : '';
        if (!command) {
          return `<span class="sc-nav-item missing" role="link" aria-disabled="true" aria-label="${escapeHtml(label)} — indisponible" title="${escapeHtml(label)} — aucune commande existante pour cette route">${compactIcon(icon)}<span>${escapeHtml(label)}</span></span>`;
        }
        // `title` and `aria-label` carry the label even when the medium
        // breakpoint collapses the rail to icons and hides the text: without
        // them the collapsed nav would be a column of unlabelled glyphs, unusable
        // by a screen reader and unreadable by anyone else.
        const shared = `class="sc-nav-item${active}" title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"${active ? ' aria-current="page"' : ''}`;
        if (asLinks) {
          // `command:` n'est honore que pour les commandes que l'hote a
          // explicitement autorisees a l'ouverture du panneau.
          return `<a ${shared} href="command:${escapeHtml(command)}">${compactIcon(icon)}<span>${escapeHtml(label)}</span></a>`;
        }
        return `<button ${shared} type="button" data-command="${escapeHtml(command)}">${compactIcon(icon)}<span>${escapeHtml(label)}</span></button>`;
      }).join('')}</section>`).join('')}
    </nav>
  </aside>`;
}

function pageAtmosphereKind(surface) {
  const value = String(surface || 'full').toLowerCase();
  if (value === 'full') return 'dashboard';
  if (['finding-details', 'scanner-details'].includes(value)) return 'details';
  if (['runtime', 'infrastructure'].includes(value)) return value;
  if (['pipeline', 'delivery'].includes(value)) return 'flow';
  if (['integrations', 'scanner-setup', 'policy', 'licenses'].includes(value)) return 'configuration';
  if (['findings', 'scan-history', 'compare-scans', 'audit', 'trends', 'analytics'].includes(value)) return 'investigation';
  return value.replace(/[^a-z0-9-]+/g, '-') || 'security';
}

function renderSecurityCenterAtmosphere(surface = 'full') {
  const kind = pageAtmosphereKind(surface);
  return `<div class="sc-page-atmosphere" data-page-kind="${escapeHtml(kind)}" aria-hidden="true">
    <div class="sc-glow-layer"></div>
    <svg class="sc-network-layer" viewBox="0 0 1200 760" focusable="false" aria-hidden="true">
      <path d="M28 598 C210 414 308 622 512 384 S872 330 1168 112"></path>
      <path d="M84 156 H286 L382 246 H608 L804 428 H1116"></path>
      <path d="M0 422 C156 330 292 338 408 454 S674 604 902 394 S1052 190 1200 226"></path>
      <path d="M144 690 C318 544 510 604 642 482 S824 258 1058 286"></path>
      <circle cx="84" cy="156" r="6"></circle><circle cx="286" cy="156" r="4"></circle><circle cx="382" cy="246" r="6"></circle>
      <circle cx="608" cy="246" r="4"></circle><circle cx="804" cy="428" r="7"></circle><circle cx="1116" cy="428" r="5"></circle>
      <circle cx="210" cy="414" r="5"></circle><circle cx="512" cy="384" r="6"></circle><circle cx="872" cy="330" r="5"></circle><circle cx="1168" cy="112" r="7"></circle>
      <circle cx="642" cy="482" r="4"></circle><circle cx="1058" cy="286" r="6"></circle>
    </svg>
    <div class="sc-watermark">${compactIcon('shield')}</div>
  </div>`;
}

/**
 * La mise en page du cadre : trois colonnes, rail sticky, zone centrale
 * scrollable, rail de contexte masque des que la largeur ne le porte plus.
 *
 * Source unique : le dashboard interpole exactement la meme chaine, ce qui
 * evite deux definitions du meme cadre qui divergeraient a la premiere retouche.
 */
function shellLayoutCss() {
  return `
    .sc-app-shell { display: grid; grid-template-columns: minmax(190px, 208px) minmax(0, 1fr) minmax(210px, 262px); min-height: 100vh; background: var(--sc-bg); color: var(--sc-text); }
    .sc-app-shell.sc-app-shell-norail { grid-template-columns: minmax(190px, 208px) minmax(0, 1fr); }
    .sc-internal-nav { position: sticky; top: 0; align-self: start; height: 100vh; overflow: auto; padding: 18px 10px 20px; border-right: 1px solid var(--sc-border); background: var(--sc-surface); }
    /* La marque n'est pas une carte : un cadre autour du nom du produit ajoutait
       un niveau de profondeur la ou le rail doit rester le fond de la page. */
    .sc-nav-brand { display: grid; grid-template-columns: 28px minmax(0,1fr); gap: 9px; align-items: center; margin: 0 4px 20px; padding: 0; border: 0; border-radius: 0; background: transparent; box-shadow: none; }
    .sc-nav-brand strong, .sc-nav-brand small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-nav-brand strong { color: var(--sc-text); font-size: 12px; font-weight: 700; letter-spacing: -.1px; }
    .sc-nav-logo { display: block; width: 28px; height: 28px; object-fit: contain; border-radius: 6px; }
    .sc-nav-brand small { margin-top: 1px; color: var(--sc-muted); font-size: 9px; font-weight: 600; letter-spacing: .5px; text-transform: uppercase; }
    .sc-nav-mark { display: grid; place-items: center; width: 28px; height: 28px; border-radius: var(--sc-radius-md); color: var(--sc-primary); background: var(--sc-primary-soft); }
    .sc-nav-mark .compact-icon { width: 15px; height: 15px; }
    .sc-nav-groups { display: grid; gap: 13px; }
    /* Un intitule de groupe ne doit jamais peser plus qu'un titre de carte : il
       classe la navigation, il ne la titre pas. */
    .sc-nav-group h2 { margin: 0 0 4px 10px; color: var(--sc-muted); font-size: 9.5px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; opacity: .82; }
    .sc-nav-item { position: relative; display: grid; grid-template-columns: 16px minmax(0,1fr); align-items: center; gap: 9px; width: 100%; min-height: 30px; padding: 6px 10px; border: 0; border-radius: var(--sc-radius-md); color: var(--sc-muted); background: transparent; text-align: left; font: 600 11px var(--vscode-font-family); cursor: pointer; transition: background-color .12s ease, color .12s ease; }
    .sc-nav-item .compact-icon { width: 15px; height: 15px; opacity: .85; }
    .sc-nav-item span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-nav-item:hover { color: var(--sc-text); background: var(--sc-surface-soft); }
    .sc-nav-item.active { color: var(--sc-primary); background: var(--sc-primary-soft); }
    .sc-nav-item.active .compact-icon { opacity: 1; }
    /* Le liseré double la teinte : l'etat courant ne repose pas sur la couleur
       seule, et aria-current le dit deja aux technologies d'assistance. */
    .sc-nav-item.active::before { content: ''; position: absolute; top: 6px; bottom: 6px; left: 0; width: 2px; border-radius: 0 2px 2px 0; background: var(--sc-primary); }
    .sc-nav-item.missing { opacity: .5; cursor: not-allowed; }
    a.sc-nav-item { text-decoration: none; }
    /* Racine des modales : ancree au viewport, au-dessus de tout le cadre, et
       vide elle ne doit rien peindre ni intercepter le pointeur. */
    #security-center-modal-root:empty { display: none; }
    #security-center-modal-root { position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; }
    .sc-main { position: relative; isolation: isolate; min-width: 0; padding: 24px; overflow-x: hidden; background: radial-gradient(circle at 80% 15%, color-mix(in srgb, var(--sc-primary) 13%, transparent), transparent 34%), radial-gradient(circle at 15% 72%, color-mix(in srgb, var(--sc-primary) 7%, transparent), transparent 40%), linear-gradient(180deg, color-mix(in srgb, var(--sc-primary) 4%, var(--sc-bg)), var(--sc-bg) 52%); }
    body.theme-dark .sc-main { background: radial-gradient(circle at 80% 15%, color-mix(in srgb, var(--sc-primary) 16%, transparent), transparent 34%), radial-gradient(circle at 15% 72%, color-mix(in srgb, var(--sc-primary) 9%, transparent), transparent 40%), linear-gradient(180deg, color-mix(in srgb, var(--sc-primary) 7%, var(--sc-bg)), var(--sc-bg) 56%); }
    .sc-page-atmosphere { position: absolute; inset: 0; z-index: 0; overflow: hidden; contain: paint; pointer-events: none; user-select: none; color: var(--sc-primary); }
    .sc-main > :not(.sc-page-atmosphere):not(.sc-topbar) { position: relative; z-index: 1; }
    .sc-glow-layer { position: absolute; inset: -8% -8% auto -8%; height: min(720px, 76vh); background: radial-gradient(circle at 80% 16%, color-mix(in srgb, var(--sc-primary) 16%, transparent), transparent 32%), radial-gradient(circle at 18% 68%, color-mix(in srgb, var(--sc-primary) 9%, transparent), transparent 38%), radial-gradient(circle at 52% 0, color-mix(in srgb, var(--sc-low, var(--sc-primary)) 5%, transparent), transparent 34%); opacity: .95; }
    .sc-watermark { position: absolute; top: clamp(48px, 7vw, 92px); right: clamp(-96px, 5vw, 120px); width: clamp(470px, 40vw, 700px); aspect-ratio: 1; color: var(--sc-primary); opacity: .085; transform: rotate(-8deg); filter: blur(.2px) drop-shadow(0 18px 34px color-mix(in srgb, var(--sc-primary) 12%, transparent)); mask-image: linear-gradient(to bottom left, rgb(0 0 0), rgb(0 0 0 / .72) 48%, transparent 94%); }
    .sc-watermark .compact-icon { width: 100%; height: 100%; stroke-width: 1.05; }
    .sc-network-layer { position: absolute; left: clamp(-220px, -8vw, -70px); top: 72px; width: min(1140px, 84vw); height: auto; opacity: .64; }
    .sc-network-layer path { fill: none; stroke: currentColor; stroke-width: 1.1; stroke-linecap: round; stroke-dasharray: 4 16; stroke-opacity: .18; }
    .sc-network-layer circle { fill: currentColor; fill-opacity: .24; filter: drop-shadow(0 0 9px color-mix(in srgb, var(--sc-primary) 36%, transparent)); }
    .sc-page-atmosphere[data-page-kind="dashboard"] .sc-watermark { top: 34px; right: clamp(-140px, 0vw, 70px); opacity: .078; }
    .sc-page-atmosphere[data-page-kind="dashboard"] .sc-network-layer { top: 108px; opacity: .58; }
    .sc-page-atmosphere[data-page-kind="investigation"] .sc-watermark { top: 46px; right: clamp(-88px, 4vw, 104px); opacity: .09; }
    .sc-page-atmosphere[data-page-kind="details"] .sc-watermark { top: 36px; right: clamp(-108px, 3vw, 96px); opacity: .095; }
    .sc-page-atmosphere[data-page-kind="details"] .sc-network-layer { left: clamp(-280px, -12vw, -120px); opacity: .54; }
    .sc-page-atmosphere[data-page-kind="runtime"] .sc-network-layer,
    .sc-page-atmosphere[data-page-kind="configuration"] .sc-network-layer { left: clamp(-130px, -4vw, 8px); opacity: .68; }
    .sc-page-atmosphere[data-page-kind="infrastructure"] .sc-network-layer,
    .sc-page-atmosphere[data-page-kind="flow"] .sc-network-layer { top: 132px; opacity: .7; }
    body.theme-dark .sc-watermark { opacity: .105; filter: blur(.2px) drop-shadow(0 20px 38px color-mix(in srgb, var(--sc-primary) 18%, transparent)); }
    body.theme-dark .sc-network-layer { opacity: .72; }
    body.theme-dark .sc-network-layer path { stroke-opacity: .22; }
    body.theme-dark .sc-network-layer circle { fill-opacity: .28; }
    .sc-companion-rail { display: grid; align-content: start; gap: 12px; min-width: 0; padding: 24px 16px; border-left: 1px solid var(--sc-border); background: var(--sc-bg); }
    .sc-context-card { padding: 13px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-lg); background: var(--sc-surface); box-shadow: var(--sc-shadow-sm); }
    .sc-context-card strong, .sc-context-card span, .sc-context-card small { display: block; }
    .sc-context-card strong { font-size: 12px; }
    .sc-context-card span { margin-top: 7px; color: var(--sc-muted); font-size: 10px; line-height: 1.45; }
    .sc-context-card small { margin-top: 10px; color: var(--sc-primary); font-size: 10px; font-weight: 700; }
    /* Les selecteurs de rupture reprennent la variante sans rail : sans elle,
       .sc-app-shell.sc-app-shell-norail (0,2,0) l'emportait sur .sc-app-shell
       (0,1,0) et les pages sans rail gardaient une navigation pleine largeur a
       toutes les tailles, au lieu de se replier en rail d'icones. */
    @media (max-width: 1200px) {
      .sc-app-shell,
      .sc-app-shell.sc-app-shell-norail { grid-template-columns: minmax(180px, 202px) minmax(0, 1fr); }
      .sc-companion-rail { display: none; }
      .sc-watermark { right: -120px; width: min(590px, 58vw); opacity: .078; }
    }
    @media (max-width: 980px) {
      .sc-app-shell,
      .sc-app-shell.sc-app-shell-norail { grid-template-columns: 64px minmax(0, 1fr); }
      .sc-internal-nav { padding: 14px 8px; }
      .sc-nav-brand { grid-template-columns: 1fr; justify-items: center; margin: 0 0 16px; padding: 0; }
      .sc-nav-brand div, .sc-nav-group h2, .sc-nav-item span { display: none; }
      .sc-nav-item { grid-template-columns: 1fr; justify-items: center; padding: 7px; }
      .sc-nav-item.active::before { display: none; }
      .sc-main { padding: 20px; }
      .sc-network-layer { left: -260px; width: 1040px; opacity: .42; }
    }
    @media (prefers-reduced-motion: reduce) {
      .sc-page-atmosphere,
      .sc-glow-layer,
      .sc-network-layer,
      .sc-watermark { animation: none; transition: none; }
    }`;
}

/**
 * Les tokens dont le cadre a besoin en plus de ceux deja produits par
 * `themeOverridesCss()`. Le dashboard les definit deja pour lui-meme ; les
 * autres pages ne les avaient pas, et le rail y serait sorti sans teinte.
 * Rien ici ne remplace une valeur existante : ce sont uniquement les alias
 * manquants, dans les deux themes.
 */
function shellTokensCss() {
  return `
    body {
      --sc-muted: var(--sc-text-secondary, var(--vscode-descriptionForeground));
      --sc-surface-soft: var(--sc-surface-secondary, var(--vscode-editor-inactiveSelectionBackground));
      --sc-primary-soft: color-mix(in srgb, var(--sc-primary) 18%, var(--sc-surface));
      --sc-radius-sm: 6px;
      --sc-radius-md: 8px;
      --sc-radius-lg: 12px;
      --sc-shadow-sm: 0 10px 28px var(--vscode-widget-shadow, rgba(15, 23, 42, .10));
      --sc-critical: var(--vscode-charts-red, #d92d20);
      --sc-high: var(--vscode-charts-orange, #f97316);
      --sc-medium: var(--vscode-charts-yellow, #ca8a04);
      --sc-low: var(--vscode-charts-green, #16a34a);
    }
    body.theme-light {
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
    }
    body.theme-dark {
      --sc-surface-soft: color-mix(in srgb, var(--vscode-editor-inactiveSelectionBackground) 70%, var(--vscode-editor-background));
      --sc-primary-soft: color-mix(in srgb, var(--sc-primary) 18%, var(--vscode-editor-background));
      --sc-muted: var(--vscode-descriptionForeground);
    }
    .compact-icon { width: 17px; height: 17px; flex: 0 0 auto; fill: none; stroke: currentColor; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }`;
}

/**
 * L'en-tete commun a toutes les pages hebergees. Il remplace les en-tetes
 * « Security Center » dupliques par chaque page : le nom du produit vit dans le
 * rail, la barre superieure ne porte plus que l'identite de la page courante.
 */
function shellTopbarCss() {
  return `
    .sc-topbar { position: sticky; top: 0; z-index: 5; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 16px; min-width: 0; margin: 0 0 20px; padding: 14px 18px; border: 1px solid color-mix(in srgb, var(--sc-primary) 12%, var(--sc-border)); border-radius: var(--sc-radius-lg); background: color-mix(in srgb, var(--sc-surface) 96%, transparent); box-shadow: 0 10px 26px color-mix(in srgb, var(--sc-primary) 7%, transparent), var(--sc-shadow-sm); backdrop-filter: blur(12px); isolation: isolate; }
    .sc-topbar-title { min-width: 0; }
    .sc-topbar-title h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: 0; color: var(--sc-text); overflow-wrap: anywhere; }
    .sc-topbar-title p { margin: 3px 0 0; color: var(--sc-muted); font-size: 11px; line-height: 1.4; overflow-wrap: anywhere; }
    .sc-topbar-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; align-items: center; gap: 8px; min-width: 0; }
    @media (max-width: 980px) { .sc-topbar { padding: 13px 16px; } }
    @media (max-width: 680px) { .sc-topbar { grid-template-columns: 1fr; align-items: stretch; gap: 11px; margin: 0 0 16px; padding: 12px 14px; } .sc-topbar-actions { justify-content: flex-start; } .sc-main { padding: 16px; } .sc-network-layer { display: none; } .sc-glow-layer { height: 430px; opacity: .78; } .sc-watermark { top: 82px; right: -168px; width: 390px; opacity: .07; } }`;
}

/**
 * Le seul comportement que le cadre ajoute : relayer un clic de navigation vers
 * une commande existante, et appliquer le theme quand l'extension l'annonce.
 *
 * Le selecteur est volontairement limite a `.sc-nav-item[data-command]` : les
 * pages qui ecoutaient deja leurs propres `[data-command]` gardent leur
 * handler, sans double envoi.
 */
function shellNavScript() {
  return `
    (function () {
      const shellApi = typeof acquireVsCodeApi === 'function'
        ? (window.__scShellApi || (window.__scShellApi = acquireVsCodeApi()))
        : null;
      document.querySelectorAll('.sc-nav-item[data-command]').forEach(function (item) {
        item.addEventListener('click', function () {
          if (!shellApi) return;
          shellApi.postMessage({ type: 'command', command: item.dataset.command });
        });
      });
      window.addEventListener('message', function (event) {
        const message = event.data;
        if (!message || message.command !== 'setTheme') return;
        const theme = message.theme === 'dark' ? 'dark' : 'light';
        document.body.classList.remove('theme-light', 'theme-dark');
        document.body.classList.add('theme-' + theme);
        document.documentElement.setAttribute('data-theme', theme);
      });
    })();`;
}

const DEFAULT_CSP = (nonce, cspSource = '') => `default-src 'none'; img-src ${cspSource || "'self'"}; style-src 'nonce-${nonce}' 'unsafe-inline'; script-src 'nonce-${nonce}';`;

/**
 * Compose une page complete dans le cadre partage.
 *
 * `content` est le contenu propre de la page, inchange. Le module ne le lit pas,
 * ne le reecrit pas, et n'y injecte aucune donnee : il l'entoure.
 */
function renderSecurityCenterShell({
  surface = 'full',
  nonce = '',
  theme = 'light',
  title = 'Security Center',
  subtitle = '',
  headerActions = '',
  content = '',
  // Modales globales. Rendues HORS de `.sc-main`, qui est la zone defilante et
  // porte `isolation: isolate` : une boite en `position: fixed` placee dedans se
  // resout contre ce contexte et finit en bas du contenu, atteignable seulement
  // en faisant defiler la page. Le dashboard utilisait deja cette racine ; ce
  // parametre est ce qui manquait pour que les autres pages puissent s'en servir.
  modalRoot = '',
  contextRail = '',
  styles = '',
  script = '',
  csp = null,
  lang = 'fr',
  bodyClass = '',
  navAsLinks = false,
  // L'identite produit, resolue par l'hote via `webview.asWebviewUri`. Vide =
  // la page retombe sur la marque vectorielle, sans image cassee.
  brandLogoUri = '',
  cspSource = ''
} = {}) {
  const appliedTheme = theme === 'dark' ? 'dark' : 'light';
  const railMarkup = contextRail
    ? `<aside class="sc-companion-rail" aria-label="Contexte Security Center">${contextRail}</aside>`
    : '';
  const shellClass = contextRail ? 'sc-app-shell' : 'sc-app-shell sc-app-shell-norail';
  const classes = ['theme-' + appliedTheme, 'sc-surface-' + surface, bodyClass].filter(Boolean).join(' ');
  return `<!doctype html>
<html lang="${escapeHtml(lang)}" data-theme="${appliedTheme}">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp || DEFAULT_CSP(nonce, cspSource)}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style nonce="${escapeHtml(nonce)}">
    * { box-sizing: border-box; }
    html { background: var(--sc-bg); }
    body { margin: 0; padding: 0; min-height: 100vh; font-family: var(--vscode-font-family); font-size: 12px; color: var(--sc-text); background: var(--sc-bg); }
    ${themeOverridesCss()}
    ${shellTokensCss()}
    ${shellLayoutCss()}
    ${shellTopbarCss()}
    ${styles}
  </style>
</head>
<body class="${escapeHtml(classes)}">
  <div class="${shellClass}">
    ${renderInternalSidebar(surface, { asLinks: navAsLinks, brandLogoUri })}
    <main class="sc-main" data-page-kind="${escapeHtml(pageAtmosphereKind(surface))}">
      ${renderSecurityCenterAtmosphere(surface)}
      <header class="sc-topbar">
        <div class="sc-topbar-title"><h1>${escapeHtml(title)}</h1>${subtitle ? `<p>${escapeHtml(subtitle)}</p>` : ''}</div>
        <div class="sc-topbar-actions">${headerActions}</div>
      </header>
      ${content}
    </main>
    ${railMarkup}
  </div>
  <div id="security-center-modal-root">${modalRoot}</div>
  ${navAsLinks ? '' : `<script nonce="${escapeHtml(nonce)}">
    ${shellNavScript()}
    ${script}
  </script>`}
</body>
</html>`;
}

module.exports = {
  NAV_GROUPS,
  SURFACE_NAV_COMMAND,
  navCommands,
  compactIcon,
  escapeHtml,
  pageAtmosphereKind,
  renderInternalSidebar,
  renderSecurityCenterAtmosphere,
  renderSecurityCenterShell,
  shellLayoutCss,
  shellTokensCss,
  shellTopbarCss,
  shellNavScript
};
