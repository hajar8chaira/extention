function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

const SONAR_MODES = Object.freeze([['auto', 'Auto'], ['local', 'Local'], ['docker', 'Docker']]);

/** Strips credentials and query values so no secret can reach the page. */
function safeServerUrl(value) {
  const input = String(value || '').trim();
  if (!input) return '';
  try {
    const url = new URL(input);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString().replace(/\/+$/, '');
  } catch { return ''; }
}

/**
 * SonarQube cannot be installed by the managed downloader: it needs an external
 * server, and its CLI is not part of the SHA-256 verified release mechanism.
 * The card therefore reports a diagnosis and offers execution modes instead of
 * an install button.
 */
function sonarDiagnosis(sonar) {
  const scannerVersion = String(sonar.scannerVersion || '');
  const mode = SONAR_MODES.some(([value]) => value === sonar.mode) ? sonar.mode : 'auto';
  if (!sonar.enabled) {
    return { state: 'disabled', label: 'Désactivé', hint: 'SonarQube ne participe pas au pipeline. Activez-le depuis cette carte pour l’y intégrer.' };
  }
  // The versioned project policy wins over the VS Code setting, so the card
  // must not claim « Prêt » for a scan that will never run.
  if (sonar.blockedByProjectPolicy) {
    return {
      state: 'disabled',
      label: 'Désactivé par la politique projet',
      hint: 'Activé dans VS Code, mais security-center.yml contient scanners.sonarqube: false. Modifiez le fichier du dépôt pour l’exécuter.'
    };
  }
  // No server chosen yet: ask for that before anything else.
  if (!sonar.serverType) {
    return { state: 'missing', label: 'Activé — serveur manquant', hint: 'Choisissez un serveur SonarQube : instance locale gérée par Docker, ou serveur existant.' };
  }
  // Enabled stays enabled: an incomplete configuration is reported, never
  // silently switched off.
  const blockers = [];
  if (mode === 'local' && !scannerVersion) blockers.push({ label: 'Scanner local absent', hint: 'Le mode Local est sélectionné mais SonarScanner n’est pas installé. Choisissez Auto ou Docker, ou installez le CLI.' });
  if (mode === 'docker' && !sonar.dockerAvailable) blockers.push({ label: 'Docker indisponible', hint: 'Le mode Docker est sélectionné mais Docker ne répond pas.' });
  if (mode === 'auto' && !scannerVersion && !sonar.dockerAvailable) blockers.push({ label: 'Scanner local absent', hint: 'Ni SonarScanner local ni Docker ne sont disponibles pour exécuter l’analyse.' });
  if (sonar.serverOnline === false) blockers.push({ label: 'Serveur indisponible', hint: sonar.serverMessage || 'Le serveur SonarQube configuré ne répond pas.' });
  if (!sonar.tokenConfigured) blockers.push({ label: 'Token manquant', hint: 'Un jeton SonarQube est nécessaire pour publier l’analyse et relire les résultats.' });
  else if (sonar.authenticationValid === false) blockers.push({ label: 'Token refusé', hint: 'Le serveur a rejeté le jeton enregistré. Remplacez-le depuis cette carte.' });
  if (blockers.length > 1) {
    return { state: 'missing', label: 'Activé — configuration incomplète', hint: blockers.map((blocker) => blocker.label).join(' • ') };
  }
  if (blockers.length === 1) {
    return { state: blockers[0].label === 'Token manquant' ? 'missing' : 'failed', ...blockers[0] };
  }
  if (!scannerVersion) {
    return { state: 'ready', label: 'Prêt — Docker', hint: 'SonarScanner local absent : l’image sonarsource/sonar-scanner-cli sera utilisée.' };
  }
  return { state: 'ready', label: 'Prêt', hint: '' };
}

/** Shared mode selector so every scanner exposes the same control surface. */
function modeButtons(attribute, id, currentMode, supports, busy) {
  return SONAR_MODES
    .filter(([value]) => supports?.[value] !== false)
    .map(([value, label]) => `<button class="${value === currentMode ? '' : 'secondary'}" ${attribute}="${escapeHtml(value)}"${id ? ` data-scanner="${escapeHtml(id)}"` : ''} ${busy ? 'disabled' : ''}${value === currentMode ? ' aria-current="true"' : ''}>Utiliser en mode ${escapeHtml(label)}</button>`)
    .join('');
}

/**
 * Managed scanner card. The diagnostic is optional so the page still renders
 * with the historical status shape alone.
 */
function renderManagedCard(tool, busy, operation) {
  const diagnostic = tool.diagnostic || null;
  const state = operation?.state || diagnostic?.state || (tool.installed ? 'ready' : 'missing');
  const label = operation?.state === 'installing' ? 'Installation…'
    : operation?.state === 'failed' ? 'Échec'
      : diagnostic?.label || (tool.installed ? 'Prêt' : 'Non installé');
  const usesDocker = diagnostic?.resolvedMode === 'docker';
  const execution = diagnostic
    ? (usesDocker ? 'Image Docker officielle' : tool.installed ? (tool.managed ? 'Gérée par Security Center' : 'Installation système détectée') : 'Auto : local puis Docker en secours')
    : (tool.installed ? (tool.managed ? 'Gérée par Security Center' : 'Installation système détectée') : 'Auto : local puis Docker en secours');
  // Docker mode never needs a local install, so the install action is hidden.
  const offerInstall = !tool.installed && diagnostic?.configuredMode !== 'docker';
  const locationRow = usesDocker
    ? `<div><dt>Image</dt><dd class="path">${escapeHtml(diagnostic.image)}${diagnostic.imagePresent === false ? ' <span class="muted">(téléchargée au premier scan)</span>' : ''}</dd></div>`
    : `<div><dt>Emplacement</dt><dd class="path">${escapeHtml(tool.executable || 'Aucun')}</dd></div>`;
  return `<article class="tool ${escapeHtml(state)}" data-tool="${escapeHtml(tool.id)}">
      <div class="tool-head"><div><h2>${escapeHtml(tool.label)}</h2><p>${escapeHtml(tool.purpose)}</p></div><span class="status">${escapeHtml(label)}</span></div>
      <dl>
        <div><dt>Exécution</dt><dd>${escapeHtml(execution)}</dd></div>
        ${diagnostic ? `<div><dt>Mode actuel</dt><dd>${escapeHtml(diagnostic.configuredModeLabel)}</dd></div>
        <div><dt>Mode utilisé</dt><dd>${diagnostic.resolvedModeLabel ? escapeHtml(diagnostic.resolvedModeLabel) : '<span class="muted">Aucun moteur disponible</span>'}</dd></div>` : ''}
        <div><dt>Version</dt><dd>${escapeHtml(tool.version || '—')}</dd></div>
        ${locationRow}
      </dl>
      ${operation ? `<div class="operation ${escapeHtml(operation.state)}"><span class="spinner" aria-hidden="true"></span><div><strong>${escapeHtml(operation.title)}</strong><p>${escapeHtml(operation.message || '')}</p>${Number.isFinite(operation.percent) ? `<progress max="100" value="${operation.percent}"></progress>` : ''}</div></div>` : ''}
      ${!operation && diagnostic?.hint ? `<div class="operation ${diagnostic.state === 'ready' ? '' : 'failed'}"><div><strong>${escapeHtml(diagnostic.label)}</strong><p>${escapeHtml(diagnostic.hint)}</p></div></div>` : ''}
      <div class="actions">${diagnostic?.enabledKey ? `<button data-scanner-enabled="${diagnostic.enabled ? 'false' : 'true'}" data-scanner="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>${diagnostic.enabled ? 'Désactiver' : 'Activer'}</button>` : ''}${diagnostic ? modeButtons('data-scanner-mode', tool.id, diagnostic.configuredMode, diagnostic.supports, busy) : `<button data-mode="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Utiliser en mode Auto</button>`}${offerInstall ? `<button data-install="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Installer localement</button>` : ''}<button class="secondary" data-recheck="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Revérifier</button></div>
    </article>`;
}

/** Engine the runner would actually pick, from the configured mode. */
function usedScannerMode(sonar) {
  const mode = SONAR_MODES.some(([value]) => value === sonar.mode) ? sonar.mode : 'auto';
  if (mode === 'local') return sonar.scannerVersion ? 'Local' : '';
  if (mode === 'docker') return sonar.dockerAvailable ? 'Docker' : '';
  return sonar.scannerVersion ? 'Local' : sonar.dockerAvailable ? 'Docker' : '';
}

function renderSonarCard(sonar, pageBusy) {
  // A server start/stop in progress locks this card's actions too.
  const busy = Boolean(pageBusy || sonar.busy);
  const diagnosis = sonarDiagnosis(sonar);
  const mode = SONAR_MODES.some(([value]) => value === sonar.mode) ? sonar.mode : 'auto';
  const serverUrl = safeServerUrl(sonar.hostUrl);
  const connection = !sonar.enabled
    ? '<span class="muted">Non vérifié — scanner désactivé</span>'
    : sonar.serverOnline === true
      ? `Connecté${sonar.serverVersion ? ` — version ${escapeHtml(sonar.serverVersion)}` : ''}`
      : `Injoignable${sonar.serverMessage ? ` — ${escapeHtml(sonar.serverMessage)}` : ''}`;
  const execution = usedScannerMode(sonar) === 'Local'
    ? (sonar.scannerPath || 'SonarScanner local détecté')
    : usedScannerMode(sonar) === 'Docker' ? 'sonarsource/sonar-scanner-cli' : 'Aucun moteur d’exécution disponible';
  const buttons = modeButtons('data-sonar-mode', '', mode, { auto: true, local: true, docker: true }, busy);
  const usedScanner = usedScannerMode(sonar);
  const installing = sonar.installing?.state === 'installing';
  // Installing SonarScanner CLI is never the same action as installing the
  // SonarQube Server, which the server section handles separately.
  const installAction = sonar.scannerVersion
    ? ''
    : `<button data-sonar-install ${busy || installing ? 'disabled' : ''}>${installing ? 'Installation de SonarScanner…' : 'Installer SonarScanner'}</button>`;
  const installProgress = sonar.installing
    ? `<div class="operation ${escapeHtml(sonar.installing.state || '')}">${installing ? '<span class="spinner" aria-hidden="true"></span>' : ''}<div><strong>${escapeHtml(sonar.installing.title || 'Installation de SonarScanner')}</strong><p>${escapeHtml(sonar.installing.message || '')}</p>${Number.isFinite(sonar.installing.percent) ? `<progress max="100" value="${sonar.installing.percent}"></progress>` : ''}</div></div>`
    : '';
  return `<article class="tool ${diagnosis.state}" data-tool="sonarqube">
      <div class="tool-head"><div><h2>SonarQube</h2><p>Analyse de qualité et sécurité du code</p></div><span class="status">${escapeHtml(diagnosis.label)}</span></div>
      ${diagnosis.hint ? `<div class="operation ${diagnosis.state === 'failed' ? 'failed' : ''}"><div><strong>${escapeHtml(diagnosis.label)}</strong><p>${escapeHtml(diagnosis.hint)}</p></div></div>` : ''}

      <h3 class="sonar-section">SonarScanner<small>Analyse le code du workspace</small></h3>
      <dl>
        <div><dt>Mode configuré</dt><dd>${escapeHtml(SONAR_MODES.find(([value]) => value === mode)[1])}</dd></div>
        <div><dt>Mode utilisé</dt><dd>${usedScanner ? escapeHtml(usedScanner) : '<span class="muted">Aucun moteur disponible</span>'}</dd></div>
        <div><dt>Version</dt><dd>${escapeHtml(sonar.scannerVersion || 'Non détectée')}</dd></div>
        <div><dt>Exécution</dt><dd class="path">${escapeHtml(execution)}</dd></div>
      </dl>
      ${installProgress}
      <div class="actions">${installAction}${buttons}</div>

      <h3 class="sonar-section">Serveur SonarQube<small>Reçoit, traite et expose les résultats</small></h3>
      ${renderSonarServerSection(sonar, busy, { serverUrl, connection })}

      <h3 class="sonar-section">Authentification<small>Jeton conservé par VS Code SecretStorage</small></h3>
      <dl>
        <div><dt>Token</dt><dd>${sonar.tokenConfigured ? `Configuré${sonar.authenticationValid === false ? ' <span class="muted">(refusé par le serveur)</span>' : sonar.authenticationValid === true ? ' <span class="muted">(validé)</span>' : ''}` : '<span class="muted">Non configuré</span>'}</dd></div>
      </dl>
      <div class="actions"><button class="secondary" data-sonar-token ${busy ? 'disabled' : ''}>${sonar.tokenConfigured ? 'Remplacer le token' : 'Configurer le token'}</button></div>

      <div class="actions sonar-footer"><button data-sonar-enabled="${sonar.enabled ? 'false' : 'true'}" ${busy ? 'disabled' : ''}>${sonar.enabled ? 'Désactiver SonarQube' : 'Activer SonarQube'}</button><button class="secondary" data-sonar-recheck ${busy ? 'disabled' : ''}>Revérifier</button></div>
    </article>`;
}

/**
 * Server section. The choice between a Security Center managed container and
 * an existing instance is deliberately independent from the scanner mode.
 */
function renderSonarServerSection(sonar, busy, { serverUrl, connection }) {
  const localState = sonar.localServerState || '';
  const disabled = busy ? 'disabled' : '';
  if (!sonar.serverType) {
    return `<dl><div><dt>Type</dt><dd><span class="muted">Aucun serveur configuré</span></dd></div></dl>
      <p class="sonar-note">Choisissez comment Security Center joint SonarQube. Aucun serveur n’est démarré sans votre confirmation.</p>
      <div class="actions"><button data-sonar-server="local" ${disabled}>Installer localement avec Docker</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
  }
  if (sonar.serverType === 'existing') {
    return `<dl>
        <div><dt>Type</dt><dd>Serveur existant</dd></div>
        <div><dt>Adresse</dt><dd class="path">${serverUrl ? escapeHtml(serverUrl) : '<span class="muted">Aucune URL configurée</span>'}</dd></div>
        <div><dt>État</dt><dd>${connection}</dd></div>
      </dl>
      <div class="actions"><button class="secondary" data-sonar-server-url ${disabled}>Modifier l’adresse</button>${serverUrl ? `<button class="secondary" data-sonar-open ${disabled}>Ouvrir SonarQube</button>` : ''}<button class="secondary" data-sonar-server="local" ${disabled}>Basculer sur un serveur local</button></div>`;
  }
  const stateLabels = {
    'docker-unavailable': 'Docker indisponible',
    missing: 'Non installé',
    stopped: 'Serveur local installé — arrêté',
    starting: 'Démarrage…',
    initializing: 'Initialisation…',
    ready: 'Prêt',
    error: 'Erreur'
  };
  const rows = `<dl>
        <div><dt>Type</dt><dd>Serveur local Docker</dd></div>
        <div><dt>Adresse</dt><dd class="path">${escapeHtml(serverUrl || 'http://127.0.0.1:9000')}</dd></div>
        <div><dt>État</dt><dd>${escapeHtml(stateLabels[localState] || 'Inconnu')}</dd></div>
        ${sonar.serverVersion ? `<div><dt>Version</dt><dd>${escapeHtml(sonar.serverVersion)}</dd></div>` : ''}
      </dl>`;
  if (localState === 'docker-unavailable') {
    return `${rows}<p class="sonar-note">Docker est requis pour le serveur SonarQube local géré par Security Center. Security Center n’installe jamais Docker à votre place.</p>
      <div class="actions"><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
  }
  if (localState === 'missing') {
    return `${rows}<p class="sonar-note">Aucun serveur local n’a encore été créé. Security Center demandera confirmation avant de démarrer le conteneur.</p>
      <div class="actions"><button data-sonar-server-start ${disabled}>Installer / démarrer le serveur</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
  }
  if (localState === 'ready') {
    return `${rows}
      <div class="actions"><button class="secondary" data-sonar-open ${disabled}>Ouvrir SonarQube</button><button class="secondary" data-sonar-server-stop ${disabled}>Arrêter le serveur</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
  }
  if (['starting', 'initializing'].includes(localState)) {
    return `${rows}<div class="operation"><span class="spinner" aria-hidden="true"></span><div><strong>${escapeHtml(stateLabels[localState])}</strong><p>SonarQube démarre. Security Center attend que le serveur réponde réellement.</p></div></div>
      <div class="actions"><button class="secondary" data-sonar-recheck ${disabled}>Revérifier</button><button class="secondary" data-sonar-server-stop ${disabled}>Arrêter le serveur</button></div>`;
  }
  // Stopped or error: restart the existing container, never recreate it.
  return `${rows}<p class="sonar-note">Les données du serveur local sont conservées : « Arrêter » ne supprime aucun volume.</p>
      <div class="actions"><button data-sonar-server-start ${disabled}>Démarrer le serveur</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
}

function renderScannerSetupHtml(statuses, nonce, theme = 'light', operations = {}, confirmation = null, sonar = null) {
  const busy = Object.values(operations).some((operation) => operation?.state === 'installing');
  const cards = statuses.map((tool) => renderManagedCard(tool, busy, operations[tool.id])).join('')
    + (sonar ? renderSonarCard(sonar, busy) : '');
  const confirmationHtml = confirmation ? `<div class="confirm-backdrop" role="presentation"><section class="confirm" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
    <div class="confirm-icon" aria-hidden="true">↓</div><div class="confirm-content"><p class="eyebrow">INSTALLATION LOCALE SÉCURISÉE</p><h2 id="confirm-title">Autoriser l’installation ?</h2>
    <p>Security Center installera uniquement les outils sélectionnés dans le stockage privé de l’extension.</p><div class="tool-chips">${confirmation.labels.map((label) => `<span>${escapeHtml(label)}</span>`).join('')}</div>
    <dl class="confirm-details"><div><dt>Destination</dt><dd class="path">${escapeHtml(confirmation.destination)}</dd></div><div><dt>Privilèges</dt><dd>Aucun droit administrateur</dd></div><div><dt>Contrôle</dt><dd>Sources officielles et vérification SHA-256</dd></div></dl>
    <p class="confirm-note">Une installation échouée n’empêchera pas les autres scanners de fonctionner.</p><div class="confirm-actions"><button id="cancel-install" class="secondary">Annuler</button><button id="approve-install">Autoriser et installer</button></div></div>
  </section></div>` : '';
  return `<!doctype html><html data-theme="${escapeHtml(theme)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>
    :root{color-scheme:light;--bg:#f7f8fb;--card:#fff;--text:#26344a;--muted:#687386;--border:#d8deea;--accent:#5577d8;--ok:#2f9e62;--warn:#c58a19;--bad:#d9534f;--overlay:rgba(21,28,40,.34)}html[data-theme=dark]{color-scheme:dark;--bg:#181818;--card:#222;--text:#ddd;--muted:#aaa;--border:#444;--accent:#7aa2ff;--ok:#75ce91;--warn:#e0ad4f;--bad:#ff7b72;--overlay:rgba(0,0,0,.6)}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13px var(--vscode-font-family,Segoe UI);padding:28px}.wrap{max-width:1120px;margin:auto}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:20px}h1{font-size:28px;margin:0 0 7px}p{color:var(--muted);margin:4px 0;line-height:1.5}.hero-actions,.actions{display:flex;gap:8px;flex-wrap:wrap}.notice{border:1px solid var(--border);border-left:3px solid var(--accent);background:var(--card);padding:14px 16px;margin-bottom:18px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.tool{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:17px}.tool-head{display:flex;justify-content:space-between;gap:15px}.tool h2{font-size:17px;margin:0}.status{font-weight:700;color:var(--muted)}.ready .status{color:var(--ok)}.failed .status{color:var(--bad)}.installing .status{color:var(--accent)}dl{margin:15px 0}dl>div{display:grid;grid-template-columns:110px 1fr;padding:7px 0;border-top:1px solid var(--border)}dt{color:var(--muted)}dd{margin:0}.path{overflow-wrap:anywhere;font-family:var(--vscode-editor-font-family,monospace);font-size:12px}.operation{display:flex;gap:10px;background:color-mix(in srgb,var(--accent) 9%,var(--card));padding:10px;border-radius:5px;margin:12px 0}.operation.failed{background:color-mix(in srgb,var(--bad) 9%,var(--card))}.spinner{width:15px;height:15px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex:none;margin-top:2px}.operation.failed .spinner{animation:none;border-color:var(--bad)}progress{width:100%;accent-color:var(--accent)}button{border:0;border-radius:4px;padding:8px 12px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}button.secondary{background:var(--vscode-button-secondaryBackground,#e8eaf0);color:var(--vscode-button-secondaryForeground,var(--text))}button:disabled{opacity:.55;cursor:wait}button:focus-visible{outline:2px solid var(--vscode-focusBorder,var(--accent));outline-offset:2px}.footer{margin-top:18px;color:var(--muted)}.tool.disabled .status{color:var(--muted)}.tool.missing .status{color:var(--warn)}.sonar-note{font-size:12px;margin:0 0 12px}.sonar-section{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:18px 0 0;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;gap:10px;align-items:baseline}.sonar-section small{text-transform:none;letter-spacing:0;font-weight:400}.sonar-footer{margin-top:16px;padding-top:14px;border-top:1px solid var(--border)}.sonar-note code{font-family:var(--vscode-editor-font-family,monospace)}.muted{color:var(--muted)}.confirm-backdrop{position:fixed;inset:0;z-index:10;background:var(--overlay);display:grid;place-items:center;padding:24px}.confirm{width:min(620px,100%);display:grid;grid-template-columns:auto 1fr;gap:16px;background:var(--card);border:1px solid var(--vscode-focusBorder,var(--accent));border-radius:10px;padding:22px;box-shadow:0 12px 38px var(--overlay)}.confirm-icon{display:grid;place-items:center;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--accent) 13%,var(--card));color:var(--accent);font-size:22px;font-weight:700}.eyebrow{color:var(--accent);font-size:11px;font-weight:800;letter-spacing:.08em}.confirm h2{font-size:21px;margin:2px 0 8px}.tool-chips{display:flex;gap:7px;flex-wrap:wrap;margin:14px 0}.tool-chips span{border:1px solid var(--border);border-radius:99px;padding:4px 9px;font-weight:700}.confirm-details{border:1px solid var(--border);border-radius:6px;margin:12px 0}.confirm-details>div:first-child{border-top:0}.confirm-note{font-size:12px}.confirm-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:760px){body{padding:16px}.grid{grid-template-columns:1fr}.hero{display:block}.hero-actions{margin-top:12px}.confirm{grid-template-columns:1fr}.confirm-icon{display:none}}
  </style></head><body><main class="wrap"><header class="hero"><div><h1>Configuration des scanners</h1><p>Des analyses locales fiables, sans dépendre de Docker Desktop.</p></div><div class="hero-actions"><button id="install-all" ${busy ? 'disabled' : ''}>Installer les outils manquants</button><button id="refresh" class="secondary" ${busy ? 'disabled' : ''}>Actualiser le diagnostic</button></div></header>
  <section class="notice"><strong>Vous gardez le contrôle.</strong><p>Aucune installation n’est lancée sans votre confirmation. Les outils sont placés dans le stockage privé de l’extension, sans droits administrateur. Les scanners déjà disponibles sont réutilisés et un échec n’empêche pas les autres analyses.</p></section><section class="grid">${cards}</section><p class="footer">Sources officielles uniquement · vérification SHA-256 des binaires · provenance enregistrée · Docker reste disponible comme secours facultatif.</p></main>${confirmationHtml}
  <script nonce="${nonce}">const vscode=acquireVsCodeApi();document.getElementById('refresh').onclick=()=>vscode.postMessage({type:'refresh'});document.getElementById('install-all').onclick=()=>vscode.postMessage({type:'requestInstallAll'});document.querySelectorAll('[data-install]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'requestInstall',tool:b.dataset.install}));document.querySelectorAll('[data-recheck]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'refresh'}));document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setAuto',tool:b.dataset.mode}));document.querySelectorAll('[data-scanner-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setScannerMode',tool:b.dataset.scanner,mode:b.dataset.scannerMode}));document.querySelectorAll('[data-sonar-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setSonarMode',mode:b.dataset.sonarMode}));document.querySelectorAll('[data-scanner-enabled]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setScannerEnabled',tool:b.dataset.scanner,enabled:b.dataset.scannerEnabled==='true'}));document.querySelector('[data-sonar-enabled]')?.addEventListener('click',e=>vscode.postMessage({type:'setSonarEnabled',enabled:e.currentTarget.dataset.sonarEnabled==='true'}));document.querySelector('[data-sonar-token]')?.addEventListener('click',()=>vscode.postMessage({type:'configureSonarToken'}));document.querySelectorAll('[data-sonar-recheck]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'refresh'}));document.querySelectorAll('[data-sonar-server]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'chooseSonarServer',serverType:b.dataset.sonarServer}));document.querySelector('[data-sonar-server-start]')?.addEventListener('click',()=>vscode.postMessage({type:'startSonarServer'}));document.querySelector('[data-sonar-server-stop]')?.addEventListener('click',()=>vscode.postMessage({type:'stopSonarServer'}));document.querySelector('[data-sonar-install]')?.addEventListener('click',()=>vscode.postMessage({type:'requestInstall',tool:'sonarscanner'}));document.querySelector('[data-sonar-server-url]')?.addEventListener('click',()=>vscode.postMessage({type:'configureSonarHostUrl'}));document.querySelector('[data-sonar-open]')?.addEventListener('click',()=>vscode.postMessage({type:'openSonarServer'}));document.getElementById('approve-install')?.addEventListener('click',()=>vscode.postMessage({type:'approveInstall'}));document.getElementById('cancel-install')?.addEventListener('click',()=>vscode.postMessage({type:'cancelInstall'}));</script></body></html>`;
}

module.exports = { renderScannerSetupHtml, renderManagedCard, renderSonarCard, renderSonarServerSection, usedScannerMode, modeButtons, sonarDiagnosis, safeServerUrl, SONAR_MODES, escapeHtml };
