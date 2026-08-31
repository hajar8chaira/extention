const { compactIcon, renderSecurityCenterShell } = require('./security-center-shell');
const { scannerPresentation, scannerToolFromId, scannerLogoUri } = require('./scanner-presentation');

function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

const SONAR_MODES = Object.freeze([['auto', 'Auto'], ['local', 'Local'], ['docker', 'Docker']]);

function scannerLogoHtml(scannerIdOrTool, state = '', assets = {}) {
  const tool = scannerToolFromId(scannerIdOrTool);
  const presentation = scannerPresentation(tool);
  const statusClass = state ? ` ${escapeHtml(state)}` : '';
  const logoUri = scannerLogoUri(tool, assets);
  if (logoUri) {
    return `<span class="scanner-logo${statusClass}" data-scanner-logo="${escapeHtml(presentation.id)}"><img class="scanner-logo-img" src="${escapeHtml(logoUri)}" alt="${escapeHtml(presentation.label)} logo" loading="lazy"></span>`;
  }
  return `<span class="scanner-logo fallback${statusClass}" data-scanner-logo="${escapeHtml(presentation.id)}" aria-hidden="true">${compactIcon(presentation.fallbackIcon)}</span>`;
}

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
    .map(([value, label]) => `<button class="mode-option${value === currentMode ? '' : ' secondary'}" ${attribute}="${escapeHtml(value)}"${id ? ` data-scanner="${escapeHtml(id)}"` : ''} ${busy ? 'disabled' : ''}${value === currentMode ? ' aria-current="true"' : ''}>Utiliser en mode ${escapeHtml(label)}</button>`)
    .join('');
}

/**
 * Managed scanner card. The diagnostic is optional so the page still renders
 * with the historical status shape alone.
 */
function renderManagedCard(tool, busy, operation, assets = {}) {
  const diagnostic = tool.diagnostic || null;
  const state = operation?.state || diagnostic?.state || (tool.installed ? 'ready' : 'missing');
  const label = operation?.state === 'installing' ? 'Installation…'
    : operation?.state === 'cancelled' ? 'Annulée'
      : operation?.state === 'failed' ? 'Échec'
      : diagnostic?.label || (tool.installed ? 'Prêt' : 'Non installé');
  const usesDocker = diagnostic?.resolvedMode === 'docker';
  const execution = diagnostic
    ? (usesDocker ? 'Image Docker officielle' : tool.installed ? (tool.managed ? 'Gérée par Security Center' : 'Installation système détectée') : 'Auto : local puis Docker en secours')
    : (tool.installed ? (tool.managed ? 'Gérée par Security Center' : 'Installation système détectée') : 'Auto : local puis Docker en secours');
  // Docker mode never needs a local install, so the install action is hidden.
  const offerInstall = !tool.installed && diagnostic?.configuredMode !== 'docker';
  const locationRow = usesDocker
    ? `<div><dt>Image</dt><dd class="path" title="${escapeHtml(diagnostic.image || '')}">${escapeHtml(diagnostic.image)}${diagnostic.imagePresent === false ? ' <span class="muted">(téléchargée au premier scan)</span>' : ''}</dd></div>`
    : `<div><dt>Emplacement</dt><dd class="path" title="${escapeHtml(tool.executable || 'Aucun')}">${escapeHtml(tool.executable || 'Aucun')}</dd></div>`;
  return `<article class="tool ${escapeHtml(state)}" data-tool="${escapeHtml(tool.id)}">
      <div class="tool-head"><div class="tool-identity">${scannerLogoHtml(tool.id, state, assets)}<div><h2>${escapeHtml(tool.label)}</h2><p>${escapeHtml(tool.purpose)}</p></div></div><span class="status">${escapeHtml(label)}</span></div>
      <dl class="tool-details">
        <div><dt>Exécution</dt><dd>${escapeHtml(execution)}</dd></div>
        ${diagnostic ? `<div><dt>Mode actuel</dt><dd>${escapeHtml(diagnostic.configuredModeLabel)}</dd></div>
        <div><dt>Mode utilisé</dt><dd>${diagnostic.resolvedModeLabel ? escapeHtml(diagnostic.resolvedModeLabel) : '<span class="muted">Aucun moteur disponible</span>'}</dd></div>` : ''}
        <div><dt>Version</dt><dd>${escapeHtml(tool.version || '—')}</dd></div>
        ${locationRow}
      </dl>
      ${operation ? `<div class="operation ${escapeHtml(operation.state)}">${operation.state === 'installing' ? '<span class="spinner" aria-hidden="true"></span>' : ''}<div><strong>${escapeHtml(operation.title)}</strong><p>${escapeHtml(operation.message || '')}</p>${Number.isFinite(operation.percent)
        ? `<progress max="100" value="${operation.percent}"></progress>`
        : operation.state === 'installing' ? '<progress aria-label="Progression indéterminée"></progress>' : ''}${operation.state === 'installing'
        ? `<div class="actions install-lifecycle"><button class="secondary" data-install-abort="${escapeHtml(tool.id)}">Annuler</button></div>`
        : ['failed', 'cancelled'].includes(operation.state)
          ? `<div class="actions install-lifecycle"><button data-install-retry="${escapeHtml(tool.id)}">Réessayer</button></div>`
          : ''}</div></div>` : ''}
      ${!operation && diagnostic?.hint ? `<div class="operation ${diagnostic.state === 'ready' ? '' : 'failed'}"><div><strong>${escapeHtml(diagnostic.label)}</strong><p>${escapeHtml(diagnostic.hint)}</p></div></div>` : ''}
      <div class="tool-controls">
        ${diagnostic ? `<div class="control-group"><span>Mode d’exécution</span><div class="actions mode-selector">${modeButtons('data-scanner-mode', tool.id, diagnostic.configuredMode, diagnostic.supports, busy)}</div></div>` : `<div class="control-group"><span>Mode d’exécution</span><div class="actions mode-selector"><button data-mode="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Utiliser en mode Auto</button></div></div>`}
        <div class="actions maintenance-actions">${diagnostic?.enabledKey ? `<button class="toggle-action" data-scanner-enabled="${diagnostic.enabled ? 'false' : 'true'}" data-scanner="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>${diagnostic.enabled ? 'Désactiver' : 'Activer'}</button>` : ''}${offerInstall ? `<button data-install="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Installer localement</button>` : ''}<button class="secondary" data-recheck="${escapeHtml(tool.id)}" ${busy ? 'disabled' : ''}>Revérifier</button></div>
      </div>
    </article>`;
}

/** Engine the runner would actually pick, from the configured mode. */
function usedScannerMode(sonar) {
  const mode = SONAR_MODES.some(([value]) => value === sonar.mode) ? sonar.mode : 'auto';
  if (mode === 'local') return sonar.scannerVersion ? 'Local' : '';
  if (mode === 'docker') return sonar.dockerAvailable ? 'Docker' : '';
  return sonar.scannerVersion ? 'Local' : sonar.dockerAvailable ? 'Docker' : '';
}

function renderSonarCard(sonar, pageBusy, assets = {}) {
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
      <div class="tool-head"><div class="tool-identity">${scannerLogoHtml('SonarQube', diagnosis.state, assets)}<div><h2>SonarQube</h2><p>Analyse de qualité et sécurité du code</p></div></div><span class="status">${escapeHtml(diagnosis.label)}</span></div>
      ${diagnosis.hint ? `<div class="operation ${diagnosis.state === 'failed' ? 'failed' : ''}"><div><strong>${escapeHtml(diagnosis.label)}</strong><p>${escapeHtml(diagnosis.hint)}</p></div></div>` : ''}

      <h3 class="sonar-section">SonarScanner<small>Analyse le code du workspace</small></h3>
      <dl class="tool-details">
        <div><dt>Mode configuré</dt><dd>${escapeHtml(SONAR_MODES.find(([value]) => value === mode)[1])}</dd></div>
        <div><dt>Mode utilisé</dt><dd>${usedScanner ? escapeHtml(usedScanner) : '<span class="muted">Aucun moteur disponible</span>'}</dd></div>
        <div><dt>Version</dt><dd>${escapeHtml(sonar.scannerVersion || 'Non détectée')}</dd></div>
        <div><dt>Exécution</dt><dd class="path" title="${escapeHtml(execution)}">${escapeHtml(execution)}</dd></div>
      </dl>
      ${installProgress}
      <div class="actions mode-selector">${installAction}${buttons}</div>

      <h3 class="sonar-section">Serveur SonarQube<small>Reçoit, traite et expose les résultats</small></h3>
      ${renderSonarServerSection(sonar, busy, { serverUrl, connection })}

      <h3 class="sonar-section">Authentification<small>Jeton conservé par VS Code SecretStorage</small></h3>
      <dl class="tool-details">
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
      <div class="actions"><button class="secondary" data-sonar-server-url ${disabled}>Modifier l’adresse</button>${serverUrl ? `<button class="secondary" data-sonar-open ${disabled}>Ouvrir SonarQube</button><button class="secondary" data-sonar-recheck ${disabled}>Revérifier</button>` : ''}<button class="secondary" data-sonar-server="local" ${disabled}>Basculer sur un serveur local</button></div>`;
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
      <div class="actions"><button class="secondary" data-sonar-open ${disabled}>Ouvrir SonarQube</button><button class="secondary" data-sonar-recheck ${disabled}>Revérifier</button><button class="secondary" data-sonar-server-stop ${disabled}>Arrêter le serveur</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
  }
  if (['starting', 'initializing'].includes(localState)) {
    return `${rows}<div class="operation"><span class="spinner" aria-hidden="true"></span><div><strong>${escapeHtml(stateLabels[localState])}</strong><p>SonarQube démarre. Security Center attend que le serveur réponde réellement.</p></div></div>
      <div class="actions"><button class="secondary" data-sonar-recheck ${disabled}>Revérifier</button><button class="secondary" data-sonar-server-stop ${disabled}>Arrêter le serveur</button></div>`;
  }
  // Stopped or error: restart the existing container, never recreate it.
  return `${rows}<p class="sonar-note">Les données du serveur local sont conservées : « Arrêter » ne supprime aucun volume.</p>
      <div class="actions"><button data-sonar-server-start ${disabled}>Démarrer le serveur</button><button class="secondary" data-sonar-server="existing" ${disabled}>Utiliser un serveur existant</button></div>`;
}

/** Engine the Snyk runner would actually pick, from the configured mode. */
function usedSnykMode(snyk) {
  const mode = SONAR_MODES.some(([value]) => value === snyk.mode) ? snyk.mode : 'auto';
  if (mode === 'local') return snyk.cliVersion ? 'Local' : '';
  if (mode === 'docker') return snyk.dockerAvailable ? 'Docker' : '';
  return snyk.cliVersion ? 'Local' : snyk.dockerAvailable ? 'Docker' : '';
}

/**
 * Snyk needs an account, so an incomplete setup is reported rather than
 * silently switched off. Snyk Code or IaC being unavailable on the plan never
 * marks the whole scanner as broken: Open Source alone makes it useful.
 */
function snykDiagnosis(snyk) {
  const mode = SONAR_MODES.some(([value]) => value === snyk.mode) ? snyk.mode : 'auto';
  if (!snyk.enabled) {
    return { state: 'disabled', label: 'Désactivé', hint: 'Snyk ne participe pas au pipeline. Activez-le depuis cette carte pour l’y intégrer.' };
  }
  if (snyk.blockedByProjectPolicy) {
    return {
      state: 'disabled',
      label: 'Désactivé par la politique projet',
      hint: 'Activé dans VS Code, mais security-center.yml contient scanners.snyk: false. Modifiez le fichier du dépôt pour l’exécuter.'
    };
  }
  const blockers = [];
  if (mode === 'local' && !snyk.cliVersion) blockers.push({ label: 'CLI absent', hint: 'Le mode Local est sélectionné mais le CLI Snyk n’est pas installé. Installez-le depuis cette carte, ou choisissez Auto ou Docker.' });
  if (mode === 'docker' && !snyk.dockerAvailable) blockers.push({ label: 'Docker indisponible', hint: 'Le mode Docker est sélectionné mais Docker ne répond pas.' });
  if (mode === 'auto' && !snyk.cliVersion && !snyk.dockerAvailable) blockers.push({ label: 'CLI absent', hint: 'Ni le CLI Snyk local ni Docker ne sont disponibles pour exécuter l’analyse.' });
  if (!snyk.tokenConfigured) blockers.push({ label: 'Token manquant', hint: 'Un jeton Snyk est nécessaire : Snyk résout les vulnérabilités via son service.' });
  else if (snyk.authenticationValid === false) blockers.push({ label: 'Token refusé', hint: 'Snyk a rejeté le jeton enregistré. Remplacez-le depuis cette carte.' });
  if (blockers.length > 1) {
    return { state: 'missing', label: 'Activé — configuration incomplète', hint: blockers.map((blocker) => blocker.label).join(' • ') };
  }
  if (blockers.length === 1) {
    return { state: blockers[0].label === 'Token manquant' ? 'missing' : 'failed', ...blockers[0] };
  }
  if (!snyk.cliVersion) {
    return { state: 'ready', label: 'Prêt — Docker', hint: 'CLI Snyk local absent : l’image officielle snyk/snyk sera utilisée.' };
  }
  return { state: 'ready', label: 'Prêt', hint: '' };
}

/**
 * Capability line. `null` means « pas encore vérifié » and is deliberately not
 * presented as a failure: only a scan or an explicit probe can decide.
 */
function snykCapabilityLabel(enabled, available) {
  if (!enabled) return '<span class="muted">Non activé</span>';
  if (available === true) return 'Disponible';
  if (available === false) return 'Indisponible pour ce compte/configuration';
  return '<span class="muted">Non vérifié</span>';
}

function renderSnykCard(snyk, pageBusy, assets = {}) {
  const busy = Boolean(pageBusy || snyk.busy);
  const diagnosis = snykDiagnosis(snyk);
  const mode = SONAR_MODES.some(([value]) => value === snyk.mode) ? snyk.mode : 'auto';
  const used = usedSnykMode(snyk);
  const capabilities = snyk.capabilities || {};
  const execution = used === 'Local'
    ? (snyk.cliPath || 'CLI Snyk local détecté')
    : used === 'Docker' ? 'snyk/snyk:linux' : 'Aucun moteur d’exécution disponible';
  const installing = snyk.installing?.state === 'installing';
  // Docker mode never needs the local binary, so the install action disappears
  // instead of proposing a download the user does not need.
  const installAction = snyk.cliVersion || mode === 'docker'
    ? ''
    : `<button data-snyk-install ${busy || installing ? 'disabled' : ''}>${installing ? 'Installation du CLI Snyk…' : 'Installer Snyk CLI'}</button>`;
  const installProgress = snyk.installing
    ? `<div class="operation ${escapeHtml(snyk.installing.state || '')}">${installing ? '<span class="spinner" aria-hidden="true"></span>' : ''}<div><strong>${escapeHtml(snyk.installing.title || 'Installation du CLI Snyk')}</strong><p>${escapeHtml(snyk.installing.message || '')}</p>${Number.isFinite(snyk.installing.percent) ? `<progress max="100" value="${snyk.installing.percent}"></progress>` : ''}</div></div>`
    : '';
  return `<article class="tool ${diagnosis.state}" data-tool="snyk">
      <div class="tool-head"><div class="tool-identity">${scannerLogoHtml('Snyk', diagnosis.state, assets)}<div><h2>Snyk</h2><p>Analyse SCA / SAST / IaC</p></div></div><span class="status">${escapeHtml(diagnosis.label)}</span></div>
      ${diagnosis.hint ? `<div class="operation ${diagnosis.state === 'failed' ? 'failed' : ''}"><div><strong>${escapeHtml(diagnosis.label)}</strong><p>${escapeHtml(diagnosis.hint)}</p></div></div>` : ''}

      <h3 class="sonar-section">CLI Snyk<small>Exécute l’analyse sur le workspace</small></h3>
      <dl class="tool-details">
        <div><dt>État</dt><dd>${escapeHtml(diagnosis.label)}</dd></div>
        <div><dt>Mode configuré</dt><dd>${escapeHtml(SONAR_MODES.find(([value]) => value === mode)[1])}</dd></div>
        <div><dt>Mode utilisé</dt><dd>${used ? escapeHtml(used) : '<span class="muted">Aucun moteur disponible</span>'}</dd></div>
        <div><dt>Version</dt><dd>${escapeHtml(snyk.cliVersion || 'Non détectée')}</dd></div>
        <div><dt>Exécution</dt><dd class="path" title="${escapeHtml(execution)}">${escapeHtml(execution)}</dd></div>
      </dl>
      ${installProgress}
      <div class="actions mode-selector">${installAction}${modeButtons('data-snyk-mode', '', mode, { auto: true, local: true, docker: true }, busy)}</div>

      <h3 class="sonar-section">Capacités<small>Open Source est la base, Code et IaC dépendent du compte</small></h3>
      <dl class="tool-details">
        <div><dt>Open Source</dt><dd>${snykCapabilityLabel(snyk.includeOpenSource !== false, capabilities.openSource)}</dd></div>
        <div><dt>Code</dt><dd>${snykCapabilityLabel(Boolean(snyk.includeCode), capabilities.code)}</dd></div>
        <div><dt>IaC</dt><dd>${snykCapabilityLabel(Boolean(snyk.includeIaC), capabilities.iac)}</dd></div>
      </dl>

      <h3 class="sonar-section">Authentification<small>Jeton conservé par VS Code SecretStorage</small></h3>
      <dl class="tool-details">
        <div><dt>Token</dt><dd>${snyk.tokenConfigured ? `Configuré${snyk.authenticationValid === false ? ' <span class="muted">(refusé par Snyk)</span>' : snyk.authenticationValid === true ? ' <span class="muted">(validé)</span>' : ''}` : '<span class="muted">Non configuré</span>'}</dd></div>
      </dl>
      <div class="actions"><button class="secondary" data-snyk-token ${busy ? 'disabled' : ''}>${snyk.tokenConfigured ? 'Remplacer le token' : 'Configurer le token'}</button></div>

      <div class="actions sonar-footer"><button data-snyk-enabled="${snyk.enabled ? 'false' : 'true'}" ${busy ? 'disabled' : ''}>${snyk.enabled ? 'Désactiver Snyk' : 'Activer Snyk'}</button><button class="secondary" data-snyk-recheck ${busy ? 'disabled' : ''}>Revérifier</button></div>
    </article>`;
}

function renderScannerSetupHtml(statuses, nonce, theme = 'light', operations = {}, confirmation = null, sonar = null, snyk = null, assets = {}) {
  const busy = Object.values(operations).some((operation) => operation?.state === 'installing');
  const cards = statuses.map((tool) => renderManagedCard(tool, busy, operations[tool.id], assets)).join('')
    + (sonar ? renderSonarCard(sonar, busy, assets) : '')
    + (snyk ? renderSnykCard(snyk, busy, assets) : '');
  const confirmationHtml = confirmation ? `<div class="confirm-backdrop" role="presentation"><section class="confirm" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
    <div class="confirm-icon" aria-hidden="true">↓</div><div class="confirm-content"><p class="eyebrow">INSTALLATION LOCALE SÉCURISÉE</p><h2 id="confirm-title">Autoriser l’installation ?</h2>
    <p>Security Center installera uniquement les outils sélectionnés dans le stockage privé de l’extension.</p><div class="tool-chips">${confirmation.labels.map((label) => `<span>${escapeHtml(label)}</span>`).join('')}</div>
    <dl class="confirm-details"><div><dt>Destination</dt><dd class="path">${escapeHtml(confirmation.destination)}</dd></div><div><dt>Privilèges</dt><dd>Aucun droit administrateur</dd></div><div><dt>Contrôle</dt><dd>Sources officielles et vérification SHA-256</dd></div></dl>
    <p class="confirm-note">Une installation échouée n’empêchera pas les autres scanners de fonctionner.</p><div class="confirm-actions"><button id="cancel-install" class="secondary">Annuler</button><button id="approve-install">Autoriser et installer</button></div></div>
  </section></div>` : '';
  return renderSecurityCenterShell({
    surface: 'scanner-setup',
    nonce,
    theme,
    title: 'Configuration des scanners',
    subtitle: 'Des analyses locales fiables, sans dépendre de Docker Desktop',
    headerActions: `<button id="install-all" ${busy ? 'disabled' : ''}>Installer les outils manquants</button><button id="refresh" class="secondary" ${busy ? 'disabled' : ''}>Actualiser le diagnostic</button>`,
    content: `
  <section class="notice"><strong>Vous gardez le contrôle.</strong><p>Aucune installation n’est lancée sans votre confirmation. Les outils sont placés dans le stockage privé de l’extension, sans droits administrateur. Les scanners déjà disponibles sont réutilisés et un échec n’empêche pas les autres analyses.</p></section><section class="grid scanner-config-grid">${cards}</section><p class="footer">Sources officielles uniquement · vérification SHA-256 des binaires · provenance enregistrée · Docker reste disponible comme secours facultatif.</p>
`,
    // La confirmation d'installation est une modale globale : elle sort du flux
    // defilant et va dans la racine de modales du cadre, comme le preflight ZAP.
    modalRoot: confirmationHtml,
    styles: `
    
    body {
      --bg: var(--sc-bg);
      --card: var(--sc-surface);
      --text: var(--sc-text);
      --muted: var(--sc-text-secondary);
      --border: var(--sc-border);
      --accent: var(--sc-primary);
      --ok: var(--sc-success);
      --warn: var(--sc-warning);
      --bad: var(--sc-danger);
      --overlay: rgba(21,28,40,.34);
    }
    
    body { background: var(--bg); color: var(--text); font: 13px var(--vscode-font-family, Segoe UI); }
    p { color: var(--muted); margin: 4px 0; line-height: 1.5; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .notice { position: relative; display: grid; gap: 5px; margin-bottom: 18px; padding: 15px 17px; border: 1px solid color-mix(in srgb,var(--accent) 18%,var(--border)); border-left: 3px solid var(--accent); border-radius: 12px; background: linear-gradient(135deg, color-mix(in srgb,var(--accent) 7%,transparent), transparent 52%), color-mix(in srgb,var(--card) 96%, transparent); box-shadow: 0 12px 30px color-mix(in srgb,var(--accent) 8%, transparent); }
    .notice strong { color: var(--text); }
    .grid, .scanner-config-grid { display: grid; grid-template-columns: 1fr; grid-auto-flow: row dense; gap: 16px; align-items: start; }
    .tool { position: relative; display: flex; flex-direction: column; gap: 13px; min-width: 0; min-height: 100%; background: linear-gradient(145deg, color-mix(in srgb,var(--accent) 3%,transparent), transparent 40%), var(--card); border: 1px solid color-mix(in srgb,var(--accent) 12%,var(--border)); border-radius: 16px; padding: 16px; box-shadow: 0 16px 34px color-mix(in srgb,var(--accent) 7%, transparent), var(--sc-shadow-sm); overflow: hidden; transition: border-color .16s ease, box-shadow .16s ease, transform .16s ease; }
    .tool:hover { border-color: color-mix(in srgb,var(--accent) 30%,var(--border)); box-shadow: 0 18px 38px color-mix(in srgb,var(--accent) 10%, transparent), var(--sc-shadow-sm); transform: translateY(-1px); }
    .tool::before { content: ''; position: absolute; inset: 0 0 auto; height: 2px; background: color-mix(in srgb,var(--accent) 42%,var(--border)); opacity: .74; }
    .tool.ready::before { background: var(--ok); }
    .tool.failed::before { background: var(--bad); }
    .tool.missing::before { background: var(--warn); }
    .tool.disabled::before { background: color-mix(in srgb,var(--muted) 60%,var(--border)); }
    .tool-head { position: relative; z-index: 1; display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; min-width: 0; }
    .tool-identity { display: grid; grid-template-columns: 52px minmax(0, 1fr); align-items: center; gap: 12px; min-width: 0; }
    .tool-identity h2 { margin: 0; color: var(--text); font-size: 16px; letter-spacing: 0; overflow-wrap: anywhere; }
    .tool-identity p { margin-top: 3px; font-size: 11px; overflow-wrap: anywhere; }
    .scanner-logo { display: grid; place-items: center; width: 52px; height: 52px; border: 1px solid color-mix(in srgb,var(--accent) 14%,var(--border)); border-radius: 14px; color: var(--accent); background: color-mix(in srgb,var(--card) 96%,var(--sc-bg)); box-shadow: 0 10px 22px color-mix(in srgb,var(--accent) 8%, transparent); overflow: hidden; }
    .scanner-logo-img { display: block; width: 40px; height: 40px; object-fit: contain; }
    .scanner-logo[data-scanner-logo="semgrep"] .scanner-logo-img, .scanner-logo[data-scanner-logo="osv"] .scanner-logo-img, .scanner-logo[data-scanner-logo="sonarqube"] .scanner-logo-img { width: 42px; height: 32px; }
    .scanner-logo .compact-icon { width: 22px; height: 22px; stroke-width: 1.8; }
    .scanner-logo.fallback.ready { color: var(--ok); border-color: color-mix(in srgb,var(--ok) 30%,var(--border)); background: color-mix(in srgb,var(--ok) 9%,var(--card)); }
    .scanner-logo.fallback.failed { color: var(--bad); border-color: color-mix(in srgb,var(--bad) 30%,var(--border)); background: color-mix(in srgb,var(--bad) 8%,var(--card)); }
    .scanner-logo.fallback.missing { color: var(--warn); border-color: color-mix(in srgb,var(--warn) 32%,var(--border)); background: color-mix(in srgb,var(--warn) 9%,var(--card)); }
    .status { flex: none; max-width: 48%; padding: 4px 9px; border-radius: 999px; color: var(--muted); background: var(--sc-surface-soft); font-size: 10px; font-weight: 800; line-height: 1.25; text-align: right; overflow-wrap: anywhere; }
    .ready .status { color: var(--ok); background: color-mix(in srgb,var(--ok) 11%,var(--card)); }
    .failed .status { color: var(--bad); background: color-mix(in srgb,var(--bad) 10%,var(--card)); }
    .installing .status { color: var(--accent); background: color-mix(in srgb,var(--accent) 12%,var(--card)); }
    .missing .status { color: var(--warn); background: color-mix(in srgb,var(--warn) 10%,var(--card)); }
    dl { margin: 0; }
    dl > div { display: grid; grid-template-columns: minmax(110px, .34fr) minmax(0, 1fr); gap: 12px; padding: 8px 0; border-top: 1px solid color-mix(in srgb,var(--border) 72%, transparent); }
    dl > div:first-child { border-top: 0; }
    dt { color: var(--muted); font-size: 10px; font-weight: 800; text-transform: uppercase; }
    dd { margin: 0; min-width: 0; color: var(--text); }
    .path { display: block; width: 100%; max-height: calc(2.9em + 12px); padding: 6px 8px; border: 1px solid color-mix(in srgb,var(--border) 70%, transparent); border-radius: 8px; background: color-mix(in srgb,var(--sc-surface-soft) 70%, transparent); overflow: hidden; overflow-wrap: anywhere; font-family: var(--vscode-editor-font-family,monospace); font-size: 11px; line-height: 1.45; }
    .path:hover, .path:focus-within { max-height: none; }
    .operation { display: flex; gap: 10px; min-width: 0; background: color-mix(in srgb,var(--accent) 9%,var(--card)); padding: 11px; border: 1px solid color-mix(in srgb,var(--accent) 14%,var(--border)); border-radius: 10px; margin: 0; }
    .operation.failed { background: color-mix(in srgb,var(--bad) 9%,var(--card)); border-color: color-mix(in srgb,var(--bad) 18%,var(--border)); }
    .spinner { width: 15px; height: 15px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .8s linear infinite; flex: none; margin-top: 2px; }
    .operation.failed .spinner { animation: none; border-color: var(--bad); }
    progress { width: 100%; accent-color: var(--accent); }
    .tool-controls { display: grid; gap: 11px; margin-top: auto; padding-top: 12px; border-top: 1px solid color-mix(in srgb,var(--border) 74%, transparent); }
    .control-group { display: grid; gap: 7px; }
    .control-group > span { color: var(--muted); font-size: 10px; font-weight: 800; text-transform: uppercase; }
    .mode-selector { display: grid; grid-template-columns: repeat(3,minmax(0, 1fr)); align-items: center; gap: 4px; padding: 4px; border: 1px solid var(--border); border-radius: 10px; background: color-mix(in srgb,var(--sc-surface-soft) 66%, transparent); }
    .mode-selector button { width: 100%; min-width: 0; padding-inline: 7px; text-align: center; line-height: 1.2; }
    .mode-selector button[data-sonar-install], .mode-selector button[data-snyk-install] { grid-column: 1 / -1; }
    .maintenance-actions { justify-content: flex-end; margin-top: auto; }
    button { border: 1px solid color-mix(in srgb,var(--accent) 26%,transparent); border-radius: 8px; padding: 8px 12px; background: var(--accent); color: var(--vscode-button-foreground,#fff); font: inherit; font-weight: 700; cursor: pointer; }
    button.secondary, .mode-option.secondary { border-color: var(--border); background: transparent; color: var(--muted); }
    .mode-option[aria-current="true"] { color: var(--vscode-button-foreground,#fff); background: var(--accent); box-shadow: 0 8px 16px color-mix(in srgb,var(--accent) 16%, transparent); }
    .toggle-action { color: var(--accent); background: color-mix(in srgb,var(--accent) 11%,var(--card)); }
    button:disabled { opacity: .55; cursor: wait; }
    button:focus-visible { outline: 2px solid var(--vscode-focusBorder,var(--accent)); outline-offset: 2px; }
    .footer { margin-top: 18px; color: var(--muted); }
    .sonar-note { font-size: 12px; margin: 0 0 12px; }
    .sonar-section { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 16px 0 0; padding-top: 12px; border-top: 1px solid color-mix(in srgb,var(--border) 76%, transparent); display: flex; justify-content: space-between; gap: 10px; align-items: baseline; }
    .sonar-section small { text-transform: none; letter-spacing: 0; font-weight: 400; }
    .sonar-footer { margin-top: 4px; padding-top: 12px; border-top: 1px solid color-mix(in srgb,var(--border) 76%, transparent); }
    .sonar-note code { font-family: var(--vscode-editor-font-family,monospace); }
    .muted { color: var(--muted); }
    @media (min-width: 900px) {
      .scanner-config-grid { grid-template-columns: repeat(2,minmax(0, 1fr)); }
      .scanner-config-grid .tool[data-tool='sonarqube'] { grid-column: span 2; }
    }
    @media (min-width: 1400px) {
      .scanner-config-grid { grid-template-columns: repeat(3,minmax(0, 1fr)); }
      .scanner-config-grid .tool[data-tool='sonarqube'] { grid-column: span 2; }
    }
    .confirm-backdrop { position: fixed; inset: 0; z-index: 1000; background: var(--overlay); display: flex; align-items: center; justify-content: center; padding: 24px; overflow: auto; }
    .confirm { width: min(620px,100%); max-height: calc(100vh - 48px); overflow: auto; display: grid; grid-template-columns: auto 1fr; gap: 16px; background: var(--card); border: 1px solid var(--vscode-focusBorder,var(--accent)); border-radius: 12px; padding: 22px; box-shadow: 0 12px 38px var(--overlay); }
    .confirm-icon { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 50%; background: color-mix(in srgb,var(--accent) 13%,var(--card)); color: var(--accent); font-size: 22px; font-weight: 700; }
    .eyebrow { color: var(--accent); font-size: 11px; font-weight: 800; letter-spacing: .08em; }
    .confirm h2 { font-size: 21px; margin: 2px 0 8px; }
    .tool-chips { display: flex; gap: 7px; flex-wrap: wrap; margin: 14px 0; }
    .tool-chips span { border: 1px solid var(--border); border-radius: 99px; padding: 4px 9px; font-weight: 700; }
    .confirm-details { border: 1px solid var(--border); border-radius: 8px; margin: 12px 0; padding: 0 10px; }
    .confirm-note { font-size: 12px; }
    .confirm-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @media (max-width: 760px) {
      .tool-head { display: grid; }
      .status { justify-self: start; max-width: 100%; text-align: left; }
      dl > div { grid-template-columns: 1fr; gap: 4px; }
      .maintenance-actions { justify-content: flex-start; }
      .scanner-config-grid .tool[data-tool='sonarqube'] { grid-column: auto; }
      .confirm { grid-template-columns: 1fr; }
      .confirm-icon { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; transition: none !important; }
    }`,
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();document.getElementById('refresh').onclick=()=>vscode.postMessage({type:'refresh'});document.getElementById('install-all').onclick=()=>vscode.postMessage({type:'requestInstallAll'});document.querySelectorAll('[data-install]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'requestInstall',tool:b.dataset.install}));document.querySelectorAll('[data-recheck]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'refresh'}));document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setAuto',tool:b.dataset.mode}));document.querySelectorAll('[data-scanner-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setScannerMode',tool:b.dataset.scanner,mode:b.dataset.scannerMode}));document.querySelectorAll('[data-sonar-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setSonarMode',mode:b.dataset.sonarMode}));document.querySelectorAll('[data-scanner-enabled]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setScannerEnabled',tool:b.dataset.scanner,enabled:b.dataset.scannerEnabled==='true'}));document.querySelector('[data-sonar-enabled]')?.addEventListener('click',e=>vscode.postMessage({type:'setSonarEnabled',enabled:e.currentTarget.dataset.sonarEnabled==='true'}));document.querySelector('[data-sonar-token]')?.addEventListener('click',()=>vscode.postMessage({type:'configureSonarToken'}));document.querySelectorAll('[data-sonar-recheck]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'refresh'}));document.querySelectorAll('[data-sonar-server]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'chooseSonarServer',serverType:b.dataset.sonarServer}));document.querySelector('[data-sonar-server-start]')?.addEventListener('click',()=>vscode.postMessage({type:'startSonarServer'}));document.querySelector('[data-sonar-server-stop]')?.addEventListener('click',()=>vscode.postMessage({type:'stopSonarServer'}));document.querySelector('[data-sonar-install]')?.addEventListener('click',()=>vscode.postMessage({type:'requestInstall',tool:'sonarscanner'}));document.querySelector('[data-sonar-server-url]')?.addEventListener('click',()=>vscode.postMessage({type:'configureSonarHostUrl'}));document.querySelector('[data-sonar-open]')?.addEventListener('click',()=>vscode.postMessage({type:'openSonarServer'}));document.querySelectorAll('[data-snyk-mode]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'setSnykMode',mode:b.dataset.snykMode}));document.querySelector('[data-snyk-enabled]')?.addEventListener('click',e=>vscode.postMessage({type:'setSnykEnabled',enabled:e.currentTarget.dataset.snykEnabled==='true'}));document.querySelector('[data-snyk-token]')?.addEventListener('click',()=>vscode.postMessage({type:'configureSnykToken'}));document.querySelector('[data-snyk-install]')?.addEventListener('click',()=>vscode.postMessage({type:'requestInstall',tool:'snyk'}));document.querySelectorAll('[data-snyk-recheck]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'refresh'}));document.querySelectorAll('[data-install-abort]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'abortInstall',tool:b.dataset.installAbort}));document.querySelectorAll('[data-install-retry]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'retryInstall',tool:b.dataset.installRetry}));document.getElementById('approve-install')?.addEventListener('click',()=>vscode.postMessage({type:'approveInstall'}));document.getElementById('cancel-install')?.addEventListener('click',()=>vscode.postMessage({type:'cancelInstall'}));`,
    csp: `default-src 'none'; img-src ${String(assets?.cspSource || '').trim() || 'vscode-resource: vscode-webview-resource: vscode-webview:'} data:; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`,
    brandLogoUri: assets?.brandLogoUri || ''
  });
}

module.exports = {
  renderScannerSetupHtml, renderManagedCard, renderSonarCard, renderSonarServerSection,
  renderSnykCard, snykDiagnosis, usedSnykMode, snykCapabilityLabel,
  usedScannerMode, modeButtons, sonarDiagnosis, safeServerUrl, SONAR_MODES, escapeHtml
};
