const semgrep = require('./semgrep');
const gitleaks = require('./gitleaks');
const trivy = require('./trivy');
const osv = require('./osv');
const { dockerCliArgs } = require('./docker');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const SCANNER_MODES = Object.freeze([['auto', 'Auto'], ['local', 'Local'], ['docker', 'Docker']]);

/**
 * Execution contract of each managed scanner.
 *
 * `resolve` delegates to the runner's own `resolveInvocation`, so the mode the
 * page reports is decided by exactly the code the analysis pipeline runs. The
 * images are read from the runners, never guessed.
 * `settingKey` reuses the historical `<tool>.command` nomenclature.
 */
const SCANNER_RUNTIMES = Object.freeze({
  semgrep: {
    settingKey: 'semgrep.command',
    image: 'semgrep/semgrep',
    resolve: (mode, workspacePath) => semgrep.resolveInvocation(mode, workspacePath, 'p/security-audit', {}, [])
  },
  gitleaks: {
    settingKey: 'gitleaks.command',
    enabledKey: 'gitleaks.enabled',
    image: 'zricethezav/gitleaks:latest',
    resolve: (mode, workspacePath) => gitleaks.resolveInvocation(mode, workspacePath)
  },
  trivy: {
    settingKey: 'trivy.command',
    enabledKey: 'trivy.enabled',
    image: 'aquasec/trivy:latest',
    resolve: (mode, workspacePath) => trivy.resolveInvocation(mode, workspacePath, [])
  },
  osv: {
    settingKey: 'osv.command',
    enabledKey: 'osv.enabled',
    image: 'ghcr.io/google/osv-scanner:latest',
    resolve: (mode, workspacePath) => osv.resolveInvocation(mode, workspacePath)
  }
});

function normalizeMode(value) {
  const mode = String(value || 'auto').toLowerCase();
  return SCANNER_MODES.some(([candidate]) => candidate === mode) ? mode : 'auto';
}

function modeLabel(mode) {
  return SCANNER_MODES.find(([candidate]) => candidate === mode)?.[1] || '';
}

/**
 * Read-only presence check. It never pulls: an absent image simply means the
 * first scan will download it, which is the current Security Center behaviour.
 */
async function dockerImagePresent(image, { exec = execFileAsync, timeoutMs = 8000 } = {}) {
  try {
    await exec('docker', dockerCliArgs(['image', 'inspect', image, '--format', '{{.Id}}']), { timeout: timeoutMs, windowsHide: true });
    return true;
  } catch { return false; }
}

/**
 * Turns a resolution outcome into the state shown on the card.
 *
 * A missing local binary is never reported as unavailable while the Docker
 * fallback works: that is the whole point of the `auto` mode.
 */
function scannerState({ enabled = true, configuredMode = 'auto', resolvedMode = '', installed = false, error = '' } = {}) {
  if (!enabled) {
    return { state: 'disabled', label: 'Désactivé', hint: 'Ce scanner est désactivé dans les paramètres : il ne participe pas au pipeline.' };
  }
  if (resolvedMode === 'local') return { state: 'ready', label: 'Prêt', hint: '' };
  if (resolvedMode === 'docker') {
    return {
      state: 'ready',
      label: 'Prêt — Docker',
      hint: installed || configuredMode === 'docker' ? '' : 'Binaire local absent : Security Center utilisera l’image Docker.'
    };
  }
  if (configuredMode === 'local') return { state: 'missing', label: 'Non installé', hint: error || 'Le binaire local est introuvable.' };
  if (configuredMode === 'docker') return { state: 'failed', label: 'Docker indisponible', hint: error || 'Docker ne répond pas.' };
  return { state: 'failed', label: 'Erreur', hint: error || 'Ni le binaire local ni Docker ne sont disponibles.' };
}

/**
 * Full diagnosis of one managed scanner. Performs binary and Docker lookups
 * only — it never starts a workspace scan.
 */
async function diagnoseScanner(id, {
  configuredMode = 'auto',
  enabled = true,
  workspacePath = process.cwd(),
  status = {},
  runtimes = SCANNER_RUNTIMES,
  checkImage = dockerImagePresent
} = {}) {
  const runtime = runtimes[id];
  if (!runtime) throw new Error(`Scanner inconnu : ${id}.`);
  const mode = normalizeMode(configuredMode);
  let resolvedMode = '';
  let error = '';
  try {
    resolvedMode = normalizeMode((await runtime.resolve(mode, workspacePath))?.mode) === 'docker' ? 'docker' : 'local';
  } catch (resolutionError) {
    error = resolutionError?.message || '';
  }
  const imagePresent = resolvedMode === 'docker' ? await checkImage(runtime.image) : null;
  return {
    id,
    configuredMode: mode,
    configuredModeLabel: modeLabel(mode),
    resolvedMode,
    resolvedModeLabel: modeLabel(resolvedMode),
    image: runtime.image,
    imagePresent,
    settingKey: runtime.settingKey,
    // Only scanners with a real `enabled` setting can be toggled. Semgrep has
    // none: it is unconditional in the current pipeline.
    enabledKey: runtime.enabledKey || '',
    enabled: runtime.enabledKey ? Boolean(enabled) : true,
    supports: { auto: true, local: true, docker: true },
    error,
    ...scannerState({ enabled, configuredMode: mode, resolvedMode, installed: Boolean(status.installed), error })
  };
}

module.exports = {
  SCANNER_MODES, SCANNER_RUNTIMES,
  normalizeMode, modeLabel, scannerState, diagnoseScanner, dockerImagePresent
};
