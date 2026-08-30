'use strict';

const SCANNER_PRESENTATION = Object.freeze({
  Semgrep: {
    id: 'semgrep',
    label: 'Semgrep',
    description: 'Analyse statique du code (SAST)',
    category: 'SAST',
    logo: 'semgrep.svg',
    fallbackIcon: 'code',
    logoSource: 'https://github.com/semgrep/semgrep/blob/develop/semgrep.svg',
    license: 'LGPL-2.1'
  },
  Gitleaks: {
    id: 'gitleaks',
    label: 'Gitleaks',
    description: 'Détection de secrets',
    category: 'Secrets',
    logo: 'gitleaks.svg',
    fallbackIcon: 'key',
    logoSource: 'https://github.com/gitleaks/gitleaks#readme',
    license: 'MIT'
  },
  Trivy: {
    id: 'trivy',
    label: 'Trivy',
    description: 'Dépendances, conteneurs et IaC',
    category: 'SCA/IaC',
    logo: 'trivy.svg',
    fallbackIcon: 'cube',
    logoSource: 'https://github.com/simple-icons/simple-icons/blob/develop/icons/trivy.svg',
    license: 'CC0-1.0'
  },
  'OSV-Scanner': {
    id: 'osv',
    label: 'OSV-Scanner',
    description: 'Vulnérabilités des dépendances',
    category: 'SCA',
    logo: 'osv-scanner.svg',
    fallbackIcon: 'shield',
    logoSource: 'https://github.com/google/osv.dev/blob/master/docs/images/osv_logo_light-full.svg',
    license: 'Apache-2.0'
  },
  SonarQube: {
    id: 'sonarqube',
    label: 'SonarQube',
    description: 'Qualité et sécurité du code (SAST)',
    category: 'Code Quality',
    logo: 'sonarqube.svg',
    fallbackIcon: 'code',
    logoSource: 'https://github.com/simple-icons/simple-icons/blob/develop/icons/sonarqube.svg',
    license: 'CC0-1.0'
  },
  Snyk: {
    id: 'snyk',
    label: 'Snyk',
    description: 'Dépendances, code et IaC (SCA/SAST/IaC)',
    category: 'SCA/SAST/IaC',
    logo: 'snyk.svg',
    fallbackIcon: 'shield',
    logoSource: 'https://github.com/simple-icons/simple-icons/blob/develop/icons/snyk.svg',
    license: 'CC0-1.0'
  },
  ZAP: {
    id: 'zap',
    label: 'ZAP',
    description: 'Analyse dynamique (DAST)',
    category: 'DAST',
    logo: 'zap.png',
    fallbackIcon: 'pulse',
    logoSource: 'https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/resources/resource/zap128x128.png',
    license: 'Apache-2.0'
  }
});

const SCANNER_ID_TO_TOOL = Object.freeze(Object.fromEntries(
  Object.entries(SCANNER_PRESENTATION).map(([tool, presentation]) => [presentation.id, tool])
));

function scannerPresentation(tool) {
  return SCANNER_PRESENTATION[tool] || {
    id: String(tool || '').toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    label: String(tool || 'Scanner'),
    description: 'Scanner de sécurité',
    category: 'Security',
    logo: '',
    fallbackIcon: 'shield',
    logoSource: '',
    license: ''
  };
}

function scannerIdForTool(tool) {
  return scannerPresentation(tool).id;
}

function scannerToolFromId(scannerIdOrTool) {
  const value = String(scannerIdOrTool || '');
  if (SCANNER_PRESENTATION[value]) return value;
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return SCANNER_ID_TO_TOOL[normalized] || value;
}

function scannerLogoUri(tool, assets = {}) {
  const presentation = scannerPresentation(tool);
  const logos = assets?.scannerLogoUris && typeof assets.scannerLogoUris === 'object'
    ? assets.scannerLogoUris
    : {};
  const uri = logos[tool] || logos[presentation.id] || '';
  return isTrustedWebviewAssetUri(uri, assets) ? uri : '';
}

function isTrustedWebviewAssetUri(value, assets = {}) {
  const uri = String(value || '');
  if (!uri) return false;
  if (/^(vscode-resource|vscode-webview-resource|vscode-webview):/i.test(uri)) return true;
  if (!/^https:\/\//i.test(uri)) return !/^http:\/\//i.test(uri);
  let parsed;
  try { parsed = new URL(uri); } catch { return false; }
  const cspSource = String(assets?.cspSource || '');
  if (/^https:\/\/\*\.vscode-cdn\.net$/i.test(cspSource) && parsed.hostname.endsWith('.vscode-cdn.net')) return true;
  if (/\.vscode-cdn\.net$/i.test(parsed.hostname)) return true;
  if (cspSource && !cspSource.includes('*')) {
    try {
      const csp = new URL(cspSource);
      return parsed.origin === csp.origin;
    } catch { /* ignore malformed cspSource */ }
  }
  return false;
}

module.exports = {
  SCANNER_PRESENTATION,
  SCANNER_ID_TO_TOOL,
  scannerPresentation,
  scannerIdForTool,
  scannerToolFromId,
  scannerLogoUri,
  isTrustedWebviewAssetUri
};
