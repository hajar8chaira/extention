'use strict';

/**
 * Les résultats ZAP, rattachés au run et au mode qui les ont produits.
 *
 * Un baseline passif observe le trafic ; un scan actif envoie des attaques. Les
 * deux produisent des alertes ZAP qui se ressemblent, et les confondre faisait
 * croire qu'un finding avait été confirmé activement alors qu'il n'avait été
 * qu'observé. Chaque finding garde donc `runId` et `scanMode`, et la carte ZAP
 * compare les deux derniers runs d'une même cible par empreinte — jamais par
 * soustraction de compteurs, qui dirait « +2 » quand deux findings différents
 * ont été remplacés par deux autres.
 *
 * Le module est pur : ni `vscode`, ni I/O.
 */

const ZAP_SCAN_MODE = Object.freeze({ PASSIVE: 'passive', ACTIVE: 'active' });

/** Nombre d'observations conservées par run : borné, jamais tronqué en silence dans les comptes. */
const MAX_OBSERVATIONS = 5000;

/** Le mode de résultat d'un mode d'exécution ZAP, ou '' s'il n'est pas connu. */
function zapScanMode(mode) {
  const value = String(mode || '').trim().toLowerCase();
  if (value === 'baseline' || value === 'passive') return ZAP_SCAN_MODE.PASSIVE;
  if (value === 'active' || value === 'openapi') return ZAP_SCAN_MODE.ACTIVE;
  return '';
}

/**
 * Un endpoint réduit à ce qui l'identifie.
 *
 * L'hôte est en minuscules, le `/` final retiré, et la chaîne de requête réduite
 * à ses noms de paramètres triés : deux alertes sur `/search?q=a` et
 * `/search?q=b` décrivent le même point d'entrée, pas deux vulnérabilités.
 */
function normalizeZapEndpoint(value) {
  const raw = String(value || '').trim();
  try {
    const url = new URL(raw);
    const names = [...new Set(url.searchParams.keys())].sort();
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    return `${url.protocol}//${url.host.toLowerCase()}${pathname}${names.length ? `?${names.join('&')}` : ''}`;
  } catch {
    return raw.replace(/\/+$/, '').toLowerCase();
  }
}

/**
 * L'empreinte normalisée d'un finding ZAP : règle, méthode, endpoint, paramètre.
 *
 * L'identifiant brut du normaliseur retombe sur l'index de l'instance quand ZAP
 * ne nomme pas de paramètre ; deux runs qui listent les mêmes alertes dans un
 * autre ordre auraient eu des identifiants différents. L'empreinte ne dépend
 * que de ce que l'alerte décrit.
 */
function zapFindingFingerprint(finding = {}) {
  const rule = String(finding.ruleId || finding.cwe || finding.title || 'zap-alert').trim().toLowerCase();
  const method = String(finding.method || 'HTTP').trim().toUpperCase();
  const endpoint = normalizeZapEndpoint(finding.endpoint || '');
  const parameter = String(finding.parameter || '').trim();
  return `zap:${rule}:${method}:${endpoint}:${parameter}`;
}

/** La clé d'une cible : son origine, pour que `/` et `/#/` restent la même cible. */
function zapTargetKey(target) {
  try {
    return new URL(String(target || '')).origin.toLowerCase();
  } catch {
    return String(target || '').trim().replace(/\/+$/, '').toLowerCase();
  }
}

/** Les findings ZAP d'un run, marqués de leur run et de leur mode. Les autres outils passent tels quels. */
function stampZapFindings(findings = [], { runId = '', scanMode = '' } = {}) {
  const mode = zapScanMode(scanMode);
  return (Array.isArray(findings) ? findings : []).map((finding) => (finding?.tool === 'ZAP'
    ? {
      ...finding,
      runId: String(runId || finding.runId || ''),
      scanMode: mode || finding.scanMode || '',
      zapFingerprint: zapFindingFingerprint(finding)
    }
    : finding));
}

function restoreObservation(raw) {
  if (!raw || typeof raw !== 'object' || !raw.fingerprint) return null;
  return {
    fingerprint: String(raw.fingerprint),
    title: String(raw.title || ''),
    rawSeverity: String(raw.rawSeverity || ''),
    endpoint: String(raw.endpoint || ''),
    method: String(raw.method || ''),
    parameter: String(raw.parameter || '')
  };
}

function restoreRun(raw, mode) {
  if (!raw || typeof raw !== 'object' || zapScanMode(raw.scanMode) !== mode) return null;
  return {
    runId: String(raw.runId || ''),
    scanMode: mode,
    target: String(raw.target || ''),
    completedAt: raw.completedAt || null,
    observations: (Array.isArray(raw.observations) ? raw.observations : []).map(restoreObservation).filter(Boolean)
  };
}

/**
 * Restaure les résultats persistés. Ce qui n'est pas reconnaissable disparaît
 * plutôt que de fausser une comparaison.
 */
function restoreZapRunResults(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const restored = {};
  for (const [target, entry] of Object.entries(raw)) {
    if (!entry || typeof entry !== 'object') continue;
    const passive = restoreRun(entry.passive, ZAP_SCAN_MODE.PASSIVE);
    const active = restoreRun(entry.active, ZAP_SCAN_MODE.ACTIVE);
    if (passive || active) restored[target] = { ...(passive ? { passive } : {}), ...(active ? { active } : {}) };
  }
  return restored;
}

/**
 * Enregistre un run ZAP terminé comme le dernier de son mode pour sa cible.
 *
 * Seul un run terminé est enregistré : un run en échec n'a pas d'ensemble
 * d'observations complet, et le comparer dirait « disparu » à tort.
 */
function recordZapRunResult(results, { target = '', runId = '', scanMode = '', completedAt = null, findings = [] } = {}) {
  const restored = restoreZapRunResults(results);
  const mode = zapScanMode(scanMode);
  const key = zapTargetKey(target);
  if (!mode || !key) return restored;
  const observations = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (finding?.tool !== 'ZAP') continue;
    const fingerprint = finding.zapFingerprint || zapFindingFingerprint(finding);
    if (observations.has(fingerprint)) continue;
    observations.set(fingerprint, restoreObservation({ ...finding, fingerprint }));
    if (observations.size >= MAX_OBSERVATIONS) break;
  }
  return {
    ...restored,
    [key]: {
      ...(restored[key] || {}),
      [mode]: {
        runId: String(runId || ''),
        scanMode: mode,
        target: key,
        completedAt: completedAt || new Date().toISOString(),
        observations: [...observations.values()]
      }
    }
  };
}

/**
 * Compare le dernier run passif et le dernier run actif d'une cible.
 *
 * Trois ensembles d'empreintes, calculés par appartenance : communs, apparus en
 * actif, restés propres au passif. `null` tant que les deux runs n'existent pas.
 */
function compareZapRuns(results, target) {
  const entry = restoreZapRunResults(results)[zapTargetKey(target)];
  if (!entry?.passive || !entry?.active) return null;
  const byFingerprint = (run) => new Map(run.observations.map((observation) => [observation.fingerprint, observation]));
  const passive = byFingerprint(entry.passive);
  const active = byFingerprint(entry.active);
  const common = [...active.values()].filter((observation) => passive.has(observation.fingerprint));
  const newInActive = [...active.values()].filter((observation) => !passive.has(observation.fingerprint));
  const onlyInPassive = [...passive.values()].filter((observation) => !active.has(observation.fingerprint));
  const summary = (run, size) => ({ runId: run.runId, completedAt: run.completedAt, observations: size });
  return {
    target: zapTargetKey(target),
    passive: summary(entry.passive, passive.size),
    active: summary(entry.active, active.size),
    common,
    newInActive,
    onlyInPassive
  };
}

module.exports = {
  ZAP_SCAN_MODE, zapScanMode, normalizeZapEndpoint, zapFindingFingerprint, zapTargetKey,
  stampZapFindings, recordZapRunResult, restoreZapRunResults, compareZapRuns
};
