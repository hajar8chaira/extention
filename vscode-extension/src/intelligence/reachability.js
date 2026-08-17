'use strict';

/**
 * Reachability engine.
 *
 * "A vulnerability exists" and "the vulnerable code can be reached" are two
 * different statements. This module answers only the second one, and it answers
 * it with evidence or not at all.
 *
 * The ladder it can climb, from weakest to strongest:
 *
 *   not_evaluated → present → imported → statically_reachable → dynamically_confirmed
 *
 * Two outcomes are deliberately *not* on that ladder:
 *   - `not_reachable` is claimed only when the import scan actually ran and
 *     found nothing. A failed or skipped analysis yields `unknown`.
 *   - `unknown` is the answer whenever the evidence is missing or unreadable.
 *
 * What `statically_reachable` means here is stated precisely and not inflated:
 * the vulnerable package is imported by a module that is itself an entry point
 * or a declared HTTP route handler. Security Center does not build a full
 * inter-procedural call graph, so that state carries `medium` confidence and
 * says so in its reason.
 */

const fs = require('fs/promises');
const path = require('path');

const STATES = Object.freeze([
  'not_evaluated', 'present', 'imported', 'statically_reachable', 'dynamically_confirmed', 'not_reachable', 'unknown'
]);

const STATE_RANK = Object.freeze({
  not_evaluated: 0, unknown: 1, not_reachable: 2, present: 3, imported: 4, statically_reachable: 5, dynamically_confirmed: 6
});

const STATE_LABELS = Object.freeze({
  not_evaluated: 'Non évaluée',
  present: 'Présente dans les dépendances',
  imported: 'Importée par le code',
  statically_reachable: 'Atteignable statiquement',
  dynamically_confirmed: 'Confirmée dynamiquement',
  not_reachable: 'Non atteignable',
  unknown: 'Indéterminée'
});

/**
 * Public status vocabulary, coarser than the internal state.
 *
 * `REACHABLE` is only ever reached from a state that carries positive evidence
 * (a dynamic confirmation, or an import from an entry point). Everything that
 * merely *might* be reachable, and everything that could not be established,
 * degrades to POTENTIALLY_REACHABLE or UNKNOWN — never to REACHABLE.
 */
const STATUSES = Object.freeze(['REACHABLE', 'POTENTIALLY_REACHABLE', 'NOT_REACHABLE', 'UNKNOWN']);

const STATE_TO_STATUS = Object.freeze({
  dynamically_confirmed: 'REACHABLE',
  statically_reachable: 'REACHABLE',
  imported: 'POTENTIALLY_REACHABLE',
  present: 'POTENTIALLY_REACHABLE',
  not_reachable: 'NOT_REACHABLE',
  unknown: 'UNKNOWN',
  not_evaluated: 'UNKNOWN'
});

const STATUS_LABELS = Object.freeze({
  REACHABLE: 'Atteignable',
  POTENTIALLY_REACHABLE: 'Potentiellement atteignable',
  NOT_REACHABLE: 'Non atteignable',
  UNKNOWN: 'Indéterminée'
});

function statusForState(state) {
  return STATE_TO_STATUS[state] || 'UNKNOWN';
}

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py']);
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', 'vendor', 'target', '__pycache__', '.venv']);
const ENTRY_FILE_NAMES = new Set(['index.js', 'app.js', 'server.js', 'main.js', 'index.ts', 'app.ts', 'server.ts', 'main.ts', 'app.py', 'main.py', 'wsgi.py', 'manage.py']);

function normalizePath(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
}

/**
 * Runtime evidence, kept apart from code reachability.
 *
 * `runtime_observed` means a dynamic tool really sent a request and saw this.
 * It carries the method, the URL and the evidence, and it names its source.
 * Static analysis never sets it.
 */
function runtimeObservation(finding, source = '') {
  const tool = String(source || finding.tool || '').toLowerCase();
  return {
    observed: true,
    source: tool.includes('burp') ? 'burp' : tool.includes('zap') ? 'zap' : tool || 'dast',
    method: String(finding.method || ''),
    url: String(finding.endpoint || ''),
    parameter: String(finding.parameter || ''),
    evidence: String(finding.evidence || ''),
    // A runtime hit on a static asset is observed traffic, not an exploited
    // application path: the distinction is recorded rather than assumed.
    staticAsset: isStaticAsset(finding.endpoint)
  };
}

/** Stylesheets, scripts, images, favicon, robots.txt … */
function isStaticAsset(endpoint) {
  const pathname = String(endpoint || '').split('?')[0].toLowerCase();
  return /\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif)$/.test(pathname)
    || /\/(robots\.txt|sitemap\.xml|favicon\.ico)$/.test(pathname);
}

function reachability(state, confidence, reason, evidence = []) {
  const resolved = STATES.includes(state) ? state : 'unknown';
  return {
    state: resolved,
    // Coarse status consumed by the UI, the CLI and the tests.
    status: statusForState(resolved),
    confidence,
    reason,
    // `explanation` is the reason plus what the status actually means, so a
    // reader never has to know the internal state vocabulary.
    explanation: `${STATUS_LABELS[statusForState(resolved)]} — ${reason}`,
    evidence
  };
}

/**
 * Import statements for a given package, in one file.
 * Scoped packages (`@scope/name`) and submodule imports (`lodash/merge`) count;
 * a substring match such as `lodash-es` does not.
 */
function importsOfPackage(text, packageName) {
  const name = String(packageName || '').trim();
  if (!name) return [];
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const specifier = `${escaped}(?:/[^'"\`]*)?`;
  const patterns = [
    new RegExp(`require\\s*\\(\\s*['"\`]${specifier}['"\`]\\s*\\)`, 'g'),
    new RegExp(`from\\s+['"\`]${specifier}['"\`]`, 'g'),
    new RegExp(`import\\s+['"\`]${specifier}['"\`]`, 'g'),
    new RegExp(`import\\s*\\(\\s*['"\`]${specifier}['"\`]\\s*\\)`, 'g'),
    // Python: `import lodash` / `from lodash import x` — word-bounded.
    new RegExp(`^\\s*(?:from|import)\\s+${escaped}(?:\\.[\\w.]+)?(?:\\s|$|,)`, 'gm')
  ];
  const hits = [];
  for (const pattern of patterns) {
    for (const match of String(text || '').matchAll(pattern)) {
      hits.push({ index: match.index, statement: match[0].trim().slice(0, 120) });
    }
  }
  return hits;
}

async function* walkSourceFiles(root, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = await fs.readdir(root, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue;
      yield* walkSourceFiles(candidate, depth + 1);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      yield candidate;
    }
  }
}

/**
 * Indexes which source files import which of the given packages.
 *
 * `analysed` reports whether the scan actually ran: a `false` here is what keeps
 * an unimported package at `unknown` instead of `not_reachable`.
 */
async function buildImportIndex(workspacePath, packageNames = [], { maxFiles = 800, maxFileSize = 1024 * 1024 } = {}) {
  const packages = [...new Set(packageNames.map((name) => String(name || '').trim()).filter(Boolean))];
  const index = new Map(packages.map((name) => [name, []]));
  if (!packages.length) return { index, analysed: true, scannedFiles: 0, files: [] };
  const root = path.resolve(workspacePath);
  const files = [];
  let scannedFiles = 0;
  try {
    for await (const file of walkSourceFiles(root)) {
      if (scannedFiles >= maxFiles) break;
      scannedFiles += 1;
      let text = '';
      try {
        const stat = await fs.stat(file);
        if (stat.size > maxFileSize) continue;
        text = await fs.readFile(file, 'utf8');
      } catch { continue; }
      const relative = normalizePath(path.relative(root, file));
      files.push(relative);
      for (const name of packages) {
        for (const hit of importsOfPackage(text, name)) {
          index.get(name).push({
            file: relative,
            line: text.slice(0, hit.index).split(/\r?\n/).length,
            statement: hit.statement
          });
        }
      }
    }
  } catch {
    return { index, analysed: false, scannedFiles, files };
  }
  return { index, analysed: scannedFiles > 0, scannedFiles, files };
}

/** Files that start the program or serve an HTTP route. */
function entryPointFiles(routeMap, files = []) {
  const fromRoutes = (routeMap?.routes || []).map((route) => normalizePath(route.file).toLowerCase());
  const conventional = files
    .filter((file) => ENTRY_FILE_NAMES.has(path.posix.basename(normalizePath(file)).toLowerCase()))
    .map((file) => normalizePath(file).toLowerCase());
  return new Set([...fromRoutes, ...conventional]);
}

/**
 * Reachability of one dependency finding.
 *
 * `dynamicEndpoints` holds the endpoints a DAST scanner actually exercised, so a
 * dependency can only be « confirmée dynamiquement » through a correlation that
 * really links it to observed traffic.
 */
function evaluateDependency(finding, { importIndex, entryPoints, dynamicallyConfirmedIds }) {
  const packageName = finding.package;
  if (!packageName) {
    return reachability('unknown', 'low', 'Le scanner n’a pas nommé le paquet concerné.');
  }
  if (dynamicallyConfirmedIds.has(finding.id)) {
    return reachability('dynamically_confirmed', 'high',
      'Une preuve dynamique corrélée porte sur ce composant.',
      [{ type: 'dast', detail: 'Corrélation DAST confirmée' }]);
  }
  if (!importIndex || importIndex.analysed !== true) {
    return reachability('unknown', 'low',
      'L’analyse des imports n’a pas pu être exécutée : l’atteignabilité reste indéterminée.');
  }
  const imports = importIndex.index.get(packageName) || [];
  const evidence = imports.slice(0, 5).map((entry) => ({
    type: 'import', file: entry.file, line: entry.line, detail: entry.statement
  }));
  if (!imports.length) {
    // The scan ran and found no import: the strongest negative statement that
    // is still honest is « aucun import trouvé », with modest confidence
    // because dynamic requires and re-exports are not resolved.
    return reachability('not_reachable', 'low',
      `Aucun import de ${packageName} n’a été trouvé dans le code analysé. Les imports dynamiques ne sont pas résolus.`,
      [{ type: 'manifest', detail: `Déclaré dans ${finding.manifest || 'le manifeste'}` }]);
  }
  const reachedFromEntry = imports.filter((entry) => entryPoints.has(entry.file.toLowerCase()));
  if (reachedFromEntry.length) {
    return reachability('statically_reachable', 'medium',
      `${packageName} est importé par ${reachedFromEntry[0].file}, qui est un point d’entrée ou un gestionnaire de route. Aucun graphe d’appel complet n’est calculé : l’appel de la fonction vulnérable elle-même n’est pas prouvé.`,
      [...evidence, { type: 'entrypoint', file: reachedFromEntry[0].file, detail: 'Point d’entrée applicatif' }]);
  }
  return reachability('imported', 'medium',
    `${packageName} est importé par ${imports.length} fichier(s), mais aucun n’est un point d’entrée identifié.`,
    evidence);
}

/** Reachability of a code finding: the code is reachable if it serves a route. */
function evaluateCode(finding, { entryPoints, dynamicallyConfirmedIds }) {
  if (dynamicallyConfirmedIds.has(finding.id)) {
    return reachability('dynamically_confirmed', 'high',
      'Le code correspond à un endpoint réellement exercé par l’analyse dynamique.',
      [{ type: 'dast', detail: 'Corrélation DAST confirmée' }]);
  }
  if (!finding.file) return reachability('unknown', 'low', 'Aucun fichier source associé à ce résultat.');
  if (entryPoints.has(finding.file.toLowerCase())) {
    return reachability('statically_reachable', 'medium',
      `${finding.file} déclare une route HTTP ou est un point d’entrée : le code signalé est exposé.`,
      [{ type: 'entrypoint', file: finding.file, detail: 'Point d’entrée applicatif' }]);
  }
  return reachability('present', 'low',
    'Le code existe dans le dépôt, mais aucun chemin depuis un point d’entrée n’a été établi.');
}

/**
 * Annotates every finding with a reachability verdict.
 *
 * Findings whose stage has no meaningful reachability notion (secrets, runtime
 * alerts) are marked `not_evaluated` rather than being given a fabricated one.
 */
function evaluateReachability(findings = [], {
  importIndex = null, routeMap = null, clusters = [], workspaceFiles = []
} = {}) {
  const entryPoints = entryPointFiles(routeMap, workspaceFiles.length ? workspaceFiles : (importIndex?.files || []));
  // A finding is dynamically confirmed when a DAST↔SAST cluster links it to an
  // alert a dynamic scanner actually produced.
  const dynamicallyConfirmedIds = new Set(
    clusters.filter((cluster) => cluster.type === 'dast-sast').flatMap((cluster) => cluster.findingIds)
  );
  const context = { importIndex, entryPoints, dynamicallyConfirmedIds };
  const annotated = findings.map((finding) => {
    if (finding.stage === 'sca') return { ...finding, reachability: evaluateDependency(finding, context) };
    if (finding.stage === 'sast' || finding.stage === 'iac') return { ...finding, reachability: evaluateCode(finding, context) };
    if (finding.stage === 'dast') {
      // A DAST alert proves an endpoint was *observed at runtime*. That is a
      // different fact from « ce composant est atteignable dans le code » — a
      // hit on /favicon.ico or a stylesheet says nothing about code reachability.
      // The two are reported separately instead of being conflated.
      return {
        ...finding,
        reachability: reachability('not_evaluated', 'low',
          'Résultat dynamique : l’atteignabilité du code n’est pas évaluée pour ce type de résultat.'),
        runtime: runtimeObservation(finding)
      };
    }
    return {
      ...finding,
      reachability: reachability('not_evaluated', 'low', 'L’atteignabilité ne s’applique pas à ce type de résultat.')
    };
  });
  const counts = {};
  const statusCounts = {};
  for (const finding of annotated) {
    // Runtime-only results are not part of the code-reachability tally: they
    // would otherwise inflate « atteignables » with favicons and stylesheets.
    if (finding.runtime?.observed) continue;
    counts[finding.reachability.state] = (counts[finding.reachability.state] || 0) + 1;
    statusCounts[finding.reachability.status] = (statusCounts[finding.reachability.status] || 0) + 1;
  }
  const runtime = annotated.filter((finding) => finding.runtime?.observed);
  return {
    findings: annotated,
    summary: {
      counts,
      statusCounts,
      runtime: {
        observed: runtime.length,
        applicationEndpoints: runtime.filter((finding) => !finding.runtime.staticAsset).length,
        staticAssets: runtime.filter((finding) => finding.runtime.staticAsset).length,
        sources: [...new Set(runtime.map((finding) => finding.runtime.source))].sort()
      },
      analysed: Boolean(importIndex?.analysed),
      scannedFiles: importIndex?.scannedFiles || 0,
      entryPoints: entryPoints.size,
      routeMapAvailable: Boolean(routeMap?.supported)
    }
  };
}

module.exports = {
  STATES, STATE_RANK, STATE_LABELS, STATUSES, STATUS_LABELS, STATE_TO_STATUS, statusForState,
  evaluateReachability, evaluateDependency, evaluateCode,
  buildImportIndex, importsOfPackage, entryPointFiles, reachability,
  runtimeObservation, isStaticAsset
};
