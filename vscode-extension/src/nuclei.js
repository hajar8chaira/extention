'use strict';

/**
 * Nuclei — moteur DAST par templates.
 *
 * Nuclei ne sait rien faire seul : le binaire est un interpréteur, et tout le
 * contenu du scan vit dans le corpus `nuclei-templates`, publié séparément.
 * Une intégration qui installe seulement le binaire ne scanne rien. Ce module
 * traite donc les templates comme un artefact installable à part entière,
 * soumis au même contrat que les autres outils managés :
 *
 *   source officielle → empreinte SHA-256 officielle → extraction → provenance
 *
 * ProjectDiscovery publie, pour chaque version de templates, une release ne
 * contenant qu'un fichier `nuclei-templates-<version>_checksums.txt`. Ce fichier
 * couvre les archives source du tag correspondant, et l'archive officielle est
 * vérifiée octet pour octet contre cette empreinte : rien n'est installé sans
 * qu'elle corresponde. Aucun miroir n'intervient — la source officielle suffit.
 */

const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

// `comparablePath` vient du module bas niveau dont celui-ci dépend déjà : une
// comparaison de sécurité ne doit pas exister en deux exemplaires.
const { download, downloadText, sha256, comparablePath } = require('./scanner-tool-manager');
const { isLoopbackHost } = require('./dynamic-target');

const TEMPLATES_REPO = 'projectdiscovery/nuclei-templates';
const TEMPLATES_API = `https://api.github.com/repos/${TEMPLATES_REPO}/releases/latest`;

/**
 * Archive source officielle du tag, celle que couvre le fichier d'empreintes.
 *
 * C'est l'hôte d'archives de GitHub, adressé directement plutôt que par la
 * redirection `github.com/<repo>/archive/refs/tags/<tag>.zip`, qui y aboutit de
 * toute façon. L'artefact est le même — empreinte SHA-256 identique, vérifiée
 * plus bas contre le fichier publié par ProjectDiscovery — mais la chaîne est
 * plus courte : mesuré sur ce poste, la forme redirigée échouait deux fois sur
 * trois là où l'adressage direct aboutissait à chaque essai. Ce n'est pas un
 * miroir : ni l'origine ni le contenu ne changent.
 */
function templatesArchiveUrl(tag) {
  const clean = String(tag || '').trim();
  if (!/^v?\d+(?:\.\d+)*$/.test(clean)) throw new Error(`Version de templates Nuclei invalide : ${tag}.`);
  return `https://codeload.github.com/${TEMPLATES_REPO}/zip/refs/tags/${clean}`;
}

/** Fichier d'empreintes officiel publié à côté du tag. */
function templatesChecksumUrl(tag, version) {
  return `https://github.com/${TEMPLATES_REPO}/releases/download/${tag}/nuclei-templates-${version}_checksums.txt`;
}

/** `<version>` sans le « v » : c'est la forme utilisée dans les noms d'archives. */
function templatesVersion(tag) {
  return String(tag || '').trim().replace(/^v/i, '');
}

/**
 * Extrait l'empreinte de l'archive nommée, et d'elle seule.
 *
 * Le fichier liste `.tar.gz` et `.zip` ; un `includes()` ferait correspondre la
 * mauvaise ligne, donc le nom est comparé exactement.
 */
function parseTemplatesChecksums(text, asset) {
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.trim().match(/^([a-f0-9]{64})\s+\*?(\S+)$/i);
    if (match && match[2].replace(/^\.\//, '') === asset) return match[1].toLowerCase();
  }
  return '';
}

/** Dernière version publiée du corpus de templates. */
async function latestTemplatesRelease() {
  const release = JSON.parse(await downloadText(TEMPLATES_API));
  const tag = String(release.tag_name || '').trim();
  if (!tag) throw new Error('La publication officielle des templates Nuclei ne porte pas de version.');
  return { tag, version: templatesVersion(tag) };
}

/** Emplacement managé du corpus, dans le stockage privé de l'extension. */
function templatesRoot(storagePath) {
  return path.join(storagePath, 'scanner-tools', 'nuclei', 'templates');
}

/**
 * Le manifeste vit à côté du corpus, jamais dedans : la mise à jour efface le
 * dossier des templates en entier, et notre provenance disparaîtrait avec lui.
 */
function templatesManifestPath(storagePath) {
  return path.join(path.dirname(templatesRoot(storagePath)), 'templates.json');
}

/**
 * Dossier dont la présence atteste d'un corpus réellement déballé.
 *
 * C'est `http/` qui porte l'essentiel des templates, et c'est lui que le scan
 * utilise. Le corpus ne range aucun dossier `cves` à sa racine — seulement un
 * fichier `cves.json` — donc le chercher là déclarait absent un corpus bel et
 * bien installé, et provoquait un retéléchargement complet à chaque scan.
 */
const TEMPLATES_SENTINEL = 'http';

/** Manifeste des templates réellement installés, `null` si aucun. */
async function installedTemplates(storagePath) {
  try {
    const manifest = JSON.parse(await fs.readFile(templatesManifestPath(storagePath), 'utf8'));
    const directory = String(manifest.directory || '');
    if (!directory || !manifest.version) return null;
    const sentinel = await fs.stat(path.join(directory, TEMPLATES_SENTINEL));
    if (!sentinel.isDirectory()) return null;
    return manifest;
  } catch {
    return null;
  }
}

/** Nombre total de tentatives pour récupérer l'archive des templates. */
const TEMPLATES_DOWNLOAD_ATTEMPTS = 3;

/**
 * Télécharge l'archive, avec quelques reprises sur coupure de transport.
 *
 * Une annulation n'est jamais reprise — l'utilisateur a demandé l'arrêt — et un
 * refus du serveur non plus, puisque réessayer donnerait le même refus. Seule
 * une connexion coupée en route est retentée, parce que c'est le seul échec
 * qu'un second essai corrige réellement. Le téléchargeur partagé n'est pas
 * modifié : la reprise appartient à ce module et à lui seul.
 */
async function downloadWithRetry(url, destination, onProgress, { signal, attempts = TEMPLATES_DOWNLOAD_ATTEMPTS } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await download(url, destination, onProgress, { signal });
    } catch (error) {
      if (error?.cancelled || signal?.aborted) throw error;
      const retryable = error?.code === 'INTERRUPTED' || error?.code === 'TIMEOUT' || error?.code === 'STALLED';
      if (!retryable || attempt === attempts) throw error;
      lastError = error;
      onProgress({ phase: 'metadata', message: `Téléchargement interrompu, nouvelle tentative (${attempt + 1}/${attempts})…` });
    }
  }
  throw lastError;
}

/**
 * Garantit qu'un corpus de templates vérifié est disponible localement.
 *
 * Rien n'est téléchargé si la version installée est déjà la dernière publiée.
 * Aucune archive n'est acceptée sans correspondance exacte avec l'empreinte
 * officielle : une archive non vérifiable est supprimée, jamais installée.
 */
async function ensureTemplates(storagePath, { onProgress = () => {}, signal, force = false } = {}) {
  const current = await installedTemplates(storagePath);
  const { tag, version } = await latestTemplatesRelease();
  if (!force && current?.version === version) {
    onProgress({ phase: 'ready', message: `Templates Nuclei ${version} déjà installés` });
    return { ...current, updated: false };
  }

  const asset = `nuclei-templates-${version}.zip`;
  const archiveUrl = templatesArchiveUrl(tag);
  onProgress({ phase: 'metadata', message: `Templates ${version} depuis ${TEMPLATES_REPO}` });

  // La zone de préparation vit à côté de sa destination, jamais dans le dossier
  // temporaire du système. Les deux sont alors sur le même volume, et poser le
  // corpus se réduit à un `rename`. Quand ils étaient sur des disques différents
  // — stockage de l'extension sur D:, temporaire sur C: — le `rename` échouait
  // et le repli recopiait les quatorze mille fichiers un par un, ce qui prenait
  // plusieurs dizaines de minutes.
  const destination = templatesRoot(storagePath);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  const temporary = await fs.mkdtemp(path.join(path.dirname(destination), '.templates-'));
  const archive = path.join(temporary, asset);
  try {
    await downloadWithRetry(archiveUrl, archive, onProgress, { signal });
    const expected = parseTemplatesChecksums(await downloadText(templatesChecksumUrl(tag, version)), asset);
    if (!expected) {
      throw new Error(`ProjectDiscovery ne publie pas d’empreinte SHA-256 pour ${asset}. Installation des templates refusée par sécurité.`);
    }
    const actual = await sha256(archive);
    if (actual !== expected) {
      await fs.rm(archive, { force: true }).catch(() => {});
      throw new Error('Échec de vérification SHA-256 de l’archive des templates Nuclei. L’archive a été supprimée.');
    }
    onProgress({ phase: 'verify', message: 'Empreinte SHA-256 officielle vérifiée' });

    const extracted = path.join(temporary, 'extract');
    await fs.mkdir(extracted, { recursive: true });
    await extractZip(archive, extracted);
    await assertNoPathEscape(extracted);

    // GitHub encapsule l'archive source dans un dossier `<repo>-<version>`.
    const entries = await fs.readdir(extracted, { withFileTypes: true });
    const root = entries.find((entry) => entry.isDirectory() && /^nuclei-templates/i.test(entry.name));
    if (!root) throw new Error('L’archive des templates Nuclei ne contient pas le dossier attendu.');

    const staged = path.join(extracted, root.name);
    // Le corpus en place n'est retiré qu'une fois le remplaçant vérifié et
    // extrait : un échec réseau ne laisse jamais Nuclei sans templates.
    await fs.rm(destination, { recursive: true, force: true });
    await fs.rename(staged, destination).catch(async () => {
      await fs.cp(staged, destination, { recursive: true });
    });

    const manifest = {
      source: archiveUrl,
      checksums: templatesChecksumUrl(tag, version),
      tag,
      version,
      asset,
      sha256: actual,
      directory: destination,
      templates: await countTemplates(destination),
      installedAt: new Date().toISOString()
    };
    await fs.writeFile(templatesManifestPath(storagePath), JSON.stringify(manifest, null, 2), 'utf8');
    onProgress({ phase: 'ready', message: `Templates Nuclei ${version} installés (${manifest.templates} templates)` });
    return { ...manifest, updated: true };
  } finally {
    await fs.rm(temporary, { recursive: true, force: true }).catch(() => {});
  }
}

async function countTemplates(directory) {
  let total = 0;
  const walk = async (current) => {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(candidate);
      else if (/\.ya?ml$/i.test(entry.name)) total += 1;
    }
  };
  await walk(directory);
  return total;
}

/**
 * Extracteurs essayés dans l'ordre, du plus rapide au plus disponible.
 *
 * Le corpus fait près de quatorze mille fichiers, et c'est ce nombre qui décide,
 * pas la taille. Mesuré sur cette archive : `tar.exe`, livré avec Windows depuis
 * la version 1803, la déballe en 7 secondes ; `Expand-Archive` tournait encore
 * après vingt-cinq minutes. PowerShell reste en second pour les postes qui n'ont
 * pas `tar`, mais il n'est plus le chemin normal.
 */
function extractionCommands(archive, destination) {
  if (process.platform === 'win32') {
    const quoted = (value) => `'${value.replaceAll("'", "''")}'`;
    // Chemin absolu, jamais `tar.exe` par le PATH : sur un poste où Git pour
    // Windows est installé, ce nom résout d'abord le GNU tar de Git, qui ne sait
    // pas lire une archive ZIP. Il échoue, et l'on retombe silencieusement sur le
    // repli lent. Celui de System32 est bsdtar, et lui sait le faire.
    const bsdtar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
    return [
      { command: bsdtar, args: ['-xf', archive, '-C', destination] },
      {
        command: 'powershell.exe',
        // `Expand-Archive` signale une archive illisible par une erreur non
        // bloquante et sort malgré tout en code 0 : sans `-ErrorAction Stop`,
        // une archive corrompue passait pour une extraction réussie.
        args: ['-NoProfile', '-NonInteractive', '-Command',
          `Expand-Archive -LiteralPath ${quoted(archive)} -DestinationPath ${quoted(destination)} -Force -ErrorAction Stop`]
      }
    ];
  }
  return [
    { command: 'unzip', args: ['-q', '-o', archive, '-d', destination] },
    { command: 'tar', args: ['-xf', archive, '-C', destination] }
  ];
}

function runExtraction({ command, args }) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { windowsHide: true });
    let stderr = '';
    child.stderr?.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    // Un outil absent n'est pas une archive invalide : il faut pouvoir passer au
    // suivant sans accuser le fichier téléchargé.
    child.on('error', () => resolve({ available: false }));
    child.on('close', (code) => resolve({ available: true, code, stderr }));
  });
}

async function extractZip(archive, destination) {
  let lastError = '';
  for (const candidate of extractionCommands(archive, destination)) {
    const outcome = await runExtraction(candidate);
    if (!outcome.available) continue;
    // Un code de sortie nul ne suffit pas : la seule preuve qu'une extraction a
    // eu lieu, c'est un dossier qui n'est plus vide.
    const produced = await fs.readdir(destination).catch(() => []);
    if (outcome.code === 0 && produced.length > 0) return;
    lastError = outcome.stderr.trim().split(/\r?\n/)[0] || lastError;
  }
  throw new Error(`Archive des templates Nuclei illisible${lastError ? ` : ${lastError}` : '.'}`);
}

/**
 * Zip Slip : rien ne doit se résoudre hors du dossier d'extraction.
 *
 * Les deux côtés de la comparaison sont canonisés de la même façon. Ils ne
 * l'étaient pas : la racine venait de `path.resolve()`, qui conserve la lettre
 * de lecteur telle qu'elle a été fournie, tandis que chaque entrée passait par
 * `fs.realpath()`, qui rend la forme canonique du système. VS Code expose son
 * stockage via `Uri.fsPath`, avec une lettre de lecteur minuscule : la racine
 * valait alors `c:\…` et les entrées `C:\…`, si bien qu'aucune entrée ne
 * « commençait » par la racine et que la toute première — le dossier racine de
 * l'archive officielle — était refusée. La règle, elle, ne change pas : toute
 * entrée qui se résout hors de la racine est toujours rejetée.
 */
async function assertNoPathEscape(root) {
  // `realpath` sur la racine aussi : un lien ou une jonction dans le chemin
  // parent la déplacerait autrement hors de sa propre sous-arborescence.
  const baseReal = await fs.realpath(root).catch(() => path.resolve(root));
  const base = comparablePath(baseReal);
  const prefix = `${base}${path.sep}`;
  const walk = async (directory) => {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      // `realpath` suit liens symboliques et jonctions : une entrée qui pointe
      // hors de la racine est vue ici, quel que soit son nom dans l'archive.
      const resolved = comparablePath(await fs.realpath(candidate).catch(() => path.resolve(candidate)));
      if (resolved !== base && !resolved.startsWith(prefix)) {
        throw new Error('Archive refusée : elle tente d’écrire en dehors du dossier d’installation.');
      }
      if (entry.isDirectory()) await walk(candidate);
    }
  };
  await walk(baseReal);
}

// --------------------------------------------------------------------- scan

const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

/**
 * Débit par défaut.
 *
 * Les valeurs d'usine de Nuclei — 150 requêtes concurrentes, aucun plafond de
 * débit — visent une infrastructure, pas une application de test
 * mono-processus. Mesuré sur OWASP Juice Shop, ce réglage d'usine a saturé la
 * cible : Nuclei l'a déclarée « unresponsive », l'a retirée du scan après 30
 * erreurs, à 39 % du parcours, et a annoncé zéro correspondance. Un scan par
 * défaut doit rester exploitable sur l'application réellement testée.
 */
const DEFAULT_RATE_LIMIT = 25;
const DEFAULT_CONCURRENCY = 10;
const DEFAULT_MAX_HOST_ERRORS = 250;

/** Nuclei a-t-il retiré la cible en route, à un moment quelconque du scan ? */
function hostWasDropped(stderr) {
  return /Skipped\s+\S+\s+from target list as found unresponsive/i.test(String(stderr || ''));
}

/**
 * Part du parcours réellement exécutée, entre 0 et 1.
 *
 * Rend 1 quand Nuclei n'a publié aucune statistique exploitable : sans mesure,
 * un scan n'est pas déclaré tronqué sur une supposition.
 */
function scanCoverage(stats) {
  if (!stats || !(stats.total > 0)) return 1;
  return Math.min(1, Math.max(0, stats.requests / stats.total));
}

/**
 * Sous ce seuil, un rapport « zéro correspondance » ne veut plus rien dire :
 * l'essentiel des templates n'a jamais été envoyé.
 */
const MIN_USABLE_COVERAGE = 0.9;

function isTruncatedScan(coverage, stderr) {
  return hostWasDropped(stderr) && coverage < MIN_USABLE_COVERAGE;
}

/**
 * Valide la cible Nuclei. Même contrat que ZAP : le distant n'est atteint que
 * si l'utilisateur a choisi le mode distant et confirmé son autorisation.
 */
function validateNucleiTarget(targetUrl, { allowRemote = false } = {}) {
  let target;
  try {
    target = new URL(targetUrl);
  } catch {
    throw new Error('URL Nuclei invalide.');
  }
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Nuclei accepte uniquement une URL HTTP ou HTTPS.');
  if (!allowRemote && !isLoopbackHost(target.hostname)) {
    throw new Error('Nuclei n’est autorisé que sur une cible locale tant que le mode distant n’est pas confirmé.');
  }
  return target;
}

/**
 * Ligne de commande du scan.
 *
 * `-duc` est indispensable : sans lui Nuclei met à jour les templates tout seul,
 * dans son propre dossier utilisateur, et le corpus vérifié installé ici ne
 * serait plus celui qui s'exécute.
 */
function nucleiArgs({ targetUrl, templatesPath, reportPath, severities = [], excludeSeverities = [], headers = [], timeoutSeconds = 10, rateLimit = DEFAULT_RATE_LIMIT, concurrency = DEFAULT_CONCURRENCY, maxHostErrors = DEFAULT_MAX_HOST_ERRORS }) {
  const args = [
    '-target', targetUrl,
    '-templates', templatesPath,
    '-jsonl',
    '-jsonl-export', reportPath,
    '-disable-update-check',
    '-no-color',
    '-omit-raw',
    '-omit-template',
    '-stats',
    '-stats-json',
    '-stats-interval', '5',
    '-timeout', String(Math.max(1, Math.round(timeoutSeconds)))
  ];
  const keep = severities.filter((value) => SEVERITIES.includes(String(value).toLowerCase()));
  if (keep.length) args.push('-severity', keep.join(','));
  const drop = excludeSeverities.filter((value) => SEVERITIES.includes(String(value).toLowerCase()));
  if (drop.length) args.push('-exclude-severity', drop.join(','));
  if (rateLimit > 0) args.push('-rate-limit', String(Math.round(rateLimit)));
  if (concurrency > 0) args.push('-concurrency', String(Math.round(concurrency)));
  if (maxHostErrors > 0) args.push('-max-host-error', String(Math.round(maxHostErrors)));
  for (const header of headers) {
    if (/\r|\n/.test(header)) throw new Error('En-tête Nuclei invalide.');
    args.push('-header', header);
  }
  return args;
}

/** Une ligne de statistiques `-stats-json`, ou null. */
function parseStatsLine(line) {
  try {
    const payload = JSON.parse(line);
    if (typeof payload?.percent === 'undefined' || typeof payload?.requests === 'undefined') return null;
    return {
      percent: Number(payload.percent) || 0,
      requests: Number(payload.requests) || 0,
      total: Number(payload.total) || 0,
      matched: Number(payload.matched) || 0,
      errors: Number(payload.errors) || 0,
      duration: String(payload.duration || '')
    };
  } catch {
    return null;
  }
}

/** JSONL → tableau. Une ligne illisible est ignorée, jamais fatale. */
function parseNucleiJsonl(text) {
  const results = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const payload = JSON.parse(trimmed);
      if (payload && (payload['template-id'] || payload.templateID)) results.push(payload);
    } catch {
      // Ligne tronquée : le reste du rapport reste exploitable.
    }
  }
  return results;
}

/**
 * Exécute un scan Nuclei réel et rend les résultats JSONL analysés.
 *
 * Nuclei sort en code non nul lorsqu'aucun template ne correspond ; un scan
 * sans résultat est un scan réussi, pas un échec. Seule une sortie sans rapport
 * lisible accompagnée d'une erreur explicite est traitée comme un échec.
 */
function runNuclei({
  targetUrl,
  executable,
  templatesPath,
  allowRemote = false,
  severities = [],
  excludeSeverities = [],
  headers = [],
  timeoutSeconds = 10,
  rateLimit = DEFAULT_RATE_LIMIT,
  concurrency = DEFAULT_CONCURRENCY,
  maxHostErrors = DEFAULT_MAX_HOST_ERRORS,
  timeoutMs = 1800000,
  signal,
  onLifecycle = () => {},
  // Appelé une fois, quand le processus Nuclei a réellement démarré. L'appelant
  // y apprend que le scan tourne, et reçoit le processus pour pouvoir l'arrêter
  // si VS Code se ferme en plein scan.
  onStart = () => {}
} = {}) {
  validateNucleiTarget(targetUrl, { allowRemote });
  if (!executable) throw new Error('Nuclei n’est pas installé.');
  if (!templatesPath) throw new Error('Les templates Nuclei ne sont pas installés.');

  return (async () => {
    const reportDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-'));
    const reportPath = path.join(reportDirectory, 'nuclei-report.jsonl');
    try {
      const args = nucleiArgs({ targetUrl, templatesPath, reportPath, severities, excludeSeverities, headers, timeoutSeconds, rateLimit, concurrency, maxHostErrors });
      const outcome = await spawnNuclei(executable, args, { timeoutMs, signal, onLifecycle, onStart });
      const report = await fs.readFile(reportPath, 'utf8').catch(() => '');
      const payload = parseNucleiJsonl(report);
      if (!report && outcome.failed) {
        throw new Error(outcome.reason || 'Échec du scan Nuclei.');
      }
      // Nuclei retire une cible qui cesse de répondre, puis termine malgré tout
      // en annonçant « scan completed ». Le message seul ne dit rien : mesuré
      // ici, il apparaît aussi bien sur un scan tronqué à 39 % que sur un scan
      // qui en couvre 98 % et rend 19 correspondances. Ce qui tranche, c'est la
      // part du parcours réellement exécutée.
      const coverage = scanCoverage(outcome.stats);
      if (isTruncatedScan(coverage, outcome.stderr)) {
        throw new Error(
          `La cible ${targetUrl} a cessé de répondre pendant le scan : Nuclei l’a retirée du parcours, `
          + `qui s’est arrêté à ${Math.round(coverage * 100)} % des requêtes prévues. Le rapport est incomplet et n’est pas exploité. `
          + 'Réduisez le débit (securityCenter.nuclei.rateLimit) ou vérifiez la stabilité de l’application avant de relancer.'
        );
      }
      return {
        payload,
        stderr: outcome.stderr,
        templatesPath,
        engine: 'nuclei',
        coverage,
        stats: outcome.stats,
        hostDropped: hostWasDropped(outcome.stderr)
      };
    } finally {
      await fs.rm(reportDirectory, { recursive: true, force: true }).catch(() => {});
    }
  })();
}

function spawnNuclei(executable, args, { timeoutMs, signal, onLifecycle, onStart = () => {} }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('Scan Nuclei annulé.'));
    const child = spawn(executable, args, { windowsHide: true });
    // `spawn` confirme que le processus existe : c'est le vrai début du scan,
    // pas la préparation qui le précède.
    child.once('spawn', () => {
      try { onStart(child); } catch { /* un écouteur ne fait jamais échouer le scan */ }
    });
    let stderr = '';
    let pending = '';
    let settled = false;
    // Dernier avancement publié par le moteur : c'est la seule mesure de ce qui
    // a réellement été exécuté, et elle sert à juger si le rapport est complet.
    let stats = null;
    const finish = (value) => { if (settled) return; settled = true; cleanup(); resolve(value); };
    const fail = (error) => { if (settled) return; settled = true; cleanup(); reject(error); };

    const timer = setTimeout(() => {
      child.kill();
      fail(new Error(`Le scan Nuclei a dépassé ${Math.round(timeoutMs / 1000)} secondes.`));
    }, timeoutMs);
    const onAbort = () => { child.kill(); fail(new Error('Scan Nuclei annulé.')); };
    signal?.addEventListener?.('abort', onAbort, { once: true });
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener?.('abort', onAbort); };

    // Nuclei écrit sa progression sur stderr. Chaque ligne `-stats-json` est un
    // avancement réel du moteur, pas une estimation de notre côté.
    const consume = (chunk) => {
      stderr += chunk;
      pending += chunk;
      const lines = pending.split(/\r?\n/);
      pending = lines.pop() || '';
      for (const line of lines) {
        const snapshot = parseStatsLine(line.trim());
        if (!snapshot) continue;
        stats = snapshot;
        // Un écouteur ne doit jamais faire échouer un scan, même s'il lève.
        try { onLifecycle({ engine: 'nuclei', ...snapshot }); } catch { /* rapport d'avancement, pas le scan */ }
      }
    };
    child.stderr?.on('data', (chunk) => consume(chunk.toString('utf8')));
    child.stdout?.on('data', (chunk) => consume(chunk.toString('utf8')));
    child.on('error', (error) => fail(new Error(`Nuclei n’a pas pu démarrer : ${error.message}`)));
    child.on('close', (code) => {
      // Un scan sans correspondance rend un code non nul : ce n'est pas une
      // erreur, et le rapport lu par l'appelant tranche.
      finish({ failed: code !== 0, reason: firstErrorLine(stderr), stderr, stats });
    });
  });
}

function firstErrorLine(stderr) {
  const line = String(stderr || '').split(/\r?\n/).map((value) => value.trim())
    .find((value) => /\[(FTL|ERR)\]/.test(value));
  return line ? line.replace(/^\[[A-Z]+\]\s*/, '') : '';
}

/**
 * Budget de temps d'un scan Nuclei lancé depuis Security Center.
 *
 * Mesuré sur OWASP Juice Shop avec les réglages par défaut (25 req/s, 10 en
 * parallèle) : environ 3 minutes de chargement des 13 641 templates, puis
 * 19 988 requêtes, soit 1 041 à 1 056 secondes pour un scan complet. Le délai
 * global des scanners (`scan.timeoutSeconds`, 300 s par défaut) tuait donc
 * chaque scan lancé depuis la carte avant qu'il ait couvert le quart du parcours.
 */
const SCAN_TIMEOUT_MS = 45 * 60 * 1000;

module.exports = {
  TEMPLATES_REPO,
  TEMPLATES_API,
  SEVERITIES,
  DEFAULT_RATE_LIMIT,
  DEFAULT_CONCURRENCY,
  DEFAULT_MAX_HOST_ERRORS,
  SCAN_TIMEOUT_MS,
  MIN_USABLE_COVERAGE,
  hostWasDropped,
  scanCoverage,
  isTruncatedScan,
  templatesArchiveUrl,
  templatesChecksumUrl,
  templatesVersion,
  parseTemplatesChecksums,
  latestTemplatesRelease,
  templatesRoot,
  templatesManifestPath,
  TEMPLATES_SENTINEL,
  installedTemplates,
  downloadWithRetry,
  TEMPLATES_DOWNLOAD_ATTEMPTS,
  ensureTemplates,
  assertNoPathEscape,
  comparablePath,
  extractionCommands,
  extractZip,
  countTemplates,
  validateNucleiTarget,
  nucleiArgs,
  parseStatsLine,
  parseNucleiJsonl,
  runNuclei
};
