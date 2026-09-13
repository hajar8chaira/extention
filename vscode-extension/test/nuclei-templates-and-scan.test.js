'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  TEMPLATES_REPO,
  DEFAULT_RATE_LIMIT, DEFAULT_CONCURRENCY, DEFAULT_MAX_HOST_ERRORS, MIN_USABLE_COVERAGE,
  templatesArchiveUrl, templatesChecksumUrl, templatesVersion, parseTemplatesChecksums,
  templatesRoot, templatesManifestPath, TEMPLATES_SENTINEL, installedTemplates,
  extractionCommands, extractZip, countTemplates, assertNoPathEscape, comparablePath,
  validateNucleiTarget, nucleiArgs, parseStatsLine, parseNucleiJsonl,
  hostWasDropped, scanCoverage, isTruncatedScan
} = require('../src/nuclei');
const { normalizeNucleiOutput, nucleiSeverity, nucleiClassification } = require('../src/findings');
const { TOOLS, commandVersion } = require('../src/scanner-tool-manager');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

// Empreintes réellement publiées par ProjectDiscovery pour les templates 10.4.8.
const REAL_CHECKSUMS = [
  '53ae80d9bcfff638fbff62c4b730c436564b6bf5e05cf4f86a7eefe37c7ecc47  nuclei-templates-10.4.8.tar.gz',
  'cb4f88504ebf9d462c2db4c8d2bdf6cb94ecc7b7f4ed09b7f4fd20ceb6bc8002  nuclei-templates-10.4.8.zip'
].join('\n');

// Événements JSONL réellement produits par Nuclei v3.11.1 contre
// http://192.168.222.132:3000 (OWASP Juice Shop).
const REAL_JSONL = [
  JSON.stringify({
    'template-url': 'https://cloud.projectdiscovery.io/public/prometheus-metrics',
    'template-id': 'prometheus-metrics',
    info: {
      name: 'Prometheus Metrics - Detect',
      severity: 'medium',
      description: 'Prometheus metrics page was detected.\n',
      reference: ['https://prometheus.io/'],
      classification: { 'cve-id': null, 'cwe-id': ['cwe-200'] }
    },
    type: 'http',
    host: '192.168.222.132',
    port: '3000',
    'matched-at': 'http://192.168.222.132:3000/metrics',
    'matcher-status': true
  }),
  JSON.stringify({
    'template-id': 'http-missing-security-headers',
    info: { name: 'HTTP Missing Security Headers', severity: 'info', classification: { 'cve-id': null, 'cwe-id': ['cwe-693'] } },
    type: 'http',
    'matched-at': 'http://192.168.222.132:3000',
    'matcher-name': 'content-security-policy',
    'matcher-status': true
  }),
  JSON.stringify({
    'template-id': 'http-missing-security-headers',
    info: { name: 'HTTP Missing Security Headers', severity: 'info', classification: { 'cve-id': null, 'cwe-id': ['cwe-693'] } },
    type: 'http',
    'matched-at': 'http://192.168.222.132:3000',
    'matcher-name': 'strict-transport-security',
    'matcher-status': true
  }),
  JSON.stringify({
    'template-id': 'robots-txt-endpoint',
    info: { name: 'robots.txt endpoint prober', severity: 'info' },
    type: 'http',
    'matched-at': 'http://192.168.222.132:3000/robots.txt',
    'extractor-name': 'endpoints',
    'extracted-results': ['/ftp'],
    'matcher-status': true
  })
].join('\n');

// ------------------------------------------- source officielle des templates

test('Nuclei : les templates viennent de la source officielle, jamais d’un miroir', () => {
  assert.equal(TEMPLATES_REPO, 'projectdiscovery/nuclei-templates');
  const archive = templatesArchiveUrl('v10.4.8');
  // L'hôte d'archives de GitHub, adressé directement : même artefact que la
  // redirection `github.com/<repo>/archive/refs/tags/...`, chaîne plus courte.
  assert.equal(archive, 'https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/tags/v10.4.8');
  assert.equal(new URL(archive).protocol, 'https:');
  assert.equal(
    templatesChecksumUrl('v10.4.8', '10.4.8'),
    'https://github.com/projectdiscovery/nuclei-templates/releases/download/v10.4.8/nuclei-templates-10.4.8_checksums.txt'
  );
  // Aucun réglage de miroir n'existe : la source officielle fonctionne, et un
  // paramètre inutilisé serait une configuration morte.
  const source = src('nuclei.js');
  assert.ok(!/templatesMirror|mirrorUrl/i.test(source), 'aucun miroir configurable');
});

test('Nuclei : une version de templates fantaisiste ne construit aucune URL', () => {
  for (const bogus of ['', '../../etc', 'main', 'v10.4.8/../..', 'https://ailleurs.example/x.zip']) {
    assert.throws(() => templatesArchiveUrl(bogus), /invalide/, `accepté à tort : ${bogus}`);
  }
  assert.equal(templatesVersion('v10.4.8'), '10.4.8');
  assert.equal(templatesVersion('10.4.8'), '10.4.8');
});

test('Nuclei : l’empreinte retenue est celle du fichier .zip, jamais du .tar.gz', () => {
  assert.equal(
    parseTemplatesChecksums(REAL_CHECKSUMS, 'nuclei-templates-10.4.8.zip'),
    'cb4f88504ebf9d462c2db4c8d2bdf6cb94ecc7b7f4ed09b7f4fd20ceb6bc8002'
  );
  assert.equal(
    parseTemplatesChecksums(REAL_CHECKSUMS, 'nuclei-templates-10.4.8.tar.gz'),
    '53ae80d9bcfff638fbff62c4b730c436564b6bf5e05cf4f86a7eefe37c7ecc47'
  );
  // Un nom absent ne rend rien : aucune empreinte approximative n'est acceptée.
  assert.equal(parseTemplatesChecksums(REAL_CHECKSUMS, 'nuclei-templates-10.4.9.zip'), '');
  assert.equal(parseTemplatesChecksums('', 'nuclei-templates-10.4.8.zip'), '');
});

test('Nuclei : une archive sans empreinte vérifiable n’est jamais installée', () => {
  const source = src('nuclei.js');
  const ensure = source.match(/async function ensureTemplates\([\s\S]*?\n\}/)[0];
  assert.match(ensure, /if \(!expected\) \{/);
  assert.match(ensure, /Installation des templates refusée par sécurité/);
  assert.match(ensure, /if \(actual !== expected\)/);
  assert.match(ensure, /fs\.rm\(archive, \{ force: true \}\)/, 'l’archive refusée est supprimée');
  // La vérification précède toujours l'extraction.
  assert.ok(ensure.indexOf('sha256(archive)') < ensure.indexOf('extractZip('), 'vérification avant extraction');
  assert.ok(ensure.includes('assertNoPathEscape(extracted)'), 'garde Zip Slip conservée');
});

test('Nuclei : le corpus vit dans le stockage de l’extension, jamais dans le dossier utilisateur', async () => {
  const storage = path.join(os.tmpdir(), 'security-center-nuclei-test-storage');
  const root = templatesRoot(storage);
  assert.equal(root, path.join(storage, 'scanner-tools', 'nuclei', 'templates'));
  // Le manifeste est à côté du corpus : une mise à jour efface le dossier des
  // templates en entier, et la provenance partirait avec lui.
  assert.equal(templatesManifestPath(storage), path.join(storage, 'scanner-tools', 'nuclei', 'templates.json'));
  assert.ok(!templatesManifestPath(storage).startsWith(`${root}${path.sep}`), 'jamais dans l’arbre des templates');
  // Le dossier personnel de Nuclei (~/nuclei-templates) n'est jamais touché.
  assert.ok(!root.includes(path.join(os.homedir(), 'nuclei-templates')));
  // Sans installation, rien n'est inventé.
  assert.equal(await installedTemplates(path.join(os.tmpdir(), 'security-center-nuclei-absent')), null);
});

test('Nuclei : un manifeste sans corpus réel n’est pas pris pour une installation', async (t) => {
  const storage = await fsp.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-manifest-'));
  t.after(() => fsp.rm(storage, { recursive: true, force: true }));
  await fsp.mkdir(templatesRoot(storage), { recursive: true });
  await fsp.writeFile(templatesManifestPath(storage), JSON.stringify({ version: '10.4.8', directory: templatesRoot(storage) }), 'utf8');
  // Le manifeste existe mais le corpus est absent : ce n'est pas une installation.
  assert.equal(await installedTemplates(storage), null);

  // Le repère doit être un dossier. Un fichier du même nom ne prouve rien — et
  // c'est exactement ce qui se passait avec `cves` : le corpus livre un fichier
  // `cves.json` et aucun dossier `cves`, si bien qu'une installation valide
  // était déclarée absente et retéléchargée à chaque scan.
  await fsp.writeFile(path.join(templatesRoot(storage), TEMPLATES_SENTINEL), 'pas un dossier');
  assert.equal(await installedTemplates(storage), null);
  await fsp.rm(path.join(templatesRoot(storage), TEMPLATES_SENTINEL));

  await fsp.mkdir(path.join(templatesRoot(storage), TEMPLATES_SENTINEL), { recursive: true });
  const manifest = await installedTemplates(storage);
  assert.equal(manifest?.version, '10.4.8');

  // Un manifeste sans version n'est pas exploitable non plus.
  await fsp.writeFile(templatesManifestPath(storage), JSON.stringify({ directory: templatesRoot(storage) }), 'utf8');
  assert.equal(await installedTemplates(storage), null);
});

test('Nuclei : le repère d’installation existe vraiment dans le corpus publié', () => {
  // `http/` porte l'essentiel des templates et c'est lui que le scan parcourt.
  assert.equal(TEMPLATES_SENTINEL, 'http');
  const source = src('nuclei.js');
  assert.ok(!/fs\.access\(path\.join\(directory, 'cves'\)\)/.test(source), 'le repère erroné a disparu');
});

// ------------------------------------------------------------- extraction

test('Nuclei : l’extraction privilégie tar, mesuré 7 s là où Expand-Archive dépassait 25 min', () => {
  const commands = extractionCommands('C:/tmp/a.zip', 'C:/tmp/out');
  assert.ok(commands.length >= 2, 'un repli existe');
  if (process.platform === 'win32') {
    // Chemin absolu vers bsdtar : par le PATH, `tar.exe` résout d'abord le GNU
    // tar de Git pour Windows, incapable de lire un ZIP — mesuré sur ce poste.
    assert.equal(commands[0].command, path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe'));
    assert.ok(path.isAbsolute(commands[0].command), 'jamais résolu par le PATH');
    assert.deepEqual(commands[0].args, ['-xf', 'C:/tmp/a.zip', '-C', 'C:/tmp/out']);
    assert.equal(commands[1].command, 'powershell.exe', 'PowerShell reste disponible en repli');
  } else {
    assert.equal(commands[0].command, 'unzip');
  }
  // Le guillemetage PowerShell reste correct pour un chemin contenant une apostrophe.
  const tricky = extractionCommands("C:/tmp/l'archive.zip", 'C:/tmp/out');
  const powershell = tricky.find((entry) => entry.command === 'powershell.exe');
  if (powershell) assert.match(powershell.args.join(' '), /l''archive\.zip/);
});

test('Nuclei : une archive illisible est nommée comme telle, jamais confondue avec un outil absent', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-extract-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const archive = path.join(directory, 'corrompu.zip');
  await fsp.writeFile(archive, 'ceci n’est pas une archive');
  const destination = path.join(directory, 'out');
  await fsp.mkdir(destination, { recursive: true });
  await assert.rejects(() => extractZip(archive, destination), /Archive des templates Nuclei illisible/);
});

test('Nuclei : la structure réelle de l’archive officielle est acceptée', async (t) => {
  const storage = await fsp.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-layout-'));
  t.after(() => fsp.rm(storage, { recursive: true, force: true }));
  // Exactement la forme des premières entrées de l'archive officielle :
  //   nuclei-templates-10.4.8/
  //   nuclei-templates-10.4.8/.github/
  //   nuclei-templates-10.4.8/.github/ISSUE_TEMPLATE/
  const root = path.join(storage, 'nuclei-templates-10.4.8');
  await fsp.mkdir(path.join(root, '.github', 'ISSUE_TEMPLATE'), { recursive: true });
  await fsp.mkdir(path.join(root, 'http', 'cves', '2024'), { recursive: true });
  await fsp.writeFile(path.join(root, 'http', 'cves', '2024', 'CVE-2024-0001.yaml'), 'id: CVE-2024-0001');
  await fsp.writeFile(path.join(root, 'cves.json'), '[]');
  await fsp.writeFile(path.join(root, 'README.md'), 'doc');
  await assertNoPathEscape(storage);

  // Le défaut réel : VS Code expose son stockage via `Uri.fsPath`, dont la lettre
  // de lecteur est minuscule. La racine venait de `path.resolve()` — donc `c:\…`
  // — et chaque entrée de `fs.realpath()` — donc `C:\…`. Aucune entrée ne
  // « commençait » par la racine et la première, le dossier racine de l'archive,
  // était refusée. Le corpus officiel ne contient pourtant aucune traversée.
  if (process.platform === 'win32') {
    const lowered = storage.charAt(0).toLowerCase() + storage.slice(1);
    assert.notEqual(lowered, storage, 'le cas de test exige une racine en majuscule');
    await assertNoPathEscape(lowered);
    const uppered = storage.charAt(0).toUpperCase() + storage.slice(1);
    await assertNoPathEscape(uppered);
  }
});

test('Nuclei : une archive qui sort du dossier reste refusée', async (t) => {
  const parent = await fsp.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-escape-'));
  t.after(() => fsp.rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, 'extract');
  const outside = path.join(parent, 'dehors');
  await fsp.mkdir(path.join(root, 'nuclei-templates-10.4.8'), { recursive: true });
  await fsp.mkdir(outside, { recursive: true });
  await fsp.writeFile(path.join(outside, 'vole.yaml'), 'id: vole');

  // Un lien qui pointe hors de la racine : c'est la forme qu'une archive
  // hostile prend une fois déballée, et `realpath` la démasque.
  let linked = false;
  try {
    await fsp.symlink(outside, path.join(root, 'nuclei-templates-10.4.8', 'evasion'), 'junction');
    linked = true;
  } catch { /* la création de jonction peut être refusée sans privilège */ }
  if (linked) {
    await assert.rejects(() => assertNoPathEscape(root), /en dehors du dossier d’installation/);
    // Et la casse de la racine ne doit pas offrir d'échappatoire non plus.
    if (process.platform === 'win32') {
      const lowered = root.charAt(0).toLowerCase() + root.slice(1);
      await assert.rejects(() => assertNoPathEscape(lowered), /en dehors du dossier d’installation/);
    }
    await fsp.rm(path.join(root, 'nuclei-templates-10.4.8', 'evasion'), { recursive: true, force: true });
  }
  // Sans le lien, la même arborescence est acceptée : c'est bien l'évasion qui
  // est refusée, pas la structure.
  await assertNoPathEscape(root);
});

test('Nuclei : la comparaison de chemins suit la sensibilité à la casse du système', () => {
  const same = comparablePath('C:/Stockage/Extract') === comparablePath('c:/stockage/extract');
  // NTFS ne distingue pas la casse : les comparer octet à octet refusait tout.
  // Un système sensible à la casse, lui, distingue deux dossiers différents, et
  // abaisser la casse y ouvrirait une évasion.
  assert.equal(same, process.platform === 'win32');
  // L'implémentation est unique et vit dans le module bas niveau : deux copies
  // d'une comparaison de sécurité finiraient par diverger.
  assert.equal(comparablePath, require('../src/scanner-tool-manager').comparablePath);
  assert.match(src('scanner-tool-manager.js'), /process\.platform === 'win32' \? resolved\.toLowerCase\(\) : resolved/);
  // La racine passe par `realpath`, comme les entrées : comparer une racine non
  // canonisée à des entrées canonisées était le défaut.
  assert.match(src('nuclei.js'), /const baseReal = await fs\.realpath\(root\)\.catch\(\(\) => path\.resolve\(root\)\);/);
});

test('Nuclei : le comptage des templates ne retient que les fichiers YAML', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'security-center-nuclei-count-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  await fsp.mkdir(path.join(directory, 'http', 'cves'), { recursive: true });
  await fsp.mkdir(path.join(directory, '.github'), { recursive: true });
  await fsp.writeFile(path.join(directory, 'http', 'cves', 'a.yaml'), 'id: a');
  await fsp.writeFile(path.join(directory, 'http', 'cves', 'b.yml'), 'id: b');
  await fsp.writeFile(path.join(directory, 'http', 'README.md'), 'doc');
  await fsp.writeFile(path.join(directory, '.github', 'ignore.yaml'), 'ci');
  assert.equal(await countTemplates(directory), 2, 'les dossiers cachés et la documentation sont exclus');
});

// ------------------------------------------------------------------ cible

test('Nuclei : la cible distante exige la même autorisation explicite que ZAP', () => {
  assert.equal(validateNucleiTarget('http://127.0.0.1:3000').hostname, '127.0.0.1');
  assert.equal(validateNucleiTarget('http://localhost:3000').hostname, 'localhost');
  // Sans autorisation, une adresse distante est refusée avant tout envoi.
  assert.throws(() => validateNucleiTarget('http://192.168.222.132:3000'), /cible locale/);
  assert.equal(
    validateNucleiTarget('http://192.168.222.132:3000', { allowRemote: true }).hostname,
    '192.168.222.132'
  );
  for (const bogus of ['ftp://192.168.1.1', 'pas-une-url', 'file:///etc/passwd']) {
    assert.throws(() => validateNucleiTarget(bogus, { allowRemote: true }));
  }
});

// -------------------------------------------------------- ligne de commande

test('Nuclei : le scan utilise le corpus vérifié et ne se met jamais à jour tout seul', () => {
  const args = nucleiArgs({ targetUrl: 'http://127.0.0.1:3000', templatesPath: 'C:/corpus', reportPath: 'C:/out.jsonl' });
  const joined = args.join(' ');
  assert.match(joined, /-target http:\/\/127\.0\.0\.1:3000/);
  assert.match(joined, /-templates C:\/corpus/);
  assert.match(joined, /-jsonl-export C:\/out\.jsonl/);
  // Sans `-disable-update-check`, Nuclei remplace les templates par les siens,
  // dans son propre dossier : le corpus vérifié ne serait plus celui qui tourne.
  assert.ok(args.includes('-disable-update-check'), 'aucune mise à jour automatique');
  assert.ok(args.includes('-jsonl'), 'sortie structurée');
  assert.ok(args.includes('-stats-json'), 'avancement lisible par le moteur');
  assert.ok(!args.includes('-update-templates'), 'jamais de mise à jour pendant un scan');
});

test('Nuclei : le débit par défaut protège une application mono-processus', () => {
  assert.equal(DEFAULT_RATE_LIMIT, 25);
  assert.equal(DEFAULT_CONCURRENCY, 10);
  assert.equal(DEFAULT_MAX_HOST_ERRORS, 250);
  const args = nucleiArgs({ targetUrl: 'http://127.0.0.1:3000', templatesPath: 'T', reportPath: 'R' });
  assert.equal(args[args.indexOf('-rate-limit') + 1], '25');
  assert.equal(args[args.indexOf('-concurrency') + 1], '10');
  // Les valeurs d'usine de Nuclei (150 en parallèle, 30 erreurs tolérées) ont
  // fait retirer la cible du parcours au bout de 39 %, en annonçant zéro
  // correspondance sur une application pourtant vulnérable.
  assert.equal(args[args.indexOf('-max-host-error') + 1], '250');
});

test('Nuclei : un en-tête d’authentification ne peut pas injecter de requête', () => {
  const args = nucleiArgs({
    targetUrl: 'http://127.0.0.1:3000', templatesPath: 'T', reportPath: 'R',
    headers: ['Authorization: Bearer abc']
  });
  assert.ok(args.includes('-header'));
  assert.ok(args.includes('Authorization: Bearer abc'));
  for (const injected of ['X: a\r\nY: b', 'X: a\nY: b']) {
    assert.throws(() => nucleiArgs({
      targetUrl: 'http://127.0.0.1:3000', templatesPath: 'T', reportPath: 'R', headers: [injected]
    }), /En-tête Nuclei invalide/);
  }
});

test('Nuclei : seules des sévérités connues atteignent la ligne de commande', () => {
  const args = nucleiArgs({
    targetUrl: 'http://127.0.0.1:3000', templatesPath: 'T', reportPath: 'R',
    severities: ['high', 'critical', 'catastrophique'],
    excludeSeverities: ['info', 'inventée']
  });
  assert.equal(args[args.indexOf('-severity') + 1], 'high,critical');
  assert.equal(args[args.indexOf('-exclude-severity') + 1], 'info');
  // Aucune sévérité valide : aucun filtre, tout le corpus s'exécute.
  const unfiltered = nucleiArgs({ targetUrl: 'http://127.0.0.1:3000', templatesPath: 'T', reportPath: 'R', severities: ['n’importe quoi'] });
  assert.ok(!unfiltered.includes('-severity'));
});

// ------------------------------------------------------- état terminal réel

test('Nuclei : un scan tronqué n’est pas présenté comme un scan sans vulnérabilité', () => {
  const dropped = '[INF] Skipped 192.168.222.132:3000 from target list as found unresponsive 30 times';
  assert.equal(hostWasDropped(dropped), true);
  assert.equal(hostWasDropped('[INF] Scan completed in 14m. 19 matches found.'), false);

  // Scan réel n°1 : réglages d'usine, cible retirée, 7931 requêtes sur 19988.
  assert.equal(isTruncatedScan(scanCoverage({ requests: 7931, total: 19988 }), dropped), true);
  // Scan réel n°2 : débit maîtrisé, cible retirée puis reprise, 19734 sur 19988.
  assert.equal(isTruncatedScan(scanCoverage({ requests: 19734, total: 19988 }), dropped), false);
  // Sans retrait de cible, une couverture partielle n'est pas un échec.
  assert.equal(isTruncatedScan(scanCoverage({ requests: 7931, total: 19988 }), ''), false);
  // Sans statistiques, rien n'est déclaré tronqué sur une supposition.
  assert.equal(scanCoverage(null), 1);
  assert.equal(scanCoverage({ requests: 10, total: 0 }), 1);
  assert.ok(MIN_USABLE_COVERAGE > 0.5 && MIN_USABLE_COVERAGE <= 1);
});

test('Nuclei : l’avancement rapporté vient du moteur, pas d’une estimation', () => {
  const stats = parseStatsLine('{"duration":"0:14:20","errors":"889","hosts":"1","matched":"19","percent":"98","requests":"19734","rps":"22","templates":"10521","total":"19988"}');
  assert.deepEqual(stats, { percent: 98, requests: 19734, total: 19988, matched: 19, errors: 889, duration: '0:14:20' });
  assert.equal(parseStatsLine('[INF] Scan completed in 14m.'), null);
  assert.equal(parseStatsLine('{"template-id":"robots-txt"}'), null);
  assert.equal(parseStatsLine(''), null);
});

test('Nuclei : un scan sans correspondance reste un scan réussi', () => {
  const source = src('nuclei.js');
  const run = source.match(/function runNuclei\([\s\S]*?\n\}\n/)[0];
  // Nuclei sort en code non nul quand rien ne correspond. Traiter ce code comme
  // une erreur ferait échouer tout scan propre d'une application saine.
  assert.match(run, /if \(!report && outcome\.failed\)/);
  assert.ok(!/if \(outcome\.failed\) throw/.test(run), 'le code de sortie seul ne fait pas échouer le scan');
});

// -------------------------------------------------------- analyse et findings

test('Nuclei : le JSONL réel est analysé, une ligne tronquée n’emporte pas le rapport', () => {
  const parsed = parseNucleiJsonl(`${REAL_JSONL}\n{"template-id":"tronqu\n[INF] Scan completed\n\n`);
  assert.equal(parsed.length, 4);
  assert.equal(parsed[0]['template-id'], 'prometheus-metrics');
  assert.equal(parseNucleiJsonl('').length, 0);
  assert.equal(parseNucleiJsonl(null).length, 0);
});

test('Nuclei : les sévérités du moteur sont traduites sans écraser l’inconnu', () => {
  assert.deepEqual(nucleiSeverity('critical'), { severity: 'error', rawSeverity: 'CRITICAL' });
  assert.deepEqual(nucleiSeverity('high'), { severity: 'error', rawSeverity: 'HIGH' });
  assert.deepEqual(nucleiSeverity('medium'), { severity: 'warning', rawSeverity: 'MEDIUM' });
  assert.deepEqual(nucleiSeverity('low'), { severity: 'information', rawSeverity: 'LOW' });
  assert.deepEqual(nucleiSeverity('info'), { severity: 'information', rawSeverity: 'INFO' });
  // Un template sans sévérité déclarée n'est pas silencieusement rangé en
  // « information » : il reste à examiner.
  assert.deepEqual(nucleiSeverity(''), { severity: 'warning', rawSeverity: 'UNKNOWN' });
  assert.deepEqual(nucleiSeverity('inventée'), { severity: 'warning', rawSeverity: 'UNKNOWN' });
});

test('Nuclei : la classification extrait le CWE et ignore un cve-id nul', () => {
  assert.deepEqual(nucleiClassification({ classification: { 'cve-id': null, 'cwe-id': ['cwe-693'] } }), { cwe: 'CWE-693', aliases: [] });
  assert.deepEqual(nucleiClassification({ classification: { 'cve-id': ['CVE-2021-44228'], 'cwe-id': ['cwe-502'] } }), { cwe: 'CWE-502', aliases: ['CVE-2021-44228'] });
  assert.deepEqual(nucleiClassification({}), { cwe: '', aliases: [] });
  assert.deepEqual(nucleiClassification({ classification: { 'cwe-id': ['pas-un-cwe'] } }), { cwe: '', aliases: [] });
});

test('Nuclei : les findings réels sont complets et exploitables par les pages SCenter', () => {
  const findings = normalizeNucleiOutput(parseNucleiJsonl(REAL_JSONL), '', 'http://192.168.222.132:3000');
  // Quatre événements, dont deux pour le même template sur la même URL.
  assert.equal(findings.length, 3);

  const prometheus = findings.find((finding) => finding.ruleId === 'prometheus-metrics');
  assert.equal(prometheus.tool, 'Nuclei');
  assert.equal(prometheus.title, 'Prometheus Metrics - Detect');
  assert.equal(prometheus.severity, 'warning');
  assert.equal(prometheus.rawSeverity, 'MEDIUM');
  assert.equal(prometheus.category, 'dynamic');
  assert.equal(prometheus.cwe, 'CWE-200');
  assert.equal(prometheus.endpoint, 'http://192.168.222.132:3000/metrics');
  assert.equal(prometheus.file, 'HTTP http://192.168.222.132:3000/metrics');
  assert.equal(prometheus.sourceContext, 'runtime');
  assert.deepEqual(prometheus.references, ['https://prometheus.io/']);

  // Chaque finding doit porter de quoi être ouvert et affiché.
  for (const finding of findings) {
    for (const field of ['id', 'tool', 'ruleId', 'title', 'severity', 'rawSeverity', 'endpoint', 'method']) {
      assert.ok(String(finding[field] || '').trim(), `${finding.ruleId} : champ ${field} vide`);
    }
    assert.equal(finding.absolutePath, '', 'un finding dynamique ne pointe aucun fichier du dépôt');
    assert.equal(finding.startLine, 0);
  }
});

test('Nuclei : les contrôles multiples d’un même template ne disparaissent pas au dédoublonnage', () => {
  const findings = normalizeNucleiOutput(parseNucleiJsonl(REAL_JSONL), '', 'http://192.168.222.132:3000');
  const headers = findings.filter((finding) => finding.ruleId === 'http-missing-security-headers');
  // Le scan réel a produit huit événements sur cette seule URL, un par en-tête
  // absent. Le dédoublonnage global n'en aurait gardé qu'un, en perdant les noms
  // des sept autres : ils sont regroupés, pas jetés.
  assert.equal(headers.length, 1);
  assert.match(headers[0].technicalDetails, /Contrôles déclenchés \(2\)/);
  assert.match(headers[0].technicalDetails, /content-security-policy/);
  assert.match(headers[0].technicalDetails, /strict-transport-security/);
  assert.equal(headers[0].parameter, 'content-security-policy, strict-transport-security');
});

test('Nuclei : les valeurs extraites remontent comme preuve', () => {
  const findings = normalizeNucleiOutput(parseNucleiJsonl(REAL_JSONL), '', 'http://192.168.222.132:3000');
  const robots = findings.find((finding) => finding.ruleId === 'robots-txt-endpoint');
  assert.equal(robots.evidence, '/ftp');
  assert.match(robots.technicalDetails, /Extracteur : endpoints/);
  assert.match(robots.technicalDetails, /Valeurs extraites : \/ftp/);
});

test('Nuclei : une charge vide ou invalide ne fabrique aucun finding', () => {
  assert.deepEqual(normalizeNucleiOutput([]), []);
  assert.deepEqual(normalizeNucleiOutput(null), []);
  assert.deepEqual(normalizeNucleiOutput([{ info: { name: 'sans identifiant' } }]), []);
});

// ------------------------------------------------------------ outil managé

test('Nuclei : le binaire suit le contrat officiel des autres outils managés', () => {
  const tool = TOOLS.nuclei;
  assert.equal(tool.repo, 'projectdiscovery/nuclei');
  assert.equal(tool.command, 'nuclei');
  assert.equal(tool.kind, 'github');
  assert.equal(tool.asset.test('nuclei_3.11.1_windows_amd64.zip'), true);
  // Aucune autre plateforme ne doit être prise pour la bonne.
  for (const wrong of ['nuclei_3.11.1_windows_arm64.zip', 'nuclei_3.11.1_linux_amd64.zip', 'nuclei_3.11.1_macOS_amd64.zip']) {
    assert.equal(tool.asset.test(wrong), false, `accepté à tort : ${wrong}`);
  }
  assert.equal(tool.checksum.test('nuclei_3.11.1_checksums.txt'), true);
  // Nuclei répond à `-version`, pas à `--version`.
  assert.deepEqual(tool.versionArgs, ['-version']);
});

test('Nuclei : la version lue est celle du moteur, pas la bannière ASCII', async () => {
  const script = path.join(os.tmpdir(), `security-center-nuclei-version-${process.pid}.js`);
  // La bannière contient elle aussi « v3.11.1 » : sans motif explicite, c'est
  // cette ligne d'art ASCII qui remontait dans la carte de l'outil.
  const banner = [
    '                     __     _',
    '   ____  __  _______/ /__  (_)',
    '  /_/ /_/\\\\__,_/\\\\___/_/\\\\___/_/   v3.11.1',
    '',
    '[INF] Nuclei Engine Version: v3.11.1',
    '[INF] Nuclei Config Directory: C:\\\\Users\\\\test\\\\AppData\\\\Roaming\\\\nuclei'
  ].join('\\n');
  fs.writeFileSync(script, `process.stderr.write(${JSON.stringify(banner)});\n`);
  try {
    const version = await commandVersion(process.execPath, 30000, [script]);
    assert.equal(version, 'v3.11.1');
  } finally {
    fs.rmSync(script, { force: true });
  }
});

// -------------------------------------------------------------- intégration

test('Nuclei : détecté, installé, templates garantis, puis scan — sans commande de terminal', () => {
  const extension = src('extension.js');
  assert.match(extension, /const ALL_SCANNER_TOOLS = Object\.freeze\(\[[^\]]*'Nuclei'\]\)/);
  // Le binaire et les templates s'installent dans le même geste : annoncer
  // « Nuclei est prêt » avec un corpus absent décrirait un outil qui ne détecte rien.
  assert.match(extension, /if \(id === 'nuclei'\) \{\s*\n\s*const manifest = await ensureNucleiTemplates\(/);
  // Avant chaque scan, les templates sont garantis.
  assert.match(extension, /let manifest = await nucleiTemplatesManifest\(\);/);
  assert.match(extension, /if \(!manifest\) \{[\s\S]{0,160}?manifest = await ensureNucleiTemplates\(/);
  assert.match(extension, /templatesPath: manifest\.directory/);
  // Aucune commande de terminal n'est demandée à l'utilisateur.
  assert.ok(!/nuclei -update-templates|npm i -g nuclei|go install/.test(extension));
});

test('Nuclei : la cible et l’autorisation sont celles de Dynamic Security, pas une seconde source', () => {
  const extension = src('extension.js');
  const slot = extension.match(/if \(nucleiStatus\?\.installed\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  assert.match(slot, /assertTargetAuthorized\(cfg\.get\('zap\.targetUrl'/);
  assert.match(slot, /remoteAuthorized: cfg\.get\('zap\.remoteAuthorized', false\) === true/);
  // Une cible distante non confirmée n'atteint jamais le moteur.
  assert.ok(slot.indexOf('assertTargetAuthorized') < slot.indexOf('runNuclei('), 'autorisation avant exécution');
  assert.match(slot, /allowRemote: cfg\.get\('zap\.targetMode'/);
});

test('Nuclei : l’avancement ne traverse jamais la machine d’états de la campagne ZAP', () => {
  const extension = src('extension.js');
  const slot = extension.match(/if \(nucleiStatus\?\.installed\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  // La campagne dynamique n'accepte que ses propres états (SPIDERING,
  // ACTIVE_SCANNING…) et lève sur tout autre. Y publier l'avancement de Nuclei
  // ferait échouer le scan et emporterait la consolidation avec lui.
  assert.ok(!slot.includes('publishDynamicLifecycle'), 'aucune publication dans la campagne ZAP');
  // L'avancement va au journal et à l'exécution commune de Nuclei (DynamicRun).
  assert.match(slot, /onLifecycle: \(event\) => \{[\s\S]*?scanLog\.appendLine\(/);
  assert.match(slot, /updateEngineRun\('nuclei', \{\s*status: RUN_STATUS\.RUNNING,\s*progress: event\.percent/);

  // Et côté moteur, un écouteur qui lève ne casse pas le scan.
  const source = src('nuclei.js');
  assert.match(source, /try \{ onLifecycle\(\{ engine: 'nuclei', \.\.\.snapshot \}\); \} catch/);
});

test('Nuclei : les réglages exposés existent tous et sont réellement lus', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const properties = pkg.contributes.configuration.properties;
  const extension = src('extension.js');
  const declared = Object.keys(properties).filter((key) => key.startsWith('securityCenter.nuclei.'));
  assert.deepEqual(declared.sort(), [
    'securityCenter.nuclei.concurrency',
    'securityCenter.nuclei.enabled',
    'securityCenter.nuclei.rateLimit',
    'securityCenter.nuclei.severities'
  ]);
  // Aucun réglage mort : chacun est lu par le code.
  for (const key of declared) {
    const short = key.replace('securityCenter.', '');
    assert.ok(extension.includes(`cfg.get('${short}'`), `réglage jamais lu : ${key}`);
  }
  assert.equal(properties['securityCenter.nuclei.rateLimit'].default, DEFAULT_RATE_LIMIT);
  assert.equal(properties['securityCenter.nuclei.concurrency'].default, DEFAULT_CONCURRENCY);
});

// ------------------------------- état d'installation partagé entre les pages

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

/** La carte Nuclei de la page Dynamic Security, isolée du reste. */
function nucleiCard(options = {}) {
  const html = renderDashboardHtml(
    buildDashboardModel([], options.scanners || [], {
      workspace: 'demo', dynamicTargetUrl: 'http://192.168.222.132:3000', ...options
    }),
    'nonce', 'dynamic', 'light', {}, {}
  );
  const start = html.indexOf('dynamic-tool-card nuclei');
  assert.ok(start > 0, 'carte Nuclei introuvable');
  return html.slice(start, html.indexOf('</article>', start));
}

test('Nuclei : l’état d’installation vient de la détection d’outil, pas de l’historique de scans', () => {
  // Le défaut réel : `model.scanners` décrit ce qui a été exécuté. Un Nuclei
  // installé mais jamais lancé n'y figure pas, et la carte annonçait
  // « NOT INSTALLED » pendant que Scanner Configuration affichait « Prêt ».
  const card = nucleiCard({ nucleiTool: { installed: true, version: 'v3.11.1', templatesVersion: '10.4.8', templatesCount: 13641 } });
  assert.match(card, /PRÊT/);
  assert.match(card, /<span>Version<\/span><strong>v3\.11\.1<\/strong>/);
  assert.match(card, /<span>Templates<\/span><strong>10\.4\.8<\/strong>/);
  assert.match(card, /13641 templates/);
  // L'action principale devient le scan, plus l'installation — et elle lance
  // Nuclei lui-même, pas le sélecteur générique où Nuclei ne figure pas.
  assert.match(card, /data-command="securityCenter\.scanNuclei"/);
  assert.ok(!card.includes('securityCenter.scanSelected'), 'le bouton passe encore par le sélecteur générique');
  assert.ok(!card.includes('>Install Nuclei<'), 'propose encore d’installer un outil déjà installé');
  assert.ok(!card.includes('Install Nuclei from Scanner Configuration'), 'invite encore à installer');
});

test('Nuclei : un outil réellement absent affiche toujours NOT INSTALLED', () => {
  for (const options of [{}, { nucleiTool: null }, { nucleiTool: { installed: false } }]) {
    const card = nucleiCard(options);
    assert.match(card, /NOT INSTALLED/, `état inattendu pour ${JSON.stringify(options)}`);
    assert.match(card, /<span>Version<\/span><strong>Not reported<\/strong>/);
    assert.match(card, /data-command="securityCenter\.openScannerSetup">Install Nuclei</);
  }
  // « Prêt » n'est jamais déduit d'une simple configuration : il faut que la
  // détection ait rendu `installed: true`.
  const configuredOnly = nucleiCard({ nucleiTool: { installed: false, version: 'v3.11.1' } });
  assert.match(configuredOnly, /NOT INSTALLED/);
});

test('Nuclei : un run en cours ou terminé décrit l’instant mieux que « prêt »', () => {
  const running = nucleiCard({
    nucleiTool: { installed: true, version: 'v3.11.1' },
    scanners: [{ tool: 'Nuclei', status: 'running' }]
  });
  assert.match(running, /Nuclei running…/);
  assert.match(running, /disabled aria-busy="true"/);
  const completed = nucleiCard({
    nucleiTool: { installed: true, version: 'v3.11.1' },
    scanners: [{ tool: 'Nuclei', status: 'completed', completedAt: '2026-09-10T16:00:00.000Z' }]
  });
  assert.match(completed, /COMPLETED/);
  assert.match(completed, /data-command="securityCenter\.scanNuclei"/);
});

test('Nuclei : les deux pages lisent la même détection, et elle est rafraîchie', () => {
  const extension = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // Une seule source qui fasse autorité : `scannerToolManager.status('nuclei')`,
  // exactement celle que Scanner Configuration utilise.
  assert.match(extension, /async function nucleiToolModel\(\) \{[\s\S]*?scannerToolManager\.status\('nuclei'\)/);
  // Publié à l'activation, à l'ouverture de la page, après installation et à
  // chaque rendu de Scanner Configuration : jamais besoin de réinstaller
  // l'extension pour voir l'état changer.
  assert.match(extension, /nucleiToolModel\(\)\.catch\(\(\) => null\)/, 'activation');
  assert.match(extension, /if \(page === 'dynamic'\) \{[\s\S]*?refreshNucleiToolModel\(\)/, 'ouverture de la page');
  // L'installation invalide d'abord la mémorisation de détection, puis republie :
  // l'état affiché après installation est mesuré, jamais servi depuis le cache.
  assert.match(extension, /if \(id === 'nuclei'\) \{ invalidateNucleiToolCache\(\); await refreshNucleiToolModel\(\)/, 'après installation');
  assert.match(extension, /const nucleiStatus = rawStatuses\.find\(\(item\) => item\.id === 'nuclei'\);/, 'rendu Scanner Configuration');
});

// ------------------------------------------ bouton Nuclei et exécution commune

test('Nuclei : le bouton lance Nuclei lui-même, via le pipeline de scan existant', () => {
  const extension = src('extension.js');
  const command = extension.match(/registerCommand\('securityCenter\.scanNuclei'[\s\S]*?\n  \}\)\);/)[0];
  // La disponibilité vient de la détection d'outil, jamais de l'historique de scans.
  assert.match(command, /await nucleiToolModel\(\)/);
  assert.ok(!/model\.scanners|currentScanStatuses/.test(command), 'aucune déduction depuis l’historique de scans');
  assert.match(command, /cfg\.get\('nuclei\.enabled', true\)/);
  // Aucun second moteur : le pipeline garde autorisation, templates, normalisation et persistance.
  assert.match(command, /executeCommand\('securityCenter\.scanWorkspace', \['Nuclei'\]\)/);
  assert.ok(!/runNuclei\(|spawn\(/.test(command), 'la commande ne lance pas Nuclei elle-même');
  // Déclarée, et autorisée depuis la page.
  assert.match(extension, /'securityCenter\.scanNuclei',/);
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.contributes.commands.some((entry) => entry.command === 'securityCenter.scanNuclei'));
});

test('Nuclei : STARTING tant que le processus n’existe pas, RUNNING dès qu’il démarre', () => {
  const extension = src('extension.js');
  // La préparation (templates, autorisation de la cible) n'est pas encore le scan.
  assert.match(extension, /if \(dynamicEngine !== 'nuclei'\) updateEngineRun\(dynamicEngine, \{ status: RUN_STATUS\.RUNNING \}\);/);
  const slot = extension.match(/if \(nucleiStatus\?\.installed\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  assert.match(slot, /onStart: \(child\) => \{[\s\S]*?updateEngineRun\('nuclei', \{ status: RUN_STATUS\.RUNNING/);
  // L'autorisation de la cible précède toujours le démarrage du processus.
  assert.ok(slot.indexOf('assertTargetAuthorized') < slot.indexOf('onStart'), 'autorisation avant démarrage');
  // Clôture par l'exécution commune : findingCount et finishedAt, ou échec avec sa raison.
  assert.match(extension, /completeRun\(finished, \{ findingCount: scanFindings\.length/);
  assert.match(extension, /failEngineRun\(dynamicEngineOf\(scan\.tool\), RUN_ERROR\.SCAN_FAILED, error\.message\)/);
  // Côté moteur : `spawn` confirme le démarrage réel, et un écouteur qui lève ne casse pas le scan.
  const engine = src('nuclei.js');
  assert.match(engine, /child\.once\('spawn', \(\) => \{\s*try \{ onStart\(child\); \} catch/);
  assert.match(engine, /spawnNuclei\(executable, args, \{ timeoutMs, signal, onLifecycle, onStart \}\)/);
});

test('Nuclei : aucun processus orphelin si la fenêtre se ferme en plein scan', () => {
  const extension = src('extension.js');
  assert.match(extension, /activeNucleiProcess = child;/);
  assert.match(extension, /child\.once\('close', \(\) => \{ if \(activeNucleiProcess === child\) activeNucleiProcess = null; \}\);/);
  assert.match(extension, /const child = activeNucleiProcess;\s*if \(child && child\.exitCode === null && child\.signalCode === null\) \{\s*try \{ child\.kill\(\); \}/);
  // L'annulation et le dépassement de délai tuent déjà le processus côté moteur.
  const engine = src('nuclei.js');
  assert.match(engine, /const onAbort = \(\) => \{ child\.kill\(\);/);
});

test('Nuclei : un scan lancé depuis la carte a le temps de se terminer', () => {
  // Mesuré : ~3 min de chargement des templates puis 19 988 requêtes, 1 041 à
  // 1 056 s au total. Le délai global des scanners (300 s par défaut, 1 800 s
  // au plus) tuait chaque scan lancé depuis la carte.
  const { SCAN_TIMEOUT_MS } = require('../src/nuclei');
  assert.ok(SCAN_TIMEOUT_MS >= 1800000, `budget trop court : ${SCAN_TIMEOUT_MS} ms`);
  const extension = src('extension.js');
  const slot = extension.match(/if \(nucleiStatus\?\.installed\) scans\.push\(\{[\s\S]*?\n        \}\);/)[0];
  assert.match(slot, /timeoutMs: Math\.max\(timeoutMs, NUCLEI_SCAN_TIMEOUT_MS\)/);
  // Le délai global reste celui des autres scanners : rien d'autre ne change.
  assert.match(extension, /const timeoutMs = cfg\.get\('scan\.timeoutSeconds', 300\) \* 1000;/);
});

/** Un instantané DynamicRun minimal pour la carte Nuclei. */
function nucleiRunModel(status, execution = {}) {
  return {
    engines: {
      nuclei: {
        engine: 'nuclei', kind: 'scan', status, reason: '',
        statusLabel: { READY: 'PRÊT', STARTING: 'DÉMARRAGE', RUNNING: 'EN COURS' }[status] || status,
        availability: { installed: true, usable: true, version: 'v3.11.1', prerequisites: [], reason: '' },
        execution: {
          neverExecuted: false, runId: 'nuclei-1', status, phase: '', progress: null,
          target: 'http://192.168.222.132:3000', startedAt: null, finishedAt: null, lastActivity: null,
          requestCount: null, findingCount: null, errorCode: '', errorReason: '', lastRun: null, ...execution
        }
      }
    }
  };
}

test('Nuclei : « Voir les findings Nuclei » ouvre la vue complète, filtrée sur Nuclei', () => {
  const card = nucleiCard({ nucleiTool: { installed: true, version: 'v3.11.1' } });
  assert.match(card, /data-command="securityCenter\.openNucleiFindings">Voir les findings Nuclei</);
  // Le bouton ne renvoie plus vers la section des seules priorités.
  assert.ok(!card.includes('data-dynamic-filter-target="nuclei"'), 'le bouton mène encore à la section prioritaire');
  const extension = src('extension.js');
  assert.match(extension, /registerCommand\('securityCenter\.openNucleiFindings'[\s\S]{0,400}?openFindingsForTool\('nuclei'\)/);
  assert.match(extension, /'securityCenter\.openNucleiFindings',/);
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.contributes.commands.some((entry) => entry.command === 'securityCenter.openNucleiFindings'));
  // L'identifiant préréglé est bien celui qu'emploie le filtre Scanner.
  const { scannerIdForTool } = require('../src/scanner-presentation');
  assert.equal(scannerIdForTool('Nuclei'), 'nuclei');
});

const UX_FINDINGS = [
  { tool: 'Nuclei', title: 'Info nuclei', rawSeverity: 'INFO', endpoint: 'http://192.168.222.132:3000/' },
  { tool: 'Nuclei', title: 'Medium nuclei', rawSeverity: 'MEDIUM', endpoint: 'http://192.168.222.132:3000/rest' },
  { tool: 'Semgrep', title: 'Autre outil', rawSeverity: 'HIGH', file: 'src/app.js' }
];

test('Nuclei : la page Findings s’ouvre avec le filtre Scanner prérempli, toutes sévérités', () => {
  const page = renderDashboardHtml(
    buildDashboardModel(UX_FINDINGS, [{ tool: 'Nuclei', status: 'completed' }], { workspace: 'demo' }),
    'nonce', 'findings', 'light', { findingsTool: 'nuclei' }, {}
  );
  assert.match(page, /<option value="nuclei" selected>/);
  // Aucune sévérité n'est imposée : le filtre ne porte que sur le scanner.
  const severitySelect = page.slice(page.indexOf('id="finding-severity"'), page.indexOf('</select>', page.indexOf('id="finding-severity"')));
  assert.ok(!severitySelect.includes('selected'), 'une sévérité est préfiltrée');
  // Le préréglage s'applique dès l'ouverture, sans clic.
  assert.match(page, /if \(tool\?\.value\) filterFindings\(\);/);
  // Les findings INFO et MEDIUM sont bien présents dans cette vue.
  assert.match(page, /Info nuclei/);
  assert.match(page, /Medium nuclei/);
  // Sans préréglage, le balisage du filtre ne change pas.
  const plain = renderDashboardHtml(buildDashboardModel(UX_FINDINGS, [], { workspace: 'demo' }), 'nonce', 'findings', 'light', {}, {});
  assert.ok(!plain.includes('value="nuclei" selected'));
});

test('Dynamic Findings annonce qu’il ne montre que les priorités, et le total réel', () => {
  const html = renderDashboardHtml(
    buildDashboardModel(UX_FINDINGS, [{ tool: 'Nuclei', status: 'completed' }], { workspace: 'demo' }),
    'nonce', 'dynamic', 'light', {}, {}
  );
  assert.match(html, /Findings prioritaires HIGH \/ CRITICAL\./);
  // « Nuclei 0 » contredisait une carte annonçant 12 findings : le total suit désormais.
  assert.match(html, /Nuclei 0\/2/);
  assert.match(html, /<strong id="dynamic-visible-count">0<\/strong> HIGH\/CRITICAL/);
  assert.match(html, /Aucun finding dynamique HIGH ou CRITICAL actif\. Les findings de sévérité moindre restent visibles dans la page Findings\./);
  // Aucune promotion artificielle : INFO et MEDIUM n'entrent pas dans la section
  // prioritaire, même si la page les montre ailleurs.
  const section = html.slice(html.indexOf('id="dynamic-findings"'), html.indexOf('</section>', html.indexOf('id="dynamic-findings"')));
  assert.ok(!section.includes('Info nuclei'), 'un finding INFO a été promu dans la section prioritaire');
  assert.ok(!section.includes('Medium nuclei'), 'un finding MEDIUM a été promu dans la section prioritaire');
});

test('Le filtre Scanner demandé par un bouton ne s’applique qu’une fois', () => {
  const extension = src('extension.js');
  assert.match(extension, /openFindingsForTool\(toolId\) \{[\s\S]*?this\.findingsToolPreset = String\(toolId \|\| ''\);/);
  assert.match(extension, /if \(surface === 'findings' && this\.findingsToolPreset\) \{[\s\S]*?this\.findingsToolPreset = '';/);
});

test('Nuclei : la carte montre l’exécution en cours, puis son issue réelle', () => {
  const tool = { installed: true, version: 'v3.11.1' };
  const running = nucleiCard({ nucleiTool: tool, dynamicRuntime: nucleiRunModel('RUNNING', {
    phase: '1200/3400 requêtes · 3 correspondance(s)', progress: 35,
    startedAt: '2026-09-11T10:00:00.000Z', lastActivity: '2026-09-11T10:01:30.000Z'
  }) });
  assert.match(running, /class="tool-status running">EN COURS</);
  assert.match(running, /1200\/3400 requêtes · 3 correspondance\(s\) · 35 %/);
  assert.match(running, /démarré à /);
  assert.match(running, /dernière activité /);
  assert.match(running, /data-command="securityCenter\.scanNuclei" disabled aria-busy="true">Nuclei running…/);

  // Un échec ne se cache plus derrière « prêt » : son code et sa raison sont affichés.
  const failed = nucleiCard({ nucleiTool: tool, dynamicRuntime: nucleiRunModel('READY', { status: 'FAILED', lastRun: {
    id: 'nuclei-1', status: 'FAILED', target: 'http://192.168.222.132:3000',
    startedAt: '2026-09-11T10:00:00.000Z', finishedAt: '2026-09-11T10:00:05.000Z',
    requestCount: null, findingCount: null, errorCode: 'SCAN_FAILED', errorReason: 'La cible distante n’est pas autorisée.'
  } }) });
  assert.match(failed, /class="tool-status failed">ÉCHEC</);
  assert.match(failed, /role="alert">Échec \(SCAN_FAILED\) : La cible distante n’est pas autorisée\./);
  assert.match(failed, /data-command="securityCenter\.scanNuclei" >Run Nuclei scan</);

  const completed = nucleiCard({ nucleiTool: tool, dynamicRuntime: nucleiRunModel('READY', { status: 'COMPLETED', lastRun: {
    id: 'nuclei-2', status: 'COMPLETED', target: 'http://192.168.222.132:3000',
    startedAt: '2026-09-11T10:00:00.000Z', finishedAt: '2026-09-11T10:03:00.000Z',
    requestCount: null, findingCount: 12, errorCode: '', errorReason: ''
  } }) });
  assert.match(completed, /class="tool-status completed">TERMINÉ</);
  assert.match(completed, /· 12 finding\(s\)/);
});
