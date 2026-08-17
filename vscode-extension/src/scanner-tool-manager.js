const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

// SonarScanner CLI is published by SonarSource on its own binaries host rather
// than on GitHub releases. Each artifact ships an official `.sha256` next to
// it, so the same download → verify → extract → check contract applies.
const SONARSCANNER_BASE = 'https://binaries.sonarsource.com/Distribution/sonar-scanner-cli';
const SONARSCANNER_LISTING = 'https://binaries.sonarsource.com/s3api?prefix=Distribution/sonar-scanner-cli/&delimiter=/&max-keys=5000';
// Verified fallback used when the official listing cannot be read.
const SONARSCANNER_PINNED_VERSION = '8.1.0.6389';

// Snyk publishes standalone executables on its own CDN, together with a single
// GPG-signed `sha256sums.txt.asc` covering every platform binary. The same
// download → verify → install contract as the other managed tools applies.
const SNYK_CLI_BASE = 'https://downloads.snyk.io/cli/stable';

/** Official Snyk standalone binary for the running platform, '' if unsupported. */
function snykCliAsset(platform = process.platform, arch = process.arch) {
  if (platform === 'win32') return arch === 'x64' ? 'snyk-win.exe' : '';
  if (platform === 'darwin') return arch === 'arm64' ? 'snyk-macos-arm64' : 'snyk-macos';
  if (platform === 'linux') return arch === 'arm64' ? 'snyk-linux-arm64' : 'snyk-linux';
  return '';
}

/**
 * `sha256sums.txt.asc` is a clear-signed list of `<sha256>  <asset>` lines.
 * Only the line naming the downloaded asset is used, and the name is matched
 * exactly so `snyk-linux` never picks up the `snyk-linux-arm64` digest.
 */
function parseSnykChecksums(text, asset) {
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.trim().match(/^([a-f0-9]{64})\s+\*?(\S+)$/i);
    if (match && match[2].replace(/^\.\//, '') === asset) return match[1].toLowerCase();
  }
  return '';
}

/** Official artifact suffix for the running platform, or '' when unsupported. */
function sonarScannerPlatform(platform = process.platform, arch = process.arch) {
  if (platform === 'win32') return arch === 'x64' ? 'windows-x64' : '';
  if (platform === 'darwin') return arch === 'arm64' ? 'macosx-aarch64' : 'macosx-x64';
  if (platform === 'linux') return arch === 'arm64' ? 'linux-aarch64' : 'linux-x64';
  return '';
}

function compareVersions(left, right) {
  const a = String(left).split('.').map(Number);
  const b = String(right).split('.').map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] || 0) - (b[index] || 0);
    if (difference) return difference;
  }
  return 0;
}

const TOOLS = Object.freeze({
  semgrep: { label: 'Semgrep', kind: 'python', command: 'semgrep', repo: 'semgrep/semgrep', purpose: 'Analyse statique du code (SAST)' },
  gitleaks: { label: 'Gitleaks', kind: 'github', command: 'gitleaks', repo: 'gitleaks/gitleaks', purpose: 'Détection de secrets', asset: /gitleaks_.*_windows_x64\.zip$/i, checksum: /checksums\.txt$/i },
  trivy: { label: 'Trivy', kind: 'github', command: 'trivy', repo: 'aquasecurity/trivy', purpose: 'Dépendances, conteneurs et IaC', asset: /trivy_.*_windows-64bit\.zip$/i, checksum: /checksums\.txt$/i },
  osv: { label: 'OSV-Scanner', kind: 'github', command: 'osv-scanner', repo: 'google/osv-scanner', purpose: 'Vulnérabilités des dépendances', asset: /osv-scanner_windows_amd64\.exe$/i, checksum: /(checksums|sha256).*\.txt$/i },
  sonarscanner: { label: 'SonarScanner', kind: 'sonarsource', command: 'sonar-scanner', purpose: 'Analyse SonarQube du code', base: SONARSCANNER_BASE, version: SONARSCANNER_PINNED_VERSION },
  snyk: { label: 'Snyk CLI', kind: 'snyk', command: 'snyk', purpose: 'Dépendances, code et IaC via Snyk', base: SNYK_CLI_BASE },
  // Cosign is a supply-chain tool, not a scanner: it signs and verifies
  // artefacts and never produces findings. It reuses the same official
  // release + SHA-256 installation contract as the scanners.
  cosign: {
    label: 'Cosign', kind: 'github', command: 'cosign', repo: 'sigstore/cosign',
    purpose: 'Signature et vérification des artefacts (supply chain)',
    asset: /^cosign-windows-amd64\.exe$/i, checksum: /^cosign_checksums\.txt$/i,
    versionArgs: ['version'], supplyChain: true
  }
});

function request(url, headers = {}) {
  return new Promise((resolve, reject) => {
    // VS Code/Node does not always inherit the Windows certificate store.
    // Merge it with Node's bundled roots so official downloads continue to
    // use strict TLS validation behind managed/corporate HTTPS inspection.
    const systemCa = typeof tls.getCACertificates === 'function'
      ? [...new Set([...tls.getCACertificates('default'), ...tls.getCACertificates('system')])]
      : undefined;
    const run = (current, redirects = 0) => https.get(current, { ca: systemCa, headers: { 'User-Agent': 'security-center-vscode', Accept: 'application/vnd.github+json', ...headers } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location && redirects < 5) {
        response.resume(); return run(new URL(response.headers.location, current).toString(), redirects + 1);
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume(); return reject(new Error(`Téléchargement refusé (HTTP ${response.statusCode}).`));
      }
      resolve(response);
    }).on('error', reject);
    run(url);
  });
}

async function download(url, destination, onProgress = () => {}) {
  const response = await request(url);
  const total = Number(response.headers['content-length'] || 0);
  let received = 0;
  const handle = await fs.open(destination, 'w');
  try {
    for await (const chunk of response) {
      await handle.write(chunk); received += chunk.length;
      onProgress({ phase: 'download', received, total });
    }
  } finally { await handle.close(); }
}

async function downloadText(url) {
  const response = await request(url);
  const chunks = [];
  for await (const chunk of response) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function sha256(file) {
  const hash = crypto.createHash('sha256');
  const data = await fs.readFile(file); hash.update(data); return hash.digest('hex');
}

/**
 * Node refuses to spawn .bat/.cmd wrappers directly, so those go through the
 * interpreter with an argument array rather than `shell: true`.
 */
function versionInvocation(executable, platform = process.platform, versionArgs = ['--version']) {
  if (platform === 'win32' && /\.(bat|cmd)$/i.test(executable)) {
    return { executable: process.env.COMSPEC || 'cmd.exe', args: ['/d', '/s', '/c', executable, ...versionArgs] };
  }
  return { executable, args: [...versionArgs] };
}

async function commandVersion(executable, timeout = 30000, versionArgs = ['--version']) {
  const invocation = versionInvocation(executable, process.platform, versionArgs);
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, { windowsHide: true, timeout, maxBuffer: 4 * 1024 * 1024 });
    const output = String(stdout || stderr);
    // SonarScanner prints a banner before the version line.
    return output.match(/SonarScanner\s+(?:CLI\s+)?v?[0-9][\w.-]*/i)?.[0]
      // Cosign prints ASCII art first: the first line carrying a version wins
      // over the first non-empty line, which would otherwise be the banner.
      || output.trim().split(/\r?\n/).find((line) => /\d+\.\d+/.test(line) && line.trim())?.trim()
      || output.trim().split(/\r?\n/).find((line) => line.trim()) || 'installé';
  } catch (error) {
    const output = `${error.stdout || ''}\n${error.stderr || ''}`;
    return output.match(/SonarScanner\s+(?:CLI\s+)?v?[0-9][\w.-]*/i)?.[0] || '';
  }
}

class ScannerToolManager {
  constructor(storagePath) { this.root = path.join(storagePath, 'scanner-tools'); }
  toolDirectory(id) { return path.join(this.root, id); }
  managedExecutable(id) {
    if (id === 'semgrep') return path.join(this.toolDirectory(id), 'venv', process.platform === 'win32' ? 'Scripts' : 'bin', process.platform === 'win32' ? 'semgrep.exe' : 'semgrep');
    // The SonarSource archive keeps its own bin/ layout. It is normalised to a
    // fixed « current » directory so this path stays deterministic.
    if (id === 'sonarscanner') return path.join(this.toolDirectory(id), 'current', 'bin', process.platform === 'win32' ? 'sonar-scanner.bat' : 'sonar-scanner');
    return path.join(this.toolDirectory(id), process.platform === 'win32' ? `${TOOLS[id].command}.exe` : TOOLS[id].command);
  }
  async exists(file) { try { await fs.access(file); return true; } catch { return false; } }
  async findOnPath(command) {
    try {
      const detector = process.platform === 'win32' ? 'where.exe' : 'which';
      const { stdout } = await execFileAsync(detector, [command], { windowsHide: true, timeout: 10000 });
      return stdout.trim().split(/\r?\n/)[0] || '';
    } catch { return ''; }
  }
  async status(id) {
    const tool = TOOLS[id];
    const managed = this.managedExecutable(id);
    const executable = await this.exists(managed) ? managed : await this.findOnPath(tool.command);
    // The first Semgrep startup on Windows can spend a few extra seconds
    // initializing its Python environment. Do not report a false failure
    // while the managed executable is healthy but cold.
    const versionTimeout = id === 'semgrep' ? 60000 : 30000;
    // Cosign v2+ exposes `cosign version`, not `--version`.
    const version = executable ? await commandVersion(executable, versionTimeout, tool.versionArgs || ['--version']) : '';
    return { id, ...tool, installed: Boolean(executable && version), executable, version, managed: executable === managed };
  }
  async statuses() { return Promise.all(Object.keys(TOOLS).map((id) => this.status(id))); }
  async activateManagedPath() {
    const directories = Object.keys(TOOLS).map((id) => path.dirname(this.managedExecutable(id)));
    process.env.PATH = [...directories, process.env.PATH || ''].join(path.delimiter);
  }
  async githubRelease(tool) {
    const body = await downloadText(`https://api.github.com/repos/${tool.repo}/releases/latest`);
    const release = JSON.parse(body);
    const asset = release.assets?.find((item) => tool.asset.test(item.name));
    const checksum = release.assets?.find((item) => tool.checksum.test(item.name));
    if (!asset) throw new Error(`Aucun binaire Windows compatible trouvé dans la publication officielle ${release.tag_name}.`);
    return { version: release.tag_name, asset, checksum };
  }
  /** Highest published version, falling back to the pinned one. */
  async latestSonarScannerVersion(fallback = SONARSCANNER_PINNED_VERSION) {
    try {
      const listing = await downloadText(SONARSCANNER_LISTING);
      const versions = [...listing.matchAll(/sonar-scanner-cli-(\d+(?:\.\d+)+)-windows-x64\.zip(?!\.)/g)].map((match) => match[1]);
      return versions.sort(compareVersions).at(-1) || fallback;
    } catch { return fallback; }
  }

  /**
   * Installs the official SonarScanner CLI into the extension's private
   * storage. Nothing is written outside that directory and the system PATH is
   * never modified.
   */
  async installSonarScanner(tool, onProgress, platform = sonarScannerPlatform()) {
    if (!platform) throw new Error(`SonarScanner CLI n’est pas distribué pour ${process.platform}/${process.arch}. Utilisez le mode Docker.`);
    const version = await this.latestSonarScannerVersion(tool.version);
    const name = `sonar-scanner-cli-${version}-${platform}.zip`;
    const archiveUrl = `${tool.base}/${name}`;
    onProgress({ phase: 'metadata', message: `${version} (${platform}) depuis binaries.sonarsource.com` });
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-sonarscanner-'));
    const archive = path.join(temporary, name);
    try {
      await download(archiveUrl, archive, onProgress);
      const expected = String(await downloadText(`${archiveUrl}.sha256`)).match(/[a-f0-9]{64}/i)?.[0]?.toLowerCase();
      if (!expected) throw new Error(`SonarSource ne publie pas d’empreinte SHA-256 pour ${name}. Installation refusée par sécurité.`);
      const actual = await sha256(archive);
      if (actual !== expected) throw new Error('Échec de vérification SHA-256 de l’archive SonarScanner. Le fichier téléchargé a été supprimé.');
      onProgress({ phase: 'verify', message: 'Empreinte SHA-256 officielle vérifiée' });

      const extracted = path.join(temporary, 'extract');
      await fs.mkdir(extracted, { recursive: true });
      await this.extractArchive(archive, extracted);
      await this.assertNoPathEscape(extracted);

      const entries = await fs.readdir(extracted, { withFileTypes: true });
      const root = entries.find((entry) => entry.isDirectory() && /^sonar-scanner/i.test(entry.name));
      if (!root) throw new Error('L’archive SonarScanner ne contient pas le dossier attendu.');

      const destination = path.join(this.toolDirectory('sonarscanner'), 'current');
      await fs.rm(destination, { recursive: true, force: true });
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.rename(path.join(extracted, root.name), destination).catch(async () => {
        await fs.cp(path.join(extracted, root.name), destination, { recursive: true });
      });
      const executable = this.managedExecutable('sonarscanner');
      if (!await this.exists(executable)) throw new Error('SonarScanner installé, mais son lanceur est introuvable dans l’archive.');
      if (process.platform !== 'win32') await fs.chmod(executable, 0o755).catch(() => {});

      await fs.writeFile(path.join(this.toolDirectory('sonarscanner'), 'provenance.json'), JSON.stringify({
        source: archiveUrl, version, asset: name, sha256: actual, platform, installedAt: new Date().toISOString()
      }, null, 2));
      await this.activateManagedPath();
      onProgress({ phase: 'verify', message: 'Vérification de sonar-scanner --version' });
      const result = await this.status('sonarscanner');
      if (!result.installed) throw new Error('SonarScanner installé, mais « sonar-scanner --version » n’a rien renvoyé. Un runtime Java est peut-être requis pour cette variante.');
      return result;
    } finally { await fs.rm(temporary, { recursive: true, force: true }).catch(() => {}); }
  }

  /**
   * Installs the official Snyk standalone binary into the extension's private
   * storage. No npm, no administrator rights, no system PATH change: the file
   * is verified against Snyk's published SHA-256 list before it is kept.
   */
  async installSnyk(tool, onProgress, asset = snykCliAsset()) {
    if (!asset) throw new Error(`Snyk CLI n’est pas distribué pour ${process.platform}/${process.arch}. Utilisez le mode Docker.`);
    const binaryUrl = `${tool.base}/${asset}`;
    onProgress({ phase: 'metadata', message: `${asset} depuis downloads.snyk.io` });
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-snyk-'));
    const downloaded = path.join(temporary, asset);
    try {
      await download(binaryUrl, downloaded, onProgress);
      const expected = parseSnykChecksums(await downloadText(`${tool.base}/sha256sums.txt.asc`), asset);
      if (!expected) throw new Error(`Snyk ne publie pas d’empreinte SHA-256 pour ${asset}. Installation refusée par sécurité.`);
      const actual = await sha256(downloaded);
      if (actual !== expected) throw new Error('Échec de vérification SHA-256 du binaire Snyk. Le fichier téléchargé a été supprimé.');
      onProgress({ phase: 'verify', message: 'Empreinte SHA-256 officielle vérifiée' });

      const executable = this.managedExecutable('snyk');
      await fs.mkdir(path.dirname(executable), { recursive: true });
      await fs.copyFile(downloaded, executable);
      if (process.platform !== 'win32') await fs.chmod(executable, 0o755).catch(() => {});

      await fs.writeFile(path.join(this.toolDirectory('snyk'), 'provenance.json'), JSON.stringify({
        source: binaryUrl, asset, sha256: actual, checksums: `${tool.base}/sha256sums.txt.asc`, installedAt: new Date().toISOString()
      }, null, 2));
      await this.activateManagedPath();
      onProgress({ phase: 'verify', message: 'Vérification de snyk --version' });
      const result = await this.status('snyk');
      if (!result.installed) throw new Error('Snyk CLI installé, mais « snyk --version » n’a rien renvoyé.');
      return result;
    } finally { await fs.rm(temporary, { recursive: true, force: true }).catch(() => {}); }
  }

  async extractArchive(archive, destination) {
    if (process.platform === 'win32') {
      return execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
        `Expand-Archive -LiteralPath '${archive.replaceAll("'", "''")}' -DestinationPath '${destination.replaceAll("'", "''")}' -Force`],
      { windowsHide: true, timeout: 300000 });
    }
    return execFileAsync('unzip', ['-q', '-o', archive, '-d', destination], { timeout: 300000 })
      .catch(() => { throw new Error('Extraction impossible : la commande « unzip » est requise sur cette plateforme.'); });
  }

  /** Zip Slip guard: nothing may resolve outside the extraction directory. */
  async assertNoPathEscape(root) {
    const base = path.resolve(root);
    const walk = async (directory) => {
      for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        const candidate = path.join(directory, entry.name);
        const resolved = await fs.realpath(candidate).catch(() => path.resolve(candidate));
        if (resolved !== base && !resolved.startsWith(`${base}${path.sep}`)) {
          throw new Error('Archive refusée : elle tente d’écrire en dehors du dossier d’installation.');
        }
        if (entry.isDirectory()) await walk(candidate);
      }
    };
    await walk(base);
  }

  async install(id, onProgress = () => {}) {
    const tool = TOOLS[id];
    if (!tool) throw new Error('Scanner inconnu.');
    await fs.mkdir(this.toolDirectory(id), { recursive: true });
    if (tool.kind === 'python') return this.installSemgrep(onProgress);
    if (tool.kind === 'sonarsource') return this.installSonarScanner(tool, onProgress);
    if (tool.kind === 'snyk') return this.installSnyk(tool, onProgress);
    const release = await this.githubRelease(tool);
    onProgress({ phase: 'metadata', message: `${release.version} trouvé sur ${tool.repo}` });
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), `security-center-${id}-`));
    const archive = path.join(temp, release.asset.name);
    try {
      await download(release.asset.browser_download_url, archive, onProgress);
      let expected = String(release.asset.digest || '').match(/sha256:([a-f0-9]{64})/i)?.[1]?.toLowerCase();
      if (!expected && release.checksum) {
        const checksums = await downloadText(release.checksum.browser_download_url);
        const expectedLine = checksums.split(/\r?\n/).find((line) => line.includes(release.asset.name));
        expected = expectedLine?.match(/[a-f0-9]{64}/i)?.[0]?.toLowerCase();
      }
      if (!expected) throw new Error(`La publication officielle ${release.version} ne fournit pas d’empreinte SHA-256 exploitable. Installation refusée par sécurité.`);
      const actual = await sha256(archive);
      if (actual !== expected) throw new Error('Échec de vérification SHA-256. Le fichier téléchargé a été supprimé.');
      onProgress({ phase: 'verify', message: 'Empreinte SHA-256 vérifiée' });
      if (archive.toLowerCase().endsWith('.zip')) {
        await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath '${archive.replaceAll("'", "''")}' -DestinationPath '${this.toolDirectory(id).replaceAll("'", "''")}' -Force`], { windowsHide: true, timeout: 120000 });
      } else await fs.copyFile(archive, this.managedExecutable(id));
      const found = await this.findExtractedExecutable(this.toolDirectory(id), `${tool.command}.exe`);
      if (found && found !== this.managedExecutable(id)) await fs.copyFile(found, this.managedExecutable(id));
      await fs.writeFile(path.join(this.toolDirectory(id), 'provenance.json'), JSON.stringify({ source: `https://github.com/${tool.repo}`, version: release.version, asset: release.asset.name, sha256: actual, installedAt: new Date().toISOString() }, null, 2));
      await this.activateManagedPath();
      const result = await this.status(id);
      if (!result.installed) throw new Error('Installation terminée, mais le binaire ne répond pas à --version.');
      return result;
    } finally { await fs.rm(temp, { recursive: true, force: true }).catch(() => {}); }
  }
  async findExtractedExecutable(directory, name) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const candidate = path.join(directory, entry.name);
      if (entry.isFile() && entry.name.toLowerCase() === name.toLowerCase()) return candidate;
      if (entry.isDirectory()) { const nested = await this.findExtractedExecutable(candidate, name); if (nested) return nested; }
    }
    return '';
  }
  async installSemgrep(onProgress) {
    const python = await this.findOnPath('python') || await this.findOnPath('python3');
    if (!python) throw new Error('Python est requis pour Semgrep. Installez Python puis réessayez.');
    const venv = path.join(this.toolDirectory('semgrep'), 'venv');
    onProgress({ phase: 'prepare', message: 'Création de l’environnement Python isolé' });
    await execFileAsync(python, ['-m', 'venv', venv], { windowsHide: true, timeout: 120000 });
    const py = path.join(venv, process.platform === 'win32' ? 'Scripts' : 'bin', process.platform === 'win32' ? 'python.exe' : 'python');
    onProgress({ phase: 'install', message: 'Installation de Semgrep depuis PyPI' });
    await execFileAsync(py, ['-m', 'pip', 'install', '--disable-pip-version-check', 'semgrep'], { windowsHide: true, timeout: 600000, maxBuffer: 10 * 1024 * 1024 });
    await this.activateManagedPath();
    const result = await this.status('semgrep');
    if (!result.installed) throw new Error('Semgrep installé, mais son exécutable ne répond pas.');
    return result;
  }
}

module.exports = {
  ScannerToolManager, TOOLS, sha256, commandVersion, versionInvocation,
  sonarScannerPlatform, compareVersions, SONARSCANNER_BASE, SONARSCANNER_PINNED_VERSION,
  snykCliAsset, parseSnykChecksums, SNYK_CLI_BASE
};
