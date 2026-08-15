const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const TOOLS = Object.freeze({
  semgrep: { label: 'Semgrep', kind: 'python', command: 'semgrep', repo: 'semgrep/semgrep', purpose: 'Analyse statique du code (SAST)' },
  gitleaks: { label: 'Gitleaks', kind: 'github', command: 'gitleaks', repo: 'gitleaks/gitleaks', purpose: 'Détection de secrets', asset: /gitleaks_.*_windows_x64\.zip$/i, checksum: /checksums\.txt$/i },
  trivy: { label: 'Trivy', kind: 'github', command: 'trivy', repo: 'aquasecurity/trivy', purpose: 'Dépendances, conteneurs et IaC', asset: /trivy_.*_windows-64bit\.zip$/i, checksum: /checksums\.txt$/i },
  osv: { label: 'OSV-Scanner', kind: 'github', command: 'osv-scanner', repo: 'google/osv-scanner', purpose: 'Vulnérabilités des dépendances', asset: /osv-scanner_windows_amd64\.exe$/i, checksum: /(checksums|sha256).*\.txt$/i }
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

async function commandVersion(executable, timeout = 30000) {
  try {
    const { stdout, stderr } = await execFileAsync(executable, ['--version'], { windowsHide: true, timeout });
    return String(stdout || stderr).trim().split(/\r?\n/)[0] || 'installé';
  } catch { return ''; }
}

class ScannerToolManager {
  constructor(storagePath) { this.root = path.join(storagePath, 'scanner-tools'); }
  toolDirectory(id) { return path.join(this.root, id); }
  managedExecutable(id) {
    if (id === 'semgrep') return path.join(this.toolDirectory(id), 'venv', process.platform === 'win32' ? 'Scripts' : 'bin', process.platform === 'win32' ? 'semgrep.exe' : 'semgrep');
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
    const version = executable ? await commandVersion(executable, versionTimeout) : '';
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
  async install(id, onProgress = () => {}) {
    const tool = TOOLS[id];
    if (!tool) throw new Error('Scanner inconnu.');
    await fs.mkdir(this.toolDirectory(id), { recursive: true });
    if (tool.kind === 'python') return this.installSemgrep(onProgress);
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

module.exports = { ScannerToolManager, TOOLS, sha256, commandVersion };
