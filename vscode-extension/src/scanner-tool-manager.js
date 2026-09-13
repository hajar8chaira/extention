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

/**
 * Comparable form of a path.
 *
 * On Windows the filesystem does not distinguish case: `C:\A` and `c:\a` name
 * the same directory, and comparing them byte for byte is wrong. On a
 * case-sensitive system `A` and `a` are two different directories, and lowering
 * the case there would open an escape.
 */
function comparablePath(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
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
  // Nuclei is a DAST engine, installed through the exact same official release
  // + SHA-256 contract as the scanners. Its templates are a second artefact,
  // published in a separate repository, and are installed by `src/nuclei.js`:
  // the binary alone detects nothing.
  nuclei: {
    label: 'Nuclei', kind: 'github', command: 'nuclei', repo: 'projectdiscovery/nuclei',
    purpose: 'Analyse dynamique par templates (DAST)',
    asset: /^nuclei_[\d.]+_windows_amd64\.zip$/i, checksum: /_checksums\.txt$/i,
    versionArgs: ['-version'], dynamic: true
  },
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

/** Installation lifecycle, shared by the manager and the UI. */
const INSTALL_PHASE = Object.freeze({
  DOWNLOADING: 'downloading',
  VERIFYING: 'verifying',
  INSTALLING: 'installing',
  READY: 'ready',
  FAILED: 'failed',
  CANCELLED: 'cancelled'
});

const INSTALL_ERROR = Object.freeze({
  TIMEOUT: 'TIMEOUT',
  STALLED: 'STALLED',
  CANCELLED: 'CANCELLED',
  // The connection died mid-transfer: the socket was reset or closed before the
  // announced size arrived. Node reports this as a bare « aborted ».
  INTERRUPTED: 'INTERRUPTED',
  // The host could not be reached at all: DNS, firewall or proxy.
  UNREACHABLE: 'UNREACHABLE',
  // The TLS chain was refused, typically behind HTTPS inspection.
  TLS: 'TLS',
  // The downloaded artefact is not a readable archive.
  ARCHIVE: 'ARCHIVE'
});

/** No useful byte for this long means the transfer is dead, not slow. */
const DEFAULT_STALL_MS = 120000;
/** Ceiling for one HTTP response to complete. Large binaries need room. */
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 900000;
/**
 * Progress is a signal for a human, not a byte log. A 60 MB binary arrives in
 * roughly nine hundred chunks; forwarding every one of them let the caller
 * schedule that many UI refreshes, each re-probing every managed tool, until the
 * event loop was so far behind that the download socket itself was reset. One
 * event per interval carries the exact same information.
 */
const DEFAULT_PROGRESS_INTERVAL_MS = 250;

class InstallCancelledError extends Error {
  constructor(message = 'Installation annulée.') {
    super(message);
    this.name = 'InstallCancelledError';
    this.code = INSTALL_ERROR.CANCELLED;
    this.cancelled = true;
  }
}

class InstallTimeoutError extends Error {
  constructor(message, code = INSTALL_ERROR.TIMEOUT) {
    super(message);
    this.name = 'InstallTimeoutError';
    this.code = code;
  }
}

class InstallNetworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'InstallNetworkError';
    this.code = code;
  }
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw new InstallCancelledError();
}

/**
 * Turns a transport failure into something a user can act on.
 *
 * Node surfaces a mid-transfer reset as a bare « aborted », which used to reach
 * the card verbatim and explained nothing. Cancellations and timeouts already
 * carry their own explicit message and are returned untouched.
 */
function describeTransportError(error, url = '') {
  if (error?.cancelled || error?.code === INSTALL_ERROR.CANCELLED) return error;
  if (error instanceof InstallTimeoutError || error instanceof InstallNetworkError) return error;
  const host = (() => { try { return new URL(url).host; } catch { return ''; } })();
  const origin = host ? ` depuis ${host}` : '';
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  if (/^(ENOTFOUND|EAI_AGAIN)$/.test(code)) {
    return new InstallNetworkError(`Serveur de téléchargement introuvable${origin} : la résolution DNS a échoué. Vérifiez la connexion réseau ou le proxy.`, INSTALL_ERROR.UNREACHABLE);
  }
  if (/^(ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EHOSTDOWN)$/.test(code)) {
    return new InstallNetworkError(`Serveur de téléchargement inaccessible${origin}. Un pare-feu ou un proxy bloque probablement la connexion.`, INSTALL_ERROR.UNREACHABLE);
  }
  if (/CERT|SELF_SIGNED|UNABLE_TO_(GET|VERIFY)/.test(code)) {
    return new InstallNetworkError(`Certificat TLS refusé${origin} (${code}). Un proxy d’inspection HTTPS intercepte la connexion.`, INSTALL_ERROR.TLS);
  }
  // Node reports a socket reset in mid-transfer as a bare « aborted ». Checked
  // last so a more precise code always wins over the generic message.
  if (/^(ECONNRESET|ECONNABORTED|EPIPE|ERR_STREAM_PREMATURE_CLOSE)$/.test(code) || /^aborted$/i.test(message.trim())) {
    return new InstallNetworkError(`Connexion interrompue pendant le téléchargement${origin}. Le fichier partiel a été supprimé ; relancez l’installation.`, INSTALL_ERROR.INTERRUPTED);
  }
  return error;
}

function request(url, headers = {}, { signal, timeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new InstallCancelledError());
    // VS Code/Node does not always inherit the Windows certificate store.
    // Merge it with Node's bundled roots so official downloads continue to
    // use strict TLS validation behind managed/corporate HTTPS inspection.
    const systemCa = typeof tls.getCACertificates === 'function'
      ? [...new Set([...tls.getCACertificates('default'), ...tls.getCACertificates('system')])]
      : undefined;
    // A connection that never answers used to hang the installer forever: the
    // request had no socket timeout and no way to be aborted, so a stalled TLS
    // handshake left the UI frozen on whatever percentage it had reached.
    let settled = false;
    let active = null;
    const cleanup = () => { signal?.removeEventListener?.('abort', onAbort); };
    const fail = (error) => { if (settled) return; settled = true; cleanup(); active?.destroy(); reject(error); };
    function onAbort() { fail(new InstallCancelledError()); }
    signal?.addEventListener?.('abort', onAbort, { once: true });

    const run = (current, redirects = 0) => {
      active = https.get(current, { ca: systemCa, headers: { 'User-Agent': 'security-center-vscode', Accept: 'application/vnd.github+json', ...headers } }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location && redirects < 5) {
          response.resume(); return run(new URL(response.headers.location, current).toString(), redirects + 1);
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          response.resume(); return fail(new Error(`Téléchargement refusé (HTTP ${response.statusCode}).`));
        }
        if (settled) { response.resume(); return; }
        settled = true; cleanup();
        // The abort still has to reach the body stream once headers are in.
        signal?.addEventListener?.('abort', () => response.destroy(new InstallCancelledError()), { once: true });
        resolve(response);
      });
      active.setTimeout(timeoutMs, () => fail(new InstallTimeoutError(`Téléchargement interrompu après ${Math.round(timeoutMs / 1000)} s.`)));
      active.on('error', (error) => fail(describeTransportError(error, current)));
    };
    run(url);
  });
}

/**
 * Downloads to `destination`, abortable and never unbounded.
 *
 * Three failure modes are now distinguishable instead of hanging: the caller
 * cancelled, the connection never answered, or bytes stopped arriving. The
 * partial file is removed on every one of them — and only that file.
 *
 * `total` is reported as `0` when the server sends no Content-Length; the caller
 * must then show an indeterminate state rather than compute a percentage from a
 * denominator it does not have.
 */
async function download(url, destination, onProgress = () => {}, { signal, timeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS, stallTimeoutMs = DEFAULT_STALL_MS, progressIntervalMs = DEFAULT_PROGRESS_INTERVAL_MS } = {}) {
  throwIfAborted(signal);
  const response = await request(url, {}, { signal, timeoutMs });
  const total = Number(response.headers['content-length'] || 0);
  let received = 0;
  let lastProgressAt = Date.now();
  // Stall detection reads every chunk; the caller does not. `lastEmitAt` only
  // rate-limits what leaves this function, so a slow transfer is still detected
  // at full resolution.
  let lastEmitAt = 0;
  const emit = (force = false) => {
    const now = Date.now();
    if (!force && now - lastEmitAt < progressIntervalMs) return;
    lastEmitAt = now;
    onProgress({ phase: INSTALL_PHASE.DOWNLOADING, received, total });
  };
  // The body can fail between the headers and the first read — `fs.open` is
  // awaited in between. Without a listener on that window the reset became an
  // unhandled stream error instead of a failed installation.
  let streamError = null;
  const captureStreamError = (error) => { streamError = streamError || error; };
  response.on('error', captureStreamError);
  const handle = await fs.open(destination, 'w');
  try {
    const stallTimer = setInterval(() => {
      if (Date.now() - lastProgressAt > stallTimeoutMs) {
        response.destroy(new InstallTimeoutError('Téléchargement interrompu — aucune progression détectée.', INSTALL_ERROR.STALLED));
      }
    }, Math.max(1000, Math.min(stallTimeoutMs, 5000)));
    try {
      emit(true);
      for await (const chunk of response) {
        throwIfAborted(signal);
        await handle.write(chunk);
        received += chunk.length;
        lastProgressAt = Date.now();
        emit();
      }
      // The last chunk must always be reported, otherwise the bar can stop
      // short of the size the server announced.
      emit(true);
    } finally { clearInterval(stallTimer); }
    if (streamError) throw streamError;
  } catch (error) {
    await handle.close().catch(() => {});
    // Only the incomplete artefact of this run. Never an installed version,
    // never another tool's cache, never any configuration.
    await fs.rm(destination, { force: true }).catch(() => {});
    throw describeTransportError(error, url);
  } finally { response.off?.('error', captureStreamError); }
  await handle.close();
  // A truncated body that ends cleanly is still a failed download: refuse it
  // here rather than let the SHA-256 check blame the publisher.
  if (total > 0 && received !== total) {
    await fs.rm(destination, { force: true }).catch(() => {});
    throw new InstallNetworkError(`Téléchargement incomplet : ${received} octets reçus sur ${total} annoncés. Connexion interrompue ; relancez l’installation.`, INSTALL_ERROR.INTERRUPTED);
  }
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
      // Nuclei answers on stderr, and prints its ASCII banner — which contains
      // the version too — before the line that actually names the engine.
      || output.match(/Nuclei Engine Version:\s*(v?[0-9][\w.-]*)/i)?.[1]
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
    // The Snyk CLI needs the same allowance for a different reason: it is a
    // single 181 MB self-extracting binary, and its very first launch after
    // download — the one `install()` performs — measured 21 s on a warm machine,
    // most of it Windows scanning a freshly written executable of that size.
    // Under the 30 s default a perfectly good installation was one slow disk
    // away from being declared « n’a rien renvoyé ».
    const versionTimeout = id === 'semgrep' || id === 'snyk' ? 60000 : 30000;
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
  async installSonarScanner(tool, onProgress, platform = sonarScannerPlatform(), { signal } = {}) {
    if (!platform) throw new Error(`SonarScanner CLI n’est pas distribué pour ${process.platform}/${process.arch}. Utilisez le mode Docker.`);
    const version = await this.latestSonarScannerVersion(tool.version);
    const name = `sonar-scanner-cli-${version}-${platform}.zip`;
    const archiveUrl = `${tool.base}/${name}`;
    onProgress({ phase: 'metadata', message: `${version} (${platform}) depuis binaries.sonarsource.com` });
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-sonarscanner-'));
    const archive = path.join(temporary, name);
    try {
      await download(archiveUrl, archive, onProgress, { signal });
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
  async installSnyk(tool, onProgress, asset = snykCliAsset(), { signal } = {}) {
    if (!asset) throw new Error(`Snyk CLI n’est pas distribué pour ${process.platform}/${process.arch}. Utilisez le mode Docker.`);
    const binaryUrl = `${tool.base}/${asset}`;
    onProgress({ phase: 'metadata', message: `${asset} depuis downloads.snyk.io` });
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-snyk-'));
    const downloaded = path.join(temporary, asset);
    try {
      await download(binaryUrl, downloaded, onProgress, { signal });
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

  /**
   * Zip Slip guard: nothing may resolve outside the extraction directory.
   *
   * Both sides of the comparison are canonicalised the same way. They were not:
   * the root came from `path.resolve()`, which keeps the drive letter exactly as
   * supplied, while every entry went through `fs.realpath()`, which returns the
   * filesystem's canonical form. VS Code hands its storage path to the extension
   * through `Uri.fsPath`, whose drive letter is lower-case, so the root read
   * `c:\…` and the entries `C:\…`. No entry then "started with" the root, and the
   * very first one — the archive's own root folder — was refused. The rule is
   * unchanged: anything resolving outside the root is still rejected.
   */
  async assertNoPathEscape(root) {
    // `realpath` on the root too: a junction or symlink anywhere in the parent
    // chain would otherwise move it out of its own subtree.
    const baseReal = await fs.realpath(root).catch(() => path.resolve(root));
    const base = comparablePath(baseReal);
    const prefix = `${base}${path.sep}`;
    const walk = async (directory) => {
      for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        const candidate = path.join(directory, entry.name);
        // `realpath` follows symlinks and junctions: an entry pointing outside
        // the root is seen here whatever its name inside the archive.
        const resolved = comparablePath(await fs.realpath(candidate).catch(() => path.resolve(candidate)));
        if (resolved !== base && !resolved.startsWith(prefix)) {
          throw new Error('Archive refusée : elle tente d’écrire en dehors du dossier d’installation.');
        }
        if (entry.isDirectory()) await walk(candidate);
      }
    };
    await walk(baseReal);
  }

  async install(id, onProgress = () => {}, { signal } = {}) {
    const tool = TOOLS[id];
    if (!tool) throw new Error('Scanner inconnu.');
    await fs.mkdir(this.toolDirectory(id), { recursive: true });
    if (tool.kind === 'python') return this.installSemgrep(onProgress, { signal });
    if (tool.kind === 'sonarsource') return this.installSonarScanner(tool, onProgress, sonarScannerPlatform(), { signal });
    if (tool.kind === 'snyk') return this.installSnyk(tool, onProgress, snykCliAsset(), { signal });
    const release = await this.githubRelease(tool);
    onProgress({ phase: 'metadata', message: `${release.version} trouvé sur ${tool.repo}` });
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), `security-center-${id}-`));
    const archive = path.join(temp, release.asset.name);
    try {
      await download(release.asset.browser_download_url, archive, onProgress, { signal });
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
        // A PowerShell extraction error says nothing useful to a user; the only
        // actionable reading of it is « the archive that arrived is unusable ».
        await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath '${archive.replaceAll("'", "''")}' -DestinationPath '${this.toolDirectory(id).replaceAll("'", "''")}' -Force`], { windowsHide: true, timeout: 120000 })
          .catch(() => { throw new InstallNetworkError(`Archive invalide : ${release.asset.name} n’a pas pu être décompressée. Relancez l’installation.`, INSTALL_ERROR.ARCHIVE); });
      } else await fs.copyFile(archive, this.managedExecutable(id));
      const found = await this.findExtractedExecutable(this.toolDirectory(id), `${tool.command}.exe`);
      // Expand-Archive reports an unreadable archive as a non-terminating error
      // and still exits 0, so an empty extraction is the only signal left. Said
      // here it names the cause, instead of a later « ne répond pas à --version ».
      if (!found && archive.toLowerCase().endsWith('.zip')) {
        throw new InstallNetworkError(`Archive invalide : ${release.asset.name} ne contient pas ${tool.command}.exe. Le téléchargement est probablement corrompu ; relancez l’installation.`, INSTALL_ERROR.ARCHIVE);
      }
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
  /**
   * Runs one installation child process under the run's abort signal.
   *
   * A process killed by that signal is a cancellation, not a failure: without
   * this mapping the card would announce an error for something the user asked
   * for. Only the step's own process is affected — nothing else is touched.
   */
  async cancellableStep(run, signal) {
    throwIfAborted(signal);
    try { return await run(); }
    catch (error) {
      if (signal?.aborted || error?.name === 'AbortError' || error?.code === 'ABORT_ERR') throw new InstallCancelledError();
      throw error;
    }
  }
  async installSemgrep(onProgress, { signal } = {}) {
    throwIfAborted(signal);
    const python = await this.findOnPath('python') || await this.findOnPath('python3');
    if (!python) throw new Error('Python est requis pour Semgrep. Installez Python puis réessayez.');
    const venv = path.join(this.toolDirectory('semgrep'), 'venv');
    onProgress({ phase: 'prepare', message: 'Création de l’environnement Python isolé' });
    // Semgrep is the one installer that spends its whole time inside child
    // processes rather than a download. Until the signal reached them, pressing
    // « Annuler » was ignored for the ~90 s pip takes, and the run still ended
    // by declaring the tool ready.
    await this.cancellableStep(() => execFileAsync(python, ['-m', 'venv', venv], { windowsHide: true, timeout: 120000, signal }), signal);
    const py = path.join(venv, process.platform === 'win32' ? 'Scripts' : 'bin', process.platform === 'win32' ? 'python.exe' : 'python');
    onProgress({ phase: 'install', message: 'Installation de Semgrep depuis PyPI' });
    await this.cancellableStep(() => execFileAsync(py, ['-m', 'pip', 'install', '--disable-pip-version-check', 'semgrep'], { windowsHide: true, timeout: 600000, maxBuffer: 10 * 1024 * 1024, signal }), signal);
    throwIfAborted(signal);
    await this.activateManagedPath();
    const result = await this.status('semgrep');
    if (!result.installed) throw new Error('Semgrep installé, mais son exécutable ne répond pas.');
    return result;
  }
}

module.exports = {
  ScannerToolManager, TOOLS, sha256, commandVersion, versionInvocation, comparablePath,
  INSTALL_PHASE, INSTALL_ERROR, DEFAULT_STALL_MS, DEFAULT_DOWNLOAD_TIMEOUT_MS,
  DEFAULT_PROGRESS_INTERVAL_MS, describeTransportError,
  InstallCancelledError, InstallTimeoutError, InstallNetworkError, download, downloadText, request,
  sonarScannerPlatform, compareVersions, SONARSCANNER_BASE, SONARSCANNER_PINNED_VERSION,
  snykCliAsset, parseSnykChecksums, SNYK_CLI_BASE
};
