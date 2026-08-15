const { execFile } = require('child_process');
const { promisify } = require('util');
const { dockerCliArgs } = require('./docker');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const execFileAsync = promisify(execFile);

async function commandExists(command) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try { await execFileAsync(detector, [command], { windowsHide: true }); return true; }
  catch { return false; }
}

function scanArgs(sourcePath, configPath = '') {
  const args = ['dir', '--report-format', 'json', '--report-path', '-', '--redact', '--no-banner', '--exit-code', '0'];
  if (configPath) args.push('--config', configPath);
  args.push(sourcePath);
  return args;
}

function historyScanArgs(sourcePath, sinceCommit = '', configPath = '') {
  const logRange = sinceCommit ? `${sinceCommit}..HEAD` : '--all';
  const args = ['git', '--report-format', 'json', '--report-path', '-', '--redact', '--no-banner', '--exit-code', '0', `--log-opts=${logRange}`];
  if (configPath) args.push('--config', configPath);
  args.push(sourcePath);
  return args;
}

function dockerArgs(workspacePath, configMount = '') {
  return dockerCliArgs(['run', '--rm', '-v', `${workspacePath}:/src:ro`, ...(configMount ? ['-v', `${configMount}:/tmp/security-center-gitleaks.toml:ro`] : []), 'zricethezav/gitleaks:latest', ...scanArgs('/src', configMount ? '/tmp/security-center-gitleaks.toml' : '')]);
}

function dockerHistoryArgs(workspacePath, sinceCommit = '', configPath = '') {
  const dockerConfig = configPath ? `/src/${String(configPath).replaceAll('\\', '/').replace(/^\.\//, '')}` : '';
  return dockerCliArgs(['run', '--rm', '-v', `${workspacePath}:/src:ro`, 'zricethezav/gitleaks:latest', ...historyScanArgs('/src', sinceCommit, dockerConfig)]);
}

async function resolveInvocation(mode, workspacePath) {
  if (mode !== 'docker' && await commandExists('gitleaks')) return { executable: 'gitleaks', args: scanArgs(workspacePath), cwd: workspacePath, mode: 'local' };
  if (mode === 'local') throw new Error('Gitleaks local est introuvable. Installez-le ou choisissez le mode Docker.');
  if (!await commandExists('docker')) throw new Error('Ni Gitleaks local ni Docker ne sont disponibles.');
  return { executable: 'docker', args: dockerArgs(workspacePath), cwd: workspacePath, mode: 'docker' };
}

function globToGitleaksRegex(glob) {
  const normalized = String(glob).replaceAll('\\', '/').replace(/^\.\//, '');
  const escaped = normalized.replace(/[.+^${}()|[\]\\]/g, '\\$&').replaceAll('**', '§§').replaceAll('*', '[^/]*').replaceAll('§§', '.*').replaceAll('?', '.');
  return `(?:^|/)${escaped}(?:$|/)`;
}

async function generatedConfig(workspacePath, configPath, exclusions = []) {
  if (!configPath && !exclusions.length) return null;
  let content = 'title = "Security Center generated rules"\n\n[extend]\nuseDefault = true\n';
  if (configPath) {
    const root = path.resolve(workspacePath);
    const resolved = path.resolve(root, configPath);
    if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) throw new Error('gitleaks.config doit rester dans le workspace.');
    content = await fs.readFile(resolved, 'utf8');
  }
  if (exclusions.length) {
    if (/^\s*\[allowlist\]/m.test(content)) throw new Error('La configuration Gitleaks contient déjà [allowlist] ; fusionnez-y exclusions.global_files pour éviter une politique ambiguë.');
    const paths = exclusions.map((item) => `  '''${globToGitleaksRegex(item)}'''`).join(',\n');
    content += `\n\n[allowlist]\ndescription = "Security Center central exclusions"\npaths = [\n${paths}\n]\n`;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-gitleaks-'));
  const filePath = path.join(directory, 'gitleaks.toml');
  await fs.writeFile(filePath, content, 'utf8');
  return { directory, filePath };
}

async function runGitleaks({ workspacePath, mode = 'auto', timeoutMs = 180000, signal, history = false, sinceCommit = '', configPath = '', exclusions = [] }) {
  const invocation = await resolveInvocation(mode, workspacePath);
  const generated = await generatedConfig(workspacePath, configPath, exclusions);
  const effectiveConfig = generated?.filePath || '';
  if (history) invocation.args = invocation.mode === 'docker'
    ? dockerCliArgs(['run', '--rm', '-v', `${workspacePath}:/src:ro`, ...(effectiveConfig ? ['-v', `${effectiveConfig}:/tmp/security-center-gitleaks.toml:ro`] : []), 'zricethezav/gitleaks:latest', ...historyScanArgs('/src', sinceCommit, effectiveConfig ? '/tmp/security-center-gitleaks.toml' : '')])
    : historyScanArgs(workspacePath, sinceCommit, effectiveConfig);
  else if (effectiveConfig) invocation.args = invocation.mode === 'docker'
    ? dockerArgs(workspacePath, effectiveConfig)
    : scanArgs(workspacePath, effectiveConfig);
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 50 * 1024 * 1024, windowsHide: true, signal
    });
    return { payload: stdout.trim() ? JSON.parse(stdout) : [], stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Scan Gitleaks annulé.');
    if (error.stdout) {
      try { return { payload: JSON.parse(error.stdout), stderr: error.stderr || '', mode: invocation.mode }; }
      catch { /* handled below */ }
    }
    if (error.killed) throw new Error(`Le scan Gitleaks a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec de Gitleaks.');
  } finally { if (generated) await fs.rm(generated.directory, { recursive: true, force: true }); }
}

module.exports = { runGitleaks, resolveInvocation, scanArgs, dockerArgs, historyScanArgs, dockerHistoryArgs, globToGitleaksRegex, generatedConfig };
