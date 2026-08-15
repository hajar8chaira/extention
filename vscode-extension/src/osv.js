const { execFile } = require('child_process');
const { promisify } = require('util');
const { dockerCliArgs } = require('./docker');
const fs = require('fs');

const execFileAsync = promisify(execFile);

async function commandExists(command) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try { await execFileAsync(detector, [command], { windowsHide: true }); return true; } catch { return false; }
}

function scanArgs(sourcePath, callAnalysis = '') {
  return [
    'scan', 'source',
    '--format=json',
    '--verbosity=error',
    ...(callAnalysis ? [`--call-analysis=${callAnalysis}`] : []),
    '--recursive',
    '--allow-no-lockfiles',
    sourcePath
  ];
}

function containsCargoLock(directory, depth = 0) {
  if (depth > 6) return false;
  let entries;
  try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch { return false; }
  if (entries.some((entry) => entry.isFile() && entry.name === 'Cargo.lock')) return true;
  return entries.some((entry) => entry.isDirectory()
    && !['.git', 'node_modules', 'target', 'dist', 'vendor'].includes(entry.name)
    && containsCargoLock(require('path').join(directory, entry.name), depth + 1));
}

function supportedCallAnalysis(workspacePath) {
  return containsCargoLock(workspacePath) ? 'rust' : '';
}

function dockerArgs(workspacePath, callAnalysis = supportedCallAnalysis(workspacePath)) {
  return dockerCliArgs([
    'run', '--rm',
    '-v', `${workspacePath}:/src:ro`,
    'ghcr.io/google/osv-scanner:latest',
    ...scanArgs('/src', callAnalysis)
  ]);
}

async function resolveInvocation(mode, workspacePath) {
  if (mode !== 'docker' && await commandExists('osv-scanner')) return { executable: 'osv-scanner', args: scanArgs(workspacePath, supportedCallAnalysis(workspacePath)), cwd: workspacePath, mode: 'local' };
  if (mode === 'local') throw new Error('OSV-Scanner local est introuvable. Ouvrez Configuration des scanners ou choisissez Auto.');
  if (!await commandExists('docker')) throw new Error('Ni OSV-Scanner local ni Docker ne sont disponibles.');
  return { executable: 'docker', args: dockerArgs(workspacePath), cwd: workspacePath, mode: 'docker' };
}

async function runOsv({ workspacePath, mode = 'auto', timeoutMs = 600000, signal }) {
  const invocation = await resolveInvocation(mode, workspacePath);
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, {
      cwd: invocation.cwd,
      timeout: timeoutMs,
      maxBuffer: 100 * 1024 * 1024,
      windowsHide: true,
      signal
    });
    return { payload: JSON.parse(stdout), stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Scan OSV-Scanner annulé.');
    if (error.stdout) {
      try {
        return { payload: JSON.parse(error.stdout), stderr: error.stderr || '', mode: invocation.mode };
      } catch {
        // Report a useful scanner error below.
      }
    }
    if (error.killed) throw new Error(`Le scan OSV-Scanner a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec d’OSV-Scanner.');
  }
}

module.exports = { runOsv, resolveInvocation, scanArgs, containsCargoLock, supportedCallAnalysis, dockerArgs };
