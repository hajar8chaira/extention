const { execFile } = require('child_process');
const { promisify } = require('util');
const { dockerCliArgs } = require('./docker');
const execFileAsync = promisify(execFile);

async function commandExists(command) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try { await execFileAsync(detector, [command], { windowsHide: true }); return true; }
  catch { return false; }
}

function scanOptions(config, exclusions = {}) {
  const configs = Array.isArray(config) ? config : [config];
  const args = configs.flatMap((item) => ['--config', item]);
  for (const pattern of exclusions.files || []) args.push('--exclude', pattern);
  for (const rule of exclusions.rules || []) args.push('--exclude-rule', rule);
  return args;
}

function localArgs(config, exclusions = {}, targets = []) {
  return ['scan', ...scanOptions(config, exclusions), '--json', '--metrics=off', ...(targets.length ? targets : ['.'])];
}

function dockerArgs(workspacePath, config, exclusions = {}, targets = []) {
  const mount = `${workspacePath}:/src`;
  return dockerCliArgs(['run', '--rm', '-v', mount, '-w', '/src', 'semgrep/semgrep', 'semgrep', 'scan', ...scanOptions(config, exclusions), '--json', '--metrics=off', ...(targets.length ? targets : ['.'])]);
}

async function resolveInvocation(mode, workspacePath, config, exclusions = {}, targets = []) {
  if (mode !== 'docker' && await commandExists('semgrep')) {
    return { executable: 'semgrep', args: localArgs(config, exclusions, targets), cwd: workspacePath, mode: 'local' };
  }
  if (mode === 'local') throw new Error('Semgrep local est introuvable. Installez-le ou choisissez le mode Docker.');
  if (!await commandExists('docker')) throw new Error('Ni Semgrep local ni Docker ne sont disponibles.');
  return { executable: 'docker', args: dockerArgs(workspacePath, config, exclusions, targets), cwd: workspacePath, mode: 'docker' };
}

async function runSemgrep({ workspacePath, mode = 'auto', config = 'p/security-audit', exclusions = {}, targets = [], timeoutMs = 180000, signal }) {
  const invocation = await resolveInvocation(mode, workspacePath, config, exclusions, targets);
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 50 * 1024 * 1024, windowsHide: true, signal
    });
    return { payload: JSON.parse(stdout), stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Scan Semgrep annulé.');
    // Semgrep may return a non-zero status while still producing valid JSON.
    if (error.stdout) {
      try { return { payload: JSON.parse(error.stdout), stderr: error.stderr || '', mode: invocation.mode }; }
      catch { /* handled below */ }
    }
    if (error.killed) throw new Error(`Le scan Semgrep a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec de Semgrep.');
  }
}

module.exports = { runSemgrep, resolveInvocation, scanOptions, localArgs, dockerArgs };
