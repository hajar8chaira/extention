const { execFile } = require('child_process');
const { promisify } = require('util');
const { dockerCliArgs } = require('./docker');
const execFileAsync = promisify(execFile);

async function commandExists(command) {
  const detector = process.platform === 'win32' ? 'where.exe' : 'which';
  try { await execFileAsync(detector, [command], { windowsHide: true }); return true; }
  catch { return false; }
}

function scanArgs(sourcePath, exclusions = []) {
  const args = ['fs', '--format', 'json', '--scanners', 'vuln,misconfig', '--quiet'];
  for (const pattern of exclusions) args.push('--skip-files', pattern);
  args.push(sourcePath);
  return args;
}

function imageScanArgs(imageName) {
  return ['image', '--format', 'json', '--scanners', 'vuln,misconfig', '--quiet', imageName];
}

function dockerArgs(workspacePath, exclusions = []) {
  return dockerCliArgs([
    'run', '--rm',
    '-v', `${workspacePath}:/src:ro`,
    '-v', 'security-center-trivy-cache:/root/.cache/trivy',
    'aquasec/trivy:latest',
    ...scanArgs('/src', exclusions)
  ]);
}

function dockerImageArgs(imageName) {
  return dockerCliArgs([
    'run', '--rm',
    '-v', 'security-center-trivy-cache:/root/.cache/trivy',
    'aquasec/trivy:latest',
    ...imageScanArgs(imageName)
  ]);
}

function sbomArgs(sourcePath) {
  return ['fs', '--format', 'cyclonedx', '--scanners', 'vuln', '--quiet', sourcePath];
}

function dockerSbomArgs(workspacePath) {
  return dockerCliArgs([
    'run', '--rm',
    '-v', `${workspacePath}:/src:ro`,
    '-v', 'security-center-trivy-cache:/root/.cache/trivy',
    'aquasec/trivy:latest',
    ...sbomArgs('/src')
  ]);
}

function imageSbomArgs(imageName) {
  return ['image', '--format', 'cyclonedx', '--scanners', 'vuln', '--quiet', imageName];
}

function dockerImageSbomArgs(imageName) {
  return dockerCliArgs([
    'run', '--rm',
    '-v', 'security-center-trivy-cache:/root/.cache/trivy',
    '-v', '/var/run/docker.sock:/var/run/docker.sock',
    'aquasec/trivy:latest',
    ...imageSbomArgs(imageName)
  ]);
}

async function generateSbom({ workspacePath, mode = 'auto', imageName = '', timeoutMs = 300000, signal }) {
  const useLocal = mode !== 'docker' && await commandExists('trivy');
  if (mode === 'local' && !useLocal) throw new Error('Trivy local est introuvable. Installez-le ou choisissez le mode Docker.');
  if (!useLocal && !await commandExists('docker')) throw new Error('Ni Trivy local ni Docker ne sont disponibles.');
  const targetImage = imageName.trim();
  const invocation = useLocal
    ? { executable: 'trivy', args: targetImage ? imageSbomArgs(targetImage) : sbomArgs(workspacePath), cwd: workspacePath, mode: 'local' }
    : { executable: 'docker', args: targetImage ? dockerImageSbomArgs(targetImage) : dockerSbomArgs(workspacePath), cwd: workspacePath, mode: 'docker' };
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
    });
    const payload = JSON.parse(stdout);
    if (payload.bomFormat !== 'CycloneDX' || !Array.isArray(payload.components)) {
      throw new Error('Trivy n’a pas produit un document CycloneDX valide.');
    }
    return { payload, stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Génération SBOM annulée.');
    if (error.killed) throw new Error(`La génération SBOM a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec de la génération SBOM.');
  }
}

async function resolveInvocation(mode, workspacePath, exclusions = []) {
  if (mode !== 'docker' && await commandExists('trivy')) return { executable: 'trivy', args: scanArgs(workspacePath, exclusions), cwd: workspacePath, mode: 'local' };
  if (mode === 'local') throw new Error('Trivy local est introuvable. Installez-le ou choisissez le mode Docker.');
  if (!await commandExists('docker')) throw new Error('Ni Trivy local ni Docker ne sont disponibles.');
  return { executable: 'docker', args: dockerArgs(workspacePath, exclusions), cwd: workspacePath, mode: 'docker' };
}

async function runTrivy({ workspacePath, mode = 'auto', timeoutMs = 300000, imageName = '', exclusions = [], signal }) {
  const invocation = await resolveInvocation(mode, workspacePath, exclusions);
  try {
    const { stdout, stderr } = await execFileAsync(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
    });
    const payload = JSON.parse(stdout);
    if (imageName.trim()) {
      const imageInvocation = invocation.mode === 'docker'
        ? { executable: 'docker', args: dockerImageArgs(imageName.trim()) }
        : { executable: 'trivy', args: imageScanArgs(imageName.trim()) };
      const imageResult = await execFileAsync(imageInvocation.executable, imageInvocation.args, {
        cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
      });
      payload.Results = [...(payload.Results || []), ...(JSON.parse(imageResult.stdout).Results || [])];
    }
    return { payload, stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Scan Trivy annulé.');
    if (error.stdout) {
      try { return { payload: JSON.parse(error.stdout), stderr: error.stderr || '', mode: invocation.mode }; }
      catch { /* handled below */ }
    }
    if (error.killed) throw new Error(`Le scan Trivy a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec de Trivy.');
  }
}

module.exports = { runTrivy, generateSbom, resolveInvocation, scanArgs, dockerArgs, imageScanArgs, dockerImageArgs, sbomArgs, dockerSbomArgs, imageSbomArgs, dockerImageSbomArgs };
