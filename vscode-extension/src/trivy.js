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

const TRIVY_IMAGE = 'aquasec/trivy:latest';
const TRIVY_CACHE = Object.freeze(['-v', 'security-center-trivy-cache:/root/.cache/trivy']);

/** CI container run. An image target is pulled from its registry: no Docker socket is ever mounted. */
function containerArgs(container, command) {
  return container.runArgs(TRIVY_IMAGE, command, { volumes: TRIVY_CACHE });
}

async function generateSbom({ workspacePath, mode = 'auto', imageName = '', timeoutMs = 300000, signal, containerRuntime = null }) {
  const container = containerRuntime ? await containerRuntime.forScanner(TRIVY_IMAGE) : null;
  const targetImage = imageName.trim();
  let invocation;
  if (container) {
    invocation = { executable: 'docker', args: containerArgs(container, targetImage ? imageSbomArgs(targetImage) : sbomArgs(container.root)), cwd: workspacePath, mode: 'docker' };
  } else {
    const useLocal = mode !== 'docker' && await commandExists('trivy');
    if (mode === 'local' && !useLocal) throw new Error('Trivy local est introuvable. Installez-le ou choisissez le mode Docker.');
    if (!useLocal && !await commandExists('docker')) throw new Error('Ni Trivy local ni Docker ne sont disponibles.');
    invocation = useLocal
      ? { executable: 'trivy', args: targetImage ? imageSbomArgs(targetImage) : sbomArgs(workspacePath), cwd: workspacePath, mode: 'local' }
      : { executable: 'docker', args: targetImage ? dockerImageSbomArgs(targetImage) : dockerSbomArgs(workspacePath), cwd: workspacePath, mode: 'docker' };
  }
  const exec = container?.exec || execFileAsync;
  try {
    const { stdout, stderr } = await exec(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
    });
    const payload = container ? container.mapPaths(JSON.parse(stdout)) : JSON.parse(stdout);
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

async function resolveInvocation(mode, workspacePath, exclusions = [], container = null) {
  if (container) return { executable: 'docker', args: containerArgs(container, scanArgs(container.root, exclusions)), cwd: workspacePath, mode: 'docker' };
  if (mode !== 'docker' && await commandExists('trivy')) return { executable: 'trivy', args: scanArgs(workspacePath, exclusions), cwd: workspacePath, mode: 'local' };
  if (mode === 'local') throw new Error('Trivy local est introuvable. Installez-le ou choisissez le mode Docker.');
  if (!await commandExists('docker')) throw new Error('Ni Trivy local ni Docker ne sont disponibles.');
  return { executable: 'docker', args: dockerArgs(workspacePath, exclusions), cwd: workspacePath, mode: 'docker' };
}

async function runTrivy({ workspacePath, mode = 'auto', timeoutMs = 300000, imageName = '', exclusions = [], signal, containerRuntime = null }) {
  const container = containerRuntime ? await containerRuntime.forScanner(TRIVY_IMAGE) : null;
  const invocation = await resolveInvocation(mode, workspacePath, exclusions, container);
  const exec = container?.exec || execFileAsync;
  const parse = (text) => (container ? container.mapPaths(JSON.parse(text)) : JSON.parse(text));
  try {
    const { stdout, stderr } = await exec(invocation.executable, invocation.args, {
      cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
    });
    const payload = parse(stdout);
    if (imageName.trim()) {
      const imageInvocation = container
        ? { executable: 'docker', args: containerArgs(container, imageScanArgs(imageName.trim())) }
        : invocation.mode === 'docker'
          ? { executable: 'docker', args: dockerImageArgs(imageName.trim()) }
          : { executable: 'trivy', args: imageScanArgs(imageName.trim()) };
      const imageResult = await exec(imageInvocation.executable, imageInvocation.args, {
        cwd: invocation.cwd, timeout: timeoutMs, maxBuffer: 100 * 1024 * 1024, windowsHide: true, signal
      });
      payload.Results = [...(payload.Results || []), ...(parse(imageResult.stdout).Results || [])];
    }
    return { payload, stderr, mode: invocation.mode };
  } catch (error) {
    if (signal?.aborted) throw new Error('Scan Trivy annulé.');
    if (error.stdout) {
      try { return { payload: parse(error.stdout), stderr: error.stderr || '', mode: invocation.mode }; }
      catch { /* handled below */ }
    }
    if (error.killed) throw new Error(`Le scan Trivy a dépassé ${Math.round(timeoutMs / 1000)} secondes.`);
    throw new Error(error.stderr?.trim() || error.message || 'Échec de Trivy.');
  }
}

module.exports = { runTrivy, generateSbom, resolveInvocation, scanArgs, dockerArgs, imageScanArgs, dockerImageArgs, sbomArgs, dockerSbomArgs, imageSbomArgs, dockerImageSbomArgs, containerArgs, TRIVY_IMAGE };
