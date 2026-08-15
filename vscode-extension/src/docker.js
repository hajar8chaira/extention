const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

function requiresDocker(modes) {
  return modes.some((mode) => mode === 'docker');
}

function dockerCliArgs(args, platform = process.platform) {
  return platform === 'win32' ? ['--context', 'desktop-linux', ...args] : args;
}

async function ensureDockerAvailable(timeoutMs = 10000) {
  try {
    const { stdout } = await execFileAsync('docker', dockerCliArgs(['version', '--format', '{{.Server.Version}}']), {
      timeout: timeoutMs, windowsHide: true
    });
    const version = stdout.trim();
    if (!version) throw new Error('Le moteur Docker ne renvoie aucune version.');
    return version;
  } catch (error) {
    if (error.killed) throw new Error('Docker Desktop ne répond pas. Redémarrez-le et attendez « Engine running ».');
    if (error.code === 'ENOENT') throw new Error('La commande Docker est introuvable. Installez Docker Desktop.');
    throw new Error('Docker Desktop n’est pas disponible. Démarrez-le et attendez « Engine running ».');
  }
}

module.exports = { dockerCliArgs, ensureDockerAvailable, requiresDocker };
