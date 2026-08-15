const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const MARKER = '# security-center-gitleaks-hook';

function hookContent() {
  return `#!/bin/sh
${MARKER}
echo "Security Center: analyse Gitleaks des changements indexés..."
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks git --pre-commit --redact --staged --verbose
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$PWD:/repo" -w /repo zricethezav/gitleaks:latest git --pre-commit --redact --staged --verbose
else
  echo "Security Center: Gitleaks ou Docker est requis pour valider ce commit." >&2
  exit 1
fi
status=$?
if [ "$status" -ne 0 ]; then
  echo "Security Center: commit bloqué car un secret potentiel a été détecté." >&2
fi
exit "$status"
`;
}

async function resolveHooksDirectory(workspacePath) {
  const { stdout } = await execFileAsync('git', ['-C', workspacePath, 'rev-parse', '--path-format=absolute', '--git-path', 'hooks'], { windowsHide: true });
  return stdout.trim();
}

async function installPreCommitHook(workspacePath) {
  const hooksDirectory = await resolveHooksDirectory(workspacePath);
  const hookPath = path.join(hooksDirectory, 'pre-commit');
  await fs.promises.mkdir(hooksDirectory, { recursive: true });
  try {
    const existing = await fs.promises.readFile(hookPath, 'utf8');
    if (existing.includes(MARKER)) return { hookPath, status: 'already-installed' };
    throw new Error(`Un hook pre-commit existe déjà : ${hookPath}. Security Center ne l’a pas remplacé.`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.promises.writeFile(hookPath, hookContent(), { encoding: 'utf8', flag: 'wx', mode: 0o755 });
  await fs.promises.chmod(hookPath, 0o755);
  return { hookPath, status: 'installed' };
}

module.exports = { MARKER, hookContent, resolveHooksDirectory, installPreCommitHook };
