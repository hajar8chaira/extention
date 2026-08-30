const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

function declaredTestScript(workspacePath) {
  const manifest = path.join(workspacePath, 'package.json');
  if (!fs.existsSync(manifest)) return null;
  try {
    const script = JSON.parse(fs.readFileSync(manifest, 'utf8')).scripts?.test;
    if (!script || /no test specified/i.test(script)) return null;
    // Node refuses to spawn .bat/.cmd wrappers directly since the CVE-2024-27980
    // mitigation: `execFile('npm.cmd', …)` throws EINVAL *synchronously*. This is
    // the same interpreter form the scanner manager already uses, with an
    // argument array rather than `shell: true`.
    if (process.platform === 'win32') {
      return { executable: process.env.COMSPEC || 'cmd.exe', args: ['/d', '/s', '/c', 'npm.cmd', 'test'], label: 'npm test' };
    }
    return { executable: 'npm', args: ['test'], label: 'npm test' };
  } catch { return null; }
}

/**
 * Runs the project's declared test script as evidence around an applied fix.
 *
 * Never rejects. Running the tests is a corroboration step, not the correction
 * itself: a spawn problem here used to escape and surface as « Correction Ollama
 * non appliquée — spawn EINVAL », blaming the model for a failure that happened
 * after its patch had already been applied and verified.
 */
function runDeclaredTests(workspacePath, timeoutMs = 300000, execImpl = execFile) {
  const command = declaredTestScript(workspacePath);
  if (!command) return Promise.resolve({ status: 'skipped', reason: 'Aucun script test déclaré.' });
  return new Promise((resolve) => {
    const settle = (result) => resolve({ command: command.label, ...result });
    try {
      execImpl(command.executable, command.args, { cwd: workspacePath, windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (error, stdout = '', stderr = '') => {
        settle({ status: error ? 'failed' : 'passed', exitCode: error?.code ?? 0, output: `${stdout}\n${stderr}`.trim().slice(-4000) });
      });
    } catch (error) {
      // A launcher that cannot start is « tests not run », not « fix rejected ».
      settle({ status: 'skipped', reason: `Les tests du projet n’ont pas pu être lancés : ${error.code || error.message}.` });
    }
  });
}

module.exports = { declaredTestScript, runDeclaredTests };
