const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

function declaredTestScript(workspacePath) {
  const manifest = path.join(workspacePath, 'package.json');
  if (!fs.existsSync(manifest)) return null;
  try {
    const script = JSON.parse(fs.readFileSync(manifest, 'utf8')).scripts?.test;
    if (!script || /no test specified/i.test(script)) return null;
    return { executable: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: ['test'], label: 'npm test' };
  } catch { return null; }
}

function runDeclaredTests(workspacePath, timeoutMs = 300000, execImpl = execFile) {
  const command = declaredTestScript(workspacePath);
  if (!command) return Promise.resolve({ status: 'skipped', reason: 'Aucun script test déclaré.' });
  return new Promise((resolve) => execImpl(command.executable, command.args, { cwd: workspacePath, windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (error, stdout = '', stderr = '') => {
    resolve({ status: error ? 'failed' : 'passed', command: command.label, exitCode: error?.code ?? 0, output: `${stdout}\n${stderr}`.trim().slice(-4000) });
  }));
}

module.exports = { declaredTestScript, runDeclaredTests };
