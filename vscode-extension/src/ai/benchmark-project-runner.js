const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { analyzeJavaScriptText } = require('../live/liveDetector');
const execFileAsync = promisify(execFile);

async function runMiniProjectValidation({ fixtureDirectory, relativeSource, patchedSource, testFile = 'test.js' }) {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'security-center-benchmark-'));
  try {
    await fs.cp(fixtureDirectory, temporaryRoot, { recursive: true });
    const sourcePath = path.join(temporaryRoot, relativeSource);
    await fs.writeFile(sourcePath, patchedSource, 'utf8');
    let testResult = 'passed';
    try { await execFileAsync(process.execPath, ['--test', path.join(temporaryRoot, testFile)], { cwd: temporaryRoot, timeout: 30000 }); }
    catch { testResult = 'failed'; }
    const findings = analyzeJavaScriptText({ text: patchedSource, uri: sourcePath, documentVersion: 1 });
    return { testResult, rescanResult: findings.length ? 'finding_present' : 'finding_absent', findings: findings.map((item) => item.ruleId) };
  } finally {
    await fs.rm(temporaryRoot, { recursive: true, force: true });
  }
}
module.exports = { runMiniProjectValidation };
