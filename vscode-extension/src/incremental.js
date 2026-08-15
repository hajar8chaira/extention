const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

function normalizeRelative(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
}

function parseGitPaths(...outputs) {
  return [...new Set(outputs.flatMap((output) => String(output || '').split(/\r?\n/))
    .map(normalizeRelative).filter(Boolean))].sort();
}

async function modifiedGitFiles(workspacePath) {
  const absoluteWorkspace = path.resolve(workspacePath);
  const safeDirectory = `safe.directory=${absoluteWorkspace.replaceAll('\\', '/')}`;
  const common = ['-c', safeDirectory, '-C', absoluteWorkspace];
  try {
    const [{ stdout: tracked }, { stdout: untracked }] = await Promise.all([
      execFileAsync('git', [...common, 'diff', '--name-only', '--diff-filter=ACMR', 'HEAD'], { windowsHide: true }),
      execFileAsync('git', [...common, 'ls-files', '--others', '--exclude-standard'], { windowsHide: true })
    ]);
    return parseGitPaths(tracked, untracked);
  } catch (error) {
    throw new Error(error.code === 'ENOENT' ? 'Git est introuvable.' : `Impossible de lire les fichiers modifiés : ${error.stderr?.trim() || error.message}`);
  }
}

function validateGitBase(baseRef) {
  const value = String(baseRef || '').trim();
  if (!value || value.startsWith('-') || !/^[A-Za-z0-9._/@{}~-]+$/.test(value)) throw new Error('Référence Git de base invalide.');
  return value;
}

async function changedFilesAgainstBase(workspacePath, baseRef) {
  const absoluteWorkspace = path.resolve(workspacePath);
  const safeDirectory = `safe.directory=${absoluteWorkspace.replaceAll('\\', '/')}`;
  const validatedBase = validateGitBase(baseRef);
  try {
    const { stdout } = await execFileAsync('git', ['-c', safeDirectory, '-C', absoluteWorkspace, 'diff', '--name-only', '--diff-filter=ACMR', `${validatedBase}...HEAD`], { windowsHide: true });
    return parseGitPaths(stdout);
  } catch (error) {
    throw new Error(error.code === 'ENOENT' ? 'Git est introuvable.' : `Impossible de calculer le diff depuis ${validatedBase} : ${error.stderr?.trim() || error.message}`);
  }
}

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rs', '.php', '.rb', '.cs', '.c', '.cc', '.cpp', '.h', '.hpp', '.html', '.vue', '.svelte']);
const DEPENDENCY_FILES = /(^|\/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|poetry\.lock|pyproject\.toml|pom\.xml|build\.gradle(?:\.kts)?|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|composer\.(?:json|lock)|packages\.lock\.json)$/i;
const TRIVY_FILES = /(^|\/)(Dockerfile(?:\.[^/]*)?|docker-compose[^/]*\.ya?ml|.*\.tf|.*\.tfvars|.*\.ya?ml|.*\.json)$/i;

function incrementalScanPlan(changedFiles, requestedTools = []) {
  const files = changedFiles.map(normalizeRelative);
  const requested = new Set(requestedTools);
  const sourceFiles = files.filter((file) => SOURCE_EXTENSIONS.has(path.posix.extname(file).toLowerCase()));
  const dependencyChanged = files.some((file) => DEPENDENCY_FILES.test(file));
  const trivyChanged = dependencyChanged || files.some((file) => TRIVY_FILES.test(file));
  const candidates = ['Semgrep', 'Gitleaks', ...(trivyChanged ? ['Trivy'] : []), ...(dependencyChanged ? ['OSV-Scanner'] : [])];
  const tools = candidates.filter((tool) => (!requested.size || requested.has(tool)) && (tool !== 'Semgrep' || sourceFiles.length));
  return { changedFiles: files, sourceFiles, dependencyChanged, trivyChanged, tools };
}

async function createIncrementalWorkspace(workspacePath, relativeFiles) {
  const temporaryRoot = path.join(os.tmpdir(), `security-center-incremental-${crypto.randomBytes(8).toString('hex')}`);
  await fs.promises.mkdir(temporaryRoot, { recursive: true });
  const copied = [];
  for (const relativeFile of relativeFiles) {
    const source = path.resolve(workspacePath, relativeFile);
    const relative = path.relative(workspacePath, source);
    if (relative.startsWith('..') || path.isAbsolute(relative)) continue;
    let stat;
    try { stat = await fs.promises.lstat(source); } catch { continue; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 10 * 1024 * 1024) continue;
    const destination = path.join(temporaryRoot, relative);
    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    await fs.promises.copyFile(source, destination);
    copied.push(normalizeRelative(relative));
  }
  return { temporaryRoot, copied };
}

function retainUnchangedFindings(findings, tools, changedFiles) {
  const selectedTools = new Set(tools);
  const changed = new Set(changedFiles.map(normalizeRelative));
  return findings.filter((finding) => !selectedTools.has(finding.tool) || !changed.has(normalizeRelative(finding.file)));
}

module.exports = { normalizeRelative, parseGitPaths, modifiedGitFiles, validateGitBase, changedFilesAgainstBase, incrementalScanPlan, createIncrementalWorkspace, retainUnchangedFindings };
