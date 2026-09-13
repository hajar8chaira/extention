'use strict';

/**
 * Après l'enregistrement de security-center.yml : état Git et étape de publication.
 *
 * Les états sont lus avec le vrai `git` sur des dépôts temporaires (un dépôt
 * distant nu joue le remote de la CI). Le câblage VS Code est le vrai code
 * d'extension.js, extrait et exécuté avec des doubles.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  PUBLICATION_ACTIONS, SOURCE_CONTROL_COMMAND, READ_ONLY_GIT, detectPolicyGitState, describePolicyPublication
} = require('../src/policy-publication');

const GIT = spawnSync('git', ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = !GIT && 'git indisponible';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-policy-publication-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));
const YAML = 'version: 1\nscanners:\n  semgrep: true\n';

/** Every git command the module runs, recorded; executed for real, read-only, never above `root`. */
function recorder() {
  const commands = [];
  const runGit = async (cwd, args) => {
    commands.push(args);
    const result = spawnSync('git', ['-C', cwd, ...args], { encoding: 'utf8', env: { ...process.env, GIT_CEILING_DIRECTORIES: root } });
    return { ok: result.status === 0, stdout: result.stdout || '' };
  };
  return { runGit, commands };
}

function git(cwd, ...args) {
  const result = spawnSync('git', ['-C', cwd, ...args], { encoding: 'utf8', env: { ...process.env, GIT_CEILING_DIRECTORIES: root } });
  assert.equal(result.status, 0, `git ${args.join(' ')}\n${result.stderr}`);
  return result.stdout.trim();
}

/** A repository whose origin is a bare remote, with one pushed commit. */
function repository(name, { remote = true } = {}) {
  const workspace = path.join(root, name);
  fs.mkdirSync(workspace, { recursive: true });
  git(workspace, 'init', '-q', '-b', 'master');
  git(workspace, 'config', 'user.email', 'dev@example.invalid');
  git(workspace, 'config', 'user.name', 'Dev');
  fs.writeFileSync(path.join(workspace, 'app.js'), 'console.log(1);\n');
  git(workspace, 'add', 'app.js');
  git(workspace, 'commit', '-q', '-m', 'initial');
  if (remote) {
    const bare = path.join(root, `${name}-remote.git`);
    git(root, 'init', '-q', '--bare', bare);
    git(workspace, 'remote', 'add', 'origin', bare);
    git(workspace, 'push', '-q', '-u', 'origin', 'master');
  }
  return workspace;
}

async function stateOf(workspace, file = 'security-center.yml') {
  const { runGit, commands } = recorder();
  const status = await detectPolicyGitState({ workspacePath: workspace, filePath: path.join(workspace, file), runGit });
  return { status, commands, publication: describePolicyPublication(status) };
}

function assertReadOnly(commands) {
  for (const args of commands) {
    assert.ok(READ_ONLY_GIT.includes(args[0]), `git ${args.join(' ')} is a read-only command`);
    assert.ok(!args.some((arg) => ['add', 'commit', 'push', 'reset', 'checkout', 'stash', 'fetch', 'pull'].includes(arg)), `never git ${args.join(' ')}`);
  }
}

// ------------------------------------------------------------ Git states

test('untracked or modified security-center.yml: commit and push required, with the matching commands', { skip: SKIP }, async () => {
  const workspace = repository('untracked');
  fs.writeFileSync(path.join(workspace, 'security-center.yml'), YAML);
  const created = await stateOf(workspace);
  assert.equal(created.status.state, 'untracked');
  assert.equal(created.publication.label, 'Non versionné — commit et push requis');
  assert.equal(created.publication.message, 'Security Center : Configuration enregistrée localement — Non versionné — commit et push requis. security-center.yml doit être versionné et poussé pour être utilisé par la CI.');
  assert.deepEqual(created.publication.commands, ['git add security-center.yml', 'git commit -m "Add Security Center configuration"', 'git push']);
  assert.equal(created.publication.sourceControl, true);
  assertReadOnly(created.commands);
  assert.equal(git(workspace, 'status', '--porcelain', '--', 'security-center.yml'), '?? security-center.yml', 'nothing was staged');

  git(workspace, 'add', 'security-center.yml');
  git(workspace, 'commit', '-q', '-m', 'policy');
  git(workspace, 'push', '-q');
  fs.writeFileSync(path.join(workspace, 'security-center.yml'), `${YAML}gate:\n  block_secrets: true\n`);
  const modified = await stateOf(workspace);
  assert.equal(modified.status.state, 'modified');
  assert.equal(modified.publication.label, 'Non versionné — commit et push requis');
  assert.deepEqual(modified.publication.commands, ['git add security-center.yml', 'git commit -m "Update Security Center configuration"', 'git push']);
  assertReadOnly(modified.commands);
});

test('committed locally but not pushed: push required', { skip: SKIP }, async () => {
  const workspace = repository('ahead');
  fs.writeFileSync(path.join(workspace, 'security-center.yml'), YAML);
  git(workspace, 'add', 'security-center.yml');
  git(workspace, 'commit', '-q', '-m', 'policy');
  const { status, publication, commands } = await stateOf(workspace);
  assert.equal(status.state, 'ahead');
  assert.equal(publication.label, 'Commit local — push requis');
  assert.deepEqual(publication.commands, ['git push']);
  assertReadOnly(commands);

  const local = repository('never-pushed', { remote: false });
  fs.writeFileSync(path.join(local, 'security-center.yml'), YAML);
  git(local, 'add', 'security-center.yml');
  git(local, 'commit', '-q', '-m', 'policy');
  const unpublished = await stateOf(local);
  assert.equal(unpublished.status.state, 'no-upstream');
  assert.equal(unpublished.publication.label, 'Commit local — push requis');
  assert.deepEqual(unpublished.publication.commands, ['git push -u origin master']);
});

test('clean and pushed: available for the CI, nothing to copy', { skip: SKIP }, async () => {
  const workspace = repository('synced');
  fs.writeFileSync(path.join(workspace, 'security-center.yml'), YAML);
  git(workspace, 'add', 'security-center.yml');
  git(workspace, 'commit', '-q', '-m', 'policy');
  git(workspace, 'push', '-q');
  // An unrelated local commit does not make the pushed configuration unavailable.
  fs.writeFileSync(path.join(workspace, 'app.js'), 'console.log(2);\n');
  git(workspace, 'commit', '-q', '-am', 'unrelated');
  const { status, publication, commands } = await stateOf(workspace);
  assert.equal(status.state, 'synced');
  assert.equal(publication.label, 'Configuration disponible pour la CI');
  assert.equal(publication.message, 'Security Center : Configuration enregistrée localement — Configuration disponible pour la CI. security-center.yml est déjà sur la branche distante utilisée par la CI.');
  assert.deepEqual(publication.commands, []);
  assertReadOnly(commands);
});

test('ignored by .gitignore: said plainly, the CI would never receive it', { skip: SKIP }, async () => {
  const workspace = repository('ignored');
  fs.writeFileSync(path.join(workspace, '.gitignore'), 'security-center.yml\n');
  fs.writeFileSync(path.join(workspace, 'security-center.yml'), YAML);
  const { status, publication } = await stateOf(workspace);
  assert.equal(status.state, 'ignored');
  assert.equal(publication.label, 'Ignoré par Git — la CI ne le recevra pas');
  assert.deepEqual(publication.commands, ['git add -f security-center.yml', 'git commit -m "Add Security Center configuration"', 'git push']);
});

test('non-Git workspace or Git missing: no error, the file was saved locally and must reach the CI repository', { skip: SKIP }, async () => {
  const plain = path.join(root, 'not-a-repository');
  fs.mkdirSync(plain);
  fs.writeFileSync(path.join(plain, 'security-center.yml'), YAML);
  const { status, publication } = await stateOf(plain);
  assert.equal(status.state, 'not-git');
  assert.equal(publication.message, 'Security Center : Configuration enregistrée localement — Enregistré localement, hors dépôt Git. security-center.yml n’est pas dans un dépôt Git : ajoutez-le au dépôt utilisé par la CI.');
  assert.deepEqual(publication.commands, []);
  assert.equal(publication.sourceControl, false);

  const missing = await detectPolicyGitState({ workspacePath: plain, filePath: path.join(plain, 'security-center.yml'), runGit: async () => ({ ok: false, missing: true }) });
  assert.equal(missing.state, 'git-unavailable');
  assert.match(describePolicyPublication(missing).message, /Git est introuvable : security-center\.yml doit être versionné et poussé pour être utilisé par la CI\./);
  await assert.rejects(detectPolicyGitState({ workspacePath: plain, filePath: path.join(plain, 'x.yml'), runGit: async () => { throw new Error('never thrown by the real runner'); } }));
});

test('only read-only git commands can ever be run by the detection', async () => {
  const seen = [];
  const fake = async (cwd, args) => {
    seen.push(args);
    if (args[0] === 'rev-parse' && args[1] === '--is-inside-work-tree') return { ok: true, stdout: 'true\n' };
    if (args[0] === 'status') return { ok: true, stdout: ' M security-center.yml\n' };
    return { ok: false, stdout: '' };
  };
  await detectPolicyGitState({ workspacePath: '/repo', filePath: '/repo/security-center.yml', runGit: fake });
  assertReadOnly(seen);
  assert.deepEqual(READ_ONLY_GIT, ['rev-parse', 'status', 'check-ignore', 'rev-list']);
  assert.equal(describePolicyPublication({ state: 'untracked', file: 'security-center.yml', relative: 'config dir/security-center.yml' }).commands[0], 'git add "config dir/security-center.yml"');
});

// ------------------------------------------------------------ VS Code wiring

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8').replace(/\r\n/g, '\n');

function extractFunction(marker) {
  const start = SOURCE.indexOf(marker);
  assert.ok(start >= 0, `absent d’extension.js : ${marker}`);
  const open = SOURCE.indexOf(') {', start) + 2;
  let depth = 0;
  for (let index = open; index < SOURCE.length; index += 1) {
    if (SOURCE[index] === '{') depth += 1;
    else if (SOURCE[index] === '}' && --depth === 0) return SOURCE.slice(start, index + 1);
  }
  throw new Error('bloc non équilibré');
}
const NOTIFY = extractFunction('async function notifyPolicyPublication(filePath)');

/** The real helper with VS Code, the clipboard and the git process replaced by doubles. */
function wiring({ answer, gitAnswers }) {
  const calls = { messages: [], commands: [], clipboard: [], exec: [] };
  const vscode = {
    workspace: { workspaceFolders: [{ uri: { fsPath: '/repo' } }] },
    window: { showInformationMessage: async (message, ...items) => { calls.messages.push({ message, items }); return calls.messages.length === 1 ? answer : undefined; } },
    commands: { executeCommand: async (...args) => { calls.commands.push(args); } },
    env: { clipboard: { writeText: async (text) => { calls.clipboard.push(text); } } }
  };
  const execFileAsync = async (command, args) => {
    calls.exec.push([command, ...args]);
    const reply = gitAnswers(args.slice(2));
    if (reply === undefined) throw Object.assign(new Error('git failed'), { code: 1, stdout: '' });
    return { stdout: reply };
  };
  const notify = new Function('deps', `
    const { vscode, execFileAsync, detectPolicyGitState, describePolicyPublication, PUBLICATION_ACTIONS, SOURCE_CONTROL_COMMAND } = deps;
    return ${NOTIFY};
  `)({ vscode, execFileAsync, detectPolicyGitState, describePolicyPublication, PUBLICATION_ACTIONS, SOURCE_CONTROL_COMMAND });
  return { calls, notify };
}
const untrackedGit = (args) => (args[0] === 'rev-parse' && args[1] === '--is-inside-work-tree' ? 'true\n' : args[0] === 'status' ? '?? security-center.yml\n' : undefined);

test('"Copier les commandes Git" copies the commands and never executes them', async () => {
  const { calls, notify } = wiring({ answer: 'Copier les commandes Git', gitAnswers: untrackedGit });
  await notify('/repo/security-center.yml');
  assert.deepEqual(calls.messages[0].items, ['Ouvrir Source Control', 'Copier les commandes Git']);
  assert.match(calls.messages[0].message, /^Security Center : Configuration enregistrée localement — Non versionné — commit et push requis\. security-center\.yml doit être versionné et poussé pour être utilisé par la CI\.$/);
  assert.deepEqual(calls.clipboard, ['git add security-center.yml\ngit commit -m "Add Security Center configuration"\ngit push']);
  assert.match(calls.messages[1].message, /commandes Git copiées\. Vérifiez-les puis exécutez-les vous-même/);
  assert.deepEqual(calls.commands, [], 'no VS Code command runs anything');
  for (const [command, ...args] of calls.exec) {
    assert.equal(command, 'git');
    assert.ok(READ_ONLY_GIT.includes(args[2]), `read-only: git ${args.join(' ')}`);
  }
  assert.doesNotMatch(NOTIFY, /'add'|'commit'|'push'|git\.(commit|push|stage)|sendText|createTerminal/, 'the helper can neither run git add/commit/push nor type into a terminal');
});

test('"Ouvrir Source Control" opens the native VS Code Source Control view', async () => {
  const { calls, notify } = wiring({ answer: 'Ouvrir Source Control', gitAnswers: untrackedGit });
  await notify('/repo/security-center.yml');
  assert.deepEqual(calls.commands, [['workbench.view.scm']]);
  assert.equal(SOURCE_CONTROL_COMMAND, 'workbench.view.scm');
  assert.deepEqual(calls.clipboard, []);

  const outside = wiring({ answer: undefined, gitAnswers: () => undefined });
  await outside.notify('/repo/security-center.yml');
  assert.deepEqual(outside.calls.messages[0].items, [], 'outside Git: explanation only, no action');
  assert.match(outside.calls.messages[0].message, /n’est pas dans un dépôt Git : ajoutez-le au dépôt utilisé par la CI\./);
});

test('guidance follows every successful save that writes security-center.yml, without blocking it', () => {
  const calls = SOURCE.match(/notifyPolicyPublication\(.*\)\.catch\(\(\) => \{\}\);/g) || [];
  assert.equal(calls.length, 3, 'scanner save, Policy Gate save and starter policy');
  assert.match(SOURCE, /const saved = await saveProjectScanners\([\s\S]{0,200}if \(saved\.ok\) \{[\s\S]{0,160}notifyPolicyPublication\(/);
  assert.match(SOURCE, /policySaveResult = await savePolicyGate\([\s\S]{0,300}if \(policySaveResult\.ok\) \{[\s\S]{0,300}notifyPolicyPublication\(/);
  assert.match(SOURCE, /policySaveResult = await createStarterPolicy\([\s\S]{0,300}if \(policySaveResult\.ok\) \{[\s\S]{0,300}notifyPolicyPublication\(policySaveResult\.filePath\)/);
});
