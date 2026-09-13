'use strict';

/**
 * Extraction du projet sur le runtime CI.
 *
 * Régression Jenkins réelle : le runtime refaisait un clone complet
 * (`+refs/heads/*`, tous les tags, tout l'historique) avant de revenir au commit
 * déjà résolu par l'agent principal, et dépassait 10 minutes.
 *
 * Les options Git sont lues dans le Jenkinsfile lui-même, puis rejouées avec le
 * vrai `git` contre un dépôt local qui a d'autres branches, des tags et une
 * branche qui a avancé : exactement ce que le plugin Git exécute avec ces options.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const JENKINSFILE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
const helper = (name) => {
  const start = JENKINSFILE.indexOf(`def ${name}() {`);
  assert.ok(start >= 0, `${name} absent du Jenkinsfile`);
  return JENKINSFILE.slice(start, JENKINSFILE.indexOf('\n}\n', start) + 3);
};
const RUNTIME_CHECKOUT = helper('scenterCheckoutAnalysedCommit');
const RUNTIME_STAGE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Prepare CI Runtime workspace')"), JENKINSFILE.indexOf("stage('Bootstrap Security Center CI Engine')"));
const CONTROLLER_STAGE = JENKINSFILE.slice(JENKINSFILE.indexOf("stage('Checkout')"), JENKINSFILE.indexOf("stage('Security Center CI Runtime')"));

function bashPath() {
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  if (process.platform === 'win32') return fs.existsSync(gitBash) ? gitBash : null;
  return 'bash';
}
const BASH = bashPath();
const GIT = spawnSync('git', ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = (!GIT && 'git indisponible') || (!BASH && 'bash indisponible');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-runtime-checkout-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));

function git(cwd, ...args) {
  const result = spawnSync('git', ['-c', 'protocol.file.allow=always', ...args], { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, `git ${args.join(' ')}\n${result.stderr}`);
  return result.stdout.trim();
}

/** An origin with history, a tag, another branch, and a branch that moved after resolution. */
function originRepository() {
  const origin = path.join(root, 'origin');
  fs.mkdirSync(origin);
  git(origin, 'init', '-q', '-b', 'master');
  git(origin, 'config', 'user.email', 'ci@example.invalid');
  git(origin, 'config', 'user.name', 'CI');
  // Hosted Git servers (GitHub, GitLab) serve a reachable commit by SHA.
  git(origin, 'config', 'uploadpack.allowReachableSHA1InWant', 'true');
  const commit = (file, message) => {
    fs.writeFileSync(path.join(origin, file), `${message}\n`);
    git(origin, 'add', file);
    git(origin, 'commit', '-q', '-m', message);
    return git(origin, 'rev-parse', 'HEAD');
  };
  const first = commit('app.js', 'initial');
  git(origin, 'tag', 'v1.0.0');
  commit('security-center.yml', 'policy');
  const resolved = commit('app.js', 'resolved by the controller');
  git(origin, 'checkout', '-q', '-b', 'feature');
  const feature = commit('feature.js', 'other branch');
  git(origin, 'checkout', '-q', 'master');
  const later = commit('app.js', 'pushed after resolution');
  git(origin, 'tag', 'v2.0.0');
  return { origin, first, resolved, feature, later };
}

const REPO = SKIP ? null : originRepository();

/** The options the runtime checkout gives the Git plugin, read from the Jenkinsfile. */
function runtimeFetchPlan(history) {
  const first = /def attempts = \[\[refspec: "(\+\$\{commit\}:refs\/remotes\/origin\/scenter-analysed)", depth: (\d+)\]\]/.exec(RUNTIME_CHECKOUT);
  assert.ok(first, 'first attempt: the commit itself');
  assert.match(RUNTIME_CHECKOUT, /honorRefspec: true, noTags: true, shallow: !history, depth: history \? 0 : attempt\.depth/);
  return { refspec: first[1].replace('${commit}', REPO.resolved), noTags: true, depth: history ? 0 : Number(first[2]) };
}

/** What the Git plugin runs for those options: fetch with the honoured refspec, then check out the commit. */
function checkoutLikeJenkins(workspace, plan) {
  fs.mkdirSync(workspace, { recursive: true });
  git(workspace, 'init', '-q');
  git(workspace, 'fetch', ...(plan.noTags ? ['--no-tags'] : ['--tags']), '--force', ...(plan.depth ? [`--depth=${plan.depth}`] : []), '--', REPO.origin, plan.refspec);
  git(workspace, 'checkout', '-q', '-f', REPO.resolved);
}

// ------------------------------------------------------------ Jenkinsfile

test('1. runtime checkout fetches neither all branches nor tags by default', () => {
  assert.match(RUNTIME_STAGE, /scenterCheckoutAnalysedCommit\(\)/);
  assert.doesNotMatch(RUNTIME_STAGE, /scenterCheckoutProject\(\)|checkout scm|git\(repository\)/, 'no default full checkout on the runtime');
  assert.match(RUNTIME_CHECKOUT, /honorRefspec: true/, 'the initial clone uses the given refspec, not +refs\/heads\/*');
  assert.match(RUNTIME_CHECKOUT, /noTags: true/);
  assert.doesNotMatch(RUNTIME_CHECKOUT, /refs\/heads\/\*|refs\/tags|--tags/);
  assert.match(RUNTIME_CHECKOUT, /\[\$class: 'CloneOption', honorRefspec: true, noTags: true, shallow: !history, depth: history \? 0 : attempt\.depth, timeout: 20\]/);
  // The fallback, only if the server refuses a fetch by SHA, is still one branch.
  assert.match(RUNTIME_CHECKOUT, /attempts << \[refspec: "\+refs\/heads\/\$\{env\.SC_SOURCE_BRANCH\}:refs\/remotes\/origin\/\$\{env\.SC_SOURCE_BRANCH\}", depth: 50\]/);
});

test('2. the exact controller-resolved commit is checked out and verified', () => {
  assert.match(CONTROLLER_STAGE, /env\.SC_SOURCE_COMMIT = sh\(returnStdout: true, label: 'Source commit', script: 'git rev-parse HEAD'\)\.trim\(\)/);
  assert.match(CONTROLLER_STAGE, /env\.SC_SOURCE_URL = env\.SCENTER_PROJECT_REPO_URL \?: \(source\.GIT_URL \?: ''\)/);
  assert.match(CONTROLLER_STAGE, /env\.SC_SOURCE_CREDENTIALS_ID = env\.SCENTER_PROJECT_CREDENTIALS_ID \?: \(source\.SCENTER_CREDENTIALS_ID \?: ''\)/);
  assert.match(RUNTIME_CHECKOUT, /if \(!\(commit ==~ \/\[0-9a-f\]\{40\}\/\) \|\| !env\.SC_SOURCE_URL\) \{\s*error\(/, 'never another version');
  assert.match(RUNTIME_CHECKOUT, /branches: \[\[name: commit\]\]/, 'the commit, not the latest branch');
  assert.match(RUNTIME_CHECKOUT, /sh\(label: 'Verify analysed commit', script: 'test "\$\(git rev-parse HEAD\)" = "\$SC_SOURCE_COMMIT"'\)/);
  assert.match(RUNTIME_CHECKOUT, /userRemoteConfigs: \[remote \+ \[refspec: attempt\.refspec\]\]/, 'same repository and credential as the controller');
});

// ------------------------------------------------------------ real git

test('3. shallow mode: one commit, the resolved one, no tags, no other branch, .git kept', { skip: SKIP }, () => {
  const workspace = path.join(root, 'shallow');
  checkoutLikeJenkins(workspace, runtimeFetchPlan(false));
  assert.equal(git(workspace, 'rev-parse', 'HEAD'), REPO.resolved, 'exact commit, although master moved on');
  assert.notEqual(git(workspace, 'rev-parse', 'HEAD'), REPO.later);
  assert.equal(git(workspace, 'rev-list', '--count', 'HEAD'), '1', 'depth 1');
  assert.equal(git(workspace, 'rev-parse', '--is-shallow-repository'), 'true');
  assert.equal(git(workspace, 'tag', '--list'), '', 'no tags');
  assert.deepEqual(git(workspace, 'for-each-ref', '--format=%(refname)', 'refs/remotes').split('\n'), ['refs/remotes/origin/scenter-analysed']);
  assert.notEqual(spawnSync('git', ['cat-file', '-e', REPO.feature], { cwd: workspace }).status, 0, 'other branches are not fetched');
  assert.ok(fs.existsSync(path.join(workspace, '.git')), '.git kept for the scanners');
  assert.ok(fs.existsSync(path.join(workspace, 'security-center.yml')));
});

test('4. history mode (gitleaks.history: true): full history of that commit only, still no tags or other branches', { skip: SKIP }, () => {
  const workspace = path.join(root, 'history');
  checkoutLikeJenkins(workspace, runtimeFetchPlan(true));
  assert.equal(git(workspace, 'rev-parse', 'HEAD'), REPO.resolved);
  assert.equal(git(workspace, 'rev-parse', '--is-shallow-repository'), 'false', 'what the runtime verifies before Gitleaks runs');
  assert.equal(git(workspace, 'rev-list', '--count', 'HEAD'), '3', 'the whole history of the analysed commit');
  assert.equal(git(workspace, 'merge-base', '--is-ancestor', REPO.first, 'HEAD') === '', true);
  assert.equal(git(workspace, 'tag', '--list'), '');
  assert.notEqual(spawnSync('git', ['cat-file', '-e', REPO.feature], { cwd: workspace }).status, 0, 'other branches still not fetched');
  assert.notEqual(spawnSync('git', ['cat-file', '-e', REPO.later], { cwd: workspace }).status, 0, 'nothing after the analysed commit');
  // The runtime refuses a truncated clone in history mode instead of letting Gitleaks scan one commit.
  assert.match(RUNTIME_CHECKOUT, /if \(history\) \{[\s\S]*?sh\(label: 'Verify Git history for Gitleaks', script: 'test "\$\(git rev-parse --is-shallow-repository\)" = false'\)/);
});

test('history mode is decided from security-center.yml by the Jenkinsfile script itself', { skip: SKIP }, () => {
  const script = /label: 'Git history required by security-center\.yml', script: '''([\s\S]*?)'''\) == 0 \? 'true' : 'false'/.exec(CONTROLLER_STAGE)?.[1];
  assert.ok(script, 'history detection present in the controller Checkout stage');
  assert.match(CONTROLLER_STAGE, /env\.SC_GIT_HISTORY = sh\(returnStatus: true/);
  const cases = [
    ['version: 1\nscanners:\n  gitleaks: true\ngitleaks:\n  history: true\n', true],
    ['version: 1\ngitleaks:\n  config: .gitleaks.toml\n  history: true   # scan every commit\n', true],
    ['gitleaks: { history: true }\n', true],
    ['version: 1\ngitleaks:\n  history: false\n', false],
    ['version: 1\nscanners:\n  gitleaks: true\n', false],
    ['version: 1\nsemgrep:\n  history: true\ngitleaks:\n  config: x\n', false],
    ['gitleaks:\n  history_incremental: true\n', false],
    [null, false]
  ];
  cases.forEach(([yaml, expected], index) => {
    const project = path.join(root, `policy-${index}`);
    fs.mkdirSync(project);
    if (yaml !== null) fs.writeFileSync(path.join(project, 'security-center.yml'), yaml);
    const result = spawnSync(BASH, ['-c', script], { cwd: project, encoding: 'utf8' });
    assert.equal(result.status === 0, expected, `${JSON.stringify(yaml)} → ${result.status}\n${result.stderr}`);
  });
});
