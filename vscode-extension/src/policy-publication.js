'use strict';

/**
 * Publication de security-center.yml après un enregistrement.
 *
 * La CI lit le security-center.yml du dépôt, pas celui du poste. Ce module lit
 * l'état Git du fichier — uniquement des commandes en lecture — et dit ce qu'il
 * reste à faire. Il ne lance jamais git add, git commit ni git push :
 * l'utilisateur garde la main, depuis Source Control ou son terminal.
 */

const path = require('path');

const PUBLICATION_ACTIONS = Object.freeze({ sourceControl: 'Ouvrir Source Control', copy: 'Copier les commandes Git' });
/** La vue Source Control native de VS Code. */
const SOURCE_CONTROL_COMMAND = 'workbench.view.scm';
/** Tout ce que ce module peut exécuter : des lectures. */
const READ_ONLY_GIT = Object.freeze(['rev-parse', 'status', 'check-ignore', 'rev-list']);

const LABELS = Object.freeze({
  untracked: 'Non versionné — commit et push requis',
  modified: 'Non versionné — commit et push requis',
  ahead: 'Commit local — push requis',
  'no-upstream': 'Commit local — push requis',
  synced: 'Configuration disponible pour la CI',
  ignored: 'Ignoré par Git — la CI ne le recevra pas',
  'not-git': 'Enregistré localement, hors dépôt Git',
  'git-unavailable': 'Enregistré localement, état Git inconnu'
});

/**
 * L'état Git de security-center.yml. `runGit(cwd, args)` résout
 * `{ ok, stdout, missing }` et ne rejette jamais ; seules les commandes de
 * READ_ONLY_GIT lui sont passées.
 */
async function detectPolicyGitState({ workspacePath, filePath, runGit }) {
  const cwd = path.dirname(filePath);
  const file = path.basename(filePath);
  const relative = path.relative(workspacePath, filePath).split(path.sep).join('/') || file;
  const git = async (args) => {
    if (!READ_ONLY_GIT.includes(args[0])) throw new Error(`git ${args[0]} n’est pas une lecture.`);
    const result = await runGit(cwd, args);
    return { ok: Boolean(result?.ok), stdout: String(result?.stdout || ''), missing: Boolean(result?.missing) };
  };
  const base = { file, relative };

  const inside = await git(['rev-parse', '--is-inside-work-tree']);
  if (!inside.ok) return { ...base, state: inside.missing ? 'git-unavailable' : 'not-git' };
  if (inside.stdout.trim() !== 'true') return { ...base, state: 'not-git' };

  const status = await git(['status', '--porcelain=v1', '--untracked-files=all', '--', file]);
  const line = status.stdout.split(/\r?\n/).find((entry) => entry.trim());
  if (line) {
    const code = line.slice(0, 2);
    return { ...base, state: code === '??' || code[0] === 'A' ? 'untracked' : 'modified' };
  }
  // Absent de `git status` : versionné et propre, ou exclu par .gitignore.
  if ((await git(['check-ignore', '--quiet', '--', file])).ok) return { ...base, state: 'ignored' };

  const head = (await git(['rev-parse', '--abbrev-ref', 'HEAD'])).stdout.trim();
  const branch = /^[A-Za-z0-9._/-]+$/.test(head) && head !== 'HEAD' ? head : '';
  const upstream = await git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}']);
  if (!upstream.ok) return { ...base, state: 'no-upstream', branch };
  // Seuls les commits non poussés qui touchent ce fichier comptent.
  const ahead = Number((await git(['rev-list', '--count', '@{u}..HEAD', '--', file])).stdout.trim()) || 0;
  return { ...base, state: ahead > 0 ? 'ahead' : 'synced', branch, upstream: upstream.stdout.trim() };
}

const shellPath = (value) => (/^[A-Za-z0-9._/-]+$/.test(value) ? value : `"${value.replace(/(["\\$`])/g, '\\$1')}"`);

/** Le message, les commandes à copier et les actions proposées pour un état. */
function describePolicyPublication(status = {}) {
  const file = status.file || 'security-center.yml';
  const state = LABELS[status.state] ? status.state : 'git-unavailable';
  const target = shellPath(status.relative || file);
  const commit = (verb) => `git commit -m "${verb} Security Center configuration"`;
  const commands = {
    untracked: [`git add ${target}`, commit('Add'), 'git push'],
    modified: [`git add ${target}`, commit('Update'), 'git push'],
    ignored: [`git add -f ${target}`, commit('Add'), 'git push'],
    ahead: ['git push'],
    'no-upstream': [status.branch ? `git push -u origin ${status.branch}` : 'git push']
  }[state] || [];
  const needed = `${file} doit être versionné et poussé pour être utilisé par la CI.`;
  const detail = {
    synced: `${file} est déjà sur la branche distante utilisée par la CI.`,
    ignored: `${file} est exclu par .gitignore : ajoutez-le explicitement au dépôt, puis poussez-le.`,
    'not-git': `${file} n’est pas dans un dépôt Git : ajoutez-le au dépôt utilisé par la CI.`,
    'git-unavailable': `Git est introuvable : ${needed}`
  }[state] || needed;
  return {
    state,
    label: LABELS[state],
    detail,
    commands,
    message: `Security Center : Configuration enregistrée localement — ${LABELS[state]}. ${detail}`,
    sourceControl: !['not-git', 'git-unavailable'].includes(state)
  };
}

module.exports = { PUBLICATION_ACTIONS, SOURCE_CONTROL_COMMAND, READ_ONLY_GIT, LABELS, detectPolicyGitState, describePolicyPublication };
