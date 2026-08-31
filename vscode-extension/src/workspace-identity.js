'use strict';

/**
 * Le nom du workspace, tel que VS Code le connaît à l'instant où on le demande.
 *
 * Avant ce module, le dashboard n'apprenait le workspace qu'en effet de bord :
 * il était écrit dans le modèle à l'intérieur du `.then()` d'un appel réseau au
 * backend, au démarrage de l'extension. Quand cet appel échouait — backend
 * arrêté, port occupé par une autre installation, clé d'API refusée — le
 * `.catch()` ne faisait rien, le champ n'était jamais renseigné, et l'interface
 * affichait « Aucun workspace » alors qu'un dossier était bel et bien ouvert.
 *
 * L'identité du workspace ne dépend d'aucun service. Elle se lit dans l'éditeur,
 * et nulle part ailleurs. Ce module est la seule fonction qui la formule, et il
 * est pur : il prend ce que VS Code expose et rend la chaîne à afficher, ce qui
 * le rend vérifiable sans éditeur.
 */

/** Ce que l'interface affiche quand aucun dossier n'est ouvert. */
const NO_WORKSPACE_LABEL = 'Aucun workspace';

/**
 * Décrit le workspace courant.
 *
 * @param {Array<{name?: string, uri?: {fsPath?: string}}>} folders
 *   `vscode.workspace.workspaceFolders`, ou un tableau vide / `undefined`.
 * @param {string} workspaceName
 *   `vscode.workspace.name` : le nom du fichier `.code-workspace` en multi-root,
 *   `undefined` quand rien n'est ouvert.
 * @returns {{label: string, folderCount: number, multiRoot: boolean, isEmpty: boolean, primaryPath: string}}
 */
function describeWorkspaceIdentity(folders, workspaceName = '') {
  const list = Array.isArray(folders) ? folders.filter(Boolean) : [];
  const primaryPath = list[0]?.uri?.fsPath || '';

  if (!list.length) {
    return Object.freeze({
      label: NO_WORKSPACE_LABEL, folderCount: 0, multiRoot: false, isEmpty: true, primaryPath: ''
    });
  }

  if (list.length === 1) {
    // Le nom du dossier tel que VS Code le donne. À défaut — un dossier ouvert
    // par URI sans nom — le dernier segment du chemin, jamais un chemin complet.
    const label = String(list[0].name || '').trim() || basename(primaryPath) || NO_WORKSPACE_LABEL;
    return Object.freeze({ label, folderCount: 1, multiRoot: false, isEmpty: false, primaryPath });
  }

  // Multi-root : le nom du workspace VS Code est l'information la plus juste
  // quand il existe. Sinon on annonce le compte, ce qui reste vrai, plutôt que
  // de désigner arbitrairement le premier dossier comme « le » workspace.
  const named = String(workspaceName || '').trim();
  return Object.freeze({
    label: named || `${list.length} workspaces`,
    folderCount: list.length,
    multiRoot: true,
    isEmpty: false,
    primaryPath
  });
}

/** Dernier segment d'un chemin, séparateurs Windows et POSIX confondus. */
function basename(fsPath) {
  const parts = String(fsPath || '').split(/[\\/]+/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

module.exports = { describeWorkspaceIdentity, NO_WORKSPACE_LABEL };
