'use strict';

/**
 * La détection du runtime Java, telle qu'elle doit être faite.
 *
 * Elle se résumait à « `java -version` sort-il avec le code 0 ? ». Or ce code ne
 * répond pas à la question posée. La JVM s'identifie d'abord, puis réserve son
 * tas — et sur une machine dont le fichier de pagination est saturé, cette
 * réservation échoue, la JVM s'arrête avec le code 1, et la sonde concluait que
 * Java n'existait pas :
 *
 *     OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(…, 536870912, 0)
 *     failed; error='Le fichier de pagination est insuffisant…' (DOS error/errno=1455)
 *     # There is insufficient memory for the Java Runtime Environment to continue.
 *
 * Le même `java -version` réussit quand la mémoire engagée se libère. D'où
 * l'instabilité constatée : ZAP local détecté et lancé au début d'une session,
 * puis « INDISPONIBLE » après un rechargement, sans que rien n'ait été désinstallé.
 *
 * Deux corrections, chacune suffisante, appliquées ensemble :
 *
 *   - **La sonde demande un tas minuscule.** Une question d'existence n'a pas à
 *     réserver le quart de la mémoire de la machine.
 *   - **La bannière fait foi.** Si la JVM s'est nommée, elle est appelable ; un
 *     code de sortie non nul décrit alors l'état de la machine, pas l'absence de
 *     Java. Il est conservé comme remarque, pas comme verdict.
 *
 * Le module ne connaît ni `vscode` ni l'extension : il reçoit son exécuteur.
 */

/** Les arguments de la sonde : s'identifier, sans rien réserver d'inutile. */
const JAVA_PROBE_ARGS = Object.freeze(['-Xmx32m', '-version']);

/** La ligne de version d'une JVM, quelle que soit sa distribution. */
const JAVA_VERSION_LINE = /(?:openjdk|java)\s+version\s+"([^"]+)"/i;

/** À défaut de ligne de version, la JVM s'identifie encore par son nom. */
const JAVA_IDENTITY_LINE = /(?:openjdk|java)[^\n]{0,60}(?:server vm|runtime environment)|java\(tm\)/i;

/** Ce que Windows répond quand il ne peut plus engager de mémoire. */
const JAVA_MEMORY_FAILURE = /insufficient memory|os::commit_memory|fichier de pagination|errno=1455/i;

/**
 * Ce que la sonde Java a réellement observé.
 *
 * `found` répond à « Java est-il appelable ? ». `version` n'est renseignée que si
 * la JVM l'a dite. `warning` porte une exécution dégradée — la JVM a répondu mais
 * n'a pas pu réserver son tas — sans transformer cela en absence.
 */
function interpretJavaProbe({ exitCode = 0, stdout = '', stderr = '', error = null } = {}) {
  const output = `${String(stdout || '')}\n${String(stderr || '')}`;
  const versionMatch = output.match(JAVA_VERSION_LINE);
  const identified = Boolean(versionMatch) || JAVA_IDENTITY_LINE.test(output);
  const memoryFailure = JAVA_MEMORY_FAILURE.test(output);
  // Un lancement impossible — exécutable introuvable — est la seule absence réelle.
  const launchFailed = Boolean(error) && !identified;
  if (launchFailed) {
    return {
      found: false,
      version: '',
      warning: '',
      reason: /ENOENT/i.test(String(error.message || ''))
        ? 'Java n’est pas installé, ou n’est pas dans le PATH.'
        : `Java n’a pas pu être exécuté : ${String(error.message || '').split('\n')[0]}.`
    };
  }
  if (!identified && exitCode !== 0) {
    return {
      found: false,
      version: '',
      warning: '',
      reason: `La commande java a échoué (code ${exitCode}) sans s’identifier.`
    };
  }
  return {
    found: true,
    version: versionMatch ? versionMatch[1] : '',
    // La JVM a répondu, mais la machine ne lui a pas laissé de place. C'est une
    // remarque utile — un scan pourrait en souffrir — jamais un « Java absent ».
    warning: memoryFailure
      ? 'La JVM s’identifie mais n’a pas pu réserver sa mémoire : le fichier de pagination Windows est saturé.'
      : exitCode !== 0 ? `La JVM s’identifie mais la commande est sortie avec le code ${exitCode}.` : '',
    reason: ''
  };
}

/**
 * Interroge le runtime Java par l'exécuteur fourni.
 *
 * `run(command, args)` doit rendre `{ stdout, stderr }` ou lever une erreur
 * portant `code`, `stdout` et `stderr` — la forme de `child_process.execFile`
 * promisifié. Aucune exception ne sort d'ici : une sonde qui échoue est une
 * observation, pas une panne du produit.
 */
async function detectJavaRuntime({ run, timeoutMs = 10000 } = {}) {
  if (typeof run !== 'function') return { found: false, version: '', warning: '', reason: 'Aucun exécuteur fourni.' };
  try {
    const result = await run('java', [...JAVA_PROBE_ARGS], { windowsHide: true, timeout: timeoutMs });
    return interpretJavaProbe({ exitCode: 0, stdout: result?.stdout, stderr: result?.stderr });
  } catch (error) {
    return interpretJavaProbe({
      exitCode: Number.isFinite(Number(error?.code)) ? Number(error.code) : 1,
      stdout: error?.stdout,
      stderr: error?.stderr,
      error
    });
  }
}

module.exports = {
  JAVA_PROBE_ARGS, JAVA_VERSION_LINE, JAVA_IDENTITY_LINE, JAVA_MEMORY_FAILURE,
  interpretJavaProbe, detectJavaRuntime
};
