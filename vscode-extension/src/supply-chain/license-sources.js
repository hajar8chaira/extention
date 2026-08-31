'use strict';

/**
 * Where a licence inventory comes from.
 *
 * Licence compliance is not one analysis but two, and conflating them is the
 * defect this module exists to prevent. The *workspace* source reads the
 * declared dependencies of the project from its manifests. The *container
 * image* source reads the layers of a built image, and therefore needs a
 * container engine — a prerequisite that has nothing to do with licence policy.
 *
 * Three rules follow, and they are the same ones Infrastructure holds to:
 *
 *   - A missing container engine is a PREREQUISITE failure of one source. It is
 *     never a compliance verdict, and never a component count of zero.
 *   - One source failing does not stop the other. A workspace inventory is
 *     still worth having when no engine is installed.
 *   - When no source could be analysed at all, the verdict is INDETERMINATE.
 *     `compliant` is null — never `true`, which would be the comfortable lie.
 *
 * Trivy itself is not touched: this module only decides what to ask it for,
 * how many times, and how to read what comes back.
 */

const { generateSbom } = require('../trivy');

/** The two inventories a licence report can be built from. */
const SOURCE = Object.freeze({
  WORKSPACE: 'workspace',
  IMAGE: 'image'
});

/**
 * What happened to one source.
 *
 * `NOT_CONFIGURED` and `RUNTIME_UNAVAILABLE` are deliberately distinct from
 * `FAILED`: the first two are answered by configuring something or installing
 * an engine, the third by reading an error. Collapsing them into one state is
 * what turned a missing Docker socket into « contrôle des licences impossible ».
 */
const SOURCE_STATE = Object.freeze({
  ANALYZED: 'analyzed',
  NOT_CONFIGURED: 'not-configured',
  RUNTIME_UNAVAILABLE: 'runtime-unavailable',
  TARGET_NOT_FOUND: 'target-not-found',
  CANCELLED: 'cancelled',
  FAILED: 'failed'
});

const SOURCE_LABELS = Object.freeze({
  [SOURCE.WORKSPACE]: 'Dépendances du workspace',
  [SOURCE.IMAGE]: 'Image de conteneur'
});

const SOURCE_STATE_LABELS = Object.freeze({
  [SOURCE_STATE.ANALYZED]: 'Analysée',
  [SOURCE_STATE.NOT_CONFIGURED]: 'Non configurée',
  [SOURCE_STATE.RUNTIME_UNAVAILABLE]: 'Moteur de conteneur inaccessible',
  [SOURCE_STATE.TARGET_NOT_FOUND]: 'Cible introuvable',
  [SOURCE_STATE.CANCELLED]: 'Annulée',
  [SOURCE_STATE.FAILED]: 'Échec'
});

/**
 * No container engine answered.
 *
 * These are the shapes Trivy and the orchestration itself produce when Docker,
 * containerd and Podman are all absent or refusing connections.
 */
const RUNTIME_SIGNATURES = Object.freeze([
  /unable to initialize container image/i,
  /docker\s*API\s*unavailable/i,
  /containerd socket not found/i,
  /podman socket not found/i,
  /cannot connect to the docker daemon/i,
  /is the docker daemon running/i,
  /ni trivy local ni docker ne sont disponibles/i,
  /trivy local est introuvable/i
]);

/** The engine answered, but does not hold the image that was asked for. */
const TARGET_SIGNATURES = Object.freeze([
  /unable to find the specified image/i,
  /manifest unknown/i,
  /no such image/i,
  /image not found/i
]);

/**
 * Reads a failure message into a state.
 *
 * Runtime signatures are tested FIRST on purpose. When no engine is running,
 * Trivy reports both « unable to find the specified image » and « docker API
 * unavailable » in the same message: the image looks missing precisely because
 * nothing can be asked. Telling the user to check the image name would send
 * them after the wrong problem.
 */
function classifySourceFailure(message) {
  const text = String(message || '');
  if (RUNTIME_SIGNATURES.some((pattern) => pattern.test(text))) return SOURCE_STATE.RUNTIME_UNAVAILABLE;
  if (TARGET_SIGNATURES.some((pattern) => pattern.test(text))) return SOURCE_STATE.TARGET_NOT_FOUND;
  return SOURCE_STATE.FAILED;
}

function sourceResult({ source, state, target = '', reason = '', document = null, executionMode = '' }) {
  const components = Array.isArray(document?.components) ? document.components : [];
  return Object.freeze({
    source,
    label: SOURCE_LABELS[source] || source,
    state,
    stateLabel: SOURCE_STATE_LABELS[state] || state,
    target,
    reason,
    executionMode,
    analyzed: state === SOURCE_STATE.ANALYZED,
    // Never `0` for a source that was not analysed: a count is a measurement,
    // and there was no measurement.
    componentCount: state === SOURCE_STATE.ANALYZED ? components.length : null,
    document: state === SOURCE_STATE.ANALYZED ? document : null
  });
}

/** Runs one inventory, converting any throw into a described state. */
async function collectSource({ source, generate, workspacePath, mode, imageName, timeoutMs, signal }) {
  const target = source === SOURCE.IMAGE ? imageName : workspacePath;
  try {
    const result = await generate({
      workspacePath,
      mode,
      // The distinction the previous orchestration lost: an empty image name
      // means « inventory the workspace », a set one means « inventory that
      // image ». They are two calls, not one call with a switch.
      imageName: source === SOURCE.IMAGE ? imageName : '',
      timeoutMs,
      signal
    });
    return sourceResult({
      source, state: SOURCE_STATE.ANALYZED, target,
      document: result?.payload || null, executionMode: result?.mode || ''
    });
  } catch (error) {
    if (signal?.aborted) {
      return sourceResult({ source, state: SOURCE_STATE.CANCELLED, target, reason: 'Analyse annulée.' });
    }
    const message = String(error?.message || 'Échec de l’inventaire.');
    return sourceResult({ source, state: classifySourceFailure(message), target, reason: message });
  }
}

/**
 * Merges the components of every analysed source into one document.
 *
 * De-duplicated on the package URL when there is one, because a dependency
 * present both in the workspace manifest and in the image is one component, not
 * two. Sources that were not analysed contribute nothing — not an empty list.
 */
function mergeSourceDocuments(sources) {
  const analyzed = sources.filter((entry) => entry.analyzed && entry.document);
  if (!analyzed.length) return null;
  const seen = new Set();
  const components = [];
  for (const entry of analyzed) {
    for (const component of entry.document.components || []) {
      const key = component?.purl
        || `${component?.name || ''}@${component?.version || ''}@${component?.type || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      components.push(component);
    }
  }
  const first = analyzed[0].document;
  return {
    bomFormat: first.bomFormat || 'CycloneDX',
    specVersion: first.specVersion || '',
    serialNumber: first.serialNumber || '',
    components
  };
}

/**
 * Collects every licence inventory source available for this workspace.
 *
 * Always attempts the workspace. Attempts the image only when one is
 * configured. Returns the sources, the merged document when at least one
 * succeeded, and whether anything at all could be analysed.
 */
async function collectLicenseSources({
  workspacePath,
  mode = 'auto',
  imageName = '',
  timeoutMs = 300000,
  signal,
  generate = generateSbom
} = {}) {
  const image = String(imageName || '').trim();
  const workspaceSource = await collectSource({
    source: SOURCE.WORKSPACE, generate, workspacePath, mode, imageName: '', timeoutMs, signal
  });
  const imageSource = image
    ? await collectSource({ source: SOURCE.IMAGE, generate, workspacePath, mode, imageName: image, timeoutMs, signal })
    : sourceResult({
      source: SOURCE.IMAGE,
      state: SOURCE_STATE.NOT_CONFIGURED,
      reason: 'Aucune image configurée pour l’analyse des licences conteneur.'
    });

  const sources = Object.freeze([workspaceSource, imageSource]);
  const document = mergeSourceDocuments(sources);
  return Object.freeze({
    sources,
    document,
    analyzable: Boolean(document),
    // A prerequisite is missing but the report is still worth producing: this
    // is the state that must not be rendered as a compliance failure.
    degraded: Boolean(document) && sources.some((entry) => !entry.analyzed && entry.state !== SOURCE_STATE.NOT_CONFIGURED)
  });
}

module.exports = {
  SOURCE,
  SOURCE_STATE,
  SOURCE_LABELS,
  SOURCE_STATE_LABELS,
  RUNTIME_SIGNATURES,
  TARGET_SIGNATURES,
  classifySourceFailure,
  collectSource,
  mergeSourceDocuments,
  collectLicenseSources
};
