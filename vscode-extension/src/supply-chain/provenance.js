'use strict';

/**
 * Build provenance.
 *
 * The document follows the in-toto Statement v1 envelope with a SLSA
 * Provenance v1 predicate. That makes it *SLSA-compatible in structure* — it is
 * not a SLSA level attestation, and nothing here claims one: a level depends on
 * the build platform's isolation and on who signs the statement, neither of
 * which a local developer machine can assert about itself.
 *
 * Every field is filled from evidence the pipeline actually collected. Fields
 * with no evidence are omitted rather than invented.
 */

const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';
const BUILDER_ID = 'https://github.com/security-center/local-builder';
const BUILD_TYPE = 'https://security-center.local/buildtypes/workspace-scan/v1';

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(await fs.readFile(filePath));
  return hash.digest('hex');
}

/**
 * A remote URL can embed credentials (`https://user:token@host/repo`). They are
 * stripped here, at the point where the value enters the document, so no caller
 * can bypass the scrubbing by supplying its own repository string.
 */
function scrubRepositoryUrl(value) {
  return String(value || '').replace(/\/\/[^@/\s]*@/, '//');
}

/** Repository evidence, only when the workspace really is a Git checkout. */
async function gitContext(workspacePath, { exec = execFileAsync } = {}) {
  const run = async (args) => {
    try {
      const { stdout } = await exec('git', ['-C', path.resolve(workspacePath), ...args], { windowsHide: true, timeout: 5000 });
      return String(stdout).trim();
    } catch { return ''; }
  };
  const [commit, remote, branch] = await Promise.all([
    run(['rev-parse', 'HEAD']),
    run(['config', '--get', 'remote.origin.url']),
    run(['rev-parse', '--abbrev-ref', 'HEAD'])
  ]);
  if (!commit) return null;
  return { commit, repository: scrubRepositoryUrl(remote), branch: branch && branch !== 'HEAD' ? branch : '' };
}

/**
 * Builds the provenance statement.
 *
 * `subject` is the artefact being attested; `sbom`, `policy` and `scanners`
 * are references to what the pipeline established about it.
 */
async function generateProvenance({
  workspacePath,
  artifactPath,
  sbom = null,
  policy = null,
  scanners = [],
  startedAt = '',
  finishedAt = new Date().toISOString(),
  outputPath = '',
  builderId = BUILDER_ID,
  git = undefined,
  exec = execFileAsync
} = {}) {
  const artifact = path.resolve(artifactPath);
  let digest;
  try { digest = await sha256File(artifact); }
  catch { return { status: 'failed', reason: `Artefact introuvable ou illisible : ${artifact}` }; }
  const context = git === undefined ? await gitContext(workspacePath, { exec }) : git;
  // Scrubbed again here: a caller-supplied context must not be trusted either.
  const repository = context ? { ...context, repository: scrubRepositoryUrl(context.repository) } : null;

  const statement = {
    _type: STATEMENT_TYPE,
    subject: [{ name: path.basename(artifact), digest: { sha256: digest } }],
    predicateType: PREDICATE_TYPE,
    predicate: {
      buildDefinition: {
        buildType: BUILD_TYPE,
        externalParameters: {
          workspace: path.basename(path.resolve(workspacePath)),
          ...(repository?.repository ? { repository: repository.repository } : {}),
          ...(repository?.branch ? { ref: repository.branch } : {})
        },
        // Only real, digest-bearing inputs are listed as resolved dependencies.
        resolvedDependencies: [
          ...(repository?.commit ? [{
            uri: repository.repository ? `git+${repository.repository}` : 'git+local',
            digest: { gitCommit: repository.commit }
          }] : []),
          ...(sbom?.digest ? [{
            name: 'sbom',
            uri: sbom.path ? `file://${String(sbom.path).replaceAll('\\', '/')}` : undefined,
            digest: { sha256: String(sbom.digest).replace(/^sha256:/, '') },
            mediaType: 'application/vnd.cyclonedx+json'
          }] : [])
        ]
      },
      runDetails: {
        builder: {
          id: builderId,
          // Named honestly: this is a developer workstation, not an isolated
          // hosted builder, and the provenance says so.
          builderDependencies: [{ name: 'security-center', uri: 'https://security-center.local' }]
        },
        metadata: {
          invocationId: crypto.randomUUID(),
          startedOn: startedAt || finishedAt,
          finishedOn: finishedAt
        },
        byproducts: [
          ...(sbom?.status === 'generated' ? [{
            name: 'sbom',
            mediaType: 'application/vnd.cyclonedx+json',
            digest: { sha256: String(sbom.digest || '').replace(/^sha256:/, '') },
            annotations: { componentCount: sbom.componentCount ?? null, format: sbom.format || '' }
          }] : []),
          ...(policy ? [{
            name: 'policy-gate',
            annotations: {
              status: policy.status,
              violations: policy.violations?.length ?? 0,
              warnings: policy.warnings?.length ?? 0,
              evaluatedAt: policy.evaluatedAt || ''
            }
          }] : []),
          ...(scanners.length ? [{
            name: 'scanners',
            annotations: {
              executed: scanners.map((scanner) => `${scanner.tool}:${scanner.status}`)
            }
          }] : [])
        ]
      }
    }
  };

  const serialized = `${JSON.stringify(statement, null, 2)}\n`;
  const destination = outputPath
    ? path.resolve(outputPath)
    : path.join(path.dirname(artifact), `${path.basename(artifact)}.provenance.json`);
  try {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, serialized, 'utf8');
  } catch (error) {
    return { status: 'failed', reason: `Écriture de la provenance impossible : ${error.message}` };
  }
  return {
    status: 'generated',
    path: destination,
    statement,
    artifact,
    artifactDigest: `sha256:${digest}`,
    digest: `sha256:${crypto.createHash('sha256').update(serialized).digest('hex')}`,
    predicateType: PREDICATE_TYPE,
    // Deliberate wording: structure-compatible, not a certified SLSA level.
    conformance: 'in-toto Statement v1 + SLSA Provenance v1 (structure)',
    slsaLevelClaimed: null,
    sbomLinked: Boolean(sbom?.digest),
    policyStatus: policy?.status || null,
    repository: repository?.repository || '',
    commit: repository?.commit || '',
    generatedAt: finishedAt
  };
}

/** Structural check used by the tests and by the Supply Chain page. */
function validateProvenance(statement) {
  const problems = [];
  if (statement?._type !== STATEMENT_TYPE) problems.push('_type doit être une Statement in-toto v1.');
  if (statement?.predicateType !== PREDICATE_TYPE) problems.push('predicateType doit être une provenance SLSA v1.');
  if (!Array.isArray(statement?.subject) || !statement.subject.length) problems.push('subject est obligatoire.');
  else if (!statement.subject.every((entry) => entry?.digest?.sha256)) problems.push('chaque subject doit porter un digest sha256.');
  if (!statement?.predicate?.buildDefinition?.buildType) problems.push('buildDefinition.buildType est obligatoire.');
  if (!statement?.predicate?.runDetails?.builder?.id) problems.push('runDetails.builder.id est obligatoire.');
  return { valid: problems.length === 0, problems };
}

module.exports = {
  STATEMENT_TYPE, PREDICATE_TYPE, BUILDER_ID, BUILD_TYPE,
  generateProvenance, validateProvenance, gitContext, sha256File, scrubRepositoryUrl
};
