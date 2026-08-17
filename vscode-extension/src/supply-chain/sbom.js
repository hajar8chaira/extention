'use strict';

/**
 * SBOM as a pipeline artefact.
 *
 * The generation itself already exists (Trivy, CycloneDX) and is not rebuilt
 * here. This module promotes its output to a first-class artefact: written to
 * disk, digested, and described well enough for the policy gate and the
 * provenance stage to reference it.
 */

const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { generateSbom } = require('../trivy');

const ARTIFACT_DIRECTORY = 'security-center';

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/** Describes a CycloneDX document without re-parsing it everywhere. */
function describeSbom(document) {
  const components = Array.isArray(document?.components) ? document.components : [];
  return {
    format: String(document?.bomFormat || ''),
    specVersion: String(document?.specVersion || ''),
    serialNumber: String(document?.serialNumber || ''),
    componentCount: components.length,
    // A quick breakdown so the UI can say what the SBOM actually covers.
    componentTypes: components.reduce((counts, component) => {
      const type = String(component?.type || 'unknown');
      return { ...counts, [type]: (counts[type] || 0) + 1 };
    }, {})
  };
}

function artifactPath(workspacePath, outputDirectory, fileName) {
  return path.resolve(outputDirectory || path.join(workspacePath, ARTIFACT_DIRECTORY), fileName);
}

/**
 * Generates the SBOM and persists it. Returns the artefact descriptor the
 * pipeline stores and the policy gate reads; failures are described, never
 * thrown into the caller's face, so one missing tool cannot abort a scan.
 */
async function generateSbomArtifact({
  workspacePath,
  mode = 'auto',
  imageName = '',
  outputDirectory = '',
  fileName = 'sbom.cdx.json',
  timeoutMs = 300000,
  signal,
  generate = generateSbom
} = {}) {
  const startedAt = new Date().toISOString();
  try {
    const result = await generate({ workspacePath, mode, imageName, timeoutMs, signal });
    const serialized = `${JSON.stringify(result.payload, null, 2)}\n`;
    const destination = artifactPath(workspacePath, outputDirectory, fileName);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, serialized, 'utf8');
    return {
      status: 'generated',
      ...describeSbom(result.payload),
      path: destination,
      digest: `sha256:${sha256Hex(serialized)}`,
      bytes: Buffer.byteLength(serialized),
      target: imageName || workspacePath,
      executionMode: result.mode,
      generatedAt: startedAt
    };
  } catch (error) {
    if (signal?.aborted) return { status: 'cancelled', reason: 'Génération SBOM annulée.', generatedAt: startedAt };
    return { status: 'failed', reason: error.message, generatedAt: startedAt };
  }
}

/** Reads back a previously generated SBOM artefact, if it is still on disk. */
async function readSbomArtifact(artifact) {
  if (!artifact?.path) return null;
  try {
    const text = await fs.readFile(artifact.path, 'utf8');
    return { document: JSON.parse(text), digest: `sha256:${sha256Hex(text)}`, path: artifact.path };
  } catch { return null; }
}

module.exports = { generateSbomArtifact, readSbomArtifact, describeSbom, artifactPath, sha256Hex, ARTIFACT_DIRECTORY };
