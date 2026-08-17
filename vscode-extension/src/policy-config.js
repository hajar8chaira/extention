'use strict';

/**
 * Reading and writing the Policy Gate section of security-center.yml.
 *
 * This module is the bridge between the configuration UI and the single source
 * of truth on disk. It holds no state: the form is rendered from the file, and
 * saving writes back to the file. There is no second policy model anywhere, and
 * nothing here evaluates a gate — evaluation belongs to
 * `intelligence/policy-gate.js` and to it alone.
 *
 * Writing is deliberately conservative:
 *   - the file is parsed and validated before being touched;
 *   - only the `gate:` and `supply_chain:` blocks are rewritten;
 *   - the result is validated again before it reaches the disk;
 *   - the write is atomic (temporary file + rename) so a crash mid-write can
 *     never leave a half-written policy that would fail to parse.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parsePolicyYaml, validatePolicy, applyGateToPolicyYaml, starterPolicyYaml, STARTER_GATE } = require('./project-policy');

const POLICY_FILE_NAMES = Object.freeze(['security-center.yml', 'security-center.yaml']);

/** The severity thresholds the UI offers, least severe last. */
const SEVERITY_CHOICES = Object.freeze(['MEDIUM', 'HIGH', 'CRITICAL']);

/**
 * The form selection → the gate shape the engine validates.
 *
 * The severity checkboxes are cumulative because the rule is: « this severity
 * or worse ». Ticking « medium » therefore yields `[MEDIUM]`, which already
 * covers high and critical — exactly how the engine reads the list.
 */
function gateFromSelection(selection = {}) {
  const failOn = selection.failMedium ? 'MEDIUM' : selection.failHigh ? 'HIGH' : selection.failCritical ? 'CRITICAL' : '';
  const warnOn = selection.warnMedium ? 'MEDIUM' : selection.warnHigh ? 'HIGH' : '';
  return {
    gate: {
      failOnSeverity: failOn ? [failOn] : [],
      warnOnSeverity: warnOn ? [warnOn] : [],
      blockSecrets: selection.blockSecrets === true,
      priorityThreshold: threshold(selection.priorityThreshold, 'priority_threshold'),
      warnPriorityThreshold: threshold(selection.warnPriorityThreshold, 'warn_priority_threshold'),
      requireSbom: selection.requireSbom === true
    },
    supplyChain: {
      requireProvenance: selection.requireProvenance === true,
      requireSignature: selection.requireSignature === true
    }
  };
}

/** A threshold from the form. Empty means « no threshold », not zero. */
function threshold(value, key) {
  if (value === null || value === undefined || value === '') return null;
  const score = Number(value);
  if (!Number.isInteger(score) || score < 0 || score > 100) {
    throw new Error(`Le seuil ${key} doit être un entier entre 0 et 100.`);
  }
  return score;
}

/**
 * Fingerprint of the gate rules alone.
 *
 * Used to tell « the policy that produced this verdict » from « the policy on
 * disk right now », so a historical scan is never silently relabelled with a
 * policy it was not judged against. It covers the rules only, so an unrelated
 * scanner edit does not mark every past verdict as stale.
 */
function policyGateHash(policy) {
  const rules = {
    failOnSeverity: policy?.gate?.failOnSeverity || [],
    warnOnSeverity: policy?.gate?.warnOnSeverity || [],
    blockSecrets: Boolean(policy?.gate?.blockSecrets),
    priorityThreshold: policy?.gate?.priorityThreshold ?? null,
    warnPriorityThreshold: policy?.gate?.warnPriorityThreshold ?? null,
    requireSbom: Boolean(policy?.gate?.requireSbom),
    requireProvenance: Boolean(policy?.supplyChain?.requireProvenance),
    requireSignature: Boolean(policy?.supplyChain?.requireSignature)
  };
  return crypto.createHash('sha256').update(JSON.stringify(rules)).digest('hex').slice(0, 16);
}

function policyFilePath(workspacePath) {
  const existing = POLICY_FILE_NAMES
    .map((name) => path.join(workspacePath, name))
    .find((candidate) => fs.existsSync(candidate));
  return { filePath: existing || path.join(workspacePath, POLICY_FILE_NAMES[0]), exists: Boolean(existing) };
}

/**
 * What the configuration UI renders.
 *
 * An unreadable file yields `error` and no rules at all — never an empty gate
 * that the UI would then present as « nothing configured », which would invite
 * the developer to overwrite a policy they cannot currently see.
 */
async function readPolicyGateConfig(workspacePath) {
  const { filePath, exists } = policyFilePath(workspacePath);
  if (!exists) {
    return { exists: false, filePath, gate: {}, supplyChain: {}, error: '', hash: '', starter: STARTER_GATE };
  }
  try {
    const text = await fs.promises.readFile(filePath, 'utf8');
    const policy = validatePolicy(parsePolicyYaml(text));
    return {
      exists: true, filePath, gate: policy.gate, supplyChain: policy.supplyChain,
      error: '', hash: policyGateHash(policy), configured: Boolean(policy.gate.configured || policy.supplyChain.configured)
    };
  } catch (error) {
    return { exists: true, filePath, gate: {}, supplyChain: {}, error: error.message, hash: '' };
  }
}

/**
 * Writes a gate selection to security-center.yml.
 *
 * Returns `{ ok, message, filePath }` rather than throwing, because every
 * failure here is a message the developer needs to read: a refused save must
 * leave the file untouched and say why.
 */
async function savePolicyGate(workspacePath, selection = {}) {
  const { filePath, exists } = policyFilePath(workspacePath);
  try {
    const { gate, supplyChain } = gateFromSelection(selection);
    const original = exists ? await fs.promises.readFile(filePath, 'utf8') : 'version: 1\n';
    // Throws on an invalid original *and* on an invalid result, so the disk is
    // only ever reached by content that parses and validates.
    const updated = applyGateToPolicyYaml(original, { gate, supplyChain });
    await atomicWrite(filePath, updated);
    const policy = validatePolicy(parsePolicyYaml(updated));
    const configured = Boolean(policy.gate.configured || policy.supplyChain.configured);
    return {
      ok: true, filePath, hash: policyGateHash(policy), configured,
      message: configured
        ? 'Les règles ont été écrites dans security-center.yml. Ré-évaluez la politique ou relancez une analyse pour appliquer le nouveau verdict.'
        : 'Aucune règle sélectionnée : la section gate a été retirée de security-center.yml. Le Policy Gate redevient non configuré.'
    };
  } catch (error) {
    return { ok: false, filePath, message: error.message };
  }
}

/**
 * Writes the starter policy. Never called implicitly — the user asks for it.
 *
 * A project that already has a security-center.yml without any gate gets the
 * starter rules added to it, surgically. An existing gate is never replaced:
 * that is the form's job, and silently overwriting rules someone chose would be
 * the one thing a « starter » must not do.
 */
async function createStarterPolicy(workspacePath) {
  const { filePath, exists } = policyFilePath(workspacePath);
  const STARTER_MESSAGE = 'Politique de départ écrite : critiques bloquantes, secrets bloquants, priorité ≥ 80 bloquante, élevées signalées.';
  try {
    if (!exists) {
      const text = starterPolicyYaml();
      validatePolicy(parsePolicyYaml(text));
      await atomicWrite(filePath, text);
      return { ok: true, filePath, configured: true, hash: policyGateHash(validatePolicy(parsePolicyYaml(text))), message: STARTER_MESSAGE };
    }
    const original = await fs.promises.readFile(filePath, 'utf8');
    const current = validatePolicy(parsePolicyYaml(original));
    if (current.gate.configured) {
      return { ok: false, filePath, message: 'Une section gate existe déjà : modifiez-la avec le formulaire ou en éditant le YAML.' };
    }
    const updated = applyGateToPolicyYaml(original, { gate: STARTER_GATE, supplyChain: current.supplyChain });
    await atomicWrite(filePath, updated);
    return {
      ok: true, filePath, configured: true,
      hash: policyGateHash(validatePolicy(parsePolicyYaml(updated))),
      message: `${STARTER_MESSAGE} Le reste de security-center.yml est inchangé.`
    };
  } catch (error) {
    return { ok: false, filePath, message: error.message };
  }
}

/**
 * Temporary file then rename, so a reader never observes a partial policy.
 * The temporary file sits next to the target to keep the rename on one volume.
 */
async function atomicWrite(filePath, content) {
  const temporary = `${filePath}.sc-tmp`;
  await fs.promises.writeFile(temporary, content, 'utf8');
  try {
    await fs.promises.rename(temporary, filePath);
  } catch (error) {
    await fs.promises.unlink(temporary).catch(() => {});
    throw error;
  }
}

module.exports = {
  POLICY_FILE_NAMES, SEVERITY_CHOICES, gateFromSelection, policyGateHash,
  policyFilePath, readPolicyGateConfig, savePolicyGate, createStarterPolicy, atomicWrite
};
