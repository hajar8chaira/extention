'use strict';

/**
 * Project configuration state — the first-use experience.
 *
 * `security-center.yml` is the project-level source of truth. This module reads
 * what it declares and writes only what the user explicitly saved:
 *
 *   - no file          → NOT_CONFIGURED. Nothing is created by opening a page.
 *   - unreadable file  → INVALID, with the parser's message.
 *   - file             → CONFIGURED; `scanners.declared` says whether the user
 *                        has chosen scanners yet (a gate saved first creates the
 *                        file without inventing scanner choices).
 *
 * Nothing here is cached or mirrored into VS Code state: every read is the file.
 */

const fs = require('fs');
const { parsePolicyYaml, validatePolicy, sectionRange, TOOL_KEYS } = require('./project-policy');
const { policyFilePath, atomicWrite } = require('./policy-config');

const PROJECT_STATE = Object.freeze({
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  CONFIGURED: 'CONFIGURED',
  INVALID: 'INVALID'
});

/** Scanners the project file can declare, in display order: [yaml key, tool]. */
const PROJECT_SCANNERS = Object.freeze(Object.entries(TOOL_KEYS));

const FIRST_USE_MESSAGE = 'Security Center n’est pas encore configuré pour ce projet.';

/** What security-center.yml declares, read from disk every time. */
async function readProjectConfiguration(workspacePath) {
  const { filePath, exists } = policyFilePath(workspacePath);
  const empty = { declared: false, enabled: [], disabled: [] };
  if (!exists) {
    return { state: PROJECT_STATE.NOT_CONFIGURED, filePath, exists: false, scanners: empty, gateConfigured: false, error: '', message: FIRST_USE_MESSAGE };
  }
  try {
    const text = await fs.promises.readFile(filePath, 'utf8');
    const raw = parsePolicyYaml(text);
    const policy = validatePolicy(raw);
    const declaredSection = raw.scanners && typeof raw.scanners === 'object' ? raw.scanners : null;
    const scanners = declaredSection
      ? {
        declared: true,
        enabled: PROJECT_SCANNERS.filter(([key]) => declaredSection[key] === true).map(([, tool]) => tool),
        disabled: PROJECT_SCANNERS.filter(([key]) => declaredSection[key] === false).map(([, tool]) => tool)
      }
      : empty;
    return {
      state: PROJECT_STATE.CONFIGURED, filePath, exists: true, scanners,
      gateConfigured: Boolean(policy.gate.configured || policy.supplyChain.configured), error: '', message: ''
    };
  } catch (error) {
    return { state: PROJECT_STATE.INVALID, filePath, exists: true, scanners: empty, gateConfigured: false, error: error.message, message: error.message };
  }
}

/** The `scanners:` block for a selection: every known scanner, explicitly true or false. */
function renderScannersSection(selectedTools = []) {
  const selected = new Set(selectedTools);
  return ['scanners:', ...PROJECT_SCANNERS.map(([key, tool]) => `  ${key}: ${selected.has(tool) ? 'true' : 'false'}`)];
}

/**
 * Replaces (or adds) only the `scanners:` block. Every other line — gate,
 * supply chain, policy, ZAP, exclusions, comments — is carried over unchanged.
 * Unselected scanners are written `false`: an absent key would let the engine
 * run a scanner the user did not choose.
 */
function applyScannersToPolicyYaml(text, selectedTools = []) {
  const original = String(text ?? '');
  validatePolicy(parsePolicyYaml(original));
  const newline = original.includes('\r\n') ? '\r\n' : '\n';
  let lines = original.split(/\r?\n/);
  if (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  const block = renderScannersSection(selectedTools);
  const range = sectionRange(lines, 'scanners');
  if (range) {
    lines = [...lines.slice(0, range.start), ...block, ...lines.slice(range.end)];
  } else {
    // Right after `version:` when present, so the file reads top-down.
    const versionIndex = lines.findIndex((line) => /^version:/.test(line));
    const at = versionIndex >= 0 ? versionIndex + 1 : 0;
    lines = [...lines.slice(0, at), ...block, ...lines.slice(at)];
  }
  const updated = `${lines.join(newline)}${newline}`;
  validatePolicy(parsePolicyYaml(updated));
  return updated;
}

/**
 * The explicit « save scanners » action. Creates security-center.yml when the
 * project has none — this is the only moment the file is created from the
 * scanner choice. An empty selection is refused rather than saved.
 */
async function saveProjectScanners(workspacePath, selectedTools = []) {
  const { filePath, exists } = policyFilePath(workspacePath);
  const known = new Set(PROJECT_SCANNERS.map(([, tool]) => tool));
  const tools = [...new Set((Array.isArray(selectedTools) ? selectedTools : []).filter((tool) => known.has(tool)))];
  if (!tools.length) {
    return { ok: false, filePath, created: false, message: 'Sélectionnez au moins un scanner avant d’enregistrer la configuration du projet.' };
  }
  try {
    const original = exists ? await fs.promises.readFile(filePath, 'utf8') : 'version: 1\n';
    const updated = applyScannersToPolicyYaml(original, tools);
    await atomicWrite(filePath, updated);
    return {
      ok: true, filePath, created: !exists, tools,
      message: exists
        ? `Scanners du projet enregistrés dans security-center.yml : ${tools.join(', ')}.`
        : `security-center.yml créé avec les scanners sélectionnés : ${tools.join(', ')}.`
    };
  } catch (error) {
    return { ok: false, filePath, created: false, message: error.message };
  }
}

module.exports = {
  PROJECT_STATE, PROJECT_SCANNERS, FIRST_USE_MESSAGE,
  readProjectConfiguration, renderScannersSection, applyScannersToPolicyYaml, saveProjectScanners
};
