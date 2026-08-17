const fs = require('fs');
const path = require('path');

const TOOL_KEYS = Object.freeze({ semgrep: 'Semgrep', gitleaks: 'Gitleaks', trivy: 'Trivy', osv: 'OSV-Scanner', sonarqube: 'SonarQube', snyk: 'Snyk', zap: 'ZAP' });
const SEVERITY_RANK = Object.freeze({ INFORMATION: 0, INFO: 0, LOW: 1, WARNING: 2, MEDIUM: 2, HIGH: 3, ERROR: 3, CRITICAL: 4 });

function scalar(value) {
  const text = String(value).trim();
  if (text.startsWith('[') && text.endsWith(']')) {
    const inner = text.slice(1, -1).trim();
    return inner ? inner.split(',').map((item) => item.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean) : [];
  }
  if (/^(true|false)$/i.test(text)) return text.toLowerCase() === 'true';
  if (/^-?\d+$/.test(text)) return Number(text);
  return text.replace(/^['"]|['"]$/g, '');
}

function parsePolicyYaml(text) {
  const result = {};
  let section;
  // The key a block sequence is currently filling, e.g. `fail_on_severity:`
  // followed by `- CRITICAL` lines. Inline `[A, B]` lists keep working
  // unchanged; this only accepts the other spelling of the same thing.
  let sequence = null;
  for (const [index, rawLine] of String(text).split(/\r?\n/).entries()) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const item = line.match(/^(\s*)-\s+(.*)$/);
    if (item) {
      if (!sequence) throw new Error(`security-center.yml ligne ${index + 1} : élément de liste sans clé parente.`);
      if (item[1].length < sequence.indent) throw new Error(`security-center.yml ligne ${index + 1} : élément de liste mal indenté.`);
      sequence.values.push(scalar(item[2]));
      continue;
    }
    const match = line.match(/^(\s*)([A-Za-z][\w-]*):(?:\s*(.*))?$/);
    if (!match) throw new Error(`security-center.yml ligne ${index + 1} invalide.`);
    const indent = match[1].length;
    const key = match[2];
    const value = match[3];
    sequence = null;
    if (indent === 0) {
      if (!value) { section = key; result[section] = {}; }
      else { section = undefined; result[key] = scalar(value); }
    } else {
      if (!section || indent !== 2) throw new Error(`security-center.yml ligne ${index + 1} : indentation attendue de 2 espaces.`);
      if (!value) {
        // A key with nothing after it opens a block sequence. The array is
        // installed immediately so an empty list stays an empty list rather
        // than becoming an absent key.
        sequence = { indent: indent + 1, values: [] };
        result[section][key] = sequence.values;
        continue;
      }
      result[section][key] = scalar(value);
    }
  }
  return result;
}

function validatePolicy(raw) {
  const scanners = {};
  for (const [key, value] of Object.entries(raw.scanners || {})) {
    if (!TOOL_KEYS[key]) throw new Error(`Scanner inconnu dans security-center.yml : ${key}.`);
    if (typeof value !== 'boolean') throw new Error(`scanners.${key} doit être true ou false.`);
    scanners[TOOL_KEYS[key]] = value;
  }
  const failOn = String(raw.policy?.fail_on || 'CRITICAL').toUpperCase();
  if (!(failOn in SEVERITY_RANK)) throw new Error(`Seuil de sévérité inconnu : ${failOn}.`);
  const maxActive = Number(raw.policy?.max_active ?? 999999);
  if (!Number.isInteger(maxActive) || maxActive < 0) throw new Error('policy.max_active doit être un entier positif ou nul.');
  const includeTests = raw.policy?.include_tests ?? true;
  if (typeof includeTests !== 'boolean') throw new Error('policy.include_tests doit être true ou false.');
  const licensesDenied = raw.licenses?.denied ?? [];
  if (!Array.isArray(licensesDenied) || licensesDenied.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error('licenses.denied doit être une liste, par exemple [AGPL-3.0, GPL-3.0].');
  }
  const gitleaksHistory = raw.gitleaks?.history ?? false;
  const gitleaksHistoryIncremental = raw.gitleaks?.history_incremental ?? true;
  if (typeof gitleaksHistory !== 'boolean' || typeof gitleaksHistoryIncremental !== 'boolean') {
    throw new Error('gitleaks.history et gitleaks.history_incremental doivent être true ou false.');
  }
  const gitleaksConfig = String(raw.gitleaks?.config || '').trim();
  const semgrepCustomRules = String(raw.semgrep?.custom_rules || '').trim();
  const zapActive = raw.zap?.active ?? false;
  if (typeof zapActive !== 'boolean') throw new Error('zap.active doit être true ou false.');
  const zapOpenapi = String(raw.zap?.openapi || '').trim();
  const zapContext = String(raw.zap?.context || '').trim();
  const zapUser = String(raw.zap?.user || '').trim();
  const zapEngine = String(raw.zap?.mode || 'auto').trim().toLowerCase();
  if (!['auto', 'local', 'docker'].includes(zapEngine)) throw new Error('zap.mode doit être auto, local ou docker.');
  const zapLocalPath = String(raw.zap?.local_path || '').trim();
  const zapPolicyMinSeverity = String(raw.zap?.policy_min_severity || 'INFO').trim().toUpperCase();
  if (!(zapPolicyMinSeverity in SEVERITY_RANK)) throw new Error(`Seuil ZAP inconnu : ${zapPolicyMinSeverity}.`);
  const zapAuth = {
    login: String(raw.zap?.auth_login || '').trim(),
    usernameEnv: String(raw.zap?.auth_username_env || 'SECURITY_CENTER_ZAP_USERNAME').trim(),
    passwordEnv: String(raw.zap?.auth_password_env || 'SECURITY_CENTER_ZAP_PASSWORD').trim(),
    tokenPath: String(raw.zap?.auth_token_path || 'authentication.token').trim(),
    usernameField: String(raw.zap?.auth_username_field || 'email').trim(),
    passwordField: String(raw.zap?.auth_password_field || 'password').trim(),
    header: String(raw.zap?.auth_header || 'Authorization').trim(),
    prefix: String(raw.zap?.auth_prefix || 'Bearer').trim()
  };
  if (zapAuth.login && (!zapAuth.usernameEnv || !zapAuth.passwordEnv || !zapAuth.tokenPath || !zapAuth.header)) {
    throw new Error('La configuration zap.auth_* est incomplète.');
  }
  if (zapActive && zapOpenapi) throw new Error('Choisissez soit zap.active, soit zap.openapi, pas les deux.');
  const exclusionKeys = ['global_files', 'semgrep_files', 'semgrep_rules', 'trivy_files', 'zap_routes'];
  const exclusions = {};
  for (const key of exclusionKeys) {
    const values = raw.exclusions?.[key] ?? [];
    if (!Array.isArray(values) || values.some((item) => typeof item !== 'string' || !item.trim())) {
      throw new Error(`exclusions.${key} doit être une liste.`);
    }
    exclusions[key] = [...new Set(values.map((item) => item.trim()))];
  }
  // Only the execution mode is versionable. `sonar.host_url` and the token stay
  // in VS Code settings/SecretStorage so an untrusted repository can never
  // redirect the analysis and its credentials to another server.
  // An absent key stays empty so the VS Code setting keeps applying: a policy
  // file without a `sonarqube:` section must not silently override it.
  const sonarMode = raw.sonarqube?.mode === undefined ? '' : String(raw.sonarqube.mode).trim().toLowerCase();
  if (sonarMode && !['auto', 'local', 'docker'].includes(sonarMode)) throw new Error('sonarqube.mode doit être auto, local ou docker.');
  const sonarIncludeCodeSmells = raw.sonarqube?.include_code_smells;
  if (sonarIncludeCodeSmells !== undefined && typeof sonarIncludeCodeSmells !== 'boolean') {
    throw new Error('sonarqube.include_code_smells doit être true ou false.');
  }
  // Same rule as SonarQube: only the execution mode and the capabilities are
  // versionable. The Snyk token never leaves SecretStorage, so an untrusted
  // repository can never redirect credentials or enable a paid capability
  // silently. Absent keys stay undefined so the VS Code settings keep applying.
  const snykMode = raw.snyk?.mode === undefined ? '' : String(raw.snyk.mode).trim().toLowerCase();
  if (snykMode && !['auto', 'local', 'docker'].includes(snykMode)) throw new Error('snyk.mode doit être auto, local ou docker.');
  const snykCapabilities = {};
  for (const [key, property] of [['include_open_source', 'includeOpenSource'], ['include_code', 'includeCode'], ['include_iac', 'includeIaC']]) {
    const value = raw.snyk?.[key];
    if (value === undefined) continue;
    if (typeof value !== 'boolean') throw new Error(`snyk.${key} doit être true ou false.`);
    snykCapabilities[property] = value;
  }
  // Policy Gate V2. Purely additive: a file without a `gate:` section keeps the
  // historical fail_on/max_active behaviour untouched. Only controls Security
  // Center can actually evaluate are accepted — an unknown key is an error
  // rather than a silently ignored promise.
  const GATE_KEYS = ['fail_on_severity', 'warn_on_severity', 'block_secrets', 'priority_threshold', 'warn_priority_threshold', 'require_sbom'];
  for (const key of Object.keys(raw.gate || {})) {
    if (!GATE_KEYS.includes(key)) throw new Error(`Clé inconnue dans gate : ${key}. Clés acceptées : ${GATE_KEYS.join(', ')}.`);
  }
  const severityList = (value, key) => {
    if (value === undefined) return [];
    const values = Array.isArray(value) ? value : [value];
    return values.map((item) => {
      const severity = String(item).trim().toUpperCase();
      if (!(severity in SEVERITY_RANK)) throw new Error(`gate.${key} contient une sévérité inconnue : ${item}.`);
      return severity;
    });
  };
  const threshold = (value, key) => {
    if (value === undefined) return null;
    const score = Number(value);
    if (!Number.isInteger(score) || score < 0 || score > 100) throw new Error(`gate.${key} doit être un entier entre 0 et 100.`);
    return score;
  };
  const booleanOption = (value, key) => {
    if (value === undefined) return false;
    if (typeof value !== 'boolean') throw new Error(`${key} doit être true ou false.`);
    return value;
  };
  const gate = {
    configured: Boolean(raw.gate && Object.keys(raw.gate).length),
    failOnSeverity: severityList(raw.gate?.fail_on_severity, 'fail_on_severity'),
    warnOnSeverity: severityList(raw.gate?.warn_on_severity, 'warn_on_severity'),
    blockSecrets: booleanOption(raw.gate?.block_secrets, 'gate.block_secrets'),
    priorityThreshold: threshold(raw.gate?.priority_threshold, 'priority_threshold'),
    warnPriorityThreshold: threshold(raw.gate?.warn_priority_threshold, 'warn_priority_threshold'),
    requireSbom: booleanOption(raw.gate?.require_sbom, 'gate.require_sbom')
  };
  // Supply-chain requirements are evaluated only for the stages that ran, so a
  // project can declare them before the corresponding artefact exists.
  const SUPPLY_CHAIN_KEYS = ['require_provenance', 'require_signature'];
  for (const key of Object.keys(raw.supply_chain || {})) {
    if (!SUPPLY_CHAIN_KEYS.includes(key)) throw new Error(`Clé inconnue dans supply_chain : ${key}. Clés acceptées : ${SUPPLY_CHAIN_KEYS.join(', ')}.`);
  }
  const supplyChain = {
    configured: Boolean(raw.supply_chain && Object.keys(raw.supply_chain).length),
    requireProvenance: booleanOption(raw.supply_chain?.require_provenance, 'supply_chain.require_provenance'),
    requireSignature: booleanOption(raw.supply_chain?.require_signature, 'supply_chain.require_signature')
  };
  const maxParallelScanners = Number(raw.execution?.max_parallel_scanners ?? 2);
  if (!Number.isInteger(maxParallelScanners) || maxParallelScanners < 1 || maxParallelScanners > 4) {
    throw new Error('execution.max_parallel_scanners doit être un entier entre 1 et 4.');
  }
  return { version: Number(raw.version || 1), scanners, failOn, maxActive, includeTests, licensesDenied, gitleaksHistory, gitleaksHistoryIncremental, gitleaksConfig, semgrepCustomRules, zapActive, zapOpenapi, zapContext, zapUser, zapEngine, zapLocalPath, zapPolicyMinSeverity, zapAuth, sonarMode, sonarIncludeCodeSmells, snykMode, snykCapabilities, gate, supplyChain, exclusions, maxParallelScanners };
}

async function loadProjectPolicy(workspacePath) {
  for (const name of ['security-center.yml', 'security-center.yaml']) {
    const filePath = path.join(workspacePath, name);
    try {
      const text = await fs.promises.readFile(filePath, 'utf8');
      return { ...validatePolicy(parsePolicyYaml(text)), filePath };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return null;
}

function evaluatePolicy(findings, policy) {
  if (!policy) return null;
  const allActive = findings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus)
    && (policy.includeTests || finding.sourceContext !== 'test'));
  const active = allActive.filter((finding) => finding.tool !== 'ZAP'
    || (SEVERITY_RANK[String(finding.rawSeverity || finding.severity).toUpperCase()] ?? 0) >= SEVERITY_RANK[policy.zapPolicyMinSeverity || 'INFO']);
  const threshold = SEVERITY_RANK[policy.failOn];
  const blockingFindings = active.filter((finding) => (SEVERITY_RANK[String(finding.rawSeverity || finding.severity).toUpperCase()] ?? 0) >= threshold);
  const reasons = [];
  if (blockingFindings.length) reasons.push(`${blockingFindings.length} alerte(s) au seuil ${policy.failOn} ou supérieur`);
  if (active.length > policy.maxActive) reasons.push(`${active.length} alerte(s) actives > maximum ${policy.maxActive}`);
  return { passed: reasons.length === 0, activeCount: active.length, totalActiveCount: allActive.length, ignoredByToolThreshold: allActive.length - active.length, blockingCount: blockingFindings.length, reasons, policy };
}

// ---------------------------------------------------------------------------
// Writing the gate back to security-center.yml
//
// The UI is an editor for this file, not a second source of truth. Writing is
// therefore surgical: only the `gate:` and `supply_chain:` blocks are replaced,
// every other line — scanner configuration, exclusions, ZAP settings, blank
// lines and comments between sections — is carried over byte for byte.
//
// Known limitation: comments written *inside* the two blocks being replaced
// cannot survive, because those blocks are regenerated from the values. Comments
// anywhere else in the file, including immediately above `gate:`, are preserved.
// ---------------------------------------------------------------------------

/** The starter policy offered when a project has no gate yet. */
const STARTER_GATE = Object.freeze({
  failOnSeverity: ['CRITICAL'], warnOnSeverity: ['HIGH'], blockSecrets: true,
  priorityThreshold: 80, warnPriorityThreshold: null, requireSbom: false
});

function renderList(values) {
  return `[${values.join(', ')}]`;
}

/** The YAML lines for a gate selection. An empty selection renders nothing. */
function renderGateSection(gate = {}) {
  const lines = [];
  if (gate.failOnSeverity?.length) lines.push(`  fail_on_severity: ${renderList(gate.failOnSeverity)}`);
  if (gate.warnOnSeverity?.length) lines.push(`  warn_on_severity: ${renderList(gate.warnOnSeverity)}`);
  if (gate.blockSecrets) lines.push('  block_secrets: true');
  if (Number.isInteger(gate.priorityThreshold)) lines.push(`  priority_threshold: ${gate.priorityThreshold}`);
  if (Number.isInteger(gate.warnPriorityThreshold)) lines.push(`  warn_priority_threshold: ${gate.warnPriorityThreshold}`);
  if (gate.requireSbom) lines.push('  require_sbom: true');
  return lines.length ? ['gate:', ...lines] : [];
}

function renderSupplyChainSection(supplyChain = {}) {
  const lines = [];
  if (supplyChain.requireProvenance) lines.push('  require_provenance: true');
  if (supplyChain.requireSignature) lines.push('  require_signature: true');
  return lines.length ? ['supply_chain:', ...lines] : [];
}

/**
 * Locates a top-level section, as a `[start, end)` line range.
 *
 * The range stops at the next top-level key, so trailing blank lines and any
 * comment introducing the *following* section stay outside it and survive.
 */
function sectionRange(lines, name) {
  const start = lines.findIndex((line) => new RegExp(`^${name}:\\s*(#.*)?$`).test(line));
  if (start === -1) return null;
  let end = start + 1;
  while (end < lines.length && !/^[A-Za-z][\w-]*:/.test(lines[end])) end += 1;
  // Blank lines and comments trailing the block belong to what comes next.
  while (end - 1 > start && !lines[end - 1].trim()) end -= 1;
  return { start, end };
}

function replaceSection(lines, name, replacement) {
  const range = sectionRange(lines, name);
  if (!range) {
    if (!replacement.length) return lines;
    const body = [...lines];
    while (body.length && !body[body.length - 1].trim()) body.pop();
    return [...body, '', ...replacement];
  }
  return [...lines.slice(0, range.start), ...replacement, ...lines.slice(range.end)];
}

/**
 * The new file content for a gate selection.
 *
 * Pure: it takes text and returns text, and it validates the result by parsing
 * it before handing it back. A selection that cannot produce a valid policy
 * throws here rather than reaching the disk.
 */
function applyGateToPolicyYaml(text, { gate = {}, supplyChain = {} } = {}) {
  const original = String(text ?? '');
  // Parse first: refusing to touch a file we cannot understand is what keeps a
  // hand-written policy from being silently flattened by the UI.
  validatePolicy(parsePolicyYaml(original));
  const newline = original.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\r?\n$/.test(original) || !original.trim();
  let lines = original.split(/\r?\n/);
  if (trailing && lines.length && !lines[lines.length - 1].trim()) lines.pop();
  lines = replaceSection(lines, 'gate', renderGateSection(gate));
  lines = replaceSection(lines, 'supply_chain', renderSupplyChainSection(supplyChain));
  const updated = `${lines.join(newline).replace(/^(\r?\n)+/, '')}${newline}`;
  // And validate what we are about to write, so an invalid file is never saved.
  validatePolicy(parsePolicyYaml(updated));
  return updated;
}

/** The starter file for a project that has no security-center.yml at all. */
function starterPolicyYaml() {
  return [
    '# Politique de sécurité Security Center.',
    '# Le gate décide si le projet peut être livré.',
    'version: 1',
    '',
    ...renderGateSection(STARTER_GATE),
    ''
  ].join('\n');
}

module.exports = {
  TOOL_KEYS, SEVERITY_RANK, parsePolicyYaml, validatePolicy, loadProjectPolicy, evaluatePolicy,
  STARTER_GATE, applyGateToPolicyYaml, starterPolicyYaml, renderGateSection, sectionRange
};
