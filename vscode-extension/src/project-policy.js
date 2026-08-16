const fs = require('fs');
const path = require('path');

const TOOL_KEYS = Object.freeze({ semgrep: 'Semgrep', gitleaks: 'Gitleaks', trivy: 'Trivy', osv: 'OSV-Scanner', sonarqube: 'SonarQube', zap: 'ZAP' });
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
  for (const [index, rawLine] of String(text).split(/\r?\n/).entries()) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = line.match(/^(\s*)([A-Za-z][\w-]*):(?:\s*(.*))?$/);
    if (!match) throw new Error(`security-center.yml ligne ${index + 1} invalide.`);
    const indent = match[1].length;
    const key = match[2];
    const value = match[3];
    if (indent === 0) {
      if (!value) { section = key; result[section] = {}; }
      else { section = undefined; result[key] = scalar(value); }
    } else {
      if (!section || indent !== 2 || !value) throw new Error(`security-center.yml ligne ${index + 1} : indentation attendue de 2 espaces.`);
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
  const maxParallelScanners = Number(raw.execution?.max_parallel_scanners ?? 2);
  if (!Number.isInteger(maxParallelScanners) || maxParallelScanners < 1 || maxParallelScanners > 4) {
    throw new Error('execution.max_parallel_scanners doit être un entier entre 1 et 4.');
  }
  return { version: Number(raw.version || 1), scanners, failOn, maxActive, includeTests, licensesDenied, gitleaksHistory, gitleaksHistoryIncremental, gitleaksConfig, semgrepCustomRules, zapActive, zapOpenapi, zapContext, zapUser, zapEngine, zapLocalPath, zapPolicyMinSeverity, zapAuth, sonarMode, sonarIncludeCodeSmells, exclusions, maxParallelScanners };
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

module.exports = { TOOL_KEYS, SEVERITY_RANK, parsePolicyYaml, validatePolicy, loadProjectPolicy, evaluatePolicy };
