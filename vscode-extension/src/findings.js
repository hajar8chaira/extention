const path = require('path');

const severityMap = Object.freeze({ ERROR: 'error', WARNING: 'warning', INFO: 'information' });
const commonSeverityMap = Object.freeze({
  CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'information', UNKNOWN: 'warning'
});

function normalizePath(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
}

function normalizeScannerPath(value) {
  const normalized = normalizePath(value);
  return normalized === '/src' ? '' : normalized.replace(/^\/src\//i, '').replace(/^src\//i, '');
}

function classifySourceContext(file) {
  const normalized = `/${normalizePath(file).toLowerCase()}`;
  const isTest = /\/(test|tests|spec|specs|__tests__|fixtures|mocks|examples?)\//.test(normalized)
    || /\.(spec|test)\.[^/]+$/.test(normalized);
  return isTest ? 'test' : 'production';
}

function gitleaksRisk(result, context) {
  const rule = String(result.RuleID || '').toLowerCase();
  if (context === 'test') return { severity: 'warning', rawSeverity: 'MEDIUM', confidence: 'low' };
  if (rule.includes('private-key') || rule.includes('github-pat') || rule.includes('aws')) {
    return { severity: 'error', rawSeverity: 'CRITICAL', confidence: 'high' };
  }
  return { severity: 'error', rawSeverity: 'HIGH', confidence: 'medium' };
}

function deduplicateFindings(findings) {
  const unique = new Map();
  for (const finding of findings) {
    const key = [
      String(finding.tool || '').toLowerCase(),
      String(finding.ruleId || '').toLowerCase(),
      normalizeScannerPath(finding.file).toLowerCase(),
      finding.startLine,
      finding.startColumn
    ].join('|');
    if (!unique.has(key)) unique.set(key, finding);
  }
  return [...unique.values()];
}

function cleanScannerText(value) {
  return String(value || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function zapConfidence(value) {
  const labels = { '0': 'false-positive', '1': 'low', '2': 'medium', '3': 'high', '4': 'confirmed' };
  return labels[String(value)] || String(value || 'medium').toLowerCase();
}

function zapDeveloperGuidance(alert) {
  const guidance = {
    '10038': {
      summary: 'Le navigateur ne reçoit pas de politique CSP pour limiter les scripts et ressources autorisés.',
      impact: 'Une injection HTML ou JavaScript peut être plus facile à exploiter, car le navigateur ne dispose pas d’une seconde barrière.',
      action: 'Définir un en-tête Content-Security-Policy restrictif, le tester en mode Report-Only, puis supprimer progressivement unsafe-inline et les sources trop larges.'
    },
    '10110': {
      summary: 'Le JavaScript livré au navigateur utilise une fonction qui contourne ou affaiblit les protections de sécurité du framework.',
      impact: 'Si une donnée contrôlée par un utilisateur atteint cette fonction, elle peut devenir une injection de contenu ou un XSS.',
      action: 'Identifier l’appel indiqué dans la preuve, vérifier l’origine de la donnée, supprimer le contournement si possible et appliquer une validation ou une sanitisation adaptée.'
    },
    '10003': {
      summary: 'Une bibliothèque JavaScript connue comme vulnérable a été observée dans la page.',
      impact: 'Le risque dépend de la version, de la fonctionnalité réellement utilisée et de son accessibilité depuis une entrée utilisateur.',
      action: 'Identifier le package et sa version, vérifier la CVE avec Trivy/OSV, puis mettre à niveau vers une version corrigée et relancer le scénario.'
    }
  };
  return guidance[String(alert.pluginid)] || {
    summary: `ZAP a observé « ${cleanScannerText(alert.alert || alert.name || 'comportement potentiellement vulnérable')} » sur une réponse HTTP.`,
    impact: 'Cette alerte doit être replacée dans le contexte de l’application avant d’être confirmée.',
    action: 'Examiner la preuve et l’endpoint, appliquer la recommandation technique, puis rejouer la requête pour vérifier la correction.'
  };
}

function normalizeSemgrepResult(result, workspacePath) {
  const extra = result.extra || {};
  const metadata = extra.metadata || {};
  const relativePath = normalizePath(result.path);
  const absolutePath = path.resolve(workspacePath, relativePath);
  const start = result.start || {};
  const end = result.end || start;
  const rawSeverity = String(extra.severity || 'WARNING').toUpperCase();

  return {
    id: `${result.check_id || 'semgrep'}:${relativePath}:${start.line || 1}:${start.col || 1}`,
    tool: 'Semgrep',
    ruleId: result.check_id || 'unknown-rule',
    title: extra.message || result.check_id || 'Vulnérabilité potentielle',
    severity: severityMap[rawSeverity] || 'warning',
    rawSeverity,
    category: metadata.category || metadata.technology || 'security',
    cwe: Array.isArray(metadata.cwe) ? metadata.cwe.join(', ') : (metadata.cwe || ''),
    file: relativePath,
    absolutePath,
    startLine: Math.max(0, (start.line || 1) - 1),
    startColumn: Math.max(0, (start.col || 1) - 1),
    endLine: Math.max(0, (end.line || start.line || 1) - 1),
    endColumn: Math.max(1, (end.col || start.col || 1) - 1),
    helpUri: metadata.source || metadata.references?.[0] || '',
    sourceContext: classifySourceContext(relativePath),
    confidence: String(metadata.confidence || 'medium').toLowerCase(),
    autofix: typeof extra.fix === 'string' ? extra.fix : '',
    originalText: typeof extra.lines === 'string' ? extra.lines : ''
  };
}

function normalizeSemgrepOutput(payload, workspacePath) {
  const results = Array.isArray(payload?.results) ? payload.results : [];
  return results.map((result) => normalizeSemgrepResult(result, workspacePath));
}

function normalizeGitleaksResult(result, workspacePath) {
  const relativePath = normalizeScannerPath(result.File);
  const startLine = Math.max(0, (result.StartLine || 1) - 1);
  const startColumn = Math.max(0, (result.StartColumn || 1) - 1);
  const sourceContext = classifySourceContext(relativePath);
  const risk = gitleaksRisk(result, sourceContext);
  return {
    id: result.Fingerprint || `gitleaks:${result.RuleID || 'secret'}:${relativePath}:${startLine + 1}`,
    tool: 'Gitleaks', ruleId: result.RuleID || 'secret-detected',
    title: result.Description || 'Secret potentiel détecté',
    severity: risk.severity, rawSeverity: risk.rawSeverity,
    category: 'secret', cwe: 'CWE-798', file: relativePath,
    absolutePath: path.resolve(workspacePath, relativePath), startLine, startColumn,
    endLine: Math.max(startLine, (result.EndLine || result.StartLine || 1) - 1),
    endColumn: Math.max(startColumn + 1, (result.EndColumn || result.StartColumn || 1) - 1),
    helpUri: 'https://github.com/gitleaks/gitleaks', fingerprint: result.Fingerprint || '',
    commit: result.Commit || '', sourceContext, confidence: risk.confidence
  };
}

function normalizeGitleaksOutput(payload, workspacePath) {
  return deduplicateFindings((Array.isArray(payload) ? payload : []).map((result) => normalizeGitleaksResult(result, workspacePath)));
}

function trivyLocation(result, target) {
  const cause = result.CauseMetadata || {};
  const file = normalizePath(cause.Resource || cause.File || target);
  return {
    file,
    startLine: Math.max(0, (cause.StartLine || 1) - 1),
    startColumn: Math.max(0, (cause.StartColumn || 1) - 1),
    endLine: Math.max(0, (cause.EndLine || cause.StartLine || 1) - 1),
    endColumn: Math.max(1, (cause.EndColumn || cause.StartColumn || 1) - 1)
  };
}

function normalizeTrivyVulnerability(result, target, workspacePath) {
  const rawSeverity = String(result.Severity || 'UNKNOWN').toUpperCase();
  const location = trivyLocation(result, target);
  const version = result.FixedVersion ? `${result.InstalledVersion || '?'} → ${result.FixedVersion}` : `${result.InstalledVersion || '?'} (aucun correctif indiqué)`;
  return {
    id: `trivy:vuln:${result.VulnerabilityID}:${result.PkgName}:${target}`,
    tool: 'Trivy', ruleId: result.VulnerabilityID || 'unknown-cve',
    title: `${result.VulnerabilityID || 'CVE'} — ${result.PkgName || 'dépendance'} (${version})`,
    severity: commonSeverityMap[rawSeverity] || 'warning', rawSeverity,
    category: 'dependency', cwe: Array.isArray(result.CweIDs) ? result.CweIDs.join(', ') : '',
    ...location, absolutePath: path.resolve(workspacePath, location.file),
    helpUri: result.PrimaryURL || result.References?.[0] || '',
    sourceContext: classifySourceContext(location.file),
    confidence: 'high',
    packageName: result.PkgName || '',
    installedVersion: result.InstalledVersion || '',
    fixedVersion: result.FixedVersion || '',
    target,
    description: result.Description || result.Title || '',
    status: result.Status || '',
    references: Array.isArray(result.References) ? result.References.slice(0, 5) : [],
    vulnerabilityAliases: [result.VulnerabilityID].filter(Boolean)
  };
}

function osvSeverity(vulnerabilities) {
  const labels = vulnerabilities
    .map((vulnerability) => vulnerability.database_specific?.severity || vulnerability.ecosystem_specific?.severity)
    .filter(Boolean)
    .map((value) => String(value).toUpperCase());
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  return order.find((severity) => labels.includes(severity)) || 'UNKNOWN';
}

function osvFixedVersion(vulnerabilities) {
  for (const vulnerability of vulnerabilities) {
    for (const affected of vulnerability.affected || []) {
      for (const range of affected.ranges || []) {
        const fixed = (range.events || []).find((event) => event.fixed)?.fixed;
        if (fixed) return fixed;
      }
    }
  }
  return '';
}

function normalizeOsvOutput(payload, workspacePath) {
  const findings = [];
  for (const result of Array.isArray(payload?.results) ? payload.results : []) {
    const sourcePath = normalizeScannerPath(result.source?.path || 'dependency-manifest');
    for (const packageResult of result.packages || []) {
      const packageInfo = packageResult.package || {};
      const vulnerabilities = packageResult.vulnerabilities || [];
      const groups = packageResult.groups?.length
        ? packageResult.groups
        : vulnerabilities.map((vulnerability) => ({ ids: [vulnerability.id] }));
      for (const group of groups) {
        const ids = [...new Set(group.ids || [])];
        const groupVulnerabilities = vulnerabilities.filter((vulnerability) => ids.includes(vulnerability.id));
        const aliases = [...new Set(groupVulnerabilities.flatMap((vulnerability) => [vulnerability.id, ...(vulnerability.aliases || [])]).filter(Boolean))];
        const canonicalId = aliases.find((id) => id.startsWith('CVE-')) || ids[0] || aliases[0] || 'OSV-UNKNOWN';
        const rawSeverity = osvSeverity(groupVulnerabilities);
        const fixedVersion = osvFixedVersion(groupVulnerabilities);
        const calledValues = Object.values(group.experimentalAnalysis || {}).map((analysis) => analysis?.called).filter((value) => typeof value === 'boolean');
        const reachable = calledValues.includes(true) ? true : calledValues.length && calledValues.every((value) => value === false) ? false : null;
        const firstVulnerability = groupVulnerabilities[0] || {};
        findings.push({
          id: `osv:${canonicalId}:${packageInfo.name || 'package'}:${sourcePath}`,
          tool: 'OSV-Scanner',
          ruleId: canonicalId,
          title: `${canonicalId} — ${packageInfo.name || 'dépendance'} (${packageInfo.version || '?' }${fixedVersion ? ` → ${fixedVersion}` : ''})`,
          severity: commonSeverityMap[rawSeverity] || 'warning',
          rawSeverity,
          category: 'dependency',
          cwe: '',
          file: sourcePath,
          absolutePath: path.resolve(workspacePath, sourcePath),
          startLine: 0,
          startColumn: 0,
          endLine: 0,
          endColumn: 1,
          helpUri: `https://osv.dev/vulnerability/${encodeURIComponent(canonicalId)}`,
          sourceContext: classifySourceContext(sourcePath),
          confidence: reachable === true ? 'high' : reachable === false ? 'low' : 'medium',
          packageName: packageInfo.name || '',
          installedVersion: packageInfo.version || '',
          fixedVersion,
          target: sourcePath,
          description: cleanScannerText(firstVulnerability.summary || firstVulnerability.details),
          references: (firstVulnerability.references || []).map((reference) => reference.url).filter(Boolean).slice(0, 5),
          vulnerabilityAliases: aliases,
          reachable,
          ecosystem: packageInfo.ecosystem || ''
        });
      }
    }
  }
  return deduplicateFindings(findings);
}

function normalizeTrivyMisconfiguration(result, target, workspacePath) {
  const rawSeverity = String(result.Severity || 'UNKNOWN').toUpperCase();
  const location = trivyLocation(result, target);
  return {
    id: `trivy:misconfig:${result.ID || result.AVDID}:${location.file}:${location.startLine + 1}`,
    tool: 'Trivy', ruleId: result.ID || result.AVDID || 'misconfiguration',
    title: result.Title || result.Message || 'Mauvaise configuration',
    severity: commonSeverityMap[rawSeverity] || 'warning', rawSeverity,
    category: 'misconfiguration', cwe: '',
    ...location, absolutePath: path.resolve(workspacePath, location.file),
    helpUri: result.PrimaryURL || result.References?.[0] || '',
    sourceContext: classifySourceContext(location.file),
    confidence: 'high',
    target,
    description: result.Description || result.Message || '',
    solution: result.Resolution || '',
    references: Array.isArray(result.References) ? result.References.slice(0, 5) : []
  };
}

function normalizeTrivyOutput(payload, workspacePath) {
  const findings = [];
  for (const scan of Array.isArray(payload?.Results) ? payload.Results : []) {
    const target = normalizePath(scan.Target);
    for (const result of scan.Vulnerabilities || []) findings.push(normalizeTrivyVulnerability(result, target, workspacePath));
    for (const result of scan.Misconfigurations || []) findings.push(normalizeTrivyMisconfiguration(result, target, workspacePath));
  }
  return findings;
}

function normalizeZapOutput(payload, _workspacePath = '', displayTargetUrl = '') {
  const findings = [];
  const severityByRisk = {
    '3': { severity: 'error', rawSeverity: 'HIGH' },
    '2': { severity: 'warning', rawSeverity: 'MEDIUM' },
    '1': { severity: 'information', rawSeverity: 'LOW' },
    '0': { severity: 'information', rawSeverity: 'INFO' }
  };
  for (const site of Array.isArray(payload?.site) ? payload.site : []) {
    for (const alert of Array.isArray(site.alerts) ? site.alerts : []) {
      const risk = severityByRisk[String(alert.riskcode)] || severityByRisk['1'];
      const guidance = zapDeveloperGuidance(alert);
      const instances = Array.isArray(alert.instances) && alert.instances.length ? alert.instances : [{}];
      for (const [index, instance] of instances.entries()) {
        const technicalDetails = cleanScannerText(instance.otherinfo || alert.otherinfo);
        const vulnerabilityAliases = [...new Set(technicalDetails.match(/CVE-\d{4}-\d+/gi) || [])].map((value) => value.toUpperCase());
        const componentMatch = technicalDetails.match(/library\s+([^,]+),\s*version\s+([^\s]+)\s+is vulnerable/i);
        const references = [...new Set((technicalDetails.match(/https?:\/\/[^\s]+/g) || []).map((value) => value.replace(/[).,]+$/, '')))];
        let uri = instance.uri || site['@name'] || '';
        if (displayTargetUrl) {
          try {
            const reported = new URL(uri);
            const displayTarget = new URL(displayTargetUrl);
            if (reported.hostname === 'host.docker.internal') {
              reported.protocol = displayTarget.protocol;
              reported.hostname = displayTarget.hostname;
              reported.port = displayTarget.port;
              uri = reported.toString();
            }
          } catch {
            // Keep the scanner value when it is not a valid absolute URL.
          }
        }
        const method = instance.method || 'HTTP';
        findings.push({
          id: `zap:${alert.pluginid || 'alert'}:${method}:${uri}:${instance.param || index}`,
          tool: 'ZAP',
          ruleId: String(alert.pluginid || 'zap-alert'),
          title: cleanScannerText(alert.alert || alert.name || 'Alerte dynamique ZAP'),
          severity: risk.severity,
          rawSeverity: risk.rawSeverity,
          category: 'dynamic',
          cwe: alert.cweid && alert.cweid !== '-1' ? `CWE-${alert.cweid}` : '',
          file: `${method} ${uri}`,
          absolutePath: '',
          startLine: 0,
          startColumn: 0,
          endLine: 0,
          endColumn: 1,
          helpUri: cleanScannerText(alert.reference).match(/https?:\/\/[^\s]+/)?.[0] || '',
          sourceContext: 'runtime',
          confidence: zapConfidence(alert.confidence || alert.confidencedesc),
          endpoint: uri,
          method,
          parameter: instance.param || '',
          evidence: instance.evidence || '',
          technicalDetails,
          vulnerabilityAliases,
          packageName: componentMatch?.[1] || '',
          installedVersion: componentMatch?.[2] || '',
          references: references.slice(0, 10),
          description: cleanScannerText(alert.desc),
          solution: cleanScannerText(alert.solution),
          developerSummary: guidance.summary,
          developerImpact: guidance.impact,
          developerAction: guidance.action
        });
      }
    }
  }
  return deduplicateFindings(findings);
}

module.exports = {
  normalizeScannerPath, classifySourceContext, deduplicateFindings, cleanScannerText, zapConfidence,
  normalizeSemgrepOutput, normalizeSemgrepResult,
  normalizeGitleaksOutput, normalizeGitleaksResult,
  normalizeTrivyOutput, normalizeTrivyVulnerability, normalizeTrivyMisconfiguration,
  normalizeZapOutput, normalizeOsvOutput
};
