function sarifLevel(severity) {
  const value = String(severity || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'ERROR'].includes(value)) return 'error';
  if (['MEDIUM', 'WARNING'].includes(value)) return 'warning';
  return 'note';
}

function sarifRuleId(finding) {
  const tool = String(finding.tool || 'security-center').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const rule = String(finding.ruleId || finding.id || 'finding').replace(/[^A-Za-z0-9._-]+/g, '-');
  return `${tool}/${rule}`;
}

function toSarif(report) {
  const rules = new Map();
  for (const finding of report.findings || []) {
    const id = sarifRuleId(finding);
    if (!rules.has(id)) rules.set(id, { id, name: finding.ruleId || id, shortDescription: { text: finding.title || id }, helpUri: finding.references?.[0] || finding.helpUri || undefined, properties: { tool: finding.tool, originalRuleId: finding.ruleId || finding.id, tags: [finding.category, ...(finding.cwes || [])].filter(Boolean) } });
  }
  const ruleList = [...rules.values()];
  const indexes = new Map(ruleList.map((rule, index) => [rule.id, index]));
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'Security Center', informationUri: 'https://github.com/', rules: ruleList } },
      results: (report.findings || []).map((finding) => {
        const ruleId = sarifRuleId(finding);
        const fingerprint = String(finding.fingerprint || finding.id || `${ruleId}:${finding.file || ''}:${finding.line || 1}`);
        const result = { ruleId, ruleIndex: indexes.get(ruleId), level: sarifLevel(finding.rawSeverity || finding.severity), message: { text: finding.message || finding.title || ruleId }, partialFingerprints: { securityCenterFingerprint: fingerprint }, properties: { scanner: finding.tool, originalRuleId: finding.ruleId || finding.id, category: finding.category, cves: finding.cves || [], cwes: finding.cwes || [], packageName: finding.packageName, packageVersion: finding.installedVersion, commit: finding.commit || undefined } };
        if (finding.file) result.locations = [{ physicalLocation: { artifactLocation: { uri: String(finding.file).replaceAll('\\', '/') }, region: { startLine: Math.max(1, Number(finding.line) || 1) } } }];
        return result;
      })
    }]
  };
}

module.exports = { sarifLevel, sarifRuleId, toSarif };
