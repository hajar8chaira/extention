function groupFindings(findings, scanStatuses = []) {
  const tools = new Map();
  for (const finding of findings) {
    if (!tools.has(finding.tool)) tools.set(finding.tool, new Map());
    const files = tools.get(finding.tool);
    if (!files.has(finding.file)) files.set(finding.file, []);
    files.get(finding.file).push(finding);
  }

  for (const scan of scanStatuses) if (!tools.has(scan.tool)) tools.set(scan.tool, new Map());

  const statusByTool = new Map(scanStatuses.map((scan) => [scan.tool, scan]));
  return [...tools.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([tool, files]) => ({
    kind: 'tool', label: tool,
    count: [...files.values()].reduce((total, list) => total + list.length, 0),
    status: statusByTool.get(tool)?.status || 'completed',
    error: statusByTool.get(tool)?.error || '',
    children: tool === 'ZAP'
      ? groupZapRules([...files.values()].flat())
      : [...files.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([file, children]) => ({
      kind: 'file', label: file, count: children.length,
      children: groupRules(children)
      }))
  }));
}

function groupZapRules(findings) {
  const rules = new Map();
  for (const finding of findings) {
    const key = finding.ruleId || finding.title;
    if (!rules.has(key)) rules.set(key, []);
    rules.get(key).push(finding);
  }
  return [...rules.values()]
    .sort((a, b) => a[0].title.localeCompare(b[0].title))
    .map((matches) => ({
      kind: 'rule',
      label: matches[0].title,
      ruleId: matches[0].ruleId,
      severity: matches[0].severity,
      rawSeverity: matches[0].rawSeverity,
      count: matches.length,
      children: matches
        .slice()
        .sort((a, b) => String(a.endpoint).localeCompare(String(b.endpoint)))
        .map((finding) => ({ kind: 'endpoint', finding }))
    }));
}

function groupRules(findings) {
  const rules = new Map();
  for (const finding of findings) {
    const key = finding.ruleId || finding.id;
    if (!rules.has(key)) rules.set(key, []);
    rules.get(key).push(finding);
  }

  return [...rules.values()]
    .sort((a, b) => a[0].startLine - b[0].startLine)
    .map((matches) => {
      const sorted = matches.slice().sort((a, b) => a.startLine - b.startLine);
      if (sorted.length === 1) return { kind: 'finding', finding: sorted[0] };
      return {
        kind: 'rule',
        label: sorted[0].title,
        ruleId: sorted[0].ruleId,
        severity: sorted[0].severity,
        rawSeverity: sorted[0].rawSeverity,
        count: sorted.length,
        children: sorted.map((finding) => ({ kind: 'finding', finding, occurrence: true }))
      };
    });
}

function summarizeFindings(findings) {
  const counts = new Map();
  for (const finding of findings) counts.set(finding.tool, (counts.get(finding.tool) || 0) + 1);
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([tool, count]) => `${tool}: ${count}`).join(' • ');
}

module.exports = { groupFindings, groupRules, groupZapRules, summarizeFindings };
