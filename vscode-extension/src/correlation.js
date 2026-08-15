const crypto = require('crypto');

function normalizedFile(finding) {
  return String(finding.file || '').replaceAll('\\', '/').replace(/^\/+/, '').toLowerCase();
}

function cweValues(finding) {
  return String(finding.cwe || '').match(/CWE-\d+/gi)?.map((value) => value.toUpperCase()) || [];
}

function routeTokens(finding) {
  const values = [finding.endpoint, finding.route, finding.file].filter(Boolean);
  return new Set(values.flatMap((value) => {
    let text = String(value);
    try { text = new URL(text).pathname; } catch { /* route ou chemin de fichier */ }
    return text.toLowerCase().split(/[^a-z0-9]+/)
      .filter((token) => token.length >= 4 && !['http', 'https', 'routes', 'route', 'controller', 'controllers'].includes(token));
  }));
}

function correlationId(type, key) {
  return `${type}-${crypto.createHash('sha1').update(key).digest('hex').slice(0, 12)}`;
}

function buildCorrelation(type, confidence, key, findings, reason) {
  const tools = [...new Set(findings.map((finding) => finding.tool))].sort();
  const cwes = [...new Set(findings.flatMap(cweValues))].sort();
  return {
    id: correlationId(type, key),
    type,
    confidence,
    title: type === 'same-location'
      ? 'Plusieurs outils signalent le même emplacement'
      : type === 'dependency-match'
        ? 'Dépendance vulnérable confirmée par plusieurs sources'
        : 'Correspondance SAST/DAST possible',
    reason,
    tools,
    cwes,
    findingIds: findings.map((finding) => finding.id),
    count: findings.length
  };
}

function correlateFindings(findings) {
  const correlations = [];
  const usedExact = new Set();

  const dependencies = findings.filter((finding) => finding.category === 'dependency' && finding.packageName);
  for (let left = 0; left < dependencies.length; left += 1) {
    const first = dependencies[left];
    for (let right = left + 1; right < dependencies.length; right += 1) {
      const second = dependencies[right];
      if (first.tool === second.tool || first.packageName.toLowerCase() !== second.packageName.toLowerCase()) continue;
      const firstIds = new Set([first.ruleId, ...(first.vulnerabilityAliases || [])].filter(Boolean));
      const sharedIds = [second.ruleId, ...(second.vulnerabilityAliases || [])].filter((id) => firstIds.has(id));
      if (!sharedIds.length) continue;
      const key = `${first.packageName.toLowerCase()}|${sharedIds.sort().join(',')}`;
      if (usedExact.has(key)) continue;
      usedExact.add(key);
      correlations.push(buildCorrelation(
        'dependency-match',
        'high',
        key,
        [first, second],
        `${sharedIds.join(', ')} affecte ${first.packageName} et est confirmé par ${first.tool} et ${second.tool}.`
      ));
    }
  }

  for (let left = 0; left < findings.length; left += 1) {
    const first = findings[left];
    if (!first.absolutePath || !normalizedFile(first)) continue;
    for (let right = left + 1; right < findings.length; right += 1) {
      const second = findings[right];
      if (first.tool === second.tool || !second.absolutePath) continue;
      const sharedCwes = cweValues(first).filter((cwe) => cweValues(second).includes(cwe));
      const close = Math.abs(first.startLine - second.startLine) <= 3;
      if (normalizedFile(first) !== normalizedFile(second) || !close || !sharedCwes.length) continue;
      const key = `${normalizedFile(first)}|${Math.min(first.startLine, second.startLine)}|${sharedCwes.join(',')}`;
      if (usedExact.has(key)) continue;
      usedExact.add(key);
      correlations.push(buildCorrelation(
        'same-location',
        'high',
        key,
        [first, second],
        `Même fichier, lignes proches et ${sharedCwes.join(', ')} commun.`
      ));
    }
  }

  const runtime = findings.filter((finding) => finding.sourceContext === 'runtime');
  const source = findings.filter((finding) => finding.sourceContext !== 'runtime');
  const stronglyLinked = new Set();
  for (const dynamicFinding of runtime) {
    for (const sourceFinding of source) {
      const sharedCwes = cweValues(dynamicFinding).filter((cwe) => cweValues(sourceFinding).includes(cwe));
      const dynamicTokens = routeTokens(dynamicFinding);
      const sharedTokens = [...routeTokens(sourceFinding)].filter((token) => dynamicTokens.has(token));
      if (!sharedCwes.length || !sharedTokens.length) continue;
      const key = `${dynamicFinding.id}|${sourceFinding.id}|${sharedCwes.join(',')}|${sharedTokens.join(',')}`;
      correlations.push(buildCorrelation(
        'endpoint-source', 'high', key, [dynamicFinding, sourceFinding],
        `${sharedCwes.join(', ')} et la route ${sharedTokens.join(', ')} relient l'endpoint observé au fichier source.`
      ));
      stronglyLinked.add(dynamicFinding.id);
      stronglyLinked.add(sourceFinding.id);
    }
  }
  const runtimeCwes = new Set(runtime.flatMap(cweValues));
  for (const cwe of runtimeCwes) {
    const dynamicMatches = runtime.filter((finding) => cweValues(finding).includes(cwe) && !stronglyLinked.has(finding.id));
    const sourceMatches = source.filter((finding) => cweValues(finding).includes(cwe) && !stronglyLinked.has(finding.id));
    if (!dynamicMatches.length || !sourceMatches.length) continue;
    const matches = [...dynamicMatches, ...sourceMatches];
    correlations.push(buildCorrelation(
      'shared-cwe',
      'medium',
      cwe,
      matches,
      `${cwe} est présent dans le code et à l’exécution, mais le mapping endpoint-code reste à confirmer.`
    ));
  }

  const correlationByFinding = new Map();
  for (const correlation of correlations) {
    for (const findingId of correlation.findingIds) {
      const list = correlationByFinding.get(findingId) || [];
      list.push(correlation);
      correlationByFinding.set(findingId, list);
    }
  }
  const annotated = findings.map((finding) => {
    const matches = correlationByFinding.get(finding.id) || [];
    if (!matches.length) return finding;
    return {
      ...finding,
      correlationIds: matches.map((match) => match.id),
      correlatedTools: [...new Set(matches.flatMap((match) => match.tools))],
      correlationConfidence: matches.some((match) => match.confidence === 'high') ? 'high' : 'medium'
    };
  });
  return { findings: annotated, correlations };
}

module.exports = { correlateFindings, cweValues, normalizedFile, routeTokens };
