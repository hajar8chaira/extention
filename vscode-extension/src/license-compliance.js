function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function componentLicenses(component) {
  const values = [];
  for (const entry of component.licenses || []) {
    const value = entry.expression || entry.license?.id || entry.license?.name;
    if (value) values.push(String(value).trim());
  }
  return [...new Set(values)];
}

function normalizedLicense(value) {
  return String(value).trim().toUpperCase().replace(/\s+/g, ' ');
}

function matchesDeniedLicense(license, deniedRule) {
  const value = normalizedLicense(license);
  const rule = normalizedLicense(deniedRule).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^A-Z0-9])${rule}($|[^A-Z0-9])`).test(value);
}

function analyzeLicenses(sbom, deniedLicenses = []) {
  const denied = deniedLicenses.map(normalizedLicense);
  const components = (sbom.components || []).map((component) => {
    const licenses = componentLicenses(component);
    const blockedBy = licenses.filter((license) => denied.some((rule) => matchesDeniedLicense(license, rule)));
    const status = !licenses.length ? 'unknown' : blockedBy.length ? 'denied' : 'allowed';
    return {
      name: component.name || 'Composant sans nom',
      version: component.version || '',
      type: component.type || '',
      purl: component.purl || '',
      licenses,
      blockedBy,
      status
    };
  });
  const counts = { allowed: 0, denied: 0, unknown: 0 };
  for (const component of components) counts[component.status] += 1;
  return { components, counts, compliant: counts.denied === 0, deniedLicenses };
}

function renderLicenseReportHtml(report, nonce) {
  const problematic = report.components.filter((component) => component.status !== 'allowed');
  const rows = problematic.length ? problematic.map((component) => `<tr><td>${escapeHtml(component.name)}</td><td>${escapeHtml(component.version || '—')}</td><td><span class="${component.status}">${component.status === 'denied' ? 'INTERDITE' : 'INCONNUE'}</span></td><td>${escapeHtml(component.licenses.join(', ') || 'Non déclarée')}</td><td>${escapeHtml(component.purl || '—')}</td></tr>`).join('') : '<tr><td colspan="5">Aucun problème de licence détecté.</td></tr>';
  return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}';"><style nonce="${nonce}">body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:24px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.card{border:1px solid var(--vscode-widget-border);border-radius:8px;padding:14px}.card strong{display:block;font-size:25px}.denied{color:#ff7b72}.unknown{color:#d29922}.allowed{color:#3fb950}table{border-collapse:collapse;width:100%}th,td{padding:9px;border-bottom:1px solid var(--vscode-widget-border);text-align:left;vertical-align:top;overflow-wrap:anywhere}th{position:sticky;top:0;background:var(--vscode-editor-background)}small{color:var(--vscode-descriptionForeground)}</style></head><body><h1>Conformité des licences</h1><p class="${report.compliant ? 'allowed' : 'denied'}"><strong>${report.compliant ? 'Aucune licence interdite détectée' : 'Politique de licences non respectée'}</strong></p><p><small>Licences interdites configurées : ${escapeHtml(report.deniedLicenses.join(', ') || 'aucune')}.</small></p><div class="cards"><div class="card"><strong class="allowed">${report.counts.allowed}</strong>Autorisées</div><div class="card"><strong class="denied">${report.counts.denied}</strong>Interdites</div><div class="card"><strong class="unknown">${report.counts.unknown}</strong>Inconnues</div></div><h2>Composants à examiner</h2><table><thead><tr><th>Composant</th><th>Version</th><th>État</th><th>Licence</th><th>PURL</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}

module.exports = { componentLicenses, matchesDeniedLicense, analyzeLicenses, renderLicenseReportHtml };
