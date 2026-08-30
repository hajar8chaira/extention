const { renderSecurityCenterShell } = require('./security-center-shell');
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

function renderLicenseReportHtml(report, nonce, theme = 'light') {
  const problematic = report.components.filter((component) => component.status !== 'allowed');
  const rows = problematic.length ? problematic.map((component) => `<tr><td>${escapeHtml(component.name)}</td><td>${escapeHtml(component.version || '—')}</td><td><span class="${component.status}">${component.status === 'denied' ? 'INTERDITE' : 'INCONNUE'}</span></td><td>${escapeHtml(component.licenses.join(', ') || 'Non déclarée')}</td><td>${escapeHtml(component.purl || '—')}</td></tr>`).join('') : '<tr><td colspan="5">Aucun problème de licence détecté.</td></tr>';
  const styles = `
    h1 { margin: 0 0 6px; font-size: 20px; }
    h2 { margin: 22px 0 10px; font-size: 13px; }
    .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 18px 0; }
    .card { border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); padding: 14px; background: var(--sc-surface); }
    .card strong { display: block; font-size: 25px; }
    .denied { color: var(--sc-critical, #d94b40); }
    .unknown { color: var(--sc-medium, #d29922); }
    .allowed { color: var(--sc-low, #3fb950); }
    .license-table-scroll { overflow-x: auto; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); }
    table { border-collapse: collapse; width: 100%; min-width: 640px; }
    th, td { padding: 9px; border-bottom: 1px solid var(--sc-border); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { position: sticky; top: 0; background: var(--sc-surface); }
    small { color: var(--sc-muted); }`;
  const content = `
  <p class="${report.compliant ? 'allowed' : 'denied'}"><strong>${report.compliant ? 'Aucune licence interdite détectée' : 'Politique de licences non respectée'}</strong></p>
  <p><small>Licences interdites configurées : ${escapeHtml(report.deniedLicenses.join(', ') || 'aucune')}.</small></p>
  <div class="cards"><div class="card"><strong class="allowed">${report.counts.allowed}</strong>Autorisées</div><div class="card"><strong class="denied">${report.counts.denied}</strong>Interdites</div><div class="card"><strong class="unknown">${report.counts.unknown}</strong>Inconnues</div></div>
  <h2>Composants à examiner</h2>
  <div class="license-table-scroll"><table><thead><tr><th>Composant</th><th>Version</th><th>État</th><th>Licence</th><th>PURL</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  // Page volontairement SANS script : c'est un rapport en lecture seule. La
  // navigation passe par des URI de commande, que l'hote restreint a la liste
  // du rail. Aucun script n'est active pour obtenir le cadre.
  return renderSecurityCenterShell({
    surface: 'licenses',
    nonce,
    theme,
    title: 'Conformité des licences',
    subtitle: 'Composants, licences déclarées et écarts avec la politique projet',
    content,
    styles,
    navAsLinks: true,
    csp: `default-src 'none'; style-src 'nonce-${nonce}';`
  });
}

module.exports = { componentLicenses, matchesDeniedLicense, analyzeLicenses, renderLicenseReportHtml };
