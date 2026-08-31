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

/**
 * Builds the licence report.
 *
 * `sources` describes where the inventory came from (see
 * `supply-chain/license-sources`). It is optional so existing callers keep
 * working, but when it is supplied and NOTHING could be analysed, `compliant`
 * is `null` rather than `true`: an inventory that was never taken cannot be
 * declared compliant, and « no container engine » is not « no denied licence ».
 */
function analyzeLicenses(sbom, deniedLicenses = [], sources = []) {
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
  const declaredSources = Array.isArray(sources) ? sources : [];
  // No declared sources means a caller that predates the source model: it has
  // already produced a document, so the inventory did happen.
  const analyzed = !declaredSources.length || declaredSources.some((entry) => entry?.analyzed);
  const degraded = declaredSources.some(
    (entry) => entry && !entry.analyzed && entry.state !== 'not-configured'
  );
  return {
    components,
    counts,
    // Tri-state on purpose: true, false, or « not established ».
    compliant: analyzed ? counts.denied === 0 : null,
    analyzed,
    degraded,
    sources: declaredSources,
    deniedLicenses
  };
}

function renderLicenseReportHtml(report, nonce, theme = 'light', assets = {}) {
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
    .muted-state { color: var(--sc-muted); }
    .license-table-scroll { overflow-x: auto; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); }
    table { border-collapse: collapse; width: 100%; min-width: 640px; }
    th, td { padding: 9px; border-bottom: 1px solid var(--sc-border); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { position: sticky; top: 0; background: var(--sc-surface); }
    small { color: var(--sc-muted); }`;
  // Trois verdicts, pas deux. « Indéterminé » est l'état honnête quand aucune
  // source n'a pu être inventoriée : il ne doit jamais se lire « conforme ».
  const verdict = report.analyzed === false
    ? { className: 'unknown', text: 'Conformité non établie — aucune source n’a pu être inventoriée' }
    : report.compliant
      ? { className: 'allowed', text: 'Aucune licence interdite détectée' }
      : { className: 'denied', text: 'Politique de licences non respectée' };
  const sources = Array.isArray(report.sources) ? report.sources : [];
  const sourceRows = sources.map((entry) => {
    const stateClass = entry.analyzed ? 'allowed' : entry.state === 'not-configured' ? 'muted-state' : 'unknown';
    // Une source non analysée n'affiche pas « 0 » : elle n'a pas été mesurée.
    const count = entry.analyzed && Number.isFinite(Number(entry.componentCount))
      ? `${entry.componentCount} composant(s)`
      : '—';
    const detail = entry.reason ? `<br><small>${escapeHtml(entry.reason)}</small>` : '';
    return `<tr><td>${escapeHtml(entry.label || entry.source)}</td><td><span class="${stateClass}">${escapeHtml(entry.stateLabel || entry.state)}</span>${detail}</td><td>${escapeHtml(entry.target || '—')}</td><td>${count}</td></tr>`;
  }).join('');
  const sourcesBlock = sources.length ? `
  <h2>Sources d’analyse</h2>
  <p><small>Le contrôle des licences s’appuie sur deux inventaires indépendants. L’indisponibilité de l’un ne remet pas en cause l’autre, et n’est pas un écart de conformité.</small></p>
  <div class="license-table-scroll"><table><thead><tr><th>Source</th><th>État</th><th>Cible</th><th>Inventaire</th></tr></thead><tbody>${sourceRows}</tbody></table></div>` : '';
  const content = `
  <p class="${verdict.className}"><strong>${verdict.text}</strong></p>
  <p><small>Licences interdites configurées : ${escapeHtml(report.deniedLicenses.join(', ') || 'aucune')}.</small></p>
  <div class="cards"><div class="card"><strong class="allowed">${report.counts.allowed}</strong>Autorisées</div><div class="card"><strong class="denied">${report.counts.denied}</strong>Interdites</div><div class="card"><strong class="unknown">${report.counts.unknown}</strong>Inconnues</div></div>
  ${sourcesBlock}
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
    csp: `default-src 'none'; img-src ${assets.cspSource || "'none'"}; style-src 'nonce-${nonce}';`,
    brandLogoUri: assets.brandLogoUri || '',
    cspSource: assets.cspSource || '',
  });
}

module.exports = { componentLicenses, matchesDeniedLicense, analyzeLicenses, renderLicenseReportHtml };
