const test = require('node:test');
const assert = require('node:assert/strict');
const { renderScannerSetupHtml, renderManagedCard, renderSonarCard, sonarDiagnosis } = require('../src/scanner-setup-page');
const { SCANNER_RUNTIMES, diagnoseScanner } = require('../src/scanner-diagnostics');

const TOGGLEABLE = ['gitleaks', 'trivy', 'osv'];
const LABELS = { semgrep: 'Semgrep', gitleaks: 'Gitleaks', trivy: 'Trivy', osv: 'OSV-Scanner' };

function sonar(overrides = {}) {
  return {
    enabled: true, mode: 'auto', serverType: 'existing', hostUrl: 'http://127.0.0.1:9000', tokenConfigured: true,
    scannerVersion: '6.2.1', dockerAvailable: true, serverOnline: true, serverVersion: '26.8', serverMessage: '',
    ...overrides
  };
}

function status(id, overrides = {}) {
  return { id, label: LABELS[id], purpose: 'Analyse', installed: true, version: '1.0.0', executable: `/bin/${id}`, managed: false, ...overrides };
}

function fakeRuntimes() {
  const runtimes = {};
  for (const id of Object.keys(SCANNER_RUNTIMES)) {
    runtimes[id] = { ...SCANNER_RUNTIMES[id], resolve: async () => ({ mode: 'local' }) };
  }
  return runtimes;
}

async function managedCard(id, { enabled = true } = {}) {
  const base = status(id);
  const diagnostic = await diagnoseScanner(id, {
    configuredMode: 'auto', enabled, workspacePath: '/repo', status: base,
    runtimes: fakeRuntimes(), checkImage: async () => true
  });
  return { html: renderManagedCard({ ...base, diagnostic }, false, undefined), diagnostic };
}

/**
 * Reproduces what the webview script posts when a button is clicked, so the
 * rendered markup and the message contract are tested together.
 */
function clickMessage(html, selector) {
  const match = html.match(new RegExp(`<button([^>]*${selector}[^>]*)>`));
  if (!match) return null;
  const attributes = match[1];
  const read = (name) => attributes.match(new RegExp(`${name}="([^"]*)"`))?.[1];
  if (read('data-sonar-enabled') !== undefined) return { type: 'setSonarEnabled', enabled: read('data-sonar-enabled') === 'true' };
  return { type: 'setScannerEnabled', tool: read('data-scanner'), enabled: read('data-scanner-enabled') === 'true' };
}

/** Configuration double mirroring vscode.workspace.getConfiguration. */
function fakeConfig(initial = {}) {
  const values = { ...initial };
  return {
    values,
    get: (key, fallback) => (key in values ? values[key] : fallback),
    update: async (key, value) => { values[key] = value; }
  };
}

/** The pipeline gate, reproducing extension.js exactly. */
function pipelineTools(cfg) {
  return [
    'Semgrep',
    ...(cfg.get('gitleaks.enabled', true) ? ['Gitleaks'] : []),
    ...(cfg.get('trivy.enabled', true) ? ['Trivy'] : []),
    ...(cfg.get('osv.enabled', true) ? ['OSV-Scanner'] : []),
    ...(cfg.get('sonar.enabled', false) ? ['SonarQube'] : [])
  ];
}

// ------------------------------------------------------------- SonarQube

test('SonarQube désactivé affiche un bouton Activer utilisable', () => {
  const html = renderSonarCard(sonar({ enabled: false }), false);
  assert.match(html, /data-sonar-enabled="true"/);
  assert.match(html, />Activer SonarQube</);
  assert.equal(html.includes('Désactiver SonarQube'), false);
});

test('l’explication de désactivation n’est plus orpheline', () => {
  const html = renderSonarCard(sonar({ enabled: false }), false);
  assert.match(html, /Activez-le depuis cette carte/);
  // Plus aucune consigne d'aller éditer le setting à la main.
  assert.equal(html.includes('securityCenter.sonar.enabled'), false);
});

test('SonarQube activé affiche un bouton Désactiver', () => {
  const html = renderSonarCard(sonar({ enabled: true }), false);
  assert.match(html, /data-sonar-enabled="false"/);
  assert.match(html, />Désactiver SonarQube</);
});

test('le clic Activer demande enabled = true, le clic Désactiver enabled = false', () => {
  assert.deepEqual(clickMessage(renderSonarCard(sonar({ enabled: false }), false), 'data-sonar-enabled'), { type: 'setSonarEnabled', enabled: true });
  assert.deepEqual(clickMessage(renderSonarCard(sonar({ enabled: true }), false), 'data-sonar-enabled'), { type: 'setSonarEnabled', enabled: false });
});

test('activer SonarQube écrit la clé réellement lue par le pipeline', async () => {
  const cfg = fakeConfig({ 'sonar.enabled': false });
  assert.equal(pipelineTools(cfg).includes('SonarQube'), false);
  const message = clickMessage(renderSonarCard(sonar({ enabled: false }), false), 'data-sonar-enabled');
  await cfg.update('sonar.enabled', message.enabled);
  assert.equal(cfg.values['sonar.enabled'], true);
  assert.ok(pipelineTools(cfg).includes('SonarQube'), 'le prochain pipeline doit inclure SonarQube');
});

test('désactiver SonarQube le retire du prochain pipeline', async () => {
  const cfg = fakeConfig({ 'sonar.enabled': true });
  const message = clickMessage(renderSonarCard(sonar({ enabled: true }), false), 'data-sonar-enabled');
  await cfg.update('sonar.enabled', message.enabled);
  assert.equal(cfg.values['sonar.enabled'], false);
  assert.equal(pipelineTools(cfg).includes('SonarQube'), false);
});

test('la carte reflète immédiatement le nouvel état après bascule', () => {
  const before = renderSonarCard(sonar({ enabled: false }), false);
  assert.match(before, /Désactivé/);
  const after = renderSonarCard(sonar({ enabled: true }), false);
  assert.match(after, />Désactiver SonarQube</);
  assert.equal(after.includes('>Désactivé<'), false);
});

test('activé sans jeton reste activé et signale Token manquant', () => {
  const html = renderSonarCard(sonar({ tokenConfigured: false }), false);
  assert.match(html, />Désactiver SonarQube</, 'SonarQube ne doit pas se désactiver tout seul');
  assert.match(html, /Token manquant/);
  assert.match(html, /<dt>Token<\/dt><dd><span class="muted">Non configuré<\/span><\/dd>/);
  assert.match(html, /data-sonar-token/);
});

test('activé avec serveur injoignable reste activé et signale Serveur indisponible', () => {
  const html = renderSonarCard(sonar({ serverOnline: false, serverMessage: 'Connexion refusée.' }), false);
  assert.match(html, />Désactiver SonarQube</);
  assert.match(html, /Serveur indisponible/);
  assert.match(html, /Injoignable — Connexion refusée\./);
});

test('une configuration incomplète n’entraîne jamais une désactivation', () => {
  for (const broken of [{ tokenConfigured: false }, { serverOnline: false }, { scannerVersion: '', dockerAvailable: false }, { tokenConfigured: false, serverOnline: false }]) {
    const diagnosis = sonarDiagnosis(sonar(broken));
    assert.notEqual(diagnosis.state, 'disabled');
    assert.notEqual(diagnosis.label, 'Désactivé');
  }
});

test('la bascule ne supprime aucune action existante de la carte SonarQube', () => {
  const html = renderSonarCard(sonar({ enabled: false }), false);
  for (const marker of ['data-sonar-mode="auto"', 'data-sonar-mode="local"', 'data-sonar-mode="docker"', 'data-sonar-token', 'data-sonar-recheck']) {
    assert.ok(html.includes(marker), `${marker} doit rester disponible`);
  }
  assert.match(html, /Utiliser en mode Auto/);
  assert.match(html, /Remplacer le token/);
  assert.match(html, /Revérifier/);
});

// ------------------------------------------------- Gitleaks / Trivy / OSV

for (const id of TOGGLEABLE) {
  test(`${LABELS[id]} expose Activer/Désactiver depuis sa carte`, async () => {
    const enabled = await managedCard(id, { enabled: true });
    assert.match(enabled.html, /data-scanner-enabled="false"/);
    assert.match(enabled.html, />Désactiver</);
    const disabled = await managedCard(id, { enabled: false });
    assert.match(disabled.html, /data-scanner-enabled="true"/);
    assert.match(disabled.html, />Activer</);
    assert.match(disabled.html, /Désactivé/);
  });

  test(`${LABELS[id]} : le clic écrit la clé lue par le pipeline`, async () => {
    const { html } = await managedCard(id, { enabled: true });
    const message = clickMessage(html, 'data-scanner-enabled');
    assert.deepEqual(message, { type: 'setScannerEnabled', tool: id, enabled: false });
    const cfg = fakeConfig();
    await cfg.update(SCANNER_RUNTIMES[id].enabledKey, message.enabled);
    assert.equal(cfg.values[SCANNER_RUNTIMES[id].enabledKey], false);
    assert.equal(pipelineTools(cfg).includes(LABELS[id]), false);
  });

  test(`${LABELS[id]} : la bascule conserve les actions de mode et Revérifier`, async () => {
    const { html } = await managedCard(id, { enabled: false });
    for (const mode of ['auto', 'local', 'docker']) assert.ok(html.includes(`data-scanner-mode="${mode}"`));
    assert.match(html, /data-recheck=/);
  });
}

test('Semgrep n’expose aucune bascule car il est obligatoire dans le pipeline', async () => {
  const { html, diagnostic } = await managedCard('semgrep');
  assert.equal(diagnostic.enabledKey, '', 'Semgrep n’a pas de réglage enabled');
  assert.equal(diagnostic.enabled, true);
  assert.equal(html.includes('data-scanner-enabled'), false, 'aucun système enabled ne doit être inventé');
  // Il reste malgré tout pilotable en mode d'exécution.
  assert.match(html, /data-scanner-mode="docker"/);
  const cfg = fakeConfig({ 'gitleaks.enabled': false, 'trivy.enabled': false, 'osv.enabled': false, 'sonar.enabled': false });
  assert.deepEqual(pipelineTools(cfg), ['Semgrep']);
});

test('les clés de bascule sont exactement celles déclarées dans package.json', () => {
  const properties = require('../package.json').contributes.configuration.properties;
  for (const id of TOGGLEABLE) {
    const key = `securityCenter.${SCANNER_RUNTIMES[id].enabledKey}`;
    assert.ok(properties[key], `${key} doit exister`);
    assert.equal(properties[key].type, 'boolean');
  }
  assert.equal(SCANNER_RUNTIMES.semgrep.enabledKey, undefined);
  assert.ok(properties['securityCenter.sonar.enabled']);
});

test('la page complète reste cohérente avec les bascules', async () => {
  const statuses = await Promise.all(['semgrep', ...TOGGLEABLE].map(async (id) => {
    const base = status(id);
    return { ...base, diagnostic: await diagnoseScanner(id, { configuredMode: 'auto', enabled: id !== 'trivy', workspacePath: '/repo', status: base, runtimes: fakeRuntimes(), checkImage: async () => true }) };
  }));
  const html = renderScannerSetupHtml(statuses, 'n', 'light', {}, null, sonar({ enabled: false }));
  assert.equal((html.match(/data-scanner-enabled=/g) || []).length, 3, 'trois scanners basculables');
  assert.match(html, /data-sonar-enabled="true"/);
  assert.match(html, />Activer SonarQube</);
  assert.match(html, /id="install-all"/);
  for (const label of ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube']) {
    assert.ok(html.includes(`<h2>${label}</h2>`));
  }
});
