const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SCANNER_MODES, SCANNER_RUNTIMES, normalizeMode, modeLabel, scannerState, diagnoseScanner
} = require('../src/scanner-diagnostics');
const { renderScannerSetupHtml, renderManagedCard } = require('../src/scanner-setup-page');
const semgrep = require('../src/semgrep');
const gitleaks = require('../src/gitleaks');
const trivy = require('../src/trivy');
const osv = require('../src/osv');

const MANAGED_IDS = ['semgrep', 'gitleaks', 'trivy', 'osv'];
const LABELS = { semgrep: 'Semgrep', gitleaks: 'Gitleaks', trivy: 'Trivy', osv: 'OSV-Scanner' };

/** Runner double: reproduces the real auto → local → docker contract. */
function fakeRuntimes({ localAvailable = true, dockerAvailable = true } = {}) {
  const runtimes = {};
  for (const id of MANAGED_IDS) {
    runtimes[id] = {
      ...SCANNER_RUNTIMES[id],
      resolve: async (mode) => {
        if (mode !== 'docker' && localAvailable) return { mode: 'local' };
        if (mode === 'local') throw new Error(`${LABELS[id]} local est introuvable.`);
        if (!dockerAvailable) throw new Error(`Ni ${LABELS[id]} local ni Docker ne sont disponibles.`);
        return { mode: 'docker' };
      }
    };
  }
  return runtimes;
}

function diagnose(id, options = {}) {
  return diagnoseScanner(id, {
    runtimes: fakeRuntimes(options.environment || {}),
    checkImage: async () => options.imagePresent ?? true,
    workspacePath: '/repo',
    ...options
  });
}

function status(id, overrides = {}) {
  return { id, label: LABELS[id], purpose: 'Analyse', installed: true, version: '1.0.0', executable: `/bin/${id}`, managed: false, ...overrides };
}

// -------------------------------------------------- support réel des modes

test('les quatre runners exposent réellement resolveInvocation(mode)', () => {
  for (const runner of [semgrep, gitleaks, trivy, osv]) {
    assert.equal(typeof runner.resolveInvocation, 'function');
  }
  assert.deepEqual(SCANNER_MODES.map(([value]) => value), ['auto', 'local', 'docker']);
});

test('les clés de configuration réutilisent la nomenclature existante', () => {
  assert.equal(SCANNER_RUNTIMES.semgrep.settingKey, 'semgrep.command');
  assert.equal(SCANNER_RUNTIMES.gitleaks.settingKey, 'gitleaks.command');
  assert.equal(SCANNER_RUNTIMES.trivy.settingKey, 'trivy.command');
  assert.equal(SCANNER_RUNTIMES.osv.settingKey, 'osv.command');
  const properties = require('../package.json').contributes.configuration.properties;
  for (const id of MANAGED_IDS) {
    const key = `securityCenter.${SCANNER_RUNTIMES[id].settingKey}`;
    assert.ok(properties[key], `${key} doit déjà exister`);
    assert.deepEqual(properties[key].enum, ['auto', 'local', 'docker']);
  }
});

test('les images Docker annoncées sont celles réellement utilisées par les runners', () => {
  assert.ok(semgrep.dockerArgs('/repo', 'p/security-audit').includes(SCANNER_RUNTIMES.semgrep.image));
  assert.ok(gitleaks.dockerArgs('/repo').includes(SCANNER_RUNTIMES.gitleaks.image));
  assert.ok(trivy.dockerArgs('/repo').includes(SCANNER_RUNTIMES.trivy.image));
  assert.ok(osv.dockerArgs('/repo').includes(SCANNER_RUNTIMES.osv.image));
});

test('normalizeMode protège contre une valeur de configuration inattendue', () => {
  assert.equal(normalizeMode('docker'), 'docker');
  assert.equal(normalizeMode('DOCKER'), 'docker');
  assert.equal(normalizeMode('kubernetes'), 'auto');
  assert.equal(normalizeMode(undefined), 'auto');
  assert.equal(modeLabel('local'), 'Local');
});

// ------------------------------------------------- mode actuel vs utilisé

for (const id of MANAGED_IDS) {
  test(`${LABELS[id]} : auto avec binaire local → mode utilisé Local`, async () => {
    const diagnostic = await diagnose(id, { configuredMode: 'auto', status: status(id) });
    assert.equal(diagnostic.configuredModeLabel, 'Auto');
    assert.equal(diagnostic.resolvedModeLabel, 'Local');
    assert.equal(diagnostic.label, 'Prêt');
  });

  test(`${LABELS[id]} : auto sans binaire local mais Docker disponible → prêt via Docker`, async () => {
    const diagnostic = await diagnose(id, {
      configuredMode: 'auto', status: status(id, { installed: false, executable: '', version: '' }),
      environment: { localAvailable: false }
    });
    assert.equal(diagnostic.configuredModeLabel, 'Auto');
    assert.equal(diagnostic.resolvedModeLabel, 'Docker');
    assert.equal(diagnostic.state, 'ready');
    assert.equal(diagnostic.label, 'Prêt — Docker');
  });

  test(`${LABELS[id]} : mode local sans binaire → Non installé`, async () => {
    const diagnostic = await diagnose(id, {
      configuredMode: 'local', status: status(id, { installed: false }),
      environment: { localAvailable: false }
    });
    assert.equal(diagnostic.state, 'missing');
    assert.equal(diagnostic.label, 'Non installé');
    assert.equal(diagnostic.resolvedModeLabel, '');
    assert.match(diagnostic.hint, /introuvable/);
  });

  test(`${LABELS[id]} : mode docker sans Docker → Docker indisponible`, async () => {
    const diagnostic = await diagnose(id, {
      configuredMode: 'docker', status: status(id),
      environment: { localAvailable: true, dockerAvailable: false }
    });
    assert.equal(diagnostic.state, 'failed');
    assert.equal(diagnostic.label, 'Docker indisponible');
  });

  test(`${LABELS[id]} : mode docker force l’exécution conteneurisée malgré un binaire local`, async () => {
    const diagnostic = await diagnose(id, { configuredMode: 'docker', status: status(id) });
    assert.equal(diagnostic.resolvedModeLabel, 'Docker');
    assert.equal(diagnostic.image, SCANNER_RUNTIMES[id].image);
  });
}

test('ni binaire local ni Docker en mode auto → Erreur', async () => {
  const diagnostic = await diagnose('semgrep', {
    configuredMode: 'auto', status: status('semgrep', { installed: false }),
    environment: { localAvailable: false, dockerAvailable: false }
  });
  assert.equal(diagnostic.label, 'Erreur');
  assert.equal(diagnostic.state, 'failed');
});

test('un scanner désactivé est signalé comme tel avant tout diagnostic', () => {
  const state = scannerState({ enabled: false, configuredMode: 'auto', resolvedMode: 'local' });
  assert.equal(state.state, 'disabled');
  assert.equal(state.label, 'Désactivé');
});

test('la présence de l’image Docker est vérifiée sans jamais la télécharger', async () => {
  const absent = await diagnose('trivy', { configuredMode: 'docker', status: status('trivy'), imagePresent: false });
  assert.equal(absent.imagePresent, false);
  const present = await diagnose('trivy', { configuredMode: 'docker', status: status('trivy'), imagePresent: true });
  assert.equal(present.imagePresent, true);
  // En mode local, aucune interrogation Docker n'est faite.
  let called = false;
  await diagnoseScanner('trivy', {
    configuredMode: 'local', workspacePath: '/repo', status: status('trivy'),
    runtimes: fakeRuntimes(), checkImage: async () => { called = true; return true; }
  });
  assert.equal(called, false);
});

test('un scanner inconnu est rejeté explicitement', async () => {
  await assert.rejects(() => diagnoseScanner('snyk', {}), /Scanner inconnu/);
});

// ------------------------------------------------------------ rendu carte

async function renderWith(id, options) {
  const base = status(id, options.status);
  const diagnostic = await diagnose(id, { ...options, status: base });
  return renderManagedCard({ ...base, diagnostic }, false, undefined);
}

for (const id of MANAGED_IDS) {
  test(`${LABELS[id]} : les trois boutons de mode sont rendus`, async () => {
    const html = await renderWith(id, { configuredMode: 'auto' });
    for (const [value, label] of SCANNER_MODES) {
      assert.ok(html.includes(`data-scanner-mode="${value}"`), `bouton ${value} manquant`);
      assert.ok(html.includes(`Utiliser en mode ${label}`), `libellé ${label} manquant`);
    }
    assert.ok(html.includes(`data-scanner="${id}"`), 'le bouton doit porter l’identifiant du scanner');
    assert.match(html, /data-recheck=/);
    assert.match(html, /Revérifier/);
  });

  test(`${LABELS[id]} : le mode courant est marqué et les deux modes sont distingués`, async () => {
    const html = await renderWith(id, { configuredMode: 'auto' });
    assert.match(html, /data-scanner-mode="auto"[^>]*aria-current="true"/);
    assert.match(html, /<dt>Mode actuel<\/dt><dd>Auto<\/dd>/);
    assert.match(html, /<dt>Mode utilisé<\/dt><dd>Local<\/dd>/);
  });
}

test('le mode Docker affiche l’image au lieu de l’emplacement local', async () => {
  const html = await renderWith('trivy', { configuredMode: 'docker' });
  assert.match(html, /<dt>Image<\/dt>/);
  assert.ok(html.includes('aquasec/trivy:latest'));
  assert.equal(html.includes('<dt>Emplacement</dt>'), false);
});

test('une image absente est annoncée sans prétendre l’avoir téléchargée', async () => {
  const html = await renderWith('osv', { configuredMode: 'docker', imagePresent: false });
  assert.match(html, /téléchargée au premier scan/);
});

test('le mode local affiche version et emplacement', async () => {
  const html = await renderWith('semgrep', { configuredMode: 'local' });
  assert.match(html, /<dt>Version<\/dt><dd>1\.0\.0<\/dd>/);
  assert.match(html, /<dt>Emplacement<\/dt><dd class="path">\/bin\/semgrep<\/dd>/);
});

test('un scanner épinglé sur Docker ne propose plus d’installation locale', async () => {
  const dockerPinned = await renderWith('gitleaks', { configuredMode: 'docker', status: { installed: false, executable: '', version: '' } });
  assert.equal(dockerPinned.includes('data-install='), false);
  const autoMissing = await renderWith('gitleaks', {
    configuredMode: 'auto', status: { installed: false, executable: '', version: '' }, environment: { localAvailable: false }
  });
  assert.match(autoMissing, /data-install="gitleaks"/, 'le workflow d’installation reste disponible en mode auto');
});

test('aucun champ serveur, connexion ou jeton n’est ajouté aux scanners locaux', async () => {
  for (const id of MANAGED_IDS) {
    const html = await renderWith(id, { configuredMode: 'auto' });
    for (const field of ['<dt>Serveur</dt>', '<dt>Connexion</dt>', '<dt>Jeton</dt>']) {
      assert.equal(html.includes(field), false, `${LABELS[id]} ne doit pas afficher ${field}`);
    }
  }
});

test('la carte reste rendue sans diagnostic et conserve le bouton Auto historique', () => {
  const html = renderManagedCard(status('semgrep'), false, undefined);
  assert.match(html, /data-mode="semgrep"/);
  assert.match(html, /Utiliser en mode Auto/);
  assert.equal(html.includes('<dt>Mode actuel</dt>'), false);
});

test('une installation en cours conserve la priorité visuelle', () => {
  const html = renderManagedCard(status('trivy', { installed: false }), true, { state: 'installing', title: 'Installation de Trivy', message: 'Téléchargement', percent: 40 });
  assert.match(html, /Installation…/);
  assert.match(html, /<progress max="100" value="40">/);
  assert.match(html, /disabled/);
});

// ------------------------------------------------------- page complète

test('la page conserve les quatre scanners et SonarQube côte à côte', async () => {
  const statuses = await Promise.all(MANAGED_IDS.map(async (id) => ({ ...status(id), diagnostic: await diagnose(id, { configuredMode: 'auto', status: status(id) }) })));
  const html = renderScannerSetupHtml(statuses, 'n', 'light', {}, null, {
    enabled: true, mode: 'auto', serverType: 'existing', hostUrl: 'http://127.0.0.1:9000', tokenConfigured: true,
    scannerVersion: '6.2', dockerAvailable: true, serverOnline: true, serverVersion: '26.8'
  });
  for (const label of ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube']) {
    assert.ok(html.includes(`<h2>${label}</h2>`), `${label} doit être présent`);
  }
  // SonarQube garde ses champs spécifiques, désormais dans des sections dédiées.
  assert.match(html, /<h3 class="sonar-section">Serveur SonarQube/);
  assert.match(html, /<dt>Token<\/dt><dd>Configuré/);
  assert.match(html, /data-sonar-token/);
  // Le bouton global d'installation reste en place.
  assert.match(html, /id="install-all"/);
  assert.match(html, /Installer les outils manquants/);
});

test('le thème sombre reste pris en charge par la page enrichie', async () => {
  const statuses = [{ ...status('semgrep'), diagnostic: await diagnose('semgrep', { configuredMode: 'auto', status: status('semgrep') }) }];
  const html = renderScannerSetupHtml(statuses, 'n', 'dark', {}, null, null);
  assert.match(html, /<html data-theme="dark">/);
  assert.match(html, /html\[data-theme=dark\]/);
});
