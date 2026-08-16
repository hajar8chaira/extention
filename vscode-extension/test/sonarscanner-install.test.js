const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  ScannerToolManager, TOOLS, versionInvocation, sonarScannerPlatform, compareVersions, SONARSCANNER_BASE
} = require('../src/scanner-tool-manager');
const { renderSonarCard, usedScannerMode } = require('../src/scanner-setup-page');
const { resolveRunner, localInvocation } = require('../src/sonarqube');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';

function sonar(overrides = {}) {
  return {
    enabled: true, mode: 'local', serverType: 'local', hostUrl: 'http://127.0.0.1:9000',
    tokenConfigured: true, scannerVersion: '', scannerPath: '', dockerAvailable: true,
    serverOnline: true, serverVersion: '26.8', localServerState: 'ready', ...overrides
  };
}

function storage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-tools-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return new ScannerToolManager(root);
}

// ------------------------------------------------------- manifeste

test('SonarScanner est déclaré dans le gestionnaire d’outils existant', () => {
  assert.ok(TOOLS.sonarscanner, 'aucune seconde infrastructure d’installation');
  assert.equal(TOOLS.sonarscanner.kind, 'sonarsource');
  assert.equal(TOOLS.sonarscanner.command, 'sonar-scanner');
  assert.equal(TOOLS.sonarscanner.label, 'SonarScanner');
});

test('la source est exclusivement le domaine officiel SonarSource en HTTPS', () => {
  const url = new URL(SONARSCANNER_BASE);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'binaries.sonarsource.com');
  assert.equal(TOOLS.sonarscanner.base, SONARSCANNER_BASE);
  // Aucune source tierce, miroir ou CDN non documenté.
  for (const forbidden of ['github.com', 'raw.githubusercontent', 'cdn', 'sourceforge']) {
    assert.equal(SONARSCANNER_BASE.includes(forbidden), false);
  }
});

test('la variante officielle est choisie par plateforme et architecture', () => {
  assert.equal(sonarScannerPlatform('win32', 'x64'), 'windows-x64');
  assert.equal(sonarScannerPlatform('linux', 'x64'), 'linux-x64');
  assert.equal(sonarScannerPlatform('linux', 'arm64'), 'linux-aarch64');
  assert.equal(sonarScannerPlatform('darwin', 'x64'), 'macosx-x64');
  assert.equal(sonarScannerPlatform('darwin', 'arm64'), 'macosx-aarch64');
  // Plateforme non distribuée : refus explicite plutôt qu’un faux positif.
  assert.equal(sonarScannerPlatform('aix', 'ppc64'), '');
  assert.equal(sonarScannerPlatform('win32', 'arm64'), '');
});

test('la comparaison de versions ordonne correctement les publications', () => {
  assert.ok(compareVersions('8.1.0.6389', '7.3.0.5189') > 0);
  assert.ok(compareVersions('8.0.1.6346', '8.0.0.6341') > 0);
  assert.equal(compareVersions('8.1.0.6389', '8.1.0.6389'), 0);
  assert.deepEqual(['7.3.0.5189', '8.1.0.6389', '8.0.0.6341'].sort(compareVersions).at(-1), '8.1.0.6389');
});

// -------------------------------------------------- chemins et binaire

test('le binaire est installé dans le stockage privé, jamais globalement', (t) => {
  const manager = storage(t);
  const executable = manager.managedExecutable('sonarscanner');
  assert.ok(executable.startsWith(manager.root), 'hors du stockage privé');
  assert.ok(executable.includes(path.join('sonarscanner', 'current', 'bin')));
  assert.match(executable, process.platform === 'win32' ? /sonar-scanner\.bat$/ : /sonar-scanner$/);
});

test('le wrapper .bat est lancé par l’interpréteur sans shell:true', () => {
  const windows = versionInvocation('C:\\tools\\bin\\sonar-scanner.bat', 'win32');
  assert.match(windows.executable, /cmd\.exe$/i);
  assert.deepEqual(windows.args, ['/d', '/s', '/c', 'C:\\tools\\bin\\sonar-scanner.bat', '--version']);
  const posix = versionInvocation('/opt/sonar/bin/sonar-scanner', 'linux');
  assert.equal(posix.executable, '/opt/sonar/bin/sonar-scanner');
  assert.deepEqual(posix.args, ['--version']);
  // Le runner utilise la même technique.
  assert.deepEqual(localInvocation('C:\\a\\sonar-scanner.bat', 'win32').prefixArgs, ['/d', '/s', '/c', 'C:\\a\\sonar-scanner.bat']);
});

test('activateManagedPath n’altère que le PATH du processus', async (t) => {
  const manager = storage(t);
  const before = process.env.PATH;
  t.after(() => { process.env.PATH = before; });
  await manager.activateManagedPath();
  assert.ok(process.env.PATH.includes(path.join('scanner-tools', 'sonarscanner', 'current', 'bin')));
  assert.ok(process.env.PATH.endsWith(before), 'le PATH existant est préservé, jamais remplacé');
});

// ---------------------------------------------------------- sécurité

test('une plateforme non distribuée est refusée avant tout téléchargement', async (t) => {
  const manager = storage(t);
  let progressed = false;
  await assert.rejects(
    () => manager.installSonarScanner({ ...TOOLS.sonarscanner }, () => { progressed = true; }, ''),
    /n’est pas distribué|Utilisez le mode Docker/
  );
  assert.equal(progressed, false, 'aucun téléchargement ne doit démarrer');
});

test('le garde Zip Slip refuse une archive qui écrit hors du dossier', async (t) => {
  const manager = storage(t);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zipslip-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const inside = path.join(root, 'extract');
  fs.mkdirSync(path.join(inside, 'sonar-scanner-8', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(inside, 'sonar-scanner-8', 'bin', 'sonar-scanner.bat'), 'echo ok');
  // Contenu légitime : aucune erreur.
  await manager.assertNoPathEscape(inside);

  if (process.platform === 'win32') return; // les liens symboliques exigent des droits élevés
  const escape = path.join(root, 'dehors');
  fs.mkdirSync(escape, { recursive: true });
  fs.symlinkSync(escape, path.join(inside, 'evade'));
  await assert.rejects(() => manager.assertNoPathEscape(inside), /en dehors du dossier d’installation/);
});

test('aucun jeton ni identifiant ne circule dans l’installateur', () => {
  const source = fs.readFileSync(require.resolve('../src/scanner-tool-manager.js'), 'utf8');
  for (const value of ['SONAR_TOKEN', 'sonar.token', 'secrets.get', 'Authorization']) {
    assert.equal(source.includes(value), false, `${value} n’a rien à faire dans l’installateur`);
  }
  // Aucune élévation de privilèges.
  for (const value of ['runas', 'sudo', 'Start-Process -Verb', 'setx ']) {
    assert.equal(source.includes(value), false, `${value} interdit`);
  }
});

// ---------------------------------------------------------- resolver

test('le resolver est unique : Local et Auto passent par le même code', async () => {
  const managed = { executable: 'cmd.exe', prefixArgs: ['/d', '/s', '/c', 'C:\\sc\\sonar-scanner.bat'], path: 'C:\\sc\\sonar-scanner.bat', version: '8.1.0.6389' };
  const detect = async () => managed;
  assert.equal((await resolveRunner('local', { detect, hasCommand: async () => false })).mode, 'local');
  const auto = await resolveRunner('auto', { detect, hasCommand: async () => true });
  assert.equal(auto.mode, 'local', 'Auto doit préférer le binaire géré');
  assert.equal(auto.local.version, '8.1.0.6389');
});

test('Auto retombe sur Docker uniquement quand le binaire géré est absent', async () => {
  const runner = await resolveRunner('auto', { detect: async () => null, hasCommand: async () => true });
  assert.equal(runner.mode, 'docker');
});

test('Docker ignore complètement l’installation locale', async () => {
  let detectCalled = false;
  const runner = await resolveRunner('docker', {
    detect: async () => { detectCalled = true; return { version: '8.1.0.6389' }; },
    hasCommand: async () => true
  });
  assert.equal(runner.mode, 'docker');
  assert.equal(detectCalled, false, 'le mode Docker ne dépend pas du binaire local');
});

test('mode Local sans binaire échoue explicitement sans basculer sur Docker', async () => {
  await assert.rejects(
    () => resolveRunner('local', { detect: async () => null, hasCommand: async () => true }),
    (error) => error.code === 'CONFIG_ERROR' && /introuvable/.test(error.message)
  );
});

// --------------------------------------------------------------- UI

test('le bouton Installer SonarScanner apparaît quand le binaire local manque', () => {
  const html = renderSonarCard(sonar({ mode: 'local', scannerVersion: '' }), false);
  assert.match(html, /data-sonar-install/);
  assert.match(html, />Installer SonarScanner</);
  assert.match(html, /Scanner local absent/);
  // Ne pas confondre avec l'installation du serveur.
  assert.equal(html.includes('Installer SonarScanner Server'), false);
});

test('le bouton disparaît une fois SonarScanner installé', () => {
  const html = renderSonarCard(sonar({ mode: 'local', scannerVersion: '8.1.0.6389', scannerPath: 'C:\\sc\\bin\\sonar-scanner.bat' }), false);
  assert.equal(html.includes('data-sonar-install'), false);
});

test('l’installation en cours verrouille le bouton et affiche la progression', () => {
  const html = renderSonarCard(sonar({ mode: 'local', scannerVersion: '', installing: { state: 'installing', title: 'Installation de SonarScanner', message: 'Téléchargement', percent: 40 } }), false);
  assert.match(html, /Installation de SonarScanner…/);
  assert.match(html, /<progress max="100" value="40">/);
  assert.match(html, /data-sonar-install[^>]*disabled/);
  assert.match(html, /spinner/);
});

test('après installation, le mode Local affiche le chemin réel et non l’image Docker', () => {
  const managedPath = 'C:\\Users\\x\\scanner-tools\\sonarscanner\\current\\bin\\sonar-scanner.bat';
  const html = renderSonarCard(sonar({ mode: 'local', scannerVersion: '8.1.0.6389', scannerPath: managedPath }), false);
  assert.match(html, /<dt>Mode configuré<\/dt><dd>Local<\/dd>/);
  assert.match(html, /<dt>Mode utilisé<\/dt><dd>Local<\/dd>/);
  assert.match(html, /<dt>Version<\/dt><dd>8\.1\.0\.6389<\/dd>/);
  assert.ok(html.includes('sonar-scanner.bat'), 'le chemin exécuté doit être affiché');
  assert.equal(html.includes('sonarsource/sonar-scanner-cli'), false, 'aucune image Docker en mode Local');
});

test('le mode Docker affiche l’image et reste indépendant de l’installation locale', () => {
  const html = renderSonarCard(sonar({ mode: 'docker', scannerVersion: '', dockerAvailable: true }), false);
  assert.match(html, /<dt>Mode configuré<\/dt><dd>Docker<\/dd>/);
  assert.match(html, /<dt>Mode utilisé<\/dt><dd>Docker<\/dd>/);
  assert.ok(html.includes('sonarsource/sonar-scanner-cli'));
  // Docker fonctionne sans binaire local : l'état reste « prêt » et rien
  // n'oblige à installer. Le bouton reste néanmoins offert (exigence 17 :
  // l'utilisateur peut toujours choisir explicitement l'installation locale).
  assert.match(html, /data-sonar-install/);
  // L'absence de binaire local est informative, jamais bloquante en Docker.
  assert.match(html, /<span class="status">Prêt — Docker<\/span>/);
  assert.equal(html.includes('class="tool failed"'), false, 'Docker ne doit pas être en échec');
  assert.equal(html.includes('class="tool missing"'), false, 'Docker ne doit pas être signalé comme incomplet');
});

test('le moteur affiché correspond au mode configuré', () => {
  assert.equal(usedScannerMode(sonar({ mode: 'local', scannerVersion: '8.1' })), 'Local');
  assert.equal(usedScannerMode(sonar({ mode: 'local', scannerVersion: '' })), '');
  assert.equal(usedScannerMode(sonar({ mode: 'docker', scannerVersion: '8.1' })), 'Docker');
  assert.equal(usedScannerMode(sonar({ mode: 'docker', dockerAvailable: false })), '');
  assert.equal(usedScannerMode(sonar({ mode: 'auto', scannerVersion: '8.1' })), 'Local');
  assert.equal(usedScannerMode(sonar({ mode: 'auto', scannerVersion: '', dockerAvailable: true })), 'Docker');
  assert.equal(usedScannerMode(sonar({ mode: 'auto', scannerVersion: '', dockerAvailable: false })), '');
});

test('la carte ne divulgue jamais le jeton pendant l’installation', () => {
  const html = renderSonarCard(sonar({ mode: 'local', scannerVersion: '', installing: { state: 'installing', title: 'Installation', message: 'Téléchargement' } }), false);
  assert.equal(html.includes(TOKEN), false);
  assert.equal(html.includes('squ_'), false);
});
