'use strict';

/**
 * CI Engine : détection côté extension et installeur administrateur.
 *
 * L'extension ne fait que constater l'état (Installed / Not detected /
 * Version unknown) depuis le rapport archivé ; l'installation reste un geste
 * administrateur exécuté sur l'hôte Docker.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { CI_ENGINE_STATE, detectCiEngine } = require('../src/ci-engine');
const { buildCiReport, validateCiReport } = require('../src/ci-report');
const { toDeliveryModel } = require('../src/integrations/delivery-jenkins');
const { name: PACKAGE_NAME, version: PACKAGE_VERSION } = require('../package.json');

const INSTALLER = path.join(__dirname, '..', '..', 'ci-engine', 'install-scenter-ci.sh');
const DIST_PACKAGE = path.join(__dirname, '..', '..', 'dist', `${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz`);

// ------------------------------------------------------------ détection

test('détection : un rapport portant la version du moteur → Installed', () => {
  const report = validateCiReport(JSON.stringify({
    schemaVersion: 1, engine: { name: PACKAGE_NAME, version: '0.9.0' }, execution: {}, policy: { status: 'PASS' }, scanners: []
  })).report;
  const engine = detectCiEngine({ reportState: 'REPORTED', report });
  assert.equal(engine.state, CI_ENGINE_STATE.INSTALLED);
  assert.equal(engine.label, 'CI Engine: Installed');
  assert.equal(engine.version, '0.9.0');
});

test('détection : un rapport Security Center sans version → Version unknown', () => {
  const legacy = validateCiReport(JSON.stringify({ schemaVersion: 1, execution: {}, policy: { status: 'PASS' }, scanners: [] })).report;
  assert.equal(detectCiEngine({ reportState: 'REPORTED', report: legacy }).state, CI_ENGINE_STATE.VERSION_UNKNOWN);
  const malformed = validateCiReport(JSON.stringify({ schemaVersion: 1, engine: { name: 'x', version: 'latest; rm -rf /' }, execution: {}, policy: { status: 'PASS' }, scanners: [] })).report;
  assert.equal(malformed.engine.version, null, 'une version illisible n’est jamais recopiée');
  assert.equal(detectCiEngine({ reportState: 'REPORTED', report: malformed }).label, 'CI Engine: Version unknown');
});

test('détection : pas de rapport, rapport invalide ou incohérent → Not detected', () => {
  for (const reportState of ['NOT_REPORTED', 'INVALID', 'UNAVAILABLE', '']) {
    const engine = detectCiEngine({ reportState, report: null });
    assert.equal(engine.state, CI_ENGINE_STATE.NOT_DETECTED);
    assert.equal(engine.label, 'CI Engine: Not detected');
    assert.ok(engine.reason.length > 0);
  }
  const report = { engine: { version: '0.9.0' } };
  assert.equal(detectCiEngine({ reportState: 'REPORTED', report, inconsistent: true }).state, CI_ENGINE_STATE.NOT_DETECTED);
});

test('le rapport CI déclare le moteur qui l’a écrit (nom et version du paquet)', () => {
  const built = buildCiReport({ findings: [], scanners: [], failures: [] }, { engine: { name: PACKAGE_NAME, version: PACKAGE_VERSION } });
  // Outside a Security Center build there is no stamped commit: null, never guessed.
  assert.deepEqual(built.engine, { name: PACKAGE_NAME, version: PACKAGE_VERSION, commit: null });
  assert.equal(buildCiReport({ findings: [], scanners: [], failures: [] }).engine, null);
  assert.deepEqual(validateCiReport(JSON.stringify(built)).report.engine, { name: PACKAGE_NAME, version: PACKAGE_VERSION, commit: null });
  // A built engine names its source commit; anything that is not a git SHA is dropped.
  const commit = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
  const stamped = buildCiReport({ findings: [], scanners: [], failures: [] }, { engine: { name: PACKAGE_NAME, version: PACKAGE_VERSION, commit } });
  assert.equal(validateCiReport(JSON.stringify(stamped)).report.engine.commit, commit);
  assert.equal(detectCiEngine({ reportState: 'REPORTED', report: validateCiReport(JSON.stringify(stamped)).report }).commit, commit);
  const forged = buildCiReport({ findings: [], scanners: [], failures: [] }, { engine: { name: PACKAGE_NAME, version: PACKAGE_VERSION, commit: 'main; curl evil' } });
  assert.equal(forged.engine.commit, null);
  // Le CLI passe bien la version de son propre package.json.
  const cli = fs.readFileSync(path.join(__dirname, '..', 'src', 'cli.js'), 'utf8');
  assert.match(cli, /require\('\.\.\/package\.json'\)/);
  assert.match(cli, /engine: \{ name: ENGINE_PACKAGE, version: ENGINE_VERSION, commit: ENGINE_COMMIT \}/);
  assert.match(cli, /require\('\.\.\/build-info\.json'\)/, 'le commit vient de l’identité de build embarquée');
});

test('Security Delivery expose l’état du moteur CI sans rien exécuter', () => {
  const report = validateCiReport(JSON.stringify({ schemaVersion: 1, engine: { name: PACKAGE_NAME, version: '0.9.0' }, execution: {}, policy: { status: 'PASS' }, scanners: [] })).report;
  const status = {
    configured: true, state: 'SUCCESS', job: 'security-pipeline', baseUrl: 'http://ci.local',
    build: { number: 3, state: 'SUCCESS', artifacts: [] },
    ci: { state: 'REPORTED', report, reason: '', artifactPath: 'security-center-report.json' },
    identity: { inconsistent: false }
  };
  const model = toDeliveryModel(status, { url: 'http://ci.local', job: 'security-pipeline' });
  assert.equal(model.securityReport.ciEngine.label, 'CI Engine: Installed');
  const none = toDeliveryModel({ ...status, ci: { state: 'NOT_REPORTED', report: null } }, { url: 'u', job: 'p' });
  assert.equal(none.securityReport.ciEngine.label, 'CI Engine: Not detected');
  // L'extension ne lance aucune installation.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'ci-engine.js'), 'utf8');
  assert.doesNotMatch(source, /child_process|docker|npm install/);
});

// ------------------------------------------------------------ installeur

function bashPath() {
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  if (process.platform === 'win32') return fs.existsSync(gitBash) ? gitBash : null;
  return 'bash';
}

function posix(file) {
  if (process.platform !== 'win32') return file;
  return file.replace(/^([A-Za-z]):\\/, (_, drive) => `/${drive.toLowerCase()}/`).replace(/\\/g, '/');
}

function runInstaller(args, { env = {} } = {}) {
  const bash = bashPath();
  const result = spawnSync(bash, [posix(INSTALLER), ...args], {
    encoding: 'utf8', timeout: 60000, env: { ...process.env, ...env }
  });
  return { status: result.status, output: `${result.stdout || ''}${result.stderr || ''}` };
}

test('installeur : script shell LF, syntaxe valide', { skip: !bashPath() && 'bash indisponible' }, () => {
  const bytes = fs.readFileSync(INSTALLER);
  assert.ok(bytes.slice(0, 20).toString('latin1').startsWith('#!/usr/bin/env bash\n'));
  assert.ok(!bytes.includes(13), 'aucun CR : le shebang doit fonctionner sur Linux');
  const syntax = spawnSync(bashPath(), ['-n', posix(INSTALLER)], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
});

test('installeur : contrat — installation npm locale, Node jamais téléchargé, aucun secret affiché', () => {
  const script = fs.readFileSync(INSTALLER, 'utf8');
  assert.match(script, /npm" install --global --prefix "\$PREFIX" "\$archive"/);
  assert.match(script, /PREFIX="\$JENKINS_HOME_DIR\/tools\/security-center"/);
  assert.match(script, /PACKAGES="\$JENKINS_HOME_DIR\/tools\/security-center-packages"/);
  assert.match(script, /JENKINS_HOME_DIR="\$\{SCENTER_JENKINS_HOME:-\/var\/jenkins_home\}"/);
  assert.match(script, /CONTAINER="\$\{SCENTER_JENKINS_CONTAINER:-jenkins\}"/);
  assert.match(script, /"\$COMMAND_PATH" --help/);
  assert.doesNotMatch(script, /\b(curl|wget)\b/, 'aucun téléchargement');
  assert.doesNotMatch(script, /\.Config\.Env|docker inspect [^\n]*--format '\{\{json/, 'l’environnement du conteneur n’est jamais lu');
  assert.doesNotMatch(script, /set -x/);
  // Les archives ne sont jamais supprimées : un build différent de même version est renommé.
  assert.doesNotMatch(script, /rm -[rf]+ "\$PACKAGES|rm -f "\$target"/);
  assert.match(script, /kept="\$PACKAGES\/\$\{ARCHIVE_NAME%\.tgz\}\.\$\{existing_sha:0:12\}\.tgz"/);
  for (const mode of ['--check', '--status', '--rollback', '--uninstall', '--container']) assert.ok(script.includes(mode), mode);
});

test('installeur : aide et erreurs d’usage sans Docker', { skip: !bashPath() && 'bash indisponible' }, () => {
  const help = runInstaller(['--help']);
  assert.equal(help.status, 0);
  assert.match(help.output, /Usage:/);
  assert.match(help.output, /--rollback/);

  const missing = runInstaller([]);
  assert.equal(missing.status, 2);
  assert.match(missing.output, /missing package archive/);

  assert.equal(runInstaller(['--bogus']).status, 2);
  assert.equal(runInstaller(['--status', 'extra.tgz']).status, 2);
});

test('installeur : archive absente, mal nommée ou qui n’est pas un paquet → code 2, rien n’est modifié', { skip: !bashPath() && 'bash indisponible' }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-installer-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const absent = runInstaller([posix(path.join(dir, 'security-center-vscode-0.9.0.tgz'))]);
  assert.equal(absent.status, 2);
  assert.match(absent.output, /not found or unreadable/);
  assert.match(absent.output, /Result\s+FAILED/);

  const wrongName = path.join(dir, 'scenter.tgz');
  fs.writeFileSync(wrongName, 'x');
  assert.match(runInstaller([posix(wrongName)]).output, /unexpected archive name/);

  const notPackage = path.join(dir, 'security-center-vscode-0.9.0.tgz');
  fs.writeFileSync(notPackage, 'not a tarball');
  const refused = runInstaller([posix(notPackage)]);
  assert.equal(refused.status, 2);
  assert.match(refused.output, /is not a Security Center npm package/);
});

test('installeur : le vrai paquet est validé, puis un démon Docker injoignable arrête proprement', {
  skip: (!bashPath() && 'bash indisponible') || (!fs.existsSync(DIST_PACKAGE) && 'paquet dist absent')
}, (t) => {
  // Un faux `docker` dont le démon ne répond pas : aucun conteneur n'est touché.
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fake-docker-'));
  t.after(() => fs.rmSync(bin, { recursive: true, force: true }));
  fs.writeFileSync(path.join(bin, 'docker'), '#!/usr/bin/env bash\necho "daemon unreachable" >&2\nexit 1\n', { mode: 0o755 });
  const result = runInstaller([posix(DIST_PACKAGE)], { env: { PATH: `${bin}${path.delimiter}${process.env.PATH}` } });
  assert.equal(result.status, 2);
  assert.match(result.output, new RegExp(`ok: ${PACKAGE_NAME}-${PACKAGE_VERSION.replace(/\./g, '\\.')}\\.tgz \\(version ${PACKAGE_VERSION.replace(/\./g, '\\.')}`));
  assert.match(result.output, /cannot reach the Docker daemon/);
  assert.match(result.output, /Result\s+FAILED/);
});
