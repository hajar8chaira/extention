const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildScans, defaultOptions } = require('../src/orchestrator');
const { validatePolicy, parsePolicyYaml, loadProjectPolicy, TOOL_KEYS } = require('../src/project-policy');
const { parseArgs, help } = require('../src/cli');
const { TOOLS, snykCliAsset, parseSnykChecksums, SNYK_CLI_BASE, ScannerToolManager } = require('../src/scanner-tool-manager');

const TOKEN = '11111111-2222-3333-4444-555555555555';

function workspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'snyk-ws-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
  return root;
}

function scanTools(options = {}, policy = null) {
  return buildScans('/repo', policy, defaultOptions(options), new AbortController().signal).map((scan) => scan.tool);
}

// -------------------------------------------------------------- orchestrateur

test('Snyk reste absent du pipeline par défaut', () => {
  assert.ok(!scanTools().includes('Snyk'));
  assert.equal(defaultOptions().snykEnabled, false);
  assert.equal(defaultOptions().snykMode, 'auto');
  assert.equal(defaultOptions().snykIncludeOpenSource, true);
  assert.equal(defaultOptions().snykIncludeCode, false);
});

test('Snyk activé rejoint la phase statique après SonarQube', () => {
  const tools = scanTools({ snykEnabled: true, snykToken: TOKEN });
  assert.deepEqual(tools, ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'Snyk', 'ZAP']);
  const scans = buildScans('/repo', null, defaultOptions({ snykEnabled: true, snykToken: TOKEN }), new AbortController().signal);
  assert.equal(scans.find((scan) => scan.tool === 'Snyk').dynamic, undefined);
});

test('aucun scanner existant ne disparaît quand Snyk est activé', () => {
  const withoutSnyk = scanTools();
  const withSnyk = scanTools({ snykEnabled: true, snykToken: TOKEN });
  for (const tool of withoutSnyk) assert.ok(withSnyk.includes(tool), `${tool} perdu`);
});

test('Snyk peut être sélectionné seul', () => {
  assert.deepEqual(scanTools({ snykEnabled: true, snykToken: TOKEN, selectedTools: ['Snyk'] }), ['Snyk']);
});

test('la politique projet peut désactiver Snyk malgré le réglage utilisateur', () => {
  const policy = validatePolicy({ scanners: { snyk: false } });
  assert.ok(!scanTools({ snykEnabled: true, snykToken: TOKEN }, policy).includes('Snyk'));
});

test('la politique projet lit le mode et les capacités Snyk', () => {
  const policy = validatePolicy(parsePolicyYaml('snyk:\n  mode: docker\n  include_code: true\n  include_iac: true\n'));
  assert.equal(policy.snykMode, 'docker');
  assert.deepEqual(policy.snykCapabilities, { includeCode: true, includeIaC: true });
});

test('la politique projet prime sur les réglages utilisateur pour les capacités', async () => {
  // include_open_source: false wins over the user setting, so the runner
  // refuses before touching the disk or the network: proof of precedence.
  const policy = validatePolicy(parsePolicyYaml('snyk:\n  include_open_source: false\n'));
  const scans = buildScans('/repo', policy, defaultOptions({
    snykEnabled: true, snykToken: TOKEN, snykIncludeOpenSource: true
  }), new AbortController().signal);
  await assert.rejects(
    () => scans.find((scan) => scan.tool === 'Snyk').execute(),
    (error) => error.code === 'CONFIG_ERROR'
  );
});

test('l’annulation du pipeline est propagée au runner Snyk', async () => {
  const controller = new AbortController();
  const scans = buildScans('/repo', null, defaultOptions({ snykEnabled: true, snykToken: TOKEN, snykMode: 'docker' }), controller.signal);
  controller.abort();
  await assert.rejects(() => scans.find((scan) => scan.tool === 'Snyk').execute());
});

// -------------------------------------------------------------- project policy

test('security-center.yml accepte scanners.snyk', () => {
  assert.equal(TOOL_KEYS.snyk, 'Snyk');
  assert.deepEqual(validatePolicy(parsePolicyYaml('scanners:\n  snyk: true\n')).scanners, { Snyk: true });
  assert.deepEqual(validatePolicy(parsePolicyYaml('scanners:\n  snyk: false\n')).scanners, { Snyk: false });
});

test('un mode Snyk invalide est refusé avec un message clair', () => {
  assert.throws(() => validatePolicy({ snyk: { mode: 'cloud' } }), /snyk\.mode doit être auto, local ou docker/);
  assert.throws(() => validatePolicy({ snyk: { include_code: 'oui' } }), /snyk\.include_code doit être true ou false/);
});

test('sans section snyk, le réglage VS Code continue de s’appliquer', () => {
  const policy = validatePolicy(parsePolicyYaml('version: 1\n'));
  assert.equal(policy.snykMode, '');
  assert.deepEqual(policy.snykCapabilities, {});
});

test('le jeton Snyk n’est jamais lisible depuis la politique projet', async (t) => {
  const root = workspace(t, { 'security-center.yml': `scanners:\n  snyk: true\nsnyk:\n  mode: auto\n  token: ${TOKEN}\n` });
  const policy = await loadProjectPolicy(root);
  assert.equal(policy.scanners.Snyk, true);
  assert.ok(!JSON.stringify(policy).includes(TOKEN));
});

// --------------------------------------------------------------- CLI headless

test('le CLI headless documente Snyk et son jeton d’environnement', () => {
  assert.match(help(), /Snyk/);
  assert.match(help(), /SNYK_TOKEN/);
  assert.ok(!help().includes(TOKEN));
});

test('le CLI headless accepte le mode et les capacités Snyk', () => {
  const args = parseArgs(['--tools', 'Snyk', '--snyk-mode', 'docker', '--snyk-code', '--snyk-iac']);
  assert.deepEqual(args.tools, ['Snyk']);
  assert.equal(args.snykMode, 'docker');
  assert.equal(args.snykCode, true);
  assert.equal(args.snykIac, true);
});

test('le CLI headless refuse un mode Snyk inconnu', () => {
  assert.throws(() => parseArgs(['--snyk-mode', 'cloud']), /--snyk-mode accepte auto, local ou docker/);
});

test('le CLI headless n’expose aucune option de jeton Snyk', () => {
  assert.ok(!help().includes('--snyk-token'));
});

// ------------------------------------------------------- installation locale

test('Snyk CLI est un outil géré par Security Center', () => {
  assert.equal(TOOLS.snyk.label, 'Snyk CLI');
  assert.equal(TOOLS.snyk.command, 'snyk');
  assert.equal(TOOLS.snyk.kind, 'snyk');
  assert.equal(TOOLS.snyk.base, SNYK_CLI_BASE);
  assert.match(SNYK_CLI_BASE, /^https:\/\/downloads\.snyk\.io\//);
});

test('l’artefact officiel dépend de la plateforme', () => {
  assert.equal(snykCliAsset('win32', 'x64'), 'snyk-win.exe');
  assert.equal(snykCliAsset('linux', 'x64'), 'snyk-linux');
  assert.equal(snykCliAsset('linux', 'arm64'), 'snyk-linux-arm64');
  assert.equal(snykCliAsset('darwin', 'arm64'), 'snyk-macos-arm64');
  assert.equal(snykCliAsset('darwin', 'x64'), 'snyk-macos');
  assert.equal(snykCliAsset('aix', 'x64'), '');
});

test('l’empreinte est lue dans la liste signée par Snyk, sans confusion de nom', () => {
  const listing = [
    '-----BEGIN PGP SIGNED MESSAGE-----', 'Hash: SHA512', '',
    `${'a'.repeat(64)}  snyk-linux-arm64`,
    `${'b'.repeat(64)}  snyk-linux`,
    `${'c'.repeat(64)}  snyk-win.exe`,
    '-----BEGIN PGP SIGNATURE-----'
  ].join('\n');
  assert.equal(parseSnykChecksums(listing, 'snyk-linux'), 'b'.repeat(64));
  assert.equal(parseSnykChecksums(listing, 'snyk-win.exe'), 'c'.repeat(64));
  assert.equal(parseSnykChecksums(listing, 'snyk-alpine'), '');
});

test('une installation sans empreinte publiée est refusée', async (t) => {
  const root = workspace(t);
  const manager = new ScannerToolManager(root);
  await assert.rejects(
    () => manager.installSnyk(TOOLS.snyk, () => {}, ''),
    /n’est pas distribué|Utilisez le mode Docker/
  );
});

test('le binaire géré est installé dans le stockage privé de l’extension', (t) => {
  const root = workspace(t);
  const manager = new ScannerToolManager(root);
  const executable = manager.managedExecutable('snyk');
  assert.ok(executable.startsWith(path.join(root, 'scanner-tools', 'snyk')));
  assert.match(path.basename(executable), /^snyk(\.exe)?$/);
});
