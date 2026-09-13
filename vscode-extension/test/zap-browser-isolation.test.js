'use strict';

/**
 * Pendant un scan actif réel de Juice Shop, la règle DOM XSS de ZAP pilotait un
 * Firefox headless qui enregistrait `incident-support.kdbx` et
 * `juicy_malware_*.url` dans le dossier Téléchargements de Windows
 * (Zone.Identifier : HostUrl=http://192.168.222.132:3000/ftp/incident-support.kdbx#javascript:alert(5397)).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  ZAP_FIREFOX_PROFILE_NAME, zapIsolationNamespace, newZapRunId, firefoxDownloadPreferences, isInsideNamespace,
  prepareZapBrowserIsolation, cleanupZapBrowserIsolation, sweepStaleZapRuns
} = require('../src/zap-browser-isolation');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');
const tmpRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sc-zap-iso-'));
const noProcesses = async () => 0;

test('chaque run a son bac à sable : téléchargements, TEMP et APPDATA sous %TEMP%\\SecurityCenter\\zap\\<run-id>', async (t) => {
  const root = tmpRoot();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const runId = newZapRunId(new Date('2026-09-13T08:30:00Z'));
  assert.match(runId, /^zap-20260913-083000-[0-9a-f]{8}$/);
  const isolation = await prepareZapBrowserIsolation({ runId, tmpRoot: root });

  assert.equal(isolation.root, path.join(root, 'SecurityCenter', 'zap', runId));
  assert.equal(isolation.downloads, path.join(isolation.root, 'downloads'));
  for (const directory of [isolation.downloads, isolation.temp, isolation.profileDir]) assert.ok(fs.statSync(directory).isDirectory());
  assert.deepEqual(isolation.env, { APPDATA: isolation.appData, TEMP: isolation.temp, TMP: isolation.temp });
  assert.deepEqual(isolation.configArgs, ['-config', `selenium.firefoxProfile=${ZAP_FIREFOX_PROFILE_NAME}`]);

  // La forme que le gestionnaire de profils Firefox de ZAP reconnaît : APPDATA\Mozilla\Firefox\Profiles\xxxxxxxx.<nom>.
  assert.equal(path.dirname(isolation.profileDir), path.join(isolation.appData, 'Mozilla', 'Firefox', 'Profiles'));
  assert.match(path.basename(isolation.profileDir), new RegExp(`^\\w{8}\\.${ZAP_FIREFOX_PROFILE_NAME}$`));

  // Selenium (`ProfilesIni`, lu par ZAP) ne trouve un profil que s'il est déclaré
  // dans %APPDATA%\Mozilla\Firefox\profiles.ini, avec un chemin relatif à ce fichier.
  assert.equal(isolation.profilesIni, path.join(isolation.appData, 'Mozilla', 'Firefox', 'profiles.ini'));
  const ini = fs.readFileSync(isolation.profilesIni, 'utf8');
  assert.match(ini, /\[Profile0\]\r\nName=security-center-zap\r\nIsRelative=1\r\nPath=Profiles\/\w{8}\.security-center-zap\r\n/);
  const declared = ini.match(/Path=(.+)\r\n/)[1];
  assert.equal(path.resolve(path.dirname(isolation.profilesIni), declared), isolation.profileDir);

  const userJs = fs.readFileSync(path.join(isolation.profileDir, 'user.js'), 'utf8');
  assert.match(userJs, /user_pref\("browser\.download\.folderList", 2\);/);
  assert.ok(userJs.includes(`user_pref("browser.download.dir", ${JSON.stringify(isolation.downloads)});`));
  assert.match(userJs, /user_pref\("browser\.download\.useDownloadDir", true\);/);
  assert.match(userJs, /user_pref\("browser\.download\.forbid_open_with", true\);/);
  assert.match(userJs, /user_pref\("browser\.download\.viewableInternally\.enabledTypes", ""\);/);
});

test('aucun dossier personnel ni profil de navigateur de l’utilisateur n’est jamais visé', async (t) => {
  const root = tmpRoot();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const isolation = await prepareZapBrowserIsolation({ tmpRoot: root });
  const home = os.homedir();
  const personal = ['Downloads', 'Desktop', 'Documents'].map((name) => path.join(home, name).toLowerCase());
  const everything = [isolation.downloads, isolation.temp, isolation.appData, isolation.profileDir, ...Object.values(isolation.env)].map((entry) => entry.toLowerCase());
  for (const entry of everything) {
    for (const folder of personal) assert.ok(!entry.startsWith(folder), `${entry} ne doit pas être sous ${folder}`);
    assert.ok(!entry.startsWith(path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Mozilla').toLowerCase()));
  }
  assert.ok(!firefoxDownloadPreferences(isolation.downloads).toLowerCase().includes(path.join(home, 'downloads').toLowerCase()));
});

test('le nettoyage supprime téléchargements, profils et temporaires du run, et rien d’autre', async (t) => {
  const root = tmpRoot();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const isolation = await prepareZapBrowserIsolation({ tmpRoot: root });
  await fsp.writeFile(path.join(isolation.downloads, 'incident-support.kdbx'), 'x');
  await fsp.writeFile(path.join(isolation.downloads, 'juicy_malware_linux_amd_64.url.download'), 'x');
  await fsp.mkdir(path.join(isolation.temp, 'rust_mozprofileAbCd12'), { recursive: true });
  const neighbour = path.join(root, 'SecurityCenter', 'keep-me.txt');
  await fsp.writeFile(neighbour, 'x');

  const result = await cleanupZapBrowserIsolation(isolation, { tmpRoot: root, delayMs: 1, stopProcesses: noProcesses });
  assert.equal(result.removed, true);
  assert.equal(result.downloads, 2);
  assert.equal(fs.existsSync(isolation.root), false);
  assert.equal(fs.existsSync(neighbour), true, 'hors du run, rien n’est touché');
});

test('le nettoyage refuse tout chemin hors de l’espace de noms Security Center', async () => {
  const root = tmpRoot();
  const outside = path.join(root, 'Downloads');
  await fsp.mkdir(outside, { recursive: true });
  const result = await cleanupZapBrowserIsolation({ root: outside, downloads: outside }, { tmpRoot: root, stopProcesses: noProcesses });
  assert.equal(result.removed, false);
  assert.equal(fs.existsSync(outside), true);
  assert.equal(isInsideNamespace(zapIsolationNamespace(root), root), false, 'l’espace de noms lui-même n’est pas un run');
  await fsp.rm(root, { recursive: true, force: true });
});

test('les bacs à sable de runs interrompus sont repris, jamais un run récent', async (t) => {
  const root = tmpRoot();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const old = await prepareZapBrowserIsolation({ runId: 'zap-20260912-100000-aaaaaaaa', tmpRoot: root });
  const recent = await prepareZapBrowserIsolation({ runId: 'zap-20260913-083000-bbbbbbbb', tmpRoot: root });
  const current = await prepareZapBrowserIsolation({ runId: 'zap-20260913-083500-cccccccc', tmpRoot: root });
  const past = new Date(Date.now() - 3 * 60 * 60 * 1000);
  fs.utimesSync(old.root, past, past);
  const foreign = path.join(zapIsolationNamespace(root), 'not-a-run');
  await fsp.mkdir(foreign, { recursive: true });
  fs.utimesSync(foreign, past, past);

  const removed = await sweepStaleZapRuns({ tmpRoot: root, keep: [current.runId] });
  assert.deepEqual(removed, [old.runId]);
  assert.equal(fs.existsSync(recent.root), true);
  assert.equal(fs.existsSync(current.root), true);
  assert.equal(fs.existsSync(foreign), true, 'un répertoire qui n’est pas un run n’est jamais supprimé');
});

test('le démon ZAP local est lancé dans le bac à sable et nettoyé sur toutes les issues', () => {
  const local = src('zap-local.js');
  const launcher = local.match(/function startLocalZap\([\s\S]*?\n\}/)[0];
  assert.match(launcher, /const env = \{ \.\.\.process\.env, \.\.\.\(isolation\?\.env \|\| \{\}\) \};/);
  assert.match(launcher, /if \(isolation\?\.configArgs\?\.length\) args\.push\(\.\.\.isolation\.configArgs\);/);

  const run = local.match(/async function runLocalZap\([\s\S]*?\n\}/)[0];
  const prepared = run.indexOf('const isolation = await prepareZapBrowserIsolation();');
  const launched = run.indexOf('startLocalZap(zapPath, { port, apiKey, authResult, home, onDiagnostic: (info) => diagnose({ launch: info }) }, isolation)');
  assert.ok(prepared > 0 && launched > prepared, 'le bac à sable existe avant le démon');
  // Lancement refusé : nettoyé avant de propager.
  assert.match(run, /lancement refusé : \$\{error\.message\}` \}\);\s*await cleanupIsolation\(\);\s*throw error;/);
  // Succès, échec, annulation : le `finally` arrête le démon puis nettoie.
  const finallyBlock = run.slice(run.lastIndexOf('} finally {'));
  assert.ok(finallyBlock.indexOf('stopLocalZap(child') < finallyBlock.indexOf('await cleanupIsolation();'));
});
