'use strict';

/**
 * Le navigateur automatisé de ZAP, isolé du profil de l'utilisateur.
 *
 * Constaté sur un scan actif réel de Juice Shop : la règle DOM XSS de ZAP pilote
 * un Firefox headless (geckodriver) qui suit les liens `/ftp/…` de la cible avec
 * ses charges `#javascript:alert(…)`. Sans réglage, ce Firefox enregistre dans le
 * dossier Téléchargements de Windows — `incident-support.kdbx`,
 * `juicy_malware_*.url` — et geckodriver laisse une copie de profil par
 * navigateur dans le TEMP partagé (291 répertoires `rust_mozprofile*`, 14 Go).
 *
 * Chaque run reçoit donc son propre bac à sable :
 *
 *   %TEMP%\SecurityCenter\zap\<run-id>\
 *     downloads\   le seul endroit où le navigateur automatisé peut enregistrer
 *     tmp\         TEMP/TMP du démon : profils geckodriver et fichiers Java
 *     appdata\     APPDATA du démon : le profil Firefox de Security Center
 *
 * Le module Selenium de ZAP cherche ses profils Firefox nommés sous
 * `%APPDATA%\Mozilla\Firefox\Profiles`, lu dans l'environnement du processus :
 * un APPDATA propre au démon lui donne un profil à nous, sans jamais toucher aux
 * profils Firefox de l'utilisateur. Rien n'est conservé comme preuve : les
 * téléchargements sont supprimés avec le run.
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

/** Le nom du profil Firefox de Security Center, tel que `selenium.firefoxProfile` le désigne. */
const ZAP_FIREFOX_PROFILE_NAME = 'security-center-zap';

/** Un run abandonné plus vieux que cela n'appartient plus à aucun scan vivant. */
const STALE_RUN_AGE_MS = 2 * 60 * 60 * 1000;

/** Le répertoire de tous les runs ZAP isolés. */
function zapIsolationNamespace(tmpRoot = os.tmpdir()) {
  return path.join(tmpRoot, 'SecurityCenter', 'zap');
}

/** Un identifiant de run sûr comme nom de répertoire, triable par date. */
function newZapRunId(now = new Date()) {
  const stamp = now.toISOString().replace(/[-:.]/g, '').replace('T', '-').slice(0, 15);
  return `zap-${stamp}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Les préférences Firefox du navigateur automatisé.
 *
 * Tout téléchargement va dans le répertoire du run, sans question, sans panneau,
 * sans ouverture : ni « ouvrir avec », ni affichage dans le navigateur.
 */
function firefoxDownloadPreferences(downloads) {
  const prefs = [
    ['browser.download.folderList', 2],
    ['browser.download.dir', downloads],
    ['browser.download.useDownloadDir', true],
    ['browser.download.start_downloads_in_tmp_dir', false],
    ['browser.download.always_ask_before_handling_new_types', false],
    ['browser.download.manager.showWhenStarting', false],
    ['browser.download.alwaysOpenPanel', false],
    ['browser.download.forbid_open_with', true],
    ['browser.download.viewableInternally.enabledTypes', ''],
    ['browser.helperApps.alwaysAsk.force', false],
    ['browser.shell.checkDefaultBrowser', false]
  ];
  return `${prefs.map(([name, value]) => `user_pref(${JSON.stringify(name)}, ${JSON.stringify(value)});`).join('\n')}\n`;
}

/** Vrai seulement pour un chemin situé strictement sous l'espace de noms des runs ZAP. */
function isInsideNamespace(target, tmpRoot = os.tmpdir()) {
  const namespace = path.resolve(zapIsolationNamespace(tmpRoot)) + path.sep;
  return path.resolve(target).toLowerCase().startsWith(namespace.toLowerCase());
}

/**
 * Prépare le bac à sable d'un run et rend ce que le lanceur doit appliquer :
 * l'environnement du démon et l'option qui désigne le profil.
 */
async function prepareZapBrowserIsolation({ runId = newZapRunId(), tmpRoot = os.tmpdir() } = {}) {
  const root = path.join(zapIsolationNamespace(tmpRoot), runId);
  const downloads = path.join(root, 'downloads');
  const temp = path.join(root, 'tmp');
  const appData = path.join(root, 'appdata');
  // `^\w{8}\.` : la forme de répertoire que le gestionnaire de profils de ZAP reconnaît.
  const profileDir = path.join(appData, 'Mozilla', 'Firefox', 'Profiles', `${crypto.randomBytes(4).toString('hex')}.${ZAP_FIREFOX_PROFILE_NAME}`);
  for (const directory of [downloads, temp, profileDir]) await fsp.mkdir(directory, { recursive: true });
  await fsp.writeFile(path.join(profileDir, 'user.js'), firefoxDownloadPreferences(downloads), 'utf8');
  // ZAP ouvre le Firefox headless par `new ProfilesIni().getProfile(nom)` de
  // Selenium, qui ne connaît un profil que s'il est déclaré dans
  // %APPDATA%\Mozilla\Firefox\profiles.ini. Sans cette déclaration, le profil
  // était ignoré et Firefox téléchargeait dans le dossier de l'utilisateur.
  const profilesIni = path.join(appData, 'Mozilla', 'Firefox', 'profiles.ini');
  const relativeProfile = path.relative(path.dirname(profilesIni), profileDir).split(path.sep).join('/');
  await fsp.writeFile(profilesIni, [
    '[General]', 'StartWithLastProfile=1', '',
    '[Profile0]', `Name=${ZAP_FIREFOX_PROFILE_NAME}`, 'IsRelative=1', `Path=${relativeProfile}`, 'Default=1', ''
  ].join('\r\n'), 'utf8');
  return {
    runId,
    root,
    downloads,
    temp,
    appData,
    profilesIni,
    profileDir,
    profileName: ZAP_FIREFOX_PROFILE_NAME,
    env: { APPDATA: appData, TEMP: temp, TMP: temp },
    configArgs: ['-config', `selenium.firefoxProfile=${ZAP_FIREFOX_PROFILE_NAME}`]
  };
}

/**
 * Arrête les navigateurs et pilotes lancés depuis ce run, et eux seuls.
 *
 * Un Firefox headless survit parfois à son démon et garde ses fichiers ouverts.
 * Seuls les processus dont la ligne de commande désigne le répertoire du run —
 * donc ses copies de profil — sont concernés : aucun navigateur de l'utilisateur.
 */
function stopProcessesUnder(root, { platform = process.platform, timeoutMs = 15000 } = {}) {
  if (platform !== 'win32') return Promise.resolve(0);
  const literal = root.replace(/'/g, "''");
  const script = `$n=0; Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf('${literal}', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }; $n`;
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: timeoutMs }, (error, stdout) => {
      resolve(error ? 0 : Number(String(stdout).trim()) || 0);
    });
  });
}

/**
 * Supprime le bac à sable d'un run : téléchargements, profils, fichiers temporaires.
 *
 * Refuse tout chemin hors de l'espace de noms des runs ZAP. Réessaie tant que des
 * fichiers restent tenus ; ce qui reste malgré tout sera repris au run suivant.
 */
async function cleanupZapBrowserIsolation(isolation, { attempts = 5, delayMs = 1000, tmpRoot = os.tmpdir(), stopProcesses = stopProcessesUnder } = {}) {
  if (!isolation?.root || !isInsideNamespace(isolation.root, tmpRoot)) {
    return { removed: false, reason: 'chemin hors de l’espace de noms Security Center — rien n’est supprimé' };
  }
  const downloaded = await fsp.readdir(isolation.downloads).catch(() => []);
  const stopped = await stopProcesses(isolation.root).catch(() => 0);
  let lastError = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await fsp.rm(isolation.root, { recursive: true, force: true });
      if (!fs.existsSync(isolation.root)) return { removed: true, downloads: downloaded.length, stoppedProcesses: stopped, attempts: attempt };
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return { removed: false, downloads: downloaded.length, stoppedProcesses: stopped, reason: lastError?.message || 'fichiers encore tenus' };
}

/**
 * Reprend les bacs à sable de runs interrompus — fenêtre fermée, démon tué —
 * restés sous l'espace de noms. Un run récent n'est jamais touché : il peut
 * appartenir à un scan encore en cours dans une autre fenêtre.
 */
async function sweepStaleZapRuns({ tmpRoot = os.tmpdir(), keep = [], olderThanMs = STALE_RUN_AGE_MS, now = Date.now() } = {}) {
  const namespace = zapIsolationNamespace(tmpRoot);
  const entries = await fsp.readdir(namespace, { withFileTypes: true }).catch(() => []);
  const removed = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^zap-\d{8}-\d{6}-[0-9a-f]{8}$/.test(entry.name) || keep.includes(entry.name)) continue;
    const target = path.join(namespace, entry.name);
    const stats = await fsp.stat(target).catch(() => null);
    if (!stats || now - stats.mtimeMs < olderThanMs) continue;
    const ok = await fsp.rm(target, { recursive: true, force: true }).then(() => true).catch(() => false);
    if (ok) removed.push(entry.name);
  }
  return removed;
}

module.exports = {
  ZAP_FIREFOX_PROFILE_NAME, STALE_RUN_AGE_MS,
  zapIsolationNamespace, newZapRunId, firefoxDownloadPreferences, isInsideNamespace,
  prepareZapBrowserIsolation, cleanupZapBrowserIsolation, sweepStaleZapRuns, stopProcessesUnder
};
