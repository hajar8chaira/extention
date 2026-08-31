'use strict';

/**
 * How components that are not the extension find the backend.
 *
 * Two files, with two different jobs and two different owners.
 *
 * THE LOCK, written by the backend process into its own data directory. It
 * says which process is serving, on which port. It is what makes a second
 * VS Code window reuse the running backend instead of starting a second one on
 * a port that is already taken. It is removed on a clean exit, and treated as
 * stale when the process it names is gone.
 *
 * THE DISCOVERY FILE, written by the extension into the user's home. It says
 * which backend is *active* — which, in Remote mode, is not a local process at
 * all. It exists because Burp is a separate application: it cannot read VS Code
 * settings, and hard-coding an address in it is exactly the coupling being
 * removed. It carries the API key, so it is written for the current user only.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { SERVICE_NAME } = require('./contract');

const LOCK_FILE_NAME = 'backend.lock.json';
const DISCOVERY_DIRECTORY = '.security-center';
const DISCOVERY_FILE_NAME = 'backend.json';

function lockFilePath(dataDir) {
  return path.join(dataDir, LOCK_FILE_NAME);
}

function discoveryFilePath(home = os.homedir()) {
  return path.join(home, DISCOVERY_DIRECTORY, DISCOVERY_FILE_NAME);
}

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

/** A process that no longer exists cannot be serving. Signal 0 asks without touching it. */
function processAlive(pid) {
  const identifier = Number(pid);
  if (!Number.isInteger(identifier) || identifier <= 0) return false;
  try { process.kill(identifier, 0); return true; }
  catch (error) { return error && error.code === 'EPERM'; }
}

function writeLockFile(dataDir, record) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(lockFilePath(dataDir), JSON.stringify({ service: SERVICE_NAME, ...record }, null, 2), 'utf8');
}

/**
 * The lock, or null when there is nothing usable in it.
 *
 * A lock naming a dead process is not an error state and does not need the
 * user's attention — it is what a crash or a machine restart leaves behind.
 * It is reported as absent so the caller simply starts a backend.
 */
function readLockFile(dataDir, { isAlive = processAlive } = {}) {
  const record = readJsonFile(lockFilePath(dataDir));
  if (!record || record.service !== SERVICE_NAME) return null;
  if (!record.url || !record.port) return null;
  if (!isAlive(record.pid)) return null;
  return record;
}

function removeLockFile(dataDir) {
  try { fs.unlinkSync(lockFilePath(dataDir)); } catch { /* already gone is the desired state */ }
}

/**
 * Publishes the active backend for out-of-process components.
 *
 * The file holds an API key, so it is created with owner-only permissions and
 * the directory with them too. On Windows the mode is advisory — the file is in
 * the user profile, which is the protection that actually applies there.
 */
function writeDiscoveryFile(record, { home = os.homedir() } = {}) {
  const file = discoveryFilePath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const payload = {
    service: SERVICE_NAME,
    url: record.url,
    mode: record.mode || 'auto',
    version: record.version || '',
    api_key: record.apiKey || '',
    updated_at: new Date().toISOString()
  };
  fs.writeFileSync(file, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch { /* best effort on filesystems without modes */ }
  return file;
}

function readDiscoveryFile({ home = os.homedir() } = {}) {
  const record = readJsonFile(discoveryFilePath(home));
  if (!record || record.service !== SERVICE_NAME || !record.url) return null;
  return record;
}

/**
 * Le registre des fenetres qui utilisent ce backend.
 *
 * Le service est partage : une seconde fenetre VS Code reutilise celui qui
 * tourne deja. Sans registre, deux comportements sont possibles au moment ou une
 * fenetre se ferme, et les deux sont mauvais — tuer le service et retirer son
 * historique a la fenetre restee ouverte, ou ne jamais rien arreter et laisser
 * un processus derriere soi. Le registre permet le seul comportement correct :
 * la derniere fenetre qui s'en va emporte le service, les autres non.
 *
 * Un pid mort est ignore puis efface : une fenetre qui a plante ne doit pas
 * empecher l'arret pour toujours.
 */
const CLIENTS_FILE_NAME = 'backend-clients.json';

function clientsFilePath(dataDir) {
  return path.join(dataDir, CLIENTS_FILE_NAME);
}

function readClients(dataDir, isAlive = processAlive) {
  const record = readJsonFile(clientsFilePath(dataDir));
  const pids = Array.isArray(record?.pids) ? record.pids : [];
  return pids.map(Number).filter((pid) => Number.isInteger(pid) && pid > 0 && isAlive(pid));
}

function writeClients(dataDir, pids) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(clientsFilePath(dataDir), JSON.stringify({ pids: [...new Set(pids)] }, null, 2), 'utf8');
  } catch { /* un registre non ecrit degrade l'arret, il ne casse rien */ }
}

function registerClient(dataDir, pid = process.pid, { isAlive = processAlive } = {}) {
  const live = readClients(dataDir, isAlive);
  writeClients(dataDir, [...live, pid]);
  return live.includes(pid) ? live : [...live, pid];
}

/** Retire cette fenetre et rend celles qui restent. Un tableau vide autorise l'arret. */
function unregisterClient(dataDir, pid = process.pid, { isAlive = processAlive } = {}) {
  const remaining = readClients(dataDir, isAlive).filter((entry) => entry !== pid);
  writeClients(dataDir, remaining);
  return remaining;
}

module.exports = {
  CLIENTS_FILE_NAME, clientsFilePath, readClients, registerClient, unregisterClient,
  LOCK_FILE_NAME, DISCOVERY_DIRECTORY, DISCOVERY_FILE_NAME,
  lockFilePath, discoveryFilePath, processAlive,
  writeLockFile, readLockFile, removeLockFile,
  writeDiscoveryFile, readDiscoveryFile
};
