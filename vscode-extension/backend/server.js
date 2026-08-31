'use strict';

/**
 * The entry point of the Security Center local backend.
 *
 * Started by the extension, not by the user. It takes its data directory from
 * the caller — never from its own location — because the extension directory is
 * replaced on every update and a scan history that lived there would be deleted
 * by an upgrade.
 *
 * Usage (the extension passes all of it; the flags exist for development):
 *   node backend/server.js --port 8765 --data-dir <path> [--idle-timeout 1800]
 *
 * The API key is read from the environment only. Passing it as an argument
 * would publish it in the process list of the machine.
 */

const { DEFAULT_PORT, LOOPBACK_HOST, PROTOCOL_VERSION } = require('./contract');
const { FileStore } = require('./store');
const { createBackendServer } = require('./service');
const { writeLockFile, removeLockFile } = require('./discovery');

/** Minutes of silence after which an unused backend stops instead of lingering forever. */
const DEFAULT_IDLE_TIMEOUT_SECONDS = 1800;

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) continue;
    const [flag, inlineValue] = argument.slice(2).split('=');
    const value = inlineValue === undefined ? argv[index + 1] : inlineValue;
    if (inlineValue === undefined) index += 1;
    options[flag] = value;
  }
  return options;
}

function resolveOptions(argv = process.argv.slice(2), environment = process.env) {
  const options = parseArguments(argv);
  const port = Number(options.port || environment.SECURITY_CENTER_PORT || DEFAULT_PORT);
  const idleSeconds = Number(
    options['idle-timeout'] || environment.SECURITY_CENTER_IDLE_TIMEOUT || DEFAULT_IDLE_TIMEOUT_SECONDS
  );
  return {
    port: Number.isFinite(port) ? port : DEFAULT_PORT,
    dataDir: options['data-dir'] || environment.SECURITY_CENTER_DATA_DIR || '',
    apiKey: environment.SECURITY_CENTER_API_KEY || '',
    idleTimeoutSeconds: Number.isFinite(idleSeconds) ? Math.max(0, idleSeconds) : DEFAULT_IDLE_TIMEOUT_SECONDS,
    version: environment.SECURITY_CENTER_VERSION || PROTOCOL_VERSION
  };
}

async function start(options) {
  if (!options.dataDir) throw new Error('--data-dir is required: the backend never writes into its own directory');
  const store = new FileStore(options.dataDir).initialize();
  const startedAt = new Date().toISOString();

  let idleTimer = null;
  const scheduleIdleShutdown = () => {
    if (!options.idleTimeoutSeconds) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => shutdown(0), options.idleTimeoutSeconds * 1000);
    // An idle timer must not be the reason the process stays up.
    if (typeof idleTimer.unref === 'function') idleTimer.unref();
  };

  const bound = { port: options.port };
  const server = createBackendServer({
    store,
    apiKey: options.apiKey,
    version: options.version,
    port: () => bound.port,
    startedAt,
    onActivity: scheduleIdleShutdown
  });

  const shutdown = (code) => {
    removeLockFile(options.dataDir);
    server.close(() => process.exit(code));
    // A client holding a keep-alive socket must not be able to prevent an exit.
    setTimeout(() => process.exit(code), 2000).unref();
  };

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    // Loopback only. Binding 0.0.0.0 would expose the scan history and the
    // captured HTTP traffic of this machine to every host on the network.
    server.listen(options.port, LOOPBACK_HOST, resolve);
  });

  const port = server.address().port;
  bound.port = port;
  const url = `http://${LOOPBACK_HOST}:${port}`;
  writeLockFile(options.dataDir, {
    pid: process.pid, port, url, version: options.version, started_at: startedAt, data_dir: store.dataDir
  });
  scheduleIdleShutdown();

  return { server, url, port, store, shutdown };
}

/**
 * The process form: signals, and the one line it prints.
 *
 * Separated from `start` so the service can be started in-process by a test
 * without registering a signal handler per instance, and without printing.
 */
async function main() {
  // The extension may exit long before this process does: it is detached on
  // purpose, so another window keeps its history. When the parent goes, the
  // inherited pipes close, and an unguarded write to them would kill a backend
  // that is still serving other windows.
  for (const stream of [process.stdout, process.stderr]) stream.on('error', () => {});
  const running = await start(resolveOptions());
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => running.shutdown(0));
  // The only line this process prints. It names the address it bound, and no secret.
  process.stdout.write(`${JSON.stringify({
    service: 'security-center-backend', url: running.url, port: running.port, pid: process.pid
  })}\n`);
  return running;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`security-center-backend: ${error.message}\n`);
    process.exit(1);
  });
}

module.exports = { start, main, resolveOptions, parseArguments, DEFAULT_IDLE_TIMEOUT_SECONDS };
