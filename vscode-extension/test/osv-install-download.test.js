'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { PassThrough } = require('node:stream');
const { EventEmitter } = require('node:events');

const manager = require('../src/scanner-tool-manager');
const {
  download, INSTALL_ERROR, DEFAULT_PROGRESS_INTERVAL_MS, describeTransportError, ScannerToolManager, TOOLS, sha256
} = manager;

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

/**
 * `request()` talks to `https.get` directly, so the transport is driven from
 * there: every case below is a real run of the shipped `download()`, only the
 * socket is scripted. The OSV binary is 59 MB and its failures are all
 * mid-transfer ones, which no local file fixture can reproduce.
 */
function stubHttps(t, handler) {
  const original = https.get;
  https.get = (url, options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = (ms, onTimeout) => { request.timeoutMs = ms; request.onTimeout = onTimeout; return request; };
    request.destroy = () => { request.destroyed = true; };
    const response = new PassThrough();
    response.statusCode = 200;
    response.headers = {};
    setImmediate(() => handler({ url: String(url), request, response, deliver: () => callback(response) }));
    return request;
  };
  t.after(() => { https.get = original; });
}

/** A response that streams `chunks` of `size` bytes with `total` announced. */
function streaming({ chunks = 4, size = 64 * 1024, total = null, statusCode = 200, delayMs = 0 } = {}) {
  return ({ request, response, deliver }) => {
    response.statusCode = statusCode;
    const declared = total === null ? chunks * size : total;
    if (declared >= 0) response.headers['content-length'] = String(declared);
    deliver();
    let written = 0;
    const push = () => {
      if (written >= chunks) return response.end();
      written += 1;
      response.write(Buffer.alloc(size, 0x41));
      delayMs ? setTimeout(push, delayMs) : setImmediate(push);
    };
    push();
    return { request, response };
  };
}

const tempFile = async (t, name = 'osv-scanner_windows_amd64.exe') => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-osv-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }).catch(() => {}));
  return path.join(dir, name);
};

const URL_OSV = 'https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_windows_amd64.exe';

// ------------------------------------------------------------------- succès

test('OSV : un téléchargement complet écrit exactement les octets annoncés', async (t) => {
  stubHttps(t, streaming({ chunks: 8, size: 1024 }));
  const destination = await tempFile(t);
  const events = [];
  await download(URL_OSV, destination, (event) => events.push(event), { progressIntervalMs: 0 });
  assert.equal(fs.statSync(destination).size, 8 * 1024);
  assert.equal(events.at(-1).received, 8 * 1024);
  assert.equal(events.at(-1).total, 8 * 1024);
  assert.equal(events.at(-1).phase, 'downloading');
});

// ------------------------------- cause racine : la tempête d'événements

test('OSV : la progression est plafonnée, quel que soit le nombre de morceaux', async (t) => {
  // La cause racine du blocage « Téléchargement 1 % » puis « aborted » : les
  // ~900 morceaux d'un binaire de 59 Mo produisaient autant de rafraîchissements
  // d'interface, chacun sondant tous les scanners, jusqu'à ce que la boucle
  // d'évènements soit si en retard que la socket était réinitialisée.
  stubHttps(t, streaming({ chunks: 400, size: 256 }));
  const destination = await tempFile(t);
  const events = [];
  await download(URL_OSV, destination, (event) => events.push(event), { progressIntervalMs: 60000 });
  assert.ok(events.length <= 2, `au plus un évènement initial et un final, reçu ${events.length}`);
  assert.equal(events.at(-1).received, 400 * 256, 'le dernier évènement porte toujours le total réel');
  assert.equal(fs.statSync(destination).size, 400 * 256);
  assert.ok(DEFAULT_PROGRESS_INTERVAL_MS >= 100, 'intervalle par défaut réellement protecteur');
});

test('OSV : l’intervalle par défaut est appliqué sans être demandé', async (t) => {
  stubHttps(t, streaming({ chunks: 200, size: 512 }));
  const destination = await tempFile(t);
  const events = [];
  await download(URL_OSV, destination, (event) => events.push(event));
  assert.ok(events.length < 200, `la valeur par défaut doit filtrer, reçu ${events.length} évènements`);
});

// -------------------------------------------------------------- interruption

test('OSV : une connexion coupée en cours de route n’affiche plus « aborted »', async (t) => {
  stubHttps(t, ({ request, response, deliver }) => {
    response.headers['content-length'] = String(59 * 1024 * 1024);
    deliver();
    response.write(Buffer.alloc(4096, 1));
    // Ce que Node remonte réellement quand la socket est réinitialisée.
    setImmediate(() => response.destroy(Object.assign(new Error('aborted'), { code: 'ECONNRESET' })));
    return request;
  });
  const destination = await tempFile(t);
  const error = await download(URL_OSV, destination, () => {}).then(() => null, (failure) => failure);
  assert.ok(error, 'le téléchargement doit échouer');
  assert.notEqual(error.message.trim(), 'aborted', 'le message brut ne doit jamais remonter tel quel');
  assert.match(error.message, /Connexion interrompue/);
  assert.match(error.message, /github\.com/);
  assert.equal(error.code, INSTALL_ERROR.INTERRUPTED);
  assert.equal(fs.existsSync(destination), false, 'le fichier partiel est supprimé');
});

test('OSV : un corps tronqué mais proprement terminé est refusé', async (t) => {
  stubHttps(t, streaming({ chunks: 2, size: 1024, total: 59 * 1024 * 1024 }));
  const destination = await tempFile(t);
  const error = await download(URL_OSV, destination, () => {}).then(() => null, (failure) => failure);
  assert.equal(error.code, INSTALL_ERROR.INTERRUPTED);
  assert.match(error.message, /Téléchargement incomplet : 2048 octets reçus sur 61865984 annoncés/);
  assert.equal(fs.existsSync(destination), false, 'aucun binaire tronqué ne survit');
});

// --------------------------------------------------------------- délai réseau

test('OSV : un délai réseau est signalé comme tel, pas comme une annulation', async (t) => {
  stubHttps(t, ({ request }) => { setImmediate(() => request.onTimeout()); });
  const destination = await tempFile(t);
  const error = await download(URL_OSV, destination, () => {}, { timeoutMs: 900000 }).then(() => null, (failure) => failure);
  assert.equal(error.code, INSTALL_ERROR.TIMEOUT);
  assert.match(error.message, /Téléchargement interrompu après 900 s/);
  assert.notEqual(error.cancelled, true, 'un délai réseau n’est pas une annulation utilisateur');
  assert.equal(fs.existsSync(destination), false);
});

test('OSV : une source muette est arrêtée par la détection de blocage', async (t) => {
  stubHttps(t, ({ request, response, deliver }) => {
    response.headers['content-length'] = String(59 * 1024 * 1024);
    deliver();
    response.write(Buffer.alloc(1024, 2)); // du progrès, puis plus rien
    return request;
  });
  const destination = await tempFile(t);
  const started = Date.now();
  const error = await download(URL_OSV, destination, () => {}, { stallTimeoutMs: 200 }).then(() => null, (failure) => failure);
  assert.equal(error.code, INSTALL_ERROR.STALLED);
  assert.match(error.message, /aucune progression détectée/);
  assert.ok(Date.now() - started < 10000, 'la détection ne doit pas attendre le plafond global');
  assert.equal(fs.existsSync(destination), false);
});

// ------------------------------------------------------- annulation utilisateur

test('OSV : l’annulation utilisateur est distincte d’un incident réseau', async (t) => {
  stubHttps(t, streaming({ chunks: 500, size: 4096, delayMs: 1 }));
  const destination = await tempFile(t);
  const controller = new AbortController();
  const error = await download(URL_OSV, destination, ({ received }) => {
    if (received >= 8192) controller.abort();
  }, { signal: controller.signal, progressIntervalMs: 0 }).then(() => null, (failure) => failure);
  assert.equal(error.cancelled, true);
  assert.equal(error.code, INSTALL_ERROR.CANCELLED);
  assert.notEqual(error.code, INSTALL_ERROR.TIMEOUT);
  assert.notEqual(error.code, INSTALL_ERROR.INTERRUPTED);
  assert.equal(fs.existsSync(destination), false, 'le fichier partiel est supprimé après annulation');
});

test('OSV : un signal déjà annulé n’ouvre aucune connexion', async (t) => {
  let opened = 0;
  stubHttps(t, () => { opened += 1; });
  const destination = await tempFile(t);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() => download(URL_OSV, destination, () => {}, { signal: controller.signal }), (error) => error.cancelled === true);
  assert.equal(opened, 0);
  assert.equal(fs.existsSync(destination), false);
});

// ------------------------------------------------------------------ HTTP

test('OSV : une réponse HTTP non-200 est refusée avec son code', async (t) => {
  stubHttps(t, ({ response, deliver }) => { response.statusCode = 404; deliver(); response.end(); });
  const destination = await tempFile(t);
  const error = await download(URL_OSV, destination, () => {}).then(() => null, (failure) => failure);
  assert.match(error.message, /Téléchargement refusé \(HTTP 404\)/);
  assert.equal(fs.existsSync(destination), false, 'aucun fichier n’est créé pour une réponse refusée');
});

test('OSV : la redirection GitHub vers le stockage des artefacts est suivie', async (t) => {
  const visited = [];
  stubHttps(t, ({ url, response, deliver }) => {
    visited.push(url);
    if (visited.length === 1) {
      response.statusCode = 302;
      response.headers.location = 'https://objects.githubusercontent.com/osv-scanner_windows_amd64.exe';
      deliver(); response.end();
      return;
    }
    response.headers['content-length'] = '4096';
    deliver();
    response.end(Buffer.alloc(4096, 3));
  });
  const destination = await tempFile(t);
  await download(URL_OSV, destination, () => {});
  assert.deepEqual(visited, [URL_OSV, 'https://objects.githubusercontent.com/osv-scanner_windows_amd64.exe']);
  assert.equal(fs.statSync(destination).size, 4096);
});

// ------------------------------------------------------- classification réseau

test('OSV : chaque panne réseau reçoit une cause explicite', () => {
  const cases = [
    [{ code: 'ENOTFOUND' }, /introuvable.*DNS/s, INSTALL_ERROR.UNREACHABLE],
    [{ code: 'ECONNREFUSED' }, /inaccessible.*pare-feu ou un proxy/s, INSTALL_ERROR.UNREACHABLE],
    [{ code: 'ETIMEDOUT' }, /inaccessible/, INSTALL_ERROR.UNREACHABLE],
    [{ code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }, /Certificat TLS refusé/, INSTALL_ERROR.TLS],
    [{ code: 'ECONNRESET' }, /Connexion interrompue/, INSTALL_ERROR.INTERRUPTED]
  ];
  for (const [shape, pattern, code] of cases) {
    const described = describeTransportError(Object.assign(new Error('aborted'), shape), URL_OSV);
    assert.match(described.message, pattern, `cause non explicitée pour ${shape.code}`);
    assert.equal(described.code, code);
    assert.match(described.message, /github\.com/, 'le serveur concerné est nommé');
  }
  // Une annulation reste une annulation : elle n'est jamais requalifiée.
  const cancelled = Object.assign(new Error('Installation annulée.'), { cancelled: true, code: INSTALL_ERROR.CANCELLED });
  assert.equal(describeTransportError(cancelled, URL_OSV), cancelled);
});

// ------------------------------------------------------------ archive invalide

test('OSV : une archive illisible est refusée avec une cause lisible', { skip: process.platform !== 'win32' ? 'PowerShell requis' : false }, async (t) => {
  const store = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-osv-store-'));
  t.after(() => fsp.rm(store, { recursive: true, force: true }).catch(() => {}));
  const toolManager = new ScannerToolManager(store);
  const payload = Buffer.from('ceci n’est pas une archive zip');
  stubHttps(t, ({ response, deliver }) => {
    response.headers['content-length'] = String(payload.length);
    deliver();
    response.end(payload);
  });
  const digest = require('node:crypto').createHash('sha256').update(payload).digest('hex');
  toolManager.githubRelease = async () => ({
    version: 'v2.5.1',
    asset: { name: 'gitleaks_windows_x64.zip', browser_download_url: URL_OSV, digest: `sha256:${digest}` },
    checksum: null
  });
  const error = await toolManager.install('gitleaks', () => {}).then(() => null, (failure) => failure);
  assert.ok(error, 'une archive illisible doit échouer');
  assert.equal(error.code, INSTALL_ERROR.ARCHIVE);
  assert.match(error.message, /Archive invalide/);
  assert.doesNotMatch(error.message, /Expand-Archive|powershell/i, 'aucun détail PowerShell brut');
});

// --------------------------------------------------------------- cible OSV

test('OSV : l’artefact officiel Windows x64 et son empreinte restent la cible', () => {
  assert.match(TOOLS.osv.asset.source, /osv-scanner_windows_amd64\\\.exe\$/);
  assert.equal(TOOLS.osv.repo, 'google/osv-scanner');
  assert.equal(TOOLS.osv.command, 'osv-scanner');
  const source = src('scanner-tool-manager.js');
  // Le binaire OSV n'est pas une archive : il est copié tel quel après SHA-256.
  assert.match(source, /if \(actual !== expected\) throw new Error\('Échec de vérification SHA-256/);
  assert.match(source, /else await fs\.copyFile\(archive, this\.managedExecutable\(id\)\)/);
  assert.equal(typeof sha256, 'function');
});

// ------------------------------------------------------------------- interface

test('OSV : un rafraîchissement d’interface par morceau ne peut plus se produire', () => {
  const extension = src('extension.js');
  // Le rendu complet sonde tous les outils : il doit être fusionné, jamais
  // empilé une fois par évènement de progression.
  assert.match(extension, /function queueScannerSetupRender\(\)/);
  assert.match(extension, /if \(scannerSetupRenderInFlight\) \{ scannerSetupRenderQueued = true;/);
  const installFn = extension.match(/async function installManagedScanners\(ids\)[\s\S]*?\n  \}/)[0];
  assert.match(installFn, /queueScannerSetupRender\(\);/);
  assert.ok(!installFn.includes('renderScannerSetup().catch(() => {})'), 'plus aucun rendu non fusionné dans la boucle de progression');
});
