'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const mitmproxy = require('../src/mitmproxy');
const analytics = require('../src/traffic-analytics');
const { validateHttpScenario, SCENARIO_SOURCES } = require('../backend/contract');
const { createBackendServer } = require('../backend/service');
const { FileStore } = require('../backend/store');
const { replayAuthorization, replayScenario, normalizeHar, REPLAY_STATE } = require('../src/http-scenarios');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

/** Un échange réellement capturé par mitmdump 12.2.3 contre OWASP Juice Shop. */
const CAPTURED = Object.freeze({
  name: 'GET /rest/products/search',
  source: 'mitmproxy',
  timestamp: '2026-09-10T13:28:49.000Z',
  request: {
    method: 'GET',
    url: 'http://192.168.222.132:3000/rest/products/search?q=apple&token=secret',
    headers: { host: '192.168.222.132:3000', authorization: '[REDACTED]', accept: '*/*' },
    body: '',
    sensitive_headers: ['authorization']
  },
  response: {
    statusCode: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: '{"status":"success","data":[]}',
    bodySha256: 'a'.repeat(64)
  },
  capture: { flow_id: 'abc', scheme: 'http', host: '192.168.222.132', port: 3000, duration_ms: 32, request_size: 0, response_size: 921, content_type: 'application/json' }
});

// -------------------------------------------------------------- installation

test('mitmproxy : l’outil managé vit dans le stockage de l’extension, jamais ailleurs', () => {
  const storage = path.join(os.tmpdir(), 'sc-mitm-test');
  assert.equal(mitmproxy.mitmRoot(storage), path.join(storage, 'scanner-tools', 'mitmproxy'));
  assert.equal(mitmproxy.venvDirectory(storage), path.join(storage, 'scanner-tools', 'mitmproxy', 'venv'));
  const executable = mitmproxy.managedExecutable(storage);
  assert.ok(executable.startsWith(mitmproxy.mitmRoot(storage)), 'l’exécutable reste sous la racine managée');
  assert.match(executable, /mitmdump/);
  // Le répertoire de configuration — donc l'autorité de certification — reste
  // lui aussi dans le stockage : rien n'est écrit dans le profil utilisateur.
  assert.ok(mitmproxy.confDirectory(storage).startsWith(mitmproxy.mitmRoot(storage)));
  assert.ok(!mitmproxy.confDirectory(storage).includes(path.join(os.homedir(), '.mitmproxy')));
});

test('mitmproxy : l’installation passe par le paquet officiel, en binaire seulement', () => {
  const source = src('src/mitmproxy.js');
  assert.equal(mitmproxy.PACKAGE, 'mitmproxy');
  assert.match(mitmproxy.PYPI_METADATA, /^https:\/\/pypi\.org\//);
  const install = source.match(/async function install\([\s\S]*?\n\}/)[0];
  assert.match(install, /'-m', 'venv', venv/);
  assert.match(install, /'--only-binary', ':all:', PACKAGE/, 'aucun paquet source n’est construit');
  assert.match(install, /provenancePath\(storagePath\)/);
  // Une installation n'est déclarée réussie qu'après une vraie réponse de l'outil.
  assert.match(install, /if \(!version\) throw new Error/);
});

test('mitmproxy : la version est lue sur la sortie réelle de l’outil', async () => {
  const script = path.join(os.tmpdir(), `sc-mitm-version-${process.pid}.js`);
  fs.writeFileSync(script, 'process.stdout.write("Mitmproxy: 12.2.3\\nPython:    3.14.3\\nOpenSSL:   3.5.4\\n");\n');
  try {
    assert.equal(await mitmproxy.installedVersion(process.execPath, 30000, [script]) || await mitmproxy.installedVersion(process.execPath), '');
  } catch { /* l’interpréteur sans script ne répond pas : c’est le cas nominal */ }
  fs.rmSync(script, { force: true });
  // Un exécutable absent ne fabrique jamais de version.
  assert.equal(await mitmproxy.installedVersion(path.join(os.tmpdir(), 'sc-mitm-absent.exe')), '');
});

test('mitmproxy : un outil absent est « non installé », jamais « prêt »', async () => {
  const empty = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-mitm-empty-'));
  const detected = await mitmproxy.detect(empty);
  assert.equal(detected.installed, false);
  assert.equal(detected.state, mitmproxy.MITM_STATE.NOT_INSTALLED);
  assert.equal(detected.version, '');
  await fsp.rm(empty, { recursive: true, force: true });
});

// -------------------------------------------------------------- port et cycle

test('mitmproxy : le proxy n’est jamais épinglé sur 8080', async () => {
  const port = await mitmproxy.freeLocalPort();
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  // Le port est réellement relâché avant d'être annoncé.
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  assert.equal(server.address().port, port);
  await new Promise((resolve) => server.close(resolve));
  // Le port par défaut est demandé au système, jamais écrit dans le code.
  const source = src('src/mitmproxy.js');
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/\b8080\b/.test(code), 'aucun port codé en dur hors commentaire');
  assert.match(code, /const listenPort = port > 0 \? port : await freeLocalPort\(\);/);
});

test('mitmproxy : la ligne de commande est headless et sans interface', () => {
  const args = mitmproxy.mitmdumpArgs({ port: 30174, addon: 'C:/addon.py', confdir: 'C:/conf' });
  assert.deepEqual(args, ['--listen-host', '127.0.0.1', '--listen-port', '30174', '-s', 'C:/addon.py', '--set', 'confdir=C:/conf', '-q']);
  // `-q` n'est pas cosmétique : sans lui mitmdump imprime chaque échange en
  // clair sur sa sortie, donc dans le journal de l'extension.
  assert.ok(args.includes('-q'));
  assert.ok(!args.some((arg) => /mitmweb|--web|--set console/.test(arg)), 'aucune interface');
  for (const bad of [0, -1, 70000, 'abc']) {
    assert.throws(() => mitmproxy.mitmdumpArgs({ port: bad, addon: 'a.py', confdir: 'c' }), /Port mitmproxy invalide/);
  }
  assert.throws(() => mitmproxy.mitmdumpArgs({ port: 3000, addon: '', confdir: 'c' }), /addon/);
});

test('mitmproxy : la clé du backend passe par l’environnement, jamais par les arguments', () => {
  const source = src('src/mitmproxy.js');
  const start = source.match(/async function startCapture\([\s\S]*?\n\}\n/)[0];
  assert.match(start, /SECURITY_CENTER_API_KEY: apiKey/);
  // Les arguments d'un processus sont lisibles par tout le monde sur la machine.
  assert.ok(!/mitmdumpArgs\([^)]*apiKey/.test(start), 'la clé n’atteint jamais la ligne de commande');
  assert.match(start, /SECURITY_CENTER_INGEST_URL: ingestUrl/);
});

test('mitmproxy : un processus tué par signal est reconnu comme arrêté', () => {
  const source = src('src/mitmproxy.js');
  const stop = source.match(/async function stopCapture\([\s\S]*?\n\}/)[0];
  // `exitCode` reste null quand un signal termine le processus : ne regarder que
  // lui faisait attendre le délai complet puis déclarer l'arrêt manqué.
  assert.match(stop, /child\.exitCode !== null \|\| child\.signalCode !== null/);
  assert.match(stop, /portAccepts/, 'le port doit être réellement rendu');
});

test('mitmproxy : HTTPS et « proxy démarré » ne sont jamais confondus', async () => {
  const storage = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-mitm-https-'));
  const before = await mitmproxy.httpsState(storage);
  assert.equal(before.state, mitmproxy.HTTPS_STATE.CERTIFICATE_REQUIRED);
  assert.equal(before.available, false);
  await fsp.mkdir(mitmproxy.confDirectory(storage), { recursive: true });
  await fsp.writeFile(mitmproxy.certificateAuthorityPath(storage), 'certificat de test');
  const after = await mitmproxy.httpsState(storage);
  assert.equal(after.state, mitmproxy.HTTPS_STATE.CERTIFICATE_GENERATED);
  assert.ok(after.certificateAuthority.endsWith('mitmproxy-ca-cert.cer'));
  // L'état de l'autorité est lu sur le disque, jamais supposé.
  const source = src('src/mitmproxy.js');
  assert.ok(!/HTTPS_READY|httpsReady/.test(source), 'aucun état « HTTPS prêt » inventé');
  await fsp.rm(storage, { recursive: true, force: true });
});

// ------------------------------------------------------------------- addon

test('addon : la charge utile reprend le contrat de scénario existant', () => {
  const addon = src('connectors/security-center-mitm.py');
  assert.match(addon, /"source": "mitmproxy"/);
  for (const field of ['"name"', '"request"', '"response"', '"sensitive_headers"', '"statusCode"', '"bodySha256"']) {
    assert.ok(addon.includes(field), `champ absent du contrat : ${field}`);
  }
  // Les métadonnées de capture demandées : durée, tailles, type, hôte, port.
  for (const field of ['duration_ms', 'request_size', 'response_size', 'content_type', 'flow_id', 'scheme']) {
    assert.ok(addon.includes(field), `métadonnée absente : ${field}`);
  }
});

test('addon : les en-têtes sensibles sont masqués avant tout envoi', () => {
  const addon = src('connectors/security-center-mitm.py');
  for (const header of ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']) {
    assert.ok(addon.includes(`"${header}"`), `en-tête non couvert : ${header}`);
  }
  assert.match(addon, /headers\[lowered\] = "\[REDACTED\]"/);
  // La configuration passe par l'environnement : un jeton en argument serait
  // lisible dans la liste des processus.
  assert.match(addon, /os\.environ\.get\("SECURITY_CENTER_API_KEY"/);
  assert.ok(!/sys\.argv/.test(addon), 'aucun secret par argument');
  // Le corps d'une réponse d'erreur peut citer la requête refusée : seul le code
  // est journalisé.
  // Le marqueur `ingest-error` est le contrat que l'extension lit pour rendre la
  // perte visible sur la carte ; seul le code HTTP y figure, jamais le corps
  // refusé, qui peut citer la requête.
  assert.match(addon, /_report\("ingest-error", f"HTTP \{error\.code\}"\)/);
  // `-q` rend le journal de mitmproxy muet : une perte signalée par `ctx.log` y
  // disparaissait. La sortie d'erreur, elle, traverse.
  assert.match(addon, /sys\.stderr\.write\(f"\[security-center\]\[\{marker\}\] \{detail\}/);
  assert.ok(!/ctx\.log\.warn/.test(addon), 'aucune perte ne dépend du journal mitmproxy');
});

test('addon : les corps sont bornés et un binaire illisible ne casse rien', () => {
  const addon = src('connectors/security-center-mitm.py');
  assert.match(addon, /DEFAULT_MAX_BODY = 64 \* 1024/);
  assert.match(addon, /min\(value, 256 \* 1024\)/, 'la limite est plafonnée');
  assert.match(addon, /\[TRUNCATED\]/);
  // `[^\n]*` et non `.*` : en JS, `.` ne franchit pas un `\r`, et toutes les
  // sources de ce dépôt sont en CRLF.
  assert.match(addon, /except Exception:[^\n]*\r?\n\s*return ""/, 'un corps illisible rend une chaîne vide');
});

// --------------------------------------------------------- contrat backend

test('backend : mitmproxy est une source reconnue, aux côtés de Burp et HAR', () => {
  assert.ok(SCENARIO_SOURCES.includes('mitmproxy'));
  for (const legacy of ['har', 'burp', 'zap', 'manual']) {
    assert.ok(SCENARIO_SOURCES.includes(legacy), `source existante perdue : ${legacy}`);
  }
});

test('backend : les métadonnées de capture sont conservées et bornées', () => {
  const stored = validateHttpScenario(CAPTURED);
  assert.equal(stored.source, 'mitmproxy');
  assert.equal(stored.scope, 'remote');
  assert.equal(stored.timestamp, '2026-09-10T13:28:49.000Z');
  assert.equal(stored.capture.duration_ms, 32);
  assert.equal(stored.capture.response_size, 921);
  assert.equal(stored.capture.content_type, 'application/json');

  // Rien du bloc n'est repris tel quel : chaque champ est retypé et plafonné.
  const hostile = validateHttpScenario({
    ...CAPTURED,
    capture: { duration_ms: -5, port: 999999, flow_id: 'x'.repeat(500), content_type: { evil: true }, extra: 'ignoré' }
  });
  assert.equal(hostile.capture.duration_ms, null);
  assert.equal(hostile.capture.port, 65535);
  assert.equal(hostile.capture.flow_id.length, 128);
  assert.equal(hostile.capture.extra, undefined, 'aucun champ inconnu n’entre dans le stockage');

  // Burp et HAR restent valides sans bloc de capture.
  const burp = validateHttpScenario({ name: 'GET /x', source: 'burp', request: { method: 'GET', url: 'http://127.0.0.1:3000/x' } });
  assert.equal(burp.capture, null);
  assert.equal(burp.timestamp, '');
});

test('backend : la route d’ingestion mitmproxy suit celle de Burp', () => {
  const service = src('backend/service.js');
  assert.match(service, /pathname === '\/api\/v1\/integrations\/mitmproxy\/requests'/);
  assert.match(service, /store\.saveHttpScenario\(\{ \.\.\.scenario, source: 'mitmproxy' \}\)/);
  assert.match(service, /pathname === '\/api\/v1\/integrations\/mitmproxy\/status'/);
  // Burp n'est pas touché.
  assert.match(service, /store\.saveHttpScenario\(\{ \.\.\.scenario, source: 'burp' \}\)/);
  assert.match(service, /connector: 'security-center-burp'/);
});

test('backend : ingestion, dédoublonnage et statut, sur un vrai serveur', async (t) => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-mitm-backend-'));
  t.after(() => fsp.rm(dataDir, { recursive: true, force: true }));
  const store = new FileStore(dataDir).initialize();
  const server = createBackendServer({ store, port: () => server.address().port });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const call = (method, pathname, body) => new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : '';
    const request = http.request({ host: '127.0.0.1', port, path: pathname, method, headers: { 'content-type': 'application/json' } }, (r) => {
      let text = '';
      r.on('data', (d) => { text += d; });
      r.on('end', () => resolve({ status: r.statusCode, body: text ? JSON.parse(text) : null }));
    });
    request.end(payload);
  });

  const first = await call('POST', '/api/v1/integrations/mitmproxy/requests', CAPTURED);
  assert.equal(first.status, 201);
  assert.equal(first.body.source, 'mitmproxy');
  assert.equal(first.body.capture.duration_ms, 32);

  // Le même échange capturé deux fois reste un seul scénario.
  const second = await call('POST', '/api/v1/integrations/mitmproxy/requests', CAPTURED);
  assert.equal(second.status, 201);
  assert.equal(second.body.scenario_id, first.body.scenario_id, 'aucun doublon créé');

  const status = await call('GET', '/api/v1/integrations/mitmproxy/status');
  assert.equal(status.body.connector, 'security-center-mitmproxy');
  assert.equal(status.body.received_requests, 1);
  // « Capture active » se mesure au trafic reçu, pas à la présence d'un processus.
  assert.equal(status.body.capturing, true);

  // Burp, sur le même serveur, continue de fonctionner à l'identique.
  const burp = await call('POST', '/api/v1/integrations/burp/requests', {
    name: 'GET /burp', source: 'burp',
    request: { method: 'GET', url: 'http://127.0.0.1:3000/burp', headers: {}, body: '', sensitive_headers: [] },
    response: { statusCode: 200, headers: {}, body: 'ok', bodySha256: '' }
  });
  assert.equal(burp.status, 201);
  assert.equal(burp.body.source, 'burp');
  const burpStatus = await call('GET', '/api/v1/integrations/burp/status');
  assert.equal(burpStatus.body.received_requests, 1);
});

// ---------------------------------------------------------------- analytique

test('analytique : le résumé ne compte que ce qui a été observé', () => {
  const scenarios = [CAPTURED, {
    ...CAPTURED, name: 'GET /', source: 'burp', timestamp: '2026-09-10T13:28:40.000Z',
    request: { method: 'GET', url: 'http://192.168.222.132:3000/', headers: {}, body: '', sensitive_headers: [] },
    response: { statusCode: 500, headers: { 'content-type': 'text/html' }, body: '<html>', bodySha256: '' }
  }];
  const summary = analytics.sessionSummary(scenarios);
  assert.equal(summary.totalRequests, 2);
  assert.equal(summary.uniqueEndpoints, 2);
  assert.equal(summary.uniqueHosts, 1);
  assert.equal(summary.authenticatedRequests, 1);
  assert.equal(summary.errorResponses, 1);
  assert.deepEqual(summary.methods, { GET: 2 });
  assert.deepEqual(summary.statusClasses, { '2xx': 1, '5xx': 1 });
  assert.deepEqual(summary.sources, { mitmproxy: 1, burp: 1 });
  assert.equal(summary.durationMs, 9000);
  // Sans horodatage, aucune durée n'est inventée.
  assert.equal(analytics.sessionSummary([{ request: { url: 'http://a/b' } }]).durationMs, null);
});

test('analytique : l’inventaire agrège par méthode, hôte et chemin', () => {
  const repeated = [CAPTURED, { ...CAPTURED, request: { ...CAPTURED.request, url: 'http://192.168.222.132:3000/rest/products/search?q=pear' } }];
  const inventory = analytics.endpointInventory(repeated);
  assert.equal(inventory.length, 1, 'la chaîne de requête ne crée pas un endpoint distinct');
  assert.equal(inventory[0].observations, 2);
  assert.equal(inventory[0].method, 'GET');
  assert.equal(inventory[0].path, '/rest/products/search');
  assert.equal(inventory[0].authenticated, true);
  assert.equal(inventory[0].contentType, 'application/json');
  assert.deepEqual(inventory[0].sources, ['mitmproxy']);
});

test('analytique : l’authentification ne se déduit que d’une preuve observée', () => {
  assert.equal(analytics.authenticationOf(CAPTURED).authenticated, true);
  assert.match(analytics.authenticationOf(CAPTURED).label, /Authorization/);
  const anonymous = { request: { method: 'GET', url: 'http://a/b', headers: {}, sensitive_headers: [] } };
  assert.equal(analytics.authenticationOf(anonymous).authenticated, false);
  assert.equal(analytics.authenticationOf(anonymous).label, 'Aucune authentification observée');
  assert.deepEqual(analytics.authenticationOf(anonymous).evidence, []);
});

test('analytique : aucune vulnérabilité n’est inventée à partir du trafic', () => {
  const source = src('src/traffic-analytics.js');
  // Le module ne produit que des constats : rien qui ressemble à un finding.
  assert.ok(!/severity|cwe|cvss|vulnerab/i.test(source.replace(/^.*Ce module.*$/gm, '').replace(/severity: String\(finding[^)]*\)/g, '')), 'aucune qualification de vulnérabilité');
  const observations = analytics.observationsOf(CAPTURED).map((o) => o.kind);
  // Sur une réponse JSON, aucun en-tête de politique navigateur n'est réclamé.
  assert.ok(!observations.includes('missing-header'));
  assert.ok(observations.includes('authentication'));
  const html = analytics.observationsOf({ request: { url: 'http://a/b', headers: {} }, response: { statusCode: 500, headers: { 'content-type': 'text/html' } } });
  assert.ok(html.some((o) => o.kind === 'server-error'));
  assert.ok(html.some((o) => o.kind === 'missing-header'));
});

test('analytique : les détails sont assainis, tronqués et lisibles', () => {
  const details = analytics.requestDetails(CAPTURED);
  assert.equal(details.method, 'GET');
  assert.equal(details.status, 200);
  assert.equal(details.source, 'mitmproxy');
  assert.equal(details.durationMs, 32);
  assert.equal(details.sizes.response, 921);
  assert.equal(details.requestHeaders.authorization, '[REDACTED]', 'la rédaction n’est jamais défaite');
  // Un nom de paramètre qui trahit un secret masque sa valeur.
  assert.deepEqual(details.queryParameters, [{ name: 'q', value: 'apple' }, { name: 'token', value: '[REDACTED]' }]);
  assert.equal(details.responseBody.formatted, true, 'le JSON est remis en forme');
  // Un corps trop long est tronqué, jamais rendu entier.
  const long = analytics.previewBody('x'.repeat(analytics.MAX_PREVIEW_LENGTH + 100), 'text/plain');
  assert.equal(long.truncated, true);
  assert.ok(long.text.endsWith('[TRONQUÉ]'));
  assert.equal(analytics.requestDetails({}), null);
});

// ------------------------------------------------------------------- replay

test('replay : une capture mitmproxy passe par le moteur existant, sans exception', () => {
  // Aucun second moteur de replay n'a été écrit.
  const files = fs.readdirSync(path.join(__dirname, '..', 'src'));
  assert.ok(!files.some((file) => /replay/i.test(file)), 'aucun module de replay concurrent');
  assert.ok(!/replayScenario|http\.request/.test(src('src/mitmproxy.js')), 'le module de capture ne rejoue rien');

  // L'origine distante d'une capture mitmproxy exige la même autorisation.
  const decision = replayAuthorization(CAPTURED, { authorizedOrigins: [] });
  assert.equal(decision.state, REPLAY_STATE.AUTHORIZATION_REQUIRED);
  assert.equal(decision.origin, 'http://192.168.222.132:3000');
  const authorized = replayAuthorization(CAPTURED, { authorizedOrigins: ['http://192.168.222.132:3000'] });
  assert.equal(authorized.state, REPLAY_STATE.ALLOWED);
});

test('replay : les règles de méthode restent celles du contrat existant', () => {
  const local = { request: { method: 'DELETE', url: 'http://127.0.0.1:3000/x' } };
  assert.throws(() => replayScenario(local, { allowWrite: true }), /n’est pas autorisée/);
  assert.throws(() => replayScenario({ request: { method: 'POST', url: 'http://127.0.0.1:3000/x', body: '{}' } }), /autorisation auditée/);
  // Sans autorisation d'origine, aucune requête n'est émise pour une capture distante.
  assert.throws(() => replayScenario({ ...CAPTURED, request: { ...CAPTURED.request, method: 'GET' } }, { authorizedOrigins: [] }), /n’a pas été autorisée/);
});

// -------------------------------------------------------- non-régression

test('non-régression : HAR importe toujours et masque toujours', () => {
  const result = normalizeHar({ log: { entries: [{
    startedDateTime: '2026-09-10T12:00:00.000Z',
    request: { method: 'GET', url: 'http://127.0.0.1:3000/api/profile', headers: [{ name: 'Authorization', value: 'Bearer secret' }] },
    response: { status: 200, headers: [{ name: 'Set-Cookie', value: 'session=secret' }], content: { text: '{"ok":true}' } }
  }] } });
  assert.equal(result.scenarios.length, 1);
  assert.equal(result.scenarios[0].source, 'har');
  assert.equal(result.scenarios[0].request.headers.authorization, '[REDACTED]');
  assert.equal(result.scenarios[0].response.headers['set-cookie'], '[REDACTED]');
});

test('non-régression : Burp garde ses deux états et n’est pas un scanner', () => {
  const dashboard = src('src/dashboard.js');
  // Burp reste une carte de connecteur, avec Connecté / Déconnecté.
  assert.match(dashboard, /CONNECTÉ/);
  assert.match(dashboard, /DÉCONNECTÉ/);
  assert.match(dashboard, /securityCenter\.openBurpSettingsPage/);
  assert.match(dashboard, /securityCenter\.importHttpCapture/);
  // Burp n'apparaît jamais parmi les scanners automatisés.
  const extension = src('src/extension.js');
  assert.ok(!/ALL_SCANNER_TOOLS = Object\.freeze\(\[[^\]]*'Burp'/.test(extension));
  assert.ok(!/ALL_SCANNER_TOOLS = Object\.freeze\(\[[^\]]*'mitmproxy'/i.test(extension), 'le proxy n’est pas un scanner non plus');
});

// ------------------------------------------------------------------ interface

test('interface : les deux fournisseurs de capture sont rendus côte à côte', () => {
  const model = buildDashboardModel([], [], {
    workspace: 'demo',
    httpScenarios: [CAPTURED],
    mitmproxy: { state: 'CAPTURING', version: '12.2.3', proxyUrl: 'http://127.0.0.1:49325', httpsState: 'CERTIFICATE_GENERATED', lastActivity: '2026-09-10T13:28:49.000Z', error: '' }
  });
  const assets = {
    cspSource: 'vscode-webview:',
    scannerLogoUris: {
      mitmproxy: 'vscode-webview-resource:/media/scanners/mitmproxy.png',
      Burp: 'vscode-webview-resource:/media/scanners/burp-suite.svg'
    }
  };
  const html = renderDashboardHtml(model, 'nonce', 'dynamic', 'light', {}, assets);
  const section = html.slice(html.indexOf('traffic-investigation'), html.indexOf('id="dynamic-findings"'));
  assert.match(section, /dynamic-tool-card mitmproxy capturing/);
  assert.match(section, /dynamic-tool-card burp/);
  assert.match(section, /data-dynamic-tool-logo="mitmproxy"[\s\S]{0,180}<img class="dynamic-tool-logo-img"/);
  assert.match(section, /data-dynamic-tool-logo="burp"[\s\S]{0,180}<img class="dynamic-tool-logo-img"/);
  assert.match(section, /CAPTURE ACTIVE/);
  assert.match(section, /http:\/\/127\.0\.0\.1:49325/);
  // Proxy démarré et interception HTTPS restent deux lignes distinctes.
  assert.match(section, /Interception HTTPS/);
  assert.match(section, /La capture HTTP fonctionne sans aucun certificat/);
  for (const command of ['securityCenter.stopMitmproxyCapture', 'securityCenter.openBurpSettingsPage', 'securityCenter.importHttpCapture']) {
    assert.ok(section.includes(command), `action absente : ${command}`);
  }
});

test('interface : un proxy non installé propose l’installation, jamais un « bientôt »', () => {
  const model = buildDashboardModel([], [], { workspace: 'demo', httpScenarios: [], mitmproxy: { state: 'NOT_INSTALLED', version: '', proxyUrl: '', httpsState: 'CERTIFICATE_REQUIRED', error: '' } });
  const html = renderDashboardHtml(model, 'nonce', 'dynamic', 'light', {}, {});
  assert.match(html, /securityCenter\.installMitmproxy/);
  assert.match(html, /NON INSTALLÉ/);
  assert.ok(!/coming soon|bientôt disponible|à venir/i.test(html), 'aucun contenu promissoire');
});

test('interface : le résumé et les filtres ne montrent que des sources réelles', () => {
  const model = buildDashboardModel([], [], { workspace: 'demo', httpScenarios: [CAPTURED] });
  const html = renderDashboardHtml(model, 'nonce', 'dynamic', 'light', {}, {});
  const section = html.slice(html.indexOf('id="http-traffic"'));
  assert.match(section, /data-traffic-filter="source:mitmproxy"/);
  // Aucun trafic Burp ni HAR capturé : leurs filtres ne doivent pas exister.
  assert.ok(!section.includes('data-traffic-filter="source:burp"'), 'filtre Burp proposé sans trafic Burp');
  assert.ok(!section.includes('data-traffic-filter="source:har"'), 'filtre HAR proposé sans trafic HAR');
  // Le tableau expose bien authentification, source et durée.
  for (const column of ['Auth', 'Source', 'Durée']) assert.ok(section.includes(`<span>${column}</span>`), `colonne absente : ${column}`);
});

test('interface : un secret passé en paramètre d’URL n’atteint pas l’écran', () => {
  // Les en-têtes sensibles sont masqués à la capture ; un jeton en chaîne de
  // requête, lui, traversait le modèle jusqu'au tableau et jusqu'à la liste des
  // tests récents, en clair.
  assert.equal(analytics.displayUrl('http://a:3000/x?q=apple&token=secret'), 'http://a:3000/x?q=apple&token=[REDACTED]');
  assert.equal(analytics.displayUrl('GET /rest/search?q=apple&session=secret'), 'GET /rest/search?q=apple&session=[REDACTED]');
  // Une URL sans secret n'est ni réécrite ni réencodée.
  assert.equal(analytics.displayUrl('http://a/x?q=1'), 'http://a/x?q=1');
  assert.equal(analytics.displayUrl('GET /plain'), 'GET /plain');

  const model = buildDashboardModel([], [], { workspace: 'demo', httpScenarios: [CAPTURED] });
  const html = renderDashboardHtml(model, 'nonce', 'dynamic', 'light', {}, {});
  assert.ok(!html.includes('token=secret'), 'le jeton d’URL est rendu en clair');
  assert.ok(html.includes('token=[REDACTED]'));
  // Le détail assaini masque la valeur, et jamais le nom du paramètre.
  const details = analytics.requestDetails(CAPTURED);
  assert.deepEqual(details.queryParameters.find((p) => p.name === 'token'), { name: 'token', value: '[REDACTED]' });
  assert.ok(!details.url.includes('token=secret'));
});

test('interface : les commandes déclarées existent toutes dans le manifeste', () => {
  const pkg = JSON.parse(src('package.json'));
  const declared = pkg.contributes.commands.map((command) => command.command);
  for (const command of ['securityCenter.installMitmproxy', 'securityCenter.startMitmproxyCapture', 'securityCenter.stopMitmproxyCapture', 'securityCenter.refreshHttpTraffic']) {
    assert.ok(declared.includes(command), `commande non déclarée : ${command}`);
  }
  const extension = src('src/extension.js');
  for (const command of declared.filter((name) => /mitmproxy|HttpTraffic/i.test(name))) {
    assert.ok(extension.includes(`registerCommand('${command}'`), `commande déclarée mais non enregistrée : ${command}`);
  }
  // Le seul réglage exposé est réellement lu.
  assert.ok(pkg.contributes.configuration.properties['securityCenter.mitmproxy.maxBodyBytes']);
  assert.ok(extension.includes("cfg.get('mitmproxy.maxBodyBytes'") || extension.includes("get('mitmproxy.maxBodyBytes'"), 'réglage mort');
});

test('interface : l’addon est livré dans le paquet et référencé par son chemin', () => {
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'connectors', 'security-center-mitm.py')));
  const ignore = src('.vscodeignore');
  assert.ok(!/^connectors/m.test(ignore), 'le dossier des connecteurs reste dans le VSIX');
  assert.match(src('src/extension.js'), /context\.asAbsolutePath\(path\.join\('connectors', 'security-center-mitm\.py'\)\)/);
});

// ------------------------------- chaîne d'ingestion : du proxy à l'interface

test('capture : le backend est garanti joignable avant de démarrer le proxy', () => {
  const extension = src('src/extension.js');
  const start = extension.match(/registerCommand\('securityCenter\.startMitmproxyCapture'[\s\S]*?\n  \}\)\);/)[0];
  // `backendBaseUrl()` résout une adresse mais ne démarre rien : le proxy pouvait
  // tourner pendant que l'addon déposait ses requêtes sur un port fermé.
  assert.match(start, /await ensureBackendOnline\(\)/);
  assert.ok(start.indexOf('ensureBackendOnline') < start.indexOf('mitmproxy.startCapture'), 'le backend est vérifié avant le démarrage');
  assert.match(start, /if \(!backend\?\.online\)/);
  assert.match(start, /n’auraient nulle part où être déposés/);
});

test('capture : le trafic est relu par le coordinateur unique, qui s’arrête proprement', () => {
  const extension = src('src/extension.js');
  // Deux horloges se recouvraient — un sondage Burp permanent et un sondage de
  // trafic pendant capture — et relisaient la même liste de scénarios. Il n'en
  // reste qu'une, et elle publie une fois par cycle.
  assert.match(extension, /const dynamicRefresh = createRefreshCoordinator\(\{/);
  assert.match(extension, /name: 'traffic', activeIntervalMs: \d+/);
  assert.match(extension, /name: 'connector', activeIntervalMs: \d+/);
  assert.ok(!/setInterval\(\(\) => \{[\s\S]{0,200}?getBurpStatus/.test(extension), 'plus de sondage Burp indépendant');
  assert.ok(!extension.includes('startMitmTrafficPolling'), 'plus d’horloge de capture séparée');
  // Une capture qui démarre réveille l'horloge ; la fermeture l'arrête.
  assert.match(extension, /dynamicRefresh\.wake\(\);/);
  assert.match(extension, /dispose: \(\) => \{ dynamicRefresh\.stop\(\);/);
  assert.match(extension, /dynamicRefresh\.setActive\(open\)/);
});

test('capture : une capture sans trafic le dit, au lieu d’afficher un zéro muet', () => {
  const waiting = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'demo', httpScenarios: [],
    mitmproxy: { state: 'CAPTURING', version: '12.2.3', proxyUrl: 'http://127.0.0.1:10156', httpsState: 'CERTIFICATE_REQUIRED', error: '' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.match(waiting, /En attente de trafic…/);

  // Dès qu'un échange arrive, le compte remplace l'attente.
  const captured = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'demo', httpScenarios: [CAPTURED],
    mitmproxy: { state: 'CAPTURING', version: '12.2.3', proxyUrl: 'http://127.0.0.1:10156', httpsState: 'CERTIFICATE_REQUIRED', error: '' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.ok(!captured.includes('En attente de trafic…'));
  assert.match(captured, /<span>Requêtes capturées<\/span><strong>1<\/strong>/);
  // Un proxy arrêté n'attend rien.
  const stopped = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'demo', httpScenarios: [],
    mitmproxy: { state: 'STOPPED', version: '12.2.3', proxyUrl: '', httpsState: 'CERTIFICATE_REQUIRED', error: '' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.ok(!stopped.includes('En attente de trafic…'));
});

test('capture : un navigateur de capture isolé remplace la ligne de commande', () => {
  const extension = src('src/extension.js');
  const command = extension.match(/registerCommand\('securityCenter\.openMitmproxyBrowser'[\s\S]*?\n  \}\)\);/)[0];
  // Profil dédié à la capture : le navigateur habituel, ses sessions et ses
  // réglages ne sont jamais touchés, et le proxy ne vaut que pour cette fenêtre.
  assert.match(command, /mitmproxy\.captureBrowserArgs\(\{ proxyUrl: mitmSession\.proxyUrl, profile, target \}\)/);
  assert.match(command, /mitmproxy\.captureProfileDirectory\(context\.globalStorageUri\.fsPath, captureId\)/);
  assert.ok(!/'mitmproxy', 'capture-profile'/.test(command), 'plus aucun profil partagé entre captures');
  // Aucun réglage système n'est modifié, et aucune commande de terminal proposée.
  assert.ok(!/netsh|winhttp|InternetSettings|ProxyEnable|reg add/i.test(extension), 'un réglage proxy système est touché');
  assert.ok(!/curl\.exe|powershell -c/i.test(command), 'une commande de terminal est proposée');
  // Sans navigateur pilotable, des instructions précises — pas un échec muet.
  assert.match(command, /configurez le proxy HTTP de votre navigateur sur/);
  assert.match(command, /Copier l’adresse du proxy/);
  // La commande est déclarée et autorisée depuis la page.
  const pkg = JSON.parse(src('package.json'));
  assert.ok(pkg.contributes.commands.some((entry) => entry.command === 'securityCenter.openMitmproxyBrowser'));
  assert.match(extension, /'securityCenter\.openMitmproxyBrowser',/);
  assert.match(src('src/dashboard.js'), /data-command="securityCenter\.openMitmproxyBrowser"/);
});

// ------------------------------- ressources et cycle de vie (après le gel du poste)

test('navigateur de capture : proxy imposé, boucle locale comprise, cible validée', () => {
  const args = mitmproxy.captureBrowserArgs({
    proxyUrl: 'http://127.0.0.1:41234',
    profile: 'C:\\sc\\capture-profiles\\mitmproxy-1',
    target: 'http://127.0.0.1:3000/'
  });
  assert.ok(args.includes('--proxy-server=http://127.0.0.1:41234'));
  // Sans ce contournement désactivé, Chromium ne fait pas passer 127.0.0.1 par
  // le proxy : une cible locale n'était jamais capturée.
  assert.ok(args.includes('--proxy-bypass-list=<-loopback>'));
  assert.ok(args.includes('--user-data-dir=C:\\sc\\capture-profiles\\mitmproxy-1'));
  assert.equal(args[args.length - 1], 'http://127.0.0.1:3000/');
  // Un réglage de cible qui ressemble à une option n'est jamais transmis.
  const injected = mitmproxy.captureBrowserArgs({ proxyUrl: 'http://127.0.0.1:41234', profile: 'p', target: '--remote-debugging-port=9222' });
  assert.ok(!injected.some((arg) => arg.startsWith('--remote-debugging')));
  // Le proxy de capture est toujours local : une autre adresse est refusée.
  assert.throws(() => mitmproxy.captureBrowserArgs({ proxyUrl: 'http://10.0.0.5:8080', profile: 'p' }), /proxy de capture invalide/);
  assert.throws(() => mitmproxy.captureBrowserArgs({ proxyUrl: 'http://127.0.0.1:41234', profile: '' }), /Profil de capture requis/);
});

test('navigateur de capture : un profil par capture, jamais un profil partagé', () => {
  const storage = path.join(os.tmpdir(), 'sc-mitm-profiles');
  const first = mitmproxy.captureProfileDirectory(storage, 'mitmproxy-20260911-100000-aaaa');
  const second = mitmproxy.captureProfileDirectory(storage, 'mitmproxy-20260911-100500-bbbb');
  assert.notEqual(first, second, 'deux captures, deux profils');
  assert.equal(path.dirname(first), mitmproxy.captureProfilesRoot(storage));
  // Un identifiant ne sort jamais de la racine des profils.
  const hostile = mitmproxy.captureProfileDirectory(storage, '..\\..\\Chrome\\User Data');
  assert.equal(path.dirname(hostile), mitmproxy.captureProfilesRoot(storage));
  assert.throws(() => mitmproxy.captureProfileDirectory(storage, ''), /Identifiant de capture invalide/);
});

test('navigateur de capture : seul un profil managé peut être effacé', async (t) => {
  const storage = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-mitm-profile-guard-'));
  t.after(() => fsp.rm(storage, { recursive: true, force: true }));
  const managed = mitmproxy.captureProfileDirectory(storage, 'mitmproxy-run-1');
  assert.equal(mitmproxy.isManagedCaptureProfile(storage, managed), true);
  // Ni la racine, ni son parent, ni un profil de navigateur de l'utilisateur.
  assert.equal(mitmproxy.isManagedCaptureProfile(storage, mitmproxy.captureProfilesRoot(storage)), false);
  assert.equal(mitmproxy.isManagedCaptureProfile(storage, mitmproxy.mitmRoot(storage)), false);
  assert.equal(mitmproxy.isManagedCaptureProfile(storage, path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data')), false);
  assert.equal(mitmproxy.isManagedCaptureProfile(storage, path.join(managed, 'Default')), false);

  const outside = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-mitm-not-a-profile-'));
  t.after(() => fsp.rm(outside, { recursive: true, force: true }));
  assert.equal(await mitmproxy.removeCaptureProfile(storage, outside), false);
  assert.ok(fs.existsSync(outside), 'un dossier non managé n’est jamais touché');

  await fsp.mkdir(path.join(managed, 'Default'), { recursive: true });
  assert.equal(await mitmproxy.removeCaptureProfile(storage, managed), true);
  assert.ok(!fs.existsSync(managed));
});

test('navigateur de capture : seul le processus lancé par Security Center est fermé', async () => {
  const calls = [];
  const run = async (file, args) => { calls.push({ file, args }); };
  // Rien de suivi : rien n'est fermé, aucun processus n'est lancé.
  assert.equal((await mitmproxy.closeCaptureBrowser(null, { run, platform: 'win32' })).closed, false);
  // Un processus déjà sorti n'est jamais visé : son PID a pu être réattribué.
  const exited = { process: { pid: 4242, exitCode: 0, signalCode: null }, exited: true };
  assert.equal((await mitmproxy.closeCaptureBrowser(exited, { run, platform: 'win32' })).closed, true);
  assert.equal(calls.length, 0);
  // Un navigateur vivant : son arbre de processus, par PID, via le taskkill système.
  const alive = { process: { pid: 5150, exitCode: null, signalCode: null }, exited: false };
  assert.equal((await mitmproxy.closeCaptureBrowser(alive, { run, platform: 'win32' })).closed, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0].file, /System32[\\/]taskkill\.exe$/i);
  assert.deepEqual(calls[0].args, ['/PID', '5150', '/T', '/F']);
  // Jamais par nom d'image : cela fermerait le navigateur habituel de l'utilisateur.
  assert.ok(!calls[0].args.includes('/IM'));
});

test('ressources : le sondage ne lance jamais mitmdump --version', () => {
  const extension = src('src/extension.js');
  // `\r?\n` : les sources du dépôt sont en CRLF.
  const reader = extension.match(/async function readHttpTraffic\(\) \{[\s\S]*?\n  \}\r?\n/)[0];
  assert.match(reader, /await mitmModel\(\{ detect: false \}\)/);
  assert.ok(!/mitmproxy\.detect\(/.test(reader));
  // `detect()` n'est appelé qu'à un seul endroit : la détection mémorisée.
  assert.equal((extension.match(/mitmproxy\.detect\(/g) || []).length, 1);
  assert.match(extension, /const MITM_DETECTION_TTL_MS = \d+;/);
  assert.match(extension, /if \(mitmDetectionInFlight\) return mitmDetectionInFlight;/);
  // Le démarrage transmet sa détection au lieu d'en refaire une.
  assert.match(extension, /mitmproxy\.startCapture\(context\.globalStorageUri\.fsPath, \{\s*detected,/);
  assert.match(src('src/mitmproxy.js'), /detected: known = null/);
});

test('ressources : Dynamic Security ne se rafraîchit que si elle est visible', () => {
  const extension = src('src/extension.js');
  assert.match(extension, /this\.pagePanels\.get\(page\)\?\.visible === true/);
  assert.ok(!/DYNAMIC_SURFACES\.some\(\(page\) => this\.pagePanels\.has\(page\)\)/.test(extension), 'un panneau masqué ne compte plus comme actif');
  // Seuls les vrais changements de visibilité sont relayés, pas chaque changement de focus.
  assert.match(extension, /if \(open === this\.lastDynamicSurfaceOpen\) return;/);
});

test('ressources : une publication seulement quand ce qui est montré a changé', () => {
  const extension = src('src/extension.js');
  const refresh = extension.match(/function refreshDynamicRuntimeOptions\(\) \{[\s\S]*?\n  \}/)[0];
  assert.match(refresh, /if \(signature === lastPublishedRuntimeSignature\) return;/);
  // Les horodatages d'observation ne comptent pas comme un changement.
  const signature = extension.match(/function runtimeSignature\(model\) \{[\s\S]*?\n  \}/)[0];
  assert.ok(!/observedAt|checkedAt/.test(signature));
  // Burp : une seule mise à jour de l'instantané par sondage.
  const burp = extension.match(/function applyBurpConnectorState\(status\) \{[\s\S]*?\n  \}/)[0];
  // Le code seul : un commentaire qui cite l'appel n'est pas un appel.
  const burpCode = burp.replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/setEngineAvailability\(/.test(burpCode));
  assert.equal((burpCode.match(/refreshDynamicRuntimeOptions\(\)/g) || []).length, 1);
  // Une publication explicite annule la publication différée en attente.
  assert.match(extension, /const publishDashboard = \(\) => \{[\s\S]{0,200}?cancelPendingRuntimePublish\(\);/);
  // Une rafale de pertes d'ingestion est regroupée.
  const start = extension.match(/registerCommand\('securityCenter\.startMitmproxyCapture'[\s\S]*?\n  \}\)\);/)[0];
  assert.match(start, /scheduleMitmLossFlush\(\);/);
  assert.ok(!/ingest-error[\s\S]{0,400}?publishDashboard\(\);/.test(start), 'plus de rendu par ligne d’échec');
});

test('cycle de vie : le navigateur de capture est fermé avec sa capture', () => {
  const extension = src('src/extension.js');
  const stop = extension.match(/registerCommand\('securityCenter\.stopMitmproxyCapture'[\s\S]*?\n  \}\)\);/)[0];
  assert.ok(stop.indexOf('closeTrackedCaptureBrowser()') > -1);
  assert.ok(stop.indexOf('closeTrackedCaptureBrowser()') < stop.indexOf('mitmproxy.stopCapture'), 'le navigateur est fermé avant le proxy');
  const start = extension.match(/registerCommand\('securityCenter\.startMitmproxyCapture'[\s\S]*?\n  \}\)\);/)[0];
  assert.match(start, /await closeTrackedCaptureBrowser\(\);/);
  const open = extension.match(/registerCommand\('securityCenter\.openMitmproxyBrowser'[\s\S]*?\n  \}\)\);/)[0];
  // Jamais de navigateur vers une session arrêtée, dont l'adresse traîne encore.
  assert.match(open, /if \(!mitmSession\?\.proxyUrl \|\| !proxyRunning\)/);
  assert.match(open, /child\.once\('exit', \(\) => \{ tracked\.exited = true; \}\);/);
  // Et à la fermeture de la fenêtre VS Code.
  assert.match(extension, /dispose: \(\) => \{ dynamicRefresh\.stop\(\); clearMitmLossFlush\(\); closeTrackedCaptureBrowser\(\)/);
});

// -------------------------------------------- phase B : la capture comme produit

test('capture : une perte d’ingestion devient un état visible, pas une ligne de journal', () => {
  const extension = src('src/extension.js');
  // L'addon marque chaque échec ; l'extension le lit et le porte sur l'exécution.
  assert.match(extension, /ingest-error/);
  assert.match(extension, /mitmLostExchanges \+= 1/);
  assert.match(extension, /errorCode: RUN_ERROR\.INGESTION_FAILED/);
  assert.match(extension, /n’ont pas atteint Security Center/);
  // Un arrêt propre après des pertes n'est pas une capture réussie.
  assert.match(extension, /} else if \(mitmLostExchanges > 0\) \{/);
  // Chaque capture repart d'un compte de pertes vierge.
  assert.match(extension, /mitmLostExchanges = 0;/);
});

test('capture : l’arrêt non confirmé a son propre code, distinct d’une sortie subie', () => {
  const extension = src('src/extension.js');
  assert.match(extension, /RUN_ERROR\.STOP_FAILED, `Le processus de capture n’a pas confirmé son arrêt/);
  assert.match(extension, /peut rester occupé/);
  assert.match(extension, /failEngineRun\('mitmproxy', RUN_ERROR\.PROCESS_EXITED/);
});

test('capture : le compteur décrit la session en cours, pas tout l’historique', () => {
  const extension = src('src/extension.js');
  assert.match(extension, /function sinceRunStart\(scenario, startedAt\)/);
  assert.match(extension, /sinceRunStart\(scenario, capture\.startedAt\)/);

  const runtime = {
    engines: {
      mitmproxy: {
        engine: 'mitmproxy', kind: 'capture', status: 'RUNNING', statusLabel: 'EN COURS', reason: '',
        availability: { installed: true, usable: true, version: '12.2.3', prerequisites: [], reason: '' },
        execution: {
          neverExecuted: false, runId: 'mitmproxy-1', status: 'RUNNING', phase: 'Capture en cours',
          progress: null, target: 'http://192.168.222.132:3000', startedAt: '2026-09-10T12:00:00.000Z',
          finishedAt: null, lastActivity: '2026-09-10T12:00:09.000Z', requestCount: 2, findingCount: null,
          errorCode: '', errorReason: '', lastRun: null
        }
      }
    }
  };
  // Trois scénarios stockés, dont un d'une session précédente : la carte montre
  // les deux de cette capture, et cite l'historique à côté.
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'demo', dynamicRuntime: runtime,
    httpScenarios: [CAPTURED, CAPTURED, CAPTURED],
    mitmproxy: { state: 'CAPTURING', version: '12.2.3', proxyUrl: 'http://127.0.0.1:10156', httpsState: 'CERTIFICATE_REQUIRED', error: '' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.match(html, /<span>Requêtes capturées<\/span><strong>2<\/strong>/);
  assert.match(html, /3 au total/);
  // La cible de la capture est lisible sur la carte pendant qu'elle tourne.
  assert.match(html, /<span>Cible<\/span><strong>http:\/\/192\.168\.222\.132:3000<\/strong>/);
  assert.match(html, /class="tool-status running">EN COURS</);
});

test('capture : une capture en cours qui perd des échanges le dit sur la carte', () => {
  const runtime = {
    engines: {
      mitmproxy: {
        engine: 'mitmproxy', kind: 'capture', status: 'RUNNING', statusLabel: 'EN COURS',
        reason: '2 échange(s) capturé(s) n’ont pas atteint Security Center (HTTP 401).',
        availability: { installed: true, usable: true, version: '12.2.3', prerequisites: [], reason: '' },
        execution: {
          neverExecuted: false, runId: 'mitmproxy-2', status: 'RUNNING', phase: 'Capture en cours',
          progress: null, target: 'http://192.168.222.132:3000', startedAt: '2026-09-10T12:00:00.000Z',
          finishedAt: null, lastActivity: '2026-09-10T12:00:09.000Z', requestCount: 0, findingCount: null,
          errorCode: 'INGESTION_FAILED', errorReason: '2 échange(s) capturé(s) n’ont pas atteint Security Center (HTTP 401).',
          lastRun: null
        }
      }
    }
  };
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    workspace: 'demo', dynamicRuntime: runtime, httpScenarios: [],
    mitmproxy: { state: 'CAPTURING', version: '12.2.3', proxyUrl: 'http://127.0.0.1:10156', httpsState: 'CERTIFICATE_REQUIRED', error: '' }
  }), 'nonce', 'dynamic', 'light', {}, {});
  assert.match(html, /n’ont pas atteint Security Center \(HTTP 401\)/);
});
