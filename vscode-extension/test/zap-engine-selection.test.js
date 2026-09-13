'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const { freeLocalPort, zapHomeDirectory, prepareZapHome, startLocalZap, detectLocalZap } = require('../src/zap-local');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

// ------------------------------------------- sélection du moteur « auto »

test('ZAP : « auto » choisit vraiment — local si installé, Docker sinon', () => {
  const source = src('zap.js');
  const runZap = source.match(/async function runZap\([\s\S]*?const reportDirectory/)[0];
  // `auto` se comportait exactement comme `local` : sans ZAP installé il levait
  // une erreur au lieu d'utiliser Docker, qui n'exige pourtant rien.
  assert.match(runZap, /const resolvedEngine = engine === 'auto' \? \(detectedLocalPath \? 'local' : 'docker'\) : engine;/);
  assert.match(runZap, /if \(resolvedEngine !== 'docker'\)/);
  assert.ok(!/if \(engine !== 'docker'\)/.test(runZap), 'la branche ne teste plus le mode brut');
});

test('ZAP : les trois modes de zap.mode restent acceptés par la politique projet', () => {
  const policy = src('project-policy.js');
  assert.match(policy, /\['auto', 'local', 'docker'\]\.includes\(zapEngine\)/);
  assert.match(policy, /String\(raw\.zap\?\.mode \|\| 'auto'\)/, 'auto reste le défaut');
});

// ------------------------------------------------ répertoire personnel ZAP

test('ZAP : le démon tourne dans le répertoire de Security Center, jamais celui de l’utilisateur', () => {
  const home = zapHomeDirectory();
  assert.ok(home.startsWith(os.tmpdir()), 'le home vit dans le répertoire temporaire');
  assert.match(home, /security-center-zap-home/);
  // Le home par défaut de ZAP (~/ZAP) n'est jamais utilisé : l'ouvrir en même
  // temps que le ZAP de l'utilisateur faisait échouer le démarrage.
  assert.ok(!home.includes(path.join(os.homedir(), 'ZAP')), 'le profil ZAP de l’utilisateur n’est pas touché');
});

test('ZAP : un verrou résiduel de notre propre répertoire est levé avant le démarrage', async (t) => {
  const home = zapHomeDirectory();
  await fsp.mkdir(home, { recursive: true });
  const lock = path.join(home, '.homelock');
  await fsp.writeFile(lock, 'verrou de test');
  assert.equal(fs.existsSync(lock), true);
  // C'est exactement l'état laissé par un démon tué : ZAP refuse alors de
  // démarrer avec « The home directory is already in use ».
  const prepared = await prepareZapHome();
  assert.equal(prepared, home);
  assert.equal(fs.existsSync(lock), false, 'le verrou résiduel est levé');
  assert.equal(fs.existsSync(home), true, 'le reste du répertoire est conservé');
});

test('ZAP : le répertoire est passé au démon en argument -dir', () => {
  // `spawn` est déstructuré au chargement du module : c'est donc la ligne de
  // commande construite qui est vérifiée, à la source.
  const source = src('zap-local.js');
  const builder = source.match(/function startLocalZap\([\s\S]*?\n\}/)[0];
  assert.match(builder, /\{ port = 8090, apiKey, authResult, home = '', onDiagnostic \} = \{\}/);
  assert.match(builder, /if \(home\) args\.push\('-dir', home\);/);
  assert.match(builder, /'-daemon'/, 'le démon reste headless');
  assert.match(builder, /'-silent'/);
  // Le home est fourni par l'appelant, jamais deviné dans le lanceur.
  assert.ok(!builder.includes('homedir()'), 'le lanceur ne compose aucun chemin utilisateur');
});

// -------------------------------------------------------------- port libre

test('ZAP : le démon n’est plus épinglé au port 8090', async () => {
  const source = src('zap-local.js');
  assert.ok(!/const baseUrl = 'http:\/\/127\.0\.0\.1:8090'/.test(source), 'plus de port codé en dur');
  assert.match(source, /const port = await freeLocalPort\(\);/);
  assert.match(source, /const baseUrl = `http:\/\/127\.0\.0\.1:\$\{port\}`;/);
  assert.match(source, /startLocalZap\(zapPath, \{ port,/);
});

test('ZAP : le port choisi est réellement libre et libéré avant le démarrage', async (t) => {
  const port = await freeLocalPort();
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536, `port invalide : ${port}`);
  // Il doit être immédiatement réutilisable : la sonde a relâché son écoute.
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  t.after(() => server.close());
  assert.equal(server.address().port, port);
  // Deux appels ne rendent pas le même port occupé.
  const second = await freeLocalPort();
  assert.notEqual(second, port, 'un port déjà pris n’est pas proposé');
});

test('ZAP : un ZAP tiers occupant 8090 n’empêche plus le moteur local', async (t) => {
  // Le cas réel : l'application ZAP de l'utilisateur écoute sur 8090.
  const occupant = net.createServer();
  await new Promise((resolve, reject) => {
    occupant.once('error', resolve); // 8090 déjà pris : le cas est déjà réalisé
    occupant.listen(8090, '127.0.0.1', resolve);
  });
  t.after(() => { try { occupant.close(); } catch { /* déjà fermé */ } });
  const port = await freeLocalPort();
  assert.notEqual(port, 8090, 'le moteur ne réclame jamais le port occupé');
});

// ------------------------------------------------- moteur réellement headless

test('ZAP : aucun moteur n’exige l’application de bureau', () => {
  const local = src('zap-local.js');
  const zap = src('zap.js');
  // Local : démon + API, jamais d'interface.
  assert.match(local, /'-daemon'/);
  assert.ok(!local.includes('-gui'), 'aucun lancement en interface graphique');
  // Docker : les scripts d'automatisation officiels d'OWASP.
  assert.match(zap, /zap-baseline\.py/);
  assert.match(zap, /zap-full-scan\.py/);
  assert.match(zap, /zap-api-scan\.py/);
  assert.match(zap, /zaproxy\/zap-stable/);
});

test('ZAP : la détection locale accepte un chemin configuré et la variable ZAP_PATH', () => {
  const source = src('zap-local.js');
  assert.match(source, /const candidates = \[configuredPath, process\.env\.ZAP_PATH/);
  // Un chemin configuré inexistant n'est jamais rendu tel quel : soit un autre
  // candidat réel prend le relais, soit la détection rend une chaîne vide.
  const detected = detectLocalZap('C:/chemin/inexistant/zap.bat');
  assert.notEqual(detected, 'C:/chemin/inexistant/zap.bat', 'un chemin absent ne ment pas');
  if (detected) assert.equal(fs.existsSync(detected), true, 'tout chemin rendu existe réellement');
});
