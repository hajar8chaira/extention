'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const {
  TARGET_MODE, TARGET_STATE, normalizeTargetUrl, assertTargetAuthorized,
  targetScope, isLoopbackHost, checkTargetReachability
} = require('../src/dynamic-target');
const { validateLocalTarget, validateZapTarget, dockerTargetUrl, zapConfig } = require('../src/zap');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

// ------------------------------------------------------------------ LOCAL

test('cible : le mode local garde exactement le contrat d’origine', () => {
  assert.equal(normalizeTargetUrl('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(normalizeTargetUrl('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.equal(normalizeTargetUrl('https://127.0.0.1:8443'), 'https://127.0.0.1:8443');
  // Le mode local est le défaut : une configuration existante ne change pas.
  assert.throws(() => normalizeTargetUrl('http://192.168.1.10:3000'), /doit être locale/);
  assert.throws(() => normalizeTargetUrl('http://exemple.test'), /doit être locale/);
});

test('cible : ZAP conserve son validateur loopback pour tous ses appelants d’origine', () => {
  assert.equal(validateLocalTarget('http://127.0.0.1:3000').port, '3000');
  assert.throws(() => validateLocalTarget('https://example.com'), /uniquement une cible locale/);
  assert.throws(() => validateLocalTarget('file:///etc/passwd'), /HTTP ou HTTPS/);
  // Et une cible locale est toujours réécrite pour le conteneur.
  assert.equal(dockerTargetUrl('http://localhost:3000'), 'http://host.docker.internal:3000');
});

// ----------------------------------------------------------------- REMOTE

test('cible : le mode distant accepte IP privée, hostname, HTTPS et port explicite', () => {
  const remote = { mode: TARGET_MODE.REMOTE };
  assert.equal(normalizeTargetUrl('http://192.168.222.132:3000', remote), 'http://192.168.222.132:3000');
  assert.equal(normalizeTargetUrl('http://10.0.0.5:8080', remote), 'http://10.0.0.5:8080');
  assert.equal(normalizeTargetUrl('https://preprod.interne.lan', remote), 'https://preprod.interne.lan');
  assert.equal(normalizeTargetUrl('http://[::1]:3000', remote), 'http://[::1]:3000');
  // Une IP privée n'est pas refusée au seul motif qu'elle n'est pas loopback.
  assert.equal(targetScope('http://192.168.222.132:3000'), TARGET_MODE.REMOTE);
  assert.equal(targetScope('http://127.0.0.1:3000'), TARGET_MODE.LOCAL);
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('192.168.1.1'), false);
});

test('cible : le mode distant refuse ce qui n’est pas une URL HTTP(S) exploitable', () => {
  const remote = { mode: TARGET_MODE.REMOTE };
  assert.throws(() => normalizeTargetUrl('ftp://serveur/app', remote), /HTTP ou HTTPS/);
  assert.throws(() => normalizeTargetUrl('file:///etc/passwd', remote), /HTTP ou HTTPS/);
  assert.throws(() => normalizeTargetUrl('pas une url', remote), /invalide/);
  // Les identifiants dans l'URL restent refusés : ils finiraient dans les settings.
  assert.throws(() => normalizeTargetUrl('http://admin:motdepasse@192.168.1.10', remote), /identifiants/);
  // Une cible vide reste vide, jamais une adresse inventée.
  assert.equal(normalizeTargetUrl('', remote), '');
});

test('cible : sans confirmation d’autorisation, aucune analyse distante n’est permise', () => {
  const target = 'http://192.168.222.132:3000';
  assert.throws(
    () => assertTargetAuthorized(target, { mode: TARGET_MODE.REMOTE, remoteAuthorized: false }),
    /confirmez disposer de l’autorisation/
  );
  // Une valeur qui n'est pas exactement `true` ne vaut pas confirmation.
  for (const value of ['true', 1, {}, null, undefined]) {
    assert.throws(() => assertTargetAuthorized(target, { mode: TARGET_MODE.REMOTE, remoteAuthorized: value }), /autorisation/);
  }
  assert.equal(assertTargetAuthorized(target, { mode: TARGET_MODE.REMOTE, remoteAuthorized: true }), target);
  // Le mode local n'a jamais besoin de confirmation.
  assert.equal(assertTargetAuthorized('http://127.0.0.1:3000', { mode: TARGET_MODE.LOCAL }), 'http://127.0.0.1:3000');
});

test('cible : une adresse distante n’est jamais réécrite en localhost', () => {
  const remote = 'http://192.168.222.132:3000';
  assert.throws(() => dockerTargetUrl(remote), /uniquement une cible locale/);
  const rewritten = dockerTargetUrl(remote, { allowRemote: true });
  assert.equal(rewritten, remote, 'l’adresse distante part telle quelle');
  assert.ok(!rewritten.includes('host.docker.internal'));
  assert.ok(!rewritten.includes('127.0.0.1'));
  assert.ok(!rewritten.includes('localhost'));
  // Les exclusions de routes visent bien l'hôte distant réel.
  // Les points sont echappes dans l'expression OUTOFSCOPE generee.
  assert.match(zapConfig(['/admin'], remote, { allowRemote: true }), /192\\.168\\.222\\.132/);
  assert.equal(validateZapTarget(remote, { allowRemote: true }).hostname, '192.168.222.132');
});

// ---------------------------------------------------- test de connectivité

test('connectivité : une cible démarrée est rapportée accessible avec son code HTTP', async (t) => {
  const server = http.createServer((request, response) => { response.writeHead(204); response.end(); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const result = await checkTargetReachability(`http://127.0.0.1:${server.address().port}`, 2000);
  assert.equal(result.state, TARGET_STATE.ONLINE);
  assert.equal(result.statusCode, 204);
  assert.equal(result.scope, TARGET_MODE.LOCAL);
});

test('connectivité : chaque panne a son propre état, jamais un « inaccessible » générique', async () => {
  const refused = await checkTargetReachability('http://127.0.0.1:1', 1500);
  assert.equal(refused.state, TARGET_STATE.REFUSED);

  const dns = await checkTargetReachability('http://hote.inexistant.invalid', 3000, { mode: TARGET_MODE.REMOTE });
  assert.equal(dns.state, TARGET_STATE.DNS_ERROR);
  assert.equal(dns.scope, TARGET_MODE.REMOTE);

  // Une cible distante sondée en mode local est refusée à la validation, pas
  // silencieusement contactée.
  const wrongMode = await checkTargetReachability('http://192.168.222.132:3000', 1500, { mode: TARGET_MODE.LOCAL });
  assert.equal(wrongMode.state, TARGET_STATE.UNREACHABLE);
  assert.match(wrongMode.error, /doit être locale/);

  assert.deepEqual(await checkTargetReachability(''), { state: TARGET_STATE.UNKNOWN });
});

test('connectivité : sonder ne lance jamais de moteur d’analyse', () => {
  const source = src('dynamic-target.js');
  assert.ok(!source.includes('runZap'), 'la sonde ne connaît aucun moteur');
  assert.ok(!source.includes('docker'), 'la sonde ne démarre aucun conteneur');
  assert.match(source, /method: 'HEAD'/, 'une seule requête HEAD');
});

// ------------------------------------------------------------- pipeline

test('pipeline : le scan refuse une cible distante non confirmée avant tout moteur', () => {
  const extension = src('extension.js');
  const zapEntry = extension.match(/tool: 'ZAP'[\s\S]*?normalize:/)[0];
  // La garde s'exécute dans `execute`, donc son échec devient un scanner FAILED
  // terminal par le chemin d'erreur existant — jamais un « running » éternel.
  assert.match(zapEntry, /assertTargetAuthorized\(/);
  assert.ok(zapEntry.indexOf('assertTargetAuthorized(') < zapEntry.indexOf('runZap('), 'la garde précède le moteur');
  assert.match(zapEntry, /allowRemote: cfg\.get\('zap\.targetMode'/);
  assert.match(zapEntry, /cfg\.get\('zap\.remoteAuthorized', false\) === true/);
});

test('pipeline : le mode et l’autorisation sont persistés dans la configuration', () => {
  const manifest = JSON.parse(src('../package.json'));
  const properties = manifest.contributes.configuration.properties;
  assert.deepEqual(properties['securityCenter.zap.targetMode'].enum, ['local', 'remote']);
  assert.equal(properties['securityCenter.zap.targetMode'].default, 'local', 'le défaut reste local');
  assert.equal(properties['securityCenter.zap.remoteAuthorized'].default, false);
  assert.equal(properties['securityCenter.zap.remoteAuthorized'].type, 'boolean');
  // La confirmation est décrite comme un garde-fou, pas comme une preuve.
  assert.match(properties['securityCenter.zap.remoteAuthorized'].description, /garde-fou/);
});

test('pipeline : changer de cible redemande le mode et reconfirme l’autorisation', () => {
  const extension = src('extension.js');
  const command = extension.match(/registerCommand\('securityCenter\.changeDynamicTarget'[\s\S]*?\n  \}\)\);/)[0];
  assert.match(command, /showQuickPick/, 'le mode est demandé explicitement');
  assert.match(command, /Je confirme être autorisé/);
  assert.match(command, /modal: true/);
  assert.match(command, /zap\.targetMode/);
  assert.match(command, /zap\.remoteAuthorized/);
  // Repasser en local remet l'autorisation à false : elle appartient à l'adresse
  // qui a été confirmée.
  assert.match(command, /let remoteAuthorized = false;/);
});

// -------------------------------------------------------------------- UX

test('interface : le mode de la cible est visible, et l’URL réellement scannée n’est jamais masquée', () => {
  const assets = {
    cspSource: 'vscode-webview:',
    scannerLogoUris: {
      ZAP: 'vscode-webview-resource:/media/scanners/zap.png',
      Nuclei: 'vscode-webview-resource:/media/scanners/nuclei.png'
    }
  };
  const remote = renderDashboardHtml(buildDashboardModel([], [], {
    dynamicTargetUrl: 'http://192.168.222.132:3000',
    dynamicTargetMode: 'remote',
    dynamicTargetRemoteAuthorized: true,
    dynamicTargetState: 'online'
  }), 'nonce', 'dynamic', 'light', {}, assets);
  assert.match(remote, /Cible distante/);
  assert.match(remote, /Autorisation confirmée/);
  assert.match(remote, /192\.168\.222\.132:3000/, 'l’URL scannée reste affichée');
  assert.match(remote, /data-dynamic-target-mode="local"/);
  assert.match(remote, /data-dynamic-target-mode="remote"/);
  assert.match(remote, /id="dynamic-target-url" type="text" value="http:\/\/192\.168\.222\.132:3000"/);
  assert.doesNotMatch(remote, /id="dynamic-target-url"[^>]*readonly/);
  assert.match(remote, /data-dynamic-target-action="save"/);
  assert.match(remote, /data-dynamic-tool-logo="zap"[\s\S]{0,180}<img class="dynamic-tool-logo-img"/);
  assert.match(remote, /data-dynamic-tool-logo="nuclei"[\s\S]{0,180}<img class="dynamic-tool-logo-img"/);
  assert.doesNotMatch(remote, /dynamic-tool-mark/);

  const unconfirmed = renderDashboardHtml(buildDashboardModel([], [], {
    dynamicTargetUrl: 'http://192.168.222.132:3000',
    dynamicTargetMode: 'remote',
    dynamicTargetRemoteAuthorized: false,
    dynamicTargetState: 'unknown'
  }), 'nonce', 'dynamic', 'light', {}, assets);
  assert.match(unconfirmed, /Autorisation non confirmée/);
  assert.match(unconfirmed, /analyse dynamique bloquée/);

  const local = renderDashboardHtml(buildDashboardModel([], [], {
    dynamicTargetUrl: 'http://127.0.0.1:3000',
    dynamicTargetMode: 'local',
    dynamicTargetState: 'refused'
  }), 'nonce', 'dynamic', 'light', {}, assets);
  assert.match(local, /Cible locale/);
  assert.match(local, /Connexion refusée/);
  assert.doesNotMatch(local, /Autorisation/);
});

test('interface : le sélecteur inline réutilise le contrat de cible existant', () => {
  const dashboard = src('dashboard.js');
  assert.match(dashboard, /type: 'dynamicTargetMode'[\s\S]*mode[\s\S]*targetUrl/);
  assert.match(dashboard, /type: 'dynamicTargetSave'[\s\S]*selectedDynamicTargetMode\(\)[\s\S]*targetUrl/);

  const extension = src('extension.js');
  assert.match(extension, /message\?\.type === 'dynamicTargetMode'[\s\S]*securityCenter\.changeDynamicTarget/);
  assert.match(extension, /message\?\.type === 'dynamicTargetSave'[\s\S]*securityCenter\.changeDynamicTarget/);
  assert.match(extension, /normalizeTargetUrl\(String\(request\.targetUrl \|\| ''\), \{ mode \}\)/);
  assert.match(extension, /Je confirme être autorisé/);
  assert.match(extension, /cfg\.update\('zap\.targetUrl', normalized/);
  assert.match(extension, /cfg\.update\('zap\.targetMode', mode/);
  assert.match(extension, /cfg\.update\('zap\.remoteAuthorized', remoteAuthorized/);
});

test('sécurité : aucune découverte automatique de cible, aucune extension de portée', () => {
  const source = src('dynamic-target.js');
  const zap = src('zap.js');
  for (const forbidden of ['scan(', 'discover', 'crawlAll', 'enumerate']) {
    assert.ok(!source.includes(forbidden), `${forbidden} absent de la sonde`);
  }
  // La portée reste l'URL configurée : ZAP est toujours pointé sur elle seule.
  assert.match(zap, /'-t', scanTarget/);
  assert.ok(!zap.includes('additionalTargets'), 'aucune cible supplémentaire');
});
