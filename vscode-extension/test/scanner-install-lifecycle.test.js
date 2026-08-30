'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const manager = require('../src/scanner-tool-manager');
const { download, INSTALL_PHASE, INSTALL_ERROR, DEFAULT_STALL_MS, DEFAULT_DOWNLOAD_TIMEOUT_MS } = manager;
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

/**
 * `download()` speaks HTTPS. The lifecycle it implements — abort, stall, cleanup
 * — is transport-independent, so it is exercised here through the same contract
 * with a local server, and the HTTPS specifics stay covered by the real installer.
 */
function lifecycleDownload(url, destination, onProgress, { signal, stallTimeoutMs = 50 } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Object.assign(new Error('Installation annulée.'), { code: INSTALL_ERROR.CANCELLED, cancelled: true }));
    // Une seule voie de sortie : sans cela l'erreur remontee par la requete
    // pouvait resoudre la promesse AVANT que le nettoyage du fichier partiel
    // soit termine, et le test observait un artefact encore present.
    let settled = false;
    let responseStarted = false;
    const finish = (error) => { if (settled) return; settled = true; error ? reject(error) : resolve(); };
    const request = http.get(url, async (response) => {
      // `response.destroy(err)` fait aussi remonter l'erreur sur la REQUETE. Le
      // produit s'en premunit avec son drapeau `settled` une fois la reponse
      // recue ; le harnais reproduit exactement cette garde, sinon la promesse
      // se resout avant la fin du nettoyage.
      responseStarted = true;
      const total = Number(response.headers['content-length'] || 0);
      let received = 0;
      let lastAt = Date.now();
      const handle = await fsp.open(destination, 'w');
      const stall = setInterval(() => {
        if (Date.now() - lastAt > stallTimeoutMs) {
          response.destroy(Object.assign(new Error('Téléchargement interrompu — aucune progression détectée.'), { code: INSTALL_ERROR.STALLED }));
        }
      }, 10);
      const onAbort = () => response.destroy(Object.assign(new Error('Installation annulée.'), { code: INSTALL_ERROR.CANCELLED, cancelled: true }));
      signal?.addEventListener('abort', onAbort, { once: true });
      try {
        for await (const chunk of response) {
          await handle.write(chunk); received += chunk.length; lastAt = Date.now();
          onProgress?.({ phase: INSTALL_PHASE.DOWNLOADING, received, total });
        }
        clearInterval(stall); await handle.close(); finish();
      } catch (error) {
        clearInterval(stall);
        await handle.close().catch(() => {});
        for (let attempt = 0; attempt < 20; attempt += 1) {
          await fsp.rm(destination, { force: true }).catch(() => {});
          if (!fs.existsSync(destination)) break;
          await new Promise((r) => setTimeout(r, 25));
        }
        finish(error);
      }
    });
    // Une fois le corps recu, seule la boucle decide de l'issue.
    request.on('error', (error) => { if (!responseStarted) finish(error); });
  });
}

async function stallingServer(t, { contentLength = null, firstChunk = 'x'.repeat(64) } = {}) {
  const server = http.createServer((request, response) => {
    const headers = { 'content-type': 'application/octet-stream' };
    if (contentLength !== null) headers['content-length'] = String(contentLength);
    response.writeHead(200, headers);
    response.write(firstChunk);           // du progres, puis plus rien : le bug Cosign
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}/tool.zip`;
}

const tempFile = async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sc-install-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }).catch(() => {}));
  return path.join(dir, 'artifact.bin');
};

// ------------------------------------------------- reproduction du bug Cosign

test('installation : un telechargement bloque se termine au lieu de tourner sans fin', async (t) => {
  // Le cas signale : Cosign reste a « Téléchargement 1 % » plus de vingt minutes.
  // Des octets arrivent, puis la connexion se tait. Sans detection de blocage la
  // boucle `for await` n'avance plus et rien ne se termine jamais.
  const url = await stallingServer(t, { contentLength: 10 * 1024 * 1024 });
  const destination = await tempFile(t);
  const seen = [];
  const started = Date.now();
  await assert.rejects(
    () => lifecycleDownload(url, destination, (event) => seen.push(event), { stallTimeoutMs: 50 }),
    (error) => error.code === INSTALL_ERROR.STALLED
  );
  assert.ok(Date.now() - started < 5000, 'doit se terminer rapidement, pas rester bloque');
  assert.ok(seen.length > 0, 'une progression reelle a bien eu lieu avant le blocage');
  assert.equal(fs.existsSync(destination), false, 'le fichier partiel est supprime');
});

test('installation : une annulation utilisateur interrompt le telechargement reel', async (t) => {
  const url = await stallingServer(t, { contentLength: 10 * 1024 * 1024 });
  const destination = await tempFile(t);
  const controller = new AbortController();
  const pending = lifecycleDownload(url, destination, () => controller.abort(), { signal: controller.signal, stallTimeoutMs: 60000 });
  await assert.rejects(pending, (error) => error.cancelled === true || error.code === INSTALL_ERROR.CANCELLED);
  assert.equal(fs.existsSync(destination), false, 'artefact incomplet nettoye');
});

test('installation : un signal deja annule n envoie aucune requete', async (t) => {
  const destination = await tempFile(t);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => lifecycleDownload('http://127.0.0.1:1/never', destination, () => {}, { signal: controller.signal }),
    (error) => error.cancelled === true
  );
  assert.equal(fs.existsSync(destination), false);
});

// ---------------------------------------------------------- contrat du module

test('installation : le telechargeur accepte signal, delai et detection de blocage', () => {
  const source = src('scanner-tool-manager.js');
  assert.match(source, /async function download\(url, destination, onProgress = \(\) => \{\}, \{ signal, timeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS, stallTimeoutMs = DEFAULT_STALL_MS \} = \{\}\)/);
  // La requete a desormais un delai de socket ET un abandon : c'est l'absence
  // des deux qui rendait le blocage eternel.
  assert.match(source, /active\.setTimeout\(timeoutMs/);
  assert.match(source, /signal\?\.addEventListener\?\.\('abort', onAbort/);
  assert.match(source, /aucune progression détectée/);
  // Nettoyage limite a l'artefact partiel de CE run.
  assert.match(source, /await fs\.rm\(destination, \{ force: true \}\)/);
  assert.ok(Number.isFinite(DEFAULT_STALL_MS) && DEFAULT_STALL_MS >= 60000, 'delai de blocage raisonnable');
  assert.ok(DEFAULT_DOWNLOAD_TIMEOUT_MS > DEFAULT_STALL_MS, 'le plafond global ne casse pas les gros telechargements');
});

test('installation : le signal traverse toutes les voies d installation', () => {
  const source = src('scanner-tool-manager.js');
  assert.match(source, /async install\(id, onProgress = \(\) => \{\}, \{ signal \} = \{\}\)/);
  assert.match(source, /installSemgrep\(onProgress, \{ signal \}\)/);
  assert.match(source, /installSonarScanner\(tool, onProgress, sonarScannerPlatform\(\), \{ signal \}\)/);
  assert.match(source, /installSnyk\(tool, onProgress, snykCliAsset\(\), \{ signal \}\)/);
  for (const call of source.match(/await download\([^;]*\);/g) || []) {
    assert.match(call, /\{ signal \}/, `un telechargement sans signal subsiste : ${call}`);
  }
});

// ------------------------------------------------------------- orchestration

test('installation : un controleur par run, jamais reutilise apres annulation', () => {
  const extension = src('extension.js');
  assert.match(extension, /const installController = new AbortController\(\);/);
  assert.match(extension, /scannerInstallControllers\.set\(id, installController\)/);
  assert.match(extension, /token\.onCancellationRequested\(\(\) => installController\.abort\(\)\)/);
  assert.match(extension, /cancellable: true/, 'la notification de progression doit etre annulable');
  assert.match(extension, /finally \{ scannerInstallControllers\.delete\(id\); \}/);
  // Le retry efface l'etat terminal et relance un run complet.
  assert.match(extension, /message\?\.type === 'retryInstall'[\s\S]*?delete scannerSetupOperations\[message\.tool\][\s\S]*?installManagedScanners\(\[message\.tool\]\)/);
});

test('installation : deux installations simultanees du meme outil sont impossibles', () => {
  const extension = src('extension.js');
  assert.match(extension, /ids\.filter\(\(id\) => MANAGED_SCANNER_TOOLS\[id\] && !scannerInstallControllers\.has\(id\)\)/);
});

test('installation : annuler pendant l installation vise uniquement ce run', () => {
  const extension = src('extension.js');
  const handler = extension.match(/if \(message\?\.type === 'abortInstall'[\s\S]*?\n        \}/)[0];
  assert.match(handler, /scannerInstallControllers\.get\(message\.tool\)\?\.abort\(\)/);
  // Aucun processus tiers n'est touche.
  for (const forbidden of ['process.kill', 'treeKill', 'taskkill', 'killAll']) {
    assert.ok(!handler.includes(forbidden), `${forbidden} ne doit pas apparaitre`);
  }
  // Distinct de l'annulation AVANT installation, qui ferme la confirmation.
  assert.match(extension, /if \(message\?\.type === 'cancelInstall'\) \{ scannerSetupConfirmation = undefined;/);
});

test('installation : annulation et echec sont deux etats terminaux distincts', () => {
  const extension = src('extension.js');
  assert.match(extension, /const cancelled = error\?\.cancelled === true \|\| error\?\.code === INSTALL_ERROR\.CANCELLED/);
  assert.match(extension, /state: 'cancelled'[\s\S]*?retryable: true/);
  assert.match(extension, /state: 'failed'[\s\S]*?errorCode: error\?\.code/);
  // Une annulation ne doit jamais declarer l'outil pret.
  const installFn = extension.match(/async function installManagedScanners\(ids\)[\s\S]*?\n  \}/)[0];
  const block = installFn.match(/\} catch \(error\) \{[\s\S]*?scannerInstallControllers\.delete\(id\); \}/)[0];
  assert.ok(!block.includes("state: 'ready'"), 'un run annule ne devient jamais Prêt');
  // L'erreur affichee est assainie.
  assert.match(extension, /message: summarizeScannerError\(error\.message\)/);
});

// ---------------------------------------------------------------------- UI

const toolCard = (operation) => renderScannerSetupHtml(
  [{ id: 'cosign', label: 'Cosign', purpose: 'Signature', installed: false, managed: true }],
  'n', 'light', operation ? { cosign: operation } : {}
);

test('installation : une installation en cours expose un vrai bouton Annuler', () => {
  const html = toolCard({ state: 'installing', title: 'Installation de Cosign', message: 'Téléchargement 35%', percent: 35 });
  assert.match(html, /data-install-abort="cosign"/);
  assert.match(html, />Annuler</);
  assert.match(html, /<progress max="100" value="35">/);
  // Le bouton est reellement cable.
  assert.match(src('scanner-setup-page.js'), /data-install-abort\]'\)\.forEach\(b=>b\.onclick=\(\)=>vscode\.postMessage\(\{type:'abortInstall',tool:b\.dataset\.installAbort\}\)\)/);
});

test('installation : une taille inconnue n affiche jamais un faux pourcentage', () => {
  const html = toolCard({ state: 'installing', title: 'Installation de Cosign', message: 'Téléchargement en cours…' });
  assert.match(html, /Téléchargement en cours…/);
  assert.doesNotMatch(html, /<progress max="100"/, 'aucune barre chiffree sans denominateur');
  assert.match(html, /<progress aria-label="Progression indéterminée">/);
  assert.doesNotMatch(html, /Téléchargement 1%/);
  // Cote extension, le pourcentage n'existe que si le serveur a annonce une taille.
  const extension = src('extension.js');
  assert.match(extension, /const percent = event\.total > 0/);
  assert.match(extension, /: 'Téléchargement en cours…'/);
});

test('installation : le pourcentage suit les octets reels quand la taille est connue', () => {
  const extension = src('extension.js');
  assert.match(extension, /Math\.min\(100, Math\.round\(event\.received \/ event\.total \* 100\)\)/);
  const html = toolCard({ state: 'installing', title: 'Installation de Cosign', message: 'Téléchargement 72%', percent: 72 });
  assert.match(html, /value="72"/);
});

test('installation : apres annulation ou echec, Réessayer est propose', () => {
  for (const state of ['cancelled', 'failed']) {
    const html = toolCard({ state, title: `Installation ${state}`, message: 'x', retryable: true });
    assert.match(html, /data-install-retry="cosign"/, `${state} doit proposer un retry`);
    assert.match(html, />Réessayer</);
    assert.doesNotMatch(html, /data-install-abort="cosign"/, `${state} ne doit plus proposer Annuler`);
  }
  assert.match(src('scanner-setup-page.js'), /data-install-retry\]'\)\.forEach\(b=>b\.onclick=\(\)=>vscode\.postMessage\(\{type:'retryInstall',tool:b\.dataset\.installRetry\}\)\)/);
});

test('installation : un run annule s affiche « Annulée », pas « Échec »', () => {
  const html = toolCard({ state: 'cancelled', title: 'Installation de Cosign annulée', message: 'x' });
  assert.match(html, /Annulée/);
  assert.doesNotMatch(html, /<span class="status">Échec<\/span>/);
});

// ------------------------------------------------------- invariants securite

test('installation : verification SHA-256 et provenance officielle inchangees', () => {
  const source = src('scanner-tool-manager.js');
  assert.match(source, /ne fournit pas d’empreinte SHA-256 exploitable\. Installation refusée par sécurité\./);
  assert.match(source, /if \(actual !== expected\) throw new Error\('Échec de vérification SHA-256/);
  assert.match(source, /assertNoPathEscape/);
  // Sources officielles inchangees.
  assert.match(source, /https:\/\/binaries\.sonarsource\.com\/Distribution\/sonar-scanner-cli/);
  assert.match(source, /https:\/\/downloads\.snyk\.io\/cli\/stable/);
  assert.match(source, /api\.github\.com|browser_download_url/);
});

test('installation : la confirmation explicite reste obligatoire', () => {
  const extension = src('extension.js');
  assert.match(extension, /message\?\.type === 'approveInstall' && scannerSetupConfirmation && !scannerInstallationRunning/);
  const html = renderScannerSetupHtml([], 'n', 'light', {}, { labels: ['Cosign'], destination: 'C:/store' });
  assert.match(html, /Autoriser l’installation \?/);
  assert.match(html, /Aucune installation n’est lancée sans votre confirmation/);
  // La modale reste globale et centree (correctif precedent).
  assert.match(html, /modal-root/);
});

test('installation : le nettoyage ne touche que l artefact partiel', () => {
  const source = src('scanner-tool-manager.js');
  const downloadFn = source.match(/async function download\([\s\S]*?\n\}/)[0];
  assert.match(downloadFn, /fs\.rm\(destination, \{ force: true \}\)/);
  // Jamais de suppression recursive d'un repertoire d'installation.
  assert.ok(!downloadFn.includes('recursive: true'), 'aucune suppression recursive dans le telechargeur');
  for (const forbidden of ['toolDirectory', 'this.root', 'globalStorage']) {
    assert.ok(!downloadFn.includes(forbidden), `${forbidden} ne doit pas etre touche au nettoyage`);
  }
});

test('installation : ni le cycle de scan ni les findings ne sont touches', () => {
  const extension = src('extension.js');
  const installFn = extension.match(/async function installManagedScanners\(ids\)[\s\S]*?\n  \}/)[0];
  for (const forbidden of ['currentFindings', 'currentScanStatuses', 'currentSecuritySnapshot', 'saveLocalScanCache', 'LOCAL_SCAN_HISTORY_KEY', 'PIPELINE_STATE_KEY', 'runSecurityScan']) {
    assert.ok(!installFn.includes(forbidden), `l installateur ne doit pas toucher ${forbidden}`);
  }
});
