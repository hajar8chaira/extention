'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');

test('affiche les scanners locaux et leurs actions sans lancer une installation', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false },
    { id: 'trivy', label: 'Trivy', purpose: 'SCA', installed: true, managed: true, version: '1.2.3', executable: 'C:\\tools\\trivy.exe' }
  ], 'nonce', 'light');

  assert.match(html, /Configuration des scanners/);
  assert.match(html, /Installer localement/);
  assert.match(html, /Utiliser en mode Auto/);
  assert.match(html, /Aucune installation n[^<]*est lanc/);
  assert.match(html, /data-theme="light"/);
  assert.doesNotMatch(html, /fetch\(|XMLHttpRequest|install\(\)/);
});

test('affiche une progression et respecte le thème sombre choisi', () => {
  const html = renderScannerSetupHtml([
    { id: 'osv', label: 'OSV-Scanner', purpose: 'Dépendances', installed: false }
  ], 'nonce', 'dark', {
    osv: { state: 'installing', title: 'Téléchargement', message: 'Vérification en cours', percent: 42 }
  });

  assert.match(html, /data-theme="dark"/);
  assert.match(html, /value="42"/);
  assert.match(html, /Vérification en cours/);
  assert.match(html, /disabled/);
});

test('affiche une confirmation intégrée et thémée avant toute installation', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false }
  ], 'nonce', 'light', {}, {
    ids: ['semgrep'], labels: ['Semgrep'], destination: 'C:\\private\\scanner-tools'
  });

  assert.match(html, /role="dialog"/);
  assert.match(html, /INSTALLATION LOCALE SÉCURISÉE/);
  assert.match(html, /Semgrep/);
  assert.match(html, /C:\\private\\scanner-tools/);
  assert.match(html, /Autoriser et installer/);
  assert.match(html, /Annuler/);
  assert.match(html, /approveInstall/);
  assert.match(html, /cancelInstall/);
  assert.doesNotMatch(html, /showWarningMessage/);
});

test('verrouille les autres installations pendant une installation active', () => {
  const html = renderScannerSetupHtml([
    { id: 'semgrep', label: 'Semgrep', purpose: 'SAST', installed: false },
    { id: 'gitleaks', label: 'Gitleaks', purpose: 'Secrets', installed: false }
  ], 'nonce', 'light', {
    semgrep: { state: 'installing', title: 'Installation', message: 'En cours' }
  });

  assert.match(html, /id="install-all" disabled/);
  assert.match(html, /data-install="gitleaks" disabled/);
  assert.match(html, /id="refresh" class="secondary" disabled/);
});
