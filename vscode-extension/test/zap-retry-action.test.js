'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { availability, engineState, createRun, transitionRun, RUN_KIND, RUN_STATUS } = require('../src/dynamic-runtime');

const TARGET = 'http://192.168.222.132:3000';
const TIMEOUT_ERROR = 'L’étape spider du scan ZAP local a dépassé 900 secondes (arrêtée à 64 %).';
const src = (name) => fs.readFileSync(path.join(__dirname, '..', 'src', name), 'utf8');

/** L'état d'exécution publié pour ZAP, tel que la page le reçoit. */
function runtime({ installed = true, reason = '', run = null } = {}) {
  return {
    engines: {
      zap: engineState('zap', {
        kind: RUN_KIND.SCAN,
        availability: availability({ installed, version: installed ? 'local' : '', reason }),
        run
      })
    }
  };
}

/** La carte Dynamic Security, rendue avec l'état ZAP demandé. */
function card(scanners, options = {}) {
  const html = renderDashboardHtml(buildDashboardModel([], scanners, {
    scanStatus: 'completed', dynamicTargetUrl: TARGET, ...options
  }), 'n', 'dynamic');
  const start = html.indexOf('dynamic-tool-card zap');
  const actions = html.indexOf('class="dynamic-actions"', start);
  return { html, actions: html.slice(actions, html.indexOf('</div>', actions)) };
}

const FAILED_RUN = [{ tool: 'ZAP', status: 'failed', mode: 'baseline', error: TIMEOUT_ERROR, completedAt: '2026-09-12T10:00:00.000Z' }];

test('READY avec un run précédent en échec propose de relancer l’analyse', () => {
  const { actions } = card(FAILED_RUN, { dynamicRuntime: runtime() });

  // L'action principale est l'analyse, et son libellé dit qu'on la reprend.
  assert.match(actions, /<button class="primary" data-command="securityCenter\.scanZap" aria-label="Lancer ZAP" >Réessayer l’analyse<\/button>/);
  // La configuration ne prend pas la place de l'analyse.
  assert.doesNotMatch(actions, /<button class="primary" data-command="securityCenter\.configureZap">/);
  // Les actions secondaires restent celles de la carte.
  assert.match(actions, /<button class="secondary" data-command="securityCenter\.configureZap">Configuration<\/button>/);
  assert.match(actions, /data-command="securityCenter\.openZapFindings">Voir les findings ZAP/);
});

test('l’échec précédent reste visible comme information, sans bloquer la relance', () => {
  const { html, actions } = card(FAILED_RUN, { dynamicRuntime: runtime() });

  // La cause réelle est toujours affichée par la carte.
  assert.match(html, /L’étape spider du scan ZAP local a dépassé 900 secondes \(arrêtée à 64 %\)/);
  assert.match(html, /class="tool-note error"/);
  // Et l'analyse reste lançable.
  assert.match(actions, /data-command="securityCenter\.scanZap"/);
});

test('un problème de configuration courant — et lui seul — remplace l’action d’analyse', () => {
  const unusable = runtime({ installed: false, reason: 'Ni ZAP local (avec Java) ni le moteur Docker ne sont disponibles.' });
  const { actions, html } = card(FAILED_RUN, { dynamicRuntime: unusable });

  assert.match(actions, /<button class="primary" data-command="securityCenter\.configureZap">Configurer ZAP<\/button>/);
  assert.doesNotMatch(actions, /data-command="securityCenter\.scanZap"/);
  // La raison courante est celle que la carte affiche, pas l'échec du run.
  assert.match(html, /Ni ZAP local \(avec Java\) ni le moteur Docker ne sont disponibles/);
});

test('une disponibilité non encore mesurée ne vaut pas indisponible : l’analyse reste offerte', () => {
  const { actions } = card(FAILED_RUN);

  assert.match(actions, /data-command="securityCenter\.scanZap"[^>]*>Réessayer l’analyse</);
  assert.doesNotMatch(actions, /<button class="primary" data-command="securityCenter\.configureZap">/);
});

test('sans run précédent, l’action garde son libellé de lancement', () => {
  const { actions } = card([], { dynamicRuntime: runtime() });

  assert.match(actions, /data-command="securityCenter\.scanZap"[^>]*>Run security scan</);
  assert.doesNotMatch(actions, /Réessayer l’analyse/);
});

test('un run terminé normalement propose de lancer, pas de réessayer', () => {
  const { actions } = card([{ tool: 'ZAP', status: 'completed', mode: 'baseline', completedAt: '2026-09-12T10:00:00.000Z' }], { dynamicRuntime: runtime() });

  assert.match(actions, /data-command="securityCenter\.scanZap"[^>]*>Run security scan</);
});

test('une analyse en cours désactive l’action au lieu de la renommer', () => {
  for (const status of ['running', 'refreshing']) {
    const { actions } = card([{ tool: 'ZAP', status, mode: 'baseline' }], { dynamicRuntime: runtime() });
    assert.match(actions, /data-command="securityCenter\.scanZap" aria-label="Lancer ZAP" disabled aria-busy="true">Analyse ZAP en cours…</, `statut ${status}`);
  }
});

test('un refus d’authentification courant garde sa propre action, qui est la bonne', () => {
  const refused = [{ tool: 'ZAP', status: 'failed', mode: 'active', error: 'ZAP login refusé : HTTP 401', completedAt: '2026-09-12T10:00:00.000Z' }];
  const { actions } = card(refused, {
    dynamicRuntime: runtime(),
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T09:00:00.000Z' }
  });

  // Le compte est bien le problème courant : c'est lui que la carte propose.
  assert.match(actions, /<button class="primary" data-command="securityCenter\.configureZapCredentials">Modifier le compte ZAP<\/button>/);
  assert.doesNotMatch(actions, /<button class="primary" data-command="securityCenter\.configureZap">Configurer ZAP<\/button>/);
});

test('un refus d’authentification devenu historique propose de relancer, compte à portée de main', () => {
  const refused = [{ tool: 'ZAP', status: 'failed', mode: 'active', error: 'ZAP login refusé : HTTP 401', completedAt: '2026-09-12T10:00:00.000Z' }];
  const { actions } = card(refused, {
    dynamicRuntime: runtime(),
    // Compte enregistré après ce scan : le refus ne porte plus sur ces identifiants.
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T11:00:00.000Z' }
  });

  assert.match(actions, /<button class="primary" data-command="securityCenter\.scanZap"[^>]*>Réessayer l’analyse<\/button><button class="secondary" data-command="securityCenter\.configureZapCredentials">Modifier le compte ZAP<\/button>/);
});

test('l’action de relance passe par la commande de scan existante, sans second chemin', () => {
  const extension = src('extension.js');
  // Le bouton demande la commande déjà enregistrée, qui confie le scan au pipeline.
  assert.match(extension, /registerCommand\('securityCenter\.scanZap'[\s\S]*?executeCommand\('securityCenter\.scanWorkspace', \['ZAP'\]\)/);
  // Et la webview est autorisée à la demander.
  assert.match(extension, /'securityCenter\.scanZap',/);
  // Le chemin « retry » générique mène au même endroit.
  assert.match(extension, /if \(tool === 'ZAP'\) return vscode\.commands\.executeCommand\('securityCenter\.scanZap'\);/);
});

test('une exécution en cours dans le socle commun n’est pas confondue avec un échec passé', () => {
  // Un run vivant : le socle rend RUNNING, et la carte ne propose pas de relance.
  const live = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), {
    status: RUN_STATUS.RUNNING, phase: 'Moteur Local · Spidering / baseline 40 %', progress: 40
  });
  const state = runtime({ run: live });
  assert.equal(state.engines.zap.status, RUN_STATUS.RUNNING);

  // Un run en échec est terminal : le socle retombe sur READY, jamais UNAVAILABLE.
  const failed = transitionRun(createRun({ engine: 'zap', kind: RUN_KIND.SCAN, target: TARGET }), {
    status: RUN_STATUS.FAILED, errorReason: TIMEOUT_ERROR
  });
  assert.equal(runtime({ run: failed }).engines.zap.status, RUN_STATUS.READY);
});

test('la décision est prise sur l’état mesuré, pas sur l’issue du run précédent', () => {
  const dashboard = src('dashboard.js');
  assert.match(dashboard, /const zapEngineUnusable = zapRuntime \? zapRuntime\.status === 'UNAVAILABLE' : false;/);
  assert.match(dashboard, /zapPreviousRunFailed \? 'Réessayer l’analyse' : 'Run security scan'/);
  // L'ancienne condition — un run en échec remplaçait l'analyse par la configuration — a disparu.
  assert.doesNotMatch(dashboard, /zapScanner\?\.status === 'failed' \? '<button class="primary" data-command="securityCenter\.configureZap">/);
});
