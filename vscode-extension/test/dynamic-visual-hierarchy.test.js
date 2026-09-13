'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8');

const render = (overrides = {}) => renderDashboardHtml(
  buildDashboardModel([], [], {
    workspace: 'demo',
    dynamicTargetUrl: 'http://192.168.222.132:3000',
    dynamicTargetState: 'online',
    dynamicTargetMode: 'local',
    dynamicTargetRemoteAuthorized: false,
    dynamicTargetEvidence: { source: 'probe', at: '2026-09-10T11:41:00.000Z', statusCode: 200 },
    ...overrides
  }),
  'nonce', 'dynamic', 'light', {}, {}
);

/**
 * Le fragment de la carte Cible, sans le reste de la page.
 *
 * La fin est cherchée à partir du début de la carte : « dynamic-workflow »
 * apparaît d'abord dans la feuille de style, bien avant le balisage.
 */
const targetCard = (html) => {
  const start = html.indexOf('class="dynamic-section dynamic-target"');
  assert.ok(start > 0, 'carte Cible introuvable dans la page rendue');
  return html.slice(start, html.indexOf('dynamic-workflow', start));
};

test('Dynamic Security : l’état de connectivité porte sa propre classe d’état', () => {
  for (const state of ['online', 'refused', 'unreachable', 'timeout', 'dns-error', 'tls-error', 'unknown']) {
    const card = targetCard(render({ dynamicTargetState: state, dynamicTargetEvidence: null }));
    assert.match(card, new RegExp(`class="target-state ${state}"`), `pastille sans état : ${state}`);
    assert.match(card, new RegExp(`class="target-connectivity ${state}"`), `encadré sans état : ${state}`);
  }
});

test('Dynamic Security : la pastille d’état est traitée, pas laissée en texte secondaire', () => {
  // Sans règle propre, `.target-state` héritait du span gris de 10 px de
  // l'en-tête de section — c'est ce qui rendait « En ligne » invisible.
  assert.match(source, /\.dynamic-section-head > span\.target-state,\s*\n\s*\.dynamic-section-head > span\.burp-connection \{/);
  assert.match(source, /\.dynamic-section-head > span\.target-state\.online,\s*\n\s*\.dynamic-section-head > span\.burp-connection\.connected \{/);
  // Compacte, jamais étirée en bannière quand l'en-tête passe en colonne.
  assert.match(source, /align-self: flex-start;/);
});

test('Dynamic Security : le vert ne sert qu’aux états sains, le rouge qu’aux échecs', () => {
  const online = targetCard(render({ dynamicTargetState: 'online' }));
  assert.match(online, /class="target-connectivity online"/);
  assert.ok(!online.includes('target-scope blocked'), 'une cible locale n’est jamais marquée bloquée');

  // Une cible distante non confirmée est le seul cas où la portée vire au rouge.
  const blocked = targetCard(render({ dynamicTargetMode: 'remote', dynamicTargetRemoteAuthorized: false }));
  assert.match(blocked, /class="target-scope blocked"/);
  const authorized = targetCard(render({ dynamicTargetMode: 'remote', dynamicTargetRemoteAuthorized: true }));
  assert.match(authorized, /class="target-scope "/);

  // Les couleurs de la charte sont mélangées au texte pour rester lisibles sur
  // leur propre teinte : mesuré, le vert brut tombait à 2,88:1.
  assert.match(source, /--sc-on-success: color-mix\(in srgb, var\(--sc-success\) 65%, var\(--sc-text\)\)/);
  assert.match(source, /--sc-on-critical: color-mix\(in srgb, var\(--sc-critical\) 80%, var\(--sc-text\)\)/);
});

test('Dynamic Security : la valeur prime visiblement sur son étiquette', () => {
  // Étiquette 9 px, valeur 14 px : « Automatic » doit dominer « ENGINE ».
  assert.match(source, /\.target-summary span, \.tool-facts span \{ display: block; color: var\(--sc-muted\); font-size: 9px;/);
  assert.match(source, /\.target-summary strong, \.tool-facts strong \{ margin-top: 4px; font-size: 14px; font-weight: 800;/);
  assert.match(source, /\.target-url-field input \{ font-size: 13\.5px; font-weight: 650; \}/);
  assert.match(source, /\.tool-card-head h2 \{ font-size: 16\.5px; font-weight: 800; \}/);
  // Le sous-titre d'un outil reste secondaire derrière son nom.
  assert.match(source, /\.tool-card-head p \{ color: var\(--sc-muted\); font-weight: 650; \}/);
});

test('Dynamic Security : le code de réponse HTTP est affiché avec la preuve', () => {
  // `statusCode` arrivait dans le modèle sans jamais être rendu : l'état « En
  // ligne » n'était vérifiable nulle part sur la page.
  const card = targetCard(render());
  assert.match(card, /HTTP 200 · Vérifiée directement le/);
  // Aucun code inventé quand la sonde n'en rapporte pas.
  const withoutCode = targetCard(render({ dynamicTargetEvidence: { source: 'zap-scan', at: '2026-09-10T11:41:00.000Z' } }));
  assert.ok(!/HTTP\s+\d/.test(withoutCode), 'aucun code de réponse inventé');
  assert.match(withoutCode, /Confirmée par l’analyse ZAP le/);
});

test('Dynamic Security : une URL de cible occupe sa propre ligne dans les cartes d’outil', () => {
  const html = render();
  // Sur deux colonnes, une URL enfermée dans 150 px se coupait n'importe où.
  assert.equal((html.match(/class="fact-wide"><span>Target<\/span>/g) || []).length, 2, 'ZAP et Nuclei');
  assert.match(source, /\.tool-facts > div\.fact-wide \{ grid-column: 1 \/ -1; \}/);
  assert.match(source, /\.target-summary strong, \.tool-facts strong \{[^}]*\}/);
  // Le repli anti-débordement des valeurs longues est conservé.
  assert.match(source, /overflow-wrap: anywhere/);
});

test('Dynamic Security : les cartes ZAP et Nuclei restent côte à côte', () => {
  // La grille passe à deux colonnes dès 760 px ; rien dans ce lot ne la change.
  assert.match(source, /@media \(min-width: 760px\) \{ \.dynamic-status-grid \{ grid-template-columns: repeat\(2, minmax\(0,1fr\)\); \} \}/);
});
