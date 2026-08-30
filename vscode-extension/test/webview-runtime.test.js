'use strict';

/**
 * Ce fichier teste ce que les tests structurels ne voyaient pas.
 *
 * Les tests existants verifiaient la presence de chaines dans le HTML rendu :
 * un bouton, une commande, une classe. Ils passaient tous alors que la page
 * Security Pipeline etait morte a l'ouverture, parce qu'un `});` en trop
 * empechait TOUT son script d'etre analyse — onglets, etapes, politique et
 * navigation partagee compris. Le HTML contenait bien les boutons ; aucun
 * n'etait cable.
 *
 * On verifie donc ici le comportement : le script s'analyse, l'API du webview
 * n'est acquise qu'une fois, et un clic produit reellement le message que le
 * handler de l'extension attend.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderScanHistoryHtml } = require('../src/scan-history-page');
const { renderAuditLogHtml } = require('../src/audit');
const { buildTrendReport, renderTrendReportHtml } = require('../src/trends');
const { renderPipelinePageHtml, TABS } = require('../src/pipeline-page');
const { renderDeliveryPageHtml } = require('../src/delivery-page');
const { renderIntegrationPageHtml } = require('../src/integrations-page');
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');
const { renderFindingDetailsHtml } = require('../src/finding-details');
const { renderScanComparisonHtml } = require('../src/scan-comparison');
const { deliveryStatusFrom } = require('../src/jenkins');

const trendReport = buildTrendReport([], [], 90, new Date('2026-08-03T00:00:00Z'));
const emptyModel = buildDashboardModel([], []);

/** Toute page de Security Center qui embarque un script. */
const RENDERED_PAGES = [
  ['Dashboard', () => renderDashboardHtml(emptyModel, 'n', 'full', 'light')],
  ['Findings', () => renderDashboardHtml(emptyModel, 'n', 'findings', 'light')],
  ['Scans', () => renderDashboardHtml(emptyModel, 'n', 'scans', 'light')],
  ['Scanner Details', () => renderDashboardHtml(emptyModel, 'n', 'scanner-details', 'light')],
  ['Dynamic Security', () => renderDashboardHtml(emptyModel, 'n', 'dynamic', 'light')],
  ['Analytics', () => renderDashboardHtml(emptyModel, 'n', 'analytics', 'light')],
  ['Burp Settings', () => renderDashboardHtml(emptyModel, 'n', 'burp-settings', 'light')],
  ['Sidebar', () => renderDashboardHtml(emptyModel, 'n', 'sidebar', 'light')],
  ['Scan History', () => renderScanHistoryHtml([], [], '', 'n', 'light')],
  ['Compare Scans', () => renderScanComparisonHtml([], 'n', 'light')],
  ['Audit Journal', () => renderAuditLogHtml([], 'n', 'light')],
  ['Trends & MTTR', () => renderTrendReportHtml(trendReport, 'n', 'light')],
  ['Security Pipeline', () => renderPipelinePageHtml({ tab: 'pipeline' }, 'n', 'light')],
  ['Security Delivery', () => renderDeliveryPageHtml(deliveryStatusFrom({ configured: false }), 'n', 'light')],
  ['Integrations', () => renderIntegrationPageHtml({}, 'n', 'light')],
  ['Scanner Configuration', () => renderScannerSetupHtml([], 'n', 'light')],
  ['Finding Details', () => renderFindingDetailsHtml({ tool: 'ZAP', title: 'X', rawSeverity: 'LOW', ruleId: 'r' }, 'n', {})]
];

/** Le contenu de la balise script de la page, tel que le navigateur le recevrait. */
function scriptOf(html) {
  const open = html.indexOf('<script');
  if (open < 0) return null;
  return html.slice(html.indexOf('>', open) + 1, html.lastIndexOf('</script>'));
}

// ============================================ le script doit etre analysable

test('le script de chaque page est syntaxiquement analysable', () => {
  for (const [name, render] of RENDERED_PAGES) {
    const code = scriptOf(render());
    assert.ok(code && code.trim().length, `${name} : aucun script`);
    // Une SyntaxError ici veut dire que la page s'ouvre mais qu'aucun bouton,
    // onglet ou item de navigation ne repond.
    assert.doesNotThrow(() => new vm.Script(code),
      `${name} : le script ne s analyse pas — toute la page serait inerte`);
  }
});

test('chaque page tient dans une seule acquisition de l API du webview', () => {
  // `acquireVsCodeApi()` leve au second appel dans un meme webview.
  for (const [name, render] of RENDERED_PAGES) {
    const html = render();
    const calls = (html.match(/acquireVsCodeApi\(\)/g) || []).length;
    const guards = (html.match(/window\.__scShellApi\s*(\|\||=)/g) || []).length;
    assert.ok(calls >= 1, `${name} : n acquiert jamais l API`);
    if (calls > 1) {
      assert.ok(guards >= calls, `${name} : ${calls} acquisitions non gardees`);
    }
  }
});

// ================================ un clic doit produire le message attendu

/** Execute le script d'une page dans un DOM minimal et collecte les messages. */
function runPage(html, { clickSelector } = {}) {
  const posted = [];
  const listeners = new Map();
  const nodes = [];
  const makeNode = (attrs = {}) => {
    const node = {
      dataset: attrs.dataset || {},
      className: attrs.className || '',
      style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      getAttribute: (k) => (attrs[k] === undefined ? null : attrs[k]),
      setAttribute() {}, appendChild() {}, remove() {}, focus() {}, scrollIntoView() {},
      addEventListener(type, fn) { listeners.set(node + ':' + type, fn); node['on' + type] = fn; },
      querySelectorAll: () => [], querySelector: () => null,
      closest: () => null, innerHTML: '', textContent: '', value: '', checked: false,
      hidden: false, type: 'button', children: [], options: []
    };
    nodes.push(node);
    return node;
  };
  const matching = [];
  const doc = {
    body: makeNode(), documentElement: makeNode(),
    createElement: () => makeNode(),
    getElementById: () => makeNode(),
    querySelector: () => makeNode(),
    querySelectorAll(sel) {
      const list = [];
      if (clickSelector && sel === clickSelector) {
        const n = makeNode({ dataset: clickSelector.includes('data-tab') ? { tab: 'correlations' } : {} });
        matching.push(n);
        list.push(n);
      }
      return list;
    },
    addEventListener() {}
  };
  const sandbox = {
    console, JSON, Date, Math, Number, String, Array, Object, Set, Map, RegExp, isNaN, parseInt, parseFloat,
    document: doc,
    window: { addEventListener() {}, setInterval() {}, setTimeout() {}, matchMedia: () => ({ matches: false }) },
    acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(m), getState() {}, setState() {} }),
    setInterval() {}, setTimeout() {}
  };
  sandbox.window.document = doc;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  // Les stubs DOM sont volontairement partiels : on veut savoir si le cablage
  // s'execute, pas re-implementer un navigateur.
  try { vm.runInContext(scriptOf(html), sandbox, { timeout: 5000 }); } catch { /* stubs partiels */ }
  return { posted, matching };
}

test('un clic sur un onglet du pipeline émet le message que l extension attend', () => {
  const html = renderPipelinePageHtml({ tab: 'pipeline' }, 'n', 'light');
  const { posted, matching } = runPage(html, { clickSelector: '[data-tab]' });
  assert.ok(matching.length, 'le script doit parcourir les onglets');
  const tab = matching[0];
  assert.equal(typeof tab.onclick, 'function', 'chaque onglet doit etre cable au clic');
  // On declenche le handler reellement installe par la page, puis on verifie le
  // message recu cote extension. C'est ce chemin complet qui etait rompu.
  tab.onclick();
  assert.equal(posted.length, 1, 'un clic doit produire exactement un message');
  assert.deepEqual(JSON.parse(JSON.stringify(posted[0])), { type: 'tab', tab: 'correlations' },
    'le message ne correspond pas a ce que le handler onDidReceiveMessage attend');
});

test('chaque onglet du pipeline existe et rend un contenu distinct', () => {
  // Regression : ils etaient tous injoignables tant que le script ne s analysait pas.
  const ids = TABS.map(([id]) => id);
  // La liste est derivee du registre plutot que figee : un onglet ajoute doit
  // etre couvert par ce test au lieu de le casser sur un simple comptage.
  for (const required of ['pipeline', 'correlations', 'reachability', 'priorities', 'policy', 'supply-chain']) {
    assert.ok(ids.includes(required), `${required} doit rester un onglet du pipeline`);
  }
  assert.equal(new Set(ids).size, ids.length, 'aucun identifiant d onglet duplique');
  const seen = new Set();
  for (const [id] of TABS) {
    const html = renderPipelinePageHtml({ tab: id }, 'n', 'light');
    const section = html.slice(html.indexOf('<section>'), html.indexOf('</main>'));
    assert.ok(section.length > 50, `${id} ne rend aucun contenu`);
    assert.match(html, new RegExp(`data-tab="${id}"[^>]*aria-current="true"`), `${id} n est pas marque courant`);
    assert.match(html, /class="sc-internal-nav"/, `${id} a perdu le cadre partage`);
    seen.add(section);
  }
  assert.equal(seen.size, TABS.length, 'deux onglets rendent le meme contenu');
});

test('le pipeline garde tous ses contrats de message métier', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'pipeline-page.js'), 'utf8');
  for (const contract of [
    /postMessage\(\{type:'tab',tab:b\.dataset\.tab\}\)/,
    /postMessage\(\{type:'action',action:b\.dataset\.action/,
    /postMessage\(\{type:'stage',stage:el\.dataset\.stage\}\)/,
    /postMessage\(\{type:'finding',index:Number\(b\.dataset\.findingIndex\)\}\)/,
    /postMessage\(\{type:'clusterSource'/,
    /postMessage\(\{ type: 'companion' \}\)/
  ]) {
    assert.match(source, contract, 'un contrat de message du pipeline a disparu');
  }
});

// ================================ ouverture sans backend (regression §6)

test('Audit et Tendances créent leur panneau avant d appeler le backend', () => {
  // Regression : le panneau naissait a l'interieur du `try`, APRES l'await. Un
  // backend injoignable — le cas courant en local — faisait echouer l'await, la
  // page ne s'ouvrait jamais et l'utilisateur ne voyait qu'une notification.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  for (const [command, panelId, fetchCall] of [
    ['securityCenter.showAuditLog', 'securityCenter.auditLog', 'listAuditEvents('],
    ['securityCenter.showTrends', 'securityCenter.trends', 'listScans(']
  ]) {
    const start = source.indexOf(`registerCommand('${command}'`);
    assert.ok(start > 0, `${command} introuvable`);
    const body = source.slice(start, source.indexOf('}));', start));
    const panelAt = body.indexOf(panelId);
    const fetchAt = body.indexOf(fetchCall);
    assert.ok(panelAt > 0 && fetchAt > 0, `${command} : panneau ou appel backend introuvable`);
    assert.ok(panelAt < fetchAt,
      `${command} : le panneau doit etre cree avant l appel au backend, sinon la page disparait quand il est injoignable`);
    assert.match(body, /backendError/, `${command} doit transmettre l erreur reelle a la page`);
  }
});

test('Audit et Tendances s ouvrent et montrent l erreur réelle sans backend', () => {
  const cases = [
    ['Audit', renderAuditLogHtml([], 'n', 'light', 'connect ECONNREFUSED 127.0.0.1:8765'), /connect ECONNREFUSED 127\.0\.0\.1:8765/],
    ['Trends', renderTrendReportHtml(trendReport, 'n', 'light', 'fetch failed'), /fetch failed/]
  ];
  for (const [name, html, realMessage] of cases) {
    assert.match(html, /<section class="backend-banner" role="alert">/, `${name} : pas d etat d erreur visible`);
    assert.match(html, realMessage, `${name} : le message reel du backend doit apparaitre`);
    assert.match(html, /class="sc-internal-nav"/, `${name} : le cadre doit rester`);
  }
  // Backend disponible : aucun bandeau, et surtout aucune donnee inventee.
  assert.doesNotMatch(renderAuditLogHtml([], 'n', 'light'), /<section class="backend-banner"/);
  assert.doesNotMatch(renderTrendReportHtml(trendReport, 'n', 'light'), /<section class="backend-banner"/);
});
