'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

function finding(extra = {}) {
  return {
    id: 'semgrep:eval:routes/login.js:12',
    tool: 'Semgrep',
    ruleId: 'javascript.lang.security.detect-eval',
    title: 'Use of eval',
    severity: 'high',
    rawSeverity: 'HIGH',
    cwe: 'CWE-95',
    file: 'routes/login.js',
    absolutePath: 'C:/repo/routes/login.js',
    startLine: 12,
    startColumn: 2,
    triageStatus: 'new',
    ...extra
  };
}

/**
 * Scanner Details renders its cards from the scanner run, not from the flat
 * list the actions address. `flat` is what `model.findings` holds; `run` is what
 * the scanner reported. The gap between the two is the whole bug.
 */
function scannerDetailsHtml(run, flat = run, scannerName = 'Semgrep') {
  const model = buildDashboardModel(flat, [
    { tool: scannerName, status: 'completed', currentRun: { findings: run, resultCount: run.length } }
  ], { workspace: 'w' });
  model.activeScanner = scannerName;
  return renderDashboardHtml(model, 'nonce', 'scanner-details', 'light', {}, {});
}

/** `.page-findings` est rendue sur toutes les surfaces : il faut viser la bonne. */
function cardActions(html) {
  const page = html.slice(html.indexOf('class="page-scanner-details"'));
  const start = page.indexOf('class="finding-card-actions"');
  assert.ok(start >= 0, 'la carte scanner doit exposer ses actions');
  return page.slice(start, start + 900);
}

// ------------------------------------------------- carte non résolvable

test('actions : une carte absente de model.findings n’émet jamais l’index -1', () => {
  const run = [finding()];
  // Le finding a bien été rapporté par le scanner, mais il n’est plus dans la
  // liste que les actions adressent : c’est le cas qui rendait les deux boutons
  // totalement muets.
  const html = scannerDetailsHtml(run, [finding({ id: 'autre-finding', file: 'autre.js', absolutePath: 'C:/repo/autre.js', ruleId: 'autre', startLine: 99 })]);
  assert.doesNotMatch(html, /data-scanner-finding-index="-1"/, 'aucun index négatif ne doit sortir du rendu');
  assert.doesNotMatch(html, /data-finding-index="-1"/, 'ni sous l’ancien nom d’attribut');
  const actions = cardActions(html);
  // Le comportement honnête : les boutons existent toujours (le design ne
  // change pas) mais ils annoncent qu’ils ne peuvent pas agir.
  assert.match(actions, /action-open-file[^>]*disabled/);
  assert.match(actions, /action-open-details[^>]*disabled/);
  assert.match(actions, /title="[^"]*rapport courant[^"]*"/);
});

test('actions : un finding sans id est résolu par sa localisation, jamais par le rang 0', () => {
  const located = finding({ id: undefined });
  const other = finding({ id: undefined, file: 'routes/admin.js', absolutePath: 'C:/repo/routes/admin.js', ruleId: 'exec', startLine: 40, title: 'Command injection' });
  // `undefined === undefined` faisait pointer toutes les cartes sur le rang 0.
  const html = scannerDetailsHtml([other], [located, other]);
  assert.match(html, /data-scanner-finding-index="1"/, 'la carte doit viser sa propre position, pas la première');
  assert.doesNotMatch(html, /data-scanner-finding-index="0"/);
});

test('actions : un finding présent est adressé par sa position réelle', () => {
  const first = finding();
  const second = finding({ id: 'gitleaks:key:config.js:3', tool: 'Semgrep', file: 'config.js', absolutePath: 'C:/repo/config.js', startLine: 3, title: 'Secret' });
  const html = scannerDetailsHtml([second], [first, second]);
  assert.match(html, /data-scanner-finding-index="1"/);
  const actions = cardActions(html);
  assert.doesNotMatch(actions, /action-open-file[^>]*disabled/);
});

// ------------------------------------------------------- double routage

test('actions : les boutons Scanner Details échappent au routeur global des findings', () => {
  const html = scannerDetailsHtml([finding()]);
  const actions = cardActions(html);
  // `[data-finding-index]` est écouté globalement pour Findings / Priority /
  // Investigate. Tant que ces boutons le portaient, un clic partait deux fois :
  // « Open code » ouvrait le panneau Détails avant le fichier.
  assert.doesNotMatch(actions, /data-finding-index=/, 'aucun bouton de carte scanner ne doit porter l’attribut global');
  assert.match(actions, /action-open-file" data-scanner-finding-index="0"/);
  assert.match(actions, /action-open-details" data-scanner-finding-index="0"/);
});

test('actions : le routeur de la surface Scanner Details lit le nouvel attribut et refuse un index invalide', () => {
  const source = src('dashboard.js');
  const delegated = source.match(/const pageScannerDetails = document\.querySelector\('\.page-scanner-details'\);[\s\S]*?\n    \}/)[0];
  assert.match(delegated, /button\.dataset\.scannerFindingIndex/);
  assert.doesNotMatch(delegated, /button\.dataset\.findingIndex/, 'plus aucune lecture de l’attribut global sur cette surface');
  // Un index vide ne doit jamais devenir 0 par `Number('')`.
  assert.match(delegated, /!== ''/);
  assert.match(delegated, /Number\.isInteger\(idx\) && idx >= 0/);
});

// ---------------------------------------- index absent jamais converti en 0

test('actions : l’aparté de la page Findings n’envoie rien quand l’index est absent', () => {
  const source = src('dashboard.js');
  for (const button of ['previewDetails', 'previewCode']) {
    const handler = source.match(new RegExp(`${button}\\?\\.addEventListener\\('click'[\\s\\S]*?\\}\\);`))[0];
    assert.match(handler, /!== ''/, `${button} : un index vide doit être refusé avant Number()`);
    assert.match(handler, /index >= 0/, `${button} : un index négatif doit être refusé`);
  }
});

// ------------------------------------------------- garde côté extension

test('actions : l’extension refuse un index hors bornes au lieu de l’avaler', () => {
  const extension = src('extension.js');
  assert.match(extension, /findingAt\(index\) \{[\s\S]*?index >= 0 && index < findings\.length/);
  assert.match(extension, /if \(message\?\.type === 'finding' && Number\.isInteger\(message\.index\)\) \{\s*\n\s*const finding = this\.findingAt\(message\.index\);/);
  assert.match(extension, /if \(message\?\.type === 'findingCode' && Number\.isInteger\(message\.index\)\) \{\s*\n\s*const finding = this\.findingAt\(message\.index\);/);
  // Une action qui ne retrouve pas son finding le dit.
  assert.match(extension, /reportUnresolvableFinding\(\)/);
  assert.match(extension, /n’est plus dans le rapport courant/);
});

// --------------------------------- surfaces voisines strictement inchangées

test('actions : la page Findings, Priority Findings et Investigate gardent leur câblage', () => {
  const model = buildDashboardModel([finding(), finding({ id: 'b', file: 'b.js', absolutePath: 'C:/repo/b.js', startLine: 4 })], []);
  const html = renderDashboardHtml(model, 'nonce', 'findings', 'light', {}, {});
  // Cartes de la page Findings : attribut global conservé, index positionnels.
  assert.match(html, /class="finding-open" data-finding-index="0"/);
  assert.match(html, /class="finding-open" data-finding-index="1"/);
  assert.match(html, /data-finding-code-index="0"/);
  assert.match(html, /Investigate →/);
  assert.match(html, /id="preview-code"/);
  assert.match(html, /id="preview-details"/);
  // Le routeur global reste armé pour ces surfaces.
  const source = src('dashboard.js');
  assert.match(source, /document\.querySelectorAll\('\[data-finding-index\]'\)\.forEach/);
  assert.match(source, /document\.querySelectorAll\('\[data-finding-code-index\]'\)\.forEach/);
  // Priority Findings et la ligne dynamique continuent de porter l’attribut global.
  assert.match(source, /class="priority-finding[\s\S]*?data-finding-index="\$\{model\.findings\.indexOf\(finding\)\}"/);
  assert.match(source, /<button class="quiet-action" data-finding-index="\$\{index\}">Investigate<\/button>/);
});

test('actions : le trafic HTTP et Fix & Verify gardent leurs propres messages', () => {
  const source = src('dashboard.js');
  const delegated = source.match(/const pageScannerDetails = document\.querySelector\('\.page-scanner-details'\);[\s\S]*?\n    \}/)[0];
  assert.match(delegated, /type: 'applyFindingFix'/);
  assert.match(delegated, /button\.dataset\.scenarioIndex/);
  assert.match(delegated, /type: 'openFullHttpRequest'/);
  assert.match(delegated, /type: 'replayHttpTraffic'/);
  const extension = src('extension.js');
  for (const contract of ['findingFromTraffic', 'httpTrafficDetails', 'replayHttpTraffic', 'openFullHttpRequest']) {
    assert.match(extension, new RegExp(`message\\?\\.type === '${contract}'`), `${contract} doit rester câblé`);
  }
});
