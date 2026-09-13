'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { projectSnapshot, completeExecution, updateRefresh, beginRefresh, createExecution } = require('../src/security-snapshot');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

/** Remplace le contenu des chaînes et des commentaires par du vide. */
function stripCodeStrings(source) {
  let out = '';
  let quote = null;
  let comment = null;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (comment) {
      if (comment === 'line' && character === '\n') { comment = null; out += '\n'; }
      else if (comment === 'block' && character === '*' && next === '/') { comment = null; index += 1; }
      continue;
    }
    if (quote) {
      if (character === '\\') { index += 1; continue; }
      if (character === quote) { quote = null; out += quote === '`' ? '``' : "''"; }
      continue;
    }
    if (character === '/' && next === '/') { comment = 'line'; index += 1; continue; }
    if (character === '/' && next === '*') { comment = 'block'; index += 1; continue; }
    if (character === "'" || character === '"' || character === '`') { quote = character; continue; }
    out += character;
  }
  return out;
}

/** Extrait une fonction de `extension.js` et l'exécute dans une portée nue. */
function isolate(name, scope = {}) {
  const source = src('extension.js');
  const start = source.indexOf(`async function ${name}(`);
  assert.ok(start >= 0, `${name} introuvable`);
  const body = source.slice(start, source.indexOf('\n  }', start) + 4);
  const context = vm.createContext({ ...scope, console });
  const fn = vm.runInContext(`${body}; ${name};`, context);
  // La fonction réaffecte `currentDashboardOptions` : c'est la valeur du
  // contexte qui fait foi, pas l'objet passé en entrée.
  return { fn, context };
}

// --------------------------------------------------------- A. la cause racine

test('flux : persistDynamicWorkspace ne lève plus « workspace is not defined »', async () => {
  // Le symptôme exact rapporté : une notification « Security Center : workspace
  // is not defined ». La fonction lisait un identifiant qui n'existe que dans
  // une autre fonction, donc toute exécution levait une ReferenceError.
  let saved = 0;
  const { fn, context } = isolate('persistDynamicWorkspace', {
    currentDashboardOptions: { dynamicWorkspace: { inventory: [], coverage: {} } },
    dynamicWorkspaceState: (workspace) => ({ seen: Boolean(workspace) }),
    saveLocalScanCache: async () => { saved += 1; }
  });
  await fn();
  assert.equal(saved, 1, 'le cache doit être écrit');
  assert.deepEqual(context.currentDashboardOptions.dynamicWorkspaceState, { seen: true });
});

test('flux : sans workspace reconstruit, la persistance sort proprement', async () => {
  let saved = 0;
  const { fn } = isolate('persistDynamicWorkspace', {
    currentDashboardOptions: {},
    dynamicWorkspaceState: () => ({}),
    saveLocalScanCache: async () => { saved += 1; }
  });
  await fn();
  assert.equal(saved, 0, 'rien à persister, et surtout aucune exception');
});

test('flux : la clôture de campagne ne peut plus faire échouer le scanner', () => {
  const closing = src('extension.js').match(/async function finishZapCampaign\([\s\S]*?\n {2}\}/)[0];
  // Le bookkeeping de campagne s'exécute entre l'affectation du statut et la
  // mise à jour du snapshot, sur le chemin succès ET sur le chemin échec.
  assert.match(closing, /try \{/);
  assert.match(closing, /catch \(error\) \{[\s\S]*?scanLog\.appendLine/);
  assert.match(closing, /rebuildDynamicWorkspace\(\);/);
  assert.match(closing, /await persistDynamicWorkspace\(\);/);
});

test('flux : toute fonction qui lit « workspace » le déclare elle-même', () => {
  // Commentaires et chaînes retirés, puis découpage par fonction : aucune ne
  // doit lire un `workspace` qu'elle n'a pas déclaré — la faute exacte.
  // Un vrai petit scanner : un remplacement par expression régulière se
  // désynchronise sur une apostrophe au milieu d'une phrase et fait passer du
  // texte pour du code.
  const stripped = stripCodeStrings(src('extension.js'));
  const blocks = stripped.split(/(?:async\s+)?function\s+/).slice(1);
  const offenders = blocks
    .map((block) => ({ name: (block.match(/^[A-Za-z0-9_$]+/) || ['?'])[0], block: block.split(/(?:async\s+)?function\s+/)[0] }))
    .filter(({ block }) => /(?:^|[^.\w$])!?workspace\s*[),.;\]]/.test(block))
    .filter(({ block }) => !/(?:const|let|var)\s+workspace\s*=/.test(block))
    .map(({ name }) => name);
  assert.deepEqual(offenders, [], `fonctions lisant un workspace non déclaré : ${offenders.join(', ')}`);
});

// ------------------------------------------------- B. consolidation du scan

test('flux : les résultats de plusieurs scanners atterrissent dans model.findings', () => {
  const findings = [
    { id: 'semgrep:1', tool: 'Semgrep', title: 'eval', severity: 'high', file: 'a.js', absolutePath: 'C:/w/a.js', startLine: 1 },
    ...Array.from({ length: 37 }, (_, i) => ({ id: `gitleaks:${i}`, tool: 'Gitleaks', title: `secret ${i}`, severity: 'critical', file: 'b.js', absolutePath: 'C:/w/b.js', startLine: i })),
    { id: 'trivy:1', tool: 'Trivy', title: 'CVE', severity: 'medium', file: 'package.json', absolutePath: 'C:/w/package.json', startLine: 0 },
    ...Array.from({ length: 280 }, (_, i) => ({ id: `sonar:${i}`, tool: 'SonarQube', title: `issue ${i}`, severity: 'low', file: 'c.js', absolutePath: 'C:/w/c.js', startLine: i }))
  ];
  const execution = createExecution({ executionId: 'e1', requestedTools: ['Semgrep', 'Gitleaks', 'Trivy', 'SonarQube', 'ZAP'], allTools: ['Semgrep', 'Gitleaks', 'Trivy', 'SonarQube', 'ZAP'] });
  let snapshot = beginRefresh({ version: 3, resultSets: {}, refresh: {} }, execution);
  const statuses = [
    { tool: 'Semgrep', status: 'completed' }, { tool: 'Gitleaks', status: 'completed' },
    { tool: 'Trivy', status: 'completed' }, { tool: 'SonarQube', status: 'completed' },
    { tool: 'ZAP', status: 'failed', error: 'cible injoignable' }
  ];
  for (const status of statuses) {
    snapshot = updateRefresh(snapshot, status.tool, status.status, {
      findings: findings.filter((f) => f.tool === status.tool), durationMs: 10, completedAt: new Date().toISOString(), error: status.error
    });
  }
  snapshot = completeExecution(snapshot, execution, findings, statuses);
  const projection = projectSnapshot(snapshot);

  // L'invariant qui manquait : la page globale doit voir ce que les pages
  // Scanner Details voient.
  assert.equal(projection.findings.length, 319, 'la liste plate agrège tous les scanners');
  const model = buildDashboardModel(projection.findings, projection.scanners, {});
  assert.equal(model.findings.length, 319);
  for (const [tool, count] of [['Semgrep', 1], ['Gitleaks', 37], ['Trivy', 1], ['SonarQube', 280]]) {
    const scanner = projection.scanners.find((s) => s.tool === tool);
    assert.equal(scanner.currentRun.findings.length, count, `${tool} : Scanner Details`);
    assert.equal(model.findings.filter((f) => f.tool === tool).length, count, `${tool} : Findings globale`);
  }
  // Chaque finding d'un run est adressable depuis la liste plate.
  for (const scanner of projection.scanners) {
    for (const finding of scanner.currentRun.findings) {
      assert.ok(model.findings.some((candidate) => candidate.id === finding.id), `${finding.id} absent de la liste plate`);
    }
  }
});

test('flux : aucun scanner ne reste « running » une fois l’exécution terminée', () => {
  const execution = createExecution({ executionId: 'e2', requestedTools: ['Semgrep', 'ZAP'], allTools: ['Semgrep', 'ZAP'] });
  let snapshot = beginRefresh({ version: 3, resultSets: {}, refresh: {} }, execution);
  const statuses = [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'ZAP', status: 'failed', error: 'ZAP indisponible' }
  ];
  snapshot = updateRefresh(snapshot, 'Semgrep', 'completed', { findings: [], durationMs: 5, completedAt: new Date().toISOString() });
  snapshot = updateRefresh(snapshot, 'ZAP', 'failed', { error: 'ZAP indisponible', durationMs: 5 });
  snapshot = completeExecution(snapshot, execution, [], statuses);
  const projection = projectSnapshot(snapshot);
  assert.equal(projection.activeExecution, null, 'l’exécution est close');
  for (const scanner of projection.scanners) {
    assert.notEqual(scanner.status, 'running', `${scanner.tool} reste bloqué`);
  }
  const zap = projection.scanners.find((s) => s.tool === 'ZAP');
  assert.equal(zap.status, 'failed');
  assert.equal(zap.error, 'ZAP indisponible', 'l’erreur réelle est conservée');
});

// ------------------------------- C. la page globale rend ce qui est consolidé

test('flux : la page Findings globale affiche les findings consolidés', () => {
  const findings = [
    { id: 'semgrep:1', tool: 'Semgrep', title: 'Unsafe eval', severity: 'high', rawSeverity: 'HIGH', ruleId: 'js.eval', file: 'a.js', absolutePath: 'C:/w/a.js', startLine: 1 },
    { id: 'gitleaks:1', tool: 'Gitleaks', title: 'API key', severity: 'critical', rawSeverity: 'CRITICAL', ruleId: 'generic-api-key', file: 'b.js', absolutePath: 'C:/w/b.js', startLine: 2 }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], {}), 'nonce', 'findings', 'light', {}, {});
  assert.match(html, /Unsafe eval/);
  assert.match(html, /API key/);
  assert.doesNotMatch(html, /Aucune vulnérabilité à afficher/);
  assert.match(html, /data-finding-index="0"/);
  assert.match(html, /data-finding-index="1"/);
});
