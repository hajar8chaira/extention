'use strict';

/**
 * Première utilisation d'un projet.
 *
 * Sans security-center.yml, le projet est NON CONFIGURÉ : aucune page ne crée le
 * fichier. Il naît d'un enregistrement explicite, avec exactement les choix de
 * l'utilisateur, puis reste la seule source de vérité de toutes les vues.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  PROJECT_STATE, readProjectConfiguration, saveProjectScanners, applyScannersToPolicyYaml
} = require('../src/project-configuration');
const { savePolicyGate, readPolicyGateConfig } = require('../src/policy-config');
const { parsePolicyYaml, validatePolicy } = require('../src/project-policy');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderScannerSetupHtml } = require('../src/scanner-setup-page');

function workspace(t, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-first-use-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
  return root;
}
const yamlPath = (root) => path.join(root, 'security-center.yml');
const commandBody = (source, command) => {
  const start = source.indexOf(`registerCommand('${command}'`);
  return source.slice(start, source.indexOf('registerCommand(', start + 20));
};
const dashboard = (projectConfiguration, scanners = []) =>
  renderDashboardHtml(buildDashboardModel([], scanners, { projectConfiguration }), 'n', 'full');
const coverage = (html) => {
  const match = html.match(/Scanner coverage<\/span><b>(\d+)%<\/b><\/div><strong>([^<]+)<\/strong>[\s\S]*?<small>([^<]*)<\/small>/);
  return match ? { percent: match[1], ratio: match[2], label: match[3] } : null;
};

// ------------------------------------------------------------ A / B

test('A — nouveau workspace sans YAML : non configuré, rien n’est créé', async (t) => {
  const root = workspace(t);
  const project = await readProjectConfiguration(root);
  assert.equal(project.state, PROJECT_STATE.NOT_CONFIGURED);
  assert.equal(project.message, 'Security Center n’est pas encore configuré pour ce projet.');
  assert.equal(fs.existsSync(yamlPath(root)), false);
  // Lire la configuration du Policy Gate ne crée pas non plus le fichier.
  await readPolicyGateConfig(root);
  assert.equal(fs.existsSync(yamlPath(root)), false);
});

test('A — ouvrir « Project Policy » ne crée plus security-center.yml', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const body = commandBody(source, 'securityCenter.openProjectPolicy');
  assert.doesNotMatch(body, /writeFile|template/, 'aucun fichier écrit en ouvrant la vue');
  assert.match(body, /Security Center n’est pas encore configuré pour ce projet/);
  assert.match(body, /securityCenter\.openScannerSetup/, 'le premier usage mène à la configuration dans l’UI');
  assert.match(body, /showTextDocument/, 'un fichier existant reste ouvert en vue avancée');
  // Aucun autre chemin de l'extension n'écrit le fichier projet.
  assert.doesNotMatch(source, /writeFile\([^)]*security-center\.ya?ml/);
});

test('B — Dashboard seul : bandeau premier usage, pas de « 0 / 0 » ni de fichier', async (t) => {
  const root = workspace(t);
  const html = dashboard(await readProjectConfiguration(root));
  assert.match(html, /data-project-state="not-configured"/);
  assert.match(html, /Security Center n’est pas encore configuré pour ce projet\./);
  assert.match(html, /data-command="securityCenter\.openScannerSetup">Configurer le projet</);
  assert.equal(coverage(html).label, 'Project not configured');
  assert.doesNotMatch(html, /No scanners configured/);
  assert.equal(fs.existsSync(yamlPath(root)), false);
});

// ------------------------------------------------------------ C / D / E

test('C → E — Semgrep + Gitleaks, puis Policy Gate, puis relecture : un seul fichier, source de vérité', async (t) => {
  const root = workspace(t);

  // C. Enregistrement explicite des scanners : le fichier est créé.
  const saved = await saveProjectScanners(root, ['Semgrep', 'Gitleaks']);
  assert.equal(saved.ok, true, saved.message);
  assert.equal(saved.created, true);
  const afterScanners = validatePolicy(parsePolicyYaml(fs.readFileSync(yamlPath(root), 'utf8')));
  assert.deepEqual(afterScanners.scanners, {
    Semgrep: true, Gitleaks: true, Trivy: false, 'OSV-Scanner': false, SonarQube: false, Snyk: false, ZAP: false
  }, 'seuls les scanners choisis sont activés, les autres explicitement désactivés');

  // D. Le Policy Gate met à jour le MÊME fichier, sans toucher aux scanners.
  const gate = await savePolicyGate(root, { failCritical: true, warnHigh: true, blockSecrets: true, requireSbom: true, requireProvenance: true });
  assert.equal(gate.ok, true, gate.message);
  const text = fs.readFileSync(yamlPath(root), 'utf8');
  const policy = validatePolicy(parsePolicyYaml(text));
  assert.deepEqual(policy.gate.failOnSeverity, ['CRITICAL']);
  assert.deepEqual(policy.gate.warnOnSeverity, ['HIGH']);
  assert.equal(policy.gate.blockSecrets, true);
  assert.equal(policy.gate.requireSbom, true);
  assert.equal(policy.supplyChain.requireProvenance, true);
  assert.equal(policy.scanners.Semgrep, true);
  assert.equal(policy.scanners.Trivy, false);
  assert.equal((text.match(/^scanners:/gm) || []).length, 1);

  // E. « Recharger VS Code » : tout est relu depuis le disque.
  const project = await readProjectConfiguration(root);
  assert.equal(project.state, PROJECT_STATE.CONFIGURED);
  assert.deepEqual(project.scanners.enabled, ['Semgrep', 'Gitleaks']);
  assert.equal(project.gateConfigured, true);
  const gateConfig = await readPolicyGateConfig(root);
  assert.deepEqual(gateConfig.gate.failOnSeverity, ['CRITICAL']);
  assert.equal(gateConfig.supplyChain.requireProvenance, true);

  const setup = renderScannerSetupHtml([], 'n', 'light', {}, null, null, null, {}, project);
  for (const tool of ['Semgrep', 'Gitleaks']) assert.match(setup, new RegExp(`data-project-scanner="${tool}" checked`));
  for (const tool of ['Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP']) assert.doesNotMatch(setup, new RegExp(`data-project-scanner="${tool}" checked`));

  const html = dashboard(project);
  assert.deepEqual(coverage(html), { percent: '0', ratio: '0 / 2', label: '2 configured · not scanned yet' });
  assert.doesNotMatch(html, /data-project-state="not-configured"/);
});

test('C — une sélection vide est refusée et ne crée rien', async (t) => {
  const root = workspace(t);
  const refused = await saveProjectScanners(root, []);
  assert.equal(refused.ok, false);
  assert.match(refused.message, /au moins un scanner/);
  assert.equal(fs.existsSync(yamlPath(root)), false);
  assert.equal((await saveProjectScanners(root, ['Inconnu'])).ok, false);
});

test('gate enregistré en premier : le fichier est créé sans inventer de choix de scanners', async (t) => {
  const root = workspace(t);
  const gate = await savePolicyGate(root, { failCritical: true });
  assert.equal(gate.ok, true);
  const raw = parsePolicyYaml(fs.readFileSync(yamlPath(root), 'utf8'));
  assert.equal(raw.scanners, undefined, 'aucun scanner inventé');
  const project = await readProjectConfiguration(root);
  assert.equal(project.state, PROJECT_STATE.CONFIGURED);
  assert.equal(project.scanners.declared, false);
  assert.equal(coverage(dashboard(project)).label, 'Scanners not selected yet');
  // La page des scanners propose de choisir, sans rien pré-cocher.
  const setup = renderScannerSetupHtml([], 'n', 'light', {}, null, null, null, {}, project);
  assert.match(setup, /Scanners du projet non déclarés/);
  assert.doesNotMatch(setup, /data-project-scanner="[^"]+" checked/);
});

test('premier usage : la page des scanners ne pré-coche rien et explique la création du fichier', async (t) => {
  const project = await readProjectConfiguration(workspace(t));
  const setup = renderScannerSetupHtml([], 'n', 'light', {}, null, null, null, {}, project);
  assert.match(setup, /data-project-state="not_configured"/);
  assert.match(setup, /sera créé à l’enregistrement/);
  assert.match(setup, /data-project-scanners-save/);
  assert.doesNotMatch(setup, /data-project-scanner="[^"]+" checked/);
  assert.match(setup, /type:'saveProjectScanners'/);
});

// ------------------------------------------------------------ F

const EXISTING = `version: 1
scanners:
  semgrep: true
  gitleaks: true
  trivy: true
  osv: true
  zap: true
policy:
  include_tests: false
# Réglages ZAP du projet
zap:
  mode: auto
  policy_min_severity: HIGH
exclusions:
  zap_routes: [/rest/user/logout, /api/Users]
`;

test('F — projet existant : lu tel quel, couverture cohérente, rien n’est réécrit à l’ouverture', async (t) => {
  const root = workspace(t, { 'security-center.yml': EXISTING });
  const before = fs.readFileSync(yamlPath(root), 'utf8');
  const project = await readProjectConfiguration(root);
  assert.equal(project.state, PROJECT_STATE.CONFIGURED);
  assert.deepEqual(project.scanners.enabled, ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'ZAP']);
  assert.deepEqual(coverage(dashboard(project)), { percent: '0', ratio: '0 / 5', label: '5 configured · not scanned yet' });
  // Après une vraie analyse, la couverture reste celle des scanners exécutés.
  const ran = coverage(dashboard(project, [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Gitleaks', status: 'failed' }]));
  assert.equal(ran.ratio, '1 / 2');
  assert.equal(fs.readFileSync(yamlPath(root), 'utf8'), before, 'lire ne modifie rien');
});

test('F — enregistrer les scanners d’un projet existant ne touche qu’au bloc scanners', async (t) => {
  const root = workspace(t, { 'security-center.yml': EXISTING });
  const saved = await saveProjectScanners(root, ['Semgrep', 'Trivy']);
  assert.equal(saved.ok, true);
  assert.equal(saved.created, false);
  const text = fs.readFileSync(yamlPath(root), 'utf8');
  assert.match(text, /# Réglages ZAP du projet/);
  assert.match(text, /zap_routes: \[\/rest\/user\/logout, \/api\/Users\]/);
  assert.match(text, /^policy:\n  include_tests: false$/m);
  const policy = validatePolicy(parsePolicyYaml(text));
  assert.equal(policy.scanners.Gitleaks, false);
  assert.equal(policy.scanners.Trivy, true);
  assert.equal(policy.zapPolicyMinSeverity, 'HIGH');
  // Une sélection identique réécrit un fichier identique.
  assert.equal(applyScannersToPolicyYaml(text, ['Semgrep', 'Trivy']), text);
});

test('F — fichier illisible : état INVALID signalé, pas de premier usage trompeur', async (t) => {
  const root = workspace(t, { 'security-center.yml': 'scanners:\n\tsemgrep: true\n' });
  const project = await readProjectConfiguration(root);
  assert.equal(project.state, PROJECT_STATE.INVALID);
  const html = dashboard(project);
  assert.match(html, /data-project-state="invalid"/);
  assert.equal(coverage(html).label, 'security-center.yml is invalid');
  const setup = renderScannerSetupHtml([], 'n', 'light', {}, null, null, null, {}, project);
  assert.match(setup, /data-project-scanners-save disabled/);
});

test('F — la page Scanner Configuration sans état projet reste inchangée', () => {
  const html = renderScannerSetupHtml([], 'n', 'light');
  // The script always carries the (inert) selector; no card, no checkbox is rendered.
  assert.doesNotMatch(html, /<input[^>]*data-project-scanner=/);
  assert.doesNotMatch(html, /<section class="notice project-scanners"/);
});
