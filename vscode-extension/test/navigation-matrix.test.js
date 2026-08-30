'use strict';

/**
 * La matrice de navigation du rail Security Center.
 *
 * Les tests structurels precedents se contentaient de verifier qu'une commande
 * etait declaree. Cela ne dit rien de ce qui se passe au clic : une commande
 * peut exister, etre enregistree, et ne rien faire d'utile. Ce fichier classe
 * chaque item du rail et verifie que le chemin correspondant existe VRAIMENT.
 *
 * A. webview dans le cadre partage  -> un panneau est cree et relaie la navigation
 * B. action sur l'editeur / fichier -> ouvre un document, pas un webview
 * C. QuickPick / InputBox           -> dialogue natif VS Code
 * D. autre action intentionnelle    -> generation de fichier, execution
 *
 * Les items B, C et D ne doivent PAS etre transformes en webviews : le test
 * fige leur nature pour empecher une « harmonisation » qui casserait l'action.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const manifest = require('../package.json');
const { navCommands, SURFACE_NAV_COMMAND } = require('../src/security-center-shell');

const source = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/**
 * Le corps d'UNE commande : de son registerCommand jusqu'au suivant. Sans cette
 * borne, l'inspection deborde sur la commande d'apres et lui attribue ses
 * appels — c'est ainsi que « SBOM » a semble ouvrir un webview alors que le
 * webview appartenait a « Licenses », declaree juste apres.
 */
function commandBody(extension, command) {
  const start = extension.indexOf(`registerCommand('${command}'`);
  if (start < 0) return null;
  const next = extension.indexOf('registerCommand(', start + 20);
  return extension.slice(start, next < 0 ? extension.length : next);
}

/** Chaque item visible du rail, avec sa nature et la preuve attendue. */
const MATRIX = [
  // groupe, libelle, commande, categorie, preuve dans extension.js
  ['Overview', 'Dashboard', 'securityCenter.openDashboard', 'A', 'openFullDashboard'],
  ['Analyze', 'Findings', 'securityCenter.openFindingsPage', 'A', 'openPage'],
  ['Analyze', 'Scans', 'securityCenter.openScansPage', 'A', 'openPage'],
  ['Analyze', 'Scan History', 'securityCenter.showScanHistoryPage', 'A', 'securityCenter.scanHistory'],
  ['Analyze', 'Dynamic Security', 'securityCenter.openDynamicPage', 'A', 'openPage'],
  ['Analyze', 'Runtime Security', 'securityCenter.openRuntimeSecurity', 'A', 'openRuntimeSecurityPage'],
  ['Analyze', 'Infrastructure', 'securityCenter.openInfrastructure', 'A', 'openInfrastructurePage'],
  ['Analyze', 'Analytics', 'securityCenter.openAnalyticsPage', 'A', 'openPage'],
  ['Improve', 'Fix & Verify', 'securityCenter.verifyFindingFix', 'C', 'showQuickPick'],
  ['Improve', 'Live Security', 'securityCenter.openLiveSecurityPage', 'A', 'liveSecurityPage'],
  ['Improve', 'Ollama / AI', 'securityCenter.configureOllama', 'C', 'showQuickPick'],
  ['Deliver', 'Security Pipeline', 'securityCenter.openSecurityPipeline', 'A', 'securityCenter.pipeline'],
  ['Deliver', 'Security Delivery', 'securityCenter.openSecurityDelivery', 'A', 'securityCenter.delivery'],
  ['Report', 'Audit Journal', 'securityCenter.showAuditLog', 'A', 'securityCenter.auditLog'],
  ['Report', 'Trends & MTTR', 'securityCenter.showTrends', 'A', 'securityCenter.trends'],
  ['Report', 'SBOM', 'securityCenter.generateSbom', 'D', 'generateSbom'],
  ['Report', 'Licenses', 'securityCenter.checkLicenses', 'A', 'securityCenter.licenseCompliance'],
  ['Configuration', 'Scanner Configuration', 'securityCenter.openScannerSetup', 'A', 'securityCenter.scannerSetup'],
  ['Configuration', 'Project Policy', 'securityCenter.openProjectPolicy', 'B', 'showTextDocument'],
  ['Configuration', 'Integrations', 'securityCenter.configureTeamIntegrations', 'A', 'openIntegrationsPage']
];

test('la matrice couvre exactement les items rendus par le rail', () => {
  const rendered = new Set(navCommands());
  const covered = new Set(MATRIX.map(([, , command]) => command));
  for (const command of rendered) {
    assert.ok(covered.has(command), `${command} est dans le rail mais absent de la matrice`);
  }
  for (const command of covered) {
    assert.ok(rendered.has(command), `${command} est dans la matrice mais plus dans le rail`);
  }
});

test('chaque item du rail est declare et enregistre', () => {
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  const extension = source();
  const loopRegistered = new Set(['findings', 'scans', 'dynamic', 'analytics']
    .map((page) => `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`));
  for (const [group, label, command] of MATRIX) {
    assert.ok(declared.has(command), `${group}/${label} : ${command} absente de package.json`);
    if (loopRegistered.has(command)) continue;
    assert.match(extension, new RegExp(`registerCommand\\('${command.replace(/\./g, '\\.')}'`),
      `${group}/${label} : ${command} sans handler`);
  }
});

test('chaque item mene bien au type d action attendu', () => {
  const extension = source();
  for (const [group, label, command, category, evidence] of MATRIX) {
    const start = extension.indexOf(`registerCommand('${command}'`);
    // Les quatre pages internes passent par une boucle a gabarit.
    if (start < 0) {
      assert.equal(category, 'A', `${label} : commande introuvable et non gabarit`);
      assert.match(extension, /for \(const page of \['findings', 'scans', 'dynamic', 'analytics'\]\)/);
      continue;
    }
    const body = commandBody(extension, command);
    assert.ok(body.includes(evidence),
      `${group}/${label} (${category}) : preuve « ${evidence} » introuvable — l action a change de nature`);
  }
});

test('aucune action native n a ete transformee en webview', () => {
  // Requirement explicite : ne pas forcer B/C/D dans des webviews pour
  // l apparence. Ce test echoue si quelqu un « harmonise » ces trois items.
  const extension = source();
  for (const [, label, command, category] of MATRIX.filter(([, , , c]) => c !== 'A')) {
    const body = commandBody(extension, command);
    assert.ok(body && !body.includes('createWebviewPanel'),
      `${label} (${category}) ne doit pas devenir un webview : son action native serait perdue`);
  }
});

// ============================== la navigation doit etre relayee par chaque page

test('chaque webview du cadre relaie la navigation partagee', () => {
  const extension = source();
  // Panneaux hebergeant le cadre et executant du script : ils doivent brancher
  // le relais de navigation, sinon les items du rail y sont muets.
  const scripted = [
    'securityCenter.scanHistory', 'securityCenter.scanComparison', 'securityCenter.auditLog',
    'securityCenter.trends', 'securityCenter.pipeline', 'securityCenter.delivery', 'securityCenter.integrations',
    'securityCenter.runtimeSecurity', 'securityCenter.infrastructure', 'securityCenter.scannerSetup',
    'securityCenter.findingDetails'
  ];
  for (const panelId of scripted) {
    const at = extension.indexOf(panelId);
    assert.ok(at > 0, `panneau ${panelId} introuvable`);
    const region = extension.slice(at, at + 6000);
    assert.ok(region.includes('handleShellNavMessage'),
      `${panelId} : la navigation partagee n est pas relayee — les items du rail seraient muets`);
  }
});

test('la page des licences obtient sa navigation sans activer les scripts', () => {
  const extension = source();
  const at = extension.indexOf('securityCenter.licenseCompliance');
  const region = extension.slice(at, at + 1200);
  // Le rapport de licences n a aucun script : la navigation passe par des URI
  // de commande, restreintes a la liste du rail. Activer les scripts pour
  // obtenir le cadre serait un elargissement inutile.
  assert.match(region, /enableScripts:\s*false/, 'les scripts doivent rester desactives');
  assert.match(region, /enableCommandUris:\s*navCommands\(\)/,
    'les URI de commande doivent etre restreintes aux items du rail');
  assert.ok(!/enableCommandUris:\s*true/.test(region),
    'ne jamais autoriser toutes les commandes par URI');
});

test('Live Security garde ses ressources locales et sa CSP d images', () => {
  const live = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'livePage.js'), 'utf8');
  // Le compagnon est servi depuis media/live : sans localResourceRoots ni
  // img-src, l image serait bloquee par la CSP du webview.
  assert.match(live, /localResourceRoots:\s*\[assetRoot\]/, 'localResourceRoots perdu');
  assert.match(live, /img-src \$\{cspSource/, 'img-src doit garder la source du webview');
  assert.match(live, /asWebviewUri/, 'l URI de ressource du compagnon a disparu');
  // La delegation de clic de la page ne doit pas doubler le relais du rail.
  assert.match(live, /classList\.contains\('sc-nav-item'\)/,
    'sans cette garde un clic de navigation partirait deux fois');
});

test('chaque surface hebergee designe un item de navigation existant', () => {
  const rail = new Set(navCommands());
  for (const [surface, command] of Object.entries(SURFACE_NAV_COMMAND)) {
    assert.ok(rail.has(command), `la surface ${surface} pointe vers ${command}, absent du rail`);
  }
});
