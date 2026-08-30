const test = require('node:test');
const assert = require('node:assert/strict');
const { renderScannerSetupHtml, sonarDiagnosis, safeServerUrl, SONAR_MODES } = require('../src/scanner-setup-page');
const { renderFindingDetailsHtml } = require('../src/finding-details');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { normalizeSonarQubeOutput } = require('../src/findings');
const { projectSnapshot, snapshotFromLegacy } = require('../src/security-snapshot');

const TOKEN = 'squ_0123456789abcdef0123456789abcdef01234567';
const MANAGED = [
  { id: 'semgrep', label: 'Semgrep', purpose: 'Analyse statique du code (SAST)', installed: true, version: '1.2.3', executable: '/bin/semgrep', managed: false },
  { id: 'gitleaks', label: 'Gitleaks', purpose: 'Détection de secrets', installed: false, version: '', executable: '', managed: false },
  { id: 'trivy', label: 'Trivy', purpose: 'Dépendances, conteneurs et IaC', installed: true, version: '0.50', executable: '/bin/trivy', managed: true },
  { id: 'osv', label: 'OSV-Scanner', purpose: 'Vulnérabilités des dépendances', installed: true, version: '2.0', executable: '/bin/osv-scanner', managed: true }
];

function sonar(overrides = {}) {
  return {
    enabled: true, mode: 'auto', serverType: 'existing', hostUrl: 'http://127.0.0.1:9000', tokenConfigured: true,
    scannerVersion: '6.2.1', scannerPath: '/opt/sonar/bin/sonar-scanner',
    dockerAvailable: true, serverOnline: true, serverVersion: '26.8.0', serverMessage: '',
    ...overrides
  };
}

function setupHtml(overrides) {
  return renderScannerSetupHtml(MANAGED, 'nonce123', 'light', {}, null, overrides === null ? null : sonar(overrides));
}

function sonarFinding(overrides = {}) {
  const [finding] = normalizeSonarQubeOutput({
    projectKey: 'demo', serverUrl: 'http://127.0.0.1:9000',
    components: [{ key: 'demo:src/a.js', path: 'src/a.js' }],
    rules: { 'js:S2076': { key: 'js:S2076', name: 'Injection', securityStandards: ['cwe:78'] } },
    issues: [{ key: 'AY-1', rule: 'js:S2076', component: 'demo:src/a.js', type: 'VULNERABILITY', severity: 'BLOCKER', message: 'Commande dynamique', textRange: { startLine: 12, startOffset: 2, endOffset: 20 }, tags: ['injection'], effort: '15min', status: 'OPEN' }]
  }, '/repo');
  return { ...finding, ...overrides };
}

// ------------------------------------------- Configuration des scanners

test('SonarQube apparaît dans Configuration des scanners avec sa description', () => {
  const html = setupHtml();
  assert.match(html, /<h2>SonarQube<\/h2>/);
  assert.match(html, /Analyse de qualité et sécurité du code/);
  assert.match(html, /data-tool="sonarqube"/);
});

test('aucun scanner existant ne disparaît de la page', () => {
  const html = setupHtml();
  for (const tool of ['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner']) {
    assert.ok(html.includes(`<h2>${tool}</h2>`), `${tool} doit rester présent`);
  }
  assert.match(html, /data-install="gitleaks"/, 'l’installation gérée reste proposée pour Gitleaks');
});

test('la page reste rendue quand aucun diagnostic SonarQube n’est fourni', () => {
  const html = renderScannerSetupHtml(MANAGED, 'n', 'light', {}, null);
  assert.match(html, /<h2>Semgrep<\/h2>/);
  assert.equal(html.includes('data-tool="sonarqube"'), false);
});

test('les trois modes d’exécution sont proposés et le mode courant est marqué', () => {
  const html = setupHtml({ mode: 'docker' });
  for (const [value, label] of SONAR_MODES) {
    assert.ok(html.includes(`data-sonar-mode="${value}"`), `bouton ${value} manquant`);
    assert.ok(html.includes(`Utiliser en mode ${label}`), `libellé ${label} manquant`);
  }
  assert.match(html, /data-sonar-mode="docker"[^>]*aria-current="true"/);
  assert.match(html, /<dt>Mode configuré<\/dt><dd>Docker<\/dd>/);
});

test('un mode inconnu retombe sur Auto sans casser le rendu', () => {
  const html = setupHtml({ mode: 'kubernetes' });
  assert.match(html, /<dt>Mode configuré<\/dt><dd>Auto<\/dd>/);
});

test('les actions Configurer le token et Revérifier sont présentes', () => {
  const html = setupHtml();
  assert.match(html, /data-sonar-token/);
  assert.match(html, /Remplacer le token/);
  assert.match(html, /data-sonar-recheck/);
  assert.match(html, /Revérifier/);
});

test('aucune installation automatique n’est proposée pour SonarQube', () => {
  const html = setupHtml({ scannerVersion: '', serverOnline: false });
  const card = html.slice(html.indexOf('data-tool="sonarqube"'), html.indexOf('</article>', html.indexOf('data-tool="sonarqube"')));
  assert.equal(card.includes('data-install='), false, 'SonarQube ne doit jamais offrir d’installation gérée');
  // Sans serveur choisi, le démarrage local est proposé mais jamais automatique.
  assert.match(setupHtml({ serverType: '' }), /Aucun serveur n’est démarré sans votre confirmation/);
});

test('le jeton n’est jamais rendu, seul son état l’est', () => {
  const configured = setupHtml({ tokenConfigured: true });
  assert.equal(configured.includes(TOKEN), false);
  assert.equal(configured.includes('squ_'), false);
  assert.match(configured, /<dt>Token<\/dt><dd>Configuré/);
  assert.match(setupHtml({ tokenConfigured: false }), /<dt>Token<\/dt><dd><span class="muted">Non configuré<\/span><\/dd>/);
});

test('l’URL du serveur est affichée sans identifiants ni paramètres', () => {
  assert.equal(safeServerUrl('http://admin:motdepasse@sonar.local:9000/?token=abc'), 'http://sonar.local:9000');
  assert.equal(safeServerUrl('http://127.0.0.1:9000/'), 'http://127.0.0.1:9000');
  assert.equal(safeServerUrl('pas-une-url'), '');
  const html = setupHtml({ hostUrl: 'http://admin:s3cret@sonar.local:9000/?t=zz' });
  assert.equal(html.includes('s3cret'), false);
  assert.equal(html.includes('admin:'), false);
  assert.match(html, /sonar\.local:9000/);
});

test('le diagnostic expose un état explicite pour chaque situation réelle', () => {
  assert.equal(sonarDiagnosis(sonar()).state, 'ready');
  assert.equal(sonarDiagnosis(sonar()).label, 'Prêt');
  assert.equal(sonarDiagnosis(sonar({ enabled: false })).label, 'Désactivé');
  assert.equal(sonarDiagnosis(sonar({ serverOnline: false })).label, 'Serveur indisponible');
  assert.equal(sonarDiagnosis(sonar({ tokenConfigured: false })).label, 'Token manquant');
  assert.equal(sonarDiagnosis(sonar({ mode: 'local', scannerVersion: '' })).label, 'Scanner local absent');
  assert.equal(sonarDiagnosis(sonar({ mode: 'docker', dockerAvailable: false })).label, 'Docker indisponible');
  assert.equal(sonarDiagnosis(sonar({ scannerVersion: '', dockerAvailable: false })).label, 'Scanner local absent');
  // Plusieurs prérequis manquants : état de synthèse, détails dans l'indice.
  const incomplete = sonarDiagnosis(sonar({ tokenConfigured: false, serverOnline: false }));
  assert.equal(incomplete.label, 'Activé — configuration incomplète');
  assert.match(incomplete.hint, /Serveur indisponible/);
  assert.match(incomplete.hint, /Token manquant/);
  // Docker reste un secours valide quand le CLI local est absent.
  assert.equal(sonarDiagnosis(sonar({ scannerVersion: '' })).label, 'Prêt — Docker');
});

test('l’état de connexion du serveur est rendu fidèlement', () => {
  assert.match(setupHtml(), /Connecté — version 26\.8\.0/);
  const offline = setupHtml({ serverOnline: false, serverMessage: 'La cible est inaccessible.' });
  assert.match(offline, /Injoignable — La cible est inaccessible\./);
  assert.match(offline, /Serveur indisponible/);
  assert.match(setupHtml({ enabled: false }), /Désactivé/);
});

test('la version SonarScanner est affichée ou signalée comme non détectée', () => {
  assert.match(setupHtml({ scannerVersion: '6.2.1' }), /<dt>Version<\/dt><dd>6\.2\.1<\/dd>/);
  assert.match(setupHtml({ scannerVersion: '' }), /<dt>Version<\/dt><dd>Non détectée<\/dd>/);
  assert.match(setupHtml({ scannerVersion: '' }), /sonarsource\/sonar-scanner-cli/);
});

test('le diagnostic SonarQube échappe le HTML', () => {
  const html = setupHtml({ serverOnline: false, serverMessage: '<img src=x onerror=alert(1)>' });
  assert.equal(html.includes('<img src=x'), false);
  assert.match(html, /&lt;img src=x/);
});

// ------------------------------------------------------------ Dashboard

test('SonarQube apparaît dans le pipeline et les résultats par outil', () => {
  const findings = [sonarFinding()];
  const scanners = [{ tool: 'SonarQube', status: 'completed', details: '1 résultat(s)', durationMs: 94000 }];
  const model = buildDashboardModel(findings, scanners, { disabledScanners: [] });
  assert.equal(model.byTool.SonarQube, 1);
  const html = renderDashboardHtml(model, 'n', 'full', 'light', {});
  assert.match(html, /SonarQube/);
  assert.match(html, /Qualité et sécurité du code \(SAST\)/);
});

test('le filtre par outil du dashboard propose SonarQube dès qu’il produit des résultats', () => {
  const model = buildDashboardModel([sonarFinding()], [{ tool: 'SonarQube', status: 'completed' }], {});
  const html = renderDashboardHtml(model, 'n', 'findings', 'light', {});
  assert.match(html, /<option value="sonarqube">SonarQube<\/option>/);
  assert.match(html, /data-tool-id="sonarqube"/);
});

test('un SonarQube désactivé est annoncé sans inventer de compteur', () => {
  const model = buildDashboardModel([], [{ tool: 'Semgrep', status: 'completed' }], { disabledScanners: ['SonarQube'] });
  assert.deepEqual(model.disabledScanners, ['SonarQube']);
  const overview = renderDashboardHtml(model, 'n', 'full', 'light', {});
  assert.match(overview, /Désactivé/);
  // Aucun « 0 alertes » fabriqué pour un scanner qui n'a jamais tourné.
  const card = overview.slice(overview.indexOf('overview-scanner disabled'));
  assert.match(card.slice(0, 700), /<strong>—<\/strong><small>alertes<\/small>/);
  assert.match(renderDashboardHtml(model, 'n', 'scans', 'light', {}), /Désactivé/);
});

test('un scanner ayant réellement tourné n’est jamais marqué désactivé', () => {
  const model = buildDashboardModel([], [{ tool: 'SonarQube', status: 'completed', details: '0 résultat(s)' }], { disabledScanners: ['SonarQube'] });
  assert.deepEqual(model.disabledScanners, [], 'la liste désactivée ne doit pas contredire une exécution réelle');
});

test('l’ordre du snapshot place SonarQube entre OSV et ZAP', () => {
  const snapshot = snapshotFromLegacy(
    [sonarFinding()],
    [{ tool: 'ZAP', status: 'completed' }, { tool: 'SonarQube', status: 'completed' }, { tool: 'Semgrep', status: 'completed' }],
    {}
  );
  assert.deepEqual(projectSnapshot(snapshot).scanners.map((scanner) => scanner.tool), ['Semgrep', 'SonarQube', 'ZAP']);
});

// ------------------------------------------------- Détails d’un finding

test('les détails d’un finding SonarQube n’affichent aucun champ ZAP', () => {
  const html = renderFindingDetailsHtml(sonarFinding(), 'nonce');
  assert.match(html, /Résultat SonarQube/);
  assert.match(html, /js:S2076/);
  assert.match(html, /CWE-78/);
  assert.match(html, /Vulnérabilité/);
  assert.match(html, /15min/);
  assert.equal(html.includes('Preuve ZAP'), false, 'un résultat statique ne doit pas afficher de preuve ZAP');
  assert.equal(html.includes('Endpoint'), false);
});

test('un security hotspot est présenté comme un point à revoir', () => {
  const hotspot = sonarFinding({ category: 'security-hotspot', issueType: 'SECURITY_HOTSPOT', vulnerabilityProbability: 'HIGH' });
  const html = renderFindingDetailsHtml(hotspot, 'nonce');
  assert.match(html, /Security hotspot signalé par SonarQube/);
  assert.match(html, /pas une vulnérabilité confirmée/);
  assert.match(html, /<div class="label">Probabilité<\/div><div>HIGH<\/div>/);
});

test('un finding SonarQube sans localisation ne fabrique pas de ligne', () => {
  const html = renderFindingDetailsHtml(sonarFinding({ file: '', unlocated: true, absolutePath: '' }), 'nonce');
  assert.match(html, /Résultat au niveau du projet/);
  assert.match(html, /Aucune ligne fournie/);
});

test('les détails des autres scanners restent inchangés', () => {
  const trivy = renderFindingDetailsHtml({ tool: 'Trivy', ruleId: 'CVE-2026-1', title: 'x', rawSeverity: 'HIGH', packageName: 'lodash', file: 'package-lock.json' }, 'n');
  assert.match(trivy, /Dépendance ou configuration concernée/);
  const gitleaks = renderFindingDetailsHtml({ tool: 'Gitleaks', ruleId: 'aws-key', title: 'secret', rawSeverity: 'CRITICAL', file: 'a.js' }, 'n');
  assert.match(gitleaks, /Secret détecté par Gitleaks/);
  const zap = renderFindingDetailsHtml({ tool: 'ZAP', ruleId: '10038', title: 'CSP', rawSeverity: 'MEDIUM', endpoint: 'http://127.0.0.1:3000', method: 'GET' }, 'n');
  assert.match(zap, /Preuve ZAP/);
});
