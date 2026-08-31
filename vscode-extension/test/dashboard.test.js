const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const manifest = require('../package.json');
const { buildDashboardModel, renderDashboardHtml, calculateRiskScore, riskLevel, summarizeScannerError, isUsefulHttpScenario, linkedFindingsForScenario, sourceCorrelationForFinding, buildSafeHttpPreview } = require('../src/dashboard');

test('generated dashboard webview script remains syntactically valid', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    httpScenarios: [{ method: 'GET', url: 'http://127.0.0.1:3000/rest/products' }]
  }), 'nonce', 'dynamic');
  const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);
  assert.doesNotThrow(() => new vm.Script(script));
});

test('ne rend plus la confirmation ZAP comme carte de page', () => {
  const html = renderDashboardHtml(buildDashboardModel(), 'nonce', 'dynamic', 'light', {
    zapConfirmationVisible: true,
    zapConfirmation: { mode: 'active', target: 'http://127.0.0.1:3000' }
  });
  assert.doesNotMatch(html, /zap-confirmation-backdrop/);
  assert.doesNotMatch(html, /Autoriser le scan local/);
  assert.doesNotMatch(html, /createWebviewPanel\('securityCenter\.zapAuthorization'/);
});

test('la confirmation ZAP n est pas cachee dans une surface Security Center', () => {
  const state = {
    zapConfirmationVisible: true,
    zapConfirmation: { mode: 'active', target: 'http://127.0.0.1:3000' }
  };
  const model = buildDashboardModel();
  assert.doesNotMatch(renderDashboardHtml(model, 'nonce', 'full', 'light', state), /role="alertdialog"/);
  assert.doesNotMatch(renderDashboardHtml(model, 'nonce', 'dynamic', 'light', state), /role="alertdialog"/);
  assert.doesNotMatch(renderDashboardHtml(model, 'nonce', 'scans', 'light', state), /role="alertdialog"/);
  assert.doesNotMatch(renderDashboardHtml(model, 'nonce', 'history', 'light', state), /role="alertdialog"/);
});

test('calcule les compteurs du dashboard', () => {
  const model = buildDashboardModel([
    { tool: 'Semgrep', rawSeverity: 'HIGH' },
    { tool: 'Semgrep', rawSeverity: 'MEDIUM' },
    { tool: 'Gitleaks', rawSeverity: 'HIGH' }
  ], [{ tool: 'Semgrep', status: 'completed' }], { workspace: 'demo', scanStatus: 'completed', backendStatus: 'online' });
  assert.equal(model.total, 3);
  assert.deepEqual(model.byTool, { Semgrep: 2, Gitleaks: 1 });
  assert.deepEqual(model.bySeverity, { HIGH: 2, MEDIUM: 1 });
});

test('expose les corrélations dans le dashboard', () => {
  // La corrélation visible vient desormais de l'intelligence V2, portee par les
  // findings via `correlationClusters` — exactement ce que `mergeIntelligence`
  // attache en production et ce que le cache de scan persiste.
  const cluster = { id: 'sca-abc123', type: 'sca', confidence: 'high', tier: 'confirmed', title: 'Même emplacement', tools: ['Semgrep', 'Gitleaks'], reasons: ['Même CWE'], findingIds: ['f1'] };
  const findings = [{ id: 'f1', tool: 'Semgrep', rawSeverity: 'HIGH', triageStatus: 'new', correlationClusters: [cluster] }];
  // V1 continue d'etre produit et transmis : il reste la source du rattachement
  // « source probable » et de l'enregistrement backend.
  const correlations = [{ id: 'c1', confidence: 'high', title: 'Même emplacement', tools: ['Semgrep', 'Gitleaks'], reason: 'Même CWE', findingIds: ['f1'] }];
  const model = buildDashboardModel(findings, [], { correlations });
  assert.equal(model.correlations.length, 1);
  assert.equal(model.correlationCounts.high, 1);
  // V1 est preserve, non supprime.
  assert.equal(model.legacyCorrelations.length, 1);
  assert.equal(model.legacyCorrelations[0].id, 'c1');
  const html = renderDashboardHtml(model, 'nonce');
  assert.match(html, /Semgrep \+ Gitleaks/);
  assert.match(html, /Corrélations/);
  assert.match(html, /Même CWE/);
});

test('échappe le contenu affiché dans la Webview', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], { workspace: '<script>' }), 'nonce');
  assert.ok(!html.includes('<div class="workspace"><script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('calcule un score de risque borné et son niveau', () => {
  assert.equal(calculateRiskScore([{ rawSeverity: 'HIGH' }, { rawSeverity: 'MEDIUM' }]), 11);
  assert.equal(calculateRiskScore(Array.from({ length: 20 }, () => ({ rawSeverity: 'CRITICAL' }))), 100);
  assert.equal(riskLevel(10), 'faible');
  assert.equal(riskLevel(50), 'élevé');
  assert.equal(riskLevel(90), 'critique');
});

test('affiche les nouvelles cartes et barres du dashboard', () => {
  const findings = [
    { tool: 'Semgrep', rawSeverity: 'HIGH', sourceContext: 'production' },
    { tool: 'ZAP', rawSeverity: 'MEDIUM', sourceContext: 'runtime' }
  ];
  const scanners = [{ tool: 'Semgrep', status: 'completed', details: '1 résultat' }];
  const html = renderDashboardHtml(buildDashboardModel(findings, scanners, {
    workspace: 'demo', scanStatus: 'completed', backendStatus: 'online'
  }), 'nonce');
  const fullHtml = renderDashboardHtml(buildDashboardModel(findings, scanners, {
    workspace: 'demo', scanStatus: 'completed', backendStatus: 'online'
  }), 'nonce', 'full');
  assert.match(html, /Risque/);
  assert.match(html, /Priorités production/);
  assert.match(html, /Alertes runtime/);
  assert.match(html, /<progress/);
  assert.match(html, /Backend online/);
  assert.match(html, /Importer un HAR/);
  assert.doesNotMatch(html, /data-command="securityCenter\.compareScans"/);
  assert.doesNotMatch(html, /Scan rapide des fichiers modifiés/);
  assert.match(html, /operational-banner/);
  assert.match(html, /risk-ring/);
  assert.match(html, /Répartition par sévérité/);
  assert.match(html, /donut-segment/);
  assert.doesNotMatch(html, /Analyse fréquente/);
  assert.doesNotMatch(html, /Comparer les scans/);
  assert.doesNotMatch(html, /Ouvrir l’historique des scans/);
  assert.match(fullHtml, /Voir tout l['’]historique/);
  assert.match(fullHtml, /securityCenter\.showScanHistoryPage/);
  const extensionSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(extensionSource, /allowed = new Set\([\s\S]*securityCenter\.showScanHistoryPage/);
  assert.match(extensionSource, /function zapRequestedForScan[\s\S]*requested\.has\('ZAP'\)/);
  assert.match(extensionSource, /const zapPreflightRequired = zapRequestedForScan\(cfg, projectPolicy, requested\)/);
  assert.match(extensionSource, /context\.secrets\.get\(zapUsernameSecretKey\)/);
  assert.match(html, /securityCenter\.configureZapCredentials/);
  assert.match(renderDashboardHtml(buildDashboardModel([{ id: 'fixed', title: 'Fix', tool: 'Semgrep', rawSeverity: 'HIGH', triageStatus: 'validated' }]), 'nonce'), /Validée par re-scan/);
  assert.match(renderDashboardHtml(buildDashboardModel([{ id: 'stale', title: 'Ancienne', tool: 'Semgrep', rawSeverity: 'HIGH', staleFromPreviousScan: true }]), 'nonce'), /Données du scan précédent/);
  assert.doesNotMatch(html, /Ouvrir le journal d’audit/);
  assert.doesNotMatch(html, /Slack \/ Jira/);
  assert.doesNotMatch(html, /Ollama local/);
  assert.doesNotMatch(html, /Rollback IA/);
  assert.doesNotMatch(html, /securityCenter\.replayHttpScenario/);
  assert.match(html, /data-command="securityCenter\.scanWorkspace"/);
  assert.match(html, />↻ Relancer<\/button>/);
  assert.match(html, /script-src 'nonce-nonce'/);
});

test('utilise une petite action Relancer dans l’en-tête du dashboard complet', () => {
  const model = buildDashboardModel([{ tool: 'Semgrep', title: 'Test', rawSeverity: 'LOW' }], [
    { tool: 'Semgrep', status: 'completed' }
  ], { scanStatus: 'completed' });
  const fullHtml = renderDashboardHtml(model, 'nonce', 'full');
  assert.match(fullHtml, /class="header-scan"/);
  assert.match(fullHtml, />↻ Relancer<\/button>/);
  // CHANGEMENT DE CONTRAT DE PRESENTATION : la vue de la barre d'activite ne
  // rend plus ce document. Elle a son propre lanceur compact, dont le contrat
  // est decrit par test/sidebar-launcher.test.js. Les anciennes assertions
  // « sidebar » de ce test decrivaient le catalogue de navigation qui vient
  // d'etre retire de cette surface ; le comportement du dashboard complet, seul
  // sujet reel de ce test, est inchange.
  assert.doesNotMatch(fullHtml, /Analyse fréquente/);
  assert.doesNotMatch(fullHtml, /Ouvrir le dashboard complet/);
});

test('résume les erreurs Docker sans exposer la commande interne dans le dashboard', () => {
  const summary = summarizeScannerError('error waiting for container: unexpected EOF dockerDesktopLinuxEngine /containers/secret/start');
  assert.match(summary, /Docker Desktop a interrompu la connexion/);
  assert.doesNotMatch(summary, /\/containers\/secret/);
});

test('affiche la page Dynamic Security et conserve les actions ZAP/Burp', () => {
  const httpScenarios = [{
    source: 'burp',
    name: 'GET /api/users',
    request: { method: 'GET', url: 'http://127.0.0.1:3000/api/users' }
  }];
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    httpScenarioCount: 7,
    httpScenarios,
    burpConnected: true
  }), 'safe-nonce', 'dynamic');
  assert.match(html, /Dynamic Security/);
  assert.match(html, /<h2>Cible<\/h2>/);
  assert.match(html, /Analyse dynamique automatisée/);
  assert.match(html, /Capture et investigation du trafic HTTP/);
  assert.match(html, /Findings dynamiques/);
  assert.match(html, /Trafic HTTP/);
  assert.match(html, /Tests dynamiques récents/);
  // La carte Burp distingue desormais l'etat de la connexion de l'historique
  // capture : « Deconnecte » ne doit plus se lire « aucune donnee ». Le libelle
  // du compteur suit ce decoupage — l'invariant teste reste que la requete
  // capturee est bien decomptee.
  assert.match(html, /Connexion actuelle<\/span><strong>(Connectée|Déconnectée)<\/strong>/);
  assert.match(html, /Historique capturé/);
  assert.match(html, /Requêtes conservées<\/span><strong>1<\/strong>/);
  assert.match(html, /Endpoints uniques<\/span><strong>1<\/strong>/);
  assert.match(html, /GET \/api\/users/);
  assert.match(html, /<h2>Burp<\/h2>[\s\S]*Connecté/);
  assert.match(html, /securityCenter\.openBurpSettingsPage/);
  assert.doesNotMatch(html, /disabled title="Importez d’abord/);
  assert.match(html, /securityCenter\.scanZap/);
  assert.doesNotMatch(html, /securityCenter\.replayHttpScenario/);
  assert.match(html, /Lancer ZAP/);
  assert.match(html, /Voir les findings/);
  assert.match(html, />Paramètres<\/button>/);
});

test('propose directement le compte ZAP après un refus d’authentification', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [
    { tool: 'ZAP', status: 'failed', error: 'Login ZAP refusé avec HTTP 401.' }
  ], { scanStatus: 'partial' }), 'nonce', 'dynamic');
  assert.match(html, /Configurer le compte ZAP/);
  assert.match(html, /securityCenter\.configureZapCredentials/);
  assert.match(html, /Paramètres ZAP/);
});

test('déplace la configuration Burp vers une vue compacte sans secret', () => {
  const model = buildDashboardModel([], [], {
    burpConnected: true,
    burpEndpoint: 'http://127.0.0.1:8765/api/v1/integrations/burp',
    burpStatus: { status: 'ready', connector: 'security-center-burp', last_seen: '2026-08-12T10:00:00Z', received_requests: 12 }
  });
  const html = renderDashboardHtml(model, 'nonce', 'burp-settings');
  assert.match(html, /Paramètres Burp/);
  assert.match(html, /État du connecteur/);
  assert.match(html, /127\.0\.0\.1:8765\/api\/v1\/integrations\/burp/);
  assert.match(html, /Dernier signal/);
  assert.match(html, /État de la capture/);
  assert.match(html, /Masquage des secrets/);
  assert.match(html, /Requêtes enregistrées<\/span><strong>12/);
  assert.match(html, /securityCenter\.testBurpConnection/);
  assert.match(html, /securityCenter\.importHttpCapture/);
  assert.match(html, /securityCenter\.configureBurp/);
  assert.doesNotMatch(html, /Authorization: Bearer|password|api[_-]?key=/i);
});

test('affiche les trois états compacts de la cible Dynamic Security', () => {
  const online = renderDashboardHtml(buildDashboardModel([], [], { dynamicTargetUrl: 'http://127.0.0.1:3000', dynamicTargetState: 'online' }), 'nonce', 'dynamic');
  const unreachable = renderDashboardHtml(buildDashboardModel([], [], { dynamicTargetUrl: 'http://127.0.0.1:3000', dynamicTargetState: 'unreachable' }), 'nonce', 'dynamic');
  const unknown = renderDashboardHtml(buildDashboardModel([], [], { dynamicTargetUrl: '', dynamicTargetState: 'unknown' }), 'nonce', 'dynamic');
  assert.match(online, /● En ligne/);
  assert.match(online, /securityCenter\.checkDynamicTarget/);
  assert.match(online, /securityCenter\.changeDynamicTarget/);
  assert.match(unreachable, /⚠ Cible inaccessible/);
  assert.match(unreachable, /Démarrez l’application avant de lancer une analyse dynamique/);
  assert.match(unknown, /Aucune cible configurée/);
  assert.match(unknown, /Inconnue \/ non vérifiée/);
});

test('affiche au plus cinq findings dynamiques prioritaires avec les corrélations existantes', () => {
  const findings = [
    { id: 'zap-1', tool: 'ZAP', title: 'Possible IDOR', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: 'http://127.0.0.1:3000/api/users/1', method: 'GET', triageStatus: 'confirmed' },
    { id: 'burp-1', tool: 'Burp', title: 'Authorization bypass', rawSeverity: 'CRITICAL', sourceContext: 'dynamic', endpoint: 'http://127.0.0.1:3000/api/admin', triageStatus: 'new' },
    { id: 'runtime-1', tool: 'Semgrep', title: 'Runtime route', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/api/runtime', triageStatus: 'new' },
    { id: 'replay-1', tool: 'HTTP Replay', title: 'Replay mismatch', rawSeverity: 'HIGH', source: 'http-replay', url: 'http://127.0.0.1:3000/api/replay', triageStatus: 'new' },
    { id: 'zap-2', tool: 'ZAP', title: 'Fifth priority', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/five', triageStatus: 'new' },
    { id: 'zap-2b', tool: 'ZAP', title: 'Fifth bis', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/five-bis', triageStatus: 'new' },
    { id: 'zap-3', tool: 'ZAP', title: 'Sixth priority hidden', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/six', triageStatus: 'new' },
    { id: 'zap-low', tool: 'ZAP', title: 'Low hidden', rawSeverity: 'LOW', sourceContext: 'runtime', endpoint: '/low', triageStatus: 'new' },
    { id: 'zap-fixed', tool: 'ZAP', title: 'Fixed hidden', rawSeverity: 'CRITICAL', sourceContext: 'runtime', endpoint: '/fixed', triageStatus: 'fixed' }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], {
    correlations: [{ id: 'corr-1', findingIds: ['zap-1'], tools: ['ZAP', 'Burp'], confidence: 'high' }],
    httpScenarios: [{ source: 'burp', name: 'GET /api/users/1', request: { method: 'GET', url: 'http://127.0.0.1:3000/api/users/1' } }]
  }), 'nonce', 'dynamic');
  const section = html.match(/<section id="dynamic-findings"[\s\S]*?<section id="http-traffic"/)?.[0] || '';
  assert.match(section, /Possible IDOR/);
  assert.match(section, /GET http:\/\/127\.0\.0\.1:3000\/api\/users\/1/);
  assert.match(section, /ZAP \+ Burp/);
  assert.match(section, /2 sources/);
  assert.match(section, /Confirmée/);
  assert.equal((section.match(/>Investigate<\/button>/g) || []).length, 5);
  assert.doesNotMatch(section, /Sixth priority hidden/);
  assert.doesNotMatch(section, /Low hidden/);
  assert.doesNotMatch(section, /Fixed hidden/);
  // Dynamic Security n'agrege que ZAP et Burp. Un finding Semgrep marque
  // « runtime » appartient au domaine de la supervision d'execution : il
  // entrait ici auparavant, il en est desormais exclu.
  assert.doesNotMatch(section, /Runtime route/);
  assert.match(section, /Voir tous les findings dynamiques/);
  assert.match(section, /securityCenter\.openFindingsPage/);
});

test('affiche une source dynamique uniquement avec une localisation et une corrélation existantes', () => {
  const dynamic = { id: 'zap-source', tool: 'ZAP', title: 'Possible IDOR', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/api/users/1' };
  const source = { id: 'semgrep-source', tool: 'Semgrep', title: 'Route authorization', rawSeverity: 'HIGH', file: 'backend/controllers/users.ts', absolutePath: 'C:\\workspace\\backend\\controllers\\users.ts', startLine: 84 };
  const likely = { id: 'likely', type: 'endpoint-source', confidence: 'high', findingIds: ['zap-source', 'semgrep-source'], tools: ['ZAP', 'Semgrep'] };
  const possible = { ...likely, id: 'possible', type: 'shared-cwe', confidence: 'medium' };
  assert.equal(sourceCorrelationForFinding(dynamic, [dynamic, source], [likely]).label, 'Likely source');
  assert.equal(sourceCorrelationForFinding(dynamic, [dynamic, source], [possible]).label, 'Possible source');
  assert.equal(sourceCorrelationForFinding(dynamic, [dynamic, source], []), null);

  const html = renderDashboardHtml(buildDashboardModel([dynamic, source], [], { correlations: [likely] }), 'nonce', 'dynamic');
  assert.match(html, /Likely source/);
  assert.match(html, /backend\/controllers\/users\.ts:84/);
  assert.match(html, /data-finding-code-index="1"/);
  assert.doesNotMatch(renderDashboardHtml(buildDashboardModel([dynamic, source], [], { correlations: [] }), 'nonce', 'dynamic'), /Likely source|Possible source/);
});

test('affiche et filtre le trafic Burp/HAR sans exposer les contenus sensibles', () => {
  const apiScenario = { source: 'burp', timestamp: '2026-08-12T10:00:00Z', name: 'GET /rest/products/search', request: { method: 'GET', url: 'http://127.0.0.1:3000/rest/products/search?q=x', headers: { authorization: '[REDACTED]' }, sensitive_headers: ['authorization'] }, response: { statusCode: 200, body: 'DO-NOT-RENDER' } };
  const socketScenario = { source: 'burp', name: 'POST /socket.io/', request: { method: 'POST', url: 'http://127.0.0.1:3000/socket.io/?transport=polling' }, response: { statusCode: 201 } };
  const imageScenario = { source: 'har', name: 'GET image', request: { method: 'GET', url: 'http://127.0.0.1:3000/assets/a.jpg' }, response: { statusCode: 304 } };
  const finding = { tool: 'ZAP', title: 'XSS', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: 'http://127.0.0.1:3000/rest/products/search?q=test', method: 'GET' };
  assert.equal(isUsefulHttpScenario(apiScenario), true);
  assert.equal(isUsefulHttpScenario(socketScenario), false);
  assert.equal(isUsefulHttpScenario(imageScenario), false);
  assert.equal(linkedFindingsForScenario(apiScenario, [finding]).length, 1);
  const html = renderDashboardHtml(buildDashboardModel([finding], [], { httpScenarios: [apiScenario, socketScenario, imageScenario], httpScenarioCount: 3 }), 'nonce');
  const section = html.match(/<section id="http-traffic"[\s\S]*?<section class="dynamic-section"><div class="dynamic-section-head"><h2>Tests dynamiques récents/)?.[0] || '';
  assert.match(section, /Méthode/);
  assert.match(section, /Endpoint/);
  assert.match(section, /Statut/);
  assert.match(section, /Source/);
  assert.match(section, /Findings/);
  assert.match(section, /Horodatage/);
  assert.match(section, /data-method="GET"/);
  assert.match(section, /data-authenticated="true"/);
  assert.match(section, /data-findings="1"/);
  assert.match(section, /\/rest\/products\/search\?q=x/);
  assert.match(section, />200<\/span>/);
  assert.match(section, />HAR<\/span>/);
  assert.match(section, /data-traffic-filter="authenticated"/);
  assert.match(section, /data-traffic-filter="findings"/);
  assert.match(section, /traffic-preview/);
  assert.doesNotMatch(section, /DO-NOT-RENDER/);
  assert.doesNotMatch(section, /authorization/i);
  assert.doesNotMatch(section, /\[REDACTED\]/);
  assert.doesNotMatch(section, /securityCenter\.replayHttpScenario/);
});

test('construit à la demande un aperçu HTTP sûr, tronqué et lié aux findings', () => {
  const scenario = {
    source: 'burp', timestamp: '2026-08-12T10:00:00Z', durationMs: 145,
    request: {
      method: 'GET', url: 'http://127.0.0.1:3000/api/users/1?token=secret-token&view=compact',
      headers: { authorization: 'Bearer original-secret', accept: 'application/json', cookie: 'session=secret' },
      body: JSON.stringify({ password: 'original-password', safe: 'value' })
    },
    response: { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
  };
  const findings = [{ id: 'f1', title: 'Possible IDOR', tool: 'ZAP', rawSeverity: 'HIGH', endpoint: 'http://127.0.0.1:3000/api/users/1', method: 'GET' }];
  const preview = buildSafeHttpPreview(scenario, findings);
  assert.equal(preview.method, 'GET');
  assert.equal(preview.statusCode, 200);
  assert.equal(preview.responseType, 'application/json');
  assert.equal(preview.duration, '0 s');
  assert.equal(preview.headers.find((header) => header.name === 'authorization').value, '[REDACTED]');
  assert.equal(preview.headers.find((header) => header.name === 'cookie').value, '[REDACTED]');
  assert.equal(preview.parameters.find((parameter) => parameter.name === 'token').value, '[REDACTED]');
  assert.equal(preview.parameters.find((parameter) => parameter.name === 'password').value, '[REDACTED]');
  assert.equal(preview.parameters.find((parameter) => parameter.name === 'safe').value, 'value');
  assert.equal(preview.linkedFindings[0].title, 'Possible IDOR');
  assert.doesNotMatch(JSON.stringify(preview), /original-secret|original-password|secret-token/);
  assert.match(preview.safeRequest, /authorization: \[REDACTED\]/);
  const html = renderDashboardHtml(buildDashboardModel(findings, [], { httpScenarios: [scenario] }), 'nonce', 'dynamic');
  assert.match(html, /Rejouer la requête/);
  assert.match(html, /Ouvrir la requête complète/);
  assert.match(html, /findingFromTraffic/);
  assert.match(html, /slice\(0, 3\)/);
  assert.match(html, /replayHttpTraffic/);
  assert.match(html, /\['GET', 'HEAD', 'POST', 'PUT', 'PATCH'\]/);
  assert.doesNotMatch(html, /DELETE'\]/);
});

test('affiche une page de vulnérabilités filtrable avec accès aux détails', () => {
  const findings = [{
    tool: 'Semgrep',
    title: 'Injection SQL possible',
    rawSeverity: 'HIGH',
    sourceContext: 'production',
    triageStatus: 'new',
    file: 'routes/login.ts',
    absolutePath: 'C:\\demo\\routes\\login.ts',
    startLine: 11,
    ruleId: 'javascript.sql-injection'
  }];
  const html = renderDashboardHtml(buildDashboardModel(findings), 'nonce');
  assert.match(html, /Vulnérabilités détaillées/);
  assert.match(html, /Injection SQL possible/);
  assert.match(html, /routes\/login\.ts:12/);
  assert.match(html, /data-finding-index="0"/);
  assert.match(html, /data-finding-code-index="0"/);
  assert.match(html, /Ouvrir le code/);
  assert.match(html, /Tous les outils/);
  assert.match(html, /filterFindings/);
});

test('affiche un pipeline horizontal avec les états et durées', () => {
  const scanners = [
    { tool: 'Semgrep', status: 'completed', durationMs: 4200 },
    { tool: 'Gitleaks', status: 'completed', durationMs: 1800 },
    { tool: 'Trivy', status: 'running' },
    { tool: 'ZAP', status: 'pending' }
  ];
  const html = renderDashboardHtml(buildDashboardModel([], scanners, {
    scanStatus: 'Trivy (3/4)', scanDurationMs: 8000
  }), 'nonce');
  assert.match(html, /Pipeline d’analyse/);
  assert.match(html, /Start/);
  assert.match(html, /Semgrep/);
  assert.match(html, /Trivy/);
  assert.match(html, /ZAP/);
  assert.match(html, /End/);
  assert.match(html, /4 s/);
  assert.match(html, /pipeline-dot running/);
  assert.match(html, /scanner-float/);
  assert.match(html, /scanner-pop/);
  assert.match(html, /Risque en recalcul/);
  assert.match(html, /<strong>0<\/strong>/);
});

test('distingue attente, analyse animée, échec et relance individuelle dans le pipeline', () => {
  const model = buildDashboardModel([], [
    { tool: 'Semgrep', status: 'running' },
    { tool: 'Gitleaks', status: 'pending' },
    { tool: 'Trivy', status: 'failed', error: 'timeout' }
  ], { scanStatus: 'running' });
  const html = renderDashboardHtml(model, 'nonce');
  assert.match(html, /pipeline-dot running/);
  assert.match(html, /pipeline-dot pending/);
  assert.match(html, /pipeline-dot failed/);
  assert.match(html, /data-retry-scanner="Trivy"/);
  assert.match(html, /\.pipeline-dot\.running, \.pipeline-dot\.refreshing/);
  assert.match(html, /type: 'retryScanner'/);
});

test('affiche le chrono actif et les findings par bulle de scanner', () => {
  const html = renderDashboardHtml(buildDashboardModel([{
    tool: 'Semgrep', title: 'Injection SQL possible', rawSeverity: 'HIGH', file: 'routes/users.ts'
  }], [
    { tool: 'Semgrep', status: 'running' },
    { tool: 'Trivy', status: 'pending' }
  ], {
    scanStatus: 'running',
    scanDurationMs: 65000,
    scanStartedAt: '2026-08-13T10:00:00.000Z'
  }), 'nonce');
  assert.match(html, /id="scan-chrono"/);
  assert.match(html, /data-started-at="2026-08-13T10:00:00.000Z"/);
  assert.match(html, /pipeline-popover/);
  assert.match(html, /\.pipeline-popover \{ position: fixed;/);
  assert.match(html, /placePipelinePopover/);
  assert.match(html, /aria-describedby="pipeline-semgrep-findings"/);
  assert.doesNotMatch(html, /<details class="pipeline-stage/);
  assert.doesNotMatch(html, /<summary aria-label="Afficher les findings du scanner"/);
  assert.match(html, /Semgrep · — finding\(s\)/);
  assert.match(html, /Trivy · — finding\(s\)/);
  assert.match(html, /Analysis in progress/);
});

test('affiche la cause détaillée d’un scanner en échec', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{
    tool: 'ZAP', status: 'failed', error: 'La cible locale est inaccessible.'
  }]), 'nonce');
  assert.match(html, /scanner-error/);
  assert.match(html, /La cible locale est inaccessible/);
  assert.match(html, /Scan incomplet/);
  assert.match(html, /Journal →/);
  assert.match(html, /securityCenter\.scanSelected/);
  assert.match(html, /Analyse dynamique/);
  assert.match(html, /Relancer ZAP uniquement/);
  assert.match(html, /securityCenter\.scanZap/);
  assert.match(html, /Installer \/ configurer ZAP/);
  assert.match(html, /securityCenter\.configureZap/);
});

test('conserve les résultats fiables des scanners terminés après une annulation', () => {
  const html = renderDashboardHtml(buildDashboardModel([{ tool: 'Semgrep', title: 'Alerte confirmée', rawSeverity: 'CRITICAL', sourceContext: 'production' }], [
    { tool: 'Semgrep', status: 'completed', durationMs: 4200 },
    { tool: 'ZAP', status: 'cancelled', durationMs: 3000, error: 'Scan ZAP annulé.' }
  ], { scanStatus: 'cancelled', scanDurationMs: 7200 }), 'nonce');
  assert.match(html, /Scan partiel — 2\/2 scanners terminés — ZAP annulé/);
  assert.match(html, /↻ Relancer/);
  assert.doesNotMatch(html, /Analyse en cours…/);
  assert.match(html, /pipeline-dot cancelled/);
  assert.match(html, /Scan partiel • 7 s/);
  assert.match(html, /Risque faible \(partiel\)/);
  assert.match(html, /Score partiel calculé uniquement avec 1 scanner/);
  assert.match(html, /<span class="priority-severity">CRITICAL<\/span>/);
  assert.match(html, /Alerte confirmée/);
  assert.match(html, /Voir les 1 priorité →/);
  assert.match(html, /<div class="overview-kpi hero-metric critical"><span class="hero-metric-label"><i class="hero-metric-dot critical"><\/i>Critical<\/span><strong>1<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric high"><span class="hero-metric-label"><i class="hero-metric-dot high"><\/i>High<\/span><strong>0<\/strong><\/div>/);
  assert.match(html, /<div class="overview-kpi hero-metric production">[\s\S]*Production[\s\S]*<strong>1<\/strong><small>priority findings<\/small><\/div>/);
  assert.doesNotMatch(html, /Politique projet non respectée/);
});

test('affiche uniquement les findings actifs HIGH et CRITICAL après un scan réussi', () => {
  const findings = [
    { tool: 'Semgrep', title: 'Low', rawSeverity: 'LOW' },
    { tool: 'Semgrep', title: 'High active', rawSeverity: 'HIGH' },
    { tool: 'Semgrep', title: 'High stale', rawSeverity: 'HIGH', staleFromPreviousScan: true },
    { tool: 'Semgrep', title: 'Critical accepted', rawSeverity: 'CRITICAL', triageStatus: 'accepted' }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [{ tool: 'Semgrep', status: 'completed' }], { scanStatus: 'completed' }), 'nonce');
  assert.match(html, /High active/);
  assert.match(html, /Voir les 1 priorité →/);
  assert.doesNotMatch(html, /<strong>Low<\/strong>/);
  assert.doesNotMatch(html, /<strong>High stale<\/strong>/);
  assert.doesNotMatch(html, /<strong>Critical accepted<\/strong>/);
});

test('exclut faux positifs et corrigées du risque actif sans perdre leur historique', () => {
  const model = buildDashboardModel([
    { tool: 'Gitleaks', rawSeverity: 'HIGH', sourceContext: 'production', triageStatus: 'false_positive' },
    { tool: 'Semgrep', rawSeverity: 'MEDIUM', sourceContext: 'production', triageStatus: 'confirmed' }
  ]);
  assert.equal(model.total, 2);
  assert.equal(model.activeTotal, 1);
  assert.equal(model.riskScore, 3);
  assert.deepEqual(model.byStatus, { false_positive: 1, confirmed: 1 });
});

test('affiche le résultat détaillé de la politique projet', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    scanStatus: 'completed',
    policyResult: {
      passed: false,
      activeCount: 4,
      blockingCount: 2,
      reasons: ['2 alerte(s) au seuil HIGH ou supérieur']
    }
  }), 'nonce');
  assert.match(html, /Politique projet non respectée/);
  assert.match(html, /2 alerte\(s\) au seuil HIGH ou supérieur/);
  // L'invariant porte sur le bandeau : quand la politique échoue avec des
  // raisons, il les affiche au lieu d'un appel à configurer. La navigation
  // interne offre désormais une entrée permanente vers Project Policy, ce qui
  // faisait échouer une recherche sur tout le document sans que le bandeau ait
  // changé.
  const banner = html.slice(html.indexOf('policy-banner'));
  assert.doesNotMatch(banner.slice(0, banner.indexOf('</section>')),
    /data-command="securityCenter\.openProjectPolicy"/,
    'le bandeau d’échec montre les raisons, pas un bouton de configuration');
  // CHANGEMENT DE CONTRAT DE PRESENTATION : ces commandes etaient auparavant
  // listees dans le catalogue de la barre d'activite. Ce catalogue a ete retire
  // de cette surface — la barre d'activite est un lanceur, pas une seconde
  // navigation. L'invariant qui compte n'a pas change : aucune commande n'a ete
  // supprimee, chacune reste declaree et donc accessible.
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  for (const command of [
    'securityCenter.openProjectPolicy', 'securityCenter.generateSbom', 'securityCenter.checkLicenses',
    'securityCenter.configureBackendApiKey', 'securityCenter.installPreCommitHook', 'securityCenter.showTrends'
  ]) {
    assert.ok(declared.has(command), `${command} ne doit pas disparaitre avec le catalogue de la sidebar`);
  }
});

test('sépare le dashboard en pages dédiées sans dupliquer les détails visibles', () => {
  const model = buildDashboardModel([{ tool: 'Semgrep', title: 'Alerte prioritaire', rawSeverity: 'HIGH', file: 'src/app.js' }], [{ tool: 'Semgrep', status: 'completed' }]);
  const full = renderDashboardHtml(model, 'nonce', 'full');
  assert.doesNotMatch(full, /Explorer Security Center/);
  assert.match(full, /data-command="securityCenter\.openFindingsPage"/);
  assert.match(full, /body\.surface-full \.page-findings/);
  assert.match(full, /Alerte prioritaire/);
  // Le retour au dashboard n'est plus un lien duplique en tete de chaque page :
  // il est porte une seule fois par la navigation interne du cadre partage.
  const pages = { findings: 'page-findings', scans: 'page-scans', dynamic: 'page-dynamic', analytics: 'page-analytics' };
  for (const [surface, section] of Object.entries(pages)) {
    const html = renderDashboardHtml(model, 'nonce', surface);
    assert.match(html, new RegExp(`surface-${surface}`));
    assert.match(html, new RegExp(`class="${section}"`));
    assert.match(html, /class="sc-internal-nav"/, `${surface} doit garder la navigation partagee`);
    assert.match(html, /data-command="securityCenter\.openDashboard"/, `${surface} doit pouvoir revenir au dashboard`);
    assert.doesNotMatch(html, /← Dashboard/, `${surface} ne doit plus dupliquer le lien de retour`);
  }
});

test('Activité de sécurité - historique vide', () => {
  const model = buildDashboardModel([], [], { scanHistory: [] });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /Tendance globale[\s\S]*—/);
  assert.match(html, /Temps moyen de correction[\s\S]*—/);
  assert.match(html, /Aucune correction validée/);
  assert.match(html, /history-chart-empty/);
});

test('Activité de sécurité - tendance positive et négative et division par zéro', () => {
  // 1. Tendance positive
  const history1 = [
    { savedAt: '2026-08-01T00:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', rawSeverity: 'HIGH' }] },
    { savedAt: '2026-08-02T00:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', rawSeverity: 'HIGH' }, { id: 'b', tool: 'Semgrep', rawSeverity: 'HIGH' }] }
  ];
  const model1 = buildDashboardModel([], [], { scanHistory: history1 });
  const html1 = renderDashboardHtml(model1, 'nonce', 'full');
  assert.match(html1, /\+100 %/);
  assert.match(html1, /sur 2 scans/);

  // 2. Tendance négative
  const history2 = [
    { savedAt: '2026-08-01T00:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', rawSeverity: 'HIGH' }, { id: 'b', tool: 'Semgrep', rawSeverity: 'HIGH' }] },
    { savedAt: '2026-08-02T00:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', rawSeverity: 'HIGH' }] }
  ];
  const model2 = buildDashboardModel([], [], { scanHistory: history2 });
  const html2 = renderDashboardHtml(model2, 'nonce', 'full');
  assert.match(html2, /-50 %/);
  assert.match(html2, /sur 2 scans/);

  // 3. Division par zéro (première valeur = 0)
  const history3 = [
    { savedAt: '2026-08-01T00:00:00Z', findings: [] },
    { savedAt: '2026-08-02T00:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', rawSeverity: 'HIGH' }] }
  ];
  const model3 = buildDashboardModel([], [], { scanHistory: history3 });
  const html3 = renderDashboardHtml(model3, 'nonce', 'full');
  assert.match(html3, /Tendance globale[\s\S]*—/);
  assert.match(html3, /sur 2 scans/);
});

test('Activité de sécurité - plusieurs scans le même jour (format HH:mm)', () => {
  const date1 = new Date(2026, 7, 1, 9, 0, 0);
  const date2 = new Date(2026, 7, 1, 10, 30, 0);
  const history = [
    { savedAt: date1.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] },
    { savedAt: date2.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  assert.match(html, /09:00/);
  assert.match(html, /10:30/);
});

test('Activité de sécurité - scans sur plusieurs jours (format DD/MM HH:mm)', () => {
  const date1 = new Date(2026, 7, 1, 9, 0, 0);
  const date2 = new Date(2026, 7, 3, 10, 30, 0);
  const history = [
    { savedAt: date1.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] },
    { savedAt: date2.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  assert.match(html, /01\/08/);
  assert.match(html, /09:00/);
  assert.match(html, /03\/08/);
  assert.match(html, /10:30/);
});

test('Activité de sécurité - scans sur période longue (format DD/MM/YYYY)', () => {
  const date1 = new Date(2026, 7, 1, 9, 0, 0);
  const date2 = new Date(2026, 7, 20, 10, 30, 0);
  const history = [
    { savedAt: date1.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] },
    { savedAt: date2.toISOString(), findings: [{ id: 'a', tool: 'Semgrep' }] }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  assert.match(html, /01\/08\/2026/);
  assert.match(html, /20\/08\/2026/);
});

test('Activité de sécurité - MTTR sans correction', () => {
  const history = [
    { savedAt: '2026-08-01T09:00:00Z', findings: [{ id: 'a', tool: 'Semgrep', triageStatus: 'new' }] }
  ];
  const model = buildDashboardModel([{ id: 'a', tool: 'Semgrep', triageStatus: 'new' }], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  assert.match(html, /Temps moyen de correction[\s\S]*—/);
  assert.match(html, /Aucune correction validée/);
});

test('Activité de sécurité - MTTR avec corrections (validatedAt, fixedAt, disparition)', () => {
  const history = [
    {
      savedAt: '2026-08-01T09:00:00Z',
      findings: [
        { id: 'f1', tool: 'Semgrep', triageStatus: 'new' },
        { id: 'f2', tool: 'Semgrep', triageStatus: 'new' },
        { id: 'f3', tool: 'Semgrep', triageStatus: 'new' }
      ]
    },
    {
      savedAt: '2026-08-01T10:00:00Z',
      findings: [
        { id: 'f1', tool: 'Semgrep', triageStatus: 'new' },
        { id: 'f2', tool: 'Semgrep', triageStatus: 'new' },
        { id: 'f3', tool: 'Semgrep', triageStatus: 'new' }
      ],
      scanners: [{ tool: 'Semgrep', status: 'completed' }]
    },
    {
      savedAt: '2026-08-01T11:00:00Z',
      findings: [
        { id: 'f1', tool: 'Semgrep', triageStatus: 'new' },
        { id: 'f2', tool: 'Semgrep', triageStatus: 'new' }
      ],
      scanners: [{ tool: 'Semgrep', status: 'completed' }]
    }
  ];

  const currentFindings = [
    { id: 'f1', tool: 'Semgrep', triageStatus: 'fixed', fixedAt: '2026-08-01T10:00:00Z' },
    { id: 'f2', tool: 'Semgrep', triageStatus: 'validated', validatedAt: '2026-08-01T11:00:00Z' }
  ];

  const model = buildDashboardModel(currentFindings, [{ tool: 'Semgrep', status: 'completed' }], { scanHistory: history, scanStatus: 'completed' });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /1 h 40 min/);
  assert.match(html, /findings validés/);
});

test('Activité de sécurité - retry ZAP n’efface pas Semgrep ni ne distord la tendance', () => {
  const snapshot1 = {
    Semgrep: { scanner: 'Semgrep', findings: [{ id: 's1', tool: 'Semgrep', triageStatus: 'new' }] },
    ZAP: { scanner: 'ZAP', findings: [{ id: 'z1', tool: 'ZAP', triageStatus: 'new' }] }
  };
  
  const history = [
    {
      savedAt: '2026-08-01T09:00:00Z',
      findings: [{ id: 's1', tool: 'Semgrep', triageStatus: 'new' }, { id: 'z1', tool: 'ZAP', triageStatus: 'new' }],
      dashboardOptions: {
        consolidatedSnapshot: true,
        snapshotResultSets: snapshot1
      }
    },
    {
      savedAt: '2026-08-01T10:00:00Z',
      findings: [{ id: 'z1', tool: 'ZAP', triageStatus: 'new' }],
      scanners: [{ tool: 'ZAP', status: 'completed' }],
      dashboardOptions: {
        consolidatedSnapshot: false,
        snapshotResultSets: {
          Semgrep: { scanner: 'Semgrep', findings: [{ id: 's1', tool: 'Semgrep', triageStatus: 'new' }] },
          ZAP: { scanner: 'ZAP', findings: [{ id: 'z1', tool: 'ZAP', triageStatus: 'new' }] }
        }
      }
    }
  ];

  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /Tendance globale[\s\S]*0 %/);
});

test('Activité de sécurité - Y scale dynamic tick generation', () => {
  const history = [
    { savedAt: '2026-08-01T09:00:00Z', findings: Array.from({ length: 343 }, (_, i) => ({ id: String(i), tool: 'Semgrep' })) }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /<text x="30" y=".*?" class="chart-y-axis-label" text-anchor="end">0<\/text>/);
  assert.match(html, /<text x="30" y=".*?" class="chart-y-axis-label" text-anchor="end">100<\/text>/);
  assert.match(html, /<text x="30" y=".*?" class="chart-y-axis-label" text-anchor="end">200<\/text>/);
  assert.match(html, /<text x="30" y=".*?" class="chart-y-axis-label" text-anchor="end">300<\/text>/);
  assert.match(html, /<text x="30" y=".*?" class="chart-y-axis-label" text-anchor="end">400<\/text>/);
});

test('Activité de sécurité - positionnement X proportionnel aux écarts de temps', () => {
  const history = [
    { savedAt: '2026-08-01T10:00:00Z', findings: [{ id: 'a', tool: 'Semgrep' }] },
    { savedAt: '2026-08-01T10:10:00Z', findings: [{ id: 'a', tool: 'Semgrep' }] },
    { savedAt: '2026-08-01T18:00:00Z', findings: [{ id: 'a', tool: 'Semgrep' }] }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /cx="40\.00"/);
  assert.match(html, /cx="49\.17"/);
  assert.match(html, /cx="480\.00"/);
});

test('Activité de sécurité - unique scan', () => {
  const history = [
    { savedAt: '2026-08-01T09:00:00Z', findings: [{ id: 'a', tool: 'Semgrep' }] }
  ];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  assert.match(html, /cx="260\.00"/);
  assert.doesNotMatch(html, /class="chart-line"/);
  assert.doesNotMatch(html, /fill="url\(#chart-area-gradient\)"/);
});

test('Activité de sécurité - script de positionnement tooltip local et clamping', () => {
  const history = [{ savedAt: '2026-08-01T09:00:00Z', findings: [] }];
  const model = buildDashboardModel([], [], { scanHistory: history });
  const html = renderDashboardHtml(model, 'nonce', 'full');
  
  // Tooltip DOM parent is chart wrapper, and NOT appended to body
  assert.match(html, /<div class="activity-chart-wrapper">[\s\S]*?<div id="activity-chart-tooltip" class="activity-tooltip"/);
  assert.doesNotMatch(html, /<\/section>\s*<div id="activity-chart-tooltip"/);
  
  // Tooltip uses absolute positioning (not fixed)
  assert.match(html, /\.activity-tooltip\s*\{[^}]*position:\s*absolute/);
  assert.doesNotMatch(html, /\.activity-tooltip\s*\{[^}]*position:\s*fixed/);

  // Local coordinate conversion
  assert.match(html, /dotRect\.left - wrapperRect\.left/);
  assert.match(html, /dotRect\.top - wrapperRect\.top/);
  
  // Clamping left and right edges, fallback to below near top
  assert.match(html, /if \(top < 8\)/);
  assert.match(html, /wrapper\.clientWidth - tooltipRect\.width - 8/);
  assert.match(html, /Math\.max\(8,\s*Math\.min\(left/);
});

// ---------------------------------------------------------------------------
// Regression : une seule verite de correlation visible (Checkpoint 3)
//
// Le Dashboard lisait la correlation V1 (`options.correlations`) pendant que la
// page Security Pipeline lisait les clusters V2. Pour un MEME scan, les deux
// surfaces annoncaient des nombres differents. La correlation visible vient
// desormais de V2, deja calculee par `mergeIntelligence` et deja persistee avec
// les findings — aucune correlation n'est recalculee au rendu.
// ---------------------------------------------------------------------------

const { correlateFindings } = require('../src/correlation');
const { analyzeFindings, mergeIntelligence } = require('../src/pipeline');

/** Le cas reel : une alerte ZAP et le finding SAST de la meme route. */
function divergentScanFixture() {
  return [
    { id: 'zap1', tool: 'ZAP', category: 'dynamic', stage: 'dast', sourceContext: 'runtime', endpoint: 'http://127.0.0.1:3000/api/login', method: 'POST', cwe: 'CWE-89', ruleId: '40018', rawSeverity: 'HIGH', severity: 'HIGH', title: 'SQL Injection', triageStatus: 'new' },
    { id: 'sg1', tool: 'Semgrep', category: 'sast', stage: 'sast', file: 'routes/login.js', absolutePath: '/w/routes/login.js', startLine: 12, line: 12, cwe: 'CWE-89', ruleId: 'sqli', rawSeverity: 'HIGH', severity: 'HIGH', title: 'SQLi in login', triageStatus: 'new' }
  ];
}

test('correlation : le compte du Dashboard vient de V2, pas de V1', () => {
  const raw = divergentScanFixture();
  const analysis = analyzeFindings(raw, {});
  const enriched = mergeIntelligence(raw, analysis);
  const legacy = correlateFindings(raw);

  // Le fixture diverge reellement : c'est ce qui rend le test probant.
  assert.equal(legacy.correlations.length, 1);
  assert.equal(analysis.clusters.length, 0);

  const model = buildDashboardModel(enriched, [], { correlations: legacy.correlations });
  assert.equal(model.correlations.length, analysis.clusters.length);
  assert.notEqual(model.correlations.length, legacy.correlations.length);
});

test('correlation : Dashboard et Security Pipeline s accordent sur le meme scan', () => {
  const raw = divergentScanFixture();
  const analysis = analyzeFindings(raw, {});
  const enriched = mergeIntelligence(raw, analysis);
  const model = buildDashboardModel(enriched, [], { correlations: correlateFindings(raw).correlations });

  // La page Pipeline lit `clusters` ; le Dashboard lit `model.correlations`.
  // Le critere d'acceptation du checkpoint est l'egalite de ces deux nombres.
  assert.equal(model.correlations.length, analysis.clusters.length);
  assert.equal(model.correlationCounts.high || 0, analysis.correlation.byConfidence.high || 0);
});

test('correlation : un scan reellement correle s accorde aussi', () => {
  // Le meme critere doit tenir quand il y a des clusters, pas seulement zero.
  const raw = [
    { id: 't1', tool: 'Trivy', category: 'dependency', stage: 'sca', packageName: 'lodash', package: 'lodash', packageVersion: '4.17.20', manifest: 'package.json', ruleId: 'CVE-2021-23337', vulnerabilityAliases: ['CVE-2021-23337'], rawSeverity: 'HIGH', severity: 'HIGH', title: 'lodash CVE', triageStatus: 'new' },
    { id: 'o1', tool: 'OSV-Scanner', category: 'dependency', stage: 'sca', packageName: 'lodash', package: 'lodash', packageVersion: '4.17.20', manifest: 'package.json', ruleId: 'CVE-2021-23337', vulnerabilityAliases: ['CVE-2021-23337'], rawSeverity: 'HIGH', severity: 'HIGH', title: 'lodash CVE', triageStatus: 'new' }
  ];
  const analysis = analyzeFindings(raw, {});
  const model = buildDashboardModel(mergeIntelligence(raw, analysis), [], { correlations: correlateFindings(raw).correlations });
  assert.ok(analysis.clusters.length > 0, 'le fixture doit produire au moins un cluster V2');
  assert.equal(model.correlations.length, analysis.clusters.length);
  assert.equal(model.correlationCounts.high || 0, analysis.correlation.byConfidence.high || 0);
});

test('correlation : zero cluster V2 s affiche zero et vide, de facon coherente', () => {
  const raw = divergentScanFixture();
  const model = buildDashboardModel(mergeIntelligence(raw, analyzeFindings(raw, {})), [], { correlations: correlateFindings(raw).correlations });
  assert.equal(model.correlations.length, 0);
  assert.equal(model.correlationCounts.high || 0, 0);
  const html = renderDashboardHtml(model, 'nonce');
  assert.match(html, /Aucune correspondance multi-outils/);
});

test('correlation : V1 peut differer sans changer le nombre visible', () => {
  const raw = divergentScanFixture();
  const enriched = mergeIntelligence(raw, analyzeFindings(raw, {}));
  // Trois etats V1 tres differents, un seul et meme nombre visible.
  for (const legacy of [[], correlateFindings(raw).correlations, [
    { id: 'x1', confidence: 'high', title: 'Bruit V1', tools: ['A', 'B'], reason: 'r', findingIds: ['zap1'] },
    { id: 'x2', confidence: 'high', title: 'Bruit V1', tools: ['A', 'C'], reason: 'r', findingIds: ['sg1'] }
  ]]) {
    const model = buildDashboardModel(enriched, [], { correlations: legacy });
    assert.equal(model.correlations.length, 0, 'le nombre visible ne doit dependre que de V2');
    assert.equal(model.legacyCorrelations.length, legacy.length, 'V1 reste intact dans le modele');
  }
});

test('correlation : le rendu des findings et l attribution de source restent fonctionnels', () => {
  const raw = divergentScanFixture();
  const enriched = mergeIntelligence(raw, analyzeFindings(raw, {}));
  const legacy = correlateFindings(raw).correlations;
  const html = renderDashboardHtml(buildDashboardModel(enriched, [{ tool: 'ZAP', status: 'completed' }], {
    correlations: legacy, scanStatus: 'completed', backendStatus: 'online'
  }), 'nonce');
  // L'attribution « source probable » vient toujours de V1 (`endpoint-source`).
  assert.equal(legacy[0].type, 'endpoint-source');
  assert.match(html, /SQL Injection/);
});

test('correlation : reachability, priorisation et policy gate sont inchanges', () => {
  const raw = divergentScanFixture();
  const analysis = analyzeFindings(raw, {});
  const enriched = mergeIntelligence(raw, analysis);
  // Le modele du Dashboard ne doit rien recalculer ni rien alterer.
  const before = JSON.stringify({ r: analysis.reachability, p: analysis.priority, g: analysis.policy });
  buildDashboardModel(enriched, [], { correlations: correlateFindings(raw).correlations });
  assert.equal(JSON.stringify({ r: analysis.reachability, p: analysis.priority, g: analysis.policy }), before);
  // Les verdicts par finding survivent au passage dans le modele.
  const model = buildDashboardModel(enriched, [], {});
  for (const finding of model.findings) {
    assert.ok(finding.reachability, 'chaque finding conserve son verdict d atteignabilite');
    assert.ok(finding.priority, 'chaque finding conserve sa priorite');
  }
});

test('correlation : aucune refonte visuelle — markup et classes inchanges', () => {
  const raw = divergentScanFixture();
  const model = buildDashboardModel(mergeIntelligence(raw, analyzeFindings(raw, {})), [], { correlations: correlateFindings(raw).correlations });
  const html = renderDashboardHtml(model, 'nonce');
  // Les memes elements, les memes classes, les memes libelles qu'avant.
  assert.match(html, /<div class="empty">Aucune correspondance multi-outils<\/div>/);
  assert.match(html, /<span>Corrélations<\/span>/);
  assert.match(html, /<span>Confiance élevée<\/span>/);
});
