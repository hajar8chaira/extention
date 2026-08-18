const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  CI_REPORT_SCHEMA, CI_REPORT_FILENAME, MAX_CI_REPORT_BYTES,
  buildCiReport, validateCiReport, stripPollution, findForbiddenKeys
} = require('../src/ci-report');
const {
  REPORT_STATE, CONNECTION_STATE, COMMIT_MATCH,
  findReportArtifact, artifactUrl, fetchCiReport, reportIdentity,
  testJenkinsConnection, deliveryStatusFrom, buildStatusFrom, fetchDeliveryStatus
} = require('../src/jenkins');
const { renderDeliveryPageHtml } = require('../src/delivery-page');

const SHA = 'abc123def456789012345678901234567890abcd';
const OTHER = 'def4567890123456789012345678901234567890';

/** A CLI report shaped exactly as `src/cli.js` produces it. */
const cliReport = (overrides = {}) => ({
  findings: [
    { id: 'sg:1', tool: 'Semgrep', rawSeverity: 'CRITICAL', title: 'Injection SQL' },
    { id: 'sg:2', tool: 'Semgrep', rawSeverity: 'HIGH', title: 'Commande système' },
    { id: 'gl:1', tool: 'Gitleaks', rawSeverity: 'HIGH', title: 'Clé AWS', match: 'AKIA2E4YXQ7HZ3JLKM5P' }
  ],
  scanners: [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'Gitleaks', status: 'completed' },
    { tool: 'Snyk', status: 'failed', error: 'jeton manquant' }
  ],
  failures: [],
  policyGate: {
    status: 'BLOCK', configured: true,
    summary: 'Livraison bloquée par 2 violation(s) de la politique projet.',
    violations: [
      { code: 'severity', rule: 'gate.fail_on_severity ≥ CRITICAL', title: 'Injection SQL', severity: 'CRITICAL', file: 'routes/login.ts', line: 42, priority: 91 },
      { code: 'secret', rule: 'gate.block_secrets', title: 'Clé AWS', severity: 'HIGH', file: 'config.js', line: 12 }
    ],
    warnings: [{ code: 'severity-warning', title: 'Commande système' }]
  },
  pipeline: {
    scanId: 'headless-1786973156055', status: 'blocked',
    correlationSummary: { total: 2 },
    reachabilitySummary: { analysed: true, counts: { statically_reachable: 1 } },
    prioritySummary: { distribution: { P0: 1, P1: 1 } },
    artifacts: { sbom: { status: 'generated' }, provenance: { status: 'generated' }, signing: { status: 'verified' } }
  },
  ...overrides
});

// -------------------------------------------------- contrat de rapport

test('le rapport CI est une projection du résultat existant', () => {
  const report = buildCiReport(cliReport(), { commit: SHA, branch: 'main' });
  assert.equal(report.schemaVersion, CI_REPORT_SCHEMA);
  assert.equal(report.execution.scanId, 'headless-1786973156055');
  assert.equal(report.execution.status, 'blocked');
  assert.equal(report.repository.commit, SHA);
  assert.equal(report.repository.branch, 'main');
  // Le verdict est copié, jamais recalculé.
  assert.equal(report.policy.status, 'BLOCK');
  assert.equal(report.policy.blockingCount, 2);
  assert.equal(report.policy.warningCount, 1);
  assert.equal(report.policy.reasons.length, 2);
  assert.equal(report.policy.reasons[0].rule, 'gate.fail_on_severity ≥ CRITICAL');
  assert.equal(report.policy.reasons[0].priority, 91);
  assert.deepEqual(report.summary, { findings: 3, critical: 1, high: 2, medium: 0, low: 0 });
  assert.equal(report.intelligence.correlation, 2);
  assert.deepEqual(report.supplyChain, { sbom: 'generated', provenance: 'generated', signature: 'verified', signatureVerified: true });
});

test('le statut de chaque scanner et son erreur sont préservés', () => {
  const report = buildCiReport(cliReport(), {});
  const snyk = report.scanners.find((scanner) => scanner.name === 'Snyk');
  assert.equal(snyk.status, 'failed');
  assert.match(snyk.error, /jeton manquant/);
  assert.equal(report.scanners.find((scanner) => scanner.name === 'Semgrep').findings, 2);
});

test('aucun finding brut ni secret n’entre dans le rapport', () => {
  const report = buildCiReport(cliReport(), { commit: SHA });
  const blob = JSON.stringify(report);
  assert.ok(!blob.includes('AKIA2E4YXQ7HZ3JLKM5P'), 'aucun secret matché');
  assert.ok(!('findings' in report), 'le rapport ne transporte pas les findings');
  assert.ok(Array.isArray(report.policy.reasons), 'seules les raisons du gate voyagent');
  assert.deepEqual(findForbiddenKeys(report), []);
});

test('un commit ou une branche inconnus restent nuls', () => {
  const report = buildCiReport(cliReport(), {});
  assert.equal(report.repository.commit, null);
  assert.equal(report.repository.branch, null);
});

test('une exécution partielle est signalée comme telle', () => {
  const report = buildCiReport(cliReport({ failures: [{ tool: 'Trivy' }] }), {});
  assert.equal(report.execution.status, 'partial');
  assert.deepEqual(report.execution.failedScanners, ['Trivy']);
});

test('sans gate, le rapport dit NOT_CONFIGURED et non PASS', () => {
  const report = buildCiReport(cliReport({ policyGate: null }), {});
  assert.equal(report.policy.status, 'NOT_CONFIGURED');
  assert.equal(report.policy.configured, false);
  assert.notEqual(report.policy.status, 'PASS');
});

// ------------------------------------------------------ validation

test('un rapport valide traverse la validation intact', () => {
  const built = buildCiReport(cliReport(), { commit: SHA, branch: 'main' });
  const result = validateCiReport(JSON.stringify(built));
  assert.equal(result.ok, true);
  assert.equal(result.report.policy.status, 'BLOCK');
  assert.equal(result.report.execution.scanId, 'headless-1786973156055');
  assert.equal(result.report.repository.commit, SHA);
  assert.equal(result.report.scanners.length, 3);
});

test('un JSON invalide est refusé sans exception', () => {
  const result = validateCiReport('{ pas du json');
  assert.equal(result.ok, false);
  assert.match(result.reason, /JSON invalide/);
});

test('une version de schéma inconnue est refusée, pas interprétée', () => {
  for (const schemaVersion of [0, 2, 99, undefined, 'x']) {
    const result = validateCiReport(JSON.stringify({ ...buildCiReport(cliReport(), {}), schemaVersion }));
    assert.equal(result.ok, false, `schéma ${schemaVersion} doit être refusé`);
    assert.match(result.reason, /schéma/);
  }
});

test('un rapport surdimensionné est refusé avant d’être lu', () => {
  const oversized = `{"schemaVersion":1,"padding":"${'x'.repeat(MAX_CI_REPORT_BYTES + 100)}"}`;
  const result = validateCiReport(oversized);
  assert.equal(result.ok, false);
  assert.match(result.reason, /trop volumineux/);
});

test('un rapport incomplet est refusé plutôt qu’à moitié accepté', () => {
  for (const broken of [
    { schemaVersion: 1 },
    { schemaVersion: 1, policy: {} },
    { schemaVersion: 1, policy: {}, execution: {} },
    { schemaVersion: 1, policy: 'BLOCK', execution: {}, scanners: [] }
  ]) {
    const result = validateCiReport(JSON.stringify(broken));
    assert.equal(result.ok, false, `${JSON.stringify(broken)} doit être refusé`);
  }
  assert.equal(validateCiReport('').ok, false);
  assert.equal(validateCiReport('[]').ok, false);
  assert.equal(validateCiReport('"texte"').ok, false);
});

test('la pollution de prototype est retirée', () => {
  const hostile = `{"schemaVersion":1,"__proto__":{"polluted":true},"policy":{"status":"PASS","constructor":{"x":1}},"execution":{"scanId":"s"},"scanners":[]}`;
  const result = validateCiReport(hostile);
  assert.equal(result.ok, true);
  assert.equal({}.polluted, undefined, 'Object.prototype ne doit pas être pollué');
  const clean = stripPollution(JSON.parse('{"__proto__":{"x":1},"a":{"prototype":2,"b":3}}'));
  assert.ok(!('__proto__' in clean) || clean.__proto__ === Object.prototype);
  assert.equal(clean.a.prototype, undefined);
  assert.equal(clean.a.b, 3);
});

// --------------------------------------- découverte et téléchargement

test('l’artefact du rapport est localisé sans faire confiance au chemin', () => {
  assert.equal(findReportArtifact({ artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath: `reports/${CI_REPORT_FILENAME}` }] }), `reports/${CI_REPORT_FILENAME}`);
  assert.equal(findReportArtifact({ artifacts: [] }), null);
  assert.equal(findReportArtifact({}), null);
  // Traversée, chemin absolu et chemin Windows sont refusés.
  for (const relativePath of [`../../${CI_REPORT_FILENAME}`, `/etc/${CI_REPORT_FILENAME}`, `C:/win/${CI_REPORT_FILENAME}`]) {
    assert.equal(findReportArtifact({ artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath }] }), null, relativePath);
  }
});

test('l’URL d’artefact encode chaque segment et exige un numéro de build', () => {
  assert.equal(
    artifactUrl('http://ci.local', 'equipe/projet', 184, 'reports/security-center-report.json'),
    'http://ci.local/job/equipe/job/projet/184/artifact/reports/security-center-report.json'
  );
  assert.match(artifactUrl('http://ci.local', 'p', 1, 'un dossier/r.json'), /un%20dossier/);
  for (const build of [0, -1, 'abc', null]) {
    assert.throws(() => artifactUrl('http://ci.local', 'p', build, 'r.json'), /Numéro de build invalide/);
  }
});

test('un build sans artefact de rapport est NOT_REPORTED, jamais une erreur', async () => {
  const result = await fetchCiReport({ baseUrl: 'http://ci.local', job: 'p', build: { number: 1, artifacts: [] } });
  assert.equal(result.state, REPORT_STATE.NOT_REPORTED);
  assert.equal(result.report, null);
});

test('un rapport téléchargé et valide est REPORTED', async () => {
  const built = buildCiReport(cliReport(), { commit: SHA, branch: 'main' });
  const result = await fetchCiReport({
    baseUrl: 'http://ci.local', job: 'p',
    build: { number: 184, artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath: CI_REPORT_FILENAME }] },
    requestText: async () => JSON.stringify(built)
  });
  assert.equal(result.state, REPORT_STATE.REPORTED);
  assert.equal(result.report.policy.status, 'BLOCK');
  assert.equal(result.artifactPath, CI_REPORT_FILENAME);
});

test('un rapport présent mais invalide est INVALID, avec la raison', async () => {
  const result = await fetchCiReport({
    baseUrl: 'http://ci.local', job: 'p',
    build: { number: 184, artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath: CI_REPORT_FILENAME }] },
    requestText: async () => '{ tronqué'
  });
  assert.equal(result.state, REPORT_STATE.INVALID);
  assert.match(result.reason, /JSON invalide/);
  assert.equal(result.report, null);
});

test('un téléchargement en échec est UNAVAILABLE, distinct de NOT_REPORTED', async () => {
  const result = await fetchCiReport({
    baseUrl: 'http://ci.local', job: 'p',
    build: { number: 184, artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath: CI_REPORT_FILENAME }] },
    requestText: async () => { throw new Error('Jenkins ne répond pas.'); }
  });
  assert.equal(result.state, REPORT_STATE.UNAVAILABLE);
  assert.match(result.reason, /ne répond pas/);
});

// -------------------------------------------- identité à trois branches

test('l’identité compare workspace, build et rapport', () => {
  const agree = reportIdentity({ workspaceCommit: SHA, buildCommit: SHA, reportCommit: SHA });
  assert.equal(agree.workspaceMatch, COMMIT_MATCH.SAME);
  assert.equal(agree.buildReportMatch, COMMIT_MATCH.SAME);
  assert.equal(agree.inconsistent, false);

  const otherWorkspace = reportIdentity({ workspaceCommit: OTHER, buildCommit: SHA, reportCommit: SHA });
  assert.equal(otherWorkspace.workspaceMatch, COMMIT_MATCH.DIFFERENT);
  assert.equal(otherWorkspace.inconsistent, false, 'un workspace divergent n’est pas une incohérence du build');

  const republished = reportIdentity({ workspaceCommit: SHA, buildCommit: SHA, reportCommit: OTHER });
  assert.equal(republished.buildReportMatch, COMMIT_MATCH.DIFFERENT);
  assert.equal(republished.inconsistent, true, 'un rapport d’un autre commit est incohérent');

  // Un commit inconnu n'est jamais une incohérence prouvée.
  assert.equal(reportIdentity({ workspaceCommit: SHA, buildCommit: SHA, reportCommit: '' }).inconsistent, false);
  assert.equal(reportIdentity({}).inconsistent, false);
});

test('un rapport incohérent n’est jamais attribué au build', () => {
  const built = buildCiReport(cliReport(), { commit: OTHER });
  const status = deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 184, result: 'SUCCESS', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }),
    ci: { state: REPORT_STATE.REPORTED, report: built, reason: '', artifactPath: CI_REPORT_FILENAME }
  });
  assert.equal(status.identity.inconsistent, true);
  assert.equal(status.policy, null, 'le verdict n’est pas attribué');
  assert.equal(status.artifacts, null);
  const html = renderDeliveryPageHtml(status, 'n', 'light');
  assert.match(html, /Données incohérentes/);
  assert.ok(!html.includes('>BLOCK<'), 'aucun verdict affiché sur un rapport incohérent');
});

// ------------------------------------------------- test de connexion

test('le test de connexion distingue chaque cause', async () => {
  const cases = [
    ['Jenkins a refusé l’authentification. Vérifiez l’utilisateur et le jeton.', CONNECTION_STATE.AUTH_FAILED],
    ['Jenkins a refusé l’accès à cette ressource.', CONNECTION_STATE.FORBIDDEN],
    ['Job Jenkins introuvable. Vérifiez le nom du job.', CONNECTION_STATE.JOB_NOT_FOUND],
    ['Jenkins ne répond pas.', CONNECTION_STATE.UNREACHABLE],
    ['connect ECONNREFUSED 127.0.0.1:8080', CONNECTION_STATE.UNREACHABLE],
    ['Jenkins a répondu HTTP 500.', CONNECTION_STATE.ERROR]
  ];
  for (const [message, expected] of cases) {
    const result = await testJenkinsConnection({
      baseUrl: 'http://ci.local', job: 'p', request: async () => { throw new Error(message); }
    });
    assert.equal(result.state, expected, message);
    assert.ok(!/<html|<body/i.test(result.message), 'aucun corps HTML brut');
  }
});

test('un test réussi confirme le job et l’authentification', async () => {
  const result = await testJenkinsConnection({
    baseUrl: 'http://ci.local', job: 'projet', token: 'tok', request: async () => ({ name: 'projet' })
  });
  assert.equal(result.state, CONNECTION_STATE.CONNECTED);
  assert.match(result.message, /projet/);
  assert.equal(result.authenticated, true);
  assert.ok(!result.message.includes('tok'));
});

test('une configuration incomplète est une erreur claire, sans appel réseau', async () => {
  let called = false;
  const request = async () => { called = true; return {}; };
  assert.equal((await testJenkinsConnection({ baseUrl: '', job: 'p', request })).state, CONNECTION_STATE.ERROR);
  assert.equal((await testJenkinsConnection({ baseUrl: 'http://ci.local', job: '', request })).state, CONNECTION_STATE.ERROR);
  assert.equal((await testJenkinsConnection({ baseUrl: 'http://u:p@ci.local', job: 'p', request })).state, CONNECTION_STATE.ERROR);
  assert.equal(called, false);
});

// ----------------------------------------------- rendu des états de page

test('chaque état CI a son propre rendu, et aucun ne devient PASS', () => {
  const base = { configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 184, result: 'SUCCESS', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }) };
  const cases = [
    [{ state: REPORT_STATE.NOT_REPORTED, report: null, reason: '' }, /Non rapporté/],
    [{ state: REPORT_STATE.INVALID, report: null, reason: 'Rapport illisible : JSON invalide.' }, /Rapport invalide/],
    [{ state: REPORT_STATE.UNAVAILABLE, report: null, reason: 'Jenkins ne répond pas.' }, /Rapport inaccessible/]
  ];
  for (const [ci, pattern] of cases) {
    const html = renderDeliveryPageHtml(deliveryStatusFrom({ ...base, ci }), 'n', 'light');
    assert.match(html, pattern);
    assert.ok(!/>PASS</.test(html), 'un rapport absent ne devient jamais PASS');
    assert.ok(!/Findings<\/dt><dd>0/.test(html), 'aucun 0 finding inventé');
  }
});

test('un rapport BLOCK affiche ses raisons et ses scanners', () => {
  const built = buildCiReport(cliReport(), { commit: SHA, branch: 'main' });
  const html = renderDeliveryPageHtml(deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 184, result: 'FAILURE', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }),
    ci: { state: REPORT_STATE.REPORTED, report: built, reason: '', artifactPath: CI_REPORT_FILENAME }
  }), 'n', 'light');
  assert.match(html, />BLOCK</);
  assert.match(html, /headless-1786973156055/);
  assert.match(html, /2 raison\(s\) de blocage/);
  assert.match(html, /Injection SQL/);
  assert.match(html, /gate\.fail_on_severity/);
  assert.match(html, /Snyk <span class="state">failed/);
  assert.match(html, /Ouvrir le rapport dans Jenkins/);
  // Les preuves supply chain viennent du rapport.
  assert.match(html, /Vérifiée/);
});

test('un rapport PASS n’affiche aucune raison de blocage', () => {
  const built = buildCiReport(cliReport({
    policyGate: { status: 'PASS', configured: true, summary: 'Le projet respecte la politique.', violations: [], warnings: [] },
    findings: []
  }), { commit: SHA });
  const html = renderDeliveryPageHtml(deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 185, result: 'SUCCESS', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }),
    ci: { state: REPORT_STATE.REPORTED, report: built, reason: '', artifactPath: CI_REPORT_FILENAME }
  }), 'n', 'light');
  assert.match(html, />PASS</);
  assert.ok(!html.includes('raison(s) de blocage'));
  assert.ok(!html.includes('Ouvrir le Policy Gate local'));
});

test('une exécution partielle est signalée sur la page', () => {
  const built = buildCiReport(cliReport({ failures: [{ tool: 'Trivy' }] }), { commit: SHA });
  const html = renderDeliveryPageHtml(deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 1, result: 'FAILURE', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }),
    ci: { state: REPORT_STATE.REPORTED, report: built, reason: '', artifactPath: 'r.json' }
  }), 'n', 'light');
  assert.match(html, /Partielle — un scanner n’a pas rapporté/);
});

test('la page d’accueil explique la mise en place et n’installe rien', () => {
  const html = renderDeliveryPageHtml(deliveryStatusFrom({ configured: false }), 'n', 'light');
  assert.match(html, /n’installe jamais Jenkins/);
  // L'accueil est devenu le formulaire inline : la promesse est portée par la
  // phrase d'introduction du formulaire, pas par l'ancien paragraphe.
  assert.match(html, /Connectez votre serveur Jenkins existant/);
  assert.match(html, /security-center-report\.json/);
  assert.match(html, /data-action="saveConfig"/);
  assert.match(html, /data-action="openJenkinsfile"/);
  // Aucun déclenchement de build n'est proposé.
  assert.ok(!/Lancer le build|Run build|triggerBuild/i.test(html));
});

test('le déploiement n’est jamais déduit du succès du build', () => {
  const html = renderDeliveryPageHtml(deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local',
    build: buildStatusFrom({ number: 1, result: 'SUCCESS' })
  }), 'n', 'light');
  assert.match(html, /Déploiement[\s\S]{0,120}État indisponible/);
  assert.match(html, /un build en succès ne prouve pas qu’un déploiement a eu lieu/);
});

test('la section connexion dit si un jeton existe, jamais lequel', () => {
  const status = { ...deliveryStatusFrom({ configured: true, job: 'p', baseUrl: 'http://ci.local', build: buildStatusFrom({ number: 1, result: 'SUCCESS' }) }), tokenConfigured: true, workspaceBranch: 'main' };
  const html = renderDeliveryPageHtml(status, 'n', 'light');
  assert.match(html, /Jeton configuré \(SecretStorage\)/);
  assert.match(html, /data-action="testConnection"/);
  assert.match(html, /main/);
  const anonymous = renderDeliveryPageHtml({ ...status, tokenConfigured: false }, 'n', 'light');
  assert.match(anonymous, /Aucun jeton/);
});

test('tout contenu fourni par Jenkins ou par le rapport est échappé', () => {
  const built = buildCiReport(cliReport({
    policyGate: {
      status: 'BLOCK', configured: true, summary: '<script>bad()</script>',
      violations: [{ code: 'severity', rule: '<img src=x onerror=alert(1)>', title: '<b>xss</b>', file: '"><script>x</script>' }],
      warnings: []
    },
    scanners: [{ tool: '<script>s</script>', status: 'completed' }]
  }), { commit: SHA });
  const html = renderDeliveryPageHtml(deliveryStatusFrom({
    configured: true, job: '<img src=x>', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 1, result: 'FAILURE', actions: [{ lastBuiltRevision: { SHA1: SHA } }] }),
    ci: { state: REPORT_STATE.REPORTED, report: built, reason: '', artifactPath: 'r.json' }
  }), 'n', 'light');
  assert.ok(!html.includes('<script>bad()'));
  assert.ok(!html.includes('<img src=x onerror'));
  assert.ok(!html.includes('<b>xss</b>'));
  assert.match(html, /Content-Security-Policy/);
  assert.ok(!html.includes('unsafe-eval'));
});

// ------------------------------------------- bout en bout avec transport

test('le statut complet est assemblé depuis Jenkins et le rapport', async () => {
  const built = buildCiReport(cliReport(), { commit: SHA, branch: 'main' });
  const status = await fetchDeliveryStatus({
    baseUrl: 'http://ci.local', job: 'equipe/projet', workspaceCommit: SHA, token: 'S3CR3T',
    request: async () => ({
      number: 184, result: 'FAILURE', building: false,
      actions: [{ lastBuiltRevision: { SHA1: SHA, branch: [{ name: 'refs/remotes/origin/main' }] } }],
      artifacts: [{ fileName: CI_REPORT_FILENAME, relativePath: CI_REPORT_FILENAME }]
    }),
    requestText: async () => JSON.stringify(built)
  });
  assert.equal(status.state, 'FAILED');
  assert.equal(status.ci.state, REPORT_STATE.REPORTED);
  assert.equal(status.policy.status, 'BLOCK');
  assert.equal(status.identity.inconsistent, false);
  assert.equal(status.commit.match, COMMIT_MATCH.SAME);
  assert.equal(status.artifacts.signatureVerified, true);
  // Le jeton ne franchit pas le modèle.
  assert.ok(!JSON.stringify(status).includes('S3CR3T'));
});

// ------------------------------------------------------- Jenkinsfile

test('le Jenkinsfile produit et archive le rapport CI, même sur un blocage', () => {
  const template = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
  assert.match(template, /--ci-report security-center-report\.json/);
  // L'archivage est dans un `post { always }` de l'étape : il précède l'arrêt.
  const stage = template.slice(template.indexOf("stage('Security Center')"), template.indexOf("stage('Policy Gate')"));
  assert.match(stage, /post\s*\{[\s\S]*always\s*\{[\s\S]*archiveArtifacts artifacts: 'security-center-report\.json'/);
  assert.ok(stage.indexOf('post {') > stage.indexOf('returnStatus'), 'le code de sortie est lu, pas propagé');
  // Le gate refuse ensuite, et Deploy reste gardé.
  assert.match(template, /Policy Gate BLOCK/);
  assert.match(template, /stage\('Deploy'\)[\s\S]*SC_EXIT == '0'/);
});
