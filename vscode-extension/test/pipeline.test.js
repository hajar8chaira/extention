const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  PIPELINE_STAGES, analyzeFindings, analyzeWorkspace, describeStages,
  buildPipelineResult, mergeIntelligence, runSupplyChainStages, packagesOfInterest
} = require('../src/pipeline');
const { renderPipelinePageHtml, renderCluster, STATE_LABELS, TABS } = require('../src/pipeline-page');
const { renderFindingDetailsHtml, renderIntelligenceSection } = require('../src/finding-details');
const { validatePolicy, parsePolicyYaml } = require('../src/project-policy');

function dependency(overrides = {}) {
  return {
    id: 'dep-trivy', tool: 'Trivy', category: 'dependency', ruleId: 'CVE-2020-8203',
    title: 'CVE-2020-8203 — lodash', rawSeverity: 'HIGH', severity: 'error',
    file: 'package-lock.json', absolutePath: '/repo/package-lock.json', unlocated: true, startLine: 0,
    packageName: 'lodash', installedVersion: '4.17.11', fixedVersion: '4.17.21',
    ecosystem: 'npm', vulnerabilityAliases: ['CVE-2020-8203'], ...overrides
  };
}

const RAW_FINDINGS = [
  dependency(),
  dependency({ id: 'dep-osv', tool: 'OSV-Scanner' }),
  {
    id: 'secret-1', tool: 'Gitleaks', category: 'secret', ruleId: 'aws-key', title: 'Clé AWS exposée',
    rawSeverity: 'CRITICAL', severity: 'error', file: 'config/production.js',
    absolutePath: '/repo/config/production.js', startLine: 3, startColumn: 0, sourceContext: 'production'
  }
];

// ------------------------------------------------------------ orchestration

test('le pipeline enchaîne corrélation, reachability, priorité et gate', () => {
  const result = analyzeFindings(RAW_FINDINGS, { policy: validatePolicy(parsePolicyYaml('gate:\n  block_secrets: true\n')) });
  assert.equal(result.findings.length, 3);
  assert.equal(result.clusters.length, 1);
  assert.ok(result.findings.every((finding) => finding.reachability && finding.priority));
  assert.equal(result.policy.status, 'BLOCK');
  assert.equal(result.correlation.total, 1);
});

test('chaque étape reste indépendante et sans effet de bord', () => {
  const before = JSON.stringify(RAW_FINDINGS);
  analyzeFindings(RAW_FINDINGS, {});
  assert.equal(JSON.stringify(RAW_FINDINGS), before, 'les findings d’entrée ne sont jamais mutés');
});

test('sans politique, le gate ne bloque rien mais ne prétend pas passer', () => {
  // Une politique absente n'a rien autorisé : elle ne peut pas rendre un PASS.
  assert.equal(analyzeFindings(RAW_FINDINGS, {}).policy.status, 'NOT_CONFIGURED');
  assert.equal(analyzeFindings(RAW_FINDINGS, {}).policy.configured, false);
});

test('l’intelligence est fusionnée sur les findings existants sans les remplacer', () => {
  const analysis = analyzeFindings(RAW_FINDINGS, {});
  const merged = mergeIntelligence(RAW_FINDINGS, analysis);
  assert.equal(merged.length, RAW_FINDINGS.length);
  const trivy = merged.find((finding) => finding.id === 'dep-trivy');
  assert.equal(trivy.tool, 'Trivy');
  assert.equal(trivy.packageName, 'lodash');
  assert.equal(trivy.fixedVersion, '4.17.21', 'les champs scanner sont préservés');
  assert.ok(trivy.priority.score > 0);
  assert.deepEqual(trivy.correlatedTools, ['OSV-Scanner']);
  assert.equal(trivy.correlationConfidence, 'high');
  assert.ok(trivy.correlationClusters[0].sources.length === 2);
});

test('un finding non analysé n’est pas altéré', () => {
  const merged = mergeIntelligence([...RAW_FINDINGS, { id: 'inconnu', tool: 'X' }], analyzeFindings(RAW_FINDINGS, {}));
  assert.deepEqual(merged.at(-1), { id: 'inconnu', tool: 'X' });
});

test('ne résout les imports que des paquets réellement vulnérables', () => {
  assert.deepEqual(packagesOfInterest(RAW_FINDINGS), ['lodash']);
});

test('analyzeWorkspace tolère un échec de lecture du workspace', async () => {
  const result = await analyzeWorkspace({
    workspacePath: '/inexistant', findings: RAW_FINDINGS,
    buildRoutes: async () => { throw new Error('illisible'); },
    buildImports: async () => { throw new Error('illisible'); }
  });
  // L'analyse continue, mais rien n'est déclaré non atteignable sur cette base.
  assert.equal(result.findings.find((finding) => finding.stage === 'sca').reachability.state, 'unknown');
});

test('l’annulation interrompt l’analyse du workspace', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() => analyzeWorkspace({
    workspacePath: '.', findings: [], signal: controller.signal,
    buildRoutes: async () => ({ routes: [], supported: false }),
    buildImports: async () => ({ index: new Map(), analysed: true, files: [] })
  }), /annulée/);
});

// ------------------------------------------------------------------ étapes

test('les étapes du pipeline couvrent scan, intelligence, décision et artefacts', () => {
  assert.deepEqual([...new Set(PIPELINE_STAGES.map((stage) => stage.kind))], ['scan', 'intelligence', 'decision', 'artifact']);
  for (const id of ['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'correlation', 'reachability', 'policy', 'sbom', 'provenance', 'signing']) {
    assert.ok(PIPELINE_STAGES.some((stage) => stage.id === id), `étape ${id} absente`);
  }
});

test('l’état des étapes provient uniquement de données réelles', () => {
  const analysis = analyzeFindings(RAW_FINDINGS, { policy: validatePolicy(parsePolicyYaml('gate:\n  block_secrets: true\n')) });
  const stages = describeStages({
    ...analysis,
    scanners: [{ tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }, { tool: 'Gitleaks', status: 'completed' }]
  });
  const byId = Object.fromEntries(stages.map((stage) => [stage.id, stage]));
  assert.equal(byId.secrets.state, 'blocked');
  assert.equal(byId.sca.state, 'warning');
  assert.equal(byId.sast.state, 'not_configured', 'aucun scanner SAST exécuté');
  assert.equal(byId.policy.state, 'blocked');
  assert.equal(byId.correlation.count, 1);
  assert.equal(byId.sbom.state, 'not_configured');
});

test('un scanner en cours est rapporté comme tel, sans progression fictive', () => {
  const stages = describeStages({ findings: [], scanners: [{ tool: 'Semgrep', status: 'running' }] }, { runningTools: ['Semgrep'] });
  assert.equal(stages.find((stage) => stage.id === 'sast').state, 'running');
});

test('un scanner en échec n’est pas présenté comme réussi', () => {
  const stages = describeStages({ findings: [], scanners: [{ tool: 'Gitleaks', status: 'failed' }] });
  assert.equal(stages.find((stage) => stage.id === 'secrets').state, 'failed');
});

test('une reachability non analysée est ignorée, jamais annoncée comme OK', () => {
  const stages = describeStages({ findings: [], scanners: [], reachability: { analysed: false, counts: {}, scannedFiles: 0 } });
  const stage = stages.find((item) => item.id === 'reachability');
  assert.equal(stage.state, 'skipped');
  assert.match(stage.detail, /indéterminée/);
});

// ---------------------------------------------------------------- résultat

test('le résultat structuré du pipeline expose toutes les étapes', () => {
  const analysis = analyzeFindings(RAW_FINDINGS, { policy: validatePolicy(parsePolicyYaml('gate:\n  block_secrets: true\n')) });
  const result = buildPipelineResult({
    scanId: 'scan-1', workspace: '/repo', startedAt: '2026-01-01T00:00:00.000Z',
    scanners: [{ tool: 'Trivy', status: 'completed' }], rawFindings: RAW_FINDINGS, analysis,
    artifacts: { sbom: { status: 'generated', componentCount: 2 } }
  });
  assert.equal(result.scanId, 'scan-1');
  assert.equal(result.normalizedFindings, 3);
  assert.equal(result.correlatedFindings, 1);
  assert.equal(result.status, 'blocked');
  assert.equal(result.artifacts.sbom.componentCount, 2);
  assert.ok(result.policy && result.reachabilitySummary && result.prioritySummary && result.correlationSummary);
});

test('le statut global reflète le gate puis les échecs de scanners', () => {
  const clean = analyzeFindings([], {});
  assert.equal(buildPipelineResult({ analysis: clean }).status, 'passed');
  assert.equal(buildPipelineResult({ analysis: clean, failures: ['Trivy: timeout'] }).status, 'partial');
});

// -------------------------------------------------------- étapes artefacts

test('les étapes supply chain ne s’exécutent que si elles sont demandées', async () => {
  assert.deepEqual(await runSupplyChainStages({ workspacePath: '/repo' }), {});
  const artifacts = await runSupplyChainStages({
    workspacePath: '/repo', sbom: { enabled: true },
    generateSbom: async () => ({ status: 'generated', path: '/repo/sbom.json', digest: 'sha256:x', componentCount: 3 })
  });
  assert.equal(artifacts.sbom.componentCount, 3);
  assert.equal(artifacts.provenance, undefined);
});

test('la provenance atteste le SBOM quand aucun autre artefact n’est fourni', async () => {
  const artifacts = await runSupplyChainStages({
    workspacePath: '/repo', sbom: { enabled: true }, provenance: { enabled: true },
    generateSbom: async () => ({ status: 'generated', path: '/repo/sbom.json', digest: 'sha256:x' }),
    generateProvenanceDocument: async ({ artifactPath, sbom }) => ({ status: 'generated', artifact: artifactPath, sbomLinked: Boolean(sbom) })
  });
  assert.equal(artifacts.provenance.artifact, '/repo/sbom.json');
  assert.equal(artifacts.provenance.sbomLinked, true);
});

test('sans artefact, la provenance échoue explicitement', async () => {
  const artifacts = await runSupplyChainStages({ workspacePath: '/repo', provenance: { enabled: true } });
  assert.equal(artifacts.provenance.status, 'failed');
  assert.match(artifacts.provenance.reason, /Aucun artefact à attester/);
});

// ---------------------------------------------------------------------- UI

function pageModel(overrides = {}) {
  const analysis = analyzeFindings(RAW_FINDINGS, { policy: validatePolicy(parsePolicyYaml('gate:\n  block_secrets: true\n')) });
  return {
    tab: 'pipeline', scanId: 'scan-1', finishedAt: '2026-01-01T00:00:00.000Z',
    findings: analysis.findings, clusters: analysis.clusters,
    correlation: analysis.correlation, reachability: analysis.reachability,
    priority: analysis.priority, policy: analysis.policy,
    artifacts: {}, cosign: { installed: false },
    stages: describeStages({ ...analysis, scanners: [{ tool: 'Trivy', status: 'completed' }, { tool: 'Gitleaks', status: 'completed' }] }),
    ...overrides
  };
}

test('la page Security Pipeline expose ses onglets', () => {
  const html = renderPipelinePageHtml(pageModel(), 'nonce', 'light');
  assert.match(html, /<h1>Security Pipeline<\/h1>/);
  for (const [, label] of TABS) assert.ok(html.includes(`>${label}</button>`), `onglet ${label} absent`);
});

test('les étapes affichent leur état réel', () => {
  const html = renderPipelinePageHtml(pageModel(), 'nonce', 'light');
  assert.match(html, /data-stage="secrets"/);
  assert.match(html, /data-stage="policy"/);
  assert.ok(html.includes(STATE_LABELS.blocked));
  assert.match(html, /BLOCK/);
});

test('la page ne fabrique aucune progression', () => {
  const html = renderPipelinePageHtml({ tab: 'pipeline', stages: [], cosign: {} }, 'nonce', 'light');
  assert.match(html, /Aucune analyse enregistrée/);
  assert.ok(!html.includes('<progress'));
});

test('l’onglet Corrélations montre les outils et les preuves d’origine', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'correlations' }), 'nonce', 'light');
  assert.match(html, /✓ Trivy/);
  assert.match(html, /✓ OSV-Scanner/);
  assert.match(html, /Preuves d’origine conservées/);
  assert.match(html, /CVE-2020-8203/);
  assert.match(html, /Confirmée/);
  assert.match(html, /confiance high/);
});

test('l’onglet Reachability explique chaque état', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'reachability' }), 'nonce', 'light');
  assert.match(html, /Reachability|atteignabilité|Indéterminée/i);
  assert.match(html, /graphe d’appel|indéterminée/i);
});

test('l’onglet Priorités justifie chaque score', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'priorities' }), 'nonce', 'light');
  assert.match(html, /\/100/);
  assert.match(html, /pourquoi/i);
  assert.match(html, /Sévérité/);
});

test('l’onglet Supply Chain n’offre que des actions implémentées', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'supply-chain' }), 'nonce', 'light');
  assert.match(html, /data-action="generateSbom"/);
  assert.match(html, /data-action="generateProvenance"/);
  assert.match(html, /data-action="verifySignature"/);
  assert.match(html, /aucun niveau SLSA revendiqué/);
});

test('la signature est refusée dans l’UI quand le gate a bloqué', () => {
  const blocked = renderPipelinePageHtml(pageModel({ tab: 'supply-chain' }), 'nonce', 'light');
  assert.match(blocked, /Signature indisponible/);
  assert.ok(!blocked.includes('data-action="signArtifact"'));
});

test('aucun secret ni chemin de clé privée n’atteint la page', () => {
  const html = renderPipelinePageHtml(pageModel({
    tab: 'supply-chain',
    cosign: { installed: true, keyConfigured: true, publicKeyPath: '/keys/cosign.pub', passwordConfigured: true, version: '3.1.3' }
  }), 'nonce', 'light');
  assert.match(html, /cosign\.pub/);
  assert.ok(!html.includes('cosign.key'));
  assert.match(html, /SecretStorage/);
});

test('le détail d’un finding corrélé montre outils, atteignabilité et priorité', () => {
  const analysis = analyzeFindings(RAW_FINDINGS, {});
  const merged = mergeIntelligence(RAW_FINDINGS, analysis);
  const html = renderFindingDetailsHtml(merged.find((finding) => finding.id === 'dep-trivy'), 'nonce');
  assert.match(html, /Détectée par/);
  assert.match(html, /✓ Trivy/);
  assert.match(html, /✓ OSV-Scanner/);
  assert.match(html, /Atteignabilité/);
  assert.match(html, /Pourquoi cette priorité/);
  // Les preuves du scanner d'origine restent affichées en dessous.
  assert.match(html, /4\.17\.21/);
});

test('un finding sans intelligence garde exactement son rendu d’origine', () => {
  assert.equal(renderIntelligenceSection({ tool: 'Semgrep', title: 'x' }), '');
});

test('Security Pipeline redesigned flow layout and badges', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'pipeline' }), 'nonce', 'light');

  // Verify visual flow sections exist
  assert.match(html, /1\. ANALYSE/);
  assert.match(html, /2\. SECURITY INTELLIGENCE/);
  assert.match(html, /3\. DÉCISION/);
  assert.match(html, /4\. PREUVES SUPPLY CHAIN/);

  // Verify responsive grids and flow connector are present
  assert.match(html, /class="pipeline-flow"/);
  assert.match(html, /class="pipeline-grid"/);
  assert.match(html, /class="flow-connector"/);

  // Verify status badges exist
  assert.match(html, /class="status-badge status-success"/);

  // Verify visual pipeline flow layout wrapper and nodes
  assert.match(html, /class="visual-pipeline-flow"/);
  assert.match(html, /class="flow-node node-project/);
  assert.match(html, /class="flow-node node-detection/);
  assert.match(html, /class="flow-node node-intel/);
  assert.match(html, /class="flow-node node-policy/);
  assert.match(html, /class="flow-node node-destination/);
  assert.match(html, /class="flow-line/);
  assert.match(html, /class="flow-pulse"/);
});

test('Security Pipeline light theme classes and variable scoping', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'pipeline' }), 'nonce', 'light');

  // Assert that body has correct light class
  assert.match(html, /body class="theme-light"/);

  // Assert themeOverridesCss stylesheet is injected
  assert.match(html, /body\.theme-light\s*\{/);

  // Assert pipeline variables scope to body and map to --sc-* values
  assert.match(html, /body\s*\{[\s\S]*?--bg:\s*var\(--sc-bg\)/);
  assert.match(html, /body\s*\{[\s\S]*?--card:\s*var\(--sc-surface\)/);

  // Verify no hardcoded dark backgrounds on normal elements in light mode
  assert.ok(!html.includes('background: #1e1e1e'));
});

test('Security Pipeline dark theme classes and variable scoping', () => {
  const html = renderPipelinePageHtml(pageModel({ tab: 'pipeline' }), 'nonce', 'dark');

  // Assert that body has correct dark class
  assert.match(html, /body class="theme-dark"/);

  // Assert themeOverridesCss stylesheet is injected
  assert.match(html, /body\.theme-dark\s*\{/);

  // Assert pipeline variables scope to body
  assert.match(html, /body\s*\{[\s\S]*?--bg:\s*var\(--sc-bg\)/);
});
