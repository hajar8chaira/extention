const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeFindings, describeStages, buildPipelineResult, mergeIntelligence } = require('../src/pipeline');
const { correlateFindingsV2, clusterId, canonicalFinding } = require('../src/intelligence/correlation-v2');
const { unifyFindings, unifiedFinding } = require('../src/intelligence/finding-model');
const { STATUSES, statusForState, evaluateReachability } = require('../src/intelligence/reachability');
const { prioritizeFinding, prioritizeFindings, PRIORITY_CODES, LEVELS } = require('../src/intelligence/prioritization');
const { renderPipelinePageHtml } = require('../src/pipeline-page');
const { appendLocalHistory } = require('../src/scan-history-page');
const { snapshotFromLegacy, projectSnapshot } = require('../src/security-snapshot');

// Findings au format exact des normaliseurs de chaque scanner.
function trivyCve(overrides = {}) {
  return {
    id: 'trivy:vuln:CVE-2019-10744:lodash:package-lock.json', tool: 'Trivy', ruleId: 'CVE-2019-10744',
    title: 'CVE-2019-10744 — lodash (4.17.11 → 4.17.12)', severity: 'error', rawSeverity: 'CRITICAL',
    category: 'dependency', file: 'package-lock.json', absolutePath: '/repo/package-lock.json',
    startLine: 0, startColumn: 0, packageName: 'lodash', installedVersion: '4.17.11',
    fixedVersion: '4.17.12', vulnerabilityAliases: ['CVE-2019-10744'], confidence: 'high', ...overrides
  };
}
function osvCve(overrides = {}) {
  return {
    id: 'osv:CVE-2019-10744:lodash:package-lock.json', tool: 'OSV-Scanner', ruleId: 'CVE-2019-10744',
    title: 'CVE-2019-10744 — lodash', severity: 'error', rawSeverity: 'CRITICAL', category: 'dependency',
    file: 'package-lock.json', absolutePath: '/repo/package-lock.json', startLine: 0, startColumn: 0,
    packageName: 'lodash', installedVersion: '4.17.11', ecosystem: 'npm',
    vulnerabilityAliases: ['CVE-2019-10744'], confidence: 'medium', ...overrides
  };
}
function snykCve(overrides = {}) {
  return {
    id: 'snyk:oss:package-lock.json:SNYK-JS-LODASH-450202:lodash@4.17.11', tool: 'Snyk',
    ruleId: 'SNYK-JS-LODASH-450202', title: 'CVE-2019-10744 — lodash', severity: 'error', rawSeverity: 'CRITICAL',
    category: 'dependency', file: 'package-lock.json', absolutePath: '/repo/package-lock.json',
    unlocated: true, startLine: 0, startColumn: 0, packageName: 'lodash', installedVersion: '4.17.11',
    packageManager: 'npm', vulnerabilityAliases: ['SNYK-JS-LODASH-450202', 'CVE-2019-10744'],
    snykCapability: 'openSource', confidence: 'high', ...overrides
  };
}
function semgrepSqli(overrides = {}) {
  return {
    id: 'sqli:server.js:10:1', tool: 'Semgrep', ruleId: 'js-sql-string-concat', title: 'Injection SQL',
    severity: 'error', rawSeverity: 'ERROR', category: 'security', cwe: 'CWE-89',
    file: 'server.js', absolutePath: '/repo/server.js', startLine: 9, startColumn: 8,
    confidence: 'high', ...overrides
  };
}
function sonarSqli(overrides = {}) {
  return {
    id: 'sonarqube:AY-1', fingerprint: 'AY-1', tool: 'SonarQube', ruleId: 'javascript:S3649',
    title: 'Requête SQL construite dynamiquement', severity: 'error', rawSeverity: 'CRITICAL',
    category: 'security', cwe: 'CWE-89', file: 'server.js', absolutePath: '/repo/server.js',
    startLine: 9, startColumn: 4, confidence: 'high', ...overrides
  };
}
function zapSqli(overrides = {}) {
  return {
    id: 'zap:40018:POST:http://127.0.0.1:3000/api/login:username', tool: 'ZAP', ruleId: '40018',
    title: 'SQL Injection', severity: 'error', rawSeverity: 'HIGH', category: 'dynamic',
    cwe: 'CWE-89', file: 'POST http://127.0.0.1:3000/api/login', absolutePath: '',
    startLine: 0, startColumn: 0, endpoint: 'http://127.0.0.1:3000/api/login', method: 'POST',
    parameter: 'username', evidence: "' OR '1'='1", sourceContext: 'runtime', confidence: 'high', ...overrides
  };
}

const ROUTE_MAP = {
  supported: true, frameworks: ['express'],
  routes: [{ file: 'server.js', line: 7, method: 'POST', route: '/api/login', pattern: '/api/login', framework: 'express' }]
};

// ------------------------------------------------- corrélation multi-scanner

test('Trivy, OSV et Snyk sur la même CVE forment un seul groupe', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([trivyCve(), osvCve(), snykCve()]));
  assert.equal(clusters.length, 1);
  const [group] = clusters;
  assert.deepEqual(group.tools, ['OSV-Scanner', 'Snyk', 'Trivy']);
  assert.equal(group.findingCount, 3);
  assert.match(group.title, /CVE-2019-10744/);
  assert.match(group.title, /lodash/);
});

test('le groupe expose son identité, sa confiance et ses preuves', () => {
  const [group] = correlateFindingsV2(unifyFindings([trivyCve(), osvCve()])).clusters;
  assert.ok(group.id.startsWith('sca-'));
  assert.equal(group.confidence, 'high');
  assert.ok(group.reasons.some((reason) => reason.includes('CVE-2019-10744')));
  assert.ok(group.reasons.some((reason) => reason.includes('lodash')));
  assert.ok(group.reasons.some((reason) => reason.includes('4.17.11')));
});

test('le groupe désigne un finding canonique sans supprimer les autres', () => {
  const [group] = correlateFindingsV2(unifyFindings([trivyCve(), osvCve(), snykCve()])).clusters;
  assert.ok(group.primaryFindingId);
  assert.ok(group.findingIds.includes(group.primaryFindingId));
  assert.equal(group.findingIds.length, 3);
  assert.equal(group.sources.length, 3, 'chaque preuve scanner reste présente');
  // Le canonique est celui qui porte le plus d'évidence à sévérité égale.
  assert.equal(canonicalFinding(unifyFindings([osvCve(), trivyCve()])).tool, 'Trivy');
});

test('Semgrep et SonarQube sur la même faiblesse de code sont corrélés', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([semgrepSqli(), sonarSqli()]));
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].type, 'sast');
  assert.equal(clusters[0].confidence, 'high');
  assert.deepEqual(clusters[0].tools, ['Semgrep', 'SonarQube']);
});

test('ZAP est corrélé au code seulement avec une route et un CWE compatibles', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([semgrepSqli(), zapSqli()]), { routeMap: ROUTE_MAP });
  const dast = clusters.filter((cluster) => cluster.type === 'dast-sast');
  assert.equal(dast.length, 1);
  assert.deepEqual(dast[0].tools, ['Semgrep', 'ZAP']);
  assert.ok(dast[0].reasons.some((reason) => reason.includes('/api/login')));
});

// -------------------------------------------- protection contre les faux liens

test('des titres identiques ne suffisent jamais à fusionner', () => {
  // Deux CVE différentes, même intitulé, même paquet : aucune fusion.
  const { clusters } = correlateFindingsV2(unifyFindings([
    trivyCve({ id: 'a', ruleId: 'CVE-2019-10744', vulnerabilityAliases: ['CVE-2019-10744'] }),
    osvCve({ id: 'b', ruleId: 'CVE-2021-23337', vulnerabilityAliases: ['CVE-2021-23337'] })
  ]));
  assert.equal(clusters.length, 0);
});

test('un CWE partagé dans deux fichiers différents ne fusionne pas', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([
    semgrepSqli({ id: 'a', file: 'a.js', absolutePath: '/repo/a.js' }),
    sonarSqli({ id: 'b', file: 'b.js', absolutePath: '/repo/b.js' })
  ]));
  assert.equal(clusters.length, 0);
});

test('un endpoint sans route déclarée ne rejoint aucun fichier', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([semgrepSqli(), zapSqli()]), {
    routeMap: { supported: true, routes: [{ file: 'autre.js', line: 3, method: 'GET', route: '/autre', pattern: '/autre', framework: 'express' }] }
  });
  assert.equal(clusters.filter((cluster) => cluster.type === 'dast-sast').length, 0);
});

test('deux résultats du même scanner ne se corrèlent pas entre eux', () => {
  const { clusters } = correlateFindingsV2(unifyFindings([trivyCve({ id: 'a' }), trivyCve({ id: 'b' })]));
  assert.equal(clusters.length, 0);
});

// ------------------------------------------------------ identifiants stables

test('l’identifiant de groupe est stable et indépendant de l’ordre d’entrée', () => {
  const first = correlateFindingsV2(unifyFindings([trivyCve(), osvCve(), snykCve()])).clusters[0].id;
  const second = correlateFindingsV2(unifyFindings([snykCve(), osvCve(), trivyCve()])).clusters[0].id;
  assert.equal(first, second);
  assert.equal(clusterId('sca', 'npm|lodash|CVE-2019-10744'), clusterId('sca', 'npm|lodash|CVE-2019-10744'));
});

test('l’identifiant change quand l’identité de la vulnérabilité change', () => {
  assert.notEqual(clusterId('sca', 'npm|lodash|CVE-1'), clusterId('sca', 'npm|lodash|CVE-2'));
});

// ------------------------------------------------------------- reachability

test('les quatre statuts publics existent et sont dérivés des états internes', () => {
  assert.deepEqual(STATUSES, ['REACHABLE', 'POTENTIALLY_REACHABLE', 'NOT_REACHABLE', 'UNKNOWN']);
  assert.equal(statusForState('dynamically_confirmed'), 'REACHABLE');
  assert.equal(statusForState('statically_reachable'), 'REACHABLE');
  assert.equal(statusForState('imported'), 'POTENTIALLY_REACHABLE');
  assert.equal(statusForState('present'), 'POTENTIALLY_REACHABLE');
  assert.equal(statusForState('not_reachable'), 'NOT_REACHABLE');
  assert.equal(statusForState('unknown'), 'UNKNOWN');
  assert.equal(statusForState('not_evaluated'), 'UNKNOWN');
});

test('sans analyse d’imports, le statut retombe sur UNKNOWN', () => {
  const { findings, summary } = evaluateReachability(unifyFindings([trivyCve()]));
  assert.equal(findings[0].reachability.status, 'UNKNOWN');
  assert.equal(summary.statusCounts.UNKNOWN, 1);
  assert.ok(!Object.keys(summary.statusCounts).includes('NOT_REACHABLE'));
});

test('REACHABLE n’est jamais annoncé sans preuve', () => {
  const importIndex = {
    analysed: true, scannedFiles: 3, files: ['server.js'],
    index: new Map([['lodash', [{ file: 'server.js', line: 2, statement: "require('lodash')" }]]])
  };
  const { findings } = evaluateReachability(unifyFindings([trivyCve()]), { importIndex, routeMap: ROUTE_MAP });
  const reachability = findings[0].reachability;
  assert.equal(reachability.status, 'REACHABLE');
  assert.ok(reachability.evidence.length > 0, 'un statut REACHABLE porte toujours une preuve');
  assert.ok(reachability.evidence.some((item) => item.type === 'import'));
  assert.ok(reachability.evidence.some((item) => item.type === 'entrypoint'));
  assert.match(reachability.explanation, /Atteignable/);
});

test('un import hors point d’entrée reste POTENTIALLY_REACHABLE', () => {
  const importIndex = {
    analysed: true, scannedFiles: 3, files: ['util.js'],
    index: new Map([['lodash', [{ file: 'util.js', line: 2, statement: "require('lodash')" }]]])
  };
  const { findings } = evaluateReachability(unifyFindings([trivyCve()]), { importIndex });
  assert.equal(findings[0].reachability.status, 'POTENTIALLY_REACHABLE');
});

test('chaque verdict porte statut, confiance, preuve et explication', () => {
  const { findings } = evaluateReachability(unifyFindings([trivyCve()]));
  const reachability = findings[0].reachability;
  for (const field of ['state', 'status', 'confidence', 'reason', 'explanation', 'evidence']) {
    assert.ok(field in reachability, `champ ${field} manquant`);
  }
});

// ------------------------------------------------------------- priorisation

test('les niveaux P0 à P3 couvrent toute l’échelle', () => {
  assert.deepEqual(PRIORITY_CODES, ['P0', 'P1', 'P2', 'P3']);
  assert.deepEqual(LEVELS.map((level) => level.code), ['P0', 'P1', 'P2', 'P3']);
});

test('le score est strictement déterministe', () => {
  const finding = unifiedFinding(trivyCve());
  const scores = Array.from({ length: 5 }, () => prioritizeFinding(finding).priority.score);
  assert.equal(new Set(scores).size, 1);
  const explanations = Array.from({ length: 3 }, () => prioritizeFinding(finding).priority.explanation);
  assert.equal(new Set(explanations).size, 1);
});

test('la priorité expose score, code, facteurs et explication lisible', () => {
  const { priority } = prioritizeFinding(unifiedFinding(trivyCve()));
  assert.ok(Number.isInteger(priority.score));
  assert.ok(PRIORITY_CODES.includes(priority.code));
  assert.ok(priority.factors.length > 0);
  assert.ok(priority.factors.every((factor) => factor.kind && factor.label && Number.isFinite(factor.points)));
  assert.match(priority.explanation, /^P[0-3] .+ \d+\/100/);
});

test('une vulnérabilité atteignable est prioritaire sur la même non atteignable', () => {
  const base = unifiedFinding(trivyCve());
  const reachable = prioritizeFinding({ ...base, reachability: { state: 'statically_reachable', status: 'REACHABLE', confidence: 'medium', reason: '', evidence: [] } });
  const notReachable = prioritizeFinding({ ...base, reachability: { state: 'not_reachable', status: 'NOT_REACHABLE', confidence: 'low', reason: '', evidence: [] } });
  assert.ok(reachable.priority.score > notReachable.priority.score);
  assert.ok(reachable.priority.reasons.some((reason) => reason.kind === 'reachability'));
});

test('une confirmation dynamique augmente la priorité', () => {
  const base = unifiedFinding(semgrepSqli());
  const staticOnly = prioritizeFinding({ ...base, reachability: { state: 'present', status: 'POTENTIALLY_REACHABLE', confidence: 'low', reason: '', evidence: [] } });
  const confirmed = prioritizeFinding({ ...base, reachability: { state: 'dynamically_confirmed', status: 'REACHABLE', confidence: 'high', reason: '', evidence: [] } });
  assert.ok(confirmed.priority.score > staticOnly.priority.score);
});

test('des doublons du même scanner ne gonflent pas artificiellement le risque', () => {
  // Le même paquet rapporté deux fois par Trivy : aucune corroboration, donc
  // aucun bonus multi-scanner et un score identique au cas unique.
  const single = analyzeFindings([trivyCve({ id: 'a' })], {});
  const duplicated = analyzeFindings([trivyCve({ id: 'a' }), trivyCve({ id: 'b' })], {});
  assert.equal(duplicated.clusters.length, 0);
  assert.equal(duplicated.findings[0].priority.score, single.findings[0].priority.score);
  assert.equal(duplicated.findings[0].correlation, null);
});

test('deux scanners indépendants ajoutent la corroboration, pas trois fois', () => {
  const one = analyzeFindings([trivyCve()], {}).findings[0].priority.score;
  const two = analyzeFindings([trivyCve(), osvCve()], {}).findings[0].priority.score;
  const three = analyzeFindings([trivyCve(), osvCve(), snykCve()], {}).findings[0].priority.score;
  assert.ok(two > one);
  assert.equal(two, three, 'le bonus de corroboration est compté une seule fois');
});

// --------------------------------------------------------- ordre du pipeline

test('le pipeline exécute corrélation puis reachability puis priorité', () => {
  const result = analyzeFindings([trivyCve(), osvCve()], {});
  const finding = result.findings[0];
  // La priorité cite la corrélation : elle a donc été calculée après elle.
  assert.ok(finding.priority.reasons.some((reason) => reason.kind === 'correlation'));
  // La priorité cite l'atteignabilité : elle a donc été calculée après elle.
  assert.ok(finding.priority.reasons.some((reason) => reason.kind === 'reachability')
    || finding.reachability.status === 'UNKNOWN');
  assert.ok(finding.correlation && finding.reachability && finding.priority);
});

test('la corrélation précède l’atteignabilité pour la confirmation dynamique', () => {
  const result = analyzeFindings([semgrepSqli(), zapSqli()], { routeMap: ROUTE_MAP });
  const sast = result.findings.find((finding) => finding.tool === 'Semgrep');
  assert.equal(sast.reachability.status, 'REACHABLE');
  assert.equal(sast.reachability.state, 'dynamically_confirmed');
});

test('un échec de Security Intelligence ne supprime aucun résultat scanner', () => {
  const scannerFindings = [trivyCve(), osvCve()];
  const result = buildPipelineResult({
    scanId: 'scan-1', scanners: [{ tool: 'Trivy', status: 'completed' }],
    rawFindings: scannerFindings, analysis: {},
    intelligence: { status: 'failed', error: 'analyse indisponible' }
  });
  assert.equal(result.normalizedFindings, 2, 'les findings des scanners restent comptés');
  assert.equal(result.status, 'partial');
  assert.equal(result.intelligence.status, 'failed');
  const stages = describeStages({ ...result, scanners: result.scannerResults, findings: [] });
  const byId = Object.fromEntries(stages.map((stage) => [stage.id, stage]));
  assert.equal(byId.correlation.state, 'failed');
  assert.equal(byId.reachability.state, 'failed');
  assert.equal(byId.priority.state, 'failed');
  assert.match(byId.correlation.detail, /analyse indisponible/);
  // Les étapes de scan gardent leur état réel.
  assert.equal(byId.sca.state, 'passed');
});

test('mergeIntelligence n’écrase jamais les champs du scanner', () => {
  const raw = [trivyCve()];
  const merged = mergeIntelligence(raw, analyzeFindings(raw.concat(osvCve()), {}));
  assert.equal(merged[0].packageName, 'lodash');
  assert.equal(merged[0].fixedVersion, '4.17.12');
  assert.equal(merged[0].tool, 'Trivy');
  assert.ok(merged[0].priority.code);
});

// ------------------------------------------------------------- persistance

test('l’historique conserve corrélation, atteignabilité et priorité', () => {
  const raw = [trivyCve(), osvCve()];
  const enriched = mergeIntelligence(raw, analyzeFindings(raw, {}));
  const history = appendLocalHistory([], {
    localId: 'local-1', savedAt: '2026-01-01T00:00:00.000Z', workspace: 'demo',
    findings: enriched, scanners: [{ tool: 'Trivy', status: 'completed' }], dashboardOptions: {}
  });
  const stored = history[0].findings.find((finding) => finding.tool === 'Trivy');
  assert.ok(stored.priority.code);
  assert.ok(stored.reachability.status);
  assert.deepEqual(stored.correlatedTools, ['OSV-Scanner']);
});

test('le snapshot restitue les findings enrichis par outil', () => {
  const raw = [trivyCve(), osvCve()];
  const enriched = mergeIntelligence(raw, analyzeFindings(raw, {}));
  const snapshot = snapshotFromLegacy(enriched, [
    { tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }
  ]);
  const projected = projectSnapshot(snapshot);
  assert.equal(projected.findings.length, 2);
  assert.ok(projected.findings.every((finding) => finding.priority && finding.reachability));
});

// ---------------------------------------------------------------------- UI

function realModel() {
  const raw = [trivyCve(), osvCve(), snykCve(), semgrepSqli(), zapSqli()];
  const analysis = analyzeFindings(raw, { routeMap: ROUTE_MAP });
  return {
    scanId: 'scan-1', finishedAt: '2026-01-01T00:00:00.000Z',
    findings: analysis.findings, clusters: analysis.clusters,
    correlation: analysis.correlation, reachability: analysis.reachability,
    priority: analysis.priority, policy: analysis.policy, artifacts: {}, cosign: {},
    intelligence: { status: 'completed' },
    stages: describeStages({
      ...analysis,
      scanners: [{ tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' },
        { tool: 'Snyk', status: 'completed' }, { tool: 'Semgrep', status: 'completed' }, { tool: 'ZAP', status: 'completed' }]
    })
  };
}

test('un résultat de pipeline complet suffit à décrire les étapes', () => {
  // Le résultat nomme les scanners `scannerResults` : passer l'objet entier ne
  // doit pas faire apparaître toutes les étapes comme « non configurées ».
  const analysis = analyzeFindings([trivyCve(), osvCve()], {});
  const result = buildPipelineResult({
    scanId: 's', scanners: [{ tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }],
    rawFindings: [trivyCve(), osvCve()], analysis
  });
  const stages = describeStages({ ...result, ...analysis });
  assert.equal(stages.find((stage) => stage.id === 'sca').state, 'warning');
  assert.notEqual(stages.find((stage) => stage.id === 'sca').state, 'not_configured');
});

test('une étape optionnelle sans preuve propre n’est jamais annoncée « OK »', () => {
  const analysis = analyzeFindings([trivyCve(), osvCve()], {});
  const stages = describeStages({ ...analysis, scanners: [{ tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }] });
  const byId = Object.fromEntries(stages.map((stage) => [stage.id, stage]));
  // Les résultats SCA du système de fichiers ne comptent pas comme conteneur.
  assert.equal(byId.container.state, 'not_configured');
  assert.match(byId.container.detail, /Aucune image configurée/);
  assert.equal(byId.license.state, 'not_configured');
  assert.match(byId.license.detail, /s’exécute séparément/);
  // L'étape SCA, elle, montre bien ses résultats réels.
  assert.equal(byId.sca.state, 'warning');
  assert.equal(byId.sca.count, 2);
});

test('une vraie analyse d’image alimente l’étape Container', () => {
  const imageFinding = trivyCve({ id: 'img', imageName: 'node:18-alpine', file: 'node:18-alpine (alpine 3.19)' });
  const analysis = analyzeFindings([imageFinding], {});
  const stages = describeStages({ ...analysis, scanners: [{ tool: 'Trivy', status: 'completed' }] });
  const container = stages.find((stage) => stage.id === 'container');
  assert.equal(container.state, 'warning');
  assert.equal(container.count, 1);
});

test('l’onglet Pipeline reflète l’état réel de chaque phase', () => {
  const html = renderPipelinePageHtml({ ...realModel(), tab: 'pipeline' }, 'n', 'light');
  for (const stage of ['secrets', 'sast', 'sca', 'correlation', 'reachability', 'priority', 'policy', 'sbom']) {
    assert.ok(html.includes(`data-stage="${stage}"`), `étape ${stage} absente`);
  }
  assert.match(html, /vulnérabilité\(s\) confirmée\(s\) par plusieurs sources/);
});

test('l’onglet Pipeline annonce un échec de Security Intelligence sans masquer les scans', () => {
  const model = realModel();
  const html = renderPipelinePageHtml({
    ...model, tab: 'pipeline', intelligence: { status: 'failed', error: 'moteur indisponible' },
    stages: describeStages({ findings: [], scanners: [{ tool: 'Trivy', status: 'completed' }], intelligence: { status: 'failed', error: 'moteur indisponible' } })
  }, 'n', 'light');
  assert.match(html, /Security Intelligence indisponible/);
  assert.match(html, /moteur indisponible/);
  assert.match(html, /résultats des scanners restent affichés/);
});

test('l’onglet Corrélations affiche groupe, outils, confiance, preuves et nombre', () => {
  const html = renderPipelinePageHtml({ ...realModel(), tab: 'correlations' }, 'n', 'light');
  assert.match(html, /CVE-2019-10744/);
  assert.match(html, /✓ Trivy/);
  assert.match(html, /✓ OSV-Scanner/);
  assert.match(html, /✓ Snyk/);
  // Le niveau prime sur la confiance brute : « Confirmée » est une affirmation.
  assert.match(html, /Confirmée/);
  assert.match(html, /confiance high/);
  assert.match(html, /Confirmées — \d+/);
  // Les niveaux sont bien séparés en sections distinctes.
  assert.match(html, /<div class="summary-tile[^"]*"><strong>\d+<\/strong><span>Confirmées<\/span>/);
  assert.match(html, /<span>Candidates<\/span>/);
  assert.match(html, /3 finding\(s\)/);
  assert.match(html, /Groupe <code>sca-/);
  assert.match(html, /Finding canonique/);
  assert.match(html, /data-cluster-index="0"/, 'navigation vers les findings d’origine');
});

test('l’onglet Reachability affiche statut, confiance, preuve et explication', () => {
  const html = renderPipelinePageHtml({ ...realModel(), tab: 'reachability' }, 'n', 'light');
  assert.match(html, /Atteignable|Indéterminée|Potentiellement atteignable/);
  assert.match(html, /confiance /);
});

test('l’onglet Priorités affiche la distribution P0–P3 et la justification', () => {
  const html = renderPipelinePageHtml({ ...realModel(), tab: 'priorities' }, 'n', 'light');
  for (const code of PRIORITY_CODES) assert.ok(html.includes(`${code} `), `bande ${code} absente`);
  assert.match(html, /<dt>Corrélation<\/dt>/);
  assert.match(html, /Atteignabilité/);
  assert.match(html, /Sévérité/);
  assert.match(html, /priority-code/);
});

test('aucun onglet n’affiche de valeur de démonstration sans données', () => {
  const empty = { tab: 'priorities', findings: [], clusters: [], stages: [], cosign: {}, artifacts: {} };
  const html = renderPipelinePageHtml(empty, 'n', 'light');
  // Vocabulaire d'état vide : « non exécutée », jamais un faux « 0 résultat ».
  assert.match(html, /Analyse non exécutée/);
  assert.match(html, /Lancez une analyse pour calculer les priorités/);
  assert.ok(!html.includes('/100'));
});

test('le résumé de priorité expose la distribution et le sommet réel', () => {
  const raw = [trivyCve(), osvCve(), semgrepSqli()];
  const { summary } = prioritizeFindings(analyzeFindings(raw, {}).findings);
  assert.equal(Object.values(summary.distribution).reduce((total, value) => total + value, 0), 3);
  assert.ok(summary.top[0].code);
  assert.ok(summary.top[0].explanation);
  assert.ok(Array.isArray(summary.top[0].correlatedTools));
});
