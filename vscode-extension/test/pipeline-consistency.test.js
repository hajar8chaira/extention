const test = require('node:test');
const assert = require('node:assert/strict');
const {
  analyzeFindings, buildPipelineResult, mergeIntelligence, describeStages,
  restorePipelineResult, pipelineStateFor, dataAvailability, DATA_STATES
} = require('../src/pipeline');
const { renderPipelinePageHtml, renderScanFooter } = require('../src/pipeline-page');
const { createLocalScanCache, restoreLocalScanCache } = require('../src/local-scan-cache');
const { snapshotFromLegacy, projectSnapshot } = require('../src/security-snapshot');

// ---------------------------------------------------------------- fixture
// Reproduit le scan réel observé : 3 corrélations, des résultats atteignables,
// un score maximal de 62 et aucune priorité critique.

const REACHABLE_TOTAL = 216;

function scaFinding(index, tool, cve, severity = 'MEDIUM', extra = {}) {
  return {
    id: `${tool.toLowerCase()}:${cve}:pkg${index}`, tool, ruleId: cve,
    title: `${cve} — paquet${index}`, severity: 'warning', rawSeverity: severity,
    category: 'dependency', file: 'package-lock.json', absolutePath: '/repo/package-lock.json',
    startLine: 0, startColumn: 0, packageName: `paquet${index}`, installedVersion: '1.0.0',
    fixedVersion: '1.0.1', ecosystem: 'npm', vulnerabilityAliases: [cve], ...extra
  };
}

/**
 * Reproduit les chiffres observés dans l'UI réelle :
 *   3 corrélations  — 3 CVE vues chacune par Trivy et OSV
 *   216 atteignables — tous les paquets sont importés par un point d'entrée
 *   62 au maximum   — HIGH(33) + atteignable(16) + exploit publié(8) + correctif(5)
 *   0 critique      — 62 reste sous le seuil P0 de 80
 */
function realisticScan() {
  const findings = [];
  for (const [index, cve] of ['CVE-2019-0001', 'CVE-2019-0002', 'CVE-2019-0003'].entries()) {
    findings.push(scaFinding(index, 'Trivy', cve));
    findings.push(scaFinding(index, 'OSV-Scanner', cve));
  }
  // Le plus prioritaire : un seul scanner, donc aucun bonus de corroboration.
  findings.push(scaFinding(100, 'Trivy', 'CVE-2019-9999', 'HIGH', { exploitMaturity: 'Proof of Concept' }));
  for (let index = findings.length; index < REACHABLE_TOTAL; index += 1) {
    findings.push(scaFinding(index, 'Trivy', `CVE-2020-1${String(index).padStart(4, '0')}`, 'LOW'));
  }
  return findings;
}

const IMPORT_INDEX = {
  analysed: true, scannedFiles: 650, files: ['server.js'],
  index: new Map([...Array.from({ length: REACHABLE_TOTAL }, (unused, index) => index), 100]
    .map((index) => [`paquet${index}`, [{ file: 'server.js', line: 2, statement: `require('paquet${index}')` }]]))
};
const ROUTE_MAP = { supported: true, frameworks: ['express'], routes: [{ file: 'server.js', line: 7, method: 'POST', route: '/api/login', pattern: '/api/login', framework: 'express' }] };

function completedScan(scanId = 'local-execution-8') {
  const raw = realisticScan();
  const analysis = analyzeFindings(raw, { importIndex: IMPORT_INDEX, routeMap: ROUTE_MAP });
  const enriched = mergeIntelligence(raw, analysis);
  const scanners = [{ tool: 'Trivy', status: 'completed' }, { tool: 'OSV-Scanner', status: 'completed' }];
  const result = buildPipelineResult({
    scanId, workspace: '/repo', startedAt: '2026-08-16T16:55:00.000Z', finishedAt: '2026-08-16T16:57:00.000Z',
    scanners, rawFindings: enriched, analysis
  });
  return { raw, analysis, enriched, scanners, result, state: pipelineStateFor(result, analysis, {}) };
}

/** Le modèle que l'extension construit, reproduit ici sans VS Code. */
function pipelineModel({ persisted, findings, inMemoryResult = null, tab = 'pipeline' }) {
  const result = inMemoryResult || restorePipelineResult(persisted, findings);
  const model = {
    tab,
    scanId: result?.scanId || persisted?.scanId || '',
    finishedAt: result?.finishedAt || persisted?.finishedAt || '',
    restored: Boolean(result?.restored),
    findings: result?.findings || [],
    clusters: result?.clusters || [],
    intelligence: result?.intelligence || persisted?.intelligence || { status: 'completed' },
    correlation: result?.correlationSummary || persisted?.correlation || null,
    reachability: result?.reachabilitySummary || persisted?.reachability || null,
    priority: result?.prioritySummary || persisted?.priority || null,
    policy: result?.policy || persisted?.policy || null,
    artifacts: {}, cosign: {}, scanners: persisted?.scanners || []
  };
  model.stages = describeStages({ ...model, scanners: model.scanners });
  return model;
}

// -------------------------------------------------- le scan de référence

test('le scan de référence reproduit 3 corrélations / 216 atteignables / max 62', () => {
  const { analysis } = completedScan();
  assert.equal(analysis.clusters.length, 3);
  assert.equal(analysis.reachability.statusCounts.REACHABLE, REACHABLE_TOTAL);
  assert.equal(analysis.priority.highest, 62);
  assert.equal(analysis.priority.counts.critical, 0);
  assert.equal(analysis.reachability.scannedFiles, 650);
});

// ------------------------------------- résumé et détail sur le même scan

test('résumé et onglets partagent le même scanId en mémoire', () => {
  const { state, enriched, result } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched, inMemoryResult: result });
  for (const tab of ['pipeline', 'correlations', 'reachability', 'priorities']) {
    const html = renderPipelinePageHtml({ ...model, tab }, 'n', 'light');
    assert.match(html, /local-execution-8/, `onglet ${tab} n’affiche pas le scanId`);
  }
});

test('APRÈS RECHARGEMENT : le résumé annonce 3 et l’onglet Corrélations montre 3 groupes', () => {
  // currentPipelineResult est perdu ; seuls l'état persisté et les findings
  // restaurés du cache subsistent — exactement la situation du bug.
  const { state, enriched, analysis } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched, inMemoryResult: null });

  assert.equal(model.correlation.total, 3, 'le résumé conserve 3');
  assert.equal(model.clusters.length, 3, 'le détail expose bien 3 groupes');
  assert.equal(model.restored, true);

  const html = renderPipelinePageHtml({ ...model, tab: 'correlations' }, 'n', 'light');
  assert.ok(!html.includes('Aucune corrélation'), 'plus de contradiction résumé/détail');
  for (const cluster of analysis.clusters) assert.ok(html.includes(cluster.id), `groupe ${cluster.id} absent`);
});

test('APRÈS RECHARGEMENT : Reachability expose les résultats annoncés', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });
  const evaluated = model.findings.filter((finding) => finding.reachability);
  assert.equal(evaluated.length, model.findings.length);
  assert.ok(evaluated.length > 0);
  const html = renderPipelinePageHtml({ ...model, tab: 'reachability' }, 'n', 'light');
  assert.ok(!html.includes('Analyse non exécutée'));
  assert.match(html, /650 fichier\(s\)|650/);
});

test('APRÈS RECHARGEMENT : Priorités montre le classement et le maximum 62', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });
  assert.equal(model.priority.highest, 62);
  const ranked = [...model.findings].filter((finding) => finding.priority)
    .sort((left, right) => right.priority.score - left.priority.score);
  assert.equal(ranked[0].priority.score, 62, 'le sommet du classement est bien le score annoncé');
  const html = renderPipelinePageHtml({ ...model, tab: 'priorities' }, 'n', 'light');
  assert.match(html, /62<small>\/100<\/small>/);
  assert.ok(!html.includes('Analyse non exécutée'));
});

test('les quatre onglets décrivent le même scanId après rechargement', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });
  const ids = ['pipeline', 'correlations', 'reachability', 'priorities'].map((tab) => {
    const html = renderPipelinePageHtml({ ...model, tab }, 'n', 'light');
    return html.match(/Scan : <code>([^<]+)<\/code>/)?.[1];
  });
  assert.deepEqual(ids, Array(4).fill('local-execution-8'));
});

// ------------------------------------------------------- états distincts

test('données persistées manquantes ≠ zéro résultat', () => {
  // Le résumé annonce 3 corrélations mais aucun groupe n'a été conservé.
  const { state } = completedScan();
  const amputated = { ...state, clusters: [] };
  const model = pipelineModel({ persisted: amputated, findings: [] });
  const availability = dataAvailability({
    summary: model.correlation, records: model.clusters, expected: model.correlation.total
  });
  assert.equal(availability.state, DATA_STATES.MISSING_PERSISTED_DATA);
  assert.equal(availability.expected, 3);
  const html = renderPipelinePageHtml({ ...model, tab: 'correlations' }, 'n', 'light');
  assert.match(html, /Détail indisponible pour ce scan/);
  assert.match(html, /annonce 3 résultat/);
  assert.ok(!html.includes('Aucune corrélation'));
});

test('analyse non exécutée, aucun résultat et erreur sont trois états distincts', () => {
  assert.equal(dataAvailability({ summary: null }).state, DATA_STATES.NOT_EXECUTED);
  assert.equal(dataAvailability({ summary: { total: 0 }, records: [], expected: 0 }).state, DATA_STATES.NO_RESULTS);
  assert.equal(dataAvailability({ summary: { total: 2 }, records: [{}, {}], expected: 2 }).state, DATA_STATES.HAS_RESULTS);
  assert.equal(dataAvailability({ summary: { total: 1 }, intelligence: { status: 'failed', error: 'moteur KO' } }).state, DATA_STATES.ERROR);
});

test('un scan sans corrélation affiche « aucun résultat », pas « données manquantes »', () => {
  const raw = [scaFinding(1, 'Trivy', 'CVE-2021-1')];
  const analysis = analyzeFindings(raw, { importIndex: IMPORT_INDEX });
  const result = buildPipelineResult({ scanId: 'scan-vide', rawFindings: mergeIntelligence(raw, analysis), analysis });
  const model = pipelineModel({ persisted: pipelineStateFor(result, analysis, {}), findings: mergeIntelligence(raw, analysis) });
  const html = renderPipelinePageHtml({ ...model, tab: 'correlations' }, 'n', 'light');
  assert.match(html, /Analyse exécutée — aucun résultat/);
  assert.ok(!html.includes('Détail indisponible'));
});

test('une intelligence en échec affiche une erreur, pas un vide', () => {
  const failed = { scanId: 'scan-ko', intelligence: { status: 'failed', error: 'moteur indisponible' }, correlation: { total: 3 } };
  const model = pipelineModel({ persisted: failed, findings: [] });
  const html = renderPipelinePageHtml({ ...model, tab: 'correlations' }, 'n', 'light');
  assert.match(html, /Analyse impossible/);
  assert.match(html, /moteur indisponible/);
});

// ------------------------------------------------------------ restauration

test('restorePipelineResult refuse un état sans scanId', () => {
  assert.equal(restorePipelineResult(null, []), null);
  assert.equal(restorePipelineResult({}, []), null);
});

test('restorePipelineResult ne retient que les findings porteurs d’intelligence', () => {
  const { state, enriched } = completedScan();
  const pollué = [...enriched, { id: 'brut', tool: 'Gitleaks', title: 'sans intelligence' }];
  const restored = restorePipelineResult(state, pollué);
  assert.equal(restored.findings.length, enriched.length);
  assert.ok(!restored.findings.some((finding) => finding.id === 'brut'));
});

test('l’état persisté contient tout ce que les onglets consomment', () => {
  const { state } = completedScan();
  for (const key of ['scanId', 'finishedAt', 'intelligence', 'correlation', 'reachability', 'priority', 'clusters', 'artifacts', 'scanners']) {
    assert.ok(key in state, `clé ${key} absente de l’état persisté`);
  }
  assert.equal(state.clusters.length, 3);
});

// ---------------------------------------------- persistance et sérialisation

test('l’état persisté survit à une sérialisation JSON complète', () => {
  const { state, enriched } = completedScan();
  const roundTripped = JSON.parse(JSON.stringify(state));
  const findings = JSON.parse(JSON.stringify(enriched));
  const model = pipelineModel({ persisted: roundTripped, findings });
  assert.equal(model.clusters.length, 3);
  assert.equal(model.priority.highest, 62);
  assert.equal(model.findings.filter((finding) => finding.priority).length, findings.length);
});

test('les findings enrichis traversent le cache de scan local', () => {
  const { enriched, scanners, state } = completedScan();
  const snapshot = snapshotFromLegacy(enriched, scanners);
  const cache = createLocalScanCache('/repo', enriched, scanners, {}, '2026-08-16T16:57:00.000Z', snapshot);
  const restored = restoreLocalScanCache(JSON.parse(JSON.stringify(cache)), '/repo');
  const projected = projectSnapshot(restored.securitySnapshot);
  // C'est exactement le chemin que suit l'extension au redémarrage.
  const model = pipelineModel({ persisted: state, findings: projected.findings });
  assert.equal(model.clusters.length, 3);
  assert.equal(model.findings.filter((finding) => finding.reachability).length, projected.findings.length);
  assert.equal([...model.findings].sort((left, right) => right.priority.score - left.priority.score)[0].priority.score, 62);
});

test('recréation de la webview : le rendu reste identique', () => {
  const { state, enriched } = completedScan();
  const first = renderPipelinePageHtml({ ...pipelineModel({ persisted: state, findings: enriched }), tab: 'correlations' }, 'nonce-1', 'light');
  const second = renderPipelinePageHtml({ ...pipelineModel({ persisted: state, findings: enriched }), tab: 'correlations' }, 'nonce-2', 'light');
  assert.equal(first.replace(/nonce-1/g, 'N'), second.replace(/nonce-2/g, 'N'));
});

// ------------------------------------------------------- scans successifs

test('deux scans consécutifs : la page suit le plus récent, sans mélange', () => {
  const previous = completedScan('local-execution-7');
  const latest = completedScan('local-execution-8');
  const model = pipelineModel({ persisted: latest.state, findings: latest.enriched });
  assert.equal(model.scanId, 'local-execution-8');
  const html = renderPipelinePageHtml({ ...model, tab: 'correlations' }, 'n', 'light');
  assert.ok(html.includes('local-execution-8'));
  assert.ok(!html.includes('local-execution-7'), 'aucune trace du scan précédent');
  assert.notEqual(previous.state.scanId, model.scanId);
});

test('un ancien état persisté n’est jamais complété par les findings d’un autre scan', () => {
  // Les findings d'un scan récent ne doivent pas repeupler un résumé ancien
  // sans que le scanId affiché change : le scanId vient de l'état persisté.
  const previous = completedScan('local-execution-7');
  const latest = completedScan('local-execution-8');
  const model = pipelineModel({ persisted: previous.state, findings: latest.enriched });
  assert.equal(model.scanId, 'local-execution-7');
  const html = renderPipelinePageHtml({ ...model, tab: 'pipeline' }, 'n', 'light');
  assert.match(html, /local-execution-7/);
});

test('le pied de page indique le scan et son horodatage', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });
  const footer = renderScanFooter(model);
  assert.match(footer, /Scan : <code>local-execution-8<\/code>/);
  assert.match(footer, /16\/08\/2026/);
  assert.match(footer, /restauré depuis le dernier scan enregistré/);
});

// ------------------------------------------------ cohérence résumé/détail

test('INVARIANT : résumé et détail concordent pour chaque section', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });

  // Corrélation : le nombre annoncé == le nombre de groupes affichables.
  assert.equal(model.correlation.total, model.clusters.length);

  // Reachability : le total annoncé == le nombre de findings évalués.
  const announcedReach = Object.values(model.reachability.counts).reduce((total, value) => total + value, 0);
  assert.equal(announcedReach, model.findings.filter((finding) => finding.reachability).length);

  // Priorité : le maximum annoncé == le sommet du classement affiché.
  const ranked = [...model.findings].filter((finding) => finding.priority)
    .sort((left, right) => right.priority.score - left.priority.score);
  assert.equal(model.priority.highest, ranked[0].priority.score);
  const announcedPriority = Object.values(model.priority.distribution).reduce((total, value) => total + value, 0);
  assert.equal(announcedPriority, ranked.length);
});

test('l’étape Corrélation du résumé et l’onglet ne peuvent plus diverger', () => {
  const { state, enriched } = completedScan();
  const model = pipelineModel({ persisted: state, findings: enriched });
  const stage = model.stages.find((item) => item.id === 'correlation');
  assert.equal(stage.count, model.clusters.length);
  assert.match(stage.detail, /3 vulnérabilité\(s\) confirmée\(s\)/);
});
