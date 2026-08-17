'use strict';

/**
 * The Security Center pipeline.
 *
 * Scanners → normalisation → deduplication → correlation → reachability →
 * prioritization → policy gate → SBOM → provenance → signing.
 *
 * This module owns the stages *after* scanner execution. The extension and the
 * headless CLI both call it, so a verdict can never differ between the IDE and
 * CI: there is exactly one implementation of the decision path.
 *
 * Scanner execution itself stays in the orchestrator; supply-chain evidence
 * stays in `supply-chain/`. This file only sequences them.
 */

const path = require('path');
const { unifyFindings } = require('./intelligence/finding-model');
const { correlateFindingsV2 } = require('./intelligence/correlation-v2');
const { buildRouteMap } = require('./intelligence/route-map');
const { evaluateReachability, buildImportIndex } = require('./intelligence/reachability');
const { prioritizeFindings } = require('./intelligence/prioritization');
const { evaluatePolicyGate, STATUS } = require('./intelligence/policy-gate');
const { generateSbomArtifact } = require('./supply-chain/sbom');
const { generateProvenance } = require('./supply-chain/provenance');

/**
 * The stages the pipeline page renders, in execution order. `tools` names the
 * scanners that can feed a stage, so a stage with no enabled scanner is
 * reported as « non configurée » rather than as « aucun problème ».
 */
const PIPELINE_STAGES = Object.freeze([
  { id: 'secrets', label: 'Secrets', kind: 'scan', tools: ['Gitleaks'], stages: ['secrets'] },
  { id: 'sast', label: 'SAST', kind: 'scan', tools: ['Semgrep', 'SonarQube', 'Snyk'], stages: ['sast'] },
  { id: 'sca', label: 'SCA', kind: 'scan', tools: ['Trivy', 'OSV-Scanner', 'Snyk'], stages: ['sca'] },
  { id: 'iac', label: 'IaC', kind: 'scan', tools: ['Trivy', 'Snyk'], stages: ['iac'] },
  // Container only counts findings that really came from an image scan, and
  // licences only from a licence analysis: neither borrows the filesystem SCA
  // results, which would make an unconfigured stage look like a passing one.
  { id: 'container', label: 'Container', kind: 'scan', tools: ['Trivy'], stages: ['sca'], optional: true, requiresEvidence: 'image', emptyDetail: 'Aucune image configurée pour l’analyse de conteneur' },
  { id: 'dast', label: 'DAST', kind: 'scan', tools: ['ZAP'], stages: ['dast'] },
  { id: 'license', label: 'Licences', kind: 'scan', tools: ['Trivy'], stages: ['license'], optional: true, emptyDetail: 'L’analyse des licences s’exécute séparément et n’a pas été lancée pour ce scan' },
  { id: 'correlation', label: 'Corrélation', kind: 'intelligence' },
  { id: 'reachability', label: 'Reachability', kind: 'intelligence' },
  { id: 'priority', label: 'Priorisation', kind: 'intelligence' },
  { id: 'policy', label: 'Policy Gate', kind: 'decision' },
  { id: 'sbom', label: 'SBOM', kind: 'artifact' },
  { id: 'provenance', label: 'Provenance', kind: 'artifact' },
  { id: 'signing', label: 'Signature', kind: 'artifact' }
]);

const STAGE_STATES = Object.freeze(['not_configured', 'ready', 'running', 'passed', 'warning', 'blocked', 'skipped', 'failed']);

/**
 * Runs the intelligence stages over already-normalized findings.
 *
 * Pure with respect to the workspace: everything read from disk is passed in
 * through `routeMap` / `importIndex`, which keeps this testable and lets the
 * CLI and the extension share it unchanged.
 */
function analyzeFindings(rawFindings = [], { routeMap = null, importIndex = null, policy = null, artifacts = null } = {}) {
  const unified = unifyFindings(rawFindings);
  const correlated = correlateFindingsV2(unified, { routeMap });
  const reachable = evaluateReachability(correlated.findings, {
    importIndex, routeMap, clusters: correlated.clusters
  });
  const prioritized = prioritizeFindings(reachable.findings);
  const gate = evaluatePolicyGate(prioritized.findings, policy, { artifacts });
  return {
    findings: prioritized.findings,
    clusters: correlated.clusters,
    correlation: correlated.summary,
    reachability: reachable.summary,
    priority: prioritized.summary,
    policy: gate
  };
}

/**
 * Carries the intelligence verdicts back onto the scanner findings the rest of
 * Security Center already renders (tree, dashboard, details, history), so no
 * surface needs a parallel finding model. Untouched fields stay untouched.
 */
function mergeIntelligence(rawFindings = [], analysis = {}) {
  const byId = new Map((analysis.findings || []).map((finding) => [finding.id, finding]));
  const clustersById = new Map((analysis.clusters || []).map((cluster) => [cluster.id, cluster]));
  return rawFindings.map((finding) => {
    const unified = byId.get(finding.id);
    if (!unified) return finding;
    return {
      ...finding,
      ...(unified.correlation ? {
        correlation: unified.correlation,
        correlationClusters: unified.correlation.clusterIds.map((id) => clustersById.get(id)).filter(Boolean),
        // The historical fields keep working for the existing UI.
        correlatedTools: unified.correlation.corroboratingTools,
        correlationConfidence: unified.correlation.confidence
      } : {}),
      reachability: unified.reachability,
      priority: unified.priority
    };
  });
}

/** Package names worth resolving imports for: the vulnerable ones only. */
function packagesOfInterest(rawFindings = []) {
  return [...new Set(rawFindings
    .filter((finding) => finding.category === 'dependency' && finding.packageName)
    .map((finding) => String(finding.packageName)))];
}

/**
 * Full analysis including the workspace reads. `collect` is injectable so tests
 * can drive the pipeline without touching a real project.
 */
async function analyzeWorkspace({
  workspacePath, findings = [], policy = null, artifacts = null, signal,
  buildRoutes = buildRouteMap, buildImports = buildImportIndex
} = {}) {
  const root = path.resolve(workspacePath || '.');
  // Both scans are best-effort: a failure degrades the evidence, and the
  // engines below report « indéterminée » rather than inventing a verdict.
  const [routeMap, importIndex] = await Promise.all([
    buildRoutes(root).catch(() => ({ routes: [], supported: false, frameworks: [], scannedFiles: 0 })),
    buildImports(root, packagesOfInterest(findings)).catch(() => ({ index: new Map(), analysed: false, scannedFiles: 0, files: [] }))
  ]);
  if (signal?.aborted) throw new Error('Analyse du pipeline annulée.');
  return { ...analyzeFindings(findings, { routeMap, importIndex, policy, artifacts }), routeMap, importIndex };
}

/**
 * Derives the state of every stage from real execution data. Nothing here is
 * animated or simulated: a stage the pipeline did not run is `skipped`, and a
 * stage whose scanners are all disabled is `not_configured`.
 */
function describeStages(result = {}, { runningTools = [] } = {}) {
  const findings = result.findings || [];
  // A pipeline result names this `scannerResults`; a live scan names it
  // `scanners`. Both are accepted so a caller passing the whole result cannot
  // silently render every stage as « non configurée ».
  const scanners = result.scanners || result.scannerResults || [];
  const statusByTool = new Map(scanners.map((scanner) => [scanner.tool, scanner.status]));
  const running = new Set(runningTools);
  const policy = result.policy;
  const artifacts = result.artifacts || {};
  // A failed intelligence run is reported as failed on its own stages. The
  // scanner stages keep their results: intelligence never deletes findings.
  const intelligenceFailure = result.intelligence?.status === 'failed' ? result.intelligence : null;

  return PIPELINE_STAGES.map((stage) => {
    if (intelligenceFailure && ['correlation', 'reachability', 'priority'].includes(stage.id)) {
      return { ...stage, state: 'failed', count: null, detail: `Security Intelligence indisponible : ${intelligenceFailure.error || 'raison inconnue'}` };
    }
    return describeStage(stage, { findings, statusByTool, running, policy, artifacts, result });
  });
}

/** State of a single stage, derived only from what actually ran. */
function describeStage(stage, { findings, statusByTool, running, policy, artifacts, result }) {
  {
    const stageFindings = stage.stages
      ? findings.filter((finding) => stage.stages.includes(finding.stage)
        && (!stage.requiresEvidence || Boolean(finding[stage.requiresEvidence])))
      : [];
    if (stage.kind === 'scan') {
      const available = stage.tools.filter((tool) => statusByTool.has(tool));
      // An optional stage with nothing of its own to show has not run: saying
      // « aucun résultat » would read as a clean bill of health it never earned.
      if (stage.optional && !stageFindings.length && available.length && stage.emptyDetail) {
        return { ...stage, state: 'not_configured', detail: stage.emptyDetail, count: null, tools: available };
      }
      if (stage.tools.some((tool) => running.has(tool))) {
        return { ...stage, state: 'running', detail: `${stage.tools.filter((tool) => running.has(tool)).join(', ')} en cours`, count: null };
      }
      if (!available.length) {
        return { ...stage, state: 'not_configured', detail: `Aucun scanner actif pour cette étape (${stage.tools.join(', ')})`, count: null };
      }
      const failed = available.filter((tool) => statusByTool.get(tool) === 'failed');
      if (failed.length === available.length) {
        return { ...stage, state: 'failed', detail: `${failed.join(', ')} en échec`, count: null, tools: available };
      }
      const blocking = stageFindings.filter((finding) => policy?.violations?.some((violation) => violation.findingId === finding.id));
      const state = blocking.length ? 'blocked' : stageFindings.length ? 'warning' : 'passed';
      return {
        ...stage,
        state,
        tools: available,
        count: stageFindings.length,
        detail: stageFindings.length
          ? `${stageFindings.length} résultat(s)${blocking.length ? ` dont ${blocking.length} bloquant(s)` : ''} — ${available.join(', ')}`
          : `Aucun résultat — ${available.join(', ')}`
      };
    }
    if (stage.id === 'correlation') {
      const summary = result.correlation;
      if (!summary) return { ...stage, state: 'skipped', detail: 'Corrélation non exécutée', count: null };
      return {
        ...stage,
        state: summary.total ? 'warning' : 'passed',
        count: summary.total,
        detail: summary.total
          ? `${summary.total} vulnérabilité(s) confirmée(s) par plusieurs sources`
          : 'Aucun recoupement entre scanners'
      };
    }
    if (stage.id === 'reachability') {
      const summary = result.reachability;
      if (!summary) return { ...stage, state: 'skipped', detail: 'Reachability non évaluée', count: null };
      const confirmed = (summary.counts?.dynamically_confirmed || 0) + (summary.counts?.statically_reachable || 0);
      return {
        ...stage,
        state: summary.analysed ? (confirmed ? 'warning' : 'passed') : 'skipped',
        count: confirmed,
        detail: summary.analysed
          ? `${confirmed} résultat(s) atteignable(s) sur ${summary.scannedFiles} fichier(s) analysé(s)`
          : 'Analyse des imports non exécutée : atteignabilité indéterminée'
      };
    }
    if (stage.id === 'priority') {
      const summary = result.priority;
      if (!summary) return { ...stage, state: 'skipped', detail: 'Priorisation non exécutée', count: null };
      const critical = summary.counts?.critical || 0;
      return {
        ...stage,
        state: critical ? 'warning' : 'passed',
        count: critical,
        detail: `${critical} priorité(s) critique(s) • score le plus élevé ${summary.highest}/100`
      };
    }
    if (stage.id === 'policy') {
      if (!policy) return { ...stage, state: 'skipped', detail: 'Policy Gate non évaluée', count: null };
      // An unusable policy is a failure of the stage, not an absent policy: it
      // must never read as « nothing configured », which sounds harmless.
      if (policy.status === STATUS.ERROR) {
        return { ...stage, state: 'failed', detail: `Politique projet invalide : ${policy.error || policy.summary}`, count: null };
      }
      if (!policy.configured) return { ...stage, state: 'not_configured', detail: 'Aucune règle gate dans security-center.yml', count: null };
      return {
        ...stage,
        state: policy.status === STATUS.BLOCK ? 'blocked' : policy.status === STATUS.WARN ? 'warning' : 'passed',
        count: policy.violations?.length || 0,
        detail: policy.summary
      };
    }
    const artifact = artifacts[stage.id];
    if (!artifact) {
      return { ...stage, state: 'not_configured', detail: 'Artefact non généré pour ce scan', count: null };
    }
    if (artifact.status === 'generated') {
      return {
        ...stage,
        state: 'passed',
        count: artifact.componentCount ?? null,
        detail: stage.id === 'sbom'
          ? `${artifact.format || 'SBOM'} ${artifact.specVersion || ''} — ${artifact.componentCount ?? 0} composant(s)`.trim()
          : `Généré — ${artifact.artifactDigest || artifact.digest || ''}`
      };
    }
    if (artifact.status === 'verified') return { ...stage, state: 'passed', detail: 'Signature vérifiée', count: null };
    if (artifact.status === 'signed') return { ...stage, state: 'passed', detail: `Signé le ${artifact.signedAt || ''}`, count: null };
    return { ...stage, state: 'failed', detail: artifact.reason || 'Échec de l’étape', count: null };
  }
}

/**
 * The structured pipeline result. It stays aligned with the shapes the history
 * and snapshot layers already persist instead of introducing a parallel schema.
 */
function buildPipelineResult({
  scanId = '', workspace = '', startedAt = '', finishedAt = new Date().toISOString(),
  scanners = [], rawFindings = [], analysis = {}, artifacts = {}, failures = [],
  intelligence = { status: 'completed' }
} = {}) {
  const policy = analysis.policy || null;
  const status = failures.length || intelligence?.status === 'failed' ? 'partial'
    : policy?.status === STATUS.BLOCK ? 'blocked'
      : policy?.status === STATUS.WARN ? 'warning' : 'passed';
  return {
    scanId: String(scanId),
    intelligence,
    workspace,
    startedAt,
    finishedAt,
    scannerResults: scanners,
    normalizedFindings: rawFindings.length,
    correlatedFindings: analysis.clusters?.length || 0,
    findings: analysis.findings || [],
    clusters: analysis.clusters || [],
    correlationSummary: analysis.correlation || null,
    reachabilitySummary: analysis.reachability || null,
    prioritySummary: analysis.priority || null,
    policy,
    artifacts,
    failures,
    status
  };
}

/**
 * Availability of one intelligence section, for the detail tabs.
 *
 * The distinction that matters: a stage that produced nothing is not the same
 * thing as a stage whose results were lost. « 0 résultat » must never be shown
 * for data that simply is not there any more.
 */
const DATA_STATES = Object.freeze({
  NOT_EXECUTED: 'NOT_EXECUTED',
  NO_RESULTS: 'NO_RESULTS',
  HAS_RESULTS: 'HAS_RESULTS',
  ERROR: 'ERROR',
  MISSING_PERSISTED_DATA: 'MISSING_PERSISTED_DATA'
});

/**
 * Decides what a detail tab should render.
 *
 * `summary` is the persisted count the Pipeline tab shows; `records` is what the
 * tab actually has to display. A summary announcing results while the records
 * are empty is exactly the inconsistency this reports as MISSING_PERSISTED_DATA
 * instead of silently rendering an empty list.
 */
function dataAvailability({ summary = null, records = [], expected = null, intelligence = null } = {}) {
  if (intelligence?.status === 'failed') return { state: DATA_STATES.ERROR, reason: intelligence.error || '' };
  if (!summary) return { state: DATA_STATES.NOT_EXECUTED, reason: '' };
  const count = Array.isArray(records) ? records.length : 0;
  const announced = Number.isFinite(expected) ? expected : count;
  if (announced > 0 && count === 0) {
    return {
      state: DATA_STATES.MISSING_PERSISTED_DATA,
      reason: `Le résumé annonce ${announced} résultat(s), mais le détail de ce scan n’est plus disponible.`,
      expected: announced
    };
  }
  if (announced === 0 && count === 0) return { state: DATA_STATES.NO_RESULTS, reason: '' };
  return { state: DATA_STATES.HAS_RESULTS, reason: '', expected: announced, shown: count };
}

/**
 * Rebuilds a pipeline result from what was persisted plus the findings the scan
 * cache restored.
 *
 * The intelligence summaries and the per-finding verdicts are written in the
 * same completion block, so they describe the same scan. This reunites them
 * after a reload instead of leaving the summaries persisted and the details
 * in a variable that died with the previous session.
 */
function restorePipelineResult(persisted, findings = []) {
  if (!persisted || !persisted.scanId) return null;
  // Only findings actually carrying intelligence belong to this result: a
  // finding without it was never processed by the engines.
  const enriched = findings.filter((finding) => finding?.priority || finding?.reachability || finding?.correlation);
  return {
    ...buildPipelineResult({
      scanId: persisted.scanId,
      workspace: persisted.workspace || '',
      startedAt: persisted.startedAt || '',
      finishedAt: persisted.finishedAt || '',
      scanners: persisted.scanners || [],
      rawFindings: enriched,
      analysis: {
        findings: enriched,
        clusters: persisted.clusters || [],
        correlation: persisted.correlation || null,
        reachability: persisted.reachability || null,
        priority: persisted.priority || null,
        policy: persisted.policy || null
      },
      artifacts: persisted.artifacts || {},
      intelligence: persisted.intelligence || { status: 'completed' }
    }),
    // Marks the result as reconstructed so the UI can say which scan it shows.
    restored: true
  };
}

/** The snapshot of intelligence persisted at the end of a scan. */
function pipelineStateFor(result, analysis = {}, artifacts = {}) {
  return {
    scanId: result.scanId,
    workspace: result.workspace,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    intelligence: result.intelligence,
    scanners: result.scannerResults || [],
    policy: analysis.policy || result.policy || null,
    correlation: analysis.correlation || result.correlationSummary || null,
    reachability: analysis.reachability || result.reachabilitySummary || null,
    priority: analysis.priority || result.prioritySummary || null,
    clusters: analysis.clusters || result.clusters || [],
    artifacts
  };
}

/**
 * Supply-chain stages. Each one is optional and each one records why it did not
 * run, so the policy gate can tell « refusée » from « non exécutée ».
 */
async function runSupplyChainStages({
  workspacePath, sbom: sbomOptions = null, provenance: provenanceOptions = null,
  scanners = [], policy = null, startedAt = '', signal,
  generateSbom = generateSbomArtifact, generateProvenanceDocument = generateProvenance
} = {}) {
  const artifacts = {};
  if (sbomOptions?.enabled) {
    artifacts.sbom = await generateSbom({
      workspacePath,
      mode: sbomOptions.mode || 'auto',
      imageName: sbomOptions.imageName || '',
      outputDirectory: sbomOptions.outputDirectory || '',
      signal
    });
  }
  if (provenanceOptions?.enabled) {
    // Provenance attests an artefact. Without one, the SBOM itself is the
    // subject — it is a real file with a real digest, which keeps the statement
    // truthful instead of attesting a directory that has no digest.
    const subject = provenanceOptions.artifactPath || artifacts.sbom?.path || '';
    if (!subject) {
      artifacts.provenance = { status: 'failed', reason: 'Aucun artefact à attester : générez un SBOM ou indiquez un fichier.' };
    } else {
      artifacts.provenance = await generateProvenanceDocument({
        workspacePath,
        artifactPath: subject,
        sbom: artifacts.sbom || provenanceOptions.sbom || null,
        policy,
        scanners,
        startedAt,
        outputPath: provenanceOptions.outputPath || ''
      });
    }
  }
  return artifacts;
}

module.exports = {
  PIPELINE_STAGES, STAGE_STATES, STATUS, DATA_STATES,
  analyzeFindings, analyzeWorkspace, describeStages, buildPipelineResult,
  runSupplyChainStages, packagesOfInterest, mergeIntelligence,
  restorePipelineResult, pipelineStateFor, dataAvailability
};
