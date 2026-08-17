'use strict';

/**
 * Correlation Engine V2.
 *
 * Answers one question: which scanner reports describe the same underlying
 * vulnerability? Each family of findings gets its own strategy with its own
 * evidence requirements, because "same CWE" is not evidence — CWE-89 appears in
 * hundreds of unrelated places and merging on it alone destroys real findings.
 *
 * Every cluster carries the reasons it exists and a confidence level. A weak
 * link stays visible as weak instead of being presented as a confirmation.
 */

const crypto = require('crypto');
const { matchEndpoint } = require('./route-map');

const CONFIDENCE_ORDER = Object.freeze(['low', 'medium', 'high']);

/**
 * What a group is allowed to claim.
 *
 *   high   → confirmed  — several scanners agree on strong, matching evidence
 *   medium → probable   — the evidence matches but something is unverified
 *   low    → candidate  — plausible, unproven, must not read as a confirmation
 *
 * Only `confirmed` may be described as « confirmée par plusieurs scanners ».
 */
const CORRELATION_TIERS = Object.freeze({ high: 'confirmed', medium: 'probable', low: 'candidate' });
const TIER_LABELS = Object.freeze({ confirmed: 'Confirmée', probable: 'Probable', candidate: 'Candidate' });

function tierFor(confidence) {
  return CORRELATION_TIERS[String(confidence || 'low').toLowerCase()] || 'candidate';
}

function clusterId(type, key) {
  return `${type}-${crypto.createHash('sha1').update(String(key)).digest('hex').slice(0, 12)}`;
}

function highestConfidence(values) {
  return CONFIDENCE_ORDER.filter((level) => values.includes(level)).at(-1) || 'low';
}

function distinctTools(findings) {
  return [...new Set(findings.map((finding) => finding.tool).filter(Boolean))].sort();
}

const SEVERITY_RANK = Object.freeze({ CRITICAL: 5, HIGH: 4, ERROR: 4, MEDIUM: 3, WARNING: 3, LOW: 2, INFO: 1, UNKNOWN: 0 });

/**
 * The canonical finding of a group: the one a developer should read first.
 * Highest severity wins; ties are broken by the richest evidence (a precise
 * location, a fix, a CVE) and finally by id so the choice is deterministic.
 */
function canonicalFinding(findings) {
  return [...findings].sort((left, right) => {
    const severity = (SEVERITY_RANK[right.severity] ?? 0) - (SEVERITY_RANK[left.severity] ?? 0);
    if (severity) return severity;
    const evidence = (Number(Boolean(right.line)) + Number(Boolean(right.fixedVersion)) + Number(right.cve.length > 0))
      - (Number(Boolean(left.line)) + Number(Boolean(left.fixedVersion)) + Number(left.cve.length > 0));
    if (evidence) return evidence;
    return String(left.id).localeCompare(String(right.id));
  })[0];
}

/** Short human title for a group, taken from the strongest identity it has. */
function clusterTitle(type, identity, primary) {
  if (type === 'sca') {
    return `${identity.identifier || 'Vulnérabilité'} — ${identity.package || 'dépendance'}${identity.version ? `@${identity.version}` : ''}`;
  }
  if (type === 'dast-sast') {
    return `${primary?.title || 'Vulnérabilité'} — ${identity.method || 'HTTP'} ${identity.endpoint || ''}`.trim();
  }
  if (type === 'iac') {
    return `${primary?.title || 'Mauvaise configuration'} — ${identity.file || ''}${identity.resource ? ` (${identity.resource})` : ''}`;
  }
  return `${primary?.title || 'Faiblesse de code'} — ${identity.file || ''}${identity.line ? `:${identity.line}` : ''}`;
}

/**
 * Builds a cluster. `sources` keeps each scanner's own evidence intact so the
 * user can always inspect what a given tool actually reported.
 */
function buildCluster({ type, confidence, key, findings, reasons, identity = {} }) {
  const sorted = [...findings].sort((left, right) => String(left.id).localeCompare(String(right.id)));
  const primary = canonicalFinding(sorted);
  return {
    id: clusterId(type, key),
    type,
    confidence,
    tier: tierFor(confidence),
    tierLabel: TIER_LABELS[tierFor(confidence)],
    title: clusterTitle(type, identity, primary),
    reasons: [...reasons],
    tools: distinctTools(sorted),
    identity,
    findingIds: sorted.map((finding) => finding.id),
    // The canonical finding is a pointer, never a replacement: every source
    // finding below stays addressable on its own.
    primaryFindingId: primary?.id || '',
    primaryTool: primary?.tool || '',
    severity: primary?.severity || 'UNKNOWN',
    count: sorted.length,
    findingCount: sorted.length,
    sources: sorted.map((finding) => ({
      tool: finding.tool,
      findingId: finding.id,
      ruleId: finding.ruleId,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      endpoint: finding.endpoint,
      evidence: finding.evidence,
      package: finding.package,
      packageVersion: finding.packageVersion
    }))
  };
}

function groupBy(items, keyOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!key) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

// --------------------------------------------------------------------- SCA

/**
 * SCA correlation. Two reports describe the same vulnerable dependency when
 * they share a vulnerability identifier *and* the package. The version and the
 * manifest refine the confidence rather than gate the match, because scanners
 * disagree on how they spell a manifest path.
 */
function correlateSca(findings) {
  const candidates = findings.filter((finding) => finding.stage === 'sca' && finding.package && finding.vulnerabilityIds.length);
  const byIdentity = new Map();
  for (const finding of candidates) {
    for (const identifier of finding.vulnerabilityIds) {
      // The ecosystem is part of the identity: lodash@npm and lodash@pypi are
      // not the same component even under the same advisory id.
      const key = [finding.ecosystem || 'unknown', finding.package.toLowerCase(), identifier].join('|');
      if (!byIdentity.has(key)) byIdentity.set(key, []);
      byIdentity.get(key).push(finding);
    }
  }
  const clusters = [];
  const claimed = new Set();
  for (const [key, group] of byIdentity) {
    const unique = group.filter((finding, index) => group.indexOf(finding) === index);
    if (distinctTools(unique).length < 2) continue;
    // A finding already merged under a stronger identifier is not merged twice.
    if (unique.every((finding) => claimed.has(finding.id))) continue;
    const [ecosystem, packageName, identifier] = key.split('|');
    const versions = [...new Set(unique.map((finding) => finding.packageVersion).filter(Boolean))];
    const manifests = [...new Set(unique.map((finding) => finding.manifest).filter(Boolean))];
    const sameVersion = versions.length <= 1;
    const reasons = [`Même identifiant de vulnérabilité ${identifier}`, `Même paquet ${packageName}${ecosystem !== 'unknown' ? ` (${ecosystem})` : ''}`];
    if (sameVersion && versions.length) reasons.push(`Même version installée ${versions[0]}`);
    else if (versions.length > 1) reasons.push(`Versions rapportées différentes : ${versions.join(', ')}`);
    if (manifests.length === 1) reasons.push(`Même manifeste ${manifests[0]}`);
    const dependencyPath = unique.map((finding) => finding.dependencyPath).find((entries) => entries.length) || [];
    if (dependencyPath.length) reasons.push(`Chemin de dépendance : ${dependencyPath.join(' → ')}`);
    for (const finding of unique) claimed.add(finding.id);
    clusters.push(buildCluster({
      type: 'sca',
      // Same advisory + same package is a strong identity; a version
      // disagreement means the scanners may be looking at different installs.
      confidence: sameVersion ? 'high' : 'medium',
      key,
      findings: unique,
      reasons,
      identity: { ecosystem, package: packageName, identifier, version: versions[0] || '', manifests, dependencyPath }
    }));
  }
  return clusters;
}

// -------------------------------------------------------------------- SAST

/** `js/sql-injection` and `javascript.lang.security.sql-injection` share `sql`+`injection`. */
function ruleTokens(ruleId) {
  return new Set(String(ruleId || '').toLowerCase().split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3 && !['rule', 'lang', 'security', 'javascript', 'python', 'java', 'typescript', 'audit', 'test'].includes(token)));
}

function sharedRuleFamily(left, right) {
  const leftTokens = ruleTokens(left.ruleId);
  return [...ruleTokens(right.ruleId)].filter((token) => leftTokens.has(token));
}

/**
 * SAST correlation. Requires the same file plus corroborating evidence:
 * a shared CWE, or a shared rule family when the lines almost coincide.
 * A shared CWE in two different files is never a correlation.
 */
function correlateSast(findings, { nearLines = 3, sameRegionLines = 25 } = {}) {
  const candidates = findings.filter((finding) => finding.stage === 'sast' && finding.file && finding.line !== null);
  const clusters = [];
  const seen = new Set();
  for (const [file, group] of groupBy(candidates, (finding) => finding.file.toLowerCase())) {
    for (let left = 0; left < group.length; left += 1) {
      for (let right = left + 1; right < group.length; right += 1) {
        const first = group[left];
        const second = group[right];
        if (first.tool === second.tool) continue;
        const sharedCwe = first.cwe.filter((cwe) => second.cwe.includes(cwe));
        const family = sharedRuleFamily(first, second);
        const distance = Math.abs(first.line - second.line);
        let confidence = '';
        const reasons = [`Même fichier ${file}`];
        if (sharedCwe.length && distance <= nearLines) {
          confidence = 'high';
          reasons.push(`Lignes ${first.line} et ${second.line} (écart ${distance})`, `CWE commun ${sharedCwe.join(', ')}`);
        } else if (sharedCwe.length && distance <= sameRegionLines) {
          confidence = 'medium';
          reasons.push(`Même zone de code (écart ${distance} lignes)`, `CWE commun ${sharedCwe.join(', ')}`);
        } else if (family.length && distance <= nearLines) {
          confidence = 'medium';
          reasons.push(`Lignes ${first.line} et ${second.line}`, `Famille de règle commune : ${family.join(', ')}`);
        } else if (sharedCwe.length) {
          // Same file and same weakness class, far apart: surfaced as a
          // `candidate` so the reader can judge it, but it carries no
          // confirmation and no priority weight. CWE-89 appears many times in
          // one file, so this must never read as « confirmée ».
          confidence = 'low';
          reasons.push(family.length
            ? `CWE commun ${sharedCwe.join(', ')} et famille de règle ${family.join(', ')}, mais lignes éloignées (${first.line} / ${second.line}) — rapprochement non prouvé`
            : `CWE commun ${sharedCwe.join(', ')} mais lignes éloignées (${first.line} / ${second.line}) — rapprochement non prouvé`);
        }
        if (!confidence) continue;
        const key = [file, Math.min(first.line, second.line), sharedCwe.join(',') || family.join(',')].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        clusters.push(buildCluster({
          type: 'sast',
          confidence,
          key,
          findings: [first, second],
          reasons,
          identity: { file, line: Math.min(first.line, second.line), cwe: sharedCwe, ruleFamily: family }
        }));
      }
    }
  }
  return clusters;
}

// --------------------------------------------------------------------- IaC

/** Normalises `spec.template.spec.containers[0].privileged` for comparison. */
function resourceKey(finding) {
  return String(finding.resource || '').toLowerCase().replace(/\[\d+\]/g, '[]').replace(/\s+/g, '');
}

/**
 * IaC correlation. Two policies match when they flag the same resource in the
 * same file, or the same semantic issue in the same file when the resource path
 * is not exposed by one of the scanners.
 */
function correlateIac(findings) {
  const candidates = findings.filter((finding) => finding.stage === 'iac' && finding.file);
  const clusters = [];
  const seen = new Set();
  for (const [file, group] of groupBy(candidates, (finding) => finding.file.toLowerCase())) {
    for (let left = 0; left < group.length; left += 1) {
      for (let right = left + 1; right < group.length; right += 1) {
        const first = group[left];
        const second = group[right];
        if (first.tool === second.tool) continue;
        const sameResource = resourceKey(first) && resourceKey(first) === resourceKey(second);
        const family = sharedRuleFamily(first, second);
        const titleFamily = sharedRuleFamily({ ruleId: first.title }, { ruleId: second.title });
        const sameLine = first.line !== null && first.line === second.line;
        let confidence = '';
        const reasons = [`Même fichier de configuration ${file}`];
        if (sameResource) {
          confidence = 'high';
          reasons.push(`Même ressource ${first.resource}`);
          if (family.length || titleFamily.length) reasons.push(`Règle équivalente : ${[...new Set([...family, ...titleFamily])].join(', ')}`);
        } else if (sameLine && (family.length || titleFamily.length)) {
          confidence = 'medium';
          reasons.push(`Même ligne ${first.line}`, `Problème équivalent : ${[...new Set([...family, ...titleFamily])].join(', ')}`);
        } else if (titleFamily.length >= 2) {
          confidence = 'low';
          reasons.push(`Formulation proche : ${titleFamily.join(', ')} — emplacement exact non confirmé`);
        }
        if (!confidence) continue;
        const key = [file, resourceKey(first) || first.line, family.join(',') || titleFamily.join(',')].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        clusters.push(buildCluster({
          type: 'iac',
          confidence,
          key,
          findings: [first, second],
          reasons,
          identity: { file, resource: first.resource || second.resource || '', policies: [first.ruleId, second.ruleId] }
        }));
      }
    }
  }
  return clusters;
}

// -------------------------------------------------------------- DAST ↔ SAST

/**
 * Maps a runtime alert back to the code that serves it:
 *
 *   ZAP endpoint → declared route → handler file → SAST finding in that file
 *
 * The route map is built from real declarations found in the workspace. With no
 * route map, no correlation is produced — an unmapped endpoint stays unmapped
 * rather than being attached to a plausible-looking file.
 */
function correlateDastSast(findings, routeMap) {
  const dynamic = findings.filter((finding) => finding.stage === 'dast' && finding.endpoint);
  const staticFindings = findings.filter((finding) => finding.stage === 'sast' && finding.file);
  if (!dynamic.length || !staticFindings.length) return [];
  const clusters = [];
  const seen = new Set();
  for (const alert of dynamic) {
    const routes = matchEndpoint(routeMap, alert.endpoint, alert.method);
    if (!routes.length) continue;
    for (const route of routes) {
      const handlers = staticFindings.filter((finding) => finding.file.toLowerCase() === route.file.toLowerCase());
      for (const handler of handlers) {
        const sharedCwe = alert.cwe.filter((cwe) => handler.cwe.includes(cwe));
        // A route match alone links a file, not a vulnerability. The weakness
        // class must be compatible before the two are called the same issue.
        if (!sharedCwe.length) continue;
        const distance = handler.line !== null ? Math.abs(handler.line - route.line) : Number.POSITIVE_INFINITY;
        const confidence = distance <= 60 ? 'high' : 'medium';
        const key = [alert.id, handler.id].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        clusters.push(buildCluster({
          type: 'dast-sast',
          confidence,
          key,
          findings: [alert, handler],
          reasons: [
            `Endpoint ${alert.method || 'HTTP'} ${alert.endpoint} servi par la route ${route.method} ${route.route}`,
            `Route déclarée dans ${route.file}:${route.line} (${route.framework})`,
            `CWE compatible ${sharedCwe.join(', ')}`,
            distance <= 60
              ? `Résultat SAST à ${handler.line}, dans le gestionnaire de la route`
              : `Résultat SAST à ${handler.line}, dans le même fichier mais hors du gestionnaire immédiat`
          ],
          identity: { endpoint: alert.endpoint, method: alert.method, route: route.route, file: route.file, cwe: sharedCwe }
        }));
      }
    }
  }
  return clusters;
}

/**
 * Runs every strategy and annotates the findings.
 *
 * `routeMap` is optional: without it the DAST↔SAST strategy simply produces
 * nothing, which is the honest outcome when no route could be read.
 */
function correlateFindingsV2(findings = [], { routeMap = null } = {}) {
  const clusters = [
    ...correlateSca(findings),
    ...correlateSast(findings),
    ...correlateIac(findings),
    ...correlateDastSast(findings, routeMap)
  ];
  const byFinding = new Map();
  for (const cluster of clusters) {
    for (const findingId of cluster.findingIds) {
      if (!byFinding.has(findingId)) byFinding.set(findingId, []);
      byFinding.get(findingId).push(cluster);
    }
  }
  const annotated = findings.map((finding) => {
    const matches = byFinding.get(finding.id) || [];
    if (!matches.length) return finding;
    const confidence = highestConfidence(matches.map((cluster) => cluster.confidence));
    return {
      ...finding,
      correlation: {
        clusterIds: matches.map((cluster) => cluster.id),
        // Primary group first: what the UI shows when it can only show one.
        groupId: matches[0].id,
        groupTitle: matches[0].title,
        isPrimary: matches.some((cluster) => cluster.primaryFindingId === finding.id),
        types: [...new Set(matches.map((cluster) => cluster.type))],
        confidence,
        tier: tierFor(confidence),
        // Only a `confirmed` group means several scanners actually agree.
        confirmed: tierFor(confidence) === 'confirmed',
        tools: [...new Set(matches.flatMap((cluster) => cluster.tools))].sort(),
        reasons: [...new Set(matches.flatMap((cluster) => cluster.reasons))],
        // Independent corroboration only counts when another tool agrees.
        corroboratingTools: [...new Set(matches.flatMap((cluster) => cluster.tools))].filter((tool) => tool !== finding.tool)
      },
      sourceScannerIds: [...new Set([finding.id, ...matches.flatMap((cluster) => cluster.findingIds)])]
    };
  });
  return {
    findings: annotated,
    clusters,
    summary: {
      total: clusters.length,
      byType: clusters.reduce((counts, cluster) => ({ ...counts, [cluster.type]: (counts[cluster.type] || 0) + 1 }), {}),
      byConfidence: clusters.reduce((counts, cluster) => ({ ...counts, [cluster.confidence]: (counts[cluster.confidence] || 0) + 1 }), {}),
      byTier: clusters.reduce((counts, cluster) => ({ ...counts, [cluster.tier]: (counts[cluster.tier] || 0) + 1 }),
        { confirmed: 0, probable: 0, candidate: 0 }),
      // The headline number is confirmations only: a candidate is not a
      // « vulnérabilité confirmée par plusieurs sources ».
      confirmed: clusters.filter((cluster) => cluster.tier === 'confirmed').length,
      routeMapAvailable: Boolean(routeMap?.supported)
    }
  };
}

module.exports = {
  correlateFindingsV2, correlateSca, correlateSast, correlateIac, correlateDastSast,
  buildCluster, clusterId, clusterTitle, canonicalFinding, ruleTokens, sharedRuleFamily,
  resourceKey, highestConfidence, distinctTools,
  CORRELATION_TIERS, TIER_LABELS, tierFor
};
