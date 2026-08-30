'use strict';

/**
 * Policy Gate V2.
 *
 * One implementation, three callers: the extension, the headless CLI and CI all
 * evaluate the very same function on the very same data. There is no UI-only
 * gate logic anywhere.
 *
 * The verdict has five distinct states, and none of them is a polite default:
 *   NOT_CONFIGURED — the project declared no gate, so there is nothing to judge
 *   PASS           — nothing the policy forbids
 *   WARN           — something the policy wants surfaced, but not blocking
 *   BLOCK          — at least one violation of a blocking rule
 *   ERROR          — the policy itself could not be read or validated
 *
 * NOT_CONFIGURED and ERROR are deliberately *not* PASS. An absent policy has
 * authorised nothing, and an unreadable policy has authorised nothing either;
 * reporting either of them as a pass would turn a configuration mistake into a
 * green light.
 *
 * A rule that cannot be evaluated (an artefact stage that never ran) is
 * reported as a warning explaining why, never silently treated as satisfied.
 */

const { SEVERITY_RANK } = require('../project-policy');

const STATUS = Object.freeze({
  NOT_CONFIGURED: 'NOT_CONFIGURED', PASS: 'PASS', WARN: 'WARN', BLOCK: 'BLOCK', ERROR: 'ERROR'
});

/** Human wording for each state, shared by every surface. */
const STATUS_SUMMARY = Object.freeze({
  NOT_CONFIGURED: 'Aucune règle de gate définie dans security-center.yml.',
  PASS: 'Le projet respecte la politique de sécurité configurée.',
  WARN: (warnings) => `Le projet peut continuer, mais ${warnings} avertissement(s) de politique demandent votre attention.`,
  BLOCK: (violations) => `Livraison bloquée par ${violations} violation(s) de la politique projet.`,
  ERROR: 'La configuration de la politique projet est invalide.'
});

function severityOf(finding) {
  return String(finding.severity || finding.rawSeverity || 'UNKNOWN').toUpperCase();
}

function severityRank(value) {
  return SEVERITY_RANK[String(value).toUpperCase()] ?? 0;
}

/** The least severe entry of a list — the threshold the whole list implies. */
function lowestSeverity(values = []) {
  return [...(values || [])].sort((left, right) => severityRank(left) - severityRank(right))[0] || '';
}

/** Findings the policy should look at: triaged-away results are excluded. */
function activeFindings(findings, { includeTests = true } = {}) {
  return findings.filter((finding) => !['false_positive', 'fixed', 'validated', 'accepted'].includes(finding.triageStatus)
    && (includeTests || finding.sourceContext !== 'test'));
}

/**
 * One violation or warning.
 *
 * Beyond what triggered the rule, it carries the signals that explain *why the
 * finding matters* — who found it, whether the code is reachable, whether
 * several scanners agree. Those are copied verbatim from the finding the
 * engines already produced: the gate reads them, it never recomputes them, and
 * a signal that was not evaluated stays absent rather than becoming a default.
 */
function violation(code, message, finding = null, extra = {}) {
  return {
    code,
    message,
    ...(finding ? {
      findingId: finding.id,
      title: finding.title,
      tool: finding.tool,
      severity: severityOf(finding),
      file: finding.file || finding.manifest || finding.endpoint || '',
      line: finding.line ?? null,
      priority: finding.priority?.score ?? null,
      priorityCode: finding.priority?.code ?? null,
      reachability: finding.reachability?.state ?? null,
      correlationTier: finding.correlation?.tier ?? null,
      // Every scanner that reported this same issue, so a corroborated finding
      // can be recognised as such in the explanation.
      sources: finding.correlation?.tools?.length
        ? [...finding.correlation.tools]
        : (finding.tool ? [finding.tool] : [])
    } : {}),
    ...extra
  };
}

/**
 * Evaluates the gate.
 *
 * `artifacts` describes what the supply-chain stages actually produced; it is
 * optional, and its absence turns artefact requirements into warnings rather
 * than passes or blocks.
 */
function evaluatePolicyGate(findings = [], policy = null, { artifacts = null } = {}) {
  const gate = policy?.gate;
  const supplyChain = policy?.supplyChain;
  const evaluatedAt = new Date().toISOString();
  if (!policy || (!gate?.configured && !supplyChain?.configured)) {
    // Not a pass: an absent policy has authorised nothing.
    return {
      status: STATUS.NOT_CONFIGURED,
      configured: false,
      violations: [],
      warnings: [],
      evaluatedAt,
      counts: { violations: 0, warnings: 0, evaluatedFindings: 0 },
      summary: STATUS_SUMMARY.NOT_CONFIGURED
    };
  }
  const active = activeFindings(findings, { includeTests: policy.includeTests !== false });
  const violations = [];
  const warnings = [];

  // One finding, one violation. The rules are therefore applied from the most
  // specific to the most general, so a leaked secret is reported as a secret
  // rather than as an anonymous « HIGH severity », and the violation count
  // matches the number of real problems instead of the number of rules matched.
  const blocked = new Set();
  const block = (code, message, finding, extra) => {
    if (finding && blocked.has(finding.id)) return;
    if (finding) blocked.add(finding.id);
    violations.push(violation(code, message, finding, extra));
  };

  if (gate?.blockSecrets) {
    for (const finding of active.filter((item) => item.stage === 'secrets' || item.category === 'secret')) {
      block('secret', `Secret exposé : ${finding.title}`, finding, { rule: 'gate.block_secrets' });
    }
  }

  // `fail_on_severity: [CRITICAL, HIGH]` means « HIGH or above ». The threshold
  // is therefore the *lowest* severity declared, whatever order the list is
  // written in — reading only the first entry would silently ignore the rest.
  const failThreshold = lowestSeverity(gate?.failOnSeverity);
  if (failThreshold) {
    for (const finding of active.filter((item) => severityRank(severityOf(item)) >= severityRank(failThreshold))) {
      block('severity', `Vulnérabilité ${severityOf(finding)} : ${finding.title}`, finding, { rule: `gate.fail_on_severity ≥ ${failThreshold}` });
    }
  }

  if (Number.isInteger(gate?.priorityThreshold)) {
    const scored = active.filter((finding) => Number.isFinite(finding.priority?.score));
    if (!scored.length && active.length) {
      warnings.push(violation('priority-unavailable', 'Seuil de priorité configuré, mais aucun score de priorité n’a été calculé pour ce scan.', null, { rule: 'gate.priority_threshold' }));
    }
    for (const finding of scored.filter((item) => item.priority.score >= gate.priorityThreshold)) {
      block('priority', `Priorité ${finding.priority.score}/100 : ${finding.title}`, finding, { rule: `gate.priority_threshold ≥ ${gate.priorityThreshold}` });
    }
  }

  // Warnings never repeat a finding that is already blocking: a blocked finding
  // does not also need to be « watched ».
  const warned = new Set();
  const warn = (code, message, finding, extra) => {
    if (finding && (blocked.has(finding.id) || warned.has(finding.id))) return;
    if (finding) warned.add(finding.id);
    warnings.push(violation(code, message, finding, extra));
  };

  const warnThreshold = lowestSeverity(gate?.warnOnSeverity);
  if (warnThreshold) {
    for (const finding of active.filter((item) => severityRank(severityOf(item)) >= severityRank(warnThreshold))) {
      warn('severity-warning', `À surveiller (${severityOf(finding)}) : ${finding.title}`, finding, { rule: `gate.warn_on_severity ≥ ${warnThreshold}` });
    }
  }

  if (Number.isInteger(gate?.warnPriorityThreshold)) {
    for (const finding of active.filter((item) => Number.isFinite(item.priority?.score)
      && item.priority.score >= gate.warnPriorityThreshold)) {
      warn('priority-warning', `Priorité ${finding.priority.score}/100 : ${finding.title}`, finding, { rule: `gate.warn_priority_threshold ≥ ${gate.warnPriorityThreshold}` });
    }
  }

  // Artefact requirements. « Not produced » blocks; « stage never ran » warns,
  // because the gate must not claim a verdict it could not establish.
  const artefactRules = [
    [gate?.requireSbom, 'sbom', 'gate.require_sbom', 'Un SBOM est exigé par la politique projet'],
    [supplyChain?.requireProvenance, 'provenance', 'supply_chain.require_provenance', 'Une provenance est exigée par la politique projet'],
    [supplyChain?.requireSignature, 'signature', 'supply_chain.require_signature', 'Une signature vérifiée est exigée par la politique projet']
  ];
  for (const [required, key, rule, label] of artefactRules) {
    if (!required) continue;
    if (!artifacts) {
      warnings.push(violation('artifact-not-evaluated', `${label}, mais l’étape correspondante n’a pas été exécutée dans ce scan.`, null, { rule, artifact: key }));
      continue;
    }
    const artifact = artifacts[key];
    if (artifact?.status === 'generated' || artifact?.status === 'verified') continue;
    violations.push(violation('artifact-missing', `${label} : ${artifact?.reason || 'artefact absent'}.`, null, { rule, artifact: key }));
  }

  const status = violations.length ? STATUS.BLOCK : warnings.length ? STATUS.WARN : STATUS.PASS;
  return {
    status,
    configured: true,
    violations,
    warnings,
    evaluatedAt,
    counts: { violations: violations.length, warnings: warnings.length, evaluatedFindings: active.length },
    // The rules that were actually applied, so a verdict can be explained by
    // what the policy asked for rather than by the engine's internals.
    rules: describeGateRules(policy),
    summary: status === STATUS.BLOCK
      ? STATUS_SUMMARY.BLOCK(violations.length)
      : status === STATUS.WARN
        ? STATUS_SUMMARY.WARN(warnings.length)
        : STATUS_SUMMARY.PASS
  };
}

/**
 * The gate verdict when the policy itself cannot be used.
 *
 * Separate from `evaluatePolicyGate` on purpose: evaluation stays a pure
 * function of findings and a *valid* policy, and an unusable policy is reported
 * as its own state instead of degrading into a verdict.
 */
function policyGateError(reason, { filePath = '' } = {}) {
  return {
    status: STATUS.ERROR,
    configured: false,
    error: String(reason || 'Politique projet illisible.'),
    filePath,
    violations: [],
    warnings: [],
    evaluatedAt: new Date().toISOString(),
    counts: { violations: 0, warnings: 0, evaluatedFindings: 0 },
    summary: STATUS_SUMMARY.ERROR
  };
}

/**
 * The configured rules, in plain language.
 *
 * Only rules the engine can actually evaluate are listed, each with the YAML key
 * it comes from, so the UI can explain the policy without inventing a rule the
 * gate would never apply.
 */
function describeGateRules(policy) {
  const gate = policy?.gate || {};
  const supplyChain = policy?.supplyChain || {};
  const rules = [];
  if (gate.failOnSeverity?.length) {
    rules.push({ key: 'gate.fail_on_severity', effect: 'block', value: gate.failOnSeverity, label: `Les vulnérabilités ${gate.failOnSeverity.join(', ')} ou plus graves bloquent la livraison.` });
  }
  if (gate.warnOnSeverity?.length) {
    rules.push({ key: 'gate.warn_on_severity', effect: 'warn', value: gate.warnOnSeverity, label: `Les vulnérabilités ${gate.warnOnSeverity.join(', ')} ou plus graves sont signalées sans bloquer.` });
  }
  if (gate.blockSecrets) {
    rules.push({ key: 'gate.block_secrets', effect: 'block', value: true, label: 'Un secret exposé bloque la livraison.' });
  }
  if (Number.isInteger(gate.priorityThreshold)) {
    rules.push({ key: 'gate.priority_threshold', effect: 'block', value: gate.priorityThreshold, label: `Un résultat dont la priorité atteint ${gate.priorityThreshold}/100 bloque la livraison.` });
  }
  if (Number.isInteger(gate.warnPriorityThreshold)) {
    rules.push({ key: 'gate.warn_priority_threshold', effect: 'warn', value: gate.warnPriorityThreshold, label: `Un résultat dont la priorité atteint ${gate.warnPriorityThreshold}/100 est signalé.` });
  }
  if (gate.requireSbom) rules.push({ key: 'gate.require_sbom', effect: 'block', value: true, label: 'Un SBOM doit avoir été généré.' });
  if (supplyChain.requireProvenance) rules.push({ key: 'supply_chain.require_provenance', effect: 'block', value: true, label: 'Une provenance doit avoir été générée.' });
  if (supplyChain.requireSignature) rules.push({ key: 'supply_chain.require_signature', effect: 'block', value: true, label: 'Une signature vérifiée est exigée.' });
  return rules;
}

/** Compact rendering shared by the CLI output and the audit comment. */
function formatGateResult(result) {
  if (result?.status === STATUS.ERROR) return `POLICY GATE: ERROR\n\n${result.error || result.summary}`;
  if (!result?.configured) return 'POLICY GATE: NOT_CONFIGURED\n\nAucune section gate: dans security-center.yml.';
  const lines = [`POLICY GATE: ${result.status}`, '', result.summary];
  if (result.violations.length) {
    lines.push('', `${result.violations.length} violation(s) bloquante(s)`);
    for (const item of result.violations.slice(0, 20)) lines.push('', ...formatItem(item));
  }
  if (result.warnings.length) {
    lines.push('', `${result.warnings.length} avertissement(s)`);
    for (const item of result.warnings.slice(0, 10)) lines.push(`  ! ${item.message}${location(item)}`);
  }
  return lines.join('\n');
}

function location(item) {
  return item.file ? ` (${item.file}${item.line ? `:${item.line}` : ''})` : '';
}

/**
 * One violation, CI-legible. Only the title travels — never a matched value —
 * so a secret detection can be reported without reprinting the secret.
 */
function formatItem(item) {
  const head = item.code === 'secret' ? 'SECRET' : (item.severity || item.code || '').toUpperCase();
  const lines = [`  ${head} — ${item.title || item.message}`];
  if (item.file) lines.push(`  ${item.file}${item.line ? `:${item.line}` : ''}`);
  const facts = [
    Number.isFinite(item.priority) ? `Priorité ${item.priority}/100` : '',
    item.reachability ? `Atteignabilité : ${item.reachability}` : '',
    item.sources?.length > 1 ? `Détecté par ${item.sources.join(' + ')}` : (item.tool ? `Détecté par ${item.tool}` : '')
  ].filter(Boolean);
  if (facts.length) lines.push(`  ${facts.join(' · ')}`);
  return lines;
}

/**
 * Exit code contract shared by the CLI and CI.
 *
 * 0 accepted (PASS, WARN, and an absent policy — which forbids nothing),
 * 1 refused by the policy, 2 the policy could not be evaluated at all.
 * WARN stays 0: promoting a warning to a block is the policy's decision, made
 * by declaring the rule under `fail_on_severity` instead.
 */
function gateExitCode(result) {
  if (result?.status === STATUS.ERROR) return 2;
  return result?.status === STATUS.BLOCK ? 1 : 0;
}

/**
 * Presents a gate verdict in the shape the dashboard banner already renders.
 *
 * One verdict, several surfaces. The Security Pipeline, the dashboard banner and
 * the end-of-scan notification must never disagree about the same scan, which
 * they could while the banner was fed by the legacy evaluator: that one knows
 * nothing about `block_secrets`, `priority_threshold` or the artefact rules, so
 * a blocked delivery could still be announced as « politique respectée ».
 *
 * This is a projection, not a second evaluation. Nothing is recomputed, no
 * threshold is applied here, and the gate object itself is never mutated.
 *
 * `NOT_CONFIGURED` deliberately yields `null`: the banner is only rendered when
 * a result exists, and an absent gate has authorised nothing — claiming
 * « politique respectée » would be exactly the unearned reassurance this module
 * refuses everywhere else.
 */
function policyResultFromGate(gate, policy = null) {
  if (!gate || gate.status === STATUS.NOT_CONFIGURED) return null;
  const blocking = gate.status === STATUS.BLOCK || gate.status === STATUS.ERROR;
  const reasons = gate.status === STATUS.ERROR
    ? [gate.error || STATUS_SUMMARY.ERROR]
    : (gate.violations || []).map((violation) => violation.message);
  return {
    passed: !blocking,
    // The gate counts what it actually judged.
    activeCount: gate.counts?.evaluatedFindings ?? 0,
    // Legacy-only notion (per-tool severity floor). The gate has no equivalent,
    // so it stays 0 rather than being invented; the banner only shows it when set.
    ignoredByToolThreshold: 0,
    reasons,
    // Carried through unchanged: the ZAP section reads the parsed policy here.
    policy,
    // The authoritative verdict, so a surface can tell WARN from PASS without
    // reinterpreting `passed`. Additive — no existing consumer is affected.
    gateStatus: gate.status,
    gateSummary: gate.summary || '',
    warningCount: gate.counts?.warnings ?? 0
  };
}

module.exports = {
  STATUS, STATUS_SUMMARY, evaluatePolicyGate, policyGateError, describeGateRules,
  formatGateResult, gateExitCode, activeFindings, severityRank, policyResultFromGate
};
