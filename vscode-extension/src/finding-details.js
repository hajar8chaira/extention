const {
  STATE_LABELS: VERIFICATION_LABELS, REASON_LABELS: VERIFICATION_REASONS
} = require('./fix-verification');

/** How a fix reached the code, in words the page can show. */
const FIX_SOURCE_LABELS = Object.freeze({
  quick_fix: 'Quick Fix déterministe', ai: 'Patch Ollama', manual: 'Correction manuelle'
});

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function valueOrUnavailable(value) {
  return value ? escapeHtml(value) : '<span class="muted">Non fourni par le rapport baseline ZAP</span>';
}

function trivyValue(value, emptyLabel = 'Non indiqué par Trivy') {
  return value ? escapeHtml(value) : `<span class="muted">${escapeHtml(emptyLabel)}</span>`;
}

function developerExplanation(finding) {
  return finding.developerSummary || finding.description
    || `Le scanner ${finding.tool || 'de sécurité'} a signalé « ${finding.title || 'un comportement à vérifier'} ». Le rapport ne contient pas assez de contexte pour confirmer automatiquement son exploitabilité.`;
}

function developerImpact(finding) {
  return finding.developerImpact
    || 'L’impact réel dépend de l’endpoint, des données contrôlées par l’utilisateur et des protections déjà présentes. Une validation manuelle est nécessaire avant de classer cette alerte comme vulnérabilité confirmée.';
}

function developerAction(finding) {
  return finding.developerAction || finding.solution
    || 'Examiner l’endpoint et la réponse associés, identifier la condition signalée par la règle, puis confirmer ou classer l’alerte comme faux positif avant toute modification du code.';
}

function renderTrivyContent(finding) {
  const references = Array.isArray(finding.references) && finding.references.length
    ? `<ul>${finding.references.map((reference) => `<li><a href="${escapeHtml(reference)}">${escapeHtml(reference)}</a></li>`).join('')}</ul>`
    : trivyValue(finding.helpUri, 'Aucune référence fournie');
  return `
  <h2>Dépendance ou configuration concernée</h2>
  <div class="grid block">
    <div class="label">Identifiant</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="label">Package</div><div>${trivyValue(finding.packageName)}</div>
    <div class="label">Version installée</div><div>${trivyValue(finding.installedVersion)}</div>
    <div class="label">Version corrigée</div><div>${finding.fixedVersion ? `<strong>${escapeHtml(finding.fixedVersion)}</strong>` : '<span class="muted">Aucun correctif indiqué</span>'}</div>
    <div class="label">Cible analysée</div><div><code>${escapeHtml(finding.target || finding.file || '')}</code></div>
    <div class="label">Type</div><div>${escapeHtml(finding.category || '')}</div>
    <div class="label">Atteignabilité</div><div>${finding.reachable === true ? '<strong>Fonction vulnérable appelée</strong>' : finding.reachable === false ? '<span class="muted">Fonction vulnérable non appelée selon l’analyse</span>' : '<span class="muted">Non évaluée pour cet écosystème</span>'}</div>
    <div class="label">Statut</div><div>${trivyValue(finding.status)}</div>
    <div class="label">CWE</div><div>${trivyValue(finding.cwe)}</div>
  </div>
  <h2>Description</h2>
  <div class="block">${trivyValue(finding.description)}</div>
  <h2>Correction recommandée</h2>
  <div class="block">${finding.fixedVersion
    ? `Mettre à niveau <code>${escapeHtml(finding.packageName)}</code> vers <strong>${escapeHtml(finding.fixedVersion)}</strong> ou une version ultérieure compatible.`
    : trivyValue(finding.solution, 'Consulter la configuration et les références associées.')}</div>
  <h2>Références</h2>
  <div class="block">${references}</div>`;
}

function renderGitleaksContent(finding) {
  return `<div class="explanation"><span class="eyebrow">Secret détecté par Gitleaks</span><p>${escapeHtml(finding.title)}</p><small class="provenance">La valeur du secret est volontairement masquée et n’est jamais enregistrée par Security Center.</small></div>
  <h2>Preuve vérifiable</h2><div class="grid block">
    <div class="label">Règle</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="label">Fichier</div><div><code>${escapeHtml(finding.file)}</code></div>
    <div class="label">Ligne</div><div>${Number(finding.startLine || 0) + 1}</div>
    <div class="label">Commit d’introduction</div><div>${finding.commit ? `<code>${escapeHtml(finding.commit)}</code>` : '<span class="muted">Scan du fichier courant — commit non fourni</span>'}</div>
    <div class="label">Confiance</div><div>${escapeHtml(finding.confidence || 'inconnue')}</div>
  </div>
  <h2>Action recommandée</h2><div class="block">Révoquer ou faire tourner le secret auprès du fournisseur, supprimer son usage du code et nettoyer l’historique Git si la politique de l’équipe l’exige. Supprimer seulement la chaîne du fichier courant ne révoque pas un secret déjà exposé.</div>`;
}

const SONARQUBE_ISSUE_TYPES = Object.freeze({
  VULNERABILITY: 'Vulnérabilité', BUG: 'Bug', CODE_SMELL: 'Code smell', SECURITY_HOTSPOT: 'Security hotspot'
});

function sonarValue(value, emptyLabel = 'Non fourni par SonarQube') {
  return value ? escapeHtml(value) : `<span class="muted">${escapeHtml(emptyLabel)}</span>`;
}

/**
 * SonarQube findings are static code results: showing the generic endpoint and
 * ZAP evidence fields for them would be misleading.
 */
function renderSonarQubeContent(finding) {
  const isHotspot = finding.category === 'security-hotspot';
  const tags = Array.isArray(finding.tags) && finding.tags.length ? finding.tags.join(', ') : '';
  const standards = Array.isArray(finding.securityStandards) && finding.securityStandards.length
    ? finding.securityStandards.join(', ') : '';
  return `<div class="explanation"><span class="eyebrow">${isHotspot ? 'Security hotspot signalé par SonarQube' : 'Résultat SonarQube'}</span>
    <p>${escapeHtml(finding.title)}</p>
    <small class="provenance">${isHotspot
      ? 'Un security hotspot est un emplacement à revoir manuellement, pas une vulnérabilité confirmée.'
      : 'Résultat produit par le serveur SonarQube et normalisé par Security Center.'}</small></div>
  <h2>Emplacement analysé</h2>
  <div class="grid block">
    <div class="label">Règle</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="label">Fichier</div><div>${finding.file ? `<code>${escapeHtml(finding.file)}</code>` : '<span class="muted">Résultat au niveau du projet — aucun fichier associé</span>'}</div>
    <div class="label">Ligne</div><div>${finding.unlocated ? '<span class="muted">Aucune ligne fournie</span>' : Number(finding.startLine || 0) + 1}</div>
    <div class="label">Type</div><div>${escapeHtml(SONARQUBE_ISSUE_TYPES[finding.issueType] || finding.category || 'Non précisé')}</div>
    <div class="label">Sévérité</div><div><strong>${escapeHtml(finding.rawSeverity)}</strong></div>
    ${isHotspot ? `<div class="label">Probabilité</div><div>${sonarValue(finding.vulnerabilityProbability)}</div>` : ''}
    <div class="label">CWE</div><div>${sonarValue(finding.cwe, 'Aucun CWE associé à cette règle')}</div>
    <div class="label">Normes</div><div>${sonarValue(standards, 'Aucune norme de sécurité référencée')}</div>
    <div class="label">Tags</div><div>${sonarValue(tags, 'Aucun tag')}</div>
    <div class="label">Effort estimé</div><div>${sonarValue(finding.effort, 'Non estimé')}</div>
    <div class="label">Statut SonarQube</div><div>${sonarValue(finding.sonarStatus)}</div>
  </div>
  <h2>Action recommandée</h2>
  <div class="block">${isHotspot
    ? 'Examiner le contexte d’utilisation, puis marquer le hotspot comme sûr ou le convertir en vulnérabilité dans SonarQube. Security Center conserve la preuve d’origine dans les deux cas.'
    : 'Ouvrir la ligne concernée, appliquer la correction indiquée par la règle, puis relancer l’analyse : le résultat disparaîtra du prochain scan s’il est corrigé.'}</div>`;
}

function snykValue(value, emptyLabel = 'Non fourni par Snyk') {
  return value ? escapeHtml(value) : `<span class="muted">${escapeHtml(emptyLabel)}</span>`;
}

/**
 * Snyk answers with three very different result shapes. Each one is rendered
 * with the evidence it actually carries: a dependency chain for Open Source, a
 * data flow for Code, a resource path for IaC.
 */
function renderSnykContent(finding) {
  const references = Array.isArray(finding.references) && finding.references.length
    ? `<ul>${finding.references.map((reference) => `<li><a href="${escapeHtml(reference)}">${escapeHtml(reference)}</a></li>`).join('')}</ul>`
    : snykValue(finding.helpUri, 'Aucune référence fournie');
  if (finding.snykCapability === 'openSource') {
    const chain = Array.isArray(finding.dependencyPath) && finding.dependencyPath.length
      ? `<code>${finding.dependencyPath.map((step) => escapeHtml(step)).join(' → ')}</code>`
      : '<span class="muted">Dépendance directe</span>';
    const upgrade = Array.isArray(finding.upgradePath) && finding.upgradePath.length
      ? `<code>${finding.upgradePath.map((step) => escapeHtml(step)).join(' → ')}</code>`
      : '<span class="muted">Aucun chemin de mise à niveau proposé</span>';
    return `<div class="explanation"><span class="eyebrow">Dépendance vulnérable signalée par Snyk</span>
      <p>${escapeHtml(finding.title)}</p>
      <small class="provenance">Résultat Snyk Open Source normalisé par Security Center. Aucune ligne de code n’est associée : le manifeste est la localisation réelle.</small></div>
    <h2>Dépendance concernée</h2>
    <div class="grid block">
      <div class="label">Identifiant Snyk</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="label">Package</div><div>${snykValue(finding.packageName)}</div>
      <div class="label">Version installée</div><div>${snykValue(finding.installedVersion)}</div>
      <div class="label">Version corrigée</div><div>${finding.fixedVersion ? `<strong>${escapeHtml(finding.fixedVersion)}</strong>` : '<span class="muted">Aucun correctif publié</span>'}</div>
      <div class="label">Manifeste</div><div><code>${escapeHtml(finding.file || '')}</code></div>
      <div class="label">Gestionnaire</div><div>${snykValue(finding.packageManager)}</div>
      <div class="label">Chaîne de dépendance</div><div>${chain}</div>
      <div class="label">Chemin de mise à niveau</div><div>${upgrade}</div>
      <div class="label">CVE</div><div>${snykValue((finding.vulnerabilityAliases || []).filter((alias) => alias.startsWith('CVE-')).join(', '), 'Aucune CVE associée')}</div>
      <div class="label">CWE</div><div>${snykValue(finding.cwe, 'Aucun CWE associé')}</div>
      <div class="label">Score CVSS</div><div>${snykValue(finding.cvssScore ? String(finding.cvssScore) : '', 'Non fourni')}</div>
      <div class="label">Maturité d’exploitation</div><div>${snykValue(finding.exploitMaturity, 'Non évaluée')}</div>
    </div>
    <h2>Description</h2>
    <div class="block">${snykValue(finding.description)}</div>
    <h2>Correction recommandée</h2>
    <div class="block">${finding.fixedVersion
      ? `Mettre à niveau <code>${escapeHtml(finding.packageName)}</code> vers <strong>${escapeHtml(finding.fixedVersion)}</strong> ou une version ultérieure compatible.${finding.isUpgradable ? '' : ' Cette dépendance est transitive : la mise à niveau passe par le parent indiqué dans la chaîne.'}`
      : 'Aucune version corrigée n’est publiée. Évaluer un remplacement de la dépendance ou une mesure de contournement.'}</div>
    <h2>Références</h2>
    <div class="block">${references}</div>`;
  }
  if (finding.snykCapability === 'iac') {
    return `<div class="explanation"><span class="eyebrow">Mauvaise configuration signalée par Snyk IaC</span>
      <p>${escapeHtml(finding.title)}</p>
      <small class="provenance">Résultat Snyk IaC normalisé par Security Center.</small></div>
    <h2>Ressource concernée</h2>
    <div class="grid block">
      <div class="label">Règle</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="label">Fichier</div><div><code>${escapeHtml(finding.file || '')}</code></div>
      <div class="label">Ligne</div><div>${finding.unlocated ? '<span class="muted">Aucune ligne fournie</span>' : Number(finding.startLine || 0) + 1}</div>
      <div class="label">Ressource</div><div>${snykValue(finding.resource, 'Chemin de ressource non fourni')}</div>
      <div class="label">Type</div><div>${snykValue(finding.resourceType)}</div>
      <div class="label">Sévérité</div><div><strong>${escapeHtml(finding.rawSeverity)}</strong></div>
    </div>
    <h2>Impact</h2>
    <div class="block">${snykValue(finding.impact, 'Impact non décrit par la règle')}</div>
    <h2>Correction recommandée</h2>
    <div class="block">${snykValue(finding.solution, 'Consulter la documentation de la règle.')}</div>
    <h2>Références</h2>
    <div class="block">${references}</div>`;
  }
  const flow = Array.isArray(finding.dataFlow) && finding.dataFlow.length
    ? `<ol>${finding.dataFlow.map((step) => `<li><code>${escapeHtml(step.file)}:${Number(step.line) || 1}</code>${step.message ? ` — ${escapeHtml(step.message)}` : ''}</li>`).join('')}</ol>`
    : '<span class="muted">Aucun flux de données fourni par Snyk Code</span>';
  return `<div class="explanation"><span class="eyebrow">Résultat Snyk Code</span>
    <p>${escapeHtml(finding.title)}</p>
    <small class="provenance">Analyse statique Snyk Code normalisée par Security Center.</small></div>
  <h2>Emplacement analysé</h2>
  <div class="grid block">
    <div class="label">Règle</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
    <div class="label">Fichier</div><div>${finding.file ? `<code>${escapeHtml(finding.file)}</code>` : '<span class="muted">Aucun fichier associé</span>'}</div>
    <div class="label">Ligne</div><div>${finding.unlocated ? '<span class="muted">Aucune ligne fournie</span>' : Number(finding.startLine || 0) + 1}</div>
    <div class="label">Sévérité</div><div><strong>${escapeHtml(finding.rawSeverity)}</strong></div>
    <div class="label">CWE</div><div>${snykValue(finding.cwe, 'Aucun CWE associé à cette règle')}</div>
    <div class="label">Score de priorité</div><div>${snykValue(finding.priorityScore ? String(finding.priorityScore) : '', 'Non fourni')}</div>
  </div>
  <h2>Flux de données</h2>
  <div class="block">${flow}</div>
  <h2>Description</h2>
  <div class="block">${snykValue(finding.description)}</div>
  <h2>Références</h2>
  <div class="block">${references}</div>`;
}

const REACHABILITY_LABELS = Object.freeze({
  not_evaluated: 'Non évaluée', present: 'Présente', imported: 'Importée',
  statically_reachable: 'Atteignable statiquement', dynamically_confirmed: 'Confirmée dynamiquement',
  not_reachable: 'Non atteignable', unknown: 'Indéterminée',
  // Public status vocabulary, preferred when the pipeline supplied it.
  REACHABLE: 'Atteignable', POTENTIALLY_REACHABLE: 'Potentiellement atteignable',
  NOT_REACHABLE: 'Non atteignable', UNKNOWN: 'Indéterminée'
});

/**
 * Security-intelligence block, added above the scanner-specific content.
 *
 * It is rendered only from verdicts the pipeline actually produced, and it
 * never replaces the original scanner evidence below it: the point is to add
 * the cross-scanner view, not to hide where each fact came from.
 */
function renderIntelligenceSection(finding) {
  const { correlation, reachability, priority } = finding;
  if (!correlation && !reachability && !priority) return '';
  const detectedBy = correlation?.tools?.length
    ? correlation.tools.map((tool) => `<li>✓ ${escapeHtml(tool)}</li>`).join('')
    : `<li>✓ ${escapeHtml(finding.tool)}</li>`;
  const clusters = Array.isArray(finding.correlationClusters) ? finding.correlationClusters : [];
  return `<section class="intelligence">
    <div class="grid block">
      ${priority ? `<div class="label">Priorité</div><div><strong>${escapeHtml(priority.code || '')} ${priority.score}/100</strong> — ${escapeHtml(priority.label)}</div>` : ''}
      <div class="label">Sévérité</div><div>${escapeHtml(finding.rawSeverity || finding.severity || '')}</div>
      ${reachability ? `<div class="label">Atteignabilité</div><div><strong>${escapeHtml(REACHABILITY_LABELS[reachability.status] || REACHABILITY_LABELS[reachability.state] || reachability.state)}</strong> <span class="muted">(confiance ${escapeHtml(reachability.confidence)})</span></div>` : ''}
    </div>
    <h2>Détectée par</h2>
    <div class="block"><ul class="plain">${detectedBy}</ul></div>
    ${priority?.reasons?.length ? `<h2>Pourquoi cette priorité</h2><div class="block"><ul class="plain">${priority.reasons.map((reason) => `<li>${reason.points >= 0 ? '✓' : '−'} ${escapeHtml(reason.label)} <span class="muted">(${reason.points >= 0 ? '+' : ''}${reason.points})</span></li>`).join('')}</ul></div>` : ''}
    ${reachability ? `<h2>Atteignabilité</h2><div class="block"><p>${escapeHtml(reachability.reason)}</p>${reachability.evidence?.length ? `<ul class="plain">${reachability.evidence.slice(0, 5).map((item) => `<li>${escapeHtml(item.type)} : ${item.file ? `<code>${escapeHtml(item.file)}${item.line ? `:${item.line}` : ''}</code> ` : ''}${escapeHtml(item.detail || '')}</li>`).join('')}</ul>` : ''}</div>` : ''}
    ${correlation ? `<h2>Corrélation <span class="muted">(confiance ${escapeHtml(correlation.confidence)})</span></h2>
      <div class="block"><ul class="plain">${correlation.reasons.slice(0, 8).map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>
      ${clusters.length ? `<p class="muted">Preuves d’origine conservées :</p><ul class="plain">${clusters.flatMap((cluster) => cluster.sources).slice(0, 8).map((source) => `<li><strong>${escapeHtml(source.tool)}</strong> ${escapeHtml(source.ruleId || '')}${source.file ? ` <code>${escapeHtml(source.file)}${source.line ? `:${source.line}` : ''}</code>` : ''}${source.endpoint ? ` <code>${escapeHtml(source.endpoint)}</code>` : ''}</li>`).join('')}</ul>` : ''}</div>` : ''}
  </section>`;
}

/**
 * The verification block.
 *
 * Says which of the two very different things is true — a fix was applied, or the
 * issue was shown to be gone — and names the evidence behind the second. A
 * finding that was merely patched shows « vérification en attente » and offers
 * the action that would settle it.
 */
function renderVerification(finding) {
  const status = String(finding?.triageStatus || 'new');
  const verification = finding?.verification;
  const relevant = verification || ['fixed', 'validating', 'validated', 'still_present', 'validation_failed', 'inconclusive', 'regressed'].includes(status);
  if (!relevant) {
    return `<div class="actions"><button data-verify="1">Vérifier la correction</button></div>
      <p class="muted">Une correction n’est validée qu’après relance du scanner concerné : appliquer un patch ne suffit pas.</p>`;
  }
  const rows = [
    ['Résultat', escapeHtml(VERIFICATION_LABELS[status] || status)],
    verification?.reason ? ['Raison', escapeHtml(VERIFICATION_REASONS[verification.reason] || verification.reason)] : null,
    verification?.validator ? ['Vérificateur', escapeHtml(verification.validator)] : null,
    finding?.fixSource ? ['Origine du correctif', escapeHtml(FIX_SOURCE_LABELS[finding.fixSource] || finding.fixSource)] : null,
    finding?.validatedAt ? ['Validée le', escapeHtml(finding.validatedAt)] : null,
    verification?.evidence?.scanId != null ? ['Scan de vérification', escapeHtml(String(verification.evidence.scanId))] : null,
    verification?.evidence?.retestId ? ['Re-test', escapeHtml(String(verification.evidence.retestId))] : null,
    verification?.evidence?.detail ? ['Détail', escapeHtml(verification.evidence.detail)] : null
  ].filter(Boolean);
  const actions = [
    status === 'validated' ? '' : `<button data-verify="1">${status === 'fixed' ? 'Vérifier la correction' : 'Relancer la vérification'}</button>`,
    finding?.fixSource === 'ai' ? '<button data-rollback="1" class="context-action">Annuler le patch IA</button>' : ''
  ].filter(Boolean).join('');
  return `<h2>Vérification</h2><div class="grid block">
      ${rows.map(([label, value]) => `<div class="label">${label}</div><div>${value}</div>`).join('')}
    </div>${actions ? `<div class="actions">${actions}</div>` : ''}
    ${status === 'fixed' ? '<p class="muted">Le correctif est appliqué, mais aucun scanner ne l’a encore confirmé.</p>' : ''}`;
}

function renderFindingDetailsHtml(finding, nonce, navigation = {}) {
  const reference = finding.helpUri
    ? `<a href="${escapeHtml(finding.helpUri)}">${escapeHtml(finding.helpUri)}</a>`
    : '<span class="muted">Aucune référence fournie</span>';
  const content = ['Trivy', 'OSV-Scanner'].includes(finding.tool) ? renderTrivyContent(finding)
    : finding.tool === 'Gitleaks' ? renderGitleaksContent(finding)
      : finding.tool === 'SonarQube' ? renderSonarQubeContent(finding)
        : finding.tool === 'Snyk' ? renderSnykContent(finding) : `
  <div class="explanation">
    <span class="eyebrow">Synthèse Security Center pour le développeur</span>
    <p>${escapeHtml(developerExplanation(finding))}</p>
    <small class="provenance">Interprétation prudente générée à partir de la règle du scanner — ce n’est pas une preuve supplémentaire.</small>
  </div>

  <div class="two-columns">
    <section>
      <h2>Impact possible</h2>
      <div class="block impact">${escapeHtml(developerImpact(finding))}</div>
    </section>
    <section>
      <h2>Priorité proposée</h2>
      <div class="block priority"><strong>${escapeHtml(finding.rawSeverity)}</strong><span>Confiance ${escapeHtml(finding.confidence || 'inconnue')}</span></div>
    </section>
  </div>

  <h2>Observation vérifiable</h2>
  <div class="grid block">
    <div class="label">Endpoint</div><div><code>${escapeHtml(finding.method || 'HTTP')} ${escapeHtml(finding.endpoint || '')}</code></div>
    <div class="label">Paramètre</div><div>${finding.parameter ? escapeHtml(finding.parameter) : '<span class="muted">Aucun paramètre spécifique identifié</span>'}</div>
    <div class="label">Preuve ZAP</div><div>${finding.evidence ? `<code>${escapeHtml(finding.evidence)}</code>` : '<span class="muted">Aucune preuve textuelle fournie</span>'}</div>
    <div class="label">Composant</div><div>${finding.packageName ? `<code>${escapeHtml(finding.packageName)} ${escapeHtml(finding.installedVersion || '')}</code>` : '<span class="muted">Non identifié</span>'}</div>
    <div class="label">CVE associées</div><div>${Array.isArray(finding.vulnerabilityAliases) && finding.vulnerabilityAliases.length ? escapeHtml(finding.vulnerabilityAliases.join(', ')) : '<span class="muted">Aucune CVE fournie</span>'}</div>
  </div>

  <h2>Plan de correction</h2>
  <div class="action-plan">
    <div><span>1</span><p>${escapeHtml(developerAction(finding))}</p></div>
    <div><span>2</span><p>Relancer le scan ZAP sur cet endpoint après la modification.</p></div>
    <div><span>3</span><p>Si l’alerte disparaît et que le replay reste fonctionnel, marquer le finding comme corrigé.</p></div>
  </div>

  <details>
    <summary>Détails techniques du scanner</summary>
    <div class="grid block technical">
      <div class="label">Règle ZAP</div><div><code>${escapeHtml(finding.ruleId)}</code></div>
      <div class="label">CWE</div><div>${valueOrUnavailable(finding.cwe)}</div>
      <div class="label">Description originale</div><div>${valueOrUnavailable(finding.description)}</div>
      <div class="label">Solution originale</div><div>${valueOrUnavailable(finding.solution)}</div>
      <div class="label">Informations techniques</div><div>${valueOrUnavailable(finding.technicalDetails)}</div>
      <div class="label">Référence</div><div>${reference}</div>
      <div class="label">Messages HTTP bruts</div><div class="muted">Non inclus dans le baseline passif. Ils seront disponibles après capture HAR/Burp.</div>
    </div>
  </details>`;
  const correlation = finding.correlatedTools?.length
    ? `<h2>Corrélation multi-outils</h2><div class="block"><strong>${escapeHtml(finding.correlatedTools.join(' + '))}</strong><br><span class="muted">Confiance ${escapeHtml(finding.correlationConfidence || 'medium')} — cette correspondance aide à prioriser, mais ne remplace pas une validation manuelle.</span></div>`
    : '';
  const triage = `<h2>Suivi</h2><div class="grid block"><div class="label">Statut</div><div><strong>${escapeHtml(VERIFICATION_LABELS[finding.triageStatus] || finding.triageStatus || 'new')}</strong></div><div class="label">Contexte</div><div>${escapeHtml(finding.sourceContext || 'non classé')}</div></div>${renderVerification(finding)}`;
  const aiAction = finding.absolutePath || finding.file ? '<button id="ai-fix" class="ai-action">✨ Proposer une correction avec Ollama</button>' : '<p class="muted">Correction IA indisponible : aucun fichier source local associé à ce finding.</p>';
  const relatedTraffic = Array.isArray(navigation.relatedTraffic) ? navigation.relatedTraffic : [];
  const backAction = Number.isInteger(navigation.backTrafficIndex) ? `<button class="context-action" data-back-traffic="${navigation.backTrafficIndex}">← Retour à la requête HTTP</button>` : '';
  const relatedEvidence = relatedTraffic.length ? `<h2>Preuves HTTP associées</h2><div class="http-evidence">${relatedTraffic.slice(0, 5).map((traffic) => `<div><strong>${escapeHtml(traffic.method)} ${escapeHtml(traffic.path)}</strong><span>Statut : ${escapeHtml(traffic.status)} · Source : ${escapeHtml(traffic.source)}</span><button data-http-index="${traffic.index}">Ouvrir la requête</button></div>`).join('')}</div>` : '';
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style nonce="${nonce}">
    body { color: var(--vscode-foreground); background: var(--vscode-editor-background); font-family: var(--vscode-font-family); padding: 28px; max-width: 1050px; margin: auto; }
    body.theme-light { --vscode-foreground:#3f4650; --vscode-descriptionForeground:#6d7480; --vscode-editor-background:#f8f9fb; --vscode-textCodeBlock-background:#eef0f4; --vscode-widget-border:#d8dce3; --vscode-button-background:#4d78d2; --vscode-button-foreground:#fff; --vscode-button-hoverBackground:#3f6fc7; --vscode-badge-background:#e5eaf4; --vscode-badge-foreground:#405677; --vscode-textLink-foreground:#416fce; --vscode-editor-inactiveSelectionBackground:#eef2fa; --vscode-focusBorder:#4d78d2; --vscode-errorForeground:#c84d43; color-scheme:light; }
    body.theme-dark { color-scheme:dark; }
    h1 { font-size: 26px; margin-bottom: 8px; letter-spacing: -.4px; }
    h2 { font-size: 15px; margin-top: 24px; }
    .badge { display: inline-block; padding: 4px 9px; border-radius: 999px; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); margin-right: 6px; font-weight: 700; }
    .grid { display: grid; grid-template-columns: minmax(120px, 180px) 1fr; gap: 8px 14px; }
    .label, .muted { color: var(--vscode-descriptionForeground); }
    code, pre { background: var(--vscode-textCodeBlock-background); border-radius: 4px; padding: 3px 5px; overflow-wrap: anywhere; white-space: pre-wrap; }
    .block { border: 1px solid var(--vscode-widget-border); border-radius: 6px; padding: 12px; }
    a { color: var(--vscode-textLink-foreground); }
    .explanation { margin: 22px 0; padding: 18px; border-radius: 7px; border: 1px solid var(--vscode-widget-border); border-left: 4px solid var(--vscode-focusBorder); background: var(--vscode-editor-inactiveSelectionBackground); }
    .explanation p { font-size: 16px; line-height: 1.55; margin: 8px 0 0; }
    .provenance { display: block; margin-top: 10px; color: var(--vscode-descriptionForeground); line-height: 1.4; }
    .eyebrow { color: var(--vscode-textLink-foreground); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; font-weight: 800; }
    .two-columns { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; }
    .impact { line-height: 1.5; min-height: 82px; }
    .priority strong, .priority span { display: block; }
    .priority strong { color: var(--vscode-errorForeground); font-size: 20px; }
    .priority span { color: var(--vscode-descriptionForeground); margin-top: 7px; }
    .action-plan { display: grid; gap: 8px; }
    .action-plan > div { display: grid; grid-template-columns: 29px minmax(0, 1fr); align-items: start; gap: 9px; border: 1px solid var(--vscode-widget-border); border-radius: 7px; padding: 10px; }
    .action-plan > div > span { width: 27px; height: 27px; display: grid; place-items: center; border-radius: 50%; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); font-weight: 800; }
    .action-plan p { min-width: 0; margin: 3px 0; line-height: 1.45; overflow-wrap: anywhere; }
    details { margin-top: 24px; }
    summary { cursor: pointer; color: var(--vscode-descriptionForeground); font-weight: 700; }
    .technical { margin-top: 10px; }
    .ai-action { margin: 18px 0 2px; padding: 10px 15px; border: 0; border-radius: 6px; cursor: pointer; font-weight: 700; color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
    .ai-action:hover { background: var(--vscode-button-hoverBackground); }
    .context-action, .http-evidence button { color: var(--vscode-button-foreground); background: var(--vscode-button-background); border: 0; border-radius: 4px; padding: 7px 10px; cursor: pointer; }
    .context-action { margin-bottom: 8px; }
    .http-evidence { border: 1px solid var(--vscode-widget-border); border-radius: 6px; }
    .http-evidence > div { display: grid; grid-template-columns: minmax(0,1fr) minmax(180px,auto) auto; gap: 10px; align-items: center; padding: 9px 11px; border-bottom: 1px solid var(--vscode-widget-border); }
    .http-evidence > div:last-child { border-bottom: 0; }
    .http-evidence span { color: var(--vscode-descriptionForeground); }
    .intelligence { margin-bottom: 6px; }
    ul.plain { list-style: none; margin: 0; padding: 0; }
    ul.plain li { padding: 3px 0; }
    .muted { color: var(--vscode-descriptionForeground); }
    @media (max-width: 700px) { .two-columns { grid-template-columns: 1fr; } body { padding: 16px; } }
  </style>
</head>
<body class="theme-${navigation.theme === 'dark' ? 'dark' : 'light'}">
  ${backAction}
  <h1>${escapeHtml(finding.title)}</h1>
  <p><span class="badge">${escapeHtml(finding.tool)}</span><span class="badge">${escapeHtml(finding.rawSeverity)}</span><span class="badge">Confiance ${escapeHtml(finding.confidence || 'inconnue')}</span></p>
  ${aiAction}
  ${renderIntelligenceSection(finding)}
  ${content}
  ${correlation}
  ${relatedEvidence}
  ${triage}
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const aiButton = document.getElementById('ai-fix');
    document.querySelector('[data-back-traffic]')?.addEventListener('click', (event) => vscode.postMessage({ type: 'backToHttpRequest', index: Number(event.currentTarget.dataset.backTraffic) }));
    document.querySelectorAll('[data-http-index]').forEach((button) => button.addEventListener('click', () => vscode.postMessage({ type: 'openHttpRequest', index: Number(button.dataset.httpIndex) })));
    document.querySelector('[data-verify]')?.addEventListener('click', (event) => { event.currentTarget.disabled = true; vscode.postMessage({ type: 'verifyFix' }); });
    document.querySelector('[data-rollback]')?.addEventListener('click', () => vscode.postMessage({ type: 'rollbackAiFix' }));
    aiButton?.addEventListener('click', () => {
      aiButton.disabled = true;
      aiButton.textContent = '⏳ Demande envoyée à Ollama…';
      vscode.postMessage({ type: 'generateAiFix' });
    });
    window.addEventListener('message', (event) => {
      if (event.data?.type !== 'aiFixStatus' || !aiButton) return;
      if (event.data.status === 'received') aiButton.textContent = '⏳ Ollama génère la correction…';
      if (event.data.status === 'done') { aiButton.disabled = false; aiButton.textContent = '✨ Proposer une nouvelle correction avec Ollama'; }
      if (event.data.status === 'error') { aiButton.disabled = false; aiButton.textContent = '⚠ Réessayer la correction Ollama'; }
    });
  </script>
</body>
</html>`;
}

module.exports = {
  escapeHtml, renderFindingDetailsHtml, renderSonarQubeContent, renderSnykContent,
  renderIntelligenceSection, SONARQUBE_ISSUE_TYPES, REACHABILITY_LABELS
};
