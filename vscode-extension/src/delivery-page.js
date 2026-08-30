'use strict';

/**
 * Security Delivery page.
 *
 * Shows the security-relevant state of the last CI build: did the same policy
 * that passes locally also pass in Jenkins, and is that build even the code the
 * developer has open.
 *
 * It renders facts, not reassurance. Anything Jenkins did not report is shown as
 * « non fourni » rather than filled in, and the commit correlation never says
 * « same » without two commits to compare. A standalone panel on purpose: it does
 * not touch the dashboard, whose layout is owned elsewhere.
 */

const { DELIVERY_STATE, COMMIT_MATCH, REPORT_STATE, CONNECTION_STATE } = require('./jenkins');
const { renderSecurityCenterShell } = require('./security-center-shell');
const { buildAssistantCardModel, renderAssistantCard, assistantCardCss, assistantCardScript } = require('./companion-assistant-card');
const { isTrustedWebviewAssetUri } = require('./scanner-presentation');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

const STATE_LABELS = Object.freeze({
  NOT_CONFIGURED: 'Non configuré',
  UNAVAILABLE: 'Indisponible',
  ERROR: 'Erreur',
  NOT_STARTED: 'Aucun build',
  RUNNING: 'Build en cours',
  SUCCESS: 'Succès',
  FAILED: 'Échec',
  UNSTABLE: 'Instable',
  ABORTED: 'Interrompu'
});

const STATE_CLASS = Object.freeze({
  SUCCESS: 'ok', RUNNING: 'warn', UNSTABLE: 'warn',
  FAILED: 'bad', ABORTED: 'bad', ERROR: 'bad'
});

const COMMIT_LABELS = Object.freeze({
  SAME: '✓ même commit que ce workspace',
  DIFFERENT: '⚠ commit différent de ce workspace',
  UNKNOWN: 'Corrélation impossible — commit inconnu d’un côté'
});

function stamp(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('fr-FR');
}

function duration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '';
  return ms < 60000 ? `${Math.round(ms / 1000)} s` : `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`;
}

function row(label, value, extra = '') {
  return `<div><dt>${escapeHtml(label)}</dt><dd${extra}>${value}</dd></div>`;
}

/** « Non fourni » is the honest rendering of a field Jenkins did not return. */
function fact(value) {
  return value ? escapeHtml(value) : '<span class="muted">Non fourni</span>';
}

function renderJenkinsLogo(assets = {}) {
  const uri = isTrustedWebviewAssetUri(assets?.jenkinsLogoUri, assets) ? String(assets.jenkinsLogoUri) : '';
  if (!uri) return '';
  return `<span class="jenkins-logo" aria-hidden="true"><img src="${escapeHtml(uri)}" alt="" loading="lazy"></span>`;
}

const CONNECTION_LABELS = Object.freeze({
  CONNECTED: 'Connecté',
  AUTH_FAILED: 'Authentification refusée',
  FORBIDDEN: 'Accès refusé',
  JOB_NOT_FOUND: 'Job introuvable',
  UNREACHABLE: 'Serveur injoignable',
  ERROR: 'Erreur de configuration'
});

/**
 * The connection section.
 *
 * Says whether a token is stored — never what it is. A missing token is a fact
 * worth showing: most Jenkins servers refuse anonymous API access, and « job
 * introuvable » is a confusing way to learn that.
 */
function renderConnectionCard(status, jenkinsLogo = '') {
  const test = status.connection;
  const state = test?.state || (status.state === DELIVERY_STATE.ERROR ? CONNECTION_STATE.UNREACHABLE : CONNECTION_STATE.CONNECTED);
  return `<article class="card ${state === CONNECTION_STATE.CONNECTED ? 'ok' : 'bad'}">
      <div class="card-head"><h3 class="provider-title">${jenkinsLogo}<span>Connexion Jenkins</span></h3><span class="state">${escapeHtml(CONNECTION_LABELS[state] || state)}</span></div>
      <dl>
        ${row('Serveur', fact(status.baseUrl))}
        ${row('Job', fact(status.job))}
        ${row('Authentification', status.tokenConfigured ? 'Jeton configuré (SecretStorage)' : '<span class="muted">Aucun jeton — l’accès anonyme est souvent refusé</span>')}
        ${test?.message ? row('Dernier test', escapeHtml(test.message)) : ''}
      </dl>
      <div class="actions">
        <button data-action="configure">Configurer Jenkins</button>
        <button class="secondary" data-action="testConnection">Tester la connexion</button>
        <button class="secondary" data-action="openJenkins">Ouvrir Jenkins</button>
      </div>
    </article>`;
}

/** What the developer has open, for comparison with the build. */
function renderWorkspaceCard(status) {
  return `<article class="card"><div class="card-head"><h3>Workspace courant</h3></div><dl>
      ${row('Branche', fact(status.workspaceBranch))}
      ${row('Commit', status.commit?.workspaceCommit ? `<code>${escapeHtml(status.commit.workspaceCommit.slice(0, 12))}</code>` : fact(''))}
    </dl></article>`;
}

/**
 * Deployment.
 *
 * The Jenkins API as used here reads the build, not its stages. A successful
 * build does not prove a deployment ran, so nothing is inferred from it.
 */
function renderDeploymentCard() {
  return `<article class="card muted"><div class="card-head"><h3>Déploiement</h3><span class="state">État indisponible</span></div>
      <p>Security Center lit l’état du build, pas celui de ses étapes : un build en succès ne prouve pas qu’un déploiement a eu lieu. Le déploiement reste piloté par Jenkins.</p></article>`;
}

function renderBuildCard(status) {
  const build = status.build;
  if (!build) {
    return `<section class="banner muted"><strong>Aucun build</strong>
      <p>Le job existe mais n’a pas encore produit de build, ou Jenkins n’en expose aucun.</p></section>`;
  }
  return `<article class="card ${escapeHtml(STATE_CLASS[status.state] || 'muted')}">
      <div class="card-head"><h3>Build ${build.number === null ? '' : `#${build.number}`}</h3>
      <span class="state">${escapeHtml(STATE_LABELS[status.state] || status.state)}</span></div>
      <dl>
        ${row('Branche', fact(build.branch))}
        ${row('Commit', build.commit ? `<code>${escapeHtml(build.commit.slice(0, 12))}</code>` : fact(''))}
        ${row('Démarré', fact(stamp(build.startedAt)))}
        ${row('Durée', fact(duration(build.durationMs)))}
        ${row('Résultat Jenkins', build.result ? escapeHtml(build.result) : '<span class="muted">En cours</span>')}
      </dl>
    </article>`;
}

/**
 * The commit correlation card.
 *
 * The point of this page: a green CI badge means nothing if it belongs to other
 * code. The mismatch is stated plainly rather than left for the reader to notice.
 */
function renderCommitCard(status) {
  const { match, workspaceCommit, buildCommit } = status.commit;
  return `<article class="card ${match === COMMIT_MATCH.SAME ? 'ok' : match === COMMIT_MATCH.DIFFERENT ? 'warn' : 'muted'}">
      <div class="card-head"><h3>Correspondance du code</h3><span class="state">${escapeHtml(COMMIT_LABELS[match])}</span></div>
      <dl>
        ${row('Commit du workspace', workspaceCommit ? `<code>${escapeHtml(workspaceCommit.slice(0, 12))}</code>` : fact(''))}
        ${row('Commit du build', buildCommit ? `<code>${escapeHtml(buildCommit.slice(0, 12))}</code>` : fact(''))}
      </dl>
      ${match === COMMIT_MATCH.DIFFERENT
    ? '<p class="note">Le verdict de sécurité de ce build ne porte pas sur le code actuellement ouvert.</p>'
    : match === COMMIT_MATCH.UNKNOWN
      ? '<p class="note">Sans les deux commits, aucune correspondance n’est affirmée.</p>' : ''}
    </article>`;
}

/**
 * The CI security verdict, from the archived report and from nothing else.
 *
 * Each non-reported case says which one it is: a pipeline that never ran Security
 * Center, an artefact that could not be downloaded, one that did not validate, or
 * a report whose commit disagrees with the build. None of them is rendered as
 * PASS, and none of them falls back to the local scan.
 */
function renderCiCard(status) {
  const ci = status.ci || { state: REPORT_STATE.NOT_REPORTED };
  const report = ci.report;

  if (status.identity?.inconsistent) {
    return `<article class="card bad"><div class="card-head"><h3>Security Center — CI</h3><span class="state">Données incohérentes</span></div>
      <p>Le rapport archivé a été produit depuis un autre commit que celui de ce build. Son verdict n’est pas attribué à ce build.</p>
      <dl>${row('Commit du build', `<code>${escapeHtml(String(status.identity.buildCommit || '').slice(0, 12))}</code>`)}
      ${row('Commit du rapport', `<code>${escapeHtml(String(status.identity.reportCommit || '').slice(0, 12))}</code>`)}</dl></article>`;
  }
  if (ci.state === REPORT_STATE.INVALID) {
    return `<article class="card bad"><div class="card-head"><h3>Security Center — CI</h3><span class="state">Rapport invalide</span></div>
      <p>${escapeHtml(ci.reason)}</p>
      <div class="actions"><button data-action="openJenkinsfile">Voir l’intégration Jenkinsfile</button></div></article>`;
  }
  if (ci.state === REPORT_STATE.UNAVAILABLE) {
    return `<article class="card warn"><div class="card-head"><h3>Security Center — CI</h3><span class="state">Rapport inaccessible</span></div>
      <p>${escapeHtml(ci.reason)}</p>
      <div class="actions"><button data-action="refresh">Réessayer</button></div></article>`;
  }
  if (!report) {
    return `<article class="card muted"><div class="card-head"><h3>Security Center — CI</h3><span class="state">Non rapporté</span></div>
      <p>Ce build Jenkins n’a pas publié de rapport Security Center. Le verdict local reste visible dans Security Pipeline — c’est une autre identité de scan, elle n’est pas mélangée ici.</p>
      <div class="actions"><button data-action="openJenkinsfile">Voir l’intégration Jenkinsfile</button></div></article>`;
  }

  const policy = report.policy;
  const partial = report.execution.status === 'partial';
  return `<article class="card ${policy.status === 'BLOCK' || policy.status === 'ERROR' ? 'bad' : policy.status === 'WARN' ? 'warn' : policy.status === 'PASS' ? 'ok' : 'muted'}">
      <div class="card-head"><h3>Security Center — CI</h3><span class="state">${escapeHtml(policy.status)}</span></div>
      <p>${escapeHtml(policy.summary || '')}</p>
      <dl>
        ${row('Scan ID', `<code>${escapeHtml(report.execution.scanId || '—')}</code>`)}
        ${row('Exécution', partial ? '<span class="warn-text">Partielle — un scanner n’a pas rapporté</span>' : escapeHtml(report.execution.status))}
        ${row('Findings', String(report.summary.findings))}
        ${row('Critiques', String(report.summary.critical))}
        ${row('Élevés', String(report.summary.high))}
      </dl>
      <h4>Scanners</h4>
      <ul class="scanners">${report.scanners.map((scanner) => `<li>${escapeHtml(scanner.name)} <span class="state">${escapeHtml(scanner.status)}</span>${scanner.findings ? ` · ${scanner.findings}` : ''}${scanner.error ? ` <span class="muted">${escapeHtml(scanner.error)}</span>` : ''}</li>`).join('') || '<li class="muted">Aucun scanner rapporté</li>'}</ul>
      ${policy.reasons.length ? `<h4>${policy.blockingCount} raison(s) de blocage</h4>
        <ol class="reasons">${policy.reasons.slice(0, 10).map((reason) => `<li>${escapeHtml(reason.title || reason.rule)}${reason.file ? ` <code>${escapeHtml(reason.file)}${reason.line ? `:${reason.line}` : ''}</code>` : ''}${reason.rule ? ` <span class="muted">${escapeHtml(reason.rule)}</span>` : ''}</li>`).join('')}</ol>` : ''}
      <div class="actions">
        ${policy.status === 'BLOCK' ? '<button data-action="openBlocking">Ouvrir le Policy Gate local</button>' : ''}
        ${ci.artifactPath ? '<button class="secondary" data-action="openReport">Ouvrir le rapport dans Jenkins</button>' : ''}
      </div>
    </article>`;
}

/**
 * Supply-chain evidence, from the CI report only.
 *
 * `Non rapporté` and `Absent` are different facts: the first means the build
 * published no report, the second that the report says the stage produced nothing.
 */
const ARTIFACT_LABELS = Object.freeze({
  generated: 'Disponible', verified: 'Vérifiée', signed: 'Signé',
  failed: 'Échec', skipped: 'Non exécuté'
});

function artifactLabel(value) {
  if (!value) return '<span class="muted">Absent</span>';
  return escapeHtml(ARTIFACT_LABELS[value] || value);
}

function renderArtifactsCard(status) {
  const supply = status.ci?.report?.supplyChain;
  if (!supply) {
    return `<article class="card muted"><div class="card-head"><h3>Preuves supply chain</h3><span class="state">Non rapportées</span></div>
      <p>Aucun rapport Security Center n’a été publié par ce build, donc aucun SBOM, provenance ni signature ne peut lui être attribué.</p></article>`;
  }
  return `<article class="card ${supply.signature === 'failed' ? 'bad' : supply.signatureVerified ? 'ok' : ''}">
      <div class="card-head"><h3>Preuves supply chain</h3></div><dl>
      ${row('SBOM', artifactLabel(supply.sbom))}
      ${row('Provenance', artifactLabel(supply.provenance))}
      ${row('Signature', artifactLabel(supply.signature))}
      ${row('Vérification', supply.signatureVerified ? 'Vérifiée par le build' : '<span class="muted">Non vérifiée par le build</span>')}
    </dl>
    <p class="note">Security Center ne revérifie pas une signature depuis cette page : la vérification reste une action explicite.</p></article>`;
}

/**
 * The inline configuration form.
 *
 * Three of the four fields are prefilled from the workspace configuration. The
 * fourth — the API token — never is: a saved token is not sent to the webview at
 * all, so there is nothing to prefill it with. What the page can say is whether
 * one exists, which is the only part of it the extension puts in the model.
 *
 * The form collects; it does not decide. Validation, the connection test and the
 * write to SecretStorage all happen in the extension, which is the trusted side.
 */
function renderJenkinsForm(status, { open = false, jenkinsLogo = '' } = {}) {
  const test = status.connection;
  const stateClass = !test ? '' : test.state === CONNECTION_STATE.CONNECTED ? 'ok' : 'bad';
  return `<section class="card jenkins-form ${stateClass}" id="jenkins-form"${open ? '' : ' hidden'}>
      <div class="card-head"><h3 class="provider-title">${jenkinsLogo}<span>Connecter Jenkins</span></h3>
        ${test ? `<span class="state">${escapeHtml(CONNECTION_LABELS[test.state] || test.state)}</span>` : ''}</div>
      <p class="muted">Connectez votre serveur Jenkins existant. Security Center n’installe jamais Jenkins.</p>
      <div class="jenkins-fields">
      <div class="field">
        <label for="jenkins-url">URL Jenkins</label>
        <input id="jenkins-url" type="url" inputmode="url" spellcheck="false" autocomplete="off"
          placeholder="http://127.0.0.1:8080" value="${escapeHtml(status.baseUrl || '')}">
        <small class="muted">N’y mettez pas d’identifiants.</small>
      </div>
      <div class="field">
        <label for="jenkins-job">Job / Pipeline</label>
        <input id="jenkins-job" type="text" spellcheck="false" autocomplete="off"
          placeholder="equipe/projet/main" value="${escapeHtml(status.job || '')}">
        <small class="muted">Nom du job, ou chemin pour un dossier ou un pipeline multibranche.</small>
      </div>
      <div class="field">
        <label for="jenkins-user">Utilisateur</label>
        <input id="jenkins-user" type="text" spellcheck="false" autocomplete="off"
          placeholder="prenom.nom" value="${escapeHtml(status.user || '')}">
      </div>
      <div class="field">
        <label for="jenkins-token">Jeton d’API</label>
        <input id="jenkins-token" type="password" autocomplete="off" placeholder="${status.tokenConfigured ? 'Laisser vide pour conserver le jeton enregistré' : 'Jeton d’API Jenkins'}">
        <small class="${status.tokenConfigured ? 'token-set' : 'muted'}">${status.tokenConfigured
          ? '✓ Configuré dans SecretStorage'
          : 'Conservé dans le SecretStorage de VS Code — jamais dans settings.json, jamais dans un journal.'}</small>
      </div>
      </div>
      ${test?.message ? `<p class="test-result ${stateClass}">${escapeHtml(test.message)}</p>` : ''}
      <div class="actions">
        <button data-action="saveConfig">Enregistrer</button>
        <button class="secondary" data-action="testConfig">Tester la connexion</button>
        <button class="secondary" data-action="openJenkinsfile">Voir le Jenkinsfile d’exemple</button>
      </div>
    </section>`;
}

/**
 * Le rapport archive, mais SEULEMENT quand il porte sur ce build.
 *
 * Un rapport produit depuis un autre commit que celui du build ne dit rien de ce
 * build : son verdict ne lui est pas attribue. `renderCiCard` le disait deja pour
 * sa propre carte ; ce helper existe pour que le bandeau, le cycle, le rail et
 * l'assistant ne puissent pas, eux, afficher « BLOCK » ou « PASS » pour un
 * rapport incoherent. Une seule regle d'attribution, un seul endroit.
 */
function attributableReport(status) {
  if (status?.identity?.inconsistent) return null;
  return status?.ci?.report || null;
}

/**
 * Le bandeau operationnel : six faits, chacun lu du modele Jenkins.
 *
 * Aucune valeur n'est composee pour remplir une case. Un champ que Jenkins n'a
 * pas rapporte affiche « Non fourni », un rapport absent affiche « Non rapporte »
 * — jamais un vert par defaut, jamais un numero de build inventé.
 */
function renderDeliveryStrip(status, jenkinsLogo = '') {
  const build = status.build;
  const ci = status.ci || {};
  const policy = attributableReport(status)?.policy;
  const connected = (status.connection?.state || CONNECTION_STATE.CONNECTED) === CONNECTION_STATE.CONNECTED
    && status.state !== DELIVERY_STATE.ERROR;
  // Le Policy Gate n'existe ici que si le build a publie un rapport : le verdict
  // local vit dans Security Pipeline et n'est jamais recopie sur ce build.
  const gate = policy
    ? { text: policy.status, tone: policy.status === 'PASS' ? 'ok' : policy.status === 'WARN' ? 'warn' : 'bad' }
    : { text: 'Non rapporté', tone: 'muted' };
  // Un rapport incoherent est « Incoherent », pas « Disponible » : il existe,
  // mais il ne decrit pas ce build.
  const report = status.identity?.inconsistent
    ? { text: 'Incohérent', tone: 'bad' }
    : ci.state === REPORT_STATE.REPORTED
      ? { text: 'Disponible', tone: 'ok' }
      : { text: REPORT_TONE_LABELS[ci.state] || 'Non rapporté', tone: ci.state === REPORT_STATE.NOT_REPORTED ? 'muted' : 'warn' };
  const tiles = [
    ['Jenkins', connected ? 'Connecté' : 'Non connecté', connected ? 'ok' : 'bad'],
    ['Job', status.job || 'Non fourni', status.job ? 'plain' : 'muted'],
    ['Dernier build', build && build.number !== null ? `#${build.number}` : 'Aucun build', build && build.number !== null ? 'plain' : 'muted'],
    ['Résultat', STATE_LABELS[status.state] || status.state, STATE_CLASS[status.state] || 'muted'],
    ['Policy Gate', gate.text, gate.tone],
    ['Rapport de sécurité', report.text, report.tone]
  ];
  return `<section class="card delivery-strip ${connected ? 'ok' : 'bad'}">
      <div class="card-head"><h3 class="provider-title">${jenkinsLogo}<span>${STATUS_GLYPH[connected ? 'ok' : 'bad']} État de la livraison</span></h3>
        <span class="state">${escapeHtml(connected ? 'Connecté' : 'Non connecté')}</span></div>
      <div class="strip-grid">${tiles.map(([label, value, tone]) => `<div class="strip-tile">
        <span>${escapeHtml(label)}</span>
        <strong class="tone-${escapeHtml(tone)}">${escapeHtml(String(value))}</strong>
      </div>`).join('')}</div>
    </section>`;
}

/**
 * Le cycle de la derniere livraison.
 *
 * L'API Jenkins telle qu'elle est utilisee ici lit le build, PAS ses etapes.
 * Les quatre premieres etapes sont donc deduites de faits reellement connus
 * (resultat du build, etat du rapport, verdict du gate, artefacts rapportes) et
 * la derniere est declaree indisponible, exactement comme la carte
 * « Deploiement » le dit deja. Rien n'est deduit d'un build en succes : un build
 * vert ne prouve pas qu'un deploiement a eu lieu.
 */
function deliveryLifecycle(status) {
  const build = status.build;
  const ci = status.ci || {};
  const report = attributableReport(status);
  const supply = report?.supplyChain;
  const buildStage = !build
    ? ['Aucun build', 'idle']
    : status.state === DELIVERY_STATE.RUNNING
      ? ['En cours', 'running']
      : status.state === DELIVERY_STATE.SUCCESS
        ? ['Succès', 'passed']
        : [STATE_LABELS[status.state] || status.state, 'failed'];
  const scanStage = status.identity?.inconsistent
    ? ['Rapport incohérent', 'failed']
    : ci.state === REPORT_STATE.REPORTED
      ? report.execution.status === 'partial' ? ['Partielle', 'warning'] : ['Rapportée', 'passed']
      : ci.state === REPORT_STATE.INVALID ? ['Rapport invalide', 'failed']
        : ci.state === REPORT_STATE.UNAVAILABLE ? ['Rapport inaccessible', 'warning']
          : ['Non rapportée', 'idle'];
  const gateStage = !report
    ? ['Non rapporté', 'idle']
    : report.policy.status === 'PASS' ? ['PASS', 'passed']
      : report.policy.status === 'WARN' ? ['WARN', 'warning'] : [report.policy.status, 'failed'];
  const artifactStage = !supply
    ? ['Non rapportés', 'idle']
    : supply.signature === 'failed' ? ['Signature en échec', 'failed']
      : supply.sbom || supply.provenance || supply.signature ? ['Rapportés', 'passed'] : ['Absents', 'idle'];
  return [
    ['Build', ...buildStage],
    ['Analyse de sécurité', ...scanStage],
    ['Policy Gate', ...gateStage],
    ['Artefacts', ...artifactStage],
    // Jamais deduit : Security Center ne lit pas les etapes du pipeline.
    ['Déploiement', 'État indisponible', 'unknown']
  ];
}

const STAGE_GLYPH = Object.freeze({
  passed: '✓', warning: '!', failed: '✕', running: '◷', idle: '·', unknown: '?'
});

function renderDeliveryLifecycle(status) {
  const stages = deliveryLifecycle(status);
  return `<section class="card">
      <div class="card-head"><h3>Cycle de la dernière livraison</h3>
        <span class="state">${escapeHtml(status.build && status.build.number !== null ? `Build #${status.build.number}` : 'Aucun build')}</span></div>
      <ol class="lifecycle">${stages.map(([label, value, tone]) => `<li class="stage-${escapeHtml(tone)}">
        <span class="stage-dot" aria-hidden="true">${STAGE_GLYPH[tone] || '·'}</span>
        <strong>${escapeHtml(label)}</strong>
        <span class="stage-value">${escapeHtml(value)}</span>
      </li>`).join('')}</ol>
      <p class="note">Security Center lit l’état du build, pas celui de ses étapes : les états ci-dessus sont déduits des faits réellement rapportés par Jenkins et par le rapport archivé.</p>
    </section>`;
}

/**
 * Les actions rapides.
 *
 * Chaque bouton reprend un `data-action` DEJA traite par le panneau Security
 * Delivery. Aucune action n'est affichee sans handler, et « Ouvrir le rapport »
 * n'apparait que lorsqu'un artefact existe reellement.
 */
function renderDeliveryActions(status) {
  const items = [
    ['testConnection', 'Tester la connexion', 'Vérifier l’accès Jenkins'],
    ['openJenkins', 'Ouvrir Jenkins', 'Ouvrir dans le navigateur'],
    ['refresh', 'Actualiser l’état', 'Relire le dernier build'],
    ...(status.ci?.artifactPath && status.build?.number ? [['openReport', 'Voir le rapport', 'Rapport archivé du build']] : []),
    ['openJenkinsfile', 'Jenkinsfile d’exemple', 'Intégration du pipeline']
  ];
  return `<section class="card"><div class="card-head"><h3>Actions</h3></div>
      <div class="quick-actions">${items.map(([action, label, hint]) => `<button class="secondary quick-action" data-action="${escapeHtml(action)}">
        <strong>${escapeHtml(label)}</strong><span>${escapeHtml(hint)}</span>
      </button>`).join('')}</div>
    </section>`;
}

const REPORT_TONE_LABELS = Object.freeze({
  REPORTED: 'Disponible', NOT_REPORTED: 'Non rapporté',
  INVALID: 'Invalide', UNAVAILABLE: 'Inaccessible'
});

/** Le glyphe double la couleur : l'etat n'est jamais porte par la teinte seule. */
const STATUS_GLYPH = Object.freeze({ ok: '✓', warn: '!', bad: '✕', muted: '·' });

/**
 * Le rail de contexte de Security Delivery.
 *
 * Trois cartes de faits, plus la carte Companion Assistant partagee. Chaque
 * valeur vient du modele Jenkins ; une carte dont les faits manquent affiche un
 * etat explicite plutot que d'etre remplie.
 */
function renderDeliveryRail(status, assistantCard) {
  const connection = status.connection;
  const state = connection?.state
    || (status.state === DELIVERY_STATE.ERROR ? CONNECTION_STATE.UNREACHABLE : CONNECTION_STATE.CONNECTED);
  const connected = state === CONNECTION_STATE.CONNECTED && status.state !== DELIVERY_STATE.ERROR;
  const build = status.build;
  const report = attributableReport(status);
  const jenkinsCard = `<section class="sc-context-card rail-card">
      <div class="rail-head"><strong>État Jenkins</strong>
        <span class="rail-pill ${connected ? 'ok' : 'bad'}">${STATUS_GLYPH[connected ? 'ok' : 'bad']} ${escapeHtml(CONNECTION_LABELS[state] || state)}</span></div>
      <div class="rail-facts">
        <div class="rail-fact"><span>Serveur</span><strong title="${escapeHtml(status.baseUrl || '')}">${escapeHtml(status.baseUrl || 'Non fourni')}</strong></div>
        <div class="rail-fact"><span>Job</span><strong title="${escapeHtml(status.job || '')}">${escapeHtml(status.job || 'Non fourni')}</strong></div>
        <div class="rail-fact"><span>Authentification</span><strong>${status.tokenConfigured ? 'Jeton enregistré' : 'Aucun jeton'}</strong></div>
        ${status.fetchedAt ? `<div class="rail-fact"><span>Dernière lecture</span><strong>${escapeHtml(stamp(status.fetchedAt))}</strong></div>` : ''}
      </div>
      <button class="rail-link secondary" data-action="testConnection">Tester la connexion →</button>
    </section>`;
  const deliveryCard = build
    ? `<section class="sc-context-card rail-card">
        <div class="rail-head"><strong>Dernière livraison</strong></div>
        <div class="rail-facts">
          <div class="rail-fact"><span>Build</span><strong>${build.number === null ? 'Non fourni' : `#${escapeHtml(String(build.number))}`}</strong></div>
          <div class="rail-fact"><span>Résultat</span><strong class="tone-${escapeHtml(STATE_CLASS[status.state] || 'muted')}">${escapeHtml(STATE_LABELS[status.state] || status.state)}</strong></div>
          <div class="rail-fact"><span>Policy Gate</span><strong class="tone-${report ? escapeHtml(report.policy.status === 'PASS' ? 'ok' : report.policy.status === 'WARN' ? 'warn' : 'bad') : 'muted'}">${escapeHtml(report ? report.policy.status : 'Non rapporté')}</strong></div>
          <div class="rail-fact"><span>Rapport</span><strong>${escapeHtml(status.identity?.inconsistent ? 'Incohérent' : REPORT_TONE_LABELS[status.ci?.state] || 'Non rapporté')}</strong></div>
        </div>
      </section>`
    : '';
  // Les compteurs viennent du rapport archive, jamais du scan local : ce sont
  // deux identites de scan differentes et elles ne sont pas melangees.
  const securityCard = report
    ? `<section class="sc-context-card rail-card">
        <div class="rail-head"><strong>Sécurité de la livraison</strong></div>
        <div class="rail-facts">
          <div class="rail-fact"><span>Policy Gate</span><strong class="tone-${escapeHtml(report.policy.status === 'PASS' ? 'ok' : report.policy.status === 'WARN' ? 'warn' : 'bad')}">${escapeHtml(report.policy.status)}</strong></div>
          <div class="rail-fact"><span>Critiques</span><strong>${escapeHtml(String(report.summary.critical))}</strong></div>
          <div class="rail-fact"><span>Élevés</span><strong>${escapeHtml(String(report.summary.high))}</strong></div>
          <div class="rail-fact"><span>Findings</span><strong>${escapeHtml(String(report.summary.findings))}</strong></div>
        </div>
        ${status.ci?.artifactPath ? '<button class="rail-link secondary" data-action="openReport">Ouvrir le rapport →</button>' : ''}
      </section>`
    : '';
  return `${assistantCard}${jenkinsCard}${deliveryCard}${securityCard}`;
}

/** Le style propre au tableau de bord de livraison, en tokens partages. */
function deliveryDashboardCss() {
  return `
  .strip-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:1px;margin-top:11px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-border);overflow:hidden}
  .strip-tile{display:grid;gap:5px;padding:11px 12px;background:var(--sc-surface);min-width:0}
  .strip-tile span{color:var(--sc-muted);font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
  .strip-tile strong{font-size:12.5px;overflow-wrap:anywhere}
  .tone-ok{color:var(--sc-success)}.tone-warn{color:var(--sc-warning)}.tone-bad{color:var(--sc-danger)}
  .tone-muted{color:var(--sc-muted)}.tone-plain{color:var(--sc-text)}
  /* Le cycle : une liste, donc lisible au clavier et par un lecteur d'ecran ;
     la barre de progression est purement decorative. */
  .lifecycle{list-style:none;display:grid;grid-template-columns:repeat(auto-fit,minmax(126px,1fr));gap:9px;margin:12px 0 0;padding:0}
  .lifecycle li{display:grid;gap:4px;justify-items:start;padding:10px 11px;border:1px solid var(--sc-border);border-radius:var(--sc-radius-md);background:var(--sc-surface)}
  .lifecycle strong{font-size:11px}
  .lifecycle .stage-value{color:var(--sc-muted);font-size:10px;overflow-wrap:anywhere}
  .stage-dot{display:grid;place-items:center;width:19px;height:19px;border-radius:50%;font-size:10px;font-weight:800;color:var(--sc-muted);background:var(--sc-surface-soft)}
  .stage-passed .stage-dot{color:var(--sc-success);background:var(--sc-success-bg)}
  .stage-warning .stage-dot{color:var(--sc-warning);background:var(--sc-warning-bg)}
  .stage-failed .stage-dot{color:var(--sc-danger);background:var(--sc-danger-bg)}
  .stage-running .stage-dot{color:var(--sc-primary);background:var(--sc-primary-soft)}
  .stage-passed{border-color:color-mix(in srgb, var(--sc-success) 34%, var(--sc-border))}
  .stage-failed{border-color:color-mix(in srgb, var(--sc-danger) 34%, var(--sc-border))}
  .quick-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:8px;margin-top:12px}
  .quick-action{display:grid;gap:3px;justify-items:start;text-align:left;padding:11px 12px}
  .quick-action span{color:var(--sc-muted);font-size:10px;font-weight:600}
  .rail-card{display:grid;gap:9px}
  .rail-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .rail-head strong{font-size:11.5px}
  .rail-pill{flex:none;padding:3px 8px;border-radius:999px;font-size:8.5px;font-weight:800;letter-spacing:.4px;text-transform:uppercase;color:var(--sc-muted);background:var(--sc-surface-soft);white-space:nowrap}
  .rail-pill.ok{color:var(--sc-success);background:var(--sc-success-bg)}
  .rail-pill.bad{color:var(--sc-danger);background:var(--sc-danger-bg)}
  .rail-facts{display:grid;gap:6px}
  .rail-fact{display:flex;justify-content:space-between;align-items:baseline;gap:9px;min-width:0}
  .rail-fact span{flex:none;color:var(--sc-muted);font-size:10px}
  .rail-fact strong{min-width:0;font-size:10.5px;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .rail-link{width:100%;margin-top:2px;font-size:10px;padding:6px 9px}
  .sc-companion-rail .sc-context-card span,.sc-companion-rail .sc-context-card small{margin-top:0}
  @media(max-width:900px){
    .strip-grid,.lifecycle,.quick-actions{grid-template-columns:1fr}
    .jenkins-fields{grid-template-columns:1fr}
  }`;
}

function renderDeliveryPageHtml(status, nonce = '', theme = 'light', assets = {}) {
  const companionImageUri = typeof assets === 'string' ? assets : assets?.companionImageUri || '';
  const cspSource = typeof assets === 'object' ? assets?.cspSource || '' : '';
  const jenkinsLogo = typeof assets === 'object' ? renderJenkinsLogo(assets) : '';
  const notConfigured = status.state === DELIVERY_STATE.NOT_CONFIGURED;
  // Unconfigured: the form is the page. Configured: the form is rendered but
  // hidden, so « Modifier la configuration » reveals it without a round-trip —
  // and it is safe to ship hidden because the token field is empty either way.
  const body = notConfigured
    ? `${renderJenkinsForm(status, { open: true, jenkinsLogo })}
      <section class="banner muted"><strong>Ce que Security Center attend du pipeline</strong>
        <p>Une fois connecté, Security Center affiche l’état de sécurité du dernier build et vérifie qu’il correspond bien au code ouvert ici.</p>
        <h4>Mise en place</h4>
        <ol>
          <li>Rendez le CLI Security Center disponible sur l’agent Jenkins.</li>
          <li>Ajoutez l’étape Security Center au pipeline.</li>
          <li>Archivez <code>security-center-report.json</code>, y compris quand le gate refuse.</li>
          <li>Laissez le Policy Gate bloquer le déploiement.</li>
        </ol></section>`
    : status.state === DELIVERY_STATE.ERROR
      ? `${renderJenkinsForm(status, { jenkinsLogo })}
        <section class="banner bad"><strong>Jenkins inaccessible</strong><p>${escapeHtml(status.error)}</p>
          <div class="actions"><button data-action="refresh">Réessayer</button>
          <button class="secondary" data-action="revealConfig">Modifier la configuration</button></div></section>`
      // Le bandeau, le cycle et les actions viennent EN TETE : la page devient un
      // tableau de bord de livraison. Les cartes de detail existantes sont toutes
      // conservees en dessous, inchangees — rien n'est retire.
      : `${renderJenkinsForm(status, { jenkinsLogo })}${renderDeliveryStrip(status, jenkinsLogo)}${renderDeliveryLifecycle(status)}${renderDeliveryActions(status)}${renderConnectionCard(status, jenkinsLogo)}${renderWorkspaceCard(status)}${renderBuildCard(status)}${renderCommitCard(status)}${renderCiCard(status)}${renderArtifactsCard(status)}${renderDeploymentCard(status)}`;

  const subtitle = notConfigured
    ? 'État de sécurité de la livraison continue'
    : `${status.job} · ${status.baseUrl}`;

  // La carte Companion Assistant partagee. Elle ne parle de la livraison que
  // lorsque le build a publie un rapport : sans rapport, il n'y a pas de verdict
  // a commenter et la carte ne s'affiche pas.
  const assistantCard = renderAssistantCard(buildAssistantCardModel({
    surface: 'delivery',
    delivery: notConfigured ? null : status
  }), { mascotImageUri: companionImageUri });
  // Le rail n'existe que sur la page configuree : tant que Jenkins n'est pas
  // connecte, le formulaire EST la page et un rail de faits vides n'aiderait pas.
  const contextRail = notConfigured ? '' : renderDeliveryRail(status, assistantCard);

  return renderSecurityCenterShell({
    surface: 'delivery',
    nonce,
    theme,
    title: 'Security Delivery',
    subtitle,
    headerActions: `${notConfigured ? '' : '<button data-action="refresh">Actualiser</button><button class="secondary" data-action="openJenkins">Ouvrir Jenkins</button><button class="secondary" data-action="testConnection">Tester la connexion</button><button class="secondary" data-action="revealConfig">Modifier la configuration</button>'}`,
    content: `
  ${body}
  ${status.fetchedAt ? `<p class="footnote">Lu depuis Jenkins le ${escapeHtml(stamp(status.fetchedAt))}. Security Center ne déclenche ni ne réalise aucun déploiement.</p>` : ''}`,
    contextRail,
    styles: `
  ${assistantCard ? assistantCardCss() : ''}
  /* Toutes les couleurs passent par les tokens --sc-*, que le controleur de
     theme redefinit pour chaque theme. C'est ce qui corrige le defaut de mode
     clair : les controles de formulaire lisaient auparavant --vscode-input-*
     directement, donc ils gardaient le fond sombre de VS Code sur une page
     forcee en clair — des champs presque noirs au milieu d'une page blanche. */
  h3{margin:0;font-size:14px;font-weight:700;color:var(--sc-text)}
  h4{margin:15px 0 5px;font-size:12px;font-weight:700;color:var(--sc-text)}
  .muted,.note{color:var(--sc-muted)}
  .card,.banner{border:1px solid var(--sc-border);border-radius:var(--sc-radius-lg);background:var(--sc-surface);box-shadow:var(--sc-shadow-sm);padding:15px;margin-bottom:13px}
  /* Le liseré de statut reste en tête de carte : la couleur double un libellé
     textuel, elle ne le remplace jamais. */
  .card.ok,.banner.ok{border-top:2px solid var(--sc-success)}
  .card.warn,.banner.warn{border-top:2px solid var(--sc-warning)}
  .card.bad,.banner.bad{border-top:2px solid var(--sc-danger)}
  .card-head{display:flex;justify-content:space-between;gap:12px;align-items:baseline;margin-bottom:9px}
  .provider-title{display:inline-flex;align-items:center;gap:8px;min-width:0}
  .provider-title span{min-width:0;overflow-wrap:anywhere}
  .jenkins-logo{display:grid;place-items:center;flex:none;width:30px;height:30px;border:1px solid var(--sc-border);border-radius:8px;background:var(--sc-surface-soft);overflow:hidden}
  .jenkins-logo img{display:block;max-width:72%;max-height:72%;object-fit:contain}
  .state{flex:none;padding:3px 9px;border-radius:999px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;color:var(--sc-muted);background:var(--sc-surface-soft)}
  .card.ok>.card-head .state{color:var(--sc-success);background:var(--sc-success-bg)}
  .card.warn>.card-head .state{color:var(--sc-warning);background:var(--sc-warning-bg)}
  .card.bad>.card-head .state{color:var(--sc-danger);background:var(--sc-danger-bg)}
  dl{margin:9px 0 0}dl>div{display:grid;grid-template-columns:minmax(120px,190px) minmax(0,1fr);gap:10px;padding:6px 0;border-top:1px solid var(--sc-border)}
  dt{color:var(--sc-muted);font-size:11px}dd{margin:0;min-width:0;overflow-wrap:anywhere;font-size:11px}
  code{font-family:var(--vscode-editor-font-family,monospace);font-size:11px;padding:1px 5px;border-radius:var(--sc-radius-sm);background:var(--sc-surface-soft);overflow-wrap:anywhere}
  ul,ol{margin:8px 0 0;padding-left:18px}li{margin:3px 0;font-size:11px}
  .scanners{list-style:none;padding:0}.scanners li{display:flex;gap:8px;align-items:baseline;padding:4px 0}
  .warn-text{color:var(--sc-warning)}
  button{font:600 11px var(--vscode-font-family);border:1px solid var(--sc-primary);border-radius:var(--sc-radius-md);padding:7px 12px;cursor:pointer;color:var(--sc-primary-text);background:var(--sc-primary)}
  button:hover{background:var(--sc-primary-hover)}
  button.secondary{color:var(--sc-text);border-color:var(--sc-border);background:var(--sc-surface)}
  button.secondary:hover{background:var(--sc-surface-soft)}
  button:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:1px}
  button[disabled]{opacity:.55;cursor:not-allowed}
  .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}
  .jenkins-form[hidden]{display:none}
  /* Grille du formulaire : deux colonnes en large, une seule des que la place
     manque — jamais de defilement horizontal. */
  .jenkins-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0 16px}
  .field{margin-top:13px;display:flex;flex-direction:column;gap:5px;min-width:0}
  .field label{font-size:11px;font-weight:700;color:var(--sc-text)}
  .field input{font:inherit;font-size:11px;min-width:0;padding:8px 10px;border-radius:var(--sc-radius-md);
    color:var(--sc-input-text);background:var(--sc-input-bg);
    border:1px solid var(--sc-input-border)}
  .field input:hover{border-color:var(--sc-border-strong)}
  .field input:focus{outline:none;border-color:var(--sc-primary);
    box-shadow:0 0 0 3px color-mix(in srgb, var(--sc-primary) 22%, transparent)}
  .field input::placeholder{color:var(--sc-input-placeholder)}
  .field small{font-size:10px;color:var(--sc-muted)}
  .token-set{color:var(--sc-success)}
  .test-result{margin:13px 0 0;font-size:11px;color:var(--sc-muted)}
  .test-result.ok{color:var(--sc-success)}
  .test-result.bad{color:var(--sc-danger)}
  .footnote{font-size:10.5px;margin-top:16px;color:var(--sc-muted)}
  ${deliveryDashboardCss()}
  @media(max-width:640px){dl>div{grid-template-columns:1fr}}`,
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();
  const form=document.getElementById('jenkins-form');
  const field=id=>{const el=document.getElementById(id);return el?el.value.trim():'';};
  // The page reads its own inputs and hands them over. It does not normalise the
  // URL, does not check the job, and does not call Jenkins: the extension does
  // all three, so there is exactly one place where those rules live.
  const config=()=>({url:field('jenkins-url'),job:field('jenkins-job'),user:field('jenkins-user'),token:field('jenkins-token')});
  // La carte d'assistant apporte son propre relais : l'exclure des deux boucles
  // ci-dessous evite qu'un meme clic parte deux fois.
  document.querySelectorAll('[data-command]:not(.sc-nav-item):not(.sc-assistant [data-command])').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  document.querySelectorAll('[data-action]:not(.sc-assistant [data-action])').forEach(b=>b.onclick=()=>{
    const action=b.dataset.action;
    if(action==='revealConfig'){if(form){form.hidden=false;form.scrollIntoView({block:'nearest'});const url=document.getElementById('jenkins-url');if(url)url.focus();}return;}
    if(action==='saveConfig'||action==='testConfig'){vscode.postMessage({type:'action',action,config:config()});return;}
    vscode.postMessage({type:'action',action});
  });
  ${assistantCard ? assistantCardScript() : ''}`,
    csp: `default-src 'none'; img-src ${cspSource || "'self'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`
  });
}

module.exports = { renderDeliveryPageHtml, STATE_LABELS, COMMIT_LABELS, escapeHtml };
