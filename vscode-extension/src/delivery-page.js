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
function renderConnectionCard(status) {
  const test = status.connection;
  const state = test?.state || (status.state === DELIVERY_STATE.ERROR ? CONNECTION_STATE.UNREACHABLE : CONNECTION_STATE.CONNECTED);
  return `<article class="card ${state === CONNECTION_STATE.CONNECTED ? 'ok' : 'bad'}">
      <div class="card-head"><h3>Connexion Jenkins</h3><span class="state">${escapeHtml(CONNECTION_LABELS[state] || state)}</span></div>
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
function renderJenkinsForm(status, { open = false } = {}) {
  const test = status.connection;
  const stateClass = !test ? '' : test.state === CONNECTION_STATE.CONNECTED ? 'ok' : 'bad';
  return `<section class="card jenkins-form ${stateClass}" id="jenkins-form"${open ? '' : ' hidden'}>
      <div class="card-head"><h3>Connecter Jenkins</h3>
        ${test ? `<span class="state">${escapeHtml(CONNECTION_LABELS[test.state] || test.state)}</span>` : ''}</div>
      <p class="muted">Connectez votre serveur Jenkins existant. Security Center n’installe jamais Jenkins.</p>
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
      ${test?.message ? `<p class="test-result ${stateClass}">${escapeHtml(test.message)}</p>` : ''}
      <div class="actions">
        <button data-action="saveConfig">Enregistrer</button>
        <button class="secondary" data-action="testConfig">Tester la connexion</button>
        <button class="secondary" data-action="openJenkinsfile">Voir le Jenkinsfile d’exemple</button>
      </div>
    </section>`;
}

function renderDeliveryPageHtml(status, nonce = '', theme = 'light') {
  const notConfigured = status.state === DELIVERY_STATE.NOT_CONFIGURED;
  // Unconfigured: the form is the page. Configured: the form is rendered but
  // hidden, so « Modifier la configuration » reveals it without a round-trip —
  // and it is safe to ship hidden because the token field is empty either way.
  const body = notConfigured
    ? `${renderJenkinsForm(status, { open: true })}
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
      ? `${renderJenkinsForm(status)}
        <section class="banner bad"><strong>Jenkins inaccessible</strong><p>${escapeHtml(status.error)}</p>
          <div class="actions"><button data-action="refresh">Réessayer</button>
          <button class="secondary" data-action="revealConfig">Modifier la configuration</button></div></section>`
      : `${renderJenkinsForm(status)}${renderConnectionCard(status)}${renderWorkspaceCard(status)}${renderBuildCard(status)}${renderCommitCard(status)}${renderCiCard(status)}${renderArtifactsCard(status)}${renderDeploymentCard(status)}`;

  return `<!doctype html><html data-theme="${escapeHtml(theme)}"><head><meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width"><style>
  :root{color-scheme:light dark}*{box-sizing:border-box}
  body{margin:0;padding:24px;color:var(--vscode-foreground);background:var(--vscode-editor-background);font-family:var(--vscode-font-family);font-size:var(--vscode-font-size)}
  main{max-width:900px;margin:auto}h1{margin:0 0 4px;font-size:22px}h3{margin:0;font-size:15px}
  .muted,.note{color:var(--vscode-descriptionForeground)}
  header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;padding-bottom:14px;margin-bottom:16px;border-bottom:1px solid var(--vscode-panel-border)}
  .card,.banner{border:1px solid var(--vscode-panel-border);border-left:3px solid var(--vscode-descriptionForeground);border-radius:6px;padding:14px;margin-bottom:12px}
  .card.ok,.banner.ok{border-left-color:var(--vscode-testing-iconPassed,#3fa66a)}
  .card.warn,.banner.warn{border-left-color:var(--vscode-editorWarning-foreground,#d0a215)}
  .card.bad,.banner.bad{border-left-color:var(--vscode-editorError-foreground,#e05252)}
  .card-head{display:flex;justify-content:space-between;gap:12px;align-items:baseline;margin-bottom:8px}
  .state{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--vscode-descriptionForeground)}
  dl{margin:8px 0 0}dl>div{display:grid;grid-template-columns:190px 1fr;gap:8px;padding:5px 0;border-top:1px solid var(--vscode-panel-border)}
  dt{color:var(--vscode-descriptionForeground)}dd{margin:0}
  code{font-family:var(--vscode-editor-font-family,monospace);font-size:12px}
  ul,ol{margin:8px 0 0;padding-left:18px}li{margin:3px 0}
  h4{margin:14px 0 4px;font-size:13px}
  .scanners{list-style:none;padding:0}.scanners li{display:flex;gap:8px;align-items:baseline;padding:3px 0}
  .warn-text{color:var(--vscode-editorWarning-foreground,#d0a215)}
  button{font:inherit;border:0;border-radius:3px;padding:6px 11px;cursor:pointer;color:var(--vscode-button-foreground);background:var(--vscode-button-background)}
  button.secondary{color:var(--vscode-button-secondaryForeground);background:var(--vscode-button-secondaryBackground)}
  .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
  .jenkins-form[hidden]{display:none}
  .field{margin-top:12px;display:flex;flex-direction:column;gap:4px}
  .field label{font-size:12px;font-weight:600}
  .field input{font:inherit;padding:6px 8px;border-radius:3px;
    color:var(--vscode-input-foreground);background:var(--vscode-input-background);
    border:1px solid var(--vscode-input-border,var(--vscode-panel-border))}
  .field input:focus{outline:1px solid var(--vscode-focusBorder);outline-offset:-1px}
  .field input::placeholder{color:var(--vscode-input-placeholderForeground)}
  .field small{font-size:11px}
  .token-set{color:var(--vscode-testing-iconPassed,#3fa66a)}
  .test-result{margin:12px 0 0;font-size:12px;color:var(--vscode-descriptionForeground)}
  .test-result.ok{color:var(--vscode-testing-iconPassed,#3fa66a)}
  .test-result.bad{color:var(--vscode-editorError-foreground,#e05252)}
  .footnote{font-size:12px;margin-top:16px;color:var(--vscode-descriptionForeground)}
  @media(max-width:640px){body{padding:14px}dl>div{grid-template-columns:1fr}}
  </style></head><body><main>
  <header><div><h1>Security Delivery</h1>
    <p class="muted">${notConfigured ? 'État de sécurité de la livraison continue' : `${escapeHtml(status.job)} · ${escapeHtml(status.baseUrl)}`}</p></div>
    <div class="actions">
      <button class="secondary" data-command="securityCenter.openDashboard">← Dashboard</button>
      ${notConfigured ? '' : '<button data-action="refresh">Actualiser</button><button class="secondary" data-action="openJenkins">Ouvrir Jenkins</button><button class="secondary" data-action="testConnection">Tester la connexion</button><button class="secondary" data-action="revealConfig">Modifier la configuration</button>'}
    </div>
  </header>
  ${body}
  ${status.fetchedAt ? `<p class="footnote">Lu depuis Jenkins le ${escapeHtml(stamp(status.fetchedAt))}. Security Center ne déclenche ni ne réalise aucun déploiement.</p>` : ''}
  </main><script nonce="${nonce}">const vscode=acquireVsCodeApi();
  const form=document.getElementById('jenkins-form');
  const field=id=>{const el=document.getElementById(id);return el?el.value.trim():'';};
  // The page reads its own inputs and hands them over. It does not normalise the
  // URL, does not check the job, and does not call Jenkins: the extension does
  // all three, so there is exactly one place where those rules live.
  const config=()=>({url:field('jenkins-url'),job:field('jenkins-job'),user:field('jenkins-user'),token:field('jenkins-token')});
  document.querySelectorAll('[data-command]').forEach(b=>b.onclick=()=>vscode.postMessage({type:'command',command:b.dataset.command}));
  document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{
    const action=b.dataset.action;
    if(action==='revealConfig'){if(form){form.hidden=false;form.scrollIntoView({block:'nearest'});const url=document.getElementById('jenkins-url');if(url)url.focus();}return;}
    if(action==='saveConfig'||action==='testConfig'){vscode.postMessage({type:'action',action,config:config()});return;}
    vscode.postMessage({type:'action',action});
  });
  </script></body></html>`;
}

module.exports = { renderDeliveryPageHtml, STATE_LABELS, COMMIT_LABELS, escapeHtml };
