const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  buildAssistantCardModel, renderAssistantCard, assistantCardCss, assistantCardScript,
  assistantMessageFor, assistantMascotPresenceState, securityTipFor, resolveAction,
  COMMAND_ACTIONS, POST_ACTIONS, ASSISTANT_POST_TYPES, ASSISTANT_INTENTS,
  SENSITIVE_FINDING_FIELDS, MAX_ACTIONS
} = require('../src/companion-assistant-card');
const { VERIFICATION_STATE } = require('../src/fix-verification');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderFindingDetailsHtml } = require('../src/finding-details');

const srcFile = (...parts) => fs.readFileSync(path.join(__dirname, '..', 'src', ...parts), 'utf8');
const cardSource = () => srcFile('companion-assistant-card.js');
const extensionSource = () => srcFile('extension.js');

/** Un finding minimal, sans etat de verification ni atteignabilite. */
const finding = (extra = {}) => ({
  id: 'f1', tool: 'Semgrep', ruleId: 'sql-string-concatenation', title: 'Injection SQL',
  rawSeverity: 'CRITICAL', severity: 'error', cwe: 'CWE-89', category: 'security',
  file: 'routes/search.js', startLine: 12, ...extra
});

// =========================================================== rendu conditionnel

test('sans aucun fait reel, la carte ne rend rien', () => {
  // Aucune surface, aucun finding, aucune liste, aucun scan : il n'y a rien a dire.
  assert.equal(buildAssistantCardModel({}), null);
  assert.equal(renderAssistantCard(null), '');
  // Un dashboard sans finding ET sans scan termine ne produit pas de carte non plus.
  assert.equal(buildAssistantCardModel({ surface: 'full', findings: [] }), null);
  // Une page pipeline sans verdict de politique connu reste muette.
  assert.equal(buildAssistantCardModel({ surface: 'pipeline', pipeline: {} }), null);
  // Une page scans sans etat de scan reste muette.
  assert.equal(buildAssistantCardModel({ surface: 'scans', scan: null }), null);
  // Un finding seul, sans etat, sans jumeau et sans atteignabilite : rien non plus.
  assert.equal(buildAssistantCardModel({ surface: 'finding-details', finding: finding(), findings: [] }), null);
});

test('la carte desactivee ne rend rien meme quand les faits existent', () => {
  const context = { surface: 'full', findings: [finding()], enabled: false };
  assert.equal(buildAssistantCardModel(context), null);
});

test('un modele absent ne laisse ni cadre vide ni squelette', () => {
  assert.equal(renderAssistantCard(buildAssistantCardModel({})), '');
});

// ================================================ les messages viennent du modele

test('l etat de verification est repris du cycle de vie reel, pas reinvente', () => {
  const applied = assistantMessageFor({ finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED }) });
  assert.equal(applied.source, 'fix-verification');
  assert.match(applied.text, /appliquée et attend sa vérification/);

  const still = assistantMessageFor({ finding: finding({ verification: { state: VERIFICATION_STATE.STILL_PRESENT } }) });
  assert.equal(still.source, 'fix-verification');
  assert.match(still.text, /toujours présente après vérification/);

  const regressed = assistantMessageFor({ finding: finding({ verification: { state: VERIFICATION_STATE.REGRESSED } }) });
  assert.match(regressed.text, /réapparue/);
  assert.equal(regressed.tone, 'alert');
});

test('« findings similaires » compte la liste reelle, pas une estimation', () => {
  const current = finding();
  const list = [
    current,
    finding({ id: 'f2', file: 'routes/login.js' }),
    finding({ id: 'f3', file: 'routes/admin.js' }),
    // Regle differente : ne doit pas etre comptee.
    finding({ id: 'f4', ruleId: 'unsafe-eval', file: 'routes/eval.js' }),
    // Deja validee : sortie du cycle, donc pas « similaire et active ».
    finding({ id: 'f5', file: 'routes/old.js', triageStatus: 'validated' })
  ];
  const message = assistantMessageFor({ finding: current, findings: list });
  assert.equal(message.source, 'findings');
  assert.equal(message.count, 2);
  assert.match(message.text, /2 findings similaires/);
});

test('l atteignabilite n est affirmee que si le pipeline l a calculee', () => {
  // Statut absent : aucune phrase sur l'atteignabilite.
  const withoutStatus = assistantMessageFor({ finding: finding({ reachability: {} }), findings: [] });
  assert.equal(withoutStatus, null);

  const reachable = assistantMessageFor({ finding: finding({ reachability: { status: 'REACHABLE' } }), findings: [] });
  assert.equal(reachable.source, 'intelligence');
  assert.match(reachable.text, /atteignable/);

  const notReachable = assistantMessageFor({ finding: finding({ reachability: { status: 'NOT_REACHABLE' } }), findings: [] });
  assert.equal(notReachable.tone, 'good');
});

test('la densite du fichier vient du comptage de la liste fournie', () => {
  const current = finding({ ruleId: '' });
  const list = [current, finding({ id: 'f2', ruleId: '', file: 'routes/search.js' })];
  const message = assistantMessageFor({ finding: current, findings: list });
  assert.equal(message.source, 'findings');
  assert.match(message.text, /Ce fichier contient 2 findings actifs/);
});

test('Live Security reprend le compte du modele companion partage', () => {
  const message = assistantMessageFor({ surface: 'live', companion: { liveFindingCount: 3 } });
  assert.equal(message.source, 'companion');
  assert.match(message.text, /3 avertissements Live/);
  // Un modele companion sans compte ni message court ne produit rien.
  assert.equal(assistantMessageFor({ surface: 'live', companion: { liveFindingCount: 0 } }), null);
});

test('le pipeline reprend le verdict de la porte de politique tel quel', () => {
  // Sur le pipeline, le gate juge le SCAN : parler de « livraison » attribuerait
  // le verdict à un build Jenkins, qui est une autre identité de scan.
  assert.match(assistantMessageFor({ surface: 'pipeline', pipeline: { policyStatus: 'BLOCK' } }).text, /bloque ce scan/);
  assert.ok(!/livraison/.test(assistantMessageFor({ surface: 'pipeline', pipeline: { policyStatus: 'WARN' } }).text));
  assert.equal(assistantMessageFor({ surface: 'pipeline', pipeline: { policyStatus: 'PASS' } }).tone, 'good');
  assert.equal(assistantMessageFor({ surface: 'pipeline', pipeline: { policyStatus: 'BLOCK' } }).source, 'pipeline');
});

test('les scans reprennent l avancement reel des scanners', () => {
  const running = assistantMessageFor({ surface: 'scans', scan: { status: 'running', completed: 2, total: 5 } });
  assert.equal(running.source, 'scan');
  assert.match(running.text, /2\/5 scanners terminés/);
  assert.match(assistantMessageFor({ surface: 'scans', scan: { status: 'failed' } }).text, /échec/);
});

test('le dashboard resume la liste qu il affiche deja', () => {
  const list = [finding(), finding({ id: 'f2', rawSeverity: 'HIGH' }), finding({ id: 'f3', rawSeverity: 'HIGH', triageStatus: 'validated' })];
  const message = assistantMessageFor({ surface: 'full', findings: list });
  assert.equal(message.source, 'findings');
  assert.equal(message.count, 2);
  assert.match(message.text, /2 alertes actives/);
  assert.match(message.text, /1 Critical · 1 High/);
});

test('la provenance du message est exposee dans le DOM', () => {
  const html = renderAssistantCard(buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.STILL_PRESENT })
  }));
  assert.match(html, /data-assistant-source="fix-verification"/);
});

test('la carte distingue Live, run courant et posture workspace dans ses faits', () => {
  const model = buildAssistantCardModel({
    surface: 'full',
    companion: {
      state: 'findings',
      mascotState: 'warning',
      currentFile: 'C:/repo/routes/search.js',
      liveFindingCount: 2,
      liveHighestSeverity: 'HIGH'
    },
    findings: [finding(), finding({ id: 'f2', rawSeverity: 'HIGH' })],
    scan: { status: 'running', completed: 1, total: 4 },
    scanners: [{ tool: 'Semgrep', status: 'completed' }, { tool: 'Gitleaks', status: 'pending' }],
    posture: { label: 'Current run', findingCount: 2, scope: 'current-run' }
  });
  assert.equal(model.status.label, 'Attention');
  assert.equal(model.contextFacts.length, 3, 'le hero reste compact');
  assert.deepEqual(model.contextFacts.map((fact) => fact.scope), ['live-file', 'live-file', 'live-file']);
  assert.match(model.heroMessage.text, /2 security issues in search\.js/);
  const html = renderAssistantCard(model);
  assert.match(html, /data-assistant-status-scope="live"/);
  assert.match(html, /data-assistant-fact-scope="live-file"[\s\S]*<strong[^>]*>2<\/strong>[\s\S]*Live issues/);
  assert.match(html, /data-assistant-fact-scope="live-file"[\s\S]*search\.js[\s\S]*Current file/);
  assert.doesNotMatch(html, /Pending scanners/);
  assert.equal((html.match(/<img class="mascot/g) || []).length, 1, 'une seule mascotte dans hero + panneau');
});

test('le hero priorise le fichier courant et ne transforme pas la posture workspace en titre sain', () => {
  const healthy = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 },
    findings: Array.from({ length: 23 }, (_, index) => finding({ id: `f${index}`, file: `src/${index}.js` })),
    posture: { label: 'Workspace posture', findingCount: 23, scope: 'workspace-posture' }
  });
  const html = renderAssistantCard(healthy);
  assert.match(healthy.heroMessage.text, /I'm watching users\.yml\. No live issues/);
  assert.doesNotMatch(html, /23 alertes actives|23 alerts|Workspace posture[\s\S]*<strong[^>]*>23<\/strong>/);

  const changed = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/admin.yml', liveFindingCount: 0 },
    findings: [],
    posture: { label: 'Workspace posture', findingCount: 0, scope: 'workspace-posture' }
  });
  assert.match(changed.heroMessage.text, /I'm watching admin\.yml/);
});

test('la degradation scanner apparait seulement quand elle est degradee', () => {
  const pending = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 },
    scanners: [{ tool: 'Gitleaks', status: 'pending' }]
  });
  assert.doesNotMatch(renderAssistantCard(pending), /Scanner health|Pending scanners|not run yet/);

  const failed = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 },
    scanners: [{ tool: 'SonarQube', status: 'failed' }]
  });
  assert.match(renderAssistantCard(failed), /data-assistant-fact-scope="scanner-state"/);
});

test('la mascotte expose une seule presence animee derivee de faits reels', () => {
  const high = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'findings', mascotState: 'warning', currentFile: 'src/auth.js', liveFindingCount: 1, liveHighestSeverity: 'HIGH' }
  });
  assert.equal(high.mascotPresenceState, 'warning');
  assert.match(renderAssistantCard(high), /class="sc-assistant-mascot companion-state-warning"/);
  assert.equal((renderAssistantCard(high).match(/<img class="mascot/g) || []).length, 1);

  const scanning = buildAssistantCardModel({
    surface: 'scans',
    scan: { status: 'running', completed: 1, total: 4 }
  });
  assert.equal(scanning.mascotPresenceState, 'analyzing');
  assert.match(renderAssistantCard(scanning), /data-companion-visual-state="analyzing"/);

  const clean = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 }
  });
  assert.equal(clean.mascotPresenceState, 'healthy');
  assert.match(renderAssistantCard(clean), /companion-state-healthy/);

  const neutral = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'idle', mascotState: 'idle', shortMessage: 'Security Center is ready.' }
  });
  assert.equal(neutral.mascotPresenceState, 'idle');
  assert.match(renderAssistantCard(neutral), /companion-state-idle/);
});

test('la presence warning ne vient pas d une animation inventee', () => {
  assert.equal(assistantMascotPresenceState({
    companion: { state: 'findings', liveFindingCount: 1, liveHighestSeverity: 'LOW' }
  }), 'idle');
  assert.equal(assistantMascotPresenceState({
    companion: { state: 'clean', liveFindingCount: 0 },
    scanners: [{ tool: 'Gitleaks', status: 'pending' }]
  }), 'healthy');
  assert.equal(assistantMascotPresenceState({
    companion: { state: 'clean', liveFindingCount: 0 },
    scanners: [{ tool: 'SonarQube', status: 'failed' }]
  }), 'warning');
});

// ================================================== les commandes sont reutilisees

test('chaque action cite une commande deja contribuee par l extension', () => {
  // `contributes.commands` est le registre faisant foi : certaines commandes de
  // page sont enregistrees dans une boucle, donc chercher `registerCommand('X'`
  // dans la source manquerait des commandes pourtant bien existantes.
  const declared = new Set((require('../package.json').contributes.commands || []).map((entry) => entry.command));
  for (const [id, action] of Object.entries(COMMAND_ACTIONS)) {
    assert.ok(declared.has(action.command), `l'action ${id} cite ${action.command}, qui n'existe pas`);
  }
  // Et aucune n'est inventee par la carte : l'extension les cite deja ailleurs.
  const source = extensionSource();
  for (const action of Object.values(COMMAND_ACTIONS)) {
    assert.ok(source.includes(action.command), `${action.command} n'apparait nulle part dans extension.js`);
  }
});

test('chaque message poste par la carte est un type deja traite par sa page hote', () => {
  const source = extensionSource();
  const handlers = {
    generateAiFix: "message?.type !== 'generateAiFix'",
    verifyFix: "message?.type === 'verifyFix'",
    findingCode: "message?.type === 'findingCode'"
  };
  for (const type of ASSISTANT_POST_TYPES) {
    assert.ok(source.includes(handlers[type]), `aucun handler preexistant pour le message ${type}`);
  }
  // Le catalogue n'emet rien d'autre que ces trois types.
  for (const [id, action] of Object.entries(POST_ACTIONS)) {
    assert.ok(ASSISTANT_POST_TYPES.includes(action.post.type), `${id} emet un type hors catalogue`);
  }
});

test('la carte n enregistre aucune commande et ne cree aucun handler', () => {
  const source = cardSource();
  assert.doesNotMatch(source, /registerCommand/);
  assert.doesNotMatch(source, /executeCommand/);
  assert.doesNotMatch(source, /onDidReceiveMessage/);
});

test('une action n est proposee que sur une surface qui sait la recevoir', () => {
  // `generateAiFix` n'est traite que par le panneau des details du finding.
  assert.ok(resolveAction('explain', { surface: 'finding-details' }));
  assert.equal(resolveAction('explain', { surface: 'full' }), null);
  // `findingCode` exige un indice : sans lui, pas de bouton mort.
  assert.equal(resolveAction('open-file', { surface: 'full' }), null);
  assert.ok(resolveAction('open-file', { surface: 'full', findingIndex: 3 }));
});

test('une action ne renvoie jamais vers la page deja ouverte', () => {
  assert.equal(resolveAction('open-live', { surface: 'live' }), null);
  assert.equal(resolveAction('open-pipeline', { surface: 'pipeline' }), null);
  assert.equal(resolveAction('show-similar', { surface: 'findings' }), null);
  // Ailleurs, la meme action reste disponible.
  assert.ok(resolveAction('open-live', { surface: 'full' }));
});

test('les actions rendues portent une commande ou un message, jamais autre chose', () => {
  const html = renderAssistantCard(buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED })
  }));
  const buttons = html.match(/<button[^>]*class="sc-assistant-action[^"]*"[^>]*>/g) || [];
  assert.ok(buttons.length >= 2);
  for (const button of buttons) {
    if (button.includes('sc-assistant-dismiss')) continue;
    assert.ok(
      /data-command="securityCenter\./.test(button) || /data-assistant-post=/.test(button),
      `bouton sans destination reelle : ${button}`
    );
  }
});

test('la carte reste compacte : deux actions au plus, plus « Pas maintenant »', () => {
  const model = buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED })
  });
  assert.ok(model.actions.length <= MAX_ACTIONS);
  const html = renderAssistantCard(model);
  assert.equal((html.match(/sc-assistant-dismiss/g) || []).length, 1);
});

test('« Pas maintenant » ecarte la suggestion sans rien executer ni memoriser', () => {
  const html = renderAssistantCard(buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED })
  }));
  const dismiss = html.match(/<button[^>]*sc-assistant-dismiss[^>]*>/)[0];
  assert.doesNotMatch(dismiss, /data-command/);
  assert.doesNotMatch(dismiss, /data-assistant-post/);
  // Cote script : masquage local, aucun postMessage, aucune persistance.
  const script = assistantCardScript();
  assert.match(script, /sc-assistant-dismiss'\)\) \{/);
  assert.match(script, /panel\.hidden = true;/);
  assert.doesNotMatch(script, /setState|localStorage|sessionStorage/);
});

// ===================================================== aucun second fournisseur IA

test('la carte ne cree ni fournisseur IA ni second backend de conversation', () => {
  const source = cardSource();
  // Aucun appel reseau, aucun client, aucun modele : la carte ne parle a rien.
  assert.doesNotMatch(source, /fetch\(|http\.request|https\.request|axios|WebSocket|EventSource/);
  assert.doesNotMatch(source, /localhost:11434|\/api\/generate|\/api\/chat|ollama-provider|provider-registry/i);
  // Aucun etat de conversation : ni historique, ni tour de parole, ni session.
  assert.doesNotMatch(source, /conversationHistory|chatHistory|messages\.push/);
});

test('le lanceur du bas est une liste fermee d intentions, pas un champ libre', () => {
  const html = renderAssistantCard(buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED })
  }));
  // Une liste de choix, jamais une saisie libre.
  assert.match(html, /<select id="sc-assistant-intent"/);
  assert.doesNotMatch(html, /<input[^>]*type="text"/);
  assert.doesNotMatch(html, /<textarea/);
  // Chaque intention proposee resout vers une action du catalogue.
  const model = buildAssistantCardModel({ surface: 'finding-details', finding: finding({ triageStatus: VERIFICATION_STATE.FIX_APPLIED }) });
  for (const intent of model.intents) {
    assert.ok(intent.action.command || intent.action.post, `intention ${intent.id} sans action reelle`);
  }
  // Le catalogue lui-meme ne contient que les intentions autorisees.
  assert.deepEqual(
    ASSISTANT_INTENTS.map((intent) => intent.id).sort(),
    ['explain-finding', 'open-related-file', 'show-evidence', 'similar-findings', 'suggest-fix', 'verify-fix', 'verify-fix-any'].sort()
  );
});

test('le script du lanceur refuse tout type de message hors catalogue', () => {
  const script = assistantCardScript();
  assert.match(script, /ALLOWED_POST_TYPES\.indexOf\(payload\.type\) === -1\) return;/);
  for (const type of ASSISTANT_POST_TYPES) assert.ok(script.includes(type));
});

// ============================================================= aucun secret rendu

test('aucun champ sensible d un finding n est lu par la carte', () => {
  const source = cardSource();
  for (const field of SENSITIVE_FINDING_FIELDS) {
    assert.doesNotMatch(
      source,
      new RegExp(`finding\\.${field}\\b|finding\\?\\.${field}\\b`),
      `la carte lit finding.${field}, qui peut porter une valeur detectee`
    );
  }
});

test('un finding porteur d un secret ne fait fuir ni la valeur ni la preuve', () => {
  const secret = 'ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234';
  const leaky = finding({
    id: 's1', tool: 'Gitleaks', ruleId: 'github-pat', cwe: 'CWE-798', category: 'secret',
    file: 'config/keys.env', title: `Secret ${secret}`, evidence: secret, secret,
    match: `token = "${secret}"`, originalText: `const token = "${secret}"`,
    description: `Trouve ${secret}`, solution: `Retirer ${secret}`, technicalDetails: secret,
    autofix: `token = process.env.TOKEN // etait ${secret}`,
    fingerprint: secret, commit: secret,
    triageStatus: VERIFICATION_STATE.FIX_APPLIED
  });
  const html = renderAssistantCard(buildAssistantCardModel({ surface: 'finding-details', finding: leaky }));
  assert.ok(html, 'la carte doit bien se rendre pour que le test ait un sens');
  assert.ok(!html.includes(secret), 'la valeur du secret est apparue dans la carte');
  assert.ok(!html.includes('token = '), 'un extrait de source est apparu dans la carte');
  // Le conseil, lui, est bien la : il vient de la table locale, pas du scanner.
  assert.match(html, /coffre, jamais dans le dépôt/);
});

test('le chemin complet du fichier ne sort pas du modele', () => {
  const model = buildAssistantCardModel({
    surface: 'finding-details',
    finding: finding({ file: 'C:/Users/dev/projet/routes/search.js', triageStatus: VERIFICATION_STATE.FIX_APPLIED })
  });
  assert.equal(model.file, 'search.js');
});

// ================================================================ conseil local

test('le conseil de securite vient d une table locale indexee par CWE', () => {
  assert.match(securityTipFor(finding({ cwe: 'CWE-89' })).text, /requêtes paramétrées/);
  assert.equal(securityTipFor(finding({ cwe: 'CWE-89' })).source, 'CWE-89');
  assert.match(securityTipFor(finding({ cwe: 'CWE-79, CWE-80' })).text, /Échappez les données/);
  // Repli sur la categorie quand aucun CWE ne correspond.
  assert.equal(securityTipFor(finding({ cwe: 'CWE-99999', category: 'secret' })).source, 'secret');
  // Rien de connu : pas de conseil generique deguise en conseil contextuel.
  assert.equal(securityTipFor(finding({ cwe: '', category: 'inconnue' })), null);
  assert.equal(securityTipFor(null), null);
});

test('le conseil n est jamais envoye a un service : c est une table en clair', () => {
  const source = cardSource();
  const table = source.slice(source.indexOf('const TIPS_BY_CWE'), source.indexOf('const TIPS_BY_CATEGORY'));
  assert.doesNotMatch(table, /\$\{/, 'un conseil interpole une donnee au lieu d etre litteral');
});

// ============================================================ tokens et themes

test('la feuille de style ne passe que par les tokens --sc-* et vscode', () => {
  const css = assistantCardCss();
  const scoped = css.slice(css.indexOf('.sc-assistant {'));
  // Aucune couleur litterale dans les regles de la carte : ni hex, ni rgb, ni hsl.
  const literals = scoped.match(/:\s*(#[0-9a-f]{3,8}|rgba?\(|hsla?\()/gi) || [];
  // Seule tolerance : le repli blanc du texte de bouton, deja utilise ailleurs.
  assert.deepEqual(literals.filter((value) => !/#fff/i.test(value)), []);
  for (const token of ['--sc-border', '--sc-surface', '--sc-text', '--sc-muted', '--sc-primary', '--sc-radius-lg', '--sc-shadow-sm']) {
    assert.ok(scoped.includes(`var(${token}`), `le token ${token} n'est pas utilise`);
  }
});

test('la carte suit les deux themes sans regle propre au theme sombre', () => {
  const css = assistantCardCss();
  const scoped = css.slice(css.indexOf('.sc-assistant {'));
  // Les tokens changent de valeur selon `body.theme-*` : la carte n'a donc
  // aucune raison de dupliquer une regle par theme.
  assert.doesNotMatch(scoped, /body\.theme-dark\s+\.sc-assistant/);
  assert.doesNotMatch(scoped, /body\.theme-light\s+\.sc-assistant/);
});

test('la severite n est jamais portee par la couleur seule', () => {
  const css = assistantCardCss();
  // La bordure teinte la bulle, et la posture de la mascotte porte la meme
  // information : deux canaux, pas un.
  assert.match(css, /\.sc-assistant-bubble\.sc-tone-alert \{ border-color: var\(--sc-critical\)/);
  const model = buildAssistantCardModel({
    surface: 'finding-details', finding: finding({ verification: { state: VERIFICATION_STATE.STILL_PRESENT } })
  });
  assert.equal(model.message.tone, 'alert');
  assert.equal(model.mascotState, 'warning');
});

test('la carte est responsive et respecte le mouvement reduit', () => {
  const css = assistantCardCss();
  assert.match(css, /@media \(max-width: 1320px\)/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(css, /minmax\(0, 1fr\)/);
  assert.match(css, /\.sc-assistant-mascot, \.sc-assistant-mascot::before, \.sc-assistant-mascot::after \{ animation: none !important/);
});

test('la carte utilise un URI image local quand la webview le fournit', () => {
  const model = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 }
  });
  const html = renderAssistantCard(model, { mascotImageUri: 'vscode-webview-resource:/media/live/security-companion.png' });
  assert.match(html, /<img class="mascot mascot-success mascot-regular"/);
  assert.match(html, /src="vscode-webview-resource:\/media\/live\/security-companion\.png"/);
  assert.match(html, /data-companion-asset="local"/);
  assert.doesNotMatch(html, /<svg class="mascot|https?:\/\//);
});

test('le panneau Companion Assistant se complete sans ajouter une seconde mascotte', () => {
  const model = buildAssistantCardModel({
    surface: 'full',
    companion: { state: 'clean', mascotState: 'success', currentFile: 'src/users.yml', liveFindingCount: 0 }
  });
  const html = renderAssistantCard(model, { mascotImageUri: 'vscode-webview-resource:/media/live/security-companion.png' });
  assert.match(html, /class="sc-assistant-panel"/);
  assert.match(html, /No immediate action is required\./);
  assert.match(html, /Security Tip/);
  assert.match(html, /Keep dependencies patched/);
  assert.match(html, /<select id="sc-assistant-intent"/);
  assert.equal((html.match(/<img class="mascot/g) || []).length, 1, 'le panneau ne rend pas de seconde mascotte');
});

test('le panneau garde le message contextuel et le conseil sûr d’un finding', () => {
  const current = finding({ cwe: 'CWE-89', triageStatus: VERIFICATION_STATE.FIX_APPLIED });
  const model = buildAssistantCardModel({
    surface: 'finding-details',
    finding: current,
    findings: [current]
  });
  const html = renderAssistantCard(model);
  assert.match(html, /data-assistant-source="fix-verification"/);
  assert.match(html, /Security Tip/);
  assert.match(html, /requêtes paramétrées/);
  assert.doesNotMatch(html, /Potential SQL injection|token = |ghp_/);
});

test('la mascotte utilise des animations CSS legeres sans timer ni dependance externe', () => {
  const css = assistantCardCss();
  assert.match(css, /@keyframes sc-companion-float/);
  assert.match(css, /@keyframes sc-companion-scan-ring/);
  assert.match(css, /companion-state-analyzing::after/);
  assert.match(css, /transform:translateY\(-3px\)/);
  const source = cardSource();
  assert.doesNotMatch(source, /setInterval|setTimeout|requestAnimationFrame/);
  assert.doesNotMatch(source, /gsap|lottie|animejs|three|canvas|webgl/i);
});

// ================================================= integration dans les surfaces

test('le dashboard place la carte en tete de son rail de contexte', () => {
  const html = renderDashboardHtml(
    buildDashboardModel(
      [finding(), finding({ id: 'f2', rawSeverity: 'HIGH', file: 'routes/login.js' })],
      [{ tool: 'Semgrep', status: 'completed' }],
      { scanStatus: 'completed', workspace: 'juice-shop', backendStatus: 'online' }
    ),
    'n', 'full', 'light', {}
  );
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  // Dans le rail, et avant les cartes existantes qui y vivaient deja.
  const rail = html.slice(html.indexOf('sc-companion-rail'));
  assert.ok(rail.indexOf('sc-assistant') < rail.indexOf('Actions rapides'));
  // Le relais global du dashboard exclut la carte, qui apporte le sien.
  assert.match(html, /\[data-command\]:not\(\.sc-assistant \[data-command\]\)/);
});

test('la page des details du finding porte la carte dans son rail', () => {
  const current = finding({ triageStatus: VERIFICATION_STATE.STILL_PRESENT });
  const html = renderFindingDetailsHtml(current, 'n', { theme: 'light', findings: [current] });
  assert.match(html, /class="sc-companion-rail"/);
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  assert.match(html, /toujours présente après vérification/);
  // Les actions passent par les messages que ce panneau traite deja.
  assert.match(html, /data-assistant-post="\{&quot;type&quot;:&quot;verifyFix&quot;\}"/);
});

test('la page des details sans fait reel garde son rail vide', () => {
  const html = renderFindingDetailsHtml(finding(), 'n', { theme: 'light', findings: [] });
  assert.doesNotMatch(html, /class="sc-assistant(?:\s|")/);
  // Sans rail, le cadre reprend sa variante deux colonnes : rien n'est laisse vide.
  assert.match(html, /sc-app-shell sc-app-shell-norail/);
});

// ================================================ rien du metier n est touche

test('la carte ne touche ni scanner, ni persistance, ni cycle de vie', () => {
  const source = cardSource();
  // Aucune ecriture, aucun processus, aucun acces disque.
  assert.doesNotMatch(source, /require\('fs'\)|require\("fs"\)|child_process|writeFile|spawn|exec\(/);
  // `fix-verification` n'est importe que pour lire son vocabulaire d'etats.
  const imports = source.match(/^const .*require\(.*\);$/gm) || [];
  assert.deepEqual(imports.map((line) => line.match(/require\('([^']+)'\)/)[1]).sort(), [
    './fix-verification', './live/companionMascot', './security-center-shell'
  ]);
});
