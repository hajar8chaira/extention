const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { renderDeliveryPageHtml } = require('../src/delivery-page');
const { renderPipelinePageHtml, renderPipelineRail } = require('../src/pipeline-page');
const { themeOverridesCss } = require('../src/theme-controller');
const { navCommands, TABS_UNUSED } = require('../src/security-center-shell');
const {
  buildAssistantCardModel, renderAssistantCard,
  POST_ACTIONS, ASSISTANT_POST_TYPES, ASSISTANT_POST_ACTIONS
} = require('../src/companion-assistant-card');

const src = (...parts) => fs.readFileSync(path.join(__dirname, '..', 'src', ...parts), 'utf8');
const extensionSource = () => src('extension.js');

const TOKEN = 'jenkins-api-token-MUST-NEVER-APPEAR-1234567890';

/** Un statut Jenkins configuré, avec un rapport CI cohérent. */
const configured = (extra = {}) => ({
  state: 'SUCCESS', baseUrl: 'http://ci.local', job: 'equipe/projet/main', user: 'prenom.nom',
  tokenConfigured: true, workspaceBranch: 'main', fetchedAt: '2026-08-19T09:00:00.000Z',
  connection: { state: 'CONNECTED', message: 'Job trouvé' },
  commit: { match: 'SAME', workspaceCommit: 'a'.repeat(40), buildCommit: 'a'.repeat(40) },
  build: { number: 42, branch: 'main', commit: 'a'.repeat(40), startedAt: '2026-08-19T08:50:00.000Z', durationMs: 126000, result: 'SUCCESS' },
  identity: { inconsistent: false },
  ci: {
    state: 'REPORTED', artifactPath: 'security-center-report.json',
    report: {
      policy: { status: 'PASS', summary: 'Gate vert', reasons: [], blockingCount: 0 },
      execution: { scanId: 'scan-9', status: 'completed' },
      summary: { findings: 7, critical: 0, high: 2 },
      scanners: [{ name: 'Semgrep', status: 'completed', findings: 7 }],
      supplyChain: { sbom: 'generated', provenance: 'generated', signature: 'signed', signatureVerified: true }
    }
  },
  ...extra
});

const notConfigured = () => ({
  state: 'NOT_CONFIGURED', baseUrl: '', job: '', user: '', tokenConfigured: false,
  commit: { match: 'UNKNOWN', workspaceCommit: null, buildCommit: null }, ci: { state: 'NOT_REPORTED' }
});

/** Un modèle pipeline dont chaque résumé est réellement fourni. */
const pipelineModel = (extra = {}) => ({
  tab: 'pipeline', stages: [], findings: [{ id: 'a' }, { id: 'b' }],
  scanId: 'scan-77', finishedAt: '2026-08-19T10:00:00.000Z',
  clusters: [{ sources: [{ tool: 'Semgrep', findingId: 'a' }, { tool: 'Snyk', findingId: 'b' }] }],
  correlation: { total: 1, confirmed: 1, byTier: { confirmed: 1, probable: 0, candidate: 0 } },
  reachability: { analysed: true, scannedFiles: 42, counts: { statically_reachable: 3, not_reachable: 9 } },
  priority: { distribution: { P0: 1, P1: 2, P2: 0, P3: 5 }, highest: 87 },
  policy: { status: 'WARN', configured: true, violations: [], warnings: [{}, {}], counts: { evaluatedFindings: 11 } },
  ...extra
});

// ===================================================== cadre applicatif partagé

test('Security Delivery reste dans le cadre applicatif partagé', () => {
  for (const status of [notConfigured(), configured()]) {
    const html = renderDeliveryPageHtml(status, 'n', 'light');
    assert.match(html, /class="sc-app-shell/, 'le cadre partagé est absent');
    assert.match(html, /class="sc-internal-nav"/, 'la navigation de gauche est absente');
    // Un seul document, un seul cadre : pas de page autonome réintroduite.
    assert.equal((html.match(/class="sc-internal-nav"/g) || []).length, 1);
    assert.equal((html.match(/<!doctype html>/gi) || []).length, 1);
  }
});

test('Security Pipeline reste dans le cadre applicatif partagé', () => {
  const html = renderPipelinePageHtml(pipelineModel(), 'n', 'light');
  assert.match(html, /class="sc-app-shell/);
  assert.match(html, /class="sc-internal-nav"/);
  assert.equal((html.match(/class="sc-internal-nav"/g) || []).length, 1);
});

test('l’item de navigation actif est celui de la page rendue', () => {
  const delivery = renderDeliveryPageHtml(configured(), 'n', 'light');
  assert.match(delivery, /class="sc-nav-item active"[^>]*aria-current="page"[^>]*>.*?Security Delivery/s);
  const pipeline = renderPipelinePageHtml(pipelineModel(), 'n', 'light');
  assert.match(pipeline, /class="sc-nav-item active"[^>]*aria-current="page"/);
  // Un seul item courant par page.
  assert.equal((pipeline.match(/aria-current="page"/g) || []).length, 1);
});

test('aucune page ne réintroduit de lien « ← Dashboard » autonome', () => {
  for (const html of [renderDeliveryPageHtml(configured(), 'n', 'light'), renderPipelinePageHtml(pipelineModel(), 'n', 'light')]) {
    assert.ok(!/←\s*(Retour au )?[Dd]ashboard/.test(html), 'un lien de retour autonome est réapparu');
  }
});

// ===================================================== navigation des sous-pages

test('les six onglets du pipeline gardent une navigation fonctionnelle', () => {
  const html = renderPipelinePageHtml(pipelineModel(), 'n', 'light');
  for (const tab of ['pipeline', 'correlations', 'reachability', 'priorities', 'policy', 'supply-chain']) {
    assert.match(html, new RegExp(`data-tab="${tab}"`), `l'onglet ${tab} a perdu son déclencheur`);
  }
  // Le relais existant : un clic sur un onglet poste le message `tab`, seul
  // handler de bascule du panneau. Aucune route parallèle n'est introduite.
  assert.match(html, /\[data-tab\]/);
  assert.match(html, /postMessage\(\{type:'tab',tab:b\.dataset\.tab\}\)/);
});

test('chaque onglet du pipeline est reçu par le handler existant', () => {
  const source = extensionSource();
  // Un seul point de bascule, et il lit bien le message des onglets.
  assert.match(source, /message\?\.type === 'tab'\W+\{ pipelineTab = message\.tab; return renderPipelinePage\(\); \}/);
  // Et la commande d'ouverture accepte l'onglet en argument : c'est ce qui rend
  // « ouvrir le Policy Gate » depuis une autre surface possible sans route neuve.
  assert.match(source, /registerCommand\('securityCenter\.openSecurityPipeline', async \(tab\) => \{\s*\n\s*if \(typeof tab === 'string'\) pipelineTab = tab;/);
});

test('le rail du pipeline navigue par le relais d’onglets déjà en place', () => {
  const rail = renderPipelineRail(pipelineModel(), '');
  for (const tab of ['correlations', 'reachability', 'priorities']) {
    assert.match(rail, new RegExp(`data-tab="${tab}"`));
  }
  // Aucune commande inventée pour la navigation interne du rail.
  assert.ok(!/data-command="securityCenter\.open(Correlations|Reachability|Priorities)/.test(rail));
});

test('les destinations de commande du rail sont des commandes existantes', () => {
  const rail = renderPipelineRail(pipelineModel(), '');
  const declared = new Set((require('../package.json').contributes.commands || []).map((entry) => entry.command));
  for (const command of rail.match(/data-command="([^"]+)"/g) || []) {
    const name = command.slice('data-command="'.length, -1);
    assert.ok(declared.has(name), `${name} n'est pas une commande contribuée`);
  }
});

// ============================================================ handlers Jenkins

test('les handlers Jenkins de la page sont préservés', () => {
  const html = renderDeliveryPageHtml(notConfigured(), 'n', 'light');
  for (const action of ['saveConfig', 'testConfig', 'openJenkinsfile']) {
    assert.match(html, new RegExp(`data-action="${action}"`), `l'action ${action} a disparu`);
  }
  const configuredHtml = renderDeliveryPageHtml(configured(), 'n', 'light');
  for (const action of ['refresh', 'testConnection', 'openJenkins', 'revealConfig', 'configure']) {
    assert.match(configuredHtml, new RegExp(`data-action="${action}"`), `l'action ${action} a disparu`);
  }
});

test('chaque data-action rendu par Delivery a un handler dans l’extension', () => {
  const source = extensionSource();
  const html = renderDeliveryPageHtml(configured(), 'n', 'light');
  const actions = new Set((html.match(/data-action="([^"]+)"/g) || [])
    .map((raw) => raw.slice('data-action="'.length, -1)));
  assert.ok(actions.size >= 6, 'trop peu d’actions pour que ce test ait du sens');
  for (const action of actions) {
    // `revealConfig` est volontairement local à la page : il ne poste rien.
    if (action === 'revealConfig') continue;
    assert.match(source, new RegExp(`message\\.action === '${action}'`), `aucun handler pour l'action ${action}`);
  }
});

test('le formulaire ne perd ni ses champs ni ses libellés', () => {
  const html = renderDeliveryPageHtml(notConfigured(), 'n', 'light');
  for (const id of ['jenkins-url', 'jenkins-job', 'jenkins-user', 'jenkins-token']) {
    assert.match(html, new RegExp(`id="${id}"`));
    // Chaque champ garde son label associé : le formulaire reste utilisable au
    // lecteur d'écran après la refonte visuelle.
    assert.match(html, new RegExp(`for="${id}"`), `le label de ${id} a disparu`);
  }
});

// ============================================================= sûreté du jeton

test('le jeton d’API n’atteint jamais le HTML rendu', () => {
  // Un statut ne transporte pas le jeton ; on en injecte un partout où un
  // modèle pourrait fuir pour prouver que la page n'en rend aucun.
  const poisoned = configured({ token: TOKEN, apiToken: TOKEN, secret: TOKEN });
  for (const theme of ['light', 'dark']) {
    const html = renderDeliveryPageHtml(poisoned, 'n', theme);
    assert.ok(!html.includes(TOKEN), 'le jeton est apparu dans la page');
  }
  // Et le champ mot de passe n'est jamais prérempli.
  const html = renderDeliveryPageHtml(poisoned, 'n', 'light');
  assert.ok(!/type="password"[^>]*value=/.test(html));
});

test('le jeton ne traverse pas le contexte de l’assistant', () => {
  const poisoned = configured({ token: TOKEN, apiToken: TOKEN });
  const card = renderAssistantCard(buildAssistantCardModel({ surface: 'delivery', delivery: poisoned }));
  assert.ok(card, 'la carte doit se rendre pour que le test ait un sens');
  assert.ok(!card.includes(TOKEN), 'le jeton est apparu dans la carte');
  // Ni l'URL complète ni le nom du job ne sont nécessaires au message.
  assert.ok(!card.includes('http://ci.local'));
});

// ================================================== aucune donnée inventée

test('la livraison n’affiche aucune valeur absente du modèle', () => {
  const html = renderDeliveryPageHtml(configured(), 'n', 'light');
  // Les valeurs de la maquette de référence ne doivent jamais être codées.
  // (Un pourcentage nu serait un mauvais marqueur : « 92% » apparaît
  // légitimement dans une image-clé d'animation de la mascotte.)
  for (const fake of ['#142', 'jenkins.local', 'security-pipeline', '18 vulnerabilities', '2m 06s', '92% Policy Gate', '3 correlations']) {
    assert.ok(!html.includes(fake), `valeur de maquette « ${fake} » présente dans la page`);
  }
  // Les vraies valeurs du modèle, elles, sont bien là.
  assert.ok(html.includes('#42'), 'le numéro de build réel est absent');
  assert.ok(html.includes('equipe/projet/main'));
});

test('un build sans rapport n’affiche jamais un Policy Gate vert', () => {
  const html = renderDeliveryPageHtml(configured({ ci: { state: 'NOT_REPORTED' } }), 'n', 'light');
  assert.ok(!html.includes('>PASS<'), 'un verdict est apparu sans rapport');
  assert.match(html, /Non rapporté/);
});

test('un rapport incohérent n’est attribué ni au bandeau, ni au cycle, ni au rail', () => {
  // Le garde-fou : le rapport existe, mais il vient d'un autre commit. Aucune
  // surface ne doit lui emprunter son verdict.
  const html = renderDeliveryPageHtml(configured({
    identity: { inconsistent: true, buildCommit: 'a'.repeat(40), reportCommit: 'b'.repeat(40) }
  }), 'n', 'light');
  assert.match(html, /Données incohérentes/);
  assert.ok(!html.includes('>PASS<'), 'le verdict d’un rapport incohérent a été affiché');
  assert.match(html, /Incohérent/);
});

test('le déploiement n’est jamais déduit d’un build en succès', () => {
  const html = renderDeliveryPageHtml(configured(), 'n', 'light');
  // Le build est en SUCCESS et le gate en PASS : le déploiement reste inconnu.
  assert.match(html, /État indisponible/);
  assert.ok(!/Déploiement[^<]*<[^>]*>\s*(Succès|Déployé|SUCCESS)/.test(html));
});

test('le rail du pipeline ne montre que les résumés réellement fournis', () => {
  // Aucun résumé d'intelligence, aucune politique : aucune carte de faits.
  const bare = renderPipelineRail({ tab: 'pipeline', findings: [] }, '');
  assert.equal((bare.match(/class="sc-context-card rail-card"/g) || []).length, 0);
  // Avec les résumés, une carte par résumé — et les nombres sont ceux du modèle.
  const full = renderPipelineRail(pipelineModel(), '');
  assert.equal((full.match(/class="sc-context-card rail-card"/g) || []).length, 5);
  assert.match(full, /Max 87/);
  assert.match(full, /Outils<\/span><strong>2</);
  assert.match(full, /Fichiers analysés<\/span><strong>42</);
});

test('une atteignabilité non analysée le dit au lieu d’afficher zéro', () => {
  const rail = renderPipelineRail(pipelineModel({
    reachability: { analysed: false, scannedFiles: 0, counts: {} }
  }), '');
  assert.match(rail, /Non analysée/);
});

test('une politique non configurée est un état explicite, pas un gate vide', () => {
  const rail = renderPipelineRail(pipelineModel({
    policy: { status: 'NOT_CONFIGURED', configured: false }
  }), '');
  assert.match(rail, /Aucune politique projet n’est configurée/);
  assert.match(rail, /Configurer la politique/);
  assert.ok(!/Blocages/.test(rail), 'aucun compteur ne doit être affiché sans politique');
});

// =========================================================== une seule mascotte

test('jamais plus d’une mascotte par surface', () => {
  const companion = { mascotState: 'warning', liveFindingCount: 2, shortMessage: '2 problèmes Live', state: 'findings' };
  const pipeline = renderPipelinePageHtml(pipelineModel({ companion, companionEnabled: true }), 'n', 'light');
  assert.equal((pipeline.match(/<img class="mascot/g) || []).length, 1);
  const delivery = renderDeliveryPageHtml(configured(), 'n', 'light');
  assert.ok((delivery.match(/<img class="mascot/g) || []).length <= 1);
  // Carte et widget flottant ne coexistent jamais.
  assert.ok(!(/class="sc-assistant/.test(pipeline) && pipeline.includes('class="sc-widget')));
});

test('la carte de l’assistant supersède le widget flottant sur le pipeline', () => {
  const html = renderPipelinePageHtml(pipelineModel(), 'n', 'light');
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  assert.ok(!html.includes('class="sc-widget'));
});

test('sans contexte métier, le hero Live propre reste disponible sans widget', () => {
  // Aucune politique : l'assistant n'a rien à dire sur le pipeline, donc le
  // hero Live garde seulement la presence propre du companion partage.
  const companion = { mascotState: 'watching', liveFindingCount: 0, state: 'clean' };
  const html = renderPipelinePageHtml({ tab: 'pipeline', stages: [], findings: [], companion, companionEnabled: true }, 'n', 'light');
  assert.match(html, /class="sc-assistant sc-assistant-hero"/);
  assert.ok(!/class="sc-widget/.test(html));
  assert.equal((html.match(/<img class="mascot/g) || []).length, 1);
});

// ============================================== actions de l’assistant réelles

test('les actions de livraison de l’assistant ciblent des handlers existants', () => {
  const source = extensionSource();
  for (const [id, action] of Object.entries(POST_ACTIONS)) {
    if (!action.hosts.includes('delivery')) continue;
    assert.equal(action.post.type, 'action', `${id} doit passer par le type d'action existant`);
    assert.match(source, new RegExp(`message\\.action === '${action.post.action}'`),
      `${id} cible ${action.post.action}, sans handler dans le panneau Delivery`);
  }
});

test('le relais valide le type ET la valeur d’action', () => {
  const { assistantCardScript } = require('../src/companion-assistant-card');
  const script = assistantCardScript();
  assert.match(script, /ALLOWED_POST_TYPES\.indexOf\(payload\.type\) === -1\) return;/);
  assert.match(script, /ALLOWED_POST_ACTIONS\.indexOf\(payload\.action\) === -1\) return;/);
  // Toute action du catalogue figure dans la liste blanche du relais.
  for (const action of Object.values(POST_ACTIONS)) {
    if (action.post.type !== 'action') continue;
    assert.ok(ASSISTANT_POST_ACTIONS.includes(action.post.action), `${action.post.action} absente de la liste blanche`);
  }
  assert.ok(ASSISTANT_POST_TYPES.includes('action'));
});

test('l’assistant de livraison ne parle que de faits Jenkins connus', () => {
  // Pas de rapport : le verdict est déclaré inconnu, jamais supposé.
  const noReport = buildAssistantCardModel({ surface: 'delivery', delivery: configured({ ci: { state: 'NOT_REPORTED' } }) });
  assert.match(noReport.message.text, /n’a publié aucun rapport/);
  assert.equal(noReport.message.source, 'jenkins');
  // Un commit divergent invalide le verdict, et le dit avant lui.
  const drifted = buildAssistantCardModel({
    surface: 'delivery',
    delivery: configured({ commit: { match: 'DIFFERENT', workspaceCommit: 'a'.repeat(40), buildCommit: 'b'.repeat(40) } })
  });
  assert.match(drifted.message.text, /ne porte pas sur le code ouvert ici/);
  // Jenkins injoignable : aucun état de livraison n'est affirmé.
  const down = buildAssistantCardModel({ surface: 'delivery', delivery: configured({ state: 'ERROR', connection: { state: 'UNREACHABLE' } }) });
  assert.match(down.message.text, /injoignable/);
  // Jenkins non configuré : aucune carte du tout.
  assert.equal(buildAssistantCardModel({ surface: 'delivery', delivery: null }), null);
});

test('le nombre de findings à risque cité par l’assistant vient du rapport', () => {
  const card = buildAssistantCardModel({ surface: 'delivery', delivery: configured() });
  // Le rapport annonce 0 critique et 2 élevés : la phrase reprend ces nombres.
  assert.match(card.message.text, /2 élevés/);
  assert.ok(!/critique/.test(card.message.text), 'aucun critique ne doit être cité quand le compte est nul');
});

// ================================================= thèmes clair et sombre

test('les contrôles de formulaire suivent le thème, jamais le sombre de VS Code', () => {
  const css = src('delivery-page.js');
  const form = css.slice(css.indexOf('.jenkins-form[hidden]'), css.indexOf('.footnote'));
  // La régression corrigée : lire --vscode-input-* laissait des champs presque
  // noirs sur une page forcée en clair.
  assert.ok(!/var\(--vscode-input-/.test(form));
  assert.match(form, /var\(--sc-input-bg\)/);
  // Et le token existe bien dans les deux thèmes du contrôleur.
  const tokens = themeOverridesCss();
  const light = tokens.slice(tokens.indexOf('body.theme-light'), tokens.indexOf('body.theme-dark'));
  assert.match(light, /--sc-input-bg:\s*#ffffff/);
  const dark = tokens.slice(tokens.indexOf('body.theme-dark'));
  assert.match(dark, /--sc-input-bg:\s*var\(--vscode-input-background/);
});

test('les deux pages rendent les deux thèmes sans changer de structure', () => {
  for (const render of [
    (theme) => renderDeliveryPageHtml(configured(), 'n', theme),
    (theme) => renderPipelinePageHtml(pipelineModel(), 'n', theme)
  ]) {
    const light = render('light');
    const dark = render('dark');
    assert.match(light, /data-theme="light"/);
    assert.match(dark, /data-theme="dark"/);
    assert.match(light, /class="[^"]*theme-light/);
    assert.match(dark, /class="[^"]*theme-dark/);
    // Même squelette : seul le thème change.
    assert.equal((light.match(/class="sc-app-shell/g) || []).length, (dark.match(/class="sc-app-shell/g) || []).length);
  }
});

test('aucune couleur de statut en dur dans les nouvelles sections', () => {
  const source = src('delivery-page.js');
  const dashboard = source.slice(source.indexOf('function deliveryDashboardCss'), source.indexOf('function renderDeliveryPageHtml'));
  const literals = dashboard.match(/:\s*(#[0-9a-f]{3,8}|rgba?\()/gi) || [];
  assert.deepEqual(literals, [], 'une couleur littérale est apparue dans le tableau de bord');
  const rail = src('pipeline-page.js');
  const railCss = rail.slice(rail.indexOf('function pipelineRailCss'), rail.indexOf('function renderPipelinePageHtml'));
  assert.deepEqual(railCss.match(/:\s*(#[0-9a-f]{3,8}|rgba?\()/gi) || [], []);
});

test('le statut n’est jamais porté par la couleur seule', () => {
  const html = renderDeliveryPageHtml(configured(), 'n', 'light');
  // Chaque état du cycle porte un glyphe en plus de sa teinte.
  assert.match(html, /class="stage-dot" aria-hidden="true">[✓!✕◷·?]</);
  const rail = renderPipelineRail(pipelineModel(), '');
  assert.match(rail, /rail-pill (ok|warn|bad)">[✓!✕·]/);
});

// =============================================================== responsive

test('les grilles se replient et n’imposent aucun défilement horizontal', () => {
  const source = src('delivery-page.js');
  const dashboard = source.slice(source.indexOf('function deliveryDashboardCss'));
  // Repli explicite sous 900px pour chaque grille dense.
  assert.match(dashboard, /@media\(max-width:900px\)/);
  assert.match(dashboard, /\.strip-grid,\.lifecycle,\.quick-actions\{grid-template-columns:1fr\}/);
  assert.match(dashboard, /\.jenkins-fields\{grid-template-columns:1fr\}/);
  // Les colonnes contraintes utilisent minmax(0,…) ou auto-fit, jamais une
  // largeur fixe qui déborderait.
  assert.match(source, /grid-template-columns:repeat\(auto-fit,minmax\(/);
  assert.ok(!/overflow-x:\s*scroll/.test(dashboard));
});

test('le repli du rail garde la variante sans rail du cadre', () => {
  // Le bug de spécificité déjà rencontré : la variante sans rail doit être citée
  // dans les points de rupture, sinon elle l'emporte et la nav reste large.
  const shell = src('security-center-shell.js');
  const breakpoints = shell.slice(shell.indexOf('@media (max-width: 1200px)'));
  assert.match(breakpoints, /\.sc-app-shell\.sc-app-shell-norail/);
  assert.match(breakpoints, /\.sc-companion-rail \{ display: none; \}/);
});

test('la page non configurée n’affiche pas de rail de faits vides', () => {
  const html = renderDeliveryPageHtml(notConfigured(), 'n', 'light');
  assert.match(html, /sc-app-shell sc-app-shell-norail/);
  assert.ok(!html.includes('class="sc-companion-rail"'));
});

// ====================================================== runtime de la webview

test('acquireVsCodeApi n’est jamais acquis deux fois', () => {
  for (const html of [renderDeliveryPageHtml(configured(), 'n', 'light'), renderPipelinePageHtml(pipelineModel(), 'n', 'light')]) {
    // Toute acquisition passe par le même cache de fenêtre.
    const raw = html.match(/acquireVsCodeApi\(\)/g) || [];
    assert.ok(raw.length >= 1);
    const guarded = html.match(/window\.__scShellApi/g) || [];
    assert.ok(guarded.length >= raw.length - 1,
      'une acquisition n’est pas passée par le cache window.__scShellApi');
  }
});

test('aucun clic ne peut partir deux fois vers l’extension', () => {
  for (const [name, html] of [
    ['delivery', renderDeliveryPageHtml(configured(), 'n', 'light')],
    ['pipeline', renderPipelinePageHtml(pipelineModel(), 'n', 'light')]
  ]) {
    if (!/class="sc-assistant/.test(html)) continue;
    // La carte apporte son propre relais : les boucles de la page l'excluent.
    // Le sélecteur peut porter d'autres `:not(...)` avant celui-ci.
    assert.match(html, /querySelectorAll\('\[data-command\](?::not\([^']*?\))*:not\(\.sc-assistant \[data-command\]\)'\)/,
      `${name} relaie encore les boutons de la carte`);
  }
  const delivery = renderDeliveryPageHtml(configured(), 'n', 'light');
  assert.match(delivery, /\[data-action\]:not\(\.sc-assistant \[data-action\]\)/);
});

test('la politique de sécurité de contenu reste stricte sur les deux pages', () => {
  for (const html of [renderDeliveryPageHtml(configured(), 'n', 'light'), renderPipelinePageHtml(pipelineModel(), 'n', 'light')]) {
    assert.match(html, /default-src 'none'/);
    assert.ok(!/script-src[^"]*'unsafe-inline'/.test(html), 'les scripts ne doivent pas être en unsafe-inline');
  }
});
