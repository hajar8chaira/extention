const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { renderDeliveryPageHtml } = require('../src/delivery-page');
const {
  deliveryStatusFrom, buildStatusFrom, testJenkinsConnection,
  CONNECTION_STATE, DELIVERY_STATE
} = require('../src/jenkins');

const TOKEN = '11aabbccddeeff00112233445566778899';

const unconfigured = (extra = {}) => ({ ...deliveryStatusFrom({ configured: false }), ...extra });
const configured = (extra = {}) => ({
  ...deliveryStatusFrom({
    configured: true, job: 'equipe/projet/main', baseUrl: 'http://ci.local',
    build: buildStatusFrom({ number: 42, result: 'SUCCESS' })
  }),
  user: 'prenom.nom', tokenConfigured: true, ...extra
});

const render = (status) => renderDeliveryPageHtml(status, 'n', 'light');

// ======================================================= état non configuré

test('l’état non configuré présente le formulaire inline', () => {
  const html = render(unconfigured());
  assert.match(html, /id="jenkins-form"/);
  for (const id of ['jenkins-url', 'jenkins-job', 'jenkins-user', 'jenkins-token']) {
    assert.match(html, new RegExp(`id="${id}"`), `champ ${id} absent`);
  }
  assert.match(html, /URL Jenkins/);
  assert.match(html, /Job \/ Pipeline/);
  assert.match(html, /Utilisateur/);
  assert.match(html, /Jeton d’API/);
  assert.match(html, /data-action="testConfig"/);
  assert.match(html, /data-action="saveConfig"/);
  assert.match(html, /data-action="openJenkinsfile"/);
});

test('le formulaire est visible d’emblée quand rien n’est configuré', () => {
  const html = render(unconfigured());
  const form = html.slice(html.indexOf('id="jenkins-form"'), html.indexOf('</section>'));
  assert.ok(!form.includes('hidden'), 'le formulaire ne doit pas être masqué');
});

test('la promesse produit est écrite, pas sous-entendue', () => {
  const html = render(unconfigured());
  assert.match(html, /Connectez votre serveur Jenkins existant/);
  assert.match(html, /Security Center n’installe jamais Jenkins/);
  // Rien ne propose d'installer ni de lancer quoi que ce soit.
  assert.ok(!/installer Jenkins|Lancer le build|triggerBuild/i.test(html));
});

test('le champ jeton annonce où il ira, quand rien n’est encore stocké', () => {
  const html = render(unconfigured());
  assert.match(html, /SecretStorage de VS Code — jamais dans settings\.json/);
  assert.ok(!html.includes('✓ Configuré dans SecretStorage'), 'aucun jeton n’est pourtant configuré');
});

// ========================================================== état configuré

test('l’état configuré montre le tableau de bord, formulaire masqué', () => {
  const html = render(configured());
  for (const section of ['Connexion Jenkins', 'Workspace courant', 'Build #42', 'Correspondance du code', 'Security Center — CI', 'Preuves supply chain', 'Déploiement']) {
    assert.ok(html.includes(section), `section « ${section} » absente`);
  }
  assert.match(html, /id="jenkins-form" hidden|id="jenkins-form"[^>]* hidden/);
});

test('les trois actions de l’état configuré sont présentes', () => {
  const html = render(configured());
  assert.match(html, /data-action="revealConfig">Modifier la configuration/);
  assert.match(html, /data-action="testConnection"/);
  assert.match(html, /data-action="openJenkins"/);
});

test('« Modifier la configuration » révèle le formulaire sans aller-retour', () => {
  const html = render(configured());
  // Le formulaire est déjà dans le document : le révéler est un changement local.
  assert.match(html, /if\(action==='revealConfig'\)\{if\(form\)\{form\.hidden=false/);
  assert.ok(!/postMessage\(\{type:'action',action:'revealConfig'/.test(html),
    'révéler le formulaire ne doit pas solliciter l’extension');
});

test('le formulaire préremplit ce qui est connu, jamais le jeton', () => {
  const html = render(configured());
  assert.match(html, /id="jenkins-url"[^>]*value="http:\/\/ci\.local"/);
  assert.match(html, /id="jenkins-job"[^>]*value="equipe\/projet\/main"/);
  assert.match(html, /id="jenkins-user"[^>]*value="prenom\.nom"/);
  // Le champ jeton n'a pas d'attribut value du tout.
  const tokenInput = html.slice(html.indexOf('id="jenkins-token"'));
  assert.ok(!tokenInput.slice(0, tokenInput.indexOf('>')).includes('value='), 'le champ jeton ne doit pas être prérempli');
  assert.match(html, /✓ Configuré dans SecretStorage/);
  assert.match(html, /Laisser vide pour conserver le jeton enregistré/);
});

test('l’état erreur garde l’accès au formulaire', () => {
  const html = render({ ...configured(), state: DELIVERY_STATE.ERROR, error: 'connexion refusée' });
  assert.match(html, /Jenkins inaccessible/);
  assert.match(html, /data-action="revealConfig"/);
  assert.match(html, /id="jenkins-form"/);
});

// ============================================== le jeton ne revient jamais

test('un jeton enregistré n’apparaît nulle part dans le HTML', () => {
  // Même en le glissant partout où un modèle pourrait le laisser fuir.
  const html = render(configured({
    token: TOKEN, apiToken: TOKEN,
    connection: { state: CONNECTION_STATE.CONNECTED, message: 'Connecté au job projet.' }
  }));
  assert.ok(!html.includes(TOKEN), 'le jeton ne doit pas atteindre la page');
  assert.ok(!/type="password"[^>]*value=/.test(html), 'aucun champ mot de passe prérempli');
});

test('le modèle envoyé à la page ne transporte pas le jeton', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const refresh = source.slice(source.indexOf('async function refreshDeliveryStatus'));
  const body = refresh.slice(0, refresh.indexOf('renderDeliveryPage();'));
  // Seul le fait qu'un jeton existe entre dans le modèle.
  assert.match(body, /tokenConfigured: Boolean\(token\)/);
  assert.ok(!/\btoken,\s*$/m.test(body.slice(body.indexOf('deliveryStatus = {'))),
    'le jeton lui-même ne doit pas être ajouté au modèle de présentation');
});

test('le jeton n’est écrit que dans SecretStorage', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const apply = source.slice(source.indexOf('async function applyJenkinsConfiguration'));
  const body = apply.slice(0, apply.indexOf('\n  }\n'));
  assert.match(body, /context\.secrets\.store\(JENKINS_TOKEN_SECRET_KEY, trimmedToken\)/);
  // Ni settings.json, ni workspaceState, ni journal, ni audit.
  assert.ok(!/cfg\.update\([^)]*[Tt]oken/.test(body), 'aucun jeton dans la configuration');
  assert.ok(!/workspaceState[\s\S]*trimmedToken/.test(body));
  assert.ok(!/appendLine[\s\S]*trimmedToken/.test(body));
  assert.match(body, /tokenStored: Boolean\(trimmedToken\)/, 'l’audit ne consigne que l’existence');
  const audit = body.slice(body.indexOf('createAuditEvent'));
  assert.ok(!/comment:[^\n]*trimmedToken/.test(audit), 'aucun jeton dans un événement d’audit');
});

test('un jeton vide conserve celui déjà enregistré', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const apply = source.slice(source.indexOf('async function applyJenkinsConfiguration'));
  assert.match(apply.slice(0, apply.indexOf('\n  }\n')), /if \(trimmedToken\) await context\.secrets\.store/);
});

// ================================== la logique existante reste la référence

test('le formulaire n’embarque ni validation ni appel à Jenkins', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'delivery-page.js'), 'utf8');
  assert.ok(!/fetch\(|XMLHttpRequest|normalizeJenkinsUrl\(/.test(source),
    'la page ne doit ni appeler Jenkins ni normaliser l’URL elle-même');
  // Elle collecte et transmet ; l'extension décide.
  const html = render(unconfigured());
  assert.match(html, /postMessage\(\{type:'action',action,config:config\(\)\}\)/);
});

test('l’extension reste la frontière de confiance pour les deux actions', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /message\.action === 'saveConfig'/);
  assert.match(source, /message\.action === 'testConfig'/);
  // Le test de connexion passe par la fonction existante, pas par une nouvelle.
  const testConfig = source.slice(source.indexOf("message.action === 'testConfig'"));
  assert.match(testConfig.slice(0, 600), /testJenkinsConnection\(\{/);
  // La sauvegarde passe par l'unique fonction de persistance.
  const saveConfig = source.slice(source.indexOf("message.action === 'saveConfig'"));
  assert.match(saveConfig.slice(0, 400), /applyJenkinsConfiguration\(\{/);
});

test('il n’existe qu’un seul chemin d’écriture de la configuration Jenkins', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // La commande InputBox et le formulaire aboutissent au même endroit.
  assert.equal((source.match(/cfg\.update\('jenkins\.url'/g) || []).length, 1);
  assert.equal((source.match(/cfg\.update\('jenkins\.job'/g) || []).length, 1);
  assert.equal((source.match(/context\.secrets\.store\(JENKINS_TOKEN_SECRET_KEY/g) || []).length, 1);
  // Une définition et deux appels : la commande InputBox et le formulaire.
  assert.equal((source.match(/applyJenkinsConfiguration\(\{/g) || []).length, 3, 'les deux entrées, une seule implémentation');
  assert.equal((source.match(/async function applyJenkinsConfiguration/g) || []).length, 1);
});

test('la commande InputBox existante fonctionne toujours', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  assert.match(source, /registerCommand\('securityCenter\.configureJenkins'/);
  assert.match(source, /title: 'Jenkins — URL de base'/);
  assert.match(source, /title: 'Jenkins — jeton d’API', password: true/);
});

// ============================================== états du test de connexion

test('le test de connexion réutilise les six états existants', async () => {
  const cases = [
    [async () => ({ name: 'projet' }), CONNECTION_STATE.CONNECTED],
    [async () => { throw new Error('Jenkins a refusé l’authentification.'); }, CONNECTION_STATE.AUTH_FAILED],
    [async () => { throw new Error('Jenkins a refusé l’accès.'); }, CONNECTION_STATE.FORBIDDEN],
    [async () => { throw new Error('Job introuvable.'); }, CONNECTION_STATE.JOB_NOT_FOUND],
    [async () => { throw new Error('Le serveur ne répond pas.'); }, CONNECTION_STATE.UNREACHABLE],
    [async () => { throw new Error('quelque chose d’autre'); }, CONNECTION_STATE.ERROR]
  ];
  for (const [request, expected] of cases) {
    const result = await testJenkinsConnection({ baseUrl: 'http://ci.local', job: 'p', request });
    assert.equal(result.state, expected);
  }
  // Une configuration incomplète est une erreur de configuration, pas un appel.
  assert.equal((await testJenkinsConnection({ job: 'p' })).state, CONNECTION_STATE.ERROR);
  assert.equal((await testJenkinsConnection({ baseUrl: 'http://ci.local' })).state, CONNECTION_STATE.ERROR);
});

test('chaque état de connexion s’affiche avec son libellé', () => {
  const expected = {
    CONNECTED: 'Connecté', AUTH_FAILED: 'Authentification refusée', FORBIDDEN: 'Accès refusé',
    JOB_NOT_FOUND: 'Job introuvable', UNREACHABLE: 'Serveur injoignable', ERROR: 'Erreur de configuration'
  };
  for (const [state, label] of Object.entries(expected)) {
    const html = render(unconfigured({ connection: { state, message: `message ${state}` } }));
    assert.match(html, new RegExp(label), `libellé manquant pour ${state}`);
    assert.match(html, new RegExp(`message ${state}`), `message manquant pour ${state}`);
  }
});

test('aucune réponse brute de Jenkins n’est rendue', () => {
  const html = render(unconfigured({
    connection: {
      state: CONNECTION_STATE.ERROR,
      message: '<html><body><h1>500</h1><script>alert(1)</script></body></html>'
    }
  }));
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('<h1>500</h1>'));
  assert.match(html, /&lt;html&gt;/, 'le contenu est échappé, pas interprété');
});

test('le contenu hostile des champs préremplis est échappé', () => {
  const html = render(configured({
    baseUrl: '"><script>alert(1)</script>', job: '"><img src=x onerror=alert(1)>', user: '"onmouseover="x'
  }));
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('<img src=x onerror'));
  assert.ok(!html.includes('"onmouseover="x'));
});

// ============================================================ thème

test('le formulaire n’utilise que les tokens de thème Security Center', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'delivery-page.js'), 'utf8');
  const css = source.slice(source.indexOf('.jenkins-form[hidden]'), source.indexOf('.footnote'));
  // Les contrôles passent par les tokens --sc-input-*, que le contrôleur de
  // thème redéfinit pour chaque thème.
  assert.match(css, /var\(--sc-input-bg\)/);
  assert.match(css, /var\(--sc-input-text\)/);
  assert.match(css, /var\(--sc-input-border\)/);
  assert.match(css, /var\(--sc-input-placeholder\)/);
  // L'anneau de focus est un token lui aussi — l'accent Security Center.
  assert.match(css, /input:focus\{[^}]*var\(--sc-primary\)/);
  // GARDE-FOU DE RÉGRESSION. Lire --vscode-input-* directement était le défaut
  // de mode clair : ces variables gardent le fond sombre de VS Code alors que la
  // page est forcée en clair, ce qui donnait des champs presque noirs au milieu
  // d'une page blanche. Les tokens --sc-input-* retombent sur --vscode-input-*
  // en thème sombre uniquement, donc les deux thèmes restent corrects.
  assert.ok(!/var\(--vscode-input-/.test(css), 'les contrôles ne doivent plus lire --vscode-input-* directement');
  // Aucun fond ni texte noir/blanc codé en dur.
  assert.ok(!/background:\s*#(000|111|1e1e1e|222|fff|ffffff)\b/i.test(css));
  assert.ok(!/color:\s*#(000|000000|fff|ffffff)\b/i.test(css));
});

test('la page rend les deux thèmes sans changer de structure', () => {
  const light = renderDeliveryPageHtml(configured(), 'n', 'light');
  const dark = renderDeliveryPageHtml(configured(), 'n', 'dark');
  assert.match(light, /data-theme="light"/);
  assert.match(dark, /data-theme="dark"/);
  // Seuls l'attribut de thème et la classe du body diffèrent : les couleurs
  // viennent des variables du cadre partagé.
  const strip = (html, theme) => html
    .replace(`data-theme="${theme}"`, '')
    .replace(`<body class="theme-${theme}`, '<body class="');
  assert.equal(strip(light, 'light'), strip(dark, 'dark'));
  assert.match(light, /color-scheme: light/);
  assert.match(dark, /color-scheme: dark/);
});

test('la politique de sécurité de contenu reste stricte', () => {
  const html = render(unconfigured());
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-n'/);
  assert.ok(!/onclick="/.test(html), 'aucun gestionnaire inline hors du script à nonce');
});
