const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const manifest = require('../package.json');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
// Le document du dashboard est desormais compose de deux fichiers : sa propre
// feuille de style et celle du cadre applicatif partage (barre laterale, zone
// centrale, rail de contexte). Les assertions portent sur la page rendue, donc
// sur la reunion des deux sources.
const dashboardSource = () => [
  fs.readFileSync(path.join(__dirname, '..', 'src', 'dashboard.js'), 'utf8'),
  fs.readFileSync(path.join(__dirname, '..', 'src', 'security-center-shell.js'), 'utf8')
].join(String.fromCharCode(10));

const html = (surface = 'full', theme = 'light') =>
  renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed' }), 'n', surface, theme);

/** Every clickable navigation entry, as rendered. */
function navItems(markup) {
  return [...markup.matchAll(/<button class="sc-nav-item([^"]*)"([^>]*)>/g)].map(([, classes, attributes]) => ({
    active: classes.includes('active'),
    command: (attributes.match(/data-command="([^"]+)"/) || [])[1],
    label: (attributes.match(/aria-label="([^"]+)"/) || [])[1],
    title: (attributes.match(/title="([^"]+)"/) || [])[1],
    current: attributes.includes('aria-current="page"')
  }));
}

// ================================= chaque item pointe vers une commande reelle

test('la navigation interne ne cite que des commandes existantes', () => {
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  const items = navItems(html());
  assert.ok(items.length >= 15, `navigation trop courte (${items.length} items)`);
  for (const item of items) {
    assert.ok(item.command, 'un item cliquable doit porter une commande');
    assert.ok(declared.has(item.command), `${item.command} n'est pas declaree dans package.json`);
  }
});

test('chaque commande de navigation possede un handler enregistre', () => {
  const source = extensionSource();
  // Les quatre pages internes sont enregistrees par une boucle a gabarit
  // (`securityCenter.open${Page}Page`) : chercher le litteral les manquerait
  // alors qu'elles ont bien un handler.
  const loopRegistered = new Set(['findings', 'scans', 'dynamic', 'analytics']
    .map((page) => `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`));
  assert.ok(source.includes("for (const page of ['findings', 'scans', 'dynamic', 'analytics'])"),
    'la boucle d enregistrement des pages doit exister');
  for (const item of navItems(html())) {
    if (loopRegistered.has(item.command)) continue;
    assert.match(source, new RegExp(`registerCommand\\('${item.command.replace('.', '\\.')}'`),
      `${item.command} n'a pas de handler`);
  }
});

test('chaque commande de navigation est autorisee par la frontiere de confiance', () => {
  // Le webview demande, l'extension decide. Un item absent de la liste blanche
  // serait muet au clic — c'etait le cas de Security Pipeline et Security
  // Delivery, cables dans la nav mais jamais autorises.
  const source = extensionSource();
  const allowlist = source.slice(source.indexOf('const allowed = new Set(['));
  const body = allowlist.slice(0, allowlist.indexOf(']);'));
  for (const item of navItems(html())) {
    assert.ok(body.includes(`'${item.command}'`), `${item.command} n'est pas dans la liste blanche`);
  }
});

test('la navigation n invente aucune commande', () => {
  const source = dashboardSource();
  const navigation = source.slice(source.indexOf('function renderInternalSidebar'));
  const groups = navigation.slice(0, navigation.indexOf('return `<aside'));
  const declared = new Set(manifest.contributes.commands.map((entry) => entry.command));
  for (const [, command] of groups.matchAll(/'(securityCenter\.[A-Za-z]+)'/g)) {
    assert.ok(declared.has(command), `${command} est cite dans la nav sans exister`);
  }
});

test('un item sans commande sure est desactive, jamais cable a vide', () => {
  const source = dashboardSource();
  const navigation = source.slice(source.indexOf('function renderInternalSidebar'));
  // Le rendu desactive existe toujours comme filet de securite.
  assert.match(navigation, /sc-nav-item missing/);
  assert.match(navigation, /aria-disabled="true"/);
  // Et il n'y a aucun bouton cliquable sans commande.
  assert.ok(!/<button class="sc-nav-item[^"]*"[^>]*data-command=""/.test(html()));
});

// ================================================= etat actif

test('le dashboard ouvert se signale comme la page courante', () => {
  const items = navItems(html('full'));
  const current = items.filter((item) => item.current);
  assert.equal(current.length, 1, 'une seule page courante a la fois');
  assert.equal(current[0].command, 'securityCenter.openDashboard');
  assert.equal(current[0].active, true, 'la classe visuelle accompagne aria-current');
});

test('chaque surface interne marque son propre item', () => {
  // L'assertion porte sur la page rendue, pas sur la forme de la table interne :
  // ce qui compte est qu'ouvrir une surface allume l'item correspondant.
  const expected = {
    full: 'securityCenter.openDashboard',
    findings: 'securityCenter.openFindingsPage',
    scans: 'securityCenter.openScansPage',
    dynamic: 'securityCenter.openDynamicPage',
    analytics: 'securityCenter.openAnalyticsPage'
  };
  for (const [surface, command] of Object.entries(expected)) {
    const active = navItems(html(surface)).filter((item) => item.active);
    assert.equal(active.length, 1, `la surface ${surface} doit marquer exactement un item`);
    assert.equal(active[0].command, command, `la surface ${surface} ne marque pas ${command}`);
    assert.equal(active[0].current, true, `la surface ${surface} doit porter aria-current`);
  }
});

test('l etat actif n est pas signale par la couleur seule', () => {
  const source = dashboardSource();
  // aria-current porte l'information pour les technologies d'assistance ; la
  // teinte indigo n'est qu'un renfort visuel.
  assert.match(source, /aria-current="page"/);
  assert.match(source, /\.sc-nav-item\.active \{[^}]*background: var\(--sc-primary-soft\)/);
});

// ================================================= accessibilite

test('chaque item reste lisible quand le rail se reduit aux icones', () => {
  const source = dashboardSource();
  // Le point de rupture masque le libelle...
  assert.match(source, /\.sc-nav-item span \{ display: none; \}/);
  // ...donc chaque item doit porter son nom autrement.
  for (const item of navItems(html())) {
    assert.ok(item.label, `${item.command} n a pas d aria-label`);
    assert.ok(item.title, `${item.command} n a pas de title`);
    assert.equal(item.label, item.title, 'le nom accessible et l infobulle concordent');
  }
});

test('les items de navigation sont des boutons focalisables', () => {
  const markup = html();
  // Un <button type="button"> est atteignable au clavier par construction ;
  // un <div> cliquable ne l aurait pas ete.
  const buttons = [...markup.matchAll(/<button class="sc-nav-item[^"]*"([^>]*)>/g)];
  for (const [, attributes] of buttons) {
    assert.match(attributes, /type="button"/, 'un item de nav doit etre un vrai bouton');
  }
  assert.ok(buttons.length >= 15);
});

test('la navigation est annoncee comme telle', () => {
  const markup = html();
  assert.match(markup, /<aside class="sc-internal-nav" aria-label="[^"]+"/);
  assert.match(markup, /<nav class="sc-nav-groups">/);
  // Les groupes sont des sections titrees, pas des div anonymes.
  assert.match(markup, /<section class="sc-nav-group"><h2>/);
});

test('le contenu hostile ne traverse pas la navigation', () => {
  const markup = html();
  // Les libelles passent par escapeHtml : une esperluette est encodee.
  assert.match(markup, /aria-label="Fix &amp; Verify"/);
  assert.ok(!markup.includes('aria-label="Fix & Verify"'));
});

// ================================================= responsive et theme

test('le shell ne cache jamais le contenu sous la navigation', () => {
  const source = dashboardSource();
  // Une grille, pas un positionnement absolu : la colonne principale ne peut pas
  // passer sous la barre laterale.
  assert.match(source, /\.sc-app-shell \{ display: grid; grid-template-columns: minmax\(190px, 208px\) minmax\(0, 1fr\)/);
  assert.match(source, /\.sc-main \{[^}]*min-width: 0;/, 'la colonne principale doit pouvoir retrecir');
  assert.match(source, /body\.surface-full, body\.sc-shelled \{[^}]*overflow-x: hidden/);
});

test('les points de rupture degradent la navigation sans la supprimer', () => {
  const source = dashboardSource();
  // Large : trois colonnes. Moyen : le rail contextuel disparait.
  assert.match(source, /@media \(max-width: 1200px\) \{[\s\S]{0,400}\.sc-companion-rail \{ display: none; \}/);
  // Plus etroit : la navigation devient un rail d icones, elle ne disparait pas.
  assert.match(source, /\.sc-app-shell,\s*\.sc-app-shell\.sc-app-shell-norail \{ grid-template-columns: 64px minmax\(0, 1fr\); \}/);
});

test('la navigation n utilise que des jetons semantiques', () => {
  const shell = fs.readFileSync(path.join(__dirname, '..', 'src', 'security-center-shell.js'), 'utf8');
  const css = shell.slice(shell.indexOf('.sc-internal-nav {'), shell.indexOf('.sc-main {'));
  assert.ok(css.length > 200, 'le bloc CSS de navigation doit exister');
  // Aucune couleur litterale : tout passe par --sc-*.
  assert.ok(!/#[0-9a-f]{3,8}/i.test(css), 'aucune couleur codee en dur dans la navigation');
  assert.match(css, /var\(--sc-border\)/);
  assert.match(css, /var\(--sc-muted\)/);
  assert.match(css, /var\(--sc-primary\)/);
});

test('les jetons existent en clair et en sombre', () => {
  const source = dashboardSource();
  for (const token of ['--sc-bg', '--sc-surface', '--sc-border', '--sc-text', '--sc-muted', '--sc-primary']) {
    assert.match(source, new RegExp(`${token}:`), `${token} absent`);
  }
  // Le theme sombre redefinit la palette plutot que de la subir.
  const dark = source.slice(source.indexOf('body.theme-dark {'));
  const darkBlock = dark.slice(0, dark.indexOf('}'));
  for (const token of ['--sc-bg', '--sc-surface', '--sc-text', '--sc-primary']) {
    assert.ok(darkBlock.includes(token), `${token} n est pas redefini en sombre`);
  }
  assert.match(darkBlock, /color-scheme: dark/);
});

test('la navigation se rend dans les deux themes sans changer de structure', () => {
  const light = html('full', 'light');
  const dark = html('full', 'dark');
  assert.equal(navItems(light).length, navItems(dark).length);
  assert.match(light, /class="theme-light"|theme-light/);
  assert.match(dark, /theme-dark/);
});

// ================================================= perimetre

test('la navigation ne vit que dans le dashboard complet', () => {
  // La sidebar reste une bande etroite : l arbre des vulnerabilites a la place.
  // On teste le balisage rendu, pas la chaine : la feuille de style declare la
  // classe sur toutes les surfaces sans que la navigation y soit rendue.
  assert.ok(!/<aside class="sc-internal-nav/.test(html('sidebar')));
  assert.equal(navItems(html('sidebar')).length, 0);
  assert.match(html('full'), /<aside class="sc-internal-nav/);
});

test('le rail contextuel n invente aucune donnee', () => {
  const source = dashboardSource();
  const rail = source.slice(source.indexOf('sc-companion-rail" aria-label'), source.indexOf('</aside></div>'));
  // Il ne montre que des faits deja portes par le modele du dashboard.
  assert.match(rail, /scanStatusLabel/);
  assert.match(rail, /model\.backendStatus/);
  // Aucun finding, aucune alerte, aucun message IA fabrique.
  assert.ok(!/Math\.random|lorem|placeholder|TODO/i.test(rail));
});
