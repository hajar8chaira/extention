'use strict';

/**
 * L'identité SCenter, vérifiée là où elle est censée apparaître — et là où
 * elle est censée ne pas apparaître.
 *
 * Un logo est le genre de changement qui se dégrade en silence : une URI non
 * résolue, une CSP qui bloque l'image, une racine de ressources oubliée, et la
 * marque disparaît sans qu'aucun test ne tombe. Ces tests décrivent donc les
 * deux moitiés du contrat :
 *
 *   - le hibou est rendu aux trois emplacements d'identité produit ;
 *   - il ne remplace ni un outil, ni un fournisseur, ni le compagnon, ni un
 *     filigrane décoratif.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const manifest = require('../package.json');
const expectedExtensionVersion = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version;
const { renderSidebarLauncherHtml } = require('../src/sidebar-launcher');
const { renderSecurityCenterShell } = require('../src/security-center-shell');
const { renderDashboardHtml, buildDashboardModel } = require('../src/dashboard');

const root = path.join(__dirname, '..');
const brandingDir = path.join(root, 'media', 'branding');

/** Une URI de webview a la forme que VS Code produit, jamais un chemin de fichier. */
const BRAND_URI = 'https://file%2B.vscode-resource.vscode-cdn.net/media/branding/secenter-icon-256.png';

/** Lit la taille d'un PNG dans son en-tête IHDR, sans dépendance. */
function pngSize(file) {
  const header = fs.readFileSync(file).subarray(16, 24);
  return { width: header.readUInt32BE(0), height: header.readUInt32BE(4) };
}

// ------------------------------------------------------------- les fichiers

test('les sources de marque sont présentes et carrées', () => {
  for (const name of ['secenter-icon.png', 'secenter-logo.png']) {
    const file = path.join(brandingDir, name);
    assert.ok(fs.existsSync(file), `${name} est absent`);
    const { width, height } = pngSize(file);
    assert.equal(width, height, `${name} n'est pas carré (${width}x${height})`);
  }
});

test('les dérivés existent aux dimensions exactes et sans déformation', () => {
  for (const size of [128, 256]) {
    const file = path.join(brandingDir, `secenter-icon-${size}.png`);
    assert.ok(fs.existsSync(file), `secenter-icon-${size}.png est absent`);
    assert.deepEqual(pngSize(file), { width: size, height: size });
  }
});

test('aucun dérivé superflu ne s’accumule dans le dossier de marque', () => {
  const files = fs.readdirSync(brandingDir).sort();
  // Quatre images de marque, plus la variante technique monochrome destinee a la
  // seule barre d'activites. Rien d'autre ne doit s'accumuler ici.
  assert.deepEqual(files, [
    'secenter-activitybar.svg',
    'secenter-icon-128.png', 'secenter-icon-256.png', 'secenter-icon.png', 'secenter-logo.png'
  ]);
});

// ---------------------------------------------------------------- manifeste

test('le manifeste porte l’icône SCenter sans casser la compatibilité', () => {
  assert.equal(manifest.icon, 'media/branding/secenter-icon-128.png');
  assert.ok(fs.existsSync(path.join(root, manifest.icon)), 'l’icône déclarée n’existe pas sur disque');
  assert.deepEqual(pngSize(path.join(root, manifest.icon)), { width: 128, height: 128 });
  assert.equal(manifest.displayName, 'SCenter — Security Center DevSecOps');
  // L'identité technique ne bouge pas : une extension déjà installée doit
  // continuer à être la même extension après cette mise à jour.
  assert.equal(manifest.name, 'security-center-vscode');
  assert.equal(manifest.publisher, 'ChairaHajar');
  assert.equal(manifest.version, expectedExtensionVersion);
});

test('la barre d activites emploie la variante SVG monochrome, jamais un PNG', () => {
  const container = manifest.contributes.viewsContainers.activitybar
    .find((entry) => entry.id === 'securityCenter');
  assert.ok(container, 'le conteneur de vues doit exister');
  assert.equal(container.title, 'SCenter');

  // Un PNG couleur y rend un carre clair qui ignore le theme : cette surface
  // exige un trace monochrome que VS Code recolore lui-meme.
  assert.equal(container.icon, 'media/branding/secenter-activitybar.svg');
  assert.doesNotMatch(container.icon, /\.png$/i, 'un retour au PNG casse le rendu de la barre');
  assert.ok(fs.existsSync(path.join(root, container.icon)), 'l icone declaree doit exister');
});

test('le SVG de la barre d activites herite de la couleur du theme et ne fige rien', () => {
  const svg = fs.readFileSync(path.join(root, 'media/branding/secenter-activitybar.svg'), 'utf8');

  // La seule couleur admise est celle que l'hote injecte.
  assert.match(svg, /currentColor/, 'sans currentColor l icone ignore le theme');
  assert.doesNotMatch(svg, /#[0-9a-f]{3,8}\b/i, 'aucune couleur hexadecimale figee');
  assert.doesNotMatch(svg, /rgba?\(/i, 'aucune couleur rgb figee');

  // Rien qui ne survivrait pas a 16 px ou a un changement de theme.
  for (const forbidden of [/<image\b/i, /Gradient\b/i, /<filter\b/i, /<text\b/i, /base64/i, /<rect\b/i]) {
    assert.doesNotMatch(svg, forbidden, `element interdit dans l icone : ${forbidden}`);
  }

  // Carre, compact, et sans fond peint.
  assert.match(svg, /viewBox="0 0 24 24"/);
  assert.match(svg, /fill="none"/);
  assert.ok(svg.length < 2048, `SVG trop lourd (${svg.length} o) pour une icone de barre`);
  const paths = (svg.match(/<path\b/g) || []).length;
  assert.ok(paths > 0 && paths <= 6, `${paths} paths : une icone de barre doit rester simple`);
});

test('la variante technique ne remplace le logo couleur sur aucune autre surface', () => {
  // Marketplace : le PNG couleur reste l identite officielle.
  assert.equal(manifest.icon, 'media/branding/secenter-icon-128.png');

  // Webviews : la marque servie reste le PNG 256, pas le trace monochrome.
  const extension = fs.readFileSync(path.join(root, 'src', 'extension.js'), 'utf8');
  assert.match(extension, /secenter-icon-256\.png/);
  assert.doesNotMatch(extension, /secenter-activitybar/, 'la variante barre ne doit pas fuiter dans les webviews');

  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /secenter-logo\.png/, 'le README garde le lockup couleur');
  assert.doesNotMatch(readme, /secenter-activitybar/);
});

test('aucune regle .vscodeignore ne prive le paquet des assets de marque', () => {
  const ignore = fs.readFileSync(path.join(root, '.vscodeignore'), 'utf8');
  const rules = ignore.split('\n').map((entry) => entry.trim())
    .filter((entry) => entry && !entry.startsWith('#') && !entry.startsWith('!'));
  // Une regle large sur les medias emporterait logos de scanners, compagnon et
  // marque d'un seul coup : c'est la panne silencieuse a interdire.
  for (const rule of rules) {
    assert.ok(!/^media(\/\*\*)?$/.test(rule), `.vscodeignore exclut tout l arbre media via ${rule}`);
    assert.ok(!/^media\/branding(\/\*\*)?$/.test(rule), `.vscodeignore exclut la marque via ${rule}`);
  }
  // Les quatre fichiers de marque sont livres : les deux derives consommes par
  // le manifeste et les webviews, le lockup du README, et la source qui permet
  // de regenerer les derives sans retrouver l'original ailleurs.
  for (const shipped of ['secenter-icon.png', 'secenter-icon-128.png', 'secenter-icon-256.png', 'secenter-logo.png']) {
    assert.ok(!rules.includes(`media/branding/${shipped}`), `${shipped} doit rester dans le paquet`);
  }
});

// ------------------------------------------------- les trois emplacements

test('barre latérale : le hibou remplace la marque vectorielle quand il est résolu', () => {
  const model = buildDashboardModel([], []);
  const withLogo = renderSidebarLauncherHtml(model, 'nonce', 'light', {}, {
    brandLogoUri: BRAND_URI, cspSource: 'https://*.vscode-cdn.net'
  });
  assert.match(withLogo, /class="brand-mark brand-mark-logo"/);
  assert.ok(withLogo.includes(BRAND_URI), 'l’URI de marque n’est pas rendue');
  assert.match(withLogo, /<strong>SCenter<\/strong>/);
  // La CSP doit autoriser l'origine, sinon l'image est bloquée à l'affichage.
  assert.match(withLogo, /img-src https:\/\/\*\.vscode-cdn\.net/);
});

test('barre latérale : sans URI résolue, la marque vectorielle reste', () => {
  const html = renderSidebarLauncherHtml(buildDashboardModel([], []), 'nonce', 'light', {}, {});
  assert.doesNotMatch(html, /class="brand-mark brand-mark-logo"/);
  assert.doesNotMatch(html, /<img[^>]*secenter/i, 'aucune image cassée ne doit être rendue');
  assert.match(html, /<strong>SCenter<\/strong>/, 'le nom du produit reste, même sans logo');
});

test('rail partagé : le hibou est rendu, et seulement quand la page peut l’afficher', () => {
  const withLogo = renderSecurityCenterShell({
    surface: 'trends', nonce: 'n', content: '<p>x</p>',
    brandLogoUri: BRAND_URI, cspSource: 'https://*.vscode-cdn.net'
  });
  assert.match(withLogo, /<img class="sc-nav-logo"/);
  assert.ok(withLogo.includes(BRAND_URI));
  assert.match(withLogo, /<strong>SCenter<\/strong>/);
  assert.match(withLogo, /img-src https:\/\/\*\.vscode-cdn\.net/);

  const withoutLogo = renderSecurityCenterShell({ surface: 'trends', nonce: 'n', content: '<p>x</p>' });
  assert.doesNotMatch(withoutLogo, /<img class="sc-nav-logo"/);
  assert.match(withoutLogo, /<strong>SCenter<\/strong>/);
});

test('dashboard : le hibou occupe la marque produit du hero', () => {
  const model = buildDashboardModel([], []);
  const html = renderDashboardHtml(model, 'nonce', 'full', 'light', {}, {
    brandLogoUri: BRAND_URI, cspSource: 'https://*.vscode-cdn.net', scannerLogoUris: {}
  });
  assert.match(html, /class="security-shield security-shield-logo"/);
  assert.ok(html.includes(BRAND_URI));
  assert.match(html, /<h2>Security Center<\/h2>/);
  assert.match(html, /Security Center DevSecOps/, 'le sens de la marque reste affiché');
});

test('toute page qui emploie le rail partage transmet la marque au cadre', () => {
  // Le rail est un composant commun : si une page oublie de lui passer l URI,
  // la meme barre affiche le hibou ailleurs et le pictogramme ici. Sept pages
  // etaient dans ce cas, et servaient leur contenu sans `img-src`.
  const sourceRoot = path.join(root, 'src');
  const offenders = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) { walk(target); continue; }
      if (!entry.name.endsWith('.js')) continue;
      const source = fs.readFileSync(target, 'utf8');
      if (!source.includes('renderSecurityCenterShell(')) continue;
      if (entry.name === 'security-center-shell.js') continue;
      if (!source.includes('brandLogoUri')) offenders.push(path.relative(sourceRoot, target));
    }
  };
  walk(sourceRoot);
  assert.deepEqual(offenders, [], 'ces pages emploient le rail sans lui donner la marque');
});

test('la marque courte tient les espaces compacts, le nom complet tient les titres', () => {
  const model = buildDashboardModel([], [], { workspace: 'juice-shop' });
  const assets = { brandLogoUri: BRAND_URI, cspSource: 'https://*.vscode-cdn.net', scannerLogoUris: {} };

  // COMPACT : barre laterale, rail, en-tete etroit du dashboard.
  const sidebar = renderSidebarLauncherHtml(model, 'n', 'light', {}, assets);
  const rail = renderSecurityCenterShell({ surface: 'trends', nonce: 'n', content: '<p></p>', ...assets });
  const compact = renderDashboardHtml(model, 'n', 'compact', 'light', {}, assets);
  for (const [name, html] of [['barre laterale', sidebar], ['rail', rail], ['en-tete compact', compact]]) {
    assert.match(html, /SCenter/, `${name} doit porter la marque courte`);
    assert.doesNotMatch(html, /Secenter/, `${name} garde l ancienne orthographe`);
  }

  // TITRE PRODUIT : le hero garde le nom complet, plus lisible et institutionnel.
  const hero = renderDashboardHtml(model, 'n', 'full', 'light', {}, assets);
  assert.match(hero, /<h2>Security Center<\/h2>/, 'le hero nomme le produit en entier');
  assert.match(hero, /Security Center DevSecOps/, 'le badge conserve la mention complete');

  // Le manifeste porte les deux : marque courte puis nom fonctionnel.
  assert.equal(manifest.displayName, 'SCenter — Security Center DevSecOps');
  assert.equal(manifest.contributes.viewsContainers.activitybar[0].title, 'SCenter');
});

// ------------------------------------------- ce qui ne doit PAS être remplacé

test('les logos d’outils et de fournisseurs gardent leur propre identité', () => {
  const extension = fs.readFileSync(path.join(root, 'src', 'extension.js'), 'utf8');
  // Chaque outil garde son fichier : le hibou n'est l'identité d'aucun d'eux.
  for (const file of ['semgrep.svg', 'gitleaks.svg', 'trivy.svg', 'osv-scanner.svg', 'sonarqube.svg', 'snyk.svg', 'zap.png']) {
    assert.ok(extension.includes(file), `le logo ${file} a disparu`);
  }
  assert.ok(extension.includes('security-companion.png'), 'le compagnon garde son avatar');
  assert.doesNotMatch(extension, /jenkins.*secenter|secenter.*jenkins/i);
});

test('le filigrane de marque est reserve au hero, jamais derriere les donnees', () => {
  // Le hero porte la signature du produit. Les autres filigranes — page,
  // findings, detail de scanner, domaines — sont decoratifs et restent sur le
  // pictogramme neutre : un hibou derriere un tableau de resultats ou des
  // chiffres critiques gene la lecture sans rien signifier de plus.
  for (const relative of ['src/dashboard.js', 'src/security-center-shell.js', 'src/enterprise-domain-pages.js', 'src/finding-details.js']) {
    const source = fs.readFileSync(path.join(root, relative), 'utf8');
    for (const match of source.match(/[a-z-]*watermark[^\n]*/g) || []) {
      if (match.includes('hero-brand-watermark')) continue;
      assert.doesNotMatch(match, /brandLogoUri|secenter/i, `${relative} met la marque dans un filigrane decoratif`);
    }
  }
});

test('le hero porte le filigrane hibou, discret et hors du flux de lecture', () => {
  const model = buildDashboardModel([], [], { workspace: 'juice-shop' });
  const html = renderDashboardHtml(model, 'n', 'full', 'light', {}, { brandLogoUri: BRAND_URI, cspSource: 'https://*.vscode-cdn.net', scannerLogoUris: {} });
  assert.match(html, /<img class="hero-brand-watermark"[^>]*aria-hidden="true"/);
  assert.ok(html.includes(BRAND_URI));

  const css = (html.match(/\.hero-brand-watermark \{[^\}]*\}/) || [''])[0];
  assert.match(css, /position: absolute/);
  assert.match(css, /pointer-events: none/, 'le filigrane ne doit jamais intercepter un clic');
  assert.match(css, /bottom:/, 'la signature est ancree en bas a droite');
  assert.match(css, /right:/);
  // Assez visible pour signer, assez pale pour ne rien masquer.
  const opacity = Number((css.match(/opacity: ([0-9.]+)/) || [0, 1])[1]);
  assert.ok(opacity > 0 && opacity <= 0.08, `opacite ${opacity} hors de la plage discrete attendue`);
  // Le contenu du hero passe explicitement au-dessus du filigrane.
  assert.match(html, /\.security-hero-copy, \.security-hero-metrics \{ position: relative; z-index: 1; \}/);

  // Sans URI resolue, aucun cadre vide n'est rendu.
  const bare = renderDashboardHtml(model, 'n', 'full', 'light', {}, { scannerLogoUris: {} });
  assert.doesNotMatch(bare, /<img class="hero-brand-watermark"/);
});

// ------------------------------------------------- résolution des ressources

test('la marque passe par le mécanisme de ressources du webview, jamais par un chemin disque', () => {
  const extension = fs.readFileSync(path.join(root, 'src', 'extension.js'), 'utf8');
  assert.match(extension, /brandingAssetRoot/, 'la racine de marque doit être déclarée');
  assert.match(extension, /brandLogoUri: webview\.asWebviewUri/, 'l’URI doit être résolue par le webview');
  assert.match(extension, /localResourceRoots: \[companionAssetRoot, scannerAssetRoot, providerAssetRoot, brandingAssetRoot\]/);
  // Un chemin de fichier local dans un webview ne se charge pas après installation.
  assert.doesNotMatch(extension, /file:\/\/\/[^\n]*branding/);
  assert.doesNotMatch(extension, /[A-Za-z]:\\\\[^\n]*branding/);
});
