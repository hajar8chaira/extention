'use strict';

/**
 * Runtime Security — configuration workspace layout.
 *
 * A layout pass, so what these tests mostly protect is what did NOT change:
 * the catalogue is still the source of providers, the form is still built from
 * the selected provider's schema, and nothing about a specific vendor decides
 * where anything is drawn.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { renderRuntimeSecurityPageHtml: renderRuntimePage, renderInfrastructurePageHtml, domainCss } = require('../src/enterprise-domain-pages');
// Depuis que l'historique d'alertes vient du moteur de recherche du
// fournisseur et non de son API de gestion, la page a besoin de la preuve
// d'execution qu'une sonde reussie fournit. Les tests qui examinent un etat
// degrade passent la leur et gagnent.
const READY_EVIDENCE = Object.freeze({ alerts: { state: 'ready' }, mitre: { state: 'ready' } });
function renderRuntimeSecurityPageHtml(model = {}, nonce = '', theme = 'light') {
  return renderRuntimePage({ capabilityEvidence: READY_EVIDENCE, ...model }, nonce, theme);
}
function renderRuntimeSecurityPageHtmlWithAssets(model = {}, assets = {}) {
  return renderRuntimePage({ capabilityEvidence: READY_EVIDENCE, ...model }, 'n', 'light', assets);
}

const { SIEM_PROVIDERS, siemProvider } = require('../src/integrations/siem');
const { CONFIG_GROUP, fieldsInGroup } = require('../src/integrations/siem-contract');

const repoRoot = path.join(__dirname, '..');
const pagesSource = () => fs.readFileSync(path.join(repoRoot, 'src', 'enterprise-domain-pages.js'), 'utf8');

/** Markup only: the stylesheet is asserted separately, through `domainCss()`. */
function markup(html) {
  return html.slice(html.indexOf('</style>'), html.lastIndexOf('<script'));
}

function setupPage(model = {}) {
  return markup(renderRuntimeSecurityPageHtml(model, 'n', 'light'));
}

/** The setup state, with one provider selected — the form under test. */
function formFor(providerId) {
  return setupPage({
    runtime: { configured: false, provider: providerId, label: siemProvider(providerId)?.label || providerId }
  });
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

test('layout : le choix et la configuration sont deux volets d une seule carte', () => {
  const html = setupPage();
  // Une carte, pas deux : la relation « fournisseur -> configuration » se lit.
  assert.equal((html.match(/class="domain-card setup-card config-workspace-card"/g) || []).length, 1);
  assert.equal((html.match(/class="config-workspace"/g) || []).length, 1);
  assert.match(html, /class="config-pane config-pane-catalogue"/);
  assert.match(html, /class="config-pane config-pane-form"/);
  // Le catalogue precede le formulaire : c est aussi l ordre en une colonne.
  assert.ok(html.indexOf('config-pane-catalogue') < html.indexOf('config-pane-form'));
  // Le catalogue vit dans le volet de gauche, le formulaire dans celui de droite.
  const catalogue = html.slice(html.indexOf('config-pane-catalogue'), html.indexOf('config-pane-form'));
  assert.match(catalogue, /class="provider-catalogue"/);
  assert.doesNotMatch(catalogue, /data-action="saveRuntimeConfig"/);
});

test('layout : la carte de configuration prend la largeur de la page', () => {
  const css = domainCss();
  // L ancienne colonne etroite laissait la moitie droite vide.
  assert.match(css, /\.setup-card\.config-workspace-card\{[^}]*width:min\(100%,1320px\)/);
  assert.match(css, /\.setup-card\.config-workspace-card\{[^}]*max-width:1320px/);
  assert.match(css, /\.setup-card\.config-workspace-card\{[^}]*margin:0 auto/);
  assert.ok(
    css.indexOf('.setup-card.config-workspace-card') < css.indexOf('.setup-card{max-width:760px}'),
    'la regle dediee doit etre assez specifique pour battre .setup-card'
  );
  assert.match(css, /\.domain-layout\.single\.wide\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(setupPage(), /class="domain-layout single wide"/);
  // Et la contrainte d origine reste en place pour les autres surfaces.
  assert.match(css, /\.domain-layout\.single\{grid-template-columns:minmax\(0,760px\)\}/);
});

test('layout : les deux colonnes gardent les proportions demandees', () => {
  const css = domainCss();
  const columns = css.match(/\.config-workspace\{[^}]*grid-template-columns:minmax\(0,(\d+)fr\) minmax\(0,(\d+)fr\)/);
  assert.ok(columns, 'la grille declare deux colonnes proportionnelles');
  const [left, right] = [Number(columns[1]), Number(columns[2])];
  const share = left / (left + right);
  assert.ok(share >= 0.32 && share <= 0.36, `le catalogue occupe ${Math.round(share * 100)}%, attendu 32-36%`);
  // Un filet, pas un fosse : les volets restent solidaires.
  assert.match(css, /\.config-pane-form\{[^}]*border-left:1px solid var\(--sc-border\)/);
});

test('layout : sous une petite largeur la grille repasse en une colonne', () => {
  const css = domainCss();
  const query = css.match(/@media\(max-width:900px\)\{[\s\S]*?\n  \}/);
  assert.ok(query, 'un point de rupture existe');
  assert.match(query[0], /\.config-workspace\{grid-template-columns:minmax\(0,1fr\)\}/);
  // Le filet vertical devient une separation horizontale plutot que du vide.
  assert.match(query[0], /\.config-pane-form\{[^}]*border-left:0/);
  assert.match(query[0], /border-top:1px solid var\(--sc-border\)/);
  // Rien ne peut deborder horizontalement : chaque volet peut retrecir.
  assert.match(css, /\.config-pane\{[^}]*min-width:0/);
  assert.match(css, /\.config-field input\{width:100%\}/);
  assert.match(css, /\.provider-option \.provider-note\{[^}]*overflow:hidden/);
});

test('layout : le catalogue defile avec la page, pas dans une fenetre interne', () => {
  const css = domainCss();
  const pane = css.match(/\.config-pane-catalogue\{([^}]*)\}/)[1];
  assert.doesNotMatch(pane, /max-height/);
  assert.doesNotMatch(pane, /overflow-y:auto/);
  assert.match(pane, /overflow:visible/);
});

test('layout : les rangees du catalogue sont plus denses sans etre serrees', () => {
  const css = domainCss();
  const row = css.match(/\.provider-option\{([^}]*)\}/)[1];
  const padding = row.match(/padding:(\d+)px (\d+)px/);
  assert.ok(padding, 'la rangee declare son rembourrage');
  assert.ok(Number(padding[1]) < 10, 'moins haut qu avant');
  assert.ok(Number(padding[1]) >= 6, 'mais toujours respirable');
  assert.match(row, /min-height:50px/);
  assert.match(css, /\.provider-option:hover\{/);
  // Le nom, la description et le bouton radio sont tous conserves.
  const html = setupPage();
  const first = html.match(/<label class="provider-option[\s\S]*?<\/label>/)[0];
  assert.match(first, /<input type="radio" name="runtime-provider-choice"/);
  assert.match(first, /<span class="provider-name">/);
  assert.match(first, /<span class="provider-note">/);
});

test('layout : les logos fournisseurs locaux decorent le catalogue et l entete', () => {
  const html = markup(renderRuntimeSecurityPageHtmlWithAssets({
    runtime: { configured: false, provider: 'wazuh', label: 'Wazuh' }
  }, {
    cspSource: 'https://*.vscode-cdn.net',
    providerLogoUris: { wazuh: 'https://file+.vscode-resource.vscode-cdn.net/media/providers/wazuh.svg' }
  }));
  assert.match(html, /class="provider-mark"[\s\S]*<img class="provider-logo" src="https:\/\/file\+\.vscode-resource\.vscode-cdn\.net\/media\/providers\/wazuh\.svg" alt="Wazuh logo"/);
  assert.match(html, /class="provider-head-mark"[\s\S]*<img class="provider-logo" src="https:\/\/file\+\.vscode-resource\.vscode-cdn\.net\/media\/providers\/wazuh\.svg" alt="Wazuh logo"/);
  assert.doesNotMatch(html, /<img[^>]+src="https?:\/\/(?!file\+\.vscode-resource\.vscode-cdn\.net)/);
  const css = domainCss();
  assert.match(css, /\.provider-option\{[^}]*grid-template-columns:18px 30px minmax\(0,1fr\) auto/);
  assert.match(css, /\.provider-head-mark\{[^}]*width:38px/);
});

test('layout : Infrastructure rend les memes logos de fournisseur sans branche specifique', () => {
  const html = markup(renderInfrastructurePageHtml({
    prometheus: { configured: false, provider: 'prometheus', label: 'Prometheus' }
  }, 'n', 'light', {
    cspSource: 'https://*.vscode-cdn.net',
    providerLogoUris: { prometheus: 'https://file+.vscode-resource.vscode-cdn.net/media/providers/prometheus.svg' }
  }));
  assert.match(html, /name="observability-provider-choice"/);
  assert.match(html, /class="provider-mark"[\s\S]*media\/providers\/prometheus\.svg/);
  assert.match(html, /class="provider-head-mark"[\s\S]*media\/providers\/prometheus\.svg/);
  assert.doesNotMatch(html, /<img[^>]+src="https?:\/\/(?!file\+\.vscode-resource\.vscode-cdn\.net)/);
});

// ---------------------------------------------------------------------------
// Ce que la mise en page ne doit pas avoir change
// ---------------------------------------------------------------------------

test('layout : tous les fournisseurs viennent toujours du catalogue', () => {
  const html = setupPage();
  assert.equal((html.match(/name="runtime-provider-choice"/g) || []).length, SIEM_PROVIDERS.length);
  for (const provider of SIEM_PROVIDERS) {
    assert.ok(html.includes(provider.label), `${provider.id} doit rester propose`);
    assert.match(html, new RegExp(`value="${provider.id}"`));
  }
  // Aucun nom de fournisseur n est ecrit dans le rendu.
  const pages = pagesSource();
  for (const provider of SIEM_PROVIDERS) {
    assert.ok(!pages.includes(`'${provider.id}'`), `${provider.id} ne doit pas etre nomme dans le rendu`);
  }
});

test('layout : aucune condition propre a un fournisseur n a ete introduite', () => {
  const pages = pagesSource();
  const form = pages.match(/function runtimeConfigForm\([\s\S]*?\n}/)[0];
  assert.doesNotMatch(form, /wazuh|splunk|sentinel|elastic|qradar|chronicle|graylog|arcsight|sumologic/i);
  // La selection compare un identifiant a un autre : c est generique, et aucun
  // identifiant litteral n apparait — ce que la ligne precedente verifie.
  assert.doesNotMatch(form, /=== '[a-z]+'/);
  // Le groupe Advanced ne se nomme plus d apres un fournisseur.
  assert.doesNotMatch(pages, /Advanced\$\{/);
});

test('layout : le formulaire reste pilote par le schema du fournisseur choisi', () => {
  for (const provider of SIEM_PROVIDERS) {
    const html = formFor(provider.id);
    const rendered = [...html.matchAll(/id="runtime-([a-zA-Z]+)"/g)].map((match) => match[1]).filter((id) => id !== 'provider');
    const declared = provider.configurationFields.map((field) => field.id);
    assert.deepEqual(rendered.sort(), [...declared].sort(), `${provider.id} doit rendre exactement son schema`);
    // Le libelle du volet nomme le fournisseur choisi, depuis le catalogue,
    // sans branche fournisseur.
    assert.ok(html.includes(`<h4>${provider.label}</h4>`));
    assert.ok(html.includes(provider.summary));
  }
});

test('layout : changer de fournisseur remplace le formulaire de droite', () => {
  const [first, second] = [SIEM_PROVIDERS[0], SIEM_PROVIDERS.find((provider) => provider.id !== SIEM_PROVIDERS[0].id)];
  const firstOnly = first.configurationFields.map((field) => field.id)
    .filter((id) => !second.configurationFields.some((field) => field.id === id));
  const html = formFor(second.id);
  for (const id of firstOnly) {
    assert.doesNotMatch(html, new RegExp(`id="runtime-${id}"`), `${id} ne doit pas survivre au changement`);
  }
  assert.match(html, new RegExp(`value="${second.id}"[^>]*checked|checked[^>]*value="${second.id}"`));
});

test('layout : le groupe Advanced garde son repli et ses champs', () => {
  const provider = SIEM_PROVIDERS.find((entry) => fieldsInGroup(entry.configurationFields, CONFIG_GROUP.ADVANCED).length);
  assert.ok(provider, 'au moins un fournisseur declare un groupe avance');
  const html = formFor(provider.id);
  const advanced = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.ADVANCED);
  const primary = fieldsInGroup(provider.configurationFields, CONFIG_GROUP.PRIMARY);

  assert.match(html, /class="config-advanced-toggle" data-action="toggleAdvanced" aria-expanded="false">/);
  assert.match(html, /<span>Advanced<\/span>/);
  assert.match(html, /class="config-advanced-body" hidden/);
  assert.match(domainCss(), /\.config-advanced-body\[hidden\]\{display:none\}/);
  const body = html.match(/<div class="config-advanced-body" hidden>([\s\S]*?)<\/div>\s*<\/div>/)[1];
  for (const field of advanced) assert.match(body, new RegExp(`id="runtime-${field.id}"`), `${field.id} est dans le repli`);
  for (const field of primary) assert.doesNotMatch(body, new RegExp(`id="runtime-${field.id}"`), `${field.id} reste hors du repli`);
  // Le repli vit dans le volet de configuration, pas dans le catalogue.
  assert.ok(html.indexOf('config-pane-form') < html.indexOf('config-advanced'));
});

test('layout : les actions sont ancrees dans le volet de configuration', () => {
  const css = domainCss();
  assert.match(css, /\.config-pane-form \.domain-actions\{[^}]*justify-content:flex-end/);
  assert.match(css, /\.config-pane-form \.domain-actions\{[^}]*border-top:1px solid var\(--sc-border\)/);
  const html = formFor(SIEM_PROVIDERS[0].id);
  assert.ok(html.indexOf('config-pane-form') < html.indexOf('data-action="testRuntimeConfig"'));
  assert.ok(html.indexOf('data-action="saveRuntimeConfig"') < html.indexOf('</div>\n      </div>\n    </div>\n  </section>'));
});

test('layout : un fournisseur sans adaptateur ne peut toujours ni tester ni enregistrer', () => {
  for (const provider of SIEM_PROVIDERS) {
    const html = formFor(provider.id);
    if (provider.implemented) {
      assert.match(html, /data-action="testRuntimeConfig"/, `${provider.id} doit rester testable`);
      assert.match(html, /data-action="saveRuntimeConfig"/);
    } else {
      assert.doesNotMatch(html, /data-action="testRuntimeConfig"/, `${provider.id} ne doit pas etre testable`);
      assert.doesNotMatch(html, /data-action="saveRuntimeConfig"/);
      assert.ok(html.includes(`Security Center does not integrate ${provider.label} yet.`));
      // Aucun champ n est propose pour un fournisseur sans adaptateur.
      assert.doesNotMatch(html, /id="runtime-(?!provider)[a-zA-Z]+"/, `${provider.id} ne doit exposer aucun champ`);
    }
  }
});

test('layout : les secrets et les actions existantes sont intacts', () => {
  const target = SIEM_PROVIDERS.find((provider) => provider.configurationFields.some((field) => field.secret));
  const urlField = target.configurationFields.find((field) => field.type === 'url');
  const withSecret = setupPage({
    runtime: {
      configured: false, provider: target.id, label: target.label,
      values: { [urlField.id]: 'https://host.example.invalid:55000' },
      secretsConfigured: Object.fromEntries(target.configurationFields.filter((field) => field.secret).map((field) => [field.id, true]))
    }
  });
  // Un champ secret n a toujours aucune valeur, seulement un etat.
  assert.doesNotMatch(withSecret, /type="password"[^>]*value=/);
  assert.match(withSecret, /Credential configured in SecretStorage\./);
  assert.match(withSecret, /data-action="cancelConfig"/);
  // Et la valeur non secrete est bien rendue dans le volet de droite.
  assert.match(withSecret, /value="https:\/\/host\.example\.invalid:55000"/);
});

test('layout : le reste de la page Runtime Security est inchange', () => {
  const configured = setupPage({
    runtime: {
      configured: true, provider: 'wazuh', label: 'Wazuh', status: 'online', credentialsConfigured: true,
      agents: [], alerts: [],
      agentSummary: { active: 0, total: 0, disconnected: 0, neverConnected: 0 },
      alertSummary: { critical: 0, high: 0, medium: 0, low: 0 }
    }
  });
  // La navigation, la carte de connexion et l apercu ne bougent pas.
  assert.match(configured, /<h3>Connection<\/h3>/);
  assert.match(configured, /class="tabs"/);
  assert.match(configured, /<h3>Alert summary<\/h3>/);
  assert.match(configured, /<h3>Recent alerts<\/h3>/);
  // Le formulaire reste replie tant qu on ne l ouvre pas.
  assert.match(configured, /class="domain-card setup-card config-workspace-card" hidden/);
});

test('layout : aucune couleur ni police n a ete introduite', () => {
  const css = domainCss();
  const workspace = css.slice(css.indexOf('.config-workspace-card'), css.indexOf('.provider-catalogue'));
  // Rien que des jetons existants : pas de litteral de couleur.
  assert.doesNotMatch(workspace, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(workspace, /rgb\(|hsl\(/i);
  assert.doesNotMatch(workspace, /font-family/);
});
