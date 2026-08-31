const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SOURCE, SOURCE_STATE, classifySourceFailure, mergeSourceDocuments, collectLicenseSources
} = require('../src/supply-chain/license-sources');
const { analyzeLicenses, renderLicenseReportHtml } = require('../src/license-compliance');

const WORKSPACE_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: [
    { name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', licenses: [{ license: { id: 'MIT' } }] },
    { name: 'copyleft-lib', version: '1.0.0', purl: 'pkg:npm/copyleft-lib@1.0.0', licenses: [{ expression: 'GPL-3.0-only' }] }
  ]
};
const IMAGE_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: [
    { name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', licenses: [{ license: { id: 'MIT' } }] },
    { name: 'openssl', version: '3.0.11', purl: 'pkg:deb/openssl@3.0.11', licenses: [{ license: { id: 'Apache-2.0' } }] }
  ]
};

// Le message réel produit quand aucun moteur de conteneur ne répond : il
// contient AUSSI « unable to find the specified image ».
const NO_ENGINE = [
  'unable to initialize container image',
  'unable to find the specified image "bkimminich/juice-shop:latest"',
  'docker API unavailable',
  'containerd socket not found',
  'podman socket not found'
].join('\n');

function generatorFor(map) {
  return async ({ imageName }) => {
    const key = String(imageName || '').trim() ? 'image' : 'workspace';
    const outcome = map[key];
    if (outcome instanceof Error) throw outcome;
    return { payload: outcome, mode: 'local' };
  };
}

test('un moteur de conteneur absent est un défaut de prérequis, pas une cible introuvable', () => {
  assert.equal(classifySourceFailure(NO_ENGINE), SOURCE_STATE.RUNTIME_UNAVAILABLE);
  assert.equal(classifySourceFailure('Ni Trivy local ni Docker ne sont disponibles.'), SOURCE_STATE.RUNTIME_UNAVAILABLE);
});

test('une image absente d’un moteur joignable reste une cible introuvable', () => {
  assert.equal(
    classifySourceFailure('unable to find the specified image "ghcr.io/acme/app:1.0"'),
    SOURCE_STATE.TARGET_NOT_FOUND
  );
});

test('une erreur quelconque n’est pas requalifiée en prérequis manquant', () => {
  assert.equal(classifySourceFailure('Trivy n’a pas produit un document CycloneDX valide.'), SOURCE_STATE.FAILED);
});

test('Docker indisponible : le workspace est analysé, l’image est signalée, rien n’est mis à zéro', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: new Error(NO_ENGINE) })
  });
  const workspace = collected.sources.find((entry) => entry.source === SOURCE.WORKSPACE);
  const image = collected.sources.find((entry) => entry.source === SOURCE.IMAGE);

  assert.equal(workspace.state, SOURCE_STATE.ANALYZED);
  assert.equal(workspace.componentCount, 2);
  assert.equal(image.state, SOURCE_STATE.RUNTIME_UNAVAILABLE);
  // Le point central : une source non analysée n'a pas d'inventaire, pas un
  // inventaire vide.
  assert.equal(image.componentCount, null);
  assert.equal(collected.analyzable, true);
  assert.equal(collected.degraded, true);
});

test('image inexistante : l’état distingue la cible du moteur', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'ghcr.io/acme/absent:9',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: new Error('unable to find the specified image "ghcr.io/acme/absent:9"') })
  });
  const image = collected.sources.find((entry) => entry.source === SOURCE.IMAGE);
  assert.equal(image.state, SOURCE_STATE.TARGET_NOT_FOUND);
  assert.equal(image.target, 'ghcr.io/acme/absent:9');
  assert.equal(collected.analyzable, true);
});

test('aucune image configurée : non configuré, et ce n’est pas une dégradation', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: '',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: new Error('jamais appelé') })
  });
  const image = collected.sources.find((entry) => entry.source === SOURCE.IMAGE);
  assert.equal(image.state, SOURCE_STATE.NOT_CONFIGURED);
  assert.equal(image.componentCount, null);
  assert.equal(collected.analyzable, true);
  // Non configuré n'est pas une erreur : le rapport n'est pas dégradé.
  assert.equal(collected.degraded, false);
});

test('workspace disponible et image indisponible : le contrôle de licences aboutit quand même', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: new Error(NO_ENGINE) })
  });
  const report = analyzeLicenses(collected.document, ['GPL-3.0'], collected.sources);
  assert.equal(report.analyzed, true);
  assert.equal(report.compliant, false);
  assert.equal(report.counts.denied, 1);
});

test('moteur présent et image disponible : les deux inventaires sont fusionnés et dédupliqués', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: IMAGE_SBOM })
  });
  assert.equal(collected.degraded, false);
  assert.equal(collected.sources.every((entry) => entry.analyzed), true);
  // express est présent dans les deux inventaires : un composant, pas deux.
  assert.equal(collected.document.components.length, 3);
  const purls = collected.document.components.map((component) => component.purl);
  assert.equal(new Set(purls).size, 3);
});

test('aucune source analysable : la conformité est indéterminée, jamais conforme', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: new Error(NO_ENGINE), image: new Error(NO_ENGINE) })
  });
  assert.equal(collected.analyzable, false);
  assert.equal(collected.document, null);

  const report = analyzeLicenses({ components: [] }, ['GPL-3.0'], collected.sources);
  assert.equal(report.analyzed, false);
  // Ni true ni false : la conformité n'a pas été établie.
  assert.equal(report.compliant, null);
  assert.notEqual(report.compliant, true);
});

test('la page annonce une conformité non établie et n’affiche pas zéro pour une source non analysée', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: new Error(NO_ENGINE), image: new Error(NO_ENGINE) })
  });
  const report = analyzeLicenses({ components: [] }, [], collected.sources);
  const html = renderLicenseReportHtml(report, 'nonce', 'light');
  assert.match(html, /Conformité non établie/);
  assert.match(html, /Moteur de conteneur inaccessible/);
  assert.doesNotMatch(html, /Aucune licence interdite détectée/);
});

test('la page nomme la source indisponible sans invalider celle qui a réussi', async () => {
  const collected = await collectLicenseSources({
    workspacePath: '/w', imageName: 'bkimminich/juice-shop:latest',
    generate: generatorFor({ workspace: WORKSPACE_SBOM, image: new Error(NO_ENGINE) })
  });
  const report = analyzeLicenses(collected.document, [], collected.sources);
  const html = renderLicenseReportHtml(report, 'nonce', 'light');
  assert.match(html, /Aucune licence interdite détectée/);
  assert.match(html, /Sources d’analyse/);
  assert.match(html, /Moteur de conteneur inaccessible/);
  assert.match(html, /2 composant\(s\)/);
});

test('la fusion ignore les sources non analysées au lieu de les compter vides', () => {
  const merged = mergeSourceDocuments([
    { analyzed: true, document: WORKSPACE_SBOM },
    { analyzed: false, document: null }
  ]);
  assert.equal(merged.components.length, 2);
  assert.equal(mergeSourceDocuments([{ analyzed: false, document: null }]), null);
});

test('l’appel historique sans sources conserve son comportement', () => {
  const report = analyzeLicenses(WORKSPACE_SBOM, ['GPL-3.0']);
  assert.equal(report.analyzed, true);
  assert.equal(report.compliant, false);
  assert.deepEqual(report.sources, []);
});
