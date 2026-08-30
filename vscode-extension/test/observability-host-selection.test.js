'use strict';

/**
 * Host selection — a scrape target is not a host.
 *
 * A real deployment exposed the defect: Prometheus scrapes itself and one
 * node_exporter. Both are healthy targets, so the inventory reads 2/2 UP — but
 * only one of them publishes `node_*` series. Selecting over the target list
 * therefore found « two hosts », refused to choose, and left CPU, memory, disk
 * and load reading « Unavailable » while the data was sitting in Prometheus the
 * whole time. The page was degraded, and the only thing wrong was the question
 * being asked.
 *
 * The rule these tests pin: **selection is over the hosts the host-metric
 * series actually name**. The inventory keeps every target, because « which
 * targets are healthy » and « which host can I read metrics for » are different
 * questions, and only the second one is a choice.
 *
 * Every address below is invented. No IP, port, job name or measurement from
 * any real deployment appears in this file.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { prometheusAdapter } = require('../src/integrations/observability-prometheus');
const {
  CAPABILITY, RESOLVED_STATE, METRIC_REASON, PROVIDER_STATUS, buildInfrastructureModel
} = require('../src/integrations/observability-contract');
const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

// Deux cibles fictives : l une expose des metriques d hote, l autre non.
const FICTIONAL = Object.freeze({
  endpoint: 'http://metrics.fixture.invalid:9090',
  selfTarget: 'self.fixture.invalid:9090',
  exporter: 'exporter-one.fixture.invalid:9100',
  otherExporter: 'exporter-two.fixture.invalid:9100'
});

const vector = (samples) => ({
  status: 'success',
  data: {
    resultType: 'vector',
    result: samples.map(([metric, value]) => ({ metric, value: [1700000000, String(value)] }))
  }
});

const target = (instance, job) => ({
  labels: { instance, job },
  health: 'up',
  scrapeUrl: `http://${instance}/metrics`,
  lastScrape: new Date().toISOString()
});

/**
 * A fake Prometheus.
 *
 * `targets` is the scrape list; `metricHosts` are the instances that actually
 * publish `node_*` series. Keeping the two separate is the whole point.
 */
function server({ targets = [], metricHosts = [], fail = [] } = {}) {
  const queries = [];
  async function request(url) {
    const parsed = new URL(url);
    if (parsed.pathname === '/api/v1/targets') {
      if (fail.includes('targets')) throw Object.assign(new Error('boom'), { code: 'QUERY_ERROR' });
      return { status: 'success', data: { activeTargets: targets } };
    }
    const query = parsed.searchParams.get('query') || '';
    queries.push(query);
    const per = (value) => vector(metricHosts.map((host) => [{ instance: host }, value]));
    if (query.includes('node_cpu')) return fail.includes('cpu') ? Promise.reject(Object.assign(new Error('boom'), { code: 'QUERY_ERROR' })) : per(12);
    if (query.includes('MemTotal')) return per(8 * 1024 ** 3);
    if (query.includes('MemAvailable')) return per(2 * 1024 ** 3);
    if (query.includes('node_filesystem_size')) return vector(metricHosts.map((host) => [{ instance: host, mountpoint: '/' }, 200 * 1024 ** 3]));
    if (query.includes('node_filesystem_avail')) return vector(metricHosts.map((host) => [{ instance: host, mountpoint: '/' }, 50 * 1024 ** 3]));
    if (query.includes('node_load1')) return per(0.75);
    return vector([]);
  }
  return { request, queries };
}

const read = (options = {}) => prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint }, {}, options);

/** The deployment that exposed the bug: one self-scrape, one exporter. */
const mixedEstate = () => server({
  targets: [target(FICTIONAL.selfTarget, 'prometheus'), target(FICTIONAL.exporter, 'node')],
  metricHosts: [FICTIONAL.exporter]
});

// ===========================================================================
// A scrape target is not a selectable host
// ===========================================================================

test('selection : la cible qui n expose aucune metrique d hote n est pas proposee au choix', async () => {
  const model = await read({ request: mixedEstate().request });

  // Le coeur de la regression : un seul hote *metrique*, donc aucun choix.
  assert.deepEqual(model.hosts, [FICTIONAL.exporter]);
  assert.equal(model.selectedEntity, FICTIONAL.exporter);
  assert.equal(model.selectionRequired, false);
  assert.equal(model.hostSelectionRequired, false);
  assert.equal(model.selectedHost, FICTIONAL.exporter);
});

test('selection : l inventaire garde toutes les cibles, 2/2 UP reste 2/2 UP', async () => {
  const model = await read({ request: mixedEstate().request });

  assert.equal(model.inventory.display, '2/2 UP');
  assert.equal(model.inventory.up, 2);
  assert.equal(model.inventory.total, 2);
  // Les deux cibles restent listees, y compris celle qu on ne peut pas choisir.
  assert.deepEqual(model.entities.map((entity) => entity.id).sort(), [FICTIONAL.exporter, FICTIONAL.selfTarget].sort());
  assert.equal(model.targets.items.length, 2);
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
});

test('selection : les valeurs reelles sont rendues, la page n est plus degradee', async () => {
  const model = await read({ request: mixedEstate().request });

  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(model.message, '');
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.metrics[capability].available, true, capability);
    assert.equal(model.capabilities[capability], RESOLVED_STATE.READY, capability);
  }
  assert.equal(model.metrics[CAPABILITY.CPU].display, '12%');
  assert.equal(model.metrics[CAPABILITY.DISK].display, '75%');
  assert.equal(model.metrics[CAPABILITY.LOAD].display, '0.75');
});

test('selection : aucun selecteur n est affiche quand il n y a rien a choisir', async () => {
  const model = await read({ request: mixedEstate().request });
  const html = renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light');

  assert.doesNotMatch(html, /id="observability-host"/);
  // Et la carte nomme l hote reellement lu.
  assert.ok(html.includes(FICTIONAL.exporter));
  assert.doesNotMatch(html, /Select a host to read its metrics/);
  assert.doesNotMatch(html, /choisissez celui a afficher/);
});

// ===========================================================================
// Several genuine metric hosts: the choice is real, and it is offered
// ===========================================================================

test('selection : plusieurs hotes metriques declenchent le choix explicite', async () => {
  const { request } = server({
    targets: [target(FICTIONAL.selfTarget, 'prometheus'), target(FICTIONAL.exporter, 'node'), target(FICTIONAL.otherExporter, 'node')],
    metricHosts: [FICTIONAL.exporter, FICTIONAL.otherExporter]
  });
  const model = await read({ request });

  assert.equal(model.selectionRequired, true);
  assert.equal(model.selectedEntity, '');
  assert.equal(model.status, PROVIDER_STATUS.DEGRADED);
  // Les deux hotes metriques sont proposes — et seulement eux.
  assert.deepEqual(model.hosts.sort(), [FICTIONAL.exporter, FICTIONAL.otherExporter].sort());
  assert.equal(model.hosts.includes(FICTIONAL.selfTarget), false, 'la cible sans metrique reste hors du choix');
  // Attendre un choix n est pas une panne : la capacite reste disponible.
  assert.equal(model.metrics[CAPABILITY.CPU].reason, METRIC_REASON.ENTITY_NOT_SELECTED);
  assert.equal(model.capabilities[CAPABILITY.CPU], RESOLVED_STATE.READY);
});

test('selection : le selecteur generique est rendu avec exactement les hotes metriques', async () => {
  const { request } = server({
    targets: [target(FICTIONAL.selfTarget, 'prometheus'), target(FICTIONAL.exporter, 'node'), target(FICTIONAL.otherExporter, 'node')],
    metricHosts: [FICTIONAL.exporter, FICTIONAL.otherExporter]
  });
  const html = renderInfrastructurePageHtml({ prometheus: await read({ request }) }, 'n', 'light');

  assert.match(html, /id="observability-host"/);
  const options = html.match(/<option value="[^"]*"/g) || [];
  // « Select a host… » plus les deux hotes metriques, et rien de plus.
  assert.equal(options.length, 3);
  assert.ok(html.includes(`<option value="${FICTIONAL.exporter}"`));
  assert.ok(html.includes(`<option value="${FICTIONAL.otherExporter}"`));
  assert.equal(html.includes(`<option value="${FICTIONAL.selfTarget}"`), false);
});

test('selection : un choix explicite est respecte et lit les series de cet hote', async () => {
  const { request } = server({
    targets: [target(FICTIONAL.exporter, 'node'), target(FICTIONAL.otherExporter, 'node')],
    metricHosts: [FICTIONAL.exporter, FICTIONAL.otherExporter]
  });
  const model = await read({ request, entity: FICTIONAL.otherExporter });

  assert.equal(model.selectedEntity, FICTIONAL.otherExporter);
  assert.equal(model.selectionRequired, false);
  assert.equal(model.metrics[CAPABILITY.CPU].available, true);
  const html = renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light');
  assert.match(html, new RegExp(`<option value="${FICTIONAL.otherExporter}" selected`));
});

// ===========================================================================
// No metric host at all: missing, not « unchosen »
// ===========================================================================

test('selection : sans aucune serie d hote, rien n est demande et rien n est invente', async () => {
  const { request } = server({
    targets: [target(FICTIONAL.selfTarget, 'prometheus')],
    metricHosts: []
  });
  const model = await read({ request });

  // Il n y a rien a choisir : demander un choix serait demander l impossible.
  assert.equal(model.selectionRequired, false);
  assert.deepEqual(model.hosts, []);
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.metrics[capability].available, false, capability);
    assert.equal(model.metrics[capability].value, null, capability);
    // « Non exporte », pas « hote non selectionne » : ce sont deux reponses
    // differentes, et une seule est vraie ici.
    assert.equal(model.metrics[capability].reason, METRIC_REASON.NOT_EXPORTED, capability);
    assert.equal(model.capabilities[capability], RESOLVED_STATE.UNAVAILABLE, capability);
  }
  // L inventaire, lui, a bien repondu.
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
  assert.equal(model.inventory.display, '1/1 UP');
});

test('selection : la page ne pretend pas que le fournisseur n a rien renvoye', async () => {
  const { request } = server({ targets: [target(FICTIONAL.selfTarget, 'prometheus')], metricHosts: [] });
  const html = renderInfrastructurePageHtml({ prometheus: await read({ request }) }, 'n', 'light');

  // L inventaire montre une cible juste au-dessus : dire « aucun hote » la
  // contredirait. L honnete est de parler des metriques.
  assert.match(html, /No monitored entity exposes host metrics/);
  assert.doesNotMatch(html, /No monitored host reported by the provider/);
});

test('selection : une requete metrique en echec reste une erreur, pas une absence', async () => {
  const { request } = server({
    targets: [target(FICTIONAL.selfTarget, 'prometheus')],
    metricHosts: [],
    fail: ['cpu']
  });
  const model = await read({ request });

  assert.equal(model.selectionRequired, false);
  assert.equal(model.metrics[CAPABILITY.CPU].reason, METRIC_REASON.QUERY_FAILED);
  assert.equal(model.capabilities[CAPABILITY.CPU], RESOLVED_STATE.ERROR);
  // Et la panne d une requete n emporte pas les autres.
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
});

// ===========================================================================
// The wiring, end to end
// ===========================================================================

test('selection : le contrat distingue inventaire et hotes selectionnables', () => {
  const withBoth = buildInfrastructureModel({
    configured: true,
    entities: [{ id: 'a' }, { id: 'b' }],
    selectableEntities: ['b']
  });
  assert.deepEqual(withBoth.entities.map((entity) => entity.id), ['a', 'b']);
  assert.deepEqual(withBoth.selectableEntities, ['b']);
  assert.deepEqual(withBoth.hosts, ['b']);

  // Un adaptateur qui ne fait pas la distinction garde le comportement d avant.
  const withoutIt = buildInfrastructureModel({ configured: true, entities: [{ id: 'a' }, { id: 'b' }] });
  assert.deepEqual(withoutIt.hosts, ['a', 'b']);
  assert.deepEqual(withoutIt.selectableEntities, ['a', 'b']);
});

test('selection : le selecteur est reellement visible, pas seulement present', () => {
  const css = source('src/enterprise-domain-pages.js');
  // `gap` sans `display` ne produit aucune mise en page : l etiquette et son
  // controle se collaient, la ou la barre de filtres ne les blockifiait pas.
  assert.match(css, /\.filter-field\{display:grid;gap:4px/);
});

test('selection : le choix remonte jusqu a la lecture du fournisseur', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const extension = source('src/extension.js');

  // La page emet l action…
  assert.match(pages, /data-observability-host/);
  assert.match(pages, /action:'selectInfrastructureHost',config:\{host:el\.value\}/);
  // …l extension la retient…
  assert.match(extension, /message\.action === 'selectInfrastructureHost'/);
  assert.match(extension, /infrastructureHost = String\(message\.config\?\.host \|\| ''\)/);
  // …et la repasse a l adaptateur comme entite lue.
  assert.match(extension, /entity: infrastructureHost/);
});
