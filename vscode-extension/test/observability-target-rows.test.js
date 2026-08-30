'use strict';

/**
 * Inventory rows — the detail must agree with the summary.
 *
 * A real deployment exposed the defect: two healthy scrape targets, an
 * inventory summary reading `2/2 UP`, and every row underneath it drawing
 * « UNKNOWN / Instance unavailable / Last scrape: Unavailable ». The provider
 * had returned all three facts; the summary and the rows were simply reading
 * the same payload under two different sets of property names.
 *
 * Adapters answer the normalized entity — `{ id, name, status, endpoint,
 * lastSeen }`. The historical `targetsFrom()` helper answers the same facts as
 * `{ instance, health, lastScrape }`. The row read only the second set, so
 * everything an adapter supplied landed under keys nobody looked at.
 *
 * These tests pin both shapes, and pin what must NOT happen: a missing fact
 * stays missing, and an unreadable status never becomes healthy.
 *
 * Every address, job name and measurement below is invented.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { prometheusAdapter } = require('../src/integrations/observability-prometheus');
const { CAPABILITY, RESOLVED_STATE, PROVIDER_STATUS } = require('../src/integrations/observability-contract');
const { targetsFrom } = require('../src/integrations/observability');
const { renderInfrastructurePageHtml } = require('../src/enterprise-domain-pages');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

const FICTIONAL = Object.freeze({
  endpoint: 'http://metrics.fixture.invalid:9090',
  selfInstance: 'self.fixture.invalid:9090',
  selfJob: 'fixture-self-job',
  nodeInstance: 'exporter.fixture.invalid:9100',
  nodeJob: 'fixture-node-job'
});

const vector = (samples) => ({
  status: 'success',
  data: { resultType: 'vector', result: samples.map(([metric, value]) => ({ metric, value: [1700000000, String(value)] })) }
});

const scrapedAt = () => new Date(Date.now() - 9000).toISOString();

const target = (instance, job, extra = {}) => ({
  labels: { instance, job },
  health: 'up',
  scrapeUrl: `http://${instance}/metrics`,
  lastScrape: scrapedAt(),
  lastError: '',
  ...extra
});

/**
 * A fake Prometheus shaped like the real one: a scrape list, and host metrics
 * published by one of the two targets only.
 */
function server({ targets = [], metricHost = FICTIONAL.nodeInstance } = {}) {
  return async function request(url) {
    const parsed = new URL(url);
    if (parsed.pathname === '/api/v1/targets') return { status: 'success', data: { activeTargets: targets } };
    const query = parsed.searchParams.get('query') || '';
    const per = (value) => vector([[{ instance: metricHost }, value]]);
    if (query.includes('node_cpu')) return per(12);
    if (query.includes('MemTotal')) return per(8 * 1024 ** 3);
    if (query.includes('MemAvailable')) return per(2 * 1024 ** 3);
    if (query.includes('node_filesystem_size')) return vector([[{ instance: metricHost, mountpoint: '/' }, 200 * 1024 ** 3]]);
    if (query.includes('node_filesystem_avail')) return vector([[{ instance: metricHost, mountpoint: '/' }, 50 * 1024 ** 3]]);
    if (query.includes('node_load1')) return per(0.75);
    return vector([]);
  };
}

const read = (request, options = {}) => prometheusAdapter.fetchStatus({ url: FICTIONAL.endpoint }, {}, { request, ...options });

/** The rendered inventory rows, one entry per `<article class="asset-row">`. */
function rowsOf(model) {
  const html = renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light');
  return [...html.matchAll(/<article class="asset-row">([\s\S]*?)<\/article>/g)].map((match) => match[1]);
}

const twoHealthy = () => ([
  target(FICTIONAL.selfInstance, FICTIONAL.selfJob),
  target(FICTIONAL.nodeInstance, FICTIONAL.nodeJob)
]);

// ===========================================================================
// A healthy target renders every fact the provider returned
// ===========================================================================

test('cibles : une cible saine affiche UP', async () => {
  const model = await read(server({ targets: twoHealthy() }));
  const rows = rowsOf(model);

  assert.equal(rows.length, 2);
  for (const row of rows) {
    assert.match(row, /<em class="ok">● UP<\/em>/);
    assert.doesNotMatch(row, /UNKNOWN/);
  }
});

test('cibles : l instance renvoyee par le fournisseur est affichee', async () => {
  const rows = rowsOf(await read(server({ targets: twoHealthy() })));

  assert.ok(rows[0].includes(FICTIONAL.selfInstance), 'la premiere cible perd son instance');
  assert.ok(rows[1].includes(FICTIONAL.nodeInstance), 'la seconde cible perd son instance');
  for (const row of rows) assert.doesNotMatch(row, /Instance unavailable/);
});

test('cibles : la date de collecte reelle est affichee', async () => {
  const rows = rowsOf(await read(server({ targets: twoHealthy() })));

  for (const row of rows) {
    assert.match(row, /Last scrape: \d+ seconds? ago/);
    assert.doesNotMatch(row, /Last scrape: Unavailable/);
  }
});

test('cibles : 2/2 UP en resume et UP sur chaque ligne', async () => {
  const model = await read(server({ targets: twoHealthy() }));
  const html = renderInfrastructurePageHtml({ prometheus: model }, 'n', 'light');

  // Le resume et le detail lisent la meme charge utile : ils doivent s accorder.
  assert.equal(model.inventory.display, '2/2 UP');
  assert.ok(html.includes('2/2 UP'), 'le resume doit rester affiche');
  const rows = rowsOf(model);
  assert.equal(rows.filter((row) => /● UP</.test(row)).length, 2);
});

// ===========================================================================
// What is missing stays missing
// ===========================================================================

test('cibles : une cible sans instance reste indisponible', async () => {
  // Aucune serie d hote : l inventaire n a donc que cette cible a montrer.
  const rows = rowsOf(await read(server({
    metricHost: '',
    targets: [{ labels: { job: FICTIONAL.selfJob }, health: 'up', scrapeUrl: '', lastScrape: scrapedAt() }]
  })));

  assert.equal(rows.length, 1);
  assert.match(rows[0], /Instance unavailable/);
  // Rien n est invente a la place : ni le job, ni l URL de collecte.
  assert.equal(rows[0].includes(`<span>${FICTIONAL.selfJob}</span>`), false);
});

test('cibles : une sante absente reste UNKNOWN et n est jamais promue', async () => {
  const rows = rowsOf(await read(server({
    metricHost: '',
    targets: [{ labels: { instance: FICTIONAL.selfInstance, job: FICTIONAL.selfJob }, scrapeUrl: '', lastScrape: scrapedAt() }]
  })));

  assert.match(rows[0], /● UNKNOWN</);
  assert.doesNotMatch(rows[0], /class="ok"/, 'inconnu n est pas sain');
});

test('cibles : une collecte absente reste indisponible', async () => {
  const rows = rowsOf(await read(server({
    metricHost: '',
    targets: [{ labels: { instance: FICTIONAL.selfInstance, job: FICTIONAL.selfJob }, health: 'up', scrapeUrl: '' }]
  })));

  assert.match(rows[0], /Last scrape: Unavailable/);
  // Mais ce qui a bien ete renvoye est affiche.
  assert.match(rows[0], /● UP</);
  assert.ok(rows[0].includes(FICTIONAL.selfInstance));
});

test('cibles : une cible en panne est rendue telle quelle', async () => {
  const rows = rowsOf(await read(server({
    metricHost: '',
    targets: [target(FICTIONAL.selfInstance, FICTIONAL.selfJob, { health: 'down' })]
  })));

  assert.match(rows[0], /<em class="bad">● DOWN<\/em>/);
});

// ===========================================================================
// The older row shape still renders
// ===========================================================================

test('cibles : la forme historique de `targetsFrom` est toujours lue', () => {
  const legacy = targetsFrom({
    data: {
      activeTargets: [{
        labels: { instance: FICTIONAL.selfInstance, job: FICTIONAL.selfJob },
        health: 'up', scrapeUrl: `http://${FICTIONAL.selfInstance}/metrics`, lastScrape: scrapedAt()
      }]
    }
  });
  // Cette forme nomme les memes faits autrement : instance / health / lastScrape.
  assert.ok('instance' in legacy.items[0] && 'health' in legacy.items[0] && 'lastScrape' in legacy.items[0]);

  const rows = rowsOf({ provider: 'prometheus', configured: true, status: 'healthy', targets: legacy, metrics: {}, capabilities: {} });
  assert.match(rows[0], /● UP</);
  assert.ok(rows[0].includes(FICTIONAL.selfInstance));
  assert.match(rows[0], /Last scrape: \d+ seconds? ago/);
});

// ===========================================================================
// Nothing else moved
// ===========================================================================

test('cibles : la selection d hote metrique est inchangee', async () => {
  const model = await read(server({ targets: twoHealthy() }));

  // Une seule cible publie des series : elle reste choisie seule, et la cible
  // qui n en publie pas reste hors du choix tout en restant inventoriee.
  assert.deepEqual(model.hosts, [FICTIONAL.nodeInstance]);
  assert.equal(model.selectedEntity, FICTIONAL.nodeInstance);
  assert.equal(model.selectionRequired, false);
  assert.equal(model.entities.length, 2);
});

test('cibles : les metriques d hote sont inchangees', async () => {
  const model = await read(server({ targets: twoHealthy() }));

  assert.equal(model.metrics[CAPABILITY.CPU].display, '12%');
  assert.equal(model.metrics[CAPABILITY.DISK].display, '75%');
  assert.equal(model.metrics[CAPABILITY.LOAD].display, '0.75');
  assert.equal(model.metrics[CAPABILITY.MEMORY].available, true);
  for (const capability of [CAPABILITY.CPU, CAPABILITY.MEMORY, CAPABILITY.DISK, CAPABILITY.LOAD]) {
    assert.equal(model.capabilities[capability], RESOLVED_STATE.READY, capability);
  }
});

test('cibles : le fournisseur reste Healthy sur ce jeu de donnees', async () => {
  const model = await read(server({ targets: twoHealthy() }));

  assert.equal(model.status, PROVIDER_STATUS.HEALTHY);
  assert.equal(model.message, '');
  assert.equal(model.capabilities[CAPABILITY.HOST_INVENTORY], RESOLVED_STATE.READY);
});

test('cibles : aucun identifiant de deploiement n entre dans le code', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const adapter = source('src/integrations/observability-prometheus.js');
  for (const code of [pages, adapter]) {
    // Ni adresse, ni port, ni nom de job d un quelconque deploiement.
    assert.doesNotMatch(code, /\b\d{1,3}(\.\d{1,3}){3}\b/);
    assert.doesNotMatch(code, /ubuntu-server|node_exporter/);
  }
});

test('cibles : le rendu generique ne nomme aucun fournisseur', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const rows = pages.slice(pages.indexOf('function inventoryEntity'), pages.indexOf('function hostHealthSubtitle'));
  for (const name of ['prometheus', 'zabbix', 'datadog', 'wazuh', 'elastic', 'splunk']) {
    assert.doesNotMatch(rows, new RegExp(name, 'i'), `${name} ne doit pas apparaitre dans le rendu des lignes`);
  }
});
