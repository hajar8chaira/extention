'use strict';

/**
 * Phase O1 — Prometheus correctness.
 *
 * Four defects are pinned here, each of which passed the previous mocked tests
 * because those mocks described one host with one filesystem:
 *
 *   1. a fleet silently reported as whichever host came back first;
 *   2. disk usage computed from one filesystem's size and another's free space;
 *   3. a failed target inventory discarding six successful metric queries;
 *   4. « Prometheus is reachable » read as « node_exporter metrics exist ».
 *
 * Every value below is invented. No address, host, job, instance or metric from
 * any real deployment appears here or in the source it exercises.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  PROMETHEUS_STATUS, METRIC_REASON, fetchPrometheusStatus,
  valuesByInstance, valuesByFilesystem, pairedFilesystems, selectHost, targetsFrom, unknownTargets
} = require('../src/integrations/observability');
const { IntegrationHttpError } = require('../src/integrations/http');

const repoRoot = path.join(__dirname, '..');
const source = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');

const HOST_A = 'fixture-host-a:9100';
const HOST_B = 'fixture-host-b:9100';
const ENDPOINT = 'http://metrics.example.invalid:9090';

/** A PromQL vector: [labels, value] pairs, in the order the server returned. */
const vector = (samples) => ({
  status: 'success',
  data: { resultType: 'vector', result: samples.map(([metric, value]) => ({ metric, value: [1, String(value)] })) }
});

const targetsPayload = (instances) => ({
  data: {
    activeTargets: instances.map(([instance, health]) => ({
      health, labels: { instance }, scrapeUrl: `http://${instance}/metrics`, lastScrape: '2026-08-20T09:00:00Z'
    }))
  }
});

/** Routes a fake Prometheus by query fragment; anything unlisted 404s. */
function server(routes) {
  const calls = [];
  const request = async (url) => {
    calls.push(url);
    for (const [fragment, answer] of Object.entries(routes)) {
      if (!url.includes(fragment)) continue;
      if (answer instanceof Error) throw answer;
      return typeof answer === 'function' ? answer(url) : answer;
    }
    throw new IntegrationHttpError('Service externe HTTP 404.', 'HTTP_ERROR');
  };
  return { calls, request };
}

/** Two hosts, each with two filesystems — deliberately in mismatched order. */
function twoHostServer(overrides = {}) {
  return server({
    '/targets': targetsPayload([[HOST_A, 'up'], [HOST_B, 'up']]),
    'node_cpu_seconds_total': vector([[{ instance: HOST_A }, 20], [{ instance: HOST_B }, 90]]),
    'MemTotal': vector([[{ instance: HOST_A }, 8 * 1024 ** 3], [{ instance: HOST_B }, 32 * 1024 ** 3]]),
    'MemAvailable': vector([[{ instance: HOST_B }, 16 * 1024 ** 3], [{ instance: HOST_A }, 2 * 1024 ** 3]]),
    // Size and available are two independent queries. Their result order does
    // not correspond, and that is exactly the point.
    'filesystem_size': vector([
      [{ instance: HOST_A, mountpoint: '/' }, 100], [{ instance: HOST_A, mountpoint: '/data' }, 900],
      [{ instance: HOST_B, mountpoint: '/' }, 500]
    ]),
    'filesystem_avail': vector([
      [{ instance: HOST_B, mountpoint: '/' }, 250], [{ instance: HOST_A, mountpoint: '/data' }, 450],
      [{ instance: HOST_A, mountpoint: '/' }, 50]
    ]),
    'node_load1': vector([[{ instance: HOST_A }, 0.5], [{ instance: HOST_B }, 4]]),
    ...overrides
  });
}

// ===========================================================================
// 1. No arbitrary host
// ===========================================================================

test('O1 : plusieurs hotes ne sont jamais reduits silencieusement au premier', async () => {
  const { request } = twoHostServer();
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request });

  assert.deepEqual(status.hosts, [HOST_A, HOST_B].sort());
  assert.equal(status.selectedHost, '', 'aucun hote n est choisi a la place de l utilisateur');
  assert.equal(status.hostSelectionRequired, true);
  // Et surtout : aucune valeur d un hote arbitraire n est presentee.
  for (const key of ['cpu', 'memory', 'disk', 'load1']) {
    assert.equal(status.metrics[key].available, false, `${key} ne doit rien afficher`);
    assert.equal(status.metrics[key].reason, METRIC_REASON.HOST_NOT_SELECTED);
    assert.equal(status.metrics[key].display, 'Unavailable');
  }
  // Le fournisseur repond : il est degrade parce qu il attend un choix, pas hors ligne.
  assert.equal(status.status, PROMETHEUS_STATUS.DEGRADED);
});

test('O1 : l hote choisi decide des valeurs lues', async () => {
  const { request } = twoHostServer();
  const first = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_A });
  const second = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_B });

  assert.equal(first.selectedHost, HOST_A);
  assert.equal(first.metrics.cpu.display, '20%');
  assert.equal(first.metrics.load1.display, '0.5');
  assert.equal(second.metrics.cpu.display, '90%');
  assert.equal(second.metrics.load1.display, '4');
  assert.notEqual(first.metrics.memory.display, second.metrics.memory.display);
  assert.equal(first.hostSelectionRequired, false);
});

test('O1 : un hote unique n a pas besoin d etre choisi', async () => {
  const { request } = server({
    '/targets': targetsPayload([[HOST_A, 'up']]),
    'node_cpu_seconds_total': vector([[{ instance: HOST_A }, 42]]),
    'MemTotal': vector([]), 'MemAvailable': vector([]),
    'filesystem_size': vector([]), 'filesystem_avail': vector([]), 'node_load1': vector([])
  });
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request });
  assert.equal(status.selectedHost, HOST_A);
  assert.equal(status.hostSelectionRequired, false);
  assert.equal(status.metrics.cpu.display, '42%');
});

test('O1 : un hote demande mais inconnu ne devient pas un autre hote', async () => {
  const { request } = twoHostServer();
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: 'fixture-host-absent:9100' });
  assert.equal(status.selectedHost, '', 'aucune substitution');
  assert.equal(status.hostSelectionRequired, true);
});

// ===========================================================================
// 2. Disk pairing
// ===========================================================================

test('O1 : taille et espace libre viennent du meme hote et du meme point de montage', async () => {
  const { request } = twoHostServer();
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_A });

  // HOST_A : / = 100 dont 50 libres, /data = 900 dont 450 libres.
  // Utilise = (1000 - 500) / 1000 = 50 %. Un appariement croise donnerait
  // n importe quoi d autre — c est precisement ce que ce test interdit.
  assert.equal(status.metrics.disk.display, '50%');
  assert.deepEqual(status.filesystems, [
    { mountpoint: '/', sizeBytes: 100, availableBytes: 50 },
    { mountpoint: '/data', sizeBytes: 900, availableBytes: 450 }
  ]);

  const other = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_B });
  assert.equal(other.metrics.disk.display, '50%');
  assert.deepEqual(other.filesystems, [{ mountpoint: '/', sizeBytes: 500, availableBytes: 250 }]);
});

test('O1 : un systeme de fichiers non apparie est ignore, pas devine', () => {
  const sizes = valuesByFilesystem(vector([
    [{ instance: HOST_A, mountpoint: '/' }, 100],
    [{ instance: HOST_A, mountpoint: '/orphan' }, 999],
    [{ instance: HOST_A, mountpoint: '/zero' }, 0]
  ]));
  const availables = valuesByFilesystem(vector([
    [{ instance: HOST_A, mountpoint: '/' }, 40],
    [{ instance: HOST_B, mountpoint: '/orphan' }, 1],
    [{ instance: HOST_A, mountpoint: '/zero' }, 0]
  ]));
  // `/orphan` n a d espace libre que sur un AUTRE hote ; `/zero` a une taille
  // nulle. Ni l un ni l autre ne peut produire un pourcentage honnete.
  assert.deepEqual(pairedFilesystems(sizes, availables, HOST_A), [
    { mountpoint: '/', sizeBytes: 100, availableBytes: 40 }
  ]);
});

test('O1 : une serie sans etiquette exploitable n est attribuee a personne', () => {
  assert.deepEqual([...valuesByInstance(vector([[{}, 7]]))], [], 'pas d instance, pas d attribution');
  assert.deepEqual([...valuesByFilesystem(vector([[{ instance: HOST_A }, 7]]))], [], 'pas de point de montage, pas d appariement');
  assert.deepEqual([...valuesByInstance(vector([[{ instance: HOST_A }, 'NaN']]))], [], 'une valeur illisible n est pas une valeur');
});

// ===========================================================================
// 3. Failure isolation
// ===========================================================================

test('O1 : un inventaire de cibles en echec ne jette pas les metriques valides', async () => {
  const { request } = twoHostServer({ '/targets': new IntegrationHttpError('Service externe HTTP 403.', 'HTTP_ERROR') });
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_A });

  assert.notEqual(status.status, PROMETHEUS_STATUS.OFFLINE, 'le fournisseur repond toujours');
  assert.equal(status.status, PROMETHEUS_STATUS.DEGRADED);
  // Les six lectures de metriques ont abouti et sont conservees.
  assert.equal(status.metrics.cpu.display, '20%');
  assert.equal(status.metrics.disk.display, '50%');
  assert.equal(status.metrics.load1.display, '0.5');
  // L inventaire, lui, est inconnu — et le dit.
  assert.equal(status.targets.known, false);
  assert.equal(status.targets.display, 'Unavailable');
  assert.ok(status.failures.some((failure) => failure.key === 'targets'));
  // Les hotes restent connus par les series, sans l inventaire.
  assert.deepEqual(status.hosts, [HOST_A, HOST_B].sort());
});

test('O1 : une seule requete de metrique en echec n emporte pas les autres', async () => {
  const { request } = twoHostServer({ 'MemTotal': new IntegrationHttpError('query failed', 'QUERY_ERROR') });
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_A });

  assert.equal(status.status, PROMETHEUS_STATUS.DEGRADED);
  assert.equal(status.metrics.cpu.display, '20%');
  assert.equal(status.metrics.disk.display, '50%');
  assert.equal(status.metrics.memory.available, false);
  assert.equal(status.metrics.memory.reason, METRIC_REASON.QUERY_FAILED);
  assert.equal(status.metrics.memory.display, 'Unavailable');
});

test('O1 : le fournisseur n est hors ligne que si le fournisseur est hors ligne', async () => {
  const offline = await fetchPrometheusStatus({
    baseUrl: ENDPOINT, request: async () => { throw new IntegrationHttpError('connect ECONNREFUSED', 'OFFLINE'); }
  });
  assert.equal(offline.status, PROMETHEUS_STATUS.OFFLINE);

  const auth = await fetchPrometheusStatus({
    baseUrl: ENDPOINT, request: async () => { throw new IntegrationHttpError('refuse', 'AUTH_ERROR'); }
  });
  assert.equal(auth.status, PROMETHEUS_STATUS.AUTH_ERROR);

  const timeout = await fetchPrometheusStatus({
    baseUrl: ENDPOINT, request: async () => { throw new IntegrationHttpError('slow', 'TIMEOUT'); }
  });
  assert.equal(timeout.status, PROMETHEUS_STATUS.TIMEOUT);
});

// ===========================================================================
// 4. Capabilities are proven by series, not by configuration
// ===========================================================================

test('O1 : un Prometheus sans node_exporter est en ligne, pas casse', async () => {
  // Un Prometheus parfaitement sain qui n exporte simplement pas ces series :
  // Kubernetes seul, windows_exporter, ou une collecte sur mesure.
  const { request } = server({
    '/targets': targetsPayload([[HOST_A, 'up']]),
    'node_': vector([]),
    'query': vector([])
  });
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request });

  assert.notEqual(status.status, PROMETHEUS_STATUS.OFFLINE);
  // L inventaire d hotes est prouve, il reste disponible.
  assert.equal(status.targets.known, true);
  assert.equal(status.targets.up, 1);
  assert.equal(status.targets.total, 1);
  // Les metriques hote ne sont pas prouvees : indisponibles, jamais zero.
  for (const key of ['cpu', 'memory', 'disk', 'load1']) {
    assert.equal(status.metrics[key].available, false, key);
    assert.equal(status.metrics[key].display, 'Unavailable');
    assert.equal(status.metrics[key].value, null, `${key} ne doit pas valoir 0`);
    assert.equal(status.metrics[key].reason, METRIC_REASON.NOT_EXPORTED);
  }
});

test('O1 : un vrai zero reste un zero', async () => {
  const { request } = server({
    '/targets': targetsPayload([[HOST_A, 'up']]),
    'node_cpu_seconds_total': vector([[{ instance: HOST_A }, 0]]),
    'MemTotal': vector([[{ instance: HOST_A }, 4 * 1024 ** 3]]),
    'MemAvailable': vector([[{ instance: HOST_A }, 4 * 1024 ** 3]]),
    'filesystem_size': vector([[{ instance: HOST_A, mountpoint: '/' }, 100]]),
    'filesystem_avail': vector([[{ instance: HOST_A, mountpoint: '/' }, 100]]),
    'node_load1': vector([[{ instance: HOST_A }, 0]])
  });
  const status = await fetchPrometheusStatus({ baseUrl: ENDPOINT, request });
  assert.equal(status.metrics.cpu.available, true);
  assert.equal(status.metrics.cpu.display, '0%');
  assert.equal(status.metrics.load1.available, true);
  assert.equal(status.metrics.load1.display, '0');
  assert.equal(status.metrics.disk.available, true);
  assert.equal(status.metrics.disk.display, '0%', 'un disque vide est 0 %, pas « indisponible »');
});

test('O1 : zero cible connue et inventaire inconnu ne se disent pas pareil', () => {
  const empty = targetsFrom({ data: { activeTargets: [] } });
  assert.equal(empty.known, true);
  assert.deepEqual([empty.up, empty.total], [0, 0]);
  assert.equal(empty.display, '0/0 UP');

  const unknown = unknownTargets();
  assert.equal(unknown.known, false);
  assert.deepEqual([unknown.up, unknown.total], [null, null]);
  assert.equal(unknown.display, 'Unavailable');
});

test('O1 : l inventaire ne designe plus une cible arbitraire comme « l hote »', () => {
  const targets = targetsFrom(targetsPayload([[HOST_B, 'down'], [HOST_A, 'up']]));
  assert.equal(targets.selectedHost, '', 'aucun hote elu par l inventaire');
  assert.equal(targets.up, 1);
  assert.equal(targets.total, 2);
  assert.equal(targets.items.length, 2);
});

// ===========================================================================
// Endpoints and neutrality
// ===========================================================================

test('O1 : les points d entree Prometheus sont inchanges', async () => {
  const { calls, request } = twoHostServer();
  await fetchPrometheusStatus({ baseUrl: ENDPOINT, request, host: HOST_A });
  assert.ok(calls.some((url) => url.includes('/api/v1/targets')));
  assert.equal(calls.filter((url) => url.includes('/api/v1/query')).length, 6, 'six requetes de metriques');
  for (const url of calls) assert.match(url, /\/api\/v1\/(targets|query)/);
});

test('O1 : aucune valeur de deploiement n est ecrite dans le code de production', () => {
  for (const file of ['src/integrations/observability.js', 'src/enterprise-domain-pages.js']) {
    const content = source(file);
    assert.doesNotMatch(content, /\b\d{1,3}(\.\d{1,3}){3}\b/, `${file} ne doit contenir aucune adresse IP`);
    assert.doesNotMatch(content, /localhost|127\.0\.0\.1/, `${file} ne doit viser aucune machine`);
    assert.doesNotMatch(content, /job\s*=\s*['"]/, `${file} ne doit fixer aucun job`);
    assert.doesNotMatch(content, /instance\s*[:=]\s*['"][^'"]+['"]/, `${file} ne doit fixer aucune instance`);
  }
});

test('O1 : la page laisse le choix de l hote a l utilisateur', () => {
  const pages = source('src/enterprise-domain-pages.js');
  const selector = pages.match(/function hostSelector\([\s\S]*?\n}/)[0];
  // Pas de selecteur pour un hote unique : il n y a rien a choisir.
  assert.match(selector, /hosts\.length < 2/);
  assert.match(selector, /prometheus\.hosts/);
  // Aucun nom d hote n est ecrit dans le rendu.
  assert.doesNotMatch(selector, /:9100|fixture-host/);
});
