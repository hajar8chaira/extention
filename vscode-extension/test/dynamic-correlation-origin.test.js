const test = require('node:test');
const assert = require('node:assert/strict');
const {
  associationFor, linkedFindingsForScenario, buildDashboardModel, renderDashboardHtml,
  ASSOCIATION_CONFIDENCE, ZAP_UNKNOWN_METHOD
} = require('../src/dashboard');

const TARGET = 'http://127.0.0.1:3000';
const OTHER = 'http://192.168.1.50:8080';

const request = (origin, path, method = 'GET') => ({
  source: 'burp',
  name: `${method} ${path}`,
  request: { url: `${origin}${path}`, method, headers: {} },
  response: { statusCode: 200, headers: {} }
});

const zapFinding = (origin, path, method = ZAP_UNKNOWN_METHOD, title = 'Alerte ZAP') => ({
  id: `zap-${path}-${method}`, tool: 'ZAP', title, rawSeverity: 'HIGH',
  endpoint: `${origin}${path}`, method, triageStatus: 'new'
});

// ------------------------------------------- règle request ↔ finding

test('une origine différente rompt l’association, même avec le même chemin', () => {
  // C'est le defaut corrige : `/` d'une cible et `/` d'une autre etaient le
  // meme endpoint, si bien qu'une requete Burp capturee heritait des findings
  // ZAP d'un hote qu'elle n'avait jamais touche.
  const association = associationFor(request(TARGET, '/'), zapFinding(OTHER, '/'));
  assert.equal(association.confidence, null);
  assert.deepEqual(association.reasons, []);
});

test('un port différent est une origine différente', () => {
  const association = associationFor(
    request('http://127.0.0.1:3000', '/api/users'),
    zapFinding('http://127.0.0.1:4000', '/api/users', 'GET')
  );
  assert.equal(association.confidence, null);
});

test('la même origine et le même chemin conservent l’association', () => {
  const association = associationFor(request(TARGET, '/'), zapFinding(TARGET, '/'));
  assert.equal(association.confidence, ASSOCIATION_CONFIDENCE.PROBABLE);
  assert.ok(association.reasons.some((reason) => /Chemin identique/.test(reason)));
});

test('une origine inconnue d’un côté ne peut rien réfuter et ne bloque pas', () => {
  // Un endpoint relatif ne porte pas d'hote : il ne prouve ni n'infirme rien.
  const association = associationFor(request(TARGET, '/api/users'), {
    id: 'rel', tool: 'ZAP', endpoint: '/api/users', method: 'GET', rawSeverity: 'HIGH'
  });
  assert.equal(association.confidence, ASSOCIATION_CONFIDENCE.STRONG);
});

test('le filtrage par origine réduit réellement les findings liés à une requête', () => {
  const findings = [
    zapFinding(TARGET, '/', ZAP_UNKNOWN_METHOD, 'CSP manquant'),
    zapFinding(OTHER, '/', ZAP_UNKNOWN_METHOD, 'Autre hôte 1'),
    zapFinding(OTHER, '/', 'GET', 'Autre hôte 2'),
    zapFinding(OTHER, '/', 'POST', 'Autre hôte 3')
  ];
  const linked = linkedFindingsForScenario(request(TARGET, '/'), findings);
  assert.equal(linked.length, 1);
  assert.equal(linked[0].title, 'CSP manquant');
});

// ------------------------------------- Dynamic Security : ZAP + Burp

test('la section des findings dynamiques n’agrège que ZAP et Burp', () => {
  const findings = [
    zapFinding(TARGET, '/api/a', 'GET', 'Alerte ZAP visible'),
    { id: 'burp-1', tool: 'Burp', title: 'Alerte Burp visible', rawSeverity: 'CRITICAL', endpoint: `${TARGET}/api/b`, triageStatus: 'new' },
    { id: 'rt-1', tool: 'Semgrep', title: 'Alerte runtime exclue', rawSeverity: 'HIGH', sourceContext: 'runtime', endpoint: '/api/c', triageStatus: 'new' },
    { id: 'wz-1', tool: 'Wazuh', title: 'Alerte SIEM exclue', rawSeverity: 'CRITICAL', sourceContext: 'runtime', endpoint: '/api/d', triageStatus: 'new' }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], { httpScenarios: [] }), 'nonce', 'dynamic');
  const section = html.match(/<section id="dynamic-findings"[\s\S]*?<section id="http-traffic"/)?.[0] || '';
  assert.match(section, /Alerte ZAP visible/);
  assert.match(section, /Alerte Burp visible/);
  assert.doesNotMatch(section, /Alerte runtime exclue/);
  assert.doesNotMatch(section, /Alerte SIEM exclue/);
});

test('chaque finding dynamique porte sa provenance, et la section offre le filtre', () => {
  const findings = [
    zapFinding(TARGET, '/api/a', 'GET', 'Alerte ZAP'),
    { id: 'burp-1', tool: 'Burp', title: 'Alerte Burp', rawSeverity: 'CRITICAL', endpoint: `${TARGET}/api/b`, triageStatus: 'new' }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], { httpScenarios: [] }), 'nonce', 'dynamic');
  const section = html.match(/<section id="dynamic-findings"[\s\S]*?<section id="http-traffic"/)?.[0] || '';
  assert.match(section, /data-dynamic-source="zap"/);
  assert.match(section, /data-dynamic-source="burp"/);
  assert.match(section, /data-dynamic-filter="all"/);
  assert.match(section, /data-dynamic-filter="zap"/);
  assert.match(section, /data-dynamic-filter="burp"/);
  // Le decompte par source est annonce dans l'en-tete de section.
  assert.match(section, /ZAP 1 · Burp 1/);
});

test('la carte ZAP annonce un compteur ZAP et ouvre la vue filtrée ZAP', () => {
  const findings = [
    zapFinding(TARGET, '/api/a', 'GET', 'Alerte ZAP'),
    { id: 'burp-1', tool: 'Burp', title: 'Alerte Burp', rawSeverity: 'CRITICAL', endpoint: `${TARGET}/api/b`, triageStatus: 'new' }
  ];
  const html = renderDashboardHtml(buildDashboardModel(findings, [], { httpScenarios: [] }), 'nonce', 'dynamic');
  // Le compteur nomme sa portee...
  assert.match(html, /Findings ZAP<\/span><strong>1<\/strong>/);
  // ...et le bouton ouvre exactement cet ensemble, pas l'agregat.
  assert.match(html, /data-dynamic-filter-target="zap"[^>]*>Voir les findings ZAP/);
});

test('la carte Burp sépare l’état de connexion de l’historique conservé', () => {
  const findings = [zapFinding(TARGET, '/api/a', 'GET', 'Alerte ZAP')];
  const scenarios = [request(TARGET, '/api/a')];
  const html = renderDashboardHtml(
    buildDashboardModel(findings, [], { httpScenarios: scenarios, burpConnected: false }), 'nonce', 'dynamic'
  );
  assert.match(html, /Connexion actuelle<\/span><strong>Déconnectée<\/strong>/);
  assert.match(html, /Historique capturé/);
  assert.match(html, /Requêtes conservées<\/span><strong>1<\/strong>/);
});
