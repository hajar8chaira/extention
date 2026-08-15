const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeSemgrepOutput,
  normalizeGitleaksOutput,
  normalizeZapOutput,
  classifySourceContext
} = require('../src/findings');

test('normalise un résultat Semgrep en finding interne', () => {
  const payload = { results: [{ check_id: 'javascript.security.test', path: 'src/app.js', start: { line: 4, col: 3 }, end: { line: 4, col: 15 }, extra: { message: 'Entrée non validée', severity: 'ERROR', metadata: { cwe: ['CWE-20'], category: 'security' } } }] };
  const [finding] = normalizeSemgrepOutput(payload, '/workspace');
  assert.equal(finding.ruleId, 'javascript.security.test');
  assert.equal(finding.startLine, 3);
  assert.equal(finding.severity, 'error');
  assert.equal(finding.cwe, 'CWE-20');
});

test('accepte une sortie sans résultats', () => assert.deepEqual(normalizeSemgrepOutput({}, '/workspace'), []));

test('conserve une correction native Semgrep sans en inventer', () => {
  const [finding] = normalizeSemgrepOutput({ results: [{
    check_id: 'company.safe-fix', path: 'src/app.js', start: { line: 1, col: 1 }, end: { line: 1, col: 9 },
    extra: { message: 'Unsafe', severity: 'WARNING', lines: 'oldCall()', fix: 'safeCall()', metadata: {} }
  }] }, '/workspace');
  assert.equal(finding.autofix, 'safeCall()');
  assert.equal(finding.originalText, 'oldCall()');
});

test('normalise un secret Gitleaks sans exposer sa valeur', () => {
  const payload = [{ RuleID: 'generic-api-key', Description: 'Generic API Key', File: 'src/config.js', StartLine: 2, EndLine: 2, StartColumn: 10, EndColumn: 30, Secret: 'do-not-copy', Fingerprint: 'abc123' }];
  const [finding] = normalizeGitleaksOutput(payload, '/workspace');
  assert.equal(finding.tool, 'Gitleaks');
  assert.equal(finding.category, 'secret');
  assert.equal(finding.startLine, 1);
  assert.equal(finding.sourceContext, 'production');
  assert.equal(Object.hasOwn(finding, 'secret'), false);
});

test('convertit un chemin Docker Gitleaks en chemin relatif au workspace', () => {
  const payload = [{ RuleID: 'jwt', File: '/src/frontend/src/app/auth.spec.ts', StartLine: 4, StartColumn: 2 }];
  const [finding] = normalizeGitleaksOutput(payload, 'C:\\workspace');
  assert.equal(finding.file, 'frontend/src/app/auth.spec.ts');
  assert.equal(finding.absolutePath, 'C:\\workspace\\frontend\\src\\app\\auth.spec.ts');
  assert.equal(finding.sourceContext, 'test');
  assert.equal(finding.rawSeverity, 'MEDIUM');
  assert.equal(finding.confidence, 'low');
});

test('supprime les doublons Gitleaks sur la même règle et la même position', () => {
  const result = { RuleID: 'generic-api-key', File: '/src/app.ts', StartLine: 8, StartColumn: 3 };
  assert.equal(normalizeGitleaksOutput([result, { ...result }], '/workspace').length, 1);
});

test('reconnaît les fichiers de test et de production', () => {
  assert.equal(classifySourceContext('test/server/auth.ts'), 'test');
  assert.equal(classifySourceContext('src/auth/auth.service.spec.ts'), 'test');
  assert.equal(classifySourceContext('src/auth/auth.service.ts'), 'production');
});

test('normalise les instances OWASP ZAP sans inventer de fichier source', () => {
  const payload = { site: [{ '@name': 'http://target', alerts: [{
    pluginid: '10038', alert: 'Missing Header', riskcode: '2', confidence: '2', cweid: '693',
    desc: '<p>Header <strong>absent</strong></p>', solution: '<p>Ajouter le header</p>',
    reference: '<p>https://www.zaproxy.org/docs/alerts/10038/</p>',
    instances: [{ uri: 'http://target/login', method: 'GET', param: '' }]
  }] }] };
  const [finding] = normalizeZapOutput(payload);
  assert.equal(finding.tool, 'ZAP');
  assert.equal(finding.rawSeverity, 'MEDIUM');
  assert.equal(finding.sourceContext, 'runtime');
  assert.equal(finding.absolutePath, '');
  assert.equal(finding.endpoint, 'http://target/login');
  assert.equal(finding.confidence, 'medium');
  assert.equal(finding.description, 'Header absent');
  assert.equal(finding.solution, 'Ajouter le header');
  assert.equal(finding.helpUri, 'https://www.zaproxy.org/docs/alerts/10038/');
  assert.match(finding.developerSummary, /politique CSP/);
});

test('conserve le composant et les CVE fournis par ZAP', () => {
  const payload = { site: [{ alerts: [{
    pluginid: '10003', alert: 'Vulnerable JS Library', riskcode: '3', confidence: '2', cweid: '1395',
    instances: [{
      uri: 'http://target/app.js', method: 'GET', evidence: '["ng-version","20.3.18"]',
      otherinfo: 'The identified library @angular/core, version 20.3.18 is vulnerable.\nCVE-2026-52725\nCVE-2026-50557\nhttps://example.test/advisory'
    }]
  }] }] };
  const [finding] = normalizeZapOutput(payload);
  assert.equal(finding.packageName, '@angular/core');
  assert.equal(finding.installedVersion, '20.3.18');
  assert.deepEqual(finding.vulnerabilityAliases, ['CVE-2026-52725', 'CVE-2026-50557']);
  assert.deepEqual(finding.references, ['https://example.test/advisory']);
});
