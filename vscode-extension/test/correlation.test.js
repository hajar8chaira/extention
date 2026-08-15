const test = require('node:test');
const assert = require('node:assert/strict');
const { correlateFindings } = require('../src/correlation');

test('corrÃ¨le fortement un endpoint et une route source avec le mÃªme CWE', () => {
  const result = correlateFindings([
    { id: 's-route', tool: 'Semgrep', file: 'routes/search.ts', absolutePath: 'C:\\repo\\routes\\search.ts', startLine: 0, cwe: 'CWE-79', sourceContext: 'production' },
    { id: 'z-route', tool: 'ZAP', file: 'GET /rest/products/search', endpoint: 'http://127.0.0.1:3000/rest/products/search?q=x', startLine: 0, cwe: 'CWE-79', sourceContext: 'runtime' }
  ]);
  assert.equal(result.correlations.length, 1);
  assert.equal(result.correlations[0].type, 'endpoint-source');
  assert.equal(result.correlations[0].confidence, 'high');
});

function finding(overrides) {
  return {
    id: overrides.id,
    tool: overrides.tool,
    file: overrides.file || '',
    absolutePath: overrides.absolutePath || '',
    startLine: overrides.startLine || 0,
    cwe: overrides.cwe || '',
    sourceContext: overrides.sourceContext || 'production',
    ...overrides
  };
}

test('corrèle fortement deux outils sur le même fichier et des lignes proches', () => {
  const result = correlateFindings([
    finding({ id: 's1', tool: 'Semgrep', file: 'src/auth.ts', absolutePath: 'C:\\repo\\src\\auth.ts', startLine: 10, cwe: 'CWE-798' }),
    finding({ id: 'g1', tool: 'Gitleaks', file: 'src/auth.ts', absolutePath: 'C:\\repo\\src\\auth.ts', startLine: 12, cwe: 'CWE-798' })
  ]);
  assert.equal(result.correlations.length, 1);
  assert.equal(result.correlations[0].type, 'same-location');
  assert.equal(result.correlations[0].confidence, 'high');
  assert.deepEqual(result.findings[0].correlatedTools, ['Gitleaks', 'Semgrep']);
});

test('signale une correspondance CWE SAST DAST comme possible seulement', () => {
  const result = correlateFindings([
    finding({ id: 's1', tool: 'Semgrep', file: 'routes/xss.ts', absolutePath: 'C:\\repo\\routes\\xss.ts', cwe: 'CWE-79' }),
    finding({ id: 'z1', tool: 'ZAP', file: 'GET http://target', sourceContext: 'runtime', cwe: 'CWE-79' })
  ]);
  assert.equal(result.correlations.length, 1);
  assert.equal(result.correlations[0].type, 'shared-cwe');
  assert.equal(result.correlations[0].confidence, 'medium');
  assert.match(result.correlations[0].reason, /reste à confirmer/);
});

test('ne corrèle pas une simple CWE entre deux emplacements source différents', () => {
  const result = correlateFindings([
    finding({ id: 's1', tool: 'Semgrep', file: 'a.ts', absolutePath: 'C:\\repo\\a.ts', cwe: 'CWE-79' }),
    finding({ id: 'g1', tool: 'Gitleaks', file: 'b.ts', absolutePath: 'C:\\repo\\b.ts', cwe: 'CWE-79' })
  ]);
  assert.equal(result.correlations.length, 0);
});

test('confirme une dépendance trouvée par Trivy et OSV', () => {
  const result = correlateFindings([
    finding({ id: 't1', tool: 'Trivy', category: 'dependency', packageName: 'demo', ruleId: 'CVE-2026-1234', vulnerabilityAliases: ['CVE-2026-1234'] }),
    finding({ id: 'o1', tool: 'OSV-Scanner', category: 'dependency', packageName: 'demo', ruleId: 'CVE-2026-1234', vulnerabilityAliases: ['GHSA-demo', 'CVE-2026-1234'] })
  ]);
  assert.equal(result.correlations.length, 1);
  assert.equal(result.correlations[0].type, 'dependency-match');
  assert.equal(result.correlations[0].confidence, 'high');
  assert.deepEqual(result.correlations[0].tools, ['OSV-Scanner', 'Trivy']);
});
