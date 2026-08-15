const test = require('node:test');
const assert = require('node:assert/strict');
const { LiveDiagnostics, diagnosticSeverity, toLiveDiagnostic } = require('../src/live/liveDiagnostics');

const DiagnosticSeverity = { Error: 0, Warning: 1, Information: 2, Hint: 3 };
class Range {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    this.start = { line: startLine, character: startCharacter };
    this.end = { line: endLine, character: endCharacter };
  }
  contains(position) {
    const afterStart = position.line > this.start.line || (position.line === this.start.line && position.character >= this.start.character);
    const beforeEnd = position.line < this.end.line || (position.line === this.end.line && position.character <= this.end.character);
    return afterStart && beforeEnd;
  }
}
class Diagnostic {
  constructor(range, message, severity) { this.range = range; this.message = message; this.severity = severity; }
}
const api = { DiagnosticSeverity, Range, Diagnostic, Uri: { parse: (value) => ({ value, toString: () => value }) } };
function finding(overrides = {}) {
  return {
    uri: 'file:///repo/app.js', documentVersion: 3,
    range: { start: { line: 2, character: 4 }, end: { line: 2, character: 18 } },
    label: 'Potential issue', title: 'Potential SQL injection', description: 'Unsafe query.',
    ruleId: 'sql-string-concatenation', cwe: 'CWE-89', confidence: 'high', severity: 'high',
    ...overrides
  };
}
function collectionFixture() {
  const values = new Map();
  let clears = 0, disposed = 0;
  return {
    set: (uri, diagnostics) => values.set(uri.toString(), diagnostics),
    delete: (uri) => values.delete(uri.toString()),
    clear: () => { values.clear(); clears += 1; },
    dispose: () => { disposed += 1; },
    inspect: () => ({ values, clears, disposed })
  };
}

test('convertit un LiveFinding en diagnostic natif avec métadonnées', () => {
  const diagnostic = toLiveDiagnostic(finding(), api);
  assert.equal(diagnostic.source, 'Security Center Live');
  assert.equal(diagnostic.code, 'sql-string-concatenation');
  assert.equal(diagnostic.severity, DiagnosticSeverity.Error);
  assert.deepEqual(diagnostic.range.start, { line: 2, character: 4 });
  assert.match(diagnostic.message, /CWE-89/);
  assert.match(diagnostic.message, /confidence:high/);
});

test('mappe prudemment les niveaux de diagnostic', () => {
  assert.equal(diagnosticSeverity(finding(), DiagnosticSeverity), DiagnosticSeverity.Error);
  assert.equal(diagnosticSeverity(finding({ confidence: 'medium' }), DiagnosticSeverity), DiagnosticSeverity.Warning);
  assert.equal(diagnosticSeverity(finding({ severity: 'low', confidence: 'low' }), DiagnosticSeverity), DiagnosticSeverity.Information);
});

test('publie uniquement les résultats correspondant à URI et version', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding(), finding({ documentVersion: 2 }), finding({ uri: 'file:///repo/other.js' })], { uri: 'file:///repo/app.js', version: 3 });
  const published = collection.inspect().values.get('file:///repo/app.js');
  assert.equal(published.length, 1);
  diagnostics.dispose();
});

test('supprime le diagnostic lorsque le code corrigé ne produit plus de finding', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding()], { uri: 'file:///repo/app.js', version: 3 });
  diagnostics.publish([], { uri: 'file:///repo/app.js', version: 4 });
  assert.equal(collection.inspect().values.has('file:///repo/app.js'), false);
  diagnostics.dispose();
});

test('ignore un resultat obsolete arrive apres une version plus recente', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding({ documentVersion: 4 })], { uri: 'file:///repo/app.js', version: 4 });
  diagnostics.publish([], { uri: 'file:///repo/app.js', version: 3 });
  assert.equal(collection.inspect().values.get('file:///repo/app.js').length, 1);
  diagnostics.dispose();
});

test('retrouve uniquement le finding de la version courante sous le curseur', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding()], { uri: 'file:///repo/app.js', version: 3 });
  const document = { uri: { toString: () => 'file:///repo/app.js' }, version: 3 };
  assert.equal(diagnostics.findFinding(document, { line: 2, character: 8 }).ruleId, 'sql-string-concatenation');
  assert.equal(diagnostics.findFinding({ ...document, version: 4 }, { line: 2, character: 8 }), undefined);
  assert.equal(diagnostics.getFinding('file:///repo/app.js', 3, 'sql-string-concatenation').cwe, 'CWE-89');
  diagnostics.dispose();
});

test('expose seulement les findings Live du document et de sa version courante', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding()], { uri: 'file:///repo/app.js', version: 3 });
  const current = { uri: { toString: () => 'file:///repo/app.js' }, version: 3 };
  assert.equal(diagnostics.findingsForDocument(current).length, 1);
  assert.equal(diagnostics.findingsForDocument({ ...current, version: 4 }).length, 0);
  diagnostics.dispose();
});

test('clear et dispose nettoient immédiatement la collection Live', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  diagnostics.publish([finding()], { uri: 'file:///repo/app.js', version: 3 });
  diagnostics.clear();
  assert.equal(collection.inspect().values.size, 0);
  diagnostics.dispose();
  assert.equal(collection.inspect().disposed, 1);
});

test('masque les faibles confiances sauf en mode verbose', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection, showLowConfidence: () => false });
  diagnostics.publish([finding({ confidence: 'low' })], { uri: 'file:///repo/app.js', version: 3 });
  assert.equal(collection.inspect().values.has('file:///repo/app.js'), false);
  diagnostics.dispose();

  const verboseCollection = collectionFixture();
  const verbose = new LiveDiagnostics({ api, collection: verboseCollection, showLowConfidence: () => true });
  verbose.publish([finding({ confidence: 'low' })], { uri: 'file:///repo/app.js', version: 3 });
  assert.equal(verboseCollection.inspect().values.get('file:///repo/app.js').length, 1);
  verbose.dispose();
});

test('ignore temporairement une alerte pour la session sans modifier la politique', () => {
  const collection = collectionFixture();
  const diagnostics = new LiveDiagnostics({ api, collection });
  const ignored = finding({ originalText: 'eval(req.body.code)' });
  diagnostics.publish([ignored], { uri: ignored.uri, version: 3 });
  diagnostics.suppressForSession(ignored);
  diagnostics.publish([ignored], { uri: ignored.uri, version: 3 });
  assert.equal(collection.inspect().values.has(ignored.uri), false);
  diagnostics.dispose();
});
