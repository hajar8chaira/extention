const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeJavaScriptText, analyzeLiveDocument, deduplicateRootFindings, isLikelyIncompleteSource } = require('../src/live/liveDetector');

function analyze(text) {
  return analyzeJavaScriptText({ text, uri: 'file:///repo/app.ts', documentVersion: 7 });
}

const cases = [
  ['unsafe-eval', 'eval(req.body.code)'],
  ['unsafe-function-constructor', 'const fn = new Function(req.body.code)'],
  ['sql-string-concatenation', 'db.query("SELECT * FROM users WHERE id=" + req.params.id)'],
  ['dynamic-command-execution', 'exec(`convert ${req.body.file}`)'],
  ['unsafe-innerhtml', 'element.innerHTML = userInput'],
  ['weak-hash', "crypto.createHash('md5').update(password)"],
  ['hardcoded-credential', "const apiKey = 'abcdefghijk12345'"],
  ['tls-verification-disabled', 'const options = { rejectUnauthorized: false }'],
  ['potential-path-traversal', 'fs.readFile(req.query.path, callback)'],
  ['shell-child-process', "spawn('tool', args, { shell: true })"]
];

for (const [ruleId, source] of cases) {
  test(`détecte ${ruleId}`, () => {
    const finding = analyze(source).find((item) => item.ruleId === ruleId);
    assert.ok(finding, source);
    assert.equal(finding.source, 'Security Center Live');
    assert.equal(finding.documentVersion, 7);
    assert.match(finding.label, /Potential issue|Live warning/);
    assert.ok(finding.range.end.character > finding.range.start.character);
    assert.equal(Object.isFrozen(finding), true);
  });
}

test('évite les variantes littérales sûres et les commentaires', () => {
  const findings = analyze(`
    // eval(req.body.code)
    const fixed = eval('2 + 2')
    db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
    element.textContent = userInput
    crypto.createHash('sha256')
    spawn('tool', ['--safe'], { shell: false })
  `);
  assert.deepEqual(findings, []);
});

test('conserve une plage exacte sur plusieurs lignes', () => {
  const findings = analyze('const ok = true;\n\neval(req.query.code);');
  assert.equal(findings[0].range.start.line, 2);
  assert.equal(findings[0].range.start.character, 0);
});

test('ne produit rien pour un langage non pris en charge ou une analyse annulée', async () => {
  const document = { languageId: 'python', version: 1, uri: { toString: () => 'file:///x.py' }, getText: () => 'eval(input())' };
  assert.deepEqual(await analyzeLiveDocument(document), []);
  assert.deepEqual(analyzeJavaScriptText({ text: 'eval(req.body.x)', uri: 'file:///x.js', documentVersion: 1, signal: { aborted: true } }), []);
});

test('ne persiste aucun finding et ne propose pas encore de quick fix', () => {
  const finding = analyze('eval(req.body.code)')[0];
  assert.equal(finding.quickFixAvailable, false);
  assert.equal('triageStatus' in finding, false);
  assert.equal('persisted' in finding, false);
});

test('tolère le code manifestement incomplet pendant la frappe', () => {
  assert.equal(isLikelyIncompleteSource('db.query("SELECT *'), true);
  assert.deepEqual(analyze('db.query("SELECT *'), []);
});

test('déduplique une même expression racine', () => {
  const duplicate = analyze('eval(req.body.code)')[0];
  assert.equal(deduplicateRootFindings([duplicate, duplicate]).length, 1);
});
