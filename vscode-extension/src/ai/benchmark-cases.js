const cases = [
  ['sql-injection', 'javascript', 'const rows = db.query("SELECT * FROM users WHERE id=" + req.params.id);', 'javascript.lang.security.audit.sqli', 'CWE-89', /\?|:\w+|\$\d+/],
  ['xss-innerhtml', 'javascript', 'element.innerHTML = req.query.message;', 'javascript.browser.security.insecure-document-method', 'CWE-79', /textContent|sanitize|escape/i],
  ['command-injection', 'javascript', 'exec("convert " + req.body.file);', 'javascript.lang.security.detect-child-process', 'CWE-78', /execFile|spawn\s*\(/],
  ['path-traversal', 'javascript', 'const file = path.join(root, req.query.name);', 'javascript.lang.security.audit.path-traversal', 'CWE-22', /resolve|basename|normalize/],
  ['unsafe-eval', 'javascript', 'const result = eval(req.body.expression);', 'javascript.lang.security.detect-eval-with-expression', 'CWE-95', /JSON\.parse|parser|allowlist/i],
  ['unsafe-function', 'javascript', 'const fn = new Function("return " + input);', 'javascript.lang.security.detect-function-constructor', 'CWE-95', /allowlist|parser|switch/i],
  ['weak-crypto-md5', 'javascript', "const digest = crypto.createHash('md5').update(value).digest('hex');", 'javascript.lang.security.audit.weak-crypto', 'CWE-328', /sha256|sha384|sha512/i],
  ['hardcoded-password', 'javascript', "const password = 'prod-secret-123';", 'generic.secrets.security.detected-generic-secret', 'CWE-798', /process\.env|config|secret/i],
  ['tls-disabled', 'javascript', 'const agent = new https.Agent({ rejectUnauthorized: false });', 'javascript.lang.security.audit.tls-reject-unauthorized', 'CWE-295', /rejectUnauthorized:\s*true|rejectUnauthorized\s*\}/],
  ['authorization', 'javascript', 'app.get("/admin", (req, res) => res.json(loadAdminData()));', 'custom.missing-authorization', 'CWE-862', /authoriz|permission|role|isAdmin/i],
  ['ssrf', 'javascript', 'const response = await fetch(req.query.url);', 'javascript.lang.security.audit.ssrf', 'CWE-918', /allowlist|hostname|protocol/i],
  ['unsafe-file-write', 'javascript', 'fs.writeFileSync(req.body.path, req.body.content);', 'javascript.lang.security.audit.path-traversal', 'CWE-73', /resolve|basename|allowlist/i],
  ['insecure-deserialization', 'javascript', 'const object = serialize.unserialize(req.body.payload);', 'javascript.lang.security.audit.insecure-deserialization', 'CWE-502', /JSON\.parse|schema|validate/i],
  ['xpath-injection', 'javascript', 'xml.find("//user[id=" + req.query.id + "]");', 'javascript.lang.security.audit.xpath-injection', 'CWE-643', /escape|parameter|validate/i],
  ['prototype-pollution', 'javascript', 'Object.assign(settings, req.body);', 'javascript.lang.security.audit.prototype-pollution', 'CWE-1321', /allowlist|pick|schema|validate/i],
  ['sql-injection-numeric', 'javascript', 'db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);', 'javascript.lang.security.audit.sqli', 'CWE-89', /\?|:\w+|\$\d+/],
  ['sql-injection-order', 'javascript', 'db.query("SELECT * FROM orders ORDER BY " + req.query.sort);', 'javascript.lang.security.audit.sqli', 'CWE-89', /allowlist|switch|valid/i],
  ['xss-document-write', 'javascript', 'document.write(req.query.banner);', 'javascript.browser.security.insecure-document-method', 'CWE-79', /textContent|sanitize|escape/i],
  ['xss-template', 'javascript', 'container.innerHTML = `<p>${req.body.name}</p>`;', 'javascript.browser.security.insecure-document-method', 'CWE-79', /textContent|sanitize|escape/i],
  ['command-exec-sync', 'javascript', 'execSync("tar -xf " + req.body.archive);', 'javascript.lang.security.detect-child-process', 'CWE-78', /execFileSync|spawnSync|allowlist/i],
  ['command-shell', 'javascript', 'spawn(req.body.command, [], { shell: true });', 'javascript.lang.security.detect-child-process', 'CWE-78', /shell:\s*false|allowlist/i],
  ['path-read-file', 'javascript', 'const data = fs.readFileSync(path.join(root, req.params.file));', 'javascript.lang.security.audit.path-traversal', 'CWE-22', /resolve|basename|normalize/],
  ['path-download', 'javascript', 'res.download(root + "/" + req.query.file);', 'javascript.lang.security.audit.path-traversal', 'CWE-22', /resolve|basename|normalize|allowlist/i],
  ['ssrf-protocol', 'javascript', 'await axios.get(req.body.callbackUrl);', 'javascript.lang.security.audit.ssrf', 'CWE-918', /allowlist|hostname|protocol/i],
  ['hardcoded-api-token', 'javascript', "const apiToken = 'sk_live_benchmark_placeholder';", 'generic.secrets.security.detected-generic-secret', 'CWE-798', /process\.env|config|secret/i]
].map(([id, language, vulnerableSnippet, ruleId, cwe, expectedPattern]) => ({
  id, language, vulnerableSnippet,
  finding: { id, tool: 'Benchmark', ruleId, title: id.replaceAll('-', ' '), severity: 'HIGH', cwe, file: `${id}.js`, startLine: 0, endLine: 0 },
  expectedSecurityProperty: `The resulting code must remove ${cwe} without disabling validation or tests.`,
  expectedPattern,
  unsafeAlternativePatterns: [/decodeURIComponent\s*\(/i, /rejectUnauthorized\s*:\s*false/i, /`[^`]*\$\{[^}]+\}[^`]*`/],
  testCommand: null
}));

module.exports = { BENCHMARK_CASES: Object.freeze(cases) };
