const JAVASCRIPT_LIVE_RULES = Object.freeze([
  {
    id: 'unsafe-eval', title: 'Potential unsafe eval', description: 'Dynamic code execution can run attacker-controlled JavaScript.', recommendation: 'Avoid dynamic code evaluation and use explicit data parsing or dispatch.', cwe: 'CWE-95', severity: 'high', confidence: 'high',
    pattern: /\beval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))[^)]+\)/g
  },
  {
    id: 'unsafe-function-constructor', title: 'Potential unsafe Function constructor', description: 'A dynamic Function constructor can execute untrusted code.', recommendation: 'Replace dynamic code construction with explicit functions.', cwe: 'CWE-95', severity: 'high', confidence: 'high',
    pattern: /\bnew\s+Function\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))[^)]+\)/g
  },
  {
    id: 'sql-string-concatenation', title: 'Potential SQL injection', description: 'A SQL query appears to concatenate request-controlled data.', recommendation: 'Use a parameterized query.', cwe: 'CWE-89', severity: 'high', confidence: 'high',
    // Two shapes are equally common and equally dangerous: the query built
    // inline inside query()/execute(), and the query assembled into a variable
    // first and executed later. Only matching the first missed the second.
    // Each quoting style is matched with its own delimiter, because a SQL
    // literal legitimately contains the other quote:
    //   "SELECT * FROM users WHERE id = '" + req.query.id
    pattern: /\b(?:query|execute|raw)\s*\(\s*["'`][^\n)]*\b(?:select|insert|update|delete)\b[^\n)]*(?:\+\s*(?:req\.(?:params|query|body)|request\.|ctx\.)|\$\{\s*(?:req\.|request\.|ctx\.))[^\n)]*|(?:"[^"\n]*\b(?:select|insert|update|delete)\b[^"\n]*"|'[^'\n]*\b(?:select|insert|update|delete)\b[^'\n]*')\s*\+\s*[^;\n]*\b(?:req|request|ctx)\.(?:params|query|body)\b|`[^`\n]*\b(?:select|insert|update|delete)\b[^`\n]*\$\{\s*(?:req|request|ctx)\.(?:params|query|body)/gi
  },
  {
    id: 'dynamic-command-execution', title: 'Potential command injection', description: 'A system command appears to include request-controlled data.', recommendation: 'Use a fixed executable and pass validated values as separate arguments.', cwe: 'CWE-78', severity: 'high', confidence: 'high',
    // Request data passed straight through — `exec(req.query.cmd)` — is the
    // most direct form of this bug and was not matched at all: the pattern
    // required a concatenation or a template literal.
    pattern: /\b(?:exec|execSync)\s*\(\s*(?:[^\n)]*\+\s*(?:req\.|request\.|ctx\.)|`[^`]*\$\{\s*(?:req\.|request\.|ctx\.)|(?:req|request|ctx)\.(?:params|query|body)\b)/g
  },
  {
    id: 'unsafe-innerhtml', title: 'Potential DOM XSS', description: 'Untrusted-looking data is assigned directly to innerHTML.', recommendation: 'Use textContent or a trusted sanitization mechanism.', cwe: 'CWE-79', severity: 'medium', confidence: 'medium',
    pattern: /\.innerHTML\s*=\s*(?:req\.|request\.|location\.|document\.URL|[^;\n]*(?:userInput|input|message))/gi
  },
  {
    id: 'weak-hash', title: 'Weak cryptographic hash', description: 'MD5 or SHA-1 should not protect passwords, signatures, or security-sensitive data.', recommendation: 'Use a modern algorithm appropriate for the security purpose.', cwe: 'CWE-328', severity: 'medium', confidence: 'high',
    pattern: /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi
  },
  {
    id: 'hardcoded-credential', title: 'Potential hardcoded credential', description: 'A credential-like variable contains a literal value.', recommendation: 'Load the credential from a protected secret source.', cwe: 'CWE-798', severity: 'high', confidence: 'medium',
    pattern: /\b(?:password|passwd|apiKey|api_key|secret|accessToken|access_token)\s*[:=]\s*["'][^"'\s]{8,}["']/gi
  },
  {
    id: 'tls-verification-disabled', title: 'TLS verification disabled', description: 'Disabling certificate verification exposes connections to interception.', recommendation: 'Keep certificate verification enabled and configure a trusted CA when needed.', cwe: 'CWE-295', severity: 'high', confidence: 'high', quickFixAvailable: true,
    pattern: /\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?)/g
  },
  {
    id: 'potential-path-traversal', title: 'Potential path traversal', description: 'A filesystem path appears to include request-controlled data.', recommendation: 'Resolve against an allowed base directory and validate the final path.', cwe: 'CWE-22', severity: 'high', confidence: 'medium',
    pattern: /\b(?:readFile|readFileSync|createReadStream|sendFile|writeFile|writeFileSync)\s*\(\s*[^\n)]*(?:req\.(?:params|query|body)|request\.|ctx\.)/g
  },
  {
    id: 'shell-child-process', title: 'Potential unsafe shell execution', description: 'Spawning a process through a shell can enable command injection.', recommendation: 'Disable shell execution and pass validated arguments directly.', cwe: 'CWE-78', severity: 'medium', confidence: 'medium',
    pattern: /\bspawn\s*\([^\n;]+\{[^}\n]*\bshell\s*:\s*true/g
  }
]);

module.exports = { JAVASCRIPT_LIVE_RULES };
