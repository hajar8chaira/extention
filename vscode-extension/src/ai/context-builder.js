const path = require('path');

const MAX_CONTEXT_CHARS = 16000;
const SENSITIVE_NAMES = /(^|\/)(\.env(?:\.|$)|id_rsa|id_ed25519|.*\.(?:pem|key|p12|pfx)|credentials?(?:\.|$)|secrets?(?:\.|$))/i;
const SECRET_ASSIGNMENT = /\b(api[_-]?key|token|password|secret|authorization)\s*=\s*(["'`])([^\r\n"'`]+)\2/gi;
const SECRET_JSON = /(["'](?:api[_-]?key|token|password|secret|authorization)["']\s*:\s*)(["'])([^\r\n"']+)\2/gi;
const SECRET_YAML = /^(\s*(?:key|api[_-]?key|token|password|secret|authorization)\s*:\s*)(["']?)([^\r\n#"']+)(["']?)(\s*(?:#.*)?)$/gim;

function safeRelativeFile(workspacePath, absolutePath) {
  const workspace = path.resolve(workspacePath);
  const file = path.resolve(absolutePath);
  const relative = path.relative(workspace, file).replaceAll('\\', '/');
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Le fichier IA doit rester dans le workspace.');
  if (SENSITIVE_NAMES.test(relative)) throw new Error('Les fichiers sensibles ne sont jamais envoyés au modèle.');
  return relative;
}

function redactSecrets(value) {
  return String(value || '')
    .replace(SECRET_ASSIGNMENT, '$1 = $2[REDACTED]$2')
    .replace(SECRET_JSON, '$1$2[REDACTED]$2')
    .replace(SECRET_YAML, '$1$2[REDACTED]$4$5')
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----/g, '[PRIVATE KEY REDACTED]');
}

function buildMinimalContext(finding, workspacePath, sourceText, radius = 35) {
  const file = safeRelativeFile(workspacePath, finding.absolutePath);
  const lines = String(sourceText || '').split(/\r?\n/);
  const start = Math.max(0, Number(finding.startLine || 0) - radius);
  const end = Math.min(lines.length, Number(finding.endLine ?? finding.startLine ?? 0) + radius + 1);
  const imports = lines.filter((line) => /^\s*(?:import\b|const\s+.+?=\s*require\()/i.test(line)).slice(0, 20);
  const declarations = lines.filter((line) => /^\s*(?:export\s+)?(?:interface|type|class|enum)\s+\w+/i.test(line)).slice(0, 20);
  let functionStart = Math.max(0, Number(finding.startLine || 0));
  const functionLike = /^\s*(?:export\s+)?(?:async\s+)?(?:function\s+[\w$]+|(?:const|let|var)\s+[\w$]+\s*=|(?:(?:public|private|protected|static|async)\s+)*[\w$]+\s*\()/i;
  while (functionStart > 0 && !functionLike.test(lines[functionStart])) functionStart -= 1;
  const functionEnd = Math.min(lines.length, Math.max(end, functionStart + 1));
  const sectionStart = Math.min(start, functionStart);
  const numbered = lines.slice(sectionStart, functionEnd).map((line, index) => `${sectionStart + index + 1}: ${redactSecrets(line)}`).join('\n');
  const sections = [imports.length ? `Imports liés:\n${imports.join('\n')}` : '', declarations.length ? `Types déclarés dans le fichier:\n${declarations.join('\n')}` : '', `Code autour du finding:\n${numbered}`].filter(Boolean).join('\n\n');
  const excerpt = redactSecrets(sections).slice(0, MAX_CONTEXT_CHARS);
  return {
    finding: { id: finding.id, tool: finding.tool, ruleId: finding.ruleId, title: finding.title, severity: finding.rawSeverity, cwe: finding.cwe || '' },
    file, excerpt, excerptStartLine: sectionStart + 1, excerptEndLine: functionEnd,
    contextKinds: { imports: imports.length, declarations: declarations.length, enclosingFunction: functionStart < Number(finding.startLine || 0) }
  };
}

module.exports = { MAX_CONTEXT_CHARS, SENSITIVE_NAMES, safeRelativeFile, redactSecrets, buildMinimalContext };
