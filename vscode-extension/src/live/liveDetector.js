const { createLiveFinding } = require('./models');
const { JAVASCRIPT_LIVE_RULES } = require('./liveRules/javascriptRules');

function positionAt(text, offset) {
  const before = text.slice(0, offset);
  const lines = before.split('\n');
  return { line: lines.length - 1, character: lines[lines.length - 1].length };
}

function maskComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/gm, (comment) => comment.replace(/[^\n]/g, ' '));
}

function isLikelyIncompleteSource(text) {
  const clean = maskComments(text);
  const oddUnescaped = (quote) => {
    let count = 0;
    for (let index = 0; index < clean.length; index += 1) {
      if (clean[index] === quote && clean[index - 1] !== '\\') count += 1;
    }
    return count % 2 !== 0;
  };
  if (oddUnescaped('"') || oddUnescaped("'") || oddUnescaped('`')) return true;
  const pairs = [['(', ')'], ['[', ']'], ['{', '}']];
  return pairs.some(([open, close]) => (clean.match(new RegExp(`\\${open}`, 'g')) || []).length !== (clean.match(new RegExp(`\\${close}`, 'g')) || []).length);
}

function deduplicateRootFindings(findings) {
  const roots = new Set();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.range.start.line}:${finding.originalText}`;
    if (roots.has(key)) return false;
    roots.add(key);
    return true;
  });
}

function analyzeJavaScriptText({ text, uri, documentVersion, signal, rules = JAVASCRIPT_LIVE_RULES }) {
  if (signal?.aborted) return [];
  if (isLikelyIncompleteSource(text)) return [];
  const searchable = maskComments(text);
  const findings = [];
  const seen = new Set();
  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(searchable))) {
      if (signal?.aborted) return [];
      const key = `${rule.id}:${match.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(createLiveFinding({
          uri,
          documentVersion,
          rule,
          originalText: match[0],
          range: { start: positionAt(text, match.index), end: positionAt(text, match.index + match[0].length) }
        }));
      }
      if (match[0].length === 0) rule.pattern.lastIndex += 1;
    }
  }
  return deduplicateRootFindings(findings);
}

async function analyzeLiveDocument(document, context = {}) {
  if (!['javascript', 'javascriptreact', 'typescript', 'typescriptreact'].includes(document.languageId)) return [];
  return analyzeJavaScriptText({ text: document.getText(), uri: context.uri || document.uri?.toString?.() || String(document.uri), documentVersion: context.version ?? document.version, signal: context.signal });
}

module.exports = { analyzeJavaScriptText, analyzeLiveDocument, deduplicateRootFindings, isLikelyIncompleteSource, maskComments, positionAt };
