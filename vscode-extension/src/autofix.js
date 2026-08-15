const path = require('path');

const MAX_FIX_LENGTH = 256 * 1024;

function normalizeEol(value) {
  return String(value ?? '').replace(/\r\n/g, '\n');
}

function buildAutofixPlan(finding, workspacePath, currentText) {
  if (finding?.tool !== 'Semgrep') throw new Error('Seules les corrections natives Semgrep sont applicables automatiquement.');
  if (typeof finding.autofix !== 'string' || !finding.autofix.length) throw new Error('Cette alerte ne contient aucune correction native du scanner.');
  if (finding.autofix.length > MAX_FIX_LENGTH) throw new Error('La correction proposée dépasse la limite de 256 Kio.');
  const absolutePath = path.resolve(String(finding.absolutePath || ''));
  const workspace = path.resolve(String(workspacePath || ''));
  const relative = path.relative(workspace, absolutePath);
  if (!absolutePath || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Le fichier à corriger doit rester dans le workspace.');
  if (finding.originalText && normalizeEol(currentText) !== normalizeEol(finding.originalText)) {
    throw new Error('Le code a changé depuis le scan. Relancez Semgrep avant d’appliquer la correction.');
  }
  return {
    absolutePath, replacement: finding.autofix, originalText: String(currentText || ''),
    startLine: Math.max(0, Number(finding.startLine) || 0),
    startColumn: Math.max(0, Number(finding.startColumn) || 0),
    endLine: Math.max(0, Number(finding.endLine) || 0),
    endColumn: Math.max(0, Number(finding.endColumn) || 0)
  };
}

module.exports = { MAX_FIX_LENGTH, normalizeEol, buildAutofixPlan };
