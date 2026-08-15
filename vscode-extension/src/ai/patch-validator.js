const path = require('path');

const MAX_PATCH_CHARS = 100000;
const FORBIDDEN = /(^|\/)(\.env|\.git|node_modules|dist|build|.*\.(?:pem|key|p12|pfx))($|\/)/i;

function cleanDiffPath(value) {
  const clean = String(value || '').trim().split(/\s/)[0].replace(/^[ab]\//, '').replaceAll('\\', '/');
  if (!clean || clean === '/dev/null' || clean.startsWith('/') || /^[A-Za-z]:/.test(clean) || clean.split('/').includes('..')) throw new Error('Chemin de patch interdit.');
  if (FORBIDDEN.test(clean)) throw new Error('Le patch cible un fichier sensible ou généré.');
  return clean;
}

function parseUnifiedDiff(patch) {
  if (typeof patch !== 'string' || !patch.trim()) throw new Error('Patch vide.');
  if (patch.length > MAX_PATCH_CHARS) throw new Error('Patch trop volumineux.');
  const lines = patch.replace(/\r\n/g, '\n').split('\n');
  const oldHeaders = lines.filter((line) => line.startsWith('--- '));
  const newHeaders = lines.filter((line) => line.startsWith('+++ '));
  if (oldHeaders.length !== 1 || newHeaders.length !== 1) throw new Error('Le patch doit modifier exactement un fichier existant.');
  const oldFile = cleanDiffPath(oldHeaders[0].slice(4));
  const newFile = cleanDiffPath(newHeaders[0].slice(4));
  if (oldFile !== newFile) throw new Error('Le renommage de fichier est interdit.');
  const hunks = [];
  let current;
  for (const line of lines) {
    const match = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (match) { current = { oldStart: Number(match[1]), oldCount: Number(match[2] || 1), newStart: Number(match[3]), newCount: Number(match[4] || 1), lines: [] }; hunks.push(current); continue; }
    if (current && (/^[ +\-]/.test(line) || line === '\\ No newline at end of file')) current.lines.push(line);
  }
  if (!hunks.length) throw new Error('Le patch ne contient aucun hunk applicable.');
  return { file: oldFile, hunks, patch };
}

function normalizeModelPatch(patch, expectedFile) {
  const value = String(patch || '').trim().replace(/^```diff\s*/i, '').replace(/\s*```$/, '');
  if (value.startsWith('@@ ')) return `--- a/${expectedFile}\n+++ b/${expectedFile}\n${value}`;
  return value;
}

function replacementToPatch(source, expectedFile, oldText, newText) {
  let oldLines = String(oldText || '').replace(/\r\n/g, '\n').split('\n');
  let newLines = String(newText || '').replace(/\r\n/g, '\n').split('\n');
  if (!String(oldText || '') || oldLines.length > 20 || newLines.length > 20) throw new Error('La correction IA doit rester un remplacement minimal.');
  if (String(oldText) === String(newText)) throw new Error('La correction IA ne modifie pas le code.');
  const offensivePayload = /(\bor\b\s+['"\d]+\s*=\s*['"\d]+|<script\b|javascript\s*:|\.\.\/\.\.\/|;\s*(?:rm|del|curl|wget)\b)/i;
  if (offensivePayload.test(String(newText))) throw new Error('La proposition IA ressemble à un payload offensif et non à un correctif.');
  const input = String(source).replace(/\r\n/g, '\n').split('\n');
  const matches = [];
  for (let index = 0; index <= input.length - oldLines.length; index += 1) {
    if (oldLines.every((line, offset) => input[index + offset] === line)) matches.push(index);
  }
  if (!matches.length && oldLines.length === 1) {
    for (let index = 0; index < input.length; index += 1) {
      if (input[index].trim() === oldLines[0].trim()) matches.push(index);
    }
    if (matches.length === 1) {
      const indentation = input[matches[0]].match(/^\s*/)[0];
      oldLines = [input[matches[0]]];
      newLines = newLines.map((line) => line ? `${indentation}${line.trimStart()}` : line);
    }
  }
  if (!matches.length && oldLines.length === 1 && newLines.length === 1) {
    const occurrences = [];
    input.forEach((line, index) => {
      let offset = line.indexOf(oldLines[0]);
      while (offset >= 0) { occurrences.push({ index, offset }); offset = line.indexOf(oldLines[0], offset + 1); }
    });
    if (occurrences.length === 1) {
      const { index, offset } = occurrences[0];
      const actualLine = input[index];
      const indentation = actualLine.match(/^\s*/)[0];
      const actualTrimmed = actualLine.trim();
      const proposedTrimmed = newLines[0].trim();
      const looksLikeWholeLine = /^(?:<|const\b|let\b|var\b|return\b|function\b|class\b|if\b)/.test(proposedTrimmed)
        && proposedTrimmed !== oldLines[0].trim()
        && proposedTrimmed.length >= actualTrimmed.length - oldLines[0].length;
      newLines = [looksLikeWholeLine
        ? `${indentation}${proposedTrimmed}`
        : `${actualLine.slice(0, offset)}${newLines[0]}${actualLine.slice(offset + oldLines[0].length)}`];
      oldLines = [actualLine];
      matches.push(index);
    }
  }
  if (matches.length !== 1) throw new Error(matches.length ? 'Le texte source proposé par l’IA est ambigu.' : 'Le texte source proposé par l’IA ne correspond pas au fichier.');
  const start = matches[0] + 1;
  return `--- a/${expectedFile}\n+++ b/${expectedFile}\n@@ -${start},${oldLines.length} +${start},${newLines.length} @@\n${[...oldLines.map((line) => `-${line}`), ...newLines.map((line) => `+${line}`)].join('\n')}`;
}

function validatePatchForFinding(parsed, finding) {
  const expected = String(finding.file || '').replaceAll('\\', '/').replace(/^\.\//, '');
  if (parsed.file !== expected) throw new Error(`Le patch vise ${parsed.file} au lieu du fichier autorisé ${expected}.`);
  if (parsed.hunks.length !== 1) throw new Error('La correction IA doit contenir exactement un hunk minimal.');
  const hunk = parsed.hunks[0];
  const changedLines = hunk.lines.filter((line) => line.startsWith('+') || line.startsWith('-')).length;
  if (changedLines > 20) throw new Error('La correction IA modifie trop de lignes.');
  const findingLine = Math.max(1, Number(finding.startLine || 0) + 1);
  const hunkEnd = hunk.oldStart + Math.max(1, hunk.oldCount) - 1;
  if (findingLine < hunk.oldStart - 3 || findingLine > hunkEnd + 3) throw new Error('Le patch ne concerne pas la ligne signalée.');
  return parsed;
}

function reanchorParsedPatch(source, parsed) {
  if (parsed.hunks.length !== 1) return parsed;
  const hunk = parsed.hunks[0];
  const expected = hunk.lines
    .filter((line) => line.startsWith(' ') || line.startsWith('-'))
    .map((line) => line.slice(1));
  if (!expected.length) throw new Error('Le patch IA ne contient aucun texte source vérifiable.');
  const input = String(source).replace(/\r\n/g, '\n').split('\n');
  const matches = [];
  for (let index = 0; index <= input.length - expected.length; index += 1) {
    if (expected.every((line, offset) => input[index + offset] === line)) matches.push(index);
  }
  if (matches.length !== 1) throw new Error(matches.length ? 'Le contexte du patch IA est ambigu dans le fichier.' : 'Le patch ne correspond plus au contenu actuel.');
  const oldStart = matches[0] + 1;
  const oldCount = expected.length;
  const additions = hunk.lines.filter((line) => line.startsWith('+')).length;
  const removals = hunk.lines.filter((line) => line.startsWith('-')).length;
  return { ...parsed, hunks: [{ ...hunk, oldStart, oldCount, newStart: oldStart, newCount: oldCount - removals + additions }] };
}

function applyParsedPatch(source, parsed) {
  const input = String(source).replace(/\r\n/g, '\n').split('\n');
  const output = []; let cursor = 0;
  for (const hunk of parsed.hunks) {
    const target = hunk.oldStart - 1;
    if (target < cursor) throw new Error('Hunks chevauchants ou désordonnés.');
    output.push(...input.slice(cursor, target)); cursor = target;
    for (const line of hunk.lines) {
      if (line === '\\ No newline at end of file') continue;
      const marker = line[0]; const text = line.slice(1);
      if (marker === ' ' || marker === '-') {
        if (input[cursor] !== text) throw new Error('Le patch ne correspond plus au contenu actuel.');
        if (marker === ' ') output.push(text);
        cursor += 1;
      } else if (marker === '+') output.push(text);
    }
  }
  output.push(...input.slice(cursor));
  return output.join('\n');
}

function calculateFixConfidence(generated, parsed) {
  const changed = parsed.hunks[0]?.lines.filter((line) => line.startsWith('+') || line.startsWith('-')).length || 0;
  let score = 0.45;
  if (parsed.hunks.length === 1) score += 0.15;
  if (changed <= 4) score += 0.1;
  if (generated.securityReason && generated.securityReason.length >= 20) score += 0.1;
  if (Array.isArray(generated.assumptions) && generated.assumptions.length === 0) score += 0.1;
  score += Math.min(0.1, Math.max(0, Number(generated.confidence || 0)) * 0.1);
  return Math.round(Math.min(1, score) * 100) / 100;
}

module.exports = { MAX_PATCH_CHARS, cleanDiffPath, normalizeModelPatch, replacementToPatch, parseUnifiedDiff, reanchorParsedPatch, validatePatchForFinding, applyParsedPatch, calculateFixConfidence };
