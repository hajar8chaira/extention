const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { MARKER, hookContent, installPreCommitHook } = require('../src/precommit');

test('le hook utilise Gitleaks local puis Docker et bloque sans outil', () => {
  const content = hookContent();
  assert.match(content, /gitleaks git --pre-commit --redact --staged --verbose/);
  assert.match(content, /zricethezav\/gitleaks:latest/);
  assert.match(content, /exit 1/);
  assert.ok(content.includes(MARKER));
});

test('installe le hook une seule fois et refuse d’écraser un hook tiers', async () => {
  const firstRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'security-center-hook-'));
  execFileSync('git', ['init', '--quiet', firstRepo]);
  const installed = await installPreCommitHook(firstRepo);
  assert.equal(installed.status, 'installed');
  assert.match(fs.readFileSync(installed.hookPath, 'utf8'), /security-center-gitleaks-hook/);
  assert.equal((await installPreCommitHook(firstRepo)).status, 'already-installed');

  const secondRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'security-center-hook-existing-'));
  execFileSync('git', ['init', '--quiet', secondRepo]);
  const hookPath = path.join(secondRepo, '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hookPath, '#!/bin/sh\necho existing\n');
  await assert.rejects(() => installPreCommitHook(secondRepo), /ne l’a pas remplacé/);
});
