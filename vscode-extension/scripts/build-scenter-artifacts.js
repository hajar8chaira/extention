#!/usr/bin/env node
'use strict';

/**
 * Builds Security Center's distributable artefacts from one source commit.
 *
 *   npm run check + npm test
 *     → build-info.json (name, version, commit, build timestamp)
 *     → VSIX   (npm run package:vsix, the existing vsce flow)
 *     → CLI .tgz (npm pack, the existing npm package)
 *     → both verified to embed the same commit, SHA-256 computed
 *     → security-center-build.json, then security-center-latest.json (last)
 *
 * Guarantees:
 *   - a failed check, test or packaging step writes nothing to the output
 *     directory: the previous manifest stays the latest;
 *   - a working tree with uncommitted changes never produces a latest manifest,
 *     because no commit could honestly be named as its source;
 *   - build-info.json is removed from the extension folder after packaging.
 *
 * Usage:
 *   node scripts/build-scenter-artifacts.js [--out <dir>] [--base-url <https url>]
 *                                           [--skip-checks] [--skip-tests] [--allow-dirty]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { spawnSync } = require('child_process');
const { pathToFileURL } = require('url');

const EXTENSION_ROOT = path.resolve(__dirname, '..');
const BUILD_INFO_FILE = 'build-info.json';
const MANIFEST_FILE = 'security-center-latest.json';
const BUILD_RECORD_FILE = 'security-center-build.json';
const MANIFEST_SCHEMA = 1;

class BuildError extends Error {}

function parseArgs(argv = []) {
  const options = {
    out: path.resolve(EXTENSION_ROOT, '..', 'dist'),
    baseUrl: '', skipChecks: false, skipTests: false, allowDirty: false, help: false
  };
  const value = (index, flag) => {
    if (index >= argv.length || String(argv[index]).startsWith('--')) throw new BuildError(`${flag} needs a value.`);
    return String(argv[index]);
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--out') options.out = path.resolve(value(++index, arg));
    else if (arg === '--base-url') options.baseUrl = value(++index, arg);
    else if (arg === '--skip-checks') options.skipChecks = true;
    else if (arg === '--skip-tests') options.skipTests = true;
    else if (arg === '--allow-dirty') options.allowDirty = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new BuildError(`Unknown argument: ${arg}`);
  }
  if (options.baseUrl && !/^https?:\/\/[^\s?#]+$/.test(options.baseUrl)) {
    throw new BuildError('--base-url must be an http(s) URL without query string.');
  }
  return options;
}

/** Runs npm/npx the same way on every platform. Returns the exit status. */
function defaultRun(command, args, { cwd = EXTENSION_ROOT } = {}) {
  const viaShell = process.platform === 'win32' && ['npm', 'npx'].includes(command);
  const quoted = viaShell ? args.map((arg) => (/[\s"]/.test(arg) ? `"${String(arg).replace(/"/g, '\\"')}"` : arg)) : args;
  const result = spawnSync(command, quoted, { cwd, stdio: 'inherit', shell: viaShell });
  return result.status === null ? 1 : result.status;
}

function gitOutput(args, cwd) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  return result.status === 0 ? String(result.stdout).trim() : null;
}

/** The source commit, and whether the working tree still matches it. */
function resolveIdentity({ cwd = EXTENSION_ROOT, env = process.env, git = gitOutput } = {}) {
  const commit = String(env.GITHUB_SHA || git(['rev-parse', 'HEAD'], cwd) || '').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new BuildError('Cannot determine the source commit (git rev-parse HEAD).');
  const status = git(['status', '--porcelain'], cwd);
  if (status === null) throw new BuildError('Cannot read the working tree status (git status).');
  return { commit, dirty: status !== '' };
}

/** One file of a ZIP archive (the VSIX), or null. Stored and deflated entries. */
function readZipEntry(buffer, name) {
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end < 0) throw new BuildError('not a ZIP archive');
  const count = buffer.readUInt16LE(end + 10);
  let offset = buffer.readUInt32LE(end + 16);
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) throw new BuildError('corrupt ZIP central directory');
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    if (buffer.toString('utf8', offset + 46, offset + 46 + nameLength) === name) {
      const start = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
      const data = buffer.subarray(start, start + compressedSize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return zlib.inflateRawSync(data);
      throw new BuildError(`unsupported ZIP compression method ${method}`);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return null;
}

/** One file of a gzipped tar archive (the npm package), or null. */
function readTgzEntry(buffer, name) {
  const tar = zlib.gunzipSync(buffer);
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const field = (start, length) => header.toString('utf8', start, start + length).split('\0')[0];
    const prefix = field(345, 155);
    const entryName = prefix ? `${prefix}/${field(0, 100)}` : field(0, 100);
    const size = parseInt(field(124, 12).trim() || '0', 8);
    if (entryName === name) return Buffer.from(tar.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}

const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

function writeAtomic(file, content) {
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content);
  fs.renameSync(temporary, file);
}

/**
 * The build. `run`, `identity` and `now` are injectable so the publication
 * rules can be tested without spawning a whole release.
 */
function buildArtifacts(options = {}, {
  run = defaultRun, identity = () => resolveIdentity(), now = () => new Date(),
  log = (message) => console.log(`[scenter-build] ${message}`), root = EXTENSION_ROOT
} = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const { commit, dirty } = identity();
  if (dirty && !options.allowDirty) {
    throw new BuildError('The working tree has uncommitted changes. Commit them (CI builds a commit), or pass --allow-dirty for a local build, which is never published as latest.');
  }

  if (!options.skipChecks) {
    log('npm run check');
    if (run('npm', ['run', 'check'], { cwd: root }) !== 0) throw new BuildError('npm run check failed: nothing was packaged or published.');
    if (!options.skipTests) {
      log('npm test');
      if (run('npm', ['test'], { cwd: root }) !== 0) throw new BuildError('npm test failed: nothing was packaged or published.');
    }
  }

  const out = path.resolve(options.out || path.resolve(root, '..', 'dist'));
  fs.mkdirSync(out, { recursive: true });
  const staging = fs.mkdtempSync(path.join(out, '.staging-'));
  const buildTimestamp = now().toISOString();
  const vsixName = `${pkg.name}-${pkg.version}.vsix`;
  const tgzName = `${pkg.name}-${pkg.version}.tgz`;
  const buildInfoPath = path.join(root, BUILD_INFO_FILE);
  const buildInfo = { name: pkg.name, version: pkg.version, commit, buildTimestamp, dirty };

  try {
    try {
      // The identity travels inside both artefacts: each can name its source commit.
      fs.writeFileSync(buildInfoPath, `${JSON.stringify(buildInfo, null, 2)}\n`);
      log(`packaging VSIX ${vsixName}`);
      if (run('npm', ['run', 'package:vsix', '--', '--out', path.join(staging, vsixName)], { cwd: root }) !== 0) {
        throw new BuildError('VSIX packaging failed: nothing was published.');
      }
      log(`packing CLI ${tgzName}`);
      if (run('npm', ['pack', '--pack-destination', staging], { cwd: root }) !== 0) {
        throw new BuildError('npm pack failed: nothing was published.');
      }
    } finally {
      fs.rmSync(buildInfoPath, { force: true });
    }

    const vsixPath = path.join(staging, vsixName);
    const tgzPath = path.join(staging, tgzName);
    if (!fs.existsSync(vsixPath)) throw new BuildError(`${vsixName} was not produced.`);
    if (!fs.existsSync(tgzPath)) throw new BuildError(`${tgzName} was not produced.`);
    const vsix = fs.readFileSync(vsixPath);
    const tgz = fs.readFileSync(tgzPath);
    for (const [label, entry] of [
      ['VSIX', readZipEntry(vsix, `extension/${BUILD_INFO_FILE}`)],
      ['TGZ', readTgzEntry(tgz, `package/${BUILD_INFO_FILE}`)]
    ]) {
      let embedded = null;
      try { embedded = entry ? JSON.parse(entry.toString('utf8')) : null; } catch { embedded = null; }
      if (!embedded || embedded.commit !== commit || embedded.version !== pkg.version) {
        throw new BuildError(`${label} does not embed the build identity of commit ${commit}.`);
      }
    }

    const assetUrl = (file) => (options.baseUrl
      ? `${options.baseUrl.replace(/\/+$/, '')}/${file}`
      : pathToFileURL(path.join(out, file)).href);
    const manifest = {
      schemaVersion: MANIFEST_SCHEMA,
      name: pkg.name,
      version: pkg.version,
      commit,
      buildTimestamp,
      tgz: { file: tgzName, url: assetUrl(tgzName), sha256: sha256(tgz), size: tgz.length },
      vsix: { file: vsixName, url: assetUrl(vsixName), sha256: sha256(vsix), size: vsix.length }
    };

    // Publication into the output directory: artefacts, build record, and the
    // latest manifest last — only once everything above has succeeded.
    fs.renameSync(tgzPath, path.join(out, tgzName));
    fs.renameSync(vsixPath, path.join(out, vsixName));
    writeAtomic(path.join(out, BUILD_RECORD_FILE), `${JSON.stringify({ ...manifest, dirty }, null, 2)}\n`);
    const manifestPath = path.join(out, MANIFEST_FILE);
    if (dirty) {
      // A stale latest manifest would now point at artefacts it does not describe.
      fs.rmSync(manifestPath, { force: true });
      log('uncommitted changes: build record written, no latest manifest');
    } else {
      writeAtomic(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      log(`latest manifest written for commit ${commit}`);
    }
    return { manifest, dirty, out, files: { vsix: path.join(out, vsixName), tgz: path.join(out, tgzName), record: path.join(out, BUILD_RECORD_FILE), manifest: dirty ? null : manifestPath } };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
      console.log('Usage: node scripts/build-scenter-artifacts.js [--out <dir>] [--base-url <https url>] [--skip-checks] [--skip-tests] [--allow-dirty]');
      process.exit(0);
    }
    const result = buildArtifacts(options);
    console.log(JSON.stringify({ ...result.manifest, dirty: result.dirty, out: result.out }, null, 2));
  } catch (error) {
    console.error(`[scenter-build] ERROR: ${error.message}`);
    process.exit(1);
  }
}

module.exports = {
  BUILD_INFO_FILE, MANIFEST_FILE, BUILD_RECORD_FILE, MANIFEST_SCHEMA, BuildError,
  parseArgs, resolveIdentity, buildArtifacts, readZipEntry, readTgzEntry
};
