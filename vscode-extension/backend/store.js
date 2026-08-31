'use strict';

/**
 * The persistence of the Security Center local backend.
 *
 * The FastAPI implementation this replaces kept everything in one SQLite file.
 * SQLite is not available here: the backend now runs on the Node that VS Code
 * already ships, and reaching SQLite from it would mean a native module — the
 * exact per-platform binary this whole architecture exists to avoid. So the
 * store is made of plain files, chosen to match how the data is actually used:
 *
 *   - A scan is large, written once and read whole. One file per scan.
 *   - A scan summary is small and read as a list. One appended line each,
 *     in `scans/index.jsonl`, so listing 100 scans does not open 100 payloads.
 *   - Audit events and HTTP scenarios are appended and read back in order.
 *     One JSONL file each.
 *
 * Every write is atomic (write a temporary file, rename over the target) or an
 * append, so an editor that is closed mid-write leaves a readable store rather
 * than a truncated one. A corrupted line is skipped, not fatal: a history that
 * lost one entry is still a history.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { NotFoundError } = require('./contract');

function readJsonLines(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const entries = [];
  for (const line of raw.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    try { entries.push(JSON.parse(text)); } catch { /* a damaged line is not a damaged history */ }
  }
  return entries;
}

function appendJsonLine(file, entry) {
  fs.appendFileSync(file, `${JSON.stringify(entry)}\n`, 'utf8');
}

function writeJsonAtomic(file, value) {
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), 'utf8');
  fs.renameSync(temporary, file);
}

/** The identity of an HTTP scenario: the same exchange captured twice is one scenario. */
function scenarioFingerprint(scenario) {
  const response = scenario.response;
  const identity = [
    String(scenario.request.method || '').toUpperCase(),
    scenario.request.url,
    scenario.request.body || '',
    response ? String(response.statusCode) : '',
    response ? String(response.bodySha256 || '') : ''
  ].join('\n');
  return crypto.createHash('sha256').update(identity, 'utf8').digest('hex');
}

class FileStore {
  constructor(dataDir) {
    this.dataDir = path.resolve(dataDir);
    this.scanDir = path.join(this.dataDir, 'scans');
    this.scanIndexFile = path.join(this.scanDir, 'index.jsonl');
    this.auditFile = path.join(this.dataDir, 'audit-events.jsonl');
    this.scenarioFile = path.join(this.dataDir, 'http-scenarios.jsonl');
  }

  initialize() {
    fs.mkdirSync(this.scanDir, { recursive: true });
    for (const file of [this.scanIndexFile, this.auditFile, this.scenarioFile]) {
      if (!fs.existsSync(file)) fs.writeFileSync(file, '', 'utf8');
    }
    return this;
  }

  /** Identifiers continue where the store left off, so an id never names two scans. */
  nextId(entries, key) {
    return entries.reduce((highest, entry) => Math.max(highest, Number(entry[key]) || 0), 0) + 1;
  }

  scanFile(scanId) {
    return path.join(this.scanDir, `${scanId}.json`);
  }

  // ------------------------------------------------------------------ scans

  save(result) {
    const index = readJsonLines(this.scanIndexFile);
    const scanId = this.nextId(index, 'scan_id');
    writeJsonAtomic(this.scanFile(scanId), { scan_id: scanId, result });
    appendJsonLine(this.scanIndexFile, {
      scan_id: scanId,
      workspace: result.workspace,
      finding_count: result.findings.length,
      scanner_count: result.scanners.length,
      finished_at: result.finished_at
    });
    return scanId;
  }

  get(scanId) {
    try {
      return JSON.parse(fs.readFileSync(this.scanFile(scanId), 'utf8'));
    } catch {
      return null;
    }
  }

  latest() {
    const index = readJsonLines(this.scanIndexFile);
    if (!index.length) return null;
    const newest = index.reduce((best, entry) => (Number(entry.scan_id) > Number(best.scan_id) ? entry : best));
    return this.get(newest.scan_id);
  }

  listScans(limit = 50) {
    return readJsonLines(this.scanIndexFile)
      .sort((a, b) => Number(b.scan_id) - Number(a.scan_id))
      .slice(0, limit);
  }

  /**
   * Moves one finding to a new triage status and records why.
   *
   * The scan payload and the audit entry are written together: a status that
   * changed without a trace is the one thing an audit journal cannot survive.
   */
  updateFindingStatus(scanId, findingId, status, actor, comment) {
    const stored = this.get(scanId);
    if (!stored) return null;
    let updated = false;
    const findings = stored.result.findings.map((finding) => {
      if (finding.id !== findingId) return finding;
      updated = true;
      return {
        ...finding,
        triageStatus: status,
        triageActor: actor,
        triageComment: comment,
        triageUpdatedAt: new Date().toISOString()
      };
    });
    if (!updated) return null;
    const result = { ...stored.result, findings };
    writeJsonAtomic(this.scanFile(scanId), { scan_id: Number(scanId), result });
    this.createAuditEvent({
      scan_id: Number(scanId),
      finding_id: findingId,
      action: `status:${status}`,
      actor,
      comment,
      metadata: {}
    });
    return { scan_id: Number(scanId), result };
  }

  // ---------------------------------------------------------------- journal

  listAuditEvents(limit = 200) {
    return readJsonLines(this.auditFile)
      .sort((a, b) => Number(b.event_id) - Number(a.event_id))
      .slice(0, limit);
  }

  createAuditEvent(event) {
    const existing = readJsonLines(this.auditFile);
    const stored = {
      event_id: this.nextId(existing, 'event_id'),
      created_at: new Date().toISOString(),
      comment: '',
      metadata: {},
      ...event
    };
    appendJsonLine(this.auditFile, stored);
    return stored;
  }

  // -------------------------------------------------------------- scenarios

  saveHttpScenario(scenario) {
    const fingerprint = scenarioFingerprint(scenario);
    const existing = readJsonLines(this.scenarioFile);
    const duplicate = existing.filter((entry) => entry.fingerprint === fingerprint).pop();
    // The same request captured twice from Burp is the same scenario. Returning
    // the stored one keeps replay history stable instead of growing a duplicate
    // every time the proxy sees the exchange again.
    if (duplicate) {
      const { fingerprint: _ignored, ...payload } = duplicate;
      return payload;
    }
    const stored = {
      scenario_id: this.nextId(existing, 'scenario_id'),
      created_at: new Date().toISOString(),
      ...scenario
    };
    appendJsonLine(this.scenarioFile, { ...stored, fingerprint });
    return stored;
  }

  listHttpScenarios(limit = 100) {
    return readJsonLines(this.scenarioFile)
      .sort((a, b) => Number(b.scenario_id) - Number(a.scenario_id))
      .slice(0, limit)
      .map(({ fingerprint: _ignored, ...scenario }) => scenario);
  }

  /** The scan a route named, or a 404 the service can return unchanged. */
  requireScan(scanId) {
    const stored = this.get(scanId);
    if (!stored) throw new NotFoundError('Scan not found');
    return stored;
  }
}

module.exports = { FileStore, scenarioFingerprint, readJsonLines };
