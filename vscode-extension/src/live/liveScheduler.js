const path = require('path');

const SUPPORTED_LANGUAGES = new Set(['javascript', 'javascriptreact', 'typescript', 'typescriptreact']);
const IGNORED_DIRECTORIES = new Set(['node_modules', 'vendor', 'dist', 'build', 'coverage', '.git', 'generated']);
const MAX_FILE_SIZE_BYTES = 512 * 1024;
const SLOW_ANALYSIS_THRESHOLD_MS = 750;
const MAX_CONSECUTIVE_SLOW_ANALYSES = 3;

function uriKey(uri) {
  return typeof uri?.toString === 'function' ? uri.toString() : String(uri?.fsPath || uri || '');
}

function normalizedPath(document) {
  return String(document?.uri?.fsPath || document?.fileName || '').replace(/\\/g, '/');
}

function matchesIgnoredPath(filePath, exclusions = []) {
  const parts = filePath.toLowerCase().split('/');
  if (parts.some((part) => IGNORED_DIRECTORIES.has(part))) return true;
  if (/\.min\.(?:js|css)$/i.test(filePath) || /(?:^|\/)generated(?:\.|\/)/i.test(filePath)) return true;
  return exclusions.some((pattern) => {
    const normalized = String(pattern).replace(/\\/g, '/').replace(/^\.\//, '');
    const prefix = normalized.replace(/\*\*.*$/, '').replace(/\*.*$/, '').replace(/\/$/, '');
    return prefix && filePath.toLowerCase().includes(`/${prefix.toLowerCase()}/`);
  });
}

function isSupportedDocument(document, workspace, options = {}) {
  if (!document || document.isClosed || document.isUntitled) return false;
  if (!SUPPORTED_LANGUAGES.has(document.languageId)) return false;
  if (document.uri?.scheme && document.uri.scheme !== 'file') return false;
  if (!workspace.getWorkspaceFolder?.(document.uri)) return false;
  const filePath = normalizedPath(document);
  if (!filePath || matchesIgnoredPath(filePath, options.exclusions)) return false;
  const byteLength = Buffer.byteLength(document.getText?.() || '', 'utf8');
  return byteLength <= (options.maxFileSizeBytes || MAX_FILE_SIZE_BYTES);
}

class LiveScheduler {
  constructor({ workspace, window, analyzeDocument, debounceMs = 450, exclusions = [], maxFileSizeBytes = MAX_FILE_SIZE_BYTES, slowAnalysisThresholdMs = SLOW_ANALYSIS_THRESHOLD_MS, maxConsecutiveSlowAnalyses = MAX_CONSECUTIVE_SLOW_ANALYSES, onState = () => {}, onResult = () => {}, onError = () => {}, onTiming = () => {}, onPerformanceReduced = () => {} }) {
    this.workspace = workspace;
    this.window = window;
    this.analyzeDocument = analyzeDocument;
    this.debounceMs = debounceMs;
    this.exclusions = exclusions;
    this.maxFileSizeBytes = maxFileSizeBytes;
    this.onState = onState;
    this.onResult = onResult;
    this.onError = onError;
    this.onTiming = onTiming;
    this.onPerformanceReduced = onPerformanceReduced;
    this.slowAnalysisThresholdMs = slowAnalysisThresholdMs;
    this.maxConsecutiveSlowAnalyses = maxConsecutiveSlowAnalyses;
    this.consecutiveSlowAnalyses = 0;
    this.saveOnlyMode = false;
    this.generation = 0;
    this.timer = undefined;
    this.activeController = undefined;
    this.disposed = false;
  }

  schedule(document, immediate = false) {
    if (this.disposed || !this.isActiveDocument(document) || !isSupportedDocument(document, this.workspace, this)) return false;
    if (this.saveOnlyMode && !immediate) return false;
    this.cancelPending();
    const generation = ++this.generation;
    const uri = uriKey(document.uri);
    const version = document.version;
    this.onState('idle', { phase: 'scheduled', uri, version });
    this.timer = setTimeout(() => this.run(document, { generation, uri, version }), immediate ? 0 : this.debounceMs);
    return true;
  }

  isActiveDocument(document) {
    const active = this.window?.activeTextEditor?.document;
    return Boolean(active && uriKey(active.uri) === uriKey(document?.uri));
  }

  async run(document, token) {
    this.timer = undefined;
    if (!this.isCurrent(document, token)) return;
    this.activeController?.abort();
    const controller = new AbortController();
    this.activeController = controller;
    this.onState('analyzing', token);
    const startedAt = performance.now();
    const cpuStartedAt = process.cpuUsage();
    const memoryStartedAt = process.memoryUsage().heapUsed;
    try {
      const result = await this.analyzeDocument(document, { signal: controller.signal, uri: token.uri, version: token.version });
      if (!this.isCurrent(document, token) || controller.signal.aborted) return;
      const durationMs = performance.now() - startedAt;
      const cpu = process.cpuUsage(cpuStartedAt);
      const timing = {
        uri: token.uri,
        version: token.version,
        debounceMs: this.debounceMs,
        analysisMs: Math.round(durationMs * 10) / 10,
        cpuMs: Math.round(((cpu.user + cpu.system) / 1000) * 10) / 10,
        heapDeltaBytes: process.memoryUsage().heapUsed - memoryStartedAt
      };
      this.onTiming(timing);
      if (durationMs > this.slowAnalysisThresholdMs) this.consecutiveSlowAnalyses += 1;
      else this.consecutiveSlowAnalyses = 0;
      if (!this.saveOnlyMode && this.consecutiveSlowAnalyses >= this.maxConsecutiveSlowAnalyses) {
        this.saveOnlyMode = true;
        this.onPerformanceReduced(timing);
      }
      this.onResult(result, token);
      this.onState(Array.isArray(result) && result.length ? 'issues' : 'clean', token);
    } catch (error) {
      if (controller.signal.aborted || !this.isCurrent(document, token)) return;
      this.onError(error, token);
      this.onState('error', token);
    } finally {
      if (this.activeController === controller) this.activeController = undefined;
    }
  }

  isCurrent(document, token) {
    return !this.disposed && token.generation === this.generation && document.version === token.version && this.isActiveDocument(document);
  }

  cancelPending() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.activeController?.abort();
    this.activeController = undefined;
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    this.cancelPending();
  }
}

module.exports = { LiveScheduler, MAX_CONSECUTIVE_SLOW_ANALYSES, MAX_FILE_SIZE_BYTES, SLOW_ANALYSIS_THRESHOLD_MS, SUPPORTED_LANGUAGES, isSupportedDocument, matchesIgnoredPath, uriKey };
