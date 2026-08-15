const { isLiveSecurityState } = require('./models');
const { LiveScheduler } = require('./liveScheduler');

class LiveSecurityService {
  constructor({ workspace, window, analyzeDocument = async () => [], diagnostics, configurationSection = 'securityCenter' }) {
    this.workspace = workspace;
    this.configurationSection = configurationSection;
    this.window = window;
    this.analyzeDocument = analyzeDocument;
    this.diagnostics = diagnostics;
    this.state = 'disabled';
    this.disposed = false;
    this.documentSubscriptions = [];
    this.stateListeners = new Set();
    this.performanceReduced = false;
    this.performanceNoticeShown = false;
    this.configurationSubscription = workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration(`${configurationSection}.live`)) this.refreshFromConfiguration();
    });
    this.refreshFromConfiguration();
  }
  get configuration() { return this.workspace.getConfiguration(this.configurationSection); }
  getState() { return this.state; }
  isPerformanceReduced() { return this.performanceReduced; }
  isEnabled() { return this.configuration.get('live.enabled', false) === true; }
  onDidChangeState(listener) {
    this.stateListeners.add(listener);
    return { dispose: () => this.stateListeners.delete(listener) };
  }
  setState(nextState) {
    if (!isLiveSecurityState(nextState)) throw new Error(`État Live Security inconnu : ${nextState}`);
    if (this.state === nextState) return;
    this.state = nextState;
    for (const listener of this.stateListeners) listener(nextState);
  }
  async enable() {
    await this.configuration.update('live.enabled', true, true);
    this.refreshFromConfiguration();
    return this.state;
  }
  async disable() {
    await this.configuration.update('live.enabled', false, true);
    this.refreshFromConfiguration();
    return this.state;
  }
  async toggle() { return this.isEnabled() ? this.disable() : this.enable(); }
  async analyzeNow(document) {
    if (this.disposed || !this.isEnabled()) return [];
    const token = { uri: document.uri.toString(), version: document.version };
    this.setState('analyzing');
    try {
      const findings = await this.analyzeDocument(document, token);
      if (document.version !== token.version) return [];
      this.diagnostics?.publish(findings, token);
      this.setState(findings.length ? 'issues' : 'clean');
      return findings;
    } catch (error) {
      this.setState('error');
      throw error;
    }
  }
  refreshFromConfiguration() {
    if (this.disposed) return;
    if (!this.isEnabled()) {
      this.disposeDocumentListeners();
      this.diagnostics?.clear();
      this.setState('disabled');
      return;
    }
    this.registerDocumentListeners();
    this.setState('idle');
  }
  registerDocumentListeners() {
    if (this.documentSubscriptions.length) return;
    const configuration = this.configuration;
    this.scheduler = new LiveScheduler({
      workspace: this.workspace,
      window: this.window,
      analyzeDocument: this.analyzeDocument,
      debounceMs: configuration.get('live.debounceMs', 450),
      slowAnalysisThresholdMs: configuration.get('live.slowAnalysisThresholdMs', 750),
      onState: (state) => this.setState(state),
      onResult: (findings, token) => {
        const startedAt = performance.now();
        this.diagnostics?.publish(findings, token);
        this.debugTiming('diagnostics', { updateMs: Math.round((performance.now() - startedAt) * 10) / 10 });
      },
      onTiming: (timing) => this.debugTiming('analysis', timing),
      onPerformanceReduced: () => {
        this.performanceReduced = true;
        if (!this.performanceNoticeShown) {
          this.performanceNoticeShown = true;
          this.window?.showWarningMessage?.('Live analysis reduced for performance. Analysis will continue when files are saved.');
        }
        this.setState('idle');
      }
    });
    if (configuration.get('live.scanOnChange', true)) {
      this.documentSubscriptions.push(this.workspace.onDidChangeTextDocument((event) => this.scheduler.schedule(event.document)));
    }
    if (configuration.get('live.scanOnSave', true)) {
      this.documentSubscriptions.push(this.workspace.onDidSaveTextDocument((document) => this.scheduler.schedule(document, true)));
    }
  }
  debugTiming(label, timing) {
    if (!this.configuration.get('live.debug', false)) return;
    // Debug-only timing avoids noisy production logs and never includes code.
    console.debug(`[Security Center Live] ${label}`, timing);
  }
  disposeDocumentListeners() {
    this.scheduler?.dispose();
    this.scheduler = undefined;
    this.performanceReduced = false;
    for (const subscription of this.documentSubscriptions.splice(0)) subscription.dispose();
  }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.disposeDocumentListeners();
    this.configurationSubscription?.dispose();
    this.diagnostics?.clear();
    this.stateListeners.clear();
    this.state = 'disabled';
  }
}

module.exports = { LiveSecurityService };
