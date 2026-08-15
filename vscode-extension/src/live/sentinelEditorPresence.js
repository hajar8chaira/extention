const path = require('path');
const { isSupportedDocument } = require('./liveScheduler');

const TRANSIENT_MS = Object.freeze({ checking: 1600, clean: 1000, resolved: 1400, issue: 2600 });

function documentKey(document) {
  return document?.uri?.toString?.() || '';
}

function firstChangedLine(event) {
  const lines = (event?.contentChanges || []).map((change) => change.range?.start?.line).filter(Number.isInteger);
  return lines.length ? Math.min(...lines) : undefined;
}

function validFindingsForDocument(findings, document) {
  const key = documentKey(document);
  return (findings || []).filter((finding) => finding.uri === key && finding.documentVersion === document?.version);
}

class SentinelEditorPresence {
  constructor({ api, service, diagnostics, extensionUri, workspace, window = api.window, transientMs = TRANSIENT_MS }) {
    this.api = api;
    this.service = service;
    this.diagnostics = diagnostics;
    this.workspace = workspace;
    this.window = window;
    this.transientMs = transientMs;
    this.changedLines = new Map();
    this.previousFindings = new Map();
    this.timers = new Map();
    this.activeEditor = window.activeTextEditor;
    const icon = (name) => api.Uri.joinPath(extensionUri, 'media', 'live', `sentinel-${name}.svg`);
    this.decorations = {
      idle: window.createTextEditorDecorationType({ gutterIconPath: icon('idle'), gutterIconSize: 'contain', overviewRulerLane: api.OverviewRulerLane?.Right }),
      analyzing: window.createTextEditorDecorationType({ gutterIconPath: icon('analyzing'), gutterIconSize: 'contain', after: { contentText: '  Sentinel · Checking…', color: new api.ThemeColor('editorCodeLens.foreground'), fontStyle: 'italic' } }),
      clean: window.createTextEditorDecorationType({ gutterIconPath: icon('resolved'), gutterIconSize: 'contain', after: { contentText: '  ✓ Looks clean', color: new api.ThemeColor('testing.iconPassed') } }),
      issue: window.createTextEditorDecorationType({ gutterIconPath: icon('issue'), gutterIconSize: 'contain', overviewRulerColor: new api.ThemeColor('editorWarning.foreground'), overviewRulerLane: api.OverviewRulerLane?.Right }),
      currentIssue: window.createTextEditorDecorationType({ gutterIconPath: icon('issue'), gutterIconSize: 'contain', after: { color: new api.ThemeColor('editorWarning.foreground'), fontWeight: '600' } }),
      resolved: window.createTextEditorDecorationType({ gutterIconPath: icon('resolved'), gutterIconSize: 'contain', after: { contentText: '  ✓ Resolved', color: new api.ThemeColor('testing.iconPassed') } })
    };
    this.subscriptions = [
      workspace.onDidChangeTextDocument((event) => this.onDocumentChanged(event)),
      window.onDidChangeActiveTextEditor((editor) => this.onActiveEditorChanged(editor)),
      service.onDidChangeState((state) => this.onStateChanged(state)),
      diagnostics.onDidChange((event) => this.onDiagnosticsChanged(event))
    ];
    this.renderIdle();
  }

  supported(editor = this.activeEditor) {
    return Boolean(editor && this.service.isEnabled() && isSupportedDocument(editor.document, this.workspace));
  }

  lineRange(document, line) {
    const safeLine = Math.max(0, Math.min(line || 0, Math.max(0, document.lineCount - 1)));
    return new this.api.Range(safeLine, 0, safeLine, 0);
  }

  onDocumentChanged(event) {
    if (!this.activeEditor || documentKey(event.document) !== documentKey(this.activeEditor.document)) return;
    const line = firstChangedLine(event);
    if (line === undefined || !this.supported()) return;
    this.changedLines.set(documentKey(event.document), { line, version: event.document.version });
    this.showTransient('analyzing', line, this.transientMs.checking);
  }

  onActiveEditorChanged(editor) {
    if (this.activeEditor && this.activeEditor !== editor) this.clearEditor(this.activeEditor);
    this.activeEditor = editor;
    this.renderFromCurrentData();
  }

  onStateChanged(state) {
    if (state === 'disabled') return this.clearAll();
    if (!this.supported()) return this.clearEditor(this.activeEditor);
    const changed = this.changedLines.get(documentKey(this.activeEditor.document));
    if (state === 'analyzing' && changed?.version === this.activeEditor.document.version) {
      this.showTransient('analyzing', changed.line, this.transientMs.checking);
    }
  }

  onDiagnosticsChanged(event = {}) {
    const editor = this.activeEditor;
    if (!this.supported(editor) || event.uri !== documentKey(editor.document)) return;
    const findings = validFindingsForDocument(event.findings, editor.document);
    const previous = this.previousFindings.get(event.uri) || [];
    this.previousFindings.set(event.uri, findings);
    if (findings.length) return this.renderIssues(findings);
    if (previous.length) {
      const line = previous[0]?.range?.start?.line || 0;
      return this.showTransient('resolved', line, this.transientMs.resolved);
    }
    const changed = this.changedLines.get(event.uri);
    if (changed?.version === editor.document.version) this.showTransient('clean', changed.line, this.transientMs.clean);
  }

  renderIssues(findings) {
    const editor = this.activeEditor;
    this.clearDecorationStates(editor);
    const compact = findings.map((finding) => ({ range: this.toRange(finding), hoverMessage: `${String(finding.severity || 'warning').toUpperCase()} · ${finding.title}\n\nSecurity Center Live` }));
    editor.setDecorations(this.decorations.issue, compact);
    const recent = findings[0];
    editor.setDecorations(this.decorations.currentIssue, [{ range: this.toRange(recent), renderOptions: { after: { contentText: `  ${String(recent.severity || 'warning').toUpperCase()} · ${recent.title}` } } }]);
    this.armTimer(editor, 'currentIssue', this.transientMs.issue, () => editor.setDecorations(this.decorations.currentIssue, []));
  }

  toRange(finding) {
    return new this.api.Range(finding.range.start.line, finding.range.start.character, finding.range.end.line, finding.range.end.character);
  }

  renderIdle() {
    if (!this.supported()) return;
    const changed = this.changedLines.get(documentKey(this.activeEditor.document));
    if (changed?.version === this.activeEditor.document.version) this.activeEditor.setDecorations(this.decorations.idle, [this.lineRange(this.activeEditor.document, changed.line)]);
  }

  renderFromCurrentData() {
    if (!this.supported()) return this.clearEditor(this.activeEditor);
    const findings = this.diagnostics.findingsForDocument(this.activeEditor.document);
    if (findings.length) this.renderIssues(findings);
    else this.renderIdle();
  }

  showTransient(kind, line, duration) {
    const editor = this.activeEditor;
    if (!this.supported(editor)) return;
    this.clearDecorationStates(editor, kind === 'analyzing' ? ['idle'] : []);
    editor.setDecorations(this.decorations[kind], [this.lineRange(editor.document, line)]);
    this.armTimer(editor, kind, duration, () => {
      editor.setDecorations(this.decorations[kind], []);
      if (kind !== 'resolved') this.renderIdle();
    });
  }

  armTimer(editor, key, duration, callback) {
    const old = this.timers.get(key);
    if (old) clearTimeout(old);
    const timer = setTimeout(() => {
      this.timers.delete(key);
      if (this.activeEditor === editor) callback();
    }, duration);
    this.timers.set(key, timer);
  }

  clearDecorationStates(editor, except = []) {
    if (!editor) return;
    for (const [key, decoration] of Object.entries(this.decorations)) if (!except.includes(key)) editor.setDecorations(decoration, []);
  }
  clearEditor(editor) { this.clearDecorationStates(editor); }
  clearAll() {
    this.clearEditor(this.activeEditor);
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    this.changedLines.clear();
    this.previousFindings.clear();
  }
  dispose() {
    this.clearAll();
    for (const subscription of this.subscriptions.splice(0)) subscription.dispose();
    for (const decoration of Object.values(this.decorations)) decoration.dispose();
  }
}

module.exports = { SentinelEditorPresence, TRANSIENT_MS, firstChangedLine, validFindingsForDocument };
