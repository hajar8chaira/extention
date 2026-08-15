function diagnosticSeverity(finding, DiagnosticSeverity) {
  if (finding.confidence === 'high' && finding.severity === 'high') return DiagnosticSeverity.Error;
  if (finding.severity === 'low' || finding.confidence === 'low') return DiagnosticSeverity.Information;
  return DiagnosticSeverity.Warning;
}

function toLiveDiagnostic(finding, api) {
  const range = new api.Range(
    finding.range.start.line,
    finding.range.start.character,
    finding.range.end.line,
    finding.range.end.character
  );
  const metadata = [finding.ruleId, finding.cwe, `confidence:${finding.confidence}`].filter(Boolean).join(' · ');
  const diagnostic = new api.Diagnostic(
    range,
    `${finding.label}: ${finding.title}\n${finding.description}\n${metadata}`,
    diagnosticSeverity(finding, api.DiagnosticSeverity)
  );
  diagnostic.source = 'Security Center Live';
  diagnostic.code = finding.ruleId;
  return diagnostic;
}

function suppressionKey(finding) {
  return `${finding.uri}:${finding.ruleId}:${finding.range.start.line}:${finding.originalText || ''}`;
}

class LiveDiagnostics {
  constructor({ api, collection, showLowConfidence = () => false }) {
    this.api = api;
    this.collection = collection;
    this.disposed = false;
    this.latestVersions = new Map();
    this.findingsByUri = new Map();
    this.listeners = new Set();
    this.suppressedForSession = new Set();
    this.showLowConfidence = showLowConfidence;
  }

  publish(findings, token, reason = 'analysis') {
    if (this.disposed) return;
    const latestVersion = this.latestVersions.get(token.uri);
    if (latestVersion !== undefined && token.version < latestVersion) return;
    this.latestVersions.set(token.uri, token.version);
    const uri = this.api.Uri.parse(token.uri);
    const currentFindings = findings.filter((finding) =>
      finding.documentVersion === token.version && finding.uri === token.uri &&
      (finding.confidence !== 'low' || this.showLowConfidence()) &&
      !this.suppressedForSession.has(suppressionKey(finding))
    );
    const diagnostics = currentFindings
      .map((finding) => toLiveDiagnostic(finding, this.api));
    if (currentFindings.length) this.findingsByUri.set(token.uri, currentFindings);
    else this.findingsByUri.delete(token.uri);
    if (diagnostics.length) this.collection.set(uri, diagnostics);
    else this.collection.delete(uri);
    this.emitChange(token.uri, currentFindings, reason);
  }

  clear() {
    if (!this.disposed) {
      this.latestVersions.clear();
      this.findingsByUri.clear();
      this.collection.clear();
      this.emitChange(undefined, []);
    }
  }

  onDidChange(listener) {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }

  emitChange(uri, findings, reason = 'analysis') {
    for (const listener of this.listeners) listener({ uri, findings, reason });
  }

  findingsForDocument(document) {
    if (!document) return [];
    return (this.findingsByUri.get(document.uri.toString()) || [])
      .filter((finding) => finding.documentVersion === document.version);
  }

  findFinding(document, position) {
    const uri = document.uri.toString();
    return (this.findingsByUri.get(uri) || []).find((finding) => {
      if (finding.documentVersion !== document.version) return false;
      const range = new this.api.Range(
        finding.range.start.line,
        finding.range.start.character,
        finding.range.end.line,
        finding.range.end.character
      );
      return range.contains(position);
    });
  }

  getFinding(uri, documentVersion, ruleId) {
    return (this.findingsByUri.get(uri) || []).find((finding) =>
      finding.documentVersion === documentVersion && finding.ruleId === ruleId
    );
  }

  suppressForSession(finding) {
    this.suppressedForSession.add(suppressionKey(finding));
    const remaining = (this.findingsByUri.get(finding.uri) || []).filter((item) => suppressionKey(item) !== suppressionKey(finding));
    this.publish(remaining, { uri: finding.uri, version: finding.documentVersion }, 'suppressed');
  }

  dispose() {
    if (this.disposed) return;
    this.clear();
    this.disposed = true;
    this.listeners.clear();
    this.collection.dispose();
  }
}

module.exports = { LiveDiagnostics, diagnosticSeverity, suppressionKey, toLiveDiagnostic };
