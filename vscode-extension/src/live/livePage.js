const path = require('path');
const { escapeHtml } = require('./liveCompanion');
const { SUPPORTED_LANGUAGES } = require('./liveScheduler');
const { themeOverridesCss } = require('../theme-controller');

class LiveSessionActivity {
  constructor({ now = () => new Date() } = {}) {
    this.now = now;
    this.byUri = new Map();
    this.detected = new Set();
    this.resolved = 0;
    this.recent = [];
    this.ruleCounts = new Map();
    this.shownTips = new Set();
    this.tip = '';
  }
  update(uri, findings) {
    if (!uri) return;
    const previous = this.byUri.get(uri) || new Map();
    const current = new Map(findings.map((finding) => [finding.id, finding]));
    for (const [id, finding] of current) {
      if (previous.has(id)) continue;
      this.detected.add(`${uri}:${id}`);
      this.add('detected', finding.title, finding);
      const count = (this.ruleCounts.get(finding.ruleId) || 0) + 1;
      this.ruleCounts.set(finding.ruleId, count);
      if (count >= 2 && !this.shownTips.has(finding.ruleId)) {
        this.shownTips.add(finding.ruleId);
        this.tip = finding.recommendation || `Review repeated ${finding.title.toLowerCase()} patterns before committing.`;
      }
    }
    for (const [id, finding] of previous) {
      if (current.has(id)) continue;
      this.resolved += 1;
      this.add('resolved', `${finding.title} resolved`, finding);
    }
    this.byUri.set(uri, current);
  }
  add(type, label, finding) {
    this.recent.unshift({ type, label, finding, at: this.now().toISOString() });
    this.recent = this.recent.slice(0, 20);
  }
  snapshot() { return { detected: this.detected.size, resolved: this.resolved, prevented: this.resolved, recent: [...this.recent], tip: this.tip }; }
}

function renderLiveSecurityPage(model, nonce, companionImageUri = '', cspSource = '', selectedTheme = 'light') {
  const active = model.state !== 'disabled' && model.state !== 'paused';
  const stateLabel = active ? 'Active' : model.state === 'paused' ? 'Paused' : 'Off';
  const fileSupportMessage = !model.file
    ? 'Open a JavaScript or TypeScript file to start local analysis.'
    : model.supportedFile
      ? `Current file: ${escapeHtml(model.file)}`
      : `Live Security is active. ${escapeHtml(model.file)} is not analyzed yet; detection currently supports JavaScript and TypeScript.`;
  const findingRows = model.findings.map((finding) => {
    const ref = escapeHtml(JSON.stringify([finding.uri, finding.documentVersion, finding.ruleId]));
    return `<article class="finding"><div><strong>${escapeHtml(String(finding.severity).toUpperCase())} · ${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.cwe || finding.ruleId)} · Line ${finding.range.start.line + 1}</span></div><div class="actions"><button data-action="open" data-ref="${ref}">Open</button><button class="secondary" data-action="explain" data-ref="${ref}">Explain</button><button class="secondary" data-action="${finding.quickFixAvailable ? 'quickfix' : 'fix'}" data-ref="${ref}">Fix</button></div></article>`;
  }).join('');
  const activityRows = model.activity.recent.slice(0, 8).map((item) => `<li><time>${escapeHtml(new Date(item.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))}</time><span>${escapeHtml(item.label)}</span><small>${item.type === 'resolved' ? 'Resolved live' : 'Detected live'}</small></li>`).join('');
  const knownContext = model.knownFindings?.length ? `<section><h2>Known findings in this file</h2><div class="info"><strong>${model.knownFindings.length} existing Security Center finding(s)</strong><small>Read-only context from completed scans. Live Security did not create these findings.</small></div></section>` : '';
  const tip = model.activity.tip ? `<section><h2>Secure coding hint</h2><div class="hint">${escapeHtml(model.activity.tip)}</div></section>` : '';
  return `<!doctype html><html><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource || "'none'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${themeOverridesCss()}
    :root{color-scheme:light dark}*{box-sizing:border-box}${selectedTheme === 'light' ? themeOverridesCss().replaceAll('body.theme-light','body') : ''}body{margin:0;padding:24px;color:var(--vscode-foreground);background:var(--vscode-editor-background);font-family:var(--vscode-font-family);font-size:var(--vscode-font-size)}main{max-width:1050px;margin:auto}h1{margin:0}.muted,.finding span,small{color:var(--vscode-descriptionForeground)}header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;padding-bottom:16px;border-bottom:1px solid var(--vscode-panel-border)}.identity{display:flex;align-items:center;gap:14px}.avatar-wrap{position:relative;width:116px;height:86px;display:grid;place-items:center;flex:none}.avatar-wrap::after{content:"";position:absolute;inset:10px 18px;border:1px solid var(--vscode-focusBorder);border-radius:50%;opacity:.32}.avatar{position:relative;z-index:1;width:116px;height:86px;object-fit:contain;filter:drop-shadow(0 4px 5px var(--vscode-widget-shadow))}.active .avatar{animation:float 3.2s ease-in-out infinite}.analyzing .avatar{animation-duration:1.35s}.analyzing .avatar-wrap::after{animation:pulse 1.1s ease-in-out infinite}.issues .avatar-wrap::after,.error .avatar-wrap::after{border-color:var(--vscode-errorForeground);opacity:.8}.disabled .avatar{opacity:.55;animation:none}.state{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:10px;color:var(--vscode-badge-foreground);background:var(--vscode-badge-background)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);margin:20px 0;border:1px solid var(--vscode-panel-border);border-radius:5px}.metric{padding:14px}.metric+.metric{border-left:1px solid var(--vscode-panel-border)}.metric strong{display:block;font-size:1.5em}.grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,.7fr);gap:20px}section{margin-bottom:20px}h2{font-size:1.05em;margin:0 0 10px}.finding{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0;border-top:1px solid var(--vscode-panel-border)}.finding span{display:block;margin-top:3px}.actions{display:flex;gap:6px;flex-wrap:wrap}button{font:inherit;border:0;border-radius:2px;padding:5px 10px;cursor:pointer;color:var(--vscode-button-foreground);background:var(--vscode-button-background)}button:hover{background:var(--vscode-button-hoverBackground)}button.secondary{color:var(--vscode-button-secondaryForeground);background:var(--vscode-button-secondaryBackground)}.empty,.info,.hint{padding:12px;border:1px solid var(--vscode-panel-border);border-radius:4px}.hint{border-left:3px solid var(--vscode-focusBorder)}.info{display:grid;gap:8px}ul{list-style:none;padding:0;margin:0}li{display:grid;grid-template-columns:55px 1fr auto;gap:8px;padding:9px 0;border-top:1px solid var(--vscode-panel-border)}@keyframes float{50%{transform:translateY(-7px) rotate(.7deg)}}@keyframes pulse{50%{opacity:.9;transform:scale(1.09)}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:700px){body{padding:14px}.grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr}.metric+.metric{border-left:0;border-top:1px solid var(--vscode-panel-border)}.finding{align-items:flex-start;flex-direction:column}.avatar-wrap{width:90px}.avatar{width:90px}}
  </style></head><body class="theme-${selectedTheme === 'dark' ? 'dark' : 'light'} ${active ? 'active' : 'disabled'} ${escapeHtml(model.state)}"><main><header><div class="identity"><div class="avatar-wrap">${companionImageUri ? `<img class="avatar" src="${escapeHtml(companionImageUri)}" alt="Security Companion active">` : ''}</div><div><h1>Live Security</h1><div class="state">● ${stateLabel}</div><p class="muted">${model.state === 'analyzing' ? 'Checking current file…' : model.state === 'issues' ? `${model.findings.length} potential issue(s)` : active ? 'Watching your code' : 'Live analysis is not running'}</p><p class="muted">${fileSupportMessage}</p></div></div>${active ? '<button data-command="securityCenter.disableLiveSecurity">Turn off</button>' : '<button data-command="securityCenter.enableLiveSecurity">Enable Live Security</button>'}</header>
  <div class="metrics"><div class="metric"><strong>${model.findings.length}</strong><span>Current file warnings</span></div><div class="metric"><strong>${model.activity.detected}</strong><span>Session warnings</span></div><div class="metric"><strong>${model.activity.resolved}</strong><span>Resolved live</span></div><div class="metric"><strong>${model.activity.prevented || 0}</strong><span>Prevented during coding</span></div></div>
  <div class="grid"><div><section><h2>Current File</h2>${findingRows || '<div class="empty">No Live warnings for the current file.</div>'}</section>${tip}<section><h2>Recent Live Activity</h2>${activityRows ? `<ul>${activityRows}</ul>` : '<div class="empty">No Live activity in this session yet.</div>'}</section></div><aside>${knownContext}<section><h2>Engine</h2><div class="info"><strong>JavaScript / TypeScript</strong><span>Security Center Live Rules</span><small>Local, lightweight and ephemeral analysis</small></div></section><section><h2>AI</h2><div class="info"><strong>Ollama</strong><span>${escapeHtml(model.ollamaModel || 'No model selected')}</span><small>Used only on request</small></div></section></aside></div>
  </main><script nonce="${nonce}">const vscode=acquireVsCodeApi();document.addEventListener('click',e=>{const button=e.target.closest('button');if(!button)return;if(button.dataset.command)return vscode.postMessage({type:'command',command:button.dataset.command});vscode.postMessage({type:button.dataset.action,ref:JSON.parse(button.dataset.ref||'[]')});});</script></body></html>`;
}

class LiveSecurityPageProvider {
  constructor({ api, service, diagnostics, executeCommand, workspacePath = '', extensionUri, getOllamaModel = () => '', getKnownFindings = () => [], themeController }) {
    this.api = api; this.service = service; this.diagnostics = diagnostics; this.executeCommand = executeCommand; this.workspacePath = workspacePath; this.extensionUri = extensionUri; this.getOllamaModel = getOllamaModel; this.getKnownFindings = getKnownFindings; this.themeController = themeController;
    this.activity = new LiveSessionActivity(); this.activeDocument = api.window.activeTextEditor?.document; this.panel = undefined;
    this.subscriptions = [service.onDidChangeState(() => this.render()), diagnostics.onDidChange(({ uri, findings, reason }) => { if (reason !== 'suppressed') this.activity.update(uri, findings); this.render(); }), api.window.onDidChangeActiveTextEditor((editor) => { if (editor?.document) this.activeDocument = editor.document; this.render(); }), themeController?.onDidChange(() => this.render())].filter(Boolean);
  }
  open() {
    if (this.panel) return this.panel.reveal(this.api.ViewColumn.Active);
    const assetRoot = this.api.Uri.joinPath(this.extensionUri, 'media', 'live');
    this.panel = this.api.window.createWebviewPanel('securityCenter.liveSecurity', 'Security Center â€” Live Security', this.api.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [assetRoot] });
    this.companionImageUri = this.panel.webview.asWebviewUri(this.api.Uri.joinPath(assetRoot, 'security-companion.png')).toString();
    this.panel.webview.onDidReceiveMessage((message) => this.handleMessage(message));
    this.panel.onDidDispose(() => { this.panel = undefined; });
    this.render();
  }
  model() {
    const document = this.activeDocument;
    const file = document?.uri?.fsPath ? path.relative(this.workspacePath, document.uri.fsPath).replaceAll('\\', '/') : '';
    const knownFindings = file ? this.getKnownFindings().filter((finding) => finding.file === file && ['high', 'critical'].includes(String(finding.rawSeverity || finding.severity).toLowerCase())) : [];
    return { state: this.service.getState(), file, supportedFile: Boolean(document && SUPPORTED_LANGUAGES.has(document.languageId)), findings: this.diagnostics.findingsForDocument(document), activity: this.activity.snapshot(), ollamaModel: this.getOllamaModel(), knownFindings };
  }
  render() { if (this.panel) this.panel.webview.html = renderLiveSecurityPage(this.model(), 'live-security-page', this.companionImageUri, this.panel.webview.cspSource, this.themeController?.getTheme() || 'light'); }
  handleMessage(message) { if (message.type === 'command') return this.executeCommand(message.command); const [uri, version, ruleId] = message.ref || []; const commands = { open: 'securityCenter.openLiveFinding', explain: 'securityCenter.explainLiveFinding', quickfix: 'securityCenter.applyLiveQuickFix', fix: 'securityCenter.generateLiveAiFix' }; if (commands[message.type]) return this.executeCommand(commands[message.type], uri, version, ruleId); }
  dispose() { this.panel?.dispose(); for (const subscription of this.subscriptions.splice(0)) subscription.dispose(); }
}

module.exports = { LiveSecurityPageProvider, LiveSessionActivity, renderLiveSecurityPage };



