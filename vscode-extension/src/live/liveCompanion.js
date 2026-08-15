const path = require('path');
const { themeOverridesCss } = require('../theme-controller');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function companionCopy(state, count) {
  if (state === 'disabled') return { label: 'Live Security off', mood: 'resting' };
  if (state === 'analyzing') return { label: 'Checking current file…', mood: 'analyzing' };
  if (state === 'issues') return { label: count === 1 ? 'Potential security issue' : `${count} potential security issues`, mood: 'attentive' };
  if (state === 'clean') return { label: 'No live issues', mood: 'clean' };
  if (state === 'error') return { label: 'Live analysis unavailable', mood: 'error' };
  if (state === 'paused') return { label: 'Live Security paused', mood: 'resting' };
  return { label: 'Watching your code', mood: 'watching' };
}

function renderCompanionHtml(model, nonce, companionImageUri = '', cspSource = '', selectedTheme = 'light') {
  const { label, mood } = companionCopy(model.state, model.findings.length);
  const findings = model.findings.map((finding) => `
    <article class="finding">
      <div class="finding-head"><strong>${escapeHtml(String(finding.severity).toUpperCase())}</strong><span>Line ${finding.range.start.line + 1}</span></div>
      <div class="finding-title">${escapeHtml(finding.title)}</div>
      <div class="actions">
        <button data-action="open" data-ref="${escapeHtml(JSON.stringify([finding.uri, finding.documentVersion, finding.ruleId]))}">Open</button>
        <button data-action="explain" data-ref="${escapeHtml(JSON.stringify([finding.uri, finding.documentVersion, finding.ruleId]))}">Explain</button>
        <button data-action="${finding.quickFixAvailable ? 'quickfix' : 'fix'}" data-ref="${escapeHtml(JSON.stringify([finding.uri, finding.documentVersion, finding.ruleId]))}">Fix</button>
      </div>
    </article>`).join('');
  const empty = model.state === 'clean' ? '<div class="empty"><strong>✓ Current file looks clean</strong><span>Live Security will continue checking while you code.</span></div>' : '';
  return `<!doctype html><html><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource || "'none'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
    :root{color-scheme:light dark}*{box-sizing:border-box}${selectedTheme === 'light' ? themeOverridesCss().replaceAll('body.theme-light','body') : ''}body{margin:0;padding:12px;color:var(--vscode-foreground);background:var(--vscode-sideBar-background);font-family:var(--vscode-font-family);font-size:var(--vscode-font-size)}
    button{font:inherit;color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;border-radius:2px;padding:4px 8px;cursor:pointer}button:hover{background:var(--vscode-button-hoverBackground)}.secondary{color:var(--vscode-button-secondaryForeground);background:var(--vscode-button-secondaryBackground)}
    .companion{display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:1px solid var(--vscode-panel-border)}.avatar-stage{position:relative;width:82px;height:68px;display:grid;place-items:center;flex:none}.avatar-stage::after{content:"";position:absolute;inset:8px 11px;border:1px solid var(--vscode-focusBorder);border-radius:50%;opacity:.28}.avatar{position:relative;z-index:1;display:block;width:82px;height:68px;object-fit:contain;filter:drop-shadow(0 3px 4px var(--vscode-widget-shadow))}
    .analyzing .avatar-stage::after{animation:pulse 1.4s ease-in-out infinite}.analyzing .avatar,.watching .avatar,.attentive .avatar{animation:float 3.5s ease-in-out infinite}.attentive .avatar-stage::after,.error .avatar-stage::after{border-color:var(--vscode-errorForeground);opacity:.75}.clean .avatar-stage::after{border-color:var(--vscode-testing-iconPassed);opacity:.65}.resting .avatar{opacity:.72}.badge{display:inline-block;min-width:18px;padding:1px 5px;border-radius:9px;text-align:center;color:var(--vscode-badge-foreground);background:var(--vscode-badge-background)}
    .state{display:grid;gap:4px;min-width:0}.state strong,.file{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.file{margin:12px 0;color:var(--vscode-descriptionForeground)}.finding{padding:9px 0;border-top:1px solid var(--vscode-panel-border)}.finding-head{display:flex;justify-content:space-between;color:var(--vscode-descriptionForeground);font-size:.9em}.finding-title{margin:4px 0 7px}.actions{display:flex;gap:5px;flex-wrap:wrap}.empty{display:grid;gap:5px;padding:12px 0}.empty span{color:var(--vscode-descriptionForeground)}.footer{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
    @keyframes pulse{50%{opacity:.85;transform:scale(1.08)}}@keyframes float{50%{transform:translateY(-4px) rotate(.6deg)}}.hidden *{animation:none!important;transition:none!important}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
  </style></head><body class="${mood}">
    <section class="companion"><div class="avatar-stage">${companionImageUri ? `<img class="avatar" src="${escapeHtml(companionImageUri)}" alt="Security Companion">` : '<span class="badge" aria-label="Security Companion">SC</span>'}</div><div class="state"><strong>${escapeHtml(label)}</strong>${model.findings.length ? `<span class="badge">${model.findings.length}</span>` : ''}</div></section>
    <div class="file">Current file: ${escapeHtml(model.file || 'No active supported file')}</div>${findings || empty}
    <div class="footer">${model.state === 'disabled' ? '<button data-command="securityCenter.enableLiveSecurity">Enable Live Security</button>' : '<button class="secondary" data-command="securityCenter.disableLiveSecurity">Turn off</button>'}<button class="secondary" data-command="securityCenter.openLiveSecurityPage">Open Live Security</button></div>
    <script nonce="${nonce}">const vscode=acquireVsCodeApi();document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.command)return vscode.postMessage({type:'command',command:b.dataset.command});const ref=JSON.parse(b.dataset.ref||'[]');vscode.postMessage({type:b.dataset.action,ref});});window.addEventListener('message',e=>{if(e.data?.type==='visibility')document.body.classList.toggle('hidden',!e.data.visible);});</script>
  </body></html>`;
}

class LiveCompanionProvider {
  constructor({ api, service, diagnostics, executeCommand, workspacePath = '', extensionUri, themeController }) {
    this.api = api; this.service = service; this.diagnostics = diagnostics; this.executeCommand = executeCommand; this.workspacePath = workspacePath; this.extensionUri = extensionUri; this.themeController = themeController;
    this.view = undefined; this.state = service.getState(); this.activeDocument = api.window.activeTextEditor?.document;
    this.subscriptions = [
      service.onDidChangeState((state) => { this.state = state; this.render(); }),
      diagnostics.onDidChange(() => this.render()),
      api.window.onDidChangeActiveTextEditor((editor) => { if (editor?.document) this.activeDocument = editor.document; this.render(); }),
      themeController?.onDidChange(() => this.render())
    ].filter(Boolean);
  }
  resolveWebviewView(view) {
    this.view = view;
    const assetRoot = this.api.Uri.joinPath(this.extensionUri, 'media', 'live');
    this.companionImageUri = view.webview.asWebviewUri(this.api.Uri.joinPath(assetRoot, 'security-companion.png')).toString();
    view.webview.options = { enableScripts: true, localResourceRoots: [assetRoot] };
    view.webview.onDidReceiveMessage((message) => this.handleMessage(message));
    view.onDidChangeVisibility(() => { if (view.visible) this.render(); else view.webview.postMessage({ type: 'visibility', visible: false }); });
    this.render();
  }
  model() {
    const document = this.activeDocument;
    const findings = this.diagnostics.findingsForDocument(document);
    const file = document?.uri?.fsPath ? path.relative(this.workspacePath, document.uri.fsPath).replaceAll('\\', '/') : '';
    return { state: this.state, file, findings };
  }
  render() {
    if (!this.view?.visible) return;
    const model = this.model();
    this.view.badge = model.findings.length
      ? { value: model.findings.length, tooltip: `${model.findings.length} Live Security warning${model.findings.length === 1 ? '' : 's'}` }
      : undefined;
    this.view.webview.html = renderCompanionHtml(model, 'live-companion', this.companionImageUri, this.view.webview.cspSource, this.themeController?.getTheme() || 'light');
  }
  handleMessage(message) {
    if (message.type === 'command') return this.executeCommand(message.command);
    const [uri, version, ruleId] = message.ref || [];
    if (message.type === 'open') return this.executeCommand('securityCenter.openLiveFinding', uri, version, ruleId);
    if (message.type === 'explain') return this.executeCommand('securityCenter.explainLiveFinding', uri, version, ruleId);
    if (message.type === 'quickfix') return this.executeCommand('securityCenter.applyLiveQuickFix', uri, version, ruleId);
    if (message.type === 'fix') return this.executeCommand('securityCenter.generateLiveAiFix', uri, version, ruleId);
  }
  dispose() { for (const subscription of this.subscriptions.splice(0)) subscription.dispose(); }
}

module.exports = { LiveCompanionProvider, companionCopy, escapeHtml, renderCompanionHtml };


