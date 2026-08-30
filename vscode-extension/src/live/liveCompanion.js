const path = require('path');
const { themeOverridesCss } = require('../theme-controller');
const { companionMessageFor, CompanionMessageGate, COMPANION_STATES, buildCompanionVisualModel, normalizeCompanionState } = require('./companionMessages');
const { mascotVisualFor, renderMascotSvg, mascotCss } = require('./companionMascot');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

/**
 * Historical copy helper, kept for the existing callers and tests. The
 * companion itself now composes its message through `companionMessageFor`,
 * which also knows about the scan, the policy and the scanner health.
 */
function companionCopy(state, count) {
  if (state === 'disabled') return { label: 'Live Security off', mood: 'resting' };
  if (state === 'analyzing') return { label: 'Checking current file…', mood: 'analyzing' };
  if (state === 'issues') return { label: count === 1 ? 'Potential security issue' : `${count} potential security issues`, mood: 'attentive' };
  if (state === 'clean') return { label: 'No live issues', mood: 'clean' };
  if (state === 'error') return { label: 'Live analysis unavailable', mood: 'error' };
  if (state === 'paused') return { label: 'Live Security paused', mood: 'resting' };
  return { label: 'Watching your code', mood: 'watching' };
}

/** Live Security service state → companion state vocabulary. */
const companionStateFor = normalizeCompanionState;

/** Severity roll-up shown under the bubble, e.g. « 1 High · 1 Medium ». */
function severityBreakdown(findings = []) {
  const counts = {};
  for (const finding of findings) {
    const key = String(finding.severity || 'unknown');
    counts[key] = (counts[key] || 0) + 1;
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return Object.entries(counts)
    .sort((left, right) => (order[left[0]] ?? 9) - (order[right[0]] ?? 9))
    .map(([severity, count]) => `${count} ${severity[0].toUpperCase()}${severity.slice(1)}`)
    .join(' · ');
}

/**
 * The companion's own markup.
 *
 * No longer mounted anywhere: the large sidebar view it used to fill was removed
 * because it took the whole panel and repeated what the dashboard already said.
 * It is kept, tested and honest so the compact surface planned next can reuse it.
 *
 * Two rules it now enforces:
 *   - the message is rendered exactly once. The header used to print the same
 *     headline as the bubble, which is how the panel came to show « Dernière
 *     analyse complète : 556 findings » twice; the header now carries context
 *     only (watched file, finding count).
 *   - it offers actions about the finding at hand, and nothing else. « Full
 *     Scan » and « Live Security » belonged to the Security Center sidebar and
 *     the status bar all along.
 */
function renderCompanionHtml(model, nonce, companionImageUri = '', cspSource = '', selectedTheme = 'light') {
  // The message comes from the centralised composer when the caller supplied
  // one; otherwise the historical copy keeps the sidebar working unchanged.
  const composed = model.message || null;
  const label = composed ? composed.headline : companionCopy(model.state, model.findings.length).label;
  const mood = composed ? composed.mood : companionCopy(model.state, model.findings.length).mood;
  const detail = composed?.detail || '';
  const visual = mascotVisualFor(model.companionState || model.state, {
    severity: composed?.severity, policyStatus: model.policyStatus
  });
  const breakdown = severityBreakdown(model.findings);
  const critical = ['critical', 'error'].includes(visual);
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
    /* Theme tokens: the mascot never hardcodes a colour. */
    body{--sc-body:var(--vscode-editorWidget-background,#2b2f38);--sc-line:var(--vscode-foreground);--sc-visor:var(--vscode-editor-background,#12141a);--sc-accent:var(--vscode-focusBorder,#4a9eff);--sc-warn:var(--vscode-editorWarning-foreground,#d0a215);--sc-danger:var(--vscode-editorError-foreground,#e05252);--sc-ok:var(--vscode-testing-iconPassed,#3fa66a);display:flex;flex-direction:column;min-height:100vh}
    .head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;padding-bottom:9px;border-bottom:1px solid var(--vscode-panel-border)}
    .file-chip{display:block;color:var(--vscode-descriptionForeground);font-size:.9em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
    /* Bubble, mascot and tally form one block, centred, with the bubble's
       arrow pointing at the character. No stray whitespace between them. */
    .stage{margin-top:auto;display:grid;justify-items:center;gap:0;padding:10px 0 2px}
    .bubble{position:relative;max-width:100%;margin-bottom:9px;text-align:left;display:grid;gap:2px;
      background:var(--vscode-editorHoverWidget-background,var(--vscode-editorWidget-background));
      color:var(--vscode-foreground);
      border:1px solid var(--vscode-editorHoverWidget-border,var(--vscode-panel-border));
      border-radius:12px;padding:7px 11px;cursor:pointer;font:inherit;
      animation:sc-bubble-in .22s ease-out}
    .bubble.critical{border-color:var(--vscode-editorError-foreground)}
    .bubble::after{content:"";position:absolute;left:50%;margin-left:-5px;bottom:-6px;width:10px;height:10px;
      background:var(--vscode-editorHoverWidget-background,var(--vscode-editorWidget-background));
      border-right:1px solid var(--vscode-editorHoverWidget-border,var(--vscode-panel-border));
      border-bottom:1px solid var(--vscode-editorHoverWidget-border,var(--vscode-panel-border));transform:rotate(45deg)}
    .bubble.critical::after{border-right-color:var(--vscode-editorError-foreground);border-bottom-color:var(--vscode-editorError-foreground)}
    .bubble-title{font-weight:600;line-height:1.3}
    .bubble-detail{color:var(--vscode-descriptionForeground);font-size:.9em;line-height:1.3;
      display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    @keyframes sc-bubble-in{from{opacity:0;transform:translateY(4px)}}
    .mascot-button{background:none;border:0;padding:0;cursor:pointer;line-height:0;border-radius:10px}
    .mascot-button:focus-visible,.bubble:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:2px}
    .tally{text-align:center;display:grid;gap:1px;margin-top:2px}
    .tally span{color:var(--vscode-descriptionForeground);font-size:.9em}
    .badge{display:inline-block;min-width:18px;padding:1px 5px;border-radius:9px;text-align:center;color:var(--vscode-badge-foreground);background:var(--vscode-badge-background);flex:none}
    /* Compact: a narrow sidebar keeps the mascot and the count, nothing else. */
    /* Narrow or short panel: keep the character and the count, drop the rest. */
    @media(max-height:300px),(max-width:180px){.finding,.tally span,.empty,.bubble-detail,.file-chip{display:none}.stage{padding:4px 0}.mascot{width:70px;height:88px}}
    @media(min-height:520px){.mascot{width:126px;height:158px}}
    .state{display:grid;gap:4px;min-width:0}.state .detail{color:var(--vscode-descriptionForeground);font-size:.92em;overflow:hidden;text-overflow:ellipsis}.state strong,.file{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.file{margin:12px 0;color:var(--vscode-descriptionForeground)}.finding{padding:9px 0;border-top:1px solid var(--vscode-panel-border)}.finding-head{display:flex;justify-content:space-between;color:var(--vscode-descriptionForeground);font-size:.9em}.finding-title{margin:4px 0 7px}.actions{display:flex;gap:5px;flex-wrap:wrap}.empty{display:grid;gap:5px;padding:12px 0}.empty span{color:var(--vscode-descriptionForeground)}.footer{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
    @keyframes pulse{50%{opacity:.85;transform:scale(1.08)}}@keyframes float{50%{transform:translateY(-4px) rotate(.6deg)}}.hidden *{animation:none!important;transition:none!important}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
  ${mascotCss()}
  </style></head><body class="${mood} ${model.animations === false ? 'no-motion' : ''}">
    <header class="head">
      <div class="state">${model.file ? `<span class="file-chip" title="Fichier surveillé">${escapeHtml(model.file)}</span>` : ''}</div>
      ${model.findings.length ? `<span class="badge" aria-label="${model.findings.length} résultat(s) Live">${model.findings.length}</span>` : ''}
    </header>

    <div class="stage">
      <button class="bubble ${critical ? 'critical' : ''}" data-action="bubble" role="status" aria-live="${critical ? 'assertive' : 'polite'}">
        <span class="bubble-title">${escapeHtml(label)}</span>
        ${detail ? `<span class="bubble-detail">${escapeHtml(detail)}</span>` : ''}
      </button>
      <button class="mascot-button" data-action="mascot" title="Security Companion" aria-label="Security Companion">
        ${renderMascotSvg(visual, 'Security Companion', { src: companionImageUri })}
      </button>
      ${model.findings.length ? `<div class="tally"><strong>${model.findings.length} ${model.findings.length === 1 ? 'Live issue' : 'Live issues'}</strong>${breakdown ? `<span>${escapeHtml(breakdown)}</span>` : ''}</div>` : ''}
    </div>

    ${findings || empty}
    <div class="footer">
      ${model.findings.length ? '<button data-action="open-first">View</button><button data-action="fix-first">Fix</button>' : ''}
      ${model.state === 'disabled' ? '<button data-command="securityCenter.enableLiveSecurity">Enable Live Security</button>' : ''}
    </div>
    <script nonce="${nonce}">const vscode=acquireVsCodeApi();
    document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
      if(b.dataset.command)return vscode.postMessage({type:'command',command:b.dataset.command});
      const ref=JSON.parse(b.dataset.ref||'[]');vscode.postMessage({type:b.dataset.action,ref});});
    window.addEventListener('message',e=>{
      const data=e.data||{};
      if(data.type==='visibility')return document.body.classList.toggle('hidden',!data.visible);
      // Incremental update: the extension pushes the new state instead of
      // re-sending the whole document, so nothing re-parses while typing.
      if(data.type!=='state')return;
      const svg=document.querySelector('.mascot');
      if(svg&&data.visual)svg.setAttribute('class','mascot mascot-'+data.visual);
      const title=document.querySelector('.bubble-title');if(title)title.textContent=data.headline||'';
      const detail=document.querySelector('.bubble-detail');if(detail)detail.textContent=data.detail||'';
      const bubble=document.querySelector('.bubble');
      if(bubble){bubble.classList.toggle('critical',!!data.critical);bubble.setAttribute('aria-live',data.critical?'assertive':'polite');}
    });</script>
  </body></html>`;
}

class LiveCompanionProvider {
  constructor({ api, service, diagnostics, executeCommand, workspacePath = '', extensionUri, themeController, getPipelineContext, onVisualModel, cooldownMs = 1500 }) {
    this.onVisualModel = onVisualModel;
    this.api = api; this.service = service; this.diagnostics = diagnostics; this.executeCommand = executeCommand; this.workspacePath = workspacePath; this.extensionUri = extensionUri; this.themeController = themeController;
    // Optional: lets the companion mention the scan, the policy gate and the
    // scanner health without knowing anything about those subsystems.
    this.getPipelineContext = getPipelineContext;
    this.animationsEnabled = api.workspace?.getConfiguration?.('securityCenter')?.get?.('companion.animations', true) !== false;
    this.gate = new CompanionMessageGate({ cooldownMs });
    this.rendered = false;
    this.postedMessages = 0;
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
    // Always a workspace-relative path: an absolute path can disclose the
    // developer's directory layout and is never needed here.
    const file = document?.uri?.fsPath ? path.relative(this.workspacePath, document.uri.fsPath).replaceAll('\\', '/') : '';
    const pipeline = { ...(this.getPipelineContext?.() || {}), performanceReduced: this.service.isPerformanceReduced?.() };
    // The one shared model. The dashboard receives this very object.
    const visual = buildCompanionVisualModel({
      serviceState: this.state, findings, file, pipeline, animations: this.animationsEnabled
    });
    return {
      state: this.state, companionState: visual.state, file, findings,
      message: visual.message, visual,
      policyStatus: pipeline.policyStatus || '',
      animations: visual.animations
    };
  }
  /** The model both surfaces share; the extension forwards it to the dashboard. */
  visualModel() { return this.model().visual; }
  render() {
    const model = this.model();
    // Anti-spam: an identical message never re-renders, and a lower-priority
    // one waits out the cooldown. A critical finding always goes through.
    // The gate runs before the visibility check so the dashboard keeps being
    // updated even when the sidebar view is hidden.
    if (!this.gate.accept(model.message)) return;
    this.onVisualModel?.(model.visual);
    if (!this.view?.visible) return;
    // Once the document exists, state changes are pushed as messages: no HTML
    // is re-parsed while the developer types.
    if (this.rendered && this.view.webview) {
      this.view.badge = model.findings.length
        ? { value: model.findings.length, tooltip: `${model.findings.length} Live Security warning${model.findings.length === 1 ? '' : 's'}` }
        : undefined;
      const visual = mascotVisualFor(model.companionState, { severity: model.message?.severity, policyStatus: model.policyStatus });
      this.postedMessages = (this.postedMessages || 0) + 1;
      this.view.webview.postMessage({
        type: 'state', visual,
        headline: model.message?.headline || '',
        detail: model.message?.detail || '',
        critical: ['critical', 'error'].includes(visual)
      });
      // The finding list itself changed shape: a full render is required.
      if (this.lastFindingCount !== model.findings.length) this.renderFull(model);
      this.lastFindingCount = model.findings.length;
      return;
    }
    this.renderFull(model);
  }
  renderFull(model = this.model()) {
    this.view.badge = model.findings.length
      ? { value: model.findings.length, tooltip: `${model.findings.length} Live Security warning${model.findings.length === 1 ? '' : 's'}` }
      : undefined;
    this.view.webview.html = renderCompanionHtml(model, this.nonce || 'live-companion', this.companionImageUri, this.view.webview.cspSource, this.themeController?.getTheme() || 'light');
    this.rendered = true;
    this.lastFindingCount = model.findings.length;
  }
  handleMessage(message) {
    // Only commands this surface is allowed to trigger. A webview message is
    // untrusted input, so the command name is never forwarded blindly. The list
    // is kept down to what the surface can actually emit: a whitelist entry for
    // a button that no longer exists only widens what a compromised page could
    // reach.
    const ALLOWED = new Set([
      'securityCenter.enableLiveSecurity', 'securityCenter.disableLiveSecurity'
    ]);
    if (message.type === 'command') {
      return ALLOWED.has(message.command) ? this.executeCommand(message.command) : undefined;
    }
    // Clicking the mascot never fixes anything on its own: it opens the current
    // finding, or focuses the view when there is nothing to show.
    if (message.type === 'mascot' || message.type === 'bubble') {
      const [first] = this.model().findings;
      return first
        ? this.executeCommand('securityCenter.openLiveFinding', first.uri, first.documentVersion, first.ruleId)
        : this.executeCommand('securityCenter.focusLiveSecurity');
    }
    if (message.type === 'open-first' || message.type === 'fix-first') {
      const [first] = this.model().findings;
      if (!first) return undefined;
      if (message.type === 'open-first') return this.executeCommand('securityCenter.openLiveFinding', first.uri, first.documentVersion, first.ruleId);
      return this.executeCommand(
        first.quickFixAvailable ? 'securityCenter.applyLiveQuickFix' : 'securityCenter.generateLiveAiFix',
        first.uri, first.documentVersion, first.ruleId
      );
    }
    const [uri, version, ruleId] = message.ref || [];
    if (message.type === 'open') return this.executeCommand('securityCenter.openLiveFinding', uri, version, ruleId);
    if (message.type === 'explain') return this.executeCommand('securityCenter.explainLiveFinding', uri, version, ruleId);
    if (message.type === 'quickfix') return this.executeCommand('securityCenter.applyLiveQuickFix', uri, version, ruleId);
    if (message.type === 'fix') return this.executeCommand('securityCenter.generateLiveAiFix', uri, version, ruleId);
  }
  dispose() { for (const subscription of this.subscriptions.splice(0)) subscription.dispose(); }
}

module.exports = { LiveCompanionProvider, companionCopy, companionStateFor, escapeHtml, renderCompanionHtml };


