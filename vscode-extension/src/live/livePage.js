const path = require('path');
const { escapeHtml } = require('./liveCompanion');
const { SUPPORTED_LANGUAGES } = require('./liveScheduler');
const { themeOverridesCss } = require('../theme-controller');
const { renderCompanionWidget, companionWidgetCss } = require('./companionWidget');
const { renderSecurityCenterShell, navCommands } = require('../security-center-shell');
const { buildAssistantCardModel, renderAssistantCard, assistantCardCss, assistantCardScript } = require('../companion-assistant-card');

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

/**
 * The Live Security page.
 *
 * The companion used to appear here as a static PNG in the header, decorative
 * and disconnected from any state. It is now the real animated mascot, anchored
 * bottom-right and driven by the shared companion model — which also means there
 * is exactly one mascot on this page, not two.
 *
 * `companionImageUri` is kept for the callers that pass it positionally before
 * `cspSource`; the image itself is no longer rendered.
 */
function renderLiveSecurityPage(model, nonce, companionImageUri = '', cspSource = '', selectedTheme = 'light', brandLogoUri = '') {
  const active = model.state !== 'disabled' && model.state !== 'paused';
  const stateLabel = active ? 'Active' : model.state === 'paused' ? 'Paused' : 'Off';
  // Texte BRUT : le cadre applique escapeHtml au sous-titre. Pre-echapper ici
  // produirait un double echappement (« &amp;lt;script&amp;gt; ») a l'ecran.
  const fileSupportMessage = !model.file
    ? 'Open a JavaScript or TypeScript file to start local analysis.'
    : model.supportedFile
      ? `Current file: ${model.file}`
      : `Live Security is active. ${model.file} is not analyzed yet; detection currently supports JavaScript and TypeScript.`;
  // La ligne d'etat vivait dans l'en-tete de la page autonome. Elle reste
  // affichee, dans le contenu, avec exactement le meme libelle qu'avant.
  const stateMessage = model.state === 'analyzing' ? 'Checking current file…'
    : model.state === 'issues' ? `${model.findings.length} potential issue(s)`
      : active ? 'Watching your code' : 'Live analysis is not running';
  const findingRows = model.findings.map((finding) => {
    const ref = escapeHtml(JSON.stringify([finding.uri, finding.documentVersion, finding.ruleId]));
    return `<article class="finding"><div><strong>${escapeHtml(String(finding.severity).toUpperCase())} · ${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.cwe || finding.ruleId)} · Line ${finding.range.start.line + 1}</span></div><div class="actions"><button data-action="open" data-ref="${ref}">Open</button><button class="secondary" data-action="explain" data-ref="${ref}">Explain</button><button class="secondary" data-action="${finding.quickFixAvailable ? 'quickfix' : 'fix'}" data-ref="${ref}">Fix</button></div></article>`;
  }).join('');
  const activityRows = model.activity.recent.slice(0, 8).map((item) => `<li><time>${escapeHtml(new Date(item.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))}</time><span>${escapeHtml(item.label)}</span><small>${item.type === 'resolved' ? 'Resolved live' : 'Detected live'}</small></li>`).join('');
  const knownContext = model.knownFindings?.length ? `<section><h2>Known findings in this file</h2><div class="info"><strong>${model.knownFindings.length} existing Security Center finding(s)</strong><small>Read-only context from completed scans. Live Security did not create these findings.</small></div></section>` : '';
  const tip = model.activity.tip ? `<section><h2>Secure coding hint</h2><div class="hint">${escapeHtml(model.activity.tip)}</div></section>` : '';
  // The companion, from the shared visual model the provider was handed. This
  // page decides nothing about it: not the posture, not the wording, not the
  // count. It only chooses where it sits.
  // FULL mode: this is the only page where the companion is the assistant of
  // the surface itself and may comment on the file being edited.
  // L'assistant du rail lit le meme modele visuel partage que la mascotte : il
  // parle du fichier ouvert, avec le compte que le moteur Live a reellement
  // produit. Sans modele companion, il ne s'affiche pas.
  const assistantCard = renderAssistantCard(buildAssistantCardModel({
    surface: 'live',
    companion: model.companion,
    enabled: model.companionEnabled !== false
  }), { mascotImageUri: companionImageUri });
  // Une seule mascotte par surface. La carte est le meme companion, avec le
  // meme modele et la meme posture, plus des actions explicites : quand elle
  // occupe le rail, le widget flottant n'a plus lieu d'etre dessine. Sans
  // carte — aucun fait a rapporter — le widget reprend sa place inchangee.
  const companion = assistantCard ? '' : renderCompanionWidget(model.companion, {
    variant: 'full', enabled: model.companionEnabled !== false, imageUri: companionImageUri
  });
  // Le cadre partage recoit la CSP EXACTE de cette page : `img-src` doit garder
  // `cspSource`, sinon l'image du companion servie depuis localResourceRoots
  // serait bloquee. Rien d'autre n'est assoupli.
  return renderSecurityCenterShell({
    surface: 'live',
    nonce,
    theme: selectedTheme,
    title: 'Live Security',
    subtitle: fileSupportMessage,
    headerActions: `${active ? '<button data-command="securityCenter.disableLiveSecurity">Turn off</button>' : '<button data-command="securityCenter.enableLiveSecurity">Enable Live Security</button>'}`,
    content: `
  <div class="live-state-strip"><span class="state">● ${stateLabel}</span><p class="muted">${escapeHtml(stateMessage)}</p></div>
  <div class="metrics"><div class="metric"><strong>${model.findings.length}</strong><span>Current file warnings</span></div><div class="metric"><strong>${model.activity.detected}</strong><span>Session warnings</span></div><div class="metric"><strong>${model.activity.resolved}</strong><span>Resolved live</span></div><div class="metric"><strong>${model.activity.prevented || 0}</strong><span>Prevented during coding</span></div></div>
  <div class="grid"><div><section><h2>Current File</h2>${findingRows || '<div class="empty">No Live warnings for the current file.</div>'}</section>${tip}<section><h2>Recent Live Activity</h2>${activityRows ? `<ul>${activityRows}</ul>` : '<div class="empty">No Live activity in this session yet.</div>'}</section></div><aside>${knownContext}<section><h2>Engine</h2><div class="info"><strong>JavaScript / TypeScript</strong><span>Security Center Live Rules</span><small>Local, lightweight and ephemeral analysis</small></div></section><section><h2>AI</h2><div class="info"><strong>Ollama</strong><span>${escapeHtml(model.ollamaModel || 'No model selected')}</span><small>Used only on request</small></div></section></aside></div>`,
    // Le companion garde son modele et son rendu ; il passe dans le rail.
    contextRail: `${assistantCard}${companion}`,
    styles: `    :root{color-scheme:light dark}*{box-sizing:border-box}.live-state-strip{display:flex;align-items:center;gap:12px;margin:0 0 4px}.live-state-strip p{margin:0}${selectedTheme === 'light' ? themeOverridesCss().replaceAll('body.theme-light','body') : ''}h1{margin:0}.muted,.finding span,small{color:var(--vscode-descriptionForeground)}header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;padding-bottom:16px;border-bottom:1px solid var(--vscode-panel-border)}.identity{display:flex;align-items:center;gap:14px}.state{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:10px;color:var(--vscode-badge-foreground);background:var(--vscode-badge-background)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);margin:20px 0;border:1px solid var(--vscode-panel-border);border-radius:5px}.metric{padding:14px}.metric+.metric{border-left:1px solid var(--vscode-panel-border)}.metric strong{display:block;font-size:1.5em}.grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,.7fr);gap:20px}section{margin-bottom:20px}h2{font-size:1.05em;margin:0 0 10px}.finding{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0;border-top:1px solid var(--vscode-panel-border)}.finding span{display:block;margin-top:3px}.actions{display:flex;gap:6px;flex-wrap:wrap}button{font:inherit;border:0;border-radius:2px;padding:5px 10px;cursor:pointer;color:var(--vscode-button-foreground);background:var(--vscode-button-background)}button:hover{background:var(--vscode-button-hoverBackground)}button.secondary{color:var(--vscode-button-secondaryForeground);background:var(--vscode-button-secondaryBackground)}.empty,.info,.hint{padding:12px;border:1px solid var(--vscode-panel-border);border-radius:4px}.hint{border-left:3px solid var(--vscode-focusBorder)}.info{display:grid;gap:8px}ul{list-style:none;padding:0;margin:0}li{display:grid;grid-template-columns:55px 1fr auto;gap:8px;padding:9px 0;border-top:1px solid var(--vscode-panel-border)}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:700px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr}.metric+.metric{border-left:0;border-top:1px solid var(--vscode-panel-border)}.finding{align-items:flex-start;flex-direction:column}}
  ${companion ? companionWidgetCss() : ''}
  ${assistantCard ? assistantCardCss() : ''}`,
    script: `const vscode=window.__scShellApi||acquireVsCodeApi();document.addEventListener('click',e=>{const button=e.target.closest('button');if(!button||button.classList.contains('sc-nav-item'))return;if(button.closest('.sc-assistant'))return;if(button.dataset.command)return vscode.postMessage({type:'command',command:button.dataset.command});vscode.postMessage({type:button.dataset.action,ref:JSON.parse(button.dataset.ref||'[]')});});
${assistantCard ? assistantCardScript() : ''}`,
    csp: `default-src 'none'; img-src ${cspSource || "'none'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`,
    brandLogoUri,
    bodyClass: `${active ? 'active' : 'disabled'} ${escapeHtml(model.state)}`
  });
}

class LiveSecurityPageProvider {
  constructor({ api, service, diagnostics, executeCommand, workspacePath = '', extensionUri, getOllamaModel = () => '', getKnownFindings = () => [], themeController, getCompanionModel = null }) {
    this.api = api; this.service = service; this.diagnostics = diagnostics; this.executeCommand = executeCommand; this.workspacePath = workspacePath; this.extensionUri = extensionUri; this.getOllamaModel = getOllamaModel; this.getKnownFindings = getKnownFindings; this.themeController = themeController;
    // The one companion engine, injected. This page never builds a model of its
    // own: it asks the provider that already owns the service state, the
    // diagnostics, the pipeline context and the anti-spam gate.
    this.getCompanionModel = getCompanionModel;
    this.activity = new LiveSessionActivity(); this.activeDocument = api.window.activeTextEditor?.document; this.panel = undefined;
    this.subscriptions = [service.onDidChangeState(() => this.render()), diagnostics.onDidChange(({ uri, findings, reason }) => { if (reason !== 'suppressed') this.activity.update(uri, findings); this.render(); }), api.window.onDidChangeActiveTextEditor((editor) => { if (editor?.document) this.activeDocument = editor.document; this.render(); }), themeController?.onDidChange(() => this.render())].filter(Boolean);
  }
  open() {
    if (this.panel) return this.panel.reveal(this.api.ViewColumn.Active);
    const assetRoot = this.api.Uri.joinPath(this.extensionUri, 'media', 'live');
    // Cette page possede son propre panneau : la racine de marque doit y etre
    // declaree explicitement, sinon `asWebviewUri` produit une URI que le
    // webview refuse de charger.
    const brandingRoot = this.api.Uri.joinPath(this.extensionUri, 'media', 'branding');
    this.panel = this.api.window.createWebviewPanel('securityCenter.liveSecurity', 'Security Center â€” Live Security', this.api.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [assetRoot, brandingRoot] });
    this.companionImageUri = this.panel.webview.asWebviewUri(this.api.Uri.joinPath(assetRoot, 'security-companion.png')).toString();
    this.brandLogoUri = this.panel.webview.asWebviewUri(this.api.Uri.joinPath(brandingRoot, 'secenter-icon-256.png')).toString();
    this.panel.webview.onDidReceiveMessage((message) => this.handleMessage(message));
    this.panel.onDidDispose(() => { this.panel = undefined; });
    this.render();
  }
  model() {
    const document = this.activeDocument;
    const file = document?.uri?.fsPath ? path.relative(this.workspacePath, document.uri.fsPath).replaceAll('\\', '/') : '';
    const knownFindings = file ? this.getKnownFindings().filter((finding) => finding.file === file && ['high', 'critical'].includes(String(finding.rawSeverity || finding.severity).toLowerCase())) : [];
    const companion = this.getCompanionModel?.() || null;
    return {
      state: this.service.getState(), file, supportedFile: Boolean(document && SUPPORTED_LANGUAGES.has(document.languageId)),
      findings: this.diagnostics.findingsForDocument(document), activity: this.activity.snapshot(),
      ollamaModel: this.getOllamaModel(), knownFindings,
      companion,
      // `securityCenter.live.companion.enabled` gates the presentation only. The
      // engine keeps running either way, so Live Security is unaffected.
      companionEnabled: this.api.workspace?.getConfiguration?.('securityCenter')?.get?.('live.companion.enabled', true) !== false
    };
  }
  render() { if (this.panel) this.panel.webview.html = renderLiveSecurityPage(this.model(), 'live-security-page', this.companionImageUri, this.panel.webview.cspSource, this.themeController?.getTheme() || 'light', this.brandLogoUri || ''); }
  handleMessage(message) {
    // A webview message is untrusted input. Only the two commands this page's
    // own buttons can emit are forwarded; the name is never passed through
    // blindly, which it used to be.
    if (message.type === 'command') {
      // Les deux commandes propres a cette page, plus les destinations que le
      // rail partage affiche reellement. Chacune existe deja et est enregistree :
      // la page n'en cree aucune et ne relaie jamais un nom arbitraire.
      const ALLOWED = new Set([
        'securityCenter.enableLiveSecurity', 'securityCenter.disableLiveSecurity',
        ...navCommands()
      ]);
      return ALLOWED.has(message.command) ? this.executeCommand(message.command) : undefined;
    }
    // Clicking the companion goes wherever its current message points — the
    // finding it is talking about, the scanner that needs configuring, the
    // pipeline that blocked. It never fixes anything and never invokes AI, and
    // the destination is decided by the message engine, not by this page.
    if (message.type === 'companion') {
      const action = this.getCompanionModel?.()?.action;
      if (action?.scope === 'finding') {
        const [first] = this.diagnostics.findingsForDocument(this.activeDocument);
        return first
          ? this.executeCommand('securityCenter.openLiveFinding', first.uri, first.documentVersion, first.ruleId)
          : undefined;
      }
      // Only destinations that already exist, and never a remediation command.
      // `live` is excluded here: this *is* the Live Security page, so sending the
      // developer to it would be a click that does nothing visible.
      const ALLOWED = new Set([
        'securityCenter.openScannerSetup', 'securityCenter.openSecurityPipeline', 'securityCenter.openDashboard'
      ]);
      return action && ALLOWED.has(action.command) ? this.executeCommand(action.command) : undefined;
    }
    const [uri, version, ruleId] = message.ref || [];
    const commands = { open: 'securityCenter.openLiveFinding', explain: 'securityCenter.explainLiveFinding', quickfix: 'securityCenter.applyLiveQuickFix', fix: 'securityCenter.generateLiveAiFix' };
    if (commands[message.type]) return this.executeCommand(commands[message.type], uri, version, ruleId);
  }
  dispose() { this.panel?.dispose(); for (const subscription of this.subscriptions.splice(0)) subscription.dispose(); }
}

module.exports = { LiveSecurityPageProvider, LiveSessionActivity, renderLiveSecurityPage };



