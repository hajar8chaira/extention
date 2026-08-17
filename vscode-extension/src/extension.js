const vscode = require('vscode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const { runSemgrep } = require('./semgrep');
const { runGitleaks } = require('./gitleaks');
const { runTrivy, generateSbom } = require('./trivy');
const { runOsv } = require('./osv');
const { runZap } = require('./zap');
const { detectLocalZap } = require('./zap-local');
const { ensureDockerAvailable } = require('./docker');
const { runSonarQube, detectLocalScanner: detectLocalSonarScanner } = require('./sonarqube');
const { checkServerStatus: checkSonarServer, validateToken: validateSonarToken, normalizeHostUrl: normalizeSonarHostUrl } = require('./sonarqube-api');
const { SERVER_URL: SONAR_LOCAL_SERVER_URL, inspectLocalServer, localServerState, startLocalServer, stopLocalServer, waitForLocalServer } = require('./sonarqube-server');
const { runSnyk, detectLocalCli: detectLocalSnykCli } = require('./snyk');
const { validateToken: validateSnykToken, looksLikeSnykToken } = require('./snyk-api');
const { normalizeSemgrepOutput, normalizeGitleaksOutput, normalizeTrivyOutput, normalizeZapOutput, normalizeOsvOutput, normalizeSonarQubeOutput, normalizeSnykOutput, deduplicateFindings, hasReportableLocation } = require('./findings');
const { groupFindings, summarizeFindings } = require('./tree');
const { setApiKey, saveScanResult, saveHttpScenario, listHttpScenarios, getBurpStatus, updateFindingStatus, listAuditEvents, createAuditEvent, listScans, getScan, requestText, scanExportUrl } = require('./backend');
const { CACHE_KEY: LOCAL_SCAN_CACHE_KEY, createLocalScanCache, restoreLocalScanCache } = require('./local-scan-cache');
const {
  CAMPAIGN_STATUS: DYNAMIC_STATUS, createCampaign: createDynamicCampaign,
  applyProgress: applyDynamicProgress, completeCampaign: completeDynamicCampaign,
  toTransaction: dynamicTransaction, restoreCampaign: restoreDynamicCampaign,
  legacyBucket: dynamicLegacyBucket, captureSessionFrom
} = require('./dynamic-campaign');
const { createExecution, snapshotFromLegacy, normalizeSnapshot, beginRefresh, updateRefresh, completeExecution, projectSnapshot } = require('./security-snapshot');
const { HISTORY_KEY: LOCAL_SCAN_HISTORY_KEY, appendLocalHistory, renderScanHistoryHtml } = require('./scan-history-page');
const { buildDashboardModel, renderDashboardHtml, buildSafeHttpPreview, linkedFindingsForScenario, summarizeScannerError } = require('./dashboard');
const { normalizeTargetUrl, checkTargetReachability } = require('./dynamic-target');
const { renderFindingDetailsHtml } = require('./finding-details');
const { correlateFindings } = require('./correlation');
const { findingKey, applyFindingStatuses, isActiveFinding, validatedAfterScan, retainValidatedFindings } = require('./triage');
const { normalizeHar, replayScenario } = require('./http-scenarios');
const { renderHttpReplayHtml, renderSafeHttpRequestHtml } = require('./http-details');
const { compareScans, renderScanComparisonHtml } = require('./scan-comparison');
const { modifiedGitFiles, createIncrementalWorkspace, retainUnchangedFindings } = require('./incremental');
const { renderAuditLogHtml } = require('./audit');
const { loadProjectPolicy, evaluatePolicy } = require('./project-policy');
const { evaluatePolicyGate, policyGateError, STATUS: GATE_STATUS } = require('./intelligence/policy-gate');
const { readPolicyGateConfig, savePolicyGate, createStarterPolicy, policyGateHash, policyFilePath } = require('./policy-config');
const { analyzeLicenses, renderLicenseReportHtml } = require('./license-compliance');
const { installPreCommitHook } = require('./precommit');
const { buildTrendReport, renderTrendReportHtml } = require('./trends');
const { runWithConcurrency } = require('./scheduler');
const { buildAutofixPlan } = require('./autofix');
const { sendSlack, createJiraIssue } = require('./team-integrations');
const { buildMinimalContext, redactSecrets } = require('./ai/context-builder');
const { createAiProvider, PROVIDERS } = require('./ai/provider-registry');
const { configureModelRoles } = require('./ai/model-configuration');
const { readModelRoleConfiguration } = require('./ai/model-roles');
const { findInstalledModel } = require('./ai/model-discovery');
const { remediationResult, fallbackReasonMessage } = require('./ai/remediation-result');
const { runTwoModelRemediation, runAdvancedRemediation } = require('./ai/remediation-router');
const { buildRemediationMetric, saveLocalRemediationMetric } = require('./ai/remediation-metrics');
const { FAILURE_MESSAGE, FAILURE_DETAIL, FAILURE_ACTIONS, isExhaustedRemediation } = require('./ai/remediation-failure');
const { replacementToPatch, parseUnifiedDiff, validatePatchForFinding, applyParsedPatch, calculateFixConfidence } = require('./ai/patch-validator');
const { runDeclaredTests } = require('./ai/fix-verifier');
const { LiveSecurityService } = require('./live/liveSecurityService');
const { analyzeLiveDocument } = require('./live/liveDetector');
const { LiveDiagnostics } = require('./live/liveDiagnostics');
const { LiveHoverProvider } = require('./live/liveHover');
const { LIVE_SELECTOR, LiveCodeActionProvider, deterministicReplacement, toRemediationFinding } = require('./live/liveCodeActions');
const { LiveCompanionProvider } = require('./live/liveCompanion');
const { LiveStatusBar } = require('./live/liveStatus');
const { SecurityStatusBar } = require('./securityStatusBar');
const { SentinelEditorPresence } = require('./live/sentinelEditorPresence');
const { LiveSecurityPageProvider } = require('./live/livePage');
const { ThemeController } = require('./theme-controller');
const { ScannerToolManager, TOOLS: MANAGED_SCANNER_TOOLS } = require('./scanner-tool-manager');
const { renderScannerSetupHtml, sonarDiagnosis, snykDiagnosis } = require('./scanner-setup-page');
const { analyzeWorkspace, mergeIntelligence, buildPipelineResult, describeStages, runSupplyChainStages, restorePipelineResult, pipelineStateFor, dataAvailability } = require('./pipeline');
const { renderPipelinePageHtml } = require('./pipeline-page');
const { detectLocalCosign, generateKeyPair, signBlob, verifyBlob, supportedModes: cosignModes, keylessSupport } = require('./supply-chain/cosign');
const { SCANNER_RUNTIMES, diagnoseScanner, normalizeMode } = require('./scanner-diagnostics');
const execFileAsync = promisify(execFile);
const SONAR_TOKEN_SECRET_KEY = 'securityCenter.sonar.token';
const SNYK_TOKEN_SECRET_KEY = 'securityCenter.snyk.token';
const COSIGN_PASSWORD_SECRET_KEY = 'securityCenter.cosign.keyPassword';
const PIPELINE_STATE_KEY = 'securityCenter.pipelineState';
// Every scanner Security Center can run, in the order the UI presents them.
const ALL_SCANNER_TOOLS = Object.freeze(['Semgrep', 'Gitleaks', 'Trivy', 'OSV-Scanner', 'SonarQube', 'Snyk', 'ZAP']);
// Scanners that can be switched off from the settings, so the dashboard can
// report « Désactivé » instead of leaving them silently absent.
const OPTIONAL_SCANNERS = Object.freeze([
  ['Gitleaks', 'gitleaks.enabled', true],
  ['Trivy', 'trivy.enabled', true],
  ['OSV-Scanner', 'osv.enabled', true],
  ['SonarQube', 'sonar.enabled', false],
  // Snyk requires an account and a token, so it is opt-in like SonarQube.
  ['Snyk', 'snyk.enabled', false],
  ['ZAP', 'zap.enabled', true]
]);

function configuredDisabledScanners() {
  try {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    return OPTIONAL_SCANNERS.filter(([, key, fallback]) => cfg.get(key, fallback) !== true).map(([tool]) => tool);
  } catch { return []; }
}

function cfgHostUrlOrEmpty() {
  try { return vscode.workspace.getConfiguration('securityCenter').get('sonar.hostUrl', '') || ''; }
  catch { return ''; }
}

let liveSecurityService;
let sonarServerBusy = false;

function burpExecutableCandidates() {
  if (process.platform !== 'win32') return [];
  return [
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'BurpSuiteCommunity', 'BurpSuite.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'BurpSuiteCommunity', 'BurpSuiteCommunity.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'BurpSuitePro', 'BurpSuitePro.exe')
  ];
}

async function isBurpRunning() {
  if (process.platform !== 'win32') return false;
  try {
    const { stdout } = await execFileAsync('tasklist.exe', ['/FI', 'IMAGENAME eq BurpSuite.exe', '/FO', 'CSV', '/NH'], { windowsHide: true });
    return /BurpSuite\.exe/i.test(stdout);
  } catch { return false; }
}

async function javaAvailable() {
  try { await execFileAsync('java', ['-version'], { windowsHide: true, timeout: 10000 }); return true; } catch { return false; }
}

class DashboardProvider {
  constructor(onCommand, themeController, getLocalHistory = () => []) {
    this.view = undefined;
    this.fullPanel = undefined;
    this.pagePanels = new Map();
    this.requestPanel = undefined;
    this.requestPanelIndex = -1;
    this.themeController = themeController;
    this.getLocalHistory = getLocalHistory;
    this.selectedTheme = themeController?.getTheme() || 'light';
    this.zapConfirmationVisible = false;
    this.zapConfirmation = undefined;
    this.resolveZapConfirmation = undefined;
    this.model = buildDashboardModel();
    this.onCommand = onCommand;
    this.themeSubscription = themeController?.onDidChange((theme) => {
      this.selectedTheme = theme;
      this.render();
      if (this.requestPanelIndex >= 0) this.openFullHttpRequest(this.requestPanelIndex);
    });
  }
  registerMessages(webview) {
    webview.onDidReceiveMessage((message) => {
      if (message?.type === 'themeChanged' && ['light', 'dark'].includes(message.theme)) {
        if (this.themeController) this.themeController.setTheme(message.theme);
        else this.selectedTheme = message.theme;
        return;
      }
      if (message?.type === 'requestZapScan') {
        this.zapConfirmationVisible = true;
        this.render();
        return;
      }
      if (message?.type === 'cancelZapScan') {
        this.zapConfirmationVisible = false;
        this.zapConfirmation = undefined;
        const resolve = this.resolveZapConfirmation;
        this.resolveZapConfirmation = undefined;
        this.render();
        resolve?.(false);
        return;
      }
      if (message?.type === 'confirmZapScan') {
        this.zapConfirmationVisible = false;
        this.zapConfirmation = undefined;
        const resolve = this.resolveZapConfirmation;
        this.resolveZapConfirmation = undefined;
        this.render();
        if (resolve) resolve(true);
        else this.onCommand('securityCenter.scanWorkspace', { tools: ['ZAP'], zapAuthorized: true });
        return;
      }
      const allowed = new Set([
        'securityCenter.openDashboard',
        'securityCenter.openFindingsPage',
        'securityCenter.openScansPage',
        'securityCenter.openDynamicPage',
        'securityCenter.openBurpSettingsPage',
        'securityCenter.checkDynamicTarget',
        'securityCenter.changeDynamicTarget',
        'securityCenter.openAnalyticsPage',
        'securityCenter.scanWorkspace',
        'securityCenter.scanSelected',
        'securityCenter.showLogs',
        'securityCenter.scanZap',
        'securityCenter.configureZap',
        'securityCenter.configureZapCredentials',
        'securityCenter.configureBurp',
        'securityCenter.testBurpConnection',
        'securityCenter.importHttpCapture',
        'securityCenter.replayHttpScenario',
        'securityCenter.showScanHistory',
        'securityCenter.showScanHistoryPage',
        'securityCenter.compareScans',
        'securityCenter.scanIncremental',
        'securityCenter.showAuditLog',
        'securityCenter.openProjectPolicy',
        'securityCenter.generateSbom',
        'securityCenter.checkLicenses',
        'securityCenter.configureBackendApiKey',
        'securityCenter.installPreCommitHook',
        'securityCenter.showTrends',
        'securityCenter.configureTeamIntegrations',
        'securityCenter.configureOllama',
        'securityCenter.rollbackAiFix'
        ,'securityCenter.openScannerSetup'
        ,'securityCenter.openSecurityPipeline'
      ]);
      if (message?.type === 'command' && message.command === 'securityCenter.scanZap') {
        this.zapConfirmationVisible = true;
        this.zapConfirmation = {
          mode: 'active',
          target: this.model.dynamicTargetUrl || 'http://127.0.0.1:3000'
        };
        this.openPage('dynamic');
        this.render();
        return;
      }
      if (message?.type === 'command' && allowed.has(message.command)) this.onCommand(message.command);
      if (message?.type === 'retryScanner' && ALL_SCANNER_TOOLS.includes(message.tool)) {
        this.onCommand('securityCenter.retryScanner', message.tool);
      }
      if (message?.type === 'finding' && Number.isInteger(message.index)) {
        const finding = this.model.findings[message.index];
        if (finding) this.onCommand('securityCenter.showFindingDetails', finding);
      }
      if (message?.type === 'findingFromTraffic' && Number.isInteger(message.findingIndex) && Number.isInteger(message.trafficIndex)) {
        const finding = this.model.findings[message.findingIndex];
        if (finding) this.onCommand('securityCenter.showFindingDetails', finding, { trafficIndex: message.trafficIndex });
      }
      if (message?.type === 'findingCode' && Number.isInteger(message.index)) {
        const finding = this.model.findings[message.index];
        if (finding) this.onCommand('securityCenter.openFindingCode', finding);
      }
      if (message?.type === 'httpTrafficDetails' && Number.isInteger(message.index)) {
        const scenario = this.model.httpScenarios[message.index];
        if (scenario) webview.postMessage({ type: 'httpTrafficDetails', detail: buildSafeHttpPreview(scenario, this.model.findings) });
      }
      if (message?.type === 'replayHttpTraffic' && Number.isInteger(message.index)) {
        const scenario = this.model.httpScenarios[message.index];
        if (scenario) this.onCommand('securityCenter.replayHttpScenario', scenario);
      }
      if (message?.type === 'openFullHttpRequest' && Number.isInteger(message.index)) this.openFullHttpRequest(message.index);
    });
  }
  openFullHttpRequest(index) {
    const scenario = this.model.httpScenarios[index];
    if (!scenario) return;
    this.requestPanelIndex = index;
    if (!this.requestPanel) {
      this.requestPanel = vscode.window.createWebviewPanel('securityCenter.httpRequest', 'Security Center — Requête HTTP', vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true });
      this.requestPanel.webview.onDidReceiveMessage((message) => {
        const currentScenario = this.model.httpScenarios[this.requestPanelIndex];
        if (!currentScenario) return;
        if (message?.type === 'finding' && Number.isInteger(message.index)) {
          const finding = this.model.findings[message.index];
          if (finding) this.onCommand('securityCenter.showFindingDetails', finding, { trafficIndex: this.requestPanelIndex });
        }
        if (message?.type === 'replay') this.onCommand('securityCenter.replayHttpScenario', currentScenario);
        if (message?.type === 'back') this.openPage('dynamic');
      });
      this.requestPanel.onDidDispose(() => { this.requestPanel = undefined; this.requestPanelIndex = -1; });
    } else this.requestPanel.reveal(vscode.ViewColumn.Active);
    const detail = buildSafeHttpPreview(scenario, this.model.findings);
    this.requestPanel.title = `Security Center — ${detail.method} ${detail.path}`;
    this.requestPanel.webview.html = renderSafeHttpRequestHtml(detail, crypto.randomBytes(16).toString('base64'), this.selectedTheme);
  }
  resolveWebviewView(view) {
    this.view = view;
    view.webview.options = { enableScripts: true };
    this.registerMessages(view.webview);
    this.render();
  }
  openFullDashboard() {
    if (this.fullPanel) {
      this.fullPanel.reveal(vscode.ViewColumn.Active);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'securityCenter.fullDashboard',
      'Security Center — Dashboard',
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    this.fullPanel = panel;
    this.registerMessages(panel.webview);
    panel.onDidDispose(() => { this.fullPanel = undefined; });
    this.renderWebview(panel.webview);
  }
  openPage(page) {
    const titles = { findings: 'Security Center — Findings', scans: 'Security Center — Scans', dynamic: 'Security Center — Dynamic Security', analytics: 'Security Center — Analytics', 'burp-settings': 'Security Center — Burp Settings' };
    const existing = this.pagePanels.get(page);
    if (existing) return existing.reveal(vscode.ViewColumn.Active);
    const panel = vscode.window.createWebviewPanel(`securityCenter.${page}`, titles[page] || 'Security Center', vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true });
    this.pagePanels.set(page, panel);
    this.registerMessages(panel.webview);
    panel.onDidDispose(() => {
      this.pagePanels.delete(page);
    });
    this.renderWebview(panel.webview, page);
  }
  requestZapAuthorization({ mode, target }) {
    if (this.resolveZapConfirmation) this.resolveZapConfirmation(false);
    this.zapConfirmation = { mode, target };
    this.zapConfirmationVisible = true;
    const decision = new Promise((resolve) => { this.resolveZapConfirmation = resolve; });
    // Keep the user on the surface from which the full scan was started.
    // The confirmation card is rendered by the existing dashboard/sidebar
    // instead of navigating to Dynamic Security mid-execution.
    this.render();
    return decision;
  }
  setData(findings, scanners, options) {
    this.model = buildDashboardModel(findings, scanners, {
      ...options,
      disabledScanners: options?.disabledScanners ?? configuredDisabledScanners(),
      scanHistory: this.getLocalHistory()
    });
    this.onModelChange?.(this.model);
    this.render();
  }
  render() {
    if (this.view) this.renderWebview(this.view.webview, 'sidebar');
    if (this.fullPanel) this.renderWebview(this.fullPanel.webview, 'full');
    for (const [page, panel] of this.pagePanels) this.renderWebview(panel.webview, page);
  }
  renderWebview(webview, surface = 'full') {
    const nonce = crypto.randomBytes(16).toString('base64');
    // The companion is read at render time, not stored in the dashboard model:
    // it changes with the file being edited, which has nothing to do with a scan
    // result. The object comes straight from the companion engine — the same one
    // the Live Security page reads — so the two surfaces cannot disagree.
    const model = {
      ...this.model,
      companion: this.getCompanionModel?.() || null,
      companionEnabled: vscode.workspace.getConfiguration('securityCenter').get('live.companion.enabled', true) !== false
    };
    webview.html = renderDashboardHtml(model, nonce, surface, this.selectedTheme, { zapConfirmationVisible: this.zapConfirmationVisible, zapConfirmation: this.zapConfirmation });
  }
  dispose() { this.themeSubscription?.dispose(); }
}

class FindingsProvider {
  constructor() { this.roots = []; this.emitter = new vscode.EventEmitter(); this.onDidChangeTreeData = this.emitter.event; }
  setFindings(findings, scanStatuses = []) { this.roots = groupFindings(findings, scanStatuses); this.emitter.fire(); }
  getTreeItem(item) {
    if (item.kind === 'tool') {
      const collapsibleState = item.children.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None;
      const node = new vscode.TreeItem(item.label, collapsibleState);
      node.description = item.status === 'failed' ? 'échec' : `${item.count} résultat(s) • terminé`;
      node.tooltip = item.status === 'failed' ? `${item.label} n’a pas terminé le scan : ${item.error}` : `${item.label} a terminé avec ${item.count} résultat(s).`;
      node.iconPath = new vscode.ThemeIcon(item.status === 'failed' ? 'error' : item.count === 0 ? 'pass' : item.label === 'Gitleaks' ? 'key' : 'shield');
      return node;
    }
    if (item.kind === 'file') {
      const node = new vscode.TreeItem(item.label, vscode.TreeItemCollapsibleState.Collapsed);
      node.description = `${item.count} alerte(s)`;
      node.iconPath = new vscode.ThemeIcon('file-code');
      return node;
    }
    if (item.kind === 'rule') {
      const node = new vscode.TreeItem(item.label, vscode.TreeItemCollapsibleState.Collapsed);
      const containsEndpoints = item.children.some((child) => child.kind === 'endpoint');
      node.description = `${item.count} ${containsEndpoints ? 'endpoint(s)' : 'occurrence(s)'} • ${item.rawSeverity}`;
      node.tooltip = containsEndpoints
        ? `Vulnérabilité ZAP ${item.ruleId}\n${item.count} endpoint(s) concerné(s). Dépliez pour voir les URL.`
        : `Cause regroupée : ${item.ruleId}\n${item.count} lignes concernées. Dépliez pour voir chaque occurrence.`;
      node.iconPath = new vscode.ThemeIcon(item.severity === 'error' ? 'error' : item.severity === 'warning' ? 'warning' : 'info');
      return node;
    }
    const finding = item.finding;
    let endpointLabel = '';
    if (item.kind === 'endpoint') {
      try {
        const endpoint = new URL(finding.endpoint);
        endpointLabel = `${finding.method || 'HTTP'} ${endpoint.pathname}${endpoint.search}`;
      } catch {
        endpointLabel = finding.file;
      }
    }
    const node = new vscode.TreeItem(item.occurrence ? `Ligne ${finding.startLine + 1}` : item.kind === 'endpoint' ? endpointLabel : finding.title, vscode.TreeItemCollapsibleState.None);
    const triageStatus = finding.triageStatus || 'new';
    node.description = item.occurrence || item.kind === 'endpoint'
      ? `${finding.rawSeverity} • ${triageStatus}`
      : `${finding.rawSeverity} • ${triageStatus} • ligne ${finding.startLine + 1}`;
    const details = new vscode.MarkdownString();
    details.appendMarkdown(`**${finding.tool} — ${finding.rawSeverity}**\n\n`);
    details.appendMarkdown(`${finding.title}\n\n`);
    details.appendMarkdown(`- Règle : \`${finding.ruleId}\`\n`);
    details.appendMarkdown(`- Fichier : \`${finding.file}:${finding.startLine + 1}\`\n`);
    if (finding.cwe) details.appendMarkdown(`- Référence : ${finding.cwe}\n`);
    if (finding.sourceContext) details.appendMarkdown(`- Contexte : \`${finding.sourceContext}\`\n`);
    if (finding.confidence) details.appendMarkdown(`- Confiance : \`${finding.confidence}\`\n`);
    if (finding.correlatedTools?.length) details.appendMarkdown(`- Corrélé avec : \`${finding.correlatedTools.join(', ')}\` (${finding.correlationConfidence})\n`);
    if (finding.endpoint) details.appendMarkdown(`- Endpoint : \`${finding.method || 'HTTP'} ${finding.endpoint}\`\n`);
    details.appendMarkdown(finding.absolutePath ? '\nCliquez pour ouvrir la ligne concernée.' : '\nRésultat dynamique : aucun fichier source associé pour le moment.');
    node.tooltip = details;
    node.contextValue = finding.tool === 'Semgrep' && finding.autofix ? 'securityFindingAutofix' : 'securityFinding';
    const findingIcon = triageStatus === 'false_positive' ? 'circle-slash'
      : triageStatus === 'fixed' ? 'pass-filled'
        : triageStatus === 'confirmed' ? 'verified-filled'
          : finding.severity === 'error' ? 'error' : finding.severity === 'warning' ? 'warning' : 'info';
    node.iconPath = new vscode.ThemeIcon(findingIcon);
    if (finding.tool === 'ZAP' || finding.tool === 'OSV-Scanner'
      || (finding.tool === 'SonarQube' && !finding.absolutePath)
      // A Snyk Open Source result names a manifest, not a line. It opens the
      // details, and the details link back to the manifest when it exists.
      || (finding.tool === 'Snyk' && (finding.unlocated || !finding.absolutePath || !fs.existsSync(finding.absolutePath)))
      || (finding.tool === 'Trivy' && (!finding.absolutePath || !fs.existsSync(finding.absolutePath)))) {
      node.command = { command: 'securityCenter.showFindingDetails', title: 'Afficher les détails', arguments: [finding] };
    } else if (finding.absolutePath && fs.existsSync(finding.absolutePath)) {
      node.command = { command: 'securityCenter.openFindingCode', title: 'Ouvrir le code', arguments: [finding] };
    }
    return node;
  }
  getChildren(item) { return item?.children || this.roots; }
}

function toDiagnostic(finding) {
  const range = new vscode.Range(finding.startLine, finding.startColumn, finding.endLine, finding.endColumn);
  const severity = finding.severity === 'error' ? vscode.DiagnosticSeverity.Error : finding.severity === 'information' ? vscode.DiagnosticSeverity.Information : vscode.DiagnosticSeverity.Warning;
  const diagnostic = new vscode.Diagnostic(range, finding.title, severity);
  diagnostic.source = `Security Center / ${finding.tool}`;
  diagnostic.code = finding.helpUri ? { value: finding.ruleId, target: vscode.Uri.parse(finding.helpUri) } : finding.ruleId;
  return diagnostic;
}

function publishDiagnostics(collection, findings) {
  collection.clear();
  const grouped = new Map();
  for (const finding of findings.filter(isActiveFinding)) {
    if (!hasReportableLocation(finding) || !fs.existsSync(finding.absolutePath)) continue;
    const uri = vscode.Uri.file(finding.absolutePath);
    const list = grouped.get(uri.fsPath) || { uri, diagnostics: [] };
    list.diagnostics.push(toDiagnostic(finding)); grouped.set(uri.fsPath, list);
  }
  for (const { uri, diagnostics } of grouped.values()) collection.set(uri, diagnostics);
}

async function activate(context) {
  setApiKey(await context.secrets.get('securityCenter.backend.apiKey') || '');
  const diagnostics = vscode.languages.createDiagnosticCollection('security-center');
  const liveDiagnosticCollection = vscode.languages.createDiagnosticCollection('security-center-live');
  const scanLog = vscode.window.createOutputChannel('Security Center');
  const provider = new FindingsProvider();
  const themeController = new ThemeController(context.globalState.get('securityCenter.theme', 'light'), (theme) => context.globalState.update('securityCenter.theme', theme));
  const scannerToolManager = new ScannerToolManager(context.globalStorageUri.fsPath);
  await scannerToolManager.activateManagedPath();
  const dashboardProvider = new DashboardProvider(
    (command, ...args) => vscode.commands.executeCommand(command, ...args),
    themeController,
    () => context.workspaceState.get(LOCAL_SCAN_HISTORY_KEY, [])
  );
  let currentFindings = [];
  let currentScanStatuses = [];
  let currentDashboardOptions = {};
  let currentSecuritySnapshot = snapshotFromLegacy();
  // Security Intelligence state lives with the other scan state so it can be
  // restored from the cache at activation, before any page is opened.
  let currentPipelineResult = null;
  let currentPipelineArtifacts = context.workspaceState.get(PIPELINE_STATE_KEY, {})?.artifacts || {};
  let currentScanRunning = false;
  /**
   * Pipeline facts the Security Companion may mention. Every field is read from
   * state that already exists — nothing here starts a scan, and an unknown fact
   * is simply omitted so the companion stays silent about it.
   */
  function buildCompanionPipelineContext() {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const scannerHealth = [];
    // Only scanners that are enabled *and* cannot run are worth mentioning.
    if (cfg.get('snyk.enabled', false) && !companionSnykTokenPresent) {
      scannerHealth.push({ tool: 'Snyk', enabled: true, reason: 'jeton manquant — configurez-le dans Configuration des scanners.' });
    }
    if (cfg.get('sonar.enabled', false) && companionSonarUnreachable) {
      scannerHealth.push({ tool: 'SonarQube Server', enabled: true, reason: 'serveur injoignable — vérifiez le serveur dans Configuration des scanners.' });
    }
    const failedScanner = currentScanStatuses.find((scanner) => scanner.status === 'failed');
    if (failedScanner) {
      scannerHealth.push({ tool: failedScanner.tool, enabled: true, reason: summarizeScannerError(failedScanner.error || failedScanner.details || '') });
    }
    return {
      scanStatus: currentScanRunning ? 'running' : (currentPipelineResult ? 'completed' : ''),
      scanFindingCount: currentPipelineResult ? currentFindings.length : undefined,
      scanPriorityCount: currentPipelineResult?.prioritySummary?.distribution
        ? (currentPipelineResult.prioritySummary.distribution.P0 || 0) + (currentPipelineResult.prioritySummary.distribution.P1 || 0)
        : undefined,
      // NOT_CONFIGURED stays silent — there is no verdict to report. An invalid
      // policy is not silent: it is a state the developer must act on.
      policyStatus: currentPipelineResult?.policy?.configured || currentPipelineResult?.policy?.status === GATE_STATUS.ERROR
        ? currentPipelineResult.policy.status : '',
      scannerHealth,
      // Which scanners are actually running right now. They run in parallel, so
      // the companion counts them rather than pretending they are sequential.
      scanProgress: currentScanRunning ? {
        running: currentScanStatuses.filter((scanner) => scanner.status === 'running').map((scanner) => scanner.tool),
        completed: currentScanStatuses.filter((scanner) => scanner.status === 'completed').length,
        total: currentScanStatuses.length
      } : null,
      // How the last scan ended, from the status the dashboard already holds.
      scanOutcome: currentScanRunning ? '' : (currentDashboardOptions.scanStatus || ''),
      // Where a remediation stands, read from the triage status the scan wrote.
      // `fixed` means applied and awaiting a re-scan; `validated` means the
      // re-scan no longer finds it.
      fixState: currentFindings.some((finding) => finding.triageStatus === 'validated') ? 'validated'
        : currentFindings.some((finding) => finding.triageStatus === 'fixed') ? 'applied' : '',
      // Supply-chain evidence, only for the stages that really ran.
      supplyChain: Object.keys(currentPipelineArtifacts || {}).length ? {
        sbom: currentPipelineArtifacts.sbom?.status || '',
        provenance: currentPipelineArtifacts.provenance?.status || '',
        signing: currentPipelineArtifacts.signing?.status || ''
      } : null,
      // The Burp connector state, only once it has actually been probed.
      burpConnected: typeof currentDashboardOptions.burpConnected === 'boolean'
        ? currentDashboardOptions.burpConnected : null,
      remediationAvailable: currentFindings.some((finding) => finding.autofix)
    };
  }
  // Cheap cached health signals: refreshed on demand, never polled.
  let companionSnykTokenPresent = false;
  let companionSonarUnreachable = false;
  context.secrets.get(SNYK_TOKEN_SECRET_KEY).then((token) => { companionSnykTokenPresent = Boolean(token); }).catch(() => {});
  let executionSequence = Number(context.workspaceState.get('securityCenter.executionSequence', 0));
  let currentScanId = null;
  let findingDetailsPanel;
  let findingDetailsFinding;
  let scanInProgress = false;
  let httpWriteReplayAuthorized = false;
  let lastAiRollback;
  let lastProjectPolicy;
  const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
  const zapCredentialScope = crypto.createHash('sha256').update(workspacePath || 'workspace').digest('hex').slice(0, 16);
  const zapUsernameSecretKey = `securityCenter.zap.username.${zapCredentialScope}`;
  const zapPasswordSecretKey = `securityCenter.zap.password.${zapCredentialScope}`;
  /**
   * The dynamic target state, with the evidence that established it.
   *
   * `state` alone was contradictory: a ZAP scan could complete — which *proves*
   * the target answered — while the badge still read « Inconnue / non vérifiée »
   * because nobody had pressed « Vérifier ». The state now records how it was
   * established and when, and a scan is a legitimate source of that evidence.
   *
   * Changing the target URL invalidates the evidence: it was about the old host.
   */
  function refreshDynamicTargetModel(state = currentDashboardOptions.dynamicTargetState || 'unknown', evidence = null) {
    const targetUrl = vscode.workspace.getConfiguration('securityCenter').get('zap.targetUrl', '');
    const sameTarget = currentDashboardOptions.dynamicTargetUrl === targetUrl;
    currentDashboardOptions = {
      ...currentDashboardOptions,
      dynamicTargetUrl: targetUrl,
      dynamicTargetState: state,
      dynamicTargetEvidence: evidence
        ? { ...evidence, at: new Date().toISOString(), target: targetUrl }
        : (sameTarget ? currentDashboardOptions.dynamicTargetEvidence || null : null)
    };
    dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
  }
  /**
   * The dynamic campaign currently being executed, or the last one restored.
   *
   * It lives in `currentDashboardOptions`, which the local scan cache already
   * persists verbatim — no second store is introduced. A campaign therefore
   * survives a reload for free, and an old cache without one restores as an
   * explicit legacy bucket rather than crashing or claiming a run it cannot prove.
   */
  function currentDynamicCampaign() {
    return currentDashboardOptions.dynamicCampaign || null;
  }

  function setDynamicCampaign(campaign) {
    currentDashboardOptions = { ...currentDashboardOptions, dynamicCampaign: campaign };
    dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
  }

  /** Starts a ZAP campaign. Its identity exists before the scan produces anything. */
  function beginZapCampaign() {
    const targetUrl = vscode.workspace.getConfiguration('securityCenter').get('zap.targetUrl', 'http://127.0.0.1:3000');
    const campaign = createDynamicCampaign({
      source: 'zap',
      target: targetUrl,
      mode: vscode.workspace.getConfiguration('securityCenter').get('zap.mode', 'baseline'),
      auth: { mode: lastProjectPolicy?.zapAuth?.login ? 'login' : 'anonymous' }
    });
    setDynamicCampaign(campaign);
    return campaign;
  }

  /**
   * A lifecycle observation from the execution layer.
   *
   * Push, never poll: the webview is re-rendered because ZAP answered, not on a
   * schedule. An event arriving without an open campaign is dropped rather than
   * attributed to whatever ran last.
   */
  function publishDynamicLifecycle(event) {
    const campaign = currentDynamicCampaign();
    if (!campaign || campaign.legacy) return;
    setDynamicCampaign(applyDynamicProgress(campaign, event));
  }

  /** Closes the campaign with the outcome the scan really had. */
  async function finishZapCampaign(status, { findingIds = [], scenarios = null } = {}) {
    const campaign = currentDynamicCampaign();
    if (!campaign || campaign.legacy) return;
    const transactions = (scenarios || currentDashboardOptions.httpScenarios || [])
      .map((scenario, index) => dynamicTransaction(scenario, { campaignId: campaign.id, index }));
    setDynamicCampaign(completeDynamicCampaign(campaign, { status, findingIds, transactions }));
    await saveLocalScanCache();
  }

  async function saveLocalScanCache() {
    if (!workspacePath) return;
    if (currentSecuritySnapshot?.resultSets) {
      const resultSets = { ...currentSecuritySnapshot.resultSets };
      for (const [tool, set] of Object.entries(resultSets)) {
        resultSets[tool] = { ...set, findings: currentFindings.filter((finding) => finding.tool === tool) };
      }
      currentSecuritySnapshot = { ...currentSecuritySnapshot, resultSets };
    }
    await context.workspaceState.update(
      LOCAL_SCAN_CACHE_KEY,
      createLocalScanCache(workspacePath, currentFindings, currentScanStatuses, currentDashboardOptions, new Date().toISOString(), currentSecuritySnapshot)
    );
  }
  async function addCurrentScanToLocalHistory(executionRecord) {
    if (!workspacePath) return;
    const savedAt = new Date().toISOString();
    const record = executionRecord || { findings: currentFindings, scanners: currentScanStatuses, dashboardOptions: currentDashboardOptions };
    const history = appendLocalHistory(context.workspaceState.get(LOCAL_SCAN_HISTORY_KEY, []), {
      localId: `local-${savedAt}-${crypto.randomBytes(4).toString('hex')}`,
      savedAt,
      workspace: vscode.workspace.name || path.basename(workspacePath),
      findings: record.findings,
      scanners: record.scanners,
      dashboardOptions: record.dashboardOptions
    });
    await context.workspaceState.update(LOCAL_SCAN_HISTORY_KEY, history);
  }
  async function notifyConfirmedFinding(finding) {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const tasks = [];
    if (cfg.get('notifications.slack.enabled', false)) {
      const webhook = await context.secrets.get('securityCenter.slackWebhook');
      if (webhook) tasks.push(sendSlack(webhook, finding, vscode.workspace.name || 'workspace').then(() => 'Slack'));
      else scanLog.appendLine('Notification Slack ignorée : webhook non configuré.');
    }
    if (cfg.get('notifications.jira.enabled', false)) {
      const token = await context.secrets.get('securityCenter.jiraToken');
      const baseUrl = cfg.get('notifications.jira.baseUrl', '');
      const email = cfg.get('notifications.jira.email', '');
      const projectKey = cfg.get('notifications.jira.projectKey', '');
      if (token && baseUrl && email && projectKey) tasks.push(createJiraIssue({ baseUrl, email, token, projectKey, issueType: cfg.get('notifications.jira.issueType', 'Task') }, finding).then((result) => `Jira${result.key ? ` ${result.key}` : ''}`));
      else scanLog.appendLine('Ticket Jira ignoré : configuration incomplète.');
    }
    const results = await Promise.allSettled(tasks);
    for (const result of results) {
      if (result.status === 'fulfilled') vscode.window.showInformationMessage(`Security Center : envoyé vers ${result.value}.`);
      else scanLog.appendLine(`Intégration équipe en échec : ${result.reason?.message || result.reason}`);
    }
  }
  const securityStatusBar = new SecurityStatusBar({ api: vscode });
  dashboardProvider.onModelChange = (model) => securityStatusBar.update(model);
  securityStatusBar.update(dashboardProvider.model);
  context.subscriptions.push(
    diagnostics,
    scanLog,
    securityStatusBar,
    vscode.window.registerTreeDataProvider('securityCenter.findings', provider),
    vscode.window.registerWebviewViewProvider('securityCenter.dashboard', dashboardProvider)
  );

  const liveDiagnostics = new LiveDiagnostics({
    api: vscode,
    collection: liveDiagnosticCollection,
    showLowConfidence: () => vscode.workspace.getConfiguration('securityCenter').get('live.verbose', false)
  });
  const liveHoverProvider = new LiveHoverProvider({ api: vscode, diagnostics: liveDiagnostics });
  const liveCodeActionProvider = new LiveCodeActionProvider({ api: vscode, diagnostics: liveDiagnostics });
  liveSecurityService = new LiveSecurityService({ workspace: vscode.workspace, window: vscode.window, analyzeDocument: analyzeLiveDocument, diagnostics: liveDiagnostics });
  const liveCompanionProvider = new LiveCompanionProvider({
    api: vscode, service: liveSecurityService, diagnostics: liveDiagnostics,
    executeCommand: (command, ...args) => vscode.commands.executeCommand(command, ...args),
    workspacePath, extensionUri: context.extensionUri, themeController,
    // The companion reads the pipeline instead of recomputing anything: scan
    // state, policy verdict and scanner health, all from what already ran.
    getPipelineContext: () => buildCompanionPipelineContext(),
    // This provider is the engine: it aggregates the service state, the
    // diagnostics of the file being edited, the pipeline context and the scanner
    // health into one visual model, and it owns the message priority and the
    // anti-spam gate. It has no view of its own — the large sidebar panel was
    // removed on purpose. The surfaces that render it are wired just below,
    // once they exist.
    onVisualModel: undefined
  });
  const liveStatusBar = new LiveStatusBar({ api: vscode, service: liveSecurityService, diagnostics: liveDiagnostics, workspacePath });
  const sentinelEditorPresence = new SentinelEditorPresence({ api: vscode, service: liveSecurityService, diagnostics: liveDiagnostics, extensionUri: context.extensionUri, workspace: vscode.workspace });
  const liveSecurityPageProvider = new LiveSecurityPageProvider({
    api: vscode,
    service: liveSecurityService,
    diagnostics: liveDiagnostics,
    workspacePath,
    extensionUri: context.extensionUri,
    executeCommand: (command, ...args) => vscode.commands.executeCommand(command, ...args),
    getOllamaModel: () => vscode.workspace.getConfiguration('securityCenter').get('ai.ollama.model', ''),
    getKnownFindings: () => currentFindings,
    themeController,
    // One engine, read on demand. The page never builds a companion state.
    getCompanionModel: () => liveCompanionProvider.visualModel()
  });
  dashboardProvider.getCompanionModel = () => liveCompanionProvider.visualModel();
  // Wired after both surfaces exist, so a state change arriving early can never
  // touch an uninitialised binding. Each surface re-reads the shared model; the
  // engine pushes no copy of it, which is why the two can never drift apart.
  liveCompanionProvider.onVisualModel = () => {
    liveSecurityPageProvider.render();
    dashboardProvider.render();
    // Any open Security Pipeline panel re-reads the same model, so two open
    // pages can never show different counts or a different posture.
    renderPipelinePage().catch(() => {});
  };
  context.subscriptions.push(themeController, dashboardProvider);
  context.subscriptions.push(liveSecurityService);
  context.subscriptions.push(liveDiagnostics);
  context.subscriptions.push(liveCompanionProvider);
  context.subscriptions.push(liveStatusBar);
  context.subscriptions.push(sentinelEditorPresence);
  context.subscriptions.push(liveSecurityPageProvider);
  context.subscriptions.push(vscode.languages.registerHoverProvider(
    LIVE_SELECTOR,
    liveHoverProvider
  ));
  context.subscriptions.push(vscode.languages.registerCodeActionsProvider(
    LIVE_SELECTOR,
    liveCodeActionProvider,
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  ));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.explainLiveFinding', async (uri, documentVersion, ruleId) => {
    const finding = liveDiagnostics.getFinding(uri, documentVersion, ruleId);
    if (!finding) return vscode.window.showInformationMessage('Security Center Live : cet avertissement n’est plus présent dans la version actuelle du fichier.');
    const recommendation = finding.recommendation ? `\n\nRecommandation : ${finding.recommendation}` : '';
    return vscode.window.showInformationMessage(
      `${finding.title}\n\n${finding.description}${recommendation}\n\n${finding.cwe || finding.ruleId}\nAnalyse locale — aucun appel à Ollama.`,
      { modal: true },
      'Ouvrir Security Center'
    ).then((action) => action === 'Ouvrir Security Center' && vscode.commands.executeCommand('securityCenter.openDashboard'));
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.applyLiveQuickFix', async (uri, documentVersion, ruleId) => {
    const finding = liveDiagnostics.getFinding(uri, documentVersion, ruleId);
    if (!finding) return vscode.window.showWarningMessage('Security Center Live : correction refusée, car le diagnostic est devenu obsolète.');
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uri));
    if (document.version !== documentVersion) return vscode.window.showWarningMessage('Security Center Live : le fichier a changé. Demandez une nouvelle correction.');
    const range = new vscode.Range(finding.range.start.line, finding.range.start.character, finding.range.end.line, finding.range.end.character);
    const currentText = document.getText(range);
    if (currentText !== finding.originalText) return vscode.window.showWarningMessage('Security Center Live : le texte ciblé a changé. Aucune modification appliquée.');
    const replacement = deterministicReplacement(finding, currentText);
    if (replacement === undefined) return vscode.window.showInformationMessage('Security Center Live : aucune correction déterministe sûre pour cet avertissement.');
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, range, replacement);
    if (!await vscode.workspace.applyEdit(edit)) return vscode.window.showErrorMessage('Security Center Live : VS Code a refusé la correction.');
    await liveSecurityService.analyzeNow(document);
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.generateLiveAiFix', async (uri, documentVersion, ruleId) => {
    const finding = liveDiagnostics.getFinding(uri, documentVersion, ruleId);
    if (!finding) return vscode.window.showWarningMessage('Security Center Live : AI Fix refusé, car le diagnostic est devenu obsolète.');
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uri));
    if (document.version !== documentVersion) return vscode.window.showWarningMessage('Security Center Live : le fichier a changé. Relancez AI Fix sur le diagnostic actuel.');
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!folder) return vscode.window.showErrorMessage('Security Center Live : fichier hors workspace refusé.');
    return vscode.commands.executeCommand('securityCenter.generateAiFix', toRemediationFinding(finding, folder.uri.fsPath, document.uri));
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openLiveFinding', async (uri, documentVersion, ruleId) => {
    const finding = liveDiagnostics.getFinding(uri, documentVersion, ruleId);
    if (!finding) return vscode.window.showInformationMessage('Security Center Live : cet avertissement n’est plus présent.');
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uri));
    const editor = await vscode.window.showTextDocument(document, { preview: false });
    const range = new vscode.Range(finding.range.start.line, finding.range.start.character, finding.range.end.line, finding.range.end.character);
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.ignoreLiveFindingForSession', (uri, documentVersion, ruleId) => {
    const finding = liveDiagnostics.getFinding(uri, documentVersion, ruleId);
    if (!finding) return vscode.window.showInformationMessage('Security Center Live : cet avertissement n’est plus présent.');
    liveDiagnostics.suppressForSession(finding);
    return vscode.window.showInformationMessage('Security Center Live : avertissement ignoré pour cette session.');
  }));
  // The command stays — the status bar and the Live quick fixes use it. It now
  // opens the Live Security page, because the sidebar view it used to focus no
  // longer exists and focusing a removed view id would silently do nothing.
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.focusLiveSecurity', async () => {
    await vscode.commands.executeCommand('workbench.view.extension.securityCenter');
    return liveSecurityPageProvider.open();
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openLiveSecurityPage', () => liveSecurityPageProvider.open()));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.enableLiveSecurity', async () => {
    await liveSecurityService.enable();
    liveSecurityPageProvider.open();
    vscode.window.showInformationMessage('Security Center : Live Security activé.');
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.disableLiveSecurity', async () => {
    await liveSecurityService.disable();
    vscode.window.showInformationMessage('Security Center : Live Security désactivé.');
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.toggleLiveSecurity', async () => {
    const state = await liveSecurityService.toggle();
    if (state !== 'disabled') liveSecurityPageProvider.open();
    vscode.window.showInformationMessage(`Security Center : Live Security ${state === 'disabled' ? 'désactivé' : 'activé'}.`);
  }));

  const restoredScan = restoreLocalScanCache(context.workspaceState.get(LOCAL_SCAN_CACHE_KEY), workspacePath);
  if (restoredScan) {
    currentSecuritySnapshot = normalizeSnapshot(restoredScan.securitySnapshot, {
      findings: restoredScan.findings, scanners: restoredScan.scanners,
      options: { ...restoredScan.dashboardOptions, savedAt: restoredScan.savedAt }
    });
    const restoredProjection = projectSnapshot(currentSecuritySnapshot);
    currentFindings = restoredProjection.findings;
    currentScanStatuses = restoredProjection.scanners;
    // A persisted campaign is revalidated before being trusted. A cache written
    // before campaign identity existed — or one whose campaign no longer parses —
    // is restored as an explicit legacy bucket: the transactions stay visible,
    // but they are never attributed to a run that cannot be proven.
    const restoredCampaign = restoreDynamicCampaign(restoredScan.dashboardOptions?.dynamicCampaign);
    const scenarioCount = (restoredScan.dashboardOptions?.httpScenarios || []).length;
    currentDashboardOptions = {
      ...restoredScan.dashboardOptions,
      dynamicCampaign: restoredCampaign || (scenarioCount ? dynamicLegacyBucket(scenarioCount) : null),
      backendStatus: 'offline',
      restoredFromCache: true,
      restoredAt: restoredScan.savedAt
    };
    publishDiagnostics(diagnostics, currentFindings);
    provider.setFindings(currentFindings, currentScanStatuses);
    dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
    const activeCount = currentFindings.filter(isActiveFinding).length;
    scanLog.appendLine(`[${new Date().toISOString()}] Dernier scan local restauré (${currentFindings.length} résultat(s), sauvegarde ${restoredScan.savedAt || 'sans date'}).`);
    // The intelligence summaries survive in workspaceState while the detail
    // records lived only in memory. Reuniting them here is what keeps the
    // Pipeline summary and its detail tabs describing the same scan.
    currentPipelineResult = restorePipelineResult(
      context.workspaceState.get(PIPELINE_STATE_KEY, {}),
      currentFindings
    );
    if (currentPipelineResult) {
      currentPipelineArtifacts = context.workspaceState.get(PIPELINE_STATE_KEY, {})?.artifacts || {};
      scanLog.appendLine(`[${new Date().toISOString()}] Security Intelligence restaurée — scan ${currentPipelineResult.scanId}, ${currentPipelineResult.clusters.length} corrélation(s), ${currentPipelineResult.findings.length} résultat(s) analysé(s).`);
    }
  }

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.clearFindings', async () => {
    diagnostics.clear(); provider.setFindings([]); dashboardProvider.setData([], [], { scanStatus: 'idle', backendStatus: 'unknown' });
    currentSecuritySnapshot = snapshotFromLegacy(); currentFindings = []; currentScanStatuses = []; currentDashboardOptions = {};
    await context.workspaceState.update(LOCAL_SCAN_CACHE_KEY, undefined);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.setFindingStatus', async (item) => {
    const finding = item?.finding;
    if (!finding) return;
    const choices = [
      { label: 'Nouvelle', value: 'new' },
      { label: 'Triée', value: 'triaged' },
      { label: 'Probable', value: 'probable' },
      { label: 'Confirmée', value: 'confirmed' },
      { label: 'Faux positif', value: 'false_positive' },
      { label: 'Risque accepté', value: 'accepted' },
      { label: 'Corrigée — en attente de revalidation', value: 'fixed' },
      { label: 'Validée — absence confirmée par un nouveau scan', value: 'validated' }
    ];
    const selected = await vscode.window.showQuickPick(choices, {
      title: `Statut — ${finding.title}`,
      placeHolder: 'Choisir le nouveau statut'
    });
    if (!selected) return;
    const requiresJustification = ['false_positive', 'accepted'].includes(selected.value);
    const comment = await vscode.window.showInputBox({
      title: `Justification — ${selected.label}`,
      prompt: requiresJustification ? 'Justification obligatoire pour l’audit.' : 'Commentaire optionnel sur ce changement de statut.',
      placeHolder: requiresJustification ? 'Expliquez précisément la décision…' : 'Ajouter une note (optionnel)',
      validateInput: (value) => requiresJustification && !value.trim() ? 'Une justification est obligatoire.' : undefined,
      ignoreFocusOut: true
    });
    if (comment === undefined) return;
    const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '')
      || process.env.USERNAME || process.env.USER || 'local-user';
    const savedStatuses = context.workspaceState.get('securityCenter.findingStatuses', {});
    savedStatuses[findingKey(finding)] = selected.value;
    await context.workspaceState.update('securityCenter.findingStatuses', savedStatuses);
    currentFindings = applyFindingStatuses(currentFindings, savedStatuses).map((item) => findingKey(item) === findingKey(finding)
      ? { ...item, triageActor: actor, triageComment: comment.trim(), triageUpdatedAt: new Date().toISOString() }
      : item);
    publishDiagnostics(diagnostics, currentFindings);
    provider.setFindings(currentFindings, currentScanStatuses);
    dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
    await saveLocalScanCache();
    if (currentScanId) {
      const backendBaseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      try {
        await updateFindingStatus(backendBaseUrl, currentScanId, finding.id, selected.value, actor, comment.trim());
        
        await createAuditEvent(backendBaseUrl, {
          scan_id: currentScanId || 0,
          finding_id: finding.id,
          action: 'finding.triage.changed',
          actor,
          comment: `Triage de l'alerte ${finding.id} modifié pour ${selected.value}.`,
          reason: comment.trim(),
          metadata: { tool: finding.tool, status: selected.value }
        }).catch(() => {});
        
        if (selected.value === 'accepted') {
          await createAuditEvent(backendBaseUrl, {
            scan_id: currentScanId || 0,
            finding_id: finding.id,
            action: 'finding.risk.accepted',
            actor,
            comment: `Risque accepté pour l'alerte ${finding.id} du scanner ${finding.tool}.`,
            reason: comment.trim(),
            metadata: { tool: finding.tool }
          }).catch(() => {});
        }

        currentDashboardOptions = { ...currentDashboardOptions, backendStatus: 'online' };
      } catch (error) {
        currentDashboardOptions = { ...currentDashboardOptions, backendStatus: 'offline' };
        scanLog.appendLine(`[${new Date().toISOString()}] Persistance du triage impossible : ${error.message}`);
      }
      dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
    }
    if (selected.value === 'confirmed') await notifyConfirmedFinding(finding);
    vscode.window.showInformationMessage(`Security Center : statut « ${selected.label} » enregistré.`);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureTeamIntegrations', async () => {
    const choice = await vscode.window.showQuickPick(['Slack', 'Jira'], { title: 'Configurer les intégrations d’équipe' });
    if (!choice) return;
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    if (choice === 'Slack') {
      const webhook = await vscode.window.showInputBox({ title: 'Webhook entrant Slack', password: true, prompt: 'URL HTTPS fournie par Slack. Elle sera stockée dans SecretStorage.' });
      if (!webhook) return;
      await context.secrets.store('securityCenter.slackWebhook', webhook.trim());
      await cfg.update('notifications.slack.enabled', true, vscode.ConfigurationTarget.Workspace);
      return vscode.window.showInformationMessage('Security Center : notifications Slack activées pour ce workspace.');
    }
    const baseUrl = await vscode.window.showInputBox({ title: 'URL Jira Cloud', prompt: 'Exemple : https://entreprise.atlassian.net' });
    if (!baseUrl) return;
    const email = await vscode.window.showInputBox({ title: 'Adresse du compte Jira' });
    if (!email) return;
    const projectKey = await vscode.window.showInputBox({ title: 'Clé du projet Jira', prompt: 'Exemple : SEC' });
    if (!projectKey) return;
    const token = await vscode.window.showInputBox({ title: 'Jeton API Jira', password: true, prompt: 'Stocké uniquement dans SecretStorage.' });
    if (!token) return;
    await context.secrets.store('securityCenter.jiraToken', token.trim());
    await cfg.update('notifications.jira.baseUrl', baseUrl.trim(), vscode.ConfigurationTarget.Workspace);
    await cfg.update('notifications.jira.email', email.trim(), vscode.ConfigurationTarget.Workspace);
    await cfg.update('notifications.jira.projectKey', projectKey.trim(), vscode.ConfigurationTarget.Workspace);
    await cfg.update('notifications.jira.enabled', true, vscode.ConfigurationTarget.Workspace);
    vscode.window.showInformationMessage('Security Center : création de tickets Jira activée pour ce workspace.');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showFindingDetails', (finding, navigationContext = {}) => {
    findingDetailsFinding = finding;
    if (!findingDetailsPanel) {
      findingDetailsPanel = vscode.window.createWebviewPanel(
        'securityCenter.findingDetails',
        'Security Center — Détails',
        vscode.ViewColumn.Active,
        { enableScripts: true, retainContextWhenHidden: true }
      );
      findingDetailsPanel.webview.onDidReceiveMessage(async (message) => {
        if (message?.type === 'openHttpRequest' && Number.isInteger(message.index)) return dashboardProvider.openFullHttpRequest(message.index);
        if (message?.type === 'backToHttpRequest' && Number.isInteger(message.index)) return dashboardProvider.openFullHttpRequest(message.index);
        if (message?.type !== 'generateAiFix' || !findingDetailsFinding) return;
        scanLog.appendLine(`[${new Date().toISOString()}] Bouton Ollama reçu — ${findingDetailsFinding.file || findingDetailsFinding.absolutePath || findingDetailsFinding.title}`);
        await findingDetailsPanel?.webview.postMessage({ type: 'aiFixStatus', status: 'received' });
        try {
          await vscode.commands.executeCommand('securityCenter.generateAiFix', findingDetailsFinding);
          await findingDetailsPanel?.webview.postMessage({ type: 'aiFixStatus', status: 'done' });
        } catch (error) {
          scanLog.appendLine(`Routage Ollama en échec : ${error.message}`);
          await findingDetailsPanel?.webview.postMessage({ type: 'aiFixStatus', status: 'error' });
          vscode.window.showErrorMessage(`Security Center : lancement Ollama impossible — ${error.message}`);
        }
      });
      findingDetailsPanel.onDidDispose(() => { findingDetailsPanel = undefined; });
    } else {
      findingDetailsPanel.reveal(vscode.ViewColumn.Active);
    }
    findingDetailsPanel.title = `Security Center — ${finding.tool}: ${finding.title}`;
    const nonce = crypto.randomBytes(16).toString('base64');
    const relatedTraffic = (currentDashboardOptions.httpScenarios || []).map((scenario, index) => ({ scenario, index })).filter(({ scenario }) => linkedFindingsForScenario(scenario, [finding]).length > 0).map(({ scenario, index }) => ({ index, method: scenario.request?.method || 'HTTP', path: (() => { try { return new URL(scenario.request?.url).pathname || '/'; } catch { return scenario.request?.url || '/'; } })(), status: scenario.response?.statusCode || scenario.response?.status || '—', source: scenario.source || 'capture' }));
    findingDetailsPanel.webview.html = renderFindingDetailsHtml(finding, nonce, { relatedTraffic, backTrafficIndex: Number.isInteger(navigationContext.trafficIndex) ? navigationContext.trafficIndex : null, theme: dashboardProvider.selectedTheme });
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openFindingCode', async (finding) => {
    if (!finding?.absolutePath || !fs.existsSync(finding.absolutePath)) {
      await vscode.commands.executeCommand('securityCenter.showFindingDetails', finding);
      return vscode.window.showInformationMessage(
        'Security Center : cette alerte ne possède pas encore de correspondance avec un fichier source local.'
      );
    }
    const startLine = Math.max(0, Number(finding.startLine) || 0);
    const startColumn = Math.max(0, Number(finding.startColumn) || 0);
    const endLine = Math.max(startLine, Number(finding.endLine) || startLine);
    const endColumn = Math.max(startColumn, Number(finding.endColumn) || startColumn + 1);
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.absolutePath));
    const editor = await vscode.window.showTextDocument(document, { preview: false });
    const selection = new vscode.Range(startLine, startColumn, endLine, endColumn);
    editor.selection = new vscode.Selection(selection.start, selection.end);
    editor.revealRange(selection, vscode.TextEditorRevealType.InCenter);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.applyFindingFix', async (item) => {
    const finding = item?.finding || item;
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!finding || !folder) return vscode.window.showWarningMessage('Security Center : aucune correction sélectionnée.');
    try {
      const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.absolutePath));
      const range = new vscode.Range(finding.startLine, finding.startColumn, finding.endLine, finding.endColumn);
      const plan = buildAutofixPlan(finding, folder.uri.fsPath, document.getText(range));
      const fullText = document.getText();
      const proposedText = fullText.slice(0, document.offsetAt(range.start)) + plan.replacement + fullText.slice(document.offsetAt(range.end));
      const preview = await vscode.workspace.openTextDocument({ content: proposedText, language: document.languageId });
      await vscode.commands.executeCommand('vscode.diff', document.uri, preview.uri, `Aperçu correction — ${finding.title}`);
      const confirmation = await vscode.window.showWarningMessage(
        'Appliquer exactement la correction native proposée par Semgrep, enregistrer le fichier puis relancer Semgrep ?',
        { modal: true },
        'Appliquer et vérifier'
      );
      if (confirmation !== 'Appliquer et vérifier') return;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(document.uri, range, plan.replacement);
      if (!await vscode.workspace.applyEdit(edit)) throw new Error('VS Code a refusé la modification.');
      await document.save();
      vscode.window.showInformationMessage('Security Center : correction appliquée. Relance de Semgrep…');
      await vscode.commands.executeCommand('securityCenter.scanWorkspace', ['Semgrep']);
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : correction impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureOllama', async () => {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const baseUrl = cfg.get('ai.ollama.baseUrl', 'http://127.0.0.1:11434');
    try {
      const provider = createAiProvider(PROVIDERS.OLLAMA, { baseUrl });
      const models = await provider.listModels();
      if (!models.length) return vscode.window.showWarningMessage('Ollama fonctionne, mais aucun modèle n’est installé. Installez un modèle de code avec Ollama puis relancez cette commande.');
      const ordered = [...models].sort((a, b) => Number(b.includes(':14b')) - Number(a.includes(':14b')));
      const selected = await configureModelRoles({
        configuration: cfg,
        models: ordered,
        showQuickPick: (...args) => vscode.window.showQuickPick(...args),
        update: (...args) => cfg.update(...args),
        configurationTarget: vscode.ConfigurationTarget.Workspace
      });
      if (!selected) return;
      const actor = cfg.get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
      const backendBaseUrl = cfg.get('backend.url', 'http://127.0.0.1:8765');
      await createAuditEvent(backendBaseUrl, {
        scan_id: currentScanId || 0,
        action: 'ai.configuration.changed',
        actor,
        comment: `Configuration Ollama mise à jour : Fast=${selected.models.fast}, Advanced=${selected.models.advanced}, fallback=${selected.fallbackToAdvanced}.`,
        metadata: { fastModel: selected.models.fast, advancedModel: selected.models.advanced, fallback: selected.fallbackToAdvanced }
      }).catch(() => {});
      vscode.window.showInformationMessage(`Security Center : Ollama local prêt — Fast ${selected.models.fast}, Advanced ${selected.models.advanced}, fallback ${selected.fallbackToAdvanced ? 'activé' : 'désactivé'}.`);
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : Ollama indisponible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.generateAiFix', async (item) => {
    let finding = item?.finding || item;
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder || (!finding?.absolutePath && !finding?.file)) return vscode.window.showWarningMessage('Security Center : cette alerte ne correspond pas à un fichier local corrigeable.');
    if (!finding.absolutePath) {
      const resolved = path.resolve(folder.uri.fsPath, finding.file);
      const relative = path.relative(folder.uri.fsPath, resolved);
      if (relative.startsWith('..') || path.isAbsolute(relative)) return vscode.window.showErrorMessage('Security Center : chemin du finding hors workspace refusé.');
      finding = { ...finding, absolutePath: resolved };
    }
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const roles = readModelRoleConfiguration(cfg);
    if (!roles.models.fast) return vscode.window.showWarningMessage('Configurez d’abord le modèle Fast avec “Security Center: Configurer Ollama”.');
    try {
      const actor = cfg.get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
      const backendBaseUrl = cfg.get('backend.url', 'http://127.0.0.1:8765');
      await createAuditEvent(backendBaseUrl, {
        scan_id: currentScanId || 0,
        finding_id: finding.id,
        action: 'ai.fix.requested',
        actor,
        comment: `Demande de correction IA démarrée pour l'alerte ${finding.id}.`,
        metadata: { tool: finding.tool, model: roles.models.fast }
      }).catch(() => {});

      const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.absolutePath));
      const originalText = document.getText();
      const aiContext = buildMinimalContext(finding, folder.uri.fsPath, originalText);
      const baseUrl = cfg.get('ai.ollama.baseUrl', 'http://127.0.0.1:11434');
      const aiProvider = createAiProvider(roles.provider, { baseUrl });
      const availableModels = await aiProvider.listModels();
      const fastModel = findInstalledModel(roles.models.fast, availableModels);
      if (!fastModel.installed) {
        const action = await vscode.window.showWarningMessage(`Security Center : modèle Fast « ${fastModel.model || 'non configuré'} » non installé.`, 'Configurer Ollama');
        if (action === 'Configurer Ollama') await vscode.commands.executeCommand('securityCenter.configureOllama');
        return;
      }
      const totalBudgetMs = Math.min(cfg.get('ai.timeoutSeconds', 90) * 1000, 60000);
      const startedAt = Date.now();
      const abortController = new AbortController();
      const metricId = crypto.randomUUID();
      const generateProposal = ({ model, context: requestContext }) => aiProvider.generateFix({ model, context: requestContext, timeoutMs: totalBudgetMs, signal: abortController.signal });
      const validateProposal = async (proposal) => {
        let safeProposal = proposal;
        if (finding.tool === 'Gitleaks' && safeProposal.oldText.includes('[REDACTED]')) {
          const originalLines = originalText.split(/\r?\n/);
          const redactedLines = redactSecrets(originalText).split(/\r?\n/);
          const proposalLine = safeProposal.oldText.trim();
          const findingLine = Math.max(0, Number(finding.startLine || 0));
          const matches = redactedLines.map((line, index) => ({ line, index })).filter(({ line, index }) => Math.abs(index - findingLine) <= 2 && (line.trim() === proposalLine || line.includes('[REDACTED]')));
          if (matches.length !== 1) throw new Error('La ligne secrète masquée ne peut pas être identifiée près du finding. Aucun fichier n’a été modifié.');
          if (safeProposal.newText.includes('[REDACTED]')) throw new Error('Ollama a conservé le secret masqué dans la correction. Aucun fichier n’a été modifié.');
          if (/placeholder|replace[_ -]?me|example|dummy|changeme/i.test(safeProposal.newText)) throw new Error('Ollama a proposé une fausse valeur de remplacement. Pour Gitleaks, le secret doit être révoqué ou renouvelé et son chargement doit être configuré explicitement. Aucun fichier n’a été modifié.');
          safeProposal = { ...safeProposal, oldText: originalLines[matches[0].index] };
        }
        return { generated: safeProposal, parsed: validatePatchForFinding(parseUnifiedDiff(replacementToPatch(originalText, finding.file, safeProposal.oldText, safeProposal.newText)), finding) };
      };
      const reportRemediationState = (aiProgress) => (state) => {
        if (state.phase === 'fallback') aiProgress.report({ message: 'Fast proposal did not pass Security Center validation. Trying advanced model…' });
        if (state.phase === 'generating') aiProgress.report({ message: state.role === 'advanced' ? 'Analyzing with advanced model…' : 'Generating secure fix…' });
        if (state.phase === 'rejected') scanLog.appendLine(`Ollama — rôle ${state.role}; modèle ${state.model}; validation ${state.state}.`);
        if (state.phase === 'validated') {
          aiProgress.report({ message: state.role === 'advanced' ? 'Advanced fix ready' : 'Secure fix ready' });
          scanLog.appendLine(`Ollama — rôle ${state.role}; modèle ${state.model}; validation ${state.state}.`);
        }
      };
      let routed = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Generating secure fix…', cancellable: true }, async (aiProgress, token) => {
        token.onCancellationRequested(() => abortController.abort());
        const timer = setInterval(() => {
          const elapsed = Date.now() - startedAt;
          aiProgress.report({ message: `${Math.round(elapsed / 1000)} s écoulées • ${Math.max(0, Math.ceil((totalBudgetMs - elapsed) / 1000))} s restantes` });
        }, 1000);
        try {
          return await runTwoModelRemediation({
            configuration: roles, installedModels: availableModels, context: aiContext,
            generate: generateProposal, validate: validateProposal, onState: reportRemediationState(aiProgress)
          });
        } finally { clearInterval(timer); }
      });
      if (!routed.ok && routed.fallbackEligible && !roles.fallbackToAdvanced) {
        const action = await vscode.window.showWarningMessage(
          'Fast proposal did not pass Security Center validation.',
          { modal: true, detail: fallbackReasonMessage(routed.fallbackReason) },
          'Try Advanced Model'
        );
        if (action === 'Try Advanced Model') {
          routed = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Analyzing with advanced model…', cancellable: false }, (aiProgress) => runAdvancedRemediation({
            configuration: roles, installedModels: availableModels, context: aiContext,
            generate: generateProposal, validate: validateProposal, onState: reportRemediationState(aiProgress)
          }));
        }
      }
      await saveLocalRemediationMetric(context.workspaceState, buildRemediationMetric(routed, { id: metricId }));
      if (!routed.ok) {
        if (isExhaustedRemediation(routed)) {
          const action = await vscode.window.showErrorMessage(FAILURE_MESSAGE, { modal: true, detail: FAILURE_DETAIL }, ...FAILURE_ACTIONS);
          if (action === 'Explain issue') {
            await vscode.window.showInformationMessage(`${finding.title}\n\n${finding.description || finding.message || 'Security finding requiring a validated correction.'}\n\n${finding.cwe || finding.ruleId || ''}`, { modal: true });
          }
          if (action === 'Open finding') await vscode.commands.executeCommand('securityCenter.showFindingDetails', finding);
          if (action === 'Retry') void vscode.commands.executeCommand('securityCenter.generateAiFix', finding);
          return;
        }
        if (routed.missingRole === 'advanced' && routed.fallbackEligible) throw new Error(`Le modèle Advanced « ${roles.models.advanced || 'non configuré'} » n’est pas installé. La proposition Fast n’a pas passé la validation.`);
        throw routed.error || new Error('Security Center n’a obtenu aucun patch valide.');
      }
      const generated = routed.generated;
      const parsed = routed.parsed;
      const effectiveModel = routed.model;
      const proposedText = applyParsedPatch(originalText, parsed);
      scanLog.appendLine(`Ollama — proposition ${routed.role} reçue en ${Math.round((Date.now() - startedAt) / 1000)} s ; fallback ${routed.fallbackUsed ? 'utilisé' : 'non utilisé'} ; validation locale du patch.`);
      const verifiedConfidence = calculateFixConfidence(generated, parsed);
      if (proposedText === originalText) throw new Error('Le patch ne modifie pas le fichier.');
      const preview = await vscode.workspace.openTextDocument({ content: proposedText, language: document.languageId });
      await vscode.commands.executeCommand('vscode.diff', document.uri, preview.uri, `Correction Ollama ${routed.role === 'fast' ? 'Fast' : 'Advanced'} — confiance vérifiée ${Math.round(verifiedConfidence * 100)}%`);
      const confirmation = await vscode.window.showWarningMessage(`Appliquer ce patch Ollama local puis lancer le scanner et le script test déclaré par le projet ? Confiance modèle ${Math.round(generated.confidence * 100)}%, confiance vérifiée Security Center ${Math.round(verifiedConfidence * 100)}%. ${generated.securityReason}`, { modal: true, detail: generated.assumptions.length ? `Hypothèses : ${generated.assumptions.join(' • ')}` : 'Aucune hypothèse déclarée.' }, 'Appliquer et valider');
      if (confirmation !== 'Appliquer et valider') return;
      const fullRange = new vscode.Range(document.positionAt(0), document.positionAt(originalText.length));
      const edit = new vscode.WorkspaceEdit(); edit.replace(document.uri, fullRange, proposedText);
      if (!await vscode.workspace.applyEdit(edit)) throw new Error('VS Code a refusé le patch.');
      await document.save();
      await createAuditEvent(backendBaseUrl, {
        scan_id: currentScanId || 0,
        finding_id: finding.id,
        action: 'ai.fix.applied',
        actor: 'System',
        comment: `Correction Ollama appliquée : modèle ${generated.model}.`,
        metadata: { tool: finding.tool, model: generated.model, confidence: generated.confidence, verifiedConfidence }
      }).catch(() => {});
      if (finding.liveSecurity) {
        lastAiRollback = { uri: document.uri, originalText, findingId: finding.id, findingKey: finding.id };
        scanLog.appendLine(`Correction Ollama Live appliquée — modèle ${generated.model}; règle ${finding.ruleId}; résumé ${generated.summary}`);
        const liveResults = await liveSecurityService.analyzeNow(document);
        const findingStillPresent = liveResults.some((candidate) => candidate.ruleId === finding.ruleId);
        const testResult = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center Live : validation des tests du projet', cancellable: false }, () => runDeclaredTests(folder.uri.fsPath));
        await saveLocalRemediationMetric(context.workspaceState, buildRemediationMetric(routed, { id: metricId, testResult: testResult.status, rescanResult: findingStillPresent ? 'finding_present' : 'finding_absent' }));
        if (findingStillPresent || testResult.status === 'failed') {
          const rollback = await vscode.window.showErrorMessage(`Correction Live non validée : ${findingStillPresent ? 'l’avertissement est toujours détecté' : 'les tests ont échoué'}.`, 'Rollback IA');
          if (rollback === 'Rollback IA') await vscode.commands.executeCommand('securityCenter.rollbackAiFix');
        } else {
          vscode.window.showInformationMessage(`Security Center Live : avertissement résolu ; tests ${testResult.status === 'passed' ? 'réussis' : 'non configurés'}.`);
        }
        return;
      }
      const aiFixedFinding = { ...finding, triageStatus: 'fixed', fixedAt: new Date().toISOString(), fixedBy: 'Ollama', aiModel: generated.model, aiSummary: generated.summary, aiVerifiedConfidence: verifiedConfidence };
      const savedAiStatuses = context.workspaceState.get('securityCenter.findingStatuses', {});
      savedAiStatuses[findingKey(finding)] = 'fixed';
      await context.workspaceState.update('securityCenter.findingStatuses', savedAiStatuses);
      currentFindings = currentFindings.map((candidate) => findingKey(candidate) === findingKey(finding) ? aiFixedFinding : candidate);
      publishDiagnostics(diagnostics, currentFindings);
      provider.setFindings(currentFindings, currentScanStatuses);
      dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
      await saveLocalScanCache();
      lastAiRollback = { uri: document.uri, originalText, findingId: finding.id, findingKey: findingKey(finding) };
      scanLog.appendLine(`Correction Ollama appliquée — modèle ${generated.model}; finding ${finding.id}; résumé ${generated.summary}`);
      await vscode.commands.executeCommand('securityCenter.scanWorkspace', [finding.tool]);
      const findingStillPresent = dashboardProvider.model.findings.some((candidate) => isActiveFinding(candidate) && findingKey(candidate) === findingKey(finding));
      const testResult = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center : validation des tests du projet', cancellable: false }, () => runDeclaredTests(folder.uri.fsPath));
      await saveLocalRemediationMetric(context.workspaceState, buildRemediationMetric(routed, { id: metricId, testResult: testResult.status, rescanResult: findingStillPresent ? 'finding_present' : 'finding_absent' }));
      if (findingStillPresent || testResult.status === 'failed') {
        scanLog.appendLine(`Validation Ollama échouée — finding présent: ${findingStillPresent}; tests: ${testResult.status}; ${testResult.output || testResult.reason || ''}`);
        const rollback = await vscode.window.showErrorMessage(`Correction non validée : ${findingStillPresent ? 'le finding est toujours détecté' : 'les tests ont échoué'}.`, 'Rollback IA');
        if (rollback === 'Rollback IA') await vscode.commands.executeCommand('securityCenter.rollbackAiFix');
      } else {
        vscode.window.showInformationMessage(`Security Center : correction validée. Finding disparu ; tests ${testResult.status === 'passed' ? 'réussis' : 'non configurés'}.`);
      }
    } catch (error) {
      const reason = String(error?.message || error);
      const classified = remediationResult({ error, model: roles.models.fast, role: 'fast' });
      scanLog.appendLine(`Ollama — résultat Fast ${classified.state}; ${classified.reason}`);
      scanLog.appendLine(`[${new Date().toISOString()}] Correction Ollama non appliquée — ${reason}`);
      if (/ne correspond pas au fichier|ne correspond plus au contenu actuel/i.test(reason)) {
        const action = await vscode.window.showWarningMessage(
          'Security Center : la correction Ollama n’a pas été appliquée, car le fichier a changé depuis le scan ou cette alerte provient d’un ancien résultat. Votre fichier reste inchangé. Relancez Semgrep pour actualiser l’alerte, puis demandez une nouvelle correction.',
          { modal: true, detail: `Diagnostic technique : ${reason}` }, 'Relancer Semgrep', 'Ouvrir le fichier');
        if (action === 'Relancer Semgrep') await vscode.commands.executeCommand('securityCenter.scanWorkspace', ['Semgrep']);
        if (action === 'Ouvrir le fichier') await vscode.commands.executeCommand('securityCenter.openFindingCode', finding);
        return;
      }
      if (/ambigu/i.test(reason)) {
        const action = await vscode.window.showWarningMessage(
          'Security Center : Ollama a proposé un fragment présent plusieurs fois dans le fichier. La correction a été bloquée pour éviter de modifier le mauvais endroit.',
          { modal: true, detail: `Diagnostic technique : ${reason}` }, 'Ouvrir le fichier', 'Relancer Semgrep');
        if (action === 'Ouvrir le fichier') await vscode.commands.executeCommand('securityCenter.openFindingCode', finding);
        if (action === 'Relancer Semgrep') await vscode.commands.executeCommand('securityCenter.scanWorkspace', ['Semgrep']);
        return;
      }
      if (finding.tool === 'Gitleaks' && /fausse valeur|secret masqué|ligne secrète/i.test(reason)) {
        const action = await vscode.window.showWarningMessage(
          'Security Center : Ollama a répondu, mais sa proposition Gitleaks n’est pas une correction sûre. Remplacer un secret par REDACTED/PLACEHOLDER ne révoque pas le secret déjà exposé et peut casser l’application.',
          { modal: true, detail: `Action requise : révoquez ou renouvelez d’abord la clé chez son fournisseur, puis configurez son chargement sécurisé selon le fonctionnement réel du projet. Le fichier est resté inchangé.\n\nDiagnostic : ${reason}` },
          'Ouvrir le fichier', 'Voir le journal');
        if (action === 'Ouvrir le fichier') await vscode.commands.executeCommand('securityCenter.openFindingCode', finding);
        if (action === 'Voir le journal') scanLog.show(true);
        return;
      }
      const action = await vscode.window.showErrorMessage(`Security Center : correction Ollama bloquée pour protéger le projet. Aucune modification n’a été appliquée. ${reason}`, 'Voir le journal');
      if (action === 'Voir le journal') scanLog.show(true);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.rollbackAiFix', async () => {
    if (!lastAiRollback) return vscode.window.showInformationMessage('Security Center : aucun patch IA à annuler dans cette session.');
    const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
    const backendBaseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
    await createAuditEvent(backendBaseUrl, {
      scan_id: currentScanId || 0,
      finding_id: lastAiRollback.findingId,
      action: 'ai.rollback',
      actor,
      comment: `Correction IA annulée pour l'alerte ${lastAiRollback.findingId}.`,
      metadata: { findingId: lastAiRollback.findingId }
    }).catch(() => {});

    const document = await vscode.workspace.openTextDocument(lastAiRollback.uri);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), lastAiRollback.originalText);
    if (!await vscode.workspace.applyEdit(edit)) return vscode.window.showErrorMessage('Security Center : rollback refusé par VS Code.');
    await document.save(); lastAiRollback = undefined;
    vscode.window.showInformationMessage('Security Center : dernier patch Ollama annulé.');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openDashboard', () => {
    dashboardProvider.openFullDashboard();
  }));
  let scannerSetupPanel;
  let scannerSetupConfirmation;
  let scannerInstallationRunning = false;
  const scannerSetupOperations = {};
  // ------------------------------------------------------ Security Pipeline
  let pipelinePanel;
  let pipelineTab = 'pipeline';
  let pipelineBusy = false;
  // The outcome of the last policy save, shown once and then cleared: it is a
  // message about an action, not part of the pipeline state.
  let policySaveResult = null;

  /** Cosign state for the Supply Chain section. Never exposes key material. */
  async function collectCosignState() {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const detected = await detectLocalCosign({ timeoutMs: 15000 }).catch(() => null);
    const managed = await scannerToolManager.status('cosign').catch(() => null);
    const privateKeyPath = cfg.get('cosign.privateKeyPath', '');
    const publicKeyPath = cfg.get('cosign.publicKeyPath', '');
    return {
      installed: Boolean(detected || managed?.installed),
      version: detected?.version || managed?.version || '',
      path: detected?.path || managed?.executable || '',
      keyConfigured: Boolean(privateKeyPath && publicKeyPath),
      publicKeyPath,
      // Only the presence of a password is ever reported, never its value.
      passwordConfigured: Boolean(await context.secrets.get(COSIGN_PASSWORD_SECRET_KEY)),
      dockerReason: cosignModes().dockerReason,
      keylessReason: keylessSupport().reason
    };
  }

  /**
   * Single source of truth for every Security Pipeline tab.
   *
   * The result is resolved once — from memory if the scan just ran, otherwise
   * rebuilt from what was persisted — and every tab of the page then reads that
   * same object. Nothing here recomputes, re-reads « the latest scan » per tab,
   * or mixes a persisted summary with in-memory details: that mismatch is what
   * made the Pipeline tab announce results the detail tabs could not show.
   */
  async function buildPipelineModel() {
    const persisted = context.workspaceState.get(PIPELINE_STATE_KEY, {}) || {};
    // Resolve once, here, and nowhere else.
    const result = currentPipelineResult || restorePipelineResult(persisted, currentFindings);
    const model = {
      tab: pipelineTab,
      busy: pipelineBusy,
      scanId: result?.scanId || persisted.scanId || '',
      finishedAt: result?.finishedAt || persisted.finishedAt || '',
      restored: Boolean(result?.restored),
      findings: result?.findings || [],
      clusters: result?.clusters || [],
      intelligence: result?.intelligence || persisted.intelligence || { status: 'completed' },
      correlation: result?.correlationSummary || persisted.correlation || null,
      reachability: result?.reachabilitySummary || persisted.reachability || null,
      priority: result?.prioritySummary || persisted.priority || null,
      policy: result?.policy || persisted.policy || null,
      artifacts: currentPipelineArtifacts,
      scanners: currentScanStatuses,
      cosign: await collectCosignState(),
      // Same shared companion model as the Live Security page and the dashboard,
      // rendered here in compact mode. Read, never derived.
      companion: liveCompanionProvider.visualModel(),
      companionEnabled: vscode.workspace.getConfiguration('securityCenter').get('live.companion.enabled', true) !== false
    };
    // The gate configuration is read from security-center.yml every time the
    // page renders: the form is a view of the file, never a cached copy of it.
    const folder = vscode.workspace.workspaceFolders?.[0];
    model.policyConfig = folder ? await readPolicyGateConfig(folder.uri.fsPath) : { exists: false, filePath: '', gate: {}, supplyChain: {}, error: '' };
    // An unreadable policy is its own verdict. It replaces the stored one so the
    // page cannot keep showing a green gate computed from a file that no longer
    // parses.
    if (model.policyConfig.error) model.policy = policyGateError(model.policyConfig.error, { filePath: model.policyConfig.filePath });
    model.policyEvaluation = {
      // The hash recorded when this scan was judged, compared with the file as
      // it stands now: that is what distinguishes « policy at scan time » from
      // « current policy » instead of silently recomputing history.
      policyHashAtScan: persisted.policyHash || '',
      currentPolicyHash: model.policyConfig.hash || '',
      policyChangedSinceScan: Boolean(persisted.policyHash && model.policyConfig.hash
        && persisted.policyHash !== model.policyConfig.hash),
      reevaluatedAt: persisted.policyReevaluatedAt || ''
    };
    model.policySaveResult = policySaveResult;
    // What each detail tab can honestly render, compared against what the
    // Pipeline summary announces for the very same scan.
    model.availability = {
      correlations: dataAvailability({
        summary: model.correlation, records: model.clusters,
        expected: model.correlation?.total, intelligence: model.intelligence
      }),
      reachability: dataAvailability({
        summary: model.reachability,
        records: model.findings.filter((finding) => finding.reachability),
        expected: model.reachability ? Object.values(model.reachability.counts || {}).reduce((total, value) => total + value, 0) : null,
        intelligence: model.intelligence
      }),
      priorities: dataAvailability({
        summary: model.priority,
        records: model.findings.filter((finding) => finding.priority),
        expected: model.priority ? Object.values(model.priority.distribution || {}).reduce((total, value) => total + value, 0) : null,
        intelligence: model.intelligence
      })
    };
    model.stages = describeStages({
      findings: model.findings,
      scanners: currentScanStatuses,
      correlation: model.correlation,
      reachability: model.reachability,
      priority: model.priority,
      policy: model.policy,
      artifacts: model.artifacts,
      intelligence: model.intelligence
    });
    return model;
  }

  async function renderPipelinePage() {
    if (!pipelinePanel) return;
    const model = await buildPipelineModel();
    if (!pipelinePanel) return;
    pipelinePanel.webview.html = renderPipelinePageHtml(model, crypto.randomBytes(16).toString('base64'), themeController.getTheme());
  }

  /** Audit trail for a policy edit. The rules travel, never the file's secrets. */
  async function auditPolicyChange(result, comment) {
    const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '')
      || process.env.USERNAME || process.env.USER || 'local-user';
    await createAuditEvent(vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765'), {
      scan_id: currentScanId || 0, action: 'policy.changed', actor, comment,
      metadata: { policyHash: result.hash || '', configured: Boolean(result.configured) }
    }).catch(() => {});
  }

  /**
   * Re-runs the policy engine against the scan that already completed.
   *
   * Deliberately does *not* touch the scanners: the findings, correlations,
   * reachability and priorities of the current scan are reused as they are, and
   * only the gate is recomputed. That is what makes « fix the policy, not the
   * code » a one-second operation instead of a full re-scan.
   *
   * If the policy cannot be read, the gate becomes ERROR — never PASS.
   */
  async function reevaluatePolicy() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const persisted = context.workspaceState.get(PIPELINE_STATE_KEY, {}) || {};
    const result = currentPipelineResult || restorePipelineResult(persisted, currentFindings);
    if (!result?.scanId) {
      return vscode.window.showWarningMessage('Security Center : aucun scan terminé à ré-évaluer. Lancez d’abord une analyse.');
    }
    let policy;
    try {
      policy = await loadProjectPolicy(folder.uri.fsPath);
    } catch (error) {
      // An invalid policy is reported as such and persisted as such, so no
      // surface can keep showing the previous verdict as if it still held.
      const gate = policyGateError(error.message, { filePath: policyFilePath(folder.uri.fsPath).filePath });
      currentPipelineResult = { ...result, policy: gate };
      await context.workspaceState.update(PIPELINE_STATE_KEY, { ...persisted, policy: gate, policyReevaluatedAt: gate.evaluatedAt });
      vscode.window.showErrorMessage(`Security Center : politique projet invalide — ${error.message}`);
      return renderPipelinePage();
    }
    // The same engine, the same findings, the same artefacts as this scan.
    const gate = evaluatePolicyGate(result.findings || [], policy, {
      artifacts: Object.keys(currentPipelineArtifacts || {}).length ? currentPipelineArtifacts : null
    });
    const reevaluatedAt = new Date().toISOString();
    currentPipelineResult = { ...result, policy: gate };
    await context.workspaceState.update(PIPELINE_STATE_KEY, {
      ...persisted, policy: gate, policyHash: policyGateHash(policy), policyReevaluatedAt: reevaluatedAt
    });
    await createAuditEvent(vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765'), {
      scan_id: currentScanId || 0,
      action: gate.status === GATE_STATUS.BLOCK ? 'policy.gate.blocked' : 'policy.gate.evaluated',
      actor: 'System',
      comment: `Ré-évaluation manuelle de la politique, sans relancer les scanners : ${gate.summary}`,
      metadata: {
        status: gate.status, scanId: result.scanId, reevaluated: true,
        violations: gate.violations.length, warnings: gate.warnings.length,
        policyHash: policyGateHash(policy)
      }
    }).catch(() => {});
    liveCompanionProvider.render();
    vscode.window.showInformationMessage(`Security Center : Policy Gate ${gate.status} — ${gate.summary}`);
    return renderPipelinePage();
  }

  /** Audit helper shared by every supply-chain action. */
  async function auditSupplyChain(action, comment, metadata = {}) {
    await createAuditEvent(vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765'), {
      scan_id: currentScanId || 0, action, actor: 'System', comment, metadata
    }).catch(() => {});
  }
  /**
   * Real SonarQube diagnosis for the setup page. Never returns the token
   * itself, only whether one is stored.
   */
  async function collectSonarDiagnostic() {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const hostUrl = cfg.get('sonar.hostUrl', 'http://127.0.0.1:9000');
    const diagnostic = {
      enabled: cfg.get('sonar.enabled', false),
      mode: cfg.get('sonar.mode', 'auto'),
      hostUrl,
      tokenConfigured: Boolean(await context.secrets.get(SONAR_TOKEN_SECRET_KEY)),
      busy: sonarServerBusy,
      scannerVersion: '',
      dockerAvailable: false,
      serverOnline: null,
      serverVersion: '',
      serverMessage: ''
    };
    const [scanner, docker] = await Promise.all([
      detectLocalSonarScanner({ timeoutMs: 20000 }).catch(() => null),
      ensureDockerAvailable(8000).then(() => true).catch(() => false)
    ]);
    diagnostic.scannerVersion = scanner?.version || '';
    diagnostic.scannerPath = scanner?.path || '';
    diagnostic.dockerAvailable = docker;

    // A managed container that already exists classifies the server as local
    // even before the user made an explicit choice.
    const containerStatus = docker ? await inspectLocalServer({}) : null;
    const configuredType = cfg.get('sonar.serverType', '');
    // A configured URL pointing at the managed container is the local server,
    // whatever the stored type says. Nothing is deleted or recreated.
    const pointsAtManagedServer = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\]):9000\/?$/i.test(String(hostUrl).trim());
    diagnostic.serverType = containerStatus && pointsAtManagedServer
      ? 'local'
      : configuredType || (containerStatus ? 'local' : '');
    let health = null;
    try {
      health = await checkSonarServer(hostUrl, { timeoutMs: 8000 });
      diagnostic.serverOnline = true;
      diagnostic.serverVersion = health.version;
    } catch (error) {
      diagnostic.serverOnline = false;
      diagnostic.serverMessage = summarizeScannerError(error.message);
    }
    if (diagnostic.serverType === 'local') {
      diagnostic.localServerState = localServerState({ dockerAvailable: docker, containerStatus, health });
    }
    // The token is only probed when a server actually answers.
    if (diagnostic.tokenConfigured && diagnostic.serverOnline) {
      diagnostic.authenticationValid = await validateSonarToken(hostUrl, await context.secrets.get(SONAR_TOKEN_SECRET_KEY) || '', { timeoutMs: 8000 }).catch(() => null);
    }
    // The versioned policy has the final say on what the pipeline runs.
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (folder) {
      const policy = await loadProjectPolicy(folder.uri.fsPath).catch(() => null);
      diagnostic.blockedByProjectPolicy = policy?.scanners?.SonarQube === false;
    }
    diagnostic.effectiveEnabled = diagnostic.enabled && !diagnostic.blockedByProjectPolicy;
    return diagnostic;
  }
  /**
   * Real Snyk diagnosis for the setup page. Scanner, authentication and
   * capabilities are established separately so a Snyk Code entitlement the
   * account does not have never marks the whole scanner as broken.
   */
  async function collectSnykDiagnostic() {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const token = await context.secrets.get(SNYK_TOKEN_SECRET_KEY) || '';
    const diagnostic = {
      enabled: cfg.get('snyk.enabled', false),
      mode: cfg.get('snyk.mode', 'auto'),
      includeOpenSource: cfg.get('snyk.includeOpenSource', true),
      includeCode: cfg.get('snyk.includeCode', false),
      includeIaC: cfg.get('snyk.includeIaC', false),
      tokenConfigured: Boolean(token),
      cliVersion: '',
      cliPath: '',
      dockerAvailable: false,
      authenticationValid: null,
      // Open Source is available as soon as the token is accepted; Code and IaC
      // are only decided by a real run, so they stay « non vérifié » until then.
      capabilities: context.workspaceState.get('securityCenter.snykCapabilities', { openSource: null, code: null, iac: null })
    };
    const [cli, docker] = await Promise.all([
      detectLocalSnykCli({ timeoutMs: 20000 }).catch(() => null),
      ensureDockerAvailable(8000).then(() => true).catch(() => false)
    ]);
    diagnostic.cliVersion = cli?.version || '';
    diagnostic.cliPath = cli?.path || '';
    diagnostic.dockerAvailable = docker;
    if (token) {
      diagnostic.authenticationValid = await validateSnykToken(token, { timeoutMs: 8000 }).catch(() => null);
      if (diagnostic.authenticationValid === true) diagnostic.capabilities = { ...diagnostic.capabilities, openSource: true };
      if (diagnostic.authenticationValid === false) diagnostic.capabilities = { openSource: false, code: false, iac: false };
    }
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (folder) {
      const policy = await loadProjectPolicy(folder.uri.fsPath).catch(() => null);
      diagnostic.blockedByProjectPolicy = policy?.scanners?.Snyk === false;
    }
    diagnostic.effectiveEnabled = diagnostic.enabled && !diagnostic.blockedByProjectPolicy;
    // Feed the companion from this existing health probe rather than adding a
    // polling loop of its own. A disabled SonarQube never raises a warning.
    companionSonarUnreachable = diagnostic.enabled && diagnostic.serverOnline === false;
    liveCompanionProvider?.render();
    return diagnostic;
  }
  /**
   * Enriches each managed scanner status with the mode actually resolved by its
   * own runner, so the page can never disagree with the analysis pipeline.
   */
  async function withScannerDiagnostics(statuses) {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd();
    return Promise.all(statuses.map(async (status) => {
      const runtime = SCANNER_RUNTIMES[status.id];
      if (!runtime) return status;
      try {
        const diagnostic = await diagnoseScanner(status.id, {
          configuredMode: cfg.get(runtime.settingKey, 'auto'),
          enabled: runtime.enabledKey ? cfg.get(runtime.enabledKey, true) : true,
          workspacePath,
          status
        });
        return { ...status, diagnostic };
      } catch { return status; }
    }));
  }
  async function renderScannerSetup() {
    if (!scannerSetupPanel) return;
    const [rawStatuses, sonar, snyk] = await Promise.all([
      scannerToolManager.statuses(), collectSonarDiagnostic(), collectSnykDiagnostic()
    ]);
    // SonarScanner is presented inside the SonarQube card, not as a fifth
    // managed scanner, so its status and install progress are routed there.
    // The Snyk CLI is routed into the Snyk card for the same reason.
    const sonarScannerStatus = rawStatuses.find((item) => item.id === 'sonarscanner');
    sonar.managedScannerInstalled = Boolean(sonarScannerStatus?.installed);
    sonar.installing = scannerSetupOperations.sonarscanner;
    const snykStatus = rawStatuses.find((item) => item.id === 'snyk');
    snyk.managedCliInstalled = Boolean(snykStatus?.managed && snykStatus?.installed);
    // The installed CLI is authoritative over the PATH probe: a managed binary
    // outside the PATH must still be reported as available.
    if (!snyk.cliVersion && snykStatus?.installed) {
      snyk.cliVersion = snykStatus.version;
      snyk.cliPath = snykStatus.executable;
    }
    snyk.installing = scannerSetupOperations.snyk;
    const statuses = await withScannerDiagnostics(rawStatuses.filter((item) => !['sonarscanner', 'snyk'].includes(item.id)));
    if (!scannerSetupPanel) return;
    scannerSetupPanel.webview.html = renderScannerSetupHtml(statuses, crypto.randomBytes(16).toString('base64'), themeController.getTheme(), scannerSetupOperations, scannerSetupConfirmation, sonar, snyk);
  }
  async function installManagedScanners(ids) {
    const tools = ids.filter((id) => MANAGED_SCANNER_TOOLS[id]);
    if (!tools.length || scannerInstallationRunning) return;
    scannerInstallationRunning = true;
    scannerSetupConfirmation = undefined;
    try {
      for (const id of tools) {
        const label = MANAGED_SCANNER_TOOLS[id].label;
        scannerSetupOperations[id] = { state: 'installing', title: `Installation de ${label}`, message: 'Préparation…' };
        await renderScannerSetup();
        try {
          await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Security Center : installation de ${label}`, cancellable: false }, async (progress) => {
            let previousPercent = 0;
            await scannerToolManager.install(id, (event) => {
              const percent = event.total ? Math.min(100, Math.round(event.received / event.total * 100)) : undefined;
              scannerSetupOperations[id] = { state: 'installing', title: `Installation de ${label}`, message: event.message || (event.phase === 'download' ? `Téléchargement ${percent ?? ''}%` : event.phase), percent };
              if (Number.isFinite(percent)) { progress.report({ increment: Math.max(0, percent - previousPercent), message: `${percent}%` }); previousPercent = percent; }
              renderScannerSetup().catch(() => {});
            });
          });
          scannerSetupOperations[id] = { state: 'ready', title: `${label} est prêt`, message: 'Installation vérifiée. Le prochain scan utilisera automatiquement cette version locale.' };
          // Snyk names its execution mode `snyk.mode`, not `snyk.command`.
          await vscode.workspace.getConfiguration('securityCenter').update(id === 'snyk' ? 'snyk.mode' : `${id}.command`, 'auto', vscode.ConfigurationTarget.Global).catch(() => {});
        } catch (error) {
          scannerSetupOperations[id] = { state: 'failed', title: `${label} n’a pas été installé`, message: error.message };
          scanLog.appendLine(`Installation ${label} — ÉCHEC : ${error.stack || error.message}`);
        }
        await renderScannerSetup();
      }
    } finally {
      scannerInstallationRunning = false;
      await renderScannerSetup();
    }
  }
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openScannerSetup', async () => {
    if (!scannerSetupPanel) {
      scannerSetupPanel = vscode.window.createWebviewPanel('securityCenter.scannerSetup', 'Security Center — Configuration des scanners', vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true });
      scannerSetupPanel.webview.onDidReceiveMessage(async (message) => {
        if (message?.type === 'refresh') await renderScannerSetup();
        if (message?.type === 'requestInstall' && MANAGED_SCANNER_TOOLS[message.tool] && !scannerInstallationRunning) {
          scannerSetupConfirmation = { ids: [message.tool], labels: [MANAGED_SCANNER_TOOLS[message.tool].label], destination: scannerToolManager.root };
          await renderScannerSetup();
        }
        if (message?.type === 'requestInstallAll' && !scannerInstallationRunning) {
          const cfg = vscode.workspace.getConfiguration('securityCenter');
          const missing = (await scannerToolManager.statuses())
            .filter((item) => {
              if (item.installed) return false;
              // SonarScanner is only "missing" when SonarQube is enabled and
              // explicitly pinned to Local. Auto keeps Docker as a valid
              // fallback, and Docker never needs the local CLI.
              if (item.id === 'sonarscanner') {
                return cfg.get('sonar.enabled', false) && cfg.get('sonar.mode', 'auto') === 'local';
              }
              // Same contract for Snyk: disabled installs nothing, Docker needs
              // no local binary, and Auto keeps Docker as a valid fallback.
              if (item.id === 'snyk') {
                return cfg.get('snyk.enabled', false) && cfg.get('snyk.mode', 'auto') === 'local';
              }
              // A scanner pinned to Docker does not need a local binary.
              return cfg.get(SCANNER_RUNTIMES[item.id]?.settingKey || '', 'auto') !== 'docker';
            })
            .map((item) => item.id);
          if (missing.length) {
            scannerSetupConfirmation = { ids: missing, labels: missing.map((id) => MANAGED_SCANNER_TOOLS[id].label), destination: scannerToolManager.root };
            await renderScannerSetup();
          } else vscode.window.showInformationMessage('Security Center : tous les scanners gérés sont déjà disponibles.');
        }
        if (message?.type === 'cancelInstall') { scannerSetupConfirmation = undefined; await renderScannerSetup(); }
        if (message?.type === 'approveInstall' && scannerSetupConfirmation && !scannerInstallationRunning) {
          const approvedTools = [...scannerSetupConfirmation.ids];
          scannerSetupConfirmation = undefined;
          await installManagedScanners(approvedTools);
        }
        if (message?.type === 'setAuto' && MANAGED_SCANNER_TOOLS[message.tool]) {
          await vscode.workspace.getConfiguration('securityCenter').update(`${message.tool}.command`, 'auto', vscode.ConfigurationTarget.Global).catch(() => {});
          vscode.window.showInformationMessage(`${MANAGED_SCANNER_TOOLS[message.tool].label} utilisera le mode local automatique.`);
          await renderScannerSetup();
        }
        // Writes the historical `<tool>.command` setting the runners already
        // read, then re-runs the diagnostic so the card shows the mode that
        // was actually selected.
        if (message?.type === 'setScannerMode' && SCANNER_RUNTIMES[message.tool] && ['auto', 'local', 'docker'].includes(message.mode)) {
          const runtime = SCANNER_RUNTIMES[message.tool];
          const label = MANAGED_SCANNER_TOOLS[message.tool]?.label || message.tool;
          await vscode.workspace.getConfiguration('securityCenter').update(runtime.settingKey, message.mode, vscode.ConfigurationTarget.Global).catch(() => {});
          await renderScannerSetup();
          const diagnostic = await diagnoseScanner(message.tool, {
            configuredMode: message.mode,
            workspacePath: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd()
          }).catch(() => null);
          if (diagnostic?.resolvedMode) vscode.window.showInformationMessage(`${label} : mode ${normalizeMode(message.mode) === 'auto' ? 'Auto' : diagnostic.configuredModeLabel} enregistré — exécution ${diagnostic.resolvedModeLabel}.`);
          else vscode.window.showWarningMessage(`${label} : mode enregistré, mais ${diagnostic?.hint || 'aucun moteur d’exécution disponible'}.`);
        }
        // SonarQube is never installed by the managed downloader: only its
        // execution mode and its token can be changed from this page.
        if (message?.type === 'setSonarMode' && ['auto', 'local', 'docker'].includes(message.mode)) {
          await vscode.workspace.getConfiguration('securityCenter').update('sonar.mode', message.mode, vscode.ConfigurationTarget.Global).catch(() => {});
          vscode.window.showInformationMessage(`SonarQube utilisera le mode ${message.mode}.`);
          await renderScannerSetup();
        }
        if (message?.type === 'configureSonarToken') {
          await vscode.commands.executeCommand('securityCenter.configureSonarToken');
          await renderScannerSetup();
        }
        // Snyk exposes the same control surface as SonarQube: mode, token and
        // activation, all written to the settings the pipeline itself reads.
        if (message?.type === 'setSnykMode' && ['auto', 'local', 'docker'].includes(message.mode)) {
          await vscode.workspace.getConfiguration('securityCenter').update('snyk.mode', message.mode, vscode.ConfigurationTarget.Global).catch(() => {});
          await renderScannerSetup();
          const diagnosis = snykDiagnosis(await collectSnykDiagnostic());
          vscode.window.showInformationMessage(diagnosis.state === 'ready'
            ? `Snyk utilisera le mode ${message.mode} — ${diagnosis.label}.`
            : `Snyk : mode ${message.mode} enregistré, mais ${diagnosis.label} : ${diagnosis.hint}`);
        }
        if (message?.type === 'configureSnykToken') {
          await vscode.commands.executeCommand('securityCenter.configureSnykToken');
          await renderScannerSetup();
        }
        if (message?.type === 'setSnykEnabled' && typeof message.enabled === 'boolean') {
          await vscode.workspace.getConfiguration('securityCenter').update('snyk.enabled', message.enabled, vscode.ConfigurationTarget.Global).catch(() => {});
          // Enabled stays enabled: an incomplete configuration is reported, it
          // never switches Snyk back off behind the user's back.
          await renderScannerSetup();
          dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
          if (!message.enabled) return vscode.window.showInformationMessage('Snyk ne sera plus exécuté lors des prochaines analyses.');
          const diagnosis = snykDiagnosis(await collectSnykDiagnostic());
          vscode.window.showInformationMessage(diagnosis.state === 'ready'
            ? `Snyk activé — ${diagnosis.label}.`
            : `Snyk activé, mais ${diagnosis.label} : ${diagnosis.hint}`);
        }
        // Enabling and disabling write the very settings the analysis pipeline
        // reads, so the page and the orchestrator can never disagree.
        if (message?.type === 'setScannerEnabled' && SCANNER_RUNTIMES[message.tool]?.enabledKey && typeof message.enabled === 'boolean') {
          const runtime = SCANNER_RUNTIMES[message.tool];
          const label = MANAGED_SCANNER_TOOLS[message.tool]?.label || message.tool;
          await vscode.workspace.getConfiguration('securityCenter').update(runtime.enabledKey, message.enabled, vscode.ConfigurationTarget.Global).catch(() => {});
          await renderScannerSetup();
          dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
          vscode.window.showInformationMessage(`${label} ${message.enabled ? 'sera inclus' : 'ne sera plus inclus'} dans les prochaines analyses.`);
        }
        // Choosing a server type never starts anything by itself.
        if (message?.type === 'chooseSonarServer' && ['local', 'existing'].includes(message.serverType)) {
          const configuration = vscode.workspace.getConfiguration('securityCenter');
          if (message.serverType === 'local') {
            await configuration.update('sonar.serverType', 'local', vscode.ConfigurationTarget.Global).catch(() => {});
            await configuration.update('sonar.hostUrl', SONAR_LOCAL_SERVER_URL, vscode.ConfigurationTarget.Global).catch(() => {});
          } else {
            const entered = await vscode.window.showInputBox({
              title: 'Adresse du serveur SonarQube existant',
              prompt: 'Exemple : https://sonarqube.company.com. Security Center n’utilise qu’une URL et un jeton, jamais de compte administrateur.',
              value: cfgHostUrlOrEmpty(),
              ignoreFocusOut: true,
              validateInput: (value) => { try { normalizeSonarHostUrl(value); return undefined; } catch (error) { return error.message; } }
            });
            if (entered === undefined) return;
            await configuration.update('sonar.hostUrl', normalizeSonarHostUrl(entered), vscode.ConfigurationTarget.Global).catch(() => {});
            await configuration.update('sonar.serverType', 'existing', vscode.ConfigurationTarget.Global).catch(() => {});
          }
          // Switching server never deletes the local server data.
          await renderScannerSetup();
        }
        if (message?.type === 'configureSonarHostUrl') {
          const entered = await vscode.window.showInputBox({
            title: 'Adresse du serveur SonarQube',
            value: cfgHostUrlOrEmpty(),
            ignoreFocusOut: true,
            validateInput: (value) => { try { normalizeSonarHostUrl(value); return undefined; } catch (error) { return error.message; } }
          });
          if (entered === undefined) return;
          await vscode.workspace.getConfiguration('securityCenter').update('sonar.hostUrl', normalizeSonarHostUrl(entered), vscode.ConfigurationTarget.Global).catch(() => {});
          await renderScannerSetup();
        }
        if (message?.type === 'openSonarServer') {
          const target = cfgHostUrlOrEmpty();
          if (target) await vscode.env.openExternal(vscode.Uri.parse(target));
        }
        if (message?.type === 'startSonarServer' && !sonarServerBusy) {
          const status = await inspectLocalServer({});
          const confirmed = await vscode.window.showWarningMessage(
            status ? 'Démarrer le serveur SonarQube local ?' : 'Créer et démarrer le serveur SonarQube local ?',
            {
              modal: true,
              detail: `Conteneur : security-center-sonarqube (image sonarqube:community)\nPort : 127.0.0.1:9000 uniquement\nVolumes persistants : données, journaux, extensions\nAucun privilège Docker supplémentaire, aucun socket Docker monté.\n\nSonarQube consomme environ 2 Go de mémoire.`
            },
            'Démarrer'
          );
          if (confirmed !== 'Démarrer') return;
          sonarServerBusy = true;
          await renderScannerSetup();
          try {
            await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center : serveur SonarQube local', cancellable: true }, async (progress, token) => {
              const controller = new AbortController();
              token.onCancellationRequested(() => controller.abort());
              progress.report({ message: status ? 'Démarrage du conteneur…' : 'Création du conteneur…' });
              await startLocalServer({});
              progress.report({ message: 'Attente de la disponibilité du serveur…' });
              const outcome = await waitForLocalServer({
                checkStatus: () => checkSonarServer(SONAR_LOCAL_SERVER_URL, { timeoutMs: 5000 }),
                signal: controller.signal,
                onProgress: (state) => progress.report({ message: state === 'initializing' ? 'Initialisation de SonarQube…' : 'Démarrage…' })
              });
              if (outcome.state !== 'ready') {
                throw new Error(outcome.reason === 'cancelled'
                  ? 'Attente annulée : le serveur continue de démarrer en arrière-plan.'
                  : 'Le serveur SonarQube n’a pas répondu dans le délai imparti. Réessayez « Revérifier » dans quelques instants.');
              }
            });
            const action = await vscode.window.showInformationMessage(
              'Serveur SonarQube local prêt sur http://127.0.0.1:9000. Terminez la configuration initiale dans SonarQube, créez un jeton, puis revenez ici.',
              'Ouvrir SonarQube', 'Configurer le token'
            );
            if (action === 'Ouvrir SonarQube') await vscode.env.openExternal(vscode.Uri.parse(SONAR_LOCAL_SERVER_URL));
            if (action === 'Configurer le token') await vscode.commands.executeCommand('securityCenter.configureSonarToken');
          } catch (error) {
            vscode.window.showWarningMessage(`Security Center : ${summarizeScannerError(error.message)}`);
          } finally {
            sonarServerBusy = false;
            await renderScannerSetup();
          }
        }
        // Stop only. Volumes are never removed here.
        if (message?.type === 'stopSonarServer' && !sonarServerBusy) {
          const confirmed = await vscode.window.showWarningMessage(
            'Arrêter le serveur SonarQube local ?',
            { modal: true, detail: 'Le conteneur est arrêté, pas supprimé. Les données, journaux et extensions sont conservés et seront retrouvés au prochain démarrage.' },
            'Arrêter'
          );
          if (confirmed !== 'Arrêter') return;
          sonarServerBusy = true;
          await renderScannerSetup();
          try {
            const result = await stopLocalServer({});
            vscode.window.showInformationMessage(result.action === 'stopped'
              ? 'Serveur SonarQube local arrêté. Les données sont conservées.'
              : 'Le serveur SonarQube local n’était pas démarré.');
          } catch (error) {
            vscode.window.showWarningMessage(`Security Center : ${summarizeScannerError(error.message)}`);
          } finally {
            sonarServerBusy = false;
            await renderScannerSetup();
          }
        }
        if (message?.type === 'setSonarEnabled' && typeof message.enabled === 'boolean') {
          await vscode.workspace.getConfiguration('securityCenter').update('sonar.enabled', message.enabled, vscode.ConfigurationTarget.Global).catch(() => {});
          // Re-render first so the new state is visible immediately, then let
          // the diagnostic report what is still missing without ever
          // switching SonarQube back off.
          await renderScannerSetup();
          dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
          if (!message.enabled) return vscode.window.showInformationMessage('SonarQube ne sera plus exécuté lors des prochaines analyses.');
          const diagnosis = sonarDiagnosis(await collectSonarDiagnostic());
          vscode.window.showInformationMessage(diagnosis.state === 'ready'
            ? `SonarQube activé — ${diagnosis.label}.`
            : `SonarQube activé, mais ${diagnosis.label} : ${diagnosis.hint}`);
        }
      });
      scannerSetupPanel.onDidDispose(() => { scannerSetupPanel = undefined; scannerSetupConfirmation = undefined; });
    } else scannerSetupPanel.reveal(vscode.ViewColumn.Active);
    await renderScannerSetup();
  }));
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openSecurityPipeline', async (tab) => {
    if (typeof tab === 'string') pipelineTab = tab;
    if (!pipelinePanel) {
      pipelinePanel = vscode.window.createWebviewPanel('securityCenter.pipeline', 'Security Center — Security Pipeline', vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true });
      pipelinePanel.onDidDispose(() => { pipelinePanel = undefined; });
      pipelinePanel.webview.onDidReceiveMessage(async (message) => {
        if (message?.type === 'tab') { pipelineTab = message.tab; return renderPipelinePage(); }
        if (message?.type === 'command') {
          const allowed = new Set(['securityCenter.scanWorkspace', 'securityCenter.openDashboard', 'securityCenter.openProjectPolicy']);
          if (allowed.has(message.command)) await vscode.commands.executeCommand(message.command);
          return;
        }
        if (message?.type === 'stage') {
          // A stage opens the surface that owns it rather than a fake detail view.
          const destinations = {
            correlation: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'correlations'),
            reachability: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'reachability'),
            priority: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'priorities'),
            policy: () => vscode.commands.executeCommand('securityCenter.openProjectPolicy'),
            sbom: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'supply-chain'),
            provenance: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'supply-chain'),
            signing: () => vscode.commands.executeCommand('securityCenter.openSecurityPipeline', 'supply-chain')
          };
          if (destinations[message.stage]) return destinations[message.stage]();
          return vscode.commands.executeCommand('securityCenter.openScansPage');
        }
        if (message?.type === 'finding' && Number.isInteger(message.index)) {
          const ranked = [...(currentPipelineResult?.findings || [])]
            .filter((finding) => finding.priority)
            .sort((left, right) => right.priority.score - left.priority.score);
          const finding = ranked[message.index];
          if (finding) await vscode.commands.executeCommand('securityCenter.showFindingDetails', finding);
          return;
        }
        if (message?.type === 'clusterSource' && Number.isInteger(message.cluster)) {
          const cluster = currentPipelineResult?.clusters?.[message.cluster];
          const source = cluster?.sources?.[message.source];
          const finding = currentFindings.find((item) => item.id === source?.findingId);
          if (finding) await vscode.commands.executeCommand('securityCenter.showFindingDetails', finding);
          return;
        }
        if (message?.type === 'action') await handlePipelineAction(message.action, message.selection);
      });
    } else pipelinePanel.reveal(vscode.ViewColumn.Active);
    await renderPipelinePage();
  }));

  /**
   * Supply-chain actions. Each one that writes, signs or creates key material
   * asks for an explicit confirmation first and records an audit event.
   */
  async function handlePipelineAction(action, selection = undefined) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dossier avant d’utiliser le pipeline.');
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    if (action === 'refresh') return renderPipelinePage();

    if (action === 'openPolicyYaml') return vscode.commands.executeCommand('securityCenter.openProjectPolicy');

    if (action === 'savePolicy') {
      policySaveResult = await savePolicyGate(folder.uri.fsPath, selection || {});
      if (policySaveResult.ok) {
        await auditPolicyChange(policySaveResult, 'Politique de gate enregistrée depuis l’interface.');
        vscode.window.showInformationMessage(`Security Center : ${policySaveResult.message}`);
      } else {
        vscode.window.showErrorMessage(`Security Center : politique non enregistrée — ${policySaveResult.message}`);
      }
      return renderPipelinePage();
    }

    if (action === 'createStarterPolicy') {
      policySaveResult = await createStarterPolicy(folder.uri.fsPath);
      if (policySaveResult.ok) {
        await auditPolicyChange(policySaveResult, 'Politique de départ créée depuis l’interface.');
        await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(vscode.Uri.file(policySaveResult.filePath)));
      } else vscode.window.showErrorMessage(`Security Center : ${policySaveResult.message}`);
      return renderPipelinePage();
    }

    if (action === 'reevaluatePolicy') return reevaluatePolicy();
    if (action === 'openSbom' || action === 'openProvenance') {
      const target = action === 'openSbom' ? currentPipelineArtifacts.sbom?.path : currentPipelineArtifacts.provenance?.path;
      if (target) await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(vscode.Uri.file(target)));
      return;
    }
    if (action === 'installCosign') {
      scannerSetupConfirmation = undefined;
      return installManagedScanners(['cosign']).then(() => renderPipelinePage());
    }

    if (action === 'generateSbom') {
      pipelineBusy = true; await renderPipelinePage();
      try {
        const artifacts = await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title: 'Security Center : génération du SBOM', cancellable: false },
          () => runSupplyChainStages({
            workspacePath: folder.uri.fsPath,
            sbom: { enabled: true, mode: cfg.get('trivy.command', 'auto'), imageName: cfg.get('trivy.image', '') },
            scanners: currentScanStatuses, policy: currentPipelineResult?.policy || null
          })
        );
        currentPipelineArtifacts = { ...currentPipelineArtifacts, ...artifacts };
        const sbom = artifacts.sbom;
        await auditSupplyChain('supplychain.sbom.generated', `SBOM ${sbom?.status === 'generated' ? 'généré' : 'non généré'}.`, {
          status: sbom?.status, componentCount: sbom?.componentCount ?? null, format: sbom?.format || '', digest: sbom?.digest || ''
        });
        vscode.window.showInformationMessage(sbom?.status === 'generated'
          ? `SBOM généré : ${sbom.componentCount} composant(s) — ${sbom.path}`
          : `SBOM non généré : ${sbom?.reason || 'raison inconnue'}`);
      } finally { pipelineBusy = false; await renderPipelinePage(); }
      return;
    }

    if (action === 'generateProvenance') {
      pipelineBusy = true; await renderPipelinePage();
      try {
        const artifacts = await runSupplyChainStages({
          workspacePath: folder.uri.fsPath,
          provenance: { enabled: true, sbom: currentPipelineArtifacts.sbom || null },
          scanners: currentScanStatuses,
          policy: currentPipelineResult?.policy || null,
          startedAt: currentPipelineResult?.startedAt || ''
        });
        // The SBOM already on disk is the subject when no other artefact was named.
        if (!artifacts.provenance && currentPipelineArtifacts.sbom?.path) artifacts.provenance = { status: 'failed', reason: 'Aucun artefact à attester.' };
        currentPipelineArtifacts = { ...currentPipelineArtifacts, ...artifacts };
        const provenance = artifacts.provenance;
        await auditSupplyChain('supplychain.provenance.generated', `Provenance ${provenance?.status === 'generated' ? 'générée' : 'non générée'}.`, {
          status: provenance?.status, artifactDigest: provenance?.artifactDigest || '', sbomLinked: Boolean(provenance?.sbomLinked), policyStatus: provenance?.policyStatus || ''
        });
        vscode.window.showInformationMessage(provenance?.status === 'generated'
          ? `Provenance générée pour ${provenance.artifactDigest}`
          : `Provenance non générée : ${provenance?.reason || 'générez d’abord un SBOM'}`);
      } finally { pipelineBusy = false; await renderPipelinePage(); }
      return;
    }

    if (action === 'configureCosignKey') {
      const choice = await vscode.window.showQuickPick([
        { label: 'Générer une nouvelle paire de clés', detail: 'Cosign crée cosign.key et cosign.pub dans un dossier que vous choisissez.' },
        { label: 'Utiliser une paire de clés existante', detail: 'Sélectionner une clé privée et sa clé publique déjà présentes sur ce poste.' }
      ], { title: 'Clé de signature Cosign', ignoreFocusOut: true });
      if (!choice) return;
      if (choice.label.startsWith('Utiliser')) {
        const privateKey = await vscode.window.showOpenDialog({ title: 'Clé privée Cosign (cosign.key)', canSelectMany: false });
        if (!privateKey?.length) return;
        const publicKey = await vscode.window.showOpenDialog({ title: 'Clé publique Cosign (cosign.pub)', canSelectMany: false });
        if (!publicKey?.length) return;
        await cfg.update('cosign.privateKeyPath', privateKey[0].fsPath, vscode.ConfigurationTarget.Global);
        await cfg.update('cosign.publicKeyPath', publicKey[0].fsPath, vscode.ConfigurationTarget.Global);
      } else {
        const destination = await vscode.window.showOpenDialog({ title: 'Dossier de destination de la clé Cosign', canSelectFolders: true, canSelectFiles: false, canSelectMany: false });
        if (!destination?.length) return;
        // Generating signing material is irreversible and must be explicit.
        const confirmed = await vscode.window.showWarningMessage(
          'Générer une paire de clés Cosign ?',
          {
            modal: true,
            detail: `Destination : ${destination[0].fsPath}\n\nLa clé privée sera protégée par un mot de passe conservé dans VS Code SecretStorage. Security Center n’écrase jamais une clé existante et ne place jamais de clé privée dans le dépôt.`
          },
          'Générer'
        );
        if (confirmed !== 'Générer') return;
        const password = await vscode.window.showInputBox({
          title: 'Mot de passe de la clé privée Cosign', password: true, ignoreFocusOut: true,
          prompt: 'Conservé dans VS Code SecretStorage. Sans lui, la clé sera inutilisable.',
          validateInput: (value) => (value && value.length >= 8 ? undefined : 'Utilisez au moins 8 caractères.')
        });
        if (!password) return;
        pipelineBusy = true; await renderPipelinePage();
        try {
          const keys = await generateKeyPair({ directory: destination[0].fsPath, password, confirmed: true });
          await context.secrets.store(COSIGN_PASSWORD_SECRET_KEY, password);
          await cfg.update('cosign.privateKeyPath', keys.privateKeyPath, vscode.ConfigurationTarget.Global);
          await cfg.update('cosign.publicKeyPath', keys.publicKeyPath, vscode.ConfigurationTarget.Global);
          await auditSupplyChain('supplychain.key.generated', 'Paire de clés Cosign générée.', { publicKeyPath: keys.publicKeyPath });
          vscode.window.showInformationMessage(`Paire de clés Cosign créée dans ${destination[0].fsPath}. Sauvegardez cosign.key hors du dépôt.`);
        } catch (error) {
          vscode.window.showErrorMessage(`Cosign : ${error.message}`);
        } finally { pipelineBusy = false; }
      }
      if (!await context.secrets.get(COSIGN_PASSWORD_SECRET_KEY)) {
        const password = await vscode.window.showInputBox({ title: 'Mot de passe de la clé Cosign', password: true, ignoreFocusOut: true });
        if (password) await context.secrets.store(COSIGN_PASSWORD_SECRET_KEY, password);
      }
      return renderPipelinePage();
    }

    if (action === 'signArtifact') {
      const gate = currentPipelineResult?.policy;
      if (gate?.status === 'BLOCK') {
        return vscode.window.showWarningMessage('Signature refusée : la politique projet a bloqué ce scan. Corrigez les violations avant de signer.');
      }
      const keyPath = cfg.get('cosign.privateKeyPath', '');
      if (!keyPath) return vscode.window.showWarningMessage('Configurez une clé Cosign avant de signer.');
      const selection = await vscode.window.showOpenDialog({
        title: 'Artefact à signer', canSelectMany: false,
        defaultUri: currentPipelineArtifacts.sbom?.path ? vscode.Uri.file(currentPipelineArtifacts.sbom.path) : undefined
      });
      if (!selection?.length) return;
      const confirmed = await vscode.window.showWarningMessage(
        'Signer cet artefact avec Cosign ?',
        { modal: true, detail: `Artefact : ${selection[0].fsPath}\nClé : ${keyPath}\n\nUne signature engage votre clé. Security Center ne signe jamais sans cette confirmation.` },
        'Signer'
      );
      if (confirmed !== 'Signer') return;
      const password = await context.secrets.get(COSIGN_PASSWORD_SECRET_KEY)
        || await vscode.window.showInputBox({ title: 'Mot de passe de la clé Cosign', password: true, ignoreFocusOut: true });
      if (!password) return;
      pipelineBusy = true; await renderPipelinePage();
      try {
        const signature = await signBlob({ filePath: selection[0].fsPath, keyPath, password, confirmed: true });
        currentPipelineArtifacts = { ...currentPipelineArtifacts, signing: signature };
        await auditSupplyChain('supplychain.artifact.signed', 'Artefact signé avec Cosign.', {
          artifact: signature.artifact, signaturePath: signature.signaturePath, cosignVersion: signature.cosignVersion
        });
        vscode.window.showInformationMessage(`Artefact signé : ${signature.signaturePath}`);
      } catch (error) {
        vscode.window.showErrorMessage(`Signature impossible : ${error.message}`);
      } finally { pipelineBusy = false; await renderPipelinePage(); }
      return;
    }

    if (action === 'verifySignature') {
      const publicKeyPath = cfg.get('cosign.publicKeyPath', '');
      if (!publicKeyPath) return vscode.window.showWarningMessage('Configurez une clé publique Cosign avant de vérifier une signature.');
      const selection = await vscode.window.showOpenDialog({
        title: 'Artefact à vérifier', canSelectMany: false,
        defaultUri: currentPipelineArtifacts.signing?.artifact ? vscode.Uri.file(currentPipelineArtifacts.signing.artifact) : undefined
      });
      if (!selection?.length) return;
      pipelineBusy = true; await renderPipelinePage();
      try {
        const verification = await verifyBlob({ filePath: selection[0].fsPath, publicKeyPath });
        currentPipelineArtifacts = { ...currentPipelineArtifacts, signing: { ...currentPipelineArtifacts.signing, ...verification } };
        await auditSupplyChain('supplychain.signature.verified', verification.status === 'verified'
          ? 'Signature vérifiée.' : 'Vérification de signature en échec.', {
          artifact: verification.artifact, status: verification.status, reason: verification.reason || ''
        });
        if (verification.status === 'verified') vscode.window.showInformationMessage(`Signature vérifiée pour ${path.basename(verification.artifact)}.`);
        else vscode.window.showWarningMessage(`Signature non vérifiée : ${verification.reason}`);
      } catch (error) {
        vscode.window.showErrorMessage(`Vérification impossible : ${error.message}`);
      } finally { pipelineBusy = false; await renderPipelinePage(); }
    }
  }

  context.subscriptions.push(themeController.onDidChange(() => renderScannerSetup().catch(() => {})));
  context.subscriptions.push(themeController.onDidChange(() => renderPipelinePage().catch(() => {})));
  for (const page of ['findings', 'scans', 'dynamic', 'analytics']) {
    const command = `securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`;
    context.subscriptions.push(vscode.commands.registerCommand(command, () => {
      if (page === 'dynamic') refreshDynamicTargetModel();
      dashboardProvider.openPage(page);
    }));
  }
  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openBurpSettingsPage', () => dashboardProvider.openPage('burp-settings')));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.checkDynamicTarget', async () => {
    const targetUrl = vscode.workspace.getConfiguration('securityCenter').get('zap.targetUrl', '');
    refreshDynamicTargetModel('unknown');
    const result = await checkTargetReachability(targetUrl);
    refreshDynamicTargetModel(result.state, { source: 'probe' });
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.changeDynamicTarget', async () => {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const current = cfg.get('zap.targetUrl', '');
    const value = await vscode.window.showInputBox({
      title: 'Dynamic Security target', prompt: 'Local HTTP/HTTPS target used by ZAP', value: current, ignoreFocusOut: true,
      validateInput: (input) => { try { return normalizeTargetUrl(input) ? undefined : 'Enter a local target URL.'; } catch (error) { return error.message; } }
    });
    if (value === undefined) return;
    await cfg.update('zap.targetUrl', normalizeTargetUrl(value), vscode.ConfigurationTarget.Workspace);
    refreshDynamicTargetModel('unknown');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showLogs', () => {
    scanLog.show(true);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureSonarToken', async () => {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const hostUrl = cfg.get('sonar.hostUrl', 'http://127.0.0.1:9000');
    const value = await vscode.window.showInputBox({
      title: `Jeton SonarQube pour ${hostUrl}`,
      prompt: 'Généré dans SonarQube via Mon compte > Sécurité. Conservé par VS Code SecretStorage, jamais dans le projet. Laissez vide pour le supprimer.',
      password: true,
      ignoreFocusOut: true
    });
    if (value === undefined) return;
    const token = value.trim();
    if (!token) {
      await context.secrets.delete(SONAR_TOKEN_SECRET_KEY);
      return vscode.window.showInformationMessage('Security Center : jeton SonarQube supprimé du stockage sécurisé.');
    }
    await context.secrets.store(SONAR_TOKEN_SECRET_KEY, token);
    // The token value is never echoed back, only the reachability of the server.
    try {
      const server = await checkSonarServer(hostUrl, { timeoutMs: 8000 });
      vscode.window.showInformationMessage(`Security Center : jeton SonarQube enregistré. Serveur ${hostUrl} disponible (version ${server.version || 'inconnue'}).`);
    } catch (error) {
      vscode.window.showWarningMessage(`Security Center : jeton enregistré, mais ${summarizeScannerError(error.message)}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.checkSonarQube', async () => {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const hostUrl = cfg.get('sonar.hostUrl', 'http://127.0.0.1:9000');
    const hasToken = Boolean(await context.secrets.get(SONAR_TOKEN_SECRET_KEY));
    const local = await detectLocalSonarScanner({ timeoutMs: 20000 });
    let serverState = '';
    try {
      const server = await checkSonarServer(hostUrl, { timeoutMs: 8000 });
      serverState = `serveur disponible (version ${server.version || 'inconnue'})`;
    } catch (error) {
      serverState = summarizeScannerError(error.message);
    }
    const scannerState = local ? `SonarScanner local ${local.version}` : 'SonarScanner local absent — Docker sera utilisé';
    const tokenState = hasToken ? 'jeton enregistré' : 'aucun jeton enregistré';
    const action = await vscode.window.showInformationMessage(
      `Security Center — SonarQube : ${serverState} • ${scannerState} • ${tokenState}.`,
      ...(hasToken ? [] : ['Configurer le jeton'])
    );
    if (action === 'Configurer le jeton') await vscode.commands.executeCommand('securityCenter.configureSonarToken');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureSnykToken', async () => {
    const value = await vscode.window.showInputBox({
      title: 'Jeton d’API Snyk',
      prompt: 'Généré dans Snyk via Account settings > Auth Token. Conservé par VS Code SecretStorage, jamais dans le projet ni dans security-center.yml. Laissez vide pour le supprimer.',
      password: true,
      ignoreFocusOut: true,
      validateInput: (input) => (!input.trim() || looksLikeSnykToken(input) ? undefined : 'Un jeton Snyk est un identifiant au format UUID.')
    });
    if (value === undefined) return;
    const token = value.trim();
    if (!token) {
      await context.secrets.delete(SNYK_TOKEN_SECRET_KEY);
      await context.workspaceState.update('securityCenter.snykCapabilities', { openSource: null, code: null, iac: null });
      return vscode.window.showInformationMessage('Security Center : jeton Snyk supprimé du stockage sécurisé.');
    }
    await context.secrets.store(SNYK_TOKEN_SECRET_KEY, token);
    // Only the verdict is reported: the token value never reaches a message.
    const valid = await validateSnykToken(token, { timeoutMs: 8000 }).catch(() => null);
    if (valid === true) vscode.window.showInformationMessage('Security Center : jeton Snyk enregistré et validé auprès de l’API Snyk.');
    else if (valid === false) vscode.window.showWarningMessage('Security Center : jeton Snyk enregistré, mais refusé par l’API Snyk. Vérifiez qu’il n’a pas expiré.');
    else vscode.window.showWarningMessage('Security Center : jeton Snyk enregistré, mais l’API Snyk est injoignable. La validation sera refaite au prochain scan.');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.checkSnyk', async () => {
    const diagnostic = await collectSnykDiagnostic();
    const diagnosis = snykDiagnosis(diagnostic);
    const engine = diagnostic.cliVersion
      ? `CLI local ${diagnostic.cliVersion}`
      : diagnostic.dockerAvailable ? 'CLI local absent — image snyk/snyk sera utilisée' : 'aucun moteur disponible';
    const tokenState = !diagnostic.tokenConfigured ? 'aucun jeton enregistré'
      : diagnostic.authenticationValid === true ? 'jeton validé'
        : diagnostic.authenticationValid === false ? 'jeton refusé par Snyk' : 'jeton enregistré, validation impossible';
    const action = await vscode.window.showInformationMessage(
      `Security Center — Snyk : ${diagnosis.label} • ${engine} • ${tokenState}.`,
      ...(diagnostic.tokenConfigured ? [] : ['Configurer le jeton'])
    );
    if (action === 'Configurer le jeton') await vscode.commands.executeCommand('securityCenter.configureSnykToken');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureBackendApiKey', async () => {
    const value = await vscode.window.showInputBox({
      title: 'Clé API du backend Security Center',
      prompt: 'Saisissez la même valeur que SECURITY_CENTER_API_KEY. Laissez vide pour supprimer la clé enregistrée.',
      password: true,
      ignoreFocusOut: true
    });
    if (value === undefined) return;
    const apiKey = value.trim();
    if (apiKey) await context.secrets.store('securityCenter.backend.apiKey', apiKey);
    else await context.secrets.delete('securityCenter.backend.apiKey');
    setApiKey(apiKey);
    vscode.window.showInformationMessage(apiKey
      ? 'Security Center : clé API enregistrée dans le stockage sécurisé de VS Code.'
      : 'Security Center : clé API supprimée.');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.installPreCommitHook', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dépôt Git avant d’installer le hook pre-commit.');
    try {
      const result = await installPreCommitHook(folder.uri.fsPath);
      vscode.window.showInformationMessage(result.status === 'installed'
        ? `Security Center : protection Gitleaks installée dans ${result.hookPath}.`
        : 'Security Center : le hook Gitleaks est déjà installé.');
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : installation du hook impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showTrends', async () => {
    try {
      const baseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      const summaries = await listScans(baseUrl, 100);
      const [scans, events] = await Promise.all([
        Promise.all(summaries.map((scan) => getScan(baseUrl, scan.scan_id))),
        listAuditEvents(baseUrl, 1000)
      ]);
      const report7 = buildTrendReport(scans, events, 7);
      const report30 = buildTrendReport(scans, events, 30);
      const report90 = buildTrendReport(scans, events, 90);
      const reports = { 7: report7, 30: report30, 90: report90 };
      const panel = vscode.window.createWebviewPanel('securityCenter.trends', 'Security Center — Tendances et MTTR', vscode.ViewColumn.Active, { enableScripts: true });
      const nonce = crypto.randomBytes(16).toString('base64');
      const renderTrends = () => { panel.webview.html = renderTrendReportHtml(reports, nonce, themeController.getTheme()); };
      renderTrends();
      const trendThemeSubscription = themeController.onDidChange(renderTrends);
      panel.onDidDispose(() => trendThemeSubscription.dispose());
      panel.webview.onDidReceiveMessage(async (message) => {
        if (message?.command === 'openDashboard') await vscode.commands.executeCommand('securityCenter.openDashboard');
      });
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : tendances indisponibles — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showAuditLog', async () => {
    try {
      const baseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      const events = await listAuditEvents(baseUrl, 500);
      const panel = vscode.window.createWebviewPanel('securityCenter.auditLog', 'Security Center — Journal d’audit', vscode.ViewColumn.Active, { enableScripts: false });
      panel.webview.html = renderAuditLogHtml(events, crypto.randomBytes(16).toString('base64'));
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : journal d’audit indisponible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.openProjectPolicy', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dossier avant de configurer la politique.');
    const existing = ['security-center.yml', 'security-center.yaml']
      .map((name) => path.join(folder.uri.fsPath, name))
      .find((filePath) => fs.existsSync(filePath));
    const filePath = existing || path.join(folder.uri.fsPath, 'security-center.yml');
    if (!existing) {
      const template = [
        'version: 1',
        'scanners:',
        '  semgrep: true',
        '  gitleaks: true',
        '  trivy: true',
        '  osv: true',
        '  zap: true',
        'policy:',
        '  fail_on: HIGH',
        '  max_active: 0',
        '  include_tests: false',
        'licenses:',
        '  denied: [AGPL-3.0, GPL-3.0]',
        'gitleaks:',
        '  history: false',
        '  history_incremental: true',
        '  config: ""',
        'semgrep:',
        '  custom_rules: ""',
        'zap:',
        '  mode: auto',
        '  local_path: ""',
        '  policy_min_severity: HIGH',
        '  active: false',
        '  openapi: ""',
        '  context: ""',
        '  user: ""',
        '  auth_login: ""',
        '  auth_username_env: SECURITY_CENTER_ZAP_USERNAME',
        '  auth_password_env: SECURITY_CENTER_ZAP_PASSWORD',
        '  auth_token_path: authentication.token',
        '  auth_username_field: email',
        '  auth_password_field: password',
        '  auth_header: Authorization',
        '  auth_prefix: Bearer',
        'exclusions:',
        '  global_files: [node_modules/**, dist/**]',
        '  semgrep_files: []',
        '  semgrep_rules: []',
        '  trivy_files: []',
        '  zap_routes: [/logout]',
        'execution:',
        '  max_parallel_scanners: 2',
        ''
      ].join('\n');
      await fs.promises.writeFile(filePath, template, { encoding: 'utf8', flag: 'wx' });
    }
    const document = await vscode.workspace.openTextDocument(filePath);
    await vscode.window.showTextDocument(document, { preview: false });
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.generateSbom', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dossier avant de générer le SBOM.');
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const uri = await vscode.window.showSaveDialog({
      title: 'Exporter le SBOM CycloneDX',
      defaultUri: vscode.Uri.file(path.join(folder.uri.fsPath, 'security-center-sbom.cdx.json')),
      filters: { 'CycloneDX JSON': ['json'] }
    });
    if (!uri) return;
    try {
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center : génération du SBOM CycloneDX' }, async () => {
        const result = await generateSbom({
          workspacePath: folder.uri.fsPath,
          mode: cfg.get('trivy.command', 'auto'),
          imageName: cfg.get('trivy.image', ''),
          timeoutMs: cfg.get('scan.timeoutSeconds', 300) * 1000
        });
        await fs.promises.writeFile(uri.fsPath, `${JSON.stringify(result.payload, null, 2)}\n`, 'utf8');
        const componentCount = result.payload.components.length;
        vscode.window.showInformationMessage(`Security Center : SBOM CycloneDX exporté — ${componentCount} composant(s).`);
      });
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : export SBOM impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.checkLicenses', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dossier avant de contrôler les licences.');
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    try {
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center : contrôle des licences' }, async () => {
        const result = await generateSbom({
          workspacePath: folder.uri.fsPath,
          mode: cfg.get('trivy.command', 'auto'),
          imageName: cfg.get('trivy.image', ''),
          timeoutMs: cfg.get('scan.timeoutSeconds', 300) * 1000
        });
        const projectPolicy = await loadProjectPolicy(folder.uri.fsPath);
        const deniedLicenses = projectPolicy?.licensesDenied?.length ? projectPolicy.licensesDenied : cfg.get('licenses.denied', []);
        const report = analyzeLicenses(result.payload, deniedLicenses);
        const panel = vscode.window.createWebviewPanel('securityCenter.licenseCompliance', 'Security Center — Conformité des licences', vscode.ViewColumn.Active, { enableScripts: false });
        panel.webview.html = renderLicenseReportHtml(report, crypto.randomBytes(16).toString('base64'));
        if (!report.compliant) vscode.window.showWarningMessage(`Security Center : ${report.counts.denied} composant(s) utilisent une licence interdite.`);
      });
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : contrôle des licences impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.compareScans', async () => {
    try {
      const baseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      const summaries = await listScans(baseUrl, 100);
      if (!summaries || summaries.length === 0) {
        return vscode.window.showInformationMessage('Security Center : aucun scan disponible pour comparer.');
      }
      
      const scans = await Promise.all(summaries.map(async (scan) => {
        try {
          return await getScan(baseUrl, scan.scan_id);
        } catch {
          return { scan_id: scan.scan_id, finished_at: scan.finished_at, workspace: scan.workspace, result: { findings: [], scanners: [] } };
        }
      }));

      // Prune scans array for list display to avoid HTML breakage / massive payloads
      const prunedScans = scans.map(s => {
        const scanners = s.result?.scanners || [];
        const findings = s.result?.findings || [];
        const active = findings.filter(f => !['false_positive', 'fixed', 'validated', 'accepted'].includes(f.triageStatus));
        return {
          scan_id: s.scan_id,
          finished_at: s.result?.finished_at || s.finished_at,
          workspace: s.workspace || s.result?.workspace,
          git_commit: s.git_commit || s.result?.git_commit,
          findingsCount: findings.length,
          result: {
            scanners: scanners,
            findings: active.map(f => ({
              id: f.id,
              fingerprint: f.fingerprint,
              tool: f.tool,
              rawSeverity: f.rawSeverity,
              triageStatus: f.triageStatus
            }))
          }
        };
      });

      const panel = vscode.window.createWebviewPanel(
        'securityCenter.scanComparison',
        'Security Center — Comparer les scans',
        vscode.ViewColumn.Active,
        { enableScripts: true }
      );

      const nonce = crypto.randomBytes(16).toString('base64');
      const theme = themeController.getTheme ? themeController.getTheme() : 'light';
      panel.webview.html = renderScanComparisonHtml(prunedScans, nonce, theme);

      const themeSubscription = themeController.onDidChange(() => {
        panel.webview.html = renderScanComparisonHtml(prunedScans, nonce, themeController.getTheme());
      });
      panel.onDidDispose(() => themeSubscription.dispose());

      panel.webview.onDidReceiveMessage(async (message) => {
        if (!message) return;
        switch (message.command) {
          case 'compare': {
            const { baselineId, currentId } = message;
            const baseline = scans.find(s => s.scan_id === baselineId);
            const current = scans.find(s => s.scan_id === currentId);
            if (baseline && current) {
              const comparison = compareScans(baseline, current);
              
              // Helper to prune findings of details/evidence for safe HTML postMessage
              const pruneComparisonFinding = (f) => ({
                id: f.id,
                fingerprint: f.fingerprint,
                tool: f.tool,
                rawSeverity: f.rawSeverity,
                title: f.title,
                file: f.file,
                endpoint: f.endpoint,
                packageName: f.packageName,
                absolutePath: f.absolutePath,
                startLine: f.startLine,
                startColumn: f.startColumn,
                endLine: f.endLine,
                endColumn: f.endColumn,
                triageStatus: f.triageStatus
              });

              const prunedComparison = {
                ...comparison,
                added: (comparison.added || []).map(pruneComparisonFinding),
                resolved: (comparison.resolved || []).map(pruneComparisonFinding),
                persistent: (comparison.persistent || []).map(pruneComparisonFinding),
                severityChanged: (comparison.severityChanged || []).map(pruneComparisonFinding),
                unchanged: (comparison.unchanged || []).map(pruneComparisonFinding)
              };

              panel.webview.postMessage({
                command: 'comparisonResult',
                comparison: prunedComparison
              });
            }
            break;
          }
          case 'showFindingDetails': {
            await vscode.commands.executeCommand('securityCenter.showFindingDetails', message.finding);
            break;
          }
          case 'openFindingCode': {
            await vscode.commands.executeCommand('securityCenter.openFindingCode', message.finding);
            break;
          }
          case 'openDashboard': {
            await vscode.commands.executeCommand('securityCenter.openDashboard');
            break;
          }
        }
      });
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : comparaison impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showScanHistoryPage', async () => {
    const localScans = context.workspaceState.get(LOCAL_SCAN_HISTORY_KEY, []);
    const baseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
    let backendScans = [];
    let backendError = '';
    try {
      backendScans = await listScans(baseUrl, 100);
    } catch (error) {
      backendError = error.message;
    }
    const panel = vscode.window.createWebviewPanel(
      'securityCenter.scanHistory',
      'Security Center — Historique des scans',
      vscode.ViewColumn.Active,
      { enableScripts: true }
    );
    const nonce = crypto.randomBytes(16).toString('base64');
    const renderHistory = () => { panel.webview.html = renderScanHistoryHtml(localScans, backendScans, backendError, nonce, themeController.getTheme()); };
    renderHistory();
    const historyThemeSubscription = themeController.onDidChange(renderHistory);
    panel.onDidDispose(() => historyThemeSubscription.dispose());
    panel.webview.onDidReceiveMessage(async (message) => {
      if (message?.command === 'openDashboard') {
        await vscode.commands.executeCommand('securityCenter.openDashboard');
        return;
      }
      if (message?.command !== 'loadScan') return;
      try {
        let stored;
        if (message.source === 'local') {
          const local = context.workspaceState.get(LOCAL_SCAN_HISTORY_KEY, []).find((scan) => scan.localId === message.id);
          if (!local) throw new Error('Cette sauvegarde locale est introuvable.');
          stored = { findings: local.findings, scanners: local.scanners, dashboardOptions: local.dashboardOptions, label: new Date(local.savedAt).toLocaleString('fr-FR') };
        } else {
          const remote = await getScan(baseUrl, message.id);
          stored = {
            findings: remote.result.findings,
            scanners: remote.result.scanners,
            dashboardOptions: { workspace: remote.result.workspace, scanStatus: 'completed', backendStatus: 'online', correlations: remote.result.correlations },
            label: `#${remote.scan_id}`
          };
        }
        const historicalPanel = vscode.window.createWebviewPanel(
          'securityCenter.historicalScan',
          `Security Center — scan historique ${stored.label}`,
          vscode.ViewColumn.Active,
          { enableScripts: true, retainContextWhenHidden: true }
        );
        const historicalModel = buildDashboardModel(stored.findings || [], stored.scanners || [], { ...(stored.dashboardOptions || {}), restoredFromHistory: true });
        const renderHistoricalScan = () => { historicalPanel.webview.html = renderDashboardHtml(historicalModel, crypto.randomBytes(16).toString('base64'), 'history', themeController.getTheme()); };
        renderHistoricalScan();
        const historicalThemeSubscription = themeController.onDidChange(renderHistoricalScan);
        historicalPanel.onDidDispose(() => historicalThemeSubscription.dispose());
        historicalPanel.webview.onDidReceiveMessage(async (historicalMessage) => {
          if (historicalMessage?.type !== 'finding' || !Number.isInteger(historicalMessage.index)) return;
          const historicalFinding = historicalModel.findings[historicalMessage.index];
          if (historicalFinding) await vscode.commands.executeCommand('securityCenter.showFindingDetails', historicalFinding);
        });
        vscode.window.showInformationMessage(`Security Center : scan historique ouvert dans un nouvel onglet (${historicalModel.findings.length} résultat(s)).`);
      } catch (error) {
        vscode.window.showErrorMessage(`Security Center : chargement du scan impossible — ${error.message}`);
      }
    });
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.showScanHistory', async () => {
    try {
      const baseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      const scans = await listScans(baseUrl, 100);
      if (!scans.length) return vscode.window.showInformationMessage('Security Center : aucun scan enregistré.');
      const selected = await vscode.window.showQuickPick(scans.map((scan) => ({
        label: `Scan #${scan.scan_id} — ${scan.finding_count} résultat(s)`,
        description: new Date(scan.finished_at).toLocaleString('fr-FR'),
        detail: `${scan.workspace} • ${scan.scanner_count} scanner(s)`, scan
      })), { title: 'Historique Security Center', placeHolder: 'Choisir un scan à consulter ou exporter' });
      if (!selected) return;
      const action = await vscode.window.showQuickPick([
        { label: '$(eye) Charger les résultats', value: 'load' },
        { label: '$(compare-changes) Comparer avec un autre scan', value: 'compare' },
        { label: '$(json) Exporter en JSON', value: 'json' },
        { label: '$(file-code) Exporter en HTML', value: 'html' }
      ], { title: `Scan #${selected.scan.scan_id}` });
      if (!action) return;
      if (action.value === 'compare') {
        await vscode.commands.executeCommand('securityCenter.compareScans');
        return;
      }
      if (action.value === 'load') {
        const stored = await getScan(baseUrl, selected.scan.scan_id);
        currentScanId = stored.scan_id;
        currentFindings = stored.result.findings;
        currentScanStatuses = stored.result.scanners;
        currentDashboardOptions = { workspace: stored.result.workspace, scanStatus: 'completed', backendStatus: 'online', correlations: stored.result.correlations };
        publishDiagnostics(diagnostics, currentFindings);
        provider.setFindings(currentFindings, currentScanStatuses);
        dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
        await saveLocalScanCache();
        return vscode.window.showInformationMessage(`Security Center : scan #${stored.scan_id} chargé.`);
      }
      const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || context.extensionPath;
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(folder, `security-center-scan-${selected.scan.scan_id}.${action.value}`)),
        filters: action.value === 'json' ? { JSON: ['json'] } : { HTML: ['html'] }
      });
      if (!uri) return;
      const content = await requestText(scanExportUrl(baseUrl, selected.scan.scan_id, action.value));
      await fs.promises.writeFile(uri.fsPath, content);
      vscode.window.showInformationMessage(`Rapport enregistré : ${uri.fsPath}`);
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : historique indisponible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureBurp', async () => {
    const connector = vscode.Uri.file(
      path.join(context.extensionPath, 'connectors', 'security-center-burp.jar')
    );
    if (!fs.existsSync(connector.fsPath)) {
      return vscode.window.showErrorMessage('Security Center : le connecteur Burp inclus est introuvable.');
    }
    const executable = burpExecutableCandidates().find((candidate) => fs.existsSync(candidate));
    const running = await isBurpRunning();
    const state = running ? 'Burp est démarré.' : executable ? 'Burp est installé mais arrêté.' : 'Burp Suite n’est pas installé.';
    const action = await vscode.window.showQuickPick([
      { label: '$(book) Afficher le guide complet', value: 'guide', description: state },
      ...(executable && !running ? [{ label: '$(play) Démarrer Burp Suite', value: 'start', description: executable }] : []),
      ...(!executable ? [{ label: '$(cloud-download) Télécharger Burp Community', value: 'download', description: 'Site officiel PortSwigger' }] : []),
      { label: '$(file-binary) Afficher le connecteur JAR', value: 'connector', description: connector.fsPath }
    ], { title: 'Assistant Burp Suite — Security Center', placeHolder: state });
    if (!action) return;
    if (action.value === 'start') {
      const child = spawn(executable, [], { detached: true, stdio: 'ignore', windowsHide: false });
      child.unref();
      return vscode.window.showInformationMessage('Burp démarre. Choisissez Temporary project, puis ouvrez l’onglet Security Center.');
    }
    if (action.value === 'download') {
      await vscode.env.openExternal(vscode.Uri.parse('https://portswigger.net/burp/communitydownload'));
      return vscode.window.showInformationMessage('Installez Community Edition depuis PortSwigger, puis relancez cet assistant.');
    }
    if (action.value === 'connector') return vscode.commands.executeCommand('revealFileInOS', connector);
    const instructions = executable
      ? `${state}\n\n1. Démarrez Burp : Temporary project → Use Burp defaults → Start Burp.\n2. Extensions → Installed → Add → Java.\n3. Sélectionnez : ${connector.fsPath}\n4. Security Center → Tester la connexion.\n5. Gardez la capture automatique cochée.\n6. Proxy → Open browser, puis ouvrez http://127.0.0.1:3000.\n\nLe replay est optionnel : il sert seulement à comparer une réponse avant et après correction.`
      : `Burp Community est optionnel et sert à capturer le trafic HTTP.\n\n1. Téléchargez-le depuis le site officiel PortSwigger.\n2. Installez Community Edition.\n3. Relancez cet assistant pour charger le connecteur Java.\n\nLes scans Semgrep, Trivy, OSV et ZAP fonctionnent sans Burp.`;
    const selected = await vscode.window.showInformationMessage(instructions, { modal: true }, 'Afficher le JAR', ...(!executable ? ['Télécharger'] : []));
    if (selected === 'Afficher le JAR') await vscode.commands.executeCommand('revealFileInOS', connector);
    if (selected === 'Télécharger') await vscode.env.openExternal(vscode.Uri.parse('https://portswigger.net/burp/communitydownload'));
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.testBurpConnection', async () => {
    const backendUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
    try {
      const burpStatus = await getBurpStatus(backendUrl);
      currentDashboardOptions = { ...currentDashboardOptions, backendStatus: 'online', burpConnected: Boolean(burpStatus.connected), burpStatus, burpSession: captureSessionFrom(burpStatus, { campaign: currentDynamicCampaign() }), burpEndpoint: `${backendUrl.replace(/\/$/, '')}/api/v1/integrations/burp` };
      dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
      vscode.window.showInformationMessage(burpStatus.connected ? 'Security Center : connecteur Burp connecté.' : 'Security Center : backend accessible, mais aucun heartbeat Burp récent.');
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : test Burp impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureZap', async () => {
    const hasJava = await javaAvailable();
    const zapPath = detectLocalZap();
    const state = zapPath
      ? `ZAP local détecté : ${zapPath}`
      : hasJava ? 'Java est installé, mais ZAP local est absent.' : 'Java et ZAP local ne sont pas détectés.';
    const action = await vscode.window.showQuickPick([
      ...(zapPath ? [{ label: '$(pass-filled) ZAP local prêt', value: 'ready', description: zapPath }] : []),
      ...(!hasJava ? [{ label: '$(cloud-download) Installer Java', value: 'java', description: 'Runtime requis par ZAP Desktop' }] : []),
      ...(!zapPath ? [{ label: '$(cloud-download) Installer OWASP ZAP', value: 'zap', description: 'Téléchargement officiel Windows' }] : []),
      { label: '$(book) Afficher les instructions', value: 'guide', description: state }
    ], { title: 'Assistant OWASP ZAP local — Security Center', placeHolder: state });
    if (!action || action.value === 'ready') return;
    if (action.value === 'java') return vscode.env.openExternal(vscode.Uri.parse('https://adoptium.net/temurin/releases/'));
    if (action.value === 'zap') return vscode.env.openExternal(vscode.Uri.parse('https://www.zaproxy.org/download/'));
    await vscode.window.showInformationMessage(`${state}\n\n1. Installez Java 17 ou supérieur.\n2. Installez OWASP ZAP Desktop.\n3. Relancez cet assistant : ZAP sera détecté et démarré automatiquement au prochain scan.\n\nZAP reste optionnel : Semgrep, Gitleaks, Trivy et OSV continuent sans lui.`, { modal: true });
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.configureZapCredentials', async () => {
    const action = await vscode.window.showQuickPick([
      { label: '$(key) Enregistrer ou remplacer le compte ZAP', value: 'set' },
      { label: '$(trash) Supprimer le compte ZAP enregistré', value: 'clear' }
    ], { title: 'Compte de test ZAP authentifié' });
    if (!action) return;
    if (action.value === 'clear') {
      await context.secrets.delete(zapUsernameSecretKey);
      await context.secrets.delete(zapPasswordSecretKey);
      return vscode.window.showInformationMessage('Security Center : compte ZAP supprimé du stockage sécurisé pour ce workspace.');
    }
    const previousUsername = await context.secrets.get(zapUsernameSecretKey) || '';
    const username = await vscode.window.showInputBox({ title: 'Compte de test ZAP', prompt: 'Adresse e-mail ou identifiant du compte local', value: previousUsername, ignoreFocusOut: true });
    if (!username?.trim()) return;
    const password = await vscode.window.showInputBox({ title: 'Mot de passe du compte de test ZAP', prompt: 'Stocké de manière sécurisée par VS Code, jamais dans le projet.', password: true, ignoreFocusOut: true });
    if (!password) return;
    await context.secrets.store(zapUsernameSecretKey, username.trim());
    await context.secrets.store(zapPasswordSecretKey, password);
    vscode.window.showInformationMessage('Security Center : compte ZAP enregistré dans le stockage sécurisé pour ce workspace.');
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.scanSelected', async () => {
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    const available = [
      { label: 'Semgrep', description: 'Analyse statique du code' },
      ...(cfg.get('gitleaks.enabled', true) ? [{ label: 'Gitleaks', description: 'Détection de secrets' }] : []),
      ...(cfg.get('trivy.enabled', true) ? [{ label: 'Trivy', description: 'Dépendances, images et configurations' }] : []),
      ...(cfg.get('osv.enabled', true) ? [{ label: 'OSV-Scanner', description: 'Validation complémentaire des dépendances' }] : []),
      ...(cfg.get('sonar.enabled', false) ? [{ label: 'SonarQube', description: 'Qualité et sécurité du code via le serveur SonarQube' }] : []),
      ...(cfg.get('snyk.enabled', false) ? [{ label: 'Snyk', description: 'Dépendances, code et IaC via le service Snyk' }] : []),
      ...(cfg.get('zap.enabled', true) ? [{ label: 'ZAP', description: 'Analyse dynamique passive de la cible locale' }] : [])
    ];
    const selected = await vscode.window.showQuickPick(available, {
      title: 'Choisir les scanners Security Center',
      placeHolder: 'Sélectionnez un ou plusieurs scanners',
      canPickMany: true
    });
    if (!selected?.length) return;
    await vscode.commands.executeCommand('securityCenter.scanWorkspace', selected.map((item) => item.label));
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.retryScanner', async (tool) => {
    const supported = [...ALL_SCANNER_TOOLS];
    if (!supported.includes(tool)) return;
    if (tool === 'ZAP') return vscode.commands.executeCommand('securityCenter.scanZap');
    await vscode.commands.executeCommand('securityCenter.scanWorkspace', [tool]);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.scanZap', async () => {
    if (!(await javaAvailable()) || !detectLocalZap()) {
      const selected = await vscode.window.showWarningMessage('ZAP local ou Java n’est pas détecté. Le scan dynamique reste optionnel.', 'Installer/configurer ZAP', 'Continuer sans ZAP');
      if (selected === 'Installer/configurer ZAP') await vscode.commands.executeCommand('securityCenter.configureZap');
      return;
    }
    await vscode.commands.executeCommand('securityCenter.scanWorkspace', ['ZAP']);
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.scanIncremental', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dépôt Git avant de lancer le scan rapide.');
    let temporaryRoot;
    try {
      const changedFiles = await modifiedGitFiles(folder.uri.fsPath);
      if (!changedFiles.length) return vscode.window.showInformationMessage('Security Center : aucun fichier modifié ou non suivi à analyser.');
      const prepared = await createIncrementalWorkspace(folder.uri.fsPath, changedFiles);
      temporaryRoot = prepared.temporaryRoot;
      if (!prepared.copied.length) return vscode.window.showInformationMessage('Security Center : aucun fichier modifié analysable (fichiers supprimés, liens ou fichiers trop volumineux).');
      const cfg = vscode.workspace.getConfiguration('securityCenter');
      const tools = ['Semgrep', ...(cfg.get('gitleaks.enabled', true) ? ['Gitleaks'] : [])];
      vscode.window.showInformationMessage(`Security Center : scan rapide de ${prepared.copied.length} fichier(s) modifié(s) avec ${tools.join(' + ')}.`);
      await vscode.commands.executeCommand('securityCenter.scanWorkspace', {
        tools,
        scanRoot: temporaryRoot,
        incrementalFiles: changedFiles
      });
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : scan incrémental impossible — ${error.message}`);
    } finally {
      if (temporaryRoot) await fs.promises.rm(temporaryRoot, { recursive: true, force: true }).catch(() => {});
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.importHttpCapture', async () => {
    const selected = await vscode.window.showOpenDialog({
      canSelectMany: false,
      filters: { 'HTTP Archive': ['har', 'json'] },
      openLabel: 'Importer la capture HTTP'
    });
    if (!selected?.length) return;
    try {
      const payload = JSON.parse(await fs.promises.readFile(selected[0].fsPath, 'utf8'));
      const { scenarios, rejected } = normalizeHar(payload);
      if (!scenarios.length) throw new Error('Aucune requête locale autorisée dans cette capture.');
      const backendUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      for (const scenario of scenarios) await saveHttpScenario(backendUrl, scenario);
      const storedScenarios = await listHttpScenarios(backendUrl);
      currentDashboardOptions = {
        ...currentDashboardOptions,
        httpScenarioCount: storedScenarios.length,
        httpScenarios: storedScenarios,
        backendStatus: 'online'
      };
      dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
      vscode.window.showInformationMessage(`Security Center : ${scenarios.length} scénario(s) HTTP importé(s), ${rejected.length} rejeté(s).`);
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : import HTTP impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.replayHttpScenario', async (requestedScenario) => {
    try {
      const backendUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      const scenarios = requestedScenario ? [requestedScenario] : await listHttpScenarios(backendUrl);
      const replayableScenarios = scenarios.filter((scenario) => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH'].includes(String(scenario.request.method).toUpperCase()));
      if (scenarios.length && !replayableScenarios.length) {
        return vscode.window.showInformationMessage('Security Center : aucun scénario rejouable. GET/HEAD et POST/PUT/PATCH contrôlés sont pris en charge ; DELETE reste interdit.');
      }
      if (!scenarios.length) return vscode.window.showInformationMessage('Security Center : aucun scénario HTTP enregistré.');
      const requestedReplayable = requestedScenario && replayableScenarios.find((scenario) => scenario === requestedScenario
        || (scenario.name === requestedScenario.name && scenario.request?.url === requestedScenario.request?.url && scenario.request?.method === requestedScenario.request?.method));
      const selected = requestedReplayable ? { scenario: requestedReplayable } : await vscode.window.showQuickPick(
        replayableScenarios.map((scenario) => ({
          label: scenario.name,
          description: `${scenario.request.method} • ${scenario.source}`,
          detail: scenario.request.url,
          scenario
        })),
        { title: 'Rejouer un scénario HTTP local', placeHolder: 'GET/HEAD sûr ou POST/PUT/PATCH contrôlé' }
      );
      if (!selected) return;
      const method = String(selected.scenario.request.method).toUpperCase();
      const isWrite = ['POST', 'PUT', 'PATCH'].includes(method);
      const safePreview = buildSafeHttpPreview(selected.scenario, currentFindings);
      const previewLines = [
        `${safePreview.method} ${safePreview.path || safePreview.url}`,
        '',
        'Headers assainis:',
        ...(safePreview.headers.length ? safePreview.headers.map((header) => `${header.name}: ${header.value}`) : ['Aucun']),
        '',
        'Paramètres/corps assainis:',
        ...(safePreview.parameters.length ? safePreview.parameters.map((parameter) => `${parameter.location} • ${parameter.name}=${parameter.value}`) : ['Aucun paramètre structuré affichable'])
      ].join('\n');
      const previewConfirmation = await vscode.window.showInformationMessage(
        `${isWrite ? '⚠ Cette requête peut modifier l’état de l’application.\n\n' : ''}${previewLines}`,
        { modal: true },
        isWrite ? 'Confirmer et rejouer' : 'Rejouer la requête'
      );
      if (!previewConfirmation) return;
      const fixedFindings = currentFindings.filter((finding) => finding.triageStatus === 'fixed');
      const linked = fixedFindings.length ? await vscode.window.showQuickPick([
        ...fixedFindings.map((finding) => ({ label: finding.title, description: `${finding.tool} • ${finding.rawSeverity || finding.severity}`, finding })),
        { label: 'Aucune vulnérabilité précise', finding: undefined }
      ], { title: 'Lier la preuve à une correction', placeHolder: 'Choisir la vulnérabilité corrigée concernée', ignoreFocusOut: true }) : undefined;
      if (fixedFindings.length && !linked) return;
      if (isWrite) {
        if (!httpWriteReplayAuthorized) {
          const confirmation = await vscode.window.showWarningMessage(
            'Les replays POST/PUT/PATCH peuvent modifier les données locales. Autoriser ces méthodes pour cette session VS Code ? DELETE restera interdit.',
            { modal: true },
            'Autoriser pour cette session'
          );
          if (confirmation !== 'Autoriser pour cette session') return;
          httpWriteReplayAuthorized = true;
        }
        const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
        const auditEvent = {
          scan_id: currentScanId || 0,
          finding_id: linked?.finding?.id || `http:${method}:${selected.scenario.request.url}`,
          action: `http-replay:${method.toLowerCase()}:authorized`,
          actor,
          comment: 'Autorisation locale accordée pour la session VS Code.'
        };
        try {
          await createAuditEvent(backendUrl, auditEvent);
        } catch (error) {
          scanLog.appendLine(`Replay HTTP — audit backend indisponible : ${error.message}`);
        }
      }
      const beforeLinkedFindings = linkedFindingsForScenario(selected.scenario, currentFindings);
      const replayStartedAt = Date.now();
      const replay = await replayScenario(selected.scenario, { allowWrite: isWrite, timeoutMs: 30000 });
      replay.durationMs = Date.now() - replayStartedAt;
      replay.linkedFindingsBefore = beforeLinkedFindings.length;
      replay.linkedFindingsAfter = null;
      if (isWrite || linked?.finding) {
        const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
        await createAuditEvent(backendUrl, {
          scan_id: currentScanId || 0,
          finding_id: linked?.finding?.id || `http:${method}:${selected.scenario.request.url}`,
          action: `http-replay:${method.toLowerCase()}:completed`,
          actor,
          comment: `HTTP ${replay.statusCode}; statut_modifié=${replay.comparison.statusChanged}; corps_modifié=${replay.comparison.bodyChanged}`
        }).catch((error) => scanLog.appendLine(`Replay HTTP terminé, mais preuve d’exécution non persistée : ${error.message}`));
      }
      const panel = vscode.window.createWebviewPanel(
        'securityCenter.httpReplay',
        `HTTP Replay — ${selected.scenario.name}`,
        vscode.ViewColumn.Active,
        { enableScripts: true }
      );
      const nonce = crypto.randomBytes(16).toString('base64');
      panel.webview.onDidReceiveMessage((message) => { if (message?.type === 'back') dashboardProvider.openPage('dynamic'); });
      panel.webview.html = renderHttpReplayHtml(selected.scenario, replay, nonce, linked?.finding, dashboardProvider.selectedTheme);
    } catch (error) {
      vscode.window.showErrorMessage(`Security Center : replay impossible — ${error.message}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand('securityCenter.scanWorkspace', async (requestedTools) => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Ouvrez un dossier avant de lancer un scan.');
    if (scanInProgress) return vscode.window.showInformationMessage('Security Center : une analyse est déjà en cours.');
    let projectPolicy;
    try {
      projectPolicy = await loadProjectPolicy(folder.uri.fsPath);
      const backendBaseUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
      if (lastProjectPolicy) {
        const { redactAuditValue } = require('./audit-events');
        const prevClean = redactAuditValue(lastProjectPolicy);
        const newClean = redactAuditValue(projectPolicy);
        const prevHash = crypto.createHash('sha256').update(JSON.stringify(prevClean)).digest('hex').slice(0, 16);
        const newHash = crypto.createHash('sha256').update(JSON.stringify(newClean)).digest('hex').slice(0, 16);
        
        if (prevHash !== newHash) {
          const actor = vscode.workspace.getConfiguration('securityCenter').get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
          await createAuditEvent(backendBaseUrl, {
            scan_id: currentScanId || 0,
            action: 'policy.changed',
            actor,
            comment: `Politique de sécurité modifiée : hash ${prevHash} → ${newHash}`,
            metadata: {
              previousHash: prevHash,
              newHash: newHash,
              previousState: prevClean,
              newState: newClean,
              timestamp: new Date().toISOString()
            }
          }).catch(() => {});
        }
      }
      lastProjectPolicy = projectPolicy;
    } catch (error) {
      return vscode.window.showErrorMessage(`Security Center : politique projet invalide — ${error.message}`);
    }
    scanInProgress = true;
    // The companion mirrors the scan lifecycle without polling anything.
    currentScanRunning = true;
    liveCompanionProvider.render();
    const previousFindings = [...currentFindings];
    const previousScanId = currentScanId;
    const scanRequest = Array.isArray(requestedTools) ? { tools: requestedTools } : (requestedTools || {});
    const requested = Array.isArray(scanRequest.tools) ? new Set(scanRequest.tools) : undefined;
    const incrementalFiles = Array.isArray(scanRequest.incrementalFiles) ? scanRequest.incrementalFiles : [];
    const retainedFindings = requested
      ? incrementalFiles.length
        ? retainUnchangedFindings(currentFindings, [...requested], incrementalFiles)
        : currentFindings.filter((finding) => !requested.has(finding.tool))
      : [];
    const analysisPath = scanRequest.scanRoot || folder.uri.fsPath;
    const cfg = vscode.workspace.getConfiguration('securityCenter');
    let activeExecution = null;
    dashboardProvider.setData(currentFindings, currentScanStatuses, { ...currentDashboardOptions, workspace: folder.name, scanStatus: 'running', backendStatus: 'checking', previousResultsVisible: true, snapshotAvailable: currentFindings.length > 0 });
    try {
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Security Center : analyse multi-outils', cancellable: true }, async (progress, cancellationToken) => {
      try {
        const abortController = new AbortController();
        cancellationToken.onCancellationRequested(() => abortController.abort());
        const timeoutMs = cfg.get('scan.timeoutSeconds', 300) * 1000;
        const scans = [{
          tool: 'Semgrep',
          execute: () => runSemgrep({
            workspacePath: analysisPath,
            mode: cfg.get('semgrep.command', 'auto'),
            config: [cfg.get('semgrep.config', 'p/security-audit'), projectPolicy?.semgrepCustomRules].filter(Boolean),
            exclusions: {
              files: [...(projectPolicy?.exclusions.global_files || []), ...(projectPolicy?.exclusions.semgrep_files || [])],
              rules: projectPolicy?.exclusions.semgrep_rules || []
            },
            timeoutMs,
            signal: abortController.signal
          }),
          normalize: normalizeSemgrepOutput
        }];
        const historyEnabled = Boolean(projectPolicy?.gitleaksHistory && !incrementalFiles.length);
        const historyStateKey = `securityCenter.gitleaksHistoryHead:${folder.uri.fsPath}`;
        const historySinceCommit = historyEnabled && projectPolicy.gitleaksHistoryIncremental
          ? context.workspaceState.get(historyStateKey, '') : '';
        let currentGitHead = '';
        if (historyEnabled) {
          try {
            currentGitHead = (await execFileAsync('git', ['-C', folder.uri.fsPath, 'rev-parse', 'HEAD'], { windowsHide: true })).stdout.trim();
          } catch { /* Gitleaks will report a clear error if this is not a Git repository. */ }
        }
        if (cfg.get('gitleaks.enabled', true)) scans.push({
          tool: 'Gitleaks',
          execute: () => runGitleaks({
            workspacePath: analysisPath,
            mode: cfg.get('gitleaks.command', 'auto'),
            timeoutMs,
            signal: abortController.signal,
            history: historyEnabled,
            sinceCommit: historySinceCommit && historySinceCommit !== currentGitHead ? historySinceCommit : '',
            configPath: projectPolicy?.gitleaksConfig || '',
            exclusions: projectPolicy?.exclusions.global_files || []
          }),
          onSuccess: async () => {
            if (historyEnabled && currentGitHead) await context.workspaceState.update(historyStateKey, currentGitHead);
          },
          normalize: normalizeGitleaksOutput
        });
        if (cfg.get('trivy.enabled', true)) scans.push({
          tool: 'Trivy',
          execute: () => runTrivy({
            workspacePath: analysisPath,
            mode: cfg.get('trivy.command', 'auto'),
            timeoutMs,
            imageName: cfg.get('trivy.image', ''),
            exclusions: [...(projectPolicy?.exclusions.global_files || []), ...(projectPolicy?.exclusions.trivy_files || [])],
            signal: abortController.signal
          }),
          normalize: normalizeTrivyOutput
        });
        if (cfg.get('osv.enabled', true)) scans.push({
          tool: 'OSV-Scanner',
          execute: () => runOsv({ workspacePath: analysisPath, mode: cfg.get('osv.command', 'auto'), timeoutMs, signal: abortController.signal }),
          normalize: normalizeOsvOutput
        });
        // SonarQube analyses the whole project against a server, so it is
        // skipped on incremental runs where only changed files are copied.
        if (cfg.get('sonar.enabled', false) && !incrementalFiles.length) {
          const sonarToken = await context.secrets.get(SONAR_TOKEN_SECRET_KEY) || '';
          scans.push({
            tool: 'SonarQube',
            execute: () => runSonarQube({
              workspacePath: analysisPath,
              mode: projectPolicy?.sonarMode || cfg.get('sonar.mode', 'auto'),
              // The host URL never comes from the versioned policy file.
              hostUrl: cfg.get('sonar.hostUrl', 'http://127.0.0.1:9000'),
              projectKey: cfg.get('sonar.projectKey', ''),
              token: sonarToken,
              includeCodeSmells: projectPolicy?.sonarIncludeCodeSmells ?? cfg.get('sonar.includeCodeSmells', false),
              exclusions: projectPolicy?.exclusions.global_files || [],
              timeoutMs: Math.max(timeoutMs, cfg.get('sonar.timeoutSeconds', 900) * 1000),
              taskTimeoutMs: cfg.get('sonar.timeoutSeconds', 900) * 1000,
              signal: abortController.signal
            }),
            normalize: normalizeSonarQubeOutput
          });
        }
        // Snyk resolves dependencies for the whole project against its service,
        // so — like SonarQube — it is skipped on incremental runs where only the
        // changed files are copied into a temporary workspace.
        if (cfg.get('snyk.enabled', false) && !incrementalFiles.length) {
          const snykToken = await context.secrets.get(SNYK_TOKEN_SECRET_KEY) || '';
          scans.push({
            tool: 'Snyk',
            execute: () => runSnyk({
              workspacePath: analysisPath,
              mode: projectPolicy?.snykMode || cfg.get('snyk.mode', 'auto'),
              token: snykToken,
              includeOpenSource: projectPolicy?.snykCapabilities?.includeOpenSource ?? cfg.get('snyk.includeOpenSource', true),
              includeCode: projectPolicy?.snykCapabilities?.includeCode ?? cfg.get('snyk.includeCode', false),
              includeIaC: projectPolicy?.snykCapabilities?.includeIaC ?? cfg.get('snyk.includeIaC', false),
              exclusions: projectPolicy?.exclusions.global_files || [],
              timeoutMs: Math.max(timeoutMs, cfg.get('snyk.timeoutSeconds', 600) * 1000),
              signal: abortController.signal
            }),
            // What the account can actually do is only known after a real run,
            // so the setup page reads the outcome back from here.
            onSuccess: async (result) => {
              if (result?.payload?.capabilities) {
                await context.workspaceState.update('securityCenter.snykCapabilities', result.payload.capabilities);
              }
              for (const warning of result?.payload?.warnings || []) scanLog.appendLine(`Snyk — ${warning}`);
            },
            normalize: normalizeSnykOutput
          });
        }
        const zapRequested = cfg.get('zap.enabled', true)
          && (!requested || requested.has('ZAP'))
          && projectPolicy?.scanners?.ZAP !== false;
        let zapMode = projectPolicy?.zapOpenapi ? 'openapi' : projectPolicy?.zapActive ? 'active' : 'baseline';
        if (zapRequested && zapMode !== 'baseline') {
          const authorized = scanRequest.zapAuthorized === true || await dashboardProvider.requestZapAuthorization({
            mode: zapMode,
            target: cfg.get('zap.targetUrl', 'http://127.0.0.1:3000')
          });
          if (!authorized) {
            zapMode = 'baseline';
            scanLog.appendLine('ZAP — scan offensif refusé, exécution passive baseline à la place.');
          } else {
            const actor = cfg.get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
            const backendBaseUrl = cfg.get('backend.url', 'http://127.0.0.1:8765');
            await createAuditEvent(backendBaseUrl, {
              scan_id: currentScanId || 0,
              finding_id: `zap:${cfg.get('zap.targetUrl', 'http://127.0.0.1:3000')}`,
              action: `zap:${zapMode}:authorized`,
              actor,
              comment: 'Autorisation locale confirmée dans Security Center.'
            }).catch((error) => scanLog.appendLine(`ZAP — audit local indisponible : ${error.message}`));
            scanLog.appendLine(`ZAP — autorisation locale confirmée pour ${actor}, sans justification textuelle.`);
          }
        }
        let zapAuthEnv = process.env;
        if (zapRequested && projectPolicy?.zapAuth?.login
          && (!process.env[projectPolicy.zapAuth.usernameEnv] || !process.env[projectPolicy.zapAuth.passwordEnv])) {
          let username = await context.secrets.get(zapUsernameSecretKey);
          let password = await context.secrets.get(zapPasswordSecretKey);
          if (!username || !password) username = await vscode.window.showInputBox({
            title: 'Compte de test pour ZAP authentifié',
            prompt: 'Adresse e-mail ou identifiant du compte Juice Shop local',
            ignoreFocusOut: true
          });
          if (!username) throw new Error('Scan ZAP annulé : identifiant du compte de test non fourni.');
          if (!password) password = await vscode.window.showInputBox({
            title: 'Mot de passe du compte de test ZAP',
            prompt: 'Ce mot de passe reste uniquement en mémoire pendant le scan.',
            password: true,
            ignoreFocusOut: true
          });
          if (!password) throw new Error('Scan ZAP annulé : mot de passe du compte de test non fourni.');
          await context.secrets.store(zapUsernameSecretKey, username.trim());
          await context.secrets.store(zapPasswordSecretKey, password);
          zapAuthEnv = { ...process.env, [projectPolicy.zapAuth.usernameEnv]: username.trim(), [projectPolicy.zapAuth.passwordEnv]: password };
        }
        if (zapRequested) scans.push({
          tool: 'ZAP',
          mode: zapMode,
          authenticated: Boolean(projectPolicy?.zapAuth?.login || projectPolicy?.zapContext),
          execute: () => runZap({
            targetUrl: cfg.get('zap.targetUrl', 'http://127.0.0.1:3000'),
            timeoutMs,
            signal: abortController.signal,
            excludedRoutes: projectPolicy?.exclusions.zap_routes || [],
            mode: zapMode,
            engine: projectPolicy?.zapEngine || 'auto',
            localPath: projectPolicy?.zapLocalPath || '',
            workspacePath: folder.uri.fsPath,
            openapi: projectPolicy?.zapOpenapi || '',
            context: projectPolicy?.zapContext || '',
            user: projectPolicy?.zapUser || '',
            auth: projectPolicy?.zapAuth,
            authEnv: zapAuthEnv,
            // Real lifecycle from ZAP's own API responses. Every state and every
            // percentage that reaches the page comes through here.
            onLifecycle: (event) => publishDynamicLifecycle(event)
          }),
          normalize: (payload, workspacePath) => normalizeZapOutput(
            payload,
            workspacePath,
            cfg.get('zap.targetUrl', 'http://127.0.0.1:3000')
          )
        });
        if (requested) {
          for (let index = scans.length - 1; index >= 0; index -= 1) {
            if (!requested.has(scans[index].tool)) scans.splice(index, 1);
          }
        }
        if (projectPolicy) {
          for (let index = scans.length - 1; index >= 0; index -= 1) {
            if (projectPolicy.scanners[scans[index].tool] === false) scans.splice(index, 1);
          }
        }
        if (!scans.length) throw new Error('Aucun scanner actif n’a été sélectionné.');
        executionSequence += 1;
        await context.workspaceState.update('securityCenter.executionSequence', executionSequence);
        activeExecution = createExecution({
          executionId: `local-execution-${executionSequence}`,
          requestedTools: scans.map((scan) => scan.tool),
          allTools: [...ALL_SCANNER_TOOLS],
          parentExecutionId: currentSecuritySnapshot.lastExecutionId
        });
        currentSecuritySnapshot = beginRefresh(currentSecuritySnapshot, activeExecution);
        const renderSnapshotProgress = (extra = {}) => {
          const projection = projectSnapshot(currentSecuritySnapshot);
          currentFindings = projection.findings;
          currentScanStatuses = projection.scanners;
          dashboardProvider.setData(currentFindings, currentScanStatuses, {
            ...currentDashboardOptions,
            workspace: folder.name,
            scanStatus: 'running',
            backendStatus: 'checking',
            snapshotAvailable: Object.keys(currentSecuritySnapshot.resultSets || {}).length > 0,
            activeExecution,
            executionType: activeExecution.type,
            ...extra
          });
        };
        renderSnapshotProgress();
        // Keep the last known results visible while scanners are running. Each
        // successful scanner replaces only its own previous results.
        const findings = [...previousFindings];
        const failures = [];
        const scanStatuses = [];
        let cancelled = false;
        const scanStartedAt = Date.now();
        scanLog.appendLine(`[${new Date().toISOString()}] Analyse démarrée — ${folder.uri.fsPath}`);
        scanLog.appendLine(`Scanners : ${scans.map((scan) => scan.tool).join(', ')}`);
        const scannerIdentity = (scan) => ({ tool: scan.tool, ...(scan.tool === 'ZAP' ? { mode: scan.mode, authenticated: scan.authenticated } : {}) });
        const liveStatuses = scans.map((scan) => ({ ...scannerIdentity(scan), status: 'pending' }));
        let completedProgress = 0;
        const runScanner = async (scan, index) => {
          const scannerStartedAt = Date.now();
          const actor = cfg.get('audit.actor', '') || process.env.USERNAME || process.env.USER || 'local-user';
          const backendBaseUrl = cfg.get('backend.url', 'http://127.0.0.1:8765');
          try {
            scanLog.appendLine(`[${new Date().toISOString()}] ${scan.tool} — démarrage`);
            liveStatuses[index] = { ...scannerIdentity(scan), status: 'running', startedAt: new Date(scannerStartedAt).toISOString() };
            // A dynamic run gets its identity before it produces anything, so the
            // lifecycle events that follow have a campaign to belong to.
            if (scan.tool === 'ZAP') beginZapCampaign();
            currentSecuritySnapshot = updateRefresh(currentSecuritySnapshot, scan.tool, 'running', { startedAt: new Date(scannerStartedAt).toISOString() });
            
            const isRetry = activeExecution && activeExecution.type === 'retry';
            await createAuditEvent(backendBaseUrl, {
              scan_id: currentScanId || 0,
              action: isRetry ? 'scanner.retry' : 'scanner.run.started',
              actor,
              comment: `Scanner ${scan.tool} démarré (${isRetry ? 'mode retry' : 'mode standard'}).`,
              metadata: { tool: scan.tool, mode: activeExecution?.type || 'full' }
            }).catch(() => {});

            renderSnapshotProgress({
              scanDurationMs: Date.now() - scanStartedAt,
              scanStartedAt: new Date(scanStartedAt).toISOString(),
            });
            progress.report({ message: `${liveStatuses.filter((item) => item.status === 'running').map((item) => item.tool).join(' + ')}` });
            const result = await scan.execute();
            if (scan.onSuccess) await scan.onSuccess(result);
            if (result.stderr?.trim()) scanLog.appendLine(`${scan.tool} — informations : ${result.stderr.trim()}`);
            const scanFindings = scan.normalize(result.payload, folder.uri.fsPath);
            for (let findingIndex = findings.length - 1; findingIndex >= 0; findingIndex -= 1) {
              if (findings[findingIndex].tool === scan.tool) findings.splice(findingIndex, 1);
            }
            findings.push(...scanFindings);
            const details = scan.tool === 'Trivy'
              ? `${scanFindings.filter((item) => item.category === 'dependency').length} CVE • ${scanFindings.filter((item) => item.category === 'misconfiguration').length} configuration(s)`
              // Snyk reports three capabilities at once: the breakdown makes an
              // unavailable Snyk Code visible instead of looking like zero risk.
              : scan.tool === 'Snyk'
                ? `${scanFindings.filter((item) => item.snykCapability === 'openSource').length} dépendance(s) • ${scanFindings.filter((item) => item.snykCapability === 'code').length} code • ${scanFindings.filter((item) => item.snykCapability === 'iac').length} IaC`
                : `${scanFindings.length} résultat(s)`;
            const durationMs = Date.now() - scannerStartedAt;
            scanStatuses[index] = { ...scannerIdentity(scan), status: 'completed', details, durationMs };
            liveStatuses[index] = { ...scannerIdentity(scan), status: 'completed', details, durationMs };
            // A ZAP run that completed is proof the target answered. Recording it
            // keeps the target badge from reading « non vérifiée » right next to a
            // finished dynamic scan.
            if (scan.tool === 'ZAP') {
              refreshDynamicTargetModel('online', { source: 'zap-scan' });
              // The campaign closes with the findings this run is answerable for.
              await finishZapCampaign(DYNAMIC_STATUS.COMPLETED, {
                findingIds: scanFindings.map((finding) => finding.id)
              });
            }
            currentSecuritySnapshot = updateRefresh(currentSecuritySnapshot, scan.tool, 'completed', { details, durationMs });
            scanLog.appendLine(`[${new Date().toISOString()}] ${scan.tool} — terminé en ${Math.round(durationMs / 1000)} s (${scanFindings.length} résultat(s))`);

            await createAuditEvent(backendBaseUrl, {
              scan_id: currentScanId || 0,
              action: 'scanner.run.completed',
              actor: 'System',
              comment: `Scanner ${scan.tool} complété avec succès.`,
              metadata: { tool: scan.tool, durationMs }
            }).catch(() => {});

          } catch (error) {
            const durationMs = Date.now() - scannerStartedAt;
            if (abortController.signal.aborted) {
              cancelled = true;
              scanStatuses[index] = { ...scannerIdentity(scan), status: 'cancelled', error: error.message, durationMs };
              liveStatuses[index] = { ...scannerIdentity(scan), status: 'cancelled', error: error.message, durationMs };
              if (scan.tool === 'ZAP') await finishZapCampaign(DYNAMIC_STATUS.CANCELLED);
              currentSecuritySnapshot = updateRefresh(currentSecuritySnapshot, scan.tool, 'cancelled', { error: error.message, durationMs });
              scanLog.appendLine(`[${new Date().toISOString()}] Analyse annulée par l’utilisateur.`);
              return;
            }
            failures.push(`${scan.tool}: ${error.message}`);
            const previousForFailedTool = previousFindings.filter((finding) => finding.tool === scan.tool);
            for (let findingIndex = 0; findingIndex < findings.length; findingIndex += 1) {
              if (findings[findingIndex].tool === scan.tool) {
                findings[findingIndex] = { ...findings[findingIndex], staleFromPreviousScan: true };
              }
            }
            const existingKeys = new Set(findings.map(findingKey));
            for (const previousFinding of previousForFailedTool) {
              if (!existingKeys.has(findingKey(previousFinding))) findings.push({ ...previousFinding, staleFromPreviousScan: true });
            }
            scanStatuses[index] = { ...scannerIdentity(scan), status: 'failed', error: error.message, durationMs };
            liveStatuses[index] = { ...scannerIdentity(scan), status: 'failed', error: error.message, durationMs };
            if (scan.tool === 'ZAP') await finishZapCampaign(DYNAMIC_STATUS.FAILED);
            currentSecuritySnapshot = updateRefresh(currentSecuritySnapshot, scan.tool, 'failed', { error: error.message, durationMs });
            scanLog.appendLine(`[${new Date().toISOString()}] ${scan.tool} — ÉCHEC : ${error.message}`);

            await createAuditEvent(backendBaseUrl, {
              scan_id: currentScanId || 0,
              action: 'scanner.run.failed',
              actor: 'System',
              comment: `Échec du scanner ${scan.tool} : ${error.message}`,
              metadata: { tool: scan.tool, error: error.message, durationMs }
            }).catch(() => {});

          } finally {
            completedProgress += 1;
            progress.report({ increment: 100 / scans.length, message: `${completedProgress}/${scans.length} scanner(s) terminé(s)` });
            renderSnapshotProgress({
              scanDurationMs: Date.now() - scanStartedAt,
              scanStartedAt: new Date(scanStartedAt).toISOString()
            });
          }
        };
        const staticEntries = scans.map((scan, index) => ({ scan, index })).filter((entry) => entry.scan.tool !== 'ZAP');
        const zapEntries = scans.map((scan, index) => ({ scan, index })).filter((entry) => entry.scan.tool === 'ZAP');
        await runWithConcurrency(staticEntries, projectPolicy?.maxParallelScanners || 2, (entry) => runScanner(entry.scan, entry.index), abortController.signal);
        if (!abortController.signal.aborted) await runWithConcurrency(zapEntries, 1, (entry) => runScanner(entry.scan, entry.index), abortController.signal);
        if (abortController.signal.aborted) {
          cancelled = true;
          for (let index = 0; index < scans.length; index += 1) {
            if (!scanStatuses[index]) {
              scanStatuses[index] = { tool: scans[index].tool, status: 'cancelled', error: 'Non exécuté après annulation.', durationMs: 0 };
              liveStatuses[index] = scanStatuses[index];
            }
          }
        }
        progress.report({ message: 'Finalisation' });
        const uniqueFindings = deduplicateFindings(findings);
        const correlated = correlateFindings(uniqueFindings);
        const savedStatuses = context.workspaceState.get('securityCenter.findingStatuses', {});
        const validatedFindings = validatedAfterScan(previousFindings, correlated.findings, scanStatuses);
        for (const finding of validatedFindings) savedStatuses[findingKey(finding)] = 'validated';
        if (validatedFindings.length) await context.workspaceState.update('securityCenter.findingStatuses', savedStatuses);
        const triagedFindings = retainValidatedFindings(applyFindingStatuses(correlated.findings, savedStatuses), validatedFindings);
        const policyResult = evaluatePolicy(triagedFindings, projectPolicy);
        currentSecuritySnapshot = completeExecution(currentSecuritySnapshot, activeExecution, triagedFindings, scanStatuses);
        const completedProjection = projectSnapshot(currentSecuritySnapshot);
        currentFindings = completedProjection.findings;
        currentScanStatuses = completedProjection.scanners;
        const consolidatedCorrelated = correlateFindings(currentFindings);
        currentFindings = consolidatedCorrelated.findings;
        const consolidatedPolicyResult = evaluatePolicy(currentFindings, projectPolicy);
        // Security intelligence runs on the consolidated result, through the
        // very same services the headless CLI calls. The verdicts are merged
        // back onto the findings so the tree, the dashboard and the details
        // page all show them without a parallel model.
        let intelligenceState = { status: 'completed' };
        try {
          progress.report({ message: 'Corrélation et priorisation' });
          const analysis = await analyzeWorkspace({
            workspacePath: folder.uri.fsPath, findings: currentFindings,
            policy: projectPolicy, signal: abortController.signal
          });
          currentFindings = mergeIntelligence(currentFindings, analysis);
          currentPipelineResult = buildPipelineResult({
            scanId: String(currentScanId || activeExecution?.executionId || ''),
            workspace: folder.uri.fsPath,
            startedAt: new Date(scanStartedAt).toISOString(),
            scanners: currentScanStatuses,
            rawFindings: currentFindings,
            analysis,
            artifacts: currentPipelineArtifacts,
            failures,
            intelligence: intelligenceState
          });
          // One persisted record per scan: summaries and correlation groups
          // together, so no tab can ever read a different scan than another.
          await context.workspaceState.update(
            PIPELINE_STATE_KEY,
            {
              ...pipelineStateFor(currentPipelineResult, analysis, currentPipelineArtifacts),
              // The rules this verdict was reached with, so a later policy edit
              // is visible as such instead of silently rewriting history.
              policyHash: projectPolicy ? policyGateHash(projectPolicy) : ''
            }
          );
          scanLog.appendLine(`Pipeline — ${analysis.clusters.length} corrélation(s), ${analysis.priority.distribution.P0} P0 / ${analysis.priority.distribution.P1} P1, Policy Gate ${analysis.policy.status}.`);
          if (analysis.policy.configured) {
            await createAuditEvent(cfg.get('backend.url', 'http://127.0.0.1:8765'), {
              scan_id: currentScanId || 0,
              action: analysis.policy.status === 'BLOCK' ? 'policy.gate.blocked' : 'policy.gate.evaluated',
              actor: 'System',
              comment: analysis.policy.summary,
              metadata: {
                status: analysis.policy.status,
                // The verdict is tied to the scan it judged, so a historical
                // record can never be read against a different scan.
                scanId: currentPipelineResult.scanId,
                policyHash: projectPolicy ? policyGateHash(projectPolicy) : '',
                violations: analysis.policy.violations.length,
                warnings: analysis.policy.warnings.length
              }
            }).catch(() => {});
          }
          renderPipelinePage().catch(() => {});
        } catch (error) {
          // Security Intelligence is additive: a failure here degrades the
          // decision layer and is reported as such, but the scanner results
          // stay exactly as the scanners produced them.
          intelligenceState = { status: 'failed', error: summarizeScannerError(error.message), failedAt: new Date().toISOString() };
          currentPipelineResult = buildPipelineResult({
            scanId: String(currentScanId || activeExecution?.executionId || ''),
            workspace: folder.uri.fsPath,
            startedAt: new Date(scanStartedAt).toISOString(),
            scanners: currentScanStatuses,
            rawFindings: currentFindings,
            analysis: {},
            artifacts: currentPipelineArtifacts,
            failures,
            intelligence: intelligenceState
          });
          await context.workspaceState.update(
            PIPELINE_STATE_KEY,
            pipelineStateFor(currentPipelineResult, {}, currentPipelineArtifacts)
          );
          scanLog.appendLine(`Pipeline — Security Intelligence indisponible : ${error.message}. Les résultats des scanners sont conservés.`);
          vscode.window.showWarningMessage(`Security Center : corrélation et priorisation indisponibles — ${intelligenceState.error}. Les résultats des scanners restent affichés.`);
          renderPipelinePage().catch(() => {});
        }
        publishDiagnostics(diagnostics, currentFindings); provider.setFindings(currentFindings, currentScanStatuses);
        let backendStatus = 'online';
        try {
          const storedScan = await saveScanResult(cfg.get('backend.url', 'http://127.0.0.1:8765'), {
            workspace: folder.uri.fsPath,
            findings: currentFindings,
            scanners: currentScanStatuses,
            correlations: consolidatedCorrelated.correlations
          });
          currentScanId = storedScan.scan_id;
          if (previousScanId && validatedFindings.length) {
            const validationUpdates = await Promise.allSettled(validatedFindings.map((finding) =>
              updateFindingStatus(cfg.get('backend.url', 'http://127.0.0.1:8765'), previousScanId, finding.id, 'validated')
            ));
            const failedUpdates = validationUpdates.filter((result) => result.status === 'rejected').length;
            if (failedUpdates) scanLog.appendLine(`Revalidation : ${failedUpdates} preuve(s) non persistée(s) dans le scan précédent.`);
            
            const backendBaseUrl = cfg.get('backend.url', 'http://127.0.0.1:8765');
            for (const finding of validatedFindings) {
              await createAuditEvent(backendBaseUrl, {
                scan_id: currentScanId || 0,
                finding_id: finding.id,
                action: 'finding.fixed',
                actor: 'System',
                comment: `Alerte résolue détectée par le scanner ${finding.tool}.`,
                metadata: { tool: finding.tool }
              }).catch(() => {});
              await createAuditEvent(backendBaseUrl, {
                scan_id: currentScanId || 0,
                finding_id: finding.id,
                action: 'finding.fix.validated',
                actor: 'System',
                comment: `Correction validée par Security Center pour l'alerte ${finding.id}.`,
                metadata: { tool: finding.tool }
              }).catch(() => {});
            }
          }
        } catch {
          backendStatus = 'offline';
          currentScanId = null;
        }
        currentDashboardOptions = {
          workspace: folder.name,
          scanStatus: cancelled ? 'cancelled' : failures.length ? 'partial' : 'completed',
          backendStatus,
          correlations: consolidatedCorrelated.correlations,
          httpScenarioCount: currentDashboardOptions.httpScenarioCount || 0,
          httpScenarios: currentDashboardOptions.httpScenarios || [],
          burpConnected: Boolean(currentDashboardOptions.burpConnected),
          scanDurationMs: Date.now() - scanStartedAt,
          scanStartedAt: new Date(scanStartedAt).toISOString(),
          policyResult: consolidatedPolicyResult,
          snapshotAvailable: Object.keys(currentSecuritySnapshot.resultSets || {}).length > 0,
          lastExecution: currentSecuritySnapshot.lastExecution,
          executionType: activeExecution.type
        };
        dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
        await saveLocalScanCache();
        // History stores the enriched findings: an archived scan keeps its
        // correlation, reachability and priority instead of losing them.
        const enrichedById = new Map(currentFindings.map((finding) => [finding.id, finding]));
        await addCurrentScanToLocalHistory({
          findings: triagedFindings
            .filter((finding) => activeExecution.scanners.includes(finding.tool) && scanStatuses.some((scanner) => scanner.tool === finding.tool && scanner.status === 'completed'))
            .map((finding) => enrichedById.get(finding.id) || finding),
          scanners: scanStatuses,
          dashboardOptions: {
            ...currentDashboardOptions,
            executionId: activeExecution.executionId,
            executionType: activeExecution.type,
            parentExecutionId: activeExecution.parentExecutionId || null,
            consolidatedSnapshot: false
          }
        });
        scanLog.appendLine(`[${new Date().toISOString()}] Analyse terminée — ${currentFindings.length} résultat(s) consolidé(s), ${failures.length} échec(s)`);
        const activeCount = currentFindings.filter(isActiveFinding).length;
        const summary = summarizeFindings(currentFindings.filter(isActiveFinding)) || 'aucune vulnérabilité active';
        const completedCount = scanStatuses.filter((scanner) => scanner.status === 'completed').length;
        vscode.window.showInformationMessage(`Security Center : ${summary} — ${completedCount}/${scans.length} outil(s) terminé(s).`);
        if (cancelled) vscode.window.showWarningMessage(`Security Center : scan partiel — ${completedCount}/${scans.length} scanners terminés, ${scanStatuses.filter((scanner) => scanner.status === 'cancelled').map((scanner) => scanner.tool).join(', ')} annulé(s).`);
        if (validatedFindings.length) vscode.window.showInformationMessage(`Security Center : ${validatedFindings.length} correction(s) validée(s) automatiquement — alertes absentes après re-scan réussi.`);
        if (failures.length) vscode.window.showWarningMessage(`Security Center : scan partiel — ${failures.join(' | ')}`);
        if (policyResult && !policyResult.passed) {
          vscode.window.showWarningMessage(`Security Center : politique projet non respectée — ${policyResult.reasons.join(' ; ')}.`);
        }
      } catch (error) {
        const projection = projectSnapshot(currentSecuritySnapshot);
        currentFindings = projection.findings;
        currentScanStatuses = projection.scanners;
        dashboardProvider.setData(currentFindings, currentScanStatuses, { ...currentDashboardOptions, workspace: folder.name, scanStatus: 'failed', backendStatus: 'unknown', snapshotAvailable: currentFindings.length > 0, activeExecution });
        vscode.window.showErrorMessage(`Security Center : ${error.message}`);
      }
      });
    } finally {
      scanInProgress = false;
      currentScanRunning = false;
      liveCompanionProvider.render();
    }
  }));

  const configuredBackendUrl = vscode.workspace.getConfiguration('securityCenter').get('backend.url', 'http://127.0.0.1:8765');
  Promise.all([listHttpScenarios(configuredBackendUrl), getBurpStatus(configuredBackendUrl)]).then(([scenarios, burpStatus]) => {
    currentDashboardOptions = {
      ...currentDashboardOptions,
      workspace: vscode.workspace.workspaceFolders?.[0]?.name || 'Aucun workspace',
      backendStatus: 'online',
      httpScenarioCount: scenarios.length,
      httpScenarios: scenarios,
      burpConnected: Boolean(burpStatus.connected),
      burpSession: captureSessionFrom(burpStatus, { campaign: currentDynamicCampaign() }),
      burpStatus,
      burpEndpoint: `${configuredBackendUrl.replace(/\/$/, '')}/api/v1/integrations/burp`
    };
    dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
  }).catch(() => {
    // Le dashboard reste utilisable même si le backend local est arrêté.
  });

  const burpPolling = setInterval(() => {
    Promise.all([listHttpScenarios(configuredBackendUrl), getBurpStatus(configuredBackendUrl)]).then(([scenarios, burpStatus]) => {
      const previousCount = currentDashboardOptions.httpScenarioCount || 0;
      const previousBurpConnected = Boolean(currentDashboardOptions.burpConnected);
      currentDashboardOptions = {
        ...currentDashboardOptions,
        backendStatus: 'online',
        httpScenarioCount: scenarios.length,
        httpScenarios: scenarios,
        burpConnected: Boolean(burpStatus.connected),
      burpSession: captureSessionFrom(burpStatus, { campaign: currentDynamicCampaign() }),
        burpStatus,
        burpEndpoint: `${configuredBackendUrl.replace(/\/$/, '')}/api/v1/integrations/burp`
      };
      if (scenarios.length !== previousCount || Boolean(burpStatus.connected) !== previousBurpConnected) {
        dashboardProvider.setData(currentFindings, currentScanStatuses, currentDashboardOptions);
      }
    }).catch(() => {
      // Une indisponibilité temporaire du backend ne doit pas interrompre VS Code.
    });
  }, 5000);
  context.subscriptions.push({ dispose: () => clearInterval(burpPolling) });
}

function deactivate() {
  liveSecurityService?.dispose();
  liveSecurityService = undefined;
}
module.exports = { activate, deactivate, toDiagnostic };
