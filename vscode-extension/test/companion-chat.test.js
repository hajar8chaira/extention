'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const chat = require('../src/companion-chat');
const { CHAT_STATE, ROLE, buildAssistantContext, contextIndicator, quickQuestionsFor, detectFixRequest, buildAssistantMessages, chatMessage, fixRoutingReply, ASSISTANT_SYSTEM_PROMPT } = chat;
const { renderCompanionChatHtml } = require('../src/companion-chat-page');

const src = (file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8');

const SECRET = 'AKIAIOSFODNN7EXAMPLE';
const secretFinding = (over = {}) => ({
  id: 'gitleaks:generic-api-key:data/static/users.yml:88',
  tool: 'Gitleaks', ruleId: 'generic-api-key', cwe: 'CWE-798',
  title: `API key detected: ${SECRET}`,
  file: 'data/static/users.yml', startLine: 88,
  rawSeverity: 'HIGH', triageStatus: 'new', sourceContext: 'production',
  evidence: `password: SuperSecret123!`,
  priority: { score: 85, code: 'P0', reasons: ['secret exposed in production'] },
  ...over
});

const sonarFinding = (over = {}) => ({
  id: 'sonarqube:javascript:S4790:Gruntfile.js:75', tool: 'SonarQube', ruleId: 'javascript:S4790',
  title: 'Weak hashing', file: 'Gruntfile.js', startLine: 75, rawSeverity: 'HIGH', triageStatus: 'new', ...over
});

// ------------------------------------------------------------------ contexte

test('companion : le contexte utilise le finding courant', () => {
  const context = buildAssistantContext({ surface: 'finding', finding: sonarFinding(), findings: [sonarFinding()], similarFindingCount: 53 });
  assert.equal(context.surface, 'finding');
  assert.equal(context.finding.scanner, 'SonarQube');
  assert.equal(context.finding.rule, 'javascript:S4790');
  assert.equal(context.finding.file, 'Gruntfile.js');
  assert.equal(context.finding.line, 75);
  assert.equal(context.finding.similarFindingCount, 53);
});

test('companion : changer de finding change le contexte', () => {
  const first = buildAssistantContext({ surface: 'finding', finding: sonarFinding() });
  const second = buildAssistantContext({ surface: 'finding', finding: secretFinding() });
  assert.notEqual(first.finding.rule, second.finding.rule);
  assert.equal(second.finding.scanner, 'Gitleaks');
  assert.notDeepEqual(contextIndicator(first), contextIndicator(second));
  assert.match(contextIndicator(second).label, /Gitleaks/);
  assert.match(contextIndicator(second).detail, /users\.yml:88/);
});

test('companion : le contexte Dashboard differe du contexte finding', () => {
  const dashboard = buildAssistantContext({ surface: 'dashboard', findings: [sonarFinding(), secretFinding()] });
  assert.equal(dashboard.finding, undefined, 'aucun finding courant sur le dashboard');
  assert.equal(dashboard.workspaceFindingCount, 2);
  assert.ok(dashboard.severityBreakdown, 'la posture remplace le detail');
  // La liste complete n'est jamais envoyee.
  assert.ok(dashboard.topFindings.length <= 5);
});

test('companion : Scanner Details fournit un contexte propre au scanner', () => {
  const context = buildAssistantContext({
    surface: 'scanner-setup',
    scanners: [{ tool: 'SonarQube', status: 'failed', error: 'serveur injoignable' }, { tool: 'Semgrep', status: 'completed', details: '12 résultat(s)' }]
  });
  assert.equal(context.scanners.length, 2);
  assert.equal(context.scanners[0].status, 'failed');
  assert.match(context.scanners[0].error, /injoignable/);
  assert.equal(context.finding, undefined);
});

test('companion : Runtime et Infrastructure exposent leur modele normalise', () => {
  const runtime = buildAssistantContext({
    surface: 'runtime',
    runtime: { provider: { label: 'Wazuh' }, connectionStatus: 'online', credentialsConfigured: true, endpointSummary: { total: 2, active: 1 }, alertSummary: { critical: 1 } }
  });
  assert.equal(runtime.runtime.provider, 'Wazuh');
  assert.equal(runtime.runtime.credentialsConfigured, true);
  assert.equal(runtime.runtime.endpoints.active, 1);

  const infra = buildAssistantContext({
    surface: 'infrastructure',
    infrastructure: { label: 'Prometheus', status: 'degraded', metrics: { cpu: { available: false }, memory: { available: true, display: '3.4 GB / 9.7 GB' } } }
  });
  assert.equal(infra.infrastructure.cpu, 'unavailable', 'une metrique absente reste indisponible');
  assert.equal(infra.infrastructure.memory, '3.4 GB / 9.7 GB');
});

test('companion : une preuve absente reste absente et n est jamais fabriquee', () => {
  const context = buildAssistantContext({ surface: 'finding', finding: sonarFinding() });
  assert.equal(context.finding.reachability, undefined, 'aucune atteignabilite inventee');
  assert.equal(context.finding.verification, undefined, 'aucune verification inventee');
  assert.equal(context.finding.cwe, undefined, 'aucun CWE invente');
  // Et le contrat systeme impose de le dire.
  assert.match(ASSISTANT_SYSTEM_PROMPT, /dis-le explicitement/);
  assert.match(ASSISTANT_SYSTEM_PROMPT, /N’invente jamais de CVE/);
  assert.match(ASSISTANT_SYSTEM_PROMPT, /sans preuve/);
});

// ------------------------------------------------------------------- secrets

test('companion : aucune valeur de secret n entre dans le contexte', () => {
  const context = buildAssistantContext({ surface: 'finding', finding: secretFinding(), findings: [secretFinding()] });
  const serialized = JSON.stringify(context);
  assert.ok(!serialized.includes('SuperSecret123'), 'la preuve brute ne doit pas passer');
  assert.ok(!serialized.includes(SECRET), 'la valeur citee dans le titre ne doit pas passer');
  // Le message envoye au modele est redige a partir de ce contexte.
  const messages = buildAssistantMessages({ context, question: `Explique ${SECRET}` });
  const payload = JSON.stringify(messages);
  assert.ok(!payload.includes('SuperSecret123'));
  assert.ok(!payload.includes(SECRET), 'un secret colle par l utilisateur est masque aussi');
});

test('companion : aucune valeur de SecretStorage n atteint le modele', () => {
  const context = buildAssistantContext({
    surface: 'runtime',
    runtime: { provider: { label: 'Wazuh' }, credentialsConfigured: true, password: 'wazuh-pass', token: 'abc123' }
  });
  const serialized = JSON.stringify(context);
  assert.ok(!serialized.includes('wazuh-pass'));
  assert.ok(!serialized.includes('abc123'));
  assert.equal(context.runtime.credentialsConfigured, true, 'seul le booleen est transmis');
  // Le contrat l'exige explicitement.
  assert.match(ASSISTANT_SYSTEM_PROMPT, /Ne révèle aucun secret/);
});

test('companion : un secret expose n est pas « corrige » par un masque', () => {
  assert.match(ASSISTANT_SYSTEM_PROMPT, /révoquer\/renouveler/);
  assert.match(ASSISTANT_SYSTEM_PROMPT, /Remplacer la valeur par un masque ne corrige rien/);
});

// ------------------------------------------------------- separation des roles

test('companion : le chat ne modifie jamais de fichier', () => {
  const chatSource = src('companion-chat.js');
  const pageSource = src('companion-chat-page.js');
  for (const forbidden of ['applyEdit', 'WorkspaceEdit', 'writeFile', 'fs.', 'generateOllamaFix', 'parseUnifiedDiff', 'applyParsedPatch']) {
    assert.ok(!chatSource.includes(forbidden), `companion-chat ne doit pas utiliser ${forbidden}`);
    assert.ok(!pageSource.includes(forbidden), `companion-chat-page ne doit pas utiliser ${forbidden}`);
  }
  assert.match(ASSISTANT_SYSTEM_PROMPT, /Tu ne modifies jamais de fichier/);
});

test('companion : une demande de correction est routee vers le flux existant', () => {
  for (const question of ['Corrige cette vulnérabilité', 'peux-tu réparer ça', 'apply a patch', 'fix this']) {
    assert.equal(detectFixRequest(question), true, `${question} doit etre detecte`);
  }
  for (const question of ['Explique ce finding', 'Pourquoi cette priorité ?', 'Combien d’agents actifs ?']) {
    assert.equal(detectFixRequest(question), false, `${question} ne doit pas etre detecte`);
  }
  const reply = fixRoutingReply();
  assert.match(reply, /Je n’applique pas de correction/);
  assert.match(reply, /confirmation explicite/);
  assert.match(reply, /Proposer une correction/);
  // Et l'extension route bien vers la commande existante, sans l'executer seule.
  const extension = src('extension.js');
  assert.match(extension, /if \(detectFixRequest\(text\)\)/);
  assert.match(extension, /message\.action === 'generateFix'[\s\S]{0,160}executeCommand\('securityCenter\.generateAiFix'/);
});

test('companion : une demande de correction n atteint jamais le modele', () => {
  const extension = src('extension.js');
  const ask = extension.match(/async function askCompanion\(question\)[\s\S]*?\n  \}/)[0];
  const guard = ask.indexOf('detectFixRequest');
  const call = ask.indexOf('generateAssistantReply');
  assert.ok(guard > -1 && call > guard, 'le routage precede tout appel au modele');
  assert.match(ask, /return renderCompanionChat\(\);/);
});

// ------------------------------------------------------------- deterministe

test('companion : les findings similaires restent deterministes', () => {
  const extension = src('extension.js');
  // Le compte vient des findings reels, pas du modele.
  assert.match(extension, /currentFindings\.filter\(\(candidate\) => candidate\.ruleId && candidate\.ruleId === finding\.ruleId\)\.length/);
  // L'action « Montre-moi » existante n'est pas remplacee.
  const card = src('companion-assistant-card.js');
  assert.match(card, /ASSISTANT_INTENTS/);
  assert.ok(card.includes('similar') || card.includes('Montre'), 'la fonctionnalite existante est preservee');
});

test('companion : la carte compacte conserve ses actions et gagne une seule entree', () => {
  const card = src('companion-assistant-card.js');
  assert.match(card, /class="sc-assistant-openchat" data-assistant-post='\{"type":"openCompanionChat"\}'/);
  // Le type est ajoute a l'allowlist existante, pas contourne.
  assert.match(card, /ASSISTANT_POST_TYPES = Object\.freeze\(\['generateAiFix', 'verifyFix', 'findingCode', 'action', 'openCompanionChat'\]\)/);
  // Les intentions existantes restent.
  assert.match(card, /sc-assistant-ask/);
  assert.match(card, /sc-assistant-intent/);
});

// -------------------------------------------------------------------- etats

test('companion : Ollama indisponible produit un etat assistant seulement', () => {
  const html = renderCompanionChatHtml({ state: CHAT_STATE.ERROR, error: 'Assistant IA local indisponible.' }, 'n');
  assert.match(html, /chat-state error/);
  assert.match(html, /Assistant IA local indisponible/);
  // L'erreur est confinee : rien d'autre n'est marque en echec.
  const extension = src('extension.js');
  const ask = extension.match(/async function askCompanion\(question\)[\s\S]*?\n  \}/)[0];
  for (const forbidden of ['currentFindings =', 'saveLocalScanCache', 'currentSecuritySnapshot', 'scanWorkspace']) {
    assert.ok(!ask.includes(forbidden), `une erreur de chat ne doit pas toucher ${forbidden}`);
  }
});

test('companion : les etats de chargement sont explicites et empechent le double envoi', () => {
  const thinking = renderCompanionChatHtml({ state: CHAT_STATE.THINKING, cancellable: true }, 'n');
  assert.match(thinking, /Le Companion réfléchit…/);
  assert.match(thinking, /id="chat-send" disabled/);
  assert.match(thinking, /data-chat-action="cancel"/);
  const idle = renderCompanionChatHtml({ state: CHAT_STATE.IDLE }, 'n');
  assert.doesNotMatch(idle, /id="chat-send" disabled/);
  assert.doesNotMatch(idle, /data-chat-action="cancel"/, 'pas de bouton mort hors generation');
  const page = src('companion-chat-page.js');
  assert.match(page, /if \(!question \|\| \(send && send\.disabled\)\) return;/);
});

test('companion : poser une question ne declenche aucun scan et ne touche pas la persistance', () => {
  const extension = src('extension.js');
  const ask = extension.match(/async function askCompanion\(question\)[\s\S]*?\n  \}/)[0];
  for (const forbidden of ['runSecurityScan', 'scanWorkspace', 'workspaceState.update', 'LOCAL_SCAN_HISTORY_KEY', 'PIPELINE_STATE_KEY', 'replaceFinding']) {
    assert.ok(!ask.includes(forbidden), `le chat ne doit pas declencher ${forbidden}`);
  }
});

// --------------------------------------------------------------- rendu

test('companion : le panneau complet et la carte partagent le meme modele', () => {
  const extension = src('extension.js');
  // Une seule construction de contexte, utilisee par le rendu du panneau.
  assert.match(extension, /function companionChatContext\(\)/);
  assert.match(extension, /buildAssistantContext\(\{/);
  assert.match(extension, /indicator: contextIndicator\(context\)/);
  assert.match(extension, /quickQuestions: quickQuestionsFor\(context\)/);
  // Le meme contexte alimente la question envoyee au modele.
  assert.match(extension, /buildAssistantMessages\(\{ context: companionChatContext\(\)/);
});

test('companion : aucun mascot duplique et aucun asset distant', () => {
  const html = renderCompanionChatHtml({
    messages: [chatMessage(ROLE.USER, 'Explique ce finding'), chatMessage(ROLE.ASSISTANT, 'Gitleaks a détecté un secret.')],
    mascotUri: 'vscode-webview://asset/security-companion.png'
  }, 'n');
  assert.equal((html.match(/security-companion\.png/g) || []).length, 1, 'le mascot apparait une seule fois');
  assert.doesNotMatch(html, /https?:\/\/(?!127\.0\.0\.1)/, 'aucun asset distant');
  assert.doesNotMatch(html, /cdn\.|unpkg|jsdelivr|googleapis/);
});

test('companion : les messages utilisateur et assistant sont distincts et echappes', () => {
  const html = renderCompanionChatHtml({
    messages: [chatMessage(ROLE.USER, '<script>alert(1)</script>'), chatMessage(ROLE.ASSISTANT, 'Ligne A\nLigne B')]
  }, 'n');
  assert.match(html, /chat-message from-user/);
  assert.match(html, /chat-message from-assistant/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /Ligne A<br>Ligne B/);
});

test('companion : les questions rapides passent par le meme chemin de chat', () => {
  const context = buildAssistantContext({ surface: 'finding', finding: sonarFinding() });
  const html = renderCompanionChatHtml({ quickQuestions: quickQuestionsFor(context) }, 'n');
  assert.match(html, /data-chat-quick="Explique ce finding"/);
  const page = src('companion-chat-page.js');
  // Un raccourci appelle `ask`, exactement comme la saisie libre.
  assert.match(page, /data-chat-quick\]'\)\.forEach\(function \(button\) \{\s*button\.onclick = function \(\) \{ ask\(button\.dataset\.chatQuick\); \};/);
});

test('companion : la conversation reste locale a la session, sans compte', () => {
  const extension = src('extension.js');
  assert.match(extension, /let companionChatMessages = \[\];/);
  // Aucune persistance, aucun profil, aucun compte.
  const block = extension.match(/let companionChatPanel;[\s\S]*?async function openCompanionChat/)[0];
  for (const forbidden of ['workspaceState', 'globalState', 'secrets.store', 'login', 'profile', 'account']) {
    assert.ok(!block.includes(forbidden), `${forbidden} ne doit pas exister dans le chat`);
  }
});

test('companion : le modele de correction n est pas modifie', () => {
  const provider = src('ai/ollama-provider.js');
  // La tache assistant ne reutilise pas le schema de patch.
  // Capture jusqu'aux exports : le corps contient des accolades imbriquees.
  const assistant = provider.slice(
    provider.indexOf('async function generateAssistantReply('),
    provider.indexOf('module.exports')
  );
  assert.ok(assistant.length > 200, 'la tache assistant doit exister');
  assert.ok(!assistant.includes('RESPONSE_SCHEMA'), 'l assistant ne produit jamais un objet patch');
  assert.match(assistant, /localOllamaUrl\(baseUrl\)/, 'meme garde local-only');
  assert.match(assistant, /redactOutgoingMessages\(messages\)/, 'meme frontiere de redaction');
  // Les fonctions de remediation existantes sont intactes.
  assert.match(provider, /async function generateOllamaFix/);
  assert.match(provider, /async function repairOllamaFix/);
  assert.match(provider, /format: RESPONSE_SCHEMA/);
});

// ===========================================================================
// Bugfix : « Ouvrir la conversation » ne faisait rien
//
// La delegation de clic de la carte n'appelait `run()` que pour quatre classes
// (`collapse`, `dismiss`, `send`, `action`). Le bouton, pourtant correctement
// declare, n'en portait aucune : le message n'etait jamais poste. Et meme poste,
// le Dashboard ne le routait pas.
// ===========================================================================

const vm = require('node:vm');
const { assistantCardScript, ASSISTANT_POST_TYPES } = require('../src/companion-assistant-card');

/** Un DOM minimal : juste ce que la delegation de la carte utilise. */
function fakeCard(buttonClass, dataset) {
  const posted = [];
  const button = { dataset, className: buttonClass, closest: null };
  const matches = (selector) => `.${buttonClass}` === selector || (selector === '[data-assistant-post]' && dataset.assistantPost);
  button.closest = (selector) => (matches(selector) ? button : null);
  const card = {
    dataset: {},
    _handler: null,
    addEventListener: (_type, handler) => { card._handler = handler; },
    querySelector: () => null
  };
  const doc = {
    querySelectorAll: (selector) => (selector === '.sc-assistant-stack' ? [card] : []),
    addEventListener: () => {}
  };
  const sandbox = {
    document: doc,
    window: {},
    acquireVsCodeApi: () => ({ postMessage: (payload) => posted.push(payload) })
  };
  vm.createContext(sandbox);
  new vm.Script(assistantCardScript()).runInContext(sandbox);
  return { card, button, posted };
}

test('bugfix : le bouton « Ouvrir la conversation » poste bien le message attendu', () => {
  const { card, button, posted } = fakeCard('sc-assistant-openchat', { assistantPost: JSON.stringify({ type: 'openCompanionChat' }) });
  assert.ok(card._handler, 'la delegation doit etre installee');
  card._handler({ target: button, stopPropagation() {} });
  // Les objets viennent du contexte VM : comparaison structurelle.
  assert.deepEqual(JSON.parse(JSON.stringify(posted)), [{ type: 'openCompanionChat' }], 'un clic doit poster le message');
});

test('bugfix : le type est autorise par l allowlist existante', () => {
  assert.ok(ASSISTANT_POST_TYPES.includes('openCompanionChat'));
  // Un type non declare reste refuse : le repli generique ne contourne rien.
  const { card, button, posted } = fakeCard('sc-assistant-openchat', { assistantPost: JSON.stringify({ type: 'somethingElse' }) });
  card._handler({ target: button, stopPropagation() {} });
  assert.deepEqual(posted, [], 'un type inconnu ne doit rien poster');
});

test('bugfix : le message est route par la navigation partagee', () => {
  const extension = src('extension.js');
  const nav = extension.match(/async function handleShellNavMessage\(message\)[\s\S]*?\n\}/)[0];
  assert.match(nav, /message\?\.type === 'openCompanionChat'/);
  assert.match(nav, /executeCommand\('securityCenter\.openCompanionChat'\)/);
  assert.match(nav, /return true;/);
});

test('bugfix : le Dashboard route aussi le message', () => {
  const extension = src('extension.js');
  // Le Dashboard n'utilise pas `handleShellNavMessage` : il route explicitement.
  assert.match(extension, /if \(message\?\.type === 'openCompanionChat'\) \{[\s\S]{0,120}this\.onCommand\('securityCenter\.openCompanionChat'\)/);
  // Finding Details passe deja par la navigation partagee.
  const detailsHandler = extension.match(/findingDetailsPanel\.webview\.onDidReceiveMessage[\s\S]{0,200}/)[0];
  assert.match(detailsHandler, /handleShellNavMessage\(message\)/);
});

test('bugfix : la commande existante ouvre le panneau de conversation', () => {
  const extension = src('extension.js');
  assert.match(extension, /registerCommand\('securityCenter\.openCompanionChat'/);
  const open = extension.match(/async function openCompanionChat\(\)[\s\S]*?\n  \}/)[0];
  assert.match(open, /createWebviewPanel\('securityCenter\.companionChat'/);
  assert.match(open, /renderCompanionChat\(\)/);
});

test('bugfix : un panneau deja ouvert est revele, jamais duplique', () => {
  const extension = src('extension.js');
  const open = extension.match(/async function openCompanionChat\(\)[\s\S]*?\n  \}/)[0];
  // Creation uniquement si le panneau n'existe pas ; sinon reveal.
  assert.match(open, /if \(!companionChatPanel\) \{/);
  assert.match(open, /\} else companionChatPanel\.reveal\(/);
  assert.equal((open.match(/createWebviewPanel/g) || []).length, 1, 'une seule creation possible');
  assert.match(extension, /companionChatPanel\.onDidDispose\(\(\) => \{ companionChatPanel = undefined; \}\)/);
});

test('bugfix : le contexte suit la surface d ouverture', () => {
  const extension = src('extension.js');
  // Le contexte est recalcule a chaque rendu, jamais fige a la creation.
  const render = extension.match(/function renderCompanionChat\(\)[\s\S]*?\n  \}/)[0];
  assert.match(render, /const context = companionChatContext\(\);/);
  const surface = extension.match(/function companionChatSurface\(\)[\s\S]*?\n  \}/)[0];
  assert.match(surface, /findingDetailsPanel\?\.active && findingDetailsFinding/, 'Finding Details garde le finding courant');
  assert.match(surface, /return findingDetailsFinding \? 'finding' : 'dashboard'/);
  // Les deux contextes restent bien distincts.
  const withFinding = buildAssistantContext({ surface: 'finding', finding: sonarFinding() });
  const dashboard = buildAssistantContext({ surface: 'dashboard', findings: [sonarFinding()] });
  assert.equal(withFinding.finding.rule, 'javascript:S4790');
  assert.equal(dashboard.finding, undefined);
});

test('bugfix : l historique de session survit a l ouverture du panneau', () => {
  const extension = src('extension.js');
  // Seule la partie creation/reveal compte ici : l'action « Effacer » est un
  // gestionnaire distinct, declenche uniquement par l'utilisateur.
  const open = extension.match(/async function openCompanionChat\(\)[\s\S]*?onDidReceiveMessage/)[0];
  assert.ok(!open.includes('companionChatMessages = []'), 'l ouverture ne vide pas l historique');
  // Seule l'action explicite « Effacer » le fait.
  assert.match(extension, /message\.action === 'clear'[\s\S]{0,120}companionChatMessages = \[\]/);
});

test('bugfix : ouvrir la conversation ne lance aucun scan et ne change aucun finding', () => {
  const extension = src('extension.js');
  const open = extension.match(/async function openCompanionChat\(\)[\s\S]*?\n  \}/)[0];
  for (const forbidden of ['scanWorkspace', 'runSecurityScan', 'replaceFinding', 'currentFindings =', 'saveLocalScanCache', 'workspaceState.update']) {
    assert.ok(!open.includes(forbidden), `ouvrir la conversation ne doit pas toucher ${forbidden}`);
  }
  const nav = extension.match(/async function handleShellNavMessage\(message\)[\s\S]*?\n\}/)[0];
  assert.ok(!nav.includes('runSecurityScan'), 'la navigation ne declenche aucun scan');
});
