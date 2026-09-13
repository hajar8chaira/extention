'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');

const USERNAME_KEY = 'securityCenter.zap.username.test';
const PASSWORD_KEY = 'securityCenter.zap.password.test';
const TARGET = 'http://127.0.0.1:3000';

function loadExtension() {
  const vscodeStub = {
    EventEmitter: class { constructor() { this.event = () => ({ dispose() {} }); } fire() {} dispose() {} },
    ThemeIcon: class { constructor(id) { this.id = id; } },
    TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    ViewColumn: { Active: -1 },
    Uri: { file: (p) => ({ fsPath: p, toString: () => p }), parse: (p) => ({ toString: () => p }) },
    commands: { registerCommand: () => ({ dispose() {} }), executeCommand: async () => undefined },
    window: {
      createWebviewPanel: () => { throw new Error('non utilise'); },
      registerWebviewViewProvider: () => ({ dispose() {} }),
      showErrorMessage: async () => undefined, showWarningMessage: async () => undefined,
      showInformationMessage: async () => undefined, createOutputChannel: () => ({ appendLine() {}, dispose() {} })
    },
    workspace: {
      getConfiguration: () => ({ get: (_key, fallback) => fallback, update: async () => undefined }),
      workspaceFolders: [], onDidChangeConfiguration: () => ({ dispose() {} })
    },
    Range: class {}, Position: class {}, Diagnostic: class {}, CodeAction: class {},
    WorkspaceEdit: class {}, RelativePattern: class {}, MarkdownString: class {},
    CodeLens: class {}, Location: class {}, Selection: class {},
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    StatusBarAlignment: { Left: 1, Right: 2 }
  };
  const load = Module._load;
  Module._load = function (request, ...rest) {
    if (request === 'vscode') return vscodeStub;
    return load.call(this, request, ...rest);
  };
  try { return require('../src/extension'); } finally { Module._load = load; }
}

const { readZapTestAccount, configureZapTestAccount, promptZapTestAccountInputs, DashboardProvider } = loadExtension();

const extensionSource = () => fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');

/** Un SecretStorage de test : les mêmes quatre opérations, avec leur journal. */
function secretStore(initial = {}) {
  const values = new Map(Object.entries(initial));
  const writes = [];
  const deletes = [];
  return {
    values, writes, deletes,
    get: async (key) => values.get(key),
    store: async (key, value) => { values.set(key, value); writes.push([key, value]); },
    delete: async (key) => { values.delete(key); deletes.push(key); }
  };
}

/** Le webview hôte du dialogue, comme pour le préflight ZAP. */
function webviewHost({ active = true, visible = true } = {}) {
  let receive = null;
  const webview = { html: '', onDidReceiveMessage: (handler) => { receive = handler; } };
  return {
    panel: { active, visible, webview, onDidDispose: () => ({ dispose() {} }) },
    webview,
    receive: (message) => receive?.(message)
  };
}

function provider() {
  const instance = new DashboardProvider(() => {});
  const host = webviewHost();
  instance.fullPanel = host.panel;
  instance.registerMessages(host.webview);
  return { instance, host };
}

const logs = [];

function flow(store, { requestForm, window } = {}) {
  return configureZapTestAccount({
    window, requestForm, secrets: store, usernameKey: USERNAME_KEY, passwordKey: PASSWORD_KEY,
    log: (message) => { logs.push(message); }
  });
}

/** Le formulaire répond tout de suite, comme le ferait un clic dans la page. */
function formAnswering(entry) {
  const seen = [];
  return {
    seen,
    requestForm: async (state) => { seen.push(state); return typeof entry === 'function' ? entry(state) : entry; }
  };
}

// ----------------------------------------------------------------- le dialogue

test('le dialogue rend les deux champs, visibles et modifiables ensemble', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], { scanStatus: 'completed', dynamicTargetUrl: TARGET }), 'n', 'dynamic', 'light', {
    zapAccount: { id: 'acc-1', username: 'scenter-test@juice-shop.local', passwordStored: false }
  });

  assert.equal((html.match(/data-zap-account-id="acc-1"/g) || []).length, 1);
  assert.match(html, /<section class="sc-zap-preflight sc-zap-account" role="dialog" aria-modal="true"/);
  // Un seul dialogue, dans la racine modale partagée : pas une chaîne d'étapes.
  assert.equal((html.match(/id="security-center-modal-root"/g) || []).length, 1);
  assert.match(html, /id="security-center-modal-root">[\s\S]*?data-zap-account-id=/);
  assert.match(html, /<body class="[^"]*sc-modal-open/);

  assert.match(html, /<label for="zap-account-username">E-mail \/ identifiant<\/label>/);
  assert.match(html, /<input id="zap-account-username" data-zap-account-field="username" type="text" value="scenter-test@juice-shop\.local"/);
  assert.match(html, /<label for="zap-account-password">Mot de passe/);
  assert.match(html, /<input id="zap-account-password" data-zap-account-field="password" type="password" value=""/);
  assert.match(html, /data-zap-account-decision="cancel"[^>]*>Annuler</);
  assert.match(html, /data-zap-account-decision="save"[^>]*>Enregistrer</);
});

test('le champ mot de passe est masqué et part toujours vide', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', 'light', {
    zapAccount: { id: 'acc-2', username: 'scenter-test@juice-shop.local', passwordStored: true }
  });

  const passwordInput = html.match(/<input id="zap-account-password"[^>]*>/)[0];
  assert.match(passwordInput, /type="password"/);
  assert.match(passwordInput, /value=""/);
  assert.match(passwordInput, /autocomplete="new-password"/);
  // Un mot de passe déjà enregistré est annoncé, jamais réaffiché.
  assert.match(html, /— mot de passe enregistré/);
  // Son existence est portée par le dialogue, pas déduite de son texte d'aide.
  assert.match(html, /data-zap-account-password-stored="true"/);
  assert.match(html, /passwordStored = zapAccount\.dataset\.zapAccountPasswordStored === 'true'/);
  assert.match(html, /Laissez ce champ vide pour le conserver/);
  assert.match(html, /Laisser vide pour conserver le mot de passe enregistré/);
});

test('l’identifiant enregistré arrive modifiable, sans champ mot de passe prérempli', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', 'light', {
    zapAccount: { id: 'acc-3', username: 'scenter-test@juice-shop.local', passwordStored: true }
  });

  const usernameInput = html.match(/<input id="zap-account-username"[^>]*>/)[0];
  assert.match(usernameInput, /type="text"/);
  assert.match(usernameInput, /value="scenter-test@juice-shop\.local"/);
  assert.doesNotMatch(usernameInput, /readonly|disabled/);
  assert.match(html, /usernameField\.focus\(\);/);
  assert.match(html, /if \(event\.key === 'Enter'\) \{ event\.preventDefault\(\); send\('save'\); \}/);
});

test('le dialogue valide avant d’envoyer, et n’exige un mot de passe que s’il n’en existe aucun', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', 'light', {
    zapAccount: { id: 'acc-4', username: '', passwordStored: false }
  });

  assert.match(html, /if \(!usernameField\.value\.trim\(\)\) return fail\('Saisissez l’adresse e-mail/);
  assert.match(html, /if \(!passwordField\.value && !passwordStored\) return fail\('Saisissez le mot de passe/);
  // Le mot de passe transmis ne reste pas dans le document.
  assert.match(html, /passwordField\.value = '';/);
  // Sans compte enregistré, rien ne propose de supprimer quoi que ce soit.
  assert.doesNotMatch(html, /data-zap-account-decision="remove"/);
  assert.match(html, /data-zap-account-password-stored="false"/);
});

test('un compte enregistré peut être supprimé depuis le dialogue', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic', 'light', {
    zapAccount: { id: 'acc-5', username: 'scenter-test@juice-shop.local', passwordStored: true }
  });
  assert.match(html, /data-zap-account-decision="remove"[^>]*>Supprimer le compte enregistré</);
});

test('aucun dialogue n’est rendu quand la page n’en demande pas', () => {
  const html = renderDashboardHtml(buildDashboardModel([], []), 'n', 'dynamic');
  assert.doesNotMatch(html, /data-zap-account-id=/);
  assert.doesNotMatch(html, /<body class="[^"]*sc-modal-open/);
});

// ------------------------------------------------- le dialogue et l'extension

test('la page ouvre le dialogue sur la surface active et rend la saisie à l’appelant', async () => {
  const { instance, host } = provider();

  const pending = instance.requestZapAccount({ username: 'scenter-test@juice-shop.local', passwordStored: true });
  assert.match(host.webview.html, /data-zap-account-id=/);
  assert.match(host.webview.html, /value="scenter-test@juice-shop\.local"/);
  // L'état du dialogue ne contient jamais de mot de passe, seulement son existence.
  assert.deepEqual(Object.keys(instance.zapAccountForm).sort(), ['id', 'passwordStored', 'username']);

  host.receive({ type: 'zapAccountResolved', id: instance.zapAccountForm.id, decision: 'save', username: 'autre@juice-shop.local', password: 'Secret-Pa55' });

  assert.deepEqual(await pending, { username: 'autre@juice-shop.local', password: 'Secret-Pa55' });
  assert.equal(instance.zapAccountForm, undefined);
  assert.doesNotMatch(host.webview.html, /data-zap-account-id=/);
  assert.doesNotMatch(host.webview.html, /Secret-Pa55/);
});

test('annuler et supprimer remontent comme tels, et un identifiant étranger est ignoré', async () => {
  for (const [decision, expected] of [['cancel', { cancelled: true }], ['remove', { remove: true }]]) {
    const { instance, host } = provider();
    const pending = instance.requestZapAccount({ username: 'scenter-test@juice-shop.local', passwordStored: true });
    host.receive({ type: 'zapAccountResolved', id: 'identifiant-étranger', decision: 'save', username: 'pirate@ailleurs', password: 'x' });
    assert.ok(instance.zapAccountForm, 'un message d’un autre dialogue ne doit rien résoudre');
    host.receive({ type: 'zapAccountResolved', id: instance.zapAccountForm.id, decision });
    assert.deepEqual(await pending, expected);
  }
});

test('fermer la surface qui porte le dialogue annule la saisie', async () => {
  const { instance, host } = provider();
  const pending = instance.requestZapAccount({ username: '', passwordStored: false });
  instance.cancelZapAccountForWebview(host.webview);
  assert.deepEqual(await pending, { cancelled: true });
});

test('sans surface ouverte, le dialogue n’est pas disponible et l’appelant le sait', async () => {
  const instance = new DashboardProvider(() => {});
  assert.equal(await instance.requestZapAccount({ username: '', passwordStored: false }), null);
});

// ----------------------------------------------------------- l'enregistrement

test('enregistrer depuis le dialogue stocke l’identifiant et le nouveau mot de passe', async () => {
  const store = secretStore();
  const form = formAnswering({ username: ' scenter-test@juice-shop.local ', password: 'Secret-Pa55' });

  const result = await flow(store, form);

  assert.deepEqual(form.seen, [{ username: '', passwordStored: false }]);
  assert.equal(result.status, 'saved');
  assert.equal(result.passwordKept, false);
  assert.equal(store.values.get(USERNAME_KEY), 'scenter-test@juice-shop.local');
  assert.equal(store.values.get(PASSWORD_KEY), 'Secret-Pa55');
});

test('le dialogue reçoit l’identifiant enregistré et l’existence du mot de passe', async () => {
  const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });
  const form = formAnswering({ cancelled: true });

  await flow(store, form);

  assert.deepEqual(form.seen, [{ username: 'scenter-test@juice-shop.local', passwordStored: true }]);
});

test('un mot de passe laissé vide conserve le secret déjà enregistré', async () => {
  const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });
  const form = formAnswering({ username: 'autre@juice-shop.local', password: '' });

  const result = await flow(store, form);

  assert.equal(result.status, 'saved');
  assert.equal(result.passwordKept, true);
  assert.equal(store.values.get(PASSWORD_KEY), 'valide', 'un champ vide ne doit jamais écraser un secret valide');
  assert.equal(store.values.get(USERNAME_KEY), 'autre@juice-shop.local');
  assert.deepEqual(store.writes, [[USERNAME_KEY, 'autre@juice-shop.local']]);
});

test('un mot de passe vide sans secret enregistré n’enregistre rien et le dit', async () => {
  const store = secretStore();

  const result = await flow(store, formAnswering({ username: 'scenter-test@juice-shop.local', password: '' }));

  assert.equal(result.status, 'password-required');
  assert.deepEqual(store.writes, []);
  assert.equal(store.values.size, 0);
});

test('un identifiant vide n’enregistre rien et le dit', async () => {
  const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });

  const result = await flow(store, formAnswering({ username: '   ', password: 'nouveau' }));

  assert.equal(result.status, 'username-required');
  assert.deepEqual(store.writes, []);
  assert.equal(store.values.get(PASSWORD_KEY), 'valide');
});

test('annuler le dialogue ne change rien du tout', async () => {
  const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });

  const result = await flow(store, formAnswering({ cancelled: true }));

  assert.equal(result.status, 'cancelled');
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.deletes, []);
  assert.equal(store.values.get(USERNAME_KEY), 'scenter-test@juice-shop.local');
  assert.equal(store.values.get(PASSWORD_KEY), 'valide');
});

test('supprimer retire les deux secrets, et ne prétend rien supprimer quand il n’y a rien', async () => {
  const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });
  const removed = await flow(store, formAnswering({ remove: true }));
  assert.equal(removed.status, 'cleared');
  assert.deepEqual(store.deletes, [USERNAME_KEY, PASSWORD_KEY]);
  assert.equal(store.values.size, 0);

  const empty = secretStore();
  const nothing = await flow(empty, formAnswering({ remove: true }));
  assert.equal(nothing.status, 'nothing-to-remove');
  assert.deepEqual(empty.deletes, []);
});

test('le mot de passe ne sort jamais du stockage sécurisé : ni journal, ni retour, ni configuration', async () => {
  logs.length = 0;
  const store = secretStore();

  const result = await flow(store, formAnswering({ username: 'scenter-test@juice-shop.local', password: 'Ultra-Secret-42' }));

  assert.ok(logs.length > 0, 'l’enregistrement doit laisser une trace');
  for (const line of logs) assert.doesNotMatch(line, /Ultra-Secret-42/);
  assert.doesNotMatch(JSON.stringify(result), /Ultra-Secret-42/);
  const source = extensionSource();
  const body = source.slice(source.indexOf('async function configureZapTestAccount'));
  const flowBody = body.slice(0, body.indexOf('\nasync function activate'));
  assert.doesNotMatch(flowBody, /getConfiguration|workspaceState|globalState|cfg\.update/);
  assert.match(flowBody, /secrets\.store\(passwordKey, password\)/);
});

// -------------------------------------------------------- la saisie de secours

test('la saisie de secours ne sert que sans surface, et garde ses deux étapes', async () => {
  const prompts = [];
  const answers = ['scenter-test@juice-shop.local', 'Secret-Pa55'];
  const store = secretStore();

  const result = await flow(store, {
    requestForm: async () => null,
    window: { showInputBox: async (options) => { prompts.push(options); return answers.shift(); } }
  });

  assert.equal(prompts.length, 2);
  assert.equal(prompts[1].password, true);
  for (const prompt of prompts) assert.equal(prompt.ignoreFocusOut, true);
  assert.equal(result.status, 'saved');
  assert.equal(store.values.get(PASSWORD_KEY), 'Secret-Pa55');
});

test('la saisie de secours annulée à l’une ou l’autre étape ne change rien', async () => {
  for (const answers of [[undefined], ['autre@juice-shop.local', undefined]]) {
    const queue = [...answers];
    const store = secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' });
    const result = await flow(store, {
      requestForm: async () => null,
      window: { showInputBox: async () => queue.shift() }
    });
    assert.equal(result.status, 'cancelled');
    assert.deepEqual(store.writes, []);
    assert.equal(store.values.get(PASSWORD_KEY), 'valide');
  }
});

test('la saisie de secours refuse un identifiant vide au niveau de l’étape', async () => {
  const prompts = [];
  await promptZapTestAccountInputs({
    existing: { username: '', passwordStored: false },
    window: { showInputBox: async (options) => { prompts.push(options); return options.password ? 'x' : 'compte@local'; } }
  });
  assert.match(prompts[0].validateInput('   '), /identifiant/i);
  assert.equal(prompts[0].validateInput('compte@local'), undefined);
});

// ----------------------------------------------------------------- la commande

test('la commande passe par le dialogue de la page, note la date et nomme chaque issue', () => {
  const source = extensionSource();
  const command = source.slice(source.indexOf("registerCommand('securityCenter.configureZapCredentials'"));
  const body = command.slice(0, command.indexOf('}));') + 4);

  assert.match(body, /requestForm: \(state\) => dashboardProvider\.requestZapAccount\(state\)/);
  assert.match(body, /secrets: context\.secrets/);
  assert.match(body, /workspaceState\.update\(ZAP_ACCOUNT_UPDATED_AT_KEY, new Date\(\)\.toISOString\(\)\)/);
  assert.match(body, /await publishZapTestAccount\(\)/);
  for (const status of ['saved', 'cleared', 'password-required', 'username-required', 'nothing-to-remove']) {
    assert.match(body, new RegExp(`result\\.status === '${status}'`), `l’issue ${status} doit être rapportée`);
  }
  assert.match(body, /annulée — identifiants inchangés/);
  assert.doesNotMatch(body, /secrets\.store|secrets\.delete|showInputBox/, 'la commande ne manipule jamais les secrets elle-même');
});

test('l’état publié ne contient que l’existence du compte, son identifiant et sa date', () => {
  const source = extensionSource();
  const publish = source.slice(source.indexOf('async function publishZapTestAccount'));
  const body = publish.slice(0, publish.indexOf('\n  }') + 4);

  assert.match(body, /zapTestAccount: account \? \{ configured: account\.configured, username: account\.username, updatedAt \} : null/);
  assert.doesNotMatch(body, /secrets\.store/);
  assert.match(source, /publishZapTestAccount\(\)\.catch\(\(\) => \{\}\);[\s\S]{0,400}dashboardProvider\.openPage\(page\)/);
});

test('l’état du compte se relit depuis SecretStorage sans révéler le mot de passe', async () => {
  const configured = await readZapTestAccount({
    secrets: secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local', [PASSWORD_KEY]: 'valide' }),
    usernameKey: USERNAME_KEY, passwordKey: PASSWORD_KEY
  });
  assert.deepEqual(configured, { username: 'scenter-test@juice-shop.local', passwordStored: true, configured: true });

  const halfStored = await readZapTestAccount({
    secrets: secretStore({ [USERNAME_KEY]: 'scenter-test@juice-shop.local' }),
    usernameKey: USERNAME_KEY, passwordKey: PASSWORD_KEY
  });
  assert.deepEqual(halfStored, { username: 'scenter-test@juice-shop.local', passwordStored: false, configured: false });

  const empty = await readZapTestAccount({ secrets: secretStore(), usernameKey: USERNAME_KEY, passwordKey: PASSWORD_KEY });
  assert.deepEqual(empty, { username: '', passwordStored: false, configured: false });
});

// ------------------------------------------------------- l'état dans la carte

test('Dynamic Security annonce le compte de test configuré sans afficher de mot de passe', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'failed', mode: 'active', error: 'ZAP login refusé : HTTP 401', completedAt: '2026-09-12T10:00:00.000Z' }], {
    scanStatus: 'completed',
    dynamicTargetUrl: TARGET,
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T09:00:00.000Z' }
  }), 'n', 'dynamic');

  assert.match(html, /Test account/);
  assert.match(html, /Compte de test authentifié configuré/);
  assert.match(html, /scenter-test@juice-shop\.local/);
  assert.match(html, /mot de passe stocké de manière sécurisée/);
  assert.match(html, /class="fact-wide zap-test-account configured"/);
  assert.match(html, /Modifier le compte ZAP/);
});

test('sans compte enregistré, Dynamic Security le dit et garde le bouton de configuration', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{ tool: 'ZAP', status: 'failed', mode: 'active', error: 'ZAP login refusé : HTTP 401' }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET, zapTestAccount: { configured: false, username: '' }
  }), 'n', 'dynamic');

  assert.match(html, /Aucun compte de test enregistré/);
  assert.match(html, /Configurer le compte ZAP/);
  assert.doesNotMatch(html, /zap-test-account configured/);
});

test('un état jamais interrogé n’affirme ni présence ni absence de compte', () => {
  const model = buildDashboardModel([], [{ tool: 'ZAP', status: 'completed', mode: 'baseline' }], { scanStatus: 'completed', dynamicTargetUrl: TARGET });
  assert.equal(model.zapTestAccount, null);
  assert.match(renderDashboardHtml(model, 'n', 'dynamic'), /Compte de test non vérifié/);
});

test('le modèle ne transporte jamais le mot de passe, même fourni par erreur', () => {
  const model = buildDashboardModel([], [], {
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', password: 'Ultra-Secret-42' }
  });

  assert.deepEqual(model.zapTestAccount, { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '' });
  assert.doesNotMatch(renderDashboardHtml(model, 'n', 'dynamic'), /Ultra-Secret-42/);
});

// -------------------------------------------- l'échec d'authentification daté

const AUTH_FAILED_SCAN = {
  tool: 'ZAP', status: 'failed', mode: 'active',
  error: 'ZAP login refusé : HTTP 401', completedAt: '2026-09-12T10:00:00.000Z'
};

test('un compte enregistré après le dernier scan rend son refus historique, pas courant', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [AUTH_FAILED_SCAN], {
    scanStatus: 'completed',
    dynamicTargetUrl: TARGET,
    // Enregistré après le scan : ces identifiants n'ont jamais été essayés.
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T11:00:00.000Z' }
  }), 'n', 'dynamic');

  assert.match(html, /Refus d’authentification du scan précédent, antérieur au compte de test enregistré depuis/);
  assert.match(html, /Relancez une analyse ZAP pour vérifier les identifiants actuels/);
  assert.doesNotMatch(html, /L’authentification a été refusée\. Vérifiez le compte configuré/);
  // La note cesse d'être une alerte en cours.
  assert.match(html, /class="tool-note historical"/);
  assert.doesNotMatch(html, /class="tool-note error[^"]*" role="alert">Refus d’authentification/);
  // Et le blocage cesse : la vérification passe par un nouveau scan.
  // Le run précédent a échoué : l'action est bien l'analyse, et son libellé dit
  // qu'il s'agit de la reprendre.
  assert.match(html, /<button class="primary" data-command="securityCenter\.scanZap"[^>]*>Réessayer l’analyse<\/button><button class="secondary" data-command="securityCenter\.configureZapCredentials">Modifier le compte ZAP<\/button>/);
});

test('un refus postérieur au compte enregistré reste un échec courant', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [AUTH_FAILED_SCAN], {
    scanStatus: 'completed',
    dynamicTargetUrl: TARGET,
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T09:00:00.000Z' }
  }), 'n', 'dynamic');

  assert.match(html, /L’authentification a été refusée\. Vérifiez le compte configuré/);
  assert.match(html, /role="alert"/);
  assert.doesNotMatch(html, /class="tool-note historical"/);
  assert.match(html, /<button class="primary" data-command="securityCenter\.configureZapCredentials">/);
});

test('sans date d’enregistrement, rien n’est requalifié en historique', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [AUTH_FAILED_SCAN], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET,
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local' }
  }), 'n', 'dynamic');

  assert.doesNotMatch(html, /class="tool-note historical"/);
  assert.match(html, /L’authentification a été refusée/);
});

test('un échec qui n’est pas d’authentification n’est jamais requalifié', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [{
    tool: 'ZAP', status: 'failed', mode: 'active',
    error: 'La cible locale est inaccessible : ECONNREFUSED', completedAt: '2026-09-12T10:00:00.000Z'
  }], {
    scanStatus: 'completed', dynamicTargetUrl: TARGET,
    zapTestAccount: { configured: true, username: 'scenter-test@juice-shop.local', updatedAt: '2026-09-12T11:00:00.000Z' }
  }), 'n', 'dynamic');

  assert.doesNotMatch(html, /class="tool-note historical"/);
  assert.match(html, /La cible locale est inaccessible/);
});
