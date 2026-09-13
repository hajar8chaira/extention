'use strict';

/**
 * Câblage VS Code de « Configure CI Runtime » dans extension.js.
 *
 * activate() démarre toute l'extension ; ce test exécute donc le vrai code du
 * gestionnaire de message, extrait tel quel d'extension.js, avec ses dépendances
 * remplacées par des doubles : réglages VS Code, état de workspace, notifications,
 * configuration Jenkins enregistrée et module d'onboarding.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ciRuntime = require('../src/ci-runtime');
const { renderCiRuntimeCard } = require('../src/ci-runtime-view');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8').replace(/\r\n/g, '\n');
const TOKEN = '11aabbccddeeff00112233445566778899';
const PEM = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----';
const STATUS_KEY = 'securityCenter.ciRuntime.status';

const FORM = Object.freeze({
  jenkinsUrl: 'http://jenkins.internal:8080', job: 'security-pipeline', host: 'ci-runtime.internal',
  sshUser: 'deploy', credentialId: 'scenter-runtime-ssh', port: '', remoteRoot: ''
});
const CONFIGURE = Object.freeze({ type: 'delivery', action: 'ciRuntimeConfigure', panel: 'ci-runtime', values: FORM });

const report = (ready, summaries) => ({
  ready,
  lines: ciRuntime.CI_RUNTIME_STEPS.map((step, index) => `${step.label}: ${summaries[index]}`),
  steps: ciRuntime.CI_RUNTIME_STEPS.map((step, index) => ({ id: step.id, label: step.label, state: ready ? 'ready' : 'failed', summary: summaries[index], detail: '' })),
  agentName: ciRuntime.AGENT_NAME,
  label: ciRuntime.RUNTIME_LABEL,
  checkedAt: '2026-09-13T10:00:00.000Z'
});
const READY = report(true, ['Connected', 'Ready', 'Ready', 'Ready']);
const NOT_READY = report(false, ['Connected', 'Not connected', 'Not checked', 'Not checked']);
const IN_PROGRESS = { ready: false, lines: [], steps: [{ id: 'jenkins', label: 'Jenkins', state: 'ready' }, { id: 'ssh', label: 'SSH', state: 'pending' }] };

/** The balanced `{ … }` block opening at `open`. */
function blockAt(source, open) {
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}' && --depth === 0) return source.slice(open, index + 1);
  }
  throw new Error('bloc non équilibré');
}

/** A unique construct of extension.js, verbatim: its header and its body. */
function extract(marker) {
  const start = SOURCE.indexOf(marker);
  assert.ok(start >= 0, `absent d’extension.js : ${marker}`);
  assert.equal(SOURCE.indexOf(marker, start + 1), -1, `non unique dans extension.js : ${marker}`);
  const open = SOURCE.indexOf(') {', start) + 2;
  return { start, header: SOURCE.slice(start, open), body: blockAt(SOURCE, open) };
}

const HANDLER = extract("if (message.action === 'ciRuntimeSave' || Object.hasOwn(ciRuntimeRunActions, message.action))");
const SAVE = extract('async function saveCiRuntimeConfiguration(values = {})');
const RUN = extract('async function runCiRuntimeOnboarding(config, { tools = null, adminSetup = false } = {})');
const INSTRUCTIONS = extract("if (message.action === 'ciRuntimeAdminInstructions')");
const ACTIONS = (() => {
  const start = SOURCE.indexOf('const ciRuntimeRunActions = Object.freeze({');
  assert.ok(start >= 0, 'ciRuntimeRunActions absent d’extension.js');
  return SOURCE.slice(start, SOURCE.indexOf('});', start) + 3);
})();

/** The real handler and save function, with VS Code and their collaborators replaced. */
function harness({ jenkins = { url: FORM.jenkinsUrl, job: FORM.job, user: 'scenter-admin', token: TOKEN }, onboarding = () => READY, answer = undefined, status = null } = {}) {
  const calls = { configure: [], jenkinsConfig: [], settings: [], workspaceState: [], info: [], error: [], warning: [], progress: [], audit: [], documents: [], shown: [], renders: 0 };
  const settings = {};
  const vscode = {
    ConfigurationTarget: { Workspace: 2 },
    ProgressLocation: { Notification: 15 },
    workspace: {
      getConfiguration: (section) => ({
        get: (key, fallback) => (key in settings ? settings[key] : fallback),
        update: async (key, value, target) => { calls.settings.push({ section, key, value, target }); settings[key] = value; }
      }),
      openTextDocument: async (options) => { calls.documents.push(options); return { uri: 'untitled:ci-runtime-admin' }; }
    },
    window: {
      showInformationMessage: async (message) => { calls.info.push(message); },
      showErrorMessage: async (message) => { calls.error.push(message); },
      showWarningMessage: async (message, options, ...items) => {
        calls.warning.push({ message, options, items });
        return typeof answer === 'function' ? answer(message, items) : answer;
      },
      showTextDocument: async (document, options) => { calls.shown.push({ document, options }); },
      withProgress: async (_options, task) => task({ report: (value) => calls.progress.push(value) }, { isCancellationRequested: false })
    }
  };
  const deps = {
    vscode,
    context: { workspaceState: { update: async (key, value) => { calls.workspaceState.push({ key, value }); } } },
    normalizeCiRuntimeConfig: ciRuntime.normalizeCiRuntimeConfig,
    configureCiRuntime: async (options) => { calls.configure.push(options); return onboarding(options); },
    mergedDeliveryConfiguration: async (providerId) => { calls.jenkinsConfig.push(providerId); return { ...jenkins }; },
    renderDeliveryPage: () => { calls.renders += 1; },
    createAuditEvent: async (_url, event) => { calls.audit.push(event); },
    backendBaseUrl: () => 'http://127.0.0.1:0'
  };
  const factory = new Function('deps', `
    const { vscode, context, normalizeCiRuntimeConfig, configureCiRuntime, mergedDeliveryConfiguration, renderDeliveryPage, createAuditEvent, backendBaseUrl } = deps;
    const currentScanId = 0;
    let ciRuntimeStatus = deps.status;
    let ciRuntimeRunning = false;
    ${SAVE.header}${SAVE.body}
    ${ACTIONS}
    ${RUN.header}${RUN.body}
    return {
      state: () => ({ ciRuntimeStatus, ciRuntimeRunning }),
      handle: async (message) => {
        ${INSTRUCTIONS.header}${INSTRUCTIONS.body}
        ${HANDLER.header}${HANDLER.body}
      }
    };
  `);
  return { calls, ...factory({ ...deps, status }) };
}

test('registered: the Security Delivery panel routes the CI Runtime actions to the onboarding module', () => {
  assert.match(SOURCE, /const \{ configureCiRuntime, normalizeCiRuntimeConfig \} = require\('\.\/ci-runtime'\);/);
  assert.match(SOURCE, /const \{ renderCiRuntimeCard \} = require\('\.\/ci-runtime-view'\);/);
  const command = SOURCE.indexOf("registerCommand('securityCenter.openSecurityDelivery'");
  const guard = SOURCE.indexOf("if (message?.type !== 'delivery') return;", command);
  const next = SOURCE.indexOf("registerCommand('securityCenter.configureJenkins'", command);
  assert.ok(command > 0 && guard > command && HANDLER.start > guard && HANDLER.start < next,
    'handled inside the Security Delivery panel message listener, after its delivery guard');
  assert.match(HANDLER.body, /runCiRuntimeOnboarding\(saved\.config, ciRuntimeRunActions\[message\.action\]\)/);
  assert.match(RUN.body, /configureCiRuntime\(\{/);
  assert.match(ACTIONS, /ciRuntimeInstallJava: \{ tools: \['java'\] \}/);
  assert.match(SOURCE, /workspacePanels: selectedProvider === 'jenkins' \? renderCiRuntimeCard\(\{/);
  const card = renderCiRuntimeCard({});
  assert.match(card, /data-action="ciRuntimeConfigure"/, 'the card posts the action the handler listens to');
  assert.match(card, /data-action="ciRuntimeSave"/);
});

test('Configure CI Runtime: saves the form, uses the saved Jenkins integration, calls onboarding and reports Ready', async () => {
  const host = harness({ onboarding: (options) => { options.onProgress(IN_PROGRESS); return READY; } });
  await host.handle(CONFIGURE);

  assert.deepEqual(host.calls.jenkinsConfig, ['jenkins'], 'the saved Jenkins integration supplies the API credentials');
  assert.equal(host.calls.configure.length, 1);
  const [options] = host.calls.configure;
  assert.deepEqual(options.config, ciRuntime.normalizeCiRuntimeConfig(FORM).config);
  assert.equal(options.user, 'scenter-admin');
  assert.equal(options.token, TOKEN);
  assert.deepEqual(host.calls.settings, [{
    section: 'securityCenter', key: 'ciRuntime', target: 2,
    value: { jenkinsUrl: FORM.jenkinsUrl, job: FORM.job, host: FORM.host, port: '22', sshUser: 'deploy', credentialId: 'scenter-runtime-ssh', remoteRoot: '/home/deploy/scenter-agent' }
  }]);
  assert.deepEqual(host.calls.progress, [{ message: 'SSH…' }]);
  assert.deepEqual(host.calls.workspaceState, [{ key: STATUS_KEY, value: READY }]);
  assert.deepEqual(host.calls.info, ['Security Center : Jenkins: Connected · SSH: Ready · Docker: Ready · CI Runtime: Ready']);
  assert.deepEqual(host.calls.error, []);
  assert.ok(host.calls.renders >= 3, 'rendered while running, on progress and when done');
  assert.deepEqual(host.state(), { ciRuntimeStatus: READY, ciRuntimeRunning: false });

  const save = harness();
  await save.handle({ ...CONFIGURE, action: 'ciRuntimeSave' });
  assert.equal(save.calls.settings.length, 1);
  assert.deepEqual(save.calls.configure, [], 'Save never starts onboarding');
  assert.deepEqual(save.calls.jenkinsConfig, []);
  assert.deepEqual(save.calls.info, ['Security Center : CI Runtime configuration saved.']);
});

test('a private SSH key is never read, stored nor forwarded', async () => {
  const pasted = harness();
  await pasted.handle({ ...CONFIGURE, values: { ...FORM, credentialId: PEM } });
  assert.deepEqual(pasted.calls.configure, [], 'onboarding not called');
  assert.deepEqual(pasted.calls.jenkinsConfig, [], 'Jenkins credentials not even read');
  assert.deepEqual(pasted.calls.settings, [], 'nothing stored');
  assert.deepEqual(pasted.calls.workspaceState, []);
  assert.equal(pasted.calls.error.length, 1);
  assert.match(pasted.calls.error[0], /^Security Center : Never paste an SSH key into Security Center/);
  assert.ok(!pasted.calls.error[0].includes('b3BlbnNzaC1rZXkt'), 'the pasted key is not echoed');

  const host = harness();
  await host.handle(CONFIGURE);
  const persisted = JSON.stringify([host.calls.settings, host.calls.workspaceState, host.calls.audit, host.calls.info, host.calls.error]);
  assert.doesNotMatch(persisted, /PRIVATE KEY|privateKey/i);
  assert.ok(!persisted.includes(TOKEN), 'the Jenkins API token is used, never stored or shown');
  assert.deepEqual(Object.keys(host.calls.settings[0].value).sort(), ['credentialId', 'host', 'jenkinsUrl', 'job', 'port', 'remoteRoot', 'sshUser']);
  assert.deepEqual(Object.keys(host.calls.configure[0].config).sort(), ['credentialId', 'host', 'jenkinsUrl', 'job', 'port', 'remoteRoot', 'sshUser']);
  assert.doesNotMatch(HANDLER.body + SAVE.body + RUN.body + INSTRUCTIONS.body, /secrets\.|privateKey|sshKey|PRIVATE KEY|showInputBox/, 'no path to key material and no password prompt in the wiring');
});

test('failure is surfaced cleanly: not ready, thrown error, invalid form, second click while running', async () => {
  const notReady = harness({ onboarding: () => NOT_READY });
  await notReady.handle(CONFIGURE);
  assert.deepEqual(notReady.calls.error, ['Security Center : Jenkins: Connected · SSH: Not connected · Docker: Not checked · CI Runtime: Not checked']);
  assert.deepEqual(notReady.calls.info, []);
  assert.deepEqual(notReady.calls.workspaceState, [{ key: STATUS_KEY, value: NOT_READY }], 'the failed status stays visible on the card');
  assert.equal(notReady.state().ciRuntimeRunning, false);

  const crash = harness({ onboarding: () => { throw new Error('Jenkins did not answer in time.'); } });
  await crash.handle(CONFIGURE);
  assert.deepEqual(crash.calls.error, ['Security Center : CI Runtime — Jenkins did not answer in time.']);
  assert.deepEqual(crash.calls.workspaceState, []);
  assert.equal(crash.state().ciRuntimeRunning, false, 'the action is available again');
  assert.ok(crash.calls.renders >= 2, 'the page is re-rendered after the failure');

  const invalid = harness();
  await invalid.handle({ ...CONFIGURE, values: { ...FORM, host: '' } });
  assert.deepEqual(invalid.calls.error, ['Security Center : Enter the runtime host.']);
  assert.deepEqual(invalid.calls.configure, []);

  let release;
  const busy = harness({ onboarding: () => new Promise((resolve) => { release = resolve; }) });
  const first = busy.handle(CONFIGURE);
  while (!busy.state().ciRuntimeRunning || !release) await new Promise((resolve) => setImmediate(resolve));
  await busy.handle(CONFIGURE);
  assert.equal(busy.calls.configure.length, 1, 'a second click does not start a second onboarding');
  release(READY);
  await first;
  assert.deepEqual(busy.state(), { ciRuntimeStatus: READY, ciRuntimeRunning: false });
});

test('SSH host key: fingerprint shown for explicit approval, onboarding re-runs pinned; a changed key is a security warning', async () => {
  const NEW_KEY = { change: 'new', host: '192.168.222.132', port: '22', algorithm: 'ssh-ed25519', key: 'AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyBlobForTest', fingerprint: 'SHA256:newHostKeyFingerprint', previousFingerprint: '' };
  const APPROVAL = { ...report(false, ['Connected', 'Host key approval required', 'Not checked', 'Not checked']), hostKeyApproval: NEW_KEY };

  const approved = harness({ answer: 'Trust this host key', onboarding: (options) => (options.approvedHostKey ? READY : APPROVAL) });
  await approved.handle(CONFIGURE);
  assert.equal(approved.calls.warning.length, 1);
  const [prompt] = approved.calls.warning;
  assert.equal(prompt.message, 'Trust the SSH host key of 192.168.222.132?');
  assert.equal(prompt.options.modal, true, 'explicit confirmation, not a toast');
  assert.ok(prompt.options.detail.includes('ssh-ed25519 SHA256:newHostKeyFingerprint'), prompt.options.detail);
  assert.deepEqual(prompt.items, ['Trust this host key']);
  assert.deepEqual(approved.calls.configure.map((options) => options.approvedHostKey), [null, { algorithm: 'ssh-ed25519', key: NEW_KEY.key, replaces: '' }]);
  assert.deepEqual(approved.calls.info, ['Security Center : Jenkins: Connected · SSH: Ready · Docker: Ready · CI Runtime: Ready']);
  assert.deepEqual(approved.state(), { ciRuntimeStatus: READY, ciRuntimeRunning: false });

  const declined = harness({ answer: undefined, onboarding: () => APPROVAL });
  await declined.handle(CONFIGURE);
  assert.equal(declined.calls.configure.length, 1, 'nothing is trusted without approval');
  assert.deepEqual(declined.calls.error, ['Security Center : Jenkins: Connected · SSH: Host key approval required · Docker: Not checked · CI Runtime: Not checked']);

  const CHANGED_KEY = { ...NEW_KEY, change: 'changed', previousFingerprint: 'SHA256:previouslyPinnedFingerprint' };
  const CHANGED = { ...report(false, ['Connected', 'Host key changed', 'Not checked', 'Not checked']), hostKeyApproval: CHANGED_KEY };
  const rotated = harness({ answer: 'Trust the new host key', onboarding: (options) => (options.approvedHostKey ? READY : CHANGED) });
  await rotated.handle(CONFIGURE);
  const [warning] = rotated.calls.warning;
  assert.equal(warning.message, 'Security warning: the SSH host key of 192.168.222.132 has changed.');
  assert.ok(warning.options.detail.includes('Previously trusted: SHA256:previouslyPinnedFingerprint'), warning.options.detail);
  assert.ok(warning.options.detail.includes('Now presented: ssh-ed25519 SHA256:newHostKeyFingerprint'));
  assert.deepEqual(warning.items, ['Trust the new host key']);
  assert.deepEqual(rotated.calls.configure[1].approvedHostKey, { algorithm: 'ssh-ed25519', key: NEW_KEY.key, replaces: 'SHA256:previouslyPinnedFingerprint' });

  const again = harness({ answer: 'Trust this host key', onboarding: () => APPROVAL });
  await again.handle(CONFIGURE);
  assert.equal(again.calls.warning.length, 1, 'one approval prompt per click, never a loop');
  assert.equal(again.calls.configure.length, 2);
  assert.equal(again.calls.error.length, 1);
});

const PLAN = Object.freeze([
  { tool: 'java', label: 'Java 21', distribution: 'Eclipse Temurin JRE', version: '21.0.12.1+1', platform: 'linux-x64', url: 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz', sha256: '2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500', destination: '/home/deploy/scenter-agent/tools/java21', host: '192.168.222.132', user: 'deploy' },
  { tool: 'node', label: 'Node.js 22', distribution: 'Node.js', version: 'v22.23.2', platform: 'linux-x64', url: 'https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.gz', sha256: 'b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a', destination: '/home/deploy/scenter-agent/tools/node22', host: '192.168.222.132', user: 'deploy' }
]);
const MISSING = { ...report(false, ['Connected', 'Ready', 'Ready', 'Prerequisites missing']), installPlan: PLAN };

test('managed installation: host, tool, version, destination, source and SHA-256 confirmed, then onboarding re-runs', async () => {
  const host = harness({ answer: (_message, items) => items[0], onboarding: (options) => (options.approvedInstalls.length ? READY : MISSING) });
  await host.handle(CONFIGURE);
  assert.equal(host.calls.warning.length, 1);
  const [prompt] = host.calls.warning;
  assert.equal(prompt.message, 'Install Java 21 and Node.js 22 on 192.168.222.132?');
  assert.equal(prompt.options.modal, true);
  for (const expected of ['Java 21: Eclipse Temurin JRE 21.0.12.1+1 (linux-x64)', 'Destination: /home/deploy/scenter-agent/tools/java21', `Source: ${PLAN[0].url}`, `SHA-256, verified before install: ${PLAN[0].sha256}`, 'Destination: /home/deploy/scenter-agent/tools/node22', 'no system package, no sudo, no project file changed']) {
    assert.ok(prompt.options.detail.includes(expected), expected);
  }
  assert.deepEqual(prompt.items, ['Install tools']);
  assert.deepEqual(host.calls.configure.map((options) => options.approvedInstalls), [[], [
    { tool: 'java', version: '21.0.12.1+1', destination: '/home/deploy/scenter-agent/tools/java21' },
    { tool: 'node', version: 'v22.23.2', destination: '/home/deploy/scenter-agent/tools/node22' }
  ]]);
  assert.deepEqual(host.calls.info, ['Security Center : Jenkins: Connected · SSH: Ready · Docker: Ready · CI Runtime: Ready']);

  const declined = harness({ answer: undefined, onboarding: () => MISSING });
  await declined.handle(CONFIGURE);
  assert.equal(declined.calls.configure.length, 1, 'declined: nothing installed');
  assert.deepEqual(declined.calls.error, ['Security Center : Jenkins: Connected · SSH: Ready · Docker: Ready · CI Runtime: Prerequisites missing']);

  const javaOnly = harness({ answer: (_message, items) => items[0], onboarding: (options) => (options.approvedInstalls.length ? READY : MISSING) });
  await javaOnly.handle({ ...CONFIGURE, action: 'ciRuntimeInstallJava' });
  assert.equal(javaOnly.calls.warning[0].message, 'Install Java 21 on 192.168.222.132?');
  assert.deepEqual(javaOnly.calls.warning[0].items, ['Install Java 21']);
  assert.deepEqual(javaOnly.calls.configure[1].approvedInstalls, [{ tool: 'java', version: '21.0.12.1+1', destination: '/home/deploy/scenter-agent/tools/java21' }]);
});

test('administrator setup: only on request, only via detected non-interactive sudo, exact commands confirmed, never a password', async () => {
  const ADMIN = {
    ...report(false, ['Connected', 'Ready', 'Administrator action required', 'Not ready']),
    admin: { required: true, reasons: ['User deploy cannot use the Docker daemon.'], sudo: true, actions: [{ id: 'docker-group', label: 'Add deploy to the docker group', command: 'sudo usermod -aG docker deploy' }], instructions: '# setup' }
  };
  const configure = harness({ answer: (_message, items) => items[0], onboarding: () => ADMIN });
  await configure.handle(CONFIGURE);
  assert.equal(configure.calls.warning.length, 0, 'Configure never proposes privileged changes by itself');
  assert.equal(configure.calls.configure.length, 1);

  const apply = harness({ answer: (_message, items) => items[0], onboarding: (options) => (options.approvedAdminActions.length ? READY : ADMIN) });
  await apply.handle({ ...CONFIGURE, action: 'ciRuntimeAdminApply' });
  const [prompt] = apply.calls.warning;
  assert.equal(prompt.message, 'Apply administrator setup on ci-runtime.internal?', 'the configured runtime host');
  assert.equal(prompt.options.modal, true);
  assert.ok(prompt.options.detail.includes('Add deploy to the docker group: sudo usermod -aG docker deploy'));
  assert.ok(prompt.options.detail.includes('No password is requested, sent or stored.'));
  assert.deepEqual(apply.calls.configure.map((options) => options.approvedAdminActions), [[], ['docker-group']]);

  const noSudo = harness({ answer: (_message, items) => items[0], onboarding: () => ({ ...ADMIN, admin: { ...ADMIN.admin, sudo: false, actions: [] } }) });
  await noSudo.handle({ ...CONFIGURE, action: 'ciRuntimeAdminApply' });
  assert.equal(noSudo.calls.configure.length, 1, 'nothing applied without non-interactive sudo');
  assert.equal(noSudo.calls.warning[0].options, undefined, 'a plain notice, not a confirmation');
  assert.match(noSudo.calls.warning[0].message, /Use "Show manual instructions"/);
  assert.doesNotMatch(JSON.stringify([apply.calls.settings, apply.calls.workspaceState, apply.calls.audit]), /password/i);
});

test('manual instructions open as an untitled Markdown document, without running onboarding or touching settings', async () => {
  const instructions = '# Security Center CI Runtime — administrator setup\n\n```sh\nsudo usermod -aG docker deploy\n```\n';
  const host = harness({ status: { ...READY, admin: { required: true, reasons: [], sudo: false, actions: [], instructions } } });
  await host.handle({ type: 'delivery', action: 'ciRuntimeAdminInstructions', panel: 'ci-runtime', values: FORM });
  assert.deepEqual(host.calls.documents, [{ content: instructions, language: 'markdown' }]);
  assert.equal(host.calls.shown.length, 1);
  assert.deepEqual(host.calls.configure, []);
  assert.deepEqual(host.calls.settings, []);

  const none = harness();
  await none.handle({ type: 'delivery', action: 'ciRuntimeAdminInstructions' });
  assert.deepEqual(none.calls.documents, []);
  assert.deepEqual(none.calls.info, ['Security Center : no administrator action is currently required for the CI Runtime.']);
});
