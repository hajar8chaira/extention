'use strict';

/**
 * Onboarding automatique du runtime CI Jenkins.
 *
 * L'API Jenkins est remplacée par un double qui répond comme un vrai serveur
 * (crumb, credentials, nœuds, file d'attente, builds, console). Le flux réel de
 * Security Center s'exécute contre lui : validation, création ou mise à jour de
 * l'agent SSH, connexion, build de vérification et rapport.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  RUNTIME_LABEL, AGENT_NAME, CHECK_JOB, MANAGED_MARKER,
  normalizeCiRuntimeConfig, agentConfigXml, checkJobConfigXml, parseCheckOutput, configureCiRuntime
} = require('../src/ci-runtime');
const { renderProviderWorkspace, renderDeliveryProviderPageHtml } = require('../src/delivery-provider-view');
const { renderCiRuntimeCard } = require('../src/ci-runtime-view');
const crypto = require('crypto');
const { describeHostKey } = require('../src/ssh-host-key');

const sshString = (value) => {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
};
/** A real ed25519 SSH host key, as the runtime host would present it. */
const ed25519HostKey = () => describeHostKey(Buffer.concat([
  sshString('ssh-ed25519'),
  sshString(Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url'))
]));
const HOST_KEY = ed25519HostKey();
const OTHER_HOST_KEY = ed25519HostKey();

const BASE = 'http://jenkins.internal:8080';
const TOKEN = '11aabbccddeeff00112233445566778899';
const CONFIG = Object.freeze({
  jenkinsUrl: BASE, job: 'security-pipeline', host: 'ci-runtime.internal', sshUser: 'deploy', credentialId: 'scenter-runtime-ssh'
});

const CONSOLE_READY = [
  'Started by user admin',
  '[Pipeline] node',
  `Running on ${AGENT_NAME} in /home/deploy/scenter-agent/workspace/${CHECK_JOB}`,
  '+ set +x',
  'SCENTER_CHECK_USER=deploy',
  `SCENTER_CHECK_WORKSPACE=/home/deploy/scenter-agent/workspace/${CHECK_JOB}`,
  'SCENTER_CHECK_WRITE=ok',
  'SCENTER_CHECK_GIT=git version 2.43.0',
  'SCENTER_CHECK_NODE=v22.11.0 /usr/bin/node',
  'SCENTER_CHECK_DOCKER=ready 27.3.1',
  'SCENTER_CHECK_DONE=1',
  'Finished: SUCCESS'
].join('\n');

const ok = (value, headers = {}) => ({ status: 200, headers, text: typeof value === 'string' ? value : JSON.stringify(value) });
const status = (code, headers = {}) => ({ status: code, headers, text: '' });

/** A Jenkins double: stateful, strict about paths, recording every call. */
function fakeJenkins({
  authorized = true,
  credential = { id: 'scenter-runtime-ssh', typeName: 'SSH Username with private key', displayName: 'deploy (CI runtime)' },
  plugins = ['workflow-job', 'workflow-cps', 'ssh-slaves'],
  existingNode = null,
  existingJob = null,
  connects = true,
  launchLog = '',
  consoleText = CONSOLE_READY,
  buildResult = 'SUCCESS'
} = {}) {
  const calls = [];
  const state = { nodeXml: existingNode, jobXml: existingJob, online: false, queueReads: 0, buildReads: 0, nodeWrites: [] };
  async function call(url, options = {}) {
    const method = options.method || 'GET';
    const parsed = new URL(url);
    calls.push({ method, url, path: parsed.pathname, headers: { ...(options.headers || {}) }, body: options.body ?? null, user: options.user, token: options.token });
    if (!authorized) return status(401);
    const route = `${method} ${parsed.pathname}`;
    switch (route) {
      case 'GET /api/json': return ok({ mode: 'NORMAL' }, { 'x-jenkins': '2.479.1' });
      case 'GET /job/security-pipeline/api/json': return ok({ name: 'security-pipeline' });
      case 'GET /pluginManager/api/json': return ok({ plugins: plugins.map((shortName) => ({ shortName, active: true })) });
      case 'GET /crumbIssuer/api/json': return ok({ crumbRequestField: 'Jenkins-Crumb', crumb: 'crumb-123' }, { 'set-cookie': ['JSESSIONID.node0=abc; Path=/; HttpOnly'] });
      case `GET /credentials/store/system/domain/_/credential/${CONFIG.credentialId}/api/json`: return credential ? ok(credential) : status(404);
      case `GET /computer/${AGENT_NAME}/config.xml`: return state.nodeXml ? ok(state.nodeXml) : status(404);
      case 'POST /computer/doCreateItem': state.nodeXml = '<slave><description>created</description></slave>'; return status(302, { location: `${BASE}/computer/` });
      case `POST /computer/${AGENT_NAME}/config.xml`: state.nodeXml = options.body; state.nodeWrites.push(options.body); return status(200);
      case `GET /computer/${AGENT_NAME}/api/json`: return ok({ offline: !state.online, connecting: false, temporarilyOffline: false });
      case `POST /computer/${AGENT_NAME}/launchSlaveAgent`: state.online = connects; return status(302);
      case `GET /computer/${AGENT_NAME}/logText/progressiveText`: return ok(launchLog);
      case `GET /job/${CHECK_JOB}/config.xml`: return state.jobXml ? ok(state.jobXml) : status(404);
      case 'POST /createItem': state.jobXml = options.body; return status(200);
      case `POST /job/${CHECK_JOB}/config.xml`: state.jobXml = options.body; return status(200);
      case `POST /job/${CHECK_JOB}/build`: return status(201, { location: `${BASE}/queue/item/7/` });
      case 'GET /queue/item/7/api/json':
        state.queueReads += 1;
        return ok(state.queueReads < 2 ? { why: `Waiting for next available executor on ${RUNTIME_LABEL}` } : { executable: { number: 3 } });
      case `GET /job/${CHECK_JOB}/3/api/json`:
        state.buildReads += 1;
        return ok(state.buildReads < 2 ? { building: true } : { building: false, result: buildResult });
      case `GET /job/${CHECK_JOB}/3/consoleText`: return ok(consoleText);
      default: return status(404);
    }
  }
  return { call, calls, state, posts: () => calls.filter((entry) => entry.method === 'POST') };
}

function run(jenkins, overrides = {}) {
  let clock = Date.parse('2026-09-13T10:00:00Z');
  const progress = [];
  return configureCiRuntime({
    config: CONFIG, user: 'scenter-admin', token: TOKEN, call: jenkins.call,
    // The host presents HOST_KEY, and the person running onboarding approved it.
    scanHostKey: async () => HOST_KEY,
    approvedHostKey: { algorithm: HOST_KEY.algorithm, key: HOST_KEY.key },
    sleep: async (ms) => { clock += ms; }, now: () => clock,
    onProgress: (report) => progress.push(report),
    ...overrides
  }).then((report) => ({ report, progress }));
}

function assertNoSecretLeak(jenkins, report) {
  for (const entry of jenkins.calls) {
    assert.ok(!entry.url.includes(TOKEN), `jeton absent de l’URL ${entry.url}`);
    assert.ok(!String(entry.body || '').includes(TOKEN), 'jeton absent des corps envoyés');
    assert.doesNotMatch(String(entry.body || ''), /PRIVATE KEY/);
    if (entry.path.includes('/credential/')) {
      assert.match(entry.url, /\/api\/json\?tree=id,typeName,displayName$/, 'seules les métadonnées du credential sont lues');
    }
  }
  assert.ok(!JSON.stringify(report).includes(TOKEN), 'jeton absent du rapport');
}

// ------------------------------------------------------------ configuration

test('configuration : seul l’ID du credential est accepté, jamais une clé', () => {
  const pasted = normalizeCiRuntimeConfig({ ...CONFIG, credentialId: '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----' });
  assert.equal(pasted.valid, false);
  assert.match(pasted.errors[0], /Never paste an SSH key/);
  assert.doesNotMatch(JSON.stringify(pasted), /b3BlbnNzaC1rZXktdjEAAAA/, 'la clé collée n’est jamais renvoyée');

  const valid = normalizeCiRuntimeConfig(CONFIG);
  assert.equal(valid.valid, true, valid.errors.join(' '));
  assert.equal(valid.config.remoteRoot, '/home/deploy/scenter-agent');
  assert.equal(valid.config.port, '22');
  assert.equal(normalizeCiRuntimeConfig({ ...CONFIG, sshUser: 'root' }).config.remoteRoot, '/root/scenter-agent');

  for (const [field, value, message] of [
    ['host', 'deploy@ci-runtime.internal:22', /host name or an IP address/],
    ['remoteRoot', 'relative/dir', /absolute directory/],
    ['remoteRoot', '/home/deploy/../etc', /absolute directory/],
    ['credentialId', 'id with spaces', /credential ID may contain/],
    ['jenkinsUrl', 'http://admin:secret@jenkins:8080', /identifiants/],
    ['port', '70000', /between 1 and 65535/]
  ]) {
    const result = normalizeCiRuntimeConfig({ ...CONFIG, [field]: value });
    assert.equal(result.valid, false, `${field}=${value}`);
    assert.match(result.errors.join(' '), message);
  }
});

test('agent SSH géré : hôte, utilisateur via credential, racine, label interne, exclusif, clé d’hôte épinglée', () => {
  const { config } = normalizeCiRuntimeConfig(CONFIG);
  const xml = agentConfigXml(config, { nodeHome: '/usr', hostKey: HOST_KEY });
  assert.match(xml, new RegExp(`<name>${AGENT_NAME}</name>`));
  assert.match(xml, /<description>Managed by Security Center \(CI Runtime\)\./);
  assert.match(xml, /<remoteFS>\/home\/deploy\/scenter-agent<\/remoteFS>/);
  assert.match(xml, /<mode>EXCLUSIVE<\/mode>/);
  assert.match(xml, new RegExp(`<label>${RUNTIME_LABEL}</label>`));
  assert.match(xml, /<launcher class="hudson\.plugins\.sshslaves\.SSHLauncher">[\s\S]*<host>ci-runtime\.internal<\/host>[\s\S]*<port>22<\/port>[\s\S]*<credentialsId>scenter-runtime-ssh<\/credentialsId>/);
  assert.ok(xml.includes('<sshHostKeyVerificationStrategy class="hudson.plugins.sshslaves.verifiers.ManuallyProvidedKeyVerificationStrategy">'), 'clé d’hôte épinglée');
  assert.ok(xml.includes('<algorithm>ssh-ed25519</algorithm>') && xml.includes(`<key>${HOST_KEY.key}</key>`));
  assert.doesNotMatch(xml, /NonVerifyingKeyVerificationStrategy|ManuallyTrustedKeyVerificationStrategy|requireInitialManualTrust/, 'ni vérification désactivée ni confiance au premier contact');
  assert.throws(() => agentConfigXml(config, { nodeHome: '/usr' }), /approved, pinned SSH host key/);
  assert.match(xml, /<int>3<\/int>\s*<string>SCENTER_CI_RUNTIME<\/string>\s*<string>managed<\/string>\s*<string>SCENTER_HOME<\/string>\s*<string>\/home\/deploy\/scenter-agent\/\.security-center<\/string>\s*<string>SCENTER_NODE_HOME<\/string>\s*<string>\/usr<\/string>/);
  assert.doesNotMatch(xml, /PRIVATE KEY|privateKey|password/i);
  assert.match(agentConfigXml({ ...config, host: 'a<b>&"c' }, { hostKey: HOST_KEY }), /<host>a&lt;b&gt;&amp;&quot;c<\/host>/, 'valeurs échappées');

  const job = checkJobConfigXml();
  assert.match(job, /<sandbox>true<\/sandbox>/);
  assert.match(job, /Managed by Security Center \(CI Runtime\)\./);
  assert.match(job, new RegExp(`node\\(&apos;${RUNTIME_LABEL}&apos;\\)`));
  assert.match(job, /docker info --format &apos;\{\{\.ServerVersion\}\}&apos; 2&gt;&amp;1/, 'script échappé pour XML');
  assert.deepEqual(parseCheckOutput(CONSOLE_READY), {
    USER: 'deploy', WORKSPACE: `/home/deploy/scenter-agent/workspace/${CHECK_JOB}`, WRITE: 'ok', GIT: 'git version 2.43.0',
    NODE: 'v22.11.0 /usr/bin/node', DOCKER: 'ready 27.3.1', DONE: '1'
  });
});

// ------------------------------------------------------------ flux Jenkins

test('Configure CI Runtime : agent créé, connecté, Docker et workspace vérifiés par un vrai build — tout Ready', async () => {
  const jenkins = fakeJenkins();
  const { report, progress } = await run(jenkins);

  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Ready', 'Docker: Ready', 'CI Runtime: Ready']);
  assert.equal(report.ready, true);
  assert.equal(report.label, RUNTIME_LABEL);
  assert.ok(progress.length >= 4, 'la progression est publiée étape par étape');

  const paths = jenkins.calls.map((entry) => `${entry.method} ${entry.path}`);
  const order = [
    'GET /api/json', 'GET /job/security-pipeline/api/json', `GET /credentials/store/system/domain/_/credential/${CONFIG.credentialId}/api/json`,
    'POST /computer/doCreateItem', `POST /computer/${AGENT_NAME}/config.xml`, `POST /computer/${AGENT_NAME}/launchSlaveAgent`,
    'POST /createItem', `POST /job/${CHECK_JOB}/build`, `GET /job/${CHECK_JOB}/3/consoleText`
  ];
  let cursor = -1;
  for (const step of order) {
    const index = paths.findIndex((entry, position) => position > cursor && entry === step);
    assert.ok(index > cursor, `${step} absent ou hors d’ordre :\n${paths.join('\n')}`);
    cursor = index;
  }

  for (const post of jenkins.posts()) {
    assert.equal(post.headers['Jenkins-Crumb'], 'crumb-123', `crumb sur ${post.path}`);
    assert.equal(post.headers.cookie, 'JSESSIONID.node0=abc');
    assert.equal(post.token, TOKEN, 'jeton transmis au transport, en en-tête');
  }
  const [firstWrite, finalWrite] = [jenkins.state.nodeWrites[0], jenkins.state.nodeWrites[jenkins.state.nodeWrites.length - 1]];
  assert.match(firstWrite, /<credentialsId>scenter-runtime-ssh<\/credentialsId>/);
  assert.ok(firstWrite.includes(`<key>${HOST_KEY.key}</key>`), 'la clé d’hôte approuvée est épinglée dès la première écriture');
  assert.equal(report.hostKeyApproval, null);
  assert.doesNotMatch(firstWrite, /SCENTER_NODE_HOME/, 'Node.js n’est pas deviné avant la vérification');
  assert.match(finalWrite, /<string>SCENTER_NODE_HOME<\/string>\s*<string>\/usr<\/string>/, 'Node.js détecté enregistré sur l’agent');
  assert.match(jenkins.state.jobXml, /<sandbox>true<\/sandbox>/);
  assertNoSecretLeak(jenkins, report);
});

test('mise à jour idempotente : agent et job gérés réécrits, jamais recréés', async () => {
  const { config } = normalizeCiRuntimeConfig(CONFIG);
  const jenkins = fakeJenkins({ existingNode: agentConfigXml(config, { nodeHome: '/usr', hostKey: HOST_KEY }), existingJob: checkJobConfigXml() });
  // Clé déjà épinglée et inchangée : aucune nouvelle approbation n'est demandée.
  const { report } = await run(jenkins, { approvedHostKey: null });
  assert.equal(report.ready, true, report.lines.join(' | '));
  const posts = jenkins.posts().map((entry) => entry.path);
  assert.ok(!posts.includes('/computer/doCreateItem'), 'aucune création d’agent');
  assert.ok(!posts.includes('/createItem'), 'aucune création de job');
  assert.ok(posts.includes(`/computer/${AGENT_NAME}/config.xml`));
  assert.ok(posts.includes(`/job/${CHECK_JOB}/config.xml`));
  assert.equal(jenkins.state.nodeWrites.length, 1, 'Node.js déjà enregistré : une seule écriture');
});

test('un nœud du même nom non créé par Security Center n’est jamais écrasé', async () => {
  const jenkins = fakeJenkins({ existingNode: '<slave><name>scenter-ci-runtime</name><description>Created by the ops team</description></slave>' });
  const { report } = await run(jenkins);
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Name in use', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.ok(!jenkins.posts().some((entry) => entry.path.startsWith('/computer/')), 'aucune écriture sur le nœud existant');
});

test('credential absent ou d’un autre type : SSH en échec précis, aucun agent créé', async () => {
  const missing = fakeJenkins({ credential: null });
  const { report } = await run(missing);
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Credential not found', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.match(report.steps[1].detail, /no global credential "scenter-runtime-ssh"/);
  assert.equal(missing.posts().length, 0, 'aucune écriture dans Jenkins');

  const password = fakeJenkins({ credential: { id: 'scenter-runtime-ssh', typeName: 'Username with password' } });
  const other = await run(password);
  assert.equal(other.report.steps[1].summary, 'Wrong credential type');
  assert.match(other.report.steps[1].detail, /"Username with password", not an SSH private key credential/);
  assert.equal(password.posts().length, 0);
});

test('authentification SSH refusée : SSH en échec avec la cause, aucun build de vérification', async () => {
  const jenkins = fakeJenkins({
    connects: false,
    launchLog: '[09/13/26 10:00:01] [SSH] Opening SSH connection to ci-runtime.internal:22.\nERROR: Server rejected the 1 private key(s) for deploy (credentialId:scenter-runtime-ssh/method:publickey)\n[09/13/26 10:00:02] [SSH] Authentication failed.'
  });
  const { report } = await run(jenkins);
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Authentication failed', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.ok(report.steps[1].detail.startsWith('Credential failure, not a host trust problem'), report.steps[1].detail);
  assert.match(report.steps[1].detail, /SSH authentication failed for user "deploy" with credential "scenter-runtime-ssh"/);
  assert.doesNotMatch(report.steps[1].detail, /Server rejected|10:00:01/, 'le journal brut n’est pas recopié');
  assert.ok(!jenkins.posts().some((entry) => entry.path.endsWith('/build')), 'aucun build lancé');
});

test('Java absent sur l’hôte : cause nommée', async () => {
  const jenkins = fakeJenkins({ connects: false, launchLog: '[SSH] Checking java version of java\nbash: java: command not found\nJava not found on hudson.slaves.SlaveComputer' });
  const { report } = await run(jenkins);
  assert.match(report.steps[1].detail, /Java is not installed on ci-runtime\.internal/);
});

test('Docker inutilisable par l’utilisateur SSH : Docker et CI Runtime non prêts, cause actionnable', async () => {
  const jenkins = fakeJenkins({ consoleText: CONSOLE_READY.replace('SCENTER_CHECK_DOCKER=ready 27.3.1', 'SCENTER_CHECK_DOCKER=permission-denied') });
  const { report } = await run(jenkins);
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Ready', 'Docker: Permission denied', 'CI Runtime: Not ready']);
  assert.match(report.steps[2].detail, /User "deploy" cannot use the Docker daemon on ci-runtime\.internal\. Add that user to the docker group/);
  assert.equal(report.ready, false);
});

test('Node.js ou git absents, workspace non inscriptible : CI Runtime non prêt avec chaque cause', async () => {
  const consoleText = CONSOLE_READY
    .replace('SCENTER_CHECK_WRITE=ok', 'SCENTER_CHECK_WRITE=failed')
    .replace('SCENTER_CHECK_GIT=git version 2.43.0', 'SCENTER_CHECK_GIT=missing')
    .replace('SCENTER_CHECK_NODE=v22.11.0 /usr/bin/node', 'SCENTER_CHECK_NODE=missing');
  const { report } = await run(fakeJenkins({ consoleText }));
  assert.equal(report.steps[2].summary, 'Ready');
  assert.equal(report.steps[3].summary, 'Not ready');
  assert.match(report.steps[3].detail, /workspace is not writable/);
  assert.match(report.steps[3].detail, /git is not installed on ci-runtime\.internal/);
  assert.match(report.steps[3].detail, /Node\.js 20 or later is not installed/);
});

test('mauvais utilisateur côté agent : SSH n’est pas déclaré prêt', async () => {
  const { report } = await run(fakeJenkins({ consoleText: CONSOLE_READY.replace('SCENTER_CHECK_USER=deploy', 'SCENTER_CHECK_USER=jenkins') }));
  assert.equal(report.steps[1].summary, 'Wrong user');
  assert.equal(report.ready, false);
});

test('Jenkins refuse le jeton ou jeton absent : échec immédiat, rien d’autre n’est tenté', async () => {
  const refused = fakeJenkins({ authorized: false });
  const { report } = await run(refused);
  assert.deepEqual(report.lines, ['Jenkins: Not authenticated', 'SSH: Not checked', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.equal(refused.calls.length, 1);

  const silent = fakeJenkins();
  const noToken = await run(silent, { token: '' });
  assert.equal(noToken.report.steps[0].summary, 'Not authenticated');
  assert.equal(silent.calls.length, 0, 'aucun appel sans jeton');
});

test('plugin SSH Build Agents absent : SSH en échec précis', async () => {
  const { report } = await run(fakeJenkins({ plugins: ['workflow-job', 'workflow-cps'] }));
  assert.equal(report.steps[1].summary, 'SSH agents unavailable');
  assert.match(report.steps[1].detail, /SSH Build Agents/);
});

// ------------------------------------------------------------ clé d'hôte SSH

test('premier contact : l’empreinte est présentée pour approbation, rien n’est écrit ni connecté avant', async () => {
  const jenkins = fakeJenkins();
  const scanned = [];
  const { report } = await run(jenkins, { approvedHostKey: null, scanHostKey: async (target) => { scanned.push(target); return HOST_KEY; } });
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Host key approval required', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.deepEqual(scanned, [{ host: CONFIG.host, port: 22, timeoutMs: 10000 }]);
  assert.deepEqual(report.hostKeyApproval, {
    change: 'new', host: CONFIG.host, port: '22', algorithm: 'ssh-ed25519', key: HOST_KEY.key, fingerprint: HOST_KEY.fingerprint, previousFingerprint: ''
  });
  assert.ok(report.steps[1].detail.includes(`Confirm its host key before Jenkins trusts it: ssh-ed25519 ${HOST_KEY.fingerprint}.`), report.steps[1].detail);
  assert.equal(jenkins.posts().length, 0, 'aucun agent créé ni connecté avant approbation');

  const stale = fakeJenkins();
  const other = await run(stale, { approvedHostKey: { algorithm: OTHER_HOST_KEY.algorithm, key: OTHER_HOST_KEY.key } });
  assert.equal(other.report.steps[1].summary, 'Host key approval required', 'l’approbation d’une autre clé ne vaut rien');
  assert.equal(other.report.hostKeyApproval.fingerprint, HOST_KEY.fingerprint);
  assert.equal(stale.posts().length, 0);
});

test('clé d’hôte modifiée : avertissement de sécurité, jamais acceptée d’office, ré-approbation liée à l’ancienne clé', async () => {
  const { config } = normalizeCiRuntimeConfig(CONFIG);
  const pinnedNode = agentConfigXml(config, { nodeHome: '/usr', hostKey: OTHER_HOST_KEY });

  const refused = fakeJenkins({ existingNode: pinnedNode });
  const { report } = await run(refused, { approvedHostKey: null });
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Host key changed', 'Docker: Not checked', 'CI Runtime: Not checked']);
  assert.ok(report.steps[1].detail.startsWith('SECURITY WARNING: ci-runtime.internal:22 now presents'), report.steps[1].detail);
  assert.ok(report.steps[1].detail.includes(OTHER_HOST_KEY.fingerprint) && report.steps[1].detail.includes(HOST_KEY.fingerprint));
  assert.deepEqual(report.hostKeyApproval, {
    change: 'changed', host: CONFIG.host, port: '22', algorithm: 'ssh-ed25519', key: HOST_KEY.key, fingerprint: HOST_KEY.fingerprint, previousFingerprint: OTHER_HOST_KEY.fingerprint
  });
  assert.equal(refused.posts().length, 0, 'le nœud géré garde la clé épinglée');

  const unbound = fakeJenkins({ existingNode: pinnedNode });
  const blind = await run(unbound, { approvedHostKey: { algorithm: HOST_KEY.algorithm, key: HOST_KEY.key } });
  assert.equal(blind.report.steps[1].summary, 'Host key changed', 'approuver la nouvelle clé sans nommer celle qu’elle remplace ne suffit pas');
  assert.equal(unbound.posts().length, 0);

  const approved = fakeJenkins({ existingNode: pinnedNode });
  const renewed = await run(approved, { approvedHostKey: { algorithm: HOST_KEY.algorithm, key: HOST_KEY.key, replaces: OTHER_HOST_KEY.fingerprint } });
  assert.equal(renewed.report.ready, true, renewed.report.lines.join(' | '));
  assert.ok(approved.state.nodeXml.includes(`<key>${HOST_KEY.key}</key>`) && !approved.state.nodeXml.includes(OTHER_HOST_KEY.key), 'nouvelle clé épinglée');
  assert.ok(!approved.posts().some((entry) => entry.path === '/computer/doCreateItem'), 'seul le nœud géré existant est modifié');
});

test('confiance d’hôte refusée par Jenkins distincte d’un credential refusé', async () => {
  const hostTrust = await run(fakeJenkins({
    connects: false,
    launchLog: ['[SSH] Opening SSH connection to ci-runtime.internal:22.', '[SSH] WARNING: The SSH key presented by the remote host does not match the key saved for this host. Connections will be denied until this new key is authorised.'].join('\n')
  }));
  assert.equal(hostTrust.report.steps[1].summary, 'Host key mismatch');
  assert.ok(hostTrust.report.steps[1].detail.startsWith('Remote host trust failure, not a credential problem'), hostTrust.report.steps[1].detail);
  assert.ok(hostTrust.report.steps[1].detail.includes(HOST_KEY.fingerprint));
  assert.doesNotMatch(hostTrust.report.steps[1].detail, /authentication failed/i);

  const credential = await run(fakeJenkins({
    connects: false,
    launchLog: ['[SSH] SSH host key matches key seen previously for this host. Connection will be allowed.', 'ERROR: Server rejected the 1 private key(s) for deploy (credentialId:vm-deploy-key/method:publickey)', '[SSH] Authentication failed.'].join('\n')
  }));
  assert.equal(credential.report.steps[1].summary, 'Authentication failed', 'une clé d’hôte acceptée n’est pas un échec de confiance');
  assert.ok(credential.report.steps[1].detail.startsWith('Credential failure, not a host trust problem'));

  const java = await run(fakeJenkins({
    connects: false,
    launchLog: ['[SSH] SSH host key matches key seen previously for this host. Connection will be allowed.', '[SSH] Checking java version of java', 'Java not found on hudson.slaves.SlaveComputer'].join('\n')
  }));
  assert.equal(java.report.steps[1].summary, 'Java missing', 'un « host key matches » dans le journal ne masque pas la vraie cause');
});

test('clé d’hôte illisible : SSH en échec précis, aucun agent écrit', async () => {
  const jenkins = fakeJenkins();
  const { report } = await run(jenkins, { scanHostKey: async () => { throw new Error('connection refused on ci-runtime.internal:22'); } });
  assert.equal(report.steps[1].summary, 'Host key unavailable');
  assert.match(report.steps[1].detail, /could not read the SSH host key of ci-runtime\.internal:22 \(connection refused on ci-runtime\.internal:22\)/);
  assert.equal(jenkins.posts().length, 0);
});

// ------------------------------------------------------------ UX

test('carte CI Runtime : dans l’espace Jenkins, séparée du déploiement, sans champ de clé', () => {
  const status = { steps: [
    { id: 'jenkins', label: 'Jenkins', state: 'ready', summary: 'Connected', detail: 'Jenkins 2.479.1' },
    { id: 'ssh', label: 'SSH', state: 'ready', summary: 'Ready', detail: '' },
    { id: 'docker', label: 'Docker', state: 'failed', summary: 'Permission denied', detail: 'Add that user to the docker group on the host.' },
    { id: 'runtime', label: 'CI Runtime', state: 'failed', summary: 'Not ready', detail: '' }
  ], checkedAt: '2026-09-13T10:00:00.000Z' };
  const card = renderCiRuntimeCard({ configuration: { host: 'ci-runtime.internal', sshUser: 'deploy', credentialId: 'scenter-runtime-ssh' }, defaults: { jenkinsUrl: BASE, job: 'security-pipeline' }, status });
  for (const [id, label] of [['jenkinsUrl', 'Jenkins URL'], ['job', 'Jenkins Job'], ['host', 'Runtime Host'], ['sshUser', 'SSH User'], ['credentialId', 'Jenkins Credential ID'], ['port', 'SSH port'], ['remoteRoot', 'Remote root']]) {
    assert.match(card, new RegExp(`id="ci-runtime-${id}" data-panel-field="${id}"`));
    assert.ok(card.includes(label), label);
  }
  assert.match(card, /data-panel="ci-runtime"/);
  assert.match(card, /value="http:\/\/jenkins\.internal:8080"/, 'URL Jenkins reprise de Security Delivery');
  assert.match(card, /data-action="ciRuntimeConfigure">Configure CI Runtime</);
  assert.match(card, /The private key stays in Jenkins Credentials: Security Center stores only this ID/);
  assert.doesNotMatch(card, /type="password"|<textarea|private key \*/i, 'aucun champ de saisie de clé');
  assert.match(card, /<strong>Jenkins:<\/strong> <span>Connected<\/span>/);
  assert.match(card, /class="panel-step failed" data-step="docker"><strong>Docker:<\/strong> <span>Permission denied<\/span>/);
  assert.doesNotMatch(card, /SCENTER_DEPLOY_COMMAND|data-action="[^"]*[Dd]eploy/, 'aucun champ ni action de déploiement');
  assert.match(renderCiRuntimeCard({ running: true }), /data-action="ciRuntimeConfigure" disabled>Configuring…/);

  // La page générique accueille le panneau sans nommer de fournisseur.
  const provider = { id: 'jenkins', label: 'Jenkins', implemented: true, configurationFields: [] };
  const workspace = renderProviderWorkspace({ providerId: 'jenkins', sections: [] }, provider, { workspacePanels: card });
  assert.ok(workspace.includes(card), 'panneau rendu dans l’espace du fournisseur');
  assert.doesNotMatch(renderProviderWorkspace({ providerId: 'jenkins', sections: [] }, provider, {}), /data-panel=/, 'aucun panneau sans demande');

  const page = renderDeliveryProviderPageHtml({ model: { providerId: 'jenkins', sections: [] }, providers: [provider], selectedProvider: 'jenkins', view: 'provider', workspacePanels: card }, 'nonce');
  assert.ok(page.includes('data-panel="ci-runtime"'));
  assert.match(page, /const panel=b\.closest\('\[data-panel\]'\);/);
  assert.match(page, /values:Object\.fromEntries\(\[\.\.\.panel\.querySelectorAll\('\[data-panel-field\]'\)\]/);
});

// ------------------------------------------------------------ Jenkinsfile

test('le Jenkinsfile exécute l’analyse sur le label du runtime géré, le déploiement reste sur l’agent principal', () => {
  const jenkinsfile = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
  const group = jenkinsfile.indexOf("stage('Security Center CI Runtime')");
  const deploy = jenkinsfile.indexOf("stage('Deploy')");
  assert.ok(group > 0 && deploy > group);
  const runtime = jenkinsfile.slice(group, deploy);
  assert.match(runtime, /agent \{ label "\$\{env\.SCENTER_CI_RUNTIME_LABEL \?: 'scenter-ci-runtime'\}" \}/);
  assert.match(runtime, /options \{ skipDefaultCheckout\(\) \}/);
  for (const stage of ['Prepare CI Runtime workspace', 'Bootstrap Security Center CI Engine', 'Security Center Analysis', 'Policy Gate', 'Supply chain evidence']) {
    assert.ok(runtime.includes(`stage('${stage}')`), `${stage} s’exécute sur le runtime`);
  }
  assert.match(runtime, /git checkout --quiet --detach "\$SC_SOURCE_COMMIT"/, 'le runtime analyse le commit extrait');
  assert.match(runtime, /stash name: 'scenter-ci-report', includes: 'security-center-report\.json', allowEmpty: true/);
  assert.match(runtime, /PATH\+SCENTER_NODE=\$\{env\.SCENTER_NODE_HOME \?: '\/var\/jenkins_home\/tools\/node22'\}\/bin/);
  const afterGroup = jenkinsfile.slice(deploy);
  assert.ok(afterGroup.includes("stage('Health Check')"));
  assert.doesNotMatch(afterGroup.slice(0, afterGroup.indexOf("stage('Health Check')")), /agent \{/, 'Deploy garde l’agent principal');
  assert.match(jenkinsfile, /^pipeline \{\n  agent any\n/m);
  assert.match(jenkinsfile, /env\.SC_SOURCE_COMMIT = sh\(returnStdout: true, label: 'Source commit', script: 'git rev-parse HEAD'\)\.trim\(\)/);
  assert.match(jenkinsfile, /try \{\s*unstash 'scenter-ci-report'\s*\} catch \(ignored\)/);
  assert.equal(MANAGED_MARKER.length > 0, true);
  assert.doesNotMatch(jenkinsfile, /PRIVATE KEY|sshUserPrivateKey|credentialId: 'scenter-runtime-ssh'/, 'aucune clé ni credential SSH dans le pipeline');
});
