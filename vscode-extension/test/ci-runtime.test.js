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

const zlib = require('zlib');
const { PREPARE_JOB } = require('../src/ci-runtime-prerequisites');

/** A minimal jar: a stored manifest and a deflated Launcher.class of the given Java version. */
function remotingJar(javaMajor, declared = 0) {
  const entries = [
    ['META-INF/MANIFEST.MF', Buffer.from(`Manifest-Version: 1.0\r\nVersion: 3301.v4363ddcca_4e7\r\n${declared ? `Remoting-Minimum-Java-Version: ${declared}\r\n` : ''}`), 0],
    ['hudson/remoting/Launcher.class', Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 44 + javaMajor]), Buffer.alloc(64)]), 8]
  ];
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, raw, method] of entries) {
    const data = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const nameBuffer = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(method, 8);
    local.writeUInt32LE(data.length, 18); local.writeUInt32LE(raw.length, 22); local.writeUInt16LE(nameBuffer.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(method, 10);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(raw.length, 24); central.writeUInt16LE(nameBuffer.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuffer, data);
    centrals.push(central, nameBuffer);
    offset += local.length + nameBuffer.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** The runtime host as the preparation job sees it over SSH. */
function runtimeHost(overrides = {}) {
  return {
    user: 'deploy', platform: 'Linux x86_64', workspaceWritable: true,
    java: ['21.0.5 /usr/bin/java'], node: ['v22.11.0 /usr/bin/node'], git: 'git version 2.43.0',
    dockerCli: '/usr/bin/docker', docker: 'ready 27.3.1', socketGroup: 'docker', groups: 'deploy docker',
    sudo: false, tools: 'curl tar sha256sum systemctl usermod apt-get', downloads: 'ok', installed: {},
    scripts: [],
    ...overrides
  };
}

function detectionOutput(host) {
  return [
    `SCENTER_PREREQ_SSH=ready ${host.user}`,
    `SCENTER_PREREQ_PLATFORM=${host.platform}`,
    `SCENTER_PREREQ_WORKSPACE=${host.workspaceWritable ? 'ready' : 'not-writable'} /home/deploy/scenter-agent`,
    ...host.java.map((entry) => `SCENTER_PREREQ_JAVA=${entry}`),
    ...host.node.map((entry) => `SCENTER_PREREQ_NODE=${entry}`),
    `SCENTER_PREREQ_GIT=${host.git}`,
    host.dockerCli ? `SCENTER_PREREQ_DOCKER_CLI=ready ${host.dockerCli}` : 'SCENTER_PREREQ_DOCKER_CLI=missing',
    ...(host.dockerCli ? [`SCENTER_PREREQ_DOCKER_DAEMON=${host.docker}`] : []),
    `SCENTER_PREREQ_DOCKER_SOCKET=${host.dockerCli ? host.socketGroup : 'missing'}`,
    `SCENTER_PREREQ_GROUPS=${host.groups}`,
    `SCENTER_PREREQ_SUDO=${host.sudo ? 'non-interactive' : 'unavailable'}`,
    `SCENTER_PREREQ_TOOLS= ${host.tools}`,
    'SCENTER_PREREQ_DONE=1'
  ].join('\n');
}

/** Runs a preparation script against the host model, as the real script would behave. */
function runOnHost(host, script) {
  host.scripts.push(script);
  if (script.includes('SCENTER_PREREQ_DONE')) return { mode: 'detect', output: detectionOutput(host) };
  if (script.includes('install_tool()')) {
    const lines = [];
    for (const match of script.matchAll(/^install_tool (\w+) '([^']+)' '([^']+)' '([0-9a-f]{64})' '([^']+)'/gm)) {
      const [, id, version, url, sha, destination] = match;
      if (host.installed[destination] === version) { lines.push(`SCENTER_INSTALL_${id}=already ${version}`); continue; }
      if (host.downloads === 'offline') { lines.push(`SCENTER_INSTALL_${id}=download-failed`); continue; }
      if (host.downloads === 'tampered') { lines.push(`SCENTER_INSTALL_${id}=checksum-mismatch ${'0'.repeat(64)}`); continue; }
      assert.match(url, /^https:\/\/(github\.com|nodejs\.org)\//, 'only trusted publishers');
      assert.match(sha, /^[0-9a-f]{64}$/);
      host.installed[destination] = version;
      if (id === 'JAVA') host.java.unshift(`${version.replace(/\+.*$/, '')} ${destination}/bin/java`);
      if (id === 'NODE') host.node.unshift(`${version} ${destination}/bin/node`);
      lines.push(`SCENTER_INSTALL_${id}=installed ${version}`);
    }
    lines.push('SCENTER_INSTALL_DONE=1');
    return { mode: 'install', output: lines.join('\n') };
  }
  const lines = [];
  if (!host.sudo) lines.push('SCENTER_ADMIN_SUDO=unavailable');
  else {
    if (script.includes('usermod -aG docker')) { host.groups += ' docker'; host.docker = 'ready 27.3.1'; lines.push('SCENTER_ADMIN_DOCKER_GROUP=applied'); }
    if (script.includes('systemctl enable --now docker')) { host.docker = 'ready 27.3.1'; lines.push('SCENTER_ADMIN_DOCKER_START=applied'); }
  }
  lines.push('SCENTER_ADMIN_DONE=1');
  return { mode: 'admin', output: lines.join('\n') };
}

/** What the managed check job reports from the agent, for the same host. */
function checkOutput(host) {
  const node = host.node[0];
  return [
    `SCENTER_CHECK_USER=${host.user}`,
    `SCENTER_CHECK_WORKSPACE=/home/deploy/scenter-agent/workspace/${CHECK_JOB}`,
    'SCENTER_CHECK_WRITE=ok',
    `SCENTER_CHECK_GIT=${host.git}`,
    `SCENTER_CHECK_NODE=${node || 'missing'}`,
    `SCENTER_CHECK_DOCKER=${!host.dockerCli ? 'missing' : host.docker}`,
    'SCENTER_CHECK_DONE=1'
  ].join('\n');
}

/** A Jenkins double: stateful, strict about paths, recording every call. */
function fakeJenkins({
  authorized = true,
  credential = { id: 'scenter-runtime-ssh', typeName: 'SSH Username with private key', displayName: 'deploy (CI runtime)' },
  plugins = ['workflow-job', 'workflow-cps', 'ssh-slaves', 'credentials-binding'],
  existingNode = null,
  existingJob = null,
  existingPrepareJob = null,
  online = false,
  connects = true,
  launchLog = '',
  consoleText = null,
  buildResult = 'SUCCESS',
  host = runtimeHost(),
  remoting = remotingJar(21)
} = {}) {
  const calls = [];
  const state = {
    nodeXml: existingNode, jobXml: existingJob, prepareXml: existingPrepareJob, online, nodeWrites: [],
    host, prepareRuns: [], disconnects: 0, queue: {}, builds: {}, nextQueue: 7, nextBuild: { [CHECK_JOB]: 3, [PREPARE_JOB]: 1 }
  };
  const jobXml = (name) => (name === CHECK_JOB ? state.jobXml : state.prepareXml);
  const saveJob = (name, body) => { if (name === CHECK_JOB) state.jobXml = body; else state.prepareXml = body; };
  async function call(url, options = {}) {
    const method = options.method || 'GET';
    const parsed = new URL(url);
    calls.push({ method, url, path: parsed.pathname, headers: { ...(options.headers || {}) }, body: options.body ?? null, user: options.user, token: options.token });
    if (!authorized) return status(401);
    const route = `${method} ${parsed.pathname}`;
    const jobRoute = /^(GET|POST) \/job\/([^/]+)\/(config\.xml|build|(\d+)\/api\/json|(\d+)\/consoleText)$/.exec(route);
    if (jobRoute && [CHECK_JOB, PREPARE_JOB].includes(decodeURIComponent(jobRoute[2]))) {
      const name = decodeURIComponent(jobRoute[2]);
      if (jobRoute[3] === 'config.xml' && method === 'GET') return jobXml(name) ? ok(jobXml(name)) : status(404);
      if (jobRoute[3] === 'config.xml') { saveJob(name, options.body); return status(200); }
      if (jobRoute[3] === 'build') {
        const id = state.nextQueue++;
        const number = state.nextBuild[name]++;
        let output;
        if (name === CHECK_JOB) output = consoleText ?? checkOutput(state.host);
        else {
          const encoded = /\.scenter-remote\.b64&apos;, text: &apos;([A-Za-z0-9+/=]+)&apos;/.exec(state.prepareXml || '')?.[1];
          assert.ok(encoded, 'the preparation job carries its remote script');
          const run = runOnHost(state.host, Buffer.from(encoded, 'base64').toString('utf8'));
          state.prepareRuns.push(run.mode);
          output = `Started by user scenter-admin\n+ set +x\n${run.output}\nSCENTER_PREPARE_EXIT=0\nFinished: SUCCESS`;
        }
        state.queue[id] = { reads: 0, number };
        state.builds[`${name}/${number}`] = { reads: 0, output };
        return status(201, { location: `${BASE}/queue/item/${id}/` });
      }
      const build = state.builds[`${name}/${jobRoute[4] || jobRoute[5]}`];
      if (!build) return status(404);
      if (jobRoute[4]) { build.reads += 1; return ok(build.reads < 2 ? { building: true } : { building: false, result: name === CHECK_JOB ? buildResult : 'SUCCESS' }); }
      return ok(build.output);
    }
    const queueRoute = /^GET \/queue\/item\/(\d+)\/api\/json$/.exec(route);
    if (queueRoute && state.queue[queueRoute[1]]) {
      const item = state.queue[queueRoute[1]];
      item.reads += 1;
      return ok(item.reads < 2 ? { why: 'Waiting for next available executor' } : { executable: { number: item.number } });
    }
    switch (route) {
      case 'GET /api/json': return ok({ mode: 'NORMAL' }, { 'x-jenkins': '2.568.2' });
      case 'GET /job/security-pipeline/api/json': return ok({ name: 'security-pipeline' });
      case 'GET /pluginManager/api/json': return ok({ plugins: plugins.map((shortName) => ({ shortName, active: true })) });
      case 'GET /crumbIssuer/api/json': return ok({ crumbRequestField: 'Jenkins-Crumb', crumb: 'crumb-123' }, { 'set-cookie': ['JSESSIONID.node0=abc; Path=/; HttpOnly'] });
      case 'GET /jnlpJars/remoting.jar': return remoting ? { status: 200, headers: {}, text: '', buffer: remoting } : status(404);
      case `GET /credentials/store/system/domain/_/credential/${CONFIG.credentialId}/api/json`: return credential ? ok(credential) : status(404);
      case `GET /computer/${AGENT_NAME}/config.xml`: return state.nodeXml ? ok(state.nodeXml) : status(404);
      case 'POST /computer/doCreateItem': state.nodeXml = '<slave><description>created</description></slave>'; return status(302, { location: `${BASE}/computer/` });
      case `POST /computer/${AGENT_NAME}/config.xml`: state.nodeXml = options.body; state.nodeWrites.push(options.body); return status(200);
      case `GET /computer/${AGENT_NAME}/api/json`: return ok({ offline: !state.online, connecting: false, temporarilyOffline: false });
      case `POST /computer/${AGENT_NAME}/launchSlaveAgent`: state.online = connects; return status(302);
      case `POST /computer/${AGENT_NAME}/doDisconnect`: state.online = false; state.disconnects += 1; return status(302);
      case `GET /computer/${AGENT_NAME}/logText/progressiveText`: return ok(launchLog);
      case 'POST /createItem': saveJob(parsed.searchParams.get('name'), options.body); return status(200);
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
  assert.match(firstWrite, /<string>SCENTER_NODE_HOME<\/string>\s*<string>\/usr<\/string>/, 'Node.js détecté par les prérequis avant l’écriture de l’agent, jamais deviné');
  assert.match(finalWrite, /<string>SCENTER_NODE_HOME<\/string>\s*<string>\/usr<\/string>/, 'Node.js détecté enregistré sur l’agent');
  assert.match(jenkins.state.jobXml, /<sandbox>true<\/sandbox>/);
  assertNoSecretLeak(jenkins, report);
});

test('mise à jour idempotente : agent et job gérés réécrits, jamais recréés', async () => {
  const { config } = normalizeCiRuntimeConfig(CONFIG);
  const jenkins = fakeJenkins({ existingNode: agentConfigXml(config, { nodeHome: '/usr', hostKey: HOST_KEY }), existingJob: checkJobConfigXml(), existingPrepareJob: `<flow-definition><description>${MANAGED_MARKER}</description></flow-definition>` });
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
  assert.ok(!jenkins.posts().some((entry) => entry.path === `/job/${CHECK_JOB}/build`), 'aucun build de vérification lancé');
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

// ------------------------------------------------------------ prérequis guidés

const JAVA21_DESTINATION = '/home/deploy/scenter-agent/tools/java21';
const NODE22_DESTINATION = '/home/deploy/scenter-agent/tools/node22';
const approve = (report) => report.installPlan.map(({ tool, version, destination }) => ({ tool, version, destination }));
const prerequisiteStates = (report) => Object.fromEntries(report.prerequisites.map((item) => [item.id, item.state]));
const agentPosts = (jenkins) => jenkins.posts().filter((entry) => entry.path.startsWith('/computer/'));

test('tout est déjà installé : chaque prérequis Ready, aucune installation, CI Runtime Ready', async () => {
  const jenkins = fakeJenkins();
  const { report } = await run(jenkins);
  assert.equal(report.ready, true, report.lines.join(' | '));
  assert.deepEqual(prerequisiteStates(report), {
    ssh: 'ready', workspace: 'ready', java: 'ready', git: 'ready', node: 'ready', 'docker-cli': 'ready', 'docker-daemon': 'ready', 'docker-access': 'ready'
  });
  assert.equal(report.prerequisites.find((item) => item.id === 'java').label, 'Java 21', 'exigence lue dans remoting.jar, pas codée en dur');
  assert.equal(report.installPlan, null);
  assert.equal(report.admin, null);
  assert.deepEqual(jenkins.state.prepareRuns, ['detect']);
  assert.doesNotMatch(jenkins.state.nodeXml, /<javaPath>/, 'Java système utilisé tel quel');
});

test('Java manquant : plan géré présenté, rien installé sans accord, puis installation vérifiée → Ready', async () => {
  const host = runtimeHost({ java: ['17.0.12 /usr/bin/java'] });
  const jenkins = fakeJenkins({ host });
  const first = await run(jenkins);
  assert.deepEqual(first.report.lines, ['Jenkins: Connected', 'SSH: Ready', 'Docker: Ready', 'CI Runtime: Prerequisites missing']);
  const java = first.report.prerequisites.find((item) => item.id === 'java');
  assert.equal(java.state, 'missing');
  assert.match(java.detail, /Found only Java 17\.0\.12 at \/usr\/bin\/java; this Jenkins needs Java 21 \(remoting/);
  assert.deepEqual(first.report.installPlan.map(({ tool, label, distribution, version, platform, destination, host: target, user }) => ({ tool, label, distribution, version, platform, destination, host: target, user })), [{
    tool: 'java', label: 'Java 21', distribution: 'Eclipse Temurin JRE', version: '21.0.12.1+1', platform: 'linux-x64', destination: JAVA21_DESTINATION, host: CONFIG.host, user: 'deploy'
  }]);
  assert.match(first.report.installPlan[0].sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(jenkins.state.prepareRuns, ['detect'], 'aucune installation sans confirmation');
  assert.deepEqual(agentPosts(jenkins), [], 'aucun agent créé tant que Java manque');

  const second = await run(jenkins, { approvedInstalls: approve(first.report) });
  assert.equal(second.report.ready, true, second.report.lines.join(' | '));
  assert.deepEqual(jenkins.state.prepareRuns, ['detect', 'detect', 'install', 'detect'], 'détection relancée après installation');
  assert.equal(second.report.installResults[0].ok, true);
  assert.equal(second.report.prerequisites.find((item) => item.id === 'java').state, 'ready');
  assert.ok(jenkins.state.nodeXml.includes(`<javaPath>${JAVA21_DESTINATION}/bin/java</javaPath>`), 'l’agent SSH utilise le Java géré');
});

test('Node.js manquant : installation gérée de Node.js 22, exposé à l’agent → Ready', async () => {
  const jenkins = fakeJenkins({ host: runtimeHost({ node: [] }) });
  const first = await run(jenkins);
  assert.equal(first.report.prerequisites.find((item) => item.id === 'node').state, 'missing');
  assert.equal(first.report.installPlan[0].version, 'v22.23.2');
  assert.equal(first.report.installPlan[0].destination, NODE22_DESTINATION);
  const second = await run(jenkins, { approvedInstalls: approve(first.report) });
  assert.equal(second.report.ready, true, second.report.lines.join(' | '));
  assert.match(jenkins.state.nodeXml, new RegExp(`<string>PATH\\+SCENTER_NODE</string>\\s*<string>${NODE22_DESTINATION}/bin</string>`));
  assert.match(jenkins.state.nodeXml, new RegExp(`<string>SCENTER_NODE_HOME</string>\\s*<string>${NODE22_DESTINATION}</string>`));
});

test('somme de contrôle invalide ou téléchargement impossible : ERREUR sûre, rien installé, aucun agent', async () => {
  for (const [downloads, message] of [
    ['tampered', /Java 21: the downloaded archive's SHA-256 0{64} does not match the pinned [0-9a-f]{64}\. Nothing was installed\./],
    ['offline', /Java 21: the download from https:\/\/github\.com\/adoptium\/temurin21-binaries\/.+ failed \(host offline, proxy or firewall\)\./]
  ]) {
    const host = runtimeHost({ java: [], downloads });
    const jenkins = fakeJenkins({ host });
    const first = await run(jenkins);
    const { report } = await run(jenkins, { approvedInstalls: approve(first.report) });
    assert.deepEqual(report.lines, ['Jenkins: Connected', 'SSH: Ready', 'Docker: Ready', 'CI Runtime: Installation failed'], downloads);
    assert.match(report.steps[3].detail, message);
    assert.equal(report.installResults[0].ok, false);
    assert.ok(report.installPlan, 'le plan reste proposé pour réessayer');
    assert.deepEqual(host.installed, {}, 'rien n’est installé');
    assert.deepEqual(agentPosts(jenkins), []);
  }
});

test('installation refusée ou approbation d’une autre version : aucun changement', async () => {
  const host = runtimeHost({ java: [] });
  const jenkins = fakeJenkins({ host });
  const first = await run(jenkins);
  await run(jenkins, { approvedInstalls: [] });
  await run(jenkins, { approvedInstalls: [{ tool: 'java', version: '21.0.1+12', destination: JAVA21_DESTINATION }] });
  await run(jenkins, { approvedInstalls: [{ tool: 'java', version: first.report.installPlan[0].version, destination: '/tmp/java21' }] });
  assert.deepEqual(jenkins.state.prepareRuns, ['detect', 'detect', 'detect', 'detect']);
  assert.ok(!host.scripts.some((script) => script.includes('install_tool()')), 'aucun script d’installation exécuté');
  assert.deepEqual(host.installed, {});
  assert.deepEqual(agentPosts(jenkins), []);
});

test('exigence Java suivie de Jenkins : remoting Java 25 → plan Java 25 ; remoting illisible → défaut annoncé', async () => {
  const newer = await run(fakeJenkins({ host: runtimeHost({ java: ['21.0.5 /usr/bin/java'] }), remoting: remotingJar(25) }));
  assert.equal(newer.report.installPlan[0].label, 'Java 25');
  assert.equal(newer.report.installPlan[0].destination, '/home/deploy/scenter-agent/tools/java25');
  const unknown = await run(fakeJenkins({ remoting: null }));
  assert.match(unknown.report.prerequisites.find((item) => item.id === 'java').detail, /required by current Jenkins releases \(remoting\.jar could not be read\)/);
});

test('Docker absent : administrateur requis, instructions exactes, aucune modification privilégiée', async () => {
  const host = runtimeHost({ dockerCli: '', sudo: true });
  const jenkins = fakeJenkins({ host });
  const { report } = await run(jenkins, { approvedAdminActions: ['docker-group', 'docker-start'] });
  assert.deepEqual(prerequisiteStates(report), {
    ssh: 'ready', workspace: 'ready', java: 'ready', git: 'ready', node: 'ready', 'docker-cli': 'admin', 'docker-daemon': 'blocked', 'docker-access': 'blocked'
  });
  assert.equal(report.steps[2].summary, 'Administrator action required');
  assert.equal(report.steps[2].detail, `Docker Engine is not installed on ${CONFIG.host}.`);
  assert.equal(report.ready, false);
  assert.deepEqual(report.admin.actions, [], 'Docker Engine n’est jamais installé automatiquement');
  assert.match(report.admin.instructions, /https:\/\/docs\.docker\.com\/engine\/install\//);
  assert.ok(!host.scripts.some((script) => /sudo -n (usermod|systemctl)/.test(script)), 'aucune commande privilégiée exécutée');
});

test('permission Docker refusée : remédiation exacte ; application seulement via sudo non interactif confirmé, puis reconnexion', async () => {
  const withoutSudo = await run(fakeJenkins({ host: runtimeHost({ docker: 'permission-denied', groups: 'deploy' }) }));
  const access = withoutSudo.report.prerequisites.find((item) => item.id === 'docker-access');
  assert.equal(access.state, 'admin');
  assert.equal(access.detail, 'User deploy cannot use the Docker daemon: /var/run/docker.sock belongs to group "docker" and deploy is not a member (groups: deploy).');
  assert.match(withoutSudo.report.admin.instructions, /sudo usermod -aG docker deploy/);
  assert.equal(withoutSudo.report.admin.sudo, false);
  assert.deepEqual(withoutSudo.report.admin.actions, [], 'sans sudo non interactif : instructions manuelles seulement');

  const host = runtimeHost({ docker: 'permission-denied', groups: 'deploy', sudo: true });
  const { config } = normalizeCiRuntimeConfig(CONFIG);
  const jenkins = fakeJenkins({ host, online: true, existingNode: agentConfigXml(config, { nodeHome: '/usr', hostKey: HOST_KEY }) });
  const offered = await run(jenkins, { approvedHostKey: null });
  assert.deepEqual(offered.report.admin.actions, [{ id: 'docker-group', label: 'Add deploy to the docker group', command: 'sudo usermod -aG docker deploy' }]);
  assert.ok(!host.scripts.some((script) => script.includes('sudo -n usermod')), 'rien d’appliqué sans confirmation');
  const applied = await run(jenkins, { approvedHostKey: null, approvedAdminActions: ['docker-group'] });
  assert.equal(applied.report.ready, true, applied.report.lines.join(' | '));
  assert.ok(host.scripts.some((script) => script.includes("sudo -n usermod -aG docker 'deploy'")));
  assert.equal(jenkins.state.disconnects, 1, 'l’agent est reconnecté pour que le nouveau groupe s’applique');
});

test('second passage idempotent : rien réinstallé, aucun job ni agent recréé', async () => {
  const host = runtimeHost({ java: [], node: [] });
  const jenkins = fakeJenkins({ host });
  const first = await run(jenkins);
  const installed = await run(jenkins, { approvedInstalls: approve(first.report) });
  assert.equal(installed.report.ready, true, installed.report.lines.join(' | '));
  const creations = jenkins.posts().filter((entry) => ['/createItem', '/computer/doCreateItem'].includes(entry.path)).length;
  const again = await run(jenkins, { approvedInstalls: approve(first.report) });
  assert.equal(again.report.ready, true);
  assert.equal(again.report.installPlan, null, 'outils gérés détectés : plus rien à installer');
  assert.equal(host.scripts.filter((script) => script.includes('install_tool()')).length, 1, 'aucune seconde installation');
  assert.equal(jenkins.posts().filter((entry) => ['/createItem', '/computer/doCreateItem'].includes(entry.path)).length, creations);
});

test('aucun mot de passe sudo ni secret demandé, envoyé, stocké ou journalisé', async () => {
  const host = runtimeHost({ java: [], docker: 'permission-denied', groups: 'deploy', sudo: true });
  const jenkins = fakeJenkins({ host });
  const first = await run(jenkins);
  const { report } = await run(jenkins, { approvedInstalls: approve(first.report), approvedAdminActions: ['docker-group'] });
  assertNoSecretLeak(jenkins, report);
  for (const script of host.scripts) {
    assert.doesNotMatch(script.replace(/command -v sudo/g, ''), /sudo(?! -n)|sudo -S|SUDO_ASKPASS|passwd/, 'sudo uniquement non interactif');
    assert.doesNotMatch(script, new RegExp(TOKEN), 'jeton absent des scripts');
  }
  assert.match(jenkins.state.prepareXml, /StrictHostKeyChecking=yes/);
  assert.match(jenkins.state.prepareXml, /sshUserPrivateKey\(credentialsId: &apos;scenter-runtime-ssh&apos;, keyFileVariable: &apos;SCENTER_SSH_KEY&apos;\)/);
  assert.doesNotMatch(jenkins.state.prepareXml, /PRIVATE KEY|StrictHostKeyChecking=no|password/i);
  assert.doesNotMatch(JSON.stringify(report), /password|passphrase/i);
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
  assert.match(runtime, /scenterCheckoutAnalysedCommit\(\)/, 'le runtime analyse le commit extrait par l’agent principal');
  assert.doesNotMatch(runtime, /scenterCheckoutProject\(\)|checkout scm|git\(repository\)/, 'aucun reclone complet sur le runtime');
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
