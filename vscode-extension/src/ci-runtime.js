'use strict';

/**
 * Security Center CI Runtime onboarding.
 *
 * Turns five facts — Jenkins URL, job, runtime host, SSH user and the ID of a
 * Jenkins credential — into a working, verified Jenkins SSH agent that runs the
 * Security Center analysis. Nobody creates a node by hand and nobody runs a
 * shell command.
 *
 * Rules this module holds to:
 *   - The private SSH key never leaves Jenkins. Security Center stores and sends
 *     only the credential ID, and reads only the credential's public metadata.
 *   - The Jenkins API token travels in an Authorization header, never in a URL,
 *     a message or a returned object.
 *   - Only the node and the check job Security Center created are ever changed:
 *     each carries a marker in its description, and anything without it is
 *     reported, never overwritten.
 *   - "Ready" is earned: every state comes from what Jenkins and a real build on
 *     the agent returned, never from what was merely submitted.
 */

const http = require('http');
const https = require('https');
const path = require('path');
const { normalizeJenkinsUrl, jenkinsJobPath, scrubJenkinsError } = require('./jenkins');
const { scanSshHostKey, describeHostKey } = require('./ssh-host-key');
const prerequisites = require('./ci-runtime-prerequisites');

const RUNTIME_LABEL = 'scenter-ci-runtime';
const AGENT_NAME = 'scenter-ci-runtime';
const CHECK_JOB = 'scenter-ci-runtime-check';
const MANAGED_MARKER = 'Managed by Security Center (CI Runtime).';
const MIN_NODE_MAJOR = 20;

const STEP_STATE = Object.freeze({ PENDING: 'pending', READY: 'ready', FAILED: 'failed', SKIPPED: 'skipped' });
const CI_RUNTIME_STEPS = Object.freeze([
  Object.freeze({ id: 'jenkins', label: 'Jenkins' }),
  Object.freeze({ id: 'ssh', label: 'SSH' }),
  Object.freeze({ id: 'docker', label: 'Docker' }),
  Object.freeze({ id: 'runtime', label: 'CI Runtime' })
]);

const HOST_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV6 = /^[0-9A-Fa-f:]{2,39}$/;
const SSH_USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const REMOTE_ROOT = /^\/[A-Za-z0-9._/-]*$/;
const KEY_MATERIAL = /BEGIN [A-Z ]*PRIVATE KEY|PuTTY-User-Key-File|ssh-(rsa|ed25519|dss) AAAA/i;

function defaultRemoteRoot(sshUser) {
  return sshUser === 'root' ? '/root/scenter-agent' : `/home/${sshUser}/scenter-agent`;
}

/** Validates the runtime form. Nothing it rejects is ever echoed back. */
function normalizeCiRuntimeConfig(input = {}) {
  const text = (value) => String(value ?? '').trim();
  if (Object.values(input || {}).some((value) => KEY_MATERIAL.test(String(value ?? '')))) {
    return {
      valid: false,
      errors: ['Never paste an SSH key into Security Center: keep it in Jenkins Credentials and enter only its credential ID.'],
      config: {}
    };
  }
  const errors = [];
  const config = {
    jenkinsUrl: '',
    job: text(input.job),
    host: text(input.host),
    port: text(input.port) || '22',
    sshUser: text(input.sshUser),
    credentialId: text(input.credentialId),
    remoteRoot: text(input.remoteRoot)
  };
  try { config.jenkinsUrl = normalizeJenkinsUrl(input.jenkinsUrl); } catch (error) { errors.push(error.message); }
  try { jenkinsJobPath(config.job); } catch (error) { errors.push(error.message); }
  if (!config.host) errors.push('Enter the runtime host.');
  else if (!HOST_NAME.test(config.host) && !IPV6.test(config.host)) errors.push('The runtime host must be a host name or an IP address, without user, port or path.');
  if (!/^\d{1,5}$/.test(config.port) || Number(config.port) < 1 || Number(config.port) > 65535) errors.push('The SSH port must be between 1 and 65535.');
  if (!config.sshUser) errors.push('Enter the SSH user.');
  else if (!SSH_USER.test(config.sshUser)) errors.push('The SSH user may contain letters, digits, ".", "_" and "-" only.');
  if (!config.credentialId) errors.push('Enter the ID of the Jenkins credential that holds the SSH private key.');
  else if (!CREDENTIAL_ID.test(config.credentialId)) errors.push('The Jenkins credential ID may contain letters, digits, ".", "_" and "-" only.');
  if (!config.remoteRoot && SSH_USER.test(config.sshUser)) config.remoteRoot = defaultRemoteRoot(config.sshUser);
  if (config.remoteRoot && (!REMOTE_ROOT.test(config.remoteRoot) || config.remoteRoot === '/' || config.remoteRoot.split('/').includes('..'))) {
    errors.push('The remote root must be an absolute directory, for example /home/jenkins/scenter-agent.');
  }
  return { valid: !errors.length, errors, config };
}

function xml(value) {
  return String(value ?? '').replace(/[<>&'"]/g, (character) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[character]));
}

function unxml(value) {
  return String(value ?? '').replace(/&(lt|gt|amp|apos|quot);/g, (_, entity) => ({ lt: '<', gt: '>', amp: '&', apos: "'", quot: '"' }[entity]));
}

/**
 * The managed SSH agent, as Jenkins stores it. Exclusive mode: it only runs
 * builds that ask for the Security Center label. Jenkins only connects to a host
 * presenting exactly the explicitly approved host key, pinned here: never trust on
 * first use, never a non-verifying strategy. SCENTER_HOME (and SCENTER_NODE_HOME
 * once detected) travel as node environment variables, so the Jenkinsfile needs
 * no host-specific path.
 */
function agentConfigXml(config, { nodeHome = '', hostKey = null, javaPath = '', managedNode = false } = {}) {
  if (!hostKey?.algorithm || !hostKey?.key) throw new Error('The managed agent is only written with an approved, pinned SSH host key.');
  const environment = [
    ['SCENTER_CI_RUNTIME', 'managed'],
    ['SCENTER_HOME', `${config.remoteRoot}/.security-center`],
    ...(nodeHome ? [['SCENTER_NODE_HOME', nodeHome]] : []),
    // A managed Node.js is not on the host's PATH: the agent adds it.
    ...(nodeHome && managedNode ? [['PATH+SCENTER_NODE', `${nodeHome}/bin`]] : [])
  ].sort(([a], [b]) => a.localeCompare(b, 'en', { sensitivity: 'base' }));
  return `<?xml version="1.1" encoding="UTF-8"?>
<slave>
  <name>${AGENT_NAME}</name>
  <description>${xml(MANAGED_MARKER)} Runs Security Center analyses on ${xml(config.host)}.</description>
  <remoteFS>${xml(config.remoteRoot)}</remoteFS>
  <numExecutors>2</numExecutors>
  <mode>EXCLUSIVE</mode>
  <retentionStrategy class="hudson.slaves.RetentionStrategy$Always"/>
  <launcher class="hudson.plugins.sshslaves.SSHLauncher">
    <host>${xml(config.host)}</host>
    <port>${Number(config.port)}</port>
    <credentialsId>${xml(config.credentialId)}</credentialsId>
${javaPath ? `    <javaPath>${xml(javaPath)}</javaPath>\n` : ''}    <launchTimeoutSeconds>60</launchTimeoutSeconds>
    <maxNumRetries>3</maxNumRetries>
    <retryWaitTime>15</retryWaitTime>
    <sshHostKeyVerificationStrategy class="hudson.plugins.sshslaves.verifiers.ManuallyProvidedKeyVerificationStrategy">
      <key>
        <algorithm>${xml(hostKey.algorithm)}</algorithm>
        <key>${xml(hostKey.key)}</key>
      </key>
    </sshHostKeyVerificationStrategy>
  </launcher>
  <label>${RUNTIME_LABEL}</label>
  <nodeProperties>
    <hudson.slaves.EnvironmentVariablesNodeProperty>
      <envVars serialization="custom">
        <unserializable-parents/>
        <tree-map>
          <default>
            <comparator class="java.lang.String$CaseInsensitiveComparator"/>
          </default>
          <int>${environment.length}</int>
${environment.map(([key, value]) => `          <string>${xml(key)}</string>\n          <string>${xml(value)}</string>`).join('\n')}
        </tree-map>
      </envVars>
    </hudson.slaves.EnvironmentVariablesNodeProperty>
  </nodeProperties>
</slave>
`;
}

/** Minimal creation payload; the full configuration is then written as config.xml. */
function createNodeJson(config) {
  return {
    name: AGENT_NAME,
    nodeDescription: MANAGED_MARKER,
    numExecutors: '2',
    remoteFS: config.remoteRoot,
    labelString: RUNTIME_LABEL,
    mode: 'EXCLUSIVE',
    '': ['hudson.slaves.JNLPLauncher', 'hudson.slaves.RetentionStrategy$Always'],
    launcher: { 'stapler-class': 'hudson.slaves.JNLPLauncher', $class: 'hudson.slaves.JNLPLauncher' },
    retentionStrategy: { 'stapler-class': 'hudson.slaves.RetentionStrategy$Always', $class: 'hudson.slaves.RetentionStrategy$Always' },
    nodeProperties: { 'stapler-class-bag': 'true' }
  };
}

/**
 * What the check build runs on the agent. Every probe runs, whatever the
 * previous one found, and prints one SCENTER_CHECK_* line: Security Center
 * reads facts, never a raw error.
 */
const CHECK_SHELL = [
  'set +x',
  'set +e',
  'echo "SCENTER_CHECK_USER=$(id -un)"',
  'echo "SCENTER_CHECK_WORKSPACE=$(pwd)"',
  'if touch .scenter-runtime-check && rm -f .scenter-runtime-check; then echo "SCENTER_CHECK_WRITE=ok"; else echo "SCENTER_CHECK_WRITE=failed"; fi',
  'if command -v git >/dev/null 2>&1; then echo "SCENTER_CHECK_GIT=$(git --version)"; else echo "SCENTER_CHECK_GIT=missing"; fi',
  'node_bin=""',
  'if [ -n "${SCENTER_NODE_HOME:-}" ] && [ -x "$SCENTER_NODE_HOME/bin/node" ]; then node_bin="$SCENTER_NODE_HOME/bin/node"; else node_bin="$(command -v node 2>/dev/null)"; fi',
  'if [ -n "$node_bin" ]; then echo "SCENTER_CHECK_NODE=$("$node_bin" --version 2>/dev/null) $node_bin"; else echo "SCENTER_CHECK_NODE=missing"; fi',
  'if ! command -v docker >/dev/null 2>&1; then echo "SCENTER_CHECK_DOCKER=missing"',
  'elif docker_out="$(docker info --format \'{{.ServerVersion}}\' 2>&1)"; then echo "SCENTER_CHECK_DOCKER=ready $docker_out"',
  'else case "$docker_out" in *ermission*) echo "SCENTER_CHECK_DOCKER=permission-denied" ;; *) echo "SCENTER_CHECK_DOCKER=unreachable" ;; esac; fi',
  'echo "SCENTER_CHECK_DONE=1"'
].join('\n');

/** The managed check pipeline: sandboxed, one build at a time, ten builds kept. */
function checkJobConfigXml() {
  const pipeline = `node('${RUNTIME_LABEL}') {\n  sh(label: 'Security Center CI Runtime check', script: '''\n${CHECK_SHELL}\n''')\n}\n`;
  return `<?xml version="1.1" encoding="UTF-8"?>
<flow-definition>
  <description>${xml(MANAGED_MARKER)} Verifies the Security Center CI Runtime: SSH, workspace and Docker.</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty/>
    <jenkins.model.BuildDiscarderProperty>
      <strategy class="hudson.tasks.LogRotator">
        <daysToKeep>-1</daysToKeep>
        <numToKeep>10</numToKeep>
        <artifactDaysToKeep>-1</artifactDaysToKeep>
        <artifactNumToKeep>-1</artifactNumToKeep>
      </strategy>
    </jenkins.model.BuildDiscarderProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
    <script>${xml(pipeline)}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>
`;
}

function parseCheckOutput(text) {
  const facts = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = /^SCENTER_CHECK_([A-Z]+)=(.*)$/.exec(line.trim());
    if (match && !(match[1] in facts)) facts[match[1]] = match[2].trim();
  }
  return facts;
}

/** Text that came from a remote host: printable and bounded. */
function safeFact(value) {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '').trim().slice(0, 200);
}

/** One Jenkins API call. Never throws on an HTTP status: the flow interprets it. */
function jenkinsCall(target, { method = 'GET', user = '', token = '', body = null, contentType = '', headers: extra = {}, timeoutMs = 15000, maxBytes = 512 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(target); } catch { return reject(new Error('Invalid Jenkins URL.')); }
    const transport = url.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json, application/xml, text/plain', ...extra };
    if (token) headers.authorization = `Basic ${Buffer.from(`${user}:${token}`).toString('base64')}`;
    if (body !== null) {
      headers['content-type'] = contentType || 'application/x-www-form-urlencoded';
      headers['content-length'] = Buffer.byteLength(body);
    }
    const request = transport.request(url, { method, headers, timeout: timeoutMs }, (response) => {
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size <= maxBytes) chunks.push(chunk);
      });
      response.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({ status: response.statusCode || 500, headers: response.headers || {}, text: body.toString('utf8'), buffer: body });
      });
    });
    request.on('timeout', () => request.destroy(new Error('Jenkins did not answer in time.')));
    request.on('error', (error) => reject(new Error(scrubJenkinsError(error.message))));
    if (body !== null) request.write(body);
    request.end();
  });
}

/** GET and crumb-protected POST against one Jenkins, with the API token in a header. */
function createJenkinsClient({ baseUrl, user, token, call, timeoutMs }) {
  let crumbHeaders = null;
  const url = (relative) => `${baseUrl}/${String(relative).replace(/^\/+/, '')}`;
  const get = (relative, options = {}) => call(url(relative), { user, token, timeoutMs, ...options });
  async function crumb() {
    if (crumbHeaders) return crumbHeaders;
    crumbHeaders = {};
    const response = await get('crumbIssuer/api/json');
    if (response.status === 200) {
      try {
        const data = JSON.parse(response.text);
        if (data.crumbRequestField && data.crumb) crumbHeaders[data.crumbRequestField] = String(data.crumb);
      } catch { /* no crumb: CSRF protection disabled */ }
      const cookies = [].concat(response.headers?.['set-cookie'] || []).map((cookie) => String(cookie).split(';')[0]).filter(Boolean);
      if (cookies.length) crumbHeaders.cookie = cookies.join('; ');
    }
    return crumbHeaders;
  }
  async function post(relative, { body = '', contentType = 'application/x-www-form-urlencoded' } = {}) {
    return call(url(relative), { method: 'POST', user, token, timeoutMs, body, contentType, headers: await crumb() });
  }
  return { get, post };
}

function httpProblem(response, what) {
  if (response.status === 401) return 'Jenkins rejected the API user or token (HTTP 401). Update them in Security Delivery → Jenkins.';
  if (response.status === 403) return `The Jenkins API user is not allowed to ${what} (HTTP 403).`;
  return `Jenkins answered HTTP ${response.status} while trying to ${what}.`;
}

/**
 * Why the SSH agent did not come online, from the agent log, without quoting it.
 * A remote host trust failure and a credential failure are different facts: only
 * an explicit refusal of the host key counts as the first — the SSH plugin also
 * logs "host key matches" on a connection whose authentication then fails.
 */
function sshConnectionFailure(log, config, pin, javaMajor = prerequisites.DEFAULT_JAVA_MAJOR) {
  const text = String(log || '');
  if (/connections will be denied|does not match the key|not currently trusted|not previously been seen|host key verification failed|host ?key (?:was )?(?:rejected|refused|denied)/i.test(text)) {
    return {
      summary: 'Host key mismatch',
      detail: `Remote host trust failure, not a credential problem: Jenkins refused the SSH host key presented to it by ${config.host}:${config.port}, which is not the approved ${pin.algorithm} ${pin.fingerprint}. Jenkins may be reaching a different or intercepted host. Nothing was trusted.`
    };
  }
  if (/authentication failed|server rejected the \d+ private key|auth fail|permission denied \(publickey/i.test(text)) {
    return {
      summary: 'Authentication failed',
      detail: `Credential failure, not a host trust problem: the host key of ${config.host} is trusted, but SSH authentication failed for user "${config.sshUser}" with credential "${config.credentialId}". The credential's public key must be authorized for ${config.sshUser} on ${config.host}.`
    };
  }
  if (/connection refused|timed out|no route to host|unknownhost|unresolved|could not resolve/i.test(text)) {
    return { summary: 'Host unreachable', detail: `Jenkins cannot reach ${config.host}:${config.port} over SSH.` };
  }
  if (/java/i.test(text) && /not found|no such file|unable to find|cannot find|could not find|couldn't figure out/i.test(text)) {
    return { summary: 'Java missing', detail: `Java is not installed on ${config.host}: this Jenkins needs Java ${javaMajor} on the runtime agent. Run Configure CI Runtime to install a managed Java ${javaMajor}.` };
  }
  return { summary: 'Not connected', detail: `Jenkins could not start agent ${AGENT_NAME} on ${config.host}. The agent log in Jenkins has the details.` };
}

/** The host key pinned on the managed agent for this host and port, if any. */
function pinnedHostKey(configXml, config) {
  const text = String(configXml || '');
  const host = unxml(/<host>([^<]*)<\/host>/.exec(text)?.[1] ?? '');
  const port = /<port>(\d+)<\/port>/.exec(text)?.[1] || '22';
  if (host !== config.host || Number(port) !== Number(config.port)) return null;
  const block = /ManuallyProvidedKeyVerificationStrategy"\s*>\s*<key>\s*<algorithm>([^<]+)<\/algorithm>\s*<key>([^<]+)<\/key>/.exec(text);
  if (!block) return null;
  try {
    const described = describeHostKey(unxml(block[2]).replace(/\s+/g, ''));
    return described.algorithm === unxml(block[1]).trim() ? described : null;
  } catch {
    return null;
  }
}

/** A host key a person approved, re-validated: its fingerprint is recomputed, never taken as given. */
function acceptedApproval(input) {
  if (!input?.key) return null;
  try {
    const described = describeHostKey(String(input.key));
    if (input.algorithm && input.algorithm !== described.algorithm) return null;
    return { ...described, replaces: String(input.replaces || '') };
  } catch {
    return null;
  }
}

function existingNodeHome(configXml, host) {
  const existingHost = /<host>([^<]*)<\/host>/.exec(configXml)?.[1];
  if (existingHost === undefined || unxml(existingHost) !== host) return '';
  const match = /<string>SCENTER_NODE_HOME<\/string>\s*<string>([^<]*)<\/string>/.exec(configXml);
  return match ? unxml(match[1]) : '';
}

const json = (response) => { try { return JSON.parse(response?.text || ''); } catch { return null; } };
const formBody = (fields) => Object.entries(fields).map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join('&');
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function poll(read, done, { sleep, now, timeoutMs, intervalMs }) {
  const deadline = now() + timeoutMs;
  let value = await read();
  while (!done(value) && now() < deadline) {
    await sleep(intervalMs);
    value = await read();
  }
  return value;
}

/**
 * Configures and verifies the CI Runtime. Returns the four-line report
 * (Jenkins, SSH, Docker, CI Runtime); `onProgress` receives it after every step.
 */
async function configureCiRuntime({
  config: input = {}, user = '', token = '', call = jenkinsCall,
  approvedHostKey = null, scanHostKey = scanSshHostKey,
  approvedInstalls = [], approvedAdminActions = [],
  sleep = defaultSleep, now = Date.now, timeouts = {}, onProgress = () => {}
} = {}) {
  const limits = { requestMs: 15000, hostKeyMs: 10000, connectMs: 180000, queueMs: 300000, buildMs: 600000, prepareMs: 1800000, pollMs: 3000, ...timeouts };
  const steps = CI_RUNTIME_STEPS.map((step) => ({ id: step.id, label: step.label, state: STEP_STATE.PENDING, summary: 'Not checked', detail: '' }));
  const byId = Object.fromEntries(steps.map((step) => [step.id, step]));
  let extras = {};
  const report = () => ({
    ready: steps.every((step) => step.state === STEP_STATE.READY),
    steps: steps.map((step) => ({ ...step })),
    lines: steps.map((step) => `${step.label}: ${step.summary}`),
    agentName: AGENT_NAME,
    label: RUNTIME_LABEL,
    // A host key waiting for explicit approval: public data, shown as a fingerprint.
    hostKeyApproval: extras.hostKeyApproval || null,
    // The prerequisite table, what Security Center may install after confirmation,
    // what it installed, and what needs an administrator. No secret in any of it.
    prerequisites: extras.prerequisites || [],
    installPlan: extras.installPlan || null,
    installResults: extras.installResults || [],
    admin: extras.admin || null,
    checkedAt: new Date(now()).toISOString()
  });
  const set = (id, state, summary, detail = '') => {
    Object.assign(byId[id], { state, summary, detail });
    onProgress(report());
  };
  const note = (extra) => {
    extras = { ...extras, ...extra };
    onProgress(report());
  };
  const stop = (id, summary, detail, extra = {}) => {
    extras = { ...extras, ...extra };
    set(id, STEP_STATE.FAILED, summary, detail);
    for (const step of steps.slice(steps.indexOf(byId[id]) + 1)) {
      if (step.state === STEP_STATE.PENDING) Object.assign(step, { state: STEP_STATE.SKIPPED, summary: 'Not checked', detail: `Waiting for ${byId[id].label}.` });
    }
    const final = report();
    onProgress(final);
    return final;
  };
  const attempt = async (action) => {
    try { return await action(); } catch (error) { return { status: 0, headers: {}, text: '', error: scrubJenkinsError(error.message) }; }
  };

  // ------------------------------------------------------------ 1. Jenkins
  const checked = normalizeCiRuntimeConfig(input);
  if (!checked.valid) return stop('jenkins', 'Not configured', checked.errors.join(' '));
  const config = checked.config;
  if (!user || !token) {
    return stop('jenkins', 'Not authenticated', 'Configure the Jenkins API user and token in Security Delivery → Jenkins: Security Center needs them to create the agent.');
  }
  set('jenkins', STEP_STATE.PENDING, 'Checking');
  const jenkins = createJenkinsClient({ baseUrl: config.jenkinsUrl, user, token, call, timeoutMs: limits.requestMs });
  const root = await attempt(() => jenkins.get('api/json?tree=mode'));
  if (root.error) return stop('jenkins', 'Unreachable', `Cannot reach Jenkins at ${config.jenkinsUrl}: ${root.error}`);
  if (root.status !== 200) return stop('jenkins', [401, 403].includes(root.status) ? 'Not authenticated' : 'Error', httpProblem(root, 'read Jenkins'));
  const job = await attempt(() => jenkins.get(`${jenkinsJobPath(config.job)}/api/json?tree=name`));
  if (job.status === 404) return stop('jenkins', 'Job not found', `Jenkins has no job "${config.job}".`);
  if (job.error || job.status !== 200) return stop('jenkins', 'Error', job.error || httpProblem(job, 'read the job'));
  const plugins = await attempt(() => jenkins.get('pluginManager/api/json?tree=plugins[shortName,active]'));
  const pluginList = plugins.status === 200 ? (json(plugins)?.plugins || []) : null;
  const pluginActive = (name) => !pluginList || pluginList.some((plugin) => plugin.shortName === name && plugin.active);
  if (!pluginActive('workflow-job') || !pluginActive('workflow-cps')) {
    return stop('jenkins', 'Pipeline unavailable', 'The Jenkins Pipeline plugins (workflow-job, workflow-cps) are not installed or not active.');
  }
  const version = /^[\w.-]{1,40}$/.test(String(root.headers?.['x-jenkins'] || '')) ? ` ${root.headers['x-jenkins']}` : '';
  set('jenkins', STEP_STATE.READY, 'Connected', `Jenkins${version} · job ${config.job}.`);

  // ------------------------------------------------------------ 2. SSH
  set('ssh', STEP_STATE.PENDING, 'Checking');
  if (!pluginActive('ssh-slaves')) {
    return stop('ssh', 'SSH agents unavailable', 'The Jenkins plugin "SSH Build Agents" (ssh-slaves) is not installed or not active.');
  }
  const credential = await attempt(() => jenkins.get(`credentials/store/system/domain/_/credential/${encodeURIComponent(config.credentialId)}/api/json?tree=id,typeName,displayName`));
  if (credential.status === 404) {
    return stop('ssh', 'Credential not found', `Jenkins has no global credential "${config.credentialId}". Create an "SSH Username with private key" credential in Jenkins Credentials, then enter its ID.`);
  }
  if (credential.error || credential.status !== 200) return stop('ssh', 'Credential unavailable', credential.error || httpProblem(credential, 'view credentials'));
  const credentialType = safeFact(json(credential)?.typeName);
  if (!/ssh/i.test(credentialType)) {
    return stop('ssh', 'Wrong credential type', `Credential "${config.credentialId}" is "${credentialType || 'unknown'}", not an SSH private key credential.`);
  }

  const nodePath = `computer/${encodeURIComponent(AGENT_NAME)}`;
  const existing = await attempt(() => jenkins.get(`${nodePath}/config.xml`));
  if (existing.status === 200 && !existing.text.includes(MANAGED_MARKER)) {
    return stop('ssh', 'Name in use', `A Jenkins node named "${AGENT_NAME}" exists but was not created by Security Center. It is never overwritten: rename or remove it in Jenkins.`);
  }
  if (existing.status !== 200 && existing.status !== 404) {
    return stop('ssh', 'Agent unavailable', existing.error || httpProblem(existing, 'read agents'));
  }
  let nodeHome = existing.status === 200 ? existingNodeHome(existing.text, config.host) : '';

  // Remote host trust comes before any connection: the key the host presents is
  // compared with the one pinned on the managed agent. A key nobody approved is
  // never pinned, and a changed key is a security warning, never accepted.
  let presented;
  try {
    presented = await scanHostKey({ host: config.host, port: Number(config.port), timeoutMs: limits.hostKeyMs });
  } catch (error) {
    return stop('ssh', 'Host key unavailable', `Security Center could not read the SSH host key of ${config.host}:${config.port} (${safeFact(error.message)}). It is read and approved before Jenkins connects.`);
  }
  const pinned = existing.status === 200 ? pinnedHostKey(existing.text, config) : null;
  const approval = acceptedApproval(approvedHostKey);
  const sameKey = (a, b) => Boolean(a && b && a.algorithm === b.algorithm && a.key === b.key);
  let pin = null;
  if (pinned && sameKey(pinned, presented)) pin = pinned;
  else if (!pinned && sameKey(approval, presented) && !approval.replaces) pin = presented;
  else if (pinned && sameKey(approval, presented) && approval.replaces === pinned.fingerprint) pin = presented;
  if (!pin) {
    const hostKeyApproval = {
      change: pinned ? 'changed' : 'new', host: config.host, port: config.port,
      algorithm: presented.algorithm, key: presented.key, fingerprint: presented.fingerprint,
      previousFingerprint: pinned ? pinned.fingerprint : ''
    };
    return pinned
      ? stop('ssh', 'Host key changed', `SECURITY WARNING: ${config.host}:${config.port} now presents ${presented.algorithm} ${presented.fingerprint}, but the managed agent trusts ${pinned.algorithm} ${pinned.fingerprint}. A reinstalled host or rotated keys explain this, and so does an intercepted connection. Jenkins will not connect until the new key is explicitly approved.`, { hostKeyApproval })
      : stop('ssh', 'Host key approval required', `First SSH connection to ${config.host}:${config.port}. Confirm its host key before Jenkins trusts it: ${presented.algorithm} ${presented.fingerprint}.`, { hostKeyApproval });
  }

  if (!pluginActive('credentials-binding')) {
    return stop('ssh', 'Credentials binding unavailable', `The Jenkins plugin "Credentials Binding" (credentials-binding) is required: it lets Jenkins use credential "${config.credentialId}" to prepare the runtime host without the key ever leaving Jenkins.`);
  }

  const capitalized = (text) => `${text.charAt(0).toUpperCase()}${text.slice(1)}`;
  /** Creates or updates a Security Center job, builds it and returns its console. */
  const runManagedJob = async (name, configXml, { what, where, timeoutMs }) => {
    const jobPath = `job/${encodeURIComponent(name)}`;
    const current = await attempt(() => jenkins.get(`${jobPath}/config.xml`));
    let saved;
    if (current.status === 200) {
      if (!current.text.includes(MANAGED_MARKER)) {
        return { failure: 'name-in-use', detail: `A Jenkins job named "${name}" exists but was not created by Security Center. It is never overwritten.` };
      }
      saved = await attempt(() => jenkins.post(`${jobPath}/config.xml`, { body: configXml, contentType: 'application/xml' }));
    } else if (current.status === 404) {
      saved = await attempt(() => jenkins.post(`createItem?name=${encodeURIComponent(name)}`, { body: configXml, contentType: 'application/xml' }));
    } else {
      saved = current;
    }
    if (saved.error || saved.status >= 400) return { failure: 'not-started', detail: saved.error || httpProblem(saved, 'create or configure jobs (Job/Create, Job/Configure)') };
    const queued = await attempt(() => jenkins.post(`${jobPath}/build?delay=0sec`));
    if (queued.error || queued.status >= 400) return { failure: 'not-started', detail: queued.error || httpProblem(queued, 'build jobs (Job/Build)') };
    const queueId = /\/queue\/item\/(\d+)\/?$/.exec(String(queued.headers?.location || ''))?.[1];
    if (!queueId) return { failure: 'not-started', detail: `Jenkins did not return the queue item of the ${what} build.` };
    const item = await poll(async () => json(await attempt(() => jenkins.get(`queue/item/${queueId}/api/json?tree=cancelled,why,executable[number]`))) || {},
      (value) => value.cancelled === true || Number.isInteger(value.executable?.number),
      { sleep, now, timeoutMs: limits.queueMs, intervalMs: limits.pollMs });
    if (!Number.isInteger(item.executable?.number)) {
      return {
        failure: 'not-started',
        detail: item.cancelled
          ? `The ${what} build was cancelled in Jenkins.`
          : `The ${what} build did not start ${where} within ${Math.round(limits.queueMs / 1000)}s${item.why ? ` (${safeFact(item.why)})` : ''}.`
      };
    }
    const number = item.executable.number;
    const build = await poll(async () => json(await attempt(() => jenkins.get(`${jobPath}/${number}/api/json?tree=building,result`))) || { building: true },
      (value) => value.building === false,
      { sleep, now, timeoutMs, intervalMs: limits.pollMs });
    if (build.building !== false) return { failure: 'timeout', detail: `${capitalized(what)} build #${number} did not finish within ${Math.round(timeoutMs / 1000)}s.` };
    const output = await attempt(() => jenkins.get(`${jobPath}/${number}/consoleText`, { maxBytes: 256 * 1024 }));
    return { number, result: build.result, consoleText: output.text || '' };
  };

  // ------------------------------------------------------------ prerequisites, from Jenkins over SSH
  // Detected before the agent exists: Java may be exactly what is missing. The
  // private key stays in Jenkins, and ssh accepts only the approved host key.
  set('ssh', STEP_STATE.PENDING, 'Checking prerequisites');
  const remoting = await attempt(() => jenkins.get('jnlpJars/remoting.jar', { maxBytes: 16 * 1024 * 1024 }));
  const javaRequirement = (remoting.status === 200 && prerequisites.javaRequirementFromRemotingJar(remoting.buffer))
    || { major: prerequisites.DEFAULT_JAVA_MAJOR, source: 'current Jenkins releases (remoting.jar could not be read)' };
  const prepare = async (mode, script) => {
    const run = await runManagedJob(prerequisites.PREPARE_JOB,
      prerequisites.prepareJobConfigXml({ config, hostKey: pin, script, runtimeLabel: RUNTIME_LABEL, marker: MANAGED_MARKER, mode }),
      { what: 'preparation', where: `on a Jenkins executor outside label ${RUNTIME_LABEL}`, timeoutMs: limits.prepareMs });
    if (run.failure) {
      return { failure: { 'name-in-use': 'Preparation job name in use', timeout: 'Preparation timed out' }[run.failure] || 'Preparation not started', detail: run.detail };
    }
    const lines = run.consoleText.split(/\r?\n/).map((line) => line.trim());
    if (lines.includes('SCENTER_PREPARE=no-ssh-client')) {
      return { failure: 'Administrator action required', detail: 'The Jenkins executor that prepares the runtime has no ssh client: an administrator must install openssh-client where that build runs (Jenkins controller or executor).' };
    }
    if (lines.includes('SCENTER_PREPARE=ssh-failed')) {
      const failure = sshConnectionFailure(lines.filter((line) => line.startsWith('SCENTER_SSH_ERROR=')).join('\n'), config, pin, javaRequirement.major);
      return { failure: failure.summary, detail: failure.detail };
    }
    return { text: run.consoleText, number: run.number };
  };
  const detect = async () => {
    const run = await prepare('detection', prerequisites.detectScript(config, javaRequirement.major));
    if (run.failure) return run;
    const markers = prerequisites.parseMarkers(run.text, 'PREREQ');
    if (!markers.DONE) return { failure: 'Prerequisites not detected', detail: `Preparation build #${run.number} ended before ${config.host} reported its prerequisites.` };
    return { evaluation: prerequisites.evaluatePrerequisites(markers, { config, javaRequirement }) };
  };
  const publish = (evaluation, extra = {}) => note({ prerequisites: evaluation.items, installPlan: evaluation.installPlan, admin: evaluation.admin, ...extra });
  const stopBeforeAgent = (evaluation, summary, detail) => {
    set('ssh', STEP_STATE.READY, 'Ready', `SSH to ${config.host} verified from Jenkins with credential ${config.credentialId}; the agent starts once its prerequisites are ready.`);
    const dockerAdmin = evaluation.items.find((entry) => entry.id.startsWith('docker') && entry.state === prerequisites.STATE.ADMIN);
    if (dockerAdmin) set('docker', STEP_STATE.FAILED, 'Administrator action required', dockerAdmin.detail);
    else set('docker', STEP_STATE.READY, 'Ready', evaluation.items.find((entry) => entry.id === 'docker-daemon')?.detail || '');
    return stop('runtime', summary, detail);
  };

  let detected = await detect();
  if (detected.failure) return stop('ssh', detected.failure, detected.detail);
  publish(detected.evaluation);

  // Privileged setup: only the actions a person approved, only through
  // non-interactive sudo already configured on the host. Never a password.
  const adminApproved = (detected.evaluation.admin?.actions || []).map((action) => action.id)
    .filter((id) => (Array.isArray(approvedAdminActions) ? approvedAdminActions : []).includes(id));
  let reconnect = false;
  if (adminApproved.length) {
    const run = await prepare('administrator setup', prerequisites.adminScript(config, adminApproved));
    if (run.failure) return stop('ssh', run.failure, run.detail);
    const markers = prerequisites.parseMarkers(run.text, 'ADMIN');
    const unavailable = markers.SUDO?.[0] === 'unavailable';
    const failed = adminApproved.filter((id) => markers[prerequisites.ADMIN_ACTIONS[id].marker]?.[0] !== 'applied');
    if (unavailable || failed.length) {
      return stopBeforeAgent(detected.evaluation, 'Administrator action required', `Administrator setup was not applied on ${config.host}: ${unavailable ? 'non-interactive sudo is not available' : `${failed.join(', ')} failed`}. Use the manual instructions.`);
    }
    reconnect = adminApproved.includes('docker-group');
    detected = await detect();
    if (detected.failure) return stop('ssh', detected.failure, detected.detail);
    publish(detected.evaluation, { adminApplied: adminApproved });
  }

  // Managed tools: only the pinned plan items a person approved.
  const toInstall = prerequisites.approvedPlan(detected.evaluation.installPlan, approvedInstalls);
  if (toInstall.length) {
    set('runtime', STEP_STATE.PENDING, `Installing ${toInstall.map((item) => item.label).join(', ')}`);
    const run = await prepare('installation', prerequisites.installScript(config, toInstall));
    if (run.failure) return stop('ssh', run.failure, run.detail);
    const installResults = prerequisites.installOutcome(prerequisites.parseMarkers(run.text, 'INSTALL'), toInstall);
    note({ installResults });
    const failed = installResults.filter((entry) => !entry.ok);
    if (failed.length) return stopBeforeAgent(detected.evaluation, 'Installation failed', failed.map((entry) => entry.detail).join(' '));
    detected = await detect();
    if (detected.failure) return stop('ssh', detected.failure, detected.detail);
    publish(detected.evaluation, { installResults });
  }
  const evaluation = detected.evaluation;
  if (evaluation.installPlan) {
    return stopBeforeAgent(evaluation, 'Prerequisites missing', `Missing on ${config.host}: ${evaluation.installPlan.map((item) => item.label).join(', ')}. Security Center installs ${evaluation.installPlan.length > 1 ? 'them' : 'it'} inside ${config.remoteRoot}/tools after your confirmation.`);
  }
  const blocking = evaluation.items.filter((entry) => ['workspace', 'java'].includes(entry.id) && entry.state === prerequisites.STATE.ADMIN);
  if (blocking.length) return stopBeforeAgent(evaluation, 'Administrator action required', blocking.map((entry) => entry.detail).join(' '));
  if (evaluation.node) nodeHome = evaluation.node.home;
  const agentOptions = () => ({
    nodeHome, hostKey: pin,
    javaPath: evaluation.java?.managed ? evaluation.java.path : '',
    managedNode: Boolean(evaluation.node?.managed)
  });

  // ------------------------------------------------------------ the managed agent
  if (existing.status === 404) {
    const created = await attempt(() => jenkins.post(`computer/doCreateItem?name=${encodeURIComponent(AGENT_NAME)}&type=hudson.slaves.DumbSlave`, {
      body: formBody({ name: AGENT_NAME, type: 'hudson.slaves.DumbSlave', json: JSON.stringify(createNodeJson(config)) })
    }));
    if (created.error || created.status >= 400) return stop('ssh', 'Agent not created', created.error || httpProblem(created, 'create agents (Agent/Create)'));
  }
  const written = await attempt(() => jenkins.post(`${nodePath}/config.xml`, { body: agentConfigXml(config, agentOptions()), contentType: 'application/xml' }));
  if (written.error || written.status >= 400) return stop('ssh', 'Agent not configured', written.error || httpProblem(written, 'configure agents (Agent/Configure)'));

  const nodeStatus = async () => {
    const response = await attempt(() => jenkins.get(`${nodePath}/api/json?tree=offline,connecting,temporarilyOffline`));
    return response.status === 200 ? (json(response) || { offline: true }) : { offline: true, connecting: false };
  };
  let computer = await nodeStatus();
  if (computer.temporarilyOffline) {
    return stop('ssh', 'Marked offline', `Agent ${AGENT_NAME} is marked temporarily offline in Jenkins. Bring it back online there, then retry.`);
  }
  if (!computer.offline && reconnect) {
    // A new group membership applies to new sessions only.
    await attempt(() => jenkins.post(`${nodePath}/doDisconnect?offlineMessage=${encodeURIComponent('Security Center: reconnecting after administrator setup')}`));
    computer = await poll(nodeStatus, (value) => value.offline === true, { sleep, now, timeoutMs: limits.connectMs, intervalMs: limits.pollMs });
  }
  if (computer.offline) {
    const launched = await attempt(() => jenkins.post(`${nodePath}/launchSlaveAgent`));
    if (launched.error || launched.status >= 400) return stop('ssh', 'Not connected', launched.error || httpProblem(launched, 'connect agents (Agent/Connect)'));
    let reads = 0;
    computer = await poll(async () => { reads += 1; return nodeStatus(); },
      (value) => !value.offline || (reads >= 2 && !value.connecting),
      { sleep, now, timeoutMs: limits.connectMs, intervalMs: limits.pollMs });
  }
  if (computer.offline) {
    const log = await attempt(() => jenkins.get(`${nodePath}/logText/progressiveText?start=0`, { maxBytes: 256 * 1024 }));
    const failure = sshConnectionFailure(log.text, config, pin, javaRequirement.major);
    return stop('ssh', failure.summary, failure.detail);
  }
  set('ssh', STEP_STATE.READY, 'Ready', `Agent ${AGENT_NAME} online on ${config.host} with credential ${config.credentialId}; host key ${pin.algorithm} ${pin.fingerprint} pinned.`);

  // ------------------------------------------------------------ 3-4. Docker and workspace, from a real build
  set('docker', STEP_STATE.PENDING, 'Checking');
  set('runtime', STEP_STATE.PENDING, 'Checking');
  const check = await runManagedJob(CHECK_JOB, checkJobConfigXml(), { what: 'check', where: `on label ${RUNTIME_LABEL}`, timeoutMs: limits.buildMs });
  if (check.failure) {
    return stop('docker', { 'name-in-use': 'Check job name in use', timeout: 'Check timed out' }[check.failure] || 'Check not started', check.detail);
  }
  const number = check.number;
  const build = { result: check.result };
  const facts = parseCheckOutput(check.consoleText);
  const result = safeFact(build.result) || 'without a result';

  const agentUser = safeFact(facts.USER);
  if (agentUser && agentUser !== config.sshUser) {
    set('ssh', STEP_STATE.FAILED, 'Wrong user', `The agent runs as "${agentUser}", but the SSH user is "${config.sshUser}". Use a credential whose username is ${config.sshUser}.`);
  }
  const docker = safeFact(facts.DOCKER);
  const dockerVersion = /^ready\s+(\S+)/.exec(docker)?.[1];
  const runner = agentUser || config.sshUser;
  const dockerAdmin = evaluation.items.find((entry) => entry.id.startsWith('docker') && entry.state === prerequisites.STATE.ADMIN);
  if (dockerVersion) set('docker', STEP_STATE.READY, 'Ready', `Docker ${dockerVersion} usable by ${runner} on ${config.host}.`);
  else if (dockerAdmin) set('docker', STEP_STATE.FAILED, 'Administrator action required', dockerAdmin.detail);
  else if (docker === 'missing') set('docker', STEP_STATE.FAILED, 'Not installed', `Docker is not installed on ${config.host}.`);
  else if (docker === 'permission-denied') set('docker', STEP_STATE.FAILED, 'Permission denied', `User "${runner}" cannot use the Docker daemon on ${config.host}. Add that user to the docker group on the host.`);
  else if (docker === 'unreachable') set('docker', STEP_STATE.FAILED, 'Daemon unreachable', `The Docker daemon on ${config.host} is not running or not reachable.`);
  else set('docker', STEP_STATE.FAILED, 'Not checked', `Check build #${number} ended ${result} before Docker was checked.`);

  const problems = [];
  if (facts.WRITE !== 'ok') problems.push('the agent workspace is not writable');
  if (!facts.GIT || facts.GIT === 'missing') problems.push(`git is not installed on ${config.host}`);
  const node = /^v(\d+)\.\d+\.\d+\s+(\/\S+)$/.exec(safeFact(facts.NODE));
  if (!node) problems.push(`Node.js ${MIN_NODE_MAJOR} or later is not installed on ${config.host}`);
  else if (Number(node[1]) < MIN_NODE_MAJOR) problems.push(`Node.js ${node[1]} on ${config.host} is too old (${MIN_NODE_MAJOR} or later is required)`);
  else {
    const detectedHome = path.posix.dirname(path.posix.dirname(node[2]));
    if (detectedHome !== nodeHome) {
      const updated = await attempt(() => jenkins.post(`${nodePath}/config.xml`, { body: agentConfigXml(config, { ...agentOptions(), nodeHome: detectedHome }), contentType: 'application/xml' }));
      if (updated.error || updated.status >= 400) problems.push(`SCENTER_NODE_HOME could not be recorded on the agent (${updated.error || `HTTP ${updated.status}`})`);
      else nodeHome = detectedHome;
    }
  }
  if (!facts.DONE || build.result !== 'SUCCESS') problems.push(`check build #${number} ended ${result}`);
  if (byId.ssh.state !== STEP_STATE.READY) problems.push('SSH is not ready');
  if (byId.docker.state !== STEP_STATE.READY) problems.push('Docker is not ready');
  if (problems.length) set('runtime', STEP_STATE.FAILED, 'Not ready', `CI Runtime not ready: ${problems.join('; ')}.`);
  else set('runtime', STEP_STATE.READY, 'Ready', `Workspace ${safeFact(facts.WORKSPACE)} writable · ${safeFact(facts.GIT)} · Node.js v${node[1]} (${nodeHome}) · label ${RUNTIME_LABEL}.`);
  return report();
}

module.exports = {
  RUNTIME_LABEL, AGENT_NAME, CHECK_JOB, MANAGED_MARKER, MIN_NODE_MAJOR, STEP_STATE, CI_RUNTIME_STEPS,
  normalizeCiRuntimeConfig, agentConfigXml, checkJobConfigXml, parseCheckOutput, sshConnectionFailure, pinnedHostKey,
  configureCiRuntime, jenkinsCall, createJenkinsClient, httpProblem
};
