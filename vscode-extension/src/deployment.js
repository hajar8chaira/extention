'use strict';

/**
 * Security Center deployment profile: "Docker on remote SSH host".
 *
 * Separate from the CI Runtime. The runtime is the Jenkins agent that runs the
 * analysis; the deployment is where an application goes after a Policy Gate
 * PASS. The two may share a host and a credential, but each has its own profile,
 * its own pinned host key and its own Jenkins objects.
 *
 * What this module does, from a few non-secret fields:
 *   1. validates them (host, user, credential ID, ports, container name, URL);
 *   2. checks Jenkins, the credential, SSH and Docker on the deployment host,
 *      from a managed sandboxed Jenkins job: the private key is bound inside
 *      Jenkins and never reaches Security Center, and ssh accepts only the
 *      explicitly approved host key;
 *   3. writes the profile into the pipeline job as managed, non-secret build
 *      parameters, so the Deploy and Health Check stages find it without anyone
 *      editing a Jenkins variable.
 * No private key, password or token is ever written into a job, a parameter or a
 * command: only the credential ID.
 */

const { normalizeJenkinsUrl, jenkinsJobPath, scrubJenkinsError } = require('./jenkins');
const { scanSshHostKey, describeHostKey, HOST_KEY_TYPES } = require('./ssh-host-key');
const { jenkinsCall, createJenkinsClient, httpProblem } = require('./ci-runtime');

const DEPLOYMENT_TYPE = 'docker-ssh';
const DEPLOYMENT_TYPE_LABEL = 'Docker on remote SSH host';
const CHECK_JOB = 'scenter-deployment-check';
const MANAGED_MARKER = 'Managed by Security Center (Deployment).';
/** The label the deploy script puts on containers it owns; it never replaces any other. */
const CONTAINER_LABEL = 'security-center.managed=true';

const STEP_STATE = Object.freeze({ PENDING: 'pending', READY: 'ready', FAILED: 'failed', SKIPPED: 'skipped' });
const DEPLOYMENT_STEPS = Object.freeze([
  Object.freeze({ id: 'jenkins', label: 'Jenkins' }),
  Object.freeze({ id: 'credential', label: 'Credential' }),
  Object.freeze({ id: 'ssh', label: 'SSH' }),
  Object.freeze({ id: 'docker', label: 'Docker' }),
  Object.freeze({ id: 'job', label: 'Pipeline job' })
]);

/**
 * The job parameters the Jenkinsfile reads, in order. Values only: none is a
 * secret, and the credential is referenced by its ID.
 */
const JOB_PARAMETERS = Object.freeze([
  ['SCENTER_DEPLOY_TYPE', 'Deployment type.'],
  ['SCENTER_DEPLOY_HOST', 'Deployment host.'],
  ['SCENTER_DEPLOY_PORT', 'SSH port of the deployment host.'],
  ['SCENTER_DEPLOY_USER', 'SSH user on the deployment host.'],
  ['SCENTER_DEPLOY_CREDENTIALS_ID', 'ID of the Jenkins SSH credential. The private key stays in Jenkins Credentials.'],
  ['SCENTER_DEPLOY_HOST_KEY', 'Approved SSH host key of the deployment host (public).'],
  ['SCENTER_DEPLOY_CONTAINER', 'Docker container name.'],
  ['SCENTER_DEPLOY_CONTAINER_PORT', 'Port the application listens on inside the container.'],
  ['SCENTER_DEPLOY_PUBLISHED_PORT', 'Port published on the deployment host.'],
  ['SCENTER_HEALTHCHECK_URL', 'URL checked after a successful deployment.']
]);

const HOST_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV6 = /^[0-9A-Fa-f:]{2,39}$/;
const SSH_USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const HOST_KEY = /^[A-Za-z0-9+/=]{16,8192}$/;
const KEY_MATERIAL = /BEGIN [A-Z ]*PRIVATE KEY|PuTTY-User-Key-File|ssh-(rsa|ed25519|dss) AAAA/i;

const FIELDS = Object.freeze(['host', 'port', 'sshUser', 'credentialId', 'containerName', 'containerPort', 'publishedPort', 'healthCheckUrl']);

function validPort(value) {
  return /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;
}

/** Validates the Deployment form. Nothing it rejects is ever echoed back. */
function normalizeDeploymentConfig(input = {}) {
  const text = (value) => String(value ?? '').trim();
  if (Object.values(input || {}).some((value) => KEY_MATERIAL.test(String(value ?? '')))) {
    return { valid: false, errors: ['Never paste an SSH key into Security Center: keep it in Jenkins Credentials and enter only its credential ID.'], config: {} };
  }
  const errors = [];
  const config = {
    type: DEPLOYMENT_TYPE,
    host: text(input.host),
    port: text(input.port) || '22',
    sshUser: text(input.sshUser),
    credentialId: text(input.credentialId),
    containerName: text(input.containerName),
    containerPort: text(input.containerPort),
    publishedPort: text(input.publishedPort),
    healthCheckUrl: text(input.healthCheckUrl)
  };
  if (!config.host) errors.push('Enter the deployment host.');
  else if (!HOST_NAME.test(config.host) && !IPV6.test(config.host)) errors.push('The deployment host must be a host name or an IP address, without user, port or path.');
  if (!validPort(config.port)) errors.push('The SSH port must be between 1 and 65535.');
  if (!config.sshUser) errors.push('Enter the SSH user.');
  else if (!SSH_USER.test(config.sshUser)) errors.push('The SSH user may contain letters, digits, ".", "_" and "-" only.');
  if (!config.credentialId) errors.push('Enter the ID of the Jenkins credential that holds the SSH private key.');
  else if (!CREDENTIAL_ID.test(config.credentialId)) errors.push('The Jenkins credential ID may contain letters, digits, ".", "_" and "-" only.');
  if (!config.containerName) errors.push('Enter the container name.');
  else if (!CONTAINER_NAME.test(config.containerName)) errors.push('The container name must start with a letter or digit and contain only letters, digits, ".", "_" and "-".');
  if (!validPort(config.containerPort)) errors.push('The container port must be between 1 and 65535.');
  if (!validPort(config.publishedPort)) errors.push('The published port must be between 1 and 65535.');
  if (!config.healthCheckUrl) errors.push('Enter the health check URL.');
  else {
    let url = null;
    try { url = new URL(config.healthCheckUrl); } catch { /* reported below */ }
    if (!url || !['http:', 'https:'].includes(url.protocol)) errors.push('The health check URL must be an http:// or https:// URL.');
    else if (url.username || url.password) errors.push('The health check URL must not contain credentials.');
    else if (/["'`$\\\s]/.test(config.healthCheckUrl)) errors.push('The health check URL contains characters that are not allowed.');
  }
  return { valid: !errors.length, errors, config };
}

function xml(value) {
  return String(value ?? '').replace(/[<>&'"]/g, (character) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[character]));
}

function unxml(value) {
  return String(value ?? '').replace(/&(lt|gt|amp|apos|quot);/g, (_, entity) => ({ lt: '<', gt: '>', amp: '&', apos: "'", quot: '"' }[entity]));
}

/** The parameter values written into the job for a profile and its approved host key. */
function jobParameterValues(config, hostKey) {
  if (!hostKey?.algorithm || !HOST_KEY.test(String(hostKey.key || ''))) throw new Error('The deployment profile is only written with an approved SSH host key.');
  return {
    SCENTER_DEPLOY_TYPE: DEPLOYMENT_TYPE,
    SCENTER_DEPLOY_HOST: config.host,
    SCENTER_DEPLOY_PORT: String(Number(config.port)),
    SCENTER_DEPLOY_USER: config.sshUser,
    SCENTER_DEPLOY_CREDENTIALS_ID: config.credentialId,
    SCENTER_DEPLOY_HOST_KEY: `${hostKey.algorithm} ${hostKey.key}`,
    SCENTER_DEPLOY_CONTAINER: config.containerName,
    SCENTER_DEPLOY_CONTAINER_PORT: String(Number(config.containerPort)),
    SCENTER_DEPLOY_PUBLISHED_PORT: String(Number(config.publishedPort)),
    SCENTER_HEALTHCHECK_URL: config.healthCheckUrl
  };
}

const MANAGED_NAMES = JOB_PARAMETERS.map(([name]) => name);
const STRING_PARAMETER = /<hudson\.model\.StringParameterDefinition>[\s\S]*?<\/hudson\.model\.StringParameterDefinition>\s*/g;

/** The managed parameter values currently stored in a job config.xml. */
function readJobParameters(configXml) {
  const values = {};
  for (const block of String(configXml || '').match(STRING_PARAMETER) || []) {
    const name = unxml(/<name>([^<]*)<\/name>/.exec(block)?.[1] ?? '');
    if (MANAGED_NAMES.includes(name)) values[name] = unxml(/<defaultValue>([^<]*)<\/defaultValue>/.exec(block)?.[1] ?? '');
  }
  return values;
}

/**
 * The job config.xml with the managed deployment parameters set. Every other
 * property and parameter of the job is kept byte for byte; only definitions
 * bearing a managed name are replaced.
 */
function withDeploymentParameters(configXml, values) {
  const text = String(configXml || '');
  if (!/<(flow-definition|project)[\s>]/.test(text)) throw new Error('Unexpected Jenkins job configuration: not a Pipeline job.');
  const definitions = JOB_PARAMETERS.map(([name, description]) => `        <hudson.model.StringParameterDefinition>
          <name>${name}</name>
          <description>${xml(`${MANAGED_MARKER} ${description} Edit it in Security Delivery → Jenkins → Deployment.`)}</description>
          <defaultValue>${xml(values[name] ?? '')}</defaultValue>
          <trim>true</trim>
        </hudson.model.StringParameterDefinition>
`).join('');
  const kept = text.replace(STRING_PARAMETER, (block) => (MANAGED_NAMES.includes(unxml(/<name>([^<]*)<\/name>/.exec(block)?.[1] ?? '')) ? '' : block));
  if (/<parameterDefinitions\s*\/>/.test(kept)) return kept.replace(/<parameterDefinitions\s*\/>/, `<parameterDefinitions>\n${definitions}      </parameterDefinitions>`);
  if (/<parameterDefinitions>/.test(kept)) return kept.replace(/<parameterDefinitions>\s*/, `<parameterDefinitions>\n${definitions}`);
  const property = `<hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
${definitions}      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>`;
  if (/<properties\s*\/>/.test(kept)) return kept.replace(/<properties\s*\/>/, `<properties>\n    ${property}\n  </properties>`);
  if (/<properties>/.test(kept)) return kept.replace(/<properties>\s*/, `<properties>\n    ${property}\n    `);
  throw new Error('Unexpected Jenkins job configuration: no <properties> element.');
}

/** The approved host key recorded in the job for this host and port, if any. */
function pinnedHostKey(values, config) {
  if (values.SCENTER_DEPLOY_HOST !== config.host || Number(values.SCENTER_DEPLOY_PORT || 22) !== Number(config.port)) return null;
  const [algorithm, key] = String(values.SCENTER_DEPLOY_HOST_KEY || '').split(/\s+/);
  if (!HOST_KEY_TYPES.includes(algorithm) || !key) return null;
  try {
    const described = describeHostKey(key);
    return described.algorithm === algorithm ? described : null;
  } catch {
    return null;
  }
}

function knownHostsLine(config, hostKey) {
  const target = Number(config.port) === 22 ? config.host : `[${config.host}]:${Number(config.port)}`;
  return `${target} ${hostKey.algorithm} ${hostKey.key}`;
}

/** What the check job runs on the deployment host. Prints facts, never raw errors. */
function checkScript(config) {
  return [
    'set +e',
    `published=${Number(config.publishedPort)}`,
    `container='${config.containerName}'`,
    'echo "SCENTER_DEPLOYCHECK_SSH=ready $(id -un)"',
    'if ! command -v docker >/dev/null 2>&1; then echo "SCENTER_DEPLOYCHECK_DOCKER=missing"',
    'elif docker_out="$(docker info --format \'{{.ServerVersion}}\' 2>&1)"; then',
    '  echo "SCENTER_DEPLOYCHECK_DOCKER=ready $docker_out"',
    '  echo "SCENTER_DEPLOYCHECK_PORT_USER=$(docker ps --filter "publish=$published" --format \'{{.Names}}\' | head -n 1)"',
    '  if docker container inspect "$container" >/dev/null 2>&1; then',
    '    if docker ps -a --filter label=security-center.managed=true --format \'{{.Names}}\' | grep -qx "$container"; then echo "SCENTER_DEPLOYCHECK_CONTAINER=managed"; else echo "SCENTER_DEPLOYCHECK_CONTAINER=foreign"; fi',
    '  else echo "SCENTER_DEPLOYCHECK_CONTAINER=absent"; fi',
    'else case "$docker_out" in *ermission*) echo "SCENTER_DEPLOYCHECK_DOCKER=permission-denied" ;; *) echo "SCENTER_DEPLOYCHECK_DOCKER=unreachable" ;; esac; fi',
    'echo "SCENTER_DEPLOYCHECK_DONE=1"'
  ].join('\n') + '\n';
}

/**
 * The managed, sandboxed check pipeline. It runs where the Deploy stage runs (any
 * non-exclusive executor), binds the credential inside Jenkins and uses ssh with
 * the approved host key only. The remote script travels as base64.
 */
function checkJobConfigXml(config, hostKey) {
  const pipeline = [
    'node {',
    `  withCredentials([sshUserPrivateKey(credentialsId: '${config.credentialId}', keyFileVariable: 'SCENTER_DEPLOY_KEY')]) {`,
    `    writeFile(file: '.scenter-deploy-known-hosts', text: '${knownHostsLine(config, hostKey)}\\n')`,
    `    writeFile(file: '.scenter-deploy-check.b64', text: '${Buffer.from(checkScript(config), 'utf8').toString('base64')}')`,
    "    sh(label: 'Security Center deployment check', script: '''set +x",
    'rm -f .scenter-deploy-check.sh .scenter-deploy-ssh.err',
    'if command -v ssh >/dev/null 2>&1; then echo "SCENTER_DEPLOYCHECK_CLIENT=ssh"; else echo "SCENTER_DEPLOYCHECK_CLIENT=missing"; fi',
    'if command -v git >/dev/null 2>&1; then echo "SCENTER_DEPLOYCHECK_GIT=ready"; else echo "SCENTER_DEPLOYCHECK_GIT=missing"; fi',
    'if command -v ssh >/dev/null 2>&1; then',
    'base64 -d .scenter-deploy-check.b64 > .scenter-deploy-check.sh',
    `ssh -i "$SCENTER_DEPLOY_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=.scenter-deploy-known-hosts -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=20 -p ${Number(config.port)} ${config.sshUser}@${config.host} 'sh -s' < .scenter-deploy-check.sh 2> .scenter-deploy-ssh.err`,
    'status=$?',
    'if [ "$status" = 255 ]; then echo "SCENTER_DEPLOYCHECK_SSHFAIL=1"; head -n 5 .scenter-deploy-ssh.err | sed "s/^/SCENTER_DEPLOYCHECK_SSHERR=/"; fi',
    'fi',
    'rm -f .scenter-deploy-check.sh .scenter-deploy-check.b64 .scenter-deploy-ssh.err .scenter-deploy-known-hosts',
    "''')",
    '  }',
    '}',
    ''
  ].join('\n');
  return `<?xml version="1.1" encoding="UTF-8"?>
<flow-definition>
  <description>${xml(MANAGED_MARKER)} Verifies SSH and Docker on the deployment host.</description>
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

/** Text that came from a remote host: printable and bounded. */
function safeFact(value) {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '').trim().slice(0, 200);
}

function parseCheckOutput(text) {
  const facts = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = /^SCENTER_DEPLOYCHECK_([A-Z_]+)=(.*)$/.exec(line.trim());
    if (match) (facts[match[1]] ||= []).push(safeFact(match[2]));
  }
  return facts;
}

function sshFailure(errors, config, pin) {
  const text = errors.join('\n');
  if (/host key verification failed|remote host identification has changed|host key for .* has changed/i.test(text)) {
    return { summary: 'Host key mismatch', detail: `Jenkins refused the SSH host key presented by ${config.host}:${config.port}: it is not the approved ${pin.algorithm} ${pin.fingerprint}. Nothing was trusted.` };
  }
  if (/permission denied|authentication/i.test(text)) {
    return { summary: 'Authentication failed', detail: `SSH authentication failed for ${config.sshUser}@${config.host} with credential "${config.credentialId}". Its public key must be authorized for ${config.sshUser} on ${config.host}.` };
  }
  return { summary: 'Host unreachable', detail: `Jenkins cannot reach ${config.host}:${config.port} over SSH.` };
}

const json = (response) => { try { return JSON.parse(response?.text || ''); } catch { return null; } };
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
 * Validates the deployment profile and configures the pipeline job. `jenkins`
 * is the saved Security Delivery → Jenkins integration: { url, job }.
 */
async function configureDeployment({
  config: input = {}, jenkins: integration = {}, user = '', token = '', call = jenkinsCall,
  approvedHostKey = null, scanHostKey = scanSshHostKey,
  sleep = defaultSleep, now = Date.now, timeouts = {}, onProgress = () => {}
} = {}) {
  const limits = { requestMs: 15000, hostKeyMs: 10000, queueMs: 300000, buildMs: 300000, pollMs: 3000, ...timeouts };
  const steps = DEPLOYMENT_STEPS.map((step) => ({ id: step.id, label: step.label, state: STEP_STATE.PENDING, summary: 'Not checked', detail: '' }));
  const byId = Object.fromEntries(steps.map((step) => [step.id, step]));
  let hostKeyApproval = null;
  const report = () => ({
    ready: steps.every((step) => step.state === STEP_STATE.READY),
    type: DEPLOYMENT_TYPE,
    steps: steps.map((step) => ({ ...step })),
    lines: steps.map((step) => `${step.label}: ${step.summary}`),
    hostKeyApproval,
    checkedAt: new Date(now()).toISOString()
  });
  const set = (id, state, summary, detail = '') => {
    Object.assign(byId[id], { state, summary, detail });
    onProgress(report());
  };
  const stop = (id, summary, detail) => {
    Object.assign(byId[id], { state: STEP_STATE.FAILED, summary, detail });
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
  const checked = normalizeDeploymentConfig(input);
  if (!checked.valid) return stop('jenkins', 'Not configured', checked.errors.join(' '));
  const config = checked.config;
  let baseUrl;
  let jobPath;
  try {
    baseUrl = normalizeJenkinsUrl(integration.url);
    jobPath = jenkinsJobPath(integration.job);
  } catch (error) {
    return stop('jenkins', 'Not configured', `Configure Security Delivery → Jenkins first (${error.message}).`);
  }
  if (!user || !token) {
    return stop('jenkins', 'Not authenticated', 'Configure the Jenkins API user and token in Security Delivery → Jenkins: Security Center needs them to configure the pipeline job.');
  }
  set('jenkins', STEP_STATE.PENDING, 'Checking');
  const client = createJenkinsClient({ baseUrl, user, token, call, timeoutMs: limits.requestMs });
  const root = await attempt(() => client.get('api/json?tree=mode'));
  if (root.error) return stop('jenkins', 'Unreachable', `Cannot reach Jenkins at ${baseUrl}: ${root.error}`);
  if (root.status !== 200) return stop('jenkins', [401, 403].includes(root.status) ? 'Not authenticated' : 'Error', httpProblem(root, 'read Jenkins'));
  const jobConfig = await attempt(() => client.get(`${jobPath}/config.xml`));
  if (jobConfig.status === 404) return stop('jenkins', 'Job not found', `Jenkins has no job "${integration.job}".`);
  if (jobConfig.error || jobConfig.status !== 200) return stop('jenkins', 'Error', jobConfig.error || httpProblem(jobConfig, 'read the job configuration (Job/Configure)'));
  const plugins = await attempt(() => client.get('pluginManager/api/json?tree=plugins[shortName,active]'));
  const pluginList = plugins.status === 200 ? (json(plugins)?.plugins || []) : null;
  const pluginActive = (name) => !pluginList || pluginList.some((plugin) => plugin.shortName === name && plugin.active);
  if (!pluginActive('credentials-binding') || !pluginActive('ssh-credentials')) {
    return stop('jenkins', 'Plugins missing', 'The Jenkins plugins "Credentials Binding" and "SSH Credentials" are required: Jenkins uses the SSH credential to deploy without the key ever leaving Jenkins.');
  }
  set('jenkins', STEP_STATE.READY, 'Connected', `Job ${integration.job}.`);

  // ------------------------------------------------------------ 2. Credential
  const credential = await attempt(() => client.get(`credentials/store/system/domain/_/credential/${encodeURIComponent(config.credentialId)}/api/json?tree=id,typeName`));
  if (credential.status === 404) {
    return stop('credential', 'Credential not found', `Jenkins has no global credential "${config.credentialId}". Create an "SSH Username with private key" credential in Jenkins Credentials, then enter its ID.`);
  }
  if (credential.error || credential.status !== 200) return stop('credential', 'Credential unavailable', credential.error || httpProblem(credential, 'view credentials'));
  const credentialType = safeFact(json(credential)?.typeName);
  if (!/ssh/i.test(credentialType)) {
    return stop('credential', 'Wrong credential type', `Credential "${config.credentialId}" is "${credentialType || 'unknown'}", not an SSH private key credential.`);
  }
  set('credential', STEP_STATE.READY, 'Found', `${credentialType} "${config.credentialId}". Only its ID is used.`);

  // ------------------------------------------------------------ 3. SSH host key, approved explicitly
  set('ssh', STEP_STATE.PENDING, 'Checking');
  let presented;
  try {
    presented = await scanHostKey({ host: config.host, port: Number(config.port), timeoutMs: limits.hostKeyMs });
  } catch (error) {
    return stop('ssh', 'Host key unavailable', `Security Center could not read the SSH host key of ${config.host}:${config.port} (${safeFact(error.message)}).`);
  }
  const pinned = pinnedHostKey(readJobParameters(jobConfig.text), config);
  const sameKey = (a, b) => Boolean(a && b && a.algorithm === b.algorithm && a.key === b.key);
  let approval = null;
  if (approvedHostKey?.key) {
    try {
      const described = describeHostKey(String(approvedHostKey.key));
      if (!approvedHostKey.algorithm || approvedHostKey.algorithm === described.algorithm) approval = { ...described, replaces: String(approvedHostKey.replaces || '') };
    } catch { /* not a host key: ignored */ }
  }
  let pin = null;
  if (pinned && sameKey(pinned, presented)) pin = pinned;
  else if (!pinned && sameKey(approval, presented) && !approval.replaces) pin = presented;
  else if (pinned && sameKey(approval, presented) && approval.replaces === pinned.fingerprint) pin = presented;
  if (!pin) {
    hostKeyApproval = {
      change: pinned ? 'changed' : 'new', host: config.host, port: config.port,
      algorithm: presented.algorithm, key: presented.key, fingerprint: presented.fingerprint,
      previousFingerprint: pinned ? pinned.fingerprint : ''
    };
    return pinned
      ? stop('ssh', 'Host key changed', `SECURITY WARNING: ${config.host}:${config.port} now presents ${presented.algorithm} ${presented.fingerprint}, but the deployment profile trusts ${pinned.algorithm} ${pinned.fingerprint}. Nothing is deployed until the new key is explicitly approved.`)
      : stop('ssh', 'Host key approval required', `First SSH connection to ${config.host}:${config.port} for deployment. Confirm its host key: ${presented.algorithm} ${presented.fingerprint}.`);
  }

  // ------------------------------------------------------------ 3-4. SSH and Docker, from a real Jenkins build
  const checkPath = `job/${encodeURIComponent(CHECK_JOB)}`;
  const current = await attempt(() => client.get(`${checkPath}/config.xml`));
  const body = checkJobConfigXml(config, pin);
  let saved;
  if (current.status === 200) {
    if (!current.text.includes(MANAGED_MARKER)) return stop('ssh', 'Check job name in use', `A Jenkins job named "${CHECK_JOB}" exists but was not created by Security Center. It is never overwritten.`);
    saved = await attempt(() => client.post(`${checkPath}/config.xml`, { body, contentType: 'application/xml' }));
  } else if (current.status === 404) {
    saved = await attempt(() => client.post(`createItem?name=${encodeURIComponent(CHECK_JOB)}`, { body, contentType: 'application/xml' }));
  } else {
    saved = current;
  }
  if (saved.error || saved.status >= 400) return stop('ssh', 'Check not started', saved.error || httpProblem(saved, 'create or configure jobs (Job/Create, Job/Configure)'));
  const queued = await attempt(() => client.post(`${checkPath}/build?delay=0sec`));
  if (queued.error || queued.status >= 400) return stop('ssh', 'Check not started', queued.error || httpProblem(queued, 'build jobs (Job/Build)'));
  const queueId = /\/queue\/item\/(\d+)\/?$/.exec(String(queued.headers?.location || ''))?.[1];
  if (!queueId) return stop('ssh', 'Check not started', 'Jenkins did not return the queue item of the deployment check build.');
  const item = await poll(async () => json(await attempt(() => client.get(`queue/item/${queueId}/api/json?tree=cancelled,why,executable[number]`))) || {},
    (value) => value.cancelled === true || Number.isInteger(value.executable?.number),
    { sleep, now, timeoutMs: limits.queueMs, intervalMs: limits.pollMs });
  if (!Number.isInteger(item.executable?.number)) {
    return stop('ssh', 'Check not started', item.cancelled ? 'The deployment check build was cancelled in Jenkins.' : `The deployment check build did not start within ${Math.round(limits.queueMs / 1000)}s${item.why ? ` (${safeFact(item.why)})` : ''}.`);
  }
  const number = item.executable.number;
  const build = await poll(async () => json(await attempt(() => client.get(`${checkPath}/${number}/api/json?tree=building,result`))) || { building: true },
    (value) => value.building === false,
    { sleep, now, timeoutMs: limits.buildMs, intervalMs: limits.pollMs });
  if (build.building !== false) return stop('ssh', 'Check timed out', `Deployment check build #${number} did not finish within ${Math.round(limits.buildMs / 1000)}s.`);
  const output = await attempt(() => client.get(`${checkPath}/${number}/consoleText`, { maxBytes: 256 * 1024 }));
  const facts = parseCheckOutput(output.text);
  const fact = (key) => facts[key]?.[0] || '';

  if (fact('CLIENT') === 'missing') return stop('ssh', 'No ssh client in Jenkins', 'The Jenkins executor that runs the Deploy stage has no ssh client: an administrator must install openssh-client there.');
  if (fact('SSHFAIL')) {
    const failure = sshFailure(facts.SSHERR || [], config, pin);
    return stop('ssh', failure.summary, failure.detail);
  }
  const remoteUser = fact('SSH').replace(/^ready\s*/, '');
  if (!fact('SSH')) return stop('ssh', 'Not checked', `Deployment check build #${number} ended ${safeFact(build.result) || 'without a result'} before SSH was verified.`);
  if (fact('GIT') === 'missing') return stop('ssh', 'No git in Jenkins', 'The Jenkins executor that runs the Deploy stage has no git: it is needed to send the analysed commit to the deployment host.');
  set('ssh', STEP_STATE.READY, 'Ready', `Connected from Jenkins as ${remoteUser || config.sshUser} with credential ${config.credentialId}; host key ${pin.algorithm} ${pin.fingerprint} pinned.`);

  const docker = fact('DOCKER');
  const version = /^ready\s+(\S+)/.exec(docker)?.[1];
  if (docker === 'missing') return stop('docker', 'Not installed', `Docker is not installed on ${config.host}. Security Center never installs it: an administrator must install Docker Engine there.`);
  if (docker === 'permission-denied') return stop('docker', 'Permission denied', `User "${remoteUser || config.sshUser}" cannot use the Docker daemon on ${config.host}. An administrator must add that user to the docker group.`);
  if (docker === 'unreachable') return stop('docker', 'Daemon unreachable', `The Docker daemon on ${config.host} is not running or not reachable.`);
  if (!version) return stop('docker', 'Not checked', `Deployment check build #${number} ended before Docker was checked.`);
  const portUser = fact('PORT_USER');
  if (portUser && portUser !== config.containerName) {
    return stop('docker', 'Port in use', `Port ${config.publishedPort} on ${config.host} is already published by container "${portUser}". Choose another published port.`);
  }
  if (fact('CONTAINER') === 'foreign') {
    return stop('docker', 'Container name in use', `A container named "${config.containerName}" exists on ${config.host} but was not deployed by Security Center. It is never replaced: choose another container name.`);
  }
  set('docker', STEP_STATE.READY, 'Ready', `Docker ${version} usable by ${remoteUser || config.sshUser} on ${config.host}; port ${config.publishedPort} available.`);

  // ------------------------------------------------------------ 5. Pipeline job
  set('job', STEP_STATE.PENDING, 'Configuring');
  const values = jobParameterValues(config, pin);
  let updated;
  try { updated = withDeploymentParameters(jobConfig.text, values); } catch (error) { return stop('job', 'Unsupported job', error.message); }
  const written = await attempt(() => client.post(`${jobPath}/config.xml`, { body: updated, contentType: 'application/xml' }));
  if (written.error || written.status >= 400) return stop('job', 'Not configured', written.error || httpProblem(written, 'configure the job (Job/Configure)'));
  const reread = await attempt(() => client.get(`${jobPath}/config.xml`));
  const stored = readJobParameters(reread.text);
  if (reread.status !== 200 || MANAGED_NAMES.some((name) => stored[name] !== values[name])) {
    return stop('job', 'Not verified', `Jenkins did not keep the deployment profile on job "${integration.job}".`);
  }
  set('job', STEP_STATE.READY, 'Configured', `On PASS, job ${integration.job} deploys container ${config.containerName} to ${config.host}:${config.publishedPort}, then checks ${config.healthCheckUrl}.`);
  return report();
}

module.exports = {
  DEPLOYMENT_TYPE, DEPLOYMENT_TYPE_LABEL, CHECK_JOB, MANAGED_MARKER, CONTAINER_LABEL, STEP_STATE, DEPLOYMENT_STEPS, JOB_PARAMETERS, FIELDS,
  normalizeDeploymentConfig, jobParameterValues, readJobParameters, withDeploymentParameters, pinnedHostKey,
  checkScript, checkJobConfigXml, parseCheckOutput, configureDeployment
};
