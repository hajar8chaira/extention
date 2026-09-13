'use strict';

/**
 * Profil de déploiement « Docker on remote SSH host ».
 *
 * L'API Jenkins est un double qui répond comme un serveur réel (job, plugins,
 * credential, file d'attente, build de vérification, console). Le vrai flux de
 * Security Center s'exécute contre lui, puis le vrai câblage d'extension.js est
 * exécuté avec VS Code remplacé par des doubles.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const deployment = require('../src/deployment');
const {
  DEPLOYMENT_TYPE, CHECK_JOB, MANAGED_MARKER, JOB_PARAMETERS,
  normalizeDeploymentConfig, jobParameterValues, readJobParameters, withDeploymentParameters, checkJobConfigXml, configureDeployment
} = deployment;
const { renderDeploymentCard } = require('../src/deployment-view');
const { renderCiRuntimeCard } = require('../src/ci-runtime-view');
const ciRuntime = require('../src/ci-runtime');
const { describeHostKey } = require('../src/ssh-host-key');

const sshString = (value) => {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
};
const ed25519HostKey = () => describeHostKey(Buffer.concat([
  sshString('ssh-ed25519'),
  sshString(Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url'))
]));
const HOST_KEY = ed25519HostKey();
const OTHER_HOST_KEY = ed25519HostKey();

const TOKEN = '11aabbccddeeff00112233445566778899';
const PEM = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----';
const JENKINS = Object.freeze({ url: 'http://192.168.222.132:8080', job: 'whoami-security' });
/** The whoami E2E values, typed by a person: none of them is a production default. */
const WHOAMI = Object.freeze({
  host: '192.168.222.132', sshUser: 'deploy', credentialId: 'vm-deploy-key', port: '',
  containerName: 'scenter-whoami', containerPort: '80', publishedPort: '8088', healthCheckUrl: 'http://192.168.222.132:8088/'
});

const JOB_XML = `<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@1400.v7fd111b_ec82f">
  <description>whoami security pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        <hudson.model.StringParameterDefinition>
          <name>SONAR_PROJECT_KEY</name>
          <defaultValue>whoami</defaultValue>
          <trim>false</trim>
        </hudson.model.StringParameterDefinition>
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers/>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps@3969.vdc9d3a_efcc6a_">
    <scriptPath>Jenkinsfile</scriptPath>
    <lightweight>true</lightweight>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>
`;

const ok = (value, headers = {}) => ({ status: 200, headers, text: typeof value === 'string' ? value : JSON.stringify(value) });
const status = (code, headers = {}) => ({ status: code, headers, text: '' });

/** The deployment host, as the check build reports it over SSH. */
function checkConsole(host) {
  const lines = ['Started by user scenter-admin', '[Pipeline] node', '+ set +x', 'SCENTER_DEPLOYCHECK_CLIENT=ssh', 'SCENTER_DEPLOYCHECK_GIT=ready'];
  if (host.sshError) lines.push('SCENTER_DEPLOYCHECK_SSHFAIL=1', `SCENTER_DEPLOYCHECK_SSHERR=${host.sshError}`);
  else {
    lines.push('SCENTER_DEPLOYCHECK_SSH=ready deploy', `SCENTER_DEPLOYCHECK_DOCKER=${host.docker}`);
    if (host.docker.startsWith('ready')) lines.push(`SCENTER_DEPLOYCHECK_PORT_USER=${host.portUser || ''}`, `SCENTER_DEPLOYCHECK_CONTAINER=${host.container || 'absent'}`);
    lines.push('SCENTER_DEPLOYCHECK_DONE=1');
  }
  return [...lines, 'Finished: SUCCESS'].join('\n');
}

/** A Jenkins double: one pipeline job, the SSH credential, the check job and its build. */
function fakeJenkins({ host = { docker: 'ready 27.3.1' }, credential = 'SSH Username with private key', jobXml = JOB_XML } = {}) {
  const state = { jobXml, checkXml: null, calls: [] };
  const call = async (url, options = {}) => {
    const { pathname, search } = new URL(url);
    const route = `${options.method || 'GET'} ${pathname.replace(/^\//, '')}${search}`;
    state.calls.push({ route, url, user: options.user, token: options.token, body: options.body ?? null });
    if (route === 'GET api/json?tree=mode') return ok({ mode: 'NORMAL' }, { 'x-jenkins': '2.479.1' });
    if (route === 'GET crumbIssuer/api/json') return ok({ crumbRequestField: 'Jenkins-Crumb', crumb: 'c0ffee' });
    if (route === 'GET pluginManager/api/json?tree=plugins[shortName,active]') {
      return ok({ plugins: ['workflow-job', 'workflow-cps', 'credentials-binding', 'ssh-credentials', 'ssh-slaves'].map((shortName) => ({ shortName, active: true })) });
    }
    if (route === `GET job/${JENKINS.job}/config.xml`) return ok(state.jobXml);
    if (route === `POST job/${JENKINS.job}/config.xml`) { state.jobXml = options.body; return status(200); }
    if (route.startsWith('GET credentials/store/system/domain/_/credential/')) {
      return route.includes('/vm-deploy-key/') && credential ? ok({ id: 'vm-deploy-key', typeName: credential }) : status(404);
    }
    if (route === `GET job/${CHECK_JOB}/config.xml`) return state.checkXml ? ok(state.checkXml) : status(404);
    if (route === `POST createItem?name=${CHECK_JOB}`) { state.checkXml = options.body; return status(200); }
    if (route === `POST job/${CHECK_JOB}/config.xml`) { state.checkXml = options.body; return status(200); }
    if (route === `POST job/${CHECK_JOB}/build?delay=0sec`) return status(201, { location: `${JENKINS.url}/queue/item/7/` });
    if (route === 'GET queue/item/7/api/json?tree=cancelled,why,executable[number]') return ok({ executable: { number: 3 } });
    if (route === `GET job/${CHECK_JOB}/3/api/json?tree=building,result`) return ok({ building: false, result: 'SUCCESS' });
    if (route === `GET job/${CHECK_JOB}/3/consoleText`) return ok(checkConsole(host));
    return status(404);
  };
  return { state, call };
}

const run = (jenkins, overrides = {}) => configureDeployment({
  config: WHOAMI, jenkins: JENKINS, user: 'scenter-admin', token: TOKEN, call: jenkins.call,
  scanHostKey: async () => HOST_KEY, sleep: async () => {}, ...overrides
});
const APPROVED = { algorithm: HOST_KEY.algorithm, key: HOST_KEY.key, replaces: '' };
const summaries = (report) => Object.fromEntries(report.steps.map((step) => [step.id, step.summary]));

// ------------------------------------------------------------ profile

test('the form accepts the whoami E2E values and rejects invalid ports, URLs and pasted keys', () => {
  const checked = normalizeDeploymentConfig(WHOAMI);
  assert.equal(checked.valid, true, checked.errors.join(' '));
  assert.deepEqual(checked.config, { type: DEPLOYMENT_TYPE, ...WHOAMI, port: '22' });

  const invalid = normalizeDeploymentConfig({ ...WHOAMI, port: '0', containerPort: '70000', publishedPort: 'http', healthCheckUrl: 'http://user:pass@192.168.222.132:8088/', containerName: '-bad name' });
  assert.equal(invalid.valid, false);
  for (const message of ['The SSH port must be between 1 and 65535.', 'The container port must be between 1 and 65535.', 'The published port must be between 1 and 65535.', 'The health check URL must not contain credentials.', 'The container name must start with a letter or digit']) {
    assert.ok(invalid.errors.some((error) => error.startsWith(message)), message);
  }
  assert.equal(normalizeDeploymentConfig({ ...WHOAMI, healthCheckUrl: 'file:///etc/passwd' }).errors[0], 'The health check URL must be an http:// or https:// URL.');
  assert.equal(normalizeDeploymentConfig({ ...WHOAMI, host: 'deploy@192.168.222.132:22' }).valid, false);

  const pasted = normalizeDeploymentConfig({ ...WHOAMI, credentialId: PEM });
  assert.deepEqual(pasted, { valid: false, errors: ['Never paste an SSH key into Security Center: keep it in Jenkins Credentials and enter only its credential ID.'], config: {} });
});

test('job parameters: every other property kept, managed values replaced idempotently, only the credential ID written', () => {
  const values = jobParameterValues(normalizeDeploymentConfig(WHOAMI).config, HOST_KEY);
  assert.deepEqual(Object.keys(values), JOB_PARAMETERS.map(([name]) => name));
  const once = withDeploymentParameters(JOB_XML, values);
  assert.deepEqual(readJobParameters(once), values);
  assert.equal(withDeploymentParameters(once, values), once, 'a second configuration changes nothing');
  for (const kept of ['<name>SONAR_PROJECT_KEY</name>', '<defaultValue>whoami</defaultValue>', 'PipelineTriggersJobProperty', '<scriptPath>Jenkinsfile</scriptPath>']) assert.ok(once.includes(kept), kept);
  assert.equal((once.match(/<hudson\.model\.ParametersDefinitionProperty>/g) || []).length, 1);
  assert.match(once, new RegExp(`<description>${MANAGED_MARKER.replace(/[.()]/g, '\\$&')} ID of the Jenkins SSH credential`));

  const moved = withDeploymentParameters(once, { ...values, SCENTER_DEPLOY_PUBLISHED_PORT: '9090' });
  assert.equal(readJobParameters(moved).SCENTER_DEPLOY_PUBLISHED_PORT, '9090');
  assert.equal((moved.match(/<name>SCENTER_DEPLOY_PUBLISHED_PORT<\/name>/g) || []).length, 1);

  const empty = withDeploymentParameters('<?xml version="1.1"?>\n<flow-definition>\n  <properties/>\n  <definition/>\n</flow-definition>\n', values);
  assert.deepEqual(readJobParameters(empty), values);
  assert.throws(() => withDeploymentParameters('<html>login</html>', values), /not a Pipeline job/);
  assert.throws(() => jobParameterValues(normalizeDeploymentConfig(WHOAMI).config, null), /approved SSH host key/);

  assert.equal(values.SCENTER_DEPLOY_CREDENTIALS_ID, 'vm-deploy-key');
  // Key material, a password or a token, not the words of the "private key stays in Jenkins" notice.
  assert.doesNotMatch(once, /-----BEGIN|PuTTY-User-Key-File|password|token/i, 'no secret in the job configuration');
});

// ------------------------------------------------------------ validation and job configuration

test('PASS path: host key approved explicitly, SSH and Docker verified from Jenkins, then the job receives the profile', async () => {
  const jenkins = fakeJenkins();
  const first = await run(jenkins);
  assert.equal(first.ready, false);
  assert.deepEqual(summaries(first), { jenkins: 'Connected', credential: 'Found', ssh: 'Host key approval required', docker: 'Not checked', job: 'Not checked' });
  assert.deepEqual({ ...first.hostKeyApproval, key: undefined }, { change: 'new', host: '192.168.222.132', port: '22', algorithm: 'ssh-ed25519', key: undefined, fingerprint: HOST_KEY.fingerprint, previousFingerprint: '' });
  assert.ok(!jenkins.state.calls.some((entry) => entry.route.startsWith('POST')), 'nothing is written before the host key is approved');

  const progress = [];
  const report = await run(jenkins, { approvedHostKey: APPROVED, onProgress: (value) => progress.push(value) });
  assert.equal(report.ready, true, report.lines.join(' · '));
  assert.deepEqual(report.lines, ['Jenkins: Connected', 'Credential: Found', 'SSH: Ready', 'Docker: Ready', 'Pipeline job: Configured']);
  assert.match(report.steps.at(-1).detail, /On PASS, job whoami-security deploys container scenter-whoami to 192\.168\.222\.132:8088, then checks http:\/\/192\.168\.222\.132:8088\//);
  assert.ok(progress.length >= 5);

  const stored = readJobParameters(jenkins.state.jobXml);
  assert.deepEqual(stored, {
    SCENTER_DEPLOY_TYPE: 'docker-ssh', SCENTER_DEPLOY_HOST: '192.168.222.132', SCENTER_DEPLOY_PORT: '22', SCENTER_DEPLOY_USER: 'deploy',
    SCENTER_DEPLOY_CREDENTIALS_ID: 'vm-deploy-key', SCENTER_DEPLOY_HOST_KEY: `ssh-ed25519 ${HOST_KEY.key}`,
    SCENTER_DEPLOY_CONTAINER: 'scenter-whoami', SCENTER_DEPLOY_CONTAINER_PORT: '80', SCENTER_DEPLOY_PUBLISHED_PORT: '8088',
    SCENTER_HEALTHCHECK_URL: 'http://192.168.222.132:8088/'
  });

  const check = jenkins.state.checkXml;
  assert.ok(check.includes(MANAGED_MARKER));
  assert.match(check, /<sandbox>true<\/sandbox>/);
  assert.match(check, /sshUserPrivateKey\(credentialsId: &apos;vm-deploy-key&apos;, keyFileVariable: &apos;SCENTER_DEPLOY_KEY&apos;\)/);
  assert.match(check, /-o StrictHostKeyChecking=yes -o UserKnownHostsFile=\.scenter-deploy-known-hosts -o GlobalKnownHostsFile=\/dev\/null/);
  assert.ok(check.includes(`192.168.222.132 ssh-ed25519 ${HOST_KEY.key}`), 'only the approved host key is trusted');
  assert.doesNotMatch(check, /StrictHostKeyChecking=(no|accept-new)|NonVerifying/i);

  // Re-running with the key already pinned in the job needs no new approval.
  const again = await run(jenkins);
  assert.equal(again.ready, true);
  assert.equal(again.hostKeyApproval, null);
});

test('credential secret never exposed: the API token only authenticates calls, no key reaches a job, a parameter or the report', async () => {
  const jenkins = fakeJenkins();
  const report = await run(jenkins, { approvedHostKey: APPROVED });
  assert.equal(report.ready, true);
  for (const entry of jenkins.state.calls) {
    assert.ok(!entry.url.includes(TOKEN), `token not in ${entry.route}`);
    assert.ok(!String(entry.body || '').includes(TOKEN), `token not in the body of ${entry.route}`);
    assert.equal(entry.token, TOKEN, 'passed to the transport, which puts it in the Authorization header');
  }
  const written = jenkins.state.calls.filter((entry) => entry.body).map((entry) => entry.body).join('\n');
  // Key material or a password, not the words of the notice nor the sshUserPrivateKey binding step asserted below.
  assert.doesNotMatch(written + JSON.stringify(report), /-----BEGIN|PuTTY-User-Key-File|password/i);
  assert.ok(!(written + JSON.stringify(report)).includes('b3BlbnNzaC1rZXkt'), 'no key body');
  assert.ok(!JSON.stringify(report).includes(TOKEN));
  const check = checkJobConfigXml(normalizeDeploymentConfig(WHOAMI).config, HOST_KEY);
  assert.match(check, /keyFileVariable/, 'Jenkins binds the key to a temporary file on its own executor');
  assert.doesNotMatch(check, /echo[^\n]*SCENTER_DEPLOY_KEY|cat[^\n]*SCENTER_DEPLOY_KEY/, 'the key file is never printed');
});

test('Docker unavailable, SSH or credential problems: precise errors, and the job is never configured', async () => {
  const cases = [
    [{ host: { docker: 'missing' } }, 'docker', 'Not installed', /Docker is not installed on 192\.168\.222\.132\. Security Center never installs it/],
    [{ host: { docker: 'permission-denied' } }, 'docker', 'Permission denied', /User "deploy" cannot use the Docker daemon on 192\.168\.222\.132/],
    [{ host: { docker: 'unreachable' } }, 'docker', 'Daemon unreachable', /not running or not reachable/],
    [{ host: { docker: 'ready 27.3.1', portUser: 'traefik' } }, 'docker', 'Port in use', /Port 8088 on 192\.168\.222\.132 is already published by container "traefik"/],
    [{ host: { docker: 'ready 27.3.1', container: 'foreign' } }, 'docker', 'Container name in use', /was not deployed by Security Center\. It is never replaced/],
    [{ host: { sshError: 'deploy@192.168.222.132: Permission denied (publickey).' } }, 'ssh', 'Authentication failed', /credential "vm-deploy-key"/],
    [{ credential: null }, 'credential', 'Credential not found', /no global credential "vm-deploy-key"/],
    [{ credential: 'Username with password' }, 'credential', 'Wrong credential type', /not an SSH private key credential/]
  ];
  for (const [options, step, summary, detail] of cases) {
    const jenkins = fakeJenkins(options);
    const report = await run(jenkins, { approvedHostKey: APPROVED });
    const failed = report.steps.find((entry) => entry.id === step);
    assert.equal(report.ready, false, summary);
    assert.equal(failed.state, 'failed', summary);
    assert.equal(failed.summary, summary);
    assert.match(failed.detail, detail);
    assert.equal(jenkins.state.jobXml, JOB_XML, `${summary}: the pipeline job is untouched`);
  }
});

test('a changed deployment host key is a security warning and requires re-approval', async () => {
  const jenkins = fakeJenkins({ jobXml: withDeploymentParameters(JOB_XML, jobParameterValues(normalizeDeploymentConfig(WHOAMI).config, OTHER_HOST_KEY)) });
  const report = await run(jenkins);
  assert.equal(report.steps.find((step) => step.id === 'ssh').summary, 'Host key changed');
  assert.match(report.steps.find((step) => step.id === 'ssh').detail, /^SECURITY WARNING:/);
  assert.equal(report.hostKeyApproval.change, 'changed');
  assert.equal(report.hostKeyApproval.previousFingerprint, OTHER_HOST_KEY.fingerprint);
  assert.equal((await run(jenkins, { approvedHostKey: APPROVED })).ready, false, 'an approval that does not name the replaced key is not enough');
  assert.equal((await run(jenkins, { approvedHostKey: { ...APPROVED, replaces: OTHER_HOST_KEY.fingerprint } })).ready, true);
});

test('runtime profile remains independent: no agent, runtime job, runtime setting or runtime pin is touched', async () => {
  const jenkins = fakeJenkins();
  await run(jenkins, { approvedHostKey: APPROVED });
  const routes = jenkins.state.calls.map((entry) => entry.route);
  assert.ok(!routes.some((route) => /computer\/|scenter-ci-runtime/.test(route)), routes.join('\n'));
  assert.notEqual(CHECK_JOB, ciRuntime.CHECK_JOB);
  assert.notEqual(MANAGED_MARKER, ciRuntime.MANAGED_MARKER);
  assert.ok(JOB_PARAMETERS.every(([name]) => !/RUNTIME|NODE_HOME|SCENTER_HOME/.test(name)));
  assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'src', 'deployment.js'), 'utf8'), /ciRuntime\.|agentConfigXml|configureCiRuntime|prerequisites/);

  // Same host and credential, still two profiles: different fields, cards and actions.
  const runtimeCard = renderCiRuntimeCard({ configuration: { host: '192.168.222.132', sshUser: 'deploy', credentialId: 'vm-deploy-key' } });
  const deploymentCard = renderDeploymentCard({ configuration: WHOAMI });
  assert.doesNotMatch(runtimeCard, /containerName|publishedPort|healthCheckUrl|data-action="deployment/);
  assert.doesNotMatch(deploymentCard, /remoteRoot|jenkinsUrl|data-action="ciRuntime/);
});

test('Deployment card: separate panel, whoami values editable, no key or password field', () => {
  const card = renderDeploymentCard({ configuration: WHOAMI, status: { steps: [{ id: 'docker', label: 'Docker', state: 'failed', summary: 'Not installed', detail: 'Docker is not installed on 192.168.222.132.' }], checkedAt: '2026-09-13T10:00:00.000Z' } });
  assert.match(card, /data-panel="deployment"/);
  assert.match(card, /<h3>Docker on remote SSH host<\/h3>/);
  for (const [id, label] of [['host', 'Deployment Host'], ['sshUser', 'SSH User'], ['credentialId', 'Jenkins Credential ID'], ['port', 'SSH Port'], ['containerName', 'Container Name'], ['containerPort', 'Container Port'], ['publishedPort', 'Published Port'], ['healthCheckUrl', 'Health Check URL']]) {
    assert.match(card, new RegExp(`id="deployment-${id}" data-panel-field="${id}"`), id);
    assert.ok(card.includes(label), label);
  }
  assert.match(card, /<details class="advanced"><summary><span>Advanced<\/span><small>SSH port<\/small>/);
  assert.match(card, /value="vm-deploy-key"/);
  assert.match(card, /value="http:\/\/192\.168\.222\.132:8088\/"/);
  assert.match(card, /data-action="deploymentConfigure">Configure Deployment</);
  assert.match(card, /class="panel-step failed" data-step="docker"><strong>Docker:<\/strong> <span>Not installed<\/span>/);
  assert.doesNotMatch(card, /type="password"|<textarea|SCENTER_DEPLOY_COMMAND|SCENTER_HEALTHCHECK_URL/);
  assert.equal(renderDeploymentCard({}).includes('192.168.222.132'), false, 'no E2E value is a default');
  assert.match(renderDeploymentCard({ running: true }), /data-action="deploymentConfigure" disabled>Configuring…/);
});

// ------------------------------------------------------------ extension.js wiring

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8').replace(/\r\n/g, '\n');

function extract(marker) {
  const start = SOURCE.indexOf(marker);
  assert.ok(start >= 0, `absent d’extension.js : ${marker}`);
  assert.equal(SOURCE.indexOf(marker, start + 1), -1, `non unique : ${marker}`);
  const open = SOURCE.indexOf(') {', start) + 2;
  let depth = 0;
  for (let index = open; index < SOURCE.length; index += 1) {
    if (SOURCE[index] === '{') depth += 1;
    else if (SOURCE[index] === '}' && --depth === 0) return SOURCE.slice(start, index + 1);
  }
  throw new Error('bloc non équilibré');
}
const HANDLER = extract("if (message.action === 'deploymentSave' || message.action === 'deploymentConfigure')");
const SAVE = extract('async function saveDeploymentConfiguration(values = {})');
const RUN = extract('async function runDeploymentConfiguration(config)');

function harness({ onboarding, answer } = {}) {
  const calls = { configure: [], settings: [], workspaceState: [], info: [], error: [], warning: [], renders: 0 };
  const vscode = {
    ConfigurationTarget: { Workspace: 2 },
    ProgressLocation: { Notification: 15 },
    workspace: { getConfiguration: (section) => ({ update: async (key, value, target) => { calls.settings.push({ section, key, value, target }); } }) },
    window: {
      showInformationMessage: async (message) => { calls.info.push(message); },
      showErrorMessage: async (message) => { calls.error.push(message); },
      showWarningMessage: async (message, options, ...items) => { calls.warning.push({ message, options, items }); return answer; },
      withProgress: async (_options, task) => task({ report: () => {} })
    }
  };
  const factory = new Function('deps', `
    const { vscode, context, normalizeDeploymentConfig, DEPLOYMENT_FIELDS, configureDeployment, mergedDeliveryConfiguration, renderDeliveryPage, createAuditEvent, backendBaseUrl } = deps;
    const currentScanId = 0;
    let deploymentStatus = null;
    let deploymentRunning = false;
    ${SAVE}
    ${RUN}
    return { state: () => ({ deploymentStatus, deploymentRunning }), handle: async (message) => { ${HANDLER} } };
  `);
  return {
    calls,
    ...factory({
      vscode,
      context: { workspaceState: { update: async (key, value) => { calls.workspaceState.push({ key, value }); } } },
      normalizeDeploymentConfig,
      DEPLOYMENT_FIELDS: deployment.FIELDS,
      configureDeployment: async (options) => { calls.configure.push(options); return onboarding(options); },
      mergedDeliveryConfiguration: async () => ({ ...JENKINS, user: 'scenter-admin', token: TOKEN }),
      renderDeliveryPage: () => { calls.renders += 1; },
      createAuditEvent: async () => {},
      backendBaseUrl: () => 'http://127.0.0.1:0'
    })
  };
}

const READY = { ready: true, lines: ['Jenkins: Connected', 'Credential: Found', 'SSH: Ready', 'Docker: Ready', 'Pipeline job: Configured'], steps: [], hostKeyApproval: null };

test('extension wiring: Configure Deployment stores only the deployment profile, confirms the host key and uses the saved Jenkins integration', async () => {
  assert.match(SOURCE, /workspacePanels: selectedProvider === 'jenkins' \? renderCiRuntimeCard\(\{[\s\S]*?\}\) \+ renderDeploymentCard\(\{/, 'rendered below the runtime card');
  const approval = { change: 'new', host: '192.168.222.132', port: '22', algorithm: 'ssh-ed25519', key: HOST_KEY.key, fingerprint: HOST_KEY.fingerprint, previousFingerprint: '' };
  const host = harness({ answer: 'Trust this host key', onboarding: (options) => (options.approvedHostKey ? READY : { ...READY, ready: false, hostKeyApproval: approval, lines: ['SSH: Host key approval required'] }) });
  await host.handle({ type: 'delivery', action: 'deploymentConfigure', panel: 'deployment', values: WHOAMI });

  assert.deepEqual(host.calls.settings, [{ section: 'securityCenter', key: 'deployment', target: 2, value: { type: 'docker-ssh', ...WHOAMI, port: '22' } }]);
  assert.equal(host.calls.warning.length, 1);
  assert.equal(host.calls.warning[0].message, 'Trust the SSH host key of deployment host 192.168.222.132?');
  assert.equal(host.calls.warning[0].options.modal, true);
  assert.deepEqual(host.calls.configure.map((options) => options.approvedHostKey), [null, { algorithm: 'ssh-ed25519', key: HOST_KEY.key, replaces: '' }]);
  assert.deepEqual(host.calls.configure[0].jenkins, JENKINS);
  assert.deepEqual(host.calls.workspaceState, [{ key: 'securityCenter.deployment.status', value: READY }]);
  assert.deepEqual(host.calls.info, ['Security Center : Jenkins: Connected · Credential: Found · SSH: Ready · Docker: Ready · Pipeline job: Configured']);
  assert.ok(!JSON.stringify([host.calls.settings, host.calls.workspaceState, host.calls.info]).includes(TOKEN));
  assert.ok(!host.calls.settings.some((entry) => entry.key === 'ciRuntime'), 'the runtime profile is never written');

  const pasted = harness({ onboarding: () => READY });
  await pasted.handle({ type: 'delivery', action: 'deploymentConfigure', values: { ...WHOAMI, credentialId: PEM } });
  assert.deepEqual([pasted.calls.settings, pasted.calls.configure], [[], []]);
  assert.ok(!pasted.calls.error[0].includes('b3BlbnNzaC1rZXkt'));

  const declined = harness({ answer: undefined, onboarding: () => ({ ...READY, ready: false, hostKeyApproval: approval, lines: ['SSH: Host key approval required'] }) });
  await declined.handle({ type: 'delivery', action: 'deploymentConfigure', values: WHOAMI });
  assert.equal(declined.calls.configure.length, 1, 'nothing is trusted without approval');
  assert.deepEqual(declined.calls.error, ['Security Center : SSH: Host key approval required']);

  const saved = harness({ onboarding: () => READY });
  await saved.handle({ type: 'delivery', action: 'deploymentSave', values: WHOAMI });
  assert.deepEqual(saved.calls.configure, []);
  assert.deepEqual(saved.calls.info, ['Security Center : Deployment configuration saved.']);

  assert.doesNotMatch(extract("if (message.action === 'ciRuntimeSave' || Object.hasOwn(ciRuntimeRunActions, message.action))"), /deployment/i, 'the runtime handler knows nothing of deployment');
});
