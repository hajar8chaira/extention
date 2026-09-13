'use strict';

/**
 * Régression Jenkins réelle : Configure Deployment sur security-pipeline-pass —
 * Jenkins, credential, SSH et Docker prêts, puis « Pipeline job: Not configured
 * — Jenkins answered HTTP 500 while trying to configure the job ».
 *
 * Jenkins lit un config.xml envoyé en POST par le lecteur du servlet : charset
 * du Content-Type, ISO-8859-1 par défaut, puis une analyse XML 1.1. Le double
 * ci-dessous fait exactement cela sur un job Declarative « Pipeline script from
 * SCM » de la forme de security-pipeline-pass, et répond comme Jenkins : HTTP 500
 * avec sa page d'erreur quand l'analyse échoue.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  CHECK_JOB, XML_CONTENT_TYPE, JOB_PARAMETERS,
  normalizeDeploymentConfig, jobParameterValues, withDeploymentParameters, readJobParameters, configureDeployment, asciiXml, jenkinsFailureReason
} = require('../src/deployment');
const { describeHostKey } = require('../src/ssh-host-key');

const sshString = (value) => {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
};
const HOST_KEY = describeHostKey(Buffer.concat([
  sshString('ssh-ed25519'),
  sshString(Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url'))
]));
const APPROVED = { algorithm: HOST_KEY.algorithm, key: HOST_KEY.key, replaces: '' };

const BASE = 'http://192.168.222.132:8080';
const USER = 'scenter-admin';
const TOKEN = '11aabbccddeeff00112233445566778899';
const WHOAMI = Object.freeze({
  host: '192.168.222.132', sshUser: 'deploy', credentialId: 'vm-deploy-key', port: '',
  containerName: 'scenter-whoami', containerPort: '80', publishedPort: '8088', healthCheckUrl: 'http://192.168.222.132:8088/'
});

/** security-pipeline-pass as Jenkins stores it: Declarative, Pipeline from SCM, pollSCM, one existing parameter. */
const PASS_JOB_XML = `<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@1540.v295eccc9778f">
  <actions>
    <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobAction plugin="pipeline-model-definition@2.2255.v56a_15e805f12"/>
    <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction plugin="pipeline-model-definition@2.2255.v56a_15e805f12">
      <jobProperties>
        <string>org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty</string>
      </jobProperties>
      <triggers>
        <string>hudson.triggers.SCMTrigger</string>
      </triggers>
      <parameters/>
      <options/>
    </org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction>
  </actions>
  <description>Pipeline de sécurité — whoami (PASS attendu)</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        <hudson.model.StringParameterDefinition>
          <name>SCENTER_ENGINE_MANIFEST_URL</name>
          <description>Manifeste du CI Engine</description>
          <defaultValue>http://192.168.222.132:8081/security-center-latest.json</defaultValue>
          <trim>false</trim>
        </hudson.model.StringParameterDefinition>
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
    <org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty>
      <abortPrevious>false</abortPrevious>
    </org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers>
        <hudson.triggers.SCMTrigger>
          <spec>H/2 * * * *</spec>
          <ignorePostCommitHooks>false</ignorePostCommitHooks>
        </hudson.triggers.SCMTrigger>
      </triggers>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps@4018.vf02e01888da_f">
    <scm class="hudson.plugins.git.GitSCM" plugin="git@5.7.0">
      <configVersion>2</configVersion>
      <userRemoteConfigs>
        <hudson.plugins.git.UserRemoteConfig>
          <url>https://github.com/hajar8chaira/whoami.git</url>
        </hudson.plugins.git.UserRemoteConfig>
      </userRemoteConfigs>
      <branches>
        <hudson.plugins.git.BranchSpec>
          <name>*/master</name>
        </hudson.plugins.git.BranchSpec>
      </branches>
      <doGenerateSubmoduleConfigurations>false</doGenerateSubmoduleConfigurations>
      <submoduleCfg class="empty-list"/>
      <extensions/>
    </scm>
    <scriptPath>Jenkinsfile</scriptPath>
    <lightweight>true</lightweight>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>
`;

/**
 * POST config.xml as Jenkins handles it: the servlet reader decodes the bytes
 * with the Content-Type charset (ISO-8859-1 when none), then the XML 1.1 parse
 * refuses restricted characters. Jenkins stores characters, not references.
 */
function jenkinsReadsConfigXml(body, contentType) {
  const charset = /charset=([\w-]+)/i.exec(String(contentType || ''))?.[1]?.toLowerCase();
  const decoded = Buffer.from(String(body), 'utf8').toString(charset === 'utf-8' || charset === 'utf8' ? 'utf8' : 'latin1');
  const restricted = /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F]/.exec(decoded);
  if (restricted) {
    return { error: `An invalid XML character (Unicode: 0x${restricted[0].charCodeAt(0).toString(16)}) was found in the element content of the document.` };
  }
  return { xml: decoded.replace(/&#(\d+);/g, (reference, code) => (Number(code) > 127 ? String.fromCodePoint(Number(code)) : reference)) };
}

/** Jenkins' HTTP 500 page for a config.xml it cannot read. */
const errorPage = (message, extra = '') => `<!DOCTYPE html><html><head><title>Jenkins [Jenkins]</title></head><body>
<h2>HTTP ERROR 500 java.io.IOException: Unable to read /var/jenkins_home/jobs/security-pipeline-pass/config.xml</h2>
<pre>java.io.IOException: Unable to read /var/jenkins_home/jobs/security-pipeline-pass/config.xml
\tat hudson.model.Items.updateByXml(Items.java:612)
\tat hudson.model.AbstractItem.doConfigDotXml(AbstractItem.java:880)
Caused by: javax.xml.transform.TransformerException: org.xml.sax.SAXParseException; lineNumber: 19; columnNumber: 112; ${message}
\tat jenkins.util.xml.XMLUtils.safeTransform(XMLUtils.java:91)
${extra}Caused by: org.xml.sax.SAXParseException; lineNumber: 19; columnNumber: 112; ${message}
\tat java.xml/com.sun.org.apache.xerces.internal.parsers.AbstractSAXParser.parse(AbstractSAXParser.java:1243)
</pre></body></html>`;

const ok = (value, headers = {}) => ({ status: 200, headers, text: typeof value === 'string' ? value : JSON.stringify(value) });
const status = (code, headers = {}, text = '') => ({ status: code, headers, text });

const READY_CONSOLE = [
  'SCENTER_DEPLOYCHECK_CLIENT=ssh', 'SCENTER_DEPLOYCHECK_GIT=ready', 'SCENTER_DEPLOYCHECK_SSH=ready deploy',
  'SCENTER_DEPLOYCHECK_DOCKER=ready 29.1.3', 'SCENTER_DEPLOYCHECK_PORT_USER=', 'SCENTER_DEPLOYCHECK_CONTAINER=absent',
  'SCENTER_DEPLOYCHECK_DONE=1', 'Finished: SUCCESS'
].join('\n');

/** Jenkins with security-pipeline-pass at `jobPath`, answering config.xml writes like the real server. */
function fakeJenkins({ jobPath = 'job/security-pipeline-pass', jobXml = PASS_JOB_XML, refuseJobWrite = null } = {}) {
  const state = { jobXml, checkXml: null, writes: [], calls: [] };
  const call = async (url, options = {}) => {
    const { pathname, search } = new URL(url);
    const route = `${options.method || 'GET'} ${pathname.replace(/^\//, '')}${search}`;
    state.calls.push({ route, url, body: options.body ?? null, contentType: options.contentType || '' });
    if (route === 'GET api/json?tree=mode') return ok({ mode: 'NORMAL' }, { 'x-jenkins': '2.516.1' });
    if (route === 'GET crumbIssuer/api/json') return ok({ crumbRequestField: 'Jenkins-Crumb', crumb: 'c0ffee' });
    if (route === 'GET pluginManager/api/json?tree=plugins[shortName,active]') {
      return ok({ plugins: ['workflow-job', 'workflow-cps', 'credentials-binding', 'ssh-credentials'].map((shortName) => ({ shortName, active: true })) });
    }
    if (route === `GET ${jobPath}/config.xml`) return ok(state.jobXml);
    if (route === `POST ${jobPath}/config.xml`) {
      state.writes.push({ url, body: options.body, contentType: options.contentType });
      if (refuseJobWrite !== null) return status(500, { 'content-type': 'text/html;charset=utf-8' }, refuseJobWrite);
      const read = jenkinsReadsConfigXml(options.body, options.contentType);
      if (read.error) return status(500, { 'content-type': 'text/html;charset=utf-8' }, errorPage(read.error));
      state.jobXml = read.xml;
      return status(200);
    }
    if (route === 'GET credentials/store/system/domain/_/credential/vm-deploy-key/api/json?tree=id,typeName') return ok({ id: 'vm-deploy-key', typeName: 'SSH Username with private key' });
    if (route === `GET job/${CHECK_JOB}/config.xml`) return state.checkXml ? ok(state.checkXml) : status(404);
    if (route === `POST createItem?name=${CHECK_JOB}` || route === `POST job/${CHECK_JOB}/config.xml`) {
      const read = jenkinsReadsConfigXml(options.body, options.contentType);
      if (read.error) return status(500, {}, errorPage(read.error));
      state.checkXml = read.xml;
      return status(200);
    }
    if (route === `POST job/${CHECK_JOB}/build?delay=0sec`) return status(201, { location: `${BASE}/queue/item/41/` });
    if (route === 'GET queue/item/41/api/json?tree=cancelled,why,executable[number]') return ok({ executable: { number: 12 } });
    if (route === `GET job/${CHECK_JOB}/12/api/json?tree=building,result`) return ok({ building: false, result: 'SUCCESS' });
    if (route === `GET job/${CHECK_JOB}/12/consoleText`) return ok(READY_CONSOLE);
    return status(404);
  };
  return { state, call };
}

const run = (jenkins, job = 'security-pipeline-pass', overrides = {}) => configureDeployment({
  config: WHOAMI, jenkins: { url: BASE, job }, user: USER, token: TOKEN, call: jenkins.call,
  approvedHostKey: APPROVED, scanHostKey: async () => HOST_KEY, sleep: async () => {}, ...overrides
});
const step = (report, id) => report.steps.find((entry) => entry.id === id);
const VALUES = jobParameterValues(normalizeDeploymentConfig(WHOAMI).config, HOST_KEY);

test('reproduces the real failure: the managed parameters posted as UTF-8 without a charset make Jenkins answer HTTP 500', () => {
  const previousBody = withDeploymentParameters(PASS_JOB_XML, VALUES);
  assert.ok(previousBody.includes('Security Delivery → Jenkins → Deployment'), 'the managed descriptions carry a non-ASCII arrow');
  // The request Security Center sent before the fix. The first restricted character is the job's own
  // "—" (UTF-8 E2 80 94, read as 0x80); the managed "→" (E2 86 92) alone gives 0x86, as Jenkins reported.
  const refused = jenkinsReadsConfigXml(previousBody, 'application/xml');
  assert.equal(refused.error, 'An invalid XML character (Unicode: 0x80) was found in the element content of the document.');
  const asciiJob = PASS_JOB_XML.replace('Pipeline de sécurité — whoami (PASS attendu)', 'whoami PASS');
  assert.match(asciiJob, /^[ -]*$/, 'an otherwise ASCII job');
  assert.equal(jenkinsReadsConfigXml(withDeploymentParameters(asciiJob, VALUES), 'application/xml').error, 'An invalid XML character (Unicode: 0x86) was found in the element content of the document.');

  // The request it sends now is read identically whatever charset the server assumes.
  const sent = asciiXml(previousBody);
  assert.match(sent, /^[\x00-\x7F]*$/, 'ASCII only');
  for (const contentType of [XML_CONTENT_TYPE, 'application/xml', 'text/xml']) {
    const read = jenkinsReadsConfigXml(sent, contentType);
    assert.equal(read.error, undefined, contentType);
    assert.equal(read.xml, previousBody, `${contentType}: Jenkins stores exactly the intended configuration`);
  }
  assert.equal(XML_CONTENT_TYPE, 'application/xml; charset=utf-8');
  assert.equal(asciiXml('a😀é'), 'a&#128512;&#233;', 'astral characters become one reference');
});

test('Configure Deployment configures security-pipeline-pass: SCM, triggers, properties and parameters kept, no duplicate on a second run', async () => {
  const jenkins = fakeJenkins();
  const first = await run(jenkins);
  assert.equal(first.ready, true, first.lines.join(' · '));
  assert.deepEqual(first.lines, ['Jenkins: Connected', 'Credential: Found', 'SSH: Ready', 'Docker: Ready', 'Pipeline job: Configured']);

  const [write] = jenkins.state.writes;
  assert.equal(write.url, `${BASE}/job/security-pipeline-pass/config.xml`, 'the job’s own config.xml endpoint');
  assert.equal(write.contentType, 'application/xml; charset=utf-8');
  assert.match(write.body, /^[\x00-\x7F]*$/, 'ASCII body: no charset guesswork on the Jenkins side');

  const stored = jenkins.state.jobXml;
  assert.deepEqual(Object.fromEntries(Object.entries(readJobParameters(stored))), VALUES);
  for (const kept of [
    '<description>Pipeline de sécurité — whoami (PASS attendu)</description>',
    '<name>SCENTER_ENGINE_MANIFEST_URL</name>',
    '<defaultValue>http://192.168.222.132:8081/security-center-latest.json</defaultValue>',
    'DeclarativeJobPropertyTrackerAction',
    '<org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty>',
    '<spec>H/2 * * * *</spec>',
    '<definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"',
    '<url>https://github.com/hajar8chaira/whoami.git</url>',
    '<name>*/master</name>',
    '<scriptPath>Jenkinsfile</scriptPath>'
  ]) assert.ok(stored.includes(kept), `kept: ${kept}`);
  assert.ok(stored.includes('Edit it in Security Delivery → Jenkins → Deployment.'), 'references decoded back to the intended text');

  const second = await run(jenkins);
  assert.equal(second.ready, true);
  assert.equal(jenkins.state.jobXml, stored, 'a second Configure Deployment changes nothing');
  assert.equal((stored.match(/<hudson\.model\.ParametersDefinitionProperty>/g) || []).length, 1);
  for (const [name] of JOB_PARAMETERS) {
    assert.equal((stored.match(new RegExp(`<name>${name}</name>`, 'g')) || []).length, 1, `${name} defined once`);
  }
  assert.equal((stored.match(/<name>SCENTER_ENGINE_MANIFEST_URL<\/name>/g) || []).length, 1);
});

test('the endpoint follows the configured job, folders and spaces URL-encoded', async () => {
  const jenkins = fakeJenkins({ jobPath: 'job/Security%20Center/job/security%20pipeline%20pass' });
  const report = await run(jenkins, 'Security Center/security pipeline pass');
  assert.equal(report.ready, true, report.lines.join(' · '));
  assert.equal(jenkins.state.writes[0].url, `${BASE}/job/Security%20Center/job/security%20pipeline%20pass/config.xml`);
});

test('a Jenkins refusal shows the sanitized reason from its error page, never a secret', async () => {
  const leaky = errorPage(
    'An invalid XML character (Unicode: 0x86) was found in the element content of the document.',
    `\tat request with Authorization: Basic ${Buffer.from(`${USER}:${TOKEN}`).toString('base64')}\n`
  );
  const jenkins = fakeJenkins({ refuseJobWrite: leaky });
  const report = await run(jenkins);
  const job = step(report, 'job');
  assert.equal(report.ready, false);
  assert.equal(job.summary, 'Not configured');
  assert.equal(job.detail, 'Jenkins answered HTTP 500 while trying to configure the job (Job/Configure): org.xml.sax.SAXParseException: lineNumber: 19; columnNumber: 112; An invalid XML character (Unicode: 0x86) was found in the element content of the document.');
  assert.ok(!JSON.stringify(report).includes(TOKEN));
  assert.ok(!JSON.stringify(report).includes(Buffer.from(`${USER}:${TOKEN}`).toString('base64')));

  // Stack traces hidden by Jenkins: the Logging ID lets an administrator find it in the Jenkins log.
  const hidden = fakeJenkins({ refuseJobWrite: '<html><body><h1>Oops!</h1><p>A problem occurred while processing the request.</p><p>Logging ID=4b0e1f7a-2c3d-4e5f-9a8b-7c6d5e4f3a2b</p></body></html>' });
  assert.equal(step(await run(hidden), 'job').detail, 'Jenkins answered HTTP 500 while trying to configure the job (Job/Configure): Jenkins logged the error with Logging ID=4b0e1f7a-2c3d-4e5f-9a8b-7c6d5e4f3a2b');

  // Nothing useful on the page: the plain HTTP status, as before.
  const empty = fakeJenkins({ refuseJobWrite: '' });
  assert.equal(step(await run(empty), 'job').detail, 'Jenkins answered HTTP 500 while trying to configure the job (Job/Configure).');

  // Secrets inside an exception message are redacted.
  const reason = jenkinsFailureReason({ text: `<pre>java.lang.IllegalStateException: token=${TOKEN} key -----BEGIN OPENSSH PRIVATE KEY-----abc-----END OPENSSH PRIVATE KEY----- password: hunter2 ${TOKEN}</pre>` }, [TOKEN]);
  assert.equal(reason, 'java.lang.IllegalStateException: token=[REDACTED] key [REDACTED] password: [REDACTED] [REDACTED]');
});
