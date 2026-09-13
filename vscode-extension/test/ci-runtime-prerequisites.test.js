'use strict';

/**
 * Prérequis du runtime CI : exigence Java lue dans Jenkins, versions épinglées,
 * évaluation Ready / Missing / Administrateur, et sûreté des scripts distants.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');

const {
  MANAGED_TOOLS, ADMIN_ACTIONS, readZipEntries, javaRequirementFromRemotingJar, detectScript, installScript, adminScript,
  prepareJobConfigXml, knownHostsLine, parseMarkers, evaluatePrerequisites, approvedPlan, installOutcome
} = require('../src/ci-runtime-prerequisites');

const CONFIG = Object.freeze({ host: '192.168.222.132', port: '22', sshUser: 'deploy', credentialId: 'vm-deploy-key', remoteRoot: '/home/deploy/scenter-agent' });
const JAVA21 = Object.freeze({ major: 21, source: 'remoting 3301 (class files)' });
const HOST_KEY = Object.freeze({ algorithm: 'ssh-ed25519', key: 'AAAAC3NzaC1lZDI1NTE5AAAAIGhvc3Qta2V5LWZvci10ZXN0cy1vbmx5LTEyMzQ1Ng==' });

function jar(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, raw, method] of files) {
    const data = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const nameBuffer = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(method, 8); local.writeUInt32LE(data.length, 18); local.writeUInt16LE(nameBuffer.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(method, 10); central.writeUInt32LE(data.length, 20); central.writeUInt16LE(nameBuffer.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuffer, data);
    centrals.push(central, nameBuffer);
    offset += 30 + nameBuffer.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
const launcherClass = (javaMajor) => Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 44 + javaMajor]), Buffer.alloc(32)]);

/** Detection markers as the host reports them; `overrides` replaces whole keys. */
function markers(overrides = {}) {
  return {
    SSH: ['ready deploy'], PLATFORM: ['Linux x86_64'], WORKSPACE: ['ready /home/deploy/scenter-agent'],
    JAVA: ['21.0.5 /usr/bin/java'], NODE: ['v22.11.0 /usr/bin/node'], GIT: ['git version 2.43.0'],
    DOCKER_CLI: ['ready /usr/bin/docker'], DOCKER_DAEMON: ['ready 27.3.1'], DOCKER_SOCKET: ['docker'],
    GROUPS: ['deploy docker'], SUDO: ['unavailable'], TOOLS: ['curl tar sha256sum systemctl usermod apt-get'], DONE: ['1'],
    ...overrides
  };
}
const evaluate = (overrides, javaRequirement = JAVA21) => evaluatePrerequisites(markers(overrides), { config: CONFIG, javaRequirement });
const byId = (evaluation, id) => evaluation.items.find((item) => item.id === id);

// ------------------------------------------------------------ Java requirement and pins

test('Java requirement comes from Jenkins remoting.jar: class files or declared minimum, whichever is higher', () => {
  const manifest = (declared) => Buffer.from(`Manifest-Version: 1.0\r\nVersion: 3301.v4363ddcca_4e7\r\n${declared ? `Remoting-Minimum-Java-Version: ${declared}\r\n` : ''}`);
  assert.deepEqual(javaRequirementFromRemotingJar(jar([['META-INF/MANIFEST.MF', manifest(0), 0], ['hudson/remoting/Launcher.class', launcherClass(21), 8]])),
    { major: 21, source: 'remoting 3301.v4363ddcca_4e7 (class files)' });
  assert.equal(javaRequirementFromRemotingJar(jar([['META-INF/MANIFEST.MF', manifest(25), 8], ['hudson/remoting/Launcher.class', launcherClass(21), 0]])).major, 25);
  assert.equal(javaRequirementFromRemotingJar(jar([['META-INF/MANIFEST.MF', manifest(17), 0], ['hudson/remoting/Launcher.class', launcherClass(21), 8]])).major, 21);
  assert.equal(javaRequirementFromRemotingJar(Buffer.from('not a jar')), null);
  assert.deepEqual(readZipEntries(Buffer.alloc(10), ['x']), {});
});

test('managed tools are version-pinned to official HTTPS downloads with SHA-256', () => {
  for (const [tool, majors] of Object.entries(MANAGED_TOOLS)) {
    for (const [major, pin] of Object.entries(majors)) {
      assert.match(pin.version, /^v?\d+\.\d+/, `${tool} ${major}`);
      for (const [arch, asset] of Object.entries(pin.assets)) {
        assert.match(asset.url, /^https:\/\/(github\.com\/adoptium\/temurin\d+-binaries\/releases\/download|nodejs\.org\/dist)\//, `${tool} ${major} ${arch}`);
        assert.ok(asset.url.includes(tool === 'java' ? `jre_${arch}_linux` : `linux-${arch === 'aarch64' ? 'arm64' : 'x64'}`), asset.url);
        assert.match(asset.sha256, /^[0-9a-f]{64}$/);
      }
    }
  }
  assert.deepEqual(Object.keys(MANAGED_TOOLS.java), ['17', '21', '25']);
  assert.equal(MANAGED_TOOLS.node[22].version, 'v22.23.2');
});

// ------------------------------------------------------------ evaluation

test('everything installed: every prerequisite ready, nothing to install, no administrator action', () => {
  const evaluation = evaluate();
  assert.deepEqual(evaluation.items.map((item) => `${item.label}:${item.state}`), [
    'SSH:ready', 'Agent workspace:ready', 'Java 21:ready', 'Git:ready', 'Node.js 22:ready', 'Docker:ready', 'Docker daemon:ready', 'Docker access:ready'
  ]);
  assert.equal(evaluation.installPlan, null);
  assert.equal(evaluation.admin, null);
  assert.deepEqual({ path: evaluation.java.path, managed: evaluation.java.managed }, { path: '/usr/bin/java', managed: false });
  assert.equal(evaluation.node.home, '/usr');
});

test('missing Java and Node.js on Linux x64/aarch64: managed plan into the agent directory, matching the platform', () => {
  const evaluation = evaluate({ JAVA: ['17.0.12 /usr/bin/java', '1.8.0_392 /opt/java8/bin/java'], NODE: ['v18.20.4 /usr/bin/node'] });
  assert.equal(byId(evaluation, 'java').state, 'missing');
  assert.equal(byId(evaluation, 'node').state, 'missing');
  assert.deepEqual(evaluation.installPlan.map(({ tool, version, platform, destination, binary }) => ({ tool, version, platform, destination, binary })), [
    { tool: 'java', version: '21.0.12.1+1', platform: 'linux-x64', destination: '/home/deploy/scenter-agent/tools/java21', binary: 'bin/java' },
    { tool: 'node', version: 'v22.23.2', platform: 'linux-x64', destination: '/home/deploy/scenter-agent/tools/node22', binary: 'bin/node' }
  ]);
  const arm = evaluate({ PLATFORM: ['Linux aarch64'], JAVA: [] });
  assert.equal(arm.installPlan[0].url, MANAGED_TOOLS.java[21].assets.aarch64.url);
  assert.equal(arm.installPlan[0].sha256, MANAGED_TOOLS.java[21].assets.aarch64.sha256);
  const managed = evaluate({ JAVA: ['21.0.12.1 /home/deploy/scenter-agent/tools/java21/bin/java', '17.0.12 /usr/bin/java'] });
  assert.equal(managed.java.managed, true);
});

test('what cannot be installed safely becomes an administrator action with exact commands', () => {
  const noDownloader = evaluate({ JAVA: [], TOOLS: ['tar systemctl apt-get'] });
  assert.equal(byId(noDownloader, 'java').state, 'admin');
  assert.match(noDownloader.admin.instructions, /sudo apt-get update && sudo apt-get install -y openjdk-21-jre-headless/);

  const unwritable = evaluate({ WORKSPACE: ['not-writable /home/deploy/scenter-agent'], JAVA: [] });
  assert.equal(byId(unwritable, 'workspace').state, 'admin');
  assert.equal(byId(unwritable, 'java').state, 'admin', 'nothing is installed into a workspace that cannot be written');
  assert.match(unwritable.admin.instructions, /sudo chown -R deploy: \/home\/deploy\/scenter-agent/);

  const git = evaluate({ GIT: ['missing'], TOOLS: ['curl tar sha256sum dnf'] });
  assert.equal(byId(git, 'git').state, 'admin');
  assert.match(git.admin.instructions, /sudo dnf install -y git/);
});

test('Docker: missing engine, stopped daemon and denied access are distinct, precise administrator actions', () => {
  const missing = evaluate({ DOCKER_CLI: ['missing'], DOCKER_DAEMON: [], SUDO: ['non-interactive'] });
  assert.deepEqual(['docker-cli', 'docker-daemon', 'docker-access'].map((id) => byId(missing, id).state), ['admin', 'blocked', 'blocked']);
  assert.deepEqual(missing.admin.actions, [], 'Docker Engine is never installed automatically, even with sudo');

  const stopped = evaluate({ DOCKER_DAEMON: ['unreachable'], SUDO: ['non-interactive'] });
  assert.equal(byId(stopped, 'docker-daemon').detail, 'The Docker daemon on 192.168.222.132 is not running or not reachable.');
  assert.deepEqual(stopped.admin.actions, [{ id: 'docker-start', label: 'Start the Docker service and enable it at boot', command: 'sudo systemctl enable --now docker' }]);

  const denied = evaluate({ DOCKER_DAEMON: ['permission-denied'], GROUPS: ['deploy adm'] });
  assert.equal(byId(denied, 'docker-access').detail, 'User deploy cannot use the Docker daemon: /var/run/docker.sock belongs to group "docker" and deploy is not a member (groups: deploy adm).');
  assert.deepEqual(denied.admin.actions, [], 'no non-interactive sudo: manual instructions only');
  assert.match(denied.admin.instructions, /sudo usermod -aG docker deploy/);
  assert.match(denied.admin.instructions, /never asks for, sends or stores a sudo password/);
  assert.deepEqual(evaluate({ DOCKER_DAEMON: ['permission-denied'], SUDO: ['non-interactive'] }).admin.actions.map((action) => action.id), ['docker-group']);
});

test('approvals bind to the exact tool, version and destination; install results name the failure', () => {
  const { installPlan } = evaluate({ JAVA: [], NODE: [] });
  assert.deepEqual(approvedPlan(installPlan, [{ tool: 'java', version: '21.0.12.1+1', destination: '/home/deploy/scenter-agent/tools/java21' }]).map((item) => item.tool), ['java']);
  assert.deepEqual(approvedPlan(installPlan, [{ tool: 'java', version: '21.0.1+12', destination: '/home/deploy/scenter-agent/tools/java21' }]), []);
  assert.deepEqual(approvedPlan(installPlan, null), []);
  const outcome = installOutcome(parseMarkers([
    'SCENTER_INSTALL_JAVA=checksum-mismatch 00ff', 'SCENTER_INSTALL_NODE=already v22.23.2'
  ].join('\n'), 'INSTALL'), installPlan);
  assert.equal(outcome[0].ok, false);
  assert.match(outcome[0].detail, /SHA-256 00ff does not match the pinned [0-9a-f]{64}\. Nothing was installed\./);
  assert.deepEqual({ ok: outcome[1].ok, status: outcome[1].status }, { ok: true, status: 'already' });
});

// ------------------------------------------------------------ remote scripts and preparation job

test('install script: trusted pinned sources only, checksum verified before unpacking, atomic, idempotent, no sudo', () => {
  const { installPlan } = evaluate({ JAVA: [], NODE: [] });
  const script = installScript(CONFIG, installPlan);
  const checksum = script.indexOf('if [ "$actual" != "$sha" ]');
  assert.ok(checksum > 0 && checksum < script.indexOf('tar -xzf'), 'SHA-256 checked before tar');
  assert.ok(script.indexOf('"$work/extract/$binary" "$probe"') < script.indexOf('mv "$work/extract" "$dest"'), 'the tool runs before it replaces anything');
  assert.match(script, /\.scenter-version/, 'idempotent through a version marker');
  assert.match(script, /--proto "=https" --tlsv1\.2/);
  assert.doesNotMatch(script, /sudo|apt-get|chmod 777/);
  assert.match(script, /install_tool JAVA '21\.0\.12\.1\+1' 'https:\/\/github\.com\/adoptium\/[^']+' '[0-9a-f]{64}' '\/home\/deploy\/scenter-agent\/tools\/java21' 'bin\/java' '-version'/);
  assert.throws(() => installScript(CONFIG, [{ ...installPlan[0], url: 'https://evil.example/java.tar.gz' }]), /unpinned or untrusted/);
  assert.throws(() => installScript(CONFIG, [{ ...installPlan[0], sha256: 'abc' }]), /unpinned or untrusted/);
});

test('detection and admin scripts never prompt: sudo -n only, and only the approved actions', () => {
  const detection = detectScript(CONFIG, 21);
  assert.match(detection, /root='\/home\/deploy\/scenter-agent'/);
  assert.match(detection, /sudo -n true/);
  assert.doesNotMatch(detection.replace(/command -v sudo|sudo -n true/g, ''), /sudo/, 'detection only asks whether non-interactive sudo exists');
  const admin = adminScript(CONFIG, ['docker-group']);
  assert.match(admin, /sudo -n usermod -aG docker 'deploy'/);
  assert.doesNotMatch(admin, /systemctl/, 'only the approved action');
  assert.doesNotMatch(admin.replace(/command -v sudo/g, ''), /sudo (?!-n)|sudo -S|SUDO_ASKPASS|password/i, 'privileged commands only through sudo -n');
  assert.equal(adminScript(CONFIG, ['rm-rf-slash']).includes('rm'), false, 'unknown actions are ignored');
  assert.deepEqual(Object.keys(ADMIN_ACTIONS), ['docker-group', 'docker-start']);
});

test('preparation job: sandboxed, credential bound inside Jenkins, only the approved host key accepted', () => {
  const script = detectScript(CONFIG, 21);
  const xml = prepareJobConfigXml({ config: CONFIG, hostKey: HOST_KEY, script, runtimeLabel: 'scenter-ci-runtime', marker: 'Managed by Security Center (CI Runtime).', mode: 'detection' });
  assert.match(xml, /<sandbox>true<\/sandbox>/);
  assert.match(xml, /node\(&apos;!scenter-ci-runtime&apos;\)/, 'never on the runtime being prepared');
  assert.match(xml, /sshUserPrivateKey\(credentialsId: &apos;vm-deploy-key&apos;, keyFileVariable: &apos;SCENTER_SSH_KEY&apos;\)/);
  assert.ok(xml.includes(`text: &apos;${knownHostsLine(CONFIG, HOST_KEY)}\\n&apos;`), 'known_hosts holds only the pinned key');
  assert.match(xml, /-o StrictHostKeyChecking=yes -o UserKnownHostsFile=\.scenter-known-hosts -o GlobalKnownHostsFile=\/dev\/null/);
  assert.match(xml, /-p 22 deploy@192\.168\.222\.132 &apos;sh -s&apos;/);
  const encoded = /\.scenter-remote\.b64&apos;, text: &apos;([A-Za-z0-9+/=]+)&apos;/.exec(xml)[1];
  assert.equal(Buffer.from(encoded, 'base64').toString('utf8'), script, 'the remote script travels unaltered');
  assert.doesNotMatch(xml, /StrictHostKeyChecking=no|PRIVATE KEY|password/i);
  assert.equal(knownHostsLine({ ...CONFIG, port: '2222' }, HOST_KEY), `[192.168.222.132]:2222 ssh-ed25519 ${HOST_KEY.key}`);
  assert.deepEqual(parseMarkers('SCENTER_PREREQ_JAVA=21 /a\n+ echo SCENTER_PREREQ_JAVA=x\nSCENTER_PREREQ_JAVA=17 /b\n', 'PREREQ'), { JAVA: ['21 /a', '17 /b'] });
});
