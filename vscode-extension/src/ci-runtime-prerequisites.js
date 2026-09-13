'use strict';

/**
 * CI Runtime prerequisites: detection, managed installations and administrator
 * guidance.
 *
 * Everything runs through Jenkins, never from this machine: a managed, sandboxed
 * job binds the SSH credential inside Jenkins — the private key never reaches
 * Security Center — and runs one fixed script on the runtime host over SSH, with
 * the approved host key pinned (StrictHostKeyChecking=yes). This works before the
 * Jenkins agent itself can connect, which is exactly when Java may be missing.
 *
 * What Security Center may change on the host, and only after an explicit
 * confirmation:
 *   - managed tools under <remoteRoot>/tools (Java, Node.js): version pinned,
 *     downloaded over HTTPS from the official publisher, SHA-256 verified before
 *     anything is unpacked, installed atomically, idempotent;
 *   - two privileged actions (docker group membership, starting the Docker
 *     service), only with non-interactive sudo already configured on the host.
 * Docker Engine and git are never installed automatically. No password is ever
 * requested, sent or stored.
 */

const path = require('path');
const zlib = require('zlib');

const PREPARE_JOB = 'scenter-ci-runtime-prepare';
const DEFAULT_JAVA_MAJOR = 21;
const MIN_NODE_MAJOR = 20;
const PREFERRED_NODE_MAJOR = 22;

/**
 * Pinned managed tools. Versions and SHA-256 come from the publishers' own
 * metadata (Adoptium API, nodejs.org SHASUMS256.txt); a download that does not
 * match is never unpacked.
 */
const MANAGED_TOOLS = Object.freeze({
  java: Object.freeze({
    17: Object.freeze({
      distribution: 'Eclipse Temurin JRE', version: '17.0.20.1+1',
      assets: Object.freeze({
        x64: { url: 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jre_x64_linux_hotspot_17.0.20.1_1.tar.gz', sha256: '0b2b640e3046b64c8ec504de0ab9d91bb5610182bda21fad454681ce54d45a62', size: 46640574 },
        aarch64: { url: 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jre_aarch64_linux_hotspot_17.0.20.1_1.tar.gz', sha256: 'b8efcd5acc9109fe8d35bed132499643048a257b4f6042906ece37d03c839d77', size: 45989435 }
      })
    }),
    21: Object.freeze({
      distribution: 'Eclipse Temurin JRE', version: '21.0.12.1+1',
      assets: Object.freeze({
        x64: { url: 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz', sha256: '2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500', size: 52059408 },
        aarch64: { url: 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_aarch64_linux_hotspot_21.0.12.1_1.tar.gz', sha256: '14be1f35ebdbd1f6e8d57eb911a3ffb74d6d9aa255abc5daf2b1302002cf2cf2', size: 51149460 }
      })
    }),
    25: Object.freeze({
      distribution: 'Eclipse Temurin JRE', version: '25.0.4.1+1',
      assets: Object.freeze({
        x64: { url: 'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jre_x64_linux_hotspot_25.0.4.1_1.tar.gz', sha256: '1731a34baadec5479258ea0202e4d5d865d2efeee60cb0c7d7eb056fe96ca219', size: 61718288 },
        aarch64: { url: 'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jre_aarch64_linux_hotspot_25.0.4.1_1.tar.gz', sha256: '34828cbb93ed31c281c84ecb31ddab655d11a802f263c1fc019d42e9e0230fed', size: 60479792 }
      })
    })
  }),
  node: Object.freeze({
    22: Object.freeze({
      distribution: 'Node.js', version: 'v22.23.2',
      assets: Object.freeze({
        x64: { url: 'https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.gz', sha256: 'b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a', size: 0 },
        aarch64: { url: 'https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-arm64.tar.gz', sha256: '013b59cfd2819703a6f4a14ab891fc46fc2a4e3f5bcd92de3fb4929b43e35b30', size: 0 }
      })
    })
  })
});

const TRUSTED_DOWNLOAD = /^https:\/\/(github\.com\/adoptium\/temurin\d+-binaries\/releases\/download|nodejs\.org\/dist)\/[A-Za-z0-9._%/+-]+\.tar\.gz$/;
const SAFE_PATH = /^\/[A-Za-z0-9._/-]+$/;

/** Privileged actions Security Center can apply, only through non-interactive sudo and after confirmation. */
const ADMIN_ACTIONS = Object.freeze({
  'docker-group': Object.freeze({
    label: (config) => `Add ${config.sshUser} to the docker group`,
    command: (config) => `sudo usermod -aG docker ${config.sshUser}`,
    requires: 'usermod',
    marker: 'DOCKER_GROUP'
  }),
  'docker-start': Object.freeze({
    label: () => 'Start the Docker service and enable it at boot',
    command: () => 'sudo systemctl enable --now docker',
    requires: 'systemctl',
    marker: 'DOCKER_START'
  })
});

const STATE = Object.freeze({ READY: 'ready', MISSING: 'missing', ADMIN: 'admin', BLOCKED: 'blocked', UNKNOWN: 'unknown' });

/** Text that came from a remote host: printable and bounded. */
function safeFact(value) {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '').trim().slice(0, 200);
}

const shellQuote = (value) => `'${String(value).replace(/'/g, `'"'"'`)}'`;

// ------------------------------------------------------------ Java requirement

/** The entries of a ZIP (jar) by name, inflated. Bounded and defensive. */
function readZipEntries(buffer, wanted) {
  const found = {};
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) return found;
  let end = -1;
  for (let offset = buffer.length - 22; offset >= Math.max(0, buffer.length - 65557); offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) { end = offset; break; }
  }
  if (end < 0) return found;
  const count = buffer.readUInt16LE(end + 10);
  let cursor = buffer.readUInt32LE(end + 16);
  for (let index = 0; index < count && cursor + 46 <= buffer.length; index += 1) {
    if (buffer.readUInt32LE(cursor) !== 0x02014b50) break;
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8');
    cursor += 46 + nameLength + extraLength + commentLength;
    if (!wanted.includes(name) || localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) continue;
    const start = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(start, start + compressedSize);
    try {
      if (method === 0) found[name] = data;
      else if (method === 8) found[name] = zlib.inflateRawSync(data, { maxOutputLength: 4 * 1024 * 1024 });
    } catch { /* unreadable entry: ignored */ }
  }
  return found;
}

/**
 * The Java version this Jenkins' agents need, read from its own remoting.jar:
 * the declared minimum, or the class-file version the remoting classes were
 * compiled for, whichever is higher.
 */
function javaRequirementFromRemotingJar(buffer) {
  const entries = readZipEntries(buffer, ['META-INF/MANIFEST.MF', 'hudson/remoting/Launcher.class']);
  const manifest = entries['META-INF/MANIFEST.MF']?.toString('utf8') || '';
  const declared = Number(/^Remoting-Minimum-Java-Version:\s*(\d+)/mi.exec(manifest)?.[1] || 0);
  const launcher = entries['hudson/remoting/Launcher.class'];
  const compiled = launcher && launcher.length > 8 && launcher.readUInt32BE(0) === 0xcafebabe ? launcher.readUInt16BE(6) - 44 : 0;
  const version = /^Version:\s*(\S+)/mi.exec(manifest)?.[1] || '';
  if (!declared && !compiled) return null;
  const major = Math.max(declared, compiled);
  return { major, source: `remoting ${safeFact(version) || 'jar'} (${compiled >= declared ? 'class files' : 'declared minimum'})` };
}

// ------------------------------------------------------------ remote scripts

function detectScript(config, javaMajor) {
  return [
    'set +e',
    `root=${shellQuote(config.remoteRoot)}`,
    `java_major=${shellQuote(String(javaMajor))}`,
    'echo "SCENTER_PREREQ_SSH=ready $(id -un)"',
    'echo "SCENTER_PREREQ_PLATFORM=$(uname -s) $(uname -m)"',
    'if mkdir -p "$root" 2>/dev/null && touch "$root/.scenter-write-check" 2>/dev/null && rm -f "$root/.scenter-write-check"; then echo "SCENTER_PREREQ_WORKSPACE=ready $root"; else echo "SCENTER_PREREQ_WORKSPACE=not-writable $root"; fi',
    'for candidate in "$root/tools/java$java_major/bin/java" "$(command -v java 2>/dev/null)"; do',
    '  if [ -n "$candidate" ] && [ -x "$candidate" ]; then',
    '    version="$("$candidate" -version 2>&1 | sed -n \'s/.*version "\\([0-9][0-9._]*\\).*/\\1/p\' | head -n 1)"',
    '    echo "SCENTER_PREREQ_JAVA=${version:-unknown} $candidate"',
    '  fi',
    'done',
    'for candidate in "$root/tools/node22/bin/node" "$(command -v node 2>/dev/null)"; do',
    '  if [ -n "$candidate" ] && [ -x "$candidate" ]; then echo "SCENTER_PREREQ_NODE=$("$candidate" --version 2>/dev/null) $candidate"; fi',
    'done',
    'if command -v git >/dev/null 2>&1; then echo "SCENTER_PREREQ_GIT=$(git --version)"; else echo "SCENTER_PREREQ_GIT=missing"; fi',
    'docker_bin="$(command -v docker 2>/dev/null)"',
    'if [ -z "$docker_bin" ]; then echo "SCENTER_PREREQ_DOCKER_CLI=missing"',
    'else',
    '  echo "SCENTER_PREREQ_DOCKER_CLI=ready $docker_bin"',
    '  if docker_out="$(docker info --format \'{{.ServerVersion}}\' 2>&1)"; then echo "SCENTER_PREREQ_DOCKER_DAEMON=ready $docker_out"',
    '  else case "$docker_out" in *ermission*) echo "SCENTER_PREREQ_DOCKER_DAEMON=permission-denied" ;; *) echo "SCENTER_PREREQ_DOCKER_DAEMON=unreachable" ;; esac; fi',
    'fi',
    'if [ -S /var/run/docker.sock ]; then echo "SCENTER_PREREQ_DOCKER_SOCKET=$(stat -c %G /var/run/docker.sock 2>/dev/null || echo unknown)"; else echo "SCENTER_PREREQ_DOCKER_SOCKET=missing"; fi',
    'echo "SCENTER_PREREQ_GROUPS=$(id -nG 2>/dev/null)"',
    // `sudo -n` never prompts: it only tells whether non-interactive sudo is already configured.
    'if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then echo "SCENTER_PREREQ_SUDO=non-interactive"; else echo "SCENTER_PREREQ_SUDO=unavailable"; fi',
    'tools=""',
    'for tool in curl wget tar sha256sum systemctl usermod apt-get dnf yum zypper apk; do if command -v "$tool" >/dev/null 2>&1; then tools="$tools $tool"; fi; done',
    'echo "SCENTER_PREREQ_TOOLS=$tools"',
    'echo "SCENTER_PREREQ_DONE=1"'
  ].join('\n') + '\n';
}

function installScript(config, plan) {
  for (const item of plan) {
    if (!TRUSTED_DOWNLOAD.test(item.url) || !/^[0-9a-f]{64}$/.test(item.sha256) || !SAFE_PATH.test(item.destination)) {
      throw new Error(`Refusing an unpinned or untrusted installation for ${item.tool}.`);
    }
  }
  return [
    'set +e',
    'umask 022',
    `root=${shellQuote(config.remoteRoot)}`,
    'if ! mkdir -p "$root/tools"; then echo "SCENTER_INSTALL_ERROR=tools-directory"; echo "SCENTER_INSTALL_DONE=1"; exit 0; fi',
    'download() {',
    '  if command -v curl >/dev/null 2>&1; then curl -fsSL --proto "=https" --tlsv1.2 --connect-timeout 20 --max-time 900 -o "$2" "$1"',
    '  elif command -v wget >/dev/null 2>&1; then wget -q --https-only --timeout=20 -O "$2" "$1"',
    '  else return 127; fi',
    '}',
    'install_tool() {',
    '  id="$1"; version="$2"; url="$3"; sha="$4"; dest="$5"; binary="$6"; probe="$7"',
    '  if [ -x "$dest/$binary" ] && [ "$(cat "$dest/.scenter-version" 2>/dev/null)" = "$version" ]; then echo "SCENTER_INSTALL_$id=already $version"; return; fi',
    '  work="$(mktemp -d "$root/tools/.install-XXXXXX")" || { echo "SCENTER_INSTALL_$id=failed temporary-directory"; return; }',
    '  if ! download "$url" "$work/archive.tar.gz"; then echo "SCENTER_INSTALL_$id=download-failed"; rm -rf "$work"; return; fi',
    '  actual="$(sha256sum "$work/archive.tar.gz" | cut -d " " -f 1)"',
    '  if [ "$actual" != "$sha" ]; then echo "SCENTER_INSTALL_$id=checksum-mismatch $actual"; rm -rf "$work"; return; fi',
    '  if ! mkdir "$work/extract" || ! tar -xzf "$work/archive.tar.gz" -C "$work/extract" --strip-components=1; then echo "SCENTER_INSTALL_$id=extract-failed"; rm -rf "$work"; return; fi',
    '  if ! "$work/extract/$binary" "$probe" >/dev/null 2>&1; then echo "SCENTER_INSTALL_$id=verify-failed"; rm -rf "$work"; return; fi',
    '  printf "%s" "$version" > "$work/extract/.scenter-version"',
    '  rm -rf "$dest.previous"',
    '  if [ -e "$dest" ]; then mv "$dest" "$dest.previous"; fi',
    '  if mv "$work/extract" "$dest"; then rm -rf "$dest.previous" "$work"; echo "SCENTER_INSTALL_$id=installed $version"',
    '  else if [ -e "$dest.previous" ]; then mv "$dest.previous" "$dest"; fi; rm -rf "$work"; echo "SCENTER_INSTALL_$id=failed move"; fi',
    '}',
    ...plan.map((item) => `install_tool ${item.tool.toUpperCase()} ${shellQuote(item.version)} ${shellQuote(item.url)} ${shellQuote(item.sha256)} ${shellQuote(item.destination)} ${shellQuote(item.binary)} ${shellQuote(item.probe)}`),
    'echo "SCENTER_INSTALL_DONE=1"'
  ].join('\n') + '\n';
}

function adminScript(config, actionIds) {
  const lines = [
    'set +e',
    'if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then echo "SCENTER_ADMIN_SUDO=unavailable"; echo "SCENTER_ADMIN_DONE=1"; exit 0; fi'
  ];
  for (const id of actionIds) {
    const action = ADMIN_ACTIONS[id];
    if (!action) continue;
    const command = id === 'docker-group'
      ? `sudo -n usermod -aG docker ${shellQuote(config.sshUser)}`
      : 'sudo -n systemctl enable --now docker';
    lines.push(`if ${command} >/dev/null 2>&1; then echo "SCENTER_ADMIN_${action.marker}=applied"; else echo "SCENTER_ADMIN_${action.marker}=failed"; fi`);
  }
  lines.push('echo "SCENTER_ADMIN_DONE=1"');
  return lines.join('\n') + '\n';
}

// ------------------------------------------------------------ preparation job

function xml(value) {
  return String(value ?? '').replace(/[<>&'"]/g, (character) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[character]));
}

function knownHostsLine(config, hostKey) {
  const target = Number(config.port) === 22 ? config.host : `[${config.host}]:${Number(config.port)}`;
  return `${target} ${hostKey.algorithm} ${hostKey.key}`;
}

/**
 * The sandboxed preparation pipeline. The credential is bound by Jenkins and
 * used by ssh on a Jenkins executor that is not the runtime itself; the only
 * host key accepted is the approved one; the remote script travels as base64,
 * so no value can break out of the Groovy string.
 */
function prepareJobConfigXml({ config, hostKey, script, runtimeLabel, marker, mode }) {
  const pipeline = [
    `node('!${runtimeLabel}') {`,
    `  withCredentials([sshUserPrivateKey(credentialsId: '${config.credentialId}', keyFileVariable: 'SCENTER_SSH_KEY')]) {`,
    `    writeFile(file: '.scenter-known-hosts', text: '${knownHostsLine(config, hostKey)}\\n')`,
    `    writeFile(file: '.scenter-remote.b64', text: '${Buffer.from(script, 'utf8').toString('base64')}')`,
    `    sh(label: 'Security Center CI Runtime ${mode}', script: '''set +x`,
    'rm -f .scenter-remote.sh .scenter-ssh.err',
    'if ! command -v ssh >/dev/null 2>&1; then echo "SCENTER_PREPARE=no-ssh-client"; rm -f .scenter-remote.b64 .scenter-known-hosts; exit 0; fi',
    'base64 -d .scenter-remote.b64 > .scenter-remote.sh',
    `ssh -i "$SCENTER_SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=.scenter-known-hosts -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=20 -p ${Number(config.port)} ${config.sshUser}@${config.host} 'sh -s' < .scenter-remote.sh 2> .scenter-ssh.err`,
    'status=$?',
    'if [ "$status" = 255 ]; then echo "SCENTER_PREPARE=ssh-failed"; head -n 5 .scenter-ssh.err | sed "s/^/SCENTER_SSH_ERROR=/"; fi',
    'echo "SCENTER_PREPARE_EXIT=$status"',
    'rm -f .scenter-remote.sh .scenter-remote.b64 .scenter-ssh.err .scenter-known-hosts',
    `''')`,
    '  }',
    '}',
    ''
  ].join('\n');
  return `<?xml version="1.1" encoding="UTF-8"?>
<flow-definition>
  <description>${xml(marker)} Detects and prepares the Security Center CI Runtime prerequisites over SSH.</description>
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

/** Every `SCENTER_<PREFIX>_<KEY>=value` line of a console, values kept in order per key. */
function parseMarkers(text, prefix) {
  const markers = {};
  const pattern = new RegExp(`^SCENTER_${prefix}_([A-Z_]+)=(.*)$`);
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = pattern.exec(line.trim());
    if (match) (markers[match[1]] ||= []).push(safeFact(match[2]));
  }
  return markers;
}

// ------------------------------------------------------------ evaluation

function javaCandidate(value) {
  const match = /^(\S+)\s+(\/\S+)$/.exec(value);
  if (!match) return null;
  const parts = match[1].split(/[._]/).map(Number);
  const major = parts[0] === 1 ? parts[1] : parts[0];
  return Number.isInteger(major) ? { major, version: match[1], path: match[2] } : null;
}

function nodeCandidate(value) {
  const match = /^v(\d+)\.(\d+)\.(\d+)\s+(\/\S+)$/.exec(value);
  return match ? { major: Number(match[1]), version: `v${match[1]}.${match[2]}.${match[3]}`, path: match[4] } : null;
}

function packageInstall(tools, packages) {
  if (tools.has('apt-get')) return `sudo apt-get update && sudo apt-get install -y ${packages.apt}`;
  if (tools.has('dnf')) return `sudo dnf install -y ${packages.rpm}`;
  if (tools.has('yum')) return `sudo yum install -y ${packages.rpm}`;
  if (tools.has('zypper')) return `sudo zypper install -y ${packages.rpm}`;
  if (tools.has('apk')) return `sudo apk add ${packages.apk}`;
  return '';
}

/**
 * Turns the detection markers into the prerequisite table, the managed install
 * plan and what an administrator must do.
 */
function evaluatePrerequisites(markers, { config, javaRequirement }) {
  const first = (key) => markers[key]?.[0] || '';
  const user = first('SSH').replace(/^ready\s*/, '') || config.sshUser;
  const [os, machine] = first('PLATFORM').split(/\s+/);
  const arch = /^(x86_64|amd64)$/i.test(machine || '') ? 'x64' : /^(aarch64|arm64)$/i.test(machine || '') ? 'aarch64' : '';
  const tools = new Set(first('TOOLS').split(/\s+/).filter(Boolean));
  const sudo = first('SUDO') === 'non-interactive';
  const toolsRoot = `${config.remoteRoot}/tools`;
  const workspaceReady = first('WORKSPACE').startsWith('ready');
  const canInstall = os === 'Linux' && Boolean(arch) && (tools.has('curl') || tools.has('wget')) && tools.has('tar') && tools.has('sha256sum') && workspaceReady;
  const items = [];
  const plan = [];
  const manual = [];
  const item = (id, label, state, summary, detail, extra = {}) => items.push({ id, label, state, summary, detail, ...extra });
  const managedItem = (tool, major, label, found) => {
    const pin = MANAGED_TOOLS[tool][major];
    const asset = pin?.assets[arch];
    if (!pin || !asset || !canInstall) return false;
    const destination = `${toolsRoot}/${tool}${major}`;
    plan.push({
      tool, major, label, distribution: pin.distribution, version: pin.version, platform: `linux-${arch}`,
      url: asset.url, sha256: asset.sha256, size: asset.size, destination,
      binary: tool === 'java' ? 'bin/java' : 'bin/node', probe: tool === 'java' ? '-version' : '--version',
      host: config.host, user
    });
    item(tool, label, STATE.MISSING, 'Missing', `${found} Security Center can install ${pin.distribution} ${pin.version} into ${destination} (SHA-256 verified).`, { action: 'install' });
    return true;
  };

  item('ssh', 'SSH', STATE.READY, 'Ready', `Connected from Jenkins as ${user} with credential ${config.credentialId}; host key pinned.`);

  if (workspaceReady) item('workspace', 'Agent workspace', STATE.READY, 'Ready', `${config.remoteRoot} is writable by ${user}.`);
  else {
    item('workspace', 'Agent workspace', STATE.ADMIN, 'Administrator action required', `${config.remoteRoot} cannot be created or written by ${user}.`);
    manual.push({ title: `Agent workspace ${config.remoteRoot}`, reason: `${config.remoteRoot} cannot be created or written by ${user}.`, commands: [`sudo mkdir -p ${config.remoteRoot}`, `sudo chown -R ${user}: ${config.remoteRoot}`] });
  }

  const javaMajor = javaRequirement.major;
  const javaLabel = `Java ${javaMajor}`;
  const javas = (markers.JAVA || []).map(javaCandidate).filter(Boolean);
  const java = javas.find((candidate) => candidate.major >= javaMajor);
  if (java) {
    item('java', javaLabel, STATE.READY, 'Ready', `Java ${java.version} at ${java.path} (required by ${javaRequirement.source}).`, { version: java.version, path: java.path, managed: java.path.startsWith(`${toolsRoot}/`) });
  } else {
    const found = javas.length ? `Found only Java ${javas[0].version} at ${javas[0].path}; this Jenkins needs Java ${javaMajor} (${javaRequirement.source}).` : `No Java on ${config.host}; this Jenkins needs Java ${javaMajor} (${javaRequirement.source}).`;
    if (!managedItem('java', javaMajor, javaLabel, found)) {
      item('java', javaLabel, STATE.ADMIN, 'Administrator action required', found);
      manual.push({ title: javaLabel, reason: found, commands: [packageInstall(tools, { apt: `openjdk-${javaMajor}-jre-headless`, rpm: `java-${javaMajor}-openjdk-headless`, apk: `openjdk${javaMajor}-jre-headless` }) || `Install a Java ${javaMajor} runtime on ${config.host}.`] });
    }
  }

  const git = first('GIT');
  if (git && git !== 'missing') item('git', 'Git', STATE.READY, 'Ready', git);
  else {
    item('git', 'Git', STATE.ADMIN, 'Administrator action required', `git is not installed on ${config.host}.`);
    manual.push({ title: 'Git', reason: `git is not installed on ${config.host}.`, commands: [packageInstall(tools, { apt: 'git', rpm: 'git', apk: 'git' }) || `Install git on ${config.host}.`] });
  }

  const nodeLabel = `Node.js ${PREFERRED_NODE_MAJOR}`;
  const nodes = (markers.NODE || []).map(nodeCandidate).filter(Boolean);
  const node = nodes.find((candidate) => candidate.major >= MIN_NODE_MAJOR);
  if (node) {
    item('node', nodeLabel, STATE.READY, 'Ready', `Node.js ${node.version} at ${node.path}.`, {
      version: node.version, path: node.path, home: path.posix.dirname(path.posix.dirname(node.path)), managed: node.path.startsWith(`${toolsRoot}/`)
    });
  } else {
    const found = nodes.length ? `Found only Node.js ${nodes[0].version}; Node.js ${MIN_NODE_MAJOR} or later is required.` : `Node.js is not installed on ${config.host}.`;
    if (!managedItem('node', PREFERRED_NODE_MAJOR, nodeLabel, found)) {
      item('node', nodeLabel, STATE.ADMIN, 'Administrator action required', found);
      manual.push({ title: nodeLabel, reason: found, commands: [`Install Node.js ${PREFERRED_NODE_MAJOR} on ${config.host} (https://nodejs.org/en/download).`] });
    }
  }

  const adminActions = [];
  const cli = first('DOCKER_CLI');
  const daemon = first('DOCKER_DAEMON');
  const socketGroup = first('DOCKER_SOCKET');
  if (!cli || cli === 'missing') {
    item('docker-cli', 'Docker', STATE.ADMIN, 'Administrator action required', `Docker Engine is not installed on ${config.host}.`);
    item('docker-daemon', 'Docker daemon', STATE.BLOCKED, 'Waiting', 'Waiting for Docker Engine.');
    item('docker-access', 'Docker access', STATE.BLOCKED, 'Waiting', 'Waiting for Docker Engine.');
    manual.push({ title: 'Docker Engine', reason: `Docker Engine is not installed on ${config.host}. Security Center never installs it automatically.`, commands: ['Install Docker Engine for this distribution: https://docs.docker.com/engine/install/', `sudo usermod -aG docker ${user}`] });
  } else {
    item('docker-cli', 'Docker', STATE.READY, 'Ready', `Docker CLI at ${cli.replace(/^ready\s*/, '')}.`);
    if (daemon.startsWith('ready')) {
      item('docker-daemon', 'Docker daemon', STATE.READY, 'Ready', `Docker Engine ${daemon.replace(/^ready\s*/, '')} is running.`);
      item('docker-access', 'Docker access', STATE.READY, 'Ready', `${user} can use the Docker daemon.`);
    } else if (daemon === 'permission-denied') {
      item('docker-daemon', 'Docker daemon', STATE.READY, 'Ready', 'The Docker daemon is running.');
      const group = socketGroup && !['missing', 'unknown'].includes(socketGroup) ? socketGroup : 'docker';
      const reason = `User ${user} cannot use the Docker daemon: /var/run/docker.sock belongs to group "${group}" and ${user} is not a member (groups: ${first('GROUPS') || 'unknown'}).`;
      item('docker-access', 'Docker access', STATE.ADMIN, 'Administrator action required', reason);
      manual.push({ title: 'Docker access', reason, commands: [`sudo usermod -aG ${group} ${user}`, 'Then run Configure CI Runtime again: Security Center reconnects the agent so the new group applies.'] });
      if (group === 'docker' && sudo && tools.has('usermod')) adminActions.push('docker-group');
    } else {
      const reason = `The Docker daemon on ${config.host} is not running or not reachable.`;
      item('docker-daemon', 'Docker daemon', STATE.ADMIN, 'Administrator action required', reason);
      item('docker-access', 'Docker access', STATE.BLOCKED, 'Waiting', 'Waiting for the Docker daemon.');
      manual.push({ title: 'Docker daemon', reason, commands: ['sudo systemctl enable --now docker'] });
      if (sudo && tools.has('systemctl')) adminActions.push('docker-start');
    }
  }

  const adminItems = items.filter((entry) => entry.state === STATE.ADMIN);
  return {
    items,
    java: java ? { ...java, managed: java.path.startsWith(`${toolsRoot}/`) } : null,
    node: node ? { ...node, home: path.posix.dirname(path.posix.dirname(node.path)), managed: node.path.startsWith(`${toolsRoot}/`) } : null,
    installPlan: plan.length ? plan : null,
    admin: adminItems.length ? {
      required: true,
      reasons: adminItems.map((entry) => entry.detail),
      sudo,
      actions: adminActions.map((id) => ({ id, label: ADMIN_ACTIONS[id].label({ ...config, sshUser: user }), command: ADMIN_ACTIONS[id].command({ ...config, sshUser: user }) })),
      instructions: adminInstructions(config, user, manual)
    } : null,
    sudo
  };
}

function adminInstructions(config, user, manual) {
  const lines = [
    `# Security Center CI Runtime — administrator setup`,
    '',
    `Host: ${config.host} · SSH user: ${user} · agent directory: ${config.remoteRoot}`,
    '',
    'These steps change system configuration, so Security Center does not apply them silently.',
    'Run them on the host as an administrator, then run Configure CI Runtime again.',
    'Security Center never asks for, sends or stores a sudo password.',
    ''
  ];
  for (const entry of manual) {
    lines.push(`## ${entry.title}`, '', entry.reason, '', '```sh', ...entry.commands, '```', '');
  }
  return lines.join('\n');
}

/** Only the plan items a person approved, matched on tool, version and destination. */
function approvedPlan(plan, approvals) {
  const accepted = Array.isArray(approvals) ? approvals : [];
  return (plan || []).filter((item) => accepted.some((approval) => approval?.tool === item.tool
    && approval?.version === item.version && approval?.destination === item.destination));
}

/** What an installation reported, per tool: `installed`, `already`, or the failure reason. */
function installOutcome(markers, plan) {
  return plan.map((item) => {
    const raw = markers[item.tool.toUpperCase()]?.[0] || (markers.ERROR?.[0] ? `failed ${markers.ERROR[0]}` : 'no-result');
    const [status, ...rest] = raw.split(/\s+/);
    const ok = status === 'installed' || status === 'already';
    const reasons = {
      'download-failed': `the download from ${item.url} failed (host offline, proxy or firewall).`,
      'checksum-mismatch': `the downloaded archive's SHA-256 ${safeFact(rest[0]) || 'unknown'} does not match the pinned ${item.sha256}. Nothing was installed.`,
      'extract-failed': 'the archive could not be unpacked. Nothing was installed.',
      'verify-failed': `the unpacked ${item.label} did not run on this host. Nothing was installed.`,
      'no-result': 'the host did not report a result.'
    };
    return { tool: item.tool, label: item.label, ok, status, detail: ok ? `${item.label} ${item.version} ${status === 'already' ? 'already installed' : 'installed'} in ${item.destination}.` : `${item.label}: ${reasons[status] || `installation failed (${safeFact(raw)}).`}` };
  });
}

module.exports = {
  PREPARE_JOB, DEFAULT_JAVA_MAJOR, MIN_NODE_MAJOR, PREFERRED_NODE_MAJOR, MANAGED_TOOLS, ADMIN_ACTIONS, STATE,
  readZipEntries, javaRequirementFromRemotingJar, detectScript, installScript, adminScript, prepareJobConfigXml,
  knownHostsLine, parseMarkers, evaluatePrerequisites, approvedPlan, installOutcome
};
