'use strict';

/**
 * Runtime des scanners CI : Semgrep, Gitleaks, Trivy et OSV-Scanner en conteneurs
 * éphémères sur le daemon Docker du nœud Jenkins d'exécution.
 *
 * Le CLI Docker est remplacé par un double qui répond comme le vrai daemon
 * (`docker info`, `docker inspect`, `docker run`). Tout le reste est réel : les
 * runners, l'orchestrateur, la politique security-center.yml, la normalisation
 * et le verdict.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { createCiScannerRuntime, scannerRuntimeMode, mapContainerPaths } = require('../src/ci-scanner-runtime');
const { runSemgrep, SEMGREP_IMAGE } = require('../src/semgrep');
const { runGitleaks, GITLEAKS_IMAGE } = require('../src/gitleaks');
const { runTrivy, generateSbom, TRIVY_IMAGE } = require('../src/trivy');
const { runOsv, OSV_IMAGE } = require('../src/osv');
const { runSecurityScan } = require('../src/orchestrator');
const { normalizeOsvOutput } = require('../src/findings');
const { verdictOf } = require('../src/cli');

const IMAGES = [SEMGREP_IMAGE, GITLEAKS_IMAGE, TRIVY_IMAGE, OSV_IMAGE];
const JENKINS_ID = 'c0ffee'.repeat(10) + 'c0ff';
const UNAVAILABLE = 'SCenter CI runtime unavailable: Docker is not accessible from this Jenkins execution node';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ci-runtime-'));
process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));

function workspace(name, yaml = '') {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  if (yaml) fs.writeFileSync(path.join(dir, 'security-center.yml'), yaml);
  return dir;
}

const failure = (code, stderr) => Object.assign(new Error('Command failed'), { code, stderr });

/**
 * A Docker CLI double. `visible` decides whether a container can read the
 * workspace marker; scanner output comes from `outputs[image]`.
 */
function fakeDocker({ info = { stdout: '27.3.1\n' }, containers = {}, visible = true, pullError = '', outputs = {}, workspacePath = '', files = null } = {}) {
  const calls = [];
  const read = (hostPath) => (files ? files.get(hostPath) : (fs.existsSync(hostPath) ? fs.readFileSync(hostPath, 'utf8') : undefined));
  async function exec(command, args) {
    assert.equal(command, 'docker');
    calls.push([...args]);
    switch (args[0]) {
      case 'info':
        if (info.error) throw info.error;
        return { stdout: info.stdout, stderr: '' };
      case 'inspect': {
        const id = args[args.length - 1];
        if (!containers[id]) throw failure(1, `Error: No such container: ${id}`);
        return { stdout: JSON.stringify([containers[id]]), stderr: '' };
      }
      case 'rm':
        return { stdout: '', stderr: '' };
      case 'run': {
        if (args.includes('--entrypoint')) {
          if (pullError) throw failure(125, pullError);
          const marker = path.posix.basename(args[args.length - 1]);
          const content = visible ? read(path.join(workspacePath, marker)) : undefined;
          if (content === undefined) throw failure(1, `cat: can't open '${marker}': No such file or directory`);
          return { stdout: content, stderr: '' };
        }
        const image = IMAGES.find((candidate) => args.includes(candidate));
        const output = outputs[image];
        if (output === undefined) throw new Error(`unexpected scanner container ${image}`);
        return { stdout: typeof output === 'function' ? output(args) : output, stderr: '' };
      }
      default:
        throw new Error(`unexpected docker ${args[0]}`);
    }
  }
  return {
    exec,
    calls,
    probes: () => calls.filter((args) => args[0] === 'run' && args.includes('--entrypoint')),
    scans: () => calls.filter((args) => args[0] === 'run' && !args.includes('--entrypoint'))
  };
}

/** The runtime as a Jenkins node would build it, with the kernel's records injected. */
function runtimeFor(docker, { workspacePath, mountinfo = '', cgroup = '', dockerenv = false, hostname = 'build-node-1', files = null }) {
  return createCiScannerRuntime({
    workspacePath,
    exec: docker.exec,
    readFile: async (file) => {
      if (file === '/proc/self/mountinfo') return mountinfo;
      if (file === '/proc/self/cgroup') return cgroup;
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    },
    exists: async (file) => file === '/.dockerenv' && dockerenv,
    hostname: () => hostname,
    ...(files ? {
      writeFile: async (file, content) => { files.set(file, content); },
      remove: async (file) => { files.delete(file); }
    } : {})
  });
}

function assertHardened(args) {
  assert.equal(args[0], 'run');
  assert.equal(args[1], '--rm', `conteneur éphémère : ${args.join(' ')}`);
  assert.ok(args.includes('no-new-privileges'), args.join(' '));
  assert.ok(!args.includes('--privileged'), args.join(' '));
  assert.ok(!args.some((arg) => /docker\.sock/.test(arg)), `aucun socket Docker monté : ${args.join(' ')}`);
  assert.ok(!args.includes('--context'), 'aucun contexte Docker Desktop');
}

// ------------------------------------------------------------ mode

test('le runtime conteneur est choisi sous Jenkins, jamais pour un poste développeur', () => {
  assert.equal(scannerRuntimeMode({ env: { JENKINS_URL: 'https://ci.example/' } }), 'container');
  assert.equal(scannerRuntimeMode({ env: { BUILD_TAG: 'jenkins-security-pipeline-42' } }), 'container');
  assert.equal(scannerRuntimeMode({ env: {} }), 'host');
  assert.equal(scannerRuntimeMode({ env: { CI: 'true' } }), 'host', 'une autre CI choisit explicitement');
  assert.equal(scannerRuntimeMode({ env: { SCENTER_SCANNER_RUNTIME: 'container' } }), 'container');
  assert.equal(scannerRuntimeMode({ flag: 'host', env: { JENKINS_URL: 'https://ci.example/' } }), 'host');
  assert.throws(() => scannerRuntimeMode({ flag: 'desktop', env: {} }), /Scanner runtime inconnu/);
});

// ------------------------------------------------------------ nœud natif

test('nœud Jenkins natif : workspace monté en lecture seule sur /src, conteneur éphémère durci', async () => {
  const ws = workspace('native');
  const docker = fakeDocker({ workspacePath: ws, outputs: { [SEMGREP_IMAGE]: JSON.stringify({ results: [{ check_id: 'js.sqli', path: 'routes/login.ts', start: { line: 3, col: 1 }, extra: { severity: 'ERROR', message: 'SQL' } }] }) } });
  const runtime = runtimeFor(docker, { workspacePath: ws });
  const result = await runSemgrep({ workspacePath: ws, containerRuntime: runtime });

  assert.equal(result.payload.results[0].path, 'routes/login.ts');
  assert.deepEqual(docker.calls[0], ['info', '--format', '{{.ServerVersion}}'], 'disponibilité réelle du daemon, pas seulement le binaire');
  assert.equal(docker.calls.filter((args) => args[0] === 'inspect').length, 0, 'aucun conteneur Jenkins à inspecter');
  const [probe] = docker.probes();
  assertHardened(probe);
  assert.deepEqual(probe.slice(probe.indexOf('-v'), probe.indexOf('-v') + 2), ['-v', `${ws}:/src:ro`]);
  assert.ok(probe.includes('none'), 'la sonde n’a pas de réseau');
  const [scan] = docker.scans();
  assertHardened(scan);
  assert.deepEqual(scan.slice(scan.indexOf('-v'), scan.indexOf('-v') + 2), ['-v', `${ws}:/src:ro`]);
  assert.deepEqual(scan.slice(scan.indexOf('-w'), scan.indexOf('-w') + 2), ['-w', '/src']);
  assert.deepEqual(scan.slice(scan.indexOf(SEMGREP_IMAGE)), [SEMGREP_IMAGE, 'semgrep', 'scan', '--config', 'p/security-audit', '--json', '--metrics=off', '.']);
  assert.deepEqual(fs.readdirSync(ws), [], 'fichier sonde retiré');
});

test('un hôte qui voit les montages d’autres conteneurs n’est pas pris pour un conteneur Jenkins', async () => {
  const ws = workspace('host-with-containers');
  const other = 'ab'.repeat(32);
  const docker = fakeDocker({ workspacePath: ws, containers: { [other]: { Id: other, Config: { Hostname: other.slice(0, 12) }, Mounts: [{ Destination: '/' }] } }, outputs: { [OSV_IMAGE]: '{"results":[]}' } });
  const mountinfo = `812 29 0:52 / /var/lib/docker/containers/${other}/mounts/shm rw,nosuid - tmpfs shm rw\n`;
  await runOsv({ workspacePath: ws, containerRuntime: runtimeFor(docker, { workspacePath: ws, mountinfo }) });
  const [scan] = docker.scans();
  assert.ok(!scan.includes('--volumes-from'), scan.join(' '));
  assert.ok(scan.includes(`${ws}:/src:ro`), scan.join(' '));
});

// ------------------------------------------------------------ Jenkins dans Docker

const JENKINS_WORKSPACE = '/var/jenkins_home/workspace/security-pipeline';
const jenkinsContainer = (mounts) => ({
  [JENKINS_ID]: { Id: JENKINS_ID, Config: { Hostname: JENKINS_ID.slice(0, 12) }, Mounts: mounts }
});
const JENKINS_MOUNTINFO = `1470 1449 8:1 /var/lib/docker/containers/${JENKINS_ID}/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw\n`;

test('Jenkins dans Docker : volumes hérités en lecture seule, chemins ramenés au workspace, normalisation inchangée', async () => {
  const files = new Map();
  const docker = fakeDocker({
    workspacePath: JENKINS_WORKSPACE, files,
    containers: jenkinsContainer([{ Type: 'volume', Name: 'jenkins_home', Source: '/var/lib/docker/volumes/jenkins_home/_data', Destination: '/var/jenkins_home', RW: true }]),
    outputs: {
      [OSV_IMAGE]: JSON.stringify({ results: [{ source: { path: `${JENKINS_WORKSPACE}/package-lock.json` }, packages: [{ package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], database_specific: { severity: 'HIGH' } }] }] }] })
    }
  });
  const runtime = runtimeFor(docker, { workspacePath: JENKINS_WORKSPACE, mountinfo: JENKINS_MOUNTINFO, files });
  const result = await runOsv({ workspacePath: JENKINS_WORKSPACE, containerRuntime: runtime });

  for (const args of [...docker.probes(), ...docker.scans()]) {
    assertHardened(args);
    assert.deepEqual(args.slice(args.indexOf('--volumes-from'), args.indexOf('--volumes-from') + 2), ['--volumes-from', `${JENKINS_ID}:ro`]);
    assert.ok(!args.includes('-v'), `aucun chemin du conteneur Jenkins monté comme chemin hôte : ${args.join(' ')}`);
    assert.ok(!args.some((arg) => arg.includes('/var/lib/docker/volumes')), 'aucun chemin hôte deviné');
  }
  const [scan] = docker.scans();
  assert.equal(scan[scan.length - 1], JENKINS_WORKSPACE, 'le scanner lit le workspace à son propre chemin');
  assert.equal(result.payload.results[0].source.path, '/src/package-lock.json');
  const [finding] = normalizeOsvOutput(result.payload, JENKINS_WORKSPACE);
  assert.equal(finding.file, 'package-lock.json');
  assert.equal(finding.ruleId, 'CVE-2021-23337');
  assert.equal(files.size, 0, 'fichier sonde retiré');
});

test('Jenkins dans Docker avec un workspace hors volume : ERROR précis, aucun scanner lancé', async () => {
  const workspacePath = '/home/jenkins/agent/workspace/app';
  const docker = fakeDocker({ workspacePath, files: new Map(), containers: jenkinsContainer([{ Type: 'volume', Destination: '/var/jenkins_home' }]) });
  const runtime = runtimeFor(docker, { workspacePath, mountinfo: JENKINS_MOUNTINFO, files: new Map() });
  await assert.rejects(runGitleaks({ workspacePath, containerRuntime: runtime }),
    /SCenter CI runtime unavailable: Jenkins runs in container c0ffeec0ffee and the workspace \/home\/jenkins\/agent\/workspace\/app is in that container's own filesystem, not on a Docker volume or bind mount/);
  assert.equal(docker.calls.filter((args) => args[0] === 'run').length, 0);
});

// ------------------------------------------------------------ Docker indisponible

test('Docker inaccessible depuis le nœud : ERROR d’infrastructure précis, aucun secret, aucun conteneur', async () => {
  const cases = [
    [Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' }), 'the docker command is not installed on this node'],
    [failure(1, 'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'), /permission denied on the Docker daemon for user \S+/],
    [failure(1, 'Cannot connect to the Docker daemon at tcp://ci:s3cr3t-token@10.20.30.40:2376. Is the docker daemon running?'), 'no Docker daemon is reachable']
  ];
  for (const [index, [error, reason]] of cases.entries()) {
    const ws = workspace(`unavailable-${index}`);
    const docker = fakeDocker({ info: { error }, workspacePath: ws });
    const rejection = await runTrivy({ workspacePath: ws, containerRuntime: runtimeFor(docker, { workspacePath: ws }) }).then(() => null, (caught) => caught);
    assert.ok(rejection, 'le scan échoue');
    assert.ok(rejection.message.startsWith(`${UNAVAILABLE} (`), rejection.message);
    if (typeof reason === 'string') assert.ok(rejection.message.includes(`(${reason})`), rejection.message);
    else assert.match(rejection.message, reason);
    assert.match(rejection.message, /One-time Jenkins node prerequisite: the user running the Jenkins agent must be able to run the docker CLI/);
    assert.doesNotMatch(rejection.message, /s3cr3t|10\.20\.30\.40|install (Semgrep|Gitleaks|Trivy|OSV)/i);
    assert.deepEqual(docker.calls.map((args) => args[0]), ['info'], 'aucun conteneur démarré');
  }
});

test('workspace invisible pour le daemon ou image impossible à tirer : ERROR précis, jamais un scan vide', async () => {
  const hidden = workspace('hidden');
  const invisible = fakeDocker({ workspacePath: hidden, visible: false, outputs: { [SEMGREP_IMAGE]: '{"results":[]}' } });
  await assert.rejects(runSemgrep({ workspacePath: hidden, containerRuntime: runtimeFor(invisible, { workspacePath: hidden }) }),
    /SCenter CI runtime unavailable: the Docker daemon used by this Jenkins execution node cannot read the workspace/);
  assert.equal(invisible.scans().length, 0, 'aucun scanner sur un workspace vide');
  assert.deepEqual(fs.readdirSync(hidden), [], 'fichier sonde retiré');

  const dind = workspace('dind');
  const remote = fakeDocker({ workspacePath: dind, visible: false });
  await assert.rejects(runSemgrep({ workspacePath: dind, containerRuntime: runtimeFor(remote, { workspacePath: dind, dockerenv: true }) }),
    /Jenkins runs inside a container that the reachable Docker daemon does not manage, and that daemon cannot read the workspace/);

  const offline = workspace('offline');
  const pull = fakeDocker({ workspacePath: offline, pullError: 'Unable to find image \'semgrep/semgrep:latest\' locally\ndocker: Error response from daemon: pull access denied' });
  await assert.rejects(runSemgrep({ workspacePath: offline, containerRuntime: runtimeFor(pull, { workspacePath: offline }) }),
    /SCenter CI runtime unavailable: this Jenkins execution node cannot pull the scanner image semgrep\/semgrep/);
});

// ------------------------------------------------------------ pipeline complet

const SCAN_YAML = `version: 1
scanners:
  semgrep: true
  gitleaks: true
  trivy: false
  osv: true
  sonarqube: false
  snyk: false
  zap: false
`;

const SCANNER_OUTPUTS = {
  [SEMGREP_IMAGE]: JSON.stringify({ results: [{ check_id: 'javascript.sqli', path: 'routes/login.ts', start: { line: 12, col: 5 }, end: { line: 12, col: 40 }, extra: { severity: 'ERROR', message: 'Injection SQL' } }] }),
  [GITLEAKS_IMAGE]: JSON.stringify([{ RuleID: 'generic-api-key', Description: 'Clé API', File: '/src/config/settings.js', StartLine: 2, EndLine: 2, StartColumn: 1, EndColumn: 30, Fingerprint: 'config/settings.js:generic-api-key:2' }]),
  [OSV_IMAGE]: JSON.stringify({ results: [{ source: { path: '/src/package-lock.json' }, packages: [{ package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], database_specific: { severity: 'HIGH' } }] }] }] })
};

test('security-center.yml choisit les scanners : conteneurs éphémères, scanner désactivé jamais démarré, normalisation et politique inchangées', async () => {
  const ws = workspace('pipeline', SCAN_YAML);
  const docker = fakeDocker({ workspacePath: ws, outputs: SCANNER_OUTPUTS });
  const runtime = runtimeFor(docker, { workspacePath: ws });
  const report = await runSecurityScan({ workspacePath: ws, options: { containerRuntime: runtime } });

  assert.deepEqual(report.scanners.map((scanner) => `${scanner.tool}:${scanner.status}`).sort(), ['Gitleaks:completed', 'OSV-Scanner:completed', 'Semgrep:completed']);
  assert.deepEqual(report.failures, []);
  assert.equal(docker.probes().length, 1, 'le runtime est prouvé une seule fois par scan');
  const scans = docker.scans();
  assert.equal(scans.length, 3);
  for (const args of scans) assertHardened(args);
  assert.ok(!scans.some((args) => args.includes(TRIVY_IMAGE)), 'Trivy désactivé dans security-center.yml : jamais démarré');
  assert.deepEqual([SEMGREP_IMAGE, GITLEAKS_IMAGE, OSV_IMAGE].map((image) => scans.some((args) => args.includes(image))), [true, true, true]);

  const byTool = Object.fromEntries(report.findings.map((finding) => [finding.tool, finding]));
  assert.equal(byTool.Semgrep.file, 'routes/login.ts');
  assert.equal(byTool.Gitleaks.file, 'config/settings.js');
  assert.equal(byTool.Gitleaks.category, 'secret');
  assert.equal(byTool['OSV-Scanner'].file, 'package-lock.json');
  assert.ok(report.policyResult, 'la politique projet est évaluée sur les résultats normalisés');
  assert.equal(verdictOf(report).status, 'PASS');

  const names = scans.map((args) => args[args.indexOf('--name') + 1]);
  const removed = docker.calls.filter((args) => args[0] === 'rm').map((args) => args[2]);
  assert.deepEqual(removed.sort(), names.sort(), 'nettoyage des conteneurs du scan');
});

test('Docker indisponible pendant le scan : chaque scanner choisi échoue avec la cause, verdict ERROR / exit 2', async () => {
  const ws = workspace('pipeline-unavailable', SCAN_YAML);
  const docker = fakeDocker({ info: { error: failure(1, 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?') }, workspacePath: ws });
  const report = await runSecurityScan({ workspacePath: ws, options: { containerRuntime: runtimeFor(docker, { workspacePath: ws }) } });

  assert.deepEqual(report.scanners.map((scanner) => `${scanner.tool}:${scanner.status}`).sort(), ['Gitleaks:failed', 'OSV-Scanner:failed', 'Semgrep:failed']);
  for (const scanner of report.scanners) assert.ok(scanner.details.startsWith(`${UNAVAILABLE} (no Docker daemon is reachable)`), scanner.details);
  assert.deepEqual(verdictOf(report), { status: 'ERROR', exitCode: 2 });
  assert.equal(docker.calls.filter((args) => args[0] === 'run').length, 0);
});

// ------------------------------------------------------------ scanners

test('Gitleaks : configuration générée visible dans le conteneur puis retirée, git autorisé sur le checkout monté', async () => {
  const ws = workspace('gitleaks-config');
  let configSeen = false;
  const docker = fakeDocker({
    workspacePath: ws,
    outputs: {
      [GITLEAKS_IMAGE]: (args) => {
        const containerConfig = args[args.indexOf('--config') + 1];
        assert.match(containerConfig, /^\/src\/\.security-center-gitleaks-[^/]+\/gitleaks\.toml$/);
        configSeen = fs.readFileSync(path.join(ws, containerConfig.slice('/src/'.length)), 'utf8').includes('[allowlist]');
        return '[]';
      }
    }
  });
  const result = await runGitleaks({ workspacePath: ws, exclusions: ['node_modules/**'], history: true, containerRuntime: runtimeFor(docker, { workspacePath: ws }) });
  assert.deepEqual(result.payload, []);
  assert.ok(configSeen, 'la configuration est lisible depuis le conteneur');
  const [scan] = docker.scans();
  assertHardened(scan);
  assert.ok(scan.includes('GIT_CONFIG_KEY_0=safe.directory'), scan.join(' '));
  assert.deepEqual(scan.slice(scan.indexOf(GITLEAKS_IMAGE) + 1, scan.indexOf(GITLEAKS_IMAGE) + 2), ['git']);
  assert.equal(scan[scan.length - 1], '/src');
  assert.deepEqual(fs.readdirSync(ws), [], 'configuration temporaire et sonde retirées');
});

test('Trivy et SBOM : cache d’images nommé, cible /src, jamais de socket Docker', async () => {
  const ws = workspace('trivy');
  const docker = fakeDocker({
    workspacePath: ws,
    outputs: {
      [TRIVY_IMAGE]: (args) => (args.includes('cyclonedx')
        ? JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'lodash', version: '4.17.20' }] })
        : JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', Severity: 'HIGH' }] }] }))
    }
  });
  const runtime = runtimeFor(docker, { workspacePath: ws });
  const scan = await runTrivy({ workspacePath: ws, exclusions: ['test/**'], containerRuntime: runtime });
  const sbom = await generateSbom({ workspacePath: ws, imageName: 'registry.example/app:1.0', containerRuntime: runtime });
  assert.equal(scan.payload.Results[0].Target, 'package-lock.json');
  assert.equal(sbom.payload.bomFormat, 'CycloneDX');
  const [fsScan, imageSbom] = docker.scans();
  for (const args of [fsScan, imageSbom]) {
    assertHardened(args);
    assert.ok(args.includes('security-center-trivy-cache:/root/.cache/trivy'), args.join(' '));
  }
  assert.deepEqual(fsScan.slice(fsScan.indexOf(TRIVY_IMAGE)), [TRIVY_IMAGE, 'fs', '--format', 'json', '--scanners', 'vuln,misconfig', '--quiet', '--skip-files', 'test/**', '/src']);
  assert.equal(imageSbom[imageSbom.length - 1], 'registry.example/app:1.0');
  assert.equal(docker.probes().length, 1);
});

test('chemins de sortie : seul le préfixe du workspace est ramené à /src', () => {
  const rootPath = '/var/jenkins_home/workspace/app';
  const payload = { a: `${rootPath}/x.js`, b: rootPath, c: `${rootPath}-other/y.js`, d: ['relative/z.js', `${rootPath}/w.js`], e: 3 };
  assert.deepEqual(mapContainerPaths(payload, rootPath), { a: '/src/x.js', b: '/src', c: `${rootPath}-other/y.js`, d: ['relative/z.js', '/src/w.js'], e: 3 });
  assert.equal(mapContainerPaths(payload, '/src'), payload, 'montage /src : sortie intacte');
});
