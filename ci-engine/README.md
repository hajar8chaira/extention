# Security Center CI Engine — Jenkins

Application repositories only carry their code and `security-center.yml`.
Jenkins provisions and runs the Security Center CI Engine; project users never
install anything.

## Automatic bootstrap (recommended)

The pipeline in `vscode-extension/templates/Jenkinsfile` embeds
`scenter-engine-bootstrap.sh` and runs it before every analysis:

| Situation | Action |
|---|---|
| Expected build already installed (same SHA-256) | nothing, no reinstall |
| Another build installed | download, verify SHA-256, upgrade |
| Engine absent | download, verify SHA-256, install |
| Download, checksum, package or install failure | `ERROR` (exit 2): no scan, no deploy |

One-time Jenkins configuration (Manage Jenkins → System → Global properties →
Environment variables), never in a project repository:

| Variable | Value |
|---|---|
| `SCENTER_ENGINE_MANIFEST_URL` | `https://github.com/hajar8chaira/extention/releases/download/scenter-latest/security-center-latest.json` |

Every push to `main` of the Security Center repository runs
`.github/workflows/scenter-artifacts.yml`: checks, tests, VSIX, CLI `.tgz`,
SHA-256, then one immutable `scenter-build-<commit>` release and the moved
`scenter-latest` manifest. The next Jenkins build reads the manifest, verifies
the SHA-256 and upgrades itself; the same build is never reinstalled.

Manifest contract (`security-center-latest.json`):

```json
{
  "schemaVersion": 1,
  "name": "security-center-vscode",
  "version": "0.9.0",
  "commit": "<40-hex git sha>",
  "buildTimestamp": "<ISO 8601>",
  "tgz": { "file": "security-center-vscode-0.9.0.tgz", "url": "<https url>", "sha256": "<64 hex>", "size": 0 },
  "vsix": { "file": "security-center-vscode-0.9.0.vsix", "url": "<https url>", "sha256": "<64 hex>", "size": 0 }
}
```

Private artifact host: add `SCENTER_ENGINE_DOWNLOAD_TOKEN_CREDENTIAL` (secret
text). The token is sent only to the manifest host, never logged.

Backward-compatible fallback without a manifest:

| Variable | Value |
|---|---|
| `SCENTER_ENGINE_TGZ_URL` | URL serving `security-center-vscode-X.Y.Z.tgz` (`npm pack`) |
| `SCENTER_ENGINE_SHA256` | SHA-256 of that exact package |

Paths used: `/var/jenkins_home/tools/node22` (prerequisite), and a Security
Center home the Jenkins user creates and checks itself before installing:
`$JENKINS_HOME/.security-center/engine` (engine) and
`$JENKINS_HOME/.security-center/packages` (verified package cache). No
`chown`/`chmod` by an administrator is needed.

Path overrides, most specific first: `SCENTER_ENGINE_PREFIX` /
`SCENTER_ENGINE_PACKAGES`, `SCENTER_HOME` (`<home>/engine`, `<home>/packages`),
legacy `SCENTER_TOOLS_DIR` (`<tools>/security-center`,
`<tools>/security-center-packages`). A configured path the Jenkins user cannot
create or write fails the build with ERROR, naming the variable.

To roll out a new engine build: publish the new `.tgz` at the URL and update
`SCENTER_ENGINE_SHA256`. The next build upgrades itself.

## Scanner runtime on the Jenkins node

Under Jenkins, the CI Engine runs the scanners that `security-center.yml`
selects among Semgrep, Gitleaks, Trivy and OSV-Scanner as ephemeral containers
(`docker run --rm`) on the Docker daemon the build's execution node can reach.
Nothing is installed on the node, images stay cached, and projects only choose
scanners.

- Jenkins directly on a node: the workspace is mounted read-only.
- Jenkins in a container on that same daemon: scanner containers inherit the
  Jenkins container's volumes read-only (`--volumes-from`); no host path is
  guessed.
- Before any scan, a probe container proves the workspace is visible that way.
- Scanner containers are never privileged, run with `no-new-privileges`, and
  never get the Docker socket.

One-time node prerequisite (administrator, not per project):

- the user running the Jenkins agent can run `docker` against a daemon: the
  docker CLI on the node (inside the Jenkins image when Jenkins runs in Docker)
  and access to the daemon socket or `DOCKER_HOST`;
- when Jenkins itself runs in a container, its workspaces are on a Docker volume
  or bind mount;
- outbound access to Docker Hub and ghcr.io to pull the scanner images, or the
  images preloaded on the node.

Otherwise the scan ends with ERROR, for example `SCenter CI runtime
unavailable: Docker is not accessible from this Jenkins execution node
(permission denied on the Docker daemon for user jenkins)`. Override the
automatic choice with `--scanner-runtime container|host` or
`SCENTER_SCANNER_RUNTIME`.

## Manual administrator install (alternative)

One-time installation of the Security Center CLI into a Docker-based Jenkins,
from the Docker host, when the automatic bootstrap is not used.

## Prerequisites

- Jenkins running as a Docker container (default name `jenkins`) with
  `/var/jenkins_home` on a Docker volume or bind mount.
- Node.js already installed at `/var/jenkins_home/tools/node22`
  (the installer never downloads Node).
- A package built on the development machine:

  ```bash
  cd vscode-extension
  npm run check
  npm pack --pack-destination ../dist
  ```

## Install or upgrade (one command, on the Docker host)

```bash
sudo ./install-scenter-ci.sh /path/to/security-center-vscode-0.9.0.tgz
```

Result:

| Item | Location |
|---|---|
| Command | `/var/jenkins_home/tools/security-center/bin/security-center` |
| Package | `/var/jenkins_home/tools/security-center/lib/node_modules/security-center-vscode` |
| Archives (rollback) | `/var/jenkins_home/tools/security-center-packages/` |
| Install record | `/var/jenkins_home/tools/security-center/scenter-ci-engine.json` |

Jenkins jobs use a stable path:

```groovy
environment {
  PATH = "/var/jenkins_home/tools/security-center/bin:/var/jenkins_home/tools/node22/bin:${env.PATH}"
}
// ...
sh 'security-center scan --workspace "$WORKSPACE" --format json --output security-center-full-report.json --ci-report security-center-report.json'
```

## Other modes

```bash
sudo ./install-scenter-ci.sh --check /path/to/security-center-vscode-0.9.0.tgz   # validate only, changes nothing
sudo ./install-scenter-ci.sh --status                                             # CI Engine: Installed / Not detected / Version unknown
sudo ./install-scenter-ci.sh --rollback 0.9.0                                     # reinstall an archived package
sudo ./install-scenter-ci.sh --uninstall                                          # remove the engine, keep archives
sudo ./install-scenter-ci.sh --container my-jenkins <package.tgz>                 # non-default container name
```

`sudo` is only needed when your user cannot talk to the Docker daemon.

Overrides: `SCENTER_JENKINS_CONTAINER`, `SCENTER_JENKINS_HOME`, `SCENTER_NODE_HOME`,
`SCENTER_JENKINS_USER`.

Exit codes: `0` success, `1` install/verification failure, `2` prerequisite or
usage error (nothing changed).
