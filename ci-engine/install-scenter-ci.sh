#!/usr/bin/env bash
#
# Security Center CI Engine - one-time Jenkins administrator installer.
#
# Installs (or upgrades) the packaged Security Center CLI into the persistent
# home of a Docker-based Jenkins, so every job can simply run:
#
#   security-center scan --workspace "$WORKSPACE" ...
#
# Usage (on the Docker host):
#   sudo ./install-scenter-ci.sh /path/to/security-center-vscode-0.9.0.tgz
#   sudo ./install-scenter-ci.sh --check [/path/to/security-center-vscode-0.9.0.tgz]
#   sudo ./install-scenter-ci.sh --status
#   sudo ./install-scenter-ci.sh --rollback 0.9.0
#   sudo ./install-scenter-ci.sh --uninstall
#   Option: --container NAME   (default: jenkins)
#
# Exit codes:
#   0  success (READY, CHECK PASSED, UNINSTALLED, or status reported)
#   1  failure while installing or verifying
#   2  prerequisite or usage error - nothing was changed
#
# Guarantees:
#   - never downloads Node.js or anything else: npm installs the local archive,
#     which has no dependencies;
#   - never prints environment variables or container configuration, which can
#     hold credentials;
#   - never deletes an archived package, so every earlier version stays
#     available for rollback.

set -Eeuo pipefail
# Git Bash on Windows (Docker Desktop) would otherwise rewrite /var/... paths
# meant for the container into Windows paths.
export MSYS_NO_PATHCONV=1

readonly PACKAGE_NAME='security-center-vscode'
readonly PACKAGE_FILE_RE='^security-center-vscode-[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?\.tgz$'
readonly ARCHIVED_FILE_RE='^security-center-vscode-[0-9A-Za-z.+-]+\.tgz$'
readonly VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'
readonly MIN_NODE_MAJOR=18

CONTAINER="${SCENTER_JENKINS_CONTAINER:-jenkins}"
CONTAINER_EXPLICIT="${SCENTER_JENKINS_CONTAINER:+yes}"
JENKINS_HOME_DIR="${SCENTER_JENKINS_HOME:-/var/jenkins_home}"
NODE_HOME="${SCENTER_NODE_HOME:-$JENKINS_HOME_DIR/tools/node22}"
JENKINS_USER="${SCENTER_JENKINS_USER:-jenkins}"

PREFIX="$JENKINS_HOME_DIR/tools/security-center"
PACKAGES="$JENKINS_HOME_DIR/tools/security-center-packages"
MARKER="$PREFIX/scenter-ci-engine.json"
COMMAND_PATH="$PREFIX/bin/security-center"
INSTALLED_PACKAGE_JSON="$PREFIX/lib/node_modules/$PACKAGE_NAME/package.json"
CONTAINER_PATH="$PREFIX/bin:$NODE_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

MODE='install'
ARG=''
NODE_VERSION='-'
NPM_VERSION='-'
ENGINE_VERSION='-'
ENGINE_STATE=''
RESULT='FAILED'
STEP='startup'
ARCHIVE_FILE=''
ARCHIVE_NAME=''
ARCHIVE_VERSION=''
ARCHIVE_SHA=''

# ------------------------------------------------------------------ output

say()  { printf '%s\n' "$*"; }
step() { STEP="$*"; printf '==> %s\n' "$*"; }
ok()   { printf '    ok: %s\n' "$*"; }

summary() {
  printf '\nSecurity Center CI Engine\n'
  printf '  %-19s %s\n' \
    'Jenkins container' "$CONTAINER" \
    'Node version' "$NODE_VERSION" \
    'npm version' "$NPM_VERSION" \
    'Package' "$PACKAGE_NAME@$ENGINE_VERSION" \
    'Install path' "$PREFIX" \
    'Command path' "$COMMAND_PATH"
  [ -z "$ENGINE_STATE" ] || printf '  %-19s %s\n' 'Detection' "$ENGINE_STATE"
  printf '  %-19s %s\n' 'Result' "$RESULT"
}

die() {
  local code="$1"; shift
  trap - ERR
  printf 'ERROR: %s\n' "$*" >&2
  RESULT='FAILED'
  summary
  exit "$code"
}

on_error() {
  local status="$1" line="$2"
  trap - ERR
  printf 'ERROR: step "%s" failed (exit %s, line %s).\n' "$STEP" "$status" "$line" >&2
  RESULT='FAILED'
  summary
  exit 1
}

usage() {
  cat <<'USAGE'
Security Center CI Engine installer for Docker-based Jenkins.

Usage:
  install-scenter-ci.sh [--container NAME] <security-center-vscode-X.Y.Z.tgz>
      Install or upgrade the CI Engine from a package built with `npm pack`.
  install-scenter-ci.sh [--container NAME] --check [<security-center-vscode-X.Y.Z.tgz>]
      Validate prerequisites (and the archive, if given). Changes nothing.
  install-scenter-ci.sh [--container NAME] --status
      Report: CI Engine: Installed / Not detected / Version unknown.
  install-scenter-ci.sh [--container NAME] --rollback <X.Y.Z | archived .tgz name>
      Reinstall a package kept in the packages directory.
  install-scenter-ci.sh [--container NAME] --uninstall
      Remove the CI Engine. Archived packages are kept.

Environment overrides:
  SCENTER_JENKINS_CONTAINER  (default: jenkins)
  SCENTER_JENKINS_HOME       (default: /var/jenkins_home)
  SCENTER_NODE_HOME          (default: $SCENTER_JENKINS_HOME/tools/node22)
  SCENTER_JENKINS_USER       (default: jenkins)
USAGE
}

usage_error() {
  printf 'ERROR: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

# ------------------------------------------------------------------ helpers

# Commands inside the Jenkins container, as the Jenkins user, with the
# persistent Node.js and the CI Engine on PATH.
jexec() {
  docker exec -u "$JENKINS_USER" -e "PATH=$CONTAINER_PATH" -e "HOME=$JENKINS_HOME_DIR" \
    -w "$JENKINS_HOME_DIR" "$CONTAINER" "$@"
}
jexec_stdin() {
  docker exec -i -u "$JENKINS_USER" -e "PATH=$CONTAINER_PATH" -e "HOME=$JENKINS_HOME_DIR" \
    -w "$JENKINS_HOME_DIR" "$CONTAINER" "$@"
}
# Only used to create the two install directories and fix their ownership.
rexec() {
  docker exec -u 0 "$CONTAINER" "$@"
}

host_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# `docker cp` needs a native path on Git Bash for Windows.
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

installed_version() {
  jexec "$NODE_HOME/bin/node" -e \
    'const v = require(process.argv[1]).version; if (!/^\d+\.\d+\.\d+/.test(v || "")) process.exit(1); process.stdout.write(v);' \
    "$INSTALLED_PACKAGE_JSON" 2>/dev/null
}

archived_list() {
  jexec sh -c 'ls -1 "$1" 2>/dev/null | grep -E "\.tgz$" || true' _ "$PACKAGES" 2>/dev/null || true
}

# ------------------------------------------------------------------ checks

validate_archive() {
  local file="$1" name json name_in version cli_head
  step 'Package archive'
  [ -f "$file" ] && [ -r "$file" ] || die 2 "package archive not found or unreadable: $file"
  name="$(basename "$file")"
  [[ "$name" =~ $PACKAGE_FILE_RE ]] \
    || die 2 "unexpected archive name '$name' (expected $PACKAGE_NAME-X.Y.Z.tgz, as produced by npm pack)"
  command -v tar >/dev/null 2>&1 || die 2 'tar is required on this host'
  tar -tzf "$file" package/package.json package/src/cli.js >/dev/null 2>&1 \
    || die 2 "'$name' is not a Security Center npm package (package/package.json or package/src/cli.js missing)"
  json="$({ tar -xOzf "$file" package/package.json || true; })"
  name_in="$({ printf '%s\n' "$json" | sed -n 's/^  "name": *"\([^"]*\)".*/\1/p' || true; } | head -n 1)"
  version="$({ printf '%s\n' "$json" | sed -n 's/^  "version": *"\([^"]*\)".*/\1/p' || true; } | head -n 1)"
  [ "$name_in" = "$PACKAGE_NAME" ] || die 2 "archive package name is '$name_in', expected $PACKAGE_NAME"
  [[ "$version" =~ $VERSION_RE ]] || die 2 "archive '$name' has no valid package version"
  [ "$name" = "$PACKAGE_NAME-$version.tgz" ] || die 2 "archive name '$name' does not match its package version $version"
  cli_head="$({ tar -xOzf "$file" package/src/cli.js || true; } | head -n 1)"
  case "$cli_head" in
    *$'\r') die 2 "src/cli.js has CRLF line endings: the security-center command would not run on Linux. Rebuild the package." ;;
  esac
  [ "$cli_head" = '#!/usr/bin/env node' ] || die 2 "src/cli.js does not start with '#!/usr/bin/env node'"
  ARCHIVE_FILE="$file"
  ARCHIVE_NAME="$name"
  ARCHIVE_VERSION="$version"
  ARCHIVE_SHA="$(host_sha256 "$file")"
  ok "$name (version $version, sha256 $ARCHIVE_SHA)"
}

require_docker() {
  step 'Docker'
  command -v docker >/dev/null 2>&1 || die 2 'docker CLI not found on this host'
  docker info >/dev/null 2>&1 \
    || die 2 'cannot reach the Docker daemon (start Docker, or run with sudo / as a member of the docker group)'
  ok 'daemon reachable'
}

detect_container() {
  local candidates count running
  step 'Jenkins container'
  [[ "$CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die 2 "invalid container name: $CONTAINER"
  if ! docker inspect --type container "$CONTAINER" >/dev/null 2>&1; then
    [ -z "$CONTAINER_EXPLICIT" ] || die 2 "container '$CONTAINER' not found"
    candidates="$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /^jenkins\/jenkins(:|$)/ {print $1}')"
    count="$(printf '%s' "$candidates" | grep -c . || true)"
    [ "$count" = 1 ] \
      || die 2 "no container named '$CONTAINER' and $count running jenkins/jenkins containers: use --container NAME"
    say "    container '$CONTAINER' not found; using the only running jenkins/jenkins container: $candidates"
    CONTAINER="$candidates"
  fi
  running="$(docker inspect --type container -f '{{.State.Running}}' "$CONTAINER")"
  [ "$running" = true ] || die 2 "container '$CONTAINER' is not running"
  ok "$CONTAINER is running"
}

check_home() {
  local mount
  step 'Persistent Jenkins home'
  # Only the mount of the Jenkins home is read - never the container environment.
  mount="$(docker inspect --type container \
    -f "{{range .Mounts}}{{if eq .Destination \"$JENKINS_HOME_DIR\"}}{{.Type}} {{if .Name}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}" \
    "$CONTAINER")"
  [ -n "$mount" ] \
    || die 2 "$JENKINS_HOME_DIR is not a Docker volume or bind mount in '$CONTAINER': an installation there would be lost when the container is recreated"
  jexec sh -c 'test -d "$1" && test -w "$1"' _ "$JENKINS_HOME_DIR" \
    || die 2 "$JENKINS_HOME_DIR is not writable by user '$JENKINS_USER' inside '$CONTAINER'"
  ok "$JENKINS_HOME_DIR persisted by $mount, writable by $JENKINS_USER"
}

check_node() {
  local major
  step 'Node.js prerequisite'
  jexec test -x "$NODE_HOME/bin/node" \
    || die 2 "Node.js not found at $NODE_HOME/bin/node. Install Node.js 22 there first (this installer does not download Node), or set SCENTER_NODE_HOME."
  NODE_VERSION="$(jexec "$NODE_HOME/bin/node" --version)" || die 2 "node at $NODE_HOME/bin/node does not run"
  major="${NODE_VERSION#v}"
  major="${major%%.*}"
  { [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge "$MIN_NODE_MAJOR" ]; } \
    || die 2 "Node.js $NODE_VERSION is too old (need >= $MIN_NODE_MAJOR)"
  ok "node $NODE_VERSION"
  step 'npm prerequisite'
  NPM_VERSION="$(jexec "$NODE_HOME/bin/npm" --version)" || die 2 "npm is not usable from $NODE_HOME/bin"
  ok "npm $NPM_VERSION"
}

engine_state() {
  local version
  if ! jexec test -x "$COMMAND_PATH" >/dev/null 2>&1; then
    ENGINE_STATE='CI Engine: Not detected'
  elif version="$(installed_version)"; then
    ENGINE_VERSION="$version"
    ENGINE_STATE="CI Engine: Installed ($version)"
  else
    ENGINE_STATE='CI Engine: Version unknown'
  fi
}

# ------------------------------------------------------------------ actions

prepare_dirs() {
  step 'Install directories'
  rexec sh -c '
    set -e
    user="$1"; shift
    group="$(id -gn "$user")"
    for dir in "$@"; do
      mkdir -p "$dir"
      chown -R "$user:$group" "$dir"
      chmod 0755 "$dir"
    done' _ "$JENKINS_USER" "$PREFIX" "$PACKAGES" \
    || die 1 "could not prepare $PREFIX and $PACKAGES"
  ok "$PREFIX"
  ok "$PACKAGES (owner $JENKINS_USER, mode 0755)"
}

archive_package() {
  local target="$PACKAGES/$ARCHIVE_NAME" incoming="$PACKAGES/.incoming-$ARCHIVE_NAME" existing_sha kept copied_sha
  step 'Archive package'
  if jexec test -f "$target"; then
    existing_sha="$(jexec sha256sum "$target" | awk '{print $1}')"
    if [ "$existing_sha" = "$ARCHIVE_SHA" ]; then
      ok "$ARCHIVE_NAME already archived (identical)"
      return 0
    fi
    # A different build under the same version is kept, never overwritten.
    kept="$PACKAGES/${ARCHIVE_NAME%.tgz}.${existing_sha:0:12}.tgz"
    jexec mv -f "$target" "$kept"
    ok "previous build of $ARCHIVE_VERSION kept for rollback: $(basename "$kept")"
  fi
  docker cp "$(host_path "$ARCHIVE_FILE")" "$CONTAINER:$incoming" >/dev/null
  rexec sh -c 'chown "$1:$(id -gn "$1")" "$2" && chmod 0644 "$2"' _ "$JENKINS_USER" "$incoming"
  copied_sha="$(jexec sha256sum "$incoming" | awk '{print $1}')"
  if [ "$copied_sha" != "$ARCHIVE_SHA" ]; then
    jexec rm -f "$incoming"
    die 1 "checksum mismatch after copying $ARCHIVE_NAME into $CONTAINER"
  fi
  jexec mv -f "$incoming" "$target"
  ok "$target"
}

install_package() {
  local archive="$1"
  step "Install $PACKAGE_NAME"
  jexec "$NODE_HOME/bin/npm" install --global --prefix "$PREFIX" "$archive" \
    --no-audit --no-fund --loglevel=error >/dev/null \
    || die 1 "npm install failed for $archive"
  ok "installed into $PREFIX"
}

verify_install() {
  local expected="$1" help
  step 'Verify'
  jexec test -x "$COMMAND_PATH" || die 1 "$COMMAND_PATH was not created"
  help="$(jexec "$COMMAND_PATH" --help 2>&1)" || die 1 "'security-center --help' failed inside $CONTAINER"
  case "$help" in
    *'Security Center headless'*) ok 'security-center --help' ;;
    *) die 1 "'security-center --help' did not print the Security Center help" ;;
  esac
  ENGINE_VERSION="$(installed_version)" || die 1 'installed package version cannot be read'
  [ -z "$expected" ] || [ "$ENGINE_VERSION" = "$expected" ] \
    || die 1 "installed version is $ENGINE_VERSION, expected $expected"
  jexec "$NODE_HOME/bin/npm" ls --global --prefix "$PREFIX" --depth=0 "$PACKAGE_NAME" >/dev/null \
    || die 1 "npm does not list $PACKAGE_NAME under $PREFIX"
  ok "$PACKAGE_NAME@$ENGINE_VERSION"
  ENGINE_STATE="CI Engine: Installed ($ENGINE_VERSION)"
}

write_marker() {
  local sha="$1"
  # Non-secret install record: what is installed, from which archive, when.
  jexec_stdin sh -c 'cat > "$1.tmp" && mv -f "$1.tmp" "$1"' _ "$MARKER" <<MARKER_JSON
{
  "engine": "security-center",
  "package": "$PACKAGE_NAME",
  "version": "$ENGINE_VERSION",
  "sha256": "$sha",
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "node": "$NODE_VERSION",
  "npm": "$NPM_VERSION",
  "command": "$COMMAND_PATH"
}
MARKER_JSON
  ok "install record $MARKER"
}

# ------------------------------------------------------------------ modes

run_install() {
  local previous
  validate_archive "$ARG"
  require_docker
  detect_container
  check_home
  check_node
  engine_state
  previous="$ENGINE_STATE"
  say "    before: $previous"
  prepare_dirs
  archive_package
  install_package "$PACKAGES/$ARCHIVE_NAME"
  verify_install "$ARCHIVE_VERSION"
  write_marker "$ARCHIVE_SHA"
  RESULT='READY'
}

run_check() {
  if [ -n "$ARG" ]; then validate_archive "$ARG"; fi
  require_docker
  detect_container
  check_home
  check_node
  step 'Install location'
  if ! jexec sh -c 'for d in "$@"; do if [ -e "$d" ] && [ ! -w "$d" ]; then exit 1; fi; done' _ "$PREFIX" "$PACKAGES"; then
    say "    note: an existing install directory is not writable by $JENKINS_USER; the installer will fix its ownership"
  fi
  engine_state
  ok "$ENGINE_STATE"
  RESULT='CHECK PASSED (nothing changed)'
}

run_status() {
  require_docker
  detect_container
  NODE_VERSION="$(jexec "$NODE_HOME/bin/node" --version 2>/dev/null)" || NODE_VERSION='not found'
  NPM_VERSION="$(jexec "$NODE_HOME/bin/npm" --version 2>/dev/null)" || NPM_VERSION='not found'
  engine_state
  RESULT="$ENGINE_STATE"
}

run_rollback() {
  local name="$ARG" sha
  [[ "$name" =~ $VERSION_RE ]] && name="$PACKAGE_NAME-$name.tgz"
  name="$(basename "$name")"
  [[ "$name" =~ $ARCHIVED_FILE_RE ]] || usage_error "invalid rollback target: $ARG"
  require_docker
  detect_container
  check_home
  check_node
  step "Rollback to $name"
  jexec test -f "$PACKAGES/$name" \
    || die 2 "$name is not in $PACKAGES (available: $(archived_list | tr '\n' ' '))"
  prepare_dirs
  install_package "$PACKAGES/$name"
  verify_install ''
  sha="$(jexec sha256sum "$PACKAGES/$name" | awk '{print $1}')"
  write_marker "$sha"
  RESULT='READY'
}

run_uninstall() {
  require_docker
  detect_container
  check_node
  step 'Uninstall'
  if jexec test -e "$PREFIX/lib/node_modules/$PACKAGE_NAME"; then
    jexec "$NODE_HOME/bin/npm" uninstall --global --prefix "$PREFIX" "$PACKAGE_NAME" --loglevel=error >/dev/null \
      || die 1 'npm uninstall failed'
    ok "removed $PACKAGE_NAME from $PREFIX"
  else
    ok "$PACKAGE_NAME was not installed"
  fi
  jexec rm -f "$MARKER"
  if jexec test -e "$COMMAND_PATH"; then die 1 "$COMMAND_PATH still exists after uninstall"; fi
  ENGINE_VERSION='-'
  ENGINE_STATE='CI Engine: Not detected'
  ok "archived packages kept in $PACKAGES"
  RESULT='UNINSTALLED'
}

# ------------------------------------------------------------------ main

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --container)
      [ $# -ge 2 ] || usage_error '--container needs a name'
      CONTAINER="$2"; CONTAINER_EXPLICIT=yes; shift 2 ;;
    --container=*) CONTAINER="${1#*=}"; CONTAINER_EXPLICIT=yes; shift ;;
    --check) MODE='check'; shift ;;
    --status) MODE='status'; shift ;;
    --uninstall) MODE='uninstall'; shift ;;
    --rollback)
      [ $# -ge 2 ] || usage_error '--rollback needs a version (X.Y.Z) or an archived .tgz name'
      MODE='rollback'; ARG="$2"; shift 2 ;;
    -*) usage_error "unknown option: $1" ;;
    *)
      [ -z "$ARG" ] || usage_error "unexpected argument: $1"
      ARG="$1"; shift ;;
  esac
done

case "$MODE" in
  install) [ -n "$ARG" ] || usage_error 'missing package archive (security-center-vscode-X.Y.Z.tgz)' ;;
  status|uninstall) [ -z "$ARG" ] || usage_error "--$MODE takes no package argument" ;;
esac

trap 'on_error $? $LINENO' ERR

case "$MODE" in
  install) run_install ;;
  check) run_check ;;
  status) run_status ;;
  rollback) run_rollback ;;
  uninstall) run_uninstall ;;
esac

summary
