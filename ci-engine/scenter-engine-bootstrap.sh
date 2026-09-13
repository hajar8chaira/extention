#!/usr/bin/env bash
#
# Security Center CI Engine - automatic Jenkins bootstrap.
#
# Runs at the start of every Security Center pipeline, inside the Jenkins
# agent. It makes sure the expected CI Engine build is installed, and does
# nothing when it already is:
#
#   installed with the expected SHA-256  -> use it, no reinstall
#   installed with another build         -> download, verify, upgrade
#   absent                               -> download, verify, install
#   any failure                          -> exit 2 (ERROR): the scan must not run
#
# Jenkins-level configuration (never in the application repository), either:
#   SCENTER_ENGINE_MANIFEST_URL  one stable URL of security-center-latest.json,
#                                published by the Security Center build: it names
#                                the TGZ URL, its SHA-256 and the source commit
# or, as a backward-compatible fallback:
#   SCENTER_ENGINE_TGZ_URL       where the engine package (npm pack .tgz) is served
#   SCENTER_ENGINE_SHA256        SHA-256 of that exact package: the expected build
# Optional:
#   SCENTER_ENGINE_DOWNLOAD_TOKEN  bearer token for a private artifact host, sent
#                                  only to the manifest host, never logged
#   SCENTER_TOOLS_DIR (default /var/jenkins_home/tools), SCENTER_NODE_HOME,
#   SCENTER_ENGINE_PREFIX, SCENTER_ENGINE_PACKAGES,
#   SCENTER_BOOTSTRAP_FAILURE_REPORT (CI report written when the engine is unavailable)
#
# This file is embedded verbatim in templates/Jenkinsfile. Keep it free of
# backslashes and triple quotes so the Groovy string stays byte-identical.

set -Eeuo pipefail

readonly PACKAGE_NAME='security-center-vscode'
readonly HELP_MARKER='Security Center headless'

TOOLS_DIR="${SCENTER_TOOLS_DIR:-/var/jenkins_home/tools}"
NODE_HOME="${SCENTER_NODE_HOME:-$TOOLS_DIR/node22}"
PREFIX="${SCENTER_ENGINE_PREFIX:-$TOOLS_DIR/security-center}"
PACKAGES="${SCENTER_ENGINE_PACKAGES:-$TOOLS_DIR/security-center-packages}"
MANIFEST_URL="${SCENTER_ENGINE_MANIFEST_URL:-}"
DOWNLOAD_TOKEN="${SCENTER_ENGINE_DOWNLOAD_TOKEN:-}"
ENGINE_URL="${SCENTER_ENGINE_TGZ_URL:-}"
EXPECTED_SHA=''
FAILURE_REPORT="${SCENTER_BOOTSTRAP_FAILURE_REPORT:-}"
LOCK_TIMEOUT="${SCENTER_BOOTSTRAP_LOCK_TIMEOUT:-600}"
MARKER="$PREFIX/scenter-ci-engine.json"
LOCK_DIR="$PACKAGES/.bootstrap.lock"

LOCK_HELD=0
NODE_BIN=''
NPM_BIN=''
NODE_VERSION=''
NPM_VERSION=''
ENGINE_VERSION=''
ENGINE_COMMAND=''
PACKAGE_VERSION=''
CACHED_PACKAGE=''
ENGINE_SOURCE='direct'
BUILD_COMMIT=''
BUILD_TIMESTAMP=''
MANIFEST_VERSION=''

log() { echo "[scenter-engine] $*"; }

# Printable, quote-free, bounded: safe inside the JSON written below.
clean_text() {
  printf '%s' "$1" | tr -cd '[:print:]' | tr -d '"' | cut -c1-300
}

# A URL without credentials, query string or fragment: safe to log and record.
safe_url() {
  local url="${1%%[?#]*}" scheme rest authority path
  case "$url" in
    *://*) scheme="${url%%://*}"; rest="${url#*://}" ;;
    *) printf '%s' "$url"; return 0 ;;
  esac
  authority="${rest%%/*}"
  path="${rest#"$authority"}"
  printf '%s://%s%s' "$scheme" "${authority##*@}" "$path"
}

# The host[:port] of a URL, without credentials.
url_authority() {
  local url="${1%%[?#]*}" rest
  case "$url" in
    *://*) rest="${url#*://}"; rest="${rest%%/*}"; printf '%s' "${rest##*@}" ;;
    *) printf '' ;;
  esac
}

json_or_null() {
  if [ -n "$1" ]; then printf '"%s"' "$(clean_text "$1")"; else printf 'null'; fi
}

# The CI report Security Delivery reads when the engine never ran: verdict
# ERROR, engine not available, and nothing else claimed.
write_failure_report() {
  local reason="$1" commit='' branch=''
  [ -n "$FAILURE_REPORT" ] || return 0
  if command -v git >/dev/null 2>&1 && [ -n "${WORKSPACE:-}" ]; then
    commit="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || true)"
    branch="$(git -C "$WORKSPACE" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    if [ "$branch" = 'HEAD' ]; then branch=''; fi
  fi
  cat > "$FAILURE_REPORT" <<REPORT
{
  "schemaVersion": 1,
  "generatedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "verdict": { "status": "ERROR", "exitCode": 2 },
  "engine": null,
  "execution": { "scanId": "", "status": "engine_unavailable", "failedScanners": [], "error": $(json_or_null "$reason") },
  "stages": null,
  "repository": { "commit": $(json_or_null "$commit"), "branch": $(json_or_null "$branch") },
  "policy": { "status": "NOT_EVALUATED", "configured": false, "blockingCount": 0, "warningCount": 0, "summary": "", "reasons": [], "legacyNotice": "" },
  "scanners": []
}
REPORT
}

release_lock() {
  if [ "$LOCK_HELD" = 1 ]; then
    rmdir "$LOCK_DIR" 2>/dev/null || true
    LOCK_HELD=0
  fi
}

fail() {
  local reason
  reason="$(clean_text "$*")"
  trap - ERR
  echo "[scenter-engine] ERROR: $reason" >&2
  echo 'SCENTER_ENGINE_STATUS=ERROR'
  write_failure_report "$reason" || true
  release_lock
  exit 2
}

trap 'fail "unexpected bootstrap error (line $LINENO)"' ERR
trap release_lock EXIT

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

resolve_toolchain() {
  local candidate
  NODE_BIN="${SCENTER_NODE:-}"
  if [ -z "$NODE_BIN" ]; then
    for candidate in "$NODE_HOME/bin/node" "$NODE_HOME/node"; do
      if [ -x "$candidate" ]; then NODE_BIN="$candidate"; break; fi
    done
  fi
  [ -n "$NODE_BIN" ] || fail "Node.js not found in $NODE_HOME (one-time Jenkins prerequisite: install Node.js 22 there)"
  NODE_VERSION="$("$NODE_BIN" --version 2>/dev/null)" || fail "Node.js at $NODE_BIN does not run"
  NPM_BIN="${SCENTER_NPM:-}"
  if [ -z "$NPM_BIN" ]; then
    for candidate in "$NODE_HOME/bin/npm" "$NODE_HOME/npm"; do
      if [ -x "$candidate" ]; then NPM_BIN="$candidate"; break; fi
    done
  fi
  [ -n "$NPM_BIN" ] || fail "npm not found next to Node.js in $NODE_HOME"
  PATH="$(dirname "$NODE_BIN"):$PATH"
  export PATH
  NPM_VERSION="$("$NPM_BIN" --version 2>/dev/null)" || fail "npm at $NPM_BIN does not run"
}

# Prints one string field of a JSON file, nothing when absent or unreadable.
json_field() {
  "$NODE_BIN" -e 'try { const v = require(process.argv[1])[process.argv[2]]; if (typeof v === "string") process.stdout.write(v); } catch (e) {}' "$1" "$2"
}

installed_package_json() {
  local candidate
  for candidate in "$PREFIX/lib/node_modules/$PACKAGE_NAME/package.json" "$PREFIX/node_modules/$PACKAGE_NAME/package.json"; do
    if [ -f "$candidate" ]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

installed_command() {
  local candidate
  for candidate in "$PREFIX/bin/security-center" "$PREFIX/security-center"; do
    if [ -f "$candidate" ] || [ -L "$candidate" ]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

acquire_lock() {
  local waited=0
  mkdir -p "$PACKAGES" "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX and $PACKAGES (the Jenkins user must own $TOOLS_DIR)"
  until mkdir "$LOCK_DIR" 2>/dev/null; do
    if [ -n "$(find "$LOCK_DIR" -maxdepth 0 -mmin +30 2>/dev/null)" ]; then
      log 'removing a stale bootstrap lock older than 30 minutes'
      rmdir "$LOCK_DIR" 2>/dev/null || true
      continue
    fi
    if [ "$waited" -ge "$LOCK_TIMEOUT" ]; then
      fail "another build has held the CI Engine bootstrap lock for more than ${LOCK_TIMEOUT}s ($LOCK_DIR)"
    fi
    sleep 2
    waited=$((waited + 2))
  done
  LOCK_HELD=1
}

# Downloads $1 to $2. With $3=yes and a token configured, the token travels in a
# private header file, never on the command line or in the log.
download() {
  local url="$1" destination="$2" with_token="${3:-no}" header_file status
  rm -f "$destination"
  if command -v curl >/dev/null 2>&1; then
    if [ "$with_token" = yes ] && [ -n "$DOWNLOAD_TOKEN" ]; then
      header_file="$PACKAGES/.auth-$$.header"
      ( umask 077; printf 'Authorization: Bearer %s' "$DOWNLOAD_TOKEN" > "$header_file" )
      if curl -fsSL --retry 2 -H "@$header_file" -o "$destination" "$url" 2>/dev/null; then status=0; else status=1; fi
      rm -f "$header_file"
      return "$status"
    fi
    if curl -fsSL --retry 2 -o "$destination" "$url" 2>/dev/null; then return 0; fi
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    if [ "$with_token" = yes ] && [ -n "$DOWNLOAD_TOKEN" ]; then
      if wget -q --header="Authorization: Bearer $DOWNLOAD_TOKEN" -O "$destination" "$url"; then return 0; fi
      return 1
    fi
    if wget -q -O "$destination" "$url"; then return 0; fi
    return 1
  fi
  fail 'neither curl nor wget is available on the Jenkins agent'
}

# Which build is expected: from the published manifest, or from the direct
# fallback variables. Nothing is installed before this is known and valid.
resolve_expected_build() {
  local manifest fields key value
  if [ -z "$MANIFEST_URL" ]; then
    ENGINE_SOURCE='direct'
    EXPECTED_SHA="$(printf '%s' "${SCENTER_ENGINE_SHA256:-}" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    [[ "$EXPECTED_SHA" =~ ^[0-9a-f]{64}$ ]] || fail 'SCENTER_ENGINE_SHA256 is not configured on Jenkins, and no SCENTER_ENGINE_MANIFEST_URL is set (one of them is required)'
    return 0
  fi
  ENGINE_SOURCE='manifest'
  if [ -n "${SCENTER_ENGINE_TGZ_URL:-}${SCENTER_ENGINE_SHA256:-}" ]; then
    log 'SCENTER_ENGINE_MANIFEST_URL is set: the direct SCENTER_ENGINE_TGZ_URL and SCENTER_ENGINE_SHA256 values are ignored'
  fi
  manifest="$PACKAGES/.manifest-latest-$$.json"
  log "reading the CI Engine manifest from $(safe_url "$MANIFEST_URL")"
  if ! download "$MANIFEST_URL" "$manifest" yes; then
    rm -f "$manifest"
    fail "CI Engine manifest unreachable: $(safe_url "$MANIFEST_URL")"
  fi
  if ! fields="$("$NODE_BIN" -e '
    const fs = require("fs");
    let m;
    try { m = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); } catch (e) { console.error("not valid JSON"); process.exit(1); }
    if (!m || typeof m !== "object" || Array.isArray(m)) { console.error("not a JSON object"); process.exit(1); }
    const hex = (v, n) => typeof v === "string" && v.length === n && /^[0-9a-f]+$/.test(v);
    const text = (v) => String(v).split("").filter((c) => c >= " " && c <= "~").join("");
    const tgz = m.tgz && typeof m.tgz === "object" ? m.tgz : {};
    const problems = [];
    if (m.schemaVersion !== 1) problems.push("schemaVersion must be 1");
    if (m.name !== "security-center-vscode") problems.push("name must be security-center-vscode");
    if (typeof m.version !== "string" || !/^[0-9]+[.][0-9]+[.][0-9]+/.test(m.version)) problems.push("version is missing");
    if (!hex(m.commit, 40)) problems.push("commit must be a 40-hex git SHA");
    if (typeof m.buildTimestamp !== "string" || Number.isNaN(Date.parse(m.buildTimestamp))) problems.push("buildTimestamp is missing");
    if (typeof tgz.url !== "string" || !/^(https?|file):[/][/]/.test(tgz.url)) problems.push("tgz.url must be an http(s) or file URL");
    if (!hex(tgz.sha256, 64)) problems.push("tgz.sha256 must be a 64-hex SHA-256");
    if (problems.length) { console.error(problems.join("; ")); process.exit(1); }
    const nl = String.fromCharCode(10);
    process.stdout.write(["TGZ_URL=" + text(tgz.url), "TGZ_SHA256=" + tgz.sha256, "COMMIT=" + m.commit, "VERSION=" + text(m.version), "BUILT=" + text(m.buildTimestamp)].join(nl) + nl);
  ' "$manifest" 2>&1)"; then
    rm -f "$manifest"
    fail "invalid CI Engine manifest from $(safe_url "$MANIFEST_URL"): $fields"
  fi
  rm -f "$manifest"
  while IFS='=' read -r key value; do
    case "$key" in
      TGZ_URL) ENGINE_URL="$value" ;;
      TGZ_SHA256) EXPECTED_SHA="$value" ;;
      COMMIT) BUILD_COMMIT="$value" ;;
      VERSION) MANIFEST_VERSION="$value" ;;
      BUILT) BUILD_TIMESTAMP="$value" ;;
    esac
  done <<FIELDS
$fields
FIELDS
  [[ "$EXPECTED_SHA" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid CI Engine manifest: no valid tgz.sha256'
  log "manifest build: $PACKAGE_NAME@$MANIFEST_VERSION, commit $BUILD_COMMIT, built $BUILD_TIMESTAMP"
}

# The expected build is installed, verified by its recorded SHA-256 and by
# actually running the command.
engine_is_expected() {
  local package_json command help marker_sha
  [ -f "$MARKER" ] || return 1
  marker_sha="$(json_field "$MARKER" sha256)"
  [ "$marker_sha" = "$EXPECTED_SHA" ] || return 1
  package_json="$(installed_package_json)" || return 1
  command="$(installed_command)" || return 1
  help="$("$command" --help 2>&1)" || return 1
  case "$help" in *"$HELP_MARKER"*) ;; *) return 1 ;; esac
  ENGINE_VERSION="$(json_field "$package_json" version)"
  ENGINE_COMMAND="$command"
  if [ -z "$BUILD_COMMIT" ]; then BUILD_COMMIT="$(json_field "$MARKER" commit)"; fi
  return 0
}

fetch_package() {
  local cached="$PACKAGES/sha256-$EXPECTED_SHA.tgz" download_file actual source token_mode=no
  CACHED_PACKAGE="$cached"
  if [ -f "$cached" ] && [ "$(sha_of "$cached")" = "$EXPECTED_SHA" ]; then
    log "package found in the persistent cache: $cached"
    return 0
  fi
  [ -n "$ENGINE_URL" ] || fail 'the CI Engine must be provisioned but SCENTER_ENGINE_TGZ_URL is not configured on Jenkins'
  source="$(safe_url "$ENGINE_URL")"
  # The download token only ever goes back to the host that served the manifest.
  if [ "$ENGINE_SOURCE" = manifest ] && [ "$(url_authority "$ENGINE_URL")" = "$(url_authority "$MANIFEST_URL")" ]; then
    token_mode=yes
  fi
  download_file="$PACKAGES/.download-$$.tgz"
  log "downloading the CI Engine package from $source"
  if ! download "$ENGINE_URL" "$download_file" "$token_mode"; then
    rm -f "$download_file"
    fail "download failed from $source"
  fi
  actual="$(sha_of "$download_file")"
  if [ "$actual" != "$EXPECTED_SHA" ]; then
    rm -f "$download_file"
    fail "checksum mismatch for $source: expected $EXPECTED_SHA, got $actual. Package rejected, nothing installed."
  fi
  mv -f "$download_file" "$cached"
  log "package verified (sha256 $EXPECTED_SHA) and cached: $cached"
}

validate_package() {
  local package="$1" manifest name version entry
  if ! tar -tzf "$package" package/package.json package/src/cli.js >/dev/null 2>&1; then
    fail 'the configured package is not a Security Center CI Engine package'
  fi
  manifest="$PACKAGES/.manifest-$$.json"
  if ! tar -xOzf "$package" package/package.json > "$manifest" 2>/dev/null; then
    rm -f "$manifest"
    fail 'cannot read package.json from the CI Engine package'
  fi
  name="$(json_field "$manifest" name)"
  version="$(json_field "$manifest" version)"
  rm -f "$manifest"
  [ "$name" = "$PACKAGE_NAME" ] || fail "unexpected package name '$name' (expected $PACKAGE_NAME)"
  [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+ ]] || fail 'the CI Engine package has no valid version'
  if [ "$ENGINE_SOURCE" = manifest ] && [ "$version" != "$MANIFEST_VERSION" ]; then
    fail "the manifest names version $MANIFEST_VERSION but the package is version $version"
  fi
  # Byte-level check: some shells strip a trailing carriage return in command
  # substitution, which would let a CRLF entrypoint pass a plain string compare.
  entry="$PACKAGES/.entry-$$.js"
  if ! tar -xOzf "$package" package/src/cli.js > "$entry" 2>/dev/null; then
    rm -f "$entry"
    fail 'cannot read the CI Engine entrypoint from the package'
  fi
  if ! "$NODE_BIN" -e 'const b = require("fs").readFileSync(process.argv[1]); const end = b.indexOf(10); const first = b.subarray(0, end < 0 ? b.length : end).toString("latin1"); process.exit(first === "#!/usr/bin/env node" ? 0 : 1);' "$entry"; then
    rm -f "$entry"
    fail 'the CI Engine entrypoint is not Linux-safe (missing shebang or CRLF line endings)'
  fi
  rm -f "$entry"
  PACKAGE_VERSION="$version"
}

install_package() {
  log "installing $PACKAGE_NAME@$PACKAGE_VERSION into $PREFIX"
  if ! "$NPM_BIN" install --global --prefix "$PREFIX" "$CACHED_PACKAGE" --no-audit --no-fund --loglevel=error >/dev/null; then
    fail 'npm install of the CI Engine failed'
  fi
}

verify_install() {
  local package_json command help
  package_json="$(installed_package_json)" || fail "installed package not found under $PREFIX after npm install"
  command="$(installed_command)" || fail "security-center command not created under $PREFIX"
  help="$("$command" --help 2>&1)" || fail 'security-center --help failed after install'
  case "$help" in *"$HELP_MARKER"*) ;; *) fail 'security-center --help did not print the Security Center help' ;; esac
  ENGINE_VERSION="$(json_field "$package_json" version)"
  [ "$ENGINE_VERSION" = "$PACKAGE_VERSION" ] || fail "installed version $ENGINE_VERSION differs from the package version $PACKAGE_VERSION"
  ENGINE_COMMAND="$command"
}

write_marker() {
  local previous="$1" temporary="$MARKER.tmp.$$" source
  if [ "$ENGINE_SOURCE" = manifest ]; then source="$(safe_url "$MANIFEST_URL")"; else source="$(safe_url "$ENGINE_URL")"; fi
  cat > "$temporary" <<MARKER_JSON
{
  "engine": "security-center",
  "package": "$PACKAGE_NAME",
  "version": "$(clean_text "$ENGINE_VERSION")",
  "sha256": "$EXPECTED_SHA",
  "commit": "$(clean_text "$BUILD_COMMIT")",
  "buildTimestamp": "$(clean_text "$BUILD_TIMESTAMP")",
  "resolvedBy": "$ENGINE_SOURCE",
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "installedBy": "jenkins-bootstrap",
  "source": "$(clean_text "$source")",
  "previousSha256": "$previous",
  "node": "$(clean_text "$NODE_VERSION")",
  "npm": "$(clean_text "$NPM_VERSION")",
  "command": "$(clean_text "$ENGINE_COMMAND")"
}
MARKER_JSON
  mv -f "$temporary" "$MARKER"
}

emit() {
  echo 'SCENTER_ENGINE_STATUS=READY'
  echo "SCENTER_ENGINE_ACTION=$1"
  echo "SCENTER_ENGINE_VERSION=$ENGINE_VERSION"
  echo "SCENTER_ENGINE_SHA256=$EXPECTED_SHA"
  echo "SCENTER_ENGINE_COMMIT=$BUILD_COMMIT"
  echo "SCENTER_ENGINE_SOURCE=$ENGINE_SOURCE"
  echo "SCENTER_ENGINE_COMMAND=$ENGINE_COMMAND"
}

main() {
  local previous='' action='installed'
  resolve_toolchain
  log "node $NODE_VERSION, npm $NPM_VERSION"
  acquire_lock
  resolve_expected_build
  if engine_is_expected; then
    log "CI Engine $ENGINE_VERSION already installed with the expected build: nothing to do"
    emit unchanged
    release_lock
    return 0
  fi
  if [ -f "$MARKER" ]; then
    previous="$(json_field "$MARKER" sha256)"
    [[ "$previous" =~ ^[0-9a-f]{64}$ ]] || previous=''
  fi
  if [ -n "$previous" ] || installed_package_json >/dev/null; then action='updated'; fi
  fetch_package
  validate_package "$CACHED_PACKAGE"
  install_package
  verify_install
  write_marker "$previous"
  log "CI Engine $ENGINE_VERSION $action and verified"
  emit "$action"
  release_lock
}

main "$@"
