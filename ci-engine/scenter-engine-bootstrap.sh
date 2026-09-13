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
#   any failure or timeout               -> exit 2 (ERROR): the scan must not run
#
# Every phase is logged before it starts and every wait is bounded: the
# bootstrap never leaves Jenkins waiting silently.
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
#   SCENTER_NODE_HOME (default /var/jenkins_home/tools/node22)
#   Where the engine and its verified package cache live, most specific first:
#     SCENTER_ENGINE_PREFIX, SCENTER_ENGINE_PACKAGES   exact directories
#     SCENTER_HOME                                     <home>/engine and <home>/packages
#     SCENTER_TOOLS_DIR                                legacy <tools>/security-center(-packages)
#     default                                          $JENKINS_HOME/.security-center/engine and /packages
#   Directories are created and checked as the Jenkins user; ownership and
#   permissions are never changed: an unusable path fails with its origin.
#   SCENTER_BOOTSTRAP_FAILURE_REPORT (CI report written when the engine is unavailable)
# Bounds, in seconds:
#   SCENTER_BOOTSTRAP_LOCK_TIMEOUT (300)       wait for another bootstrap's install lock
#   SCENTER_BOOTSTRAP_LOCK_STALE_AFTER (900)   a lock whose owner is older than this is abandoned
#   SCENTER_BOOTSTRAP_LOCK_OWNER_GRACE (3)     a lock still without owner record after this is abandoned
#   SCENTER_BOOTSTRAP_CONNECT_TIMEOUT (20)     TCP/TLS connection, per attempt
#   SCENTER_BOOTSTRAP_MANIFEST_TIMEOUT (60)    whole manifest download, redirects included
#   SCENTER_BOOTSTRAP_DOWNLOAD_TIMEOUT (300)   whole engine package download
#   SCENTER_BOOTSTRAP_INSTALL_TIMEOUT (300)    npm install of the engine
#   SCENTER_BOOTSTRAP_VERIFY_TIMEOUT (60)      each run of security-center --help
#
# This file is embedded verbatim in templates/Jenkinsfile. Keep it free of
# backslashes and triple quotes so the Groovy string stays byte-identical.

set -Eeuo pipefail

readonly PACKAGE_NAME='security-center-vscode'
readonly HELP_MARKER='Security Center headless'

TOOLS_DIR="${SCENTER_TOOLS_DIR:-/var/jenkins_home/tools}"
NODE_HOME="${SCENTER_NODE_HOME:-$TOOLS_DIR/node22}"
SC_HOME="${SCENTER_HOME:-${JENKINS_HOME:-/var/jenkins_home}/.security-center}"
if [ -n "${SCENTER_ENGINE_PREFIX:-}" ]; then
  PREFIX="$SCENTER_ENGINE_PREFIX"; PREFIX_ORIGIN='SCENTER_ENGINE_PREFIX'
elif [ -n "${SCENTER_HOME:-}" ]; then
  PREFIX="$SC_HOME/engine"; PREFIX_ORIGIN='SCENTER_HOME'
elif [ -n "${SCENTER_TOOLS_DIR:-}" ]; then
  PREFIX="$TOOLS_DIR/security-center"; PREFIX_ORIGIN='SCENTER_TOOLS_DIR'
else
  PREFIX="$SC_HOME/engine"; PREFIX_ORIGIN='default'
fi
if [ -n "${SCENTER_ENGINE_PACKAGES:-}" ]; then
  PACKAGES="$SCENTER_ENGINE_PACKAGES"; PACKAGES_ORIGIN='SCENTER_ENGINE_PACKAGES'
elif [ -n "${SCENTER_HOME:-}" ]; then
  PACKAGES="$SC_HOME/packages"; PACKAGES_ORIGIN='SCENTER_HOME'
elif [ -n "${SCENTER_TOOLS_DIR:-}" ]; then
  PACKAGES="$TOOLS_DIR/security-center-packages"; PACKAGES_ORIGIN='SCENTER_TOOLS_DIR'
else
  PACKAGES="$SC_HOME/packages"; PACKAGES_ORIGIN='default'
fi
MANIFEST_URL="${SCENTER_ENGINE_MANIFEST_URL:-}"
DOWNLOAD_TOKEN="${SCENTER_ENGINE_DOWNLOAD_TOKEN:-}"
ENGINE_URL="${SCENTER_ENGINE_TGZ_URL:-}"
EXPECTED_SHA=''
FAILURE_REPORT="${SCENTER_BOOTSTRAP_FAILURE_REPORT:-}"
LOCK_TIMEOUT="${SCENTER_BOOTSTRAP_LOCK_TIMEOUT:-300}"
LOCK_STALE_AFTER="${SCENTER_BOOTSTRAP_LOCK_STALE_AFTER:-900}"
LOCK_OWNER_GRACE="${SCENTER_BOOTSTRAP_LOCK_OWNER_GRACE:-3}"
CONNECT_TIMEOUT="${SCENTER_BOOTSTRAP_CONNECT_TIMEOUT:-20}"
MANIFEST_TIMEOUT="${SCENTER_BOOTSTRAP_MANIFEST_TIMEOUT:-60}"
DOWNLOAD_TIMEOUT="${SCENTER_BOOTSTRAP_DOWNLOAD_TIMEOUT:-300}"
INSTALL_TIMEOUT="${SCENTER_BOOTSTRAP_INSTALL_TIMEOUT:-300}"
VERIFY_TIMEOUT="${SCENTER_BOOTSTRAP_VERIFY_TIMEOUT:-60}"
MARKER="$PREFIX/scenter-ci-engine.json"
LOCK_DIR="$PACKAGES/.bootstrap.lock"
LOCK_OWNER_FILE="$LOCK_DIR/owner"

PHASE='starting'
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
DOWNLOAD_ERROR=''
TEMP_FILES=''

log() { echo "[scenter-engine] $*"; }

# The current phase, logged before the work starts: the last line in the build
# log always names what the bootstrap is doing.
phase() {
  PHASE="$1"
  log "$1"
}

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

# Temporary files removed on success, failure and interruption alike.
track_temp() { TEMP_FILES="$TEMP_FILES $1"; }
cleanup_temp() {
  local file
  for file in $TEMP_FILES; do rm -f "$file" 2>/dev/null || true; done
  TEMP_FILES=''
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

current_host() {
  hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown
}

# The lock owner record as printable text, nothing when there is none. The group
# redirection also silences the shell's own error when the file disappears.
lock_owner_record() {
  [ -f "$LOCK_OWNER_FILE" ] || return 0
  { tr -cd 'A-Za-z0-9=._: -' < "$LOCK_OWNER_FILE"; } 2>/dev/null || true
}

# One key=value field ($2) of an owner record ($1).
owner_field() {
  local entry
  for entry in $1; do
    case "$entry" in "$2="*) printf '%s' "${entry#*=}"; return 0 ;; esac
  done
  return 0
}

# One key=value field of the current lock owner record.
lock_owner_field() {
  owner_field "$(lock_owner_record)" "$1"
}

# Releases the lock only if this process still owns it.
release_lock() {
  if [ "$LOCK_HELD" = 1 ]; then
    if [ "$(lock_owner_field pid)" = "$$" ]; then
      rm -f "$LOCK_OWNER_FILE" 2>/dev/null || true
      rmdir "$LOCK_DIR" 2>/dev/null || true
    fi
    LOCK_HELD=0
  fi
}

fail() {
  local reason
  reason="$(clean_text "$*")"
  trap - ERR INT TERM HUP
  # A bounded download or install still running is stopped with the bootstrap.
  if [ -n "${CHILD_PID:-}" ]; then kill "$CHILD_PID" 2>/dev/null || true; CHILD_PID=''; fi
  # Written to the build log saved at startup: a signal trap can run while a
  # bounded call has stdout or stderr redirected, and the reason must not be lost.
  echo "[scenter-engine] ERROR during '$PHASE': $reason" >&4
  echo 'SCENTER_ENGINE_STATUS=ERROR' >&3
  cleanup_temp
  write_failure_report "$PHASE: $reason" || true
  release_lock
  exit 2
}

on_signal() {
  fail "interrupted by signal $1 (build aborted or agent stopping); the installed engine was not modified by this phase unless it was installing"
}

# The build log as it was at startup (3: stdout, 4: stderr), for fail.
exec 3>&1 4>&2

trap 'fail "unexpected bootstrap error (line $LINENO)"' ERR
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP
trap 'cleanup_temp; release_lock' EXIT

# Runs "$@" for at most $1 seconds when the timeout command exists; exit 124 or
# 137 means the limit was hit. The command runs in the background and is waited
# for, so an abort (TERM/INT) interrupts the wait at once instead of being
# deferred until a hanging download or install ends.
run_bounded() {
  local limit="$1" status=0
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 10 "$limit" "$@" 3>&- 4>&- &
  else
    "$@" 3>&- 4>&- &
  fi
  CHILD_PID=$!
  wait "$CHILD_PID" || status=$?
  CHILD_PID=''
  return "$status"
}

is_timeout_status() {
  [ "$1" = 124 ] || [ "$1" = 137 ] || [ "$1" = 143 ]
}

check_bounds() {
  local name value
  for name in LOCK_TIMEOUT LOCK_STALE_AFTER LOCK_OWNER_GRACE CONNECT_TIMEOUT MANIFEST_TIMEOUT DOWNLOAD_TIMEOUT INSTALL_TIMEOUT VERIFY_TIMEOUT; do
    value="${!name}"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ]; then
      fail "invalid SCENTER_BOOTSTRAP_$name value '$value' (expected a number of seconds)"
    fi
  done
  if ! command -v timeout >/dev/null 2>&1; then
    log 'note: the timeout command is not available; downloads stay bounded by curl, npm install and the CLI check are bounded only by the Jenkins stage'
  fi
}

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

resolve_toolchain() {
  local candidate
  phase 'resolving Node.js and npm'
  NODE_BIN="${SCENTER_NODE:-}"
  if [ -z "$NODE_BIN" ]; then
    for candidate in "$NODE_HOME/bin/node" "$NODE_HOME/node"; do
      if [ -x "$candidate" ]; then NODE_BIN="$candidate"; break; fi
    done
  fi
  [ -n "$NODE_BIN" ] || fail "Node.js not found in $NODE_HOME (one-time Jenkins prerequisite: install Node.js 22 there)"
  NODE_VERSION="$(run_bounded "$VERIFY_TIMEOUT" "$NODE_BIN" --version 2>/dev/null)" || fail "Node.js at $NODE_BIN does not run"
  NPM_BIN="${SCENTER_NPM:-}"
  if [ -z "$NPM_BIN" ]; then
    for candidate in "$NODE_HOME/bin/npm" "$NODE_HOME/npm"; do
      if [ -x "$candidate" ]; then NPM_BIN="$candidate"; break; fi
    done
  fi
  [ -n "$NPM_BIN" ] || fail "npm not found next to Node.js in $NODE_HOME"
  PATH="$(dirname "$NODE_BIN"):$PATH"
  export PATH
  NPM_VERSION="$(npm_config_update_notifier=false run_bounded "$VERIFY_TIMEOUT" "$NPM_BIN" --version 2>/dev/null)" || fail "npm at $NPM_BIN does not run"
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

# Why the owner record $1 of the existing install lock is abandoned, or nothing
# when it may still belong to a running bootstrap.
lock_stale_reason() {
  local pid host started now age mtime probe
  [ -n "$1" ] || return 0
  pid="$(owner_field "$1" pid)"
  host="$(owner_field "$1" host)"
  started="$(owner_field "$1" started)"
  now="$(date +%s)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$host" = "$(current_host)" ]; then
    if ! kill -0 "$pid" 2>/dev/null; then
      probe="$(kill -0 "$pid" 2>&1 || true)"
      case "$probe" in
        *ermitted*) ;;
        *) printf 'its owner process %s on %s is no longer running' "$pid" "$host"; return 0 ;;
      esac
    fi
  fi
  if [[ "$started" =~ ^[0-9]+$ ]]; then
    age=$((now - started))
  else
    mtime="$(stat -c %Y "$LOCK_OWNER_FILE" 2>/dev/null || stat -f %m "$LOCK_OWNER_FILE" 2>/dev/null || true)"
    if [[ "$mtime" =~ ^[0-9]+$ ]]; then age=$((now - mtime)); else age=''; fi
  fi
  if [ -n "$age" ] && [ "$age" -ge "$LOCK_STALE_AFTER" ]; then
    printf 'it is %ss old (abandoned after %ss)' "$age" "$LOCK_STALE_AFTER"
  fi
  return 0
}

lock_holder() {
  local pid host build
  pid="$(lock_owner_field pid)"
  host="$(lock_owner_field host)"
  build="$(lock_owner_field build)"
  if [ -n "$pid" ]; then
    printf 'pid %s on %s, build %s' "$pid" "${host:-unknown host}" "${build:-unknown}"
  else
    printf 'no owner record (lock left by an older bootstrap or a killed process)'
  fi
}

# One attempt to take the lock. The owner record ($1) is written beforehand, then
# the directory is created and the record hard-linked into it: a link never
# replaces an existing file, so exactly one bootstrap owns the lock even when
# several recover the same abandoned directory at once. Ownership is confirmed
# by reading the record back.
try_lock() {
  mkdir "$LOCK_DIR" 2>/dev/null || return 1
  if ! ln "$1" "$LOCK_OWNER_FILE" 2>/dev/null; then
    # Filesystems without hard links: a no-clobber rename, confirmed below.
    if [ -d "$LOCK_DIR" ] && [ ! -e "$LOCK_OWNER_FILE" ]; then mv -n "$1" "$LOCK_OWNER_FILE" 2>/dev/null || true; fi
  fi
  [ "$(lock_owner_field pid)" = "$$" ]
}

# A lock directory without owner record: a bootstrap between its mkdir and its
# owner link (milliseconds), or one killed there, or an older bootstrap. It is
# abandoned when the record is still missing after the grace period. rmdir only
# removes an empty directory: once any owner record exists, it is kept.
recover_ownerless_lock() {
  local contents
  log "found lock without owner; waiting ${LOCK_OWNER_GRACE}s grace period"
  sleep "$LOCK_OWNER_GRACE"
  LOCK_WAITED=$((LOCK_WAITED + LOCK_OWNER_GRACE))
  if [ ! -d "$LOCK_DIR" ] || [ -e "$LOCK_OWNER_FILE" ]; then return 0; fi
  log 'owner still missing; recovering abandoned lock'
  if rmdir "$LOCK_DIR" 2>/dev/null; then return 0; fi
  # Another bootstrap recovered it first, recreated it, or linked its owner: retry.
  contents="$(ls -A "$LOCK_DIR" 2>/dev/null || true)"
  if [ -z "$contents" ] || [ "$contents" = owner ] || [ -e "$LOCK_OWNER_FILE" ]; then return 0; fi
  log "cannot recover $LOCK_DIR automatically: it contains unexpected files"
  OWNERLESS_RECOVERY=0
  return 1
}

# Removes the owner record judged abandoned ($1) only if it is still that record:
# it is renamed away first (atomic) and put back when another bootstrap took the
# lock in the meantime.
remove_abandoned_owner() {
  local moved="$PACKAGES/.bootstrap.abandoned-$$"
  mv "$LOCK_OWNER_FILE" "$moved" 2>/dev/null || return 1
  if [ "$({ tr -cd 'A-Za-z0-9=._: -' < "$moved"; } 2>/dev/null || true)" != "$1" ]; then
    ln "$moved" "$LOCK_OWNER_FILE" 2>/dev/null || true
    rm -f "$moved"
    return 1
  fi
  rm -f "$moved"
  rmdir "$LOCK_DIR" 2>/dev/null || true
  return 0
}

acquire_lock() {
  local next_report=0 reason record host build owner_record
  phase "acquiring install lock ($LOCK_DIR, timeout ${LOCK_TIMEOUT}s)"
  mkdir -p "$PACKAGES" "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX and $PACKAGES"
  LOCK_WAITED=0
  OWNERLESS_RECOVERY=1
  host="$(current_host)"
  build="$(printf '%s' "${BUILD_TAG:-manual}" | tr -cd 'A-Za-z0-9._-' | cut -c1-120)"
  owner_record="$PACKAGES/.bootstrap.owner-$$"
  track_temp "$owner_record"
  while :; do
    printf 'pid=%s host=%s started=%s build=%s' "$$" "$host" "$(date +%s)" "$build" > "$owner_record"
    if try_lock "$owner_record"; then break; fi
    if [ -d "$LOCK_DIR" ] && [ ! -e "$LOCK_OWNER_FILE" ]; then
      if [ "$OWNERLESS_RECOVERY" = 1 ] && recover_ownerless_lock; then continue; fi
    elif [ -d "$LOCK_DIR" ]; then
      record="$(lock_owner_record)"
      reason="$(lock_stale_reason "$record")"
      if [ -n "$reason" ]; then
        log "removing abandoned install lock: $reason"
        if remove_abandoned_owner "$record"; then continue; fi
      fi
    fi
    if [ "$LOCK_WAITED" -ge "$LOCK_TIMEOUT" ]; then
      fail "install lock still held after ${LOCK_TIMEOUT}s: $LOCK_DIR ($(lock_holder)). If no Security Center build is running, remove that directory."
    fi
    if [ "$LOCK_WAITED" -ge "$next_report" ]; then
      log "waiting for install lock held by $(lock_holder) (${LOCK_WAITED}s of ${LOCK_TIMEOUT}s)"
      next_report=$((LOCK_WAITED + 10))
    fi
    sleep 1
    LOCK_WAITED=$((LOCK_WAITED + 1))
  done
  rm -f "$owner_record"
  LOCK_HELD=1
  log 'install lock acquired'
}

# Downloads $1 to $2 within $4 seconds (connection, redirects, retries and
# transfer included). With $3=yes and a token configured, the token travels in a
# private header file, never on the command line or in the log. On failure,
# DOWNLOAD_ERROR explains what happened, without the URL.
download() {
  local url="$1" destination="$2" with_token="${3:-no}" limit="$4" label="$5" header_file='' status=0
  local -a arguments
  rm -f "$destination"
  track_temp "$destination"
  DOWNLOAD_ERROR=''
  if command -v curl >/dev/null 2>&1; then
    arguments=(-fsSL --max-redirs 10 --proto '=https,http,file' --proto-redir '=https,http' --connect-timeout "$CONNECT_TIMEOUT" --max-time "$limit" --retry 2 --retry-delay 2 --retry-max-time "$limit" -o "$destination")
    if [ "$with_token" = yes ] && [ -n "$DOWNLOAD_TOKEN" ]; then
      header_file="$PACKAGES/.auth-$$.header"
      track_temp "$header_file"
      ( umask 077; printf 'Authorization: Bearer %s' "$DOWNLOAD_TOKEN" > "$header_file" )
      arguments+=(-H "@$header_file")
    fi
    run_bounded "$((limit + 15))" curl "${arguments[@]}" "$url" 2>/dev/null || status=$?
    if [ -n "$header_file" ]; then rm -f "$header_file"; fi
    case "$status" in
      0) return 0 ;;
      28|124|137|143) DOWNLOAD_ERROR="$label timed out after ${limit}s" ;;
      5|6) DOWNLOAD_ERROR="$label failed: host could not be resolved" ;;
      7) DOWNLOAD_ERROR="$label failed: connection refused or host unreachable" ;;
      22) DOWNLOAD_ERROR="$label failed: the server answered with an HTTP error" ;;
      47) DOWNLOAD_ERROR="$label failed: too many redirects" ;;
      35|51|58|60) DOWNLOAD_ERROR="$label failed: TLS error (curl exit $status)" ;;
      *) DOWNLOAD_ERROR="$label failed (curl exit $status)" ;;
    esac
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    if [ "$with_token" = yes ] && [ -n "$DOWNLOAD_TOKEN" ]; then
      run_bounded "$limit" wget -q --tries=2 --timeout="$CONNECT_TIMEOUT" --max-redirect=10 --header="Authorization: Bearer $DOWNLOAD_TOKEN" -O "$destination" "$url" || status=$?
    else
      run_bounded "$limit" wget -q --tries=2 --timeout="$CONNECT_TIMEOUT" --max-redirect=10 -O "$destination" "$url" || status=$?
    fi
    if [ "$status" = 0 ]; then return 0; fi
    if is_timeout_status "$status"; then DOWNLOAD_ERROR="$label timed out after ${limit}s"; else DOWNLOAD_ERROR="$label failed (wget exit $status)"; fi
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
    phase 'reading direct engine configuration (SCENTER_ENGINE_TGZ_URL, SCENTER_ENGINE_SHA256)'
    EXPECTED_SHA="$(printf '%s' "${SCENTER_ENGINE_SHA256:-}" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    [[ "$EXPECTED_SHA" =~ ^[0-9a-f]{64}$ ]] || fail 'SCENTER_ENGINE_SHA256 is not configured on Jenkins, and no SCENTER_ENGINE_MANIFEST_URL is set (one of them is required)'
    return 0
  fi
  ENGINE_SOURCE='manifest'
  if [ -n "${SCENTER_ENGINE_TGZ_URL:-}${SCENTER_ENGINE_SHA256:-}" ]; then
    log 'SCENTER_ENGINE_MANIFEST_URL is set: the direct SCENTER_ENGINE_TGZ_URL and SCENTER_ENGINE_SHA256 values are ignored'
  fi
  manifest="$PACKAGES/.manifest-latest-$$.json"
  phase "fetching engine manifest ($(safe_url "$MANIFEST_URL"), timeout ${MANIFEST_TIMEOUT}s)"
  if ! download "$MANIFEST_URL" "$manifest" yes "$MANIFEST_TIMEOUT" 'manifest download'; then
    rm -f "$manifest"
    fail "CI Engine manifest unreachable: $(safe_url "$MANIFEST_URL") ($DOWNLOAD_ERROR)"
  fi
  phase 'validating engine manifest'
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
  log "manifest received: $PACKAGE_NAME@$MANIFEST_VERSION, commit $BUILD_COMMIT, built $BUILD_TIMESTAMP"
}

# Runs the installed command's --help within the verify bound.
run_help() {
  run_bounded "$VERIFY_TIMEOUT" "$1" --help 2>&1
}

# The expected build is installed, verified by its recorded SHA-256 and by
# actually running the command.
engine_is_expected() {
  local package_json command help marker_sha
  phase 'checking installed engine'
  [ -f "$MARKER" ] || return 1
  marker_sha="$(json_field "$MARKER" sha256)"
  [ "$marker_sha" = "$EXPECTED_SHA" ] || return 1
  package_json="$(installed_package_json)" || return 1
  command="$(installed_command)" || return 1
  help="$(run_help "$command")" || return 1
  case "$help" in *"$HELP_MARKER"*) ;; *) return 1 ;; esac
  ENGINE_VERSION="$(json_field "$package_json" version)"
  [ "$ENGINE_VERSION" = "$(json_field "$MARKER" version)" ] || return 1
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
  phase "downloading engine package ($source, timeout ${DOWNLOAD_TIMEOUT}s)"
  if ! download "$ENGINE_URL" "$download_file" "$token_mode" "$DOWNLOAD_TIMEOUT" 'engine package download'; then
    rm -f "$download_file"
    fail "download failed from $source ($DOWNLOAD_ERROR)"
  fi
  phase 'verifying SHA-256'
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
  phase 'validating engine package'
  if ! tar -tzf "$package" package/package.json package/src/cli.js >/dev/null 2>&1; then
    fail 'the configured package is not a Security Center CI Engine package'
  fi
  manifest="$PACKAGES/.manifest-$$.json"
  track_temp "$manifest"
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
  track_temp "$entry"
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
  local status=0
  # From here the installed files change: the previous record no longer vouches
  # for them until the new install is verified.
  if [ -f "$MARKER" ]; then mv -f "$MARKER" "$MARKER.previous" 2>/dev/null || true; fi
  phase "installing engine ($PACKAGE_NAME@$PACKAGE_VERSION into $PREFIX, timeout ${INSTALL_TIMEOUT}s)"
  npm_config_update_notifier=false run_bounded "$INSTALL_TIMEOUT" "$NPM_BIN" install --global --prefix "$PREFIX" "$CACHED_PACKAGE" --offline --no-audit --no-fund --loglevel=error >/dev/null || status=$?
  if is_timeout_status "$status"; then
    fail "npm install of the CI Engine timed out after ${INSTALL_TIMEOUT}s"
  fi
  if [ "$status" != 0 ]; then
    fail "npm install of the CI Engine failed (exit $status)"
  fi
}

verify_install() {
  local package_json command help status=0
  phase 'verifying installed CLI'
  package_json="$(installed_package_json)" || fail "installed package not found under $PREFIX after npm install"
  command="$(installed_command)" || fail "security-center command not created under $PREFIX"
  help="$(run_help "$command")" || status=$?
  if is_timeout_status "$status"; then fail "security-center --help timed out after ${VERIFY_TIMEOUT}s"; fi
  [ "$status" = 0 ] || fail 'security-center --help failed after install'
  case "$help" in *"$HELP_MARKER"*) ;; *) fail 'security-center --help did not print the Security Center help' ;; esac
  ENGINE_VERSION="$(json_field "$package_json" version)"
  [ "$ENGINE_VERSION" = "$PACKAGE_VERSION" ] || fail "installed version $ENGINE_VERSION differs from the package version $PACKAGE_VERSION"
  ENGINE_COMMAND="$command"
}

write_marker() {
  local previous="$1" temporary="$MARKER.tmp.$$" source
  phase 'recording installed engine'
  if [ "$ENGINE_SOURCE" = manifest ]; then source="$(safe_url "$MANIFEST_URL")"; else source="$(safe_url "$ENGINE_URL")"; fi
  track_temp "$temporary"
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
  rm -f "$MARKER.previous" 2>/dev/null || true
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

# How to fix a directory that cannot be used, by where its path came from.
path_hint() {
  local user="$1" origin="$2"
  if [ "$origin" = default ]; then
    printf 'default Security Center home; JENKINS_HOME must be writable by user %s, or set SCENTER_HOME to a directory it owns' "$user"
  else
    printf 'configured by %s; give user %s write access to it, or unset %s to use the default %s' "$origin" "$user" "$origin" "${JENKINS_HOME:-/var/jenkins_home}/.security-center"
  fi
}

# Creates a directory as the Jenkins process and proves it is writable. Never
# changes ownership or permissions: an unusable path is reported, not repaired.
ensure_writable_dir() {
  local dir="$1" origin="$2" user probe
  user="$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")"
  if ! mkdir -p "$dir" 2>/dev/null || [ ! -d "$dir" ]; then
    fail "$dir cannot be created by user $user ($(path_hint "$user" "$origin"))"
  fi
  probe="$dir/.scenter-write-test-$$"
  if ! { : > "$probe"; } 2>/dev/null; then
    fail "$dir is not writable by user $user ($(path_hint "$user" "$origin"))"
  fi
  rm -f "$probe"
}

prepare_directories() {
  local sub user
  # Short phase: the failing path is in the reason, and the CI report keeps
  # only the first 300 characters of the error.
  phase 'preparing Security Center home'
  log "Security Center home: engine $PREFIX, packages $PACKAGES"
  ensure_writable_dir "$PACKAGES" "$PACKAGES_ORIGIN"
  ensure_writable_dir "$PREFIX" "$PREFIX_ORIGIN"
  # An existing engine tree must stay writable too, or npm install fails later.
  for sub in bin lib lib/node_modules; do
    if [ -d "$PREFIX/$sub" ] && [ ! -w "$PREFIX/$sub" ]; then
      user="$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")"
      fail "$PREFIX/$sub is not writable by user $user ($(path_hint "$user" "$PREFIX_ORIGIN"))"
    fi
  done
}

main() {
  local previous='' action='installed'
  check_bounds
  resolve_toolchain
  log "node $NODE_VERSION, npm $NPM_VERSION"
  prepare_directories
  acquire_lock
  resolve_expected_build
  if engine_is_expected; then
    log "CI Engine $ENGINE_VERSION already installed with the expected build: nothing to do"
    emit unchanged
    release_lock
    return 0
  fi
  for previous in "$MARKER" "$MARKER.previous"; do
    if [ -f "$previous" ]; then
      previous="$(json_field "$previous" sha256)"
      break
    fi
    previous=''
  done
  [[ "$previous" =~ ^[0-9a-f]{64}$ ]] || previous=''
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
