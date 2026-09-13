'use strict';

/**
 * Host-independent resolution of scanner-reported paths.
 *
 * Node's `path.resolve()` follows the operating system Security Center runs
 * on. A Windows workspace such as `C:\repo` is therefore not absolute on a
 * Linux host, and resolving against it silently prefixed the Linux working
 * directory: `/home/runner/.../C:\repo/package-lock.json`.
 *
 * Only that foreign case changes. A Windows absolute path (drive or UNC) is
 * resolved with Windows semantics on a POSIX host; everything else keeps the
 * host's native resolution, byte for byte.
 */

const path = require('path');

/** `C:\foo`, `C:/foo` — a drive-relative `C:foo` is not absolute. */
const WINDOWS_DRIVE_ABSOLUTE = /^[A-Za-z]:[\\/]/;
/** `\\server\share\...` — a POSIX `//host/x` stays a POSIX path. */
const WINDOWS_UNC = /^\\\\[^\\/]+[\\/]+[^\\/]+/;

function isWindowsAbsolutePath(value) {
  const text = String(value ?? '');
  return WINDOWS_DRIVE_ABSOLUTE.test(text) || WINDOWS_UNC.test(text);
}

function isPosixAbsolutePath(value) {
  return String(value ?? '').startsWith('/');
}

function isAbsoluteScannerPath(value) {
  return isWindowsAbsolutePath(value) || isPosixAbsolutePath(value);
}

/**
 * `path.resolve(base, target)` that never turns a Windows absolute path into a
 * path relative to a POSIX working directory. `platform` is injectable so both
 * host behaviours are testable on either system.
 */
function resolveScannerPath(base, target, { platform = process.platform } = {}) {
  const baseText = String(base ?? '');
  const targetText = String(target ?? '');
  if (platform !== 'win32') {
    if (isWindowsAbsolutePath(targetText)) return path.win32.resolve(targetText);
    if (isWindowsAbsolutePath(baseText) && !isPosixAbsolutePath(targetText)) return path.win32.resolve(baseText, targetText);
    return path.posix.resolve(baseText, targetText);
  }
  return path.win32.resolve(baseText, targetText);
}

module.exports = { isWindowsAbsolutePath, isPosixAbsolutePath, isAbsoluteScannerPath, resolveScannerPath };
