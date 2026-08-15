'use strict';

const CACHE_VERSION = 2;
const CACHE_KEY = 'securityCenter.lastScan.v1';

function normalizeWorkspace(value) {
  return String(value || '').replace(/\//g, '\\').replace(/[\\]+$/, '').toLowerCase();
}

function createLocalScanCache(workspacePath, findings, scanners, dashboardOptions, savedAt = new Date().toISOString(), securitySnapshot = null) {
  return {
    version: CACHE_VERSION,
    workspacePath: String(workspacePath || ''),
    savedAt,
    findings: Array.isArray(findings) ? findings : [],
    scanners: Array.isArray(scanners) ? scanners : [],
    dashboardOptions: dashboardOptions && typeof dashboardOptions === 'object' ? dashboardOptions : {},
    ...(securitySnapshot ? { securitySnapshot } : {})
  };
}

function restoreLocalScanCache(cache, workspacePath) {
  if (!cache || ![1, CACHE_VERSION].includes(cache.version)) return null;
  if (!normalizeWorkspace(cache.workspacePath) || normalizeWorkspace(cache.workspacePath) !== normalizeWorkspace(workspacePath)) return null;
  if (!Array.isArray(cache.findings) || !Array.isArray(cache.scanners)) return null;
  return {
    savedAt: cache.savedAt,
    findings: cache.findings,
    scanners: cache.scanners,
    dashboardOptions: cache.dashboardOptions && typeof cache.dashboardOptions === 'object' ? cache.dashboardOptions : {},
    securitySnapshot: cache.securitySnapshot || null
  };
}

module.exports = { CACHE_KEY, createLocalScanCache, restoreLocalScanCache };
