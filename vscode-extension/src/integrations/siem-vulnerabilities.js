'use strict';

/**
 * Runtime vulnerabilities, in Security Center's vocabulary.
 *
 * This layer is provider-neutral on purpose. It knows that *a* provider
 * supplied a field map — logical key → document path — and how to turn matching
 * documents into records the UI can render. It does not know what a Wazuh
 * Indexer is, what an OpenSearch aggregation looks like, or that agents have
 * numeric ids. Those live below the adapter boundary, so a future Splunk or
 * Sentinel adapter can reach this same shape by an entirely different route.
 *
 * The vocabulary deliberately matches the existing finding model where the
 * meaning is the same (`cve`, `cvssScore`, `severity`, `package`,
 * `packageVersion`, `description`) and adds only the runtime context a
 * development-time finding has no reason to carry. Nothing is forced through
 * `unifiedFinding()`: a package installed on a running host has no file, no
 * line and no repository, and inventing them to satisfy a shape would be a lie
 * that later correlation would have to unpick.
 *
 * One rule governs everything below: a field the provider did not supply is
 * absent. Not `0`, not `'Unknown'`, not derived from a neighbouring field.
 */

const { normalizeSeverity } = require('./siem-contract');

/** Display order for severity, whatever a provider calls its own levels. */
const SEVERITY_ORDER = Object.freeze(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

/**
 * The logical keys a record may carry, mapped to how they are read.
 *
 * `numeric` fields are only accepted when they really parse as a number, which
 * is what stops a missing CVSS score from becoming zero.
 */
const RECORD_FIELDS = Object.freeze([
  { key: 'cve', field: 'cve' },
  { key: 'severity', field: 'severity' },
  { key: 'cvssScore', field: 'cvssScore', numeric: true },
  { key: 'cvssVersion', field: 'cvssVersion' },
  { key: 'description', field: 'description' },
  { key: 'package', field: 'packageName' },
  { key: 'packageVersion', field: 'packageVersion' },
  { key: 'packageArchitecture', field: 'packageArchitecture' },
  { key: 'packageType', field: 'packageType' },
  { key: 'packageCondition', field: 'packageCondition' },
  { key: 'asset', field: 'assetName' },
  { key: 'agentId', field: 'assetId' },
  { key: 'agentIp', field: 'assetIp' },
  { key: 'osName', field: 'osName' },
  { key: 'osVersion', field: 'osVersion' },
  { key: 'osFull', field: 'osFull' },
  { key: 'detectedAt', field: 'detectedAt' },
  { key: 'publishedAt', field: 'publishedAt' },
  { key: 'underEvaluation', field: 'underEvaluation', boolean: true },
  { key: 'category', field: 'category' },
  { key: 'references', field: 'references', list: true }
]);

/** Reads `a.b.c` out of a document without throwing on a missing branch. */
function readPath(source, path) {
  if (!source || !path) return undefined;
  return String(path).split('.').reduce((value, segment) => (
    value === null || value === undefined ? undefined : value[segment]
  ), source);
}

function presentText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return '';
  return String(value).trim();
}

/**
 * One vulnerability record.
 *
 * Every key is conditional. `fieldMap` decides what can even be attempted, and
 * the document decides what is actually there — so the same code produces a
 * rich record on a deployment that fills every field and a minimal one on a
 * deployment that fills three, without either being wrong.
 */
function normalizeVulnerabilityRecord(source = {}, fieldMap = {}, { provider = '', providerFindingId = '' } = {}) {
  const record = {};
  for (const definition of RECORD_FIELDS) {
    const field = fieldMap[definition.field];
    if (!field) continue;
    const raw = readPath(source, field.path);
    if (raw === undefined || raw === null) continue;

    if (definition.list) {
      const values = (Array.isArray(raw) ? raw : [raw]).map(presentText).filter(Boolean);
      if (values.length) record[definition.key] = values;
      continue;
    }
    if (definition.numeric) {
      const numeric = Number(raw);
      // A score that is absent, empty or unparseable is absent. Never 0.
      if (!Number.isFinite(numeric) || presentText(raw) === '') continue;
      record[definition.key] = numeric;
      continue;
    }
    if (definition.boolean) {
      if (typeof raw !== 'boolean') continue;
      record[definition.key] = raw;
      continue;
    }
    const text = presentText(raw);
    if (text) record[definition.key] = text;
  }

  // Composed only from values that exist; never a placeholder.
  const os = record.osFull || [record.osName, record.osVersion].filter(Boolean).join(' ');
  if (os) record.os = os;
  // A title is the identifier the provider gave, not a sentence written here.
  if (record.cve) record.title = record.cve;
  if (record.severity) record.uiSeverity = normalizeSeverity(record.severity, 'INFO');
  if (provider) record.provider = String(provider);
  if (providerFindingId) record.providerFindingId = String(providerFindingId);
  return record;
}

/** A stable key for one record, preferring the provider's own document id. */
function vulnerabilityKey(record = {}, index = 0) {
  return String(record.providerFindingId
    || [record.cve, record.agentId || record.asset, record.package].filter(Boolean).join('|')
    || `vulnerability:${index}`);
}

/**
 * The query, always complete and always in range.
 *
 * The caller is a webview, so nothing it sends is trusted: page numbers,
 * page sizes and free text are all clamped before they reach a provider.
 */
function normalizeVulnerabilityQuery(query = {}, { defaultPageSize = 10, maxPageSize = 50 } = {}) {
  const text = (value) => String(value ?? '').trim();
  const page = Number.parseInt(query.page, 10);
  const pageSize = Number.parseInt(query.pageSize, 10);
  return {
    search: text(query.search),
    severity: text(query.severity),
    asset: text(query.asset),
    cve: text(query.cve),
    package: text(query.package),
    page: Number.isFinite(page) && page > 0 ? page : 1,
    pageSize: Number.isFinite(pageSize) && pageSize > 0 ? Math.min(pageSize, maxPageSize) : defaultPageSize,
    vulnerability: text(query.vulnerability)
  };
}

function isVulnerabilityFiltered(query = {}) {
  const normalized = normalizeVulnerabilityQuery(query);
  return Boolean(normalized.search || normalized.severity || normalized.asset || normalized.cve || normalized.package);
}

/**
 * Severity counts for the summary cards.
 *
 * `null` when the provider could not supply a distribution at all — the cards
 * must then say nothing rather than show four zeros.
 */
function severityCounts(buckets) {
  if (!Array.isArray(buckets)) return null;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const bucket of buckets) {
    const level = normalizeSeverity(bucket?.value, 'INFO');
    counts[level] = (counts[level] || 0) + (Number(bucket?.count) || 0);
  }
  return counts;
}

/**
 * The investigation layout: sections of label/value pairs, built only from
 * what the record actually carries. An empty section disappears entirely.
 */
function vulnerabilityDetailSections(record = {}) {
  const rows = (entries) => entries
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([label, value]) => ({ label, value: Array.isArray(value) ? value.join(', ') : String(value) }));

  const sections = [
    {
      title: 'Vulnerability',
      fields: rows([
        ['CVE', record.cve],
        ['Severity', record.severity],
        ['CVSS score', Number.isFinite(record.cvssScore) ? String(record.cvssScore) : ''],
        ['CVSS version', record.cvssVersion],
        ['Category', record.category],
        ['Under evaluation', typeof record.underEvaluation === 'boolean' ? (record.underEvaluation ? 'Yes' : 'No') : '']
      ])
    },
    {
      title: 'Affected component',
      fields: rows([
        ['Package', record.package],
        ['Installed version', record.packageVersion],
        ['Architecture', record.packageArchitecture],
        ['Package type', record.packageType],
        // The provider's own wording, kept verbatim. It is not re-read as a
        // fixed version: a condition and a fixed version are not the same claim.
        ['Package condition', record.packageCondition]
      ])
    },
    {
      title: 'Asset',
      fields: rows([
        ['Asset', record.asset],
        ['Agent ID', record.agentId],
        ['Agent IP', record.agentIp],
        ['Operating system', record.os]
      ])
    },
    {
      title: 'Timeline',
      fields: rows([
        ['Detected at', record.detectedAt],
        ['Published at', record.publishedAt]
      ])
    },
    {
      title: 'Provider',
      fields: rows([
        ['Provider', record.provider],
        ['Provider reference', record.providerFindingId]
      ])
    }
  ];
  return sections.filter((section) => section.fields.length);
}

module.exports = {
  SEVERITY_ORDER,
  RECORD_FIELDS,
  readPath,
  normalizeVulnerabilityRecord,
  vulnerabilityKey,
  normalizeVulnerabilityQuery,
  isVulnerabilityFiltered,
  severityCounts,
  vulnerabilityDetailSections
};
