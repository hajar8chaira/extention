'use strict';

/**
 * The SIEM catalogue.
 *
 * Runtime Security is a multi-SIEM domain, so the product surface lists the
 * enterprise platforms it is built to integrate. This file holds their
 * *identity* and nothing else: no configuration schema, no capabilities, no
 * endpoints, no authentication, no behaviour.
 *
 * Four separate facts, deliberately never conflated:
 *
 *   CATALOGUE PRESENCE  — the product intends to integrate this platform (here)
 *   ADAPTER EXISTS      — code can actually talk to it            (`siem.js`)
 *   CONFIGURED          — this workspace supplied its connection  (settings)
 *   CAPABILITY RESOLVED — a probe proved what it can serve        (runtime)
 *
 * An earlier version of this file declared configuration fields and
 * capabilities for platforms with no adapter. Those declarations were written
 * from memory rather than from each vendor's API, and several were wrong. A
 * schema is a claim about someone else's product; making it without having
 * implemented against that product is how a catalogue starts lying. Each entry
 * regains its schema when, and only when, its adapter is written against the
 * real API — exactly as the Wazuh entry did.
 */

const SIEM_CATALOGUE = Object.freeze([
  {
    id: 'wazuh',
    label: 'Wazuh',
    icon: 'wazuh.svg',
    summary: 'Open-source XDR and SIEM platform.',
    docsHint: 'Manager API credentials with read access.'
    // Configuration and capabilities come from the implemented adapter.
  },
  { id: 'splunk', label: 'Splunk Enterprise Security', icon: 'splunk.svg', summary: 'Splunk ES notable events and risk analysis.' },
  { id: 'sentinel', label: 'Microsoft Sentinel', icon: 'sentinel.svg', summary: 'Azure-native SIEM and SOAR.' },
  { id: 'elastic', label: 'Elastic Security', icon: 'elastic.svg', summary: 'Elastic SIEM detections and endpoint data.' },
  { id: 'qradar', label: 'IBM QRadar', icon: 'qradar.svg', summary: 'QRadar offenses and event correlation.' },
  { id: 'chronicle', label: 'Google Security Operations', icon: 'chronicle.svg', summary: 'Google SecOps detections and entity context.' },
  { id: 'graylog', label: 'Graylog', icon: 'graylog.svg', summary: 'Graylog log management and alerting.' },
  { id: 'arcsight', label: 'ArcSight', icon: 'arcsight.svg', summary: 'ArcSight ESM correlation and events.' },
  { id: 'sumologic', label: 'Sumo Logic Cloud SIEM', icon: 'sumologic.svg', summary: 'Sumo Logic Cloud SIEM insights and signals.' }
]);

function catalogueEntry(id) {
  return SIEM_CATALOGUE.find((entry) => entry.id === String(id || '').toLowerCase()) || null;
}

module.exports = { SIEM_CATALOGUE, catalogueEntry };
