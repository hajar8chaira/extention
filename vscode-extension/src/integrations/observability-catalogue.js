'use strict';

/**
 * The observability catalogue.
 *
 * Infrastructure is a domain with an adapter slot, so the product surface lists
 * the metrics backends it is built to integrate. This file holds their
 * *identity* and nothing else: no configuration schema, no capabilities, no
 * endpoints, no authentication, no query language.
 *
 * Four separate facts, deliberately never conflated:
 *
 *   CATALOGUE PRESENCE  — the product intends to integrate this backend (here)
 *   ADAPTER EXISTS      — code can actually query it        (`observability.js`)
 *   CONFIGURED          — this workspace supplied a connection    (settings)
 *   CAPABILITY RESOLVED — a probe proved what it can serve         (runtime)
 *
 * Declaring a schema for a backend nobody has implemented against is a claim
 * about another vendor's product. Each entry gains its schema when, and only
 * when, its adapter is written against the real API.
 *
 * Grafana is deliberately absent: it is a visualization layer over other data
 * sources, not a metrics backend. Listing it would promise a reading capability
 * no adapter could have.
 */

const OBSERVABILITY_CATALOGUE = Object.freeze([
  {
    id: 'prometheus',
    label: 'Prometheus',
    icon: 'prometheus.svg',
    summary: 'Prometheus HTTP API and exporter metrics.'
    // Configuration and capabilities come from the implemented adapter.
  },
  { id: 'zabbix', label: 'Zabbix', icon: 'zabbix.svg', summary: 'Zabbix host monitoring and problems.' },
  { id: 'datadog', label: 'Datadog', icon: 'datadog.svg', summary: 'Datadog infrastructure metrics.' },
  { id: 'newrelic', label: 'New Relic', icon: 'newrelic.svg', summary: 'New Relic host telemetry.' },
  { id: 'influxdb', label: 'InfluxDB / Telegraf', icon: 'influxdb.svg', summary: 'InfluxDB time-series metrics.' },
  { id: 'opentelemetry', label: 'OpenTelemetry', icon: 'opentelemetry.svg', summary: 'OpenTelemetry-compatible metrics backend.' }
]);

function observabilityCatalogueEntry(id) {
  return OBSERVABILITY_CATALOGUE.find((entry) => entry.id === String(id || '').toLowerCase()) || null;
}

module.exports = { OBSERVABILITY_CATALOGUE, observabilityCatalogueEntry };
