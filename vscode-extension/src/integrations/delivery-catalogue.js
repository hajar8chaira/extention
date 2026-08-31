'use strict';

/**
 * The CI/CD delivery catalogue.
 *
 * Security Delivery is a domain with an adapter slot, exactly like Runtime
 * Security and Infrastructure. This file holds provider *identity* and nothing
 * else: no configuration schema, no capabilities, no endpoints, no
 * authentication.
 *
 * Four separate facts, never conflated:
 *
 *   CATALOGUE PRESENCE  — the product intends to integrate this platform (here)
 *   ADAPTER EXISTS      — code can actually query it            (`delivery.js`)
 *   CONFIGURED          — this workspace supplied a connection      (settings)
 *   CAPABILITY RESOLVED — a call proved what it can serve            (runtime)
 *
 * Declaring a schema for a platform nobody has implemented against is a claim
 * about another vendor's product. Each entry gains its schema when, and only
 * when, its adapter is written against the real API.
 */

const DELIVERY_CATALOGUE = Object.freeze([
  {
    id: 'jenkins',
    label: 'Jenkins',
    icon: 'jenkins.svg',
    summary: 'Jenkins jobs, builds and archived security reports.'
    // Configuration and capabilities come from the implemented adapter.
  },
  { id: 'gitlab-ci', label: 'GitLab CI/CD', icon: 'gitlab.svg', summary: 'GitLab pipelines, jobs and artefacts.' },
  { id: 'github-actions', label: 'GitHub Actions', icon: 'github.svg', summary: 'GitHub Actions workflow runs and artefacts.' },
  { id: 'azure-pipelines', label: 'Azure DevOps Pipelines', icon: 'azure-devops.svg', summary: 'Azure Pipelines runs and published artefacts.' },
  { id: 'circleci', label: 'CircleCI', icon: 'circleci.svg', summary: 'CircleCI workflows and job artefacts.' },
  { id: 'bitbucket-pipelines', label: 'Bitbucket Pipelines', icon: 'bitbucket.svg', summary: 'Bitbucket Pipelines runs and artefacts.' }
]);

function deliveryCatalogueEntry(id) {
  return DELIVERY_CATALOGUE.find((entry) => entry.id === String(id || '').toLowerCase()) || null;
}

module.exports = { DELIVERY_CATALOGUE, deliveryCatalogueEntry };
