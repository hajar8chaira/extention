'use strict';

/**
 * The GitHub Actions delivery adapter.
 *
 * Every GitHub-specific fact lives here: the `/repos/:owner/:repo` endpoints,
 * the bearer scheme, the API version header, the split between a run's `status`
 * and its `conclusion`, and the rate-limit headers. Nothing above this file
 * knows that GitHub exists.
 *
 * GitHub is the provider where « not finished » and « failed » are two
 * different fields: a run in progress has no conclusion at all. Reading the
 * conclusion alone would report every running workflow as a failure, so the
 * mapping reads the status first and the conclusion only once the run is
 * complete.
 */

const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, RUN_OUTCOME,
  SECTION_KIND, FIELD_TYPE, CONFIG_GROUP,
  buildDeliveryModel, notReportedCapability, readyCapability, validateAgainstFields
} = require('./delivery-contract');
const {
  normalizeDeliveryBaseUrl, deliveryUrl, deliveryGetJson, durationBetween
} = require('./delivery-http');

const ID = 'github-actions';
const LABEL = 'GitHub Actions';
const ICON = 'github.svg';
const DEFAULT_API_URL = 'https://api.github.com';
/** GitHub requires a user agent and pins its REST contract by version. */
const API_VERSION = '2022-11-28';
const USER_AGENT = 'security-center-vscode';

const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'owner',
    type: FIELD_TYPE.TEXT,
    label: 'Propriétaire',
    placeholder: 'organisation ou utilisateur',
    required: true,
    hint: 'Organisation ou compte propriétaire du dépôt.'
  },
  {
    id: 'repository',
    type: FIELD_TYPE.TEXT,
    label: 'Dépôt',
    placeholder: 'mon-depot',
    required: true,
    hint: 'Nom du dépôt, sans le propriétaire.'
  },
  {
    id: 'workflow',
    type: FIELD_TYPE.TEXT,
    label: 'Workflow',
    group: CONFIG_GROUP.ADVANCED,
    placeholder: 'security.yml',
    hint: 'Optionnel. Nom de fichier ou identifiant du workflow. Sans valeur, Security Center lit la dernière exécution tous workflows confondus.'
  },
  {
    id: 'url',
    type: FIELD_TYPE.URL,
    label: 'URL de l’API',
    group: CONFIG_GROUP.ADVANCED,
    placeholder: DEFAULT_API_URL,
    default: DEFAULT_API_URL,
    hint: 'Laissez la valeur par défaut pour github.com. Pour GitHub Enterprise Server, utilisez https://votre-instance/api/v3.'
  },
  {
    id: 'token',
    type: FIELD_TYPE.PASSWORD,
    label: 'Jeton d’accès',
    group: CONFIG_GROUP.ADVANCED,
    secret: true,
    hint: 'Jeton avec la portée actions:read (dépôt privé) ou public_repo. Conservé par le SecretStorage de VS Code et transmis en en-tête Authorization.'
  }
]);

const CAPABILITIES = Object.freeze({
  [CAPABILITY.PIPELINE_STATUS]: DECLARED_STATE.READY,
  [CAPABILITY.LAST_RUN]: DECLARED_STATE.READY,
  [CAPABILITY.STAGES]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.ARTIFACTS]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.DEPLOYMENT_STATUS]: DECLARED_STATE.REQUIRES_PROBE
});

const SECTIONS = Object.freeze([
  { kind: SECTION_KIND.CONNECTION, title: 'Connexion' },
  { kind: SECTION_KIND.RUN_SUMMARY, title: 'Dernière exécution' },
  { kind: SECTION_KIND.STAGE_LIST, title: 'Jobs' },
  { kind: SECTION_KIND.ARTIFACT_LIST, title: 'Artefacts' }
]);

/** A run that has not completed has no conclusion: its status is the answer. */
const OUTCOME_BY_STATUS = Object.freeze({
  queued: RUN_OUTCOME.RUNNING,
  in_progress: RUN_OUTCOME.RUNNING,
  waiting: RUN_OUTCOME.RUNNING,
  requested: RUN_OUTCOME.RUNNING,
  pending: RUN_OUTCOME.RUNNING
});

/** Conclusions of a completed run. */
const OUTCOME_BY_CONCLUSION = Object.freeze({
  success: RUN_OUTCOME.SUCCESS,
  failure: RUN_OUTCOME.FAILED,
  timed_out: RUN_OUTCOME.FAILED,
  startup_failure: RUN_OUTCOME.FAILED,
  cancelled: RUN_OUTCOME.ABORTED,
  action_required: RUN_OUTCOME.UNSTABLE,
  neutral: RUN_OUTCOME.UNSTABLE,
  skipped: RUN_OUTCOME.NOT_STARTED,
  stale: RUN_OUTCOME.NOT_REPORTED
});

function outcomeFor({ status, conclusion } = {}) {
  const state = String(status || '').toLowerCase();
  if (state && state !== 'completed') return OUTCOME_BY_STATUS[state] || RUN_OUTCOME.RUNNING;
  const result = String(conclusion || '').toLowerCase();
  if (!result) return RUN_OUTCOME.NOT_REPORTED;
  return OUTCOME_BY_CONCLUSION[result] || RUN_OUTCOME.NOT_REPORTED;
}

function segment(value, label) {
  const text = String(value || '').trim().replace(/^\/+|\/+$/g, '');
  if (!text) throw new Error(`Renseignez ${label}.`);
  if (text.includes('/') || text === '..') throw new Error(`${label} invalide.`);
  return encodeURIComponent(text);
}

function headersFor(configuration = {}) {
  const headers = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': API_VERSION,
    'user-agent': USER_AGENT
  };
  const token = String(configuration.token || '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

function apiUrl(configuration = {}) {
  return String(configuration.url || '').trim() || DEFAULT_API_URL;
}

function validateConfiguration(configuration = {}) {
  const { valid, errors } = validateAgainstFields(CONFIGURATION_FIELDS, configuration);
  if (!valid) return { valid: false, errors };
  try {
    normalizeDeliveryBaseUrl(apiUrl(configuration), 'de l’API GitHub');
    segment(configuration.owner, 'le propriétaire');
    segment(configuration.repository, 'le dépôt');
  } catch (error) {
    return { valid: false, errors: [error.message] };
  }
  return { valid: true, errors: [] };
}

/** GitHub signals an exhausted quota with a 403 and a remaining count of zero. */
function isRateLimited(response) {
  const remaining = response?.headers?.['x-ratelimit-remaining'];
  return String(remaining) === '0' || /rate limit/i.test(String(response?.body?.message || ''));
}

function describeStatus(response, { context = 'dépôt' } = {}) {
  const status = response?.status;
  if (status === 401) {
    return { status: PROVIDER_STATUS.AUTH_ERROR, message: 'GitHub a refusé le jeton (HTTP 401). Vérifiez sa validité et sa portée.' };
  }
  if (status === 403 || status === 429) {
    if (isRateLimited(response)) {
      return { status: PROVIDER_STATUS.DEGRADED, message: 'Quota d’appels GitHub épuisé. Réessayez plus tard, ou configurez un jeton pour relever la limite.' };
    }
    return { status: PROVIDER_STATUS.AUTH_ERROR, message: 'Le jeton GitHub n’a pas les droits suffisants (HTTP 403). La portée actions:read est requise sur un dépôt privé.' };
  }
  if (status === 404) {
    return { status: PROVIDER_STATUS.ERROR, message: `GitHub ne renvoie aucun ${context} (HTTP 404) : il n’existe pas, ou le jeton n’y a pas accès.` };
  }
  if (status >= 500) {
    return { status: PROVIDER_STATUS.OFFLINE, message: `GitHub a renvoyé une erreur interne (HTTP ${status}).` };
  }
  return { status: PROVIDER_STATUS.ERROR, message: `GitHub a répondu HTTP ${status}.` };
}

function describeTransport(error) {
  const code = error?.code || 'OFFLINE';
  if (code === 'TIMEOUT') return { status: PROVIDER_STATUS.OFFLINE, message: 'GitHub n’a pas répondu dans le délai imparti.' };
  if (code === 'REDIRECT') return { status: PROVIDER_STATUS.ERROR, message: 'GitHub a renvoyé une redirection : vérifiez l’URL de l’API.' };
  return { status: PROVIDER_STATUS.OFFLINE, message: `API GitHub injoignable — ${error?.message || 'erreur réseau'}.` };
}

function repositoryPath(configuration) {
  return `repos/${segment(configuration.owner, 'le propriétaire')}/${segment(configuration.repository, 'le dépôt')}`;
}

async function testConnection(configuration = {}, { timeoutMs = 10000, request } = {}) {
  const validation = validateConfiguration(configuration);
  if (!validation.valid) {
    return { status: PROVIDER_STATUS.NOT_CONFIGURED, connected: false, message: validation.errors[0] || '', authenticated: false };
  }
  const authenticated = Boolean(String(configuration.token || '').trim());
  try {
    const target = deliveryUrl(apiUrl(configuration), repositoryPath(configuration), {}, 'de l’API GitHub');
    const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
    if (response.status === 200) {
      const name = response.body?.full_name || '';
      return {
        status: PROVIDER_STATUS.HEALTHY,
        connected: true,
        message: name ? `Dépôt ${name} accessible.` : 'Dépôt GitHub accessible.',
        authenticated
      };
    }
    return { ...describeStatus(response, { context: 'dépôt' }), connected: false, authenticated };
  } catch (error) {
    return { ...describeTransport(error), connected: false, authenticated };
  }
}

/** The newest workflow run, optionally restricted to one workflow file. */
async function readLatestRun(configuration, { timeoutMs, request }) {
  const workflow = String(configuration.workflow || '').trim();
  const path = workflow
    ? `${repositoryPath(configuration)}/actions/workflows/${encodeURIComponent(workflow)}/runs`
    : `${repositoryPath(configuration)}/actions/runs`;
  const target = deliveryUrl(apiUrl(configuration), path, { per_page: 1 }, 'de l’API GitHub');
  const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
  if (response.status !== 200) {
    return { error: describeStatus(response, { context: workflow ? 'workflow' : 'dépôt' }) };
  }
  const runs = Array.isArray(response.body?.workflow_runs) ? response.body.workflow_runs : [];
  return { run: runs[0] || null };
}

/** Jobs of a run — GitHub's equivalent of stages. */
async function readJobs(configuration, runId, { timeoutMs, request }) {
  const target = deliveryUrl(
    apiUrl(configuration),
    `${repositoryPath(configuration)}/actions/runs/${encodeURIComponent(String(runId))}/jobs`,
    { per_page: 100 },
    'de l’API GitHub'
  );
  const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
  if (response.status !== 200) return [];
  const jobs = Array.isArray(response.body?.jobs) ? response.body.jobs : [];
  return jobs.map((job) => ({
    name: String(job?.name || ''),
    path: String(job?.conclusion || job?.status || ''),
    outcome: outcomeFor({ status: job?.status, conclusion: job?.conclusion })
  }));
}

/** Artefacts published by a run. */
async function readArtifacts(configuration, runId, { timeoutMs, request }) {
  const target = deliveryUrl(
    apiUrl(configuration),
    `${repositoryPath(configuration)}/actions/runs/${encodeURIComponent(String(runId))}/artifacts`,
    { per_page: 100 },
    'de l’API GitHub'
  );
  const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
  if (response.status !== 200) return [];
  const artifacts = Array.isArray(response.body?.artifacts) ? response.body.artifacts : [];
  return artifacts
    .filter((artifact) => artifact && artifact.name)
    .map((artifact) => ({ name: String(artifact.name), path: '', kind: artifact.expired ? 'expired-artifact' : 'run-artifact' }));
}

async function fetchDelivery(configuration = {}, options = {}) {
  const { timeoutMs = 10000, request } = options;
  const common = {
    providerId: ID,
    providerLabel: LABEL,
    providerIcon: ICON,
    target: apiUrl(configuration),
    pipeline: [String(configuration.owner || ''), String(configuration.repository || '')].filter(Boolean).join('/'),
    credentialsConfigured: Boolean(String(configuration.token || '').trim()),
    sections: SECTIONS
  };

  const validation = validateConfiguration(configuration);
  if (!validation.valid) {
    return buildDeliveryModel({
      ...common,
      target: '', pipeline: '',
      status: PROVIDER_STATUS.NOT_CONFIGURED,
      message: validation.errors[0] || '',
      capabilities: everyCapability(RESOLVED_STATE.REQUIRES_CONFIG)
    });
  }

  try {
    const { run, error } = await readLatestRun(configuration, { timeoutMs, request });
    if (error) {
      return buildDeliveryModel({
        ...common,
        status: error.status,
        message: error.message,
        fetchedAt: new Date().toISOString(),
        capabilities: everyCapability(RESOLVED_STATE.UNAVAILABLE, error.message)
      });
    }
    if (!run) {
      return buildDeliveryModel({
        ...common,
        status: PROVIDER_STATUS.DEGRADED,
        message: configuration.workflow
          ? 'Le dépôt est accessible mais ce workflow n’a encore produit aucune exécution.'
          : 'Le dépôt est accessible mais aucune exécution de workflow n’a encore eu lieu.',
        fetchedAt: new Date().toISOString(),
        capabilities: {
          [CAPABILITY.PIPELINE_STATUS]: readyCapability(),
          [CAPABILITY.LAST_RUN]: notReportedCapability('Aucune exécution de workflow rapportée.'),
          [CAPABILITY.STAGES]: notReportedCapability('Aucune exécution, donc aucun job.'),
          [CAPABILITY.ARTIFACTS]: notReportedCapability('Aucune exécution, donc aucun artefact.'),
          [CAPABILITY.DEPLOYMENT_STATUS]: notReportedCapability('Security Center lit l’exécution, pas ses environnements de déploiement.')
        }
      });
    }

    const [stages, artifacts] = await Promise.all([
      readJobs(configuration, run.id, { timeoutMs, request }),
      readArtifacts(configuration, run.id, { timeoutMs, request })
    ]);
    const completed = String(run.status || '').toLowerCase() === 'completed';
    // GitHub publishes no duration for a run. It is derived from its own two
    // timestamps only once the run is complete, and stays null otherwise.
    const durationMs = completed ? durationBetween(run.run_started_at || run.created_at, run.updated_at) : null;

    return buildDeliveryModel({
      ...common,
      status: PROVIDER_STATUS.HEALTHY,
      fetchedAt: new Date().toISOString(),
      capabilities: {
        [CAPABILITY.PIPELINE_STATUS]: readyCapability(),
        [CAPABILITY.LAST_RUN]: readyCapability(),
        [CAPABILITY.STAGES]: stages.length ? readyCapability() : notReportedCapability('GitHub n’a exposé aucun job pour cette exécution.'),
        [CAPABILITY.ARTIFACTS]: artifacts.length ? readyCapability() : notReportedCapability('Aucun artefact publié par cette exécution.'),
        [CAPABILITY.DEPLOYMENT_STATUS]: notReportedCapability('Security Center lit l’exécution, pas ses environnements de déploiement.')
      },
      run: {
        id: String(run.id != null ? run.id : ''),
        displayName: run.run_number != null ? `#${run.run_number}` : String(run.name || ''),
        outcome: outcomeFor({ status: run.status, conclusion: run.conclusion }),
        // GitHub's own words, kept apart and shown as-is.
        providerResult: [run.status, run.conclusion].filter(Boolean).join(' / '),
        startedAt: run.run_started_at || run.created_at || null,
        durationMs,
        branch: String(run.head_branch || ''),
        commit: String(run.head_sha || ''),
        url: String(run.html_url || ''),
        commitMatch: null
      },
      stages,
      artifacts,
      deployment: null,
      securityReport: null,
      raw: { runId: run.id, workflowName: run.name || '', event: run.event || '' }
    });
  } catch (error) {
    const described = describeTransport(error);
    return buildDeliveryModel({
      ...common,
      status: described.status,
      message: described.message,
      capabilities: everyCapability(RESOLVED_STATE.UNAVAILABLE, described.message)
    });
  }
}

function everyCapability(state, reason = '') {
  return Object.values(CAPABILITY).reduce((all, capability) => ({ ...all, [capability]: { state, reason } }), {});
}

/** The repository's own Actions page, on the web host rather than the API host. */
function consoleUrl(configuration = {}) {
  try {
    const owner = String(configuration.owner || '').trim();
    const repository = String(configuration.repository || '').trim();
    if (!owner || !repository) return '';
    const api = normalizeDeliveryBaseUrl(apiUrl(configuration), 'de l’API GitHub');
    // github.com serves its API from a dedicated host; GHES serves it from the
    // same host under /api/v3.
    const web = api === DEFAULT_API_URL ? 'https://github.com' : api.replace(/\/api\/v3$/, '');
    return `${web}/${owner}/${repository}/actions`;
  } catch {
    return '';
  }
}

const githubDeliveryAdapter = Object.freeze({
  id: ID,
  label: LABEL,
  icon: ICON,
  summary: 'GitHub Actions workflow runs and artefacts.',
  configurationFields: CONFIGURATION_FIELDS,
  capabilities: CAPABILITIES,
  sections: SECTIONS,
  validateConfiguration,
  testConnection,
  fetchDelivery,
  consoleUrl
});

module.exports = {
  githubDeliveryAdapter,
  CONFIGURATION_FIELDS,
  DEFAULT_API_URL,
  API_VERSION,
  OUTCOME_BY_STATUS,
  OUTCOME_BY_CONCLUSION,
  outcomeFor,
  describeStatus,
  isRateLimited
};
