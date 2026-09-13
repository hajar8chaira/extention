'use strict';

/**
 * The GitLab CI/CD delivery adapter.
 *
 * Every GitLab-specific fact lives here: the `/api/v4` endpoints, the
 * `PRIVATE-TOKEN` header, the eleven pipeline statuses, the wording of each
 * error. Nothing above this file knows that GitLab exists.
 *
 * It reports only what GitLab returned. A pipeline GitLab never produced is
 * `NOT_STARTED`, not a failure; jobs it does not expose leave the stage list
 * explicitly not reported rather than empty-and-implying-success.
 *
 * The token travels in a header and nowhere else — never in the query string,
 * which GitLab also accepts but which proxies and access logs record.
 */

const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, RUN_OUTCOME,
  SECTION_KIND, FIELD_TYPE, CONFIG_GROUP,
  buildDeliveryModel, notReportedCapability, readyCapability, validateAgainstFields
} = require('./delivery-contract');
const {
  DeliveryTransportError, normalizeDeliveryBaseUrl, deliveryUrl, deliveryGetJson, durationBetween
} = require('./delivery-http');

const ID = 'gitlab-ci';
const LABEL = 'GitLab CI/CD';
const ICON = 'gitlab.svg';
const DEFAULT_URL = 'https://gitlab.com';

const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: FIELD_TYPE.URL,
    label: 'URL GitLab',
    placeholder: DEFAULT_URL,
    required: true,
    default: DEFAULT_URL,
    hint: 'Racine de l’instance GitLab. Laissez https://gitlab.com pour le service hébergé. N’y intégrez jamais de jeton.'
  },
  {
    id: 'project',
    type: FIELD_TYPE.TEXT,
    label: 'Projet',
    placeholder: 'groupe/sous-groupe/projet ou 12345',
    required: true,
    hint: 'Chemin complet du projet ou son identifiant numérique.'
  },
  {
    id: 'ref',
    type: FIELD_TYPE.TEXT,
    label: 'Branche / ref',
    group: CONFIG_GROUP.ADVANCED,
    placeholder: 'main',
    hint: 'Optionnel. Sans valeur, Security Center lit le dernier pipeline toutes branches confondues.'
  },
  {
    id: 'token',
    type: FIELD_TYPE.PASSWORD,
    label: 'Jeton d’accès',
    group: CONFIG_GROUP.ADVANCED,
    secret: true,
    hint: 'Jeton personnel, de projet ou de groupe avec la portée read_api. Conservé par le SecretStorage de VS Code et transmis en en-tête PRIVATE-TOKEN.'
  }
]);

/**
 * What this adapter can serve.
 *
 * `stages` is `REQUIRES_PROBE` rather than `READY`: GitLab exposes them through
 * the jobs of a pipeline, and a token without `read_api` — or a pipeline with no
 * job — returns none. Only a real call settles it.
 */
const CAPABILITIES = Object.freeze({
  [CAPABILITY.PIPELINE_STATUS]: DECLARED_STATE.READY,
  [CAPABILITY.LAST_RUN]: DECLARED_STATE.READY,
  [CAPABILITY.STAGES]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.ARTIFACTS]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.DEPLOYMENT_STATUS]: DECLARED_STATE.REQUIRES_PROBE
});

const SECTIONS = Object.freeze([
  { kind: SECTION_KIND.CONNECTION, title: 'Connexion' },
  { kind: SECTION_KIND.RUN_SUMMARY, title: 'Dernier pipeline' },
  { kind: SECTION_KIND.STAGE_LIST, title: 'Étapes' },
  { kind: SECTION_KIND.ARTIFACT_LIST, title: 'Artefacts' }
]);

/**
 * GitLab pipeline and job statuses mapped to the domain's run outcomes.
 *
 * `manual` and `skipped` are not failures and not successes: nothing ran, which
 * the domain calls NOT_STARTED. Anything queued or preparing is already an
 * active pipeline, so it reads as RUNNING.
 */
const OUTCOME_BY_STATUS = Object.freeze({
  created: RUN_OUTCOME.RUNNING,
  waiting_for_resource: RUN_OUTCOME.RUNNING,
  preparing: RUN_OUTCOME.RUNNING,
  pending: RUN_OUTCOME.RUNNING,
  running: RUN_OUTCOME.RUNNING,
  scheduled: RUN_OUTCOME.RUNNING,
  success: RUN_OUTCOME.SUCCESS,
  failed: RUN_OUTCOME.FAILED,
  canceled: RUN_OUTCOME.ABORTED,
  cancelled: RUN_OUTCOME.ABORTED,
  canceling: RUN_OUTCOME.RUNNING,
  manual: RUN_OUTCOME.NOT_STARTED,
  skipped: RUN_OUTCOME.NOT_STARTED
});

function outcomeFor(status) {
  return OUTCOME_BY_STATUS[String(status || '').toLowerCase()] || RUN_OUTCOME.NOT_REPORTED;
}

/** `groupe/projet` must be URL-encoded whole; a numeric id is passed as-is. */
function projectPath(project) {
  const text = String(project || '').trim().replace(/^\/+|\/+$/g, '');
  if (!text) throw new Error('Renseignez le projet GitLab.');
  if (text.split('/').some((segment) => segment === '..')) throw new Error('Projet GitLab invalide.');
  return /^\d+$/.test(text) ? text : encodeURIComponent(text);
}

function headersFor(configuration = {}) {
  const headers = { accept: 'application/json' };
  const token = String(configuration.token || '').trim();
  if (token) headers['private-token'] = token;
  return headers;
}

function validateConfiguration(configuration = {}) {
  const { valid, errors } = validateAgainstFields(CONFIGURATION_FIELDS, configuration);
  if (!valid) return { valid: false, errors };
  try {
    normalizeDeliveryBaseUrl(configuration.url, 'GitLab');
    projectPath(configuration.project);
  } catch (error) {
    return { valid: false, errors: [error.message] };
  }
  return { valid: true, errors: [] };
}

/**
 * Turns an HTTP answer into the sentence a developer can act on.
 *
 * GitLab answers 404 both for « no such project » and for « your token cannot
 * see this project ». Saying so is more useful than picking one.
 */
function describeStatus(status, { context = 'projet' } = {}) {
  if (status === 401) {
    return { status: PROVIDER_STATUS.AUTH_ERROR, message: 'GitLab a refusé le jeton (HTTP 401). Vérifiez sa validité et sa portée read_api.' };
  }
  if (status === 403) {
    return { status: PROVIDER_STATUS.AUTH_ERROR, message: 'Le jeton GitLab n’a pas les droits suffisants sur ce projet (HTTP 403).' };
  }
  if (status === 404) {
    return { status: PROVIDER_STATUS.ERROR, message: `GitLab ne renvoie aucun ${context} (HTTP 404) : il n’existe pas, ou le jeton n’y a pas accès.` };
  }
  if (status === 429) {
    return { status: PROVIDER_STATUS.DEGRADED, message: 'GitLab a limité le débit des appels (HTTP 429). Réessayez dans quelques instants.' };
  }
  if (status >= 500) {
    return { status: PROVIDER_STATUS.OFFLINE, message: `GitLab a renvoyé une erreur interne (HTTP ${status}).` };
  }
  return { status: PROVIDER_STATUS.ERROR, message: `GitLab a répondu HTTP ${status}.` };
}

/** Transport failures, already scrubbed of anything credential-shaped. */
function describeTransport(error) {
  const code = error?.code || 'OFFLINE';
  if (code === 'TIMEOUT') return { status: PROVIDER_STATUS.OFFLINE, message: 'GitLab n’a pas répondu dans le délai imparti.' };
  if (code === 'REDIRECT') return { status: PROVIDER_STATUS.ERROR, message: 'GitLab a renvoyé une redirection : vérifiez l’URL de l’instance.' };
  return { status: PROVIDER_STATUS.OFFLINE, message: `Instance GitLab injoignable — ${error?.message || 'erreur réseau'}.` };
}

async function testConnection(configuration = {}, { timeoutMs = 10000, request } = {}) {
  const validation = validateConfiguration(configuration);
  if (!validation.valid) {
    return { status: PROVIDER_STATUS.NOT_CONFIGURED, connected: false, message: validation.errors[0] || '', authenticated: false };
  }
  const authenticated = Boolean(String(configuration.token || '').trim());
  try {
    const target = deliveryUrl(configuration.url, `api/v4/projects/${projectPath(configuration.project)}`, {}, 'GitLab');
    const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
    if (response.status === 200) {
      const name = response.body?.path_with_namespace || response.body?.name || '';
      return {
        status: PROVIDER_STATUS.HEALTHY,
        connected: true,
        message: name ? `Projet ${name} accessible.` : 'Projet GitLab accessible.',
        authenticated
      };
    }
    const described = describeStatus(response.status, { context: 'projet' });
    return { ...described, connected: false, authenticated };
  } catch (error) {
    const described = describeTransport(error);
    return { ...described, connected: false, authenticated };
  }
}

/** The newest pipeline of the project, or null when the project has none. */
async function readLatestPipeline(configuration, { timeoutMs, request }) {
  const listUrl = deliveryUrl(
    configuration.url,
    `api/v4/projects/${projectPath(configuration.project)}/pipelines`,
    { per_page: 1, order_by: 'id', sort: 'desc', ref: String(configuration.ref || '').trim() },
    'GitLab'
  );
  const list = await deliveryGetJson(listUrl, { headers: headersFor(configuration), timeoutMs, request });
  if (list.status !== 200) return { error: describeStatus(list.status, { context: 'pipeline' }) };
  const summary = Array.isArray(list.body) ? list.body[0] : null;
  if (!summary || summary.id === undefined || summary.id === null) return { pipeline: null };
  // The list entry carries no timing: the detail endpoint is what reports
  // `started_at`, `duration` and the commit title.
  const detailUrl = deliveryUrl(
    configuration.url,
    `api/v4/projects/${projectPath(configuration.project)}/pipelines/${encodeURIComponent(String(summary.id))}`,
    {}, 'GitLab'
  );
  const detail = await deliveryGetJson(detailUrl, { headers: headersFor(configuration), timeoutMs, request });
  return { pipeline: detail.status === 200 && detail.body ? { ...summary, ...detail.body } : summary };
}

/** Jobs of a pipeline, grouped into the stages GitLab declares. */
async function readStages(configuration, pipelineId, { timeoutMs, request }) {
  const target = deliveryUrl(
    configuration.url,
    `api/v4/projects/${projectPath(configuration.project)}/pipelines/${encodeURIComponent(String(pipelineId))}/jobs`,
    { per_page: 100 },
    'GitLab'
  );
  const response = await deliveryGetJson(target, { headers: headersFor(configuration), timeoutMs, request });
  if (response.status !== 200 || !Array.isArray(response.body)) return { stages: [], jobs: [] };
  const jobs = response.body;
  const order = [];
  const byStage = new Map();
  for (const job of jobs) {
    const stage = String(job?.stage || '').trim() || 'sans étape';
    if (!byStage.has(stage)) { byStage.set(stage, []); order.push(stage); }
    byStage.get(stage).push(job);
  }
  const stages = order.map((stage) => {
    const stageJobs = byStage.get(stage);
    return {
      name: stage,
      path: stageJobs.map((job) => job?.name).filter(Boolean).join(', '),
      // A stage is as bad as its worst job: GitLab reports no stage verdict of
      // its own, so it is derived from the jobs it did report — never invented.
      outcome: worstOutcome(stageJobs.map((job) => outcomeFor(job?.status)))
    };
  });
  return { stages, jobs };
}

const OUTCOME_SEVERITY = Object.freeze([
  RUN_OUTCOME.FAILED, RUN_OUTCOME.ABORTED, RUN_OUTCOME.UNSTABLE,
  RUN_OUTCOME.RUNNING, RUN_OUTCOME.SUCCESS, RUN_OUTCOME.NOT_STARTED, RUN_OUTCOME.NOT_REPORTED
]);

function worstOutcome(outcomes = []) {
  for (const candidate of OUTCOME_SEVERITY) {
    if (outcomes.includes(candidate)) return candidate;
  }
  return RUN_OUTCOME.NOT_REPORTED;
}

/** Job artefacts GitLab actually reported for this pipeline. */
function artifactsFrom(jobs = []) {
  const artifacts = [];
  for (const job of jobs) {
    for (const artifact of Array.isArray(job?.artifacts) ? job.artifacts : []) {
      if (!artifact || !artifact.filename) continue;
      artifacts.push({ name: String(artifact.filename), path: String(job.name || ''), kind: String(artifact.file_type || 'artifact') });
    }
  }
  return artifacts;
}

async function fetchDelivery(configuration = {}, options = {}) {
  const { timeoutMs = 10000, request } = options;
  const common = {
    providerId: ID,
    providerLabel: LABEL,
    providerIcon: ICON,
    target: String(configuration.url || ''),
    pipeline: String(configuration.project || ''),
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
    const { pipeline, error } = await readLatestPipeline(configuration, { timeoutMs, request });
    if (error) {
      return buildDeliveryModel({
        ...common,
        status: error.status,
        message: error.message,
        fetchedAt: new Date().toISOString(),
        capabilities: everyCapability(RESOLVED_STATE.UNAVAILABLE, error.message)
      });
    }
    if (!pipeline) {
      return buildDeliveryModel({
        ...common,
        status: PROVIDER_STATUS.DEGRADED,
        message: 'Le projet est accessible mais n’a encore produit aucun pipeline.',
        fetchedAt: new Date().toISOString(),
        capabilities: {
          [CAPABILITY.PIPELINE_STATUS]: readyCapability(),
          [CAPABILITY.LAST_RUN]: notReportedCapability('Le projet n’a pas encore produit de pipeline.'),
          [CAPABILITY.STAGES]: notReportedCapability('Aucun pipeline, donc aucune étape.'),
          [CAPABILITY.ARTIFACTS]: notReportedCapability('Aucun pipeline, donc aucun artefact.'),
          [CAPABILITY.DEPLOYMENT_STATUS]: notReportedCapability('GitLab ne rapporte pas d’état de déploiement ici.')
        }
      });
    }

    const { stages, jobs } = await readStages(configuration, pipeline.id, { timeoutMs, request });
    const artifacts = artifactsFrom(jobs);
    // GitLab reports `duration` in seconds; when it is absent the two
    // timestamps are used, and when those are absent too it stays null.
    const durationMs = Number.isFinite(Number(pipeline.duration))
      ? Math.round(Number(pipeline.duration) * 1000)
      : durationBetween(pipeline.started_at, pipeline.finished_at);

    return buildDeliveryModel({
      ...common,
      status: PROVIDER_STATUS.HEALTHY,
      fetchedAt: new Date().toISOString(),
      capabilities: {
        [CAPABILITY.PIPELINE_STATUS]: readyCapability(),
        [CAPABILITY.LAST_RUN]: readyCapability(),
        [CAPABILITY.STAGES]: stages.length ? readyCapability() : notReportedCapability('GitLab n’a exposé aucun job pour ce pipeline.'),
        [CAPABILITY.ARTIFACTS]: artifacts.length ? readyCapability() : notReportedCapability('Aucun artefact rapporté par ce pipeline.'),
        [CAPABILITY.DEPLOYMENT_STATUS]: notReportedCapability('Security Center lit le pipeline, pas ses environnements de déploiement.')
      },
      run: {
        id: String(pipeline.id),
        displayName: `#${pipeline.id}`,
        outcome: outcomeFor(pipeline.status),
        // GitLab's own word, shown as-is and never translated into a verdict.
        providerResult: String(pipeline.status || ''),
        startedAt: pipeline.started_at || pipeline.created_at || null,
        durationMs,
        branch: String(pipeline.ref || ''),
        commit: String(pipeline.sha || ''),
        url: String(pipeline.web_url || ''),
        commitMatch: null
      },
      stages,
      artifacts,
      deployment: null,
      securityReport: null,
      raw: { pipeline, jobCount: jobs.length }
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

/** The project's own pipeline page. */
function consoleUrl(configuration = {}) {
  try {
    const project = String(configuration.project || '').trim().replace(/^\/+|\/+$/g, '');
    if (!project || /^\d+$/.test(project)) return normalizeDeliveryBaseUrl(configuration.url, 'GitLab');
    return `${normalizeDeliveryBaseUrl(configuration.url, 'GitLab')}/${project}/-/pipelines`;
  } catch {
    return '';
  }
}

const gitlabDeliveryAdapter = Object.freeze({
  id: ID,
  label: LABEL,
  icon: ICON,
  summary: 'GitLab pipelines, jobs and artefacts.',
  configurationFields: CONFIGURATION_FIELDS,
  capabilities: CAPABILITIES,
  sections: SECTIONS,
  validateConfiguration,
  testConnection,
  fetchDelivery,
  consoleUrl
});

module.exports = {
  gitlabDeliveryAdapter,
  CONFIGURATION_FIELDS,
  DEFAULT_URL,
  OUTCOME_BY_STATUS,
  outcomeFor,
  projectPath,
  worstOutcome,
  describeStatus
};
