'use strict';

/**
 * The Jenkins delivery adapter.
 *
 * Every Jenkins-specific fact lives here: endpoints, authentication, the shape
 * of a build payload, the vocabulary of a job, the wording of an error. Nothing
 * above this file knows that Jenkins exists.
 *
 * The Jenkins protocol itself is not reimplemented — `../jenkins` already reads
 * the API correctly, scrubs the token out of every message and refuses to infer
 * a verdict Jenkins did not report. This adapter is the translation layer that
 * turns its output into the domain model of `delivery-contract`, so that the
 * page and the dashboard can be written once for every provider.
 */

const {
  DELIVERY_STATE, REPORT_STATE, CONNECTION_STATE,
  fetchDeliveryStatus, testJenkinsConnection, jobUrl, normalizeJenkinsUrl
} = require('../jenkins');
const {
  PROVIDER_STATUS, CAPABILITY, DECLARED_STATE, RESOLVED_STATE, RUN_OUTCOME,
  SECTION_KIND, FIELD_TYPE, CONFIG_GROUP,
  buildDeliveryModel, notReportedCapability, readyCapability, validateAgainstFields
} = require('./delivery-contract');

const ID = 'jenkins';
const LABEL = 'Jenkins';

/**
 * What Jenkins needs, declared rather than hardcoded in a form.
 * `secret: true` marks what must never leave SecretStorage.
 */
const CONFIGURATION_FIELDS = Object.freeze([
  {
    id: 'url',
    type: FIELD_TYPE.URL,
    label: 'URL Jenkins',
    placeholder: 'http://host:8080',
    required: true,
    hint: 'Racine du serveur Jenkins. N’y intégrez jamais d’identifiants : le jeton est conservé dans le SecretStorage de VS Code.'
  },
  {
    id: 'job',
    type: FIELD_TYPE.TEXT,
    label: 'Job / Pipeline',
    placeholder: 'security-pipeline',
    required: true,
    hint: 'Nom du job dont Security Center lit le dernier build.'
  },
  {
    id: 'user',
    type: FIELD_TYPE.TEXT,
    label: 'Utilisateur',
    group: CONFIG_GROUP.ADVANCED,
    hint: 'Optionnel. La plupart des serveurs Jenkins refusent l’accès anonyme à l’API.'
  },
  {
    id: 'token',
    type: FIELD_TYPE.PASSWORD,
    label: 'Jeton d’API',
    group: CONFIG_GROUP.ADVANCED,
    secret: true,
    hint: 'Conservé par le SecretStorage de VS Code. Transmis en en-tête Authorization, jamais dans une URL ni dans un message d’erreur.'
  }
]);

/**
 * What this adapter can serve.
 *
 * `stages` and `deploymentStatus` are `REQUIRES_PROBE`, not `READY`: the
 * Jenkins API as read here returns the build, not its stages, and says nothing
 * about a deployment. Declaring them ready would promise data no call produces.
 */
const CAPABILITIES = Object.freeze({
  [CAPABILITY.PIPELINE_STATUS]: DECLARED_STATE.READY,
  [CAPABILITY.LAST_RUN]: DECLARED_STATE.READY,
  [CAPABILITY.ARTIFACTS]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.STAGES]: DECLARED_STATE.REQUIRES_PROBE,
  [CAPABILITY.DEPLOYMENT_STATUS]: DECLARED_STATE.REQUIRES_PROBE
});

const SECTIONS = Object.freeze([
  { kind: SECTION_KIND.CONNECTION, title: 'Connexion' },
  { kind: SECTION_KIND.RUN_SUMMARY, title: 'Dernière exécution' },
  { kind: SECTION_KIND.STAGE_LIST, title: 'Étapes' },
  { kind: SECTION_KIND.SECURITY_REPORT, title: 'Rapport de sécurité' },
  { kind: SECTION_KIND.ARTIFACT_LIST, title: 'Artefacts' }
]);

/** Jenkins build states mapped to the domain's run outcomes. */
const OUTCOME_BY_STATE = Object.freeze({
  [DELIVERY_STATE.RUNNING]: RUN_OUTCOME.RUNNING,
  [DELIVERY_STATE.SUCCESS]: RUN_OUTCOME.SUCCESS,
  [DELIVERY_STATE.UNSTABLE]: RUN_OUTCOME.UNSTABLE,
  [DELIVERY_STATE.FAILED]: RUN_OUTCOME.FAILED,
  [DELIVERY_STATE.ABORTED]: RUN_OUTCOME.ABORTED,
  [DELIVERY_STATE.NOT_STARTED]: RUN_OUTCOME.NOT_STARTED
});

/** Connection outcomes mapped to provider status. */
const STATUS_BY_CONNECTION = Object.freeze({
  [CONNECTION_STATE.CONNECTED]: PROVIDER_STATUS.HEALTHY,
  [CONNECTION_STATE.AUTH_FAILED]: PROVIDER_STATUS.AUTH_ERROR,
  [CONNECTION_STATE.FORBIDDEN]: PROVIDER_STATUS.AUTH_ERROR,
  [CONNECTION_STATE.UNREACHABLE]: PROVIDER_STATUS.OFFLINE,
  [CONNECTION_STATE.JOB_NOT_FOUND]: PROVIDER_STATUS.ERROR,
  [CONNECTION_STATE.ERROR]: PROVIDER_STATUS.ERROR
});

function validateConfiguration(configuration = {}) {
  const errors = validateAgainstFields(CONFIGURATION_FIELDS, configuration);
  if (errors.length) return { valid: false, errors };
  try {
    normalizeJenkinsUrl(configuration.url);
  } catch (error) {
    return { valid: false, errors: [error.message] };
  }
  return { valid: true, errors: [] };
}

async function testConnection(configuration = {}, { timeoutMs = 10000, request } = {}) {
  const outcome = await testJenkinsConnection({
    baseUrl: configuration.url || '',
    job: configuration.job || '',
    user: configuration.user || '',
    token: configuration.token || '',
    timeoutMs,
    ...(request ? { request } : {})
  });
  return {
    status: STATUS_BY_CONNECTION[outcome.state] || PROVIDER_STATUS.ERROR,
    connected: outcome.state === CONNECTION_STATE.CONNECTED,
    message: outcome.message || '',
    authenticated: Boolean(outcome.authenticated)
  };
}

/**
 * Reads the last run and translates it into the domain model.
 *
 * The whole point of the mapping: a status Jenkins never reported becomes
 * `NOT_REPORTED`, never `FAILED`. A job with no build is `NOT_STARTED`. An
 * unreachable server is `OFFLINE` and leaves `run` null rather than inventing
 * an outcome for it.
 */
async function fetchDelivery(configuration = {}, options = {}) {
  const { workspaceCommit = '', timeoutMs = 10000, request, requestText } = options;
  const status = await fetchDeliveryStatus({
    baseUrl: configuration.url || '',
    job: configuration.job || '',
    user: configuration.user || '',
    token: configuration.token || '',
    workspaceCommit,
    timeoutMs,
    ...(request ? { request } : {}),
    ...(requestText ? { requestText } : {})
  });
  return toDeliveryModel(status, configuration);
}

/** Maps a `jenkins.js` delivery status onto the domain model. */
function toDeliveryModel(status = {}, configuration = {}) {
  const common = {
    providerId: ID,
    providerLabel: LABEL,
    providerIcon: 'jenkins.svg',
    target: status.baseUrl || configuration.url || '',
    pipeline: status.job || configuration.job || '',
    credentialsConfigured: Boolean(configuration.token),
    fetchedAt: status.fetchedAt || null,
    sections: SECTIONS,
    raw: status
  };

  if (!status.configured || status.state === DELIVERY_STATE.NOT_CONFIGURED) {
    return buildDeliveryModel({
      ...common,
      status: PROVIDER_STATUS.NOT_CONFIGURED,
      target: '', pipeline: '',
      capabilities: everyCapability(RESOLVED_STATE.REQUIRES_CONFIG)
    });
  }

  if (status.state === DELIVERY_STATE.ERROR) {
    return buildDeliveryModel({
      ...common,
      status: PROVIDER_STATUS.OFFLINE,
      message: status.error || '',
      // Offline is not a failed run: `run` stays null and every capability is
      // unavailable rather than reporting a verdict nobody produced.
      capabilities: everyCapability(RESOLVED_STATE.UNAVAILABLE, status.error || '')
    });
  }

  const build = status.build || null;
  const report = status.ci || {};
  const artifacts = Array.isArray(build?.artifacts) ? build.artifacts : [];
  const hasArtifacts = artifacts.length > 0;

  const capabilities = {
    [CAPABILITY.PIPELINE_STATUS]: readyCapability(),
    [CAPABILITY.LAST_RUN]: build ? readyCapability() : notReportedCapability('Le job n’a pas encore produit d’exécution.'),
    // Not a claim of absence: the API as read here does not expose stages.
    [CAPABILITY.STAGES]: notReportedCapability('Le fournisseur expose le build, pas ses étapes.'),
    [CAPABILITY.ARTIFACTS]: hasArtifacts ? readyCapability() : notReportedCapability('Aucun artefact rapporté par cette exécution.'),
    [CAPABILITY.DEPLOYMENT_STATUS]: notReportedCapability('Le fournisseur ne rapporte pas d’état de déploiement.')
  };

  return buildDeliveryModel({
    ...common,
    status: build ? PROVIDER_STATUS.HEALTHY : PROVIDER_STATUS.DEGRADED,
    message: build ? '' : 'Le job existe mais n’a pas encore produit d’exécution.',
    capabilities,
    run: build ? {
      id: build.number != null ? String(build.number) : '',
      displayName: build.displayName || '',
      outcome: OUTCOME_BY_STATE[build.state] || RUN_OUTCOME.NOT_REPORTED,
      // The vendor's own word for the result, shown as-is and never translated
      // into a verdict of our own.
      providerResult: build.result || '',
      startedAt: build.startedAt || null,
      durationMs: build.durationMs != null ? build.durationMs : null,
      branch: build.branch || '',
      commit: build.commit || '',
      url: build.url || '',
      commitMatch: status.commit?.match || null
    } : null,
    stages: [],
    artifacts: artifacts.map((artifact) => ({
      name: artifact.fileName || '',
      path: artifact.relativePath || '',
      kind: 'build-artifact'
    })),
    deployment: null,
    securityReport: {
      // `REPORTED` is the only state that carries a verdict. The others say why
      // there is none, which is what the page must show instead of a failure.
      reported: report.state === REPORT_STATE.REPORTED,
      state: String(report.state || REPORT_STATE.NOT_REPORTED),
      reason: report.reason || '',
      policy: status.policy || null,
      supplyChain: status.artifacts || null,
      artifactPath: report.artifactPath || null,
      inconsistent: Boolean(status.identity?.inconsistent)
    }
  });
}

function everyCapability(state, reason = '') {
  return Object.values(CAPABILITY).reduce(
    (all, capability) => ({ ...all, [capability]: { state, reason } }),
    {}
  );
}

/** The provider's own console URL for the configured pipeline. */
function consoleUrl(configuration = {}) {
  try {
    return jobUrl(configuration.url || '', configuration.job || '');
  } catch {
    return '';
  }
}

const jenkinsDeliveryAdapter = Object.freeze({
  id: ID,
  label: LABEL,
  icon: 'jenkins.svg',
  summary: 'Jenkins jobs, builds and archived security reports.',
  configurationFields: CONFIGURATION_FIELDS,
  capabilities: CAPABILITIES,
  sections: SECTIONS,
  validateConfiguration,
  testConnection,
  fetchDelivery,
  toDeliveryModel,
  consoleUrl
});

module.exports = { jenkinsDeliveryAdapter, CONFIGURATION_FIELDS, OUTCOME_BY_STATE, STATUS_BY_CONNECTION, toDeliveryModel };
