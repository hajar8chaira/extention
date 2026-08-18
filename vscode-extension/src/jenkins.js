'use strict';

/**
 * Jenkins delivery status.
 *
 * Security Center does not replace Jenkins and does not orchestrate delivery. It
 * reads the security-relevant facts of the last build so a developer can see, in
 * the editor, whether the policy that passes locally also passed in CI — and
 * whether the build they are looking at is even the code they have.
 *
 * Rules this module holds to:
 *
 *   - It reports only what Jenkins actually returned. A field the API did not
 *     provide stays `null`; nothing is inferred from a build number or a colour.
 *   - It never claims the workspace and the build are the same code without
 *     comparing the two commits.
 *   - The API token never appears in a URL, a log line, an error message or a
 *     returned object. It travels in an Authorization header and nowhere else.
 *   - It is pure with respect to VS Code: the caller supplies the token from
 *     SecretStorage and the workspace commit.
 */

const http = require('http');
const https = require('https');
const { validateCiReport, CI_REPORT_FILENAME, MAX_CI_REPORT_BYTES } = require('./ci-report');

/** Delivery stages Security Center can honestly speak about. */
const DELIVERY_STATE = Object.freeze({
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  UNAVAILABLE: 'UNAVAILABLE',
  ERROR: 'ERROR',
  NOT_STARTED: 'NOT_STARTED',
  RUNNING: 'RUNNING',
  SUCCESS: 'SUCCESS',
  FAILED: 'FAILED',
  UNSTABLE: 'UNSTABLE',
  ABORTED: 'ABORTED'
});

/** How a workspace commit relates to the commit a build was made from. */
const COMMIT_MATCH = Object.freeze({ SAME: 'SAME', DIFFERENT: 'DIFFERENT', UNKNOWN: 'UNKNOWN' });

/**
 * Validates a Jenkins base URL.
 *
 * Credentials embedded in the URL are refused outright: they would end up in
 * settings, in logs and in every error message. The token belongs in
 * SecretStorage and in a header.
 */
function normalizeJenkinsUrl(value) {
  const text = String(value || '').trim();
  if (!text) throw new Error('Renseignez l’URL de Jenkins.');
  let url;
  try { url = new URL(text); } catch { throw new Error('URL Jenkins invalide.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Seules les URL HTTP et HTTPS sont acceptées.');
  if (url.username || url.password) {
    throw new Error('N’intégrez pas d’identifiants dans l’URL. Le jeton est conservé dans le SecretStorage de VS Code.');
  }
  url.hash = '';
  url.search = '';
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

/**
 * Turns a job name or folder path into a Jenkins job path.
 *
 * `folder/job` and `folder/job/branch` both work, which covers multibranch
 * pipelines. Each segment is encoded, so a job name with a space or an accent
 * cannot break the path or smuggle in a traversal.
 */
function jenkinsJobPath(job) {
  const segments = String(job || '').split('/').map((part) => part.trim()).filter(Boolean);
  if (!segments.length) throw new Error('Renseignez le nom du job Jenkins.');
  if (segments.some((part) => part === '..')) throw new Error('Nom de job Jenkins invalide.');
  return segments.map((part) => `job/${encodeURIComponent(part)}`).join('/');
}

/** The fields Security Center reads. Asking for a subtree keeps the reply small. */
const BUILD_TREE = [
  'number', 'result', 'building', 'timestamp', 'duration', 'url', 'displayName',
  'actions[lastBuiltRevision[SHA1,branch[name,SHA1]]]',
  'changeSets[items[commitId]]',
  // Archived artefacts, so the CI report can be located without guessing a path.
  'artifacts[fileName,relativePath]'
].join(',');

/** A short list of recent builds, for build selection. */
const BUILDS_TREE = `builds[${BUILD_TREE}]{0,10}`;

/** How the report artefact was resolved, or why it was not. */
const REPORT_STATE = Object.freeze({
  REPORTED: 'REPORTED',
  NOT_REPORTED: 'NOT_REPORTED',
  INVALID: 'INVALID',
  UNAVAILABLE: 'UNAVAILABLE'
});

/** Connection test outcomes. Each one tells the developer what to fix. */
const CONNECTION_STATE = Object.freeze({
  CONNECTED: 'CONNECTED',
  AUTH_FAILED: 'AUTH_FAILED',
  FORBIDDEN: 'FORBIDDEN',
  JOB_NOT_FOUND: 'JOB_NOT_FOUND',
  UNREACHABLE: 'UNREACHABLE',
  ERROR: 'ERROR'
});

/**
 * Reads the last build of a job.
 *
 * The token is sent as a Basic Authorization header. It is never placed in the
 * query string, because URLs are logged by proxies and by Jenkins itself.
 */
function requestJenkins(target, { user = '', token = '', timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(target); } catch { return reject(new Error('URL Jenkins invalide.')); }
    const transport = url.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json' };
    if (token) {
      const credentials = Buffer.from(`${user || 'security-center'}:${token}`).toString('base64');
      headers.authorization = `Basic ${credentials}`;
    }
    const request = transport.request(url, { method: 'GET', headers, timeout: timeoutMs }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const status = response.statusCode || 500;
        const text = Buffer.concat(chunks).toString('utf8');
        // The body is never echoed: a Jenkins error page can contain a crumb or
        // a redirect carrying credentials.
        if (status === 401 || status === 403) return reject(new Error('Jenkins a refusé l’authentification. Vérifiez l’utilisateur et le jeton.'));
        if (status === 404) return reject(new Error('Job Jenkins introuvable. Vérifiez le nom du job.'));
        if (status >= 400) return reject(new Error(`Jenkins a répondu HTTP ${status}.`));
        try { resolve(text ? JSON.parse(text) : {}); }
        catch { reject(new Error('Jenkins a renvoyé une réponse non JSON. L’URL pointe peut-être ailleurs.')); }
      });
    });
    request.on('timeout', () => request.destroy(new Error('Jenkins ne répond pas.')));
    request.on('error', (error) => reject(new Error(scrubJenkinsError(error.message))));
    request.end();
  });
}

/** Strips anything credential-shaped from a transport error before it is shown. */
function scrubJenkinsError(message) {
  return String(message || 'Erreur réseau.')
    .replace(/\/\/[^@/\s]+@/g, '//')
    .replace(/(Basic|Bearer)\s+[A-Za-z0-9+/=._-]+/gi, '$1 [REDACTED]');
}

/** The last build URL for a job. */
function lastBuildUrl(baseUrl, job) {
  return `${normalizeJenkinsUrl(baseUrl)}/${jenkinsJobPath(job)}/lastBuild/api/json?tree=${encodeURIComponent(BUILD_TREE)}`;
}

/**
 * Normalizes a Jenkins build payload.
 *
 * Every field is optional in the API, so every field is optional here. `commit`
 * is taken from the git plugin's `lastBuiltRevision` first and from the change
 * set only as a fallback; when neither exists it stays `null` rather than being
 * guessed from the display name.
 */
function buildStatusFrom(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const revision = (raw.actions || [])
    .map((action) => action?.lastBuiltRevision)
    .find((value) => value && (value.SHA1 || value.branch?.[0]?.SHA1));
  const changeCommit = raw.changeSets?.[0]?.items?.[0]?.commitId || null;
  const commit = revision?.SHA1 || revision?.branch?.[0]?.SHA1 || changeCommit || null;
  const branch = revision?.branch?.[0]?.name || null;
  const building = raw.building === true;
  return {
    number: Number.isFinite(Number(raw.number)) ? Number(raw.number) : null,
    displayName: raw.displayName ? String(raw.displayName) : null,
    building,
    // A running build has no result yet. `null` is the honest value.
    result: raw.result ? String(raw.result).toUpperCase() : null,
    state: building ? DELIVERY_STATE.RUNNING : resultToState(raw.result),
    commit: commit ? String(commit) : null,
    branch: branch ? String(branch).replace(/^refs\/remotes\/[^/]+\//, '') : null,
    startedAt: Number.isFinite(Number(raw.timestamp)) && Number(raw.timestamp) > 0
      ? new Date(Number(raw.timestamp)).toISOString() : null,
    durationMs: Number.isFinite(Number(raw.duration)) && Number(raw.duration) > 0 ? Number(raw.duration) : null,
    url: raw.url ? String(raw.url) : null,
    // Kept so the report artefact can be located without a second API call.
    artifacts: Array.isArray(raw.artifacts)
      ? raw.artifacts.map((artifact) => ({
        fileName: String(artifact?.fileName || ''),
        relativePath: String(artifact?.relativePath || '')
      })).filter((artifact) => artifact.fileName)
      : []
  };
}

function resultToState(result) {
  return {
    SUCCESS: DELIVERY_STATE.SUCCESS,
    FAILURE: DELIVERY_STATE.FAILED,
    UNSTABLE: DELIVERY_STATE.UNSTABLE,
    ABORTED: DELIVERY_STATE.ABORTED
  }[String(result || '').toUpperCase()] || DELIVERY_STATE.NOT_STARTED;
}

/**
 * Compares the workspace commit with the commit a build was made from.
 *
 * Short and long SHAs compare by prefix, because Jenkins and `git rev-parse` do
 * not always agree on length. An unknown commit on either side yields UNKNOWN —
 * never SAME, because « probably the same » is exactly the claim to avoid.
 */
function commitCorrelation(workspaceCommit, buildCommit) {
  const left = String(workspaceCommit || '').trim().toLowerCase();
  const right = String(buildCommit || '').trim().toLowerCase();
  if (!left || !right) return { match: COMMIT_MATCH.UNKNOWN, workspaceCommit: left || null, buildCommit: right || null };
  const length = Math.min(left.length, right.length, 40);
  const same = length >= 7 && left.slice(0, length) === right.slice(0, length);
  return {
    match: same ? COMMIT_MATCH.SAME : COMMIT_MATCH.DIFFERENT,
    workspaceCommit: left,
    buildCommit: right
  };
}

/**
 * The delivery model a page renders.
 *
 * Deliberately conservative: `deployment` is only ever what Jenkins reported for
 * the build as a whole. Security Center does not deploy and does not claim a
 * deployment stage it cannot see.
 */
function deliveryStatusFrom({
  configured = false, build = null, error = '', workspaceCommit = '',
  policy = null, artifacts = null, job = '', baseUrl = '', fetchedAt = null, ci = null
} = {}) {
  if (!configured) {
    return {
      state: DELIVERY_STATE.NOT_CONFIGURED, configured: false, job: '', baseUrl: '',
      build: null, commit: { match: COMMIT_MATCH.UNKNOWN, workspaceCommit: workspaceCommit || null, buildCommit: null },
      policy: null, artifacts: null, error: '', fetchedAt: null,
      ci: { state: REPORT_STATE.NOT_REPORTED, report: null, reason: '', artifactPath: null }, identity: null
    };
  }
  if (error) {
    return {
      state: DELIVERY_STATE.ERROR, configured: true, job, baseUrl,
      build: null, commit: { match: COMMIT_MATCH.UNKNOWN, workspaceCommit: workspaceCommit || null, buildCommit: null },
      policy: null, artifacts: null, error: scrubJenkinsError(error), fetchedAt,
      ci: { state: REPORT_STATE.UNAVAILABLE, report: null, reason: scrubJenkinsError(error), artifactPath: null }, identity: null
    };
  }
  if (!build) {
    return {
      state: DELIVERY_STATE.NOT_STARTED, configured: true, job, baseUrl,
      build: null, commit: { match: COMMIT_MATCH.UNKNOWN, workspaceCommit: workspaceCommit || null, buildCommit: null },
      policy: null, artifacts: null, error: '', fetchedAt,
      ci: { state: REPORT_STATE.NOT_REPORTED, report: null, reason: '', artifactPath: null }, identity: null
    };
  }
  const report = ci?.report || null;
  const identity = reportIdentity({
    workspaceCommit, buildCommit: build.commit, reportCommit: report?.repository?.commit || ''
  });
  return {
    state: build.state, configured: true, job, baseUrl, build,
    commit: commitCorrelation(workspaceCommit, build.commit),
    // The CI verdict is the archived report's, never the local scan's. When the
    // report's commit disagrees with the build's, the verdict is not attributed:
    // something republished an artefact and it cannot be trusted for this build.
    ci: ci || { state: REPORT_STATE.NOT_REPORTED, report: null, reason: '', artifactPath: null },
    identity,
    policy: !identity.inconsistent && report ? report.policy : (policy || null),
    artifacts: !identity.inconsistent && report ? report.supplyChain : (artifacts || null),
    error: '',
    fetchedAt
  };
}

/**
 * Fetches the delivery status.
 *
 * A failure is a state, not an exception: an unreachable Jenkins produces
 * `ERROR` with a scrubbed reason so the page can say what happened.
 */
async function fetchDeliveryStatus({
  baseUrl = '', job = '', user = '', token = '', workspaceCommit = '', timeoutMs = 10000,
  request = requestJenkins, requestText = requestJenkinsText
} = {}) {
  if (!String(baseUrl).trim() || !String(job).trim()) {
    return deliveryStatusFrom({ configured: false, workspaceCommit });
  }
  const fetchedAt = new Date().toISOString();
  try {
    const raw = await request(lastBuildUrl(baseUrl, job), { user, token, timeoutMs });
    const build = buildStatusFrom(raw);
    // The CI verdict comes from the archived report and from nowhere else. The
    // local scan is a different scan identity and is never substituted.
    const ci = build
      ? await fetchCiReport({ baseUrl, job, build, user, token, timeoutMs, requestText })
      : { state: REPORT_STATE.NOT_REPORTED, report: null, reason: '', artifactPath: null };
    return deliveryStatusFrom({
      configured: true, build, workspaceCommit,
      job, baseUrl: normalizeJenkinsUrl(baseUrl), fetchedAt, ci
    });
  } catch (error) {
    // A job with no build yet answers 404 on lastBuild; that is « not started »,
    // not a configuration error.
    if (/introuvable/i.test(error.message)) {
      return deliveryStatusFrom({ configured: true, build: null, workspaceCommit, job, baseUrl, fetchedAt });
    }
    return deliveryStatusFrom({ configured: true, error: error.message, workspaceCommit, job, baseUrl, fetchedAt });
  }
}

/** The URL of the job page, for an « Open Jenkins » action. */
function jobUrl(baseUrl, job) {
  return `${normalizeJenkinsUrl(baseUrl)}/${jenkinsJobPath(job)}/`;
}

/**
 * Locates the Security Center report among a build's artefacts.
 *
 * The relative path is validated rather than trusted: a Jenkins artefact name is
 * data controlled by whatever produced the build, and a `..` segment or an
 * absolute path in it must never be turned into a URL.
 */
function findReportArtifact(build, fileName = CI_REPORT_FILENAME) {
  const artifacts = Array.isArray(build?.artifacts) ? build.artifacts : [];
  const match = artifacts.find((artifact) => String(artifact?.fileName || '') === fileName)
    || artifacts.find((artifact) => String(artifact?.relativePath || '').endsWith(`/${fileName}`));
  if (!match) return null;
  const relative = String(match.relativePath || match.fileName || '');
  if (!relative || relative.startsWith('/') || /^[A-Za-z]:/.test(relative)) return null;
  if (relative.split('/').some((segment) => segment === '..')) return null;
  return relative;
}

/** The artefact download URL for a specific build. */
function artifactUrl(baseUrl, job, buildNumber, relativePath) {
  const build = Number(buildNumber);
  if (!Number.isInteger(build) || build <= 0) throw new Error('Numéro de build invalide.');
  const safe = String(relativePath).split('/').map((segment) => encodeURIComponent(segment)).join('/');
  return `${normalizeJenkinsUrl(baseUrl)}/${jenkinsJobPath(job)}/${build}/artifact/${safe}`;
}

/**
 * Fetches raw text from Jenkins, size-capped.
 *
 * The cap is enforced while the body streams: reading an unbounded artefact into
 * memory first and checking afterwards would already have done the damage.
 */
function requestJenkinsText(target, { user = '', token = '', timeoutMs = 15000, maxBytes = MAX_CI_REPORT_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(target); } catch { return reject(new Error('URL Jenkins invalide.')); }
    const transport = url.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json, text/plain' };
    if (token) headers.authorization = `Basic ${Buffer.from(`${user || 'security-center'}:${token}`).toString('base64')}`;
    const request = transport.request(url, { method: 'GET', headers, timeout: timeoutMs }, (response) => {
      const status = response.statusCode || 500;
      if (status === 401) { response.destroy(); return reject(new Error('Jenkins a refusé l’authentification. Vérifiez l’utilisateur et le jeton.')); }
      if (status === 403) { response.destroy(); return reject(new Error('Jenkins a refusé l’accès à cette ressource.')); }
      if (status === 404) { response.destroy(); return reject(new Error('Artefact introuvable sur ce build.')); }
      if (status >= 400) { response.destroy(); return reject(new Error(`Jenkins a répondu HTTP ${status}.`)); }
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          response.destroy();
          return reject(new Error(`Artefact trop volumineux (plus de ${Math.round(maxBytes / 1024)} Kio).`));
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    request.on('timeout', () => request.destroy(new Error('Jenkins ne répond pas.')));
    request.on('error', (error) => reject(new Error(scrubJenkinsError(error.message))));
    request.end();
  });
}

/**
 * Retrieves and validates the CI report of a build.
 *
 * A build with no report is `NOT_REPORTED` — a normal situation for a pipeline
 * that does not run Security Center — and never `ERROR`, which is reserved for a
 * Jenkins or transport failure. A report that exists but does not validate is
 * `INVALID`, with the reason, because silently ignoring it would leave the page
 * showing nothing while evidence sat on the server.
 */
async function fetchCiReport({
  baseUrl, job, build, user = '', token = '', timeoutMs = 15000,
  requestText = requestJenkinsText, fileName = CI_REPORT_FILENAME
} = {}) {
  const relative = findReportArtifact(build, fileName);
  if (!relative) return { state: REPORT_STATE.NOT_REPORTED, report: null, reason: '', artifactPath: null };
  if (!Number.isInteger(Number(build?.number))) {
    return { state: REPORT_STATE.NOT_REPORTED, report: null, reason: 'Numéro de build inconnu.', artifactPath: relative };
  }
  try {
    const text = await requestText(artifactUrl(baseUrl, job, build.number, relative), { user, token, timeoutMs });
    const validation = validateCiReport(text);
    if (!validation.ok) return { state: REPORT_STATE.INVALID, report: null, reason: validation.reason, artifactPath: relative };
    return { state: REPORT_STATE.REPORTED, report: validation.report, reason: '', artifactPath: relative };
  } catch (error) {
    return { state: REPORT_STATE.UNAVAILABLE, report: null, reason: scrubJenkinsError(error.message), artifactPath: relative };
  }
}

/**
 * Three-way commit identity.
 *
 * The workspace, the build and the report must agree. A build whose report was
 * produced from a different commit is `INCONSISTENT`: something republished an
 * artefact, and its verdict cannot be attributed to this build — let alone to the
 * workspace.
 */
function reportIdentity({ workspaceCommit = '', buildCommit = '', reportCommit = '' } = {}) {
  const workspace = commitCorrelation(workspaceCommit, buildCommit);
  const buildVsReport = commitCorrelation(buildCommit, reportCommit);
  return {
    workspaceMatch: workspace.match,
    buildReportMatch: buildVsReport.match,
    // Only a proven disagreement is inconsistent. An unknown commit is unknown.
    inconsistent: buildVsReport.match === COMMIT_MATCH.DIFFERENT,
    workspaceCommit: workspace.workspaceCommit,
    buildCommit: workspace.buildCommit || buildVsReport.workspaceCommit,
    reportCommit: buildVsReport.buildCommit
  };
}

/**
 * Non-destructive connection test.
 *
 * Reads job metadata and nothing else: no build is triggered, no configuration is
 * written. Each failure maps to a state the developer can act on rather than to a
 * raw Jenkins error page.
 */
async function testJenkinsConnection({ baseUrl = '', job = '', user = '', token = '', timeoutMs = 10000, request = requestJenkins } = {}) {
  if (!String(baseUrl).trim()) return { state: CONNECTION_STATE.ERROR, message: 'Renseignez l’URL de Jenkins.' };
  if (!String(job).trim()) return { state: CONNECTION_STATE.ERROR, message: 'Renseignez le nom du job Jenkins.' };
  let target;
  try {
    target = `${normalizeJenkinsUrl(baseUrl)}/${jenkinsJobPath(job)}/api/json?tree=name,url`;
  } catch (error) {
    return { state: CONNECTION_STATE.ERROR, message: error.message };
  }
  try {
    const payload = await request(target, { user, token, timeoutMs });
    return {
      state: CONNECTION_STATE.CONNECTED,
      message: `Connecté au job ${payload?.name || job}.`,
      authenticated: Boolean(token)
    };
  } catch (error) {
    const message = scrubJenkinsError(error.message);
    if (/refusé l’authentification/i.test(message)) return { state: CONNECTION_STATE.AUTH_FAILED, message };
    if (/refusé l’accès/i.test(message)) return { state: CONNECTION_STATE.FORBIDDEN, message };
    if (/introuvable/i.test(message)) return { state: CONNECTION_STATE.JOB_NOT_FOUND, message };
    if (/ne répond pas|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|timeout/i.test(message)) {
      return { state: CONNECTION_STATE.UNREACHABLE, message };
    }
    return { state: CONNECTION_STATE.ERROR, message };
  }
}

module.exports = {
  DELIVERY_STATE, COMMIT_MATCH, BUILD_TREE, BUILDS_TREE, REPORT_STATE, CONNECTION_STATE,
  normalizeJenkinsUrl, jenkinsJobPath, lastBuildUrl, jobUrl, artifactUrl,
  requestJenkins, requestJenkinsText, buildStatusFrom, commitCorrelation, deliveryStatusFrom,
  fetchDeliveryStatus, scrubJenkinsError,
  findReportArtifact, fetchCiReport, reportIdentity, testJenkinsConnection
};
