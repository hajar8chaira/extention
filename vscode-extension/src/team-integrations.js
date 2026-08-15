function conciseFinding(finding) {
  return {
    id: String(finding.id || finding.ruleId || 'finding'),
    title: String(finding.title || 'Vulnérabilité confirmée'),
    tool: String(finding.tool || 'Security Center'),
    severity: String(finding.rawSeverity || finding.severity || 'UNKNOWN').toUpperCase(),
    location: finding.file ? `${finding.file}:${Number(finding.startLine || 0) + 1}` : String(finding.endpoint || 'runtime'),
    cwe: String(finding.cwe || '')
  };
}

function slackPayload(finding, projectName = 'workspace') {
  const item = conciseFinding(finding);
  return {
    text: `[Security Center] ${item.severity} — ${item.title}`,
    blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `*${item.severity} — ${item.title}*\n${item.tool} · \`${item.location}\`${item.cwe ? ` · ${item.cwe}` : ''}\nProjet : ${projectName}` } }]
  };
}

function adfParagraph(text) {
  return { type: 'paragraph', content: [{ type: 'text', text: String(text) }] };
}

function jiraPayload(finding, projectKey, issueType = 'Task') {
  const item = conciseFinding(finding);
  return { fields: {
    project: { key: projectKey },
    issuetype: { name: issueType },
    summary: `[${item.severity}] ${item.title}`.slice(0, 255),
    description: { type: 'doc', version: 1, content: [
      adfParagraph(`Scanner : ${item.tool}`), adfParagraph(`Emplacement : ${item.location}`),
      adfParagraph(`Identifiant : ${item.id}`), ...(item.cwe ? [adfParagraph(`CWE : ${item.cwe}`)] : [])
    ] },
    labels: ['security-center', item.severity.toLowerCase()]
  } };
}

function integrationUrl(value, kind, allowLocal = false) {
  const target = new URL(value);
  const local = ['127.0.0.1', 'localhost', '::1'].includes(target.hostname);
  if (target.protocol !== 'https:' && !(allowLocal && target.protocol === 'http:' && local)) {
    throw new Error(`${kind} exige une URL HTTPS.`);
  }
  return target;
}

async function postJson(url, payload, headers = {}, fetchImpl = fetch, allowLocal = false) {
  const target = integrationUrl(url, 'L’intégration', allowLocal);
  const response = await fetchImpl(target, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) });
  const body = await response.text();
  if (!response.ok) throw new Error(`HTTP ${response.status}${body ? ` — ${body.slice(0, 300)}` : ''}`);
  try { return body ? JSON.parse(body) : {}; } catch { return { text: body }; }
}

function sendSlack(webhookUrl, finding, projectName, options = {}) {
  return postJson(webhookUrl, slackPayload(finding, projectName), {}, options.fetchImpl, options.allowLocal);
}

function createJiraIssue({ baseUrl, email, token, projectKey, issueType }, finding, options = {}) {
  const target = integrationUrl(baseUrl, 'Jira', options.allowLocal);
  const endpoint = new URL('/rest/api/3/issue', target).toString();
  const authorization = Buffer.from(`${email}:${token}`, 'utf8').toString('base64');
  return postJson(endpoint, jiraPayload(finding, projectKey, issueType), { accept: 'application/json', authorization: `Basic ${authorization}` }, options.fetchImpl, options.allowLocal);
}

module.exports = { conciseFinding, slackPayload, jiraPayload, integrationUrl, postJson, sendSlack, createJiraIssue };
