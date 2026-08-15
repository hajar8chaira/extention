const test = require('node:test');
const assert = require('node:assert/strict');
const { slackPayload, jiraPayload, sendSlack, createJiraIssue } = require('../src/team-integrations');

const finding = { id: 'semgrep:1', title: 'Injection possible', tool: 'Semgrep', rawSeverity: 'HIGH', file: 'src/app.js', startLine: 4, cwe: 'CWE-89' };

test('construit des notifications sans données secrètes', () => {
  assert.match(slackPayload(finding, 'demo').text, /HIGH/);
  const jira = jiraPayload(finding, 'SEC', 'Bug');
  assert.equal(jira.fields.project.key, 'SEC');
  assert.equal(jira.fields.description.type, 'doc');
  assert.doesNotMatch(JSON.stringify(jira), /token|password|authorization/i);
});

test('envoie Slack et Jira avec les contrats HTTP attendus', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: url.toString(), options });
    return { ok: true, status: 200, text: async () => '{"key":"SEC-1"}' };
  };
  await sendSlack('http://127.0.0.1:9999/hook', finding, 'demo', { fetchImpl, allowLocal: true });
  await createJiraIssue({ baseUrl: 'http://127.0.0.1:9999', email: 'dev@example.test', token: 'secret-token', projectKey: 'SEC', issueType: 'Bug' }, finding, { fetchImpl, allowLocal: true });
  assert.equal(calls.length, 2);
  assert.match(calls[1].url, /\/rest\/api\/3\/issue$/);
  assert.match(calls[1].options.headers.authorization, /^Basic /);
  assert.doesNotMatch(calls[1].options.body, /secret-token/);
});

test('refuse les intégrations externes non HTTPS', async () => {
  await assert.rejects(() => sendSlack('http://example.com/hook', finding, 'demo'), /HTTPS/);
});
