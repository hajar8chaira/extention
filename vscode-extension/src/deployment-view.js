'use strict';

/**
 * The Deployment card of the Jenkins workspace, below the CI Runtime card.
 *
 * A separate profile: nothing here is shared with the runtime card, even when
 * both point at the same host. There is no field for a key or a password — only
 * the ID of the Jenkins credential that holds the key.
 */

const { DEPLOYMENT_STEPS, DEPLOYMENT_TYPE_LABEL } = require('./deployment');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function formatTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('fr-FR');
}

function renderDeploymentCard({ configuration = {}, status = null, running = false } = {}) {
  const value = (id) => escapeHtml(configuration[id] || '');
  const input = (id, label, { placeholder = '', hint = '', type = 'text', required = true } = {}) => `<div class="field"><label for="deployment-${id}">${escapeHtml(label)}${required ? ' *' : ''}</label>
<input id="deployment-${id}" data-panel-field="${id}" type="${type}" autocomplete="off" spellcheck="false" value="${value(id)}" placeholder="${escapeHtml(placeholder)}">${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</div>`;
  const steps = Array.isArray(status?.steps) && status.steps.length
    ? status.steps
    : DEPLOYMENT_STEPS.map((step) => ({ ...step, state: 'pending', summary: 'Not checked', detail: '' }));
  const rows = steps.map((step) => `<li class="panel-step ${escapeHtml(step.state)}" data-step="${escapeHtml(step.id)}"><strong>${escapeHtml(step.label)}:</strong> <span>${escapeHtml(step.summary)}</span>${step.detail ? `<small>${escapeHtml(step.detail)}</small>` : ''}</li>`).join('');
  const disabled = running ? ' disabled' : '';
  return `<section class="delivery-config-panel workspace-panel" data-panel="deployment" aria-label="Deployment">
<div class="provider-head-copy"><span class="field-label">Deployment</span><h3>${escapeHtml(DEPLOYMENT_TYPE_LABEL)}</h3><p>After a Policy Gate PASS, Jenkins builds the analysed commit on this host and replaces the container, then runs the health check. On BLOCK nothing is deployed. Separate from the CI Runtime.</p></div>
<div class="config-section">
  <span class="config-section-title">Target</span>
  <div class="delivery-fields">
${input('host', 'Deployment Host', { placeholder: 'app.internal', hint: 'The host Jenkins reaches over SSH to run the container.' })}
${input('sshUser', 'SSH User', { placeholder: 'deploy' })}
${input('credentialId', 'Jenkins Credential ID', { placeholder: 'scenter-deploy-ssh', hint: 'ID of an "SSH Username with private key" credential. The private key stays in Jenkins Credentials: Security Center stores only this ID.' })}
  </div>
</div>
<div class="config-section">
  <span class="config-section-title">Container</span>
  <div class="delivery-fields">
${input('containerName', 'Container Name', { placeholder: 'my-app' })}
${input('containerPort', 'Container Port', { type: 'number', placeholder: '8080', hint: 'The port the application listens on inside the container.' })}
${input('publishedPort', 'Published Port', { type: 'number', placeholder: '8080', hint: 'The port opened on the deployment host.' })}
${input('healthCheckUrl', 'Health Check URL', { type: 'url', placeholder: 'http://app.internal:8080/' })}
  </div>
</div>
<details class="advanced"><summary><span>Advanced</span><small>SSH port</small></summary><div class="delivery-fields">
${input('port', 'SSH Port', { type: 'number', placeholder: '22', required: false })}
</div></details>
<ul class="panel-status" aria-live="polite">${rows}</ul>
${status?.checkedAt ? `<small class="panel-checked">Last check: ${escapeHtml(formatTimestamp(status.checkedAt))}</small>` : ''}
<div class="actions">
<button data-action="deploymentConfigure"${disabled}>${running ? 'Configuring…' : 'Configure Deployment'}</button>
<button class="secondary" data-action="deploymentSave"${disabled}>Save</button>
</div></section>`;
}

module.exports = { renderDeploymentCard };
