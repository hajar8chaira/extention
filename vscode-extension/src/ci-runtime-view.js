'use strict';

/**
 * The CI Runtime card of the Jenkins workspace.
 *
 * It lives outside the generic Security Delivery renderer, which names no
 * provider: the extension decides where the card goes, and the renderer only
 * hosts a panel and posts its fields. There is no field for a key — only the ID
 * of the Jenkins credential that holds it.
 */

const { CI_RUNTIME_STEPS, RUNTIME_LABEL } = require('./ci-runtime');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function formatTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('fr-FR');
}

function renderCiRuntimeCard({ configuration = {}, defaults = {}, status = null, running = false } = {}) {
  const value = (id) => escapeHtml(configuration[id] || defaults[id] || '');
  const input = (id, label, { placeholder = '', hint = '', type = 'text', required = true } = {}) => `<div class="field"><label for="ci-runtime-${id}">${escapeHtml(label)}${required ? ' *' : ''}</label>
<input id="ci-runtime-${id}" data-panel-field="${id}" type="${type}" autocomplete="off" spellcheck="false" value="${value(id)}" placeholder="${escapeHtml(placeholder)}">${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</div>`;
  const steps = Array.isArray(status?.steps) && status.steps.length
    ? status.steps
    : CI_RUNTIME_STEPS.map((step) => ({ ...step, state: 'pending', summary: 'Not checked', detail: '' }));
  const rows = steps.map((step) => `<li class="panel-step ${escapeHtml(step.state)}" data-step="${escapeHtml(step.id)}"><strong>${escapeHtml(step.label)}:</strong> <span>${escapeHtml(step.summary)}</span>${step.detail ? `<small>${escapeHtml(step.detail)}</small>` : ''}</li>`).join('');
  return `<section class="delivery-config-panel workspace-panel" data-panel="ci-runtime" aria-label="CI Runtime">
<div class="provider-head-copy"><span class="field-label">CI Runtime</span><h3>Managed Jenkins runtime</h3><p>Security Center creates and verifies the Jenkins SSH agent that runs the analysis (label ${escapeHtml(RUNTIME_LABEL)}). Separate from deployment.</p></div>
<div class="config-section">
  <span class="config-section-title">Runtime</span>
  <div class="delivery-fields">
${input('jenkinsUrl', 'Jenkins URL', { type: 'url', placeholder: 'http://jenkins:8080' })}
${input('job', 'Jenkins Job', { placeholder: 'security-pipeline' })}
${input('host', 'Runtime Host', { placeholder: 'ci-runtime.internal', hint: 'The host Jenkins reaches over SSH to run the analysis.' })}
${input('sshUser', 'SSH User', { placeholder: 'jenkins' })}
${input('credentialId', 'Jenkins Credential ID', { placeholder: 'scenter-runtime-ssh', hint: 'ID of an "SSH Username with private key" credential. The private key stays in Jenkins Credentials: Security Center stores only this ID.' })}
  </div>
</div>
<details class="advanced"><summary><span>Advanced</span><small>SSH port and agent directory</small></summary><div class="delivery-fields">
${input('port', 'SSH port', { placeholder: '22', required: false })}
${input('remoteRoot', 'Remote root', { placeholder: '/home/<ssh user>/scenter-agent', required: false })}
</div></details>
<ul class="panel-status" aria-live="polite">${rows}</ul>
${status?.checkedAt ? `<small class="panel-checked">Last check: ${escapeHtml(formatTimestamp(status.checkedAt))}</small>` : ''}
<div class="actions">
<button data-action="ciRuntimeConfigure"${running ? ' disabled' : ''}>${running ? 'Configuring…' : 'Configure CI Runtime'}</button>
<button class="secondary" data-action="ciRuntimeSave"${running ? ' disabled' : ''}>Save</button>
</div></section>`;
}

module.exports = { renderCiRuntimeCard };
