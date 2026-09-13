'use strict';

/**
 * The CI Runtime card of the Jenkins workspace.
 *
 * It lives outside the generic Security Delivery renderer, which names no
 * provider: the extension decides where the card goes, and the renderer only
 * hosts a panel and posts its fields. There is no field for a key — only the ID
 * of the Jenkins credential that holds it — and no field for a password.
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

const PREREQUISITE_CLASS = Object.freeze({ ready: 'ready', missing: 'failed', admin: 'failed', blocked: 'skipped', unknown: 'pending' });
const INSTALL_ACTION = Object.freeze({ java: 'ciRuntimeInstallJava', node: 'ciRuntimeInstallNode' });

/** Prerequisites one by one, what Security Center can install, and what needs an administrator. */
function renderPrerequisites(status, running) {
  const items = Array.isArray(status?.prerequisites) ? status.prerequisites : [];
  if (!items.length) return '';
  const disabled = running ? ' disabled' : '';
  const rows = items.map((item) => `<li class="panel-step ${escapeHtml(PREREQUISITE_CLASS[item.state] || 'pending')}" data-prerequisite="${escapeHtml(item.id)}"><strong>${escapeHtml(item.label)}</strong> <span>${escapeHtml(item.summary)}</span>${item.state === 'missing' && INSTALL_ACTION[item.id] ? ` <button class="secondary" data-action="${INSTALL_ACTION[item.id]}"${disabled}>Install</button>` : ''}${item.detail ? `<small>${escapeHtml(item.detail)}</small>` : ''}</li>`).join('');
  const results = Array.isArray(status.installResults) && status.installResults.length
    ? `<ul class="panel-status" data-install-results>${status.installResults.map((entry) => `<li class="panel-step ${entry.ok ? 'ready' : 'failed'}"><strong>${escapeHtml(entry.label)}</strong> <span>${entry.ok ? 'Installed' : 'Installation failed'}</span><small>${escapeHtml(entry.detail)}</small></li>`).join('')}</ul>`
    : '';
  const plan = Array.isArray(status.installPlan) && status.installPlan.length
    ? `<div class="config-section" data-install-plan><span class="config-section-title">Managed installation</span>
<ul class="panel-status">${status.installPlan.map((item) => `<li class="panel-step pending"><strong>${escapeHtml(item.label)}</strong> <span>${escapeHtml(`${item.distribution} ${item.version} (${item.platform})`)}</span><small>${escapeHtml(`Installs into ${item.destination} on ${item.host}, as ${item.user}. SHA-256 ${item.sha256} is verified before anything is unpacked.`)}</small></li>`).join('')}</ul>
<div class="actions"><button data-action="ciRuntimePrepare"${disabled}>Prepare runtime</button></div></div>`
    : '';
  const admin = status.admin?.required
    ? `<div class="config-section" data-admin-required><span class="config-section-title">Administrator action required</span>
<ul class="panel-status">${(status.admin.reasons || []).map((reason) => `<li class="panel-step failed"><small>${escapeHtml(reason)}</small></li>`).join('')}</ul>
<div class="actions"><button class="secondary" data-action="ciRuntimeAdminInstructions">Show manual instructions</button>${status.admin.sudo && status.admin.actions?.length ? `<button class="secondary" data-action="ciRuntimeAdminApply"${disabled}>Apply admin setup</button>` : ''}</div></div>`
    : '';
  return `<div class="config-section" data-prerequisites><span class="config-section-title">CI Runtime prerequisites</span><ul class="panel-status">${rows}</ul></div>${results}${plan}${admin}`;
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
${renderPrerequisites(status, running)}
${status?.checkedAt ? `<small class="panel-checked">Last check: ${escapeHtml(formatTimestamp(status.checkedAt))}</small>` : ''}
<div class="actions">
<button data-action="ciRuntimeConfigure"${running ? ' disabled' : ''}>${running ? 'Configuring…' : 'Configure CI Runtime'}</button>
<button class="secondary" data-action="ciRuntimeSave"${running ? ' disabled' : ''}>Save</button>
</div></section>`;
}

module.exports = { renderCiRuntimeCard, renderPrerequisites };
