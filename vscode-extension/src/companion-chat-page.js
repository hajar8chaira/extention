'use strict';

/**
 * The full Security Companion conversation.
 *
 * A larger surface for the same assistant the rail already shows — same model,
 * same context, same safety contract. It exists because a two-line card is a bad
 * place to read an explanation, not because it does anything the card cannot.
 *
 * No account, no profile, no history beyond the session. The mascot appears once,
 * in the header, and every asset is local.
 */

const { renderSecurityCenterShell } = require('./security-center-shell');
const { CHAT_STATE, ROLE } = require('./companion-chat');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

/** Assistant prose is plain text: newlines and bullets only, never markup. */
function renderBody(content) {
  return escapeHtml(content)
    .split(/\n{2,}/)
    .map((block) => `<p>${block.split('\n').join('<br>')}</p>`)
    .join('');
}

function renderMessage(message) {
  const isUser = message.role === ROLE.USER;
  return `<article class="chat-message ${isUser ? 'from-user' : 'from-assistant'}">
      <span class="chat-author">${isUser ? 'Vous' : 'Security Companion'}</span>
      <div class="chat-body">${renderBody(message.content)}</div>
    </article>`;
}

function chatCss() {
  return `
  .chat-layout { display: grid; gap: 14px; max-width: 860px; }
  .chat-context { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); background: var(--sc-primary-soft); }
  .chat-context .chat-context-mark { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 50%; overflow: hidden; background: var(--sc-surface); flex: none; }
  .chat-context img { width: 100%; height: 100%; object-fit: cover; }
  .chat-context dl { display: grid; gap: 1px; margin: 0; min-width: 0; }
  .chat-context dt { color: var(--sc-primary); font-size: 9px; font-weight: 900; letter-spacing: .7px; text-transform: uppercase; }
  .chat-context dd { margin: 0; color: var(--sc-text); font-size: 12px; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .chat-context small { color: var(--sc-muted); font-size: 11px; }
  .chat-thread { display: grid; gap: 10px; min-height: 220px; padding: 4px; }
  .chat-message { display: grid; gap: 4px; max-width: 84%; padding: 11px 14px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-lg); background: var(--sc-surface); }
  .chat-message.from-user { justify-self: end; border-color: color-mix(in srgb, var(--sc-primary) 34%, var(--sc-border)); background: var(--sc-primary-soft); }
  .chat-author { color: var(--sc-muted); font-size: 9px; font-weight: 900; letter-spacing: .6px; text-transform: uppercase; }
  .chat-body { color: var(--sc-text); font-size: 12px; line-height: 1.55; }
  .chat-body p { margin: 0 0 7px; }
  .chat-body p:last-child { margin-bottom: 0; }
  .chat-empty { padding: 20px; border: 1px dashed var(--sc-border); border-radius: var(--sc-radius-md); color: var(--sc-muted); font-size: 12px; text-align: center; }
  .chat-quick { display: flex; flex-wrap: wrap; gap: 7px; }
  .chat-quick button { padding: 6px 11px; border: 1px solid var(--sc-border); border-radius: 999px; background: var(--sc-surface); color: var(--sc-text); font: 600 11px var(--vscode-font-family); cursor: pointer; }
  .chat-quick button:hover { border-color: var(--sc-primary); color: var(--sc-primary); }
  .chat-composer { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; }
  .chat-composer textarea { min-height: 62px; padding: 10px 12px; border: 1px solid var(--sc-input-border); border-radius: var(--sc-radius-md); background: var(--sc-input-bg); color: var(--sc-input-text); font: 12px var(--vscode-font-family); resize: vertical; }
  .chat-actions { display: grid; gap: 6px; align-content: start; }
  .chat-state { display: flex; align-items: center; gap: 8px; color: var(--sc-muted); font-size: 11px; }
  .chat-state.error { color: var(--sc-danger); }
  .chat-caveat { color: var(--sc-muted); font-size: 11px; line-height: 1.5; }
  @media (max-width: 620px) { .chat-composer { grid-template-columns: minmax(0, 1fr); } .chat-message { max-width: 100%; } }`;
}

function chatScript() {
  return `
    const vscode = window.__scShellApi || acquireVsCodeApi();
    const input = document.getElementById('chat-input');
    const send = document.getElementById('chat-send');
    const ask = function (text) {
      const question = String(text || (input ? input.value : '')).trim();
      // Un envoi en cours desactive le bouton : pas de double soumission.
      if (!question || (send && send.disabled)) return;
      if (input) input.value = '';
      vscode.postMessage({ type: 'companionChat', action: 'ask', question: question });
    };
    if (send) send.onclick = function () { ask(); };
    if (input) input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); ask(); }
    });
    document.querySelectorAll('[data-chat-quick]').forEach(function (button) {
      button.onclick = function () { ask(button.dataset.chatQuick); };
    });
    document.querySelectorAll('[data-chat-action]').forEach(function (button) {
      button.onclick = function () { vscode.postMessage({ type: 'companionChat', action: button.dataset.chatAction }); };
    });
    const thread = document.querySelector('.chat-thread');
    if (thread) thread.scrollIntoView({ block: 'end' });`;
}

/** The routed action offered when a repair was requested. Never automatic. */
function renderRouteAction(route) {
  if (!route) return '';
  return `<div class="chat-quick"><button data-chat-action="${escapeHtml(route.action)}">${escapeHtml(route.label)}</button></div>`;
}

function renderCompanionChatHtml(model = {}, nonce = '', theme = 'light') {
  const messages = Array.isArray(model.messages) ? model.messages : [];
  const quick = Array.isArray(model.quickQuestions) ? model.quickQuestions : [];
  const indicator = model.indicator || { label: 'Workspace overview', detail: '' };
  const state = model.state || CHAT_STATE.IDLE;
  const thinking = state === CHAT_STATE.THINKING;

  const stateLine = state === CHAT_STATE.ERROR
    ? `<div class="chat-state error">${escapeHtml(model.error || 'Assistant IA local indisponible.')}</div>`
    : thinking
      ? '<div class="chat-state"><span class="spinner" aria-hidden="true"></span>Le Companion réfléchit…</div>'
      : state === CHAT_STATE.CANCELLED
        ? '<div class="chat-state">Réponse annulée.</div>'
        : '';

  return renderSecurityCenterShell({
    surface: 'companion-chat',
    brandLogoUri: model.brandLogoUri || '',
    cspSource: model.cspSource || '',
    nonce,
    theme,
    title: 'Security Companion',
    subtitle: 'Poser une question sur ce que Security Center a réellement observé',
    headerActions: messages.length ? '<button class="secondary" data-chat-action="clear">Effacer la conversation</button>' : '',
    content: `
  <div class="chat-layout">
    <section class="chat-context">
      ${model.mascotUri ? `<span class="chat-context-mark"><img src="${escapeHtml(model.mascotUri)}" alt=""></span>` : ''}
      <dl><dt>Contexte</dt><dd>${escapeHtml(indicator.label)}</dd></dl>
      ${indicator.detail ? `<small>${escapeHtml(indicator.detail)}</small>` : ''}
    </section>

    <section class="chat-thread">
      ${messages.length
        ? messages.map(renderMessage).join('')
        : '<div class="chat-empty">Posez une question sur le finding, le scanner ou l’analyse en cours. Le Companion répond à partir de ce que Security Center a réellement observé.</div>'}
    </section>

    ${stateLine}
    ${renderRouteAction(model.route)}

    ${quick.length ? `<section class="chat-quick">${quick.map((question) => `<button data-chat-quick="${escapeHtml(question)}">${escapeHtml(question)}</button>`).join('')}</section>` : ''}

    <section class="chat-composer">
      <textarea id="chat-input" placeholder="Poser une question…" ${thinking ? 'disabled' : ''}></textarea>
      <div class="chat-actions">
        <button id="chat-send" ${thinking ? 'disabled' : ''}>Envoyer</button>
        ${thinking && model.cancellable ? '<button class="secondary" data-chat-action="cancel">Annuler</button>' : ''}
      </div>
    </section>

    <p class="chat-caveat">Le Companion explique et oriente. Il ne modifie aucun fichier : toute correction passe par la génération de patch, sa validation et votre confirmation explicite.</p>
  </div>`,
    styles: chatCss(),
    script: chatScript()
  });
}

module.exports = { renderCompanionChatHtml, chatCss, escapeHtml };
