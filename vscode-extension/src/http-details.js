function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function themeClass(theme) {
  return theme === 'dark' ? 'theme-dark' : 'theme-light';
}

const sharedThemeCss = `
  body.theme-light { --vscode-foreground:#3f4650; --vscode-descriptionForeground:#6d7480; --vscode-editor-background:#f8f9fb; --vscode-textCodeBlock-background:#eef0f4; --vscode-widget-border:#d8dce3; --vscode-button-background:#4d78d2; --vscode-button-foreground:#fff; --vscode-testing-iconPassed:#388a4b; --vscode-diffEditor-insertedTextBackground:#e4f2e7; --vscode-testing-iconFailed:#c84d43; --vscode-diffEditor-removedTextBackground:#f7e4e2; --vscode-focusBorder:#4d78d2; color-scheme:light; }
  body.theme-dark { color-scheme:dark; }
`;

function renderSafeHttpRequestHtml(detail, nonce, theme = 'light') {
  const rows = (items, empty = 'Aucune donnée') => items?.length
    ? `<pre>${escapeHtml(items.map((item) => `${item.name}: ${item.value}`).join('\n'))}</pre>`
    : `<p class="muted">${empty}</p>`;
  const findings = (detail.linkedFindings || []).map((finding) => `<div class="finding"><strong>${escapeHtml(finding.severity)}</strong><span>${escapeHtml(finding.title)}</span><small>${escapeHtml(finding.source)}</small><button data-finding-index="${finding.index}">Ouvrir →</button></div>`).join('') || '<p class="muted">Aucun finding lié.</p>';
  return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style nonce="${nonce}">
  body{color:var(--vscode-foreground);background:var(--vscode-editor-background);font-family:var(--vscode-font-family);padding:18px;max-width:1050px;margin:auto}${sharedThemeCss}h1{font-size:22px;overflow-wrap:anywhere}h2{font-size:14px;margin-top:22px}.grid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:7px 12px;border:1px solid var(--vscode-widget-border);border-radius:6px;padding:12px}.label,.muted,small{color:var(--vscode-descriptionForeground)}code,pre{background:var(--vscode-textCodeBlock-background);padding:7px;border-radius:4px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow:auto}.finding{display:grid;grid-template-columns:60px minmax(0,1fr) 90px auto;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--vscode-widget-border)}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;border-radius:3px;padding:6px 9px;cursor:pointer}.back{margin-bottom:10px}.actions{display:flex;flex-wrap:wrap;gap:7px;margin:18px 0}@media(max-width:650px){body{padding:12px}.grid,.finding{grid-template-columns:1fr}.label{font-weight:700}}
  </style></head><body class="${themeClass(theme)}"><button id="back" class="back">← Retour à Dynamic Security</button><h1>${escapeHtml(detail.method)} ${escapeHtml(detail.path || detail.url)}</h1><div class="grid"><span class="label">URL</span><code>${escapeHtml(detail.url)}</code><span class="label">Horodatage</span><span>${escapeHtml(detail.timestamp || 'Non disponible')}</span><span class="label">Source</span><span>${escapeHtml(detail.source)}</span><span class="label">Durée</span><span>${escapeHtml(detail.duration)}</span></div><h2>En-têtes de la requête</h2>${rows(detail.headers)}<h2>Paramètres</h2>${rows((detail.parameters || []).map((item) => ({name:`${item.location} · ${item.name}`,value:item.value})))}<h2>Corps assaini de la requête</h2><pre>${escapeHtml(detail.requestBody || 'Aucun corps')}</pre><h2>Réponse</h2><div class="grid"><span class="label">Statut</span><span>${escapeHtml(detail.statusCode || '—')}</span><span class="label">Type</span><span>${escapeHtml(detail.responseType)}</span></div><h2>En-têtes de réponse</h2>${rows(detail.responseHeaders)}<h2>Aperçu sécurisé</h2><pre>${escapeHtml(detail.responsePreview || 'Aucun corps')}</pre><h2>Findings liés</h2>${findings}<pre id="safe-request" hidden>${escapeHtml(detail.safeRequest || '')}</pre><div class="actions"><button id="copy">Copier la requête assainie</button><button id="replay">Rejouer la requête</button></div><script nonce="${nonce}">const vscode=acquireVsCodeApi();document.getElementById('back').addEventListener('click',()=>vscode.postMessage({type:'back'}));document.querySelectorAll('[data-finding-index]').forEach(b=>b.addEventListener('click',()=>vscode.postMessage({type:'finding',index:Number(b.dataset.findingIndex)})));document.getElementById('copy').addEventListener('click',()=>navigator.clipboard.writeText(document.getElementById('safe-request').textContent));document.getElementById('replay').addEventListener('click',()=>vscode.postMessage({type:'replay'}));</script></body></html>`;
}

function renderHttpReplayHtml(scenario, replay, nonce, linkedFinding, theme = 'light') {
  const comparison = replay.comparison || {};
  const verdict = comparison.statusChanged || comparison.bodyChanged ? 'Réponse modifiée' : 'Réponse stable';
  const verdictClass = comparison.statusChanged || comparison.bodyChanged ? 'changed' : 'stable';
  const duration = Number.isFinite(replay.durationMs) ? `${replay.durationMs} ms` : 'non disponible';
  const linkedAfter = Number.isInteger(replay.linkedFindingsAfter) ? replay.linkedFindingsAfter : 'non évalué — aucun nouveau scan';
  return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style nonce="${nonce}">
  body{color:var(--vscode-foreground);background:var(--vscode-editor-background);font-family:var(--vscode-font-family);padding:18px;max-width:980px;margin:auto}${sharedThemeCss}h1{font-size:22px}h2{font-size:14px;margin-top:23px}.verdict{display:inline-block;border-radius:999px;padding:5px 10px;font-weight:700}.stable{color:var(--vscode-testing-iconPassed);background:var(--vscode-diffEditor-insertedTextBackground)}.changed{color:var(--vscode-testing-iconFailed);background:var(--vscode-diffEditor-removedTextBackground)}.grid{display:grid;grid-template-columns:170px 1fr;gap:8px 12px;border:1px solid var(--vscode-widget-border);border-radius:7px;padding:12px}.label{color:var(--vscode-descriptionForeground)}code,pre{background:var(--vscode-textCodeBlock-background);border-radius:4px;padding:5px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:240px;overflow:auto}.notice{color:var(--vscode-descriptionForeground);border-left:2px solid var(--vscode-focusBorder);padding-left:9px;line-height:1.45}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;border-radius:3px;padding:6px 9px;cursor:pointer;margin-bottom:10px}@media(max-width:520px){body{padding:12px}.grid{grid-template-columns:1fr}.label{margin-top:5px;font-weight:700}}
  </style></head><body class="${themeClass(theme)}"><button id="back">← Retour à Dynamic Security</button><h1>${escapeHtml(scenario.name)}</h1><p><span class="verdict ${verdictClass}">${verdict}</span></p>${linkedFinding ? `<p>Preuve liée à la correction : <strong>${escapeHtml(linkedFinding.title)}</strong> <small>(${escapeHtml(linkedFinding.tool)} · statut ${escapeHtml(linkedFinding.triageStatus)})</small></p>` : ''}<h2>Requête rejouée</h2><div class="grid"><div class="label">Méthode</div><div><code>${escapeHtml(scenario.request.method)}</code></div><div class="label">URL</div><div><code>${escapeHtml(scenario.request.url)}</code></div><div class="label">Source</div><div>${escapeHtml(scenario.source)}</div><div class="label">En-têtes masqués</div><div>${escapeHtml((scenario.request.sensitive_headers || []).join(', ') || 'aucun')}</div></div><h2>Comparaison</h2><div class="grid"><div class="label">Statut original</div><div>${escapeHtml(comparison.originalStatusCode || 'inconnu')}</div><div class="label">Statut replay</div><div>${escapeHtml(replay.statusCode)}</div><div class="label">Statut modifié</div><div>${comparison.statusChanged ? 'oui' : 'non'}</div><div class="label">Corps modifié</div><div>${comparison.bodyChanged ? 'oui' : 'non'}</div><div class="label">Réponse modifiée</div><div>${comparison.statusChanged || comparison.bodyChanged ? 'oui' : 'non'}</div><div class="label">Durée</div><div>${escapeHtml(duration)}</div><div class="label">Findings liés avant</div><div>${escapeHtml(replay.linkedFindingsBefore ?? 'non disponible')}</div><div class="label">Findings liés après</div><div>${escapeHtml(linkedAfter)}</div></div><p class="notice"><small>Le statut HTTP et la stabilité de la réponse ne prouvent pas à eux seuls qu’une vulnérabilité est corrigée. Une validation par scan reste nécessaire.</small></p><h2>Réponse du replay</h2><pre>${escapeHtml(replay.body)}</pre><script nonce="${nonce}">const vscode=acquireVsCodeApi();document.getElementById('back').addEventListener('click',()=>vscode.postMessage({type:'back'}));</script></body></html>`;
}

/** La famille d'une méthode HTTP, pour la couleur de son badge. */
function methodTone(method) {
  const value = String(method || '').toUpperCase();
  if (value === 'GET' || value === 'HEAD') return 'read';
  if (value === 'POST') return 'create';
  if (value === 'PUT' || value === 'PATCH') return 'update';
  if (value === 'DELETE') return 'delete';
  return 'other';
}

/**
 * La confirmation affichée avant un replay HTTP.
 *
 * Elle remplace une boîte de dialogue native où la requête était déversée en
 * paragraphes. Le contenu est strictement le même aperçu assaini — méthode,
 * chemin, en-têtes, paramètres —, présenté dans une carte structurée. Cette page
 * ne décide de rien : elle renvoie seulement « confirmer » ou « annuler » à
 * l'extension, qui conserve toute la logique de replay.
 */
function renderReplayConfirmationHtml(detail, { isWrite = false, confirmLabel = 'Rejouer la requête', sensitiveHeaders = [] } = {}, nonce, theme = 'light') {
  const method = String(detail?.method || 'HTTP').toUpperCase();
  const headers = Array.isArray(detail?.headers) ? detail.headers : [];
  const parameters = Array.isArray(detail?.parameters) ? detail.parameters : [];
  const requestBody = String(detail?.requestBody || '');
  const isRedacted = (value) => String(value ?? '').includes('[REDACTED]');
  const redacted = [...new Set([
    ...headers.filter((header) => isRedacted(header.value)).map((header) => String(header.name || '').toLowerCase()),
    ...(Array.isArray(sensitiveHeaders) ? sensitiveHeaders : []).map((name) => String(name || '').toLowerCase())
  ].filter(Boolean))];
  const valueHtml = (value) => (isRedacted(value)
    ? `<span class="redacted">${escapeHtml(value)}</span>`
    : escapeHtml(value));
  const headerList = headers.length
    ? `<dl class="kv">${headers.map((header) => `<div class="kv-row"><dt>${escapeHtml(header.name)}</dt><dd>${valueHtml(header.value)}</dd></div>`).join('')}</dl>`
    : '<p class="empty">Aucun</p>';
  const parameterList = parameters.length
    ? `<dl class="kv">${parameters.map((parameter) => `<div class="kv-row"><dt><span class="location">${escapeHtml(parameter.location)}</span><span class="name">${escapeHtml(parameter.name)}</span></dt><dd>${valueHtml(parameter.value)}</dd></div>`).join('')}</dl>`
    : '<p class="empty">Aucun paramètre structuré affichable</p>';
  const redactedSummary = redacted.length
    ? `<span class="pill masked">${redacted.length} masqué${redacted.length > 1 ? 's' : ''}</span><span class="names">${escapeHtml(redacted.join(', '))}</span>`
    : '<span class="muted">Aucun</span>';
  const path = detail?.path || detail?.url || '';
  return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Confirmer le replay de la requête</title><style nonce="${nonce}">
  *{box-sizing:border-box}
  body{--sc-bg:var(--vscode-sideBar-background);--sc-surface:var(--vscode-editor-background);--sc-surface-soft:var(--vscode-editor-inactiveSelectionBackground);--sc-border:var(--vscode-widget-border);--sc-text:var(--vscode-foreground);--sc-muted:var(--vscode-descriptionForeground);--sc-primary:var(--vscode-button-background);--sc-primary-hover:var(--vscode-button-hoverBackground);--sc-primary-soft:color-mix(in srgb,var(--sc-primary) 12%,var(--sc-surface));--sc-warning:var(--vscode-editorWarning-foreground,#b45309);--sc-code:var(--vscode-textCodeBlock-background,var(--sc-surface-soft));margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;color:var(--sc-text);background:color-mix(in srgb,var(--sc-bg) 88%,#0b1020 12%);font-family:var(--vscode-font-family);font-size:13px}
  body.theme-light{--vscode-focusBorder:#467bd7;--sc-bg:#eef1f7;--sc-surface:#ffffff;--sc-surface-soft:#f4f6fb;--sc-border:#dde3ee;--sc-text:#172033;--sc-muted:#687386;--sc-primary:#5b5fef;--sc-primary-hover:#484bd6;--sc-primary-soft:#eef0ff;--sc-warning:#b45309;--sc-code:#f6f8fc;color-scheme:light}
  body.theme-dark{color-scheme:dark}
  .modal{width:min(760px,100%);max-height:calc(100vh - 48px);display:flex;flex-direction:column;background:var(--sc-surface);border:1px solid var(--sc-border);border-radius:14px;box-shadow:0 24px 60px rgba(15,23,42,.18);overflow:hidden}
  .modal-head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:start;padding:20px 22px 16px;border-bottom:1px solid var(--sc-border)}
  .kicker{display:block;margin-bottom:5px;color:var(--sc-primary);font-size:10px;font-weight:800;letter-spacing:.7px;text-transform:uppercase}
  h1{margin:0;font-size:18px;line-height:1.3;letter-spacing:0}
  .subtitle{margin:6px 0 0;color:var(--sc-muted);line-height:1.5}
  .close{width:32px;height:32px;display:grid;place-items:center;padding:0;color:var(--sc-muted);background:transparent;border:1px solid transparent;border-radius:8px;font-size:20px;line-height:1;cursor:pointer}
  .close:hover{color:var(--sc-text);background:var(--sc-surface-soft)}
  .modal-body{flex:1 1 auto;min-height:0;overflow:auto;padding:16px 22px 18px;display:grid;gap:16px}
  .callout{display:flex;gap:10px;align-items:flex-start;margin:0;padding:10px 12px;border-radius:10px;line-height:1.5}
  .callout.warning{color:var(--sc-warning);background:color-mix(in srgb,var(--sc-warning) 10%,var(--sc-surface));border:1px solid color-mix(in srgb,var(--sc-warning) 32%,transparent);font-weight:600}
  .callout.info{color:var(--sc-muted);background:var(--sc-surface-soft);border:1px solid var(--sc-border)}
  .summary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .field{min-width:0;padding:10px 12px;background:var(--sc-surface-soft);border:1px solid var(--sc-border);border-radius:10px}
  .field.wide{grid-column:1 / -1}
  .label{display:block;margin-bottom:5px;color:var(--sc-muted);font-size:10px;font-weight:700;letter-spacing:.6px;text-transform:uppercase}
  .value{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-width:0}
  code,.mono{font-family:var(--vscode-editor-font-family,Consolas,monospace);font-size:12px}
  .url{overflow-wrap:anywhere;word-break:break-word;line-height:1.45}
  .method{display:inline-flex;align-items:center;min-width:48px;justify-content:center;padding:3px 9px;border-radius:6px;font-family:var(--vscode-editor-font-family,Consolas,monospace);font-size:11px;font-weight:800;letter-spacing:.4px}
  .method.read{color:#1d4ed8;background:#e0e9ff}.method.create{color:#047857;background:#dcf5ea}.method.update{color:#b45309;background:#fdf0d8}.method.delete{color:#b42318;background:#fde4e1}.method.other{color:var(--sc-muted);background:var(--sc-surface)}
  body.theme-dark .method.read{color:#93b4ff;background:rgba(59,130,246,.18)}body.theme-dark .method.create{color:#6ee7b7;background:rgba(16,185,129,.16)}body.theme-dark .method.update{color:#fcd34d;background:rgba(245,158,11,.16)}body.theme-dark .method.delete{color:#fca5a5;background:rgba(239,68,68,.16)}
  .pill{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
  .pill.source{color:var(--sc-primary);background:var(--sc-primary-soft)}
  .pill.masked{color:var(--sc-warning);background:color-mix(in srgb,var(--sc-warning) 12%,var(--sc-surface))}
  .names{color:var(--sc-muted);overflow-wrap:anywhere}
  .muted{color:var(--sc-muted)}
  section h2{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:0 0 8px;font-size:12px;font-weight:700;letter-spacing:.2px}
  section h2 small{color:var(--sc-muted);font-weight:500}
  section h2.subhead{margin-top:12px}
  .block{max-height:220px;overflow:auto;background:var(--sc-code);border:1px solid var(--sc-border);border-radius:10px}
  .kv{margin:0}
  .kv-row{display:grid;grid-template-columns:minmax(120px,32%) minmax(0,1fr);gap:12px;padding:7px 12px;border-top:1px solid color-mix(in srgb,var(--sc-border) 70%,transparent)}
  .kv-row:first-child{border-top:0}
  dt{margin:0;color:var(--sc-muted);font-family:var(--vscode-editor-font-family,Consolas,monospace);font-size:12px;overflow-wrap:anywhere;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
  dd{margin:0;font-family:var(--vscode-editor-font-family,Consolas,monospace);font-size:12px;overflow-wrap:anywhere;word-break:break-word;white-space:pre-wrap}
  .location{padding:1px 6px;border-radius:5px;color:var(--sc-primary);background:var(--sc-primary-soft);font-size:10px;font-weight:700;text-transform:uppercase}
  .name{color:var(--sc-text)}
  .redacted{display:inline-block;padding:0 6px;border-radius:5px;color:var(--sc-warning);background:color-mix(in srgb,var(--sc-warning) 10%,var(--sc-surface))}
  .empty{margin:0;padding:12px;color:var(--sc-muted);font-style:italic}
  pre.body{margin:0;padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--vscode-editor-font-family,Consolas,monospace);font-size:12px}
  .modal-foot{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:9px;padding:14px 22px;border-top:1px solid var(--sc-border);background:color-mix(in srgb,var(--sc-surface-soft) 55%,var(--sc-surface))}
  .modal-foot button{min-height:34px;padding:0 16px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
  .primary{color:#fff;background:var(--sc-primary);border:1px solid var(--sc-primary)}
  .primary:hover{background:var(--sc-primary-hover)}
  .secondary{color:var(--sc-primary);background:var(--sc-surface);border:1px solid color-mix(in srgb,var(--sc-primary) 36%,var(--sc-border))}
  .secondary:hover{background:var(--sc-primary-soft)}
  button:disabled{opacity:.6;cursor:default}
  button:focus-visible{outline:2px solid var(--vscode-focusBorder);outline-offset:2px}
  @media(max-width:620px){body{padding:10px;place-items:stretch}.modal{max-height:calc(100vh - 20px)}.modal-head,.modal-body,.modal-foot{padding-left:14px;padding-right:14px}.summary{grid-template-columns:1fr}.kv-row{grid-template-columns:1fr;gap:3px}.modal-foot button{flex:1 1 auto}}
  </style></head><body class="${themeClass(theme)}">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="replay-title" aria-describedby="replay-subtitle">
    <header class="modal-head">
      <div><span class="kicker">Dynamic Security · Replay HTTP</span><h1 id="replay-title">Confirmer le replay de la requête</h1><p class="subtitle" id="replay-subtitle">Aperçu assaini de la requête qui va être rejouée. Les valeurs sensibles restent masquées.</p></div>
      <button type="button" class="close" id="close" aria-label="Fermer">×</button>
    </header>
    <div class="modal-body">
      ${isWrite ? '<p class="callout warning" role="alert"><span aria-hidden="true">⚠</span><span>Cette requête peut modifier l’état de l’application.</span></p>' : ''}
      <div class="summary">
        <div class="field"><span class="label">Méthode</span><div class="value"><span class="method ${methodTone(method)}">${escapeHtml(method)}</span></div></div>
        <div class="field"><span class="label">Source</span><div class="value"><span class="pill source">${escapeHtml(detail?.source || 'capture')}</span></div></div>
        <div class="field wide"><span class="label">Chemin</span><div class="value"><code class="url">${escapeHtml(path)}</code></div></div>
        ${detail?.url && detail.url !== path ? `<div class="field wide"><span class="label">URL</span><div class="value"><code class="url">${escapeHtml(detail.url)}</code></div></div>` : ''}
        <div class="field wide"><span class="label">En-têtes masqués</span><div class="value">${redactedSummary}</div></div>
      </div>
      <section aria-labelledby="headers-title"><h2 id="headers-title">En-têtes assainis <small>${headers.length}</small></h2><div class="block">${headerList}</div></section>
      <section aria-labelledby="params-title"><h2 id="params-title">Paramètres et corps assainis <small>${parameters.length}</small></h2><div class="block">${parameterList}</div>${requestBody ? `<h2 class="subhead">Corps assaini</h2><div class="block"><pre class="body">${escapeHtml(requestBody)}</pre></div>` : ''}</section>
      <p class="callout info"><span aria-hidden="true">ℹ</span><span>Cet aperçu ne montre que des données assainies, et les en-têtes masqués ne sont pas renvoyés au serveur. Aucune requête n’est envoyée avant votre confirmation.</span></p>
    </div>
    <footer class="modal-foot">
      <button type="button" class="secondary" id="cancel">Annuler</button>
      <button type="button" class="primary" id="confirm">${escapeHtml(confirmLabel)}</button>
    </footer>
  </div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const send = (type) => {
      document.querySelectorAll('button').forEach((button) => { button.disabled = true; });
      vscode.postMessage({ type });
    };
    document.getElementById('confirm').addEventListener('click', () => send('replayConfirm'));
    document.getElementById('cancel').addEventListener('click', () => send('replayCancel'));
    document.getElementById('close').addEventListener('click', () => send('replayCancel'));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') send('replayCancel'); });
    document.getElementById('confirm').focus();
  </script>
  </body></html>`;
}

module.exports = { escapeHtml, renderHttpReplayHtml, renderSafeHttpRequestHtml, renderReplayConfirmationHtml };
