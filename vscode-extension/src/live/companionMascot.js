'use strict';

/**
 * Security Companion mascot asset renderer.
 *
 * The companion is a packaged bitmap product asset, not a CSS/SVG drawing.
 * State still travels as classes so existing presentation surfaces can apply
 * conservative glow/float treatments without changing the Live model.
 */

const DEFAULT_MASCOT_IMAGE = 'media/live/security-companion.png';

const MASCOT_VISUAL_STATES = Object.freeze([
  'idle', 'watching', 'thinking', 'warning', 'critical', 'success', 'sleeping', 'error'
]);

// Kept as an exported contract for older tests/imports; the asset itself is no
// longer assembled from these parts.
const MASCOT_PARTS = Object.freeze([]);

/**
 * Companion state -> mascot visual state. Accepts the companion vocabulary and
 * the raw Live Security service words, so callers keep their existing model.
 */
function mascotVisualFor(rawState, { severity = '', policyStatus = '' } = {}) {
  const state = { issues: 'findings', paused: 'degraded' }[rawState] || rawState;
  if (state === 'error') return 'error';
  if (state === 'disabled') return 'sleeping';
  if (state === 'analyzing') return 'thinking';
  if (state === 'findings') return String(severity).toLowerCase() === 'critical' ? 'critical' : 'warning';
  if (state === 'degraded') return 'warning';
  if (String(policyStatus).toUpperCase() === 'BLOCK') return 'critical';
  if (state === 'clean') return 'success';
  if (state === 'watching') return 'watching';
  return 'idle';
}

function escapeAttribute(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function renderMascotSvg(visualState = 'idle', title = 'Security Companion', { size = 'regular', src = DEFAULT_MASCOT_IMAGE } = {}) {
  const state = MASCOT_VISUAL_STATES.includes(visualState) ? visualState : 'idle';
  const safeSize = ['regular', 'compact'].includes(size) ? size : 'regular';
  const safeSrc = src || DEFAULT_MASCOT_IMAGE;
  return `<img class="mascot mascot-${state} mascot-${safeSize}" src="${escapeAttribute(safeSrc)}" alt="${escapeAttribute(title)}" role="img" draggable="false" data-companion-asset="local" data-companion-state="${escapeAttribute(state)}">`;
}

function mascotCss() {
  return `
  .mascot{display:block;width:104px;height:130px;object-fit:contain;object-position:center bottom;user-select:none;pointer-events:none;filter:drop-shadow(0 10px 18px var(--sc-shadow,rgba(15,23,42,.22))) drop-shadow(0 0 14px var(--sc-accent-soft,rgba(91,95,239,.22)));transform-origin:50% 78%}
  .mascot-compact{width:64px;height:80px}
  .mascot-idle,.mascot-watching{animation:sc-breathe 4.8s ease-in-out infinite}
  .mascot-thinking{animation:sc-scan 1.8s ease-in-out infinite}
  .mascot-warning{animation:sc-attend 2.8s ease-in-out infinite}
  .mascot-critical{animation:sc-pulse 2s ease-in-out infinite}
  .mascot-success{animation:sc-success-pulse 4.8s ease-in-out infinite}
  .mascot-sleeping{opacity:.72;transform:translateY(8px)}
  .mascot-error{animation:sc-shake .5s ease-in-out 2}
  @keyframes sc-breathe{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-3px) scale(1.012)}}
  @keyframes sc-scan{0%,100%{transform:translateY(0) scale(1);filter:drop-shadow(0 10px 18px var(--sc-shadow,rgba(15,23,42,.22))) drop-shadow(0 0 12px var(--sc-accent-soft,rgba(91,95,239,.22)))}50%{transform:translateY(-4px) scale(1.018);filter:drop-shadow(0 10px 18px var(--sc-shadow,rgba(15,23,42,.22))) drop-shadow(0 0 22px var(--sc-accent,rgba(91,95,239,.45)))}}
  @keyframes sc-attend{0%,100%{transform:translateY(0) scale(1)}45%{transform:translateY(-2px) scale(1.014)}60%{transform:translateY(0) scale(1.006)}}
  @keyframes sc-pulse{0%,100%{transform:scale(1);filter:drop-shadow(0 10px 18px var(--sc-shadow,rgba(15,23,42,.22))) drop-shadow(0 0 12px var(--sc-danger,rgba(217,75,64,.28)))}50%{transform:scale(1.025);filter:drop-shadow(0 10px 18px var(--sc-shadow,rgba(15,23,42,.22))) drop-shadow(0 0 24px var(--sc-danger,rgba(217,75,64,.45)))}}
  @keyframes sc-success-pulse{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-2px) scale(1.01)}}
  @keyframes sc-shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-2px)}75%{transform:translateX(2px)}}
  @media(prefers-reduced-motion:reduce){.mascot{animation:none!important;transition:none!important}}
  .no-motion .mascot{animation:none!important;transition:none!important}`;
}

module.exports = {
  MASCOT_VISUAL_STATES, MASCOT_PARTS, DEFAULT_MASCOT_IMAGE,
  mascotVisualFor, renderMascotSvg, mascotCss, escapeAttribute
};
