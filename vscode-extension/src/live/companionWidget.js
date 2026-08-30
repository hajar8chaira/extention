'use strict';

/**
 * The compact Security Companion.
 *
 * One presentation component, two modes, several hosts. It renders a small
 * mascot and a short speech bubble from the shared companion visual model and
 * nothing else: it holds no state, subscribes to nothing, computes no finding
 * count and composes no message. Every string it shows was already decided by
 * `companionMessages.js`, and every posture by `companionMascot.js`.
 *
 * `full` is for the Live Security page, where the companion is the page's
 * assistant and may speak about the current file. `compact` is for every other
 * Security Center page, where it is a presence: a small mascot, a badge, and a
 * bubble only when something actually warrants one.
 *
 * The component is deliberately non-blocking. The outer layer never receives
 * pointer events, it keeps a safe distance from the page's own controls and from
 * the editor chrome below, and it sits on a stacking level above sticky content
 * but below any modal or tooltip the host page owns.
 */

const { renderMascotSvg, mascotCss } = require('./companionMascot');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

/**
 * Mascot sizes per mode, both far below the 140px of the removed panel.
 *
 * `compact` is the primary surface and sits at 44px wide: that is the WCAG 2.5.5
 * target-size minimum, so the companion stays clickable without growing.
 *
 * `full` is 1.6x its area — enough that the two modes read as different at a
 * glance, which is the whole point of having two. A previous value of 52x65 made
 * `full` all but indistinguishable from `compact`, and a mode the user cannot
 * see is not a mode. It stays under 100px so it never competes with the code.
 *
 * Every pair keeps the 4:5 ratio of the 120x150 viewBox, so the figure is never
 * distorted at any breakpoint.
 */
const WIDGET_SIZES = Object.freeze({
  full: { width: 72, height: 90, narrow: { width: 60, height: 75 } },
  compact: { width: 44, height: 56, narrow: { width: 38, height: 48 } }
});

/**
 * Local stacking level.
 *
 * The host pages already use: 10 for sticky table headers, 20 for the modal
 * confirmation backdrop, 1000 for popovers. The companion belongs above pinned
 * content and below anything that demands a decision, so it takes 15 — a
 * documented level, not an arbitrary large number.
 */
const WIDGET_Z_INDEX = 15;

/** Safe distance from the page edges, per viewport width. */
const SAFE_AREA = Object.freeze({
  wide: { right: 24, bottom: 28 },
  medium: { right: 16, bottom: 20 },
  small: { right: 10, bottom: 14 }
});

/**
 * States that always deserve a bubble, in either mode and at any width.
 * Everything else is allowed to stay silent when the surface is cramped.
 */
const IMPORTANT_STATES = Object.freeze(['warning', 'critical', 'error']);

/**
 * Message kinds with nothing worth saying.
 *
 * `idle` says « Live Security est prêt », which a Security Center page has
 * already established. Repeating it is the duplication this component exists to
 * avoid, so the mascot simply stands there.
 */
const SILENT_KINDS = Object.freeze(['idle']);

/** How long a bubble may get before it is clipped and moved to the tooltip. */
const BUBBLE_MAX_CHARS = 120;

/** How long a transient bubble stays before it fades. Long enough to read. */
const BUBBLE_LINGER_MS = 6000;

/**
 * The companion.
 *
 * `visual` is the shared model from `buildCompanionVisualModel`. A missing model
 * renders nothing at all rather than a placeholder companion — an assistant with
 * no state to report should not appear.
 */
function renderCompanionWidget(visual, { variant = 'full', enabled = true, interactive = true, imageUri = '' } = {}) {
  if (!enabled || !visual) return '';
  const mode = variant === 'compact' ? 'compact' : 'full';
  const state = visual.mascotState || 'idle';
  const message = visual.message || null;
  const important = IMPORTANT_STATES.includes(state);
  const headline = message?.headline || '';
  // Compact mode only speaks when it matters; full mode speaks unless it has
  // nothing to say. Neither invents a string of its own.
  const speak = Boolean(headline)
    && !SILENT_KINDS.includes(message?.kind)
    && (mode === 'full' || important);
  const clipped = headline.length > BUBBLE_MAX_CHARS;
  const bubbleText = clipped ? `${headline.slice(0, BUBBLE_MAX_CHARS).trimEnd()}…` : headline;
  // The project-level line, small, under the primary message. Full mode only:
  // compact has no room, and the pages it sits on already show those numbers.
  const secondary = mode === 'full' && visual.secondary?.headline ? visual.secondary.headline : '';
  const findings = Number.isInteger(visual.liveFindingCount) ? visual.liveFindingCount : 0;
  const tag = interactive ? 'button' : 'div';
  const label = speak ? `Security Companion — ${headline}` : 'Security Companion';
  // A report fades once read; a warning stays until its state changes. The fade
  // is a CSS animation with a delay — no timer, no frame loop, nothing to clean
  // up when the page is hidden.
  const fading = message?.transient ? ' sc-widget-fading' : '';
  return `<aside class="sc-widget sc-widget-${escapeHtml(mode)}${important ? ' sc-widget-important' : ''}${visual.animations === false ? ' sc-no-motion' : ''}" data-companion-state="${escapeHtml(state)}">
      ${speak ? `<div class="sc-widget-bubble${important ? ' sc-important' : ''}${fading}" role="status" aria-live="${state === 'critical' || state === 'error' ? 'assertive' : 'polite'}"${clipped ? ` title="${escapeHtml(headline)}"` : ''}>
        <span class="sc-widget-headline">${escapeHtml(bubbleText)}</span>
        ${secondary ? `<span class="sc-widget-secondary">${escapeHtml(secondary)}</span>` : ''}
      </div>` : ''}
      <${tag} class="sc-widget-mascot"${interactive ? ' type="button" data-action="companion" title="Security Companion"' : ''} aria-label="${escapeHtml(label)}">
        ${renderMascotSvg(state, 'Security Companion', { src: imageUri })}
        ${findings ? `<span class="sc-widget-count">${findings}<span class="sc-widget-sr"> problème(s) Live dans ce fichier</span></span>` : ''}
      </${tag}>
    </aside>`;
}

/**
 * The component's stylesheet, including the mascot's own.
 *
 * Every colour goes through a VS Code theme variable with a literal fallback, so
 * the bubble is readable in light and dark themes and the mascot can never
 * render as a black silhouette in a host that defines no `--sc-*` variables.
 */
function companionWidgetCss() {
  return `${mascotCss()}
    /* The bubble's own palette. editorHoverWidget is the right pairing here:
       it is the surface VS Code itself uses for a small floating explanation, so
       its background and foreground are guaranteed to contrast in every theme.
       The previous version paired that background with the generic
       --vscode-foreground, which is what made the text hard to read. */
    .sc-widget{
      --sc-bubble-bg:var(--vscode-editorHoverWidget-background,var(--vscode-editorWidget-background,#f8f9fb));
      --sc-bubble-fg:var(--vscode-editorHoverWidget-foreground,var(--vscode-editorWidget-foreground,var(--vscode-foreground,#1f2328)));
      --sc-bubble-border:var(--vscode-editorHoverWidget-border,var(--vscode-widget-border,var(--vscode-panel-border,#c9d1d9)));
      --sc-bubble-muted:var(--vscode-descriptionForeground,#6a737d);
      --sc-bubble-shadow:var(--vscode-widget-shadow,rgba(0,0,0,.18));
      --sc-bubble-alert:var(--vscode-editorError-foreground,#e05252);
      --sc-focus:var(--vscode-focusBorder,#4a9eff)}

    /* Floating layer, inside the webview document only. Nothing here overlays the
       VS Code workbench and no private API is involved.
       pointer-events:none is the important part: the layer spans a transparent
       area, and without it that area would swallow clicks meant for the page. */
    .sc-widget{position:fixed;right:${SAFE_AREA.wide.right}px;bottom:${SAFE_AREA.wide.bottom}px;
      z-index:${WIDGET_Z_INDEX};
      display:grid;justify-items:center;gap:0;pointer-events:none;
      max-width:min(240px,44vw)}
    /* Only the real controls take pointer events back. */
    .sc-widget-mascot,.sc-widget-bubble,.sc-widget-action{pointer-events:auto}

    .sc-widget-bubble{position:relative;margin-bottom:8px;padding:8px 12px;border-radius:8px;
      display:grid;gap:3px;text-align:left;font-size:12px;line-height:1.4;
      color:var(--sc-bubble-fg);background:var(--sc-bubble-bg);
      border:1px solid var(--sc-bubble-border);
      box-shadow:0 4px 12px var(--sc-bubble-shadow);
      max-width:220px;overflow-wrap:anywhere;
      animation:sc-widget-in .22s cubic-bezier(0.16,1,0.3,1)}
    .sc-widget-headline{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    .sc-widget-secondary{color:var(--sc-bubble-muted);font-size:.9em;
      display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden}
    /* Severity is carried by the border *and* by the mascot's own state class, so
       it is never communicated by colour alone. */
    .sc-widget-bubble.sc-important{border-color:var(--sc-bubble-alert)}
    .sc-widget-bubble::after{content:"";position:absolute;left:50%;margin-left:-4px;bottom:-5px;width:8px;height:8px;
      background:var(--sc-bubble-bg);
      border-right:1px solid var(--sc-bubble-border);
      border-bottom:1px solid var(--sc-bubble-border);
      transform:rotate(45deg)}
    .sc-widget-bubble.sc-important::after{border-right-color:var(--sc-bubble-alert);border-bottom-color:var(--sc-bubble-alert)}
    /* A transient bubble fades out on its own after a glance. Pure CSS: the page
       schedules nothing and there is no timer to cancel when it is hidden. */
    .sc-widget-bubble.sc-widget-fading{animation:sc-widget-in .2s ease-out,sc-widget-out .5s ease-in ${BUBBLE_LINGER_MS}ms forwards}
    @keyframes sc-widget-in{from{opacity:0;transform:translateY(3px)}}
    @keyframes sc-widget-out{to{opacity:0;transform:translateY(-2px);visibility:hidden}}

    .sc-widget-mascot{position:relative;display:block;background:none;border:0;padding:0;line-height:0;border-radius:9px}
    button.sc-widget-mascot{cursor:pointer}
    .sc-widget-mascot:focus-visible{outline:2px solid var(--sc-focus);outline-offset:2px}
    .sc-widget-count{position:absolute;top:-2px;right:-4px;min-width:16px;padding:0 4px;border-radius:8px;
      font-size:10px;line-height:16px;text-align:center;
      color:var(--vscode-badge-foreground,#fff);background:var(--vscode-badge-background,#3a7bd5)}
    /* Screen-reader-only text: the badge number alone does not say what it counts. */
    .sc-widget-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}

    .sc-widget-full .mascot{width:${WIDGET_SIZES.full.width}px;height:${WIDGET_SIZES.full.height}px}
    .sc-widget-compact .mascot{width:${WIDGET_SIZES.compact.width}px;height:${WIDGET_SIZES.compact.height}px}
    .sc-no-motion .mascot{animation:none!important;transition:none!important}

    /* Medium viewport: closer to the edges, still clear of the content. */
    @media(max-width:1000px){.sc-widget{right:${SAFE_AREA.medium.right}px;bottom:${SAFE_AREA.medium.bottom}px}}
    /* Narrow viewport: compact size, and the bubble only for what matters. A
       cramped page must never have its content covered by a comment about it. */
    @media(max-width:620px){
      .sc-widget{right:${SAFE_AREA.small.right}px;bottom:${SAFE_AREA.small.bottom}px;max-width:60vw}
      .sc-widget-full .mascot{width:${WIDGET_SIZES.full.narrow.width}px;height:${WIDGET_SIZES.full.narrow.height}px}
      .sc-widget-compact .mascot{width:${WIDGET_SIZES.compact.narrow.width}px;height:${WIDGET_SIZES.compact.narrow.height}px}
      .sc-widget:not(.sc-widget-important) .sc-widget-bubble{display:none}
      .sc-widget-secondary{display:none}
    }
    /* Short viewport: mascot and badge only. */
    @media(max-height:420px){
      .sc-widget .sc-widget-bubble{display:none}
      .sc-widget-full .mascot{width:${WIDGET_SIZES.compact.width}px;height:${WIDGET_SIZES.compact.height}px}
    }
    @media(prefers-reduced-motion:reduce){.sc-widget-bubble{animation:none}}`;
}

module.exports = {
  renderCompanionWidget, companionWidgetCss,
  WIDGET_SIZES, WIDGET_Z_INDEX, SAFE_AREA, IMPORTANT_STATES, SILENT_KINDS,
  BUBBLE_MAX_CHARS, BUBBLE_LINGER_MS
};
