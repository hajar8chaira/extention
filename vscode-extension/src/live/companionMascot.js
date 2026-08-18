'use strict';

/**
 * Security Companion mascot — a full-body original character.
 *
 * A small cyber sentinel: rounded head with an expressive visor, torso, two
 * arms with hands, two legs with feet, and an antenna. Original artwork for
 * this project.
 *
 * The SVG is inline for three reasons: no `img-src` is needed in the CSP, every
 * colour comes from a VS Code theme variable, and each body part is its own
 * group so CSS transforms can animate limbs independently — no animation
 * library, no JavaScript timer, nothing that could ever trigger analysis.
 *
 * Every eye expression is drawn once and revealed by the state class, so a
 * state change is a class swap and never a re-render.
 */

const MASCOT_VISUAL_STATES = Object.freeze([
  'idle', 'watching', 'thinking', 'warning', 'critical', 'success', 'sleeping', 'error'
]);

/** The body groups the animations act on. Named so tests can assert them. */
const MASCOT_PARTS = Object.freeze([
  'head', 'eyes', 'body', 'left-arm', 'right-arm', 'left-leg', 'right-leg', 'status-effect'
]);

/**
 * Companion state → mascot visual state. Accepts the companion vocabulary and
 * the raw Live Security service words, so no caller silently falls back to
 * `idle` just because it used the service's own term.
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

/** Plain-language description of the pose, for screen readers. */
const STATE_DESCRIPTIONS = Object.freeze({
  idle: 'au repos', watching: 'en surveillance', thinking: 'en analyse',
  warning: 'alerte', critical: 'alerte critique', success: 'satisfait',
  sleeping: 'en veille', error: 'en erreur'
});

/**
 * The character. `size` scales it; `title` becomes the accessible name and is
 * escaped because it carries the composed message, which quotes finding titles
 * coming from the developer's own source.
 */
function renderMascotSvg(visualState = 'idle', title = 'Security Companion', { size = 'regular' } = {}) {
  const state = MASCOT_VISUAL_STATES.includes(visualState) ? visualState : 'idle';
  return `<svg class="mascot mascot-${state} mascot-${size}" viewBox="0 0 120 150" role="img" aria-label="${escapeAttribute(title)}" focusable="false">
    <ellipse class="sc-shadow" cx="60" cy="143" rx="30" ry="5"/>
    <g class="sc-figure">
      <g id="left-leg" class="sc-leg sc-leg-left">
        <rect class="sc-limb" x="44" y="112" width="10" height="20" rx="5"/>
        <ellipse class="sc-foot" cx="47" cy="135" rx="11" ry="6"/>
      </g>
      <g id="right-leg" class="sc-leg sc-leg-right">
        <rect class="sc-limb" x="66" y="112" width="10" height="20" rx="5"/>
        <ellipse class="sc-foot" cx="73" cy="135" rx="11" ry="6"/>
      </g>

      <g id="left-arm" class="sc-arm sc-arm-left">
        <rect class="sc-limb" x="26" y="76" width="9" height="26" rx="4.5"/>
        <circle class="sc-hand" cx="30.5" cy="105" r="7"/>
      </g>
      <g id="right-arm" class="sc-arm sc-arm-right">
        <rect class="sc-limb" x="85" y="76" width="9" height="26" rx="4.5"/>
        <circle class="sc-hand" cx="89.5" cy="105" r="7"/>
        <g class="sc-tool" aria-hidden="true">
          <circle class="sc-lens" cx="99" cy="112" r="6"/>
          <line class="sc-lens-grip" x1="103" y1="116" x2="108" y2="121"/>
        </g>
      </g>

      <g id="body" class="sc-body">
        <rect class="sc-torso" x="33" y="70" width="54" height="46" rx="16"/>
        <rect class="sc-core" x="52" y="86" width="16" height="14" rx="5"/>
        <path class="sc-core-mark" d="M60 89v8M56.5 93h7"/>
      </g>

      <g id="head" class="sc-head">
        <line class="sc-antenna" x1="60" y1="24" x2="60" y2="12"/>
        <circle class="sc-spark" cx="60" cy="9" r="4.5"/>
        <rect class="sc-skull" x="27" y="22" width="66" height="48" rx="20"/>
        <rect class="sc-visor" x="34" y="33" width="52" height="26" rx="12"/>
        <g id="eyes" class="sc-eyes">
          <g class="sc-eye-set sc-eye-dot">
            <circle cx="49" cy="46" r="5"/><circle cx="71" cy="46" r="5"/>
          </g>
          <g class="sc-eye-set sc-eye-focus">
            <path d="M44 40l8 6-8 6"/><path d="M76 40l-8 6 8 6"/>
          </g>
          <g class="sc-eye-set sc-eye-alert">
            <path d="M49 39v9"/><path d="M71 39v9"/>
            <circle cx="49" cy="52" r="1.8"/><circle cx="71" cy="52" r="1.8"/>
          </g>
          <g class="sc-eye-set sc-eye-happy">
            <path d="M43 49l6-7 6 7"/><path d="M65 49l6-7 6 7"/>
          </g>
          <g class="sc-eye-set sc-eye-closed">
            <path d="M43 46h12"/><path d="M65 46h12"/>
          </g>
          <g class="sc-eye-set sc-eye-cross">
            <path d="M44 41l10 10M54 41l-10 10"/><path d="M66 41l10 10M76 41l-10 10"/>
          </g>
        </g>
        <rect class="sc-scanline" x="34" y="34" width="52" height="3" rx="1.5"/>
        <path class="sc-mouth" d="M52 64c3 2.6 13 2.6 16 0"/>
      </g>

      <g id="status-effect" class="sc-status" aria-hidden="true">
        <g class="sc-check"><path d="m88 34 7 7 13-15"/></g>
        <g class="sc-bang"><path d="M100 22v13"/><circle cx="100" cy="41" r="2.2"/></g>
        <g class="sc-zzz">
          <text class="sc-z sc-z1" x="92" y="34">z</text>
          <text class="sc-z sc-z2" x="102" y="22">z</text>
        </g>
        <g class="sc-dots"><circle cx="96" cy="30" r="2.6"/><circle cx="105" cy="30" r="2.6"/><circle cx="114" cy="30" r="2.6"/></g>
      </g>
    </g>
  </svg>`;
}

/**
 * Mascot styles. Motion is opt-out twice — the OS preference and the extension
 * setting — and no animation ever schedules work.
 */
function mascotCss() {
  return `
  /* The mascot defines its own palette, with a literal fallback on every step.
     A missing variable used to make the fill invalid at computed-value time,
     which CSS resolves to the initial value — black. The character then
     rendered as a silhouette on any surface that did not happen to declare
     these tokens. Nothing here may depend on a variable existing. */
  .mascot{
    --sc-body:var(--vscode-editorWidget-background,#2b313d);
    --sc-line:var(--vscode-foreground,#c9d1d9);
    --sc-visor:var(--vscode-editor-background,#11141a);
    --sc-accent:var(--vscode-focusBorder,#4a9eff);
    --sc-warn:var(--vscode-editorWarning-foreground,#d0a215);
    --sc-danger:var(--vscode-editorError-foreground,#e05252);
    --sc-ok:var(--vscode-testing-iconPassed,#3fa66a);
    display:block;width:112px;height:140px;overflow:visible}
  .mascot-compact{width:64px;height:80px}
  .mascot *{transform-box:fill-box}
  .sc-shadow{fill:var(--vscode-widget-shadow,rgba(0,0,0,.3));opacity:.28}
  .sc-skull,.sc-torso{fill:var(--sc-body);stroke:var(--sc-line);stroke-width:2.5;stroke-linejoin:round}
  .sc-visor{fill:var(--sc-visor)}
  .sc-limb{fill:var(--sc-body);stroke:var(--sc-line);stroke-width:2}
  .sc-hand,.sc-foot{fill:var(--sc-body);stroke:var(--sc-line);stroke-width:2}
  .sc-antenna{stroke:var(--sc-line);stroke-width:2.5;stroke-linecap:round}
  .sc-spark{fill:var(--sc-accent)}
  .sc-core{fill:var(--sc-visor)}
  .sc-core-mark{stroke:var(--sc-accent);stroke-width:2;stroke-linecap:round}
  .sc-mouth{fill:none;stroke:var(--sc-line);stroke-width:2;stroke-linecap:round;opacity:.6}
  .sc-scanline{fill:var(--sc-accent);opacity:0}
  .sc-tool{opacity:0}
  .sc-lens{fill:none;stroke:var(--sc-accent);stroke-width:2.5}
  .sc-lens-grip{stroke:var(--sc-accent);stroke-width:2.5;stroke-linecap:round}
  .sc-eye-set{opacity:0;fill:var(--sc-accent);stroke:var(--sc-accent);stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
  .sc-eye-dot,.sc-eye-alert{stroke:none}
  .sc-eye-focus,.sc-eye-happy,.sc-eye-closed,.sc-eye-cross{fill:none}
  .sc-status>g{opacity:0}
  .sc-check path{fill:none;stroke:var(--sc-ok);stroke-width:4;stroke-linecap:round;stroke-linejoin:round}
  .sc-bang path{stroke:var(--sc-danger);stroke-width:4;stroke-linecap:round}
  .sc-bang circle{fill:var(--sc-danger)}
  .sc-dots circle{fill:var(--sc-accent)}
  .sc-z{fill:var(--sc-line);font-size:15px;font-weight:700;opacity:.75}
  .sc-arm{transform-origin:50% 6%}
  .sc-leg{transform-origin:50% 8%}
  .sc-head{transform-origin:50% 90%}

  /* ---------- idle : breathing and an occasional blink ---------- */
  .mascot-idle .sc-eye-dot{opacity:1;animation:sc-blink 6s ease-in-out infinite}
  .mascot-idle .sc-figure{animation:sc-breathe 4.2s ease-in-out infinite,sc-sit-down 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-idle .sc-head{animation:sc-idle-head 8s ease-in-out infinite,sc-head-sit 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-idle .sc-arm-left{animation:sc-sway 4.2s ease-in-out infinite,sc-arm-sit-left 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-idle .sc-arm-right{animation:sc-sway 4.2s ease-in-out reverse infinite,sc-arm-sit-right 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-idle .sc-leg-left{animation:sc-leg-sit-left 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-idle .sc-leg-right{animation:sc-leg-sit-right 15s cubic-bezier(0.25,1,0.5,1) forwards}

  /* ---------- watching : eyes scan, head tilts, magnifier out ---------- */
  .mascot-watching .sc-eye-dot{opacity:1}
  .mascot-watching .sc-figure{animation:sc-breathe 4.2s ease-in-out infinite}
  .mascot-watching .sc-eyes{animation:sc-look 4.5s ease-in-out infinite}
  .mascot-watching .sc-head{animation:sc-tilt-soft 6s ease-in-out infinite}
  .mascot-watching .sc-tool{opacity:1}
  .mascot-watching .sc-arm-right{animation:sc-point 6s ease-in-out infinite}

  /* ---------- thinking : scan line, working arm, thought dots ---------- */
  .mascot-thinking .sc-eye-focus{opacity:1}
  .mascot-thinking .sc-scanline{opacity:.9;animation:sc-scan 1.2s linear infinite}
  .mascot-thinking .sc-figure{animation:sc-hop 1.2s ease-in-out infinite}
  .mascot-thinking .sc-arm-right{animation:sc-work .8s ease-in-out infinite}
  .mascot-thinking .sc-tool{opacity:1}
  .mascot-thinking .sc-dots{opacity:1}
  .mascot-thinking .sc-dots circle{animation:sc-dot 1.2s ease-in-out infinite}
  .mascot-thinking .sc-dots circle:nth-child(2){animation-delay:.2s}
  .mascot-thinking .sc-dots circle:nth-child(3){animation-delay:.4s}

  /* ---------- warning : leans back, arms react ---------- */
  .mascot-warning .sc-eye-alert{opacity:1;fill:var(--sc-warn)}
  .mascot-warning .sc-figure{animation:sc-recoil .55s ease-out 2}
  .mascot-warning .sc-arm-left{animation:sc-raise-left .55s ease-out 2}
  .mascot-warning .sc-arm-right{animation:sc-raise-right .55s ease-out 2}
  .mascot-warning .sc-bang{opacity:1}
  .mascot-warning .sc-mouth{d:path("M52 66c3-2.6 13-2.6 16 0")}

  /* ---------- critical : hands up, slow pulse, never a strobe ---------- */
  .mascot-critical .sc-eye-alert{opacity:1}
  .mascot-critical .sc-arm-left{transform:rotate(-42deg)}
  .mascot-critical .sc-arm-right{transform:rotate(42deg)}
  .mascot-critical .sc-figure{animation:sc-pulse 2s ease-in-out infinite}
  .mascot-critical .sc-bang{opacity:1;animation:sc-pulse 2s ease-in-out infinite}
  .mascot-critical .sc-skull,.mascot-critical .sc-torso{stroke:var(--sc-danger)}
  .mascot-critical .sc-mouth{d:path("M52 66c3-2.6 13-2.6 16 0")}

  /* ---------- success : jump, arms up, check ---------- */
  .mascot-success .sc-eye-happy{opacity:1;stroke:var(--sc-ok)}
  .mascot-success .sc-figure{animation:sc-jump .75s cubic-bezier(.3,1.4,.5,1) 1,sc-breathe 4.2s ease-in-out infinite,sc-sit-down 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-success .sc-head{animation:sc-idle-head 8s ease-in-out infinite,sc-head-sit 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-success .sc-arm-left{animation:sc-cheer-left .75s ease-out 1,sc-arm-sit-left 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-success .sc-arm-right{animation:sc-cheer-right .75s ease-out 1,sc-arm-sit-right 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-success .sc-check{opacity:1;animation:sc-pop .5s ease-out 1}
  .mascot-success .sc-core-mark{stroke:var(--sc-ok)}
  .mascot-success .sc-leg-left{animation:sc-leg-sit-left 15s cubic-bezier(0.25,1,0.5,1) forwards}
  .mascot-success .sc-leg-right{animation:sc-leg-sit-right 15s cubic-bezier(0.25,1,0.5,1) forwards}

  /* ---------- sleeping : lowered, eyes closed, Zz ---------- */
  .mascot-sleeping .sc-eye-closed{opacity:1}
  .mascot-sleeping .sc-figure{transform:translateY(12px);opacity:.68}
  .mascot-sleeping .sc-head{transform:rotate(-7deg)}
  .mascot-sleeping .sc-leg-left{transform:rotate(-75deg) translate(-5px,-12px)}
  .mascot-sleeping .sc-leg-right{transform:rotate(75deg) translate(5px,-12px)}
  .mascot-sleeping .sc-zzz{opacity:1}
  .mascot-sleeping .sc-z1{animation:sc-float 2.8s ease-in-out infinite}
  .mascot-sleeping .sc-z2{animation:sc-float 2.8s ease-in-out .6s infinite}

  /* ---------- error : confused, hands outward ---------- */
  .mascot-error .sc-eye-cross{opacity:1;stroke:var(--sc-danger)}
  .mascot-error .sc-figure{animation:sc-shake .5s ease-in-out 2}
  .mascot-error .sc-arm-left{transform:rotate(-28deg)}
  .mascot-error .sc-arm-right{transform:rotate(28deg)}
  .mascot-error .sc-mouth{d:path("M52 66c3-2.6 13-2.6 16 0")}

  @keyframes sc-breathe{50%{transform:translateY(-2.5px) scaleY(1.015)}}
  @keyframes sc-blink{0%,92%,100%{transform:scaleY(1)}96%{transform:scaleY(.1)}}
  @keyframes sc-look{0%,100%{transform:translateX(0)}30%{transform:translateX(-4px)}65%{transform:translateX(4px)}}
  @keyframes sc-tilt-soft{0%,100%{transform:rotate(0)}40%{transform:rotate(-4deg)}70%{transform:rotate(3deg)}}
  @keyframes sc-point{0%,100%{transform:rotate(0)}45%{transform:rotate(-16deg)}}
  @keyframes sc-scan{0%{transform:translateY(0)}100%{transform:translateY(23px)}}
  @keyframes sc-hop{50%{transform:translateY(-3px)}}
  @keyframes sc-work{0%,100%{transform:rotate(0)}50%{transform:rotate(-22deg)}}
  @keyframes sc-dot{0%,100%{opacity:.25;transform:translateY(0)}50%{opacity:1;transform:translateY(-3px)}}
  @keyframes sc-recoil{0%{transform:rotate(0) translateY(0)}40%{transform:rotate(4deg) translateY(-2px)}100%{transform:rotate(0) translateY(0)}}
  @keyframes sc-raise-left{0%,100%{transform:rotate(0)}45%{transform:rotate(-30deg)}}
  @keyframes sc-raise-right{0%,100%{transform:rotate(0)}45%{transform:rotate(30deg)}}
  @keyframes sc-pulse{50%{opacity:.7}}
  @keyframes sc-jump{0%{transform:translateY(0)}45%{transform:translateY(-14px)}70%{transform:translateY(2px)}100%{transform:translateY(0)}}
  @keyframes sc-cheer-left{0%,100%{transform:rotate(0)}50%{transform:rotate(-58deg)}}
  @keyframes sc-cheer-right{0%,100%{transform:rotate(0)}50%{transform:rotate(58deg)}}
  @keyframes sc-pop{0%{transform:scale(.4);opacity:0}70%{transform:scale(1.15);opacity:1}100%{transform:scale(1)}}
  @keyframes sc-float{50%{transform:translateY(-5px)}}
  @keyframes sc-shake{25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}

  @keyframes sc-idle-head {
    0%, 100% { transform: rotate(0) translateY(0); }
    50% { transform: rotate(1.5deg) translateY(0.5px); }
  }
  @keyframes sc-sit-down {
    0%, 66% { transform: translateY(0); }
    100% { transform: translateY(12px); }
  }
  @keyframes sc-head-sit {
    0%, 66% { transform: rotate(0); }
    100% { transform: rotate(2deg) translateY(-2px); }
  }
  @keyframes sc-arm-sit-left {
    0%, 66% { transform: rotate(0); }
    100% { transform: rotate(-15deg) translateY(-4px); }
  }
  @keyframes sc-arm-sit-right {
    0%, 66% { transform: rotate(0); }
    100% { transform: rotate(15deg) translateY(-4px); }
  }
  @keyframes sc-leg-sit-left {
    0%, 66% { transform: rotate(0) translateY(0); }
    100% { transform: rotate(-75deg) translate(-5px, -12px); }
  }
  @keyframes sc-leg-sit-right {
    0%, 66% { transform: rotate(0) translateY(0); }
    100% { transform: rotate(75deg) translate(5px, -12px); }
  }

  /* Motion is opt-out twice. The static pose still reads: eyes, limbs and the
     status effect stay in their state position, only movement stops. */
  @media(prefers-reduced-motion:reduce){.mascot *{animation:none!important;transition:none!important}}
  .no-motion .mascot *{animation:none!important;transition:none!important}
  .no-motion .sc-scanline{opacity:0}`;
}

module.exports = {
  MASCOT_VISUAL_STATES, MASCOT_PARTS, STATE_DESCRIPTIONS,
  mascotVisualFor, renderMascotSvg, mascotCss, escapeAttribute
};
