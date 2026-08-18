const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { mascotCss, renderMascotSvg } = require('../src/live/companionMascot');
const { renderCompanionWidget, companionWidgetCss, WIDGET_SIZES } = require('../src/live/companionWidget');
const { buildCompanionVisualModel } = require('../src/live/companionMessages');

const liveFinding = (severity = 'high', ruleId = 'dynamic-command-execution') => ({
  ruleId, severity, title: 'Potential security issue',
  range: { start: { line: 2, character: 2 }, end: { line: 2, character: 40 } },
  uri: 'file:///ws/routes/login.js', documentVersion: 1, quickFixAvailable: false
});

function visualFor({ state = 'idle', findings = [], file = 'routes/login.js', pipeline = {} } = {}) {
  return buildCompanionVisualModel({ serviceState: state, findings, file, pipeline });
}

test('les deux modes forment un seul contrat de taille coherent', () => {
  // Ce fichier imposait 45-65px pendant que companion-visual-hardening imposait
  // 70-100px : deux contrats contradictoires qu'aucune valeur ne pouvait
  // satisfaire. Le contrat unique est exprime en relations, pas en pixels figes.
  const { full, compact } = WIDGET_SIZES;
  // 44px est le minimum de cible tactile WCAG 2.5.5 : le compact reste cliquable.
  assert.ok(compact.width >= 44, 'le mode compact doit rester cliquable');
  // Le compact ne domine jamais le code.
  assert.ok(compact.height <= 60, 'le mode compact doit rester discret');
  // Les deux modes doivent se distinguer a l oeil, sinon le mode n en est pas un.
  assert.ok(full.width * full.height >= compact.width * compact.height * 2,
    'le mode full doit etre nettement plus grand que le compact');
  // Mais il reste petit : jamais le panneau de 140px qui a ete retire.
  assert.ok(full.height <= 100, 'le mode full ne doit jamais dominer l ecran');
  // Le viewBox est 120x150 : tout couple hors ratio 4:5 deformerait la figure.
  for (const size of [full, compact, full.narrow, compact.narrow]) {
    const ratio = size.height / size.width;
    assert.ok(Math.abs(ratio - 1.25) < 0.06, `ratio ${ratio.toFixed(2)} deforme la mascotte`);
  }
});

test('companion widget states map to the correct visual mascot mood/pose classes', () => {
  const states = [
    { state: 'idle', expected: 'mascot-idle' },
    { state: 'analyzing', expected: 'mascot-thinking' },
    { state: 'clean', expected: 'mascot-success' },
    { state: 'disabled', expected: 'mascot-sleeping' },
    { state: 'degraded', expected: 'mascot-warning' },
    { state: 'error', expected: 'mascot-error' }
  ];

  for (const { state, expected } of states) {
    const visual = visualFor({ state });
    const html = renderCompanionWidget(visual, { variant: 'full' });
    assert.match(html, new RegExp(expected));
  }

  // Critical findings
  const criticalVisual = visualFor({ state: 'issues', findings: [liveFinding('critical')] });
  const criticalHtml = renderCompanionWidget(criticalVisual, { variant: 'full' });
  assert.match(criticalHtml, /mascot-critical/);
});

test('correct speech bubble messages are rendered and no duplicate messages are present', () => {
  const visual = visualFor({ state: 'clean', file: 'routes/login.js' });
  const html = renderCompanionWidget(visual, { variant: 'full' });

  // La bulle porte une seule ligne : le titre. Le detail reste dans le modele et
  // s'affiche sur la page Live Security, pas dans la surface flottante — un
  // compagnon discret ne dit qu'une chose a la fois.
  assert.match(html, /Aucun problème Live détecté/);
  assert.ok(!html.includes(visual.message.detail), 'le detail ne double pas le titre dans la bulle');
  // Mais le texte complet reste accessible sans souris.
  assert.match(html, /aria-label="Security Companion — Aucun problème Live détecté/);

  // Assert no duplicate container or messages
  const headlineOccurrences = (html.match(/sc-widget-headline/g) || []).length;
  assert.equal(headlineOccurrences, 1, 'should only have one headline element');
});

test('reduced motion style selectors exist in mascot CSS and widget CSS', () => {
  const widgetStyles = companionWidgetCss();
  const mascotStyles = mascotCss();

  assert.match(widgetStyles, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(widgetStyles, /\.sc-no-motion/);

  assert.match(mascotStyles, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(mascotStyles, /\.no-motion/);
});

test('no timers, setInterval, setTimeout or requestAnimationFrame in mascot/widget code', () => {
  const widgetCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionWidget.js'), 'utf8');
  const mascotCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'live', 'companionMascot.js'), 'utf8');

  const timerRegex = /setInterval|setTimeout|requestAnimationFrame/;
  assert.ok(!timerRegex.test(widgetCode), 'companionWidget.js must not contain timers');
  assert.ok(!timerRegex.test(mascotCode), 'companionMascot.js must not contain timers');
});
