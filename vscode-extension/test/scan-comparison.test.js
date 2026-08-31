const test = require('node:test');
const assert = require('node:assert/strict');
const { compareScans, renderScanComparisonHtml, completedTools, findingIdentity } = require('../src/scan-comparison');

function scan(scanId, findings, scanners, workspace = 'juice-shop') {
  return { scan_id: scanId, workspace, result: { findings, scanners } };
}

test('compare Scans calculate severityChanged and unchanged correctly', () => {
  const baseline = scan(13, [
    { id: 's1', tool: 'Semgrep', rawSeverity: 'HIGH', title: 'Code vuln 1' },
    { id: 's2', tool: 'Semgrep', rawSeverity: 'MEDIUM', title: 'Code vuln 2' }
  ], [{ tool: 'Semgrep', status: 'completed' }]);

  const current = scan(14, [
    { id: 's1', tool: 'Semgrep', rawSeverity: 'CRITICAL', title: 'Code vuln 1' }, // severity changed
    { id: 's2', tool: 'Semgrep', rawSeverity: 'MEDIUM', title: 'Code vuln 2' } // unchanged
  ], [{ tool: 'Semgrep', status: 'completed' }]);

  const comparison = compareScans(baseline, current);
  assert.equal(comparison.severityChanged.length, 1);
  assert.equal(comparison.severityChanged[0].id, 's1');
  assert.equal(comparison.unchanged.length, 1);
  assert.equal(comparison.unchanged[0].id, 's2');
  assert.equal(comparison.added.length, 0);
  assert.equal(comparison.resolved.length, 0);
});

test('compare Scans handles missing scanner result and partial coverage', () => {
  const baseline = scan(13, [
    { id: 's1', tool: 'Semgrep', rawSeverity: 'HIGH', title: 'Vulnerability' }
  ], [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'ZAP', status: 'completed' }
  ]);

  const current = scan(14, [
    { id: 's1', tool: 'Semgrep', rawSeverity: 'HIGH', title: 'Vulnerability' }
  ], [
    { tool: 'Semgrep', status: 'completed' },
    { tool: 'ZAP', status: 'failed' } // ZAP failed in current, so it is excluded
  ]);

  const comparison = compareScans(baseline, current);
  assert.deepEqual(comparison.comparableTools, ['Semgrep']);
  assert.deepEqual(comparison.excludedTools, ['ZAP']);
});

test('renderScanComparisonHtml markup containing search, sorting, and dynamic theme', () => {
  const scans = [
    scan(13, [], []),
    scan(14, [], [])
  ];
  const htmlLight = renderScanComparisonHtml(scans, 'nonce-1', 'light');
  assert.match(htmlLight, /theme-light/);
  assert.match(htmlLight, /Rechercher par ID/);
  assert.match(htmlLight, /filter-status-select/);
  assert.match(htmlLight, /sort-order-select/);
  assert.match(htmlLight, /comparable-only-checkbox/);

  const htmlDark = renderScanComparisonHtml(scans, 'nonce-2', 'dark');
  assert.match(htmlDark, /theme-dark/);
  assert.match(htmlDark, /btn-compare-scans/);
});

test('compareScans logic with valid zero results', () => {
  const baseline = scan(13, [], [{ tool: 'Semgrep', status: 'completed' }]);
  const current = scan(14, [], [{ tool: 'Semgrep', status: 'completed' }]);

  const comparison = compareScans(baseline, current);
  assert.equal(comparison.added.length, 0);
  assert.equal(comparison.resolved.length, 0);
  assert.equal(comparison.persistent.length, 0);
});

test('renderScanComparisonHtml does not render raw JSON directly', () => {
  const scans = [
    scan(13, [{ id: 's1', tool: 'Semgrep', title: 'raw-title-vuln' }], [])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce', 'dark');
  // The raw finding details shouldn't be visible in plain HTML text
  assert.doesNotMatch(html, /raw-title-vuln/);
  
  // It should contain the Base64 representation in script tag
  const expectedBase64 = Buffer.from(JSON.stringify(scans)).toString('base64');
  assert.match(html, new RegExp(expectedBase64));
});

test('renderScanComparisonHtml handles empty scans list safely', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  assert.match(html, /Historique des scans disponibles/);
  assert.match(html, /btn-compare-scans/);
});

test('light theme contrast markup and VS Code variables', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  // Check that theme overrides css is injected
  assert.match(html, /theme-light/);
  assert.match(html, /--sc-bg:\s*#f3f4f6/);
  assert.match(html, /--sc-surface:\s*#ffffff/);
});

test('dark theme contrast markup and VS Code variables', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'dark');
  assert.match(html, /theme-dark/);
  assert.match(html, /--sc-bg:\s*var\(--vscode-editor-background,\s*#1e1e1e\)/);
  assert.match(html, /--sc-surface:\s*var\(--vscode-sideBar-background/);
});

test('A/B selection styling in CSS classes', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  // Check left border shadows for selected row cells
  assert.match(html, /\.scans-row\.selected-A td:first-child[\s\S]*?box-shadow/);
  assert.match(html, /\.scans-row\.selected-B td:first-child[\s\S]*?box-shadow/);
  // Check selected cards accent colors
  assert.match(html, /\.selection-card\.selected-A[\s\S]*?border-left/);
  assert.match(html, /\.selection-card\.selected-B[\s\S]*?border-left/);
});

test('real VS Code body selectors are defined for inputs and selects', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  assert.match(html, /\.filter-bar input/);
  assert.match(html, /background:\s*var\(--sc-input-bg\)/);
});

test('compare button has correct initial disabled state and ID', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  assert.match(html, /id="btn-compare-scans"/);
  assert.match(html, /disabled/);
});

test('quality badge labels and tooltips explain scan completeness', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  // Verify explain tooltips are defined in the file
  assert.match(html, /"État suffisamment complet pour une comparaison fiable."/);
  assert.match(html, /"Tous les scanners attendus n\\?'ont pas été exécutés."/);
  assert.match(html, /"Le scan contient une couverture insuffisante ou un échec."/);
});

test('coverage tooltip explains completed vs expected scanner count', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  // Verify coverage count header column and JS tooltip rendering code
  assert.match(html, /Couverture scanners/);
  assert.match(html, /scannersTd\.title\s*=\s*completedScanners\.length/);
  assert.match(html, /exécuté/);
  assert.match(html, /sur/);
});

test('third selection behavior displays a warning banner', () => {
  const html = renderScanComparisonHtml([], 'nonce', 'light');
  // Verify warning banner logic in JS code
  assert.match(html, /Vous avez déjà sélectionné deux scans. Veuillez en désélectionner un pour faire un nouveau choix./);
});

// ============================================================
// REGRESSION TESTS FOR BROKEN DATA FLOW & CLIENT-SIDE LOGIC
// ============================================================

const vm = require('node:vm');

function runWebviewScript(html, overrides = {}) {
  const startIdx = html.indexOf('<script');
  const scriptStart = html.indexOf('>', startIdx) + 1;
  const endIdx = html.indexOf('</script>', scriptStart);
  const scriptCode = html.slice(scriptStart, endIdx);

  // Mock DOM
  const elements = {};
  const eventListeners = {};
  const tbodyChildren = [];

  const getElement = (id) => {
    if (!elements[id]) {
      let defVal = '';
      if (id === 'sort-order-select') defVal = 'newest';
      if (id === 'filter-status-select') defVal = 'All';
      
      elements[id] = {
        id,
        style: {},
        classList: {
          add: (cls) => { elements[id].classes.add(cls); },
          remove: (cls) => { elements[id].classes.delete(cls); }
        },
        classes: new Set(),
        innerText: '',
        _innerHTML: '',
        get innerHTML() { return this._innerHTML; },
        set innerHTML(val) {
          this._innerHTML = val;
          if (val === '' && id === 'scans-table-tbody') {
            tbodyChildren.length = 0;
          }
        },
        value: defVal,
        addEventListener: (event, handler) => {
          if (!eventListeners[id]) eventListeners[id] = {};
          eventListeners[id][event] = handler;
        },
        appendChild: (child) => {
          if (id === 'scans-table-tbody') {
            tbodyChildren.push(child);
          }
        }
      };
    }
    return elements[id];
  };

  const makeElem = (tag) => {
    const el = {
      tag,
      style: {},
      classList: {
        add: (cls) => { el.classes.add(cls); },
        remove: (cls) => { el.classes.delete(cls); }
      },
      classes: new Set(),
      innerText: '',
      innerHTML: '',
      title: '',
      colSpan: 0,
      children: [],
      addEventListener: (event, handler) => {
        el.listeners = el.listeners || {};
        el.listeners[event] = handler;
      },
      appendChild: (c) => {
        el.children.push(c);
      }
    };
    return el;
  };

  const context = {
    acquireVsCodeApi: () => ({ postMessage: (msg) => { context.lastPostedMessage = msg; } }),
    window: {
      addEventListener: (event, handler) => {
        context.windowListeners = context.windowListeners || {};
        context.windowListeners[event] = handler;
      }
    },
    document: {
      getElementById: getElement,
      querySelectorAll: (sel) => {
        if (sel === '.tab-btn') {
          return [
            getElement('tab-btn-new'),
            getElement('tab-btn-resolved'),
            getElement('tab-btn-persistent'),
            getElement('tab-btn-sevchanged')
          ];
        }
        if (sel === '.tab-content') {
          return [
            getElement('tab-new'),
            getElement('tab-resolved'),
            getElement('tab-persistent'),
            getElement('tab-sevchanged')
          ];
        }
        return [];
      },
      createElement: makeElem
    },
    atob: (str) => Buffer.from(str, 'base64').toString('binary'),
    ...overrides
  };

  vm.createContext(context);
  vm.runInContext(scriptCode, context);

  return {
    context,
    elements,
    eventListeners,
    tbodyChildren
  };
}

test('1. persisted scans are serialized into comparison page', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  // Check that the base64 contains the serialized scans data
  const base64Match = html.match(/const scansBase64 = "([^"]+)"/);
  assert.ok(base64Match);
  const decoded = JSON.parse(Buffer.from(base64Match[1], 'base64').toString('utf8'));
  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].scan_id, 15);
});

test('2. default page renders scan rows', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);
  // Default comparable length >= 2 preselects them and updates UI
  assert.equal(sandbox.tbodyChildren.length, 2);
  assert.equal(sandbox.tbodyChildren[0].children[1].innerText, '#15'); // Scan ID cell is index 1
  assert.equal(sandbox.tbodyChildren[1].children[1].innerText, '#14');
});

test('3. default filters do NOT hide scans', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);
  // Initial search is empty, status is ALL, comparableOnly is false, sort is newest. All should be visible.
  assert.equal(sandbox.tbodyChildren.length, 2);
});

test('4. newest-first ordering works', () => {
  const scans = [
    scan(13, [], [{ tool: 'Semgrep', status: 'completed' }], 'juice-shop'),
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }], 'juice-shop')
  ];
  // Scan 13 finished first, Scan 15 finished later
  scans[0].result.finished_at = '2026-08-10T12:00:00Z';
  scans[1].result.finished_at = '2026-08-12T12:00:00Z';

  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);
  
  // Sort is newest first by default: scan 15 then scan 13
  assert.equal(sandbox.tbodyChildren[0].children[1].innerText, '#15');
  assert.equal(sandbox.tbodyChildren[1].children[1].innerText, '#13');
});

test('5. comparableOnly=false shows partial scans', () => {
  // Scan 15 is comparable, Scan 14 is partiel (has a failed scan)
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'failed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);
  
  // Under comparableOnly = false, both are visible
  assert.equal(sandbox.tbodyChildren.length, 2);
});

test('6. comparableOnly=true filters correctly', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'failed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Set comparableOnly checkbox to true and trigger filter change listener
  sandbox.elements['comparable-only-checkbox'].checked = true;
  sandbox.eventListeners['comparable-only-checkbox'].change();

  // Only scan 15 (comparable) remains visible
  assert.equal(sandbox.tbodyChildren.length, 1);
  assert.equal(sandbox.tbodyChildren[0].children[1].innerText, '#15');
});

test('7. search works', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }], 'workspace-A'),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }], 'workspace-B')
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Search for workspace-B
  sandbox.elements['search-scan-input'].value = 'workspace-B';
  sandbox.eventListeners['search-scan-input'].input();

  assert.equal(sandbox.tbodyChildren.length, 1);
  assert.equal(sandbox.tbodyChildren[0].children[1].innerText, '#14');
});

test('8. first selection populates A', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Deselect automatically preselected ones to start fresh
  sandbox.eventListeners['btn-deselect-A'].click({ stopPropagation: () => {} });
  sandbox.eventListeners['btn-deselect-B'].click({ stopPropagation: () => {} });

  assert.equal(sandbox.elements['card-A-empty'].style.display, 'block');
  assert.equal(sandbox.elements['card-B-empty'].style.display, 'block');

  // Click on row 15 (which is index 0 in filtered rows list)
  sandbox.tbodyChildren[0].listeners.click();

  assert.equal(sandbox.elements['card-A-id'].innerText, 'Scan #15');
  assert.equal(sandbox.elements['card-A-empty'].style.display, 'none');
  assert.equal(sandbox.elements['card-A-details'].style.display, 'block');
});

test('9. second selection populates B', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Clear selections
  sandbox.eventListeners['btn-deselect-A'].click({ stopPropagation: () => {} });
  sandbox.eventListeners['btn-deselect-B'].click({ stopPropagation: () => {} });

  // Select 15 then 14
  sandbox.tbodyChildren[0].listeners.click(); // selects A = 15
  sandbox.tbodyChildren[1].listeners.click(); // selects B = 14

  assert.equal(sandbox.elements['card-A-id'].innerText, 'Scan #15');
  assert.equal(sandbox.elements['card-B-id'].innerText, 'Scan #14');
  assert.equal(sandbox.elements['card-B-empty'].style.display, 'none');
  assert.equal(sandbox.elements['card-B-details'].style.display, 'block');
});

test('10. compare button enables with two scans', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }]),
    scan(14, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Default preselected comparable length is 2, so compare button should be enabled
  assert.equal(sandbox.elements['btn-compare-scans'].disabled, false);
  assert.match(sandbox.elements['btn-compare-scans'].innerText, /Comparer #14 → #15/); // A is 14 (lower ID), B is 15 (higher ID)

  // Clear one selection
  sandbox.eventListeners['btn-deselect-A'].click({ stopPropagation: () => {} });
  assert.equal(sandbox.elements['btn-compare-scans'].disabled, true);
});

test('11. optional missing metadata does not remove row', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  // Remove workspace and git commit
  scans[0].workspace = undefined;
  scans[0].git_commit = undefined;

  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Row should still be visible and not crash
  assert.equal(sandbox.tbodyChildren.length, 1);
  assert.equal(sandbox.tbodyChildren[0].children[1].innerText, '#15');
});

test('12. no raw JSON appears', () => {
  const scans = [
    scan(15, [{ id: 'vuln-1', tool: 'Semgrep', title: 'dangerous-command-execution' }], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  // Check html text does not leak findings title in raw JSON dump
  assert.doesNotMatch(html, /dangerous-command-execution/);
});

test('13. details expansion still works', () => {
  const scans = [
    scan(15, [], [{ tool: 'Semgrep', status: 'completed' }])
  ];
  const html = renderScanComparisonHtml(scans, 'nonce');
  const sandbox = runWebviewScript(html);

  // Row expand element is last cell (children[7] in 8-column layout)
  // Inside expandTd there is an expandBtn
  const expandTd = sandbox.tbodyChildren[0].children[7];
  const expandBtn = expandTd.children[0];
  
  // Click expand
  expandBtn.listeners.click({ stopPropagation: () => {} });
  
  // After expanding, sandbox.tbodyChildren should contain two rows: 
  // index 0: standard row, index 1: details row
  assert.equal(sandbox.tbodyChildren.length, 2);
  assert.ok(sandbox.tbodyChildren[1].className.includes('expanded'));
});

const { normalizeScanToCamelCase } = require('../src/backend');

test('selected scan returns actual findings and maps snake_case to camelCase', () => {
  const rawScan = {
    scan_id: 42,
    result: {
      workspace: 'test',
      findings: [
        {
          id: 'vuln-1',
          tool: 'Semgrep',
          rule_id: 'rule-id-1',
          title: 'Title',
          severity: 'error',
          raw_severity: 'CRITICAL',
          category: 'security',
          file: 'src/main.js',
          start_line: 10,
          start_column: 5,
          end_line: 10,
          end_column: 15
        }
      ],
      scanners: [
        { tool: 'Semgrep', status: 'completed' }
      ]
    }
  };

  const scan = normalizeScanToCamelCase(rawScan);
  assert.equal(scan.scan_id, 42);
  assert.equal(scan.result.findings.length, 1);
  
  // Check that properties are normalized to camelCase
  const finding = scan.result.findings[0];
  assert.equal(finding.ruleId, 'rule-id-1');
  assert.equal(finding.rawSeverity, 'CRITICAL');
  assert.equal(finding.startLine, 10);
  assert.equal(finding.startColumn, 5);
});

test('severity counts, scanner counts, and diff calculations match findings', () => {
  const scanA = {
    scan_id: 13,
    result: {
      findings: [
        { id: 'f-1', tool: 'Semgrep', rawSeverity: 'CRITICAL' },
        { id: 'f-2', tool: 'Semgrep', rawSeverity: 'HIGH' }
      ],
      scanners: [{ tool: 'Semgrep', status: 'completed' }]
    }
  };
  const scanB = {
    scan_id: 14,
    result: {
      findings: [
        { id: 'f-1', tool: 'Semgrep', rawSeverity: 'CRITICAL' }, // Persistent
        { id: 'f-2', tool: 'Semgrep', rawSeverity: 'LOW' },      // Severity changed
        { id: 'f-3', tool: 'Semgrep', rawSeverity: 'HIGH' }      // New
      ],
      scanners: [{ tool: 'Semgrep', status: 'completed' }]
    }
  };

  const comp = compareScans(scanA, scanB);
  
  assert.equal(comp.added.length, 1); // f-3
  assert.equal(comp.resolved.length, 0);
  assert.equal(comp.persistent.length, 2); // f-1, f-2
  assert.equal(comp.severityChanged.length, 1); // f-2 changed HIGH -> LOW
  assert.equal(comp.unchanged.length, 1); // f-1 CRITICAL
  
  assert.equal(comp.beforeBySeverity['CRITICAL'], 1);
  assert.equal(comp.beforeBySeverity['HIGH'], 1);
  assert.equal(comp.afterBySeverity['CRITICAL'], 1);
  assert.equal(comp.afterBySeverity['LOW'], 1);
  assert.equal(comp.afterBySeverity['HIGH'], 1);

  assert.equal(comp.perTool[0].before, 2);
  assert.equal(comp.perTool[0].after, 3);
});

test('missing scanner does not create false resolved findings and marks partial scans non-comparable', () => {
  const scanA = {
    scan_id: 13,
    result: {
      findings: [
        { id: 'f-1', tool: 'Semgrep', rawSeverity: 'CRITICAL' },
        { id: 'f-2', tool: 'Gitleaks', rawSeverity: 'HIGH' }
      ],
      scanners: [
        { tool: 'Semgrep', status: 'completed' },
        { tool: 'Gitleaks', status: 'completed' }
      ]
    }
  };
  const scanB = {
    scan_id: 14,
    result: {
      findings: [
        { id: 'f-1', tool: 'Semgrep', rawSeverity: 'CRITICAL' }
      ],
      scanners: [
        { tool: 'Semgrep', status: 'completed' }
      ] // Gitleaks is missing/not completed in scanB
    }
  };

  const comp = compareScans(scanA, scanB);
  
  // Since Gitleaks is missing in scanB, f-2 from scanA must NOT be marked resolved!
  assert.equal(comp.resolved.length, 0);
  assert.equal(comp.excludedTools.includes('Gitleaks'), true);
  assert.equal(comp.comparableTools.includes('Semgrep'), true);
});



// ===========================================================================
// Regression : Compare Scans doit retomber sur l historique local (Checkpoint 5)
//
// La commande ne lisait que le backend. Hors ligne, ou avec moins de deux scans
// exploitables, elle annoncait « aucun scan disponible pour comparer » alors que
// Security Center avait deja persiste ces scans sous LOCAL_SCAN_HISTORY_KEY.
// La page Historique des scans avait deja le bon comportement : c est elle qui
// sert de reference.
// ===========================================================================

const fsCk5 = require('node:fs');
const pathCk5 = require('node:path');
const { appendLocalHistory, localScanAsComparable, comparableLocalScans, HISTORY_KEY } = require('../src/scan-history-page');

const ck5ExtensionSource = () => fsCk5.readFileSync(pathCk5.join(__dirname, '..', 'src', 'extension.js'), 'utf8').split('\r').join('');

/** Une sauvegarde locale telle que `addCurrentScanToLocalHistory` l ecrit. */
function localEntry(localId, savedAt, findings, scanners = [{ tool: 'Semgrep', status: 'completed' }]) {
  return { localId, savedAt, workspace: 'demo', findings, scanners, dashboardOptions: { workspace: 'demo' } };
}

/** Un enregistrement backend tel que `getScan` le renvoie. */
function backendScan(scanId, finishedAt, findings, scanners = [{ tool: 'Semgrep', status: 'completed' }]) {
  return { scan_id: scanId, finished_at: finishedAt, workspace: 'demo', result: { finished_at: finishedAt, workspace: 'demo', findings, scanners } };
}

const ck5Finding = (id, severity = 'HIGH') => ({ id, fingerprint: id, tool: 'Semgrep', rawSeverity: severity, title: `Alerte ${id}`, file: 'src/a.js', startLine: 1, triageStatus: 'new' });

/**
 * Reproduit la selection de source du produit corrige : backend d abord,
 * historique local en repli, message honnete si aucune des deux ne suffit.
 */
function selectComparisonSource({ backendScans = null, backendThrows = '', history = [] }) {
  const MINIMUM = 2;
  let scans = [];
  let backendError = '';
  try {
    if (backendThrows) throw new Error(backendThrows);
    scans = backendScans || [];
  } catch (error) { backendError = error.message; }
  let source = 'backend';
  if (scans.length < MINIMUM) {
    const local = comparableLocalScans(history);
    if (local.length >= MINIMUM) { scans = local; source = 'local'; }
  }
  if (scans.length < MINIMUM) {
    if (backendError) return { state: 'error', message: backendError };
    return { state: 'empty', message: 'Security Center : aucun scan disponible pour comparer.' };
  }
  return { state: 'ready', source, scans };
}

test('compare : le backend reste prefere quand il fournit assez de scans', () => {
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')]), localEntry('local-2', '2026-08-02T00:00:00Z', [])];
  const result = selectComparisonSource({
    backendScans: [backendScan(1, '2026-08-10T00:00:00Z', [ck5Finding('B1')]), backendScan(2, '2026-08-11T00:00:00Z', [])],
    history
  });
  assert.equal(result.state, 'ready');
  assert.equal(result.source, 'backend', 'le backend ne doit jamais etre remplace quand il suffit');
  assert.deepEqual(result.scans.map((scan) => scan.scan_id), [1, 2]);
});

test('compare : backend indisponible, l historique local prend le relais', () => {
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')]), localEntry('local-2', '2026-08-02T00:00:00Z', [])];
  const result = selectComparisonSource({ backendThrows: 'Le backend local ne répond pas.', history });
  assert.equal(result.state, 'ready');
  assert.equal(result.source, 'local');
  const comparison = compareScans(result.scans[0], result.scans[1]);
  assert.equal(comparison.resolved.length, 1, 'la comparaison fonctionne depuis l historique local');
  assert.equal(comparison.added.length, 0);
});

test('compare : backend vide, l historique local prend le relais', () => {
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')]), localEntry('local-2', '2026-08-02T00:00:00Z', [ck5Finding('L1'), ck5Finding('L2')])];
  const result = selectComparisonSource({ backendScans: [], history });
  assert.equal(result.state, 'ready');
  assert.equal(result.source, 'local');
  const comparison = compareScans(result.scans[0], result.scans[1]);
  assert.equal(comparison.added.length, 1);
  assert.equal(comparison.persistent.length, 1);
});

test('compare : un seul scan backend ne suffit pas, le local prend le relais', () => {
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')]), localEntry('local-2', '2026-08-02T00:00:00Z', [])];
  const result = selectComparisonSource({ backendScans: [backendScan(1, '2026-08-10T00:00:00Z', [])], history });
  assert.equal(result.state, 'ready');
  assert.equal(result.source, 'local', 'deux scans sont necessaires pour comparer');
  assert.equal(result.scans.length, 2);
});

test('compare : aucune source suffisante conserve le message honnete existant', () => {
  assert.equal(selectComparisonSource({ backendScans: [], history: [] }).message, 'Security Center : aucun scan disponible pour comparer.');
  assert.equal(selectComparisonSource({ backendScans: [], history: [localEntry('local-1', '2026-08-01T00:00:00Z', [])] }).state, 'empty');
  // Une panne backend reelle n est pas masquee par « aucun scan ».
  const failed = selectComparisonSource({ backendThrows: 'Le backend local ne répond pas.', history: [] });
  assert.equal(failed.state, 'error');
  assert.match(failed.message, /ne répond pas/);
});

test('compare : une sauvegarde locale sans scanner n est pas comparable', () => {
  // Sans statut de scanner, `compareScans` n a aucune couverture a intersecter :
  // l entree est ecartee au lieu de produire une comparaison vide trompeuse.
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')], []), localEntry('local-2', '2026-08-02T00:00:00Z', [], [])];
  assert.equal(comparableLocalScans(history).length, 0);
  assert.equal(selectComparisonSource({ backendScans: [], history }).state, 'empty');
});

test('compare : l historique local n est ni mute ni vide par la comparaison', () => {
  const history = [localEntry('local-1', '2026-08-01T00:00:00Z', [ck5Finding('L1')]), localEntry('local-2', '2026-08-02T00:00:00Z', [])];
  const snapshot = JSON.stringify(history);
  const result = selectComparisonSource({ backendThrows: 'offline', history });
  compareScans(result.scans[0], result.scans[1]);
  assert.equal(JSON.stringify(history), snapshot, 'les entrees persistees restent intactes');
  assert.equal(history.length, 2);
  // L adaptateur retourne bien un nouvel objet.
  const adapted = localScanAsComparable(history[0]);
  assert.notEqual(adapted, history[0]);
  assert.equal(adapted.result.findings, history[0].findings, 'les findings sont passes tels quels, sans copie ni recalcul');
});

test('compare : l algorithme de comparaison est inchange, quelle que soit la source', () => {
  const findingsA = [ck5Finding('X1'), ck5Finding('X2', 'LOW')];
  const findingsB = [ck5Finding('X2', 'HIGH'), ck5Finding('X3')];
  const fromBackend = compareScans(backendScan(1, '2026-08-01T00:00:00Z', findingsA), backendScan(2, '2026-08-02T00:00:00Z', findingsB));
  const fromLocal = compareScans(
    localScanAsComparable(localEntry('local-1', '2026-08-01T00:00:00Z', findingsA)),
    localScanAsComparable(localEntry('local-2', '2026-08-02T00:00:00Z', findingsB))
  );
  for (const key of ['added', 'resolved', 'persistent', 'severityChanged', 'unchanged']) {
    assert.deepEqual(fromLocal[key].map((f) => f.id), fromBackend[key].map((f) => f.id), `${key} doit etre identique quelle que soit la source`);
  }
});

test('compare : l adaptateur local respecte le contrat lu par la comparaison', () => {
  const entry = localEntry('local-9', '2026-08-05T12:00:00Z', [ck5Finding('Z1')]);
  const adapted = localScanAsComparable(entry);
  assert.equal(adapted.scan_id, 'local-9');
  assert.equal(adapted.finished_at, '2026-08-05T12:00:00Z');
  assert.equal(adapted.result.finished_at, '2026-08-05T12:00:00Z');
  assert.deepEqual(adapted.result.scanners, entry.scanners);
  assert.equal(localScanAsComparable(null), null);
  assert.equal(localScanAsComparable({ savedAt: 'x' }), null, 'une entree sans identifiant local est ignoree');
});

test('compare : cablage reel, repli local sans seconde cle de persistance', () => {
  const source = ck5ExtensionSource();
  const command = source.match(/registerCommand\('securityCenter\.compareScans'[\s\S]*?const prunedScans/);
  assert.ok(command, 'la commande compareScans doit exister');
  // Le backend reste tente en premier.
  assert.match(command[0], /await listScans\(baseUrl, 100\)/);
  // Le repli lit l historique local existant, via la meme cle.
  assert.match(command[0], /comparableLocalScans\(context\.workspaceState\.get\(LOCAL_SCAN_HISTORY_KEY, \[\]\)\)/);
  // Une panne backend n avorte plus la commande avant le repli.
  assert.doesNotMatch(command[0], /const summaries = await listScans\(baseUrl, 100\);\s*\n\s*if \(!summaries/);
  // Aucune seconde cle de persistance n a ete introduite.
  assert.equal(HISTORY_KEY, 'securityCenter.scanHistory.v1');
  assert.equal((source.match(/securityCenter\.scanHistory\.v\d/g) || []).length, 0, 'la cle n est referencee que par son export');
  // Et rien n est ecrit dans l historique par la comparaison.
  assert.doesNotMatch(command[0], /workspaceState\.update\(LOCAL_SCAN_HISTORY_KEY/);
});

test('compare : la page Historique des scans conserve son comportement', () => {
  const source = ck5ExtensionSource();
  const history = source.match(/registerCommand\('securityCenter\.showScanHistoryPage'[\s\S]*?renderScanHistoryHtml\(localScans, backendScans, backendError/);
  assert.ok(history, 'la page Historique lit toujours local + backend + erreur backend');
  assert.match(source, /const localScans = context\.workspaceState\.get\(LOCAL_SCAN_HISTORY_KEY, \[\]\);/);
});

test('compare : aucune refonte visuelle de la page de comparaison', () => {
  const source = ck5ExtensionSource();
  const command = source.match(/registerCommand\('securityCenter\.compareScans'[\s\S]*?renderScanComparisonHtml\(prunedScans, nonce, theme[^)]*\)/);
  assert.ok(command, 'le rendu de la comparaison est inchange');
  assert.match(command[0], /createWebviewPanel\(\s*'securityCenter\.scanComparison'/);
  // Aucun libelle de debogage de source n a ete ajoute a la page.
  assert.doesNotMatch(source, /LOCAL FALLBACK|REPLI LOCAL|fallbackBadge/i);
});
