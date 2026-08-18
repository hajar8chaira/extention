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


