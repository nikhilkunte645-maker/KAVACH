/**
 * KAVACH - Main Application Controller
 * Premium 100% Client-Side Privacy Engine & Security Dashboard
 */

import { PiiType, RedactionMode, ValidationStatus } from './core/types.js';
import { processText, processCsv } from './core/engine.js';
import { computeDiffSegments, renderSafeDiffToDom } from './core/diff.js';
import { logger } from './core/logger.js';
import { stateManager } from './core/state.js';
import { runAllSelfTests } from './self-test/runner.js';
import { getSelfTestCases } from './self-test/test-cases.js';

// DOM Elements
const tabBtns = /** @type {NodeListOf<HTMLButtonElement>} */ (document.querySelectorAll('.liquid-tab-btn'));
const tabPanes = document.querySelectorAll('.tab-pane');
const glassLens = /** @type {HTMLElement} */ (document.getElementById('glass-lens'));
const inputText = /** @type {HTMLTextAreaElement} */ (document.getElementById('input-text'));
const outputText = /** @type {HTMLTextAreaElement} */ (document.getElementById('output-text'));
const diffOutput = /** @type {HTMLElement} */ (document.getElementById('diff-output'));
const findingsTbody = /** @type {HTMLElement} */ (document.getElementById('findings-tbody'));
const findingsCountBadge = document.getElementById('findings-count-badge');
const charCount = document.getElementById('char-count');
const sourceFormatLabel = document.getElementById('source-format-label');
const dropZone = document.getElementById('drop-zone');
const fileInput = /** @type {HTMLInputElement} */ (document.getElementById('file-input'));
const btnCopyOutput = document.getElementById('btn-copy-output');
const btnClearInput = document.getElementById('btn-clear-input');
const btnLoadSample = document.getElementById('btn-load-sample');
const btnRunRedact = document.getElementById('btn-run-redact');
const btnExportRedacted = document.getElementById('btn-export-redacted');
const btnExportLogs = document.getElementById('btn-export-logs');
const btnExportLogsPane = document.getElementById('btn-export-logs-pane');
const btnClearLogs = document.getElementById('btn-clear-logs');
const btnReset = document.getElementById('btn-reset');
const btnRunTests = document.getElementById('btn-run-tests');
const heroBtnRedact = document.getElementById('hero-btn-redact');
const heroBtnSelfTest = document.getElementById('hero-btn-selftest');
const logTerminal = document.getElementById('log-terminal');
const diffStatusLabel = document.getElementById('diff-status-label');

// Metric elements for self-test
const metricTotal = document.getElementById('metric-total');
const metricPassed = document.getElementById('metric-passed');
const metricFailed = document.getElementById('metric-failed');
const metricDuration = document.getElementById('metric-duration');
const testRunnerStatus = document.getElementById('test-runner-status');
const testResultsList = document.getElementById('test-results-list');
const progressBarPass = document.getElementById('progress-bar-pass');
const progressBarFail = document.getElementById('progress-bar-fail');
const progressLabel = document.getElementById('progress-label');
const reliabilityRateLabel = document.getElementById('reliability-rate-label');
const donutCircle = document.getElementById('donut-circle');
const donutText = document.getElementById('donut-text');
const testSearch = /** @type {HTMLInputElement} */ (document.getElementById('test-search'));
const failuresOnlyToggle = /** @type {HTMLInputElement} */ (document.getElementById('failures-only-toggle'));
const expandAllBtn = document.getElementById('expand-all-btn');
const collapseAllBtn = document.getElementById('collapse-all-btn');

// Analytics elements
const statCards = document.getElementById('stat-cards');
const statPan = document.getElementById('stat-pan');
const statAadhaar = document.getElementById('stat-aadhaar');
const statIpv4 = document.getElementById('stat-ipv4');
const statPhone = document.getElementById('stat-phone');
const statEmail = document.getElementById('stat-email');
const statLuhnRejected = document.getElementById('stat-luhn-rejected');
const statTotalMasked = document.getElementById('stat-total-masked');
const statCharsProcessed = document.getElementById('stat-chars-processed');
const statActiveMode = document.getElementById('stat-active-mode');
const logCountMetric = document.getElementById('log-count-metric');
const activityLogEmpty = document.getElementById('activity-log-empty');

// Configuration Checkboxes & Radios
const detCheckboxes = {
  [PiiType.CREDIT_CARD]: document.getElementById('det-cc'),
  [PiiType.PAN]: document.getElementById('det-pan'),
  [PiiType.AADHAAR]: document.getElementById('det-aadhaar'),
  [PiiType.IPV4]: document.getElementById('det-ipv4'),
  [PiiType.PHONE_IN]: document.getElementById('det-phone-in'),
  [PiiType.PHONE_INTL]: document.getElementById('det-phone-intl'),
  [PiiType.EMAIL]: document.getElementById('det-email')
};

const optFormulaShield = /** @type {HTMLInputElement} */ (document.getElementById('opt-formula-shield'));
const optAadhaarVerhoeff = /** @type {HTMLInputElement} */ (document.getElementById('opt-aadhaar-verhoeff'));
const redactionModeRadios = /** @type {NodeListOf<HTMLInputElement>} */ (document.querySelectorAll('input[name="redaction-mode"]'));

// Active log filter
let currentLogFilter = 'all';

// Debounce timer
let debounceTimer = /** @type {any} */ (null);

/**
 * Updates the physical position and width of the Liquid Glass Lens.
 * @param {HTMLButtonElement} activeBtn
 */
function updateGlassLens(activeBtn) {
  if (!glassLens || !activeBtn) return;
  const parentRect = activeBtn.parentElement?.getBoundingClientRect();
  const btnRect = activeBtn.getBoundingClientRect();

  if (parentRect) {
    const offsetLeft = btnRect.left - parentRect.left;
    glassLens.style.transform = `translateX(${offsetLeft - 2}px)`;
    glassLens.style.width = `${btnRect.width}px`;
  }
}

/**
 * Activates a specific tab by ID.
 * @param {string} targetId
 */
function activateTab(targetId) {
  if (targetId === 'tab-docs') {
    targetId = 'tab-analytics';
    setTimeout(() => {
      const specEl = document.getElementById('tab-docs');
      specEl?.scrollIntoView({ behavior: 'smooth' });
    }, 50);
  }

  tabBtns.forEach((btn) => {
    const isTarget = btn.getAttribute('data-tab') === targetId;
    btn.classList.toggle('active', isTarget);
    btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    btn.setAttribute('tabindex', isTarget ? '0' : '-1');
    if (isTarget) {
      updateGlassLens(btn);
    }
  });

  tabPanes.forEach((p) => {
    p.classList.toggle('active', p.id === targetId);
  });
}

/**
 * Initializes the Tab Bar with keyboard navigation.
 */
function initLiquidTabs() {
  const btnArray = Array.from(tabBtns);

  btnArray.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      if (targetId) activateTab(targetId);
    });

    // WAI-ARIA Keyboard Navigation: ArrowLeft / ArrowRight / Home / End
    btn.addEventListener('keydown', (e) => {
      let targetIndex = index;
      if (e.key === 'ArrowRight') {
        targetIndex = (index + 1) % btnArray.length;
      } else if (e.key === 'ArrowLeft') {
        targetIndex = (index - 1 + btnArray.length) % btnArray.length;
      } else if (e.key === 'Home') {
        targetIndex = 0;
      } else if (e.key === 'End') {
        targetIndex = btnArray.length - 1;
      } else {
        return;
      }

      e.preventDefault();
      const nextBtn = btnArray[targetIndex];
      nextBtn.focus();
      const targetId = nextBtn.getAttribute('data-tab');
      if (targetId) activateTab(targetId);
    });
  });

  const initialActive = document.querySelector('.liquid-tab-btn.active');
  if (initialActive instanceof HTMLButtonElement) {
    setTimeout(() => updateGlassLens(initialActive), 50);
  }

  window.addEventListener('resize', () => {
    const currentActive = document.querySelector('.liquid-tab-btn.active');
    if (currentActive instanceof HTMLButtonElement) {
      updateGlassLens(currentActive);
    }
  });
}

/**
 * Reads current active configuration from UI inputs.
 */
function getActiveConfig() {
  const enabledTypes = new Set();
  for (const [type, el] of Object.entries(detCheckboxes)) {
    if (el && /** @type {HTMLInputElement} */ (el).checked) {
      enabledTypes.add(type);
    }
  }

  let redactionMode = /** @type {string} */ (RedactionMode.FULL_MASK);
  redactionModeRadios.forEach((radio) => {
    if (radio.checked) {
      redactionMode = radio.value;
    }
  });

  return {
    enabledTypes,
    redactionMode,
    sanitizeCsvFormulas: optFormulaShield?.checked ?? true,
    requireVerhoeff: optAadhaarVerhoeff?.checked ?? true
  };
}

/**
 * Updates line numbers gutters for input and output textareas.
 */
function updateLineNumbers() {
  const origLines = (inputText?.value || '').split('\n').length;
  const redLines = (outputText?.value || '').split('\n').length;
  const totalLines = Math.max(origLines, redLines, 12);
  const gutterText = Array.from({ length: totalLines }, (_, i) => String(i + 1).padStart(2, '0')).join('\n');

  const origGutter = document.getElementById('pane-original-gutter');
  const redGutter = document.getElementById('pane-redacted-gutter');
  const lineCountBadge = document.getElementById('line-count-badge');

  if (origGutter) origGutter.textContent = gutterText;
  if (redGutter) redGutter.textContent = gutterText;
  if (lineCountBadge) lineCountBadge.textContent = `${origLines} lines`;
}

/**
 * Initializes synchronized scrolling without feedback loops.
 */
function initScrollSync() {
  const origGutter = document.getElementById('pane-original-gutter');
  const redGutter = document.getElementById('pane-redacted-gutter');
  let isSyncing = false;

  inputText?.addEventListener('scroll', () => {
    if (isSyncing) return;
    isSyncing = true;
    if (origGutter) origGutter.scrollTop = inputText.scrollTop;
    if (outputText) outputText.scrollTop = inputText.scrollTop;
    if (redGutter) redGutter.scrollTop = inputText.scrollTop;
    isSyncing = false;
  });

  outputText?.addEventListener('scroll', () => {
    if (isSyncing) return;
    isSyncing = true;
    if (redGutter) redGutter.scrollTop = outputText.scrollTop;
    if (inputText) inputText.scrollTop = outputText.scrollTop;
    if (origGutter) origGutter.scrollTop = outputText.scrollTop;
    isSyncing = false;
  });
}

/**
 * Initializes the Segmented Mode Control UI.
 */
function initSegmentedControl() {
  const modeFull = document.getElementById('label-mode-full');
  const modePartial = document.getElementById('label-mode-partial');
  const modePseudo = document.getElementById('label-mode-pseudo');
  const modeLabels = [modeFull, modePartial, modePseudo];

  redactionModeRadios.forEach((radio) => {
    radio.addEventListener('change', () => {
      modeLabels.forEach((lbl) => {
        const input = lbl?.querySelector('input');
        lbl?.classList.toggle('active', input?.checked ?? false);
      });
      runProcessing();
    });
  });

  modeLabels.forEach((lbl) => {
    lbl?.addEventListener('click', () => {
      const input = lbl.querySelector('input');
      if (input) {
        input.checked = true;
        modeLabels.forEach((l) => l?.classList.toggle('active', l === lbl));
        runProcessing();
      }
    });
  });
}

/**
 * Main processing function triggered on text or configuration change.
 */
export function runProcessing() {
  const text = inputText.value;
  if (charCount) charCount.textContent = `${text.length} chars`;
  if (statCharsProcessed) statCharsProcessed.textContent = String(text.length);

  const config = getActiveConfig();
  if (statActiveMode) statActiveMode.textContent = config.redactionMode.replace('_', ' ');

  updateLineNumbers();

  if (!text) {
    outputText.value = '';
    updateLineNumbers();
    if (diffStatusLabel) diffStatusLabel.textContent = 'No modifications';
    while (diffOutput?.firstChild) diffOutput.removeChild(diffOutput.firstChild);
    if (diffOutput) {
      const span = document.createElement('span');
      span.className = 'diff-unchanged';
      span.textContent = 'Input text above to see side-by-side safe redaction diff...';
      diffOutput.appendChild(span);
    }

    if (findingsTbody) {
      while (findingsTbody.firstChild) findingsTbody.removeChild(findingsTbody.firstChild);
      const emptyRow = document.createElement('tr');
      const emptyCell = document.createElement('td');
      emptyCell.colSpan = 5;
      emptyCell.style.textAlign = 'center';
      emptyCell.style.color = 'var(--text-muted)';
      emptyCell.style.padding = '1.5rem';
      emptyCell.textContent = 'No PII findings detected in current input.';
      emptyRow.appendChild(emptyCell);
      findingsTbody.appendChild(emptyRow);
    }
    if (findingsCountBadge) findingsCountBadge.textContent = '0';
    updateAnalyticsCards({}, 0, 0);
    return;
  }

  const isCsv = stateManager.sourceType === 'csv';

  if (isCsv) {
    if (sourceFormatLabel) sourceFormatLabel.textContent = 'CSV File';
    const csvResult = processCsv(text, {
      enabledTypes: config.enabledTypes,
      redactionMode: config.redactionMode,
      pseudonymizer: stateManager.pseudonymizer,
      sanitizeFormulas: config.sanitizeCsvFormulas,
      requireVerhoeff: config.requireVerhoeff
    });

    outputText.value = csvResult.redactedCsv;
    updateLineNumbers();

    if (findingsCountBadge) findingsCountBadge.textContent = String(csvResult.findings.length);
    if (diffStatusLabel) {
      diffStatusLabel.textContent = `${csvResult.findings.length} modification${csvResult.findings.length === 1 ? '' : 's'}`;
    }
    renderFindingsTable(csvResult.findings);

    const luhnRejected = 0;

    updateAnalyticsCards(csvResult.countsByType, csvResult.findings.length, luhnRejected);

    // Render preview diff safely
    const previewRaw = text.slice(0, 3000);
    const previewFindings = csvResult.findings.filter((f) => f.start < 3000);
    const diffSegs = computeDiffSegments(previewRaw, previewFindings);
    if (diffOutput) renderSafeDiffToDom(diffOutput, diffSegs);
  } else {
    if (sourceFormatLabel) sourceFormatLabel.textContent = 'Raw Text';
    const textResult = processText(text, {
      enabledTypes: config.enabledTypes,
      redactionMode: config.redactionMode,
      pseudonymizer: stateManager.pseudonymizer,
      requireVerhoeff: config.requireVerhoeff
    });

    outputText.value = textResult.redactedText;
    updateLineNumbers();

    if (findingsCountBadge) findingsCountBadge.textContent = String(textResult.findings.length);
    if (diffStatusLabel) {
      diffStatusLabel.textContent = `${textResult.findings.length} modification${textResult.findings.length === 1 ? '' : 's'}`;
    }
    renderFindingsTable(textResult.findings);

    const luhnRejected = (textResult.rejectedCandidates || []).filter(
      (c) => c.type === PiiType.CREDIT_CARD && (c.status === ValidationStatus.INVALID_LUHN || c.status === 'INVALID_LUHN')
    ).length;

    updateAnalyticsCards(textResult.countsByType, textResult.findings.length, luhnRejected);

    const diffSegs = computeDiffSegments(text, textResult.findings);
    if (diffOutput) renderSafeDiffToDom(diffOutput, diffSegs);
  }
}

/**
 * Updates the 8 detection metric cards.
 * @param {Record<string, number>} counts
 * @param {number} [total=0]
 * @param {number} [luhnRejected=0]
 */
function updateAnalyticsCards(counts, total = 0, luhnRejected = 0) {
  if (statEmail) statEmail.textContent = String(counts[PiiType.EMAIL] || 0);
  const totalPhone = (counts[PiiType.PHONE_IN] || 0) + (counts[PiiType.PHONE_INTL] || 0);
  if (statPhone) statPhone.textContent = String(totalPhone);
  if (statIpv4) statIpv4.textContent = String(counts[PiiType.IPV4] || 0);
  if (statPan) statPan.textContent = String(counts[PiiType.PAN] || 0);
  if (statAadhaar) statAadhaar.textContent = String(counts[PiiType.AADHAAR] || 0);
  if (statCards) statCards.textContent = String(counts[PiiType.CREDIT_CARD] || 0);
  if (statLuhnRejected) statLuhnRejected.textContent = String(luhnRejected);
  if (statTotalMasked) statTotalMasked.textContent = String(total);
}

/**
 * Safely renders the findings table without raw PII exposure.
 * @param {Array<any>} findings
 */
function renderFindingsTable(findings) {
  if (!findingsTbody) return;
  while (findingsTbody.firstChild) {
    findingsTbody.removeChild(findingsTbody.firstChild);
  }

  if (findings.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.style.padding = '1.5rem';
    td.textContent = 'No PII findings detected in current input.';
    tr.appendChild(td);
    findingsTbody.appendChild(tr);
    return;
  }

  findings.forEach((f, idx) => {
    const tr = document.createElement('tr');

    // Index
    const tdIdx = document.createElement('td');
    tdIdx.textContent = String(idx + 1);
    tr.appendChild(tdIdx);

    // Type Badge
    const tdType = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.className = 'type-badge';
    typeBadge.textContent = f.type;
    tdType.appendChild(typeBadge);
    tr.appendChild(tdType);

    // Span [start, end)
    const tdSpan = document.createElement('td');
    tdSpan.style.fontFamily = 'var(--font-mono)';
    tdSpan.textContent = `[${f.start}, ${f.end})`;
    tr.appendChild(tdSpan);

    // Validation Status
    const tdStatus = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = 'status-badge valid';
    statusBadge.textContent = 'VALID';
    tdStatus.appendChild(statusBadge);
    tr.appendChild(tdStatus);

    // Redacted Value
    const tdVal = document.createElement('td');
    tdVal.style.fontFamily = 'var(--font-mono)';
    tdVal.textContent = f.redactedValue || '********';
    tr.appendChild(tdVal);

    findingsTbody.appendChild(tr);
  });
}

/**
 * Filter and render activity logs.
 * @param {Array<any>} logs
 */
function renderLogs(logs) {
  if (!logTerminal) return;
  while (logTerminal.firstChild) {
    logTerminal.removeChild(logTerminal.firstChild);
  }

  if (logCountMetric) logCountMetric.textContent = String(logs.length);

  const filtered = logs.filter((log) => {
    if (currentLogFilter === 'all') return true;
    if (currentLogFilter === 'redaction') return log.operation?.includes('REDACT');
    if (currentLogFilter === 'mode') return log.operation?.includes('MODE') || log.category === 'MODE';
    if (currentLogFilter === 'session') return log.category === 'SESSION' || log.category === 'SYSTEM' || log.operation?.includes('INIT') || log.operation?.includes('FILE');
    return true;
  });

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.id = 'activity-log-empty';
    empty.style.color = 'var(--text-muted)';
    empty.style.fontSize = '12px';
    empty.style.padding = '16px';
    empty.style.textAlign = 'center';
    empty.textContent = 'No activity events matching filter.';
    logTerminal.appendChild(empty);
    return;
  }

  filtered.slice(-100).forEach((log) => {
    const row = document.createElement('div');
    row.className = 'kv-log-row';

    const left = document.createElement('div');
    left.style.display = 'flex';
    left.style.alignItems = 'center';
    left.style.gap = '12px';
    left.style.minWidth = '0';

    const ts = document.createElement('span');
    ts.style.color = 'var(--text-muted)';
    ts.textContent = log.timestamp.slice(11, 23);

    const badge = document.createElement('span');
    badge.className = 'type-badge';
    badge.textContent = log.category || 'LOG';

    const msg = document.createElement('span');
    msg.style.color = 'var(--text-primary)';
    msg.textContent = `${log.operation ? `[${log.operation}] ` : ''}${log.details}`;

    left.appendChild(ts);
    left.appendChild(badge);
    left.appendChild(msg);

    const right = document.createElement('span');
    right.style.color = 'var(--emerald-fg)';
    right.style.fontSize = '11px';
    right.textContent = log.status || 'OK';

    row.appendChild(left);
    row.appendChild(right);
    logTerminal.appendChild(row);
  });

  logTerminal.scrollTop = logTerminal.scrollHeight;
}

/**
 * Safely downloads a string as a client-side file.
 * @param {string} content
 * @param {string} filename
 * @param {string} mimeType
 */
function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 100);
}

// File Drop Zone Setup
function initFileDropZone() {
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer?.files?.length) {
      loadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files?.length) {
      loadFile(fileInput.files[0]);
    }
  });
}

/**
 * Loads a file into transient memory with size boundary verification (20MB limit).
 * @param {File} file
 */
function loadFile(file) {
  const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB
  if (file.size > MAX_FILE_SIZE) {
    logger.log({
      operation: 'FILE_LOAD',
      category: 'ERROR',
      status: 'ERROR',
      details: `File "${file.name}" exceeds 20MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB). Aborted.`
    });
    alert(`File exceeds 20MB client memory limit. Please process files under 20MB.`);
    return;
  }

  const reader = new FileReader();
  const isCsv = file.name.toLowerCase().endsWith('.csv');

  reader.onload = (e) => {
    const content = /** @type {string} */ (e.target?.result || '');
    stateManager.sourceType = isCsv ? 'csv' : 'txt';
    stateManager.fileName = file.name;
    inputText.value = content;
    runProcessing();
    logger.log({
      operation: 'FILE_LOAD',
      category: isCsv ? 'CSV' : 'TEXT',
      count: 1,
      status: 'SUCCESS',
      details: `File read locally "${file.name}" (${(file.size / 1024).toFixed(1)} KB) into memory.`
    });
  };

  reader.readAsText(file, 'utf-8');
}

/**
 * Renders the real 61 self-tests in initial "Not run" state grouped by categories.
 */
function renderInitialTests() {
  if (!testResultsList) return;
  while (testResultsList.firstChild) testResultsList.removeChild(testResultsList.firstChild);

  const testCases = getSelfTestCases();
  const categories = {};

  testCases.forEach((tc) => {
    if (!categories[tc.category]) categories[tc.category] = [];
    categories[tc.category].push(tc);
  });

  Object.entries(categories).forEach(([categoryName, tests]) => {
    const group = document.createElement('div');
    group.className = 'kv-test-group';
    group.dataset.category = categoryName;

    const header = document.createElement('div');
    header.className = 'kv-test-group-header';

    const title = document.createElement('span');
    title.className = 'kv-test-group-title';
    title.textContent = categoryName;

    const badge = document.createElement('span');
    badge.className = 'kv-pane-badge';
    badge.textContent = `0 / ${tests.length} passed`;
    badge.id = `badge-${categoryName.replace(/[^a-zA-Z0-9]/g, '_')}`;

    header.appendChild(title);
    header.appendChild(badge);

    const list = document.createElement('div');
    list.className = 'kv-test-list';

    header.addEventListener('click', () => {
      const isHidden = list.style.display === 'none';
      list.style.display = isHidden ? 'flex' : 'none';
    });

    tests.forEach((t) => {
      const item = document.createElement('div');
      item.className = 'kv-test-item';
      item.dataset.testName = t.name.toLowerCase();
      item.dataset.status = 'not-run';

      const meta = document.createElement('div');
      meta.className = 'kv-test-meta';

      const pill = document.createElement('span');
      pill.className = 'kv-test-status-pill not-run';
      pill.textContent = 'Not run';

      const name = document.createElement('span');
      name.className = 'kv-test-name';
      name.textContent = t.name;

      meta.appendChild(pill);
      meta.appendChild(name);

      const duration = document.createElement('span');
      duration.style.color = 'var(--text-muted)';
      duration.style.fontFamily = 'var(--font-mono)';
      duration.style.fontSize = '12px';
      duration.textContent = '0ms';

      item.appendChild(meta);
      item.appendChild(duration);
      list.appendChild(item);
    });

    group.appendChild(header);
    group.appendChild(list);
    testResultsList.appendChild(group);
  });
}

/**
 * Initializes self-test runner UI interactions.
 */
function initSelfTestRunner() {
  if (!btnRunTests) return;

  renderInitialTests();

  // Search filter
  testSearch?.addEventListener('input', () => {
    const query = testSearch.value.trim().toLowerCase();
    const items = document.querySelectorAll('.kv-test-item');
    items.forEach((item) => {
      const testName = item.getAttribute('data-test-name') || '';
      const parentGroup = item.closest('.kv-test-group');
      const category = parentGroup?.getAttribute('data-category')?.toLowerCase() || '';
      const matches = !query || testName.includes(query) || category.includes(query);
      /** @type {HTMLElement} */ (item).style.display = matches ? 'flex' : 'none';
    });
  });

  // Failures-only toggle
  failuresOnlyToggle?.addEventListener('change', () => {
    const showOnlyFailures = failuresOnlyToggle.checked;
    const items = document.querySelectorAll('.kv-test-item');
    items.forEach((item) => {
      const status = item.getAttribute('data-status');
      if (showOnlyFailures) {
        /** @type {HTMLElement} */ (item).style.display = status === 'fail' ? 'flex' : 'none';
      } else {
        /** @type {HTMLElement} */ (item).style.display = 'flex';
      }
    });
  });

  // Expand / Collapse all
  expandAllBtn?.addEventListener('click', () => {
    document.querySelectorAll('.kv-test-list').forEach((l) => (/** @type {HTMLElement} */ (l).style.display = 'flex'));
  });
  collapseAllBtn?.addEventListener('click', () => {
    document.querySelectorAll('.kv-test-list').forEach((l) => (/** @type {HTMLElement} */ (l).style.display = 'none'));
  });

  btnRunTests.addEventListener('click', async () => {
    btnRunTests.setAttribute('disabled', 'true');
    if (testRunnerStatus) testRunnerStatus.textContent = 'Executing full test suite locally (61 tests)...';

    const testItemEls = document.querySelectorAll('.kv-test-item');
    const categoryPassMap = {};

    const summary = await runAllSelfTests((res, curr, total) => {
      if (progressLabel) progressLabel.textContent = `${curr} / ${total}`;
      const percent = (curr / total) * 100;
      if (progressBarPass) progressBarPass.style.width = `${percent}%`;

      if (!categoryPassMap[res.category]) categoryPassMap[res.category] = { passed: 0, total: 0 };
      categoryPassMap[res.category].total++;
      if (res.passed) categoryPassMap[res.category].passed++;

      // Update badge
      const badgeId = `badge-${res.category.replace(/[^a-zA-Z0-9]/g, '_')}`;
      const badgeEl = document.getElementById(badgeId);
      if (badgeEl) {
        badgeEl.textContent = `${categoryPassMap[res.category].passed} / ${categoryPassMap[res.category].total} passed`;
      }

      // Update row item
      testItemEls.forEach((el) => {
        const nameSpan = el.querySelector('.kv-test-name');
        if (nameSpan && nameSpan.textContent === res.name) {
          el.setAttribute('data-status', res.passed ? 'pass' : 'fail');
          const pill = el.querySelector('.kv-test-status-pill');
          if (pill) {
            pill.className = `kv-test-status-pill ${res.passed ? 'pass' : 'fail'}`;
            pill.textContent = res.passed ? 'Pass' : 'Fail';
          }
          const durSpan = el.querySelector('span:last-child');
          if (durSpan) durSpan.textContent = `${res.durationMs}ms`;
        }
      });
    });

    if (metricTotal) metricTotal.textContent = String(summary.total);
    if (metricPassed) metricPassed.textContent = String(summary.passed);
    if (metricFailed) metricFailed.textContent = String(summary.failed);
    if (metricDuration) metricDuration.textContent = `${summary.durationMs}ms`;

    const passRate = ((summary.passed / summary.total) * 100).toFixed(1);
    if (reliabilityRateLabel) reliabilityRateLabel.textContent = `${passRate}%`;
    if (donutText) donutText.textContent = `${summary.passed}/${summary.total}`;

    // SVG donut calculation: circumference = 2 * PI * 15.5 ~ 97.4
    const dashLength = (summary.passed / summary.total) * 97.4;
    if (donutCircle) donutCircle.setAttribute('stroke-dasharray', `${dashLength} 97.4`);

    if (testRunnerStatus) {
      testRunnerStatus.textContent = summary.failed === 0
        ? `All ${summary.total} tests passed in ${summary.durationMs}ms`
        : `${summary.failed} tests failed!`;
    }
    btnRunTests.removeAttribute('disabled');
  });
}

// Event Listeners Initialization
function initEventListeners() {
  // Text input debounce
  inputText.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runProcessing, 100);
  });

  // Config changes
  Object.values(detCheckboxes).forEach((chk) => {
    chk?.addEventListener('change', runProcessing);
  });
  redactionModeRadios.forEach((rad) => rad.addEventListener('change', runProcessing));
  optFormulaShield?.addEventListener('change', runProcessing);
  optAadhaarVerhoeff?.addEventListener('change', runProcessing);

  // Clear input
  btnClearInput?.addEventListener('click', () => {
    inputText.value = '';
    stateManager.sourceType = 'text';
    runProcessing();
  });

  // Load Sample PII Data (Fictional data representing all categories + 1 Luhn-rejected test card)
  btnLoadSample?.addEventListener('click', () => {
    inputText.value = `# Customer KYC & Payment Verification Log
Customer: Priya Sharma <priya.sharma@example.com>
Phone: +91 98765 43210
PAN: ABCDE1234F | Aadhaar: 2345 6789 0123
Client IP: 192.168.1.24
Primary Card: 4111 1111 1111 1111
Fallback Card (Test): 4111 1111 1111 1112 (Luhn-Rejected)
Backup Contact: ops.alerts@example.com
Secondary Phone: +91 91234 56789
Gateway Node: 10.0.4.18
Audit Reviewer: audit.team@example.com
Status: VERIFIED_LOCAL_ONLY`;
    stateManager.sourceType = 'text';
    runProcessing();
    logger.log({
      operation: 'SAMPLE_LOAD',
      category: 'DATA',
      count: 7,
      status: 'SUCCESS',
      details: 'Loaded sample multi-category PII test data into local memory.'
    });
  });

  // Explicit Redact Button Click
  btnRunRedact?.addEventListener('click', () => {
    runProcessing();
    logger.log({
      operation: 'REDACT',
      category: 'ENGINE',
      status: 'SUCCESS',
      details: 'Executed PII redaction and interval verification pass.'
    });
  });

  // Copy output
  btnCopyOutput?.addEventListener('click', async () => {
    if (outputText.value) {
      await navigator.clipboard.writeText(outputText.value);
      const span = btnCopyOutput.querySelector('span');
      if (span) {
        const originalText = span.textContent;
        span.textContent = 'Copied!';
        setTimeout(() => {
          span.textContent = originalText || 'Copy';
        }, 1500);
      }
    }
  });

  // Export Redacted File
  btnExportRedacted?.addEventListener('click', () => {
    const isCsv = stateManager.sourceType === 'csv';
    const ext = isCsv ? 'csv' : 'txt';
    const filename = `kavach_redacted_${Date.now()}.${ext}`;
    const mime = isCsv ? 'text/csv;charset=utf-8;' : 'text/plain;charset=utf-8;';
    downloadBlob(outputText.value, filename, mime);
    logger.log({
      operation: 'EXPORT',
      category: isCsv ? 'CSV' : 'TEXT',
      count: 1,
      status: 'SUCCESS',
      details: `Exported redacted output to "${filename}".`
    });
  });

  // Export Logs
  const handleExportLogs = () => {
    const filename = `kavach_privacy_logs_${Date.now()}.json`;
    downloadBlob(logger.exportJson(), filename, 'application/json;charset=utf-8;');
  };
  btnExportLogs?.addEventListener('click', handleExportLogs);
  btnExportLogsPane?.addEventListener('click', handleExportLogs);

  // Clear Logs
  btnClearLogs?.addEventListener('click', () => {
    logger.clear();
    renderLogs([]);
  });

  // Activity Log Filter Buttons
  document.querySelectorAll('.log-filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.log-filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentLogFilter = btn.getAttribute('data-filter') || 'all';
      renderLogs(logger.getLogs());
    });
  });

  // Reset / Wipe
  btnReset?.addEventListener('click', () => {
    stateManager.reset();
    inputText.value = '';
    outputText.value = '';
    if (fileInput) fileInput.value = '';
    runProcessing();
    logger.clear();
    renderLogs([]);
    logger.log({
      operation: 'RESET',
      category: 'SESSION',
      status: 'INFO',
      details: 'Wiped local browser memory and reset all state.'
    });
  });

  // Hero Buttons
  heroBtnRedact?.addEventListener('click', () => {
    activateTab('tab-workspace');
    inputText.focus();
  });

  heroBtnSelfTest?.addEventListener('click', () => {
    activateTab('tab-selftest');
    btnRunTests?.click();
  });

  // Toggle Security Docs Secondary Section
  const toggleDocsBtn = document.getElementById('toggle-docs-btn');
  const tabDocs = document.getElementById('tab-docs');
  const tabBtnDocs = document.getElementById('tab-btn-docs');

  tabBtnDocs?.addEventListener('click', (e) => {
    e.stopPropagation();
    if (tabDocs instanceof HTMLDetailsElement) {
      tabDocs.open = !tabDocs.open;
      tabBtnDocs.textContent = tabDocs.open ? 'Collapse' : 'Expand';
    }
  });

  // Subscribe logger
  logger.subscribe(renderLogs);
}

/**
 * Initializes the mobile Original / Redacted pane switcher.
 */
function initMobilePaneToggle() {
  const toggleBtns = document.querySelectorAll('.kv-mobile-pane-btn');
  const panes = document.querySelectorAll('.kv-pane[data-pane-name]');
  toggleBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-pane');
      toggleBtns.forEach((b) => {
        const isActive = b === btn;
        b.classList.toggle('active', isActive);
        b.setAttribute('aria-selected', isActive ? 'true' : 'false');
      });
      panes.forEach((pane) => {
        pane.classList.toggle('mobile-active', pane.getAttribute('data-pane-name') === target);
      });
    });
  });
}

// Entrypoint
document.addEventListener('DOMContentLoaded', () => {
  initLiquidTabs();
  initSegmentedControl();
  initMobilePaneToggle();
  initScrollSync();
  initFileDropZone();
  initSelfTestRunner();
  initEventListeners();
  runProcessing();
  logger.log({
    operation: 'INIT',
    category: 'SYSTEM',
    status: 'INFO',
    details: 'KAVACH initialized in client browser memory. Zero external network connections.'
  });
});
