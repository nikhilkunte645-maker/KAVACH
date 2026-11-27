/**
 * KAVACH - Main Application Controller
 * Connects UI events to 100% client-side production modules.
 */

import { PiiType, RedactionMode, ValidationStatus } from './core/types.js';
import { processText, processCsv } from './core/engine.js';
import { computeDiffSegments, renderSafeDiffToDom } from './core/diff.js';
import { logger } from './core/logger.js';
import { stateManager } from './core/state.js';
import { runAllSelfTests } from './self-test/runner.js';

// DOM Elements
const tabBtns = document.querySelectorAll('.nav-tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
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
const btnExportRedacted = document.getElementById('btn-export-redacted');
const btnExportLogs = document.getElementById('btn-export-logs');
const btnExportLogsPane = document.getElementById('btn-export-logs-pane');
const btnClearLogs = document.getElementById('btn-clear-logs');
const btnReset = document.getElementById('btn-reset');
const btnRunTests = document.getElementById('btn-run-tests');
const logTerminal = document.getElementById('log-terminal');

// Metric elements for self-test
const metricTotal = document.getElementById('metric-total');
const metricPassed = document.getElementById('metric-passed');
const metricFailed = document.getElementById('metric-failed');
const metricDuration = document.getElementById('metric-duration');
const testRunnerStatus = document.getElementById('test-runner-status');
const testResultsList = document.getElementById('test-results-list');

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
const redactionModeRadios = document.querySelectorAll('input[name="redaction-mode"]');

// Debounce timer
let debounceTimer = null;

/**
 * Initializes navigation tabs.
 */
function initTabs() {
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabBtns.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanes.forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
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
    if (/** @type {HTMLInputElement} */ (radio).checked) {
      redactionMode = /** @type {HTMLInputElement} */ (radio).value;
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
 * Main processing function triggered on text or configuration change.
 */
export function runProcessing() {
  const text = inputText.value;
  charCount.textContent = `${text.length} chars`;

  if (!text) {
    outputText.value = '';
    while (diffOutput.firstChild) diffOutput.removeChild(diffOutput.firstChild);
    const span = document.createElement('span');
    span.className = 'diff-unchanged';
    span.textContent = 'Input text above to see side-by-side safe redaction diff...';
    diffOutput.appendChild(span);

    findingsTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No PII findings detected in current input.</td></tr>';
    findingsCountBadge.textContent = '0';
    return;
  }

  const config = getActiveConfig();
  const isCsv = stateManager.sourceType === 'csv';

  if (isCsv) {
    sourceFormatLabel.textContent = 'CSV File';
    const csvResult = processCsv(text, {
      enabledTypes: config.enabledTypes,
      redactionMode: config.redactionMode,
      pseudonymizer: stateManager.pseudonymizer,
      sanitizeFormulas: config.sanitizeCsvFormulas,
      requireVerhoeff: config.requireVerhoeff
    });

    outputText.value = csvResult.redactedCsv;
    findingsCountBadge.textContent = String(csvResult.findings.length);
    renderFindingsTable(csvResult.findings);

    // Render preview diff safely
    const previewRaw = text.slice(0, 3000);
    const previewFindings = csvResult.findings.filter((f) => f.start < 3000);
    const diffSegs = computeDiffSegments(previewRaw, previewFindings);
    renderSafeDiffToDom(diffOutput, diffSegs);
  } else {
    sourceFormatLabel.textContent = 'Raw Text';
    const textResult = processText(text, {
      enabledTypes: config.enabledTypes,
      redactionMode: config.redactionMode,
      pseudonymizer: stateManager.pseudonymizer,
      requireVerhoeff: config.requireVerhoeff
    });

    outputText.value = textResult.redactedText;
    findingsCountBadge.textContent = String(textResult.findings.length);
    renderFindingsTable(textResult.findings);

    const diffSegs = computeDiffSegments(text, textResult.findings);
    renderSafeDiffToDom(diffOutput, diffSegs);
  }
}

/**
 * Safely renders the findings table without raw PII exposure.
 *
 * @param {Array<any>} findings
 */
function renderFindingsTable(findings) {
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
 * Renders real-time privacy logs into the logs pane.
 * @param {Array<any>} logs
 */
function renderLogs(logs) {
  if (!logTerminal) return;
  while (logTerminal.firstChild) {
    logTerminal.removeChild(logTerminal.firstChild);
  }

  logs.slice(-100).forEach((log) => {
    const line = document.createElement('div');
    line.className = 'log-line';

    const ts = document.createElement('span');
    ts.className = 'log-ts';
    ts.textContent = log.timestamp.slice(11, 19);

    const op = document.createElement('span');
    op.className = 'log-op';
    op.textContent = `[${log.operation}]`;

    const msg = document.createElement('span');
    msg.className = 'log-msg';
    msg.textContent = `${log.category ? `(${log.category}) ` : ''}${log.details}`;

    line.appendChild(ts);
    line.appendChild(op);
    line.appendChild(msg);
    logTerminal.appendChild(line);
  });

  logTerminal.scrollTop = logTerminal.scrollHeight;
}

/**
 * Safely downloads a string as a client-side file.
 *
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
  dropZone.addEventListener('click', () => fileInput.click());

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
 * Loads a file into transient memory.
 * @param {File} file
 */
function loadFile(file) {
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
      details: `Loaded file "${file.name}" (${(file.size / 1024).toFixed(1)} KB) into memory.`
    });
  };

  reader.readAsText(file, 'utf-8');
}

/**
 * Initializes self-test runner UI interactions.
 */
function initSelfTestRunner() {
  btnRunTests.addEventListener('click', async () => {
    btnRunTests.setAttribute('disabled', 'true');
    testRunnerStatus.textContent = 'Running test suite...';
    while (testResultsList.firstChild) testResultsList.removeChild(testResultsList.firstChild);

    const summary = await runAllSelfTests((res, curr, total) => {
      metricTotal.textContent = String(curr);

      const item = document.createElement('div');
      item.className = 'test-item';

      const left = document.createElement('div');
      left.className = 'test-meta';

      const badge = document.createElement('span');
      badge.className = `status-badge ${res.passed ? 'valid' : 'invalid'}`;
      badge.textContent = res.status;

      const title = document.createElement('span');
      title.textContent = `[${res.category}] ${res.name}`;

      left.appendChild(badge);
      left.appendChild(title);

      const time = document.createElement('span');
      time.style.color = 'var(--text-muted)';
      time.style.fontFamily = 'var(--font-mono)';
      time.textContent = `${res.durationMs}ms`;

      item.appendChild(left);
      item.appendChild(time);
      testResultsList.appendChild(item);
    });

    metricTotal.textContent = String(summary.total);
    metricPassed.textContent = String(summary.passed);
    metricFailed.textContent = String(summary.failed);
    metricDuration.textContent = `${summary.durationMs}ms`;

    testRunnerStatus.textContent = summary.failed === 0 ? 'All tests passed successfully' : 'Some tests failed';
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

  // Copy output
  btnCopyOutput.addEventListener('click', async () => {
    if (outputText.value) {
      await navigator.clipboard.writeText(outputText.value);
      btnCopyOutput.textContent = 'Copied!';
      setTimeout(() => (btnCopyOutput.textContent = 'Copy'), 1500);
    }
  });

  // Export Redacted File
  btnExportRedacted.addEventListener('click', () => {
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
  btnExportLogs.addEventListener('click', handleExportLogs);
  btnExportLogsPane.addEventListener('click', handleExportLogs);

  // Clear Logs
  btnClearLogs.addEventListener('click', () => logger.clear());

  // Reset / Wipe
  btnReset.addEventListener('click', () => {
    stateManager.reset();
    inputText.value = '';
    outputText.value = '';
    fileInput.value = '';
    runProcessing();
  });

  // Subscribe logger
  logger.subscribe(renderLogs);
}

// Entrypoint
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
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
