/**
 * KAVACH - XSS-Safe Diff Engine & DOM Renderer
 *
 * Guarantees zero HTML injection / XSS vulnerabilities.
 * Never uses unsafe innerHTML for untrusted content.
 * All user text is rendered through textContent or strict escaping.
 */

/**
 * Escapes characters with special meaning in HTML.
 *
 * @param {string} str
 * @returns {string} Escaped HTML string
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Computes an interval-based diff between original text and redacted findings.
 *
 * @param {string} originalText
 * @param {Array<import('./types.js').PiiFinding>} resolvedFindings - Sorted by start ascending
 * @returns {Array<{type: string, text: string, piiType?: string}>}
 */
export function computeDiffSegments(originalText, resolvedFindings) {
  const segments = [];
  let lastIndex = 0;

  for (const finding of resolvedFindings) {
    if (finding.start > lastIndex) {
      segments.push({
        type: 'unchanged',
        text: originalText.slice(lastIndex, finding.start)
      });
    }

    // Redacted part:
    // Original (removed)
    segments.push({
      type: 'removed',
      text: originalText.slice(finding.start, finding.end),
      piiType: finding.type
    });

    // Replacement (added)
    segments.push({
      type: 'added',
      text: finding.redactedValue || '********',
      piiType: finding.type
    });

    lastIndex = finding.end;
  }

  if (lastIndex < originalText.length) {
    segments.push({
      type: 'unchanged',
      text: originalText.slice(lastIndex)
    });
  }

  return segments;
}

/**
 * Safely renders diff segments into a DOM element using text nodes.
 * Guarantees no XSS execution.
 *
 * @param {HTMLElement} containerElement
 * @param {Array<{type: string, text: string, piiType?: string}>} diffSegments
 */
export function renderSafeDiffToDom(containerElement, diffSegments) {
  while (containerElement.firstChild) {
    containerElement.removeChild(containerElement.firstChild);
  }

  const fragment = document.createDocumentFragment();
  for (let i = 0; i < diffSegments.length; i++) {
    const seg = diffSegments[i];
    if (seg.type === 'unchanged') {
      const span = document.createElement('span');
      span.className = 'diff-unchanged';
      span.textContent = seg.text;
      fragment.appendChild(span);
    } else if (seg.type === 'removed') {
      const del = document.createElement('del');
      del.className = 'diff-removed';
      del.title = `Original: ${seg.piiType || 'PII'}`;
      del.textContent = seg.text;
      fragment.appendChild(del);
    } else if (seg.type === 'added') {
      const ins = document.createElement('ins');
      ins.className = 'diff-added';
      ins.title = `Masked: ${seg.piiType || 'PII'}`;
      ins.textContent = seg.text;
      fragment.appendChild(ins);
    }
  }
  containerElement.appendChild(fragment);
}
