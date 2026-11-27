/**
 * KAVACH - Deterministic Overlap Resolution
 *
 * Implements O(n log n) interval scheduling:
 * 1. Filters invalid/empty spans safely
 * 2. Sorts by start ascending, span length descending, priority descending, type tie-breaker
 * 3. Linear greedy sweep over half-open intervals [start, end)
 *
 * Guarantee: No source character is redacted twice. Offsets use UTF-16 code units.
 */

import { PII_PRIORITY } from './types.js';

/**
 * Resolves overlapping PII findings deterministically in O(n log n) time.
 *
 * @param {Array<import('./types.js').PiiFinding>} findings
 * @returns {Array<import('./types.js').PiiFinding>} Non-overlapping findings sorted by start ascending
 */
export function resolveOverlaps(findings) {
  if (!findings || findings.length === 0) return [];

  // Filter out malformed, negative, or empty spans
  const valid = [];
  for (let i = 0; i < findings.length; i++) {
    const item = findings[i];
    if (
      item &&
      typeof item.start === 'number' &&
      typeof item.end === 'number' &&
      Number.isFinite(item.start) &&
      Number.isFinite(item.end) &&
      item.start >= 0 &&
      item.end > item.start
    ) {
      valid.push(item);
    }
  }

  if (valid.length <= 1) return valid;

  // Sort deterministically
  valid.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenA !== lenB) return lenB - lenA;
    const priorityMap = /** @type {Record<string, number>} */ (PII_PRIORITY);
    const prioA = priorityMap[a.type] ?? 0;
    const prioB = priorityMap[b.type] ?? 0;
    if (prioA !== prioB) return prioB - prioA;
    return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
  });

  // Single linear sweep; `valid` is already ordered by `start` ascending,
  // and each accepted item has `item.start >= currentEnd > prev.start`,
  // so `accepted` is inherently sorted by `start` ascending.
  const accepted = [];
  let currentEnd = -1;

  for (let i = 0; i < valid.length; i++) {
    const item = valid[i];
    if (item.start >= currentEnd) {
      accepted.push(item);
      currentEnd = item.end;
    }
  }

  return accepted;
}
