/**
 * KAVACH - Deterministic Overlap Resolution
 *
 * Implements strict interval scheduling:
 * 1. Sort by start ascending
 * 2. Sort by length (end - start) descending
 * 3. Tie-breaker by detection priority
 * 4. Pure deterministic tie-breaker by type name
 *
 * Standard half-open intervals: [start, end)
 * Guarantee: No source character is redacted twice. Offsets use UTF-16 code units.
 */

import { PII_PRIORITY } from './types.js';

/**
 * Resolves overlapping PII findings deterministically.
 *
 * @param {Array<import('./types.js').PiiFinding>} findings
 * @returns {Array<import('./types.js').PiiFinding>} Non-overlapping findings sorted by start ascending
 */
export function resolveOverlaps(findings) {
  if (!findings || findings.length <= 1) return findings ? [...findings] : [];

  // Sort deterministically
  const sorted = [...findings].sort((a, b) => {
    // 1. Start index ascending
    if (a.start !== b.start) {
      return a.start - b.start;
    }
    // 2. Span length descending (longer span wins)
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenA !== lenB) {
      return lenB - lenA;
    }
    // 3. Priority descending
    const prioA = PII_PRIORITY[a.type] ?? 0;
    const prioB = PII_PRIORITY[b.type] ?? 0;
    if (prioA !== prioB) {
      return prioB - prioA;
    }
    // 4. Deterministic string tie-breaker
    return a.type.localeCompare(b.type);
  });

  const accepted = [];
  let currentEnd = -1;

  for (const item of sorted) {
    // Half-open interval check: item.start must be >= previous item's end
    if (item.start >= currentEnd) {
      accepted.push(item);
      currentEnd = item.end;
    }
    // Otherwise overlaps with accepted span -> discard overlapping lower-priority candidate
  }

  // Final sort strictly by start index ascending for linear redaction
  return accepted.sort((a, b) => a.start - b.start);
}
