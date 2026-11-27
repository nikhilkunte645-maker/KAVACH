/**
 * KAVACH - Candidate Detectors
 * Deterministic candidate pattern matching with module-scoped compiled regexes.
 */

import { PiiType } from './types.js';

/**
 * Trailing punctuation characters that commonly adhere to tokens at the end of sentences
 * and must be trimmed from candidate spans.
 */
export const TRAILING_PUNCTUATION_REGEX = /[.,;:!?)"'>]+$/;

// Module-scoped compiled patterns (reset .lastIndex = 0 before each scan)
const CC_REGEX = /(?:^|(?<=[^0-9A-Za-z]))(\d(?:[ -]?\d){11,18}\d)(?=[^0-9A-Za-z]|$)/g;
const PAN_REGEX = /(?:^|(?<=[^0-9A-Za-z]))([a-zA-Z]{5}[0-9]{4}[a-zA-Z])(?=[^0-9A-Za-z]|$)/g;
const IPV4_REGEX = /(?:^|(?<=[^0-9.]))(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=[^0-9.]|$)/g;
const AADHAAR_REGEX = /(?:^|(?<=[^0-9A-Za-z]))([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?=[^0-9A-Za-z]|$)/g;
const PHONE_IN_REGEX = /(?:^|(?<=[^0-9A-Za-z+]))((?:\+91|91|0)?[ -]?[6-9]\d{4}[ -]?\d{5}|(?:\+91|91|0)?[ -]?[6-9]\d{9})(?=[^0-9A-Za-z]|$)/g;
const PHONE_INTL_REGEX = /(?:^|(?<=[^0-9A-Za-z+]))(\+[1-9]\d{0,2}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{1,4}(?:[ -]?\d{1,4}){1,3})(?=[^0-9A-Za-z]|$)/g;
const EMAIL_REGEX = /(?:^|(?<=[^a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]))([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)/g;

/**
 * Scans text with a global regex and pushes candidate objects.
 * Resets regex.lastIndex before and after scanning to avoid shared-state bugs.
 *
 * @param {RegExp} regex
 * @param {string} text
 * @param {string} type
 * @param {Array<{type: string, start: number, end: number, rawValue: string}>} out
 */
function scanWithRegex(regex, text, type, out) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const fullMatch = match[1];
    const start = match.index + (match[0].length - fullMatch.length);
    out.push({
      type,
      start,
      end: start + fullMatch.length,
      rawValue: fullMatch
    });
  }
  regex.lastIndex = 0;
}

/**
 * Finds all candidate spans in the text for each enabled PII type.
 * Note: These are candidates, not validated findings.
 *
 * @param {string} text - Source text
 * @param {Set<string> | null} [enabledTypes] - Optional subset of types to detect
 * @returns {Array<{type: string, start: number, end: number, rawValue: string}>}
 */
export function detectCandidates(text, enabledTypes = null) {
  if (!text || typeof text !== 'string') return [];

  /** @type {Array<{type: string, start: number, end: number, rawValue: string}>} */
  const candidates = [];
  const isEnabled = (/** @type {string} */ type) => !enabledTypes || enabledTypes.has(type);

  if (isEnabled(PiiType.CREDIT_CARD)) {
    scanWithRegex(CC_REGEX, text, PiiType.CREDIT_CARD, candidates);
  }
  if (isEnabled(PiiType.PAN)) {
    scanWithRegex(PAN_REGEX, text, PiiType.PAN, candidates);
  }
  if (isEnabled(PiiType.IPV4)) {
    scanWithRegex(IPV4_REGEX, text, PiiType.IPV4, candidates);
  }
  if (isEnabled(PiiType.AADHAAR)) {
    scanWithRegex(AADHAAR_REGEX, text, PiiType.AADHAAR, candidates);
  }
  if (isEnabled(PiiType.PHONE_IN)) {
    scanWithRegex(PHONE_IN_REGEX, text, PiiType.PHONE_IN, candidates);
  }
  if (isEnabled(PiiType.PHONE_INTL)) {
    scanWithRegex(PHONE_INTL_REGEX, text, PiiType.PHONE_INTL, candidates);
  }
  if (isEnabled(PiiType.EMAIL)) {
    EMAIL_REGEX.lastIndex = 0;
    let match;
    while ((match = EMAIL_REGEX.exec(text)) !== null) {
      let rawCandidate = match[1];
      const start = match.index + (match[0].length - rawCandidate.length);

      const punctMatch = rawCandidate.match(TRAILING_PUNCTUATION_REGEX);
      if (punctMatch) {
        rawCandidate = rawCandidate.slice(0, rawCandidate.length - punctMatch[0].length);
      }

      if (rawCandidate.length > 0 && rawCandidate.includes('@')) {
        candidates.push({
          type: PiiType.EMAIL,
          start,
          end: start + rawCandidate.length,
          rawValue: rawCandidate
        });
      }
    }
    EMAIL_REGEX.lastIndex = 0;
  }

  return candidates;
}
