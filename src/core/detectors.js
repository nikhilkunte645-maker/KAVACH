/**
 * KAVACH - Candidate Detectors
 * Deterministic candidate pattern matching with boundary rules.
 */

import { PiiType } from './types.js';

/**
 * Trailing punctuation characters that commonly adhere to tokens at the end of sentences
 * and must be trimmed from candidate spans.
 */
export const TRAILING_PUNCTUATION_REGEX = /[.,;:!?)"'>]+$/;

/**
 * Finds all candidate spans in the text for each enabled PII type.
 * Note: These are candidates, not validated findings.
 *
 * @param {string} text - Source text
 * @param {Set<string>} [enabledTypes] - Optional subset of types to detect
 * @returns {Array<{type: string, start: number, end: number, rawValue: string}>}
 */
export function detectCandidates(text, enabledTypes = null) {
  if (!text || typeof text !== 'string') return [];

  const candidates = [];
  const isEnabled = (type) => !enabledTypes || enabledTypes.has(type);

  // 1. Credit Card Candidates (13-19 digits, optional spaces/hyphens)
  // Left and right boundary: must not be adjacent to digits or word characters
  if (isEnabled(PiiType.CREDIT_CARD)) {
    const ccRegex = /(?:^|(?<=[^0-9A-Za-z]))(\d(?:[ -]?\d){11,18}\d)(?=[^0-9A-Za-z]|$)/g;
    let match;
    while ((match = ccRegex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.CREDIT_CARD,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 2. PAN Candidates (5 letters, 4 digits, 1 letter)
  // Strict boundary: not preceded or followed by alphanumeric
  if (isEnabled(PiiType.PAN)) {
    const panRegex = /(?:^|(?<=[^0-9A-Za-z]))([a-zA-Z]{5}[0-9]{4}[a-zA-Z])(?=[^0-9A-Za-z]|$)/g;
    let match;
    while ((match = panRegex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.PAN,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 3. IPv4 Candidates (4 decimal octets separated by dots)
  // Strict boundary: not preceded or followed by digits or dots
  if (isEnabled(PiiType.IPV4)) {
    const ipv4Regex = /(?:^|(?<=[^0-9.]))(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=[^0-9.]|$)/g;
    let match;
    while ((match = ipv4Regex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.IPV4,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 4. Aadhaar Candidates (12 digits, starting with 2-9, optional 4-4-4 spacing/hyphen)
  if (isEnabled(PiiType.AADHAAR)) {
    const aadhaarRegex = /(?:^|(?<=[^0-9A-Za-z]))([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?=[^0-9A-Za-z]|$)/g;
    let match;
    while ((match = aadhaarRegex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.AADHAAR,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 5. Indian Phone Candidates (+91 / 91 / 0 prefix optional, 10-digit mobile starting 6-9)
  if (isEnabled(PiiType.PHONE_IN)) {
    const phoneInRegex = /(?:^|(?<=[^0-9A-Za-z+]))((?:\+91|91|0)?[ -]?[6-9]\d{4}[ -]?\d{5}|(?:\+91|91|0)?[ -]?[6-9]\d{9})(?=[^0-9A-Za-z]|$)/g;
    let match;
    while ((match = phoneInRegex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.PHONE_IN,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 6. International Phone Candidates (E.164-like: starting with + and country code)
  if (isEnabled(PiiType.PHONE_INTL)) {
    const phoneIntlRegex = /(?:^|(?<=[^0-9A-Za-z+]))(\+[1-9]\d{0,2}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{1,4}(?:[ -]?\d{1,4}){1,3})(?=[^0-9A-Za-z]|$)/g;
    let match;
    while ((match = phoneIntlRegex.exec(text)) !== null) {
      const fullMatch = match[1];
      const start = match.index + (match[0].length - fullMatch.length);
      const end = start + fullMatch.length;
      candidates.push({
        type: PiiType.PHONE_INTL,
        start,
        end,
        rawValue: fullMatch
      });
    }
  }

  // 7. Email Candidates
  if (isEnabled(PiiType.EMAIL)) {
    const emailRegex = /(?:^|(?<=[^a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]))([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)/g;
    let match;
    while ((match = emailRegex.exec(text)) !== null) {
      let rawCandidate = match[1];
      let start = match.index + (match[0].length - rawCandidate.length);

      // Trailing punctuation trim: remove trailing . , ; : ! ? ) etc.
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
  }

  return candidates;
}
