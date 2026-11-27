/**
 * KAVACH - Redaction & Pseudonymization Engine
 *
 * Supports:
 * 1. Full Mask (100% replacement with mask token)
 * 2. Partial Mask (reveals explicitly configured safe portions only)
 * 3. Consistent Pseudonymization (deterministic run-scoped token mapping)
 */

import { PiiType, RedactionMode } from './types.js';

/**
 * Generates partial mask for a given finding based on its type.
 *
 * @param {import('./types.js').PiiFinding} finding
 * @returns {string} Safe partially-masked string
 */
export function generatePartialMask(finding) {
  const raw = finding.rawValue;
  const len = raw.length;

  switch (finding.type) {
    case PiiType.EMAIL: {
      const atIdx = raw.indexOf('@');
      if (atIdx === -1) return '*'.repeat(len);
      const user = raw.slice(0, atIdx);
      const domain = raw.slice(atIdx);
      if (user.length <= 2) {
        return `${user[0]}*${domain}`;
      }
      return `${user.slice(0, 2)}${'*'.repeat(Math.max(1, user.length - 2))}${domain}`;
    }

    case PiiType.CREDIT_CARD: {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `${'*'.repeat(Math.max(0, digits.length - 4))}${last4}`;
    }

    case PiiType.AADHAAR: {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `********${last4}`;
    }

    case PiiType.PAN: {
      const upper = raw.toUpperCase();
      if (upper.length === 10) {
        return `${upper.slice(0, 2)}*****${upper.slice(-2)}`;
      }
      return `${upper.slice(0, 2)}${'*'.repeat(Math.max(1, upper.length - 4))}${upper.slice(-2)}`;
    }

    case PiiType.PHONE_IN: {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      const hasPrefix = raw.includes('+91') ? '+91 ' : '';
      return `${hasPrefix}******${last4}`;
    }

    case PiiType.PHONE_INTL: {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `+***-***-${last4}`;
    }

    case PiiType.IPV4: {
      const octets = raw.split('.');
      if (octets.length === 4) {
        return `${octets[0]}.${octets[1]}.***.***`;
      }
      return '***.***.***.***';
    }

    default:
      return '*'.repeat(len);
  }
}

/**
 * State container for consistent pseudonymization during a single processing run.
 */
export class Pseudonymizer {
  constructor() {
    /** @type {Map<string, string>} Key: `${type}:${normalizedValue}` -> Value: `TOKEN` */
    this.tokenMap = new Map();
    /** @type {Map<string, number>} Key: type -> Counter */
    this.counters = new Map();
  }

  /**
   * Clears all token mappings and counters.
   */
  reset() {
    this.tokenMap.clear();
    this.counters.clear();
  }

  /**
   * Deterministically returns the pseudonym token for a finding.
   *
   * @param {string} type
   * @param {string} normalizedValue
   * @returns {string} Pseudonym token, e.g. EMAIL_01, CARD_01
   */
  getToken(type, normalizedValue) {
    const key = `${type}:${normalizedValue.toLowerCase()}`;
    if (this.tokenMap.has(key)) {
      return /** @type {string} */ (this.tokenMap.get(key));
    }

    const currentCount = (this.counters.get(type) ?? 0) + 1;
    this.counters.set(type, currentCount);

    const prefixMap = {
      [PiiType.CREDIT_CARD]: 'CARD',
      [PiiType.AADHAAR]: 'AADHAAR',
      [PiiType.PAN]: 'PAN',
      [PiiType.EMAIL]: 'EMAIL',
      [PiiType.PHONE_IN]: 'PHONE',
      [PiiType.PHONE_INTL]: 'PHONE',
      [PiiType.IPV4]: 'IPV4'
    };

    const prefix = prefixMap[type] || type;
    const token = `${prefix}_${String(currentCount).padStart(2, '0')}`;
    this.tokenMap.set(key, token);
    return token;
  }
}

/**
 * Computes replacement text for a finding based on configuration.
 *
 * @param {import('./types.js').PiiFinding} finding
 * @param {string} mode - RedactionMode
 * @param {Pseudonymizer} pseudonymizer
 * @param {Object} [customMasks]
 * @returns {string}
 */
export function getReplacementValue(finding, mode, pseudonymizer, customMasks = {}) {
  switch (mode) {
    case RedactionMode.FULL_MASK: {
      if (customMasks && customMasks[finding.type]) {
        return customMasks[finding.type];
      }
      return `[REDACTED_${finding.type}]`;
    }

    case RedactionMode.PARTIAL_MASK:
      return generatePartialMask(finding);

    case RedactionMode.PSEUDONYMIZE:
      return pseudonymizer.getToken(finding.type, finding.normalizedValue);

    default:
      return '********';
  }
}

/**
 * Applies redaction to source text using resolved, non-overlapping findings.
 *
 * @param {string} sourceText
 * @param {Array<import('./types.js').PiiFinding>} resolvedFindings - Must be sorted by start ascending
 * @param {string} mode - RedactionMode
 * @param {Pseudonymizer} pseudonymizer
 * @param {Object} [customMasks]
 * @returns {string} Redacted output text
 */
export function redactText(sourceText, resolvedFindings, mode, pseudonymizer, customMasks = {}) {
  if (!sourceText) return '';
  if (!resolvedFindings || resolvedFindings.length === 0) return sourceText;

  let result = '';
  let lastIndex = 0;

  for (const finding of resolvedFindings) {
    // Append unchanged segment before this finding
    result += sourceText.slice(lastIndex, finding.start);

    // Compute replacement
    const replacement = getReplacementValue(finding, mode, pseudonymizer, customMasks);
    finding.redactedValue = replacement;
    result += replacement;

    lastIndex = finding.end;
  }

  // Append remaining text
  if (lastIndex < sourceText.length) {
    result += sourceText.slice(lastIndex);
  }

  return result;
}
