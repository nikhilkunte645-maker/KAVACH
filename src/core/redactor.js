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
      const host = raw.slice(atIdx + 1);
      const firstUser = user.length > 0 ? user[0] : '';
      const maskedUser = `${firstUser}${'*'.repeat(Math.max(1, user.length - 1))}`;

      const dotIdx = host.lastIndexOf('.');
      let maskedHost = host;
      if (dotIdx > 0) {
        const domainName = host.slice(0, dotIdx);
        const tld = host.slice(dotIdx);
        const firstDomain = domainName.length > 0 ? domainName[0] : '';
        maskedHost = `${firstDomain}${'*'.repeat(Math.max(1, domainName.length - 1))}${tld}`;
      } else if (host.length > 0) {
        maskedHost = `${host[0]}${'*'.repeat(Math.max(1, host.length - 1))}`;
      }
      return `${maskedUser}@${maskedHost}`;
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

const PSEUDONYM_PREFIX_MAP = Object.freeze({
  [PiiType.CREDIT_CARD]: 'CARD',
  [PiiType.AADHAAR]: 'AADHAAR',
  [PiiType.PAN]: 'PAN',
  [PiiType.EMAIL]: 'EMAIL',
  [PiiType.PHONE_IN]: 'PHONE',
  [PiiType.PHONE_INTL]: 'PHONE',
  [PiiType.IPV4]: 'IPV4'
});

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
    const existing = this.tokenMap.get(key);
    if (existing !== undefined) {
      return existing;
    }

    const currentCount = (this.counters.get(type) ?? 0) + 1;
    this.counters.set(type, currentCount);

    const prefix = /** @type {Record<string, string>} */ (PSEUDONYM_PREFIX_MAP)[type] || type;
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
 * @param {Record<string, string>} [customMasks]
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
 * @param {Record<string, string>} [customMasks]
 * @returns {string} Redacted output text
 */
export function redactText(sourceText, resolvedFindings, mode, pseudonymizer, customMasks = {}) {
  if (!sourceText) return '';
  if (!resolvedFindings || resolvedFindings.length === 0) return sourceText;

  /** @type {Array<string>} */
  const parts = [];
  let lastIndex = 0;

  for (let i = 0; i < resolvedFindings.length; i++) {
    const finding = resolvedFindings[i];
    if (finding.start > lastIndex) {
      parts.push(sourceText.slice(lastIndex, finding.start));
    }

    const replacement = getReplacementValue(finding, mode, pseudonymizer, customMasks);
    finding.redactedValue = replacement;
    parts.push(replacement);

    lastIndex = finding.end;
  }

  if (lastIndex < sourceText.length) {
    parts.push(sourceText.slice(lastIndex));
  }

  return parts.join('');
}
