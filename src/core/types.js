/**
 * KAVACH - PII Types and Constants
 * 100% Client-Side Privacy Engine
 */

export const PiiType = Object.freeze({
  CREDIT_CARD: 'CREDIT_CARD',
  AADHAAR: 'AADHAAR',
  PAN: 'PAN',
  EMAIL: 'EMAIL',
  PHONE_IN: 'PHONE_IN',
  PHONE_INTL: 'PHONE_INTL',
  IPV4: 'IPV4'
});

export const ValidationStatus = Object.freeze({
  VALID: 'VALID',
  VALID_CARD: 'VALID_CARD',
  INVALID: 'INVALID',
  INVALID_LUHN: 'INVALID_LUHN',
  INVALID_LENGTH: 'INVALID_LENGTH',
  INVALID_BOUNDARY: 'INVALID_BOUNDARY',
  REJECTED_LUHN: 'INVALID_LUHN',
  REJECTED_VERHOEFF: 'REJECTED_VERHOEFF',
  REJECTED_BOUNDARY: 'INVALID_BOUNDARY',
  REJECTED_OCTET_RANGE: 'REJECTED_OCTET_RANGE',
  REJECTED_VERSION_STRING: 'REJECTED_VERSION_STRING',
  REJECTED_LENGTH: 'INVALID_LENGTH',
  REJECTED_FORMAT: 'REJECTED_FORMAT'
});

export const RedactionMode = Object.freeze({
  FULL_MASK: 'FULL_MASK',
  PARTIAL_MASK: 'PARTIAL_MASK',
  PSEUDONYMIZE: 'PSEUDONYMIZE'
});

/**
 * Priority order for resolving overlapping candidates.
 * Higher number = higher precedence.
 * Credit cards and Aadhaar have strict mathematical checksums;
 * they take precedence over general phone or numeric fragments.
 */
export const PII_PRIORITY = Object.freeze({
  [PiiType.CREDIT_CARD]: 100,
  [PiiType.AADHAAR]: 90,
  [PiiType.PAN]: 80,
  [PiiType.EMAIL]: 70,
  [PiiType.PHONE_IN]: 60,
  [PiiType.PHONE_INTL]: 50,
  [PiiType.IPV4]: 40
});

/**
 * @typedef {Object} PiiFinding
 * @property {string} id - Unique deterministic ID
 * @property {string} type - PiiType
 * @property {number} start - 0-based UTF-16 start index (inclusive)
 * @property {number} end - 0-based UTF-16 end index (exclusive)
 * @property {string} rawValue - Raw candidate value in transient memory
 * @property {string} normalizedValue - Canonical normalized string
 * @property {string} status - ValidationStatus
 * @property {string} [reason] - Validation explanation
 * @property {string} [redactedValue] - Masked or pseudonymized replacement
 * @property {{row: number, col: number}} [cellCoord] - Coordinates if inside CSV
 */
