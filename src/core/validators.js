/**
 * KAVACH - Candidate Validators
 * Strict, deterministic validation separating candidate detection from validation.
 */

import { PiiType, ValidationStatus } from './types.js';
import { validateLuhn } from './luhn.js';
import { validateVerhoeff } from './verhoeff.js';

/**
 * Checks if a candidate is embedded in a longer alphanumeric token in the source text.
 *
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @param {RegExp} [boundaryRegex]
 * @returns {boolean} True if boundary is safe
 */
export function isSafeWordBoundary(sourceText, start, end, boundaryRegex = /[a-zA-Z0-9]/) {
  if (start > 0) {
    const prevChar = sourceText[start - 1];
    if (boundaryRegex.test(prevChar)) return false;
  }
  if (end < sourceText.length) {
    const nextChar = sourceText[end];
    if (boundaryRegex.test(nextChar)) return false;
  }
  return true;
}

/**
 * Checks if the string before the start offset indicates a version string.
 * Examples: 'v1.2.3.4', 'version 10.20.30.40', 'release-2.3.4.5', 'build.1.2.3.4'
 *
 * @param {string} sourceText
 * @param {number} start
 * @returns {boolean} True if preceded by a version prefix
 */
export function hasVersionPrefix(sourceText, start) {
  const prefixWindow = sourceText.slice(Math.max(0, start - 20), start);
  return /(?:^|[\s_/-])(?:v|ver|version|release|build)[._\s-]*$/i.test(prefixWindow);
}

/**
 * Checks if candidate is part of a standard date format.
 * Examples: YYYY-MM-DD, DD/MM/YYYY, YYYYMMDD
 *
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {boolean}
 */
export function isPartOfDate(sourceText, start, end) {
  const contextWindow = sourceText.slice(Math.max(0, start - 5), Math.min(sourceText.length, end + 5));
  // YYYY-MM-DD or DD-MM-YYYY or YYYY/MM/DD
  if (/\d{4}[-/]\d{2}[-/]\d{2}/.test(contextWindow)) return true;
  if (/\d{2}[-/]\d{2}[-/]\d{4}/.test(contextWindow)) return true;
  // ISO timestamps with T
  if (/\d{4}-\d{2}-\d{2}T\d{2}/.test(contextWindow)) return true;
  return false;
}

/**
 * Validates a Credit Card candidate.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateCreditCard(rawValue, sourceText, start, end) {
  // Check boundaries: cannot be adjacent to digits or alphanumeric
  if (!isSafeWordBoundary(sourceText, start, end, /[0-9A-Za-z]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'Credit card candidate is adjacent to digits or alphanumeric characters',
      normalizedValue: rawValue
    };
  }

  // Normalize: extract only ASCII digits
  const digitsOnly = rawValue.replace(/\D/g, '');

  if (digitsOnly.length < 13 || digitsOnly.length > 19) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: `Length must be between 13 and 19 digits (got ${digitsOnly.length})`,
      normalizedValue: digitsOnly
    };
  }

  // Luhn checksum test
  const luhnPass = validateLuhn(digitsOnly);
  if (!luhnPass) {
    return {
      status: ValidationStatus.REJECTED_LUHN,
      reason: 'Failed Luhn modulus 10 checksum',
      normalizedValue: digitsOnly
    };
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: digitsOnly
  };
}

/**
 * Validates an Indian PAN candidate.
 * Format: 5 uppercase letters, 4 digits, 1 uppercase letter.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validatePan(rawValue, sourceText, start, end) {
  // Boundary check: must not be part of longer alphanumeric word
  if (!isSafeWordBoundary(sourceText, start, end, /[a-zA-Z0-9]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'PAN candidate is part of a longer alphanumeric identifier',
      normalizedValue: rawValue.toUpperCase()
    };
  }

  const normalized = rawValue.toUpperCase();
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(normalized)) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Invalid PAN structure. Must match [A-Z]{5}[0-9]{4}[A-Z]',
      normalizedValue: normalized
    };
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: normalized
  };
}

/**
 * Validates an IPv4 candidate.
 * Exactly 4 octets, each 0-255, strict boundary, version strings rejected.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateIpv4(rawValue, sourceText, start, end) {
  // Check if preceded or followed by dots or digits
  if (!isSafeWordBoundary(sourceText, start, end, /[0-9.]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'IPv4 candidate is adjacent to numbers or dots',
      normalizedValue: rawValue
    };
  }

  // Check version string policy: e.g. v1.2.3.4, version 10.20.30.40, release-2.3.4.5
  if (hasVersionPrefix(sourceText, start)) {
    return {
      status: ValidationStatus.REJECTED_VERSION_STRING,
      reason: 'Rejected as software version string',
      normalizedValue: rawValue
    };
  }

  const octets = rawValue.split('.');
  if (octets.length !== 4) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: `IPv4 must have exactly 4 octets (found ${octets.length})`,
      normalizedValue: rawValue
    };
  }

  for (let i = 0; i < 4; i++) {
    const octetStr = octets[i];
    // No empty octet
    if (octetStr === '') {
      return {
        status: ValidationStatus.REJECTED_FORMAT,
        reason: 'Empty octet found',
        normalizedValue: rawValue
      };
    }
    // Check leading zeros (e.g. 01 vs 0)
    if (octetStr.length > 1 && octetStr.startsWith('0')) {
      return {
        status: ValidationStatus.REJECTED_FORMAT,
        reason: `Octet ${i + 1} has invalid leading zero`,
        normalizedValue: rawValue
      };
    }
    const val = Number(octetStr);
    if (Number.isNaN(val) || val < 0 || val > 255) {
      return {
        status: ValidationStatus.REJECTED_OCTET_RANGE,
        reason: `Octet ${i + 1} (${octetStr}) out of range [0, 255]`,
        normalizedValue: rawValue
      };
    }
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: octets.map(Number).join('.')
  };
}

/**
 * Validates an Indian Aadhaar candidate.
 * 12 digits, first digit 2-9, strict boundary.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @param {boolean} [requireVerhoeff=false] - Whether to require Verhoeff checksum
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateAadhaar(rawValue, sourceText, start, end, requireVerhoeff = false) {
  // Boundary check: cannot be adjacent to digits or alphanumeric
  if (!isSafeWordBoundary(sourceText, start, end, /[0-9A-Za-z]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'Aadhaar candidate is adjacent to alphanumeric characters',
      normalizedValue: rawValue
    };
  }

  const digitsOnly = rawValue.replace(/\D/g, '');

  if (digitsOnly.length !== 12) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: `Aadhaar must be exactly 12 digits (found ${digitsOnly.length})`,
      normalizedValue: digitsOnly
    };
  }

  // Aadhaar cannot start with 0 or 1
  if (digitsOnly.startsWith('0') || digitsOnly.startsWith('1')) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Aadhaar cannot start with 0 or 1',
      normalizedValue: digitsOnly
    };
  }

  if (requireVerhoeff) {
    const passesVerhoeff = validateVerhoeff(digitsOnly);
    if (!passesVerhoeff) {
      return {
        status: ValidationStatus.REJECTED_VERHOEFF,
        reason: 'Failed Verhoeff checksum validation',
        normalizedValue: digitsOnly
      };
    }
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: digitsOnly
  };
}

/**
 * Validates an Indian Phone number candidate.
 * 10 digits starting with 6-9, optional +91/91/0 prefix.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateIndianPhone(rawValue, sourceText, start, end) {
  // Boundary check
  if (!isSafeWordBoundary(sourceText, start, end, /[0-9A-Za-z]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'Phone candidate is adjacent to alphanumeric characters',
      normalizedValue: rawValue
    };
  }

  // Date and timestamp rejection
  if (isPartOfDate(sourceText, start, end)) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Rejected: candidate is part of a date or timestamp',
      normalizedValue: rawValue
    };
  }

  // Normalize digits
  let digits = rawValue.replace(/\D/g, '');

  // Strip prefix
  if (digits.length === 12 && digits.startsWith('91')) {
    digits = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith('0')) {
    digits = digits.slice(1);
  }

  if (digits.length !== 10) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: `Indian mobile number must be 10 digits (found ${digits.length})`,
      normalizedValue: digits
    };
  }

  if (!/^[6-9]\d{9}$/.test(digits)) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Indian mobile number must start with 6, 7, 8, or 9',
      normalizedValue: digits
    };
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: `+91${digits}`
  };
}

/**
 * Validates an International Phone candidate (E.164-like).
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateInternationalPhone(rawValue, sourceText, start, end) {
  if (!isSafeWordBoundary(sourceText, start, end, /[0-9A-Za-z]/)) {
    return {
      status: ValidationStatus.REJECTED_BOUNDARY,
      reason: 'International phone candidate is adjacent to alphanumeric characters',
      normalizedValue: rawValue
    };
  }

  if (isPartOfDate(sourceText, start, end)) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Rejected: candidate is part of a date or timestamp',
      normalizedValue: rawValue
    };
  }

  // Must begin with +
  if (!rawValue.trim().startsWith('+')) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'International phone must begin with country code prefix (+)',
      normalizedValue: rawValue
    };
  }

  const digits = rawValue.replace(/\D/g, '');
  if (digits.length < 8 || digits.length > 15) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: `E.164 phone length must be 8-15 digits (found ${digits.length})`,
      normalizedValue: digits
    };
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: `+${digits}`
  };
}

/**
 * Validates an Email candidate.
 *
 * @param {string} rawValue
 * @param {string} sourceText
 * @param {number} start
 * @param {number} end
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateEmail(rawValue, sourceText, start, end) {
  const parts = rawValue.split('@');
  if (parts.length !== 2) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Email must contain exactly one @ symbol',
      normalizedValue: rawValue
    };
  }

  const [localPart, domain] = parts;

  // Local-part checks
  if (!localPart || localPart.length > 64) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: 'Email local-part must be 1-64 characters',
      normalizedValue: rawValue
    };
  }

  if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Email local-part cannot start/end with dot or contain consecutive dots',
      normalizedValue: rawValue
    };
  }

  // Domain checks
  if (!domain || domain.length > 253) {
    return {
      status: ValidationStatus.REJECTED_LENGTH,
      reason: 'Email domain must be 1-253 characters',
      normalizedValue: rawValue
    };
  }

  if (!domain.includes('.')) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Email domain must contain at least one dot',
      normalizedValue: rawValue
    };
  }

  const domainLabels = domain.split('.');
  for (const label of domainLabels) {
    if (!label || label.length > 63) {
      return {
        status: ValidationStatus.REJECTED_FORMAT,
        reason: 'Domain labels must be 1-63 characters',
        normalizedValue: rawValue
      };
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return {
        status: ValidationStatus.REJECTED_FORMAT,
        reason: 'Domain labels cannot start or end with hyphen',
        normalizedValue: rawValue
      };
    }
  }

  const tld = domainLabels[domainLabels.length - 1];
  if (tld.length < 2) {
    return {
      status: ValidationStatus.REJECTED_FORMAT,
      reason: 'Email TLD must be at least 2 characters',
      normalizedValue: rawValue
    };
  }

  return {
    status: ValidationStatus.VALID,
    normalizedValue: `${localPart.toLowerCase()}@${domain.toLowerCase()}`
  };
}

/**
 * Master candidate validator dispatcher.
 *
 * @param {{type: string, rawValue: string, start: number, end: number}} candidate
 * @param {string} sourceText
 * @param {Object} [options]
 * @param {boolean} [options.requireVerhoeff=false]
 * @returns {{status: string, reason?: string, normalizedValue: string}}
 */
export function validateCandidate(candidate, sourceText, options = {}) {
  switch (candidate.type) {
    case PiiType.CREDIT_CARD:
      return validateCreditCard(candidate.rawValue, sourceText, candidate.start, candidate.end);
    case PiiType.PAN:
      return validatePan(candidate.rawValue, sourceText, candidate.start, candidate.end);
    case PiiType.IPV4:
      return validateIpv4(candidate.rawValue, sourceText, candidate.start, candidate.end);
    case PiiType.AADHAAR:
      return validateAadhaar(candidate.rawValue, sourceText, candidate.start, candidate.end, options.requireVerhoeff ?? false);
    case PiiType.PHONE_IN:
      return validateIndianPhone(candidate.rawValue, sourceText, candidate.start, candidate.end);
    case PiiType.PHONE_INTL:
      return validateInternationalPhone(candidate.rawValue, sourceText, candidate.start, candidate.end);
    case PiiType.EMAIL:
      return validateEmail(candidate.rawValue, sourceText, candidate.start, candidate.end);
    default:
      return {
        status: ValidationStatus.INVALID,
        reason: `Unknown PII type: ${candidate.type}`,
        normalizedValue: candidate.rawValue
      };
  }
}
