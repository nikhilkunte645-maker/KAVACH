/**
 * Luhn Algorithm Implementation
 * ISO/IEC 7812-1 modulus 10 checksum for credit card validation
 */

/**
 * Validates a string of digits using the Luhn algorithm.
 * Rejects non-digit characters, lengths outside [13, 19], or failing checksums.
 *
 * @param {string} digitsOnly - String containing only digits (0-9)
 * @returns {boolean} True if passes Luhn checksum
 */
export function validateLuhn(digitsOnly) {
  if (typeof digitsOnly !== 'string') return false;

  // Strict digit check (ASCII 0-9)
  if (!/^\d{13,19}$/.test(digitsOnly)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let digit = digitsOnly.charCodeAt(i) - 48; // Faster than parseInt
    if (digit < 0 || digit > 9) return false;

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}
