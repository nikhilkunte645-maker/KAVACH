/**
 * Verhoeff Checksum Algorithm
 * Dihedral Group D5 checksum used for Indian Aadhaar 12-digit number validation.
 */

// The multiplication table (d)
const D_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];

// The permutation table (p)
const P_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
];

// The inverse table (inv)
const INV_TABLE = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/**
 * Validates a numeric string using the Verhoeff algorithm.
 *
 * @param {string} digitsOnly - String containing only digits (0-9)
 * @returns {boolean} True if checksum is valid
 */
export function validateVerhoeff(digitsOnly) {
  if (typeof digitsOnly !== 'string' || !/^\d+$/.test(digitsOnly)) {
    return false;
  }

  let c = 0;
  const len = digitsOnly.length;

  for (let i = 0; i < len; i++) {
    const digit = digitsOnly.charCodeAt(len - 1 - i) - 48;
    c = D_TABLE[c][P_TABLE[i % 8][digit]];
  }

  return c === 0;
}

/**
 * Calculates the Verhoeff checksum digit for a number string.
 * Useful for test generation.
 *
 * @param {string} digitsOnly
 * @returns {number} Checksum digit (0-9)
 */
export function generateVerhoeff(digitsOnly) {
  let c = 0;
  const len = digitsOnly.length;
  for (let i = 0; i < len; i++) {
    const digit = digitsOnly.charCodeAt(len - 1 - i) - 48;
    c = D_TABLE[c][P_TABLE[(i + 1) % 8][digit]];
  }
  return INV_TABLE[c];
}
