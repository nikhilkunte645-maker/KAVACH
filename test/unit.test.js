/**
 * KAVACH - Comprehensive Unit Test Suite
 * Tests with native Node.js test runner (node:test).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { validateLuhn } from '../src/core/luhn.js';
import { validateVerhoeff, generateVerhoeff } from '../src/core/verhoeff.js';
import { detectCandidates } from '../src/core/detectors.js';
import { validateCandidate, isSafeWordBoundary, hasVersionPrefix } from '../src/core/validators.js';
import { resolveOverlaps } from '../src/core/overlap.js';
import { Pseudonymizer, redactText, generatePartialMask } from '../src/core/redactor.js';
import { processText } from '../src/core/engine.js';
import { PiiType, ValidationStatus, RedactionMode } from '../src/core/types.js';

describe('1. Luhn Checksum Algorithm', () => {
  it('should accept valid 13 to 19 digit numbers', () => {
    assert.strictEqual(validateLuhn('4532015112830366'), true); // 16 digits
    assert.strictEqual(validateLuhn('4012888888881'), true);    // 13 digits
  });

  it('should reject invalid Luhn numbers and wrong lengths', () => {
    assert.strictEqual(validateLuhn('4532015112830367'), false); // corrupted checksum
    assert.strictEqual(validateLuhn('123456789012'), false);     // 12 digits (too short)
    assert.strictEqual(validateLuhn('12345678901234567890'), false); // 20 digits (too long)
    assert.strictEqual(validateLuhn('453201511283036A'), false); // non-digit
  });
});

describe('2. Verhoeff Algorithm for Aadhaar', () => {
  it('should correctly calculate and validate Verhoeff checksums', () => {
    const base = '36759832451';
    const checksum = generateVerhoeff(base);
    const validNumber = `${base}${checksum}`;
    assert.strictEqual(validateVerhoeff(validNumber), true);
    // Corrupted checksum
    const corrupted = `${base}${(checksum + 1) % 10}`;
    assert.strictEqual(validateVerhoeff(corrupted), false);
  });
});

describe('3. PAN Validation', () => {
  it('should validate standard 10-character PAN format', () => {
    const text = 'PAN: ABCDE1234F';
    const cand = { type: PiiType.PAN, rawValue: 'ABCDE1234F', start: 5, end: 15 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.VALID);
    assert.strictEqual(res.normalizedValue, 'ABCDE1234F');
  });

  it('should normalize lowercase PAN', () => {
    const text = 'PAN: abcde1234f';
    const cand = { type: PiiType.PAN, rawValue: 'abcde1234f', start: 5, end: 15 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.VALID);
    assert.strictEqual(res.normalizedValue, 'ABCDE1234F');
  });

  it('should reject PAN embedded in longer alphanumeric token', () => {
    const text = 'TXNABCDE1234F99';
    const cand = { type: PiiType.PAN, rawValue: 'ABCDE1234F', start: 3, end: 13 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.REJECTED_BOUNDARY);
  });
});

describe('4. IPv4 Validation & Version String Policy', () => {
  it('should accept valid IPv4', () => {
    const text = 'Host 10.0.0.1';
    const cand = { type: PiiType.IPV4, rawValue: '10.0.0.1', start: 5, end: 13 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.VALID);
  });

  it('should reject octets > 255', () => {
    const text = 'Host 256.0.0.1';
    const cand = { type: PiiType.IPV4, rawValue: '256.0.0.1', start: 5, end: 14 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.REJECTED_OCTET_RANGE);
  });

  it('should reject negative octets', () => {
    const text = 'Host 192.168.-1.1';
    const cand = { type: PiiType.IPV4, rawValue: '192.168.-1.1', start: 5, end: 17 };
    const res = validateCandidate(cand, text);
    assert.strictEqual(res.status, ValidationStatus.REJECTED_OCTET_RANGE);

    const textFirstNeg = 'Host -1.2.3.4';
    const candFirstNeg = { type: PiiType.IPV4, rawValue: '1.2.3.4', start: 6, end: 13 };
    const resFirstNeg = validateCandidate(candFirstNeg, textFirstNeg);
    assert.strictEqual(resFirstNeg.status, ValidationStatus.REJECTED_OCTET_RANGE);
  });

  it('should reject version strings like v1.2.3.4 and release-2.3.4.5', () => {
    const text1 = 'App v1.2.3.4 is out';
    const cand1 = { type: PiiType.IPV4, rawValue: '1.2.3.4', start: 5, end: 12 };
    assert.strictEqual(validateCandidate(cand1, text1).status, ValidationStatus.REJECTED_VERSION_STRING);

    const text2 = 'Deploy release-2.3.4.5 today';
    const cand2 = { type: PiiType.IPV4, rawValue: '2.3.4.5', start: 15, end: 22 };
    assert.strictEqual(validateCandidate(cand2, text2).status, ValidationStatus.REJECTED_VERSION_STRING);
  });
});

describe('5. Deterministic Overlap Resolution', () => {
  it('should resolve overlapping spans by start ascending, length descending, priority', () => {
    // Overlapping candidates: A [0, 10), B [5, 15)
    const findings = [
      { id: '1', type: PiiType.PHONE_IN, start: 5, end: 15, rawValue: '9876543210', normalizedValue: '+919876543210', status: ValidationStatus.VALID },
      { id: '2', type: PiiType.CREDIT_CARD, start: 0, end: 16, rawValue: '4532015112830366', normalizedValue: '4532015112830366', status: ValidationStatus.VALID }
    ];
    const resolved = resolveOverlaps(findings);
    // Credit card starts earlier (0) and is longer (16) -> wins
    assert.strictEqual(resolved.length, 1);
    assert.strictEqual(resolved[0].type, PiiType.CREDIT_CARD);
  });

  it('should handle adjacent non-overlapping spans without dropping either', () => {
    const findings = [
      { id: '1', type: PiiType.PAN, start: 0, end: 10, rawValue: 'ABCDE1234F', normalizedValue: 'ABCDE1234F', status: ValidationStatus.VALID },
      { id: '2', type: PiiType.EMAIL, start: 10, end: 25, rawValue: 'test@example.com', normalizedValue: 'test@example.com', status: ValidationStatus.VALID }
    ];
    const resolved = resolveOverlaps(findings);
    assert.strictEqual(resolved.length, 2);
  });
});

describe('6. Redaction Modes & Consistent Pseudonymization', () => {
  it('should consistently pseudonymize repeated values across a run', () => {
    const p = new Pseudonymizer();
    const token1 = p.getToken(PiiType.EMAIL, 'user@example.com');
    const token2 = p.getToken(PiiType.EMAIL, 'other@example.com');
    const token3 = p.getToken(PiiType.EMAIL, 'USER@example.com'); // case-insensitive

    assert.strictEqual(token1, 'EMAIL_01');
    assert.strictEqual(token2, 'EMAIL_02');
    assert.strictEqual(token3, 'EMAIL_01'); // mapped to same token
  });

  it('should isolate namespaces between different categories', () => {
    const p = new Pseudonymizer();
    const emailToken = p.getToken(PiiType.EMAIL, 'user@example.com');
    const cardToken = p.getToken(PiiType.CREDIT_CARD, '4532015112830366');
    assert.strictEqual(emailToken, 'EMAIL_01');
    assert.strictEqual(cardToken, 'CARD_01');
  });

  it('should generate proper partial mask for emails with domain masking', () => {
    const finding = {
      id: 'f_1',
      type: PiiType.EMAIL,
      rawValue: 'user@example.com',
      normalizedValue: 'user@example.com',
      start: 0,
      end: 16,
      status: ValidationStatus.VALID
    };
    const masked = generatePartialMask(finding);
    assert.strictEqual(masked, 'u***@e******.com');
  });
});
