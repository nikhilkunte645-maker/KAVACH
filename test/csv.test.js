/**
 * KAVACH - CSV Parsing, Integrity & Security Tests
 * Tests RFC-4180 conformance and spreadsheet formula injection defenses.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { parseCsv, serializeCsv, sanitizeFormulaInjection } from '../src/core/csv-parser.js';
import { processCsv } from '../src/core/engine.js';
import { Pseudonymizer } from '../src/core/redactor.js';
import { RedactionMode } from '../src/core/types.js';

describe('1. RFC-4180 CSV Parser', () => {
  it('should handle basic comma-separated fields', () => {
    const csv = 'A,B,C\r\n1,2,3';
    const parsed = parseCsv(csv);
    assert.deepStrictEqual(parsed, [['A', 'B', 'C'], ['1', '2', '3']]);
  });

  it('should handle quoted fields containing commas', () => {
    const csv = 'Name,Address\r\n"Doe, John","123 Main St, Apt 4"';
    const parsed = parseCsv(csv);
    assert.strictEqual(parsed[1][0], 'Doe, John');
    assert.strictEqual(parsed[1][1], '123 Main St, Apt 4');
  });

  it('should handle escaped double quotes ("")', () => {
    const csv = 'Quote\r\n"He said ""Hello"" to them"';
    const parsed = parseCsv(csv);
    assert.strictEqual(parsed[1][0], 'He said "Hello" to them');
  });

  it('should handle embedded newlines within quotes', () => {
    const csv = 'ID,Comment\r\n1,"Line 1\r\nLine 2\nLine 3"';
    const parsed = parseCsv(csv);
    assert.strictEqual(parsed[1][1], 'Line 1\r\nLine 2\nLine 3');
  });

  it('should handle empty fields and trailing commas', () => {
    const csv = 'A,B,C,\r\n1,,3,';
    const parsed = parseCsv(csv);
    assert.strictEqual(parsed[0].length, 4);
    assert.strictEqual(parsed[0][3], '');
    assert.strictEqual(parsed[1][1], '');
    assert.strictEqual(parsed[1][3], '');
  });
});

describe('2. RFC-4180 Serialization Round-Trip', () => {
  it('should serialize and re-parse identical structures', () => {
    const originalRows = [
      ['Name', 'Bio', 'Notes'],
      ['Alice', 'Likes "quotes" and, commas', 'Single line'],
      ['Bob', 'Multiline:\nRow 2', '']
    ];

    const serialized = serializeCsv(originalRows, { sanitizeFormulas: false });
    const reparsed = parseCsv(serialized);

    assert.deepStrictEqual(reparsed, originalRows);
  });
});

describe('3. CSV Formula Injection Defense', () => {
  it('should sanitize cells starting with =, +, -, @, or tabs', () => {
    assert.strictEqual(sanitizeFormulaInjection('=cmd|/c calc!A0'), "'=cmd|/c calc!A0");
    assert.strictEqual(sanitizeFormulaInjection('+1+2'), "'+1+2");
    assert.strictEqual(sanitizeFormulaInjection('-2+3'), "'-2+3");
    assert.strictEqual(sanitizeFormulaInjection('@SUM(A1:A10)'), "'@SUM(A1:A10)");
    assert.strictEqual(sanitizeFormulaInjection('\t=evil()'), "'\t=evil()");
  });

  it('should leave normal text untouched', () => {
    assert.strictEqual(sanitizeFormulaInjection('Normal text'), 'Normal text');
    assert.strictEqual(sanitizeFormulaInjection('12345'), '12345');
    assert.strictEqual(sanitizeFormulaInjection('user@example.com'), 'user@example.com');
  });

  it('should apply sanitization during processCsv export', () => {
    const evilCsv = 'Formula,Email\r\n"=cmd",alice@example.com';
    const p = new Pseudonymizer();
    const res = processCsv(evilCsv, {
      redactionMode: RedactionMode.FULL_MASK,
      pseudonymizer: p,
      sanitizeFormulas: true
    });

    const parsed = parseCsv(res.redactedCsv);
    assert.strictEqual(parsed[1][0], "'=cmd");
    assert.strictEqual(parsed[1][1], '[REDACTED_EMAIL]');
  });
});
