/**
 * KAVACH - Comprehensive Integration, Overlap, Diff, Logger, State, A11y & Security Invariant Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { resolveOverlaps } from '../src/core/overlap.js';
import { computeDiffSegments, escapeHtml } from '../src/core/diff.js';
import { PrivacyLogger } from '../src/core/logger.js';
import { KavachStateManager } from '../src/core/state.js';
import { processText, processCsv } from '../src/core/engine.js';
import { Pseudonymizer, redactText } from '../src/core/redactor.js';
import { parseCsv } from '../src/core/csv-parser.js';
import { PiiType, RedactionMode, ValidationStatus } from '../src/core/types.js';

describe('7. Overlap Resolution Edge Cases', () => {
  it('should discard invalid, negative, NaN, and empty spans safely', () => {
    const findings = /** @type {any[]} */ ([
      null,
      { id: 'bad1', type: PiiType.PAN, start: -1, end: 5, rawValue: 'X', normalizedValue: 'X', status: 'VALID' },
      { id: 'bad2', type: PiiType.PAN, start: 5, end: 5, rawValue: '', normalizedValue: '', status: 'VALID' },
      { id: 'bad3', type: PiiType.PAN, start: 10, end: 5, rawValue: 'X', normalizedValue: 'X', status: 'VALID' },
      { id: 'bad4', type: PiiType.PAN, start: NaN, end: 10, rawValue: 'X', normalizedValue: 'X', status: 'VALID' },
      { id: 'ok', type: PiiType.PAN, start: 2, end: 12, rawValue: 'ABCDE1234F', normalizedValue: 'ABCDE1234F', status: 'VALID' }
    ]);
    const resolved = resolveOverlaps(findings);
    assert.strictEqual(resolved.length, 1);
    assert.strictEqual(resolved[0].id, 'ok');
  });

  it('should resolve identical, nested, same-start, same-end, and partial overlaps deterministically', () => {
    const findings = [
      // Same-start [0, 16) vs [0, 12) -> longer wins
      { id: '1', type: PiiType.AADHAAR, start: 0, end: 12, rawValue: '234567890124', normalizedValue: '234567890124', status: 'VALID' },
      { id: '2', type: PiiType.CREDIT_CARD, start: 0, end: 16, rawValue: '4532015112830366', normalizedValue: '4532015112830366', status: 'VALID' },
      // Identical [20, 30) PAN vs EMAIL -> PAN has higher priority (80 > 70)
      { id: '3', type: PiiType.EMAIL, start: 20, end: 30, rawValue: 'a@test.com', normalizedValue: 'a@test.com', status: 'VALID' },
      { id: '4', type: PiiType.PAN, start: 20, end: 30, rawValue: 'ABCDE1234F', normalizedValue: 'ABCDE1234F', status: 'VALID' },
      // Adjacent [30, 40) -> preserved
      { id: '5', type: PiiType.IPV4, start: 30, end: 40, rawValue: '192.168.1.1', normalizedValue: '192.168.1.1', status: 'VALID' },
      // Same-end nested [32, 40) -> discarded because [30, 40) is accepted
      { id: '6', type: PiiType.IPV4, start: 32, end: 40, rawValue: '2.168.1.1', normalizedValue: '2.168.1.1', status: 'VALID' }
    ];
    const resolved = resolveOverlaps(findings);
    assert.deepStrictEqual(resolved.map((f) => f.id), ['2', '4', '5']);
  });

  it('should resolve 10,000 candidates efficiently in O(n log n)', () => {
    const large = [];
    for (let i = 0; i < 10000; i++) {
      large.push({
        id: `f_${i}`,
        type: PiiType.PAN,
        start: i * 12,
        end: i * 12 + 10,
        rawValue: 'ABCDE1234F',
        normalizedValue: 'ABCDE1234F',
        status: 'VALID'
      });
    }
    const t0 = performance.now();
    const resolved = resolveOverlaps(large);
    const dt = performance.now() - t0;
    assert.strictEqual(resolved.length, 10000);
    assert.ok(dt < 500, `Expected <500ms, took ${dt}ms`);
  });
});

describe('8. Diff Generation & Unicode Integrity', () => {
  it('should handle empty, identical, adjacent, HTML-escaped, and Unicode inputs', () => {
    assert.deepStrictEqual(computeDiffSegments('', []), []);
    assert.deepStrictEqual(computeDiffSegments('hello', []), [{ type: 'unchanged', text: 'hello' }]);

    const unicodeText = '👋你好 <script>alert(1)</script> a@b.comABCDE1234F\r\nend';
    const p = new Pseudonymizer();
    const res = processText(unicodeText, { redactionMode: RedactionMode.FULL_MASK, pseudonymizer: p });
    const segs = computeDiffSegments(unicodeText, res.findings);
    assert.ok(segs.some((s) => s.type === 'unchanged' && s.text.includes('👋你好 <script>')));
    assert.strictEqual(escapeHtml('<script>"\'&'), '&lt;script&gt;&quot;&#39;&amp;');
  });
});

describe('9. Logger & State Isolation Invariants', () => {
  it('should strip accidental emails and card numbers from logs and cap entries at 500', () => {
    const log = new PrivacyLogger();
    log.log({
      operation: 'TEST',
      details: 'User alice@example.com with card 4532 0151 1283 0366 failed'
    });
    const exported = log.exportJson();
    assert.ok(!exported.includes('alice@example.com'));
    assert.ok(!exported.includes('4532 0151 1283 0366'));

    for (let i = 0; i < 520; i++) {
      log.log({ operation: 'BULK', details: `Event ${i}` });
    }
    assert.strictEqual(log.getLogs().length, 500);
    log.clear();
    assert.strictEqual(log.getLogs().length, 0);
  });

  it('should reset state cleanly without sharing mutable pseudonym maps across runs', () => {
    const state = new KavachStateManager();
    const res1 = processText('a@example.com', {
      redactionMode: RedactionMode.PSEUDONYMIZE,
      pseudonymizer: state.pseudonymizer
    });
    assert.strictEqual(res1.redactedText, 'EMAIL_01');

    state.reset();
    const res2 = processText('b@example.com', {
      redactionMode: RedactionMode.PSEUDONYMIZE,
      pseudonymizer: state.pseudonymizer
    });
    assert.strictEqual(res2.redactedText, 'EMAIL_01');
  });
});

describe('10. End-to-End Engine Integration (All Modes & CSV)', () => {
  it('should process mixed PII across FULL_MASK, PARTIAL_MASK, and PSEUDONYMIZE deterministically', () => {
    const input = 'Mail: priya@example.com, Card: 4111 1111 1111 1111, Bad: 4111 1111 1111 1112, IP: 10.0.0.1';
    for (const mode of [RedactionMode.FULL_MASK, RedactionMode.PARTIAL_MASK, RedactionMode.PSEUDONYMIZE]) {
      const p = new Pseudonymizer();
      const res = processText(input, { redactionMode: mode, pseudonymizer: p });
      assert.strictEqual(res.findings.length, 3);
      assert.ok(!res.redactedText.includes('priya@example.com'));
      assert.ok(!res.redactedText.includes('4111 1111 1111 1111'));
      assert.ok(res.redactedText.includes('4111 1111 1111 1112')); // Luhn-rejected untouched
      assert.strictEqual(res.rejectedCandidates.some((c) => c.status === ValidationStatus.INVALID_LUHN), true);
    }
  });

  it('should preserve CSV structure and cross-cell pseudonym consistency', () => {
    const csv = 'Name,Email,Formula\r\n"A, B",dup@example.com,=1+1\r\nC,dup@example.com,ok';
    const p = new Pseudonymizer();
    const res = processCsv(csv, {
      redactionMode: RedactionMode.PSEUDONYMIZE,
      pseudonymizer: p,
      sanitizeFormulas: true
    });
    const rows = parseCsv(res.redactedCsv);
    assert.strictEqual(rows.length, 3);
    assert.strictEqual(rows[1][1], 'EMAIL_01');
    assert.strictEqual(rows[2][1], 'EMAIL_01');
    assert.strictEqual(rows[1][2], "'=1+1");
  });
});

describe('11. Accessibility & DOM Security Invariants', () => {
  const root = process.cwd();
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(root, 'style.css'), 'utf8');
  const appJs = fs.readFileSync(path.join(root, 'src/app.js'), 'utf8');

  it('should include skip-navigation, main landmark, live regions, and accessible labels in index.html', () => {
    assert.ok(html.includes('href="#main-content"'), 'Missing skip link');
    assert.ok(html.includes('<main id="main-content"'), 'Missing main landmark id');
    assert.ok(html.includes('aria-live="polite"'), 'Missing polite live region');
    assert.ok(html.includes('role="tablist"') && html.includes('role="tabpanel"'), 'Missing ARIA tab roles');
    assert.ok(html.includes('id="input-text"') && html.includes('aria-label="Original input text or CSV"'), 'Missing input textarea aria-label');
    assert.ok(html.includes('id="output-text"') && html.includes('aria-label="Redacted output text"'), 'Missing output textarea aria-label');
    assert.ok(html.includes('100% Client-Side • Zero Network Leaks'), 'Missing exact privacy pill text');
  });

  it('should include reduced-motion media query and skip-link focus styles in style.css', () => {
    assert.ok(css.includes('prefers-reduced-motion: reduce'), 'Missing reduced-motion support');
    assert.ok(css.includes('.skip-link:focus'), 'Missing skip-link focus rule');
  });

  it('should contain zero unsafe DOM sinks or persistent storage calls in src/app.js', () => {
    assert.ok(!/\.innerHTML\s*=/.test(appJs), 'innerHTML assignment found in app.js');
    assert.ok(!/\.outerHTML\s*=/.test(appJs), 'outerHTML assignment found in app.js');
    assert.ok(!/insertAdjacentHTML/.test(appJs), 'insertAdjacentHTML found in app.js');
    assert.ok(!/\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b/.test(appJs), 'Persistent storage found in app.js');
  });
});
