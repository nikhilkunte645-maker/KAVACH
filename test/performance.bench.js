/**
 * KAVACH - Reproducible Performance Benchmark Suite
 * Measures Detection, Validation, Overlap Resolution, Redaction, CSV Parsing,
 * Diff Generation, and End-to-End processing across 100 KB, 500 KB, 1 MB, and 5 MB.
 *
 * Zero raw PII is printed in benchmark reports.
 */

import assert from 'node:assert/strict';
import { detectCandidates } from '../src/core/detectors.js';
import { validateCandidate } from '../src/core/validators.js';
import { resolveOverlaps } from '../src/core/overlap.js';
import { redactText, Pseudonymizer } from '../src/core/redactor.js';
import { parseCsv } from '../src/core/csv-parser.js';
import { computeDiffSegments } from '../src/core/diff.js';
import { processText, processCsv } from '../src/core/engine.js';
import { RedactionMode, ValidationStatus } from '../src/core/types.js';

const SAMPLE_TEXT_UNIT =
  'Log user@example.com phone +91 9876543210 pan ABCDE1234F ip 192.168.1.1 card 4532-0151-1283-0366\n';
const SAMPLE_CSV_UNIT =
  '"Doe, John",user@example.com,+91 9876543210,ABCDE1234F,192.168.1.1,4532-0151-1283-0366\r\n';

/**
 * Computes median of numeric array.
 * @param {Array<number>} values
 * @returns {number}
 */
function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Benchmarks a synchronous function and returns median ms.
 * @param {() => void} fn
 * @param {number} runs
 * @returns {number}
 */
function measureMedianMs(fn, runs) {
  const timings = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    fn();
    timings.push(performance.now() - t0);
  }
  return Math.round(median(timings) * 100) / 100;
}

console.log('\n============================================================');
console.log('⚡ KAVACH Performance Benchmark Suite (Median Timings)');
console.log('============================================================\n');

// Warmup JIT on a small payload
{
  const p = new Pseudonymizer();
  processText(SAMPLE_TEXT_UNIT.repeat(50), { redactionMode: RedactionMode.PSEUDONYMIZE, pseudonymizer: p });
  processCsv('A,B,C,D,E,F\r\n' + SAMPLE_CSV_UNIT.repeat(50), { redactionMode: RedactionMode.FULL_MASK, pseudonymizer: p });
}

const WORKLOADS = [
  { label: '100 KB', bytes: 100 * 1024, runs: 5, maxTextMs: 300, maxCsvMs: 600 },
  { label: '500 KB', bytes: 500 * 1024, runs: 5, maxTextMs: 1000, maxCsvMs: 1500 },
  { label: '1 MB', bytes: 1024 * 1024, runs: 3, maxTextMs: 1500, maxCsvMs: 2500 },
  { label: '5 MB', bytes: 5 * 1024 * 1024, runs: 3, maxTextMs: 4000, maxCsvMs: 6000 }
];

for (const w of WORKLOADS) {
  const text = SAMPLE_TEXT_UNIT.repeat(Math.ceil(w.bytes / SAMPLE_TEXT_UNIT.length));
  const csv = 'Name,Email,Phone,PAN,IP,Card\r\n' + SAMPLE_CSV_UNIT.repeat(Math.ceil(w.bytes / SAMPLE_CSV_UNIT.length));

  const cands = detectCandidates(text);
  /** @type {Array<any>} */
  const validFindings = [];
  for (const c of cands) {
    const v = validateCandidate(c, text, { requireVerhoeff: true });
    if (v.status === ValidationStatus.VALID) {
      validFindings.push({ id: `f_${validFindings.length}`, ...c, normalizedValue: v.normalizedValue, status: v.status });
    }
  }
  const resolved = resolveOverlaps(validFindings);

  const detMs = measureMedianMs(() => detectCandidates(text), w.runs);
  const valMs = measureMedianMs(() => {
    for (const c of cands) validateCandidate(c, text, { requireVerhoeff: true });
  }, w.runs);
  const ovMs = measureMedianMs(() => resolveOverlaps(validFindings), w.runs);
  const redMs = measureMedianMs(() => {
    const p = new Pseudonymizer();
    redactText(text, resolved, RedactionMode.PSEUDONYMIZE, p);
  }, w.runs);
  const diffMs = measureMedianMs(() => computeDiffSegments(text, resolved), w.runs);
  const csvParseMs = measureMedianMs(() => parseCsv(csv), w.runs);

  const textE2EMs = measureMedianMs(() => {
    const p = new Pseudonymizer();
    processText(text, { redactionMode: RedactionMode.FULL_MASK, pseudonymizer: p, skipLog: true });
  }, w.runs);

  const csvE2EMs = measureMedianMs(() => {
    const p = new Pseudonymizer();
    processCsv(csv, { redactionMode: RedactionMode.FULL_MASK, pseudonymizer: p });
  }, w.runs);

  console.log(
    `[${w.label}] (${resolved.length} findings) | ` +
    `Det: ${detMs}ms | Val: ${valMs}ms | Ov: ${ovMs}ms | Red: ${redMs}ms | ` +
    `Diff: ${diffMs}ms | CsvParse: ${csvParseMs}ms | TextE2E: ${textE2EMs}ms | CsvE2E: ${csvE2EMs}ms`
  );

  assert.ok(textE2EMs < w.maxTextMs, `${w.label} Text E2E exceeded ${w.maxTextMs}ms (${textE2EMs}ms)`);
  assert.ok(csvE2EMs < w.maxCsvMs, `${w.label} CSV E2E exceeded ${w.maxCsvMs}ms (${csvE2EMs}ms)`);
}

console.log('\n✅ All performance regression thresholds passed.\n');
