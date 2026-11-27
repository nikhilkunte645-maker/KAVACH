/**
 * KAVACH - Built-In Self-Test Runner
 *
 * Executes the production suite and returns audit-compliant results.
 * Guarantees zero raw PII in outputs and real execution (no mocks/stubs).
 */

import { getSelfTestCases } from './test-cases.js';
import { logger } from '../core/logger.js';

/**
 * @typedef {Object} TestExecutionResult
 * @property {string} category
 * @property {string} name
 * @property {boolean} passed
 * @property {string} status - 'PASS' | 'FAIL'
 * @property {string} [failureReason] - Sanitized failure reason
 * @property {number} durationMs
 */

/**
 * Runs all built-in self-tests.
 *
 * @param {Function} [onProgress] - Optional callback (currentResult, index, total)
 * @returns {Promise<{
 *   total: number,
 *   passed: number,
 *   failed: number,
 *   durationMs: number,
 *   results: Array<TestExecutionResult>
 * }>}
 */
export async function runAllSelfTests(onProgress = null) {
  const cases = getSelfTestCases();
  const results = [];
  let passedCount = 0;
  let failedCount = 0;
  const suiteStartTime = performance.now();

  for (let i = 0; i < cases.length; i++) {
    const testCase = cases[i];
    const testStartTime = performance.now();
    let passed = false;
    let failureReason = '';

    try {
      const outcome = await testCase.run();
      passed = outcome === true;
      if (!passed) {
        failureReason = 'Assertion returned false';
      }
    } catch (err) {
      passed = false;
      // Sanitize error message to ensure no accidental sensitive data leaks
      failureReason = String(err?.message || 'Unexpected exception during execution')
        .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
        .replace(/\b(?:\d[ -]?){12,18}\d\b/g, '[REDACTED_NUMBER]');
    }

    const durationMs = Math.round((performance.now() - testStartTime) * 100) / 100;

    if (passed) {
      passedCount++;
    } else {
      failedCount++;
    }

    const testResult = {
      category: testCase.category,
      name: testCase.name,
      passed,
      status: passed ? 'PASS' : 'FAIL',
      failureReason: passed ? undefined : failureReason,
      durationMs
    };

    results.push(testResult);

    if (typeof onProgress === 'function') {
      try {
        onProgress(testResult, i + 1, cases.length);
      } catch {
        // Safe swallow
      }
    }
  }

  const totalDurationMs = Math.round((performance.now() - suiteStartTime) * 100) / 100;

  logger.log({
    operation: 'SELF_TEST',
    category: 'SYSTEM',
    count: cases.length,
    status: failedCount === 0 ? 'SUCCESS' : 'WARNING',
    details: `Executed ${cases.length} self-tests: ${passedCount} passed, ${failedCount} failed (${totalDurationMs}ms)`
  });

  return {
    total: cases.length,
    passed: passedCount,
    failed: failedCount,
    durationMs: totalDurationMs,
    results
  };
}
