#!/usr/bin/env node
/**
 * KAVACH - CLI Self-Test Runner
 * Executes production tests from terminal and returns appropriate exit code.
 */

import { runAllSelfTests } from '../src/self-test/runner.js';

async function main() {
  console.log('\n============================================================');
  console.log('🛡️  KAVACH - Client-Side PII Redactor Self-Test Suite');
  console.log('============================================================\n');

  let currentCategory = '';

  const summary = await runAllSelfTests((/** @type {any} */ result, /** @type {number} */ index, /** @type {number} */ total) => {
    if (result.category !== currentCategory) {
      currentCategory = result.category;
      console.log(`\n--- [${currentCategory}] ---`);
    }

    const statusBadge = result.passed ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m';
    console.log(`  ${statusBadge} ${result.name} (${result.durationMs}ms)`);
    if (!result.passed && result.failureReason) {
      console.log(`         \x1b[33mReason: ${result.failureReason}\x1b[0m`);
    }
  });

  console.log('\n============================================================');
  console.log('Test Execution Summary');
  console.log('============================================================');
  console.log(`Total Tests Run:  ${summary.total}`);
  console.log(`Passed:           \x1b[32m${summary.passed}\x1b[0m`);
  console.log(`Failed:           ${summary.failed > 0 ? `\x1b[31m${summary.failed}\x1b[0m` : '0'}`);
  console.log(`Total Time:       ${summary.durationMs}ms`);
  console.log('============================================================\n');

  if (summary.failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Fatal self-test runner error:', err);
  process.exit(1);
});
