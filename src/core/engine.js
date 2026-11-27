/**
 * KAVACH - Main Processing Engine
 *
 * Orchestrates:
 * 1. Candidate detection
 * 2. Strict validation & rejection tracking
 * 3. Deterministic overlap resolution
 * 4. Redaction & pseudonymization
 * 5. CSV processing with cell-level precision
 */

import { detectCandidates } from './detectors.js';
import { validateCandidate } from './validators.js';
import { resolveOverlaps } from './overlap.js';
import { redactText } from './redactor.js';
import { parseCsv, serializeCsv, processCsvCells } from './csv-parser.js';
import { ValidationStatus, PiiType } from './types.js';
import { logger } from './logger.js';

// Shortest valid PII across all supported types is 6 chars (e.g., "a@b.cd")
const MIN_PII_CANDIDATE_LENGTH = 6;

/**
 * Processes plain text: detects, validates, resolves overlaps, and redacts.
 *
 * @param {string} text - Source text
 * @param {Object} options
 * @param {Set<string>} [options.enabledTypes]
 * @param {string} [options.redactionMode]
 * @param {import('./redactor.js').Pseudonymizer} options.pseudonymizer
 * @param {boolean} [options.requireVerhoeff=true]
 * @param {Record<string, string>} [options.customMasks]
 * @param {boolean} [options.skipLog=false] - Suppress per-call logging (used by batch CSV cell processing)
 * @returns {{
 *   redactedText: string,
 *   findings: Array<import('./types.js').PiiFinding>,
 *   rejectedCandidates: Array<any>,
 *   countsByType: Record<string, number>
 * }}
 */
export function processText(text, options) {
  if (typeof text !== 'string' || text.length < MIN_PII_CANDIDATE_LENGTH) {
    return {
      redactedText: typeof text === 'string' ? text : '',
      findings: [],
      rejectedCandidates: [],
      countsByType: {}
    };
  }

  // 1. Detect all candidates
  const candidates = detectCandidates(text, options.enabledTypes);

  // 2. Validate each candidate
  const validFindings = [];
  const rejectedCandidates = [];
  let findingIdCounter = 1;

  for (const cand of candidates) {
    const valResult = validateCandidate(cand, text, {
      requireVerhoeff: options.requireVerhoeff ?? true
    });

    if (valResult.status === ValidationStatus.VALID) {
      validFindings.push({
        id: `f_${findingIdCounter++}`,
        type: cand.type,
        start: cand.start,
        end: cand.end,
        rawValue: cand.rawValue,
        normalizedValue: valResult.normalizedValue,
        status: valResult.status
      });
    } else {
      rejectedCandidates.push({
        id: `rej_${findingIdCounter++}`,
        type: cand.type,
        start: cand.start,
        end: cand.end,
        rawValue: cand.rawValue,
        normalizedValue: valResult.normalizedValue,
        status: valResult.status,
        reason: valResult.reason
      });
    }
  }

  // 3. Resolve overlaps deterministically
  const resolvedFindings = resolveOverlaps(validFindings);

  // 4. Apply redaction
  const redactedText = redactText(
    text,
    resolvedFindings,
    options.redactionMode || 'FULL_MASK',
    options.pseudonymizer,
    options.customMasks
  );

  // Compute counts
  /** @type {Record<string, number>} */
  const countsByType = {};
  for (const f of resolvedFindings) {
    countsByType[f.type] = (countsByType[f.type] || 0) + 1;
  }

  // Log safe summary unless suppressed by batch caller (e.g. processCsv)
  if (!options.skipLog) {
    logger.log({
      operation: 'DETECTION',
      category: 'TEXT',
      count: resolvedFindings.length,
      status: 'SUCCESS',
      details: `Processed text (${text.length} chars). Detected ${resolvedFindings.length} valid PII findings.`
    });
  }

  return {
    redactedText,
    findings: resolvedFindings,
    rejectedCandidates,
    countsByType
  };
}

/**
 * Processes CSV text with cell-level precision, preserving columns and records.
 *
 * @param {string} csvText - Raw CSV content
 * @param {Object} options
 * @param {Set<string>} [options.enabledTypes]
 * @param {string} [options.redactionMode]
 * @param {import('./redactor.js').Pseudonymizer} options.pseudonymizer
 * @param {boolean} [options.sanitizeFormulas=true]
 * @param {boolean} [options.requireVerhoeff=true]
 * @param {Record<string, string>} [options.customMasks]
 * @returns {{
 *   redactedCsv: string,
 *   originalRows: Array<Array<string>>,
 *   redactedRows: Array<Array<string>>,
 *   findings: Array<any>,
 *   rejectedCandidates: Array<any>,
 *   countsByType: Record<string, number>
 * }}
 */
export function processCsv(csvText, options) {
  const originalRows = parseCsv(csvText);
  if (originalRows.length === 0) {
    return {
      redactedCsv: '',
      originalRows: [],
      redactedRows: [],
      findings: [],
      rejectedCandidates: [],
      countsByType: {}
    };
  }

  /** @type {Array<any>} */
  const allRejectedCandidates = [];

  const { redactedRows, allFindings } = processCsvCells(
    originalRows,
    (/** @type {string} */ cellText, /** @type {number} */ row, /** @type {number} */ col) => {
    if (!cellText || cellText.length < MIN_PII_CANDIDATE_LENGTH) {
      return { redactedText: cellText, findings: [] };
    }
    const result = processText(cellText, {
      ...options,
      skipLog: true,
      // Pass the same pseudonymizer so cross-cell pseudonym consistency is maintained!
      pseudonymizer: options.pseudonymizer
    });
    if (result.rejectedCandidates && result.rejectedCandidates.length > 0) {
      for (const rc of result.rejectedCandidates) {
        allRejectedCandidates.push({
          ...rc,
          cellCoord: { row, col }
        });
      }
    }
    return {
      redactedText: result.redactedText,
      findings: result.findings
    };
  });

  const redactedCsv = serializeCsv(redactedRows, {
    sanitizeFormulas: options.sanitizeFormulas ?? true
  });

  /** @type {Record<string, number>} */
  const countsByType = {};
  for (const f of allFindings) {
    countsByType[f.type] = (countsByType[f.type] || 0) + 1;
  }

  logger.log({
    operation: 'REDACTION',
    category: 'CSV',
    count: allFindings.length,
    status: 'SUCCESS',
    details: `Processed CSV (${originalRows.length} rows). Redacted ${allFindings.length} cell PII findings.`
  });

  return {
    redactedCsv,
    originalRows,
    redactedRows,
    findings: allFindings,
    rejectedCandidates: allRejectedCandidates,
    countsByType
  };
}
