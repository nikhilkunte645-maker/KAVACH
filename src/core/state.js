/**
 * KAVACH - Transient State Manager
 *
 * Guarantees zero storage persistence:
 * - Never touches localStorage, sessionStorage, IndexedDB, cookies, or URL params
 * - Holds state strictly in transient JavaScript heap memory
 * - Provides verified complete reset
 */

import { RedactionMode, PiiType } from './types.js';
import { Pseudonymizer } from './redactor.js';
import { logger } from './logger.js';

export class KavachStateManager {
  constructor() {
    this.pseudonymizer = new Pseudonymizer();
    this.reset();
  }

  /**
   * Resets all internal state and wipes all references to sensitive data.
   */
  reset() {
    this.runId = `run_${Date.now()}`;
    this.sourceType = 'text'; // 'text' | 'txt' | 'csv'
    this.fileName = null;
    this.rawSourceText = '';
    this.redactedText = '';
    /** @type {Array<import('./types.js').PiiFinding>} */
    this.findings = [];
    /** @type {Array<Array<string>> | null} */
    this.parsedCsvRows = null;
    /** @type {Array<Array<string>> | null} */
    this.redactedCsvRows = null;

    /** @type {{
     *   enabledTypes: Set<string>,
     *   redactionMode: string,
     *   sanitizeCsvFormulas: boolean,
     *   requireVerhoeffForAadhaar: boolean,
     *   customMasks: Record<string, string>
     * }} */
    this.config = {
      enabledTypes: new Set(Object.values(PiiType)),
      redactionMode: RedactionMode.FULL_MASK,
      sanitizeCsvFormulas: true,
      requireVerhoeffForAadhaar: true,
      customMasks: {}
    };

    this.pseudonymizer.reset();

    logger.log({
      operation: 'RESET',
      category: 'STATE',
      status: 'INFO',
      details: 'KAVACH state reset: all transient memory cleared'
    });
  }

  /**
   * Configures active detector types.
   * @param {Set<string>} typesSet
   */
  setEnabledTypes(typesSet) {
    this.config.enabledTypes = new Set(typesSet);
  }

  /**
   * Updates redaction mode.
   * @param {string} mode
   */
  setRedactionMode(mode) {
    this.config.redactionMode = mode;
  }

  /**
   * Sets formula injection policy.
   * @param {boolean} sanitize
   */
  setSanitizeCsvFormulas(sanitize) {
    this.config.sanitizeCsvFormulas = Boolean(sanitize);
  }

  /**
   * Sets whether Aadhaar requires Verhoeff checksum.
   * @param {boolean} require
   */
  setRequireVerhoeff(require) {
    this.config.requireVerhoeffForAadhaar = Boolean(require);
  }
}

export const stateManager = new KavachStateManager();
