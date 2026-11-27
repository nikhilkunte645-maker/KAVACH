/**
 * KAVACH - Privacy-Safe Activity Logger
 *
 * Strictly records safe operational metadata:
 * - Timestamps
 * - Operation types (DETECTION, REDACTION, EXPORT, RESET, SELF_TEST)
 * - PII category
 * - Total counts
 * - Success/failure status
 *
 * NEVER records raw PII, input text, or sensitive exception bodies.
 */

export class PrivacyLogger {
  constructor() {
    /** @type {Array<Object>} */
    this.logs = [];
    /** @type {Array<Function>} */
    this.listeners = [];
  }

  /**
   * Adds an observer listener.
   * @param {Function} listener
   */
  subscribe(listener) {
    this.listeners.push(listener);
  }

  /**
   * Emits safe event to listeners.
   */
  notify() {
    for (const listener of this.listeners) {
      try {
        listener(this.getLogs());
      } catch {
        // Safe swallow of listener errors
      }
    }
  }

  /**
   * Records a safe operational log entry.
   *
   * @param {Object} entry
   * @param {string} entry.operation - e.g. 'DETECTION', 'REDACTION', 'EXPORT'
   * @param {string} [entry.category] - e.g. 'CREDIT_CARD', 'CSV', 'SYSTEM'
   * @param {number} [entry.count=0] - Number of findings
   * @param {'SUCCESS' | 'INFO' | 'WARNING' | 'ERROR'} [entry.status='SUCCESS']
   * @param {string} [entry.details=''] - Sanitized description (never raw PII)
   */
  log({ operation, category = 'GENERAL', count = 0, status = 'SUCCESS', details = '' }) {
    // Sanitize details just in case: strip any possible email, card numbers or sensitive tokens
    const sanitizedDetails = String(details)
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
      .replace(/\b(?:\d[ -]?){12,18}\d\b/g, '[REDACTED_NUMBER]');

    const record = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      operation,
      category,
      count,
      status,
      details: sanitizedDetails
    };

    this.logs.push(record);

    // Limit memory log size to last 500 entries to prevent memory exhaustion
    if (this.logs.length > 500) {
      this.logs.shift();
    }

    this.notify();
    return record;
  }

  /**
   * Returns current safe logs.
   * @returns {Array<Object>}
   */
  getLogs() {
    return [...this.logs];
  }

  /**
   * Exports logs as privacy-safe JSON string.
   * @returns {string}
   */
  exportJson() {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Clears all logs in memory.
   */
  clear() {
    this.logs = [];
    this.notify();
  }
}

export const logger = new PrivacyLogger();
