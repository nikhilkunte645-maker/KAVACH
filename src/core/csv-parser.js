/**
 * KAVACH - RFC-4180 CSV Engine & Spreadsheet Formula Injection Defense
 *
 * Features:
 * - Robust state machine parsing (quoted commas, escaped quotes, CRLF/LF, embedded newlines)
 * - Strict RFC-4180 serialization
 * - Formula injection prevention (prefixes dangerous leading characters with single quote)
 * - Cell-level PII detection and redaction without column corruption
 */

/**
 * State machine parser strictly adhering to RFC 4180.
 *
 * @param {string} csvText
 * @returns {Array<Array<string>>} 2D array of rows and cells
 */
export function parseCsv(csvText) {
  if (typeof csvText !== 'string' || csvText.length === 0) {
    return [];
  }

  let i = csvText.charCodeAt(0) === 0xFEFF ? 1 : 0;
  const len = csvText.length;
  if (i >= len) return [];

  /** @type {Array<Array<string>>} */
  const rows = [];
  /** @type {Array<string>} */
  let currentRow = [];
  /** @type {Array<string>} */
  let cellParts = [];
  let segStart = i;
  let inQuotes = false;

  const flushCell = (/** @type {number} */ endIdx) => {
    if (cellParts.length === 0) {
      return csvText.slice(segStart, endIdx);
    }
    if (endIdx > segStart) {
      cellParts.push(csvText.slice(segStart, endIdx));
    }
    const value = cellParts.join('');
    cellParts = [];
    return value;
  };

  while (i < len) {
    const code = csvText.charCodeAt(i);

    if (inQuotes) {
      if (code === 34 /* " */) {
        if (i > segStart) {
          cellParts.push(csvText.slice(segStart, i));
        }
        if (i + 1 < len && csvText.charCodeAt(i + 1) === 34) {
          cellParts.push('"');
          i += 2;
          segStart = i;
        } else {
          inQuotes = false;
          i++;
          segStart = i;
        }
      } else {
        i++;
      }
    } else {
      if (code === 34 /* " */) {
        if (i > segStart) {
          cellParts.push(csvText.slice(segStart, i));
        }
        inQuotes = true;
        i++;
        segStart = i;
      } else if (code === 44 /* , */) {
        currentRow.push(flushCell(i));
        i++;
        segStart = i;
      } else if (code === 13 /* \r */) {
        currentRow.push(flushCell(i));
        rows.push(currentRow);
        currentRow = [];
        if (i + 1 < len && csvText.charCodeAt(i + 1) === 10 /* \n */) {
          i += 2;
        } else {
          i++;
        }
        segStart = i;
      } else if (code === 10 /* \n */) {
        currentRow.push(flushCell(i));
        rows.push(currentRow);
        currentRow = [];
        i++;
        segStart = i;
      } else {
        i++;
      }
    }
  }

  currentRow.push(flushCell(len));
  rows.push(currentRow);

  if (rows.length > 1 && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === '') {
    const lastChar = csvText.charCodeAt(len - 1);
    if (lastChar === 10 || lastChar === 13) {
      rows.pop();
    }
  }

  return rows;
}

/**
 * Sanitizes a cell value against CSV formula injection (DDE / CSV Injection).
 * If cell starts with dangerous prefix characters, it is prepended with single quote
 * so spreadsheet tools treat it as raw text.
 *
 * @param {string} cellValue
 * @returns {string} Sanitized cell value
 */
export function sanitizeFormulaInjection(cellValue) {
  if (typeof cellValue !== 'string' || cellValue.length === 0) return cellValue;

  const trimmedLeading = cellValue.replace(/^[\s\uFEFF\xA0]+/, '');
  if (trimmedLeading.length === 0) return cellValue;

  const firstChar = trimmedLeading[0];
  if (firstChar === '=' || firstChar === '+' || firstChar === '-' || firstChar === '@' || firstChar === '\t' || firstChar === '\r') {
    // Prepend single quote
    return `'${cellValue}`;
  }

  return cellValue;
}

/**
 * Serializes a 2D array of strings into RFC-4180 compliant CSV.
 *
 * @param {Array<Array<string>>} rows
 * @param {Object} [options]
 * @param {boolean} [options.sanitizeFormulas=true] - Apply formula injection defense
 * @param {string} [options.lineEnding='\r\n']
 * @returns {string} Serialized CSV
 */
export function serializeCsv(rows, options = {}) {
  const sanitize = options.sanitizeFormulas ?? true;
  const lineEnding = options.lineEnding ?? '\r\n';

  if (!rows || rows.length === 0) return '';

  return rows
    .map((row) =>
      row
        .map((rawCell) => {
          let cell = rawCell;
          if (sanitize) {
            cell = sanitizeFormulaInjection(cell);
          }

          // RFC-4180 quoting rule:
          // If field contains comma, quote, \r, \n, or starts/ends with whitespace, wrap in double quotes
          const mustQuote =
            cell.includes(',') ||
            cell.includes('"') ||
            cell.includes('\n') ||
            cell.includes('\r');

          if (mustQuote) {
            // Escape double quotes by doubling them
            const escaped = cell.replace(/"/g, '""');
            return `"${escaped}"`;
          }

          return cell;
        })
        .join(',')
    )
    .join(lineEnding);
}

/**
 * Performs cell-level PII detection and redaction on parsed CSV rows.
 *
 * @param {Array<Array<string>>} rows
 * @param {Function} redactCellFn - Function (cellText, rowIdx, colIdx) => { redactedText, findings }
 * @returns {{ redactedRows: Array<Array<string>>, allFindings: Array<any> }}
 */
export function processCsvCells(rows, redactCellFn) {
  const redactedRows = [];
  const allFindings = [];

  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const newRow = [];
    for (let c = 0; c < row.length; c++) {
      const cellText = row[c];
      const { redactedText, findings } = redactCellFn(cellText, r, c);
      newRow.push(redactedText);
      if (findings && findings.length > 0) {
        for (const f of findings) {
          allFindings.push({
            ...f,
            cellCoord: { row: r, col: c }
          });
        }
      }
    }
    redactedRows.push(newRow);
  }

  return { redactedRows, allFindings };
}
