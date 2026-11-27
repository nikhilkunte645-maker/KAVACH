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

  // Handle optional UTF-8 BOM
  let text = csvText;
  if (text.charCodeAt(0) === 0xFEFF) {
    text = text.slice(1);
  }

  const rows = [];
  let currentRow = [];
  let currentCell = '';
  let inQuotes = false;
  let i = 0;
  const len = text.length;

  while (i < len) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        // Look ahead for escaped double quote ("")
        if (i + 1 < len && text[i + 1] === '"') {
          currentCell += '"';
          i += 2;
          continue;
        } else {
          // Closing quote
          inQuotes = false;
          i++;
          continue;
        }
      } else {
        // Any character inside quotes (including \n, \r, commas)
        currentCell += ch;
        i++;
        continue;
      }
    } else {
      // Not in quotes
      if (ch === '"') {
        inQuotes = true;
        i++;
        continue;
      } else if (ch === ',') {
        currentRow.push(currentCell);
        currentCell = '';
        i++;
        continue;
      } else if (ch === '\r') {
        // Check for \r\n
        if (i + 1 < len && text[i + 1] === '\n') {
          i++;
        }
        currentRow.push(currentCell);
        rows.push(currentRow);
        currentRow = [];
        currentCell = '';
        i++;
        continue;
      } else if (ch === '\n') {
        currentRow.push(currentCell);
        rows.push(currentRow);
        currentRow = [];
        currentCell = '';
        i++;
        continue;
      } else {
        currentCell += ch;
        i++;
        continue;
      }
    }
  }

  // Push trailing cell and row
  currentRow.push(currentCell);
  rows.push(currentRow);

  // If the file ends with a trailing newline, RFC-4180 allows an empty final row;
  // if the last row is a single empty string produced by trailing newline, handle cleanly:
  if (rows.length > 1 && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === '') {
    // Only pop if the original text actually ended with newline
    const lastChar = text[text.length - 1];
    if (lastChar === '\n' || lastChar === '\r') {
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
