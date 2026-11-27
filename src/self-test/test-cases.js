/**
 * KAVACH - Built-In Self-Test Cases
 *
 * Directly tests the production detection, validation, redaction,
 * CSV, and privacy modules against all requirements in Section 9.
 */

import { processText, processCsv } from '../core/engine.js';
import { Pseudonymizer } from '../core/redactor.js';
import { RedactionMode, PiiType, ValidationStatus } from '../core/types.js';
import { parseCsv, serializeCsv } from '../core/csv-parser.js';
import { computeDiffSegments, escapeHtml } from '../core/diff.js';
import { logger } from '../core/logger.js';
import { stateManager } from '../core/state.js';
import { validateLuhn } from '../core/luhn.js';
import { validateVerhoeff, generateVerhoeff } from '../core/verhoeff.js';
import { validateCandidate } from '../core/validators.js';

/**
 * @typedef {Object} SelfTestCase
 * @property {string} category
 * @property {string} name
 * @property {() => boolean | Promise<boolean>} run
 */

/**
 * Creates the complete test suite adhering to Section 9.
 * @returns {Array<SelfTestCase>}
 */
export function getSelfTestCases() {
  return [
    // ==========================================
    // 1. CREDIT CARDS
    // ==========================================
    {
      category: 'Credit Cards',
      name: 'Luhn Checksum Pass for Valid Card',
      run: () => {
        // Standard Visa test card passing Luhn
        const validVisa = '4532015112830366';
        return validateLuhn(validVisa) === true;
      }
    },
    {
      category: 'Credit Cards',
      name: 'Luhn Checksum Fail for Corrupted Card',
      run: () => {
        // Same card with corrupted last digit
        const invalidVisa = '4532015112830367';
        return validateLuhn(invalidVisa) === false;
      }
    },
    {
      category: 'Credit Cards',
      name: '13-Digit Valid Card Candidate Accepted',
      run: () => {
        // Valid 13-digit Visa card passing Luhn
        const card13 = '4012888888881';
        const p = new Pseudonymizer();
        const res = processText(`My card is ${card13} here`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.CREDIT_CARD;
      }
    },
    {
      category: 'Credit Cards',
      name: '19-Digit Valid Card Candidate Accepted',
      run: () => {
        // Build valid 19-digit Luhn card
        const base = '453201511283036600';
        let checkDigit = 0;
        for (let d = 0; d <= 9; d++) {
          if (validateLuhn(base + d)) {
            checkDigit = d;
            break;
          }
        }
        const card19 = base + checkDigit;
        const p = new Pseudonymizer();
        const res = processText(`Card: ${card19}`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.CREDIT_CARD;
      }
    },
    {
      category: 'Credit Cards',
      name: '12-Digit Numeric Sequence Rejected',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Value is 123456789012 end', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const cardFindings = res.findings.filter((f) => f.type === PiiType.CREDIT_CARD);
        return cardFindings.length === 0;
      }
    },
    {
      category: 'Credit Cards',
      name: '20-Digit Numeric Sequence Rejected',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Long number 12345678901234567890 end', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const cardFindings = res.findings.filter((f) => f.type === PiiType.CREDIT_CARD);
        return cardFindings.length === 0;
      }
    },
    {
      category: 'Credit Cards',
      name: 'Random 16-Digit Non-Luhn Sequence Rejected',
      run: () => {
        const random16 = '1234567812345678';
        const p = new Pseudonymizer();
        const res = processText(`Card candidate: ${random16}`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const cardFindings = res.findings.filter((f) => f.type === PiiType.CREDIT_CARD);
        const luhnRejection = res.rejectedCandidates.find(
          (r) => r.type === PiiType.CREDIT_CARD && r.status === ValidationStatus.REJECTED_LUHN
        );
        return cardFindings.length === 0 && Boolean(luhnRejection);
      }
    },
    {
      category: 'Credit Cards',
      name: 'Longer Embedded Number Rejection (Boundary)',
      run: () => {
        // Card digits embedded directly in alphanumeric token
        const p = new Pseudonymizer();
        const res = processText('TXN4532015112830366ID', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const cardFindings = res.findings.filter((f) => f.type === PiiType.CREDIT_CARD);
        return cardFindings.length === 0;
      }
    },

    // ==========================================
    // 2. PAN (INDIAN PERMANENT ACCOUNT NUMBER)
    // ==========================================
    {
      category: 'PAN',
      name: 'Valid Uppercase PAN Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('PAN is ABCDE1234F here', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.PAN;
      }
    },
    {
      category: 'PAN',
      name: 'Valid Lowercase PAN Normalized and Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('PAN is abcde1234f here', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].normalizedValue === 'ABCDE1234F';
      }
    },
    {
      category: 'PAN',
      name: 'Invalid PAN Structure Rejected',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Bad PAN: 12345ABCDE and ABC12345F', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type === PiiType.PAN).length === 0;
      }
    },
    {
      category: 'PAN',
      name: 'Longer Identifier Boundary Rejection',
      run: () => {
        const p = new Pseudonymizer();
        // 11 chars or alphanumeric prefix/suffix
        const res = processText('Code ABCDE1234F5 and 9ABCDE1234F and TXNABCDE1234F99', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type === PiiType.PAN).length === 0;
      }
    },

    // ==========================================
    // 3. IPV4
    // ==========================================
    {
      category: 'IPv4',
      name: 'Valid IPv4 Address Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Server at 192.168.1.1 is active', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.IPV4;
      }
    },
    {
      category: 'IPv4',
      name: 'Octet 255 Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Broadcast is 255.255.255.255', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.IPV4;
      }
    },
    {
      category: 'IPv4',
      name: 'Octet 256 Rejected',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Bad IP 256.1.1.1 and 192.168.1.999', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const ipFindings = res.findings.filter((f) => f.type === PiiType.IPV4);
        return ipFindings.length === 0;
      }
    },
    {
      category: 'IPv4',
      name: 'Missing or Extra Octet Rejected',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Subnet 1.2.3 and 1.2.3.4.5', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type === PiiType.IPV4).length === 0;
      }
    },
    {
      category: 'IPv4',
      name: 'Version String v1.2.3.4 Rejected by Policy',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('App v1.2.3.4 and version 10.20.30.40 and release-2.3.4.5', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        const ipFindings = res.findings.filter((f) => f.type === PiiType.IPV4);
        return ipFindings.length === 0;
      }
    },

    // ==========================================
    // 4. AADHAAR
    // ==========================================
    {
      category: 'Aadhaar',
      name: '12-Digit Verhoeff-Valid Aadhaar Accepted',
      run: () => {
        // Generate valid 12-digit Aadhaar using Verhoeff
        const base = '36759832451';
        const checksum = generateVerhoeff(base);
        const validAadhaar = `${base}${checksum}`;

        const p = new Pseudonymizer();
        const res = processText(`Aadhaar: ${validAadhaar}`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p,
          requireVerhoeff: true
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.AADHAAR;
      }
    },
    {
      category: 'Aadhaar',
      name: '11, 13, 14-Digit Numbers Rejected for Aadhaar',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Numbers: 36759832451 and 3675983245100 and 36759832451000', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type === PiiType.AADHAAR).length === 0;
      }
    },
    {
      category: 'Aadhaar',
      name: 'Card Overlap Handling (Priority to Credit Card)',
      run: () => {
        // 16-digit valid credit card must NOT be sliced into a 12-digit Aadhaar
        const validVisa = '4532015112830366';
        const p = new Pseudonymizer();
        const res = processText(`Payment with ${validVisa}`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return (
          res.findings.length === 1 &&
          res.findings[0].type === PiiType.CREDIT_CARD &&
          res.findings.filter((f) => f.type === PiiType.AADHAAR).length === 0
        );
      }
    },

    // ==========================================
    // 5. PHONES
    // ==========================================
    {
      category: 'Phone',
      name: 'Indian 10-Digit Mobile Candidate Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Call me at 9876543210 please', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.PHONE_IN;
      }
    },
    {
      category: 'Phone',
      name: 'Indian Phone with +91 or 0 Prefix Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Phones: +91 9876543210 and 09876543210', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type === PiiType.PHONE_IN).length === 2;
      }
    },
    {
      category: 'Phone',
      name: 'International E.164 Phone Candidate Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('US office: +1 415 555 2671 end', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.PHONE_INTL;
      }
    },
    {
      category: 'Phone',
      name: 'Date and Timestamp Rejection as Phone',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Dates: 2026-11-27 and 2026-11-27T10:42:50Z and 27/11/2026', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.filter((f) => f.type.startsWith('PHONE')).length === 0;
      }
    },

    // ==========================================
    // 6. EMAIL
    // ==========================================
    {
      category: 'Email',
      name: 'Valid Email Address Accepted',
      run: () => {
        const p = new Pseudonymizer();
        const res = processText('Contact user.name+tag@example.co.uk today', {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.EMAIL;
      }
    },
    {
      category: 'Email',
      name: 'Trailing Punctuation Trimmed from Email Span',
      run: () => {
        const text = 'Write to support@kavach.org, right now! (or admin@kavach.org).';
        const p = new Pseudonymizer();
        const res = processText(text, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        // Check that commas, exclamation marks, and parentheses are NOT in the finding spans
        const f1 = res.findings[0];
        const f2 = res.findings[1];
        return (
          f1.rawValue === 'support@kavach.org' &&
          f2.rawValue === 'admin@kavach.org' &&
          res.redactedText.includes(', right now!') &&
          res.redactedText.includes(').')
        );
      }
    },

    // ==========================================
    // 7. REDACTION & PSEUDONYMIZATION
    // ==========================================
    {
      category: 'Redaction',
      name: 'Full Mask Mode Replaces Entire Finding',
      run: () => {
        const text = 'User john@example.com logged in';
        const p = new Pseudonymizer();
        const res = processText(text, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.redactedText === 'User [REDACTED_EMAIL] logged in';
      }
    },
    {
      category: 'Redaction',
      name: 'Partial Mask Reveals Safe Portions Only',
      run: () => {
        const text = 'Email: contact@example.com and Card: 4532015112830366';
        const p = new Pseudonymizer();
        const res = processText(text, {
          redactionMode: RedactionMode.PARTIAL_MASK,
          pseudonymizer: p
        });
        return (
          res.redactedText.includes('co*****@example.com') &&
          res.redactedText.includes('************0366')
        );
      }
    },
    {
      category: 'Redaction',
      name: 'Consistent Pseudonymization Mapping',
      run: () => {
        const text = 'From alice@example.com to bob@test.com and back to alice@example.com';
        const p = new Pseudonymizer();
        const res = processText(text, {
          redactionMode: RedactionMode.PSEUDONYMIZE,
          pseudonymizer: p
        });
        // alice@example.com must get EMAIL_01 both times, bob gets EMAIL_02
        return (
          res.redactedText === 'From EMAIL_01 to EMAIL_02 and back to EMAIL_01'
        );
      }
    },
    {
      category: 'Redaction',
      name: 'Deterministic Overlap Resolution (No Double-Redaction)',
      run: () => {
        // Nested / adjacent test: 16-digit card must not also trigger 10-digit phone
        const text = 'Card 4532015112830366';
        const p = new Pseudonymizer();
        const res = processText(text, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });
        return res.findings.length === 1 && res.findings[0].type === PiiType.CREDIT_CARD;
      }
    },

    // ==========================================
    // 8. CSV INTEGRITY
    // ==========================================
    {
      category: 'CSV Integrity',
      name: 'RFC-4180 Quoted Commas & Escaped Quotes Round-Trip',
      run: () => {
        const originalCsv = 'ID,Notes,Status\r\n1,"Hello, ""World""",OK\r\n2,"Line 1\nLine 2",Active';
        const parsed = parseCsv(originalCsv);
        if (parsed.length !== 3) return false;
        if (parsed[1][1] !== 'Hello, "World"') return false;
        if (parsed[2][1] !== 'Line 1\nLine 2') return false;

        const serialized = serializeCsv(parsed, { sanitizeFormulas: false, lineEnding: '\r\n' });
        const reparsed = parseCsv(serialized);
        return (
          reparsed[1][1] === 'Hello, "World"' &&
          reparsed[2][1] === 'Line 1\nLine 2'
        );
      }
    },
    {
      category: 'CSV Integrity',
      name: 'Cell-Level Redaction Preserves Column Count',
      run: () => {
        const csv = 'Name,Email,IP\r\nAlice,alice@example.com,192.168.1.1\r\nBob,bob@example.com,10.0.0.1';
        const p = new Pseudonymizer();
        const res = processCsv(csv, {
          redactionMode: RedactionMode.PSEUDONYMIZE,
          pseudonymizer: p
        });
        const rows = parseCsv(res.redactedCsv);
        return (
          rows.length === 3 &&
          rows[0].length === 3 &&
          rows[1].length === 3 &&
          rows[1][1] === 'EMAIL_01' &&
          rows[1][2] === 'IPV4_01'
        );
      }
    },
    {
      category: 'CSV Integrity',
      name: 'CSV Formula Injection Sanitization Policy',
      run: () => {
        const evilCsv = 'Formula\r\n"=cmd|/c calc"!A0\r\n+123\r\n-456\r\n@SUM(1,2)';
        const p = new Pseudonymizer();
        const res = processCsv(evilCsv, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p,
          sanitizeFormulas: true
        });
        const parsed = parseCsv(res.redactedCsv);
        // Each dangerous cell must be safely prefixed with single quote '
        return (
          parsed[1][0].startsWith("'=") &&
          parsed[2][0].startsWith("'+") &&
          parsed[3][0].startsWith("'-") &&
          parsed[4][0].startsWith("'@")
        );
      }
    },

    // ==========================================
    // 9. PRIVACY, LOGS, AND XSS
    // ==========================================
    {
      category: 'Privacy & XSS',
      name: 'Raw PII Is Never Recorded in Activity Logs',
      run: () => {
        logger.clear();
        const sensitiveEmail = 'super_secret_pii@privatecorp.internal';
        const p = new Pseudonymizer();
        processText(`Confidential: ${sensitiveEmail}`, {
          redactionMode: RedactionMode.FULL_MASK,
          pseudonymizer: p
        });

        const logs = logger.getLogs();
        const exportedJson = logger.exportJson();

        // Ensure sensitive string never appears anywhere in log objects or serialized logs
        return (
          !exportedJson.includes(sensitiveEmail) &&
          !exportedJson.includes('super_secret_pii') &&
          logs.every((l) => !JSON.stringify(l).includes(sensitiveEmail))
        );
      }
    },
    {
      category: 'Privacy & XSS',
      name: 'XSS Injection Payloads Render Completely Inert',
      run: () => {
        const evilPayloads = [
          '<script>alert(1)</script>',
          '<img src=x onerror=alert(1)>',
          '<svg onload=alert(1)>',
          '"><script>alert(document.cookie)</script>'
        ];

        for (const payload of evilPayloads) {
          const escaped = escapeHtml(payload);
          // Must not contain unescaped < or >
          if (escaped.includes('<') || escaped.includes('>') || escaped.includes('"')) {
            return false;
          }
        }
        return true;
      }
    },
    {
      category: 'Privacy & XSS',
      name: 'Reset Clears All Transient State and Token Maps',
      run: () => {
        const p = stateManager.pseudonymizer;
        p.getToken(PiiType.EMAIL, 'user@example.com');
        if (p.tokenMap.size === 0) return false;

        stateManager.reset();
        // After reset, tokenMap and buffers must be empty
        return (
          stateManager.pseudonymizer.tokenMap.size === 0 &&
          stateManager.rawSourceText === '' &&
          stateManager.redactedText === ''
        );
      }
    }
  ];
}
