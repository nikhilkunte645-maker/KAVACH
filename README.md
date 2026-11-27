# KAVACH — 100% Client-Side PII Redactor & Privacy Engine

> **KAVACH** is a zero-leak, deterministic client-side privacy engine engineered to detect, validate, redact, pseudonymize, compare, log, and export sensitive personally identifiable information (PII) from raw text, `.txt`, and `.csv` files entirely in local browser memory.

---

## Key Security & Privacy Guarantees

1. **Zero-Leak Client-Side Execution:**
   - All processing executes exclusively in local browser RAM.
   - Zero outbound requests: no `fetch()`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `navigator.sendBeacon()`, or third-party CDNs.
   - Works 100% offline.
2. **Zero Persistent Storage:**
   - Never writes sensitive data or raw PII to `localStorage`, `sessionStorage`, `IndexedDB`, cookies, or browser history.
   - Immediate full transient state wiping on reset.
3. **Deterministic Mathematical Validation:**
   - **Credit Cards:** 13–19 digits, boundary checks against longer numbers, strict ISO/IEC 7812-1 modulus 10 Luhn checksum validation.
   - **Indian PAN:** Case-insensitive `[A-Z]{5}[0-9]{4}[A-Z]` format with strict left and right word boundary isolation.
   - **IPv4 Addresses:** Strict 4-octet bounds [0, 255] and software version string rejection policy (e.g., `v1.2.3.4`, `release-2.3.4.5`).
   - **Indian Aadhaar:** 12-digit candidate validation with Dihedral Group D5 Verhoeff checksum algorithm.
   - **Indian Mobile:** 10-digit mobile detection with `+91` / `0` prefix normalization, date & timestamp rejection.
   - **International Phone:** E.164-compatible length and token rules.
   - **Email:** RFC 5322 syntax validation with automated trailing punctuation trimming.
4. **Deterministic Overlap Resolution:**
   - Sorted by `start` ascending, span length descending, and deterministic priority tie-breaking.
   - Half-open intervals `[start, end)` guarantee that no character is ever double-redacted.
5. **RFC-4180 CSV Engine & Injection Defense:**
   - State-machine parser supporting quoted commas, escaped quotes (`""`), and embedded newlines.
   - CSV formula injection shield prefixes dangerous leading `=, +, -, @, \t, \r` with `'`.
6. **XSS & HTML Injection Defense:**
   - Zero unsafe `innerHTML` usage with untrusted strings. All diffs rendered via safe DOM text nodes.
7. **Privacy-Safe Activity Logs:**
   - Only operational metadata (timestamp, operation type, category, counts, status) is stored or exported. Zero raw PII in logs or console.
8. **Built-In Self-Test Runner:**
   - Interactive browser UI runner and terminal CLI runner (`npm run test:self`) executing 36 automated test cases against production code.

---

## Project Structure

```
c:\Users\lucifer\Downloads\KAVACH\
  ├── index.html                  # Standalone client-side web application
  ├── style.css                   # Cyber-defense dark mode UI styling
  ├── tsconfig.json               # TypeScript configuration for strict type checking
  ├── package.json                # Project configuration, test scripts, build script
  ├── .gitignore                  # Git ignore rules
  ├── src/
  │   ├── core/
  │   │   ├── types.js            # PII types, priorities, and interfaces
  │   │   ├── luhn.js             # Luhn modulus 10 checksum algorithm
  │   │   ├── verhoeff.js         # Verhoeff D5 checksum algorithm
  │   │   ├── detectors.js        # Deterministic candidate boundary detectors
  │   │   ├── validators.js       # Strict candidate validators
  │   │   ├── overlap.js          # Half-open interval overlap resolver
  │   │   ├── redactor.js         # Full mask, partial mask, consistent pseudonymizer
  │   │   ├── csv-parser.js       # RFC-4180 parser, serializer & formula shield
  │   │   ├── diff.js             # Safe text diff generator & XSS-inert DOM renderer
  │   │   ├── logger.js           # Privacy-safe operational logger (zero raw PII)
  │   │   ├── state.js            # Transient in-memory state manager
  │   │   └── engine.js           # Main processing engine orchestrator
  │   ├── self-test/
  │   │   ├── test-cases.js       # Production test cases covering Section 9 spec
  │   │   └── runner.js           # Self-test runner module
  │   └── app.js                  # Main UI controller & DOM event handling
  ├── test/
  │   ├── unit.test.js            # Node:test unit test suite
  │   ├── csv.test.js             # RFC-4180 CSV and formula injection test suite
  │   ├── privacy-audit.js        # Static privacy & zero-leak network scanner
  │   └── cli-runner.js           # CLI self-test execution wrapper
  └── scripts/
      └── build.js                # Production asset validator & dist builder
```

---

## Verification & Execution Commands

```bash
# 1. Run all unit tests (node:test)
npm test

# 2. Run built-in self-test suite (36 production tests)
npm run test:self

# 3. Run TypeScript static type checking
npm run typecheck

# 4. Run automated privacy and zero-leak network audit
npm run lint:privacy

# 5. Run full verification pipeline (typecheck + test + test:self + lint:privacy)
npm run verify

# 6. Build production distribution
npm run build
```

---

## Launching KAVACH

Because KAVACH contains zero external runtime dependencies and is 100% client-side, you can open `index.html` directly in any modern web browser or serve locally with any static HTTP server:

```bash
# Example with Node.js http-server or npx serve:
npx serve .
# Or simply double click / open index.html in Chrome, Edge, Firefox, or Safari!
```
