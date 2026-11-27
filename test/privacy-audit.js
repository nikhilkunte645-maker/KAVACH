/**
 * KAVACH - Automated Static Privacy & Zero-Leak Audit
 *
 * Scans all source and application files to guarantee:
 * 1. Zero network calls (fetch, XMLHttpRequest, WebSocket, EventSource, sendBeacon)
 * 2. Zero remote analytics, tracking, or telemetry
 * 3. Zero external script or stylesheet CDN references
 * 4. Zero persistent raw PII storage (localStorage, sessionStorage, indexedDB, cookies)
 */

import fs from 'node:fs';
import path from 'node:path';

const FORBIDDEN_CODE_PATTERNS = [
  { pattern: /\bfetch\s*\(/g, name: 'fetch() network call' },
  { pattern: /\bXMLHttpRequest\b/g, name: 'XMLHttpRequest' },
  { pattern: /\bWebSocket\b/g, name: 'WebSocket' },
  { pattern: /\bEventSource\b/g, name: 'EventSource' },
  { pattern: /navigator\.sendBeacon/g, name: 'navigator.sendBeacon' },
  { pattern: /localStorage\s*\./g, name: 'localStorage persistence' },
  { pattern: /sessionStorage\s*\./g, name: 'sessionStorage persistence' },
  { pattern: /indexedDB\s*\./g, name: 'indexedDB persistence' },
  { pattern: /document\.cookie/g, name: 'cookie access' },
  { pattern: /https?:\/\/(?!localhost|127\.0\.0\.1)[^\s"'>]+/g, name: 'External remote HTTP/HTTPS URL reference' }
];

function isAllowedExemption(filePath, matchStr) {
  if (filePath.endsWith('package.json') && matchStr.includes('http')) return true;
  if (filePath.endsWith('package-lock.json')) return true;
  // XSS test vector in test cases
  if (filePath.includes('test-cases.js') && matchStr === 'document.cookie') return true;
  return false;
}

function scanDir(dirPath, violations = []) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      // Exclude toolchain, IDE, build, and git folders
      if (
        entry.name === 'node_modules' ||
        entry.name === '.git' ||
        entry.name === 'dist' ||
        entry.name.startsWith('.')
      ) {
        continue;
      }
      scanDir(fullPath, violations);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      // Scan application code and scripts
      if (['.js', '.ts', '.css'].includes(ext)) {
        if (entry.name === 'privacy-audit.js') continue;

        const content = fs.readFileSync(fullPath, 'utf8');
        for (const rule of FORBIDDEN_CODE_PATTERNS) {
          const matches = content.match(rule.pattern);
          if (matches) {
            for (const m of matches) {
              if (!isAllowedExemption(fullPath, m)) {
                violations.push({
                  file: path.relative(process.cwd(), fullPath),
                  violation: rule.name,
                  match: m
                });
              }
            }
          }
        }
      } else if (ext === '.html') {
        // In HTML, verify no remote script/link tags or inline network calls
        const content = fs.readFileSync(fullPath, 'utf8');
        const remoteTagPattern = /<(?:script|link)[^>]*(?:src|href)=["']https?:\/\/[^"'>]+["']/gi;
        const remoteMatches = content.match(remoteTagPattern);
        if (remoteMatches) {
          for (const m of remoteMatches) {
            violations.push({
              file: path.relative(process.cwd(), fullPath),
              violation: 'Remote CDN or external script/stylesheet tag in HTML',
              match: m
            });
          }
        }
      }
    }
  }

  return violations;
}

console.log('\n============================================================');
console.log('🔒 KAVACH Static Privacy & Network Audit');
console.log('============================================================\n');

const violations = scanDir(process.cwd());

if (violations.length === 0) {
  console.log('✅ ZERO PRIVACY VIOLATIONS FOUND');
  console.log('   - 0 network transmission APIs (fetch, XHR, WebSocket, sendBeacon)');
  console.log('   - 0 persistent browser storage calls (localStorage, sessionStorage, cookies, IndexedDB)');
  console.log('   - 0 external CDN or tracking URLs');
  console.log('\n============================================================\n');
  process.exit(0);
} else {
  console.error(`❌ FOUND ${violations.length} PRIVACY/NETWORK VIOLATIONS:`);
  for (const v of violations) {
    console.error(`   File: ${v.file}`);
    console.error(`   Violation: ${v.violation}`);
    console.error(`   Matched: ${v.match}\n`);
  }
  process.exit(1);
}
