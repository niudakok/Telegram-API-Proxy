import { readFileSync, writeFileSync } from 'node:fs';

const ADMIN_HTML_PATH = 'admin.html';
const WORKER_PATH = 'manual-worker/worker.js';

const html = readFileSync(ADMIN_HTML_PATH, 'utf8').trimEnd();
const worker = readFileSync(WORKER_PATH, 'utf8');

const escaped = html
  .replace(/\\/g, '\\\\')
  .replace(/`/g, '\\`')
  .replace(/\$\{/g, '\\${');

const startMarker = 'const ADMIN_HTML = `';
const start = worker.indexOf(startMarker);
if (start === -1) {
  throw new Error('Cannot find `const ADMIN_HTML = ` in manual-worker/worker.js');
}
const end = worker.indexOf('`;', start);
if (end === -1) {
  throw new Error('Cannot find end of ADMIN_HTML template (`;) in manual-worker/worker.js');
}

const next = `${worker.slice(0, start)}const ADMIN_HTML = \`\n${escaped}\n\`;${worker.slice(end + 2)}`;

if (next !== worker) {
  writeFileSync(WORKER_PATH, next, 'utf8');
  console.log('Synced manual-worker/worker.js ADMIN_HTML from admin.html');
} else {
  console.log('Already in sync');
}

const adminHtmlCount = (next.match(/const ADMIN_HTML = `/g) || []).length;
if (adminHtmlCount !== 1) {
  throw new Error(`Expected exactly one ADMIN_HTML block, found ${adminHtmlCount}`);
}
