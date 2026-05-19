import { readFileSync, writeFileSync } from 'node:fs';

const ADMIN_HTML_PATH = 'admin.html';
const WORKER_PATH = 'manual-worker/worker.js';

const html = readFileSync(ADMIN_HTML_PATH, 'utf8').trimEnd();
const worker = readFileSync(WORKER_PATH, 'utf8');

const escaped = html
  .replace(/\\/g, '\\\\')
  .replace(/`/g, '\\`')
  .replace(/\$\{/g, '\\${');

const pattern = /const ADMIN_HTML = `([\s\S]*?)`;/;
if (!pattern.test(worker)) {
  throw new Error('Cannot find `const ADMIN_HTML = `...`;` block in manual-worker/worker.js');
}

const next = worker.replace(pattern, `const ADMIN_HTML = \`\n${escaped}\n\`;`);

if (next !== worker) {
  writeFileSync(WORKER_PATH, next, 'utf8');
  console.log('Synced manual-worker/worker.js ADMIN_HTML from admin.html');
} else {
  console.log('Already in sync');
}
