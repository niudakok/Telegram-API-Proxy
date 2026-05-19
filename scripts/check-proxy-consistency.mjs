import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

execSync('node scripts/sync-admin-html.mjs', { stdio: 'inherit' });

const worker = readFileSync('manual-worker/worker.js', 'utf8');
const blocks = (worker.match(/const ADMIN_HTML = `/g) || []).length;
if (blocks !== 1) throw new Error(`Expected exactly one ADMIN_HTML block, found ${blocks}`);
if (!worker.includes('SETWEBHOOK_STRIP_PROXY_URL')) throw new Error('Missing SETWEBHOOK_STRIP_PROXY_URL switch');
if (!worker.includes('stats.successfulRequests++')) throw new Error('successfulRequests not tracked');

console.log('Proxy consistency checks passed');
