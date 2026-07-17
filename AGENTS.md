# AGENTS.md — Telegram API Proxy

## Build & Test

- **No build step** (Cloudflare Pages deploys raw files). Only `npm install` to pull wrangler.
- **Local dev**: `npx wrangler pages dev .` (Pages, port 8788) or `npx wrangler dev manual-worker/worker.js` (Worker, port 8787).
- **Mock Telegram**: `node scripts/mock-telegram-server.mjs` (port 9001). Set `TELEGRAM_API_BASE=http://localhost:9001` in `.dev.vars`.
- **Testing**: manual curl against mock server (see TESTING.md). No test runner exists.
- **Consistency checks**: `node scripts/check-proxy-consistency.mjs` — run before commit.

## Architecture

Two co-existing codebases in one repo:

| Aspect | Pages (`functions/api/api.js`) | Worker (`manual-worker/worker.js`) |
|--------|-------------------------------|-----------------------------------|
| Export | `export { onRequest as default }` | `export default { fetch(request, env, ctx) }` |
| URL prefix | `/api/bot<TOKEN>/<METHOD>` | `/bot<TOKEN>/<METHOD>` |
| Features | circuit breaker, 3-tier rate limiting, caching, suspicious IP tracking | basic rate limiting, no circuit breaker |
| Token validation | stricter: botId >= 8 digits, hash >= 30 chars, total >= 40 | minimal: total >= 30 chars |

## Recent History (from DEVLOG.md)

The repo was previously worked on by another agent who fixed several issues:

- **`[[path]].js` → `api.js` rename** — Cloudflare's build system chokes on `[[` in filenames. The Pages entry was renamed from `functions/api/[[path]].js` to `functions/api/api.js` (commit `d7fed24`).
- **File download path fix** — Telegram file URLs require `/file/` prefix: `https://api.telegram.org/file/bot{token}/{file_path}`. Old code omitted it, causing 401 InvalidToken on image downloads (commit `b281317`).
- **ES Module default export** — Added `export { onRequest as default }` for Cloudflare Pages Functions compatibility (commit `42dca91`).
- **`/ping` endpoint** — Added for testing Telegram API connectivity (commit `0cdb496`).
- **Known issue: GitHub auto-deploy fails** — Cloudflare's API rejects the Service Worker syntax. The agent couldn't fix it; manual deploy via Dashboard is needed.

**Current production state**: `manual-worker/worker.js` (old version) is running at `tgapi.indevs.in`. The fixed `api.js` has **not** been deployed.

## Critical Gotchas

1. **admin.html → Worker sync**: `admin.html` is the source of truth for the admin panel. After editing it, run `node scripts/sync-admin-html.mjs` to embed it into `worker.js` as `ADMIN_HTML`. The sync script has a **bug**: line 8 (`const html = ...`) is duplicated with different logic (one replaces `__COMMIT_HASH__`, the other does `.trimEnd()` only). Check this before relying on the output.
2. **`.dev.vars` is gitignored** — create it manually with `ALLOWED_BOT_TOKENS`, `ADMIN_PASSWORD`, `TELEGRAM_API_BASE`. wrangler does NOT inherit shell env vars.
3. **Kill `workerd`, not `wrangler`**: `killall -9 workerd` to free ports. wrangler spawns a workerd subprocess that survives `killall wrangler`.
4. **Path traversal detection**: `new URL(request.url)` normalizes `../` away. Check the raw `request.url` string instead. Use `%2e%2e%2f` (encoded form) in test payloads.
5. **Version info is dual-maintained**: in `version.json` AND as a `VERSION` constant at the top of `api.js` (line 3). Keep both in sync.
6. **Pages vs Worker token validation differs** — a token that works in Worker mode may fail in Pages mode. The test token `1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X` (41 chars) satisfies both.
7. **`wrangler.toml` `main` field** must point to `manual-worker/worker.js` for Workers deployments. The `functions/api/api.js` uses `export { onRequest as default }` (Pages Functions format), which is **incompatible** with Workers — Workers expect `export default { fetch(...) }`. Setting `main` to `api.js` will cause the Worker to fail with HTTP 522.