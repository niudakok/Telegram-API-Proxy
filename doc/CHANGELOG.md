# 版本更新记录

## v7.1.0-dev (2026-07-17)

当前开发版本，基于 `dev` 分支。

### 修复

- **文件下载路径双重 `/file/bot`** — `getTelegramFileBaseUrl` 返回的 baseUrl 已含 `/file/bot`，但拼接处又加了一次，导致 URL 变为 `.../file/bot/file/botTOKEN/FILEID`。修复后与 `api.js` 保持一致。
- **ADMIN_HTML 模板字符串截断** — `sync-admin-html.mjs` 用 `indexOf` 查找 `` `; `` 结束标记，但 admin.html 中 JS 模板字面量也包含 `\`;`，导致截断错误。改用 `lastIndexOf` 修复。
- **`wrangler.toml` `main` 指向错误** — 指向 `functions/api/api.js`（Pages Functions 格式 `export { onRequest as default }`），Worker 运行时无法识别，导致 HTTP 522。改回 `manual-worker/worker.js`（Worker 原生格式 `export default { fetch(...) }`）。
- **`sync-admin-html.mjs` 重复行** — 删除了被覆盖的重复 `const html` 和 `const next` 声明。
- **token URL 编码导致文件下载 401** — `python-telegram-bot` 库的 `File._get_encoded_url()` 会将 `:` 编码为 `%3A`，代理解析 token 时拿到的是编码后的字符串，与白名单不匹配导致 401。`parseFileRequest` 中添加 `decodeURIComponent()` 修复。

### 新增

- **VERSION 常量** — `manual-worker/worker.js` 添加 `VERSION` 对象，`/stats` 端点返回版本信息。
- **`/ping` 端点** — 测试 Telegram API 连通性，绕过白名单验证。
- **`AGENTS.md`** — 项目指令文件，帮助 AI 代理理解代码库。

### 已知问题

- GitHub 自动构建失败，需通过 Cloudflare Dashboard 手动部署。
- `functions/api/api.js` 使用 Pages Functions 格式，不兼容 Worker 运行时。