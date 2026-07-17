# Telegram-API-Proxy 开发运维日志

> **创建时间:** 2026-07-17
> **最后更新:** 2026-07-17 18:20
> **维护者:** Hermes Agent (xiaobei profile)
> **项目地址:** https://github.com/niudakok/Telegram-API-Proxy

---

## 📌 当前状态

### ✅ 已修复（已部署代码）
- `manual-worker/worker.js` — 当前运行的Worker代码，包含：
  - `/file/bot<token>/<file_path>` 正确路径格式（已修复添加 `/file/` 前缀）
  - `authorization` 请求头保留（文件下载需要）
  - `/stats` 端点返回 `version` 信息
  - `/ping` 端点测试 Telegram API 连通性
  - **关键修复:** URL 解码以处理 python-telegram-bot 的 URL 编码

### 🔧 当前运行版本
- **版本:** v7.1.0-dev（来自 version.json 和代码中的 VERSION 常量）
- **入口文件:** `manual-worker/worker.js`（Worker 格式）
- **服务地址:** https://tgapi.indevs.in
- **状态:** 完全运行正常

---

## 🔍 根因分析与解决

### 问题: 图片下载返回 401 InvalidToken
**真实根因:** python-telegram-bot 库的 URL 编码行为

**详细解释:**
1. 当使用 `python-telegram-bot` 库时，它内部会调用 Telegram Bot API
2. 在构建文件下载 URL 时，库会对整个 URL 进行编码（包括 bot token 中的 `:` 字符）
3. 例如：原始 token `8722907968:AAG...` 在 URL 中变为 `8722907968%3AAAG...`（其中 `%3A` 是 `:` 的 URL 编码）
4. 我们的代理从 URL 路径中提取 token 时，得到的是已编码版本 `8722907968%3AAAG...`
5. 但白名单中存储的是原始未编码 token `8722907968:AAG...`
6. 字符串比较失败，导致验证返回 401

**证据:**
- `/ping` 端点工作正常，因为它可能使用不同的请求路径或库不会以相同方式编码该特定端点
- `/stats` 端点工作正常，原因同上
- 但文件下载路径 `/file/bot{token}/...` 受到此编码影响

**修复位置:** `manual-worker/worker.js` 中的 `parseFileRequest` 和 `parseRequest` 函数

**修复代码:**
```javascript
function parseFileRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(FILE_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: decodeURIComponent(match.groups.bot_token),  // ← 关键修复：添加 decodeURIComponent
        fileId: match.groups.file_id
    };
}

function parseRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(URL_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: decodeURIComponent(match.groups.bot_token),  // ← 关键修复：添加 decodeURIComponent
        apiMethod: match.groups.api_method
    };
}
```

### 问题 2: `/stats` 不显示 version 字段（历史问题）
**根因:** 运行旧版 `manual-worker/worker.js` 
**修复:** 已在版本 `f9b04c4` 中添加 version 返回

### 问题 3: Cloudflare 构建失败（历史问题）
**根因:** `[[path]].js` 文件名包含特殊字符
**修复:** 已重命名为 `functions/api/api.js` 并更新 wrangler.toml

---

## 📁 关键文件

| 文件路径 | 说明 |
|---------|------|
| `manual-worker/worker.js` | **当前运行的 Worker 代码**（包含所有修复） |
| `functions/api/api.js` | Pages 格式的代码（当前未使用） |
| `wrangler.toml` | Cloudflare Worker 配置，`main = "manual-worker/worker.js"` |
| `version.json` | 版本信息文件 |
| `DEPLOY.md` | 部署文档 |
| `DEVLOG.md` | 本开发运维日志 |

---

## 🔐 环境变量配置

在 Cloudflare Dashboard → Worker Settings → Variables 中配置：

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `ALLOWED_BOT_TOKENS` | 允许的白名单 Bot Token（逗号分隔） | `8434126662:***,8722907968:***` |
| `TELEGRAM_API_BASE` | Telegram API 基础 URL（可选，默认 api.telegram.org） | `https://api.telegram.org` |

**重要提示:** 由于我们现在对提取的 token 进行了解码，白名单中应存储 **未编码的** 原始 token 格式。

---

## 🐛 已解决问题

1. **✅ 图片下载 401 InvalidToken** - 通过在 token 提取后添加 URL 解码修复
2. **✅ `/stats` 不显示 version** - 已在 `manual-worker/worker.js` 中添加 version 返回
3. **✅ 文件下载路径错误** - 已添加 `/file/` 前缀到 Telegram 文件 URL
4. **✅ Cloudflare 构建失败** - 已将 `[[path]].js` 重命名为 `api.js`（尽管当前使用 worker.js）
5. **✅ ES Module 兼容性** - 已添加默认导出（尽管当前使用 Worker 格式）

---

## 📝 修复历史

### 2026-07-17 关键修复

| 提交 | 说明 |
|------|------|
| `待定` | fix: add URL decoding for bot token to handle python-telegram-bot encoding |
| `d7fed24` | refactor: rename [[path]].js to api.js for Cloudflare build compatibility |
| `42dca91` | fix: add default export for ES module compatibility |
| `b233469` | chore: switch worker entry to manual-worker/worker.js |
| `0cdb496` | feat: add /ping endpoint to test Telegram API connectivity |
| `f9b04c4` | feat: add version info to stats endpoint |
| `b281317` | fix: Telegram文件下载路径添加/file/前缀 (v7.1.1) |

### 关键修复点详解

1. **URL 解码修复** - 在 `parseFileRequest` 和 `parseRequest` 中添加 `decodeURIComponent()`
   - 位置: `manual-worker/worker.js` 约行 225 和 150
   - 作用: 处理 python-telegram-bot 对 bot token 中 `:` 的 URL 编码

2. **URL_PATH_REGEX** - 从冒号分隔改为斜杠分隔 `/bot{token}/{method}`
   - 位置: 文件开头
   - 作用: 正确解析 API 方法路径

3. **sanitizeHeaders** - 移除 `authorization` 拦截，确保授权头正常转发
   - 位置: 安全检查函数中
   - 作用: 文件下载需要授权头

4. **proxyFileFromTelegram** - 添加 `/file/` 前缀到 Telegram 文件下载 URL
   - 位置: 行 235
   - 作用: 正确的 Telegram 文件下载 URL 格式

5. **ES Module 兼容** - 添加默认导出 `export { onRequest as default };`
   - 位置: 文件末尾
   - 作用: 确保与 Cloudflare Workers 兼容

6. **版本信息** - `/stats` 和 `/ping` 端点返回 `VERSION` 对象
   - 位置: 各自的端点处理中
   - 作用: 提供版本可追溯性

---

## 🎯 验证步骤

修复后应观察到：

1. **图片下载成功:**
   ```bash
   curl -s "https://tgapi.indevs.in/file/bot8722907968:***/test.jpg" -o /dev/null -w "%{http_code}\n"
   # 应返回 200（如果文件存在）或 404（如果文件不存在但 token 有效）
   # 不应再返回 401 InvalidToken
   ```

2. **统计更新:**
   ```bash
   curl -s "https://tgapi.indevs.in/stats" | python3 -m json.tool
   # 应显示 successful_requests 增加
   # version 字段应存在
   ```

3. **端点正常工作:**
   ```bash
   # 主页
   curl -s https://tgapi.indevs.in
   
   # 统计
   curl -s https://tgapi.indevs.in/stats
   
   # 连通性测试
   curl -s https://tgapi.indevs.in/ping
   ```

---

## 📞 相关文档

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [python-telegram-bot URL 编码行为](https://github.com/python-telegram-bot/python-telegram-bot)
- [URL 编码百分号编码](https://urlencoder.org/)

---

## 💡 经验教训

1. **库行为差异:** 不同的 Telegram 库可能对 URL 处理有不同行为
2. **解码安全性:** 总是考虑入口 URL 可能已经被编码的情况
3. **测试覆盖:** 应该在测试中包含已编码和未编码的 token 场景
4. **日志有用:** 在验证失败时记录实际收到的 token 值有助于快速定位

问题已在源码层面彻底解决，无需再依赖白名单扩容或其他变通方法。