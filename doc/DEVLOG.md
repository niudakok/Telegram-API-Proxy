# Telegram-API-Proxy 开发运维日志

> **创建时间:** 2026-07-17
> **最后更新:** 2026-07-17 18:30
> **维护者:** Hermes Agent (xiaobei profile) → AtomCode
> **项目地址:** https://github.com/niudakok/Telegram-API-Proxy

---

## 📌 当前状态

### ✅ 已修复（dev 分支，已部署）
- `manual-worker/worker.js` — 修复后的 Worker 版代理代码，包含：
  - VERSION 常量（`/stats` 返回版本信息）
  - `/ping` 端点测试 Telegram API 连通性
  - `/file/bot<token>/<file_path>` 正确路径格式（无重复 `/file/bot`）
- `AGENTS.md` — 新增项目指令文件
- 已知问题：`wrangler.toml` `main` 需指向 `manual-worker/worker.js`（Worker 兼容格式），`api.js` 的 Pages Functions 格式不兼容 Worker 运行时

### ❌ 未修复
- GitHub 自动构建流程问题（Cloudflare Dashboard 手动部署可用）

### 🔧 当前运行版本
- **版本:** v7.1.0-dev（commit `f92b52c`）
- **入口文件:** `manual-worker/worker.js`（包含 VERSION、/ping、文件下载修复）
- **服务地址:** https://tgapi.indevs.in
- **部署方式:** Cloudflare Dashboard 手动部署（dev 分支）

---

## 🔍 核心问题分析

### 问题 1: `/stats` 不显示 version 字段

**根因:** 当前运行的 Worker 是旧版 `manual-worker/worker.js`，代码中没有 `version` 字段返回逻辑。

**修复代码位置:** `functions/api/api.js` 第 202-213 行
```javascript
// 状态端点
if (rawPathName.endsWith('/stats')) {
    return new Response(JSON.stringify({
        ...requestStats,
        version: VERSION  // VERSION 定义在第3行
    }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}
```

**VERSION 定义（第3行）:**
```javascript
const VERSION = { major: 7, minor: 1, patch: 0, build: '20260717', tag: 'dev' };
```

### 问题 2: 图片下载报 InvalidToken

**根因:** 旧版代码中文件下载路径构造错误：
- 错误: `https://api.telegram.org/bot{token}/{file_path}`
- 正确: `https://api.telegram.org/file/bot{token}/{file_path}` （必须有 `/file/` 前缀）

**修复代码位置:** `functions/api/api.js` 第 164-172 行
```javascript
async function proxyFileFromTelegram(fileInfo, env) {
    const baseUrl = getTelegramFileBaseUrl(env);
    // Telegram 文件下载路径：https://api.telegram.org/file/bot{token}/{file_path}
    const fileUrl = `${baseUrl}/file/bot${fileInfo.botToken}/${fileInfo.fileId}`;
    
    const response = await fetch(fileUrl, {
        method: 'GET',
        headers: { 'Authorization': `Bot ${fileInfo.botToken}` }
    });
    // ...
}
```

### 问题 3: Cloudflare 构建失败

**根因:** `main = "functions/api/[[path]].js"` 文件名包含特殊字符 `[[path]]`，Cloudflare 构建系统处理异常。

**修复:** 已重命名为 `functions/api/api.js`，wrangler.toml 已更新：
```
main = "functions/api/api.js"
```

---

## 🚀 部署指南

### 方式 1: Cloudflare Dashboard 手动部署（推荐）

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **Workers & Pages** → 选择 `tap` Worker
3. 点击 **Edit Code** 或 **Quick Edit**
4. 复制 `functions/api/api.js` 的全部内容粘贴进去
5. 点击 **Save and Deploy**

### 方式 2: GitHub 自动部署

**问题:** 当前 GitHub 集成构建失败，需要排查。

**待解决:**
1. 确认 GitHub 仓库已绑定到 Cloudflare
2. 检查 `wrangler.toml` 的 `main` 路径是否正确
3. 可能需要调整 `package.json` 或添加构建脚本

### 方式 3: 手动 wrangler 部署

```bash
cd /home/llm/Telegram-API-Proxy
npx wrangler login  # 首次需要登录
npx wrangler versions upload  # 上传新版本
```

---

## 🧪 测试流程

### 测试 1: 检查 /stats 是否返回 version

```bash
curl -s https://tgapi.indevs.in/stats | python3 -m json.tool
```

**预期输出:**
```json
{
    "startTime": 0,
    "totalRequests": 0,
    "successfulRequests": 0,
    "failedRequests": 0,
    "rateLimited": 0,
    "blocked": 0,
    "retries": 0,
    "avgResponseTime": 0,
    "lastReset": 0,
    "version": {
        "major": 7,
        "minor": 1,
        "patch": 0,
        "build": "20260717",
        "tag": "dev"
    }
}
```

### 测试 2: 检查 /ping 端点

```bash
curl -s https://tgapi.indevs.in/ping | python3 -m json.tool
```

**预期输出:**
```json
{
    "version": { ... },
    "allowedTokensConfigured": true/false,
    "testUrl": "https://api.telegram.org/bot...",
    "upstreamStatus": 200,
    "telegramApiAccessible": true
}
```

### 测试 3: Telegram 图片下载

1. 通过 Telegram 向 Bot 发送一张图片
2. 检查返回的 `base_file_url` 是否指向 `https://tgapi.indevs.in/file/bot{token}/...`
3. 访问该 URL，应该能成功下载图片（不再报 401 InvalidToken）
4. 检查 `/stats` 计数是否增加

---

## 📁 关键文件

| 文件路径 | 说明 |
|---------|------|
| `functions/api/api.js` | **修复后的代理代码**（包含所有修复） |
| `manual-worker/worker.js` | 旧版代码（当前运行的版本） |
| `wrangler.toml` | Cloudflare Worker 配置，`main` 指向 `functions/api/api.js` |
| `version.json` | 版本信息文件 |
| `DEPLOY.md` | 部署文档 |

---

## 🔐 环境变量配置

在 Cloudflare Dashboard → Worker Settings → Variables 中配置：

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `ALLOWED_BOT_TOKENS` | 允许的白名单 Bot Token（逗号分隔） | `8434126662:xxx,8722907968:xxx` |
| `TELEGRAM_API_BASE` | Telegram API 基础 URL（可选，默认 api.telegram.org） | `https://api.telegram.org` |

---

## 🐛 已知问题

1. **GitHub 自动构建失败** — 需要在 Cloudflare Dashboard 手动部署
2. **`functions/api/api.js` 未用于 Worker 部署** — 该文件使用 Pages Functions 格式（`export { onRequest as default }`），不兼容 Worker 运行时。如需使用 Pages 部署需调整配置

---

## 📝 开发记录

### 2026-07-17 关键修改

| 提交 | 说明 | 作者 |
|------|------|------|
| `d7fed24` | refactor: rename [[path]].js to api.js for Cloudflare build compatibility | Hermes |
| `42dca91` | fix: add default export for ES module compatibility | Hermes |
| `b233469` | chore: switch worker entry to functions/api/api.js | Hermes |
| `0cdb496` | feat: add /ping endpoint to test Telegram API connectivity | Hermes |
| `f9b04c4` | feat: add version info to stats endpoint | Hermes |
| `b281317` | fix: Telegram文件下载路径添加/file/前缀 (v7.1.1) | Hermes |
| `7e06d0d` | fix: 修复 sync-admin-html.mjs 重复行，添加 VERSION 和 /ping 到 worker.js | AtomCode |
| `c84b47c` | fix: wrangler.toml main 指向 manual-worker/worker.js 修复 522 错误 | AtomCode |
| `61f7fea` | fix: sync-admin-html.mjs 用 lastIndexOf 替代 indexOf 查找 ADMIN_HTML 结尾 | AtomCode |
| `f92b52c` | fix: getTelegramFileBaseUrl 去掉重复的 /file/bot | AtomCode |
| `47ea2da` | fix: parseFileRequest 对 bot_token 做 URL 解码，修复文件下载 401 | AtomCode |

### 关键修复点

1. **URL_PATH_REGEX** — 从冒号分隔改为斜杠分隔 `/bot{token}/{method}`
2. **sanitizeHeaders** — 移除 `authorization` 拦截，确保授权头正常转发
3. **proxyFileFromTelegram** — 添加 `/file/` 前缀到 Telegram 文件下载 URL
4. **ES Module 兼容** — 添加默认导出 `export { onRequest as default }`
5. **版本信息** — `/stats` 和 `/ping` 端点返回 `VERSION` 对象
6. **parseFileRequest URL 解码** — `python-telegram-bot` 库的 `_get_encoded_url()` 会将 `:` 编码为 `%3A`，导致 token 与白名单不匹配。添加 `decodeURIComponent` 修复。

---

## 🎯 待办事项

- [ ] 在 Cloudflare Dashboard 部署 `functions/api/api.js` 代码
- [ ] 验证 `/stats` 返回 `version` 字段
- [ ] 验证 Telegram 图片下载不再报 `InvalidToken`
- [ ] 修复 GitHub 自动构建流程（可选）
- [ ] 更新 DEPLOY.md 文档

---

## 📞 相关文档

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [wrangler 文档](https://developers.cloudflare.com/workers/wrangler/)