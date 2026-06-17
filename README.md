# Telegram API 安全代理

![版本](https://img.shields.io/badge/版本-7.0-blue.svg?cacheSeconds=2592000)
![许可证: GPL-3.0](https://img.shields.io/badge/许可证-GPL--3.0-yellow.svg)
![部署: Cloudflare](https://img.shields.io/badge/部署-Cloudflare-orange.svg)

基于 Cloudflare 的高性能 Telegram Bot API 代理服务。支持白名单管理、全自动化部署及可视化管理后台，专为网络受限环境设计。

---

## 📋 目录

- [项目简介](#-项目简介)
- [功能特性](#-功能特性)
- [架构说明](#-架构说明)
- [快速部署](#-快速部署)
- [环境变量](#️-环境变量)
- [使用示例](#-使用示例)
- [管理后台](#️-管理后台)
- [错误处理](#-错误处理)
- [本地开发](#-本地开发)
- [项目结构](#-项目结构)
- [常见问题](#-常见问题)
- [许可证](#-许可证)

---

## 🚀 项目简介

本项目提供了一个安全、透明的 Telegram Bot API 代理网关。

- **自动同步**：支持关联 GitHub 仓库，实现 `git push` 后自动构建与部署。
- **多平台支持**：同时支持 Cloudflare Workers 和 Cloudflare Pages 部署。
- **隐私安全**：透明转发请求，不存储任何消息内容。

---

## ✨ 功能特性

| 特性 | 说明 |
|------|------|
| ✅ **完整 API 支持** | 所有 Telegram Bot API 方法及文件上传，包括 webhook |
| 🔐 **Token 白名单** | 内置授权机制，仅允许特定 Bot 使用代理，防止滥用 |
| 🛠️ **可视化后台** | 内置无 KV 管理页面，浏览器直接修改授权 Token |
| 🛡️ **多层安全防护** | Token 白名单 + 速率限制 + 熔断器 + 恶意请求过滤 + 可疑 IP 追踪 |
| ⚡ **高可用** | 自动重试（指数退避）+ 熔断保护 + 超时控制 + Cloudflare 全球网络 |
| 🇨🇳 **中文化界面** | 主页及后台管理面板全面支持中文 |
| 🌐 **Webhook 支持** | 完整支持 `setWebhook`、`deleteWebhook`、`getWebhookInfo`，自动移除 `proxy_url` |

---

## 🏗️ 架构说明

项目提供两种部署模式，代码独立但功能互补：

| 对比项 | Worker 版 | Pages 版（推荐） |
|--------|-----------|-----------------|
| **入口** | `manual-worker/worker.js` | `functions/api/[[path]].js` |
| **路由前缀** | `/bot<TOKEN>/<METHOD>` | `/api/bot<TOKEN>/<METHOD>` |
| **部署方式** | 粘贴代码 / `wrangler deploy` | GitHub 关联自动部署 |
| **安全防护** | 基础（全局限流 + Token 白名单） | 完整（IP/Token/突发三级限流 + 熔断器 + 可疑IP追踪） |
| **自动重试** | ✅ 超时/连接池满重试 2 次 | ✅ 指数退避重试 3 次 + 多端点轮询 |
| **缓存优化** | ❌ | ✅ 读操作缓存（getMe 1h，getChat 10min） |
| **错误分类** | ✅ `error_type` 字段 | ✅ `error_type` 字段 + `request_id` + 时间戳 |

**请求处理流程（两版通用）：**

```
客户端请求 → 安全检查 → 速率限制 → Token 白名单校验 → 代理转发到 api.telegram.org → 返回响应
                                                            ↓
                                                    超时/连接池满自动重试
```

---

## 🛠️ 快速部署

> 📖 **详细喂奶级部署教程**（含每步截图级文字说明）请移步 [DEPLOY.md](DEPLOY.md)

### 方式一：Cloudflare Pages 部署（推荐，自动更新）

| 步骤 | 操作 |
|------|------|
| ① Fork 仓库 | 在 GitHub 上 Fork 本仓库到你的账号 |
| ② 创建 Pages 项目 | Cloudflare → Workers & Pages → Create application → **Pages** → Connect to Git |
| ③ 关联仓库 | 选择你 Fork 的仓库，构建命令**留空**，点击 **Save and Deploy** |
| ④ 配置环境变量 | Settings → Environment variables → 添加 `ALLOWED_BOT_TOKENS` |
| ⑤ 重新部署 | Deployments → **Retry deployment** 使环境变量生效 |
| ✅ 完成 | 代理地址：`https://你的项目名.pages.dev/api/bot<TOKEN>/<METHOD>` |

### 方式二：Cloudflare Workers 部署（手动粘贴）

| 步骤 | 操作 |
|------|------|
| ① 创建 Worker | Cloudflare → Workers & Pages → Create application → **Workers** → Create Worker |
| ② 粘贴代码 | 将 `manual-worker/worker.js` 全部内容粘贴到编辑器中，保存 |
| ③ 配置 Secrets | Settings → Variables → **Secrets** → 添加 `ALLOWED_BOT_TOKENS` |
| ✅ 完成 | 代理地址：`https://你的worker名.你的用户名.workers.dev/bot<TOKEN>/<METHOD>` |

> ⚠️ Workers 方式务必使用 **Secrets（加密变量）**，不要用普通环境变量。

### 验证部署

```bash
curl "https://你的域名/bot你的Token/getMe"
# 预期：{"ok":true,"result":{"id":...,"first_name":"..."}}
```

---

## ⚙️ 环境变量

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `ALLOWED_BOT_TOKENS` | **是** | — | 允许使用的 Bot Token，多个用英文逗号分隔，如 `123:ABC,456:DEF` |
| `ADMIN_PASSWORD` | 可选 | — | 登录 `/admin` 后台的管理员密码 |
| `CF_ACCOUNT_ID` | 可选 | — | Cloudflare 账户 ID，用于后台动态修改 Token（域名 Overview 右下角）|
| `CF_SCRIPT_NAME` | 可选 | — | 当前 Worker 名称（如 `telegram-api-proxy`）|
| `CF_API_TOKEN` | 可选 | — | 具有 **Edit Workers Scripts** 权限的 Cloudflare API Token |
| `SETWEBHOOK_STRIP_PROXY_URL` | 可选 | `true` | 为 `true` 时自动移除 `setWebhook` 请求中的 `proxy_url`；设为 `false` 启用严格透传 |

> 💡 配置了 `CF_ACCOUNT_ID` + `CF_SCRIPT_NAME` + `CF_API_TOKEN` 后，可直接在管理后台修改 Token，无需进 Cloudflare 控制台。

---

## 📖 使用示例

将 API 前缀替换为你的代理地址：

```
# 原地址
https://api.telegram.org/bot<TOKEN>/<METHOD>

# Workers 方式
https://your-worker.workers.dev/bot<TOKEN>/<METHOD>

# Pages 方式
https://your-page.pages.dev/api/bot<TOKEN>/<METHOD>
```

### Python

```python
import requests

API_BASE = "https://your-page.pages.dev/api/bot123456:ABCdef"

def send_message(chat_id, text):
    url = f"{API_BASE}/sendMessage"
    data = {"chat_id": chat_id, "text": text}
    return requests.post(url, json=data).json()

print(send_message("123456789", "Hello via Proxy!"))
```

### Webhook

```python
API_BASE = "https://your-page.pages.dev/api/bot123456:ABCdef"

# 设置 Webhook
resp = requests.post(f"{API_BASE}/setWebhook", json={"url": "https://your-domain.com/webhook"})

# 获取 Webhook 信息
resp = requests.get(f"{API_BASE}/getWebhookInfo")

# 删除 Webhook
resp = requests.post(f"{API_BASE}/deleteWebhook")
```

### curl

```bash
curl "https://your-page.pages.dev/api/bot123456:ABCdef/getMe"
# 预期返回：{"ok":true,"result":{"id":...,"first_name":"..."}}
```

---

## 🖥️ 管理后台

访问 `https://你的域名/admin` 进入管理后台。

- **无需数据库**：通过 Cloudflare API 直接同步设置。
- **Token 管理**：支持逐条添加、删除、清空、去重。
- **设置管理**：开关 `setWebhook` 的 `proxy_url` 自动移除。

### 管理 API

如需要程序化管理 Token，可使用以下 API（需 `Authorization: Bearer <ADMIN_PASSWORD>` 头）：

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/admin/tokens` | 获取当前 Token 列表 |
| `POST` | `/api/admin/tokens` | 更新 Token，body: `{"tokens": "123:ABC,456:DEF"}` |
| `GET` | `/api/admin/settings` | 获取当前设置 |
| `POST` | `/api/admin/settings` | 更新设置，body: `{"stripProxyUrl": true}` |

### 管理后台页面单一来源

`/admin` 页面由 `manual-worker/worker.js` 中的 `ADMIN_HTML` 提供。修改 `admin.html` 后需同步：

```bash
cd Telegram-API-Proxy
node scripts/sync-admin-html.mjs
```

---

## 🚨 错误处理

代理返回的所有错误响应均包含 `error_type` 字段，客户端可根据此字段决定重试策略。

### 错误类型速查

| `error_type` | HTTP 状态码 | 含义 | 客户端策略 |
|-------------|------------|------|-----------|
| `rate_limited` | 429 | 请求频率过高 | 等待 `retry_after` 秒后重试 |
| `timeout` | 504 | Telegram API 超时 | 指数退避重试 |
| `connection_pool_full` | 503 | CF 连接池已满 | 退避重试 |
| `circuit_breaker` | 503 | 熔断器打开（连续失败过多）| 等待 30s 以上再试 |
| `invalid_token` | 401 | Bot Token 不在白名单 | 检查配置，**不要重试** |
| `security_violation` | 400/405 | 恶意请求被拦截 | 检查请求内容 |
| `telegram_error` | 502 | Telegram 返回服务器错误 | 可重试 |
| `proxy_error` | 500 | 代理内部错误 | 可重试 |
| `not_found` | 404 | API 路径不存在 | 检查 URL 格式 |

### 错误响应格式

**Pages 版：**
```json
{
  "ok": false,
  "error": "Rate limit exceeded. Please try again later.",
  "error_type": "rate_limited",
  "retry_after": 60,
  "timestamp": "2026-06-17T15:07:43.070Z",
  "request_id": "k8f3a7x2b"
}
```

**Worker 版：**
```json
{
  "ok": false,
  "error": "Rate limit exceeded",
  "error_type": "rate_limited",
  "retry_after": 60
}
```

### 客户端重试示例

```python
import requests, time

API_BASE = "https://your-domain.pages.dev/api/botTOKEN"

def call_telegram(method, **kwargs):
    url = f"{API_BASE}/{method}"
    max_retries = 3

    for attempt in range(max_retries):
        resp = requests.post(url, json=kwargs)
        if resp.ok:
            return resp.json()

        err = resp.json()
        etype = err.get('error_type', 'unknown')

        if etype == 'rate_limited':
            wait = err.get('retry_after', 10)
            print(f"[限速] 等待 {wait}s")
            time.sleep(wait)

        elif etype in ('timeout', 'connection_pool_full'):
            wait = 2 ** attempt
            print(f"[连接异常] {wait}s 后重试")
            time.sleep(wait)

        elif etype == 'invalid_token':
            print("[配置错误] Token 无效，停止重试")
            break

        elif etype == 'circuit_breaker':
            print("[熔断] 等待 30s")
            time.sleep(30)

        elif etype in ('proxy_error', 'telegram_error'):
            print(f"[服务器错误] 尝试重试 ({attempt+1}/{max_retries})")
            time.sleep(2 ** attempt)
        else:
            print(f"[未知错误] {err.get('error')}")
            break

    return None
```

---

## 💻 本地开发

### 环境准备

```bash
node -v  # 需要 Node.js 18+
```

### 本地运行

本项目是 Cloudflare Workers/Pages 项目，推荐使用 `wrangler` 本地开发：

```bash
# 安装 wrangler
npm install -g wrangler

# 登录 Cloudflare
wrangler login

# 本地预览 Worker 版
wrangler dev manual-worker/worker.js

# 本地预览 Pages 版
npx wrangler pages dev .
```

### 代码同步（开发时注意）

修改 `admin.html` 后必须同步到 Worker 内嵌的 `ADMIN_HTML`：

```bash
node scripts/sync-admin-html.mjs
```

提交前运行一致性检查：

```bash
node scripts/sync-admin-html.mjs
node scripts/check-proxy-consistency.mjs
```

### 分支规范

```bash
main      # 稳定发布分支
dev       # 开发分支
```

---

## 📁 项目结构

```
Telegram-API-Proxy/
├── manual-worker/
│   └── worker.js              ← Worker 部署入口（含内嵌 ADMIN_HTML）
├── functions/api/
│   └── [[path]].js            ← Pages Functions 部署入口（推荐）
├── admin.html                 ← 管理后台 HTML 源文件
├── index.html                 ← 主页介绍页面
├── css/style.css              ← 主页样式
├── js/main.js                 ← 主页交互（代码高亮、复制按钮）
├── wrangler.toml              ← Cloudflare 部署配置
├── scripts/
│   ├── sync-admin-html.mjs    ← admin.html → worker.js ADMIN_HTML 同步脚本
│   └── check-proxy-consistency.mjs ← 一致性校验脚本
├── DEPLOY.md                  ← 部署文档
├── README.md                  ← 项目说明
└── LICENSE                    ← GPL-3.0 许可证
```

---

## ❓ 常见问题

**Q：配置完环境变量后请求还是被拒绝？**
A：需要重新部署才能生效。Pages 方式：Deployments → Retry deployment；Workers 方式：保存后自动生效。

**Q：返回 `Invalid bot token` 401 错误？**
A：确认 `ALLOWED_BOT_TOKENS` 已正确配置，且请求中使用的 Token 在列表内。多次出现请检查客户端配置。

**Q：出现 `send_path_degraded` 或连接池满错误？**
A：这些问题已在 v7.0-dev 中修复：
- 删除了错误的 `:80` 端点
- 添加了 fetch 超时（15s），避免慢连接占用连接池
- 连接池满时自动重试（指数退避）
- 缩短了超时时间以快速释放连接

**Q：Cloudflare Pages 免费额度是多少？**
A：每天 100,000 次请求，个人使用完全够用。

**Q：如何验证代理是否正常工作？**
A：执行 `curl "https://你的域名/bot你的Token/getMe"`，返回 `{"ok":true,"result":{"id":...}}` 即正常。

---

## 📄 许可证

本项目采用 [GPL-3.0](LICENSE) 许可证。

### 👤 Author

**niudakok**

### 📜 Source

This project is modified based on:
[4n0nymou3/Telegram-API-Proxy](https://github.com/4n0nymou3/Telegram-API-Proxy)
