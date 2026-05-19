# Telegram API 安全代理

![版本](https://img.shields.io/badge/版本-7.0-blue.svg?cacheSeconds=2592000)
![许可证: GPL-3.0](https://img.shields.io/badge/许可证-GPL--3.0-yellow.svg)
![部署: Cloudflare](https://img.shields.io/badge/部署-Cloudflare-orange.svg)

基于 Cloudflare 的高性能 Telegram Bot API 代理服务。支持白名单管理、全自动化部署及可视化管理后台，专为网络受限环境设计。

---

## 🚀 项目简介

本项目提供了一个安全、透明的 Telegram Bot API 代理网关。
- **自动同步**：支持关联 GitHub 仓库，实现 `git push` 后自动构建与部署。
- **多平台支持**：同时支持 Cloudflare Workers 和 Cloudflare Pages 部署。
- **隐私安全**：透明转发请求，不存储任何消息内容。

## ✨ 功能特性

- ✅ **完整支持**：支持所有 Telegram Bot API 方法和文件上传，包括 webhook 相关方法。
- 🔐 **Token 白名单**：内置授权机制，仅允许特定 Bot 使用代理，防止滥用。
- 🛠️ **可视化后台**：内置无 KV 管理页面，可直接在浏览器修改授权 Token。
- 🛡️ **安全过滤**：自动拦截恶意攻击、SQL 注入及可疑请求。
- ⚡ **高性能**：利用 Cloudflare 全球网络，支持自动重试与熔断机制。
- 🇨🇳 **中文化界面**：主页及后台管理面板全面支持中文。
- 🌐 **Webhook 支持**：完整支持 setWebhook、deleteWebhook 和 getWebhookInfo 方法。

## 🛠️ 快速部署 (GitHub 自动化版)

1. **Fork 本仓库** 到你的 GitHub 账号。
2. 登录 **Cloudflare 控制台**。
3. 进入 **Workers & Pages** -> **Create Application** -> **Workers**。
4. 选择 **Connect to Git** 并关联你的仓库。
5. 在配置页面，`wrangler.toml` 会自动指定入口为 `manual-worker/worker.js`。
6. 点击部署。

> 💡 详细部署及 API 权限配置请参考 [DEPLOY.md](DEPLOY.md)。

## ⚙️ 环境变量配置

要启用管理后台和 Token 白名单，请在 Cloudflare 控制台设置以下变量：

| 变量名 | 必填 | 说明 |
| :--- | :--- | :--- |
| `ALLOWED_BOT_TOKENS` | 是 | 允许使用的 Bot Token (多个用逗号隔开) |
| `ADMIN_PASSWORD` | 可选 | 登录 `/admin` 后台的管理员密码 |
| `CF_ACCOUNT_ID` | 可选 | 用于后台动态修改配置 (CF 账户 ID) |
| `CF_SCRIPT_NAME` | 可选 | 当前 Worker 的名称 (如 `tap`) |
| `CF_API_TOKEN` | 可选 | 具有 Edit Worker 权限的 API 令牌 |

## 📖 使用示例

将 API 前缀替换为你的代理地址：
- **Workers 路径**：`https://your-worker.workers.dev/bot<TOKEN>/<METHOD>`
- **Pages 路径**：`https://your-page.pages.dev/api/bot<TOKEN>/<METHOD>`

### Python 示例
```python
import requests
API_BASE = "https://tap.test.workers.dev/bot12345:TOKEN"
resp = requests.get(f"{API_BASE}/getMe")
print(resp.json())
```

### Webhook 使用示例
```python
import requests
API_BASE = "https://tap.test.workers.dev/bot12345:TOKEN"

# 设置 Webhook
webhook_url = "https://your-domain.com/webhook"
resp = requests.post(f"{API_BASE}/setWebhook", json={"url": webhook_url})
print("Set Webhook:", resp.json())

# 获取 Webhook 信息
resp = requests.get(f"{API_BASE}/getWebhookInfo")
print("Webhook Info:", resp.json())

# 删除 Webhook
resp = requests.post(f"{API_BASE}/deleteWebhook")
print("Delete Webhook:", resp.json())
```

## 🖥️ 管理后台

访问 `https://你的域名/admin` 即可进入管理后台。
- 无需配置数据库，通过 Cloudflare API 直接同步设置。
- 界面简洁，支持实时更新 Token 白名单。

## 🔄 管理后台页面单一来源

`/admin` 在线页面由 `manual-worker/worker.js` 中的 `ADMIN_HTML` 提供。为避免“只改了 `admin.html` 但线上不生效”，本仓库提供同步脚本：

```bash
node scripts/sync-admin-html.mjs
```

每次修改 `admin.html` 后，请先运行该脚本，再提交变更。


---

## 📄 项目许可证

本项目采用 [GPL-3.0](LICENSE) 许可证。

---

### 👤 Author
**niudakok**

### 📜 Source
This project is modified based on:
[4n0nymou3/Telegram-API-Proxy](https://github.com/4n0nymou3/Telegram-API-Proxy)
