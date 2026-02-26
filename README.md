# Telegram API 代理

![版本](https://img.shields.io/badge/版本-6.0-blue.svg?cacheSeconds=2592000)
![许可证: GPL-3.0](https://img.shields.io/badge/许可证-GPL--3.0-yellow.svg)

基于 Cloudflare 的 Telegram Bot API 代理服务，用于在访问受限地区无需 VPN 即可使用 Telegram API。

## 项目简介

本项目提供了一个安全可靠的 Telegram Bot API 代理，托管在 Cloudflare Pages 上，具备高可用性和高性能。代理会将你的 API 请求透明转发至 `api.telegram.org`。

支持两种部署方式：
- **Cloudflare Pages**（推荐）：使用 `functions/` 目录，绑定 GitHub 仓库自动部署
- **Cloudflare Workers**：使用 `manual-worker/worker.js`，手动粘贴代码部署

## 功能特性

- ✅ 支持所有 Telegram Bot API 方法
- ⚡ 速率限制：每 IP 每分钟 100 次请求，全局每分钟 5000 次
- 🛡️ 安全防护：拦截 SQL 注入、XSS、路径遍历等恶意请求
- 🔄 自动重试：失败请求最多重试 3 次（指数退避）
- 🔌 熔断器：连续失败时自动断路保护
- 🔐 Bot Token 白名单：通过环境变量限制只有自己的 Bot 才能使用

## 快速使用

将标准 Telegram API 地址替换为代理地址即可（前缀 `/api/bot`）：

```
https://你的域名.pages.dev/api/bot
```

### JavaScript 示例

```javascript
const botToken = "你的_Bot_Token";
const chatId = "目标_Chat_ID";
const message = "Hello World";

const url = `https://你的域名.pages.dev/api/bot${botToken}/sendMessage?text=${message}&chat_id=${chatId}`;

fetch(url).then(res => res.json()).then(console.log);
```

### Python 示例

```python
import requests

def send_telegram_message(message):
    token = "你的_Bot_Token"
    chat_id = "目标_Chat_ID"
    url = f"https://你的域名.pages.dev/api/bot{token}/sendMessage"
    
    payload = {
        "text": message,
        "chat_id": chat_id
    }
    
    response = requests.post(url, json=payload)
    return response.json()
```

## 部署说明

详细部署步骤请参阅 [DEPLOY.md](DEPLOY.md)。

## 安全配置（限制只有自己使用）

通过 Cloudflare 控制台配置环境变量 `ALLOWED_BOT_TOKENS`，填入你自己的 Bot Token（多个用英文逗号分隔）：

```
ALLOWED_BOT_TOKENS=1234567890:AABBccDDeeFF,9876543210:ZZYYxxWWvvUU
```

配置后，只有白名单中的 Token 才能使用此代理，其他请求会被拒绝（返回 403）。

## 项目许可证

本项目采用 [GPL-3.0](LICENSE) 许可证。

## 作者

**Anonymous**

* Telegram: [@BXAMbot](https://t.me/BXAMbot)
