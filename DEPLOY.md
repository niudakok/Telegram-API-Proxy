# 部署指南 - Telegram API 代理

## 前置准备

1. **Cloudflare 账号**：免费注册 [cloudflare.com](https://cloudflare.com)
2. **你的 Bot Token**：从 [@BotFather](https://t.me/BotFather) 获取，格式如 `1234567890:AABBccDDeeFF...`
3. **GitHub 账号**（仅 Pages 方式需要）

---

## 方式一：Cloudflare Pages 部署（推荐）

> 优点：自动部署、免费额度充足、绑定 GitHub 自动更新

### 步骤

**1. Fork 仓库到 GitHub**

将本项目 Fork 到你的 GitHub 账号下。

**2. 登录 Cloudflare 控制台**

访问 [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages** → **Create application** → **Pages** → **Connect to Git**

**3. 选择仓库**

选择你 Fork 的仓库，点击 **Begin setup**。

**4. 构建配置**

| 设置项 | 值 |
|--------|-----|
| 构建命令 | 留空 |
| 构建输出目录 | 留空（或填 `/`）|
| 根目录 | 留空 |

点击 **Save and Deploy**，等待部署完成。

**5. 配置环境变量（关键步骤：限制只有自己使用）**

部署完成后，进入项目设置：
**Settings** → **Environment variables** → **Add variable**

| 变量名 | 值（填你自己的 Bot Token）|
|--------|-----|
| `ALLOWED_BOT_TOKENS` | `1234567890:AABBccDDeeFF你的Token` |

> 多个 Bot Token 用英文逗号分隔：
> `1234567890:AABBccDDeeFF,9876543210:ZZYYxxWWvvUU`

**6. 重新部署生效**

添加环境变量后，点击 **Deployments** → **Retry deployment** 使配置生效。

**7. 完成**

你的代理地址为：
```
https://你的项目名.pages.dev/api/bot
```

---

## 方式二：Cloudflare Workers 部署

> 手动粘贴代码，无需 GitHub

### 步骤

**1. 进入 Workers 控制台**

[dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages** → **Create application** → **Create Worker**

**2. 粘贴代码**

点击 **Edit code**，将 `manual-worker/worker.js` 的全部内容粘贴进去，点击 **Save and Deploy**。

**3. 配置环境变量 (持久化方案)**

> [!IMPORTANT]
> **请务必使用 Cloudflare 的 Secrets (加密变量) 功能**。
> 相比普通环境变量，Secrets 不会被 GitHub 自动部署过程中的 `wrangler.toml` 清空或覆盖，是实现 Token 长久保存的最佳方式。

**操作步骤：**
1.  进入 Worker 详情页 → **Settings** → **Variables**。
2.  找到下方的 **Secrets** 栏目（而不是上面的 Environment Variables）。
3.  点击 **Add variable**，分别填入：
    - `ALLOWED_BOT_TOKENS`: 你的 Bot Token 列表。
    - `ADMIN_PASSWORD`: 管理后台登录密码。
4.  如果你要使用自动管理功能，还需添加：
    - `CF_ACCOUNT_ID` / `CF_SCRIPT_NAME` / `CF_API_TOKEN`。

---

你可以直接配置固定白名单：
| 变量名 | 值 | 说明 |
|--------|-----|-----|
| `ALLOWED_BOT_TOKENS` | `你的Bot Token` | 多个 Token 用英文逗号分隔 |

**（可选）启用网页版管理后台（无需 KV）**
如果您想要随时通过网页修改 Token，不用每次进 Cloudflare 控制台，请额外配置以下 4 个环境变量：

| 变量名 | 值 | 说明 |
|--------|-----|-----|
| `ADMIN_PASSWORD` | 自定义密码 | 登录管理后台用的密码 |
| `CF_ACCOUNT_ID` | `1234abcd...` | 你的 CF 账号 ID（在域名 Overview 右下角）|
| `CF_SCRIPT_NAME` | `telegram-api-proxy` | 你创建的这个 Worker 的名字 |
| `CF_API_TOKEN` | `xxxx` | CF API Token（在 My Profile → API Tokens 创建，需包含 Edit Workers Scripts 权限）|

点击 **Save**。

**4. 完成**

你的代理地址为：
```
https://你的worker名.你的用户名.workers.dev/bot
```

**管理后台地址（如已配置可选环境变量）：**
```
https://你的worker名.你的用户名.workers.dev/admin
```

> ⚠️ 注意：Workers 方式的路径前缀是 `/bot`，Pages 方式是 `/api/bot`

---

## 使用代理

将你代码中原来的 Telegram API 地址替换为代理地址：

### 原地址
```
https://api.telegram.org/bot{Token}/{Method}
```

### 替换为（Pages 方式）
```
https://你的域名.pages.dev/api/bot{Token}/{Method}
```

### Python 代码示例
```python
import requests

# 将 api_base 改为你的代理地址
API_BASE = "https://你的域名.pages.dev/api/bot你的Token"

def send_message(chat_id, text):
    url = f"{API_BASE}/sendMessage"
    data = {"chat_id": chat_id, "text": text}
    return requests.post(url, json=data).json()

# 与直连 Telegram 完全相同的用法
result = send_message("7649915591", "Hello via Proxy!")
print(result)
```

### curl 测试示例
```bash
# 测试代理是否正常（替换为你的域名和 Token）
curl "https://你的域名.pages.dev/api/bot你的Token/getMe"

# 预期返回：{"ok":true,"result":{"id":...}}
```

---

## 安全说明

| 安全机制 | 说明 |
|---------|------|
| **Bot Token 白名单** | 只有 `ALLOWED_BOT_TOKENS` 中的 Token 才能使用代理 |
| **速率限制** | 每 IP 每分钟最多 100 次请求，突发限制 10 次/秒 |
| **恶意请求拦截** | 自动拦截 SQL 注入、XSS 等攻击 |
| **熔断保护** | 连续 5 次失败自动断路，30 秒后恢复 |
| **自动重试** | 失败最多重试 3 次（指数退避：1s → 2s → 4s）|

---

## 常见问题

**Q：配置完环境变量后请求还是被拒绝？**  
A：需要重新部署才能生效。Pages 方式：Deployments → Retry deployment；Workers 方式：保存后自动生效。

**Q：返回 `Geographic restriction` 403 错误？**  
A：代码中已去除国家限制，如果还有此错误，确认你部署的是本改造后的版本。

**Q：返回 `Invalid bot token` 401 错误？**  
A：Bot Token 格式不符合要求（长度、字符格式），请检查 Token 是否完整。

**Q：Cloudflare Pages 免费额度是多少？**  
A：每天 100,000 次请求，个人使用完全够用。
