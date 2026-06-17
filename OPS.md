# 📋 运维记录 — Telegram API 代理

> 记录版本发布、问题排查、变更历史及注意事项。

---

## 版本历史

| 版本 | 日期 | 标签 | 说明 |
|------|------|------|------|
| 7.0-dev | 2026-06-17 | `v7.0-dev` | 初始 dev 分支，修复连接池满、send_path_degraded，新增本地测试环境、error_type |
| 7.0 | 2026-06-17 | `v7.0` | 生产验证通过，合并到 main |

---

## 问题处理记录

### P1: `send_path_degraded` + 连接池满

**现象：**
```
2026-06-17 15:07:43 WARNING gateway.platforms.base: [Telegram] Send failed
(attempt 1/2, retrying in 3.0s): send_path_degraded
```

**根因：**
1. Pages 版的 `TELEGRAM_ENDPOINTS` 包含 `api.telegram.org:80`——HTTPS 协议走 80 端口导致连接异常，Telegram 返回 `send_path_degraded`
2. Cloudflare Workers 免费版并发出站请求上限 6 个，代理无并发控制和超时，慢连接永久占用连接池

**修复：** `12e0ce8` (`main`) / `6d4e4eb` (`dev`)
- 删除 `:80` 和冗余 `:443` 端点，只保留 `api.telegram.org`
- 添加 fetch 超时（普通 15s，文件上传 60s）
- 连接池满错误（`EXCEEDED_CONCURRENT`）自动重试
- 缩短超时时间快速释放连接

---

### P2: 客户端连接池满

**现象：**
```
telegram.error.TimedOut: Pool timeout: All connections in the connection pool
are occupied. Request was *not* sent to Telegram.
```

**根因：** 代理端对超时做了重试（15s + 1s + 15s + 2s + ...），客户端（python-telegram-bot）自己也在重试（attempt 2/3），两层重试叠加导致单请求最长 48s，客户端连接池被占满。

**修复：** `12e0ce8`
- 仅重试 Cloudflare 特有的 `EXCEEDED_CONCURRENT` 错误
- 超时错误直接返回（504），让客户端自己重试

---

### P3: 路径遍历检测失效（安全漏洞）

**现象：** 发送 `xxx/../../etc/passwd` 未被拦截。

**根因：** `new URL(request.url).pathname` 已被 URL 类规范化，`..` 序列被消除后才进入安全检查。

**修复：** `6d4e4eb`
- 改用 `request.url` 原始字符串检测路径遍历
- 同时检测 URL 编码形式 `%2e%2e%2f`
- 两个版本均修复

---

## 配置清单

### 环境变量

| 变量 | 必填 | 说明 | 备注 |
|------|------|------|------|
| `ALLOWED_BOT_TOKENS` | ✅ 是 | 允许的 Token 列表（逗号分隔） | Pages 版要求 hash >= 30 字符，botId >= 8 位数字，总长 >= 40 |
| `ADMIN_PASSWORD` | 可选 | 管理后台密码 | 配置后才可访问 `/admin` |
| `CF_ACCOUNT_ID` | 可选 | Cloudflare 账户 ID | 用于后台动态修改 Token |
| `CF_SCRIPT_NAME` | 可选 | Worker 名称 | 同上 |
| `CF_API_TOKEN` | 可选 | CF API Token（Edit Workers 权限） | 同上 |
| `SETWEBHOOK_STRIP_PROXY_URL` | 可选 | 是否移除 setWebhook 的 proxy_url | 默认 `true` |
| `TELEGRAM_API_BASE` | 可选 | 覆盖上游 API 地址 | 仅本地开发用，生产不设置 |

### 本地开发配置（`.dev.vars`）

```
ALLOWED_BOT_TOKENS=1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X
ADMIN_PASSWORD=admin123
TELEGRAM_API_BASE=http://localhost:9001
```

---

## 部署架构

```
客户端（python-telegram-bot 等）
        │
        ▼
Cloudflare Worker/Pages（代理层）
        │
        ├── 安全检查（Token 白名单 / 限流 / 熔断 / UA 过滤 / 路径遍历）
        ├── 超时控制（15s 普通 / 60s 文件上传）
        ├── 连接池保护（EXCEEDED_CONCURRENT 时重试）
        │
        ▼
Telegram API（api.telegram.org）
```

---

## 监控指标

### 关键日志关键词

| 关键词 | 含义 | 处理 |
|--------|------|------|
| `Invalid bot token` | Token 不在白名单 | 检查客户端 Token 配置 |
| `Rate limit exceeded` | 请求频率过高 | 客户端降速，等待 `retry_after` |
| `EXCEEDED_CONCURRENT` | CF 连接池满（瞬态） | 代理会自动重试，观察频率 |
| `Malicious request detected` | 恶意请求被拦截 | 检查请求内容，排除误报 |
| `Pool timeout` | 客户端连接池满 | 降低客户端并发数或增大 pool 大小 |
| `Gateway timeout` | Telegram 响应超时 | 确认 Telegram 可用性 |

---

## 开发工作流

```
dev → 开发 → 你测试通过 → 合并到 main → 部署生产
```

### 分支管理

| 分支 | 用途 |
|------|------|
| `main` | 生产稳定版本，仅从 dev 合并 |
| `dev` | 日常开发，所有改动先在这提交 |

### 本地测试

```bash
# 终端 1：启动 mock 服务器
node scripts/mock-telegram-server.mjs

# 终端 2：启动代理
npx wrangler dev manual-worker/worker.js --port 8787

# 终端 3：测试
curl "http://localhost:8787/bot$TOKEN/getMe"
```

详见 [TESTING.md](TESTING.md)。

---

## 常见运维操作

### 更新 Token

**方法一：Cloudflare 控制台**
Settings → Environment variables（Pages）/ Variables → Secrets（Workers）→ 修改 `ALLOWED_BOT_TOKENS`

**方法二：管理后台**
访问 `https://你的域名/admin`，登录后直接管理 Token 列表

### 更新代码

**Pages 版：** `git push` 到 GitHub → Cloudflare 自动部署（构建配置需指向对应分支）

**Workers 版：** 复制 `manual-worker/worker.js` 内容 → 粘贴到 Cloudflare Workers 编辑器 → 保存

### 查看统计

`GET https://你的域名/stats` — 返回请求总数、成功/失败数、限流数等

### 确认代理运行状态

```bash
curl "https://你的域名/bot你的Token/getMe"
# → {"ok":true,"result":{"id":...,"first_name":"..."}}
```
