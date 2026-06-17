# 🧪 本地测试指南

> 本地测试踩坑记录，包含测试环境搭建、注意事项、以及本人在测试中遇到的实际问题和解决方案。

---

## 📋 目录

- [环境准备](#-环境准备)
- [启动测试环境](#-启动测试环境)
- [运行测试](#-运行测试)
- [踩坑记录](#-踩坑记录)
- [测试用例编写规范](#-测试用例编写规范)
- [常见问题速查](#-常见问题速查)

---

## 🔧 环境准备

### 依赖

```bash
node -v  # 需要 Node.js 18+
npm -v
```

### 安装 wrangler

```bash
# 方式一：项目本地安装（推荐）
cd Telegram-API-Proxy
npm install wrangler --save-dev

# 方式二：全局安装
npm install -g wrangler
```

> ⚠️ 首次 `npx wrangler` 会自动下载包（约 80MB），需要等待 5-10 秒。**不是卡住了，在下载。**

### 启动 Mock 服务器

由于本地可能无法直连 `api.telegram.org`，需要一个 mock 服务器模拟 Telegram：

**终端 1：**
```bash
node scripts/mock-telegram-server.mjs
```

Mock 服务器默认监听 `http://localhost:9001`，支持以下 API：
- `getMe` / `sendMessage` / `getWebhookInfo` / `setWebhook` / `deleteWebhook`
- `getUpdates` / `getChat` / `getFile`
- 文件下载（返回 1x1 PNG）
- 模拟 50~150ms 网络延迟

### 配置 `.dev.vars`

在项目根目录创建 `.dev.vars`，wrangler 会自动读取：

```bash
ALLOWED_BOT_TOKENS=1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X
ADMIN_PASSWORD=admin123
TELEGRAM_API_BASE=http://localhost:9001
```

> ⚠️ **Token 长度要求：** Pages 版要求 Bot Token 的 hash 部分 >= 30 字符，botId >= 8 位数字，总长 >= 40。
> 测试用 Token `1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X`（41 字符）满足全部要求。
> Worker 版只要求 Token 总长 >= 30（`1234567890:AAGkLmNoPqRsTuVwXyZ1234567890` 40 字符即可）。

---

## 🚀 启动测试环境

### Worker 版

```bash
TELEGRAM_API_BASE=http://localhost:9001 \
ALLOWED_BOT_TOKENS=1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X \
npx wrangler dev manual-worker/worker.js --port 8787
```

> 关于环境变量传递方式，参考下方「踩坑记录 #1」。

### Pages 版

```bash
npx wrangler pages dev . --port 8788
```

> Pages 版会自动读取 `.dev.vars` 和 `wrangler.toml`，不需要 shell 传参。

### 测试

```bash
# Worker 版
curl "http://localhost:8787/bot你的Token/getMe"

# Pages 版（注意路径有 /api 前缀）
curl "http://localhost:8788/api/bot你的Token/getMe"
```

---

## 🧪 运行测试

参考 `scripts/` 目录下的测试脚本，或者手动测试关键路径：

```bash
# 1. 基础 API 代理
curl "http://localhost:8788/api/bot$TOKEN/getMe"
curl "http://localhost:8788/api/bot$TOKEN/sendMessage" -X POST \
  -H "Content-Type: application/json" \
  -d '{"chat_id":123,"text":"hello"}'

# 2. Webhook
curl "http://localhost:8788/api/bot$TOKEN/setWebhook" -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"https://ex.com/hook"}'

# 3. 安全拦截
curl "http://localhost:8788/api/bot$BAD_TOKEN/getMe"            # 401
curl -X PATCH "http://localhost:8788/api/bot$TOKEN/getMe"       # 405
curl -A "sqlmap/1.2" "http://localhost:8788/api/bot$TOKEN/getMe" # 403

# 4. 路径遍历（编码形式，直接 ../ 会被 URL 类提前规范化）
curl "http://localhost:8788/api/bot$TOKEN/%2e%2e%2f%2e%2e%2fetc/passwd"

# 5. CORS
curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
  "http://localhost:8788/api/bot$TOKEN/getMe"  # 204
```

---

## 🐛 踩坑记录

### 1. 环境变量没传进 Worker

**问题：** 启动 wrangler 时用 shell 传环境变量，但 Worker 拿不到。

```
❌ TELEGRAM_API_BASE=http://localhost:9001 wrangler dev worker.js
```

**原因：** wrangler 的 `dev` 命令不会继承 shell 环境变量。

**解决：** 使用 `.dev.vars` 文件（**所有 wrangler 版本通用**）：

```
# .dev.vars — 和 package.json 同级
ALLOWED_BOT_TOKENS=1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X
ADMIN_PASSWORD=admin123
TELEGRAM_API_BASE=http://localhost:9001
```

wrangler 启动时会输出以下内容确认已加载：
```
Using secrets defined in .dev.vars
env.ALLOWED_BOT_TOKENS ("(hidden)")    Environment Variable   local
env.TELEGRAM_API_BASE ("(hidden)")     Environment Variable   local
```

> ⚠️ 修改 `.dev.vars` 后必须重启 wrangler。

### 2. 进程杀不掉，端口被占用

**问题：** `killall -9 wrangler` 杀不掉，端口还是被占。

```
Error: Address already in use (127.0.0.1:8787)
```

**原因：** wrangler 启动的实际子进程叫 `workerd`，不是 `wrangler`。

**解决：**
```bash
# 方法一：找到并杀掉 workerd
killall -9 workerd

# 方法二：根据端口杀
lsof -ti :8787 -ti :8788 | xargs kill -9

# 方法三：换个端口（逃避问题但也解决问题）
npx wrangler dev --port 8789
```

### 3. Worker 和 Pages 的 Token 校验规则不同

**问题：** Worker 版可以正常通过的 Token，Pages 版报 401。

```
Worker 版 → ✅ ok:true
Pages 版 → ❌ Invalid bot token
```

**原因：** 两版的 `validateBotToken` 规则不同：

| 校验规则 | Worker 版 | Pages 版 |
|---------|-----------|---------|
| 最小总长度 | >= 30 | >= 40 |
| botId 最小长度 | 不单独检查 | >= 8 |
| botHash 最小长度 | 不单独检查 | >= 30 |
| botId 全数字 | 不检查 | 必须 |
| botHash 字符集 | 不检查 | `[A-Za-z0-9_-]` |

**解决：** 使用满足 Pages 版要求的测试 Token：
```
1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X
# ↑ botId=10字符(全数字) ↑ hash=30字符(字母数字混合，总长41)
```

> 验证方式：`echo -n "你的Token" | wc -c`，确保 >= 40。

### 4. 路径遍历检测 `../` 无效

**问题：** 发送 `../../etc/passwd`，安全检查没拦截。

```javascript
// ❌ 这段检测无效：url.pathname 已经被 URL 类规范化了
const url = new URL(request.url);
MALICIOUS_PATTERNS.test(url.pathname);  // url.pathname = "/etc/passwd"，.test() = false
```

**原因：** `new URL(request.url)` 内部会规范化路径，`/api/botTOKEN/../../etc/passwd` → `/etc/passwd`。

> 注意：在 wrangler Pages dev 环境下，`../` 会在更早的 HTTP 层被规范化，请求根本到不了 Functions 代码。在生产环境 Workers 中，`request.url` 保留原始字符串，但 `url.pathname` 已被规范化。

**解决：** 改用 `request.url` 原始字符串检测：

```javascript
const url = new URL(request.url);
// ✅ 检查原始 URL 字符串（保留 ../）
const rawPath = decodeURIComponent(request.url.replace(/^https?:\/\/[^/]+/, ''));
const hasPathTraversal = /(\.\.\/|\.\.\\)/i.test(rawPath);

// 编码形式也要检测（不会在 URL 规范化阶段被消除）
const fullPath = url.pathname + url.search;  // %2e%2e%2f 保留在 pathname 中
```

测试路径遍历时建议使用编码形式：
```bash
# ✅ 用 %2e%2e%2f 替代 ../
curl "http://localhost:8788/api/bot$TOKEN/%2e%2e%2f%2e%2e%2fetc/passwd"

# ❌ 直接 ../ 会被 URL 类提前规范化，测试意义不大
curl "http://localhost:8788/api/bot$TOKEN/../../etc/passwd"
```

### 5. grep 匹配含引号的字符串误判

**问题：** 测试脚本检查响应时，本应通过的测试被判失败。

```bash
# ❌ 问题代码
check "路径遍历拦截" '"Malicious"' "$(curl ...)"

# check 函数内部：
echo "$actual" | grep -q "$expected"
# 实际查找的是字符串 "Malicious"（带双引号）
# 但响应中是 "Malicious request detected"（只有左引号）
```

**解决：** 测试期望值不要包含双引号：

```bash
# ✅ 正确写法
check "路径遍历拦截" "Malicious" "$(curl ...)"
# grep 查找 Malicious（不包含引号，匹配更灵活）
```

### 6. Pages 版 URL 前缀和 Worker 版不同

**问题：** 用 Worker 版的 URL 格式请求 Pages 版，一直 404。

```
Worker 版：   /bot<TOKEN>/<METHOD>          → ✅
Pages 版：    /api/bot<TOKEN>/<METHOD>       → ✅
Pages 版错误：/bot<TOKEN>/<METHOD>           → ❌ 404
```

**原因：** Pages Functions 的 `[[path]].js` 匹配的是 `/api/*` 路径。代码内部会在 `parseRequest` 中做 `pathname.replace('/api', '')` 去掉前缀。

**解决：** 根据部署版本使用正确的 URL：

```bash
# Worker
curl "http://localhost:8787/botTOKEN/getMe"

# Pages  
curl "http://localhost:8788/api/botTOKEN/getMe"
```

### 7. 首次启动 wrangler 超时

**问题：** 执行 `npx wrangler dev` 后没有输出，等很久没反应，以为卡死了。

**原因：** `npx` 首次执行需要下载 wrangler 包（~80MB，含 workerd 二进制），在网络慢时可能耗时 30s 以上。wrangler 4.x 使用全局缓存，第二次启动会快很多。

**解决：**
1. 先安装再执行：`npm install wrangler --save-dev`
2. 安装后首次启动耐心等 10-30 秒
3. 观察 `node_modules` 的大小：`du -sh node_modules/`（wrangler 约 150MB）

### 8. wrangler pages dev 启动后旧进程仍运行

**问题：** 杀掉 wrangler 后重启，提示 Address already in use。

```bash
killall -9 wrangler    # 以为杀了
npx wrangler dev ...   # 报端口被占
```

**原因：** wrangler 通过 Node.js 启动 miniflare，miniflare 再启动 workerd。`killall wrangler` 只杀了 Node.js 进程，workerd 子进程变成孤儿进程继续运行。

**根治：**
```bash
# 1. 先找到所有 workerd
ps aux | grep workerd

# 2. 一键清理
killall -9 workerd node 2>/dev/null

# 3. 确认端口空闲
lsof -i :8787

# 4. 或者用不同的端口完全避免冲突
npx wrangler dev --port 8790
```

> `lsof -ti :端口号` 命令可以直接获取占用某端口的 PID。

### 9. curl 的 Authorization 头顺序问题

**问题：** 测试管理 API 时有时返回 `Unauthorized`，有时成功。

```bash
# ❌ 有时失败
curl "http://localhost:8789/api/admin/tokens" -H "Authorization: Bearer admin123"

# ❌ 顺序影响？
curl -H "Authorization: Bearer admin123" "http://localhost:8789/api/admin/tokens"
```

**实际原因：** 与 curl 参数顺序无关，问题往往出在：
1. 测试脚本中变量 `$PASS` 未正确设置（shell 变量作用域）
2. `.dev.vars` 修改后未重启 wrangler
3. 旧 wrangler 进程仍在运行（实际请求到了旧进程）

**解决：** 总是先确认：

```bash
# 1. 确认 wrangler 启动日志显示加载了 .dev.vars
npx wrangler dev ...
# → 看输出：Using secrets defined in .dev.vars

# 2. 确认杀死旧进程
lsof -i :8787  # 确保端口没被占

# 3. 直接测试
curl -v "http://localhost:8787/api/admin/tokens" \
  -H "Authorization: Bearer admin123"
```

---

## 📝 测试用例编写规范

### 基本模板

```bash
TOKEN="1234567890:AAGkLmNoPqRsTuVwXyZ1234567890X"
PASS=0; FAIL=0

check() {
  local desc="$1"; local expected="$2"; local actual="$3"
  if echo "$actual" | grep -qF "$expected"; then
    echo "  ✅ $desc"; PASS=$((PASS + 1))
  else
    echo "  ❌ $desc"
    echo "      期待包含: $expected"
    echo "      实际: $(echo "$actual" | head -c 200)"
    FAIL=$((FAIL + 1))
  fi
}

# 测试
check "getMe" "ok\":true" "$(curl -s "$BASE/bot$TOKEN/getMe")"

echo "结果: $PASS 通过, $FAIL 失败"
```

### 规则

| # | 规则 | 原因 |
|---|------|------|
| 1 | `grep` 匹配内容**不带外层的引号** | 避免引号匹配问题（踩坑 #5）|
| 2 | 使用 `grep -qF`（固定字符串）而非默认的正则 | 响应 JSON 中的 `.` `{` `[` 等字符在正则中是特殊符号 |
| 3 | URL 中的 Token 用变量 `${TOKEN}` | 避免拼写错误，修改 Token 时只改一处 |
| 4 | 路径遍历测试用 `%2e%2e%2f` 而非 `../` | `../` 会被 URL 类规范化（踩坑 #4）|
| 5 | 测试前确认 wrangler 已启动、端口可访问 | 避免测到旧进程（踩坑 #2, #8）|
| 6 | 修改 `.dev.vars` 后重启 wrangler | env 只在启动时加载一次（踩坑 #1）|
| 7 | Worker/Pages 的 URL 前缀不同 | Worker `/bot`，Pages `/api/bot`（踩坑 #6）|

---

## ⚡ 常见问题速查

| 问题 | 排查步骤 |
|------|---------|
| **端口被占** | `lsof -ti :8787 \| xargs kill -9` |
| **wrangler 启动慢** | 首次下载 ~80MB，耐心等；或先 `npm install wrangler` |
| **401 Invalid bot token** | 检查 `.dev.vars` 的 Token 是否 >= 40 字符；hash 部分 >= 30；botId 全数字 |
| **401 Unauthorized (管理API)** | 确认 `.dev.vars` 有 `ADMIN_PASSWORD`；确认 wrangler 日志显示加载了 env |
| **404** | 确认用对了前缀：Worker `/botTOKEN`，Pages `/api/botTOKEN` |
| **500/超时** | 确认 mock 服务器在运行：`curl http://localhost:9001/botX/getMe` |
| **修改代码后不生效** | wrangler 大部分情况热更新，但 `.dev.vars` 变更和 Pages 版需要重启 |
| **Pages 版请求返回根页面HTML** | 路径没匹配到 `/api/*`，检查 URL 格式 |
| **路径遍历不拦截** | 用 `%2e%2e%2f` 测试（踩坑 #4）|
