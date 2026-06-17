# 🍼 部署指南 — Telegram API 代理

> 本指南面向**零基础用户**，每一步都告诉你点什么、填什么、看到什么算成功。
> 如果你遇到任何一步和描述不一致，请检查你的 Cloudflare 控制台是否为中文/英文界面。

---

## 📋 前置准备

在开始之前，请准备好以下 3 样东西：

| # | 需要准备 | 哪里获取 | 格式示例 |
|---|---------|---------|---------|
| 1 | **Cloudflare 账号** | [dash.cloudflare.com](https://dash.cloudflare.com) 免费注册 | 邮箱 + 密码 |
| 2 | **Bot Token** | 在 Telegram 找 [@BotFather](https://t.me/BotFather) → `/newbot` 创建 | `7234567890:AAGkLmNoPqRsT...` |
| 3 | **GitHub 账号**（仅 Pages 方式需要） | [github.com](https://github.com) 免费注册 | 用户名 + 密码 |

> ⚠️ **Bot Token 是密码！** 不要分享给任何人，不要提交到 GitHub。

---

## 方式一：Cloudflare Pages 部署（推荐，自动更新）

> **特点**：关联 GitHub 仓库后，每次 `git push` 自动部署，无需手动操作。
> **免费额度**：每天 100,000 次请求，个人用完全够。

### 第 1 步：Fork 仓库

1. 打开浏览器访问本仓库：`https://github.com/niudakok/Telegram-API-Proxy`
2. 点击页面右上角的 **Fork** 按钮（🪓 图标旁边）
3. 在弹出的窗口里，**不要修改任何设置**，直接点击 **Create fork**
4. 等待几秒，浏览器会自动跳转到 **你的 GitHub 账号下** 的 `Telegram-API-Proxy` 仓库
   - ✅ **成功标志**：浏览器地址栏显示为 `https://github.com/你的用户名/Telegram-API-Proxy`

### 第 2 步：登录 Cloudflare 并创建 Pages 项目

1. 打开 [dash.cloudflare.com](https://dash.cloudflare.com) 并登录
2. 在左侧菜单栏点击 **Workers & Pages**（如果找不到，先看看有没有 > 箭头，点开更多菜单）
3. 点击 **Create application**（蓝色按钮，在页面右上方）
4. 你会看到两个 Tab：**Workers** 和 **Pages** → 点击 **Pages**（第二个 Tab）
5. 在 **Connect to Git** 那一栏，点击 **Connect to Git** 按钮
   - ✅ **成功标志**：页面跳转到让你选 Git 提供商的页面

> 💡 如果没看到 **Connect to Git** 按钮，而是看到几个卡片（"Connect to Git"、"Direct Upload"、"Create using Workers CLI"），点 **Connect to Git** 那个卡片。

### 第 3 步：关联 GitHub 仓库

1. 如果之前没连过 GitHub，Cloudflare 会要求你授权：
   - 点击 **Connect to GitHub**
   - 弹窗里点击 **Install & Authorize**（或者 "Authorize cloudflare"）
   - ❗ 可能要求输入 GitHub 密码确认
2. 授权完成后，回到 Cloudflare，在 "Install" 下拉框中选择 **Only select repositories**
3. 在仓库列表中找到你刚 **Fork** 的仓库 `Telegram-API-Proxy`，勾选上
4. 点击 **Install & Authorize**（或 **Save**）
5. 回到 Cloudflare，在下方的 **Repository** 下拉框中选择你 Fork 的仓库
6. 点击 **Begin setup**（蓝色按钮）

### 第 4 步：配置构建参数

此时你看到的页面标题是 **"Set up builds and deployments"**，需要填写以下参数：

| 字段名 | 应该填什么 | 注意 |
|--------|-----------|------|
| **Project name** | 随便填，比如 `tg-proxy` | 只能用英文/数字/横杠 |
| **Production branch** | 保持默认 `main` | 不要改 |
| **Build command** | **留空** | 什么都不填 |
| **Build output directory** | **留空** | 什么都不填 |
| **Root directory** | **留空** | 什么都不填 |

**操作步骤：**
1. **Project name**：输入 `tg-proxy`（或你喜欢的名字，这个会作为你的域名前缀）
2. 其他所有输入框都是空的，**不要填任何东西**
3. **Environment variables (advanced)**：点开看也行，但**现在先不要添加**，后面单独操作
4. 点击页面底部的 **Save and Deploy**（蓝色按钮）

### 第 5 步：等待首次部署

1. 点击 **Save and Deploy** 后，页面会跳转到部署日志页面
2. 你会看到一个进度条方块正在跑，显示：
   - `⏱️ Initializing build cache...`
   - `⏱️ Cloning repository...`
   - `⏱️ Building...`
   - `✅ Deployed!` ← 看到这个就是部署成功了
3. 整个过程一般 **30 秒到 2 分钟**
4. ✅ **成功标志**：页面顶部出现 `✨ Success! Your site was deployed!` 绿色提示，下方会显示一个地址，类似：
   ```
   https://tg-proxy.pages.dev
   ```
   - **点击这个地址**，如果看到一个深色背景的页面，写着 "Telegram API 安全网关"，说明部署成功

> ⚠️ 现在先不要着急用，因为还没配置 Bot Token，所有请求都会被拒绝。

### 第 6 步：配置环境变量（最关键！不加谁都别想用）

1. 在 Cloudflare 页面中，找到你刚创建的项目页面
2. 点击 **Settings**（在页面中间偏上的 Tab 区，和 Deployments 并列）
3. 在左侧菜单栏点击 **Environment variables**（环境变量）
4. 点击 **Add variable** 按钮（蓝色）
5. 在弹出的对话框中填写：

   | 字段 | 值（以你自己的 Token 为例） |
   |------|---------------------------|
   | **Name** | `ALLOWED_BOT_TOKENS` |
   | **Value** | `7234567890:AAGkLmNoPqRsTuVwXyZ1234567890`（换成你的实际 Token）|
   | **Encrypt** | 保持**不勾选**（关着的）|

6. 点击 **Save**（蓝色按钮）
7. ✅ **成功标志**：表格里多了一行 `ALLOWED_BOT_TOKENS`

> 💡 **多个 Bot Token**：如果你有多个 Bot 要走这个代理，用英文逗号隔开：
> ```
> 7234567890:AAAA,9876543210:BBBB,111222333:CCCC
> ```
> 注意是**英文逗号** `,` 不是中文逗号 `，`

8. ⭐ **（可选）配置管理后台密码：**
   - 再次点击 **Add variable**
   - Name: `ADMIN_PASSWORD`，Value: 你自己设一个密码（比如 `MyAdmin123`）
   - 点击 **Save**

### 第 7 步：重新部署使配置生效

> Pages 的环境变量**不是立即生效**的，必须重新部署一次。

1. 点击 **Deployments** Tab（在 Settings 的左边）
2. 你会看到一条部署记录，旁边有一个 **❇️ Retry deployment** 按钮（三个点 `···` 或直接显示）
   - 点击 **Retry deployment**（或者点 `···` → **Retry deployment**）
3. 等待部署完成（再次看到 `✅ Deployed`）
4. ✅ **成功标志**：新部署记录的时间戳是刚刚的时间

### 🎉 完成！

你的代理地址：
```
https://tg-proxy.pages.dev/api/bot<你的Token>/<方法名>
```

**立即测试：**
```bash
# 打开终端（CMD / PowerShell / Terminal），把域名和 Token 换成你的
curl "https://tg-proxy.pages.dev/api/bot7234567890:AAGk/getMe"
```

**预期返回（类似这样）：**
```json
{"ok":true,"result":{"id":7234567890,"is_bot":true,"first_name":"你的Bot名字"}}
```

> ❌ 如果返回 `401 Invalid bot token`：检查 `ALLOWED_BOT_TOKENS` 是否填对，然后重新部署。
> ❌ 如果返回 `404`：检查 URL 路径是不是 `/api/bot`，不是 `/bot`。Pages 方式必须是 `/api/bot`。

---

## 方式二：Cloudflare Workers 部署（手动粘贴）

> **特点**：无需 GitHub，直接在网页里粘贴代码。适合不想用 GitHub 的用户。
> **注意**：更新代码需要手动重新粘贴，不能自动同步。

### 第 1 步：获取 worker.js 的完整代码

你需要在本地或者直接从 GitHub 上获取代码内容。

**方法 A — 从本地获取（如果你已经 git clone）：**
```bash
# 打开终端，进入项目目录，运行：
cat manual-worker/worker.js
# 全选并复制终端输出的全部内容
```

**方法 B — 从 GitHub 网页获取：**
1. 在浏览器打开 `https://github.com/niudakok/Telegram-API-Proxy/blob/main/manual-worker/worker.js`
2. 点击文件内容右上角的 **Raw** 按钮（或 Copy raw file）
3. 全选（Ctrl+A / Cmd+A）并复制全部代码

> ⚠️ 一定要复制**全部内容**，不要漏掉第一行 `// Telegram API Proxy...`

### 第 2 步：创建 Worker

1. 打开 [dash.cloudflare.com](https://dash.cloudflare.com) 并登录
2. 点击左侧菜单的 **Workers & Pages**
3. 点击 **Create application**
4. 这次选择 **Workers** Tab（默认就是 Workers）
5. 在 **Create Worker** 卡片下，点击 **Create Worker**（蓝色按钮）
6. 在弹出的对话框里给 Worker 起个名，比如 `tg-proxy-worker`
   - **Name**：输入 `tg-proxy-worker`
   - 点击 **Deploy**（蓝色按钮）

### 第 3 步：粘贴代码

1. 部署完成后，点击 **Edit code**（蓝色按钮）
2. 你会看到一个在线的代码编辑器，左侧是文件列表，中间是代码
3. **全选**编辑器里的默认代码（Ctrl+A / Cmd+A），**按 Delete 删掉**
4. **粘贴**你刚才复制的 `worker.js` 全部代码（Ctrl+V / Cmd+V）
5. 按 **Ctrl+S**（Mac: Cmd+S）保存
6. ✅ **成功标志**：保存按钮变灰，编辑器没有报红（红色波浪线）

### 第 4 步：配置 Secrets（加密变量）

> ⚠️ **重要**：这里必须用 **Secrets**（加密变量），不要用普通的环境变量。
> Secrets 不会被 `wrangler.toml` 覆盖，Token 才能持久保存。

1. 点击 **Settings** Tab（在编辑器上方）
2. 在左侧菜单点击 **Variables**（变量）
3. **往下滚动**，找到 **Secrets** 这个栏目（在页面下方，不是上面的 Environment Variables）
4. 点击 **Add variable**（蓝色按钮）

**首先添加必须的 Token 白名单：**

| 字段 | 值 |
|------|-----|
| **Name** | `ALLOWED_BOT_TOKENS` |
| **Value** | 你的 Bot Token（如 `7234567890:AAGkLmNoPqRsTuVwXyZ1234567890`）|
| **Type** | 默认是 **Secret**，不用改 |

1. 点击 **Add variable** → 在弹出的对话框里输入 Name 和 Value
2. 点击 **Encrypt** 按钮（绿色，点一下）
3. 点击 **Add**（蓝色按钮）
4. ✅ **成功标志**：Secrets 表格里多了一行 `ALLOWED_BOT_TOKENS`

**（可选）添加管理后台密码：**
1. 再次点击 **Add variable**
2. Name: `ADMIN_PASSWORD`，Value: 你的管理员密码
3. 点击 **Encrypt** → **Add**

### 第 5 步：部署生效

1. 配置好 Secrets 后，环境变量是**自动生效**的，不需要重新部署
2. 回到 Worker 页面顶部，会显示你的 Worker 地址：
   ```
   https://tg-proxy-worker.你的用户名.workers.dev
   ```

### 🎉 完成！

你的代理地址：
```
https://tg-proxy-worker.你的用户名.workers.dev/bot<你的Token>/<方法名>
```

**立即测试：**
```bash
curl "https://tg-proxy-worker.你的用户名.workers.dev/bot7234567890:AAGk/getMe"
```

**预期返回：**
```json
{"ok":true,"result":{"id":7234567890,"is_bot":true,"first_name":"你的Bot名字"}}
```

> ❌ 如果返回 `401`：检查 Secrets 里的 `ALLOWED_BOT_TOKENS` 是否写对了。
> ❌ 如果返回 `404`：检查路径是不是 `/bot` 开头，Workers 方式**没有** `/api` 前缀。

---

## 方式三：使用 wrangler CLI 部署（开发者用）

> 适合有命令行经验、需要本地调试的开发者。

### 前置安装

```bash
# 1. 确认 Node.js 已安装（需要 18+ 版本）
node -v

# 2. 安装 wrangler（全局安装，一次即可）
npm install -g wrangler

# 3. 登录 Cloudflare（浏览器会弹窗让你授权）
wrangler login
```

### 部署 Worker 版

```bash
# 进入项目目录
cd Telegram-API-Proxy

# 部署（会自动读取 wrangler.toml 的配置）
wrangler deploy

# 设置 Secrets（部署后执行，Token 不会暴露在代码里）
echo "7234567890:AAGk..." | wrangler secret put ALLOWED_BOT_TOKENS
echo "MyAdmin123" | wrangler secret put ADMIN_PASSWORD
```

### 部署 Pages 版

```bash
cd Telegram-API-Proxy

# 部署 Pages 项目
npx wrangler pages deploy .
```

### 本地预览

```bash
# 预览 Worker 版（在 http://localhost:8787 运行）
wrangler dev manual-worker/worker.js

# 预览 Pages 版（在 http://localhost:8788 运行）
npx wrangler pages dev .
```

---

## ✅ 验证部署（通用）

无论用哪种方式部署，都可以用以下方法验证：

### 方法 1：curl 测试

```bash
# Pages 方式
curl "https://你的项目名.pages.dev/api/bot你的Token/getMe"

# Workers 方式
curl "https://你的worker名.你的用户名.workers.dev/bot你的Token/getMe"
```

### 方法 2：浏览器访问

直接在浏览器地址栏输入上面的 URL，如果看到类似这样的 JSON：
```json
{"ok":true,"result":{"id":7234567890,"is_bot":true,"first_name":"MyBot"}}
```
就是成功了 ✅

### 方法 3：访问根页面

浏览器打开你的代理域名根路径（如 `https://tg-proxy.pages.dev`），应该看到一个深色背景的页面，写着：
- "Telegram API 安全网关"
- "系统运行正常"

### 方法 4：访问管理后台

浏览器打开 `https://你的域名/admin`，如果配置了 `ADMIN_PASSWORD`，会显示一个登录框，输入密码后可管理 Token。

---

## ⚠️ 常见部署错误

| 错误现象 | 原因 | 解决方法 |
|---------|------|---------|
| `401 Invalid bot token` | Token 不在白名单里 | 检查 `ALLOWED_BOT_TOKENS` 是否填对了 Token，然后重新部署 |
| `401 Unauthorized` | 管理后台密码错误 | 检查你的 `Authorization` 头是否用了正确的密码 |
| `404 Endpoint not found` | URL 路径写错了 | Pages 用 `/api/bot`，Workers 用 `/bot`，注意区别 |
| 浏览器显示空白或 "Not Found" | 路径不对 | 确保 URL 末尾没有多余的斜杠 `/` |
| 访问 `/.env` 或类似路径 | 没影响，直接 404 | 这是正常的，本项目没有 `.env` 文件 |
| 部署 Pages 后访问还是旧代码 | 环境变量未生效 | 去 Deployments 页面点 **Retry deployment** |
| `err_code: 10021` 类似错误 | Cloudflare Workers 并发数超限 | 这是免费计划限制，代码会自动重试，稍后再试 |

---

## 🔄 更新代码

### Pages 方式

1. 在本地修改代码后 `git push` 到你的 GitHub 仓库
2. Cloudflare 会自动检测到变化，**自动部署**
3. 等待 1-2 分钟，新代码自动生效
4. ✅ 可在 **Deployments** 页面看到新的部署记录

### Workers 方式

1. 打开 Cloudflare 控制台 → Workers & Pages → 你的 Worker
2. 点击 **Edit code**
3. 把新代码粘贴进去，覆盖旧代码
4. 按 **Ctrl+S** 保存，**自动生效**
