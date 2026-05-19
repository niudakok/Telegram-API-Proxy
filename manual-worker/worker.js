// Telegram API Proxy - Workers Version (ES Module)
// Author: Anonymous (Modded by Antigravity)

const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;
const FILE_PATH_REGEX = /^\/file\/bot(?<bot_token>[^/]+)\/(?<file_id>.+)$/i;

const RATE_LIMITS = {
    IP: { max: 100, window: 60000 },
    TOKEN: { max: 200, window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST: { max: 10, window: 1000 }
};

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];

let stats = {
    startTime: Date.now(),
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    rateLimited: 0,
    blocked: 0,
    retries: 0,
    avgResponseTime: 0,
    lastReset: Date.now()
};

const requestCounters = {
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

export default {
    async fetch(request, env, ctx) {
        return handleRequest(request, env);
    }
};

async function handleRequest(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.toLowerCase().replace(/\/$/, "");

    if (pathname === '/stats') {
        return handleStatsRequest();
    }

    if (pathname === '' || pathname === '/') {
        return handleRootRequest(request);
    }

    // 管理页面
    if (pathname === '/admin') {
        return new Response(ADMIN_HTML, {
            status: 200,
            headers: { 'content-type': 'text/html;charset=UTF-8' }
        });
    }

    // 管理 API
    if (pathname.startsWith('/api/admin/')) {
        return handleAdminApiRequest(request, pathname, env);
    }

    if (request.method === 'OPTIONS') {
        return handleCorsPreflightRequest();
    }

    // 文件代理路径匹配
    const rawPathname = url.pathname;
    if (FILE_PATH_REGEX.test(rawPathname)) {
        const startTime = Date.now();
        try {
            await cleanupExpiredData();

            // 安全检查
            const securityCheck = performAdvancedSecurityChecks(request);
            if (securityCheck.blocked) {
                stats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }

            const fileInfo = parseFileRequest(request);
            if (!fileInfo.valid) {
                stats.blocked++;
                return createErrorResponse('Invalid file request format', 400);
            }

            // Token 验证
            const tokenValid = await validateBotToken(fileInfo.botToken, env);
            if (!tokenValid) {
                stats.blocked++;
                return createErrorResponse('Invalid or unauthorized bot token', 401);
            }

            const response = await proxyFileFromTelegram(fileInfo);
            updateStats(startTime, response.ok);
            return response;

        } catch (error) {
            console.error('File proxy error:', error);
            stats.failedRequests++;
            return createErrorResponse(error.message, 500);
        }
    }

    // 原始路径匹配 (不转小写，因为 Token 大小写敏感)
    if (URL_PATH_REGEX.test(rawPathname)) {
        const startTime = Date.now();
        try {
            await cleanupExpiredData();

            // 安全检查
            const securityCheck = performAdvancedSecurityChecks(request);
            if (securityCheck.blocked) {
                stats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }

            const requestInfo = parseRequest(request);
            if (!requestInfo.valid) {
                stats.blocked++;
                return createErrorResponse('Invalid request format', 400);
            }

            // 频率限制
            if (checkGlobalRateLimit()) {
                stats.rateLimited++;
                return createRateLimitResponse(60);
            }

            // Token 验证
            const tokenValid = await validateBotToken(requestInfo.botToken, env);
            if (!tokenValid) {
                stats.blocked++;
                return createErrorResponse('Invalid or unauthorized bot token', 401);
            }

            const response = await proxyToTelegram(request, requestInfo);
            updateStats(startTime, response.ok);
            return response;

        } catch (error) {
            console.error('Proxy error:', error);
            stats.failedRequests++;
            return createErrorResponse(error.message, 500);
        }
    }

    return handle404Request();
}

// ==========================================
// 核心业务函数
// ==========================================

async function validateBotToken(token, env) {
    const allowedTokens = env.ALLOWED_BOT_TOKENS;
    if (!allowedTokens) {
        console.error('[Security] ALLOWED_BOT_TOKENS not configured.');
        return false;
    }

    const allowedList = allowedTokens.split(',').map(t => t.trim()).filter(t => t.length > 0);
    if (!allowedList.includes(token)) {
        return false;
    }

    if (!token.includes(':') || token.length < 30) return false;
    return true;
}

function parseFileRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(FILE_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: match.groups.bot_token,
        fileId: match.groups.file_id
    };
}

async function proxyFileFromTelegram(fileInfo) {
    const fileUrl = `https://api.telegram.org/file/bot${fileInfo.botToken}/${fileInfo.fileId}`;
    
    const headers = new Headers();
    headers.set('User-Agent', 'Cloudflare-Worker-Proxy/2.0');
    
    try {
        const response = await fetch(fileUrl, {
            method: 'GET',
            headers: headers,
            redirect: 'follow'
        });
        
        const respHeaders = new Headers(response.headers);
        respHeaders.set('Access-Control-Allow-Origin', '*');
        respHeaders.set('Cache-Control', 'public, max-age=3600'); // 1 小时缓存
        
        return new Response(response.body, {
            status: response.status,
            headers: respHeaders
        });
    } catch (error) {
        console.error('File download error:', error);
        throw error;
    }
}

function performAdvancedSecurityChecks(request) {
    if (!ALLOWED_METHODS.includes(request.method)) {
        return { blocked: true, reason: 'Method Forbidden', status: 405 };
    }
    const url = new URL(request.url);
    const MALICIOUS_PATTERNS = [/(\.\.|\/\.\/|\\\.\\|%2e%2e|%252e%252e)/i, /<script[^>]*>/i];
    for (const pattern of MALICIOUS_PATTERNS) {
        if (pattern.test(url.pathname) || pattern.test(url.search)) {
            return { blocked: true, reason: 'Security violation', status: 400 };
        }
    }
    return { blocked: false };
}

function parseRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(URL_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: match.groups.bot_token,
        apiMethod: match.groups.api_method,
        path: url.pathname + url.search
    };
}

async function proxyToTelegram(request, info) {
    const newUrl = "https://api.telegram.org" + info.path;
    const headers = new Headers(request.headers);
    headers.delete('host');
    headers.set('User-Agent', 'Cloudflare-Worker-Proxy/2.0');

    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        const contentType = request.headers.get('content-type') || '';
        if (info.apiMethod === 'setWebhook') {
            if (contentType.includes('multipart/form-data')) {
                const formData = await request.formData();
                // 处理 setWebhook 方法，确保 proxy_url 正确设置
                if (formData.has('proxy_url')) {
                    // 移除 proxy_url 参数，让 Telegram 直接使用我们的代理地址
                    formData.delete('proxy_url');
                }
                body = formData;
                headers.delete('content-type');
            } else {
                // 处理 JSON 格式的 setWebhook 请求
                const bodyText = await request.text();
                try {
                    const bodyJson = JSON.parse(bodyText);
                    // 移除 proxy_url 参数
                    if (bodyJson.proxy_url) {
                        delete bodyJson.proxy_url;
                    }
                    body = JSON.stringify(bodyJson);
                    headers.set('Content-Type', 'application/json');
                } catch {
                    // 如果不是有效的 JSON，直接使用原始请求体
                    body = bodyText;
                }
            }
        } else {
            body = await request.clone().arrayBuffer();
        }
    }

    const response = await fetch(newUrl, {
        method: request.method,
        headers: headers,
        body: body,
        redirect: 'follow'
    });

    const respHeaders = new Headers(response.headers);
    respHeaders.set('Access-Control-Allow-Origin', '*');

    return new Response(response.body, {
        status: response.status,
        headers: respHeaders
    });
}

// ==========================================
// 管理后台逻辑
// ==========================================

async function handleAdminApiRequest(request, pathname, env) {
    const auth = request.headers.get('Authorization');
    const pwd = env.ADMIN_PASSWORD;
    if (!pwd || auth !== `Bearer ${pwd}`) {
        return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
    }

    if (request.method === 'GET' && pathname === '/api/admin/tokens') {
        const t = env.ALLOWED_BOT_TOKENS || '';
        return new Response(JSON.stringify({ tokens: t }), { headers: { 'content-type': 'application/json' } });
    }

    if (request.method === 'POST' && pathname === '/api/admin/tokens') {
        try {
            const { tokens } = await request.json();
            const result = await updateCloudflareEnv('ALLOWED_BOT_TOKENS', tokens, env);
            return new Response(JSON.stringify(result), {
                status: result.success ? 200 : 400,
                headers: { 'content-type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 });
        }
    }
    return new Response('Not Found', { status: 404 });
}

async function updateCloudflareEnv(key, value, env) {
    const accId = env.CF_ACCOUNT_ID;
    const scName = env.CF_SCRIPT_NAME;
    const apiTok = env.CF_API_TOKEN;

    if (!accId || !scName || !apiTok) {
        return { success: false, error: '未配置 CF_ACCOUNT_ID/CF_SCRIPT_NAME/CF_API_TOKEN' };
    }

    try {
        // 尝试使用 Secrets API 进行更新，这样既可以更新普通变量也可以更新 Secret，且不干扰其他绑定
        const url = `https://api.cloudflare.com/client/v4/accounts/${accId}/workers/scripts/${scName}/secrets`;
        const res = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiTok}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: key,
                text: value,
                type: 'secret_text'
            })
        });

        const data = await res.json();
        if (data.success) {
            return { success: true };
        } else {
            const err = data.errors?.[0]?.message || '更新失败';
            // 如果 Secrets API 不适用（例如脚本不存在或其他原因），返回详细错误
            return { success: false, error: `CF API 报错: ${err}` };
        }
    } catch (e) {
        return { success: false, error: '网络或系统异常: ' + e.message };
    }
}

// ==========================================
// 基础工具函数
// ==========================================

function handleStatsRequest() {
    return new Response(JSON.stringify(stats), { headers: { 'content-type': 'application/json' } });
}

function handle404Request() {
    return new Response(JSON.stringify({ ok: false, error: 'Endpoint not found' }), { status: 404 });
}

function handleRootRequest(request) {
    const workerUrl = new URL(request.url).origin;
    return new Response(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>Telegram Proxy</title><style>body{background:#121212;color:white;font-family:sans-serif;text-align:center;padding:50px}a{color:#61dafb}</style></head>
<body><h1>Telegram API 代理服务</h1><p>系统运行中...</p><p>管理入口: <a href="/admin">/admin</a></p></body></html>`, {
        headers: { 'content-type': 'text/html;charset=UTF-8' }
    });
}

function checkGlobalRateLimit() {
    const now = Date.now();
    if (now > requestCounters.global.resetTime) {
        requestCounters.global.count = 0;
        requestCounters.global.resetTime = now + RATE_LIMITS.GLOBAL.window;
    }
    requestCounters.global.count++;
    return requestCounters.global.count > RATE_LIMITS.GLOBAL.max;
}

async function cleanupExpiredData() { }
function updateStats(startTime, ok) {
    stats.totalRequests++;
    if (!ok) stats.failedRequests++;
    stats.avgResponseTime = (stats.avgResponseTime + (Date.now() - startTime)) / 2;
}

function createErrorResponse(err, status) {
    return new Response(JSON.stringify({ ok: false, error: err }), { status, headers: { 'content-type': 'application/json' } });
}

function createRateLimitResponse(retry) {
    return new Response(JSON.stringify({ ok: false, error: 'Rate limit' }), { status: 429, headers: { 'Retry-After': retry, 'content-type': 'application/json' } });
}

function handleCorsPreflightRequest() {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': '*' } });
}

const ADMIN_HTML = `
<!DOCTYPE html>
<html lang="zh-CN">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token 管理后台</title>
    <style>
        body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); width: 100%; max-width: 680px; }
        h1 { margin-top: 0; font-size: 1.5rem; color: #111827; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; color: #374151; }
        textarea, input { width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; }
        textarea { min-height: 96px; font-family: monospace; resize: vertical; }
        button { width: 100%; background: #2563eb; color: white; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px; transition: background 0.2s; }
        button:hover { background: #1d4ed8; }
        #msg { margin-top: 15px; padding: 10px; border-radius: 4px; display: none; font-size: 0.9rem; }
        .help-text { font-size: 0.8rem; color: #6b7280; margin-top: 4px; }
        .token-toolbar { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; margin-bottom: 10px; }
        .ghost-btn, .danger-btn { width: auto; margin-top: 0; padding: 10px 12px; }
        .ghost-btn { background: #f9fafb; color: #1f2937; border: 1px solid #d1d5db; }
        .ghost-btn:hover { background: #f3f4f6; }
        .danger-btn { background: #dc2626; }
        .danger-btn:hover { background: #b91c1c; }
        .token-list { border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px; max-height: 260px; overflow-y: auto; background: #fafafa; }
        .token-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 8px; border-radius: 4px; background: white; border: 1px solid #e5e7eb; margin-bottom: 6px; }
        .token-item:last-child { margin-bottom: 0; }
        .token-text { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; color: #111827; }
        .token-meta { font-size: 0.75rem; color: #6b7280; margin-top: 2px; }
        .remove-btn { width: auto; margin: 0; padding: 6px 10px; background: #ef4444; font-size: 0.8rem; }
        .remove-btn:hover { background: #dc2626; }
        .empty { padding: 16px; text-align: center; color: #6b7280; font-size: 0.9rem; }
        .bad-token { color: #b91c1c; font-size: 0.8rem; margin-top: 6px; }
        #tk { display: none; }
    </style>
</head>

<body>
    <div class="box">
        <h1>Token 管理后台</h1>
        <div class="form-group">
            <label>管理员密码</label>
            <input type="password" id="pw" placeholder="输入 ADMIN_PASSWORD">
        </div>
        <button onclick="load()">连接并获取配置</button>

        <div id="editor" style="display:none; margin-top: 20px;">
            <div class="form-group">
                <label>允许的 Bot Tokens</label>
                <div class="token-toolbar">
                    <input id="newToken" placeholder="例如: 123456:ABCDEF..." onkeydown="if(event.key==='Enter'){event.preventDefault();addToken();}">
                    <button class="ghost-btn" onclick="addToken()">添加</button>
                    <button class="danger-btn" onclick="clearTokens()">清空</button>
                </div>
                <div id="badTokenMsg" class="bad-token" style="display:none;"></div>
                <div id="tokenList" class="token-list"></div>
                <textarea id="tk" placeholder="123456:ABC...,789012:DEF..."></textarea>
                <div class="help-text">支持逐条添加、删除和去重；保存时会自动转换成环境变量格式。</div>
            </div>
            <button onclick="save()">保存并应用</button>
        </div>
        <div id="msg"></div>
    </div>
    <script>
        const msg = document.getElementById('msg');
        const tokenListEl = document.getElementById('tokenList');
        const badTokenMsg = document.getElementById('badTokenMsg');
        let tokenList = [];

        function show(txt, err) {
            msg.innerText = txt;
            msg.style.display = 'block';
            msg.style.background = err ? '#fee2e2' : '#d1fae5';
            msg.style.color = err ? '#991b1b' : '#065f46';
            if (!err) setTimeout(() => msg.style.display = 'none', 5000);
        }

        const apiPath = '/api/admin/tokens';

        function normalizeToken(token) { return token.trim(); }
        function isValidToken(token) { return /^\\d{5,}:[\\w-]{10,}$/.test(token); }
        function maskToken(token) {
            const i = token.indexOf(':');
            if (i < 0) return token;
            const prefix = token.slice(0, i + 1);
            const secret = token.slice(i + 1);
            if (secret.length <= 8) return prefix + '********';
            return prefix + secret.slice(0, 4) + '...' + secret.slice(-4);
        }

        function parseTokens(raw) {
            return [...new Set(raw.split(',').map(normalizeToken).filter(Boolean))];
        }

        function syncTextarea() {
            document.getElementById('tk').value = tokenList.join(',');
        }

        function renderTokens() {
            tokenListEl.innerHTML = '';
            if (!tokenList.length) {
                tokenListEl.innerHTML = '<div class="empty">暂无 Token，请添加至少一个。</div>';
                syncTextarea();
                return;
            }
            tokenList.forEach((token, idx) => {
                const item = document.createElement('div');
                item.className = 'token-item';
                item.innerHTML = \`<div><div class="token-text">\${maskToken(token)}</div><div class="token-meta">#\${idx + 1} · \${isValidToken(token) ? '格式正常' : '格式可能有误'}</div></div><button class="remove-btn" onclick="removeToken(\${idx})">删除</button>\`;
                tokenListEl.appendChild(item);
            });
            syncTextarea();
        }

        function addToken() {
            const input = document.getElementById('newToken');
            const token = normalizeToken(input.value);
            if (!token) return;
            if (tokenList.includes(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = '该 Token 已存在，已自动忽略重复项。';
                return;
            }
            if (!isValidToken(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = 'Token 格式看起来不正确（应类似 123456:ABC...），请确认后再添加。';
                return;
            }
            badTokenMsg.style.display = 'none';
            tokenList.push(token);
            input.value = '';
            renderTokens();
        }

        function removeToken(idx) {
            tokenList.splice(idx, 1);
            renderTokens();
        }

        function clearTokens() {
            tokenList = [];
            renderTokens();
        }

        async function load() {
            const p = document.getElementById('pw').value;
            if (!p) return show('请输入密码', true);
            try {
                const res = await fetch(apiPath, { headers: { 'Authorization': 'Bearer ' + p } });
                if (res.ok) {
                    const d = await res.json();
                    tokenList = parseTokens(d.tokens || '');
                    document.getElementById('editor').style.display = 'block';
                    renderTokens();
                    show(\`连接成功，已加载 \${tokenList.length} 个 Token\`, false);
                } else {
                    const d = await res.json().catch(() => ({}));
                    show(d.error || '认证失败，请检查密码', true);
                }
            } catch (e) {
                show('网络错误，请确认服务已正确部署', true);
            }
        }

        async function save() {
            const p = document.getElementById('pw').value;
            const t = document.getElementById('tk').value;
            if (!tokenList.length) return show('请至少保留一个 Token 再保存', true);
            try {
                const res = await fetch(apiPath, {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + p, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tokens: t })
                });
                if (res.ok) {
                    show(\`保存成功！已提交 \${tokenList.length} 个 Token，约几秒后生效。\`, false);
                } else {
                    const d = await res.json().catch(() => ({}));
                    show(d.error || '保存失败，请检查 API 权限配置', true);
                }
            } catch (e) {
                show('网络错误', true);
            }
        }
    </script>
</body>

</html>
`;
                tokenListEl.appendChild(item);
            });
            syncTextarea();
        }

        function addToken() {
            const input = document.getElementById('newToken');
            const token = normalizeToken(input.value);
            if (!token) return;
            if (tokenList.includes(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = '该 Token 已存在，已自动忽略重复项。';
                return;
            }
            if (!isValidToken(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = 'Token 格式看起来不正确（应类似 123456:ABC...），请确认后再添加。';
                return;
            }
            badTokenMsg.style.display = 'none';
            tokenList.push(token);
            input.value = '';
            renderTokens();
        }

        function removeToken(idx) {
            tokenList.splice(idx, 1);
            renderTokens();
        }

        function clearTokens() {
            tokenList = [];
            renderTokens();
        }

        async function load() {
            const p = document.getElementById('pw').value;
            if (!p) return show('请输入密码', true);
            try {
                const res = await fetch(apiPath, { headers: { 'Authorization': 'Bearer ' + p } });
                if (res.ok) {
                    const d = await res.json();
                    tokenList = parseTokens(d.tokens || '');
                    document.getElementById('editor').style.display = 'block';
                    renderTokens();
                    show(\`连接成功，已加载 \${tokenList.length} 个 Token\`, false);
                } else {
                    const d = await res.json().catch(() => ({}));
                    show(d.error || '认证失败，请检查密码', true);
                }
            } catch (e) {
                show('网络错误，请确认服务已正确部署', true);
            }
        }

        async function save() {
            const p = document.getElementById('pw').value;
            const t = document.getElementById('tk').value;
            if (!tokenList.length) return show('请至少保留一个 Token 再保存', true);
            try {
                const res = await fetch(apiPath, {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + p, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tokens: t })
                });
                if (res.ok) {
                    show(\`保存成功！已提交 \${tokenList.length} 个 Token，约几秒后生效。\`, false);
                } else {
                    const d = await res.json().catch(() => ({}));
                    show(d.error || '保存失败，请检查 API 权限配置', true);
                }
            } catch (e) {
                show('网络错误', true);
            }
        }
    </script>
</body>

</html>
`;
                tokenListEl.appendChild(item);
            });
            syncTextarea();
        }
        function addToken() {
            const input = document.getElementById('newToken');
            const token = normalizeToken(input.value);
            if (!token) return;
            if (tokenList.includes(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = '该 Token 已存在，已自动忽略重复项。';
                return;
            }
            if (!isValidToken(token)) {
                badTokenMsg.style.display = 'block';
                badTokenMsg.innerText = 'Token 格式看起来不正确（应类似 123456:ABC...），请确认后再添加。';
                return;
            }
            badTokenMsg.style.display = 'none';
            tokenList.push(token);
            input.value = '';
            renderTokens();
        }
        function removeToken(idx) { tokenList.splice(idx, 1); renderTokens(); }
        function clearTokens() { tokenList = []; renderTokens(); }

        async function load() {
            const p = document.getElementById('pw').value;
            if (!p) return show('请输入密码', true);
            try {
                const res = await fetch('/api/admin/tokens', { headers: { 'Authorization': 'Bearer ' + p } });
                const d = await res.json().catch(() => ({}));
                if (res.ok) {
                    tokenList = parseTokens(d.tokens || '');
                    document.getElementById('editor').style.display = 'block';
                    renderTokens();
                    show(`连接成功，已加载 ${tokenList.length} 个 Token`, false);
                } else {
                    show(d.error || '认证失败，请检查密码', true);
                }
            } catch (e) {
                show('网络错误，请确认服务已正确部署', true);
            }
        }

        async function save() {
            const p = document.getElementById('pw').value;
            const t = document.getElementById('tk').value;
            if (!tokenList.length) return show('请至少保留一个 Token 再保存', true);
            try {
                const res = await fetch('/api/admin/tokens', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + p, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tokens: t })
                });
                const d = await res.json().catch(() => ({}));
                if (res.ok && d.success) {
                    show(`保存成功！已提交 ${tokenList.length} 个 Token，约几秒后生效。`, false);
                } else {
                    show(d.error || '保存失败，请检查 API 权限配置', true);
                }
            } catch (e) {
                show('网络错误', true);
            }
        }
    </script>
</body>
</html>
`;