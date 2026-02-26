// Telegram API Proxy - Workers Version
// Author: Anonymous (Modded by Antigravity)

const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;

const RATE_LIMITS = {
    IP: { max: 100, window: 60000 },
    TOKEN: { max: 200, window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST: { max: 10, window: 1000 }
};

const CIRCUIT_BREAKER = {
    FAILURE_THRESHOLD: 5,
    TIMEOUT: 30000,
    HALF_OPEN_MAX_CALLS: 3
};

const RETRY_CONFIG = {
    MAX_RETRIES: 3,
    INITIAL_DELAY: 1000,
    MAX_DELAY: 8000,
    BACKOFF_FACTOR: 2
};

const requestCounters = {
    ip: new Map(),
    token: new Map(),
    burst: new Map(),
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

const circuitBreakers = new Map();
const tokenValidationCache = new Map();
const suspiciousIPs = new Map();
const CACHE_TTL = 300000;
const SUSPICIOUS_THRESHOLD = 10;

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const MAX_BODY_SIZE = 50 * 1024 * 1024;
const ALLOWED_COUNTRIES = []; // 已去除国家限制
const BLOCKED_COUNTRIES = [];
const ALLOWED_USER_AGENTS = /telegram|bot|curl|postman|httpie|axios|fetch/i;
const BLOCKED_USER_AGENTS = /scanner|crawler|spider|bot.*attack|sqlmap|nikto|nmap/i;

const TELEGRAM_ENDPOINTS = [
    'api.telegram.org',
    'api.telegram.org:443',
    'api.telegram.org:80'
];

const CACHE_CONFIGS = {
    getChatMember: { ttl: 300, edge: true },
    getMe: { ttl: 3600, edge: true },
    getUpdates: { ttl: 0, edge: false },
    sendMessage: { ttl: 0, edge: false },
    sendPhoto: { ttl: 0, edge: false },
    sendDocument: { ttl: 0, edge: false },
    sendVideo: { ttl: 0, edge: false },
    sendAudio: { ttl: 0, edge: false },
    sendVoice: { ttl: 0, edge: false },
    sendAnimation: { ttl: 0, edge: false },
    sendSticker: { ttl: 0, edge: false },
    sendVideoNote: { ttl: 0, edge: false },
    sendMediaGroup: { ttl: 0, edge: false },
    getChat: { ttl: 600, edge: true },
    getChatAdministrators: { ttl: 1800, edge: true }
};

const MALICIOUS_PATTERNS = [
    /(\.\.|\/\.\/|\\\.\\|%2e%2e|%252e%252e)/i,
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi,
    /eval\s*\(/gi,
    /union\s+select/gi,
    /(\bor\b|\band\b)\s+\d+\s*=\s*\d+/gi
];

const FILE_UPLOAD_METHODS = new Set([
    'sendPhoto', 'sendDocument', 'sendVideo', 'sendAudio',
    'sendVoice', 'sendAnimation', 'sendSticker', 'sendVideoNote',
    'sendMediaGroup', 'setChatPhoto', 'uploadStickerFile',
    'createNewStickerSet', 'addStickerToSet', 'setStickerSetThumb'
]);

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

// ==========================================
// 主请求入口
// ==========================================

addEventListener('fetch', (event) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    const pathname = url.pathname.toLowerCase().replace(/\/$/, ""); // 归一化路径，去除末尾斜杠

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
        return handleAdminApiRequest(request, pathname);
    }

    if (request.method === 'OPTIONS') {
        return handleCorsPreflightRequest();
    }

    // 原始路径匹配 (不转小写，因为 Token 大小写敏感)
    const rawPathname = url.pathname;
    if (URL_PATH_REGEX.test(rawPathname)) {
        const startTime = Date.now();
        try {
            await cleanupExpiredData();

            const securityCheck = await performAdvancedSecurityChecks(request);
            if (securityCheck.blocked) {
                stats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }

            const requestInfo = await parseRequest(request);
            if (!requestInfo.valid) {
                stats.blocked++;
                return createErrorResponse('Invalid request format', 400);
            }

            const circuitState = checkCircuitBreaker(requestInfo.clientIP);
            if (circuitState === 'OPEN') {
                return createErrorResponse('Service temporarily unavailable', 503);
            }

            const rateLimitResult = await checkAdvancedRateLimit(requestInfo.clientIP, requestInfo.botToken);
            if (rateLimitResult.limited) {
                stats.rateLimited++;
                return createRateLimitResponse(rateLimitResult.retryAfter);
            }

            const tokenValid = await validateBotTokenAdvanced(requestInfo.botToken);
            if (!tokenValid) {
                await recordSuspiciousActivity(requestInfo.clientIP, 'invalid_token');
                stats.blocked++;
                return createErrorResponse('Invalid bot token', 401);
            }

            const response = await proxyToTelegramWithRetry(request, requestInfo);

            updateCircuitBreaker(requestInfo.clientIP, response.ok);
            updateStats(startTime, response.ok);

            return response;

        } catch (error) {
            console.error('Proxy error:', error);
            stats.failedRequests++;
            updateCircuitBreaker(getClientIP(request), false);
            return handleProxyError(error);
        }
    }

    return handle404Request();
}

// ==========================================
// 业务处理逻辑
// ==========================================

function handleStatsRequest() {
    const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
    const successful = stats.totalRequests - stats.failedRequests - stats.blocked - stats.rateLimited;

    return new Response(JSON.stringify({
        ok: true,
        uptime,
        totalRequests: stats.totalRequests,
        successfulRequests: Math.max(0, successful),
        failedRequests: stats.failedRequests,
        rateLimited: stats.rateLimited,
        blocked: stats.blocked,
        retries: stats.retries,
        avgLatency: Math.floor(stats.avgResponseTime)
    }), {
        status: 200,
        headers: {
            'content-type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

function handle404Request() {
    return new Response(JSON.stringify({
        ok: false,
        error_code: 404,
        description: 'Endpoint not found or invalid format. Correct format: /bot<token>/<method>'
    }), {
        status: 404,
        headers: { 'content-type': 'application/json' }
    });
}

function handleRootRequest(request) {
    const workerUrl = new URL(request.url).origin;
    const apiUrl = workerUrl + '/bot';

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Telegram API 安全网关</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #121212; color: #ffffff; display: flex; justify-content: center; min-height: 100vh; padding: 20px 0; }
        .container { text-align: center; padding: 2rem; background: #1e1e1e; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); max-width: 800px; width: 95%; border: 1px solid #333; }
        h1 { color: #61dafb; font-size: 2rem; margin-bottom: 1.5rem; }
        h2 { color: #61dafb; font-size: 1.5rem; margin-bottom: 1rem; text-align: left; }
        .status-badge { background: #2d2d2d; padding: 0.75rem 1.5rem; border-radius: 50px; display: inline-flex; align-items: center; margin-bottom: 1.5rem; border: 1px solid #3d3d3d; }
        .status-indicator { width: 12px; height: 12px; background-color: #2ecc71; border-radius: 50%; margin-right: 8px; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(46, 204, 113, 0); } 100% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0); } }
        p { color: #dadada; line-height: 1.6; margin-bottom: 1.5rem; text-align: left; }
        .section { margin-bottom: 2rem; padding: 1.5rem; background: #252525; border-radius: 8px; border-left: 4px solid #61dafb; }
        .api-container { display: flex; align-items: center; background: #1a1a1a; padding: 1rem; border-radius: 4px; gap: 10px; margin: 1rem 0; }
        .api-url { flex-grow: 1; text-align: left; word-break: break-all; color: #61dafb; font-family: monospace; }
        .copy-button { background: #61dafb; color: #1a1a1a; border: none; border-radius: 4px; padding: 0.5rem 1rem; cursor: pointer; font-weight: bold; }
        .code-block { background: #1a1a1a; padding: 1rem; border-radius: 4px; text-align: left; font-family: monospace; font-size: 0.9rem; overflow-x: auto; white-space: pre; color: #79c0ff; margin-top: 10px; }
        footer { margin-top: 2rem; border-top: 1px solid #333; padding-top: 1rem; color: #888; font-size: 0.8rem; }
        a { color: #61dafb; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Telegram API 安全网关</h1>
        <div class="status-badge"><div class="status-indicator"></div>系统运行正常</div>
        
        <div class="section">
            <h2>关于本服务</h2>
            <p>本网关提供稳定可靠的 Telegram API 代理。支持所有 API 方法，具备速率限制、安全过滤和 Bot Token 白名单功能。</p>
        </div>

        <div class="section">
            <h2>API 地址</h2>
            <p>替换官方地址的前缀即可：</p>
            <div class="api-container">
                <div class="api-url" id="apiUrl">${apiUrl}</div>
                <button class="copy-button" onclick="copy()">复制</button>
            </div>
        </div>

        <div class="section">
            <h2>代码示例 (Python)</h2>
            <div class="code-block">
import requests
API_BASE = "${apiUrl}/12345:TOKEN"
resp = requests.get(f"{API_BASE}/getMe")
print(resp.json())
            </div>
        </div>

        <footer>
            <p>Created by Anonymous | Licensed under GPL-3.0</p>
            <p>管理入口: <a href="/admin">/admin</a></p>
        </footer>
    </div>
    <script>
        function copy() {
            const text = document.getElementById('apiUrl').innerText;
            navigator.clipboard.writeText(text);
            const btn = document.querySelector('.copy-button');
            btn.innerText = '已复制';
            setTimeout(() => btn.innerText = '复制', 2000);
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: { 'content-type': 'text/html;charset=UTF-8' }
    });
}

// ==========================================
// 辅助函数 (API 代理、验证等)
// ==========================================

async function validateBotTokenAdvanced(token) {
    const allowedEnv = (typeof ALLOWED_BOT_TOKENS !== 'undefined') ? ALLOWED_BOT_TOKENS : null;
    if (allowedEnv) {
        const allowed = allowedEnv.split(',').map(t => t.trim()).filter(t => t.length > 0);
        if (!allowed.includes(token)) {
            console.warn(`[Blocked] Unlisted token prefix: ${token.substring(0, 10)}...`);
            return false;
        }
    } else {
        console.warn('[Security] ALLOWED_BOT_TOKENS not configured. All requests blocked.');
        return false;
    }

    if (!token || !token.includes(':') || token.length < 30) return false;
    return true;
}

async function performAdvancedSecurityChecks(request) {
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || '';

    if (!ALLOWED_METHODS.includes(request.method)) return { blocked: true, reason: 'Method Forbidden', status: 405 };

    if (BLOCKED_USER_AGENTS.test(userAgent)) return { blocked: true, reason: 'Forbidden User Agent', status: 403 };

    const url = new URL(request.url);
    for (const pattern of MALICIOUS_PATTERNS) {
        if (pattern.test(url.pathname) || pattern.test(url.search)) {
            return { blocked: true, reason: 'Malicious Request Detected', status: 400 };
        }
    }

    return { blocked: false };
}

function getClientIP(request) {
    return request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || 'unknown';
}

async function cleanupExpiredData() {
    const now = Date.now();
    if (now - stats.lastReset > 3600000) {
        stats.totalRequests = 0;
        stats.failedRequests = 0;
        stats.rateLimited = 0;
        stats.blocked = 0;
        stats.retries = 0;
        stats.lastReset = now;
        stats.avgResponseTime = 0;
    }
}

async function checkAdvancedRateLimit(clientIP, botToken) {
    const now = Date.now();
    if (requestCounters.global.count >= RATE_LIMITS.GLOBAL.max && now < requestCounters.global.resetTime) {
        return { limited: true, retryAfter: 60 };
    }
    requestCounters.global.count++;
    return { limited: false };
}

function checkCircuitBreaker(ip) { return 'CLOSED'; }
function updateCircuitBreaker(ip, ok) { }
function recordSuspiciousActivity(ip, type) { }

async function parseRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(URL_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        clientIP: getClientIP(request),
        botToken: match.groups.bot_token,
        apiMethod: match.groups.api_method,
        path: url.pathname + url.search
    };
}

async function proxyToTelegramWithRetry(request, info) {
    return proxyToTelegram(request, info);
}

async function proxyToTelegram(request, info) {
    const newUrl = "https://api.telegram.org" + info.path;
    const headers = new Headers(request.headers);
    headers.delete('host');
    headers.set('User-Agent', 'Cloudflare-Worker-Proxy/1.0');

    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        body = await request.arrayBuffer();
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

function updateStats(startTime, ok) {
    stats.totalRequests++;
    if (!ok) stats.failedRequests++;
    stats.avgResponseTime = (stats.avgResponseTime + (Date.now() - startTime)) / 2;
}

function generateRequestId() { return Math.random().toString(36).substr(2, 9); }

function createErrorResponse(err, status) {
    return new Response(JSON.stringify({ ok: false, error: err }), { status, headers: { 'content-type': 'application/json' } });
}

function createRateLimitResponse(retry) {
    return new Response(JSON.stringify({ ok: false, error: 'Too Many Requests' }), { status: 429, headers: { 'Retry-After': retry, 'content-type': 'application/json' } });
}

function handleProxyError(e) {
    return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
}

function handleCorsPreflightRequest() {
    return new Response(null, {
        status: 204, headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*'
        }
    });
}

// ==========================================
// 管理后台逻辑 (Cloudflare API)
// ==========================================

async function handleAdminApiRequest(request, pathname) {
    const auth = request.headers.get('Authorization');
    const pwd = typeof ADMIN_PASSWORD !== 'undefined' ? ADMIN_PASSWORD : null;
    if (!pwd || auth !== `Bearer ${pwd}`) return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { status: 401 });

    if (request.method === 'GET' && pathname === '/api/admin/tokens') {
        const t = typeof ALLOWED_BOT_TOKENS !== 'undefined' ? ALLOWED_BOT_TOKENS : '';
        return new Response(JSON.stringify({ tokens: t }), { headers: { 'content-type': 'application/json' } });
    }

    if (request.method === 'POST' && pathname === '/api/admin/tokens') {
        try {
            const { tokens } = await request.json();
            const result = await updateCloudflareEnv('ALLOWED_BOT_TOKENS', tokens);
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

async function updateCloudflareEnv(key, value) {
    const accId = typeof CF_ACCOUNT_ID !== 'undefined' ? CF_ACCOUNT_ID : null;
    const scName = typeof CF_SCRIPT_NAME !== 'undefined' ? CF_SCRIPT_NAME : null;
    const apiTok = typeof CF_API_TOKEN !== 'undefined' ? CF_API_TOKEN : null;

    if (!accId || !scName || !apiTok) {
        return { success: false, error: '缺少必要的 CF 环境变量：CF_ACCOUNT_ID, CF_SCRIPT_NAME 或 CF_API_TOKEN' };
    }

    try {
        // 先获取当前所有绑定，以保持完整性
        const getUrl = `https://api.cloudflare.com/client/v4/accounts/${accId}/workers/scripts/${scName}`;
        const res = await fetch(getUrl, { headers: { 'Authorization': `Bearer ${apiTok}` } });
        const data = await res.json();

        if (!data.success) {
            const err = data.errors?.[0]?.message || '获取 Worker 配置失败';
            return { success: false, error: `CF API 错误: ${err}` };
        }

        let bindings = data.result.bindings || [];
        let found = false;
        for (let b of bindings) {
            if (b.name === key) {
                b.text = value;
                found = true;
                break;
            }
        }
        if (!found) {
            bindings.push({ type: 'plain_text', name: key, text: value });
        }

        // 使用 PUT bindings 接口更新
        const putUrl = `https://api.cloudflare.com/client/v4/accounts/${accId}/workers/scripts/${scName}/bindings`;
        const putRes = await fetch(putUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiTok}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(bindings)
        });

        const putData = await putRes.json();
        if (putData.success) {
            return { success: true };
        } else {
            const err = putData.errors?.[0]?.message || '更新失败';
            return { success: false, error: `CF API 更新错误: ${err}` };
        }
    } catch (e) {
        return { success: false, error: `系统异常: ${e.message}` };
    }
}

const ADMIN_HTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token 管理后台</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #f3f4f6; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 500px; }
        h1 { margin-top: 0; font-size: 1.5rem; }
        textarea { width: 100%; height: 100px; margin: 10px 0; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input { width: 100%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0056b3; }
        #msg { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Token 管理后台</h1>
        <input type="password" id="pw" placeholder="管理员密码">
        <button onclick="load()">连接并获取配置</button>
        <div id="editor" style="display:none; margin-top: 20px;">
            <label>Bot Tokens (逗号分隔):</label>
            <textarea id="tk"></textarea>
            <button onclick="save()">保存并应用</button>
        </div>
        <div id="msg"></div>
    </div>
    <script>
        const msg = document.getElementById('msg');
        function show(txt, err) {
            msg.innerText = txt;
            msg.style.display = 'block';
            msg.style.background = err ? '#fee' : '#efe';
            msg.style.color = err ? '#c33' : '#3c3';
        }
        async function load() {
            const p = document.getElementById('pw').value;
            const res = await fetch('/api/admin/tokens', { headers: { 'Authorization': 'Bearer '+p } });
            if (res.ok) {
                const d = await res.json();
                document.getElementById('tk').value = d.tokens;
                document.getElementById('editor').style.display = 'block';
                show('连接成功', false);
            } else show('密码错误或配置无效', true);
        }
        async function save() {
            const p = document.getElementById('pw').value;
            const t = document.getElementById('tk').value;
            show('正在保存...', false);
            try {
                const res = await fetch('/api/admin/tokens', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer '+p, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tokens: t })
                });
                const d = await res.json();
                if (res.ok && d.success) {
                    show('保存成功！环境变量已更新，新请求约几秒后生效。', false);
                } else {
                    show('保存失败: ' + (d.error || '原因未知'), true);
                }
            } catch (e) {
                show('系统错误: ' + e.message, true);
            }
        }
    </script>
</body>
</html>
`;
