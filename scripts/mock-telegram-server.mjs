/**
 * Telegram API Mock Server — 本地开发测试用
 *
 * 模拟 Telegram Bot API 的部分响应，让代理可以在无法直连
 * api.telegram.org 的环境中正常开发和调试。
 *
 * 启动方式：
 *   node scripts/mock-telegram-server.mjs
 *
 * 默认监听 http://localhost:9001
 * 可通过环境变量 MOCK_PORT 修改端口。
 *
 * 示例：
 *   # 启动 mock 服务器
 *   MOCK_PORT=9001 node scripts/mock-telegram-server.mjs
 *
 *   # 另开终端，启动 wrangler（带上 TELEGRAM_API_BASE）
 *   TELEGRAM_API_BASE=http://localhost:9001 wrangler dev manual-worker/worker.js
 *
 *   # 测试
 *   curl http://localhost:8787/bot123456:TESTTOKEN/getMe
 */

import http from 'node:http';

const PORT = parseInt(process.env.MOCK_PORT || '9001', 10);

// ====== Mock 响应数据 ======

const MOCK_RESPONSES = {
  getMe: {
    ok: true,
    result: {
      id: 1234567890,
      is_bot: true,
      first_name: 'MockBot',
      username: 'MockBot',
      can_join_groups: true,
      can_read_all_group_messages: false,
      supports_inline_queries: false,
    },
  },
  getUpdates: {
    ok: true,
    result: [],
  },
  sendMessage: {
    ok: true,
    result: {
      message_id: 1,
      from: { id: 1234567890, is_bot: true, first_name: 'MockBot', username: 'MockBot' },
      chat: { id: 987654321, first_name: 'Test', type: 'private' },
      date: Math.floor(Date.now() / 1000),
      text: 'Hello via Proxy!',
    },
  },
  getWebhookInfo: {
    ok: true,
    result: {
      url: '',
      has_custom_certificate: false,
      pending_update_count: 0,
      max_connections: 40,
    },
  },
  setWebhook: {
    ok: true,
    result: true,
    description: 'Webhook was set',
  },
  deleteWebhook: {
    ok: true,
    result: true,
    description: 'Webhook was deleted',
  },
  getChat: {
    ok: true,
    result: {
      id: 987654321,
      type: 'private',
      first_name: 'Test User',
    },
  },
};

// ====== 服务器逻辑 ======

function parsePath(pathname) {
  // 匹配 /bot<TOKEN>/<METHOD> 或 /file/bot<TOKEN>/<FILE_PATH>
  const botMatch = pathname.match(/^\/bot([^/]+)\/(.+)$/);
  if (botMatch) {
    return { type: 'api', token: botMatch[1], method: botMatch[2] };
  }
  const fileMatch = pathname.match(/^\/file\/bot([^/]+)\/(.+)$/);
  if (fileMatch) {
    return { type: 'file', token: fileMatch[1], filePath: fileMatch[2] };
  }
  return null;
}

function buildResponse(data, status = 200) {
  const body = JSON.stringify(data);
  return `HTTP/1.1 ${status} OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n${body}`;
}

const server = http.createServer((req, res) => {
  const parsed = parsePath(req.url);

  console.log(`[Mock Telegram] ${req.method} ${req.url}`);

  if (!parsed) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Not found' }));
    return;
  }

  if (parsed.type === 'api') {
    const method = parsed.method;
    const mock = MOCK_RESPONSES[method];

    if (mock) {
      // 模拟网络延迟 50-150ms，更接近真实情况
      const delay = 50 + Math.random() * 100;
      setTimeout(() => {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        });
        // 如果是 sendMessage，动态生成 message_id
        if (method === 'sendMessage') {
          const response = JSON.parse(JSON.stringify(mock));
          response.result.message_id = Math.floor(Math.random() * 10000) + 1;
          response.result.date = Math.floor(Date.now() / 1000);
          res.end(JSON.stringify(response));
        } else {
          res.end(JSON.stringify(mock));
        }
        console.log(`[Mock Telegram] → 200 OK (${delay.toFixed(0)}ms) ${method}`);
      }, delay);
    } else if (method === 'getFile') {
      // 模拟 getFile 响应
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({
        ok: true,
        result: {
          file_id: 'mock-file-id-12345',
          file_unique_id: 'mock-unique-id',
          file_size: 12345,
          file_path: 'mock/path/to/file.jpg',
        },
      }));
    } else {
      // 未知方法返回错误
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: false,
        error_code: 400,
        description: `[Mock] Unknown method: ${method}`,
      }));
    }
  } else if (parsed.type === 'file') {
    // 模拟文件下载 —— 返回一张 1x1 像素的 PNG
    const png = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      'base64'
    );
    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': png.length,
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    });
    res.end(png);
    console.log(`[Mock Telegram] → 200 (file) ${parsed.filePath}`);
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║     Telegram API Mock Server                ║');
  console.log(`║     Listening on http://localhost:${PORT}         ║`);
  console.log('║                                              ║');
  console.log('║   Usage:                                     ║');
  console.log(`║     TELEGRAM_API_BASE=http://localhost:${PORT} \\  ║`);
  console.log('║     wrangler dev manual-worker/worker.js     ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
  console.log('Supported methods:');
  Object.keys(MOCK_RESPONSES).forEach((m) => console.log(`  - ${m}`));
  console.log('  - getFile');
  console.log('');
});
