'use strict';

/**
 * 集成测试：拉起真实服务进程 + 模拟 SSH 服务，覆盖登录、SSH 会话、
 * 本机终端（若 node-pty 可用）、命令审计与登出吊销。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Server, utils } = require('ssh2');
const WebSocket = require('ws');

const ROOT = path.resolve(__dirname, '..');
const PASSWORD = 'it-pass-123';

let ptyAvailable = true;
try {
  require('node-pty');
} catch {
  ptyAvailable = false;
}

let child;
let baseUrl;
let cookie;
let sshServer;
let sshPort;
let stderr = '';

function startMockSsh() {
  return new Promise((resolve) => {
    const hostKey = utils.generateKeyPairSync('rsa', { bits: 2048 }).private;
    const server = new Server({ hostKeys: [hostKey] }, (client) => {
      client.on('error', () => {});
      client
        .on('authentication', (ctx) => {
          if (ctx.method === 'password' && ctx.username === 'demo' && ctx.password === 'demo') return ctx.accept();
          return ctx.reject(['password']);
        })
        .on('ready', () => {
          client.on('session', (accept) => {
            const session = accept();
            session.on('pty', (a) => a && a());
            session.on('window-change', (a) => a && a());
            session.on('shell', (acceptShell) => {
              const stream = acceptShell();
              let line = '';
              stream.write('MOCK_SSH_READY\r\n$ ');
              stream.on('data', (chunk) => {
                for (const ch of chunk.toString('utf8')) {
                  if (ch === '\r') {
                    stream.write(`\r\nOUT:${line}\r\n$ `);
                    line = '';
                  } else {
                    line += ch;
                    stream.write(ch);
                  }
                }
              });
            });
          });
        });
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function waitForPort(proc, timeout = 20000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`服务启动超时\n${buffer}\n${stderr}`)), timeout);
    proc.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      const match = buffer.match(/已启动\s*→\s*https?:\/\/[^:]+:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    proc.once('exit', (code) => reject(new Error(`服务退出 code=${code}\n${buffer}\n${stderr}`)));
  });
}

function openWs() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${new URL(baseUrl).port}/ws`, {
      headers: { Cookie: cookie, Origin: baseUrl },
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

function collector(ws) {
  const messages = [];
  ws.on('message', (raw) => messages.push(JSON.parse(raw.toString())));
  return {
    messages,
    waitFor(pred, timeout = 15000) {
      const hit = messages.find(pred);
      if (hit) return Promise.resolve(hit);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('等待消息超时')), timeout);
        function on(raw) {
          const msg = JSON.parse(raw.toString());
          if (pred(msg)) {
            clearTimeout(timer);
            ws.off('message', on);
            resolve(msg);
          }
        }
        ws.on('message', on);
      });
    },
    text() {
      return messages.filter((m) => m.type === 'data').map((m) => m.data).join('');
    },
    waitText(text, timeout = 15000) {
      const deadline = Date.now() + timeout;
      return new Promise((resolve, reject) => {
        const tick = () => {
          if (this.text().includes(text)) return resolve();
          if (Date.now() > deadline) return reject(new Error(`等待输出超时: ${text}`));
          return setTimeout(tick, 100);
        };
        tick();
      });
    },
  };
}

test.before(async () => {
  const mock = await startMockSsh();
  sshServer = mock.server;
  sshPort = mock.port;

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-it-'));
  child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: '0',
      HOST: '127.0.0.1',
      DATA_DIR: dataDir,
      WEBSSH_USER: 'tester',
      WEBSSH_PASS: PASSWORD,
      SESSION_SECRET: 'e'.repeat(64),
      LOG_LEVEL: 'info',
      AUDIT_FORWARD_URL: '',
      AUDIT_REQUIRE_DELIVERY: 'false',
      LOCAL_TERMINAL_ENABLED: 'true',
      SSH_BLOCK_PRIVATE_HOSTS: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  const port = await waitForPort(child);
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (child) child.kill();
  if (sshServer) await new Promise((resolve) => sshServer.close(resolve));
});

test('登录失败与成功', async () => {
  const bad = await fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: baseUrl },
    body: JSON.stringify({ username: 'tester', password: 'wrong' }),
  });
  assert.equal(bad.status, 401);

  const ok = await fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: baseUrl },
    body: JSON.stringify({ username: 'tester', password: PASSWORD }),
  });
  assert.equal(ok.status, 200);
  const setCookie = ok.headers.getSetCookie()[0];
  assert.match(setCookie, /HttpOnly/);
  cookie = setCookie.split(';')[0];
});

test('就绪探针与请求 ID', async () => {
  const ready = await fetch(`${baseUrl}/readyz`);
  assert.equal(ready.status, 200);
  const body = await ready.json();
  assert.equal(body.ok, true);
  assert.equal(body.checks.users.ok, true);

  const me = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: cookie } });
  const requestId = me.headers.get('x-request-id');
  assert.match(requestId, /^[A-Za-z0-9._-]{8,64}$/);
});

test('SSH 会话：建连、执行命令、关闭', { timeout: 30000 }, async () => {
  const ws = await openWs();
  const c = collector(ws);

  ws.send(
    JSON.stringify({
      type: 'connect',
      kind: 'ssh',
      host: '127.0.0.1',
      port: sshPort,
      username: 'demo',
      authType: 'password',
      password: 'demo',
      cols: 100,
      rows: 30,
    })
  );

  const ready = await c.waitFor((m) => m.type === 'ready' || m.type === 'error');
  assert.equal(ready.type, 'ready', JSON.stringify(ready));

  await c.waitText('MOCK_SSH_READY');
  ws.send(JSON.stringify({ type: 'input', data: 'echo integration\r' }));
  await c.waitText('OUT:echo integration');

  ws.send(JSON.stringify({ type: 'close' }));
  const closed = await c.waitFor((m) => m.type === 'closed');
  assert.equal(closed.reason, 'closed_by_user');
  ws.close();
});

test('本机终端：需二次认证，执行命令并写入审计', { timeout: 40000, skip: !ptyAvailable && 'node-pty 不可用' }, async () => {
  // 未做 step-up 时应被拒绝
  const deniedWs = await openWs();
  const denied = collector(deniedWs);
  deniedWs.send(JSON.stringify({ type: 'connect', kind: 'local', cols: 100, rows: 30 }));
  const deniedMsg = await denied.waitFor((m) => m.type === 'ready' || m.type === 'error');
  assert.equal(deniedMsg.code, 'STEP_UP_REQUIRED');
  deniedWs.close();

  // 完成二次认证后再连接
  const step = await fetch(`${baseUrl}/api/step-up`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: baseUrl },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(step.status, 200);

  const ws = await openWs();
  const c = collector(ws);

  ws.send(JSON.stringify({ type: 'connect', kind: 'local', cols: 110, rows: 30 }));
  const ready = await c.waitFor((m) => m.type === 'ready' || m.type === 'error');
  assert.equal(ready.type, 'ready', JSON.stringify(ready));
  assert.equal(ready.meta.kind, 'local');

  await new Promise((resolve) => setTimeout(resolve, 800));
  ws.send(JSON.stringify({ type: 'input', data: 'echo LOCAL_INTEGRATION\r' }));
  await c.waitText('LOCAL_INTEGRATION');

  await new Promise((resolve) => setTimeout(resolve, 500));
  const audit = await (await fetch(`${baseUrl}/api/audit?type=command&limit=50`, { headers: { Cookie: cookie } })).json();
  const mine = audit.entries.filter((e) => e.sessionId === ready.sessionId);
  assert.ok(mine.some((e) => e.cmd.includes('echo LOCAL_INTEGRATION')));

  const verify = await (await fetch(`${baseUrl}/api/audit/verify`, { headers: { Cookie: cookie } })).json();
  assert.equal(verify.result.ok, true);

  ws.send(JSON.stringify({ type: 'close' }));
  await c.waitFor((m) => m.type === 'closed');
  ws.close();
});

test('指标端点：Prometheus 文本格式', async () => {
  const res = await fetch(`${baseUrl}/metrics`);
  assert.equal(res.status, 200);
  const text = await res.text();

  assert.match(text, /webssh_up 1/);
  assert.match(text, /webssh_login_total\{result="success"\} [1-9]/);
  assert.match(text, /webssh_sessions\{kind="ssh"\}/);
  assert.match(text, /webssh_command_total\{kind="local"\} [1-9]/);
  assert.match(text, /webssh_process_resident_memory_bytes \d+/);
});

test('会话录像：列表与下载', { timeout: 20000 }, async () => {
  let items = [];
  for (let i = 0; i < 20; i += 1) {
    const res = await fetch(`${baseUrl}/api/recordings?limit=10`, { headers: { Cookie: cookie } });
    const data = await res.json();
    items = data.items || [];
    if (items.length) break;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  assert.ok(items.length > 0, '应生成录像');

  const cast = await fetch(`${baseUrl}/api/recordings/${items[0].id}`, { headers: { Cookie: cookie } });
  assert.equal(cast.status, 200);
  const text = await cast.text();
  const header = JSON.parse(text.split('\n')[0]);
  assert.equal(header.version, 2);
});

test('登出后旧票据失效', async () => {
  const res = await fetch(`${baseUrl}/api/logout`, {
    method: 'POST',
    headers: { Cookie: cookie, Origin: baseUrl },
  });
  assert.equal(res.status, 200);

  const me = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: cookie } });
  assert.equal(me.status, 401);
});
