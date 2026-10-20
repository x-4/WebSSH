'use strict';

/**
 * WebSocket 接入层：浏览器 ↔ 服务端的双向通道。
 *
 * 握手阶段完成三件事：同源校验、登录态校验、单 IP 并发限制；
 * 握手成功后用一个极简 JSON 协议驱动 SSH 会话：
 *
 *   client -> server : connect | resume | input | resize | ping | close
 *   server -> client : ready | data | error | exit | closed | pong
 */

const crypto = require('crypto');
const os = require('os');
const { WebSocketServer } = require('ws');
const config = require('./config');
const auth = require('./auth');
const audit = require('./audit');
const users = require('./users');
const logger = require('./logger');
const {
  registry,
  validateSshParams,
  validateLocalParams,
  assertHostAllowed,
  friendlyError,
  localTerminalAvailability,
} = require('./sessions');

const log = logger.create('ws');

function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function rawSend(ws, payload) {
  if (ws.readyState !== 1) return false;
  try {
    ws.send(JSON.stringify(payload));
    return true;
  } catch {
    return false;
  }
}

function attachWebSocketServer(server) {
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: config.ws.maxPayloadBytes,
    perMessageDeflate: false, // 压缩会引入额外 CPU 与内存开销，终端流量通常已足够小
    clientTracking: true,
  });

  const connPerIp = new Map();

  server.on('upgrade', (req, socket, head) => {
    let pathname = '/';
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      socket.destroy();
      return;
    }
    if (pathname !== '/ws') {
      socket.destroy();
      return;
    }

    const reject = (code, text) => {
      socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
    };

    if (!auth.isTrustedOrigin(req)) {
      log.warn(`拒绝跨站 WebSocket 握手 origin=${auth.requestOrigin(req)}`);
      return reject(403, 'Forbidden');
    }

    const user = auth.userFromRequest(req);
    if (!user) return reject(401, 'Unauthorized');

    const ip = auth.clientIp(req);
    const used = connPerIp.get(ip) || 0;
    if (used >= config.ws.maxConnPerIp) {
      log.warn(`IP ${ip} 并发连接数超限`);
      return reject(429, 'Too Many Requests');
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      connPerIp.set(ip, used + 1);
      ws.once('close', () => {
        const left = (connPerIp.get(ip) || 1) - 1;
        if (left > 0) connPerIp.set(ip, left);
        else connPerIp.delete(ip);
      });
      wss.emit('connection', ws, req, user, ip);
    });
  });

  wss.on('connection', (ws, req, user, ip) => {
    const ctx = {
      ws,
      user,
      ip,
      session: null,
      windowStart: Date.now(),
      windowCount: 0,
      alive: true,
    };

    log.info(`WebSocket 已连接 user=${user.username} ip=${ip}`);

    ws.on('pong', () => {
      ctx.alive = true;
    });

    ws.on('message', (raw, isBinary) => {
      if (isBinary) return; // 协议仅接受文本帧
      // 简易窗口限流：防止单连接滥用造成 CPU 打满
      const now = Date.now();
      if (now - ctx.windowStart >= 1000) {
        ctx.windowStart = now;
        ctx.windowCount = 0;
      }
      if (++ctx.windowCount > config.ws.maxMessagesPerSecond) return;

      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return rawSend(ws, { type: 'error', code: 'BAD_MESSAGE', message: '消息格式错误' });
      }
      if (!msg || typeof msg.type !== 'string') return;

      handleMessage(ctx, msg).catch((err) => {
        log.warn('消息处理异常', err.message);
        rawSend(ws, { type: 'error', code: 'INTERNAL', message: err.message || '服务端处理失败' });
      });
    });

    ws.on('close', () => {
      log.info(`WebSocket 断开 user=${user.username} ip=${ip}`);
      if (ctx.session) {
        ctx.session.detach(ws);
        ctx.session = null;
      }
    });

    ws.on('error', (err) => log.debug('WebSocket 错误', err.message));
  });

  // 服务端心跳：清理半开连接（网络中断但 TCP 未感知）
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      try {
        ws.ping();
      } catch {
        /* ignore */
      }
    }
  }, 30000);
  if (heartbeat.unref) heartbeat.unref();

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });
  });

  return wss;
}

/* ------------------------------ 消息处理 ------------------------------ */

async function handleMessage(ctx, msg) {
  const { ws, user } = ctx;

  switch (msg.type) {
    case 'connect':
      return handleConnect(ctx, msg);
    case 'resume':
      return handleResume(ctx, msg);
    case 'input': {
      if (!ctx.session) return;
      const data = typeof msg.data === 'string' ? msg.data : '';
      if (data.length > 64 * 1024) return;
      ctx.session.write(data);
      return;
    }
    case 'resize': {
      if (!ctx.session) return;
      ctx.session.resize(msg.cols, msg.rows);
      return;
    }
    case 'ping':
      return rawSend(ws, { type: 'pong', t: msg.t || Date.now() });
    case 'close': {
      if (ctx.session) {
        const id = ctx.session.id;
        ctx.session.close('closed_by_user');
        ctx.session = null;
        log.info(`用户主动关闭会话 ${id} user=${user.username}`);
      }
      return;
    }
    default:
      return rawSend(ws, { type: 'error', code: 'UNKNOWN_TYPE', message: `未知消息类型: ${msg.type}` });
  }
}

async function handleConnect(ctx, msg) {
  const { ws, user } = ctx;
  if (ctx.session && !ctx.session.closed) {
    return rawSend(ws, { type: 'error', code: 'ALREADY_BOUND', message: '当前连接已绑定会话，请先关闭' });
  }

  const kind = msg.kind === 'local' ? 'local' : 'ssh';
  const permissions = user.permissions || [];

  // RBAC：角色必须具备对应终端权限
  const required = kind === 'local' ? 'terminal:local' : 'terminal:ssh';
  if (!permissions.includes(required)) {
    log.warn(`拒绝无权限的终端请求 user=${user.username} role=${user.role} kind=${kind}`);
    audit.record({
      type: 'security.denied',
      user: user.username,
      role: user.role,
      ip: ctx.ip,
      reason: 'rbac',
      detail: required,
    });
    return rawSend(ws, { type: 'error', code: 'FORBIDDEN', message: '当前角色无权打开该类型终端' });
  }

  // 敏感操作二次认证：本机终端需要近期口令确认
  if (kind === 'local' && config.auth.stepUpRequired && !auth.hasStepUp(user.payload)) {
    return rawSend(ws, {
      type: 'error',
      code: 'STEP_UP_REQUIRED',
      message: '打开部署机终端需要进行二次身份验证',
    });
  }

  let params;
  try {
    if (kind === 'local') {
      const info = localTerminalAvailability();
      if (!info.enabled) {
        const err = new Error('部署机终端已禁用（LOCAL_TERMINAL_ENABLED=false）');
        err.code = 'LOCAL_DISABLED';
        throw err;
      }
      if (!info.available) {
        const err = new Error(info.reason || '部署机终端当前不可用');
        err.code = 'LOCAL_UNAVAILABLE';
        throw err;
      }
      // fail-closed：要求审计远端投递但投递不健康时，拒绝新建本机会话
      if (!audit.canAcceptLocalSession()) {
        const err = new Error('审计投递不可用，已按 fail-closed 策略拒绝打开本机终端');
        err.code = 'AUDIT_UNAVAILABLE';
        throw err;
      }
      params = { ...validateLocalParams(msg), shell: info.shell };
    } else {
      params = validateSshParams(msg);
      if (!users.canAccessHost(user.username, params.host)) {
        const err = new Error('目标主机不在你的授权范围内');
        err.code = 'FORBIDDEN';
        throw err;
      }
      await assertHostAllowed(params.host);
    }
  } catch (err) {
    return rawSend(ws, { type: 'error', code: err.code || 'BAD_PARAMS', message: err.message });
  }

  rawSend(ws, {
    type: 'status',
    state: 'connecting',
    message: kind === 'local' ? '正在打开部署机终端…' : `正在连接 ${params.host}:${params.port} …`,
  });

  let session;
  try {
    session = registry.create(user.username, kind, params);
  } catch (err) {
    return rawSend(ws, { type: 'error', code: 'LIMIT', message: err.message });
  }
  ctx.session = session;

  try {
    await session.connect();
  } catch (err) {
    const message = kind === 'local' ? err.message : friendlyError(err);
    log.warn(`${kind === 'local' ? '本机终端' : 'SSH'}连接失败 - ${err.message}`);
    session.close('connect_failed');
    ctx.session = null;
    return rawSend(ws, { type: 'error', code: 'CONNECT_FAILED', message });
  }

  // 握手期间前端已断开：直接回收，避免僵尸会话
  if (ws.readyState !== 1) {
    session.close('client_gone');
    ctx.session = null;
    return;
  }

  const attached = session.attach(ws);
  rawSend(ws, {
    type: 'ready',
    resumed: false,
    sessionId: session.id,
    token: session.token,
    replay: attached.data || '',
    truncated: Boolean(attached.truncated),
    meta: attached.meta,
  });
  log.info(
    `会话就绪 ${session.id} kind=${kind} ${
      kind === 'local' ? `${params.shell} @ ${os.hostname()}` : `${params.username}@${params.host}:${params.port}`
    }`
  );
}

function handleResume(ctx, msg) {
  const { ws, user } = ctx;
  const sessionId = String(msg.sessionId || '');
  const token = String(msg.token || '');
  const session = registry.get(sessionId);

  if (!session || session.owner !== user.username) {
    return rawSend(ws, { type: 'error', code: 'RESUME_FAILED', message: '会话不存在或已被回收' });
  }
  if (!safeEqual(token, session.token)) {
    log.warn(`会话凭据校验失败 ${sessionId} user=${user.username}`);
    return rawSend(ws, { type: 'error', code: 'RESUME_FAILED', message: '会话凭据无效' });
  }

  // 接管前先替换旧 socket（例如上一次断开但服务端尚未感知）
  const attached = session.attach(ws);
  if (!attached.ok) {
    return rawSend(ws, { type: 'error', code: 'RESUME_FAILED', message: attached.reason || '会话已结束' });
  }
  ctx.session = session;
  session.resize(msg.cols, msg.rows);

  rawSend(ws, {
    type: 'ready',
    resumed: true,
    sessionId: session.id,
    token: session.token,
    replay: attached.data || '',
    truncated: Boolean(attached.truncated),
    meta: attached.meta,
  });
  log.info(`会话重连成功 ${session.id} user=${user.username}`);
}

module.exports = { attachWebSocketServer };
