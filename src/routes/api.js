'use strict';

/**
 * HTTP API：
 *   POST   /api/login      登录，签发 HttpOnly Cookie
 *   POST   /api/logout     退出登录
 *   GET    /api/me         当前登录信息
 *   GET    /api/sessions   当前账号的会话列表（不含凭据）
 *   DELETE /api/sessions/:id  主动结束某个会话
 *   GET    /api/config     前端所需的公开配置
 *   GET    /healthz        健康检查（供负载均衡 / 容器探针使用）
 */

const express = require('express');
const config = require('../config');
const auth = require('../auth');
const logger = require('../logger');
const audit = require('../audit');
const users = require('../users');
const metrics = require('../metrics');
const recordings = require('../recordings');
const { hashPasswordAsync } = require('../password');
const { registry, localTerminalAvailability } = require('../sessions');

const log = logger.create('api');
const router = express.Router();

function requireAuth(req, res, next) {
  const user = auth.userFromRequest(req);
  if (!user) return res.status(401).json({ ok: false, message: '未登录或登录已过期' });
  req.user = user;
  next();
}

function hasPermission(user, permission) {
  return Boolean(user && Array.isArray(user.permissions) && user.permissions.includes(permission));
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ ok: false, message: '当前角色无权执行该操作' });
    }
    next();
  };
}

/* ------------------------------ 登录态 ------------------------------ */

router.post('/login', asyncHandler(async (req, res) => {
  if (!auth.isTrustedOrigin(req)) {
    return res.status(403).json({ ok: false, message: '非法的请求来源' });
  }

  const ip = auth.clientIp(req);
  const gate = auth.checkLoginAllowed(ip);
  if (!gate.allowed) {
    metrics.inc('webssh_login_total', { result: 'rate_limited' });
    audit.record({ type: 'auth.login', result: 'rate_limited', user: username, ip });
    log.warn(`登录限流触发 ip=${ip}`);
    res.setHeader('Retry-After', String(gate.retryAfter));
    return res.status(429).json({ ok: false, message: `尝试过于频繁，请 ${gate.retryAfter} 秒后再试` });
  }

  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  if (!username || !password) {
    return res.status(400).json({ ok: false, message: '请输入用户名和密码' });
  }
  if (username.length > 128 || password.length > 512) {
    return res.status(400).json({ ok: false, message: '输入内容过长' });
  }

  const account = await auth.authenticate(username, password);
  if (!account) {
    auth.recordLoginFailure(ip);
    metrics.inc('webssh_login_total', { result: 'failure' });
    audit.record({ type: 'auth.login', result: 'failure', user: username, ip });
    log.warn(`登录失败 user=${username} ip=${ip}`);
    return res.status(401).json({ ok: false, message: '用户名或密码错误' });
  }

  auth.resetLoginAttempts(ip);
  metrics.inc('webssh_login_total', { result: 'success' });
  audit.record({ type: 'auth.login', result: 'success', user: account.username, role: account.role, ip });

  // 旧哈希成本低于当前配置时，后台自动升级（不阻塞登录响应）
  if (users.source === 'file' && users.needsRehash(account)) {
    hashPasswordAsync(password)
      .then((hash) => users.updatePasswordHash(account.username, hash))
      .catch((err) => log.warn(`口令哈希升级失败 user=${account.username}: ${err.message}`));
  }
  const token = auth.createSessionToken(account.username);
  res.setHeader('Set-Cookie', auth.sessionCookie(token, config.auth.sessionTtlMs));
  log.info(`登录成功 user=${account.username} role=${account.role} ip=${ip}`);
  return res.json({
    ok: true,
    user: users.principal(account),
    expiresIn: Math.floor(config.auth.sessionTtlMs / 1000),
  });
}));

router.post('/logout', (req, res) => {
  if (!auth.isTrustedOrigin(req)) return res.status(403).json({ ok: false, message: '非法的请求来源' });
  const user = auth.userFromRequest(req);
  if (user) {
    // 退出时一并回收该账号的会话，并吊销此前签发的所有票据
    for (const s of registry.list(user.username)) registry.close(s.id, 'logout', user.username);
    auth.revokeAllForUser(user.username);
    audit.record({ type: 'auth.logout', user: user.username, ip: auth.clientIp(req) });
  }
  res.setHeader('Set-Cookie', auth.clearCookie());
  return res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({
    ok: true,
    user: {
      username: req.user.username,
      role: req.user.role,
      roleLabel: req.user.roleLabel,
      permissions: req.user.permissions,
    },
  });
});

/**
 * 敏感操作二次认证：重新输入当前账号口令，成功后该票据在 TTL 内可打开本机终端。
 * 与登录共用同一套失败限流，避免成为口令爆破入口。
 */
router.post('/step-up', requireAuth, asyncHandler(async (req, res) => {
  if (!auth.isTrustedOrigin(req)) {
    return res.status(403).json({ ok: false, message: '非法的请求来源' });
  }

  const ip = auth.clientIp(req);
  const gate = auth.checkLoginAllowed(ip);
  if (!gate.allowed) {
    res.setHeader('Retry-After', String(gate.retryAfter));
    return res.status(429).json({ ok: false, message: `尝试过于频繁，请 ${gate.retryAfter} 秒后再试` });
  }

  const plain = String((req.body && req.body.password) || '');
  if (!plain || plain.length > 512) {
    return res.status(400).json({ ok: false, message: '请输入当前账号口令' });
  }

  if (!(await auth.authenticate(req.user.username, plain))) {
    auth.recordLoginFailure(ip);
    metrics.inc('webssh_step_up_total', { result: 'failure' });
    audit.record({ type: 'auth.step_up', result: 'failure', user: req.user.username, ip });
    log.warn(`二次认证失败 user=${req.user.username} ip=${ip}`);
    return res.status(401).json({ ok: false, message: '口令不正确' });
  }

  auth.markStepUp(req.user.payload);
  metrics.inc('webssh_step_up_total', { result: 'success' });
  audit.record({ type: 'auth.step_up', result: 'success', user: req.user.username, ip });
  log.info(`二次认证通过 user=${req.user.username} ip=${ip}`);
  return res.json({ ok: true, expiresIn: Math.floor(config.auth.stepUpTtlMs / 1000) });
}));

/* ------------------------------ 会话管理 ------------------------------ */

router.get('/sessions', requireAuth, requirePermission('sessions:manage'), (req, res) => {
  res.json({ ok: true, sessions: registry.list(req.user.username) });
});

router.delete('/sessions/:id', requireAuth, requirePermission('sessions:manage'), (req, res) => {
  if (!auth.isTrustedOrigin(req)) return res.status(403).json({ ok: false, message: '非法的请求来源' });
  const closed = registry.close(req.params.id, 'closed_by_user', req.user.username);
  if (!closed) return res.status(404).json({ ok: false, message: '会话不存在或无权操作' });
  log.info(`会话被用户结束 id=${req.params.id} user=${req.user.username}`);
  res.json({ ok: true });
});

/* ------------------------------ 会话录像 ------------------------------ */

router.get('/recordings', requireAuth, requirePermission('audit:read'), (req, res) => {
  const all = hasPermission(req.user, 'audit:readAll');
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 300);

  res.json({
    ok: true,
    scope: all ? 'all' : 'self',
    items: recordings.list({ user: req.user.username, all, limit }),
    info: recordings.info(),
  });
});

router.get('/recordings/:id', requireAuth, requirePermission('audit:read'), (req, res) => {
  const all = hasPermission(req.user, 'audit:readAll');
  const found = recordings.get(req.params.id, { user: req.user.username, all });
  if (!found) return res.status(404).json({ ok: false, message: '录像不存在或无权访问' });

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `inline; filename="${found.meta.id}.cast"`);
  res.setHeader('Cache-Control', 'no-store');
  return res.sendFile(found.file);
});

/* ------------------------------ 公开信息 ------------------------------ */

router.get('/config', requireAuth, (req, res) => {
  const local = localTerminalAvailability();
  res.json({
    ok: true,
    tls: config.tls.enabled,
    maxSessionsPerUser: config.session.maxPerUser,
    resumeGraceSeconds: Math.floor(config.session.resumeGraceMs / 1000),
    scrollback: config.session.scrollbackLines,
    user: req.user.username,
    role: req.user.role,
    roleLabel: req.user.roleLabel,
    permissions: req.user.permissions,
    hostRestricted: Boolean(req.user.hostRestricted),
    multiUser: users.size() > 1,
    stepUp: {
      required: config.auth.stepUpRequired,
      ttlSeconds: Math.floor(config.auth.stepUpTtlMs / 1000),
      remainingSeconds: Math.floor(auth.stepUpRemaining(req.user.payload) / 1000),
    },
    localTerminal: {
      enabled: local.enabled,
      available: local.available && audit.canAcceptLocalSession(),
      reason:
        local.available && !audit.canAcceptLocalSession()
          ? '审计投递不可用，已按 fail-closed 策略禁用本机终端'
          : local.reason,
      shell: local.shell,
      cwd: local.cwd,
      hostname: local.hostname,
      platform: local.platform,
      user: local.user,
      maxSessions: local.maxSessions,
      auditEnabled: local.auditEnabled,
      limits: local.limits,
    },
    audit: audit.info(),
    recording: recordings.info(),
  });
});

/* ------------------------------ 审计查询 ------------------------------ */

router.get('/audit/verify', requireAuth, requirePermission('audit:read'), async (req, res) => {
  try {
    const result = await audit.verify();
    log.info(`审计哈希链校验 user=${req.user.username} ok=${result.ok} checked=${result.checked}`);
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

router.get('/audit', requireAuth, requirePermission('audit:read'), (req, res) => {
  const allowed = [
    'command',
    'session.start',
    'session.end',
    'session.limit',
    'auth.login',
    'auth.logout',
    'auth.step_up',
    'security.denied',
  ];
  const type = allowed.includes(String(req.query.type || '')) ? String(req.query.type) : null;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  // 审计员（audit:readAll）可查看全部用户，其余角色仅查看自己
  const scope = hasPermission(req.user, 'audit:readAll') ? null : req.user.username;

  res.json({
    ok: true,
    scope: scope ? 'self' : 'all',
    entries: audit.query({ user: scope || undefined, type, limit }),
    info: audit.info(),
  });
});

module.exports = router;
