'use strict';

/**
 * 认证与会话票据。
 *
 * - 口令校验委托给 users.js（支持多用户 / 角色），哈希算法见 password.js；
 * - 票据为 HMAC-SHA256 签名，写入 HttpOnly + SameSite=Strict Cookie；
 * - 票据绑定进程实例标识（重启失效）与用户版本号（登出吊销）；
 * - 敏感操作二次认证（step-up）：按票据 jti 记录最近一次口令确认时间。
 */

const crypto = require('crypto');
const config = require('./config');
const logger = require('./logger');
const users = require('./users');
const password = require('./password');

const log = logger.create('auth');

const { hashPassword, hashPasswordAsync, verifyPasswordHash, verifyPasswordHashAsync, safeEqual } = password;

/* ------------------------------ 凭证 ------------------------------ */

function verifyCredentials(username, plainPassword) {
  return Boolean(users.verifyCredentials(username, plainPassword));
}

/** 登录入口：成功返回用户记录，失败返回 null（异步，避免阻塞事件循环） */
async function authenticate(username, plainPassword) {
  return users.verifyCredentialsAsync(username, plainPassword);
}

/* ------------------------------ 登录票据 ------------------------------ */

// 进程实例标识：写入票据并校验，服务重启后旧票据自动失效
const INSTANCE_EPOCH = crypto.randomBytes(8).toString('hex');

// 按用户维护票据版本号：登出后版本 +1，旧票据立即失效
const tokenVersions = new Map();

// 二次认证记录：jti -> { user, at }
const stepUps = new Map();

function currentVersion(username) {
  return tokenVersions.get(username) || 0;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', config.auth.sessionSecrets[0]).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function createSessionToken(username) {
  const now = Date.now();
  return sign({
    sub: username,
    iat: Math.floor(now / 1000),
    iatMs: now,
    exp: Math.floor((now + config.auth.sessionTtlMs) / 1000),
    ep: INSTANCE_EPOCH,
    ver: currentVersion(username),
    jti: crypto.randomBytes(8).toString('hex'),
  });
}

/** 吊销该用户此前签发的所有票据（登出、改密后调用） */
function revokeAllForUser(username) {
  tokenVersions.set(username, currentVersion(username) + 1);
  for (const [jti, record] of stepUps) {
    if (record.user === username) stepUps.delete(jti);
  }
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const idx = token.lastIndexOf('.');
  if (idx <= 0) return null;
  const body = token.slice(0, idx);
  const mac = token.slice(idx + 1);

  // 密钥环验证：支持 SESSION_SECRETS 轮换期间新旧票据并存
  let signatureOk = false;
  for (const secret of config.auth.sessionSecrets) {
    const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
    if (safeEqual(mac, expected)) {
      signatureOk = true;
      break;
    }
  }
  if (!signatureOk) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
    if (payload.ep !== INSTANCE_EPOCH) return null; // 服务已重启
    if (Number(payload.ver || 0) !== currentVersion(payload.sub)) return null; // 已吊销
    return payload;
  } catch {
    return null;
  }
}

/* ------------------------------ 二次认证 ------------------------------ */

function markStepUp(payload) {
  if (!payload || !payload.jti) return;
  stepUps.set(payload.jti, { user: payload.sub, at: Date.now() });
}

function hasStepUp(payload) {
  if (!payload || !payload.jti) return false;
  const record = stepUps.get(payload.jti);
  if (!record || record.user !== payload.sub) return false;
  return Date.now() - record.at < config.auth.stepUpTtlMs;
}

function stepUpRemaining(payload) {
  if (!hasStepUp(payload)) return 0;
  return Math.max(0, config.auth.stepUpTtlMs - (Date.now() - stepUps.get(payload.jti).at));
}

const stepUpSweeper = setInterval(() => {
  const now = Date.now();
  for (const [jti, record] of stepUps) {
    if (now - record.at > config.auth.stepUpTtlMs) stepUps.delete(jti);
  }
}, 60 * 1000);
if (stepUpSweeper.unref) stepUpSweeper.unref();

/* ------------------------------ Cookie ------------------------------ */

function parseCookies(header = '') {
  const out = {};
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k) continue;
    const raw = part.slice(i + 1).trim();
    try {
      out[k] = decodeURIComponent(raw);
    } catch {
      out[k] = raw; // 畸形 Cookie 不应导致请求失败
    }
  }
  return out;
}

function sessionCookie(token, maxAgeMs) {
  const attrs = [
    `${config.auth.cookieName}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (config.auth.secureCookie) attrs.push('Secure');
  return attrs.join('; ');
}

function clearCookie() {
  const attrs = [`${config.auth.cookieName}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (config.auth.secureCookie) attrs.push('Secure');
  return attrs.join('; ');
}

/**
 * 从请求中解析登录主体（HTTP 与 WebSocket 握手共用）。
 * 返回 { username, role, roleLabel, permissions, token, payload } 或 null。
 */
function userFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies[config.auth.cookieName];
  const payload = verifySessionToken(token);
  if (!payload) return null;

  const user = users.get(payload.sub);
  if (!user || user.disabled) return null;

  return { ...users.principal(user), token, payload };
}

/* ------------------------------ 登录限流 ------------------------------ */

const attempts = new Map(); // ip -> { count, resetAt, blockedUntil }

function clientIp(req) {
  const forwarded = config.http.trustProxy ? req.headers['x-forwarded-for'] : null;
  const raw = (Array.isArray(forwarded) ? forwarded[0] : forwarded) || req.socket.remoteAddress || 'unknown';
  return String(raw).split(',')[0].trim();
}

function checkLoginAllowed(ip) {
  const rec = attempts.get(ip);
  if (!rec) return { allowed: true };
  const now = Date.now();
  if (rec.blockedUntil && rec.blockedUntil > now) {
    return { allowed: false, retryAfter: Math.ceil((rec.blockedUntil - now) / 1000) };
  }
  if (rec.resetAt < now) {
    attempts.delete(ip);
    return { allowed: true };
  }
  if (rec.count >= config.auth.loginMaxAttempts) {
    rec.blockedUntil = now + config.auth.loginWindowMs;
    return { allowed: false, retryAfter: Math.ceil(config.auth.loginWindowMs / 1000) };
  }
  return { allowed: true };
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || rec.resetAt < now) {
    attempts.set(ip, { count: 1, resetAt: now + config.auth.loginWindowMs, blockedUntil: 0 });
  } else {
    rec.count += 1;
  }
}

function resetLoginAttempts(ip) {
  attempts.delete(ip);
}

const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of attempts) {
    if (rec.resetAt < now && (!rec.blockedUntil || rec.blockedUntil < now)) attempts.delete(ip);
  }
}, 60 * 1000);
if (sweeper.unref) sweeper.unref();

/* ------------------------------ 同源校验 ------------------------------ */

function requestOrigin(req) {
  return req.headers.origin || '';
}

function isTrustedOrigin(req) {
  const origin = requestOrigin(req);
  if (!origin) return true; // 非浏览器客户端（curl / 探活）
  if (config.http.allowedOrigins.length) return config.http.allowedOrigins.includes(origin);

  let originHost;
  try {
    originHost = new URL(origin).host;
  } catch {
    return false;
  }
  return originHost === String(req.headers.host || '');
}

module.exports = {
  hashPassword,
  hashPasswordAsync,
  verifyPasswordHash,
  verifyPasswordHashAsync,
  verifyCredentials,
  authenticate,
  createSessionToken,
  verifySessionToken,
  revokeAllForUser,
  markStepUp,
  hasStepUp,
  stepUpRemaining,
  sessionCookie,
  clearCookie,
  userFromRequest,
  parseCookies,
  clientIp,
  checkLoginAllowed,
  recordLoginFailure,
  resetLoginAttempts,
  isTrustedOrigin,
  requestOrigin,
};
