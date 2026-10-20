'use strict';

/**
 * 轻量固定窗口限流（按 IP），用于 /api 的通用保护。
 * 登录与二次认证另有更严格的失败计数，不依赖本模块。
 */

function createRateLimiter({ windowMs = 60000, max = 300, keyFn, message } = {}) {
  const hits = new Map();

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of hits) {
      if (record.resetAt <= now) hits.delete(key);
    }
  }, Math.max(windowMs, 30000));
  if (sweeper.unref) sweeper.unref();

  return function rateLimit(req, res, next) {
    if (!max) return next();

    const key = keyFn ? keyFn(req) : req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let record = hits.get(key);

    if (!record || record.resetAt <= now) {
      record = { count: 0, resetAt: now + windowMs };
      hits.set(key, record);
    }

    record.count += 1;
    const remaining = Math.max(0, max - record.count);

    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(Math.ceil((record.resetAt - now) / 1000)));

    if (record.count > max) {
      res.setHeader('Retry-After', String(Math.ceil((record.resetAt - now) / 1000)));
      return res.status(429).json({ ok: false, message: message || '请求过于频繁，请稍后再试' });
    }

    return next();
  };
}

module.exports = { createRateLimiter };
