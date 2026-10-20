'use strict';

/**
 * Express 应用装配：安全响应头、API 路由、页面与静态资源。
 */

const crypto = require('crypto');
const express = require('express');
const path = require('path');
const config = require('./config');
const auth = require('./auth');
const logger = require('./logger');
const apiRouter = require('./routes/api');
const metrics = require('./metrics');
const health = require('./health');
const { createRateLimiter } = require('./ratelimit');
const { safeEqual } = require('./password');

const log = logger.create('http');

function securityHeaders(req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'", // xterm 运行时注入内联样式
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'", // 只允许同源 HTTP/WS，避免被注入脚本向任意端点外传
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "object-src 'none'",
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (config.tls.enabled) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.http.trustProxy);

  // 请求 ID：便于把访问日志与错误日志串起来
  app.use((req, res, next) => {
    const incoming = String(req.headers['x-request-id'] || '');
    req.id = /^[A-Za-z0-9._-]{8,64}$/.test(incoming) ? incoming : crypto.randomUUID();
    res.setHeader('X-Request-Id', req.id);
    next();
  });

  app.use(securityHeaders);

  // 反向代理后强制 HTTPS（依据 X-Forwarded-Proto，需同时开启 TRUST_PROXY）
  if (config.http.forceHttps) {
    app.use((req, res, next) => {
      if (req.path === '/healthz') return next();
      if (req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https') return next();
      const host = req.headers.host || '';
      return res.redirect(308, `https://${host}${req.originalUrl}`);
    });
  }

  app.use(express.json({ limit: '64kb' }));

  // /api 通用限流（登录另有更严格的失败计数）
  app.use(
    '/api',
    createRateLimiter({
      windowMs: 60 * 1000,
      max: config.http.rateLimitPerMin,
      keyFn: auth.clientIp,
    })
  );

  app.use('/api', apiRouter);
  app.get('/healthz', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

  app.get('/readyz', (req, res) => {
    const result = health.checkReadiness();
    res.status(result.ok ? 200 : 503).json(result);
  });

  app.get('/metrics', (req, res) => {
    if (!config.metrics.enabled) return res.status(404).end();
    if (config.metrics.token) {
      const header = String(req.headers.authorization || '');
      const token = header.startsWith('Bearer ') ? header.slice(7) : String(req.query.token || '');
      if (!safeEqual(token, config.metrics.token)) return res.status(401).end();
    }
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(metrics.render());
  });

  const publicDir = config.paths.public;

  app.get('/login', (req, res) => {
    if (auth.userFromRequest(req)) return res.redirect('/');
    res.sendFile(path.join(publicDir, 'login.html'));
  });

  app.get('/', (req, res) => {
    if (!auth.userFromRequest(req)) return res.redirect('/login');
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  app.use(
    express.static(publicDir, {
      index: false,
      etag: true,
      lastModified: true,
      // 第三方库长缓存，业务代码短缓存，便于升级后立即生效
      setHeaders(res, filePath) {
        if (filePath.includes(`${path.sep}vendor${path.sep}`)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else {
          res.setHeader('Cache-Control', 'no-cache');
        }
      },
    })
  );

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, message: '接口不存在' });
    res.status(404).sendFile(path.join(publicDir, '404.html'));
  });

  // 统一错误处理，避免把堆栈泄漏给客户端
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log.error(`请求处理失败 rid=${req.id} ${req.method} ${req.originalUrl}`, err.message);
    if (res.headersSent) return;
    const status = err.status && err.status < 500 ? err.status : 500;
    res.status(status).json({ ok: false, message: status === 500 ? '服务器内部错误' : err.message });
  });

  return app;
}

module.exports = { createApp };
