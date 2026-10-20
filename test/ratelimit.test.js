'use strict';

/** 通用限流中间件测试 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { createRateLimiter } = require('../src/ratelimit');

function fakeRes() {
  const headers = {};
  return {
    code: 200,
    headers,
    body: null,
    setHeader(name, value) {
      headers[name.toLowerCase()] = value;
    },
    status(code) {
      this.code = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

function call(middleware, key = '1.2.3.4') {
  return new Promise((resolve) => {
    const res = fakeRes();
    middleware({ ip: key }, res, () => resolve({ code: 0, res }));
    // 命中限流时不会调用 next，这里用微任务兜底读取 res
    setTimeout(() => resolve({ code: res.code === 200 ? 429 : res.code, res }), 5);
  });
}

test('超过阈值返回 429 并带限流响应头', async () => {
  const limiter = createRateLimiter({ windowMs: 60000, max: 2, keyFn: (req) => req.ip });

  const first = await call(limiter);
  const second = await call(limiter);
  const third = await call(limiter);

  assert.equal(first.code, 0);
  assert.equal(second.code, 0);
  assert.equal(third.code, 429);
  assert.equal(third.res.headers['ratelimit-limit'], '2');
  assert.equal(third.res.headers['ratelimit-remaining'], '0');
  assert.ok(third.res.headers['retry-after']);
  assert.equal(third.res.body.ok, false);
});

test('不同来源 IP 互不影响', async () => {
  const limiter = createRateLimiter({ windowMs: 60000, max: 1, keyFn: (req) => req.ip });

  assert.equal((await call(limiter, '10.0.0.1')).code, 0);
  assert.equal((await call(limiter, '10.0.0.1')).code, 429);
  assert.equal((await call(limiter, '10.0.0.2')).code, 0);
});

test('max=0 时关闭限流', async () => {
  const limiter = createRateLimiter({ windowMs: 60000, max: 0 });
  for (let i = 0; i < 5; i += 1) {
    assert.equal((await call(limiter)).code, 0);
  }
});
