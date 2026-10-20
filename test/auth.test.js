'use strict';

/**
 * 认证单元测试：口令哈希、票据签发/篡改、登出吊销。
 * 注意：config 在 require 时读取环境变量，必须先设置再引入模块。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-auth-'));
process.env.WEBSSH_USER = 'admin';
process.env.WEBSSH_PASS = 'test-pass-123';
process.env.SESSION_SECRET = 'a'.repeat(64);

const auth = require('../src/auth');
const config = require('../src/config');

test('口令哈希：可验证、不含明文、错误口令拒绝', () => {
  const hash = auth.hashPassword('Secret-123');
  assert.match(hash, /^scrypt\$/);
  assert.ok(!hash.includes('Secret-123'));
  assert.equal(auth.verifyPasswordHash('Secret-123', hash), true);
  assert.equal(auth.verifyPasswordHash('Secret-124', hash), false);
  assert.equal(auth.verifyPasswordHash('Secret-123', 'not-a-hash'), false);
});

test('异步哈希：与同步实现互通，错误口令拒绝', async () => {
  const asyncHash = await auth.hashPasswordAsync('Async-123');
  assert.equal(await auth.verifyPasswordHashAsync('Async-123', asyncHash), true);
  assert.equal(await auth.verifyPasswordHashAsync('wrong', asyncHash), false);

  const syncHash = auth.hashPassword('Sync-123');
  assert.equal(await auth.verifyPasswordHashAsync('Sync-123', syncHash), true);
});

test('凭证校验：用户名与口令都必须匹配', () => {
  assert.equal(auth.verifyCredentials('admin', 'test-pass-123'), true);
  assert.equal(auth.verifyCredentials('admin', 'wrong'), false);
  assert.equal(auth.verifyCredentials('root', 'test-pass-123'), false);
  assert.equal(auth.verifyCredentials('', ''), false);
});

test('会话票据：签发后可校验，篡改后失效', () => {
  const token = auth.createSessionToken('admin');
  const payload = auth.verifySessionToken(token);
  assert.equal(payload.sub, 'admin');
  assert.ok(payload.exp > Math.floor(Date.now() / 1000));

  const tampered = `${token.slice(0, -2)}${token.endsWith('aa') ? 'bb' : 'aa'}`;
  assert.equal(auth.verifySessionToken(tampered), null);
  assert.equal(auth.verifySessionToken('garbage'), null);
  assert.equal(auth.verifySessionToken(''), null);
});

test('登出吊销：旧票据立即失效，重新签发的票据可用', async () => {
  const before = auth.createSessionToken('admin');
  assert.ok(auth.verifySessionToken(before));

  auth.revokeAllForUser('admin');
  assert.equal(auth.verifySessionToken(before), null);

  await new Promise((resolve) => setTimeout(resolve, 5));
  const after = auth.createSessionToken('admin');
  assert.ok(auth.verifySessionToken(after));
});

test('密钥轮换：旧票据在过渡期仍可用，移除旧密钥后失效', () => {
  const original = config.auth.sessionSecrets;
  const issued = auth.createSessionToken('admin');

  config.auth.sessionSecrets = ['n'.repeat(64), ...original];
  try {
    assert.ok(auth.verifySessionToken(issued), '旧密钥签发的票据仍可验证');
    const fresh = auth.createSessionToken('admin');

    config.auth.sessionSecrets = [config.auth.sessionSecrets[0]];
    assert.equal(auth.verifySessionToken(issued), null, '旧密钥移除后旧票据失效');
    assert.ok(auth.verifySessionToken(fresh), '新密钥签发的票据有效');
  } finally {
    config.auth.sessionSecrets = original;
  }
});

test('Cookie 属性：HttpOnly + SameSite=Strict', () => {
  const cookie = auth.sessionCookie('token-value', 60000);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=60/);
});
