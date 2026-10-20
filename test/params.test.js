'use strict';

/** 参数校验单元测试 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-params-'));
process.env.SESSION_SECRET = 'd'.repeat(64);

const { validateSshParams, validateLocalParams } = require('../src/sessions');

test('SSH 参数：合法输入与默认值', () => {
  const p = validateSshParams({ host: 'example.com', username: 'root', password: 'x' });
  assert.equal(p.host, 'example.com');
  assert.equal(p.port, 22);
  assert.equal(p.authType, 'password');
  assert.equal(p.cols, 80);
  assert.equal(p.rows, 24);
  assert.equal(p.term, 'xterm-256color');
});

test('SSH 参数：拒绝非法主机与端口', () => {
  assert.throws(() => validateSshParams({ host: 'bad host', username: 'root', password: 'x' }), /主机地址/);
  assert.throws(() => validateSshParams({ host: '', username: 'root', password: 'x' }), /主机地址/);
  assert.throws(() => validateSshParams({ host: 'a.com', port: 70000, username: 'root', password: 'x' }), /端口/);
  assert.throws(() => validateSshParams({ host: 'a.com', port: 22, username: 'a b', password: 'x' }), /用户名/);
});

test('SSH 参数：认证方式校验', () => {
  assert.throws(() => validateSshParams({ host: 'a.com', username: 'root' }), /密码/);
  assert.throws(
    () => validateSshParams({ host: 'a.com', username: 'root', authType: 'key', privateKey: 'not-a-key' }),
    /私钥/
  );

  const withKey = validateSshParams({
    host: 'a.com',
    username: 'root',
    authType: 'key',
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----',
  });
  assert.equal(withKey.authType, 'key');
  assert.equal(withKey.password, '');
});

test('本机参数：尺寸被限制在合理范围', () => {
  assert.deepEqual(validateLocalParams({ cols: 5, rows: 1 }), { cols: 20, rows: 5, term: 'xterm-256color' });
  assert.deepEqual(validateLocalParams({ cols: 9999, rows: 9999 }), { cols: 500, rows: 300, term: 'xterm-256color' });
  assert.equal(validateLocalParams({ term: 'bad term!' }).term, 'xterm-256color');
});
