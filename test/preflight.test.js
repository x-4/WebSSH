'use strict';

/** 启动自检测试 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-preflight-'));
process.env.DATA_DIR = dataDir;
process.env.NODE_ENV = 'development';
process.env.WEBSSH_USER = 'admin';
process.env.WEBSSH_PASS = 'preflight-pass-123';
process.env.SESSION_SECRET = 'h'.repeat(64);
process.env.SCRYPT_N = '16384';

const config = require('../src/config');
const { validate } = require('../src/preflight');

test('默认配置无致命错误，且创建数据目录', () => {
  const result = validate();
  assert.deepEqual(result.errors, []);
  assert.ok(fs.existsSync(dataDir));
});

test('SCRYPT_N 非 2 的幂时报错', () => {
  const original = config.auth.scryptN;
  config.auth.scryptN = 12345;
  try {
    const result = validate();
    assert.ok(result.errors.some((e) => e.includes('SCRYPT_N')));
  } finally {
    config.auth.scryptN = original;
  }
});

test('会话上限配置矛盾时报错', () => {
  const original = config.session.maxPerUser;
  config.session.maxPerUser = config.session.maxTotal + 1;
  try {
    const result = validate();
    assert.ok(result.errors.some((e) => e.includes('MAX_SESSIONS_PER_USER')));
  } finally {
    config.session.maxPerUser = original;
  }
});

test('数据目录不可写时报错', () => {
  const original = config.paths.data;
  // 以「文件」作为父路径，任何平台 mkdir 都会失败
  const blocker = path.join(dataDir, 'blocker');
  fs.writeFileSync(blocker, 'x');
  config.paths.data = path.join(blocker, 'data');
  try {
    const result = validate();
    assert.ok(result.errors.some((e) => e.includes('数据目录')));
  } finally {
    config.paths.data = original;
  }
});
