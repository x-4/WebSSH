'use strict';

/** 多用户与 RBAC 单元测试 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-rbac-'));
process.env.DATA_DIR = dataDir;
process.env.SESSION_SECRET = 'f'.repeat(64);
process.env.WEBSSH_USER = 'fallback';
process.env.WEBSSH_PASS = 'fallback-pass-123';

const { hashPassword } = require('../src/password');

// 先落盘用户文件，再加载 users（模块加载时自初始化）
fs.writeFileSync(
  path.join(dataDir, 'users.json'),
  JSON.stringify({
    users: [
      { username: 'root', role: 'admin', passwordHash: hashPassword('admin-pass-123') },
      {
        username: 'ops',
        role: 'operator',
        passwordHash: hashPassword('ops-pass-123'),
        hosts: ['10.0.0.*', '*.internal'],
      },
      { username: 'dev', role: 'developer', passwordHash: hashPassword('dev-pass-123') },
      { username: 'audit', role: 'auditor', passwordHash: hashPassword('audit-pass-123') },
      { username: 'off', role: 'admin', passwordHash: hashPassword('off-pass-123'), disabled: true },
    ],
  })
);

const users = require('../src/users');
const auth = require('../src/auth');

test('用户文件加载：角色与禁用状态', () => {
  assert.equal(users.size(), 5);
  assert.equal(users.get('ops').role, 'operator');
  assert.equal(users.get('off').disabled, true);
});

test('口令校验：正确 / 错误 / 禁用 / 未知用户', () => {
  assert.ok(users.verifyCredentials('ops', 'ops-pass-123'));
  assert.equal(users.verifyCredentials('ops', 'wrong'), null);
  assert.equal(users.verifyCredentials('off', 'off-pass-123'), null);
  assert.equal(users.verifyCredentials('nobody', 'whatever'), null);
});

test('异步凭证校验与哈希升级判断', async () => {
  const user = await users.verifyCredentialsAsync('ops', 'ops-pass-123');
  assert.ok(user);
  assert.equal(user.username, 'ops');

  assert.equal(await users.verifyCredentialsAsync('ops', 'wrong'), null);
  assert.equal(await users.verifyCredentialsAsync('nobody', 'x'), null);

  const weakHash = require('../src/password').hashPassword('x', { N: 16384 });
  assert.equal(users.needsRehash({ passwordHash: weakHash }), true);
  const current = require('../src/password').hashPassword('x');
  assert.equal(users.needsRehash({ passwordHash: current }), false);
});

test('角色权限矩阵符合最小权限', () => {
  const admin = users.roleInfo('admin').permissions;
  const operator = users.roleInfo('operator').permissions;
  const developer = users.roleInfo('developer').permissions;
  const auditor = users.roleInfo('auditor').permissions;

  assert.ok(admin.includes('terminal:local') && admin.includes('audit:readAll'));
  assert.ok(operator.includes('terminal:local') && !operator.includes('audit:readAll'));
  assert.ok(developer.includes('terminal:ssh') && !developer.includes('terminal:local'));
  assert.ok(auditor.includes('audit:readAll') && !auditor.includes('terminal:ssh'));
  assert.ok(!auditor.includes('terminal:local'));
});

test('请求主体：包含角色与权限', () => {
  const token = auth.createSessionToken('ops');
  const req = { headers: { cookie: `${'webssh_sid'}=${token}` } };
  const principal = auth.userFromRequest(req);

  assert.equal(principal.username, 'ops');
  assert.equal(principal.role, 'operator');
  assert.ok(principal.permissions.includes('terminal:local'));
  assert.ok(principal.payload.jti);
});

test('票据吊销后请求主体为空', () => {
  const token = auth.createSessionToken('dev');
  assert.ok(auth.userFromRequest({ headers: { cookie: `webssh_sid=${token}` } }));

  auth.revokeAllForUser('dev');
  assert.equal(auth.userFromRequest({ headers: { cookie: `webssh_sid=${token}` } }), null);
});

test('二次认证：标记后 TTL 内有效', () => {
  const token = auth.createSessionToken('root');
  const principal = auth.userFromRequest({ headers: { cookie: `webssh_sid=${token}` } });

  assert.equal(auth.hasStepUp(principal.payload), false);
  auth.markStepUp(principal.payload);
  assert.equal(auth.hasStepUp(principal.payload), true);
  assert.ok(auth.stepUpRemaining(principal.payload) > 0);
});

test('主机白名单：通配匹配与未限制账号', () => {
  assert.equal(users.canAccessHost('ops', '10.0.0.8'), true);
  assert.equal(users.canAccessHost('ops', '10.0.1.8'), false);
  assert.equal(users.canAccessHost('ops', 'db.internal'), true);
  assert.equal(users.canAccessHost('ops', 'a.b.internal'), false);
  assert.equal(users.canAccessHost('ops', 'evil.example.com'), false);

  // 未配置 hosts 的账号不受限制
  assert.equal(users.canAccessHost('dev', 'any.example.com'), true);
  assert.equal(users.principal(users.get('ops')).hostRestricted, true);
  assert.equal(users.principal(users.get('dev')).hostRestricted, false);
});

test('未知角色回退为 developer', () => {
  assert.equal(users.roleInfo('superuser').role, 'developer');
});
