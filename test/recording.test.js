'use strict';

/** 会话录像单元测试 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-rec-'));
process.env.DATA_DIR = dataDir;
process.env.SESSION_SECRET = 'g'.repeat(64);

const recordings = require('../src/recordings');

async function waitFor(predicate, timeout = 3000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

test('录制输出与尺寸事件，元信息可查询', async () => {
  const id = crypto.randomUUID();
  const rec = recordings.start({ id, user: 'alice', kind: 'local', target: 'local@host', cols: 80, rows: 24 });
  assert.ok(rec, '应创建录像');

  rec.write('hello ');
  rec.resize(100, 30);
  rec.write('world');
  await rec.stop('test_end');

  const item = recordings.list({ user: 'alice' })[0];
  assert.equal(item.status, 'finished');
  assert.ok(item.sizeBytes > 0);

  const found = recordings.get(id, { user: 'alice' });
  assert.ok(found);
  const lines = fs.readFileSync(found.file, 'utf8').trim().split('\n');
  const header = JSON.parse(lines[0]);
  assert.equal(header.version, 2);
  assert.equal(header.width, 80);

  const body = lines.slice(1).map((line) => JSON.parse(line));
  assert.ok(body.some((ev) => ev[1] === 'o' && ev[2].includes('hello')));
  assert.ok(body.some((ev) => ev[1] === 'r' && ev[2] === '100x30'));
});

test('权限隔离：其他用户无法读取', async () => {
  const id = crypto.randomUUID();
  const rec = recordings.start({ id, user: 'bob', kind: 'ssh', target: 'root@host:22', cols: 90, rows: 30 });
  rec.write('secret-ish output');
  await rec.stop('test_end');

  assert.ok(recordings.get(id, { user: 'bob' }));
  assert.equal(recordings.get(id, { user: 'alice' }), null);
  assert.ok(recordings.get(id, { user: 'auditor', all: true }));
});

test('空会话不保留录像文件', async () => {
  const id = crypto.randomUUID();
  const rec = recordings.start({ id, user: 'carol', kind: 'ssh', target: 'x', cols: 80, rows: 24 });
  await rec.stop('connect_failed');
  assert.ok(!recordings.list({ user: 'carol' }).some((x) => x.id === id));
  assert.ok(!fs.existsSync(path.join(dataDir, 'recordings', `${id}.cast`)));
});

test('非法 id 不会被读取', () => {
  assert.equal(recordings.get('../../etc/passwd', { user: 'alice' }), null);
  assert.equal(recordings.get('not-a-uuid', { user: 'alice' }), null);
});
