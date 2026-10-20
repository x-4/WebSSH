'use strict';

/** 审计单元测试：哈希链、篡改检测、脱敏、远端投递 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-audit-'));
process.env.DATA_DIR = dataDir;
process.env.SESSION_SECRET = 'c'.repeat(64);
process.env.AUDIT_CHAIN_KEY = 'unit-test-chain-key';
process.env.AUDIT_RECORD_COMMANDS = 'true';
process.env.AUDIT_MAX_FILE_MB = '1';

const auditFile = path.join(dataDir, 'audit.log');
const received = [];

async function waitForFile(file, timeout = 2000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('文件未创建: ' + file);
}

let audit;
let sink;

test.before(async () => {
  sink = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        received.push(JSON.parse(body));
      } catch {
        received.push({ raw: body });
      }
      res.writeHead(204);
      res.end();
    });
  });

  await new Promise((resolve) => sink.listen(0, '127.0.0.1', resolve));
  process.env.AUDIT_FORWARD_URL = `http://127.0.0.1:${sink.address().port}/ingest`;

  // 必须在设置环境变量后再加载模块
  audit = require('../src/audit');
  audit.init();
});

test.after(async () => {
  await audit.shutdown();
  await new Promise((resolve) => sink.close(resolve));
});

test('写入后立即可读，不依赖流缓冲刷新', () => {
  audit.record({ type: 'durability.test', user: 'tester' });
  const text = fs.readFileSync(auditFile, 'utf8');
  assert.ok(text.includes('durability.test'));
});

test('记录写入文件并带哈希链字段', async () => {
  audit.sessionStart({ user: 'tester', sessionId: 's1', kind: 'local', target: 'bash' });
  audit.command({ user: 'tester', sessionId: 's1', kind: 'local', cmd: 'echo hi' });
  await waitForFile(auditFile);

  const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean);
  assert.ok(lines.length >= 2);

  const entry = JSON.parse(lines[lines.length - 1]);
  assert.equal(entry.type, 'command');
  assert.equal(entry.cmd, 'echo hi');
  assert.equal(typeof entry.seq, 'number');
  assert.match(entry.prev, /^[0-9a-f]{64}$/);
  assert.match(entry.hash, /^[0-9a-f]{64}$/);

  const result = await audit.verify();
  assert.equal(result.ok, true);
  assert.ok(result.checked >= 2);
});

test('篡改命令内容后校验失败', async () => {
  const original = fs.readFileSync(auditFile, 'utf8');
  const lines = original.split('\n');
  const index = lines.findIndex((line) => line.includes('echo hi'));
  assert.ok(index >= 0);

  lines[index] = lines[index].replace('echo hi', 'echo HACKED');
  fs.writeFileSync(auditFile, lines.join('\n'));

  const result = await audit.verify();
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'hash-mismatch');
  assert.equal(result.line, index + 1);

  fs.writeFileSync(auditFile, original);
  assert.equal((await audit.verify()).ok, true);
});

test('删除中间记录会被检出（序号断档）', async () => {
  audit.record({ type: 'test.marker', user: 'tester' });
  const original = fs.readFileSync(auditFile, 'utf8').split('\n').filter(Boolean);
  assert.ok(original.length >= 3);

  const removed = original.filter((_, i) => i !== 1);
  fs.writeFileSync(auditFile, `${removed.join('\n')}\n`);

  const result = await audit.verify();
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'sequence-gap');

  fs.writeFileSync(auditFile, `${original.join('\n')}\n`);
});

test('敏感输入只记录脱敏标记', () => {
  const entry = audit.command({
    user: 'tester',
    sessionId: 's1',
    kind: 'local',
    cmd: '',
    redacted: true,
  });
  assert.equal(entry.redacted, true);
  assert.match(entry.cmd, /REDACTED/);
  assert.ok(!entry.cmd.includes('SuperSecret'));
});

test('远端投递：事件送达且健康度为真', async () => {
  for (let i = 0; i < 20 && received.length === 0; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  assert.ok(received.length > 0, '应收到至少一批投递');
  const events = received.flatMap((batch) => batch.events || []);
  assert.ok(events.some((e) => e.type === 'command'));
  assert.ok(events.some((e) => e.type === 'session.start'));

  const info = audit.info();
  assert.equal(info.forward.enabled, true);
  assert.equal(info.forward.healthy, true);
  assert.equal(audit.canAcceptLocalSession(), true);
});
