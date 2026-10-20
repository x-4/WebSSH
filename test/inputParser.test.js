'use strict';

/** 输入解析单元测试：命令还原与口令提示识别 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { createLineTracker, stripControlSequences, isSecretPrompt } = require('../src/sessions/inputParser');

test('普通命令按回车提交', () => {
  const tracker = createLineTracker();
  assert.deepEqual(tracker.feed('ls -la\r'), ['ls -la']);
  assert.deepEqual(tracker.feed('pwd\r'), ['pwd']);
});

test('退格与 Ctrl+U / Ctrl+W 生效', () => {
  const tracker = createLineTracker();
  assert.deepEqual(tracker.feed('ls ax\u007f\u007f\r'), ['ls ']);

  const t2 = createLineTracker();
  assert.deepEqual(t2.feed('garbage\u0015echo ok\r'), ['echo ok']);

  const t3 = createLineTracker();
  assert.deepEqual(t3.feed('echo bad\u0017\r'), ['echo ']);
});

test('方向键等转义序列不进入命令缓冲', () => {
  const tracker = createLineTracker();
  assert.deepEqual(tracker.feed('\u001b[A\u001b[Cecho hi\r'), ['echo hi']);
  assert.deepEqual(tracker.feed('\u001b]0;title\u0007ls\r'), ['ls']);
});

test('粘贴多行时逐行提交', () => {
  const tracker = createLineTracker();
  assert.deepEqual(tracker.feed('echo a\necho b\necho c\n'), ['echo a', 'echo b', 'echo c']);
});

test('Ctrl+C 清空当前行', () => {
  const tracker = createLineTracker();
  assert.deepEqual(tracker.feed('rm -rf /\u0003\r'), ['']);
});

test('控制序列剥离', () => {
  assert.equal(stripControlSequences('\u001b[31mred\u001b[0m'), 'red');
});

test('口令提示识别', () => {
  assert.equal(isSecretPrompt('Password: '), true);
  assert.equal(isSecretPrompt('[sudo] password for bob: '), true);
  assert.equal(isSecretPrompt('Enter passphrase for key: '), true);
  assert.equal(isSecretPrompt('输入密码：'), true);
  assert.equal(isSecretPrompt('Verify token:'), true);
  assert.equal(isSecretPrompt('PS D:\\webssh> '), false);
  assert.equal(isSecretPrompt('$ '), false);
  assert.equal(isSecretPrompt('mock-output: echo hi'), false);
});
