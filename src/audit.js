'use strict';

/**
 * 操作审计（v2）。
 *
 * 记录 session.start / session.end / command / session.limit 四类事件，特性：
 * 1. 哈希链：每条记录携带 seq / prev / hash（HMAC-SHA256），篡改或删行可被检出；
 *    密钥由 AUDIT_CHAIN_KEY 提供，未配置时从 SESSION_SECRET 派生。
 * 2. 远端投递：AUDIT_FORWARD_URL 批量推送 JSON 事件到 SIEM / 日志网关；
 *    队列与健康状态可查询，AUDIT_REQUIRE_DELIVERY=true 时投递不健康将拒绝新建本机会话（fail-closed）。
 * 3. 可选 UDP syslog 旁路（AUDIT_SYSLOG_HOST），只发送不参与健康判定。
 * 4. 多文件轮转：audit.log → .1 … .N，按 AUDIT_KEEP_FILES 保留。
 *
 * 边界：
 * - 只记录「部署机本机会话」提交的命令行；SSH 远程命令需由目标主机审计。
 * - 命令按原文记录（密码提示处可用 AUDIT_REDACT_SECRET_PROMPTS 屏蔽），
 *   审计文件权限需收紧，避免在命令行书写明文密钥。
 * - 哈希链能发现篡改，但不能阻止拥有文件写权限的人删除整个文件；
 *   合规场景应启用远端投递，把日志实时送出本机。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dgram = require('dgram');

const config = require('./config');
const logger = require('./logger');
const metrics = require('./metrics');

const log = logger.create('audit');

const MAX_MEMORY = Math.max(50, config.audit.memoryEntries);
const MAX_CMD_LEN = 4096;
const GENESIS = '0'.repeat(64);
const FORWARD_RETRY_MAX_MS = 30000;
const FORWARD_FAILURE_THRESHOLD = 3; // 连续失败达到该次数判定为不健康

let ring = [];
let fd = null;
let fsyncTimer = null;
let fsyncWarned = false;
let seq = 0;
let lastHash = GENESIS;
let chainKey = null;
let udpSocket = null;

const queue = [];
let flushing = false;
let flushTimer = null;
let lastSuccessAt = 0;
let lastError = null;
let consecutiveFailures = 0;

/* ------------------------------ 初始化 ------------------------------ */

/** 审计链密钥：优先环境变量，其次独立的 data/audit.key，避免受 SESSION_SECRET 轮换影响 */
function loadChainKey() {
  if (config.audit.chainKey) return config.audit.chainKey;

  const keyFile = path.join(config.paths.data, 'audit.key');
  try {
    const existing = fs.readFileSync(keyFile, 'utf8').trim();
    if (existing) return existing;
  } catch {
    /* 首次启动 */
  }

  const generated = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(keyFile, `${generated}\n`, { mode: 0o600 });
  } catch (err) {
    log.warn(`无法持久化审计链密钥（将使用临时密钥）: ${err.message}`);
  }
  return generated;
}

function init() {
  chainKey = loadChainKey();

  loadTail();
  ensureFile();
  log.info(
    `审计: ${config.audit.enabled ? config.audit.file : '仅内存'} · 哈希链=${config.audit.hashChain ? '开' : '关'} · ` +
      `远端投递=${config.audit.forwardUrl ? '开' : '关'}${config.audit.requireDelivery ? '（fail-closed）' : ''}`
  );
  if (config.audit.requireDelivery && !config.audit.forwardUrl) {
    log.warn('AUDIT_REQUIRE_DELIVERY=true 但未配置 AUDIT_FORWARD_URL：本机终端将被拒绝，直到投递配置完成');
  }
}

function readTailEntries(file) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    return [];
  }
  if (!stat.size) return [];

  const start = Math.max(0, stat.size - 512 * 1024);
  const length = stat.size - start;
  let text = '';
  try {
    const fd = fs.openSync(file, 'r');
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, start);
    fs.closeSync(fd);
    text = buffer.toString('utf8');
  } catch (err) {
    log.warn('读取审计日志失败', err.message);
    return [];
  }

  const entries = [];
  for (const line of text.split('\n').filter(Boolean)) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      /* 从中间截断的行，忽略 */
    }
  }
  return entries;
}

function loadTail() {
  let entries = readTailEntries(config.audit.file);

  // 轮转后主文件可能为空：从最近一份备份续上 seq / hash，避免重启后链起点错乱
  if (!entries.length) entries = readTailEntries(`${config.audit.file}.1`);
  if (!entries.length) return;

  const last = entries[entries.length - 1];
  ring = entries.slice(-MAX_MEMORY);

  // 旧版本日志没有哈希链：归档后重新起链，避免校验被历史数据污染
  if (config.audit.hashChain && !last.hash) {
    log.warn('检测到旧格式审计日志（无哈希链），已归档并重新起链');
    rotate({ reason: 'upgrade' });
    return;
  }

  seq = Number(last.seq) || entries.length;
  if (config.audit.hashChain && last.hash) lastHash = last.hash;
}

/* ------------------------------ 写入 ------------------------------ */

/**
 * 以追加方式持有文件描述符，用 writeSync 写入：
 * - 进程崩溃时数据已交给内核，不会停留在 Node 的 Stream 缓冲区；
 * - 由定时器批量 fsync，兼顾断电场景与写入性能。
 */
function ensureFile() {
  if (!config.audit.enabled || fd !== null) return;
  try {
    fs.mkdirSync(path.dirname(config.audit.file), { recursive: true, mode: 0o700 });
    fd = fs.openSync(config.audit.file, 'a', 0o600);
    startFsyncTimer();
  } catch (err) {
    lastError = `本地审计不可用: ${err.message}`;
    log.warn(lastError);
  }
}

function startFsyncTimer() {
  if (fsyncTimer || !config.audit.fsyncIntervalMs) return;
  fsyncTimer = setInterval(() => {
    if (fd === null) return;
    try {
      fs.fsyncSync(fd);
    } catch (err) {
      if (!fsyncWarned) {
        fsyncWarned = true;
        log.warn(`审计 fsync 失败（后续不再重复告警）: ${err.message}`);
      }
    }
  }, config.audit.fsyncIntervalMs);
  if (fsyncTimer.unref) fsyncTimer.unref();
}

function stopFsyncTimer() {
  clearInterval(fsyncTimer);
  fsyncTimer = null;
}

function writeLine(line) {
  if (fd === null) return;
  try {
    fs.writeSync(fd, line);
  } catch (err) {
    lastError = `本地审计写入失败: ${err.message}`;
    log.warn(lastError);
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
    fd = null;
    stopFsyncTimer();
  }
}

function rotateIfNeeded() {
  if (!config.audit.enabled) return;
  try {
    if (fs.statSync(config.audit.file).size >= config.audit.maxFileBytes) rotate({ reason: 'size' });
  } catch {
    /* 文件不存在 */
  }
}

function rotate({ reason } = {}) {
  if (fd !== null) {
    try {
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
    fd = null;
  }
  stopFsyncTimer();
  const file = config.audit.file;
  const keep = config.audit.keepFiles;
  try {
    // 删除最旧的备份，再依次后移
    for (let i = keep; i >= 1; i -= 1) {
      const src = i === 1 ? file : `${file}.${i - 1}`;
      const dst = `${file}.${i}`;
      if (!fs.existsSync(src)) continue;
      if (i === keep && fs.existsSync(dst)) fs.unlinkSync(dst);
      fs.renameSync(src, dst);
    }
    log.info(`审计日志已轮转（${reason}），保留 ${keep} 份`);
  } catch (err) {
    log.warn('审计日志轮转失败', err.message);
  }
  ensureFile();
}

function computeHash(entry) {
  return crypto.createHmac('sha256', chainKey).update(JSON.stringify(entry)).digest('hex');
}

function record(event) {
  const entry = { ts: new Date().toISOString(), seq: (seq += 1), ...event };

  if (config.audit.hashChain) {
    entry.prev = lastHash;
    entry.hash = computeHash(entry);
    lastHash = entry.hash;
  }

  ring.push(entry);
  if (ring.length > MAX_MEMORY) ring.splice(0, ring.length - MAX_MEMORY);

  if (config.audit.enabled) {
    if (entry.type === 'command' || entry.type === 'session.start') rotateIfNeeded();
    ensureFile();
    writeLine(`${JSON.stringify(entry)}\n`);
  }

  deliver(entry);
  return entry;
}

/* ------------------------------ 事件封装 ------------------------------ */

function sessionStart({ user, sessionId, kind, target }) {
  return record({ type: 'session.start', user, sessionId, kind, target });
}

function sessionEnd({ user, sessionId, kind, reason, durationMs }) {
  return record({ type: 'session.end', user, sessionId, kind, reason, durationMs });
}

function sessionLimit({ user, sessionId, kind, reason, detail }) {
  return record({ type: 'session.limit', user, sessionId, kind, reason, detail });
}

function command({ user, sessionId, kind, cmd, shell, redacted = false }) {
  if (!config.audit.recordCommands) return null;
  const text = String(cmd || '').slice(0, MAX_CMD_LEN);
  if (!redacted && !text.trim()) return null;
  metrics.inc('webssh_command_total', { kind });
  return record({
    type: 'command',
    user,
    sessionId,
    kind,
    // 密码提示处的输入只保留标记，不落明文
    cmd: redacted ? '[REDACTED: 疑似密码输入]' : text,
    ...(redacted ? { redacted: true } : {}),
    ...(shell ? { shell } : {}),
  });
}

/* ------------------------------ 远端投递 ------------------------------ */

function forwardTargetLabel() {
  try {
    const u = new URL(config.audit.forwardUrl);
    return `${u.protocol}//${u.host}`;
  } catch {
    return 'invalid-url';
  }
}

function deliver(entry) {
  if (config.audit.forwardUrl) {
    if (queue.length >= config.audit.forwardQueueMax) {
      queue.shift();
      if (!lastError) lastError = '投递队列已满，最早的事件被丢弃';
    }
    queue.push(entry);
    scheduleFlush(100);
  }
  if (config.audit.syslogHost) sendSyslog(entry);
}

function scheduleFlush(delay) {
  if (flushTimer || flushing || !queue.length) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flush();
  }, delay);
  if (flushTimer.unref) flushTimer.unref();
}

async function flush() {
  if (flushing || !queue.length || !config.audit.forwardUrl) return;
  flushing = true;

  const batch = queue.slice(0, config.audit.forwardBatch);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.audit.forwardTimeoutMs);

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (config.audit.forwardToken) headers.Authorization = `Bearer ${config.audit.forwardToken}`;

    const res = await fetch(config.audit.forwardUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ source: 'webssh', host: forwardTargetLabel(), events: batch }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    queue.splice(0, batch.length);
    lastSuccessAt = Date.now();
    lastError = null;
    consecutiveFailures = 0;
  } catch (err) {
    consecutiveFailures += 1;
    lastError = err.name === 'AbortError' ? '投递超时' : err.message;
    log.warn(`审计投递失败（第 ${consecutiveFailures} 次）: ${lastError}`);
  } finally {
    clearTimeout(timer);
    flushing = false;
    if (queue.length) {
      const backoff = Math.min(1000 * 2 ** Math.min(consecutiveFailures, 5), FORWARD_RETRY_MAX_MS);
      scheduleFlush(backoff);
    }
  }
}

function sendSyslog(entry) {
  try {
    if (!udpSocket) {
      udpSocket = dgram.createSocket('udp4');
      udpSocket.unref();
      udpSocket.on('error', (err) => log.debug('syslog 发送失败', err.message));
    }
    const payload = Buffer.from(`<14>${JSON.stringify(entry)}`);
    udpSocket.send(payload, config.audit.syslogPort, config.audit.syslogHost, () => {});
  } catch (err) {
    log.debug('syslog 异常', err.message);
  }
}

/**
 * 投递是否健康：未配置远端投递时恒为 true。
 * 判定依据是「连续失败次数」与「积压量」，而非是否有流量，
 * 避免长时间空闲后被误判为不健康。
 */
function isHealthy() {
  if (!config.audit.forwardUrl) return true;
  if (queue.length >= config.audit.forwardQueueMax) return false;
  return consecutiveFailures < FORWARD_FAILURE_THRESHOLD;
}

/**
 * fail-closed 判定：要求投递时必须配置 AUDIT_FORWARD_URL，
 * 且投递链路健康，否则拒绝新建本机会话。
 */
function canAcceptLocalSession() {
  if (!config.audit.requireDelivery) return true;
  if (!config.audit.forwardUrl) return false;
  return isHealthy();
}

/* ------------------------------ 查询与校验 ------------------------------ */

function query({ user, type, limit = 100 } = {}) {
  let list = ring;
  if (user) list = list.filter((e) => e.user === user);
  if (type) list = list.filter((e) => e.type === type);
  return list.slice(-Math.min(Math.max(Number(limit) || 100, 1), 500));
}

/**
 * 校验当前审计文件的哈希链完整性。
 * 仅覆盖当前文件（不含已轮转的备份），用于「是否被篡改」的快速判断。
 */
async function verify() {
  if (!config.audit.hashChain) {
    return { ok: true, hashChain: false, checked: 0, file: null, reason: 'hashChainDisabled' };
  }

  let text;
  try {
    text = await fs.promises.readFile(config.audit.file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return { ok: true, hashChain: true, checked: 0, file: config.audit.file };
    return { ok: false, hashChain: true, checked: 0, file: config.audit.file, reason: err.message };
  }

  const lines = text.split('\n').filter(Boolean);
  let prev = GENESIS;
  let expectedSeq = null;
  let checked = 0;
  let startsAtSeq = null;

  for (let i = 0; i < lines.length; i += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return { ok: false, hashChain: true, checked, file: config.audit.file, reason: 'unparsable-line', line: i + 1 };
    }

    if (typeof entry.seq !== 'number' || !entry.hash || !entry.prev) {
      return { ok: false, hashChain: true, checked, file: config.audit.file, reason: 'unsigned-entry', line: i + 1 };
    }
    if (expectedSeq === null) {
      // 文件可能从轮转点开始（seq > 1）：以首行的 seq/prev 作为基线，
      // 跨文件连续性需结合远端投递的副本判断。
      expectedSeq = entry.seq;
      startsAtSeq = entry.seq;
      if (startsAtSeq > 1 && entry.prev) prev = entry.prev;
    }
    if (entry.seq !== expectedSeq) {
      return { ok: false, hashChain: true, checked, file: config.audit.file, reason: 'sequence-gap', line: i + 1, seq: entry.seq };
    }
    if (entry.prev !== prev) {
      return { ok: false, hashChain: true, checked, file: config.audit.file, reason: 'broken-link', line: i + 1, seq: entry.seq };
    }

    const { hash, ...rest } = entry;
    if (computeHash(rest) !== hash) {
      return { ok: false, hashChain: true, checked, file: config.audit.file, reason: 'hash-mismatch', line: i + 1, seq: entry.seq };
    }

    prev = hash;
    expectedSeq += 1;
    checked += 1;
  }

  return {
    ok: true,
    hashChain: true,
    checked,
    file: config.audit.file,
    startsAtSeq,
    lastHash: prev === GENESIS ? null : prev,
  };
}

function info() {
  return {
    enabled: config.audit.enabled,
    recordCommands: config.audit.recordCommands,
    redactSecretPrompts: config.audit.redactSecretPrompts,
    hashChain: config.audit.hashChain,
    file: config.audit.enabled ? config.audit.file : null,
    memoryEntries: ring.length,
    seq,
    forward: {
      enabled: Boolean(config.audit.forwardUrl),
      target: config.audit.forwardUrl ? forwardTargetLabel() : null,
      requireDelivery: config.audit.requireDelivery,
      healthy: isHealthy(),
      pending: queue.length,
      lastError,
    },
    syslog: { enabled: Boolean(config.audit.syslogHost), host: config.audit.syslogHost || null },
  };
}

/** 优雅退出前尽力把队列刷出（最多等待 1.5s） */
async function shutdown() {
  clearTimeout(flushTimer);
  flushTimer = null;
  if (queue.length) {
    await Promise.race([flush(), new Promise((r) => setTimeout(r, 1500))]);
  }
  stopFsyncTimer();
  if (fd !== null) {
    try {
      fs.fsyncSync(fd);
    } catch {
      /* ignore */
    }
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
    fd = null;
  }
  if (udpSocket) {
    try {
      udpSocket.close();
    } catch {
      /* ignore */
    }
    udpSocket = null;
  }
}

module.exports = {
  init,
  record,
  sessionStart,
  sessionEnd,
  sessionLimit,
  command,
  query,
  verify,
  info,
  isHealthy,
  canAcceptLocalSession,
  shutdown,
};
