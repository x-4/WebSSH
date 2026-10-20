'use strict';

/**
 * 会话录像（asciinema v2 cast）。
 *
 * 每个会话输出一个 .cast 文件（含终端尺寸与逐帧输出），旁边保存 .json 元信息，
 * 便于列表查询与权限校验。录像只记录「终端输出」，不记录键盘输入，
 * 因此不会把密码等键入内容写进录像（输出中的敏感内容仍可能被记录，需控制权限）。
 *
 * 文件布局：data/recordings/<sessionId>.cast / <sessionId>.json
 * 容量控制：单会话 RECORDING_MAX_MB，保留 RECORDING_KEEP_DAYS 天。
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const config = require('./config');
const logger = require('./logger');

const log = logger.create('recording');

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_LIST = 300;

function ensureDir() {
  fs.mkdirSync(config.recording.dir, { recursive: true, mode: 0o700 });
}

function metaPath(id) {
  return path.join(config.recording.dir, `${id}.json`);
}

function castPath(id) {
  return path.join(config.recording.dir, `${id}.cast`);
}

function readMeta(id) {
  try {
    return JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
  } catch {
    return null;
  }
}

function writeMeta(meta) {
  try {
    fs.writeFileSync(metaPath(meta.id), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
  } catch (err) {
    log.warn(`写入录像元信息失败: ${err.message}`);
  }
}

/**
 * 开始录制。返回 null 表示未启用。
 * @param {{id:string,user:string,kind:string,target?:string,cols:number,rows:number}} info
 */
function start(info) {
  if (!config.recording.enabled) return null;
  if (!ID_RE.test(String(info.id || ''))) return null;

  try {
    ensureDir();
  } catch (err) {
    log.warn(`录像目录不可用: ${err.message}`);
    return null;
  }

  const id = String(info.id);
  const startedAt = Date.now();
  const startedIso = new Date(startedAt).toISOString();
  const meta = {
    id,
    user: info.user || 'unknown',
    kind: info.kind || 'ssh',
    target: info.target || '',
    cols: Number(info.cols) || 80,
    rows: Number(info.rows) || 24,
    startedAt: startedIso,
    status: 'recording',
    sizeBytes: 0,
    events: 0,
  };

  let stream;
  try {
    stream = fs.createWriteStream(castPath(id), { mode: 0o600 });
  } catch (err) {
    log.warn(`创建录像文件失败: ${err.message}`);
    return null;
  }

  let stopped = false;

  // 磁盘写满 / 权限变化等错误不应影响终端主流程
  stream.on('error', (err) => {
    log.warn(`录像写入失败（${id}）: ${err.message}`);
    stopped = true;
  });

  const header = JSON.stringify({
    version: 2,
    width: meta.cols,
    height: meta.rows,
    timestamp: Math.floor(startedAt / 1000),
    env: { TERM: 'xterm-256color', HOST: os.hostname() },
  });
  stream.write(`${header}\n`);

  let bytes = Buffer.byteLength(header) + 1;
  let events = 0;
  writeMeta(meta);

  function finish(reason) {
    if (stopped) return Promise.resolve();
    stopped = true;
    const durationMs = Date.now() - startedAt;

    return new Promise((resolve) => {
      stream.end(() => {
        if (events === 0 && durationMs < 2000) {
          // 连接失败等空会话，不保留垃圾文件
          try {
            fs.unlinkSync(castPath(id));
          } catch {
            /* ignore */
          }
          try {
            fs.unlinkSync(metaPath(id));
          } catch {
            /* ignore */
          }
          resolve();
          return;
        }
        writeMeta({
          ...meta,
          status: reason === 'size_limit' ? 'truncated' : 'finished',
          endedAt: new Date().toISOString(),
          durationMs,
          sizeBytes: bytes,
          events,
          stopReason: reason,
        });
        resolve();
      });
    });
  }

  return {
    id,
    write(text) {
      if (stopped || !text) return;
      const t = ((Date.now() - startedAt) / 1000).toFixed(3);
      const line = `${JSON.stringify([Number(t), 'o', text])}\n`;
      const size = Buffer.byteLength(line);
      if (bytes + size > config.recording.maxBytes) {
        log.warn(`录像达到大小上限，提前结束: ${id}`);
        finish('size_limit');
        return;
      }
      bytes += size;
      events += 1;
      stream.write(line);
    },
    resize(cols, rows) {
      if (stopped) return;
      meta.cols = cols;
      meta.rows = rows;
      const t = ((Date.now() - startedAt) / 1000).toFixed(3);
      const line = `${JSON.stringify([Number(t), 'r', `${cols}x${rows}`])}\n`;
      const size = Buffer.byteLength(line);
      if (bytes + size > config.recording.maxBytes) return;
      bytes += size;
      events += 1;
      stream.write(line);
    },
    stop(reason = 'session_end') {
      return finish(reason);
    },
  };
}

/** 服务重启时把残留的 recording 状态标记为 interrupted */
function recover() {
  if (!config.recording.enabled) return;
  let names = [];
  try {
    names = fs.readdirSync(config.recording.dir);
  } catch {
    return;
  }
  let count = 0;
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    const meta = readMeta(name.slice(0, -5));
    if (!meta) continue;

    // 元信息存在但录像文件丢失：清理孤儿元信息
    if (!fs.existsSync(castPath(meta.id))) {
      try {
        fs.unlinkSync(metaPath(meta.id));
      } catch {
        /* ignore */
      }
      continue;
    }
    if (meta.status !== 'recording') continue;
    let size = 0;
    try {
      size = fs.statSync(castPath(meta.id)).size;
    } catch {
      /* ignore */
    }
    writeMeta({ ...meta, status: 'interrupted', endedAt: new Date().toISOString(), sizeBytes: size });
    count += 1;
  }
  if (count) log.info(`已将 ${count} 个未正常结束的录像标记为 interrupted`);
}

/** 清理超过保留期的录像 */
function cleanup() {
  if (!config.recording.enabled || !config.recording.keepDays) return;
  const cutoff = Date.now() - config.recording.keepDays * 24 * 60 * 60 * 1000;
  let names = [];
  try {
    names = fs.readdirSync(config.recording.dir);
  } catch {
    return;
  }
  let removed = 0;
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    const meta = readMeta(name.slice(0, -5));
    if (!meta) continue;
    const started = Date.parse(meta.startedAt || '');
    if (!Number.isFinite(started) || started >= cutoff) continue;
    for (const suffix of ['.json', '.cast']) {
      try {
        fs.unlinkSync(path.join(config.recording.dir, `${meta.id}${suffix}`));
        removed += 1;
      } catch {
        /* ignore */
      }
    }
  }
  if (removed) log.info(`已清理 ${removed} 个过期录像文件`);
}

function list({ user, all = false, limit = 100 } = {}) {
  let names = [];
  try {
    names = fs.readdirSync(config.recording.dir).filter((n) => n.endsWith('.json'));
  } catch {
    return [];
  }

  const items = [];
  for (const name of names) {
    const meta = readMeta(name.slice(0, -5));
    if (!meta) continue;
    if (!all && meta.user !== user) continue;
    // 没有录像文件的条目不可回放，直接跳过
    if (!fs.existsSync(path.join(config.recording.dir, `${meta.id}.cast`))) continue;
    items.push({
      id: meta.id,
      user: meta.user,
      kind: meta.kind,
      target: meta.target,
      startedAt: meta.startedAt,
      endedAt: meta.endedAt || null,
      durationMs: meta.durationMs || 0,
      sizeBytes: meta.sizeBytes || 0,
      status: meta.status,
      cols: meta.cols,
      rows: meta.rows,
    });
  }

  items.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
  return items.slice(0, Math.min(Math.max(Number(limit) || 100, 1), MAX_LIST));
}

function get(id, { user, all = false } = {}) {
  if (!ID_RE.test(String(id || ''))) return null;
  const meta = readMeta(id);
  if (!meta) return null;
  if (!all && meta.user !== user) return null;
  if (!fs.existsSync(castPath(id))) return null;
  return { meta, file: castPath(id) };
}

function info() {
  return {
    enabled: config.recording.enabled,
    dir: config.recording.enabled ? config.recording.dir : null,
    maxMb: Math.round(config.recording.maxBytes / (1024 * 1024)),
    keepDays: config.recording.keepDays,
  };
}

module.exports = { start, list, get, info, recover, cleanup, ID_RE };
