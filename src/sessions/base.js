'use strict';

/**
 * 会话基类：承载与具体传输方式无关的能力。
 *
 * 无论是 SSH 远程会话还是部署机本机会话，都需要：
 * 输出缓冲与重连回放、输出合帧、背压、Socket 挂载/卸载、统一关闭流程。
 * 具体建连方式由子类（ssh / local）实现。
 */

const os = require('os');
const config = require('../config');
const logger = require('../logger');
const recordings = require('../recordings');

const log = logger.create('session');

const HIGH_WATER_BYTES = 4 * 1024 * 1024; // WebSocket 待发送积压高水位
const LOW_WATER_BYTES = 1 * 1024 * 1024; // 低水位，降至此值以下恢复读取

class BaseSession {
  constructor({ id, token, owner, kind, params }) {
    this.id = id;
    this.token = token;
    this.owner = owner;
    this.kind = kind; // 'ssh' | 'local'
    this.params = params;
    this.cols = params.cols;
    this.rows = params.rows;

    this.socket = null;
    this.state = 'connecting'; // connecting | connected | closed
    this.closed = false;
    this.closeReason = null;
    this.exitInfo = null;

    this.createdAt = Date.now();
    this.connectedAt = null;
    this.lastActiveAt = Date.now();

    this.replay = [];
    this.replayBytes = 0;
    this.replayTruncated = false;

    this.outQueue = [];
    this.flushTimer = null;

    this.detachTimer = null;
    this.idleTimer = null;
    this.pauseTimer = null;

    this.onClose = null;

    // 会话录像（只记录输出与窗口尺寸变化）
    const target =
      kind === 'local'
        ? `local@${os.hostname()}`
        : params.host
          ? `${params.username}@${params.host}:${params.port}`
          : '';
    this.recording = recordings.start({
      id,
      user: owner,
      kind,
      target,
      cols: this.cols,
      rows: this.rows,
    });
  }

  /* ---------- 对外只读元信息（不含凭据） ---------- */
  meta() {
    return {
      id: this.id,
      kind: this.kind,
      label: this.label(),
      state: this.state,
      attached: Boolean(this.socket),
      cols: this.cols,
      rows: this.rows,
      createdAt: this.createdAt,
      connectedAt: this.connectedAt,
      lastActiveAt: this.lastActiveAt,
      closeReason: this.closeReason,
    };
  }

  label() {
    return this.params.label || '会话';
  }

  /* ---------- 输出 ---------- */

  /** 子类把解码后的文本交给这里：写回放缓冲 + 推向前端 */
  emitOutput(text) {
    if (!text) return;
    this.lastActiveAt = Date.now();
    if (this.recording) this.recording.write(text);
    this.appendReplay(text);
    this.queueOutput(text);
  }

  /** 子类在调整窗口尺寸后调用，保证录像中的重绘尺寸正确 */
  recordResize(cols, rows) {
    if (this.recording) this.recording.resize(cols, rows);
  }

  appendReplay(text) {
    this.replay.push(text);
    this.replayBytes += Buffer.byteLength(text);
    while (this.replayBytes > config.session.replayBufferBytes && this.replay.length > 1) {
      const removed = this.replay.shift();
      this.replayBytes -= Buffer.byteLength(removed);
      this.replayTruncated = true;
    }
  }

  replayPayload() {
    return { data: this.replay.join(''), truncated: this.replayTruncated };
  }

  queueOutput(text) {
    if (!this.socket) return; // 未挂载前端时只写回放缓冲
    this.outQueue.push(text);
    if (this.flushTimer) return;
    // 8ms 合并窗口：把高频小分片聚合成一帧，显著降低 WebSocket 帧开销
    this.flushTimer = setTimeout(() => this.flush(), 8);
  }

  flush() {
    this.flushTimer = null;
    if (!this.outQueue.length) return;
    const data = this.outQueue.join('');
    this.outQueue = [];
    this.send({ type: 'data', data });
    this.applyBackpressure();
  }

  /** 前端消费不及时时暂停数据源，避免内存被无界输出撑爆 */
  applyBackpressure() {
    if (!this.isTransportActive()) return;

    if (this.socket && this.socket.bufferedAmount > HIGH_WATER_BYTES) {
      this.pauseSource();
      if (!this.pauseTimer) {
        this.pauseTimer = setTimeout(() => {
          this.pauseTimer = null;
          if (!this.socket || this.socket.bufferedAmount <= LOW_WATER_BYTES) {
            this.resumeSource();
          } else {
            this.applyBackpressure();
          }
        }, 50);
      }
    }
  }

  /* ---------- 前端连接挂载 / 卸载 ---------- */

  attach(socket) {
    if (this.closed) return { ok: false, reason: '会话已结束' };
    if (this.socket && this.socket !== socket) {
      try {
        this.socket.close(4001, 'session replaced');
      } catch {
        /* ignore */
      }
    }
    this.socket = socket;
    clearTimeout(this.detachTimer);
    this.detachTimer = null;
    this.outQueue = [];
    this.lastActiveAt = Date.now();
    return { ok: true, ...this.replayPayload(), meta: this.meta() };
  }

  detach(socket) {
    if (this.socket !== socket) return;
    this.socket = null;
    clearTimeout(this.flushTimer);
    this.flushTimer = null;
    this.outQueue = [];
    clearTimeout(this.detachTimer);
    // 宽限期内保留传输连接，等待前端重连
    this.detachTimer = setTimeout(() => {
      log.info(`会话 ${this.id} 超出重连宽限期，主动回收`);
      this.close('resume_timeout');
    }, config.session.resumeGraceMs);
    if (this.detachTimer.unref) this.detachTimer.unref();
  }

  send(payload) {
    if (!this.socket) return false;
    if (this.socket.readyState !== 1) return false; // WebSocket.OPEN
    try {
      this.socket.send(JSON.stringify(payload));
      return true;
    } catch (err) {
      log.debug('发送失败', err.message);
      return false;
    }
  }

  emitError(message, code = 'SESSION_ERROR') {
    this.send({ type: 'error', code, message });
  }

  touch() {
    this.lastActiveAt = Date.now();
  }

  /* ---------- 回收 ---------- */

  close(reason = 'closed') {
    if (this.closed) return;
    this.closed = true;
    this.state = 'closed';
    this.closeReason = reason;

    clearTimeout(this.detachTimer);
    clearTimeout(this.flushTimer);
    clearTimeout(this.idleTimer);
    clearTimeout(this.pauseTimer);
    this.detachTimer = this.flushTimer = this.idleTimer = this.pauseTimer = null;

    if (this.recording) {
      this.recording.stop(reason);
      this.recording = null;
    }

    this.onBeforeDestroy();

    if (this.socket) {
      this.send({ type: 'closed', reason, exit: this.exitInfo });
      try {
        this.socket.close(1000, String(reason).slice(0, 100));
      } catch {
        /* ignore */
      }
      this.socket = null;
    }

    try {
      this.destroyTransport();
    } catch (err) {
      log.debug('销毁传输失败', err.message);
    }

    this.replay = [];
    this.replayBytes = 0;
    this.outQueue = [];

    log.info(`会话关闭 ${this.id} kind=${this.kind} reason=${reason}`);
    if (typeof this.onClose === 'function') this.onClose(this);
  }

  /* ---------- 子类需实现（或按需覆盖） ---------- */
  connect() {
    throw new Error('connect() 未实现');
  }

  write() {
    return false;
  }

  resize() {}

  pauseSource() {}

  resumeSource() {}

  isTransportActive() {
    return this.state === 'connected';
  }

  destroyTransport() {}

  onBeforeDestroy() {}
}

module.exports = { BaseSession, HIGH_WATER_BYTES, LOW_WATER_BYTES };
