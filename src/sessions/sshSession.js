'use strict';

/**
 * SSH 远程会话：通过 ssh2 连接目标主机并申请交互式 PTY。
 * 一个实例对应一条 SSH 连接，独立于前端 WebSocket 的生命周期。
 */

const { Client } = require('ssh2');
const { StringDecoder } = require('string_decoder');
const net = require('net');
const dns = require('dns');

const config = require('../config');
const logger = require('../logger');
const hostKeys = require('../hostKeyStore');
const { BaseSession } = require('./base');

const log = logger.create('ssh');

/* ------------------------------ 工具函数 ------------------------------ */

function friendlyError(err) {
  const msg = String((err && err.message) || err || '');
  const map = [
    [/All configured authentication methods failed/i, '认证失败：用户名、密码或密钥不正确'],
    [/Host denied/i, '主机密钥校验失败，连接可能被中间人劫持'],
    [/Timed out while waiting for/i, '连接超时，请检查网络或目标主机状态'],
    [/ECONNREFUSED/i, '目标主机拒绝连接（端口未开放或被防火墙拦截）'],
    [/ENOTFOUND|EAI_AGAIN/i, '目标主机域名解析失败'],
    [/EHOSTUNREACH|ENETUNREACH/i, '目标主机不可达'],
    [/Cannot parse privateKey|bad passphrase|Integrity check failed/i, '私钥解析失败：请检查私钥内容或口令'],
    [/Received disconnect/i, '目标主机主动断开连接'],
    [/ECONNRESET|read ECONNRESET/i, '连接被重置'],
  ];
  for (const [re, text] of map) if (re.test(msg)) return text;
  return msg || 'SSH 连接失败';
}

const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\./,
];

function isPrivateAddress(ip) {
  const family = net.isIP(ip);
  if (family === 4) return PRIVATE_V4.some((re) => re.test(ip));
  if (family === 6) {
    const v = ip.toLowerCase();
    return v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
  }
  return false;
}

/** 校验 SSH 连接参数，避免把任意字符串直接塞给 ssh2 */
function validateSshParams(raw = {}) {
  const host = String(raw.host || '').trim();
  if (!host || host.length > 255) throw new Error('主机地址不合法');
  if (!/^[A-Za-z0-9._:\-\[\]]+$/.test(host)) throw new Error('主机地址包含非法字符');

  const port = Number(raw.port) || 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口号不合法（1-65535）');

  const username = String(raw.username || '').trim();
  if (!username || username.length > 64) throw new Error('用户名不合法');
  if (!/^[^\s@]+$/.test(username)) throw new Error('用户名包含非法字符');

  const authType = raw.authType === 'key' ? 'key' : 'password';
  const password = authType === 'password' ? String(raw.password || '') : '';
  const privateKey = authType === 'key' ? String(raw.privateKey || '') : '';
  const passphrase = authType === 'key' ? String(raw.passphrase || '') : '';

  if (authType === 'password' && !password) throw new Error('请填写登录密码');
  if (authType === 'key' && !/BEGIN [A-Z ]*PRIVATE KEY/.test(privateKey)) {
    throw new Error('私钥格式不正确（需为 OpenSSH / PEM 私钥）');
  }
  if (privateKey.length > 64 * 1024) throw new Error('私钥内容过长');

  const cols = Math.min(Math.max(parseInt(raw.cols, 10) || 80, 20), 500);
  const rows = Math.min(Math.max(parseInt(raw.rows, 10) || 24, 5), 300);
  const term = /^[A-Za-z0-9._\-]{1,32}$/.test(String(raw.term || '')) ? String(raw.term) : 'xterm-256color';

  return { host, port, username, authType, password, privateKey, passphrase, cols, rows, term };
}

/**
 * 解析并固定目标地址（仅在 SSH_BLOCK_PRIVATE_HOSTS=true 时启用）。
 *
 * 先校验解析结果、再直接用该 IP 建立 TCP 连接，避免「校验时解析一次、
 * 连接时再解析一次」造成的 DNS 重绑定绕过（TOCTOU）。
 * 返回 null 表示不启用固定，交由 ssh2 自行解析。
 */
async function resolvePinnedAddress(host) {
  if (!config.ssh.blockPrivateHosts) return null;

  if (net.isIP(host)) {
    if (isPrivateAddress(host)) throw new Error('出于安全策略，禁止连接内网或保留地址');
    return host;
  }

  const records = await dns.promises.lookup(host, { all: true }).catch(() => []);
  if (!records.length) throw new Error('目标主机域名解析失败');
  if (records.some((r) => isPrivateAddress(r.address))) {
    throw new Error('出于安全策略，禁止连接内网或保留地址');
  }

  const preferred = records.find((r) => r.family === 4) || records[0];
  return preferred.address;
}

/** 入口处的快速校验（真正连接时会再次解析并固定 IP） */
async function assertHostAllowed(host) {
  await resolvePinnedAddress(host);
}

/* ------------------------------ 会话实体 ------------------------------ */

class SshSession extends BaseSession {
  constructor(opts) {
    super({ ...opts, kind: 'ssh' });
    this.client = null;
    this.stream = null;
    this.decoder = new StringDecoder('utf8');
  }

  label() {
    const { username, host, port } = this.params;
    return `${username}@${host}${Number(port) === 22 ? '' : `:${port}`}`;
  }

  meta() {
    return {
      ...super.meta(),
      host: this.params.host,
      port: this.params.port,
      username: this.params.username,
      authType: this.params.authType,
    };
  }

  async connect() {
    const p = this.params;
    // 解析并固定 IP，缩小 DNS 重绑定窗口
    const pinned = await resolvePinnedAddress(p.host);

    return new Promise((resolve, reject) => {
      let settled = false;
      const conn = new Client();
      this.client = conn;

      const fail = (err) => {
        if (this.closed) return;
        if (!settled) {
          settled = true;
          reject(err);
        } else {
          this.emitError(friendlyError(err), 'SSH_ERROR');
        }
      };

      conn.on('keyboard-interactive', (_name, _instr, _lang, prompts, finish) => {
        // 部分服务器启用 keyboard-interactive（PAM）认证，用同一口令应答
        finish(prompts.map(() => p.password || ''));
      });

      conn.on('banner', (message) => {
        this.emitOutput(message.replace(/\r?\n/g, '\r\n'));
      });

      conn.on('ready', () => {
        conn.shell(
          {
            term: p.term,
            cols: this.cols,
            rows: this.rows,
            width: this.cols * 8,
            height: this.rows * 17,
          },
          (err, stream) => {
            if (err) return fail(err);
            this.stream = stream;
            this.state = 'connected';
            this.connectedAt = Date.now();
            this.lastActiveAt = Date.now();

            stream.on('data', (chunk) => this.handleStreamData(chunk));
            stream.stderr.on('data', (chunk) => this.handleStreamData(chunk));

            stream.on('close', (code, signal) => {
              if (this.closed) return;
              this.exitInfo = { code, signal };
              this.send({ type: 'exit', code, signal });
              log.info(`SSH 通道关闭 ${this.id} code=${code} signal=${signal}`);
              this.close('shell_exit');
            });

            settled = true;
            resolve(this);
          }
        );
      });

      conn.on('error', (err) => {
        log.warn(`SSH 错误 ${this.id}`, err.message);
        fail(err);
        if (this.state === 'connected') this.close('ssh_error');
      });

      conn.on('close', () => {
        if (!this.closed) {
          log.info(`SSH 连接关闭 ${this.id}`);
          this.close(this.closeReason || 'ssh_closed');
        }
      });

      const options = {
        host: p.host,
        port: p.port,
        username: p.username,
        readyTimeout: config.ssh.readyTimeoutMs,
        keepaliveInterval: config.ssh.keepaliveIntervalMs,
        keepaliveCountMax: config.ssh.keepaliveCountMax,
        tryKeyboard: true,
        hostVerifier: hostKeys.createVerifier(p.host, p.port),
      };

      if (p.authType === 'password') {
        options.password = p.password;
      } else {
        options.privateKey = p.privateKey;
        if (p.passphrase) options.passphrase = p.passphrase;
      }

      // 直连已校验的 IP；host 仍保留原域名用于日志与主机密钥标识
      if (pinned && pinned !== p.host) {
        const socket = net.connect({ host: pinned, port: p.port });
        socket.on('error', () => {}); // 统一由 ssh2 的 error 事件上报
        options.sock = socket;
      }

      try {
        conn.connect(options);
      } catch (err) {
        fail(err);
      }
    });
  }

  /** SSH 数据是 Buffer 分片，用 StringDecoder 处理跨分片的多字节字符 */
  handleStreamData(chunk) {
    const text = this.decoder.write(chunk);
    if (text) this.emitOutput(text);
  }

  write(data) {
    if (this.closed || this.state !== 'connected' || !this.stream) return false;
    this.lastActiveAt = Date.now();
    return this.stream.write(data);
  }

  resize(cols, rows) {
    if (cols === this.cols && rows === this.rows) return;
    this.cols = cols;
    this.rows = rows;
    this.recordResize(cols, rows);
    if (this.stream && this.state === 'connected') {
      try {
        this.stream.setWindow(rows, cols, 0, 0);
      } catch (err) {
        log.debug('设置窗口尺寸失败', err.message);
      }
    }
  }

  pauseSource() {
    if (this.stream) this.stream.pause();
  }

  resumeSource() {
    if (!this.stream) return;
    try {
      this.stream.resume();
    } catch {
      /* 流已销毁 */
    }
  }

  destroyTransport() {
    try {
      if (this.stream) this.stream.end();
    } catch {
      /* ignore */
    }
    try {
      if (this.client) this.client.end();
    } catch {
      /* ignore */
    }
    this.stream = null;
    this.client = null;
  }

  onBeforeDestroy() {
    // 凭据仅驻留内存，随会话关闭立即清除
    this.params.password = '';
    this.params.privateKey = '';
    this.params.passphrase = '';
  }
}

module.exports = {
  SshSession,
  validateSshParams,
  assertHostAllowed,
  resolvePinnedAddress,
  friendlyError,
  isPrivateAddress,
};
