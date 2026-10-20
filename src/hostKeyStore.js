'use strict';

/**
 * SSH 主机密钥校验（防中间人攻击）。
 *
 * 首次连接采用 TOFU（Trust On First Use）：记录目标主机公钥指纹；
 * 后续连接必须与记录一致，否则拒绝连接并在日志中明确告警。
 * 严格模式下（SSH_STRICT_HOST_KEY=true），未记录指纹的主机一律拒绝。
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const logger = require('./logger');

const log = logger.create('hostkey');

let cache = null;

function load() {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(config.paths.knownHosts, 'utf8'));
    if (!cache || typeof cache !== 'object') cache = {};
  } catch {
    cache = {};
  }
  return cache;
}

function persist() {
  try {
    fs.mkdirSync(path.dirname(config.paths.knownHosts), { recursive: true });
    fs.writeFileSync(config.paths.knownHosts, JSON.stringify(cache, null, 2), { mode: 0o600 });
  } catch (err) {
    log.error('写入 known_hosts 失败', err.message);
  }
}

function fingerprint(keyBuffer) {
  const digest = crypto.createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');
  return `SHA256:${digest}`;
}

function hostKeyId(host, port) {
  return `${String(host).toLowerCase()}:${port}`;
}

/**
 * 生成 hostVerifier 回调。
 * key 为服务端原始主机公钥（Buffer），verify 用于返回校验结果。
 */
function createVerifier(host, port) {
  return function hostVerifier(key, verify) {
    const id = hostKeyId(host, port);
    const fp = fingerprint(key);
    const store = load();
    const record = store[id];

    if (!record) {
      if (config.ssh.strictHostKey) {
        log.warn(`拒绝未知主机密钥（严格模式）: ${id} ${fp}`);
        return verify(false);
      }
      store[id] = { fingerprint: fp, firstSeen: new Date().toISOString() };
      persist();
      log.info(`首次连接，已记录主机密钥: ${id} ${fp}`);
      return verify(true);
    }

    if (record.fingerprint !== fp) {
      log.error(`主机密钥不匹配，可能遭受中间人攻击: ${id} 期望=${record.fingerprint} 实际=${fp}`);
      return verify(false);
    }

    record.lastSeen = new Date().toISOString();
    return verify(true);
  };
}

function knownFingerprint(host, port) {
  const record = load()[hostKeyId(host, port)];
  return record ? record.fingerprint : null;
}

module.exports = { createVerifier, fingerprint, knownFingerprint, hostKeyId };
