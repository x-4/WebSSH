'use strict';

/**
 * 就绪探针：判断当前实例是否可以接收流量。
 *
 * 与 /healthz（存活探针）不同，/readyz 会检查依赖：
 * 用户表、数据目录可写、审计目录可写（含投递健康）、录像目录可写。
 * 探针结果缓存 15 秒，避免频率过高时反复写盘。
 */

const fs = require('fs');
const path = require('path');

const config = require('./config');
const users = require('./users');
const audit = require('./audit');
const { localTerminalAvailability } = require('./sessions');

const CACHE_TTL = 15000;
const cache = new Map();

function probeWritable(dir) {
  const now = Date.now();
  const cached = cache.get(dir);
  if (cached && now - cached.at < CACHE_TTL) return cached.result;

  let result;
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const probe = path.join(dir, `.ready-probe-${process.pid}`);
    fs.writeFileSync(probe, 'ok', { mode: 0o600 });
    fs.unlinkSync(probe);
    result = { ok: true };
  } catch (err) {
    result = { ok: false, error: err.message };
  }

  cache.set(dir, { at: now, result });
  return result;
}

function checkReadiness() {
  const checks = {};

  checks.users = {
    ok: users.size() > 0 && users.hasActiveAdmin(),
    source: users.source,
  };

  checks.dataDir = probeWritable(config.paths.data);

  if (config.audit.enabled) {
    const writable = probeWritable(path.dirname(config.audit.file));
    const delivery = audit.isHealthy();
    checks.audit = {
      ok: writable.ok && (!config.audit.requireDelivery || delivery),
      writable: writable.ok,
      delivery,
      pending: audit.info().forward.pending,
    };
  }

  if (config.recording.enabled) {
    checks.recordings = probeWritable(config.recording.dir);
  }

  if (config.local.enabled) {
    const local = localTerminalAvailability();
    checks.localTerminal = { ok: true, optional: true, available: local.available, reason: local.reason };
  }

  const required = Object.entries(checks).filter(([, value]) => !value.optional);
  return {
    ok: required.every(([, value]) => value.ok),
    checks,
    uptime: Math.floor(process.uptime()),
  };
}

module.exports = { checkReadiness };
