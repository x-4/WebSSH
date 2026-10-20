'use strict';

/**
 * 轻量日志：统一时间戳 + 级别 + 模块名，并对敏感字段做脱敏。
 * 不引入额外依赖，输出到 stdout/stderr 由容器或 systemd 收集。
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const current = LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] || LEVELS.info;

const SECRET_KEYS = /^(password|passphrase|privateKey|token|secret|cookie|authorization)$/i;

function redact(value, depth = 0) {
  if (value === null || typeof value !== 'object' || depth > 4) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SECRET_KEYS.test(k) ? '***' : redact(v, depth + 1);
  }
  return out;
}

function stringifyArg(a) {
  if (a instanceof Error) return `${a.name}: ${a.message}`;
  if (typeof a === 'object' && a !== null) {
    try {
      return JSON.stringify(redact(a));
    } catch {
      return '[object]';
    }
  }
  return String(a);
}

function format(level, scope, args) {
  const ts = new Date().toISOString();
  const message = args.map(stringifyArg).join(' ');

  // LOG_FORMAT=json 便于容器日志平台 / ELK 直接解析
  if (String(process.env.LOG_FORMAT || '').toLowerCase() === 'json') {
    return JSON.stringify({ ts, level, scope, msg: message });
  }
  return `${ts} ${level.toUpperCase().padEnd(5)} [${scope}] ${message}`;
}

function create(scope) {
  return {
    debug: (...a) => current <= LEVELS.debug && console.log(format('debug', scope, a)),
    info: (...a) => current <= LEVELS.info && console.log(format('info', scope, a)),
    warn: (...a) => current <= LEVELS.warn && console.warn(format('warn', scope, a)),
    error: (...a) => current <= LEVELS.error && console.error(format('error', scope, a)),
  };
}

module.exports = { create };
