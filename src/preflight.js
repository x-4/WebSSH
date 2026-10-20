'use strict';

/**
 * 启动自检：把「配置错误」在进程启动阶段暴露，而不是等第一次请求才失败。
 *
 * 返回 { errors, warnings }：
 * - errors：致命问题，服务应拒绝启动；
 * - warnings：可运行但需要运维关注（TLS、密钥长度、示例口令等）。
 */

const fs = require('fs');
const path = require('path');

const config = require('./config');
const users = require('./users');

function isPowerOfTwo(n) {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

function probeWritable(dir, label, errors) {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const probe = path.join(dir, `.write-probe-${process.pid}`);
    fs.writeFileSync(probe, 'ok', { mode: 0o600 });
    fs.unlinkSync(probe);
    return true;
  } catch (err) {
    errors.push(`${label}不可写（${dir}）：${err.message}`);
    return false;
  }
}

function checkFileReadable(file, label, errors) {
  try {
    fs.accessSync(file, fs.constants.R_OK);
  } catch (err) {
    errors.push(`${label}不可读（${file}）：${err.message}`);
  }
}

function validate() {
  const errors = [];
  const warnings = [];

  /* ---------- 认证与会话密钥 ---------- */
  if (!isPowerOfTwo(config.auth.scryptN) || config.auth.scryptN < 1 << 14) {
    errors.push(`SCRYPT_N 必须是不少于 16384 的 2 的幂（当前 ${config.auth.scryptN}）`);
  } else if (config.auth.scryptN > 1 << 20) {
    warnings.push('SCRYPT_N 过大，单次登录将消耗大量内存，可能被用于资源耗尽');
  }

  if (config.auth.ephemeralSecret) {
    warnings.push('未配置 SESSION_SECRET，本次使用临时密钥，重启后所有登录态失效');
  }
  if (config.auth.sessionSecrets.some((secret) => secret.length < 32)) {
    warnings.push('会话密钥长度建议不少于 32 字符（或 64 位十六进制）');
  }
  if (config.auth.sessionSecrets.length > 1) {
    warnings.push(`已启用密钥环（${config.auth.sessionSecrets.length} 个），签发使用第一个，验证兼容其余`);
  }

  if (config.env === 'production') {
    if (config.auth.ephemeralSecret) {
      errors.push('生产环境必须显式配置 SESSION_SECRET 或 SESSION_SECRETS');
    }
    if (!config.tls.enabled && !config.http.forceHttps) {
      warnings.push('生产环境建议启用 TLS 或 FORCE_HTTPS，否则口令与终端内容在链路上明文传输');
    }
    if (users.source === 'env' && /change_me|changeme|^webssh$/i.test(config.auth.password || '')) {
      errors.push('生产环境仍在使用示例口令，请修改 WEBSSH_PASS 或改用 WEBSSH_PASS_HASH');
    }
  }

  /* ---------- 用户 ---------- */
  if (users.source === 'env' && !config.auth.password && !config.auth.passwordHash) {
    if (config.env === 'production') {
      errors.push('未配置登录口令：请设置 WEBSSH_PASS / WEBSSH_PASS_HASH，或改用用户文件');
    } else {
      warnings.push('未配置登录口令，启动时会生成一次性口令并打印到控制台');
    }
  }

  if (users.size() === 0) {
    errors.push('没有可用账号：请配置 WEBSSH_USER/WEBSSH_PASS 或创建用户文件');
  } else if (!users.hasActiveAdmin()) {
    errors.push('用户文件中至少需要一个启用状态的 admin 账号，否则无法管理');
  }
  if (users.source === 'file') {
    try {
      const mode = fs.statSync(users.file).mode & 0o777;
      if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
        warnings.push(`用户文件权限过宽（${mode.toString(8)}），建议 chmod 600 ${users.file}`);
      }
    } catch {
      /* 文件刚被删除等竞态，忽略 */
    }
  }

  /* ---------- 网络与会话 ---------- */
  if (config.http.port < 0 || config.http.port > 65535) {
    errors.push(`PORT 不合法：${config.http.port}`);
  }
  if (config.session.maxTotal < 1) errors.push('MAX_SESSIONS 必须大于 0');
  if (config.session.maxPerUser < 1) errors.push('MAX_SESSIONS_PER_USER 必须大于 0');
  if (config.session.maxPerUser > config.session.maxTotal) {
    errors.push('MAX_SESSIONS_PER_USER 不能大于 MAX_SESSIONS');
  }
  if (config.session.replayBufferBytes < 16 * 1024) {
    warnings.push('REPLAY_BUFFER_KB 过小，重连时可能丢失较多历史输出');
  }
  if (config.local.maxSessions > config.session.maxPerUser) {
    warnings.push('LOCAL_TERMINAL_MAX_SESSIONS 大于单账号会话上限，实际以更小值为准');
  }

  /* ---------- 审计与录像 ---------- */
  if (config.audit.requireDelivery && !config.audit.forwardUrl) {
    warnings.push('AUDIT_REQUIRE_DELIVERY=true 但未配置 AUDIT_FORWARD_URL，本机终端将被拒绝');
  }
  if (config.metrics.token && config.metrics.token.length < 16) {
    warnings.push('METRICS_TOKEN 过短，建议至少 16 字符');
  }

  /* ---------- 目录与文件 ---------- */
  probeWritable(config.paths.data, '数据目录', errors);
  if (config.audit.enabled) probeWritable(path.dirname(config.audit.file), '审计日志目录', errors);
  if (config.recording.enabled) probeWritable(config.recording.dir, '录像目录', errors);

  if (config.tls.enabled) {
    checkFileReadable(config.tls.keyPath, 'TLS 私钥', errors);
    checkFileReadable(config.tls.certPath, 'TLS 证书', errors);
  }

  if (process.platform !== 'win32' && !errors.length) {
    try {
      fs.chmodSync(config.paths.data, 0o700);
    } catch (err) {
      warnings.push(`无法收紧数据目录权限：${err.message}`);
    }
  }

  return { errors, warnings };
}

module.exports = { validate };
