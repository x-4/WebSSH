'use strict';

/**
 * WebSSH 服务入口。
 *
 * - 默认启动 HTTP 服务（建议置于 Nginx / Caddy 之后由反向代理终结 TLS）；
 * - 配置 TLS_KEY / TLS_CERT 后可直接以 HTTPS + WSS 运行；
 * - 支持优雅退出：先关闭所有 SSH 会话，再停止接收新连接。
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

const config = require('./src/config');
const logger = require('./src/logger');
const { createApp } = require('./src/app');
const { attachWebSocketServer } = require('./src/ws');
const { registry, localTerminalAvailability } = require('./src/sessions');
const audit = require('./src/audit');
const users = require('./src/users');
const metrics = require('./src/metrics');
const recordings = require('./src/recordings');
const { validate } = require('./src/preflight');

const log = logger.create('server');

/* ---------------------- 启动前的安全自查 ---------------------- */

function resolveAdminPassword() {
  // 使用多用户文件时，不再生成/展示任何口令
  if (users.source === 'file') return { source: 'users' };
  if (config.auth.passwordHash) return { source: 'hash' };
  if (config.auth.password) return { source: 'env' };
  const generated = crypto.randomBytes(9).toString('base64url');
  config.auth.password = generated;
  return { source: 'generated', password: generated };
}

function preflight() {
  const pw = resolveAdminPassword();
  const warnings = [];

  if (users.source === 'file') {
    warnings.push(`已启用多用户文件（${users.size()} 个账号），环境变量中的单账号配置将被忽略。`);
  }
  if (!config.auth.stepUpRequired) {
    warnings.push('STEP_UP_FOR_LOCAL=false：打开本机终端无需二次认证，建议仅在隔离环境使用。');
  }
  if (config.ssh.blockPrivateHosts === false) {
    warnings.push('SSH_BLOCK_PRIVATE_HOSTS=false：允许连接内网地址，若服务对公网开放请评估 SSRF 风险。');
  }
  const local = localTerminalAvailability();
  if (local.enabled && local.available) {
    warnings.push(
      `部署机终端已开启：登录用户可获得 ${local.user} 权限的 Shell（${local.shell}），请确认访问控制与审计要求；可用 LOCAL_TERMINAL_ENABLED=false 关闭。`
    );
  }
  if (!local.available && local.enabled) {
    warnings.push(`部署机终端配置为开启但当前不可用：${local.reason}`);
  }
  return { pw, warnings };
}

/* ---------------------- 启动服务 ---------------------- */

const validation = validate();
for (const warning of validation.warnings) log.warn(`配置检查: ${warning}`);
if (validation.errors.length) {
  for (const error of validation.errors) log.error(`配置错误: ${error}`);
  log.error('启动中止：请修正上述配置后重试');
  process.exit(1);
}

const { pw, warnings } = preflight();
audit.init();
recordings.recover();
recordings.cleanup();
// 每日清理一次过期录像，避免长期运行堆积
const recordingSweeper = setInterval(() => recordings.cleanup(), 24 * 60 * 60 * 1000);
if (recordingSweeper.unref) recordingSweeper.unref();
const app = createApp();

let server;
if (config.tls.enabled) {
  let options;
  try {
    options = {
      key: fs.readFileSync(config.tls.keyPath),
      cert: fs.readFileSync(config.tls.certPath),
    };
  } catch (err) {
    log.error(`读取 TLS 证书失败（检查 TLS_KEY / TLS_CERT）: ${err.message}`);
    process.exit(1);
  }
  server = https.createServer(options, app);
} else {
  server = http.createServer(app);
}

const wss = attachWebSocketServer(server);

metrics.registerGauge('webssh_sessions', '当前活跃会话数', () => [
  { labels: { kind: 'ssh' }, value: registry.countByKind('ssh') },
  { labels: { kind: 'local' }, value: registry.countByKind('local') },
]);
metrics.registerGauge('webssh_ws_connections', '当前 WebSocket 连接数', () => wss.clients.size);
metrics.registerGauge('webssh_audit_forward_pending', '待投递的审计事件数', () => audit.info().forward.pending);
metrics.registerGauge('webssh_audit_seq', '审计链当前序号', () => audit.info().seq);
metrics.registerGauge('webssh_process_resident_memory_bytes', '进程常驻内存', () => process.memoryUsage().rss);
metrics.registerGauge('webssh_uptime_seconds', '进程运行时长', () => Math.floor(process.uptime()));

server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;

server.listen(config.http.port, config.http.host, () => {
  const scheme = config.tls.enabled ? 'https' : 'http';
  const shownHost = config.http.host === '0.0.0.0' ? 'localhost' : config.http.host;
  const actualPort = server.address().port; // PORT=0 时为系统分配端口

  log.info('='.repeat(64));
  log.info(`WebSSH 已启动 → ${scheme}://${shownHost}:${actualPort}`);
  if (pw.source === 'users') {
    log.info(`登录用户: ${users.size()} 个（来源 ${users.file}）`);
  } else {
    log.info(`登录账号: ${config.auth.username}（单账号模式）`);
  }
  if (pw.source === 'generated') {
    log.warn(`未配置登录口令，已生成一次性密码: ${pw.password}`);
    log.warn('请将其写入 .env 的 WEBSSH_PASS，或使用 npm run hash 生成哈希后配置 WEBSSH_PASS_HASH。');
  } else if (pw.source !== 'users') {
    log.info(`口令来源: ${pw.source === 'hash' ? 'WEBSSH_PASS_HASH（scrypt）' : 'WEBSSH_PASS（明文）'}`);
  }
  log.info(`并发上限: 总 ${config.session.maxTotal} / 单账号 ${config.session.maxPerUser}`);
  if (config.local.enabled) {
    const local = localTerminalAvailability();
    log.info(
      `部署机终端: ${local.available ? `可用（${local.shell}，cwd=${local.cwd}）` : `不可用（${local.reason}）`}`
    );
  } else {
    log.info('部署机终端: 已禁用');
  }
  log.info(`操作审计: ${config.audit.enabled ? `写入 ${config.audit.file}` : '已关闭'}`);
  log.info(
    config.recording.enabled
      ? `会话录像: ${config.recording.dir}（单会话上限 ${Math.round(config.recording.maxBytes / 1048576)}MB，保留 ${config.recording.keepDays} 天）`
      : '会话录像: 已关闭'
  );
  log.info(`断线重连宽限期: ${Math.floor(config.session.resumeGraceMs / 1000)}s`);
  for (const w of warnings) log.warn(w);
  log.info('='.repeat(64));
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    log.error(`端口 ${config.http.port} 已被占用，请修改 PORT 后重试`);
  } else {
    log.error('服务启动失败', err.message);
  }
  process.exit(1);
});

/* ---------------------- 优雅退出 ---------------------- */

let shuttingDown = false;

function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info(`收到 ${signal}，开始优雅退出…`);

  registry.closeAll('server_shutdown');
  audit.shutdown().catch(() => {});
  try {
    wss.close();
  } catch {
    /* ignore */
  }

  server.close(() => {
    log.info('HTTP 服务已关闭');
    process.exit(exitCode);
  });

  // 兜底：8 秒内未完成则强制退出
  setTimeout(() => {
    log.warn('优雅退出超时，强制结束进程');
    process.exit(exitCode || 1);
  }, 8000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  log.error('未处理的 Promise 拒绝', reason instanceof Error ? reason.stack || reason.message : String(reason));
  metrics.inc('webssh_unhandled_rejection_total');
});

process.on('uncaughtException', (err) => {
  // 未捕获异常意味着进程状态可能已不一致：记录后尽快退出，由进程管理器拉起
  log.error('未捕获异常，准备退出', err.stack || err.message);
  metrics.inc('webssh_uncaught_exception_total');
  shutdown('uncaughtException', 1);
});
