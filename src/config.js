'use strict';

/**
 * 配置加载：全部来自环境变量（.env），并做类型转换与安全默认值处理。
 * 敏感项（密码、密钥）只保存在内存中，不落盘、不写日志。
 */

const path = require('path');
const crypto = require('crypto');

require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const ROOT = path.resolve(__dirname, '..');

function envStr(name, def = '') {
  const v = process.env[name];
  return v === undefined || v === '' ? def : v;
}

function envInt(name, def) {
  const n = parseInt(process.env[name] || '', 10);
  return Number.isFinite(n) ? n : def;
}

function envBool(name, def = false) {
  const v = (process.env[name] || '').trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  return def;
}

const tlsKeyPath = envStr('TLS_KEY');
const tlsCertPath = envStr('TLS_CERT');
const tlsEnabled = Boolean(tlsKeyPath && tlsCertPath);

// 数据目录（known_hosts / 审计日志），测试与容器挂载时可覆盖
const DATA_DIR = path.resolve(ROOT, envStr('DATA_DIR', 'data'));

const config = {
  root: ROOT,
  env: envStr('NODE_ENV', 'development'),

  paths: {
    public: path.join(ROOT, 'public'),
    data: DATA_DIR,
    knownHosts: envStr('KNOWN_HOSTS_FILE', path.join(DATA_DIR, 'known_hosts.json')),
  },

  http: {
    host: envStr('HOST', '0.0.0.0'),
    port: envInt('PORT', 3000),
    trustProxy: envBool('TRUST_PROXY', false),
    // /api 的通用请求限流（每 IP 每分钟），0 表示关闭
    rateLimitPerMin: envInt('HTTP_RATE_LIMIT_PER_MIN', 300),
    // 置为 true 时，非 HTTPS 请求（依据 X-Forwarded-Proto）将被 308 跳转
    forceHttps: envBool('FORCE_HTTPS', false),
    // 允许的 Origin 白名单（逗号分隔）。为空时按请求 Host 做同源校验。
    allowedOrigins: envStr('ALLOWED_ORIGINS', '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  },

  tls: {
    enabled: tlsEnabled,
    keyPath: tlsKeyPath,
    certPath: tlsCertPath,
  },

  auth: {
    username: envStr('WEBSSH_USER', 'admin'),
    password: envStr('WEBSSH_PASS', ''),
    passwordHash: envStr('WEBSSH_PASS_HASH', ''),
    // 多用户文件；存在时优先生效，否则回退到上面的单账号
    usersFile: envStr('WEBSSH_USERS_FILE', path.join(DATA_DIR, 'users.json')),
    // 新口令哈希的 scrypt 成本（必须是 2 的幂，且不小于 2^14）
    scryptN: envInt('SCRYPT_N', 1 << 16),
    // 打开本机终端前的二次认证（step-up）
    stepUpRequired: envBool('STEP_UP_FOR_LOCAL', true),
    stepUpTtlMs: envInt('STEP_UP_TTL_MINUTES', 5) * 60 * 1000,
    sessionSecret: envStr('SESSION_SECRET', ''),
    // 逗号分隔的密钥环：首个用于签发，其余用于验证（支持无感轮换）
    sessionSecrets: envStr('SESSION_SECRETS', '')
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean),
    sessionTtlMs: envInt('SESSION_TTL_MINUTES', 480) * 60 * 1000,
    cookieName: 'webssh_sid',
    // 未启用 TLS 时不能强制 Secure，否则浏览器不会回传 Cookie
    secureCookie: envBool('COOKIE_SECURE', tlsEnabled),
    loginWindowMs: envInt('LOGIN_WINDOW_MINUTES', 10) * 60 * 1000,
    loginMaxAttempts: envInt('LOGIN_MAX_ATTEMPTS', 10),
  },

  ssh: {
    connectTimeoutMs: envInt('SSH_CONNECT_TIMEOUT_MS', 20000),
    readyTimeoutMs: envInt('SSH_READY_TIMEOUT_MS', 20000),
    keepaliveIntervalMs: envInt('SSH_KEEPALIVE_MS', 15000),
    keepaliveCountMax: envInt('SSH_KEEPALIVE_COUNT', 3),
    // 主机密钥校验：true=严格（首次需已存在于 known_hosts），false=TOFU（首次信任并记录）
    strictHostKey: envBool('SSH_STRICT_HOST_KEY', false),
    // 禁止连接的内网/保留地址（留空表示不限制，生产环境建议开启）
    blockPrivateHosts: envBool('SSH_BLOCK_PRIVATE_HOSTS', false),
  },

  // 部署机本机终端（在 WebSSH 服务所在机器上直接拉起 Shell）
  local: {
    enabled: envBool('LOCAL_TERMINAL_ENABLED', true),
    shell: envStr('LOCAL_TERMINAL_SHELL', ''),
    args: envStr('LOCAL_TERMINAL_ARGS', '')
      .split(' ')
      .map((x) => x.trim())
      .filter(Boolean),
    cwd: envStr('LOCAL_TERMINAL_CWD', ''),
    maxSessions: envInt('LOCAL_TERMINAL_MAX_SESSIONS', 2),
    // 进程树资源看门狗（仅 Linux 生效）：进程数、常驻内存上限
    maxProcs: envInt('LOCAL_TERMINAL_MAX_PROCS', 200),
    maxMemoryMb: envInt('LOCAL_TERMINAL_MAX_MEMORY_MB', 1024),
    watchIntervalMs: envInt('LOCAL_TERMINAL_WATCH_INTERVAL_MS', 5000),
    // 额外允许传入本机 Shell 的环境变量名（逗号分隔）
    envAllow: envStr('LOCAL_TERMINAL_ENV_ALLOW', '')
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean),
  },

  // 操作审计（会话生命周期 + 本机命令）
  audit: {
    enabled: envBool('AUDIT_LOG_ENABLED', true),
    recordCommands: envBool('AUDIT_RECORD_COMMANDS', true),
    file: envStr('AUDIT_LOG_FILE', path.join(DATA_DIR, 'audit.log')),
    memoryEntries: envInt('AUDIT_MEMORY_ENTRIES', 500),
    maxFileBytes: envInt('AUDIT_MAX_FILE_MB', 10) * 1024 * 1024,
    // 批量 fsync 间隔（毫秒），0 表示只写内核缓冲、不主动 fsync
    fsyncIntervalMs: envInt('AUDIT_FSYNC_MS', 1000),
    keepFiles: Math.max(1, envInt('AUDIT_KEEP_FILES', 5)),
    // 在密码 / 口令提示处提交的内容不写入明文
    redactSecretPrompts: envBool('AUDIT_REDACT_SECRET_PROMPTS', true),
    // 哈希链：每条记录带 seq/prev/hash，可检测篡改
    hashChain: envBool('AUDIT_HASH_CHAIN', true),
    chainKey: envStr('AUDIT_CHAIN_KEY', ''),
    // 远端投递（HTTP webhook，批量推送 JSON 事件）
    forwardUrl: envStr('AUDIT_FORWARD_URL', ''),
    forwardToken: envStr('AUDIT_FORWARD_TOKEN', ''),
    forwardTimeoutMs: envInt('AUDIT_FORWARD_TIMEOUT_MS', 5000),
    forwardBatch: envInt('AUDIT_FORWARD_BATCH', 100),
    forwardQueueMax: envInt('AUDIT_FORWARD_QUEUE_MAX', 5000),
    // true = 投递不健康时拒绝新建本机终端（fail-closed）
    requireDelivery: envBool('AUDIT_REQUIRE_DELIVERY', false),
    // 可选 UDP syslog 旁路（只发送，不参与健康判定）
    syslogHost: envStr('AUDIT_SYSLOG_HOST', ''),
    syslogPort: envInt('AUDIT_SYSLOG_PORT', 514),
  },

  session: {
    maxTotal: envInt('MAX_SESSIONS', 100),
    maxPerUser: envInt('MAX_SESSIONS_PER_USER', 10),
    // 前端断线后，后端保留 SSH 会话用于「断线重连」的时长
    resumeGraceMs: envInt('RESUME_GRACE_SECONDS', 120) * 1000,
    // 无操作自动断开（0 = 不限制）
    idleTimeoutMs: envInt('IDLE_TIMEOUT_MINUTES', 0) * 60000,
    // 重连时回放给前端的输出缓冲上限
    replayBufferBytes: envInt('REPLAY_BUFFER_KB', 256) * 1024,
    scrollbackLines: envInt('SCROLLBACK_LINES', 5000),
  },

  // 会话录像（asciinema v2 cast）
  recording: {
    enabled: envBool('RECORDING_ENABLED', true),
    dir: envStr('RECORDING_DIR', path.join(DATA_DIR, 'recordings')),
    maxBytes: envInt('RECORDING_MAX_MB', 50) * 1024 * 1024,
    keepDays: envInt('RECORDING_KEEP_DAYS', 30),
  },

  metrics: {
    enabled: envBool('METRICS_ENABLED', true),
    // 设置后访问 /metrics 需携带 Authorization: Bearer <token>
    token: envStr('METRICS_TOKEN', ''),
  },

  ws: {
    maxPayloadBytes: envInt('WS_MAX_PAYLOAD_KB', 256) * 1024,
    maxConnPerIp: envInt('WS_MAX_CONN_PER_IP', 20),
    maxMessagesPerSecond: envInt('WS_MAX_MSG_PER_SECOND', 400),
  },
};

// 密钥环：SESSION_SECRETS 优先；否则回退到单个 SESSION_SECRET；都为空时临时生成
if (!config.auth.sessionSecrets.length) {
  if (config.auth.sessionSecret) {
    config.auth.sessionSecrets = [config.auth.sessionSecret];
  } else {
    const generated = crypto.randomBytes(32).toString('hex');
    config.auth.sessionSecrets = [generated];
    config.auth.sessionSecret = generated;
    config.auth.ephemeralSecret = true;
  }
} else {
  config.auth.sessionSecret = config.auth.sessionSecrets[0];
}

module.exports = config;
