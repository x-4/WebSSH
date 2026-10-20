'use strict';

/**
 * 部署机本机会话：在 WebSSH 服务所在机器上直接拉起一个交互式 Shell。
 *
 * 通过 node-pty 创建真正的伪终端（Linux: /dev/ptmx，Windows: ConPTY），
 * 因此 vim、top 等全屏程序、彩色提示符、窗口尺寸变更都能正常工作。
 *
 * 安全前提：
 * - Shell 以 WebSSH 服务进程的身份运行，权限等同该服务账号；
 * - 子进程环境变量会剔除 WebSSH 自身的密钥类配置；
 * - 提交的命令行写入审计日志（data/audit.log）。
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

const config = require('../config');
const logger = require('../logger');
const audit = require('../audit');
const { BaseSession } = require('./base');
const { createLineTracker, isSecretPrompt } = require('./inputParser');
const { processTreeUsage } = require('./resourceGuard');

const log = logger.create('local');

const HOSTNAME = os.hostname();

let pty = null;
let ptyError = null;
try {
  // node-pty 为可选依赖：缺少预编译产物且无编译工具链时不应影响 SSH 功能
  // eslint-disable-next-line import/no-unresolved, global-require
  pty = require('node-pty');
} catch (err) {
  // 只保留简短原因，避免把 require 调用栈暴露给前端
  ptyError =
    err && err.code === 'MODULE_NOT_FOUND'
      ? '未安装 node-pty（可选依赖缺失）'
      : String((err && err.message) || err).split('\n')[0];
}

/* ------------------------------ Shell 解析 ------------------------------ */

function existingFile(candidate) {
  try {
    return candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function resolveShell() {
  if (config.local.shell) {
    return { file: config.local.shell, args: config.local.args, source: 'config' };
  }

  if (process.platform === 'win32') {
    const root = process.env.SystemRoot || 'C:\\Windows';
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const candidates = [
      path.join(programFiles, 'PowerShell', '7', 'pwsh.exe'),
      path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ];
    const found = candidates.find(existingFile);
    if (found) return { file: found, args: ['-NoLogo'], source: 'auto' };
    return { file: process.env.COMSPEC || 'cmd.exe', args: [], source: 'comspec' };
  }

  const shell = process.env.SHELL || '/bin/bash';
  if (existingFile(shell)) {
    // 登录 Shell：加载 /etc/profile 与用户 profile，得到与手工登录一致的 PATH
    return { file: shell, args: config.local.args.length ? config.local.args : ['-l'], source: 'auto' };
  }
  return { file: '/bin/sh', args: [], source: 'fallback' };
}

function resolveCwd() {
  const candidate = config.local.cwd || process.cwd();
  try {
    if (fs.statSync(candidate).isDirectory()) return candidate;
  } catch {
    /* 回退 */
  }
  return os.homedir();
}

/**
 * 传给本机 Shell 的环境变量使用**白名单**，而不是黑名单。
 * 黑名单无法穷举 AWS_SECRET_ACCESS_KEY、DATABASE_URL 等第三方凭据，
 * 白名单只保留运行 Shell 必需的变量，额外的可用 LOCAL_TERMINAL_ENV_ALLOW 显式放行。
 */
const ENV_ALLOW = new Set(
  [
    'PATH', 'PATHEXT', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'USERNAME', 'USER', 'LOGNAME',
    'SHELL', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TMPDIR', 'TEMP', 'TMP',
    'SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'OS', 'NUMBER_OF_PROCESSORS',
    'PROCESSOR_ARCHITECTURE', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData',
    'APPDATA', 'LOCALAPPDATA', 'PSModulePath', 'PWD', 'TERM', 'COLORTERM',
    'XDG_RUNTIME_DIR', 'XDG_SESSION_TYPE', 'SSH_AUTH_SOCK', 'KRB5CCNAME',
  ].map((k) => k.toLowerCase())
);

const ENV_HARD_DENY = /^(WEBSSH_.*|SESSION_SECRET|TLS_KEY|TLS_CERT|AUDIT_.*|LOCAL_TERMINAL_.*)$/i;

function sanitizedEnv() {
  const extra = new Set(config.local.envAllow.map((k) => k.toLowerCase()));
  const env = {};

  for (const [key, value] of Object.entries(process.env)) {
    const lower = key.toLowerCase();
    if (ENV_HARD_DENY.test(key)) continue;
    if (!ENV_ALLOW.has(lower) && !extra.has(lower)) continue;
    env[key] = value;
  }

  env.TERM = 'xterm-256color';
  env.COLORTERM = 'truecolor';
  return env;
}

/* ------------------------------ 参数与可用性 ------------------------------ */

function availability() {
  const shell = resolveShell();
  return {
    enabled: config.local.enabled,
    available: Boolean(pty) && config.local.enabled,
    reason: !config.local.enabled
      ? '本机终端已通过 LOCAL_TERMINAL_ENABLED=false 关闭'
      : pty
        ? null
        : `node-pty 未正确安装（${ptyError || '未知原因'}），请安装构建工具后重新 npm install`,
    shell: shell.file,
    cwd: resolveCwd(),
    hostname: HOSTNAME,
    platform: process.platform,
    user: os.userInfo().username,
    maxSessions: config.local.maxSessions,
    auditEnabled: config.audit.enabled,
    limits: {
      supported: process.platform === 'linux',
      maxProcs: config.local.maxProcs,
      maxMemoryMb: config.local.maxMemoryMb,
    },
  };
}

function validateLocalParams(raw = {}) {
  const cols = Math.min(Math.max(parseInt(raw.cols, 10) || 80, 20), 500);
  const rows = Math.min(Math.max(parseInt(raw.rows, 10) || 24, 5), 300);
  const term = /^[A-Za-z0-9._\-]{1,32}$/.test(String(raw.term || '')) ? String(raw.term) : 'xterm-256color';
  return { cols, rows, term };
}

/* ------------------------------ 会话实体 ------------------------------ */

class LocalSession extends BaseSession {
  constructor(opts) {
    super({ ...opts, kind: 'local' });
    this.proc = null;
    this.shellInfo = null;

    // 命令审计：行缓冲 + 密码提示状态
    this.tracker = createLineTracker();
    this.expectSecret = false;
    this.secretArmedAt = 0;

    // 资源看门狗（仅 Linux）
    this.watchdog = null;
  }

  label() {
    return `部署机 · ${HOSTNAME}`;
  }

  meta() {
    return {
      ...super.meta(),
      hostname: HOSTNAME,
      shell: this.shellInfo ? this.shellInfo.file : resolveShell().file,
      cwd: this.shellInfo ? this.shellInfo.cwd : resolveCwd(),
      platform: process.platform,
      user: os.userInfo().username,
    };
  }

  connect() {
    return new Promise((resolve, reject) => {
      if (!config.local.enabled) {
        return reject(new Error('本机终端已禁用（LOCAL_TERMINAL_ENABLED=false）'));
      }
      if (!pty) {
        return reject(new Error(`node-pty 不可用：${ptyError || '未安装'}`));
      }

      const shell = resolveShell();
      const cwd = resolveCwd();

      try {
        this.proc = pty.spawn(shell.file, shell.args, {
          name: this.params.term,
          cols: this.cols,
          rows: this.rows,
          cwd,
          env: sanitizedEnv(),
        });
      } catch (err) {
        return reject(new Error(`无法启动本机 Shell（${shell.file}）：${err.message}`));
      }

      this.shellInfo = { ...shell, cwd };
      this.state = 'connected';
      this.connectedAt = Date.now();
      this.lastActiveAt = Date.now();

      this.proc.onData((data) => {
        // 口令提示只影响审计，不改变终端输出
        if (config.audit.redactSecretPrompts && isSecretPrompt(data)) this.armSecretPrompt();
        this.emitOutput(data);
      });
      this.proc.onExit(({ exitCode, signal }) => {
        if (this.closed) return;
        this.exitInfo = { code: exitCode, signal };
        this.send({ type: 'exit', code: exitCode, signal });
        log.info(`本机 Shell 退出 ${this.id} code=${exitCode} signal=${signal}`);
        this.close('shell_exit');
      });

      this.startWatchdog();
      log.info(
        `本机会话就绪 ${this.id} shell=${shell.file} cwd=${cwd}` +
          (process.platform === 'linux'
            ? ` limits=procs:${config.local.maxProcs}/mem:${config.local.maxMemoryMb}MB`
            : ' limits=unsupported')
      );
      resolve(this);
    });
  }

  write(data) {
    if (this.closed || this.state !== 'connected' || !this.proc) return false;
    this.lastActiveAt = Date.now();
    if (config.audit.recordCommands) this.trackInput(data);
    try {
      this.proc.write(data);
      return true;
    } catch (err) {
      log.debug('写入 PTY 失败', err.message);
      return false;
    }
  }

  /* ---------- 审计：口令提示与命令还原 ---------- */

  armSecretPrompt() {
    this.expectSecret = true;
    this.secretArmedAt = Date.now();
  }

  /** 提示出现后 60 秒内没有输入则视为误判，避免长期屏蔽后续命令 */
  isSecretExpected() {
    if (!this.expectSecret) return false;
    if (Date.now() - this.secretArmedAt > 60000) {
      this.expectSecret = false;
      return false;
    }
    return true;
  }

  trackInput(data) {
    const lines = this.tracker.feed(data);
    for (const raw of lines) {
      const cmd = raw.trim();
      const secret = this.isSecretExpected();

      if (secret) {
        // 只记录「发生过一次敏感输入」，不落明文
        this.expectSecret = false;
        if (config.audit.redactSecretPrompts) {
          audit.command({
            user: this.owner,
            sessionId: this.id,
            kind: 'local',
            cmd: '',
            redacted: true,
            shell: this.shellInfo ? this.shellInfo.file : undefined,
          });
          continue;
        }
      }

      if (!cmd) continue;
      audit.command({
        user: this.owner,
        sessionId: this.id,
        kind: 'local',
        cmd,
        shell: this.shellInfo ? this.shellInfo.file : undefined,
      });
    }
  }

  /* ---------- 资源看门狗 ---------- */

  startWatchdog() {
    if (process.platform !== 'linux') return;
    const { maxProcs, maxMemoryMb, watchIntervalMs } = config.local;
    if (!maxProcs && !maxMemoryMb) return;

    this.watchdog = setInterval(() => this.checkResources(), Math.max(watchIntervalMs, 1000));
    if (this.watchdog.unref) this.watchdog.unref();
  }

  checkResources() {
    if (this.closed || !this.proc) return;
    const usage = processTreeUsage(this.proc.pid);

    const overProcs = config.local.maxProcs > 0 && usage.count > config.local.maxProcs;
    const overMemory = config.local.maxMemoryMb > 0 && usage.rssBytes > config.local.maxMemoryMb * 1024 * 1024;
    if (!overProcs && !overMemory) return;

    const detail = `procs=${usage.count}/${config.local.maxProcs} rss=${Math.round(usage.rssBytes / 1048576)}MB/${
      config.local.maxMemoryMb
    }MB`;
    log.warn(`会话 ${this.id} 触发资源上限: ${detail}`);
    audit.sessionLimit({ user: this.owner, sessionId: this.id, kind: 'local', reason: 'resource', detail });

    this.emitOutput('\r\n\x1b[31m[资源使用超出上限，会话已被服务端终止]\x1b[0m\r\n');
    this.exitInfo = { code: null, signal: 'resource_limit' };
    this.close('resource_limit');
  }

  resize(cols, rows) {
    if (cols === this.cols && rows === this.rows) return;
    this.cols = cols;
    this.rows = rows;
    this.recordResize(cols, rows);
    if (this.proc && this.state === 'connected') {
      try {
        this.proc.resize(cols, rows);
      } catch (err) {
        log.debug('调整 PTY 尺寸失败', err.message);
      }
    }
  }

  pauseSource() {
    if (this.proc) {
      try {
        this.proc.pause();
      } catch {
        /* ignore */
      }
    }
  }

  resumeSource() {
    if (!this.proc) return;
    try {
      this.proc.resume();
    } catch {
      /* ignore */
    }
  }

  destroyTransport() {
    if (this.proc) {
      try {
        this.proc.kill();
      } catch {
        /* 进程可能已退出 */
      }
    }
    this.proc = null;
  }

  onBeforeDestroy() {
    this.tracker.reset();
    this.expectSecret = false;
    clearInterval(this.watchdog);
    this.watchdog = null;
  }
}

module.exports = {
  LocalSession,
  validateLocalParams,
  availability,
  resolveShell,
  resolveCwd,
  HOSTNAME,
};
