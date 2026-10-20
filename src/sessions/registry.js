'use strict';

/**
 * 会话注册表：负责创建、限额、查询与统一回收会话。
 * 同时在这里埋审计点（会话开始 / 结束），保证所有入口都能覆盖。
 */

const crypto = require('crypto');
const os = require('os');
const config = require('../config');
const logger = require('../logger');
const audit = require('../audit');
const metrics = require('../metrics');
const { SshSession } = require('./sshSession');
const { LocalSession } = require('./localSession');

const log = logger.create('registry');

class SessionRegistry {
  constructor() {
    this.sessions = new Map();
    this.idleSweeper = setInterval(() => this.sweepIdle(), 30000);
    if (this.idleSweeper.unref) this.idleSweeper.unref();
  }

  countByOwner(owner) {
    let n = 0;
    for (const s of this.sessions.values()) if (s.owner === owner) n += 1;
    return n;
  }

  countByKind(kind) {
    let n = 0;
    for (const s of this.sessions.values()) if (s.kind === kind) n += 1;
    return n;
  }

  create(owner, kind, params) {
    if (this.sessions.size >= config.session.maxTotal) {
      throw new Error('服务器并发会话数已达上限，请稍后再试');
    }
    if (this.countByOwner(owner) >= config.session.maxPerUser) {
      throw new Error(`单个账号最多同时保持 ${config.session.maxPerUser} 个会话`);
    }
    if (kind === 'local' && this.countByKind('local') >= config.local.maxSessions) {
      throw new Error(`部署机终端最多同时打开 ${config.local.maxSessions} 个会话`);
    }

    const id = crypto.randomUUID();
    const token = crypto.randomBytes(24).toString('base64url');
    const SessionClass = kind === 'local' ? LocalSession : SshSession;
    const session = new SessionClass({ id, token, owner, params });

    const target =
      kind === 'local'
        ? `${params.shell || 'local-shell'} @ ${os.hostname()}`
        : `${params.username}@${params.host}:${params.port}`;

    audit.sessionStart({ user: owner, sessionId: id, kind, target });

    session.onClose = (closed) => {
      this.sessions.delete(id);
      audit.sessionEnd({
        user: owner,
        sessionId: id,
        kind,
        reason: closed.closeReason,
        durationMs: Date.now() - closed.createdAt,
      });
    };

    if (config.session.idleTimeoutMs > 0) {
      session.idleTimer = setInterval(() => {
        if (Date.now() - session.lastActiveAt > config.session.idleTimeoutMs) {
          log.info(`会话 ${id} 空闲超时`);
          session.close('idle_timeout');
        }
      }, 30000);
      if (session.idleTimer.unref) session.idleTimer.unref();
    }

    this.sessions.set(id, session);
    metrics.inc('webssh_session_total', { kind });
    return session;
  }

  get(id) {
    return this.sessions.get(id) || null;
  }

  list(owner) {
    return [...this.sessions.values()]
      .filter((s) => s.owner === owner)
      .map((s) => s.meta());
  }

  close(id, reason = 'closed_by_user', owner = null) {
    const s = this.sessions.get(id);
    if (!s) return false;
    if (owner && s.owner !== owner) return false;
    s.close(reason);
    return true;
  }

  sweepIdle() {
    const now = Date.now();
    for (const s of this.sessions.values()) {
      // 长时间未被挂载的僵尸会话兜底回收
      if (!s.socket && now - s.lastActiveAt > config.session.resumeGraceMs * 3) {
        s.close('stale');
      }
    }
  }

  closeAll(reason = 'server_shutdown') {
    for (const s of this.sessions.values()) s.close(reason);
    this.sessions.clear();
  }
}

module.exports = { SessionRegistry, registry: new SessionRegistry() };
