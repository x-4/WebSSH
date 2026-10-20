'use strict';

/**
 * 会话模块统一出口：
 * - registry：全局会话注册表
 * - SshSession / LocalSession：两种会话实现
 * - 参数校验与可用性探测：供 WebSocket 层与 HTTP API 复用
 */

const { registry, SessionRegistry } = require('./registry');
const {
  SshSession,
  validateSshParams,
  assertHostAllowed,
  resolvePinnedAddress,
  friendlyError,
} = require('./sshSession');
const { LocalSession, validateLocalParams, availability, resolveShell } = require('./localSession');

module.exports = {
  registry,
  SessionRegistry,
  SshSession,
  LocalSession,
  validateSshParams,
  validateLocalParams,
  assertHostAllowed,
  resolvePinnedAddress,
  friendlyError,
  localTerminalAvailability: availability,
  resolveShell,
};
