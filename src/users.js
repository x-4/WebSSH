'use strict';

/**
 * 用户与角色（RBAC）。
 *
 * 两种来源：
 * 1. WEBSSH_USERS_FILE 指向的 JSON 文件（推荐，支持多用户）：
 *      { "users": [ { "username": "alice", "role": "operator", "passwordHash": "scrypt$...", "disabled": false } ] }
 * 2. 未提供用户文件时，回退到 WEBSSH_USER / WEBSSH_PASS(_HASH) 的单账号模式，角色固定为 admin。
 *
 * 角色：
 *   admin     管理员：全部能力（含本机终端、查看全部审计）
 *   operator  运维：SSH + 本机终端 + 自己的审计
 *   developer 开发：仅 SSH + 自己的审计
 *   auditor   审计员：只读审计（可查看全部用户），不能打开任何终端
 *
 * 权限变更在服务重启后生效（用户文件不热加载，避免运行期权限漂移）。
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');
const logger = require('./logger');
const { verifyPasswordHash, verifyPasswordHashAsync, hashPasswordAsync, safeEqual } = require('./password');

const log = logger.create('users');

const ROLES = {
  admin: {
    label: '管理员',
    permissions: ['terminal:ssh', 'terminal:local', 'audit:read', 'audit:readAll', 'sessions:manage'],
  },
  operator: {
    label: '运维',
    permissions: ['terminal:ssh', 'terminal:local', 'audit:read', 'sessions:manage'],
  },
  developer: {
    label: '开发',
    permissions: ['terminal:ssh', 'audit:read', 'sessions:manage'],
  },
  auditor: {
    label: '审计员',
    permissions: ['audit:read', 'audit:readAll'],
  },
};

const users = new Map();
let source = 'env';

let dummyHash = null;
function timingDummyHash() {
  if (!dummyHash) {
    // 延迟生成，用于未知用户时保持与真实校验接近的耗时
    // eslint-disable-next-line global-require
    dummyHash = require('./password').hashPassword('webssh-timing-dummy');
  }
  return dummyHash;
}

function normalizeRole(role) {
  return ROLES[role] ? role : 'developer';
}

function normalizeHosts(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => String(item).trim().toLowerCase())
    .filter((item) => item && item.length <= 255)
    .slice(0, 100);
}

function toUser(raw) {
  return {
    username: String(raw.username),
    role: normalizeRole(raw.role),
    passwordHash: raw.passwordHash || null,
    passwordPlain: raw.passwordHash ? null : String(raw.password || ''),
    disabled: Boolean(raw.disabled),
    note: raw.note ? String(raw.note) : '',
    // 为空表示不限制；非空时仅允许匹配的主机
    hosts: normalizeHosts(raw.hosts),
  };
}

function load() {
  users.clear();
  const file = config.auth.usersFile;

  if (file && fs.existsSync(file)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      const list = Array.isArray(parsed) ? parsed : parsed.users;
      if (!Array.isArray(list)) throw new Error('缺少 users 数组');

      for (const raw of list) {
        if (!raw || !raw.username) continue;
        const user = toUser(raw);
        if (!user.passwordHash) {
          log.warn(`用户 ${user.username} 未配置 passwordHash，已跳过`);
          continue;
        }
        users.set(user.username, user);
      }
      source = 'file';
      log.info(`用户来源: ${file}（${users.size} 个账号）`);
      return;
    } catch (err) {
      log.error(`用户文件不可用（${file}），回退到环境变量单账号: ${err.message}`);
    }
  }

  const username = config.auth.username;
  users.set(username, {
    username,
    role: 'admin',
    passwordHash: config.auth.passwordHash || null,
    passwordPlain: config.auth.passwordHash ? null : config.auth.password,
    disabled: false,
    note: '',
    hosts: [],
  });
  source = 'env';
}

function get(username) {
  return users.get(String(username || '')) || null;
}

function size() {
  return users.size;
}

/** 是否至少存在一个未禁用的管理员（防止把自己锁在门外） */
function hasActiveAdmin() {
  return [...users.values()].some((u) => u.role === 'admin' && !u.disabled);
}

function roleInfo(role) {
  const def = ROLES[normalizeRole(role)];
  return { role: normalizeRole(role), roleLabel: def.label, permissions: [...def.permissions] };
}

/** 校验账号口令；失败返回 null。未知用户也执行一次哈希以对齐耗时。 */
let dummyHashPromise = null;
function timingDummyHashAsync() {
  if (!dummyHashPromise) dummyHashPromise = hashPasswordAsync('webssh-timing-dummy');
  return dummyHashPromise;
}

/** 异步凭证校验（登录路径使用，避免阻塞事件循环） */
async function verifyCredentialsAsync(username, password) {
  const user = get(username);

  if (!user || user.disabled) {
    await verifyPasswordHashAsync(password, await timingDummyHashAsync());
    return null;
  }

  const ok = user.passwordHash
    ? await verifyPasswordHashAsync(password, user.passwordHash)
    : safeEqual(password, user.passwordPlain || '');
  return ok ? user : null;
}

/** 口令哈希是否弱于当前配置（用于登录时自动升级） */
function needsRehash(user) {
  if (!user || !user.passwordHash) return false;
  const parts = String(user.passwordHash).split('$');
  if (parts[0] !== 'scrypt') return true;
  return Number(parts[1]) < config.auth.scryptN;
}

/** 更新单个用户的口令哈希（内存 + 用户文件原子写） */
function updatePasswordHash(username, passwordHash) {
  const user = get(username);
  if (!user) return false;

  user.passwordHash = passwordHash;
  user.passwordPlain = null;
  if (source !== 'file') return true;

  const list = readFileUsers();
  const entry = list.find((item) => item.username === username);
  if (entry) {
    entry.passwordHash = passwordHash;
    delete entry.password;
  } else {
    list.push({
      username,
      role: user.role,
      passwordHash,
      ...(user.hosts && user.hosts.length ? { hosts: user.hosts } : {}),
      createdAt: new Date().toISOString(),
    });
  }
  writeFileUsers(list);
  return true;
}

function verifyCredentials(username, password) {
  const user = get(username);

  if (!user || user.disabled) {
    verifyPasswordHash(password, timingDummyHash());
    return null;
  }

  const ok = user.passwordHash
    ? verifyPasswordHash(password, user.passwordHash)
    : safeEqual(password, user.passwordPlain || '');
  return ok ? user : null;
}

/** 把用户记录转换为可安全下发/挂载的主体信息 */
function principal(user) {
  const info = roleInfo(user.role);
  return {
    username: user.username,
    ...info,
    hostRestricted: Array.isArray(user.hosts) && user.hosts.length > 0,
  };
}

/**
 * 目标主机是否在用户的白名单内。
 * 支持 `*` 通配（不跨 `.`）与 `?` 单字符，例如：
 *   10.0.0.*、*.internal、db-??.example.com
 * 未配置 hosts 的账号不受限制。
 */
function canAccessHost(username, host) {
  const user = get(username);
  if (!user) return false;
  if (!user.hosts || !user.hosts.length) return true;

  const target = String(host || '').toLowerCase();
  return user.hosts.some((pattern) => {
    if (pattern === '*') return true;
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '[^.]*')
      .replace(/\?/g, '.');
    try {
      return new RegExp(`^${escaped}$`).test(target);
    } catch {
      return false;
    }
  });
}

function ensureDataDir() {
  fs.mkdirSync(path.dirname(config.auth.usersFile), { recursive: true });
}

/** 供 CLI 使用：读取原始用户文件（不存在则返回空列表） */
function readFileUsers() {
  const file = config.auth.usersFile;
  if (!file || !fs.existsSync(file)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(parsed) ? parsed : parsed.users || [];
  } catch {
    return [];
  }
}

/**
 * 供 CLI 使用：原子写回用户文件（0600），并保留一份 .bak。
 * 先写临时文件并 fsync，再 rename，避免进程中断导致文件被截断。
 */
function writeFileUsers(list) {
  ensureDataDir();
  const file = config.auth.usersFile;
  const tmp = `${file}.tmp-${process.pid}`;
  const body = `${JSON.stringify({ users: list }, null, 2)}\n`;

  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeFileSync(fd, body);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  if (fs.existsSync(file)) {
    try {
      fs.copyFileSync(file, `${file}.bak`);
    } catch {
      /* 备份失败不阻断写入 */
    }
  }
  fs.renameSync(tmp, file);
}

// 模块加载即完成初始化，保证 auth / API / WS 任何入口拿到的都是同一份用户表
load();

module.exports = {
  ROLES,
  load,
  get,
  size,
  hasActiveAdmin,
  roleInfo,
  principal,
  verifyCredentials,
  verifyCredentialsAsync,
  needsRehash,
  updatePasswordHash,
  canAccessHost,
  readFileUsers,
  writeFileUsers,
  get source() {
    return source;
  },
  get file() {
    return config.auth.usersFile;
  },
};
