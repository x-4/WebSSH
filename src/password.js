'use strict';

/**
 * 口令哈希（scrypt）。
 *
 * - 哈希串自带参数（scrypt$N$r$p$salt$hash），升级 N 后旧哈希仍可验证；
 * - 新哈希使用 config.auth.scryptN（默认 2^16），高于早期版本的 2^14；
 * - 恒时比较，避免通过响应时间推测口令。
 */

const crypto = require('crypto');
const config = require('./config');

function scrypt(password, salt, keylen, N, r, p) {
  return crypto.scryptSync(password.normalize('NFKC'), salt, keylen, {
    N,
    r,
    p,
    // scrypt 需要约 128*N*r 字节内存，显式放宽 maxmem
    maxmem: 128 * N * r * 2,
  });
}

function scryptAsyncBuffer(password, salt, keylen, N, r, p) {
  return new Promise((resolve, reject) => {
    const options = { N, r, p, maxmem: 128 * N * r * 2 };
    crypto.scrypt(password.normalize('NFKC'), salt, keylen, options, (err, derived) => {
      if (err) reject(err);
      else resolve(derived);
    });
  });
}

/** 异步哈希：登录路径使用，避免 scrypt 阻塞事件循环 */
async function hashPasswordAsync(password, { N = config.auth.scryptN, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsyncBuffer(password, salt, 64, N, r, p);
  return ['scrypt', N, r, p, salt.toString('base64url'), derived.toString('base64url')].join('$');
}

async function verifyPasswordHashAsync(password, stored) {
  try {
    const [algo, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (algo !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(hashB64, 'base64url');
    const derived = await scryptAsyncBuffer(password, salt, expected.length, Number(N), Number(r), Number(p));
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function hashPassword(password, { N = config.auth.scryptN, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16);
  const keylen = 64;
  const derived = scrypt(password, salt, keylen, N, r, p);
  return ['scrypt', N, r, p, salt.toString('base64url'), derived.toString('base64url')].join('$');
}

function verifyPasswordHash(password, stored) {
  try {
    const [algo, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (algo !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(hashB64, 'base64url');
    const derived = scrypt(password, salt, expected.length, Number(N), Number(r), Number(p));
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

/** 恒时比较字符串 */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

module.exports = {
  hashPassword,
  hashPasswordAsync,
  verifyPasswordHash,
  verifyPasswordHashAsync,
  safeEqual,
};
