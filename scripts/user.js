'use strict';

/**
 * 用户管理 CLI（多用户 / 角色）。
 *
 * 用法：
 *   npm run user -- list
 *   npm run user -- add alice --role operator
 *   npm run user -- passwd alice
 *   npm run user -- role alice developer
 *   npm run user -- disable alice
 *   npm run user -- enable alice
 *   npm run user -- hosts alice "10.0.0.*,*.internal"
 *   npm run user -- remove alice
 *
 * 角色：admin | operator | developer | auditor
 * 写入 WEBSSH_USERS_FILE（默认 data/users.json，权限 0600），重启服务后生效。
 */

process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'warn';

const readline = require('readline');
const config = require('../src/config');
const users = require('../src/users');
const { hashPassword } = require('../src/password');

function ask(question, { silent = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (silent) {
      rl._writeToOutput = function writeToOutput(str) {
        if (str.includes(question)) rl.output.write(question);
        else rl.output.write('*');
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function readPassword(provided) {
  if (provided) return provided;
  const value = await ask('设置口令（至少 8 位）: ', { silent: true });
  const confirm = await ask('再次输入确认: ', { silent: true });
  if (value !== confirm) throw new Error('两次输入不一致');
  return value;
}

function loadList() {
  const list = users.readFileUsers();
  if (list.length) return list;

  // 首次创建用户文件时，把当前环境变量账号迁移为 admin，避免把自己锁在门外
  const env = users.get(config.auth.username);
  if (env && (env.passwordHash || env.passwordPlain)) {
    return [
      {
        username: env.username,
        role: 'admin',
        passwordHash: env.passwordHash || hashPassword(env.passwordPlain),
        createdAt: new Date().toISOString(),
      },
    ];
  }
  return [];
}

function save(list) {
  list.sort((a, b) => a.username.localeCompare(b.username));
  users.writeFileUsers(list);
  console.log(`已写入 ${config.auth.usersFile}（重启服务后生效）`);
}

function find(list, username) {
  const item = list.find((u) => u.username === username);
  if (!item) throw new Error(`用户不存在: ${username}`);
  return item;
}

function assertRole(role) {
  if (!users.ROLES[role]) {
    throw new Error(`未知角色: ${role}（可选：${Object.keys(users.ROLES).join(' / ')}）`);
  }
}

(async function main() {
  const [command, username, ...rest] = process.argv.slice(2);
  const list = loadList();

  const roleIndex = rest.indexOf('--role');
  const roleArg = roleIndex >= 0 ? rest[roleIndex + 1] : null;
  const passIndex = rest.indexOf('--password');
  const passArg = passIndex >= 0 ? rest[passIndex + 1] : null;

  switch (command) {
    case 'list': {
      if (!list.length) {
        console.log('当前没有用户文件，使用环境变量单账号模式。');
        break;
      }
      console.log(`用户文件: ${config.auth.usersFile}`);
      for (const u of list) {
        console.log(
          `  ${u.username.padEnd(16)} ${String(u.role).padEnd(10)} ${u.disabled ? '已禁用' : '正常'}  ${u.note || ''}`
        );
      }
      break;
    }

    case 'add': {
      if (!username) throw new Error('用法: add <username> --role <role>');
      if (list.some((u) => u.username === username)) throw new Error(`用户已存在: ${username}`);
      const role = roleArg || 'developer';
      assertRole(role);

      const plain = await readPassword(passArg);
      if (!plain || plain.length < 8) throw new Error('口令长度至少 8 位');

      list.push({
        username,
        role,
        passwordHash: hashPassword(plain),
        createdAt: new Date().toISOString(),
      });
      save(list);
      console.log(`已添加用户 ${username}（角色 ${role}）`);
      break;
    }

    case 'passwd': {
      if (!username) throw new Error('用法: passwd <username>');
      const user = find(list, username);
      const plain = await readPassword(passArg);
      if (!plain || plain.length < 8) throw new Error('口令长度至少 8 位');
      user.passwordHash = hashPassword(plain);
      user.updatedAt = new Date().toISOString();
      save(list);
      console.log(`已更新 ${username} 的口令`);
      break;
    }

    case 'role': {
      if (!username || !roleArg) throw new Error('用法: role <username> <role>');
      assertRole(roleArg);
      const user = find(list, username);
      user.role = roleArg;
      save(list);
      console.log(`已将 ${username} 的角色改为 ${roleArg}`);
      break;
    }

    case 'hosts': {
      if (!username) throw new Error('用法: hosts <username> ["10.0.0.*,*.internal"]');
      const user = find(list, username);
      const patternArg = rest.find((item) => !item.startsWith('--'));

      if (patternArg === undefined) {
        console.log(`${username} 的授权主机: ${user.hosts && user.hosts.length ? user.hosts.join(', ') : '（不限制）'}`);
        break;
      }

      const patterns = patternArg
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);

      for (const pattern of patterns) {
        if (!/^[A-Za-z0-9.*?_\-\[\]:]+$/.test(pattern)) {
          throw new Error(`非法的主机模式: ${pattern}`);
        }
      }

      user.hosts = patterns;
      save(list);
      console.log(
        patterns.length
          ? `已将 ${username} 限制为: ${patterns.join(', ')}`
          : `已取消 ${username} 的主机限制`
      );
      break;
    }

    case 'disable':
    case 'enable': {
      if (!username) throw new Error(`用法: ${command} <username>`);
      const user = find(list, username);
      user.disabled = command === 'disable';
      save(list);
      console.log(`已${user.disabled ? '禁用' : '启用'} ${username}`);
      break;
    }

    case 'remove': {
      if (!username) throw new Error('用法: remove <username>');
      find(list, username);
      const next = list.filter((u) => u.username !== username);
      if (!next.some((u) => u.role === 'admin')) {
        throw new Error('至少保留一个 admin 账号');
      }
      save(next);
      console.log(`已删除 ${username}`);
      break;
    }

    default:
      console.log(
        [
          '用法:',
          '  npm run user -- list',
          '  npm run user -- add <username> --role <admin|operator|developer|auditor>',
          '  npm run user -- passwd <username>',
          '  npm run user -- role <username> <role>',
          '  npm run user -- disable|enable <username>',
          '  npm run user -- hosts <username> ["10.0.0.*,*.internal"]',
          '  npm run user -- remove <username>',
        ].join('\n')
      );
  }
})().catch((err) => {
  console.error(`操作失败: ${err.message}`);
  process.exit(1);
});
