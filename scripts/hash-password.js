'use strict';

/**
 * 生成登录口令的 scrypt 哈希，用于 .env 中的 WEBSSH_PASS_HASH。
 *
 * 用法：
 *   npm run hash                 # 交互式输入
 *   npm run hash -- 'MyPassw0rd' # 直接传参（会留在 shell 历史里，仅建议临时使用）
 */

const readline = require('readline');
const { hashPassword } = require('../src/auth');

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

(async function main() {
  let password = process.argv[2];

  if (!password) {
    password = await ask('请输入登录口令: ', { silent: true });
    const confirm = await ask('请再次输入以确认: ', { silent: true });
    if (password !== confirm) {
      console.error('两次输入不一致，已取消。');
      process.exit(1);
    }
  }

  if (!password || password.length < 8) {
    console.error('口令长度至少 8 位。');
    process.exit(1);
  }

  const hash = hashPassword(password);
  console.log('\n将下面一行写入 .env（并删除 WEBSSH_PASS）：\n');
  console.log(`WEBSSH_PASS_HASH=${hash}\n`);
})();
