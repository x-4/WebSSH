'use strict';

/**
 * 本地演示用 SSH 服务（仅开发环境使用，默认只监听 127.0.0.1）。
 *
 * 目的：在没有可连的真实主机时，也能完整体验「登录 → 建连 → 终端交互 → 断线重连」。
 * 它不是生产组件，账号固定为 demo / demo，请勿对外暴露。
 *
 * 用法：npm run mock  [-- 2222]
 */

const fs = require('fs');
const path = require('path');
const { Server, utils } = require('ssh2');

const PORT = Number(process.argv[2]) || 2222;
const HOST = '127.0.0.1';

// 首次运行生成主机密钥并落盘复用，避免每次重启都触发「主机密钥变更」告警
const keyFile = path.join(__dirname, '..', 'data', 'mock_ssh_host_key');
let hostKey;
try {
  hostKey = fs.readFileSync(keyFile);
} catch {
  hostKey = utils.generateKeyPairSync('rsa', { bits: 2048 }).private;
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  fs.writeFileSync(keyFile, hostKey, { mode: 0o600 });
}

const server = new Server({ hostKeys: [hostKey] }, (client) => {
  client.on('error', () => {});

  client
    .on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === 'demo' && ctx.password === 'demo') {
        return ctx.accept();
      }
      return ctx.reject(['password', 'keyboard-interactive']);
    })
    .on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (acceptPty) => acceptPty && acceptPty());
        session.on('window-change', (acceptWin) => acceptWin && acceptWin());

        session.on('shell', (acceptShell) => {
          const stream = acceptShell();
          let line = '';

          stream.write('Welcome to mock-ssh (demo only)\r\n$ ');

          stream.on('data', (chunk) => {
            for (const ch of chunk.toString('utf8')) {
              if (ch === '\r' || ch === '\n') {
                const cmd = line.trim();
                stream.write(`\r\nmock-output: ${cmd}\r\n$ `);
                line = '';
              } else if (ch === '\u007f') {
                line = line.slice(0, -1);
                stream.write('\b \b');
              } else if (ch === '\u0003') {
                line = '';
                stream.write('^C\r\n$ ');
              } else {
                line += ch;
                stream.write(ch);
              }
            }
          });
        });
      });
    });
});

server.listen(PORT, HOST, () => {
  console.log(`mock ssh listening on ${HOST}:${PORT}  (user: demo / password: demo)`);
});
