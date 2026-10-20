'use strict';

/**
 * 浏览器端到端测试：登录 → 二次认证 → 打开部署机终端 → 执行命令 → 看到输出。
 * 需要本机存在 Chrome / Chromium / Edge；否则自动跳过。
 *
 * 运行：npm run test:e2e
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { chromium } = require('playwright-core');

const ROOT = path.resolve(__dirname, '..', '..');
const PASSWORD = 'e2e-pass-123';

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

const chromePath = CHROME_CANDIDATES.find((candidate) => {
  try {
    return fs.existsSync(candidate);
  } catch {
    return false;
  }
});

function waitForPort(proc, timeout = 20000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`服务启动超时\n${buffer}`)), timeout);
    proc.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      const match = buffer.match(/已启动\s*→\s*https?:\/\/[^:]+:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    proc.once('exit', (code) => reject(new Error(`服务退出 code=${code}\n${buffer}`)));
  });
}

async function waitUntil(page, fn, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await page.evaluate(fn)) return;
    await page.waitForTimeout(150);
  }
  throw new Error(`等待超时: ${label}`);
}

test('浏览器端到端：登录、二次认证、本机终端', { timeout: 90000, skip: !chromePath && '未找到 Chrome/Chromium' }, async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-e2e-'));
  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: '0',
      HOST: '127.0.0.1',
      DATA_DIR: dataDir,
      WEBSSH_USER: 'tester',
      WEBSSH_PASS: PASSWORD,
      SESSION_SECRET: 'e2e'.repeat(20),
      LOG_LEVEL: 'info',
      LOCAL_TERMINAL_ENABLED: 'true',
      RECORDING_ENABLED: 'false',
      AUDIT_FORWARD_URL: '',
      HTTP_RATE_LIMIT_PER_MIN: '1000',
      SSH_BLOCK_PRIVATE_HOSTS: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  let browser;
  try {
    const port = await waitForPort(child);
    const base = `http://127.0.0.1:${port}`;

    browser = await chromium.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox'],
    });

    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    await page.goto(`${base}/login`);

    await page.fill('#username', 'tester');
    await page.fill('#password', PASSWORD);
    await page.click('#submit-btn');
    await page.waitForURL(`${base}/`, { timeout: 15000 });

    await page.waitForSelector('#connect-local-btn');
    await page.click('#connect-local-btn');

    await waitUntil(page, () => !document.getElementById('stepup-modal').hidden, '二次认证弹窗');
    await page.fill('#stepup-password', PASSWORD);
    await page.click('#stepup-submit');
    await waitUntil(page, () => document.getElementById('stepup-modal').hidden, '二次认证通过');

    await waitUntil(page, () => document.querySelector('.tab-dot.connected') !== null, '本机终端连接', 30000);
    await waitUntil(
      page,
      () => {
        const el = document.querySelector('.term-pane.active .xterm-rows');
        return Boolean(el && el.innerText.trim());
      },
      '终端提示符'
    );

    await page.click('.term-pane.active .xterm');
    await page.keyboard.type('echo E2E_OK');
    await page.keyboard.press('Enter');
    await waitUntil(
      page,
      () => {
        const el = document.querySelector('.term-pane.active .xterm-rows');
        return Boolean(el && el.innerText.includes('E2E_OK'));
      },
      '命令输出',
      20000
    );

    const status = await page.textContent('#status-left');
    assert.match(status, /已连接/);
  } catch (err) {
    throw new Error(`${err.message}\n--- server stderr ---\n${stderr}`);
  } finally {
    if (browser) await browser.close().catch(() => {});
    child.kill();
  }
});
