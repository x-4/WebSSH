'use strict';

/**
 * 终端输入解析：从原始按键流中还原「已提交的命令行」，用于审计。
 *
 * 输入流包含方向键等转义序列、退格、Ctrl+C/U/W，需先剥离控制序列再按行缓冲。
 * 这是启发式还原，不追求 100% 语义精确，目标是留下可追溯的操作记录：
 * - 粘贴多行时每一行都会记录；
 * - 行内光标移动（左/右方向键）无法精确重放，记录结果可能与实际执行略有差异；
 * - 密码提示处的输入由调用方标记为敏感并屏蔽。
 */

const CSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const OSC_RE = /\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g;
const OTHER_ESC_RE = /\x1bO[A-Za-z]|\x1b./g;
const MAX_LINE = 4096;

function stripControlSequences(input) {
  return String(input).replace(OSC_RE, '').replace(CSI_RE, '').replace(OTHER_ESC_RE, '');
}

function createLineTracker() {
  let buffer = '';

  return {
    /** 送入一段输入，返回本次提交的命令行（按回车切分，可能为空串） */
    feed(data) {
      const clean = stripControlSequences(data);
      const submitted = [];
      for (const ch of clean) {
        const code = ch.codePointAt(0);
        if (ch === '\r' || ch === '\n') {
          submitted.push(buffer);
          buffer = '';
        } else if (ch === '\u007f' || ch === '\b') {
          buffer = buffer.slice(0, -1);
        } else if (ch === '\u0015' || ch === '\u0003') {
          buffer = ''; // Ctrl+U / Ctrl+C
        } else if (ch === '\u0017') {
          buffer = buffer.replace(/\S+\s*$/, ''); // Ctrl+W
        } else if (code >= 0x20 && code !== 0x7f && buffer.length < MAX_LINE) {
          buffer += ch;
        }
      }
      return submitted;
    },
    reset() {
      buffer = '';
    },
    peek() {
      return buffer;
    },
  };
}

/** 常见口令提示：sudo / su / ssh / 数据库客户端 / 中文提示 */
const SECRET_PROMPT_RE =
  /(password|passphrase|passwd|passcode|\bpin\b|\btoken\b|\bsecret\b|密码|口令|密钥|验证码|动态码)[^:：\n]{0,40}[:：]\s*$/i;

function isSecretPrompt(text) {
  const visible = stripControlSequences(text).split(/[\r\n]/).pop() || '';
  return SECRET_PROMPT_RE.test(visible.trim());
}

module.exports = { createLineTracker, stripControlSequences, isSecretPrompt };
