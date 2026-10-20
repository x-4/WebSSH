'use strict';

/**
 * 本机会话资源看门狗（仅 Linux）。
 *
 * 通过 /proc 统计某个 Shell 的进程树规模与常驻内存，超过阈值时由会话自行终止，
 * 用于兜住 fork bomb、内存耗尽型命令，避免拖垮 WebSSH 与整台部署机。
 *
 * 这是一层「软限制」：
 * - 采样间隔内仍可能出现瞬时峰值；
 * - 不限制 CPU 时间与磁盘 IO；
 * - Windows / macOS 暂不支持（启动日志会明确提示）。
 */

const fs = require('fs');

const PAGE_SIZE = 4096;

/** 读取 /proc 下的进程快照（导出以便单元测试） */
function readProcTable(procRoot = '/proc') {
  const table = [];
  let names;
  try {
    names = fs.readdirSync(procRoot);
  } catch {
    return table;
  }

  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = fs.readFileSync(`${procRoot}/${name}/stat`, 'utf8');
      const close = stat.lastIndexOf(')');
      const pid = Number(stat.slice(0, stat.indexOf(' ')));
      const rest = stat.slice(close + 1).trim().split(/\s+/);
      // ) 之后依次是 state(0) ppid(1) ... rss(21)
      table.push({ pid, ppid: Number(rest[1]), rssBytes: Number(rest[21]) * PAGE_SIZE });
    } catch {
      /* 进程可能已退出 */
    }
  }
  return table;
}

/** 统计以 rootPid 为根的进程树规模（导出以便单元测试） */
function summarize(tree, rootPid) {
  const byParent = new Map();
  for (const p of tree) {
    if (!byParent.has(p.ppid)) byParent.set(p.ppid, []);
    byParent.get(p.ppid).push(p);
  }

  let count = 0;
  let rssBytes = 0;
  const stack = [rootPid];
  const seen = new Set();

  while (stack.length) {
    const pid = stack.pop();
    if (seen.has(pid)) continue;
    seen.add(pid);

    const node = tree.find((p) => p.pid === pid);
    if (!node) continue;

    count += 1;
    rssBytes += Number(node.rssBytes) || 0;
    for (const child of byParent.get(pid) || []) stack.push(child.pid);
  }

  return { count, rssBytes };
}

function processTreeUsage(rootPid) {
  if (!rootPid) return { count: 0, rssBytes: 0 };
  return summarize(readProcTable(), rootPid);
}

module.exports = { readProcTable, summarize, processTreeUsage, PAGE_SIZE };
