'use strict';

/**
 * 轻量指标：Prometheus 文本格式，无需额外依赖。
 *
 * 计数器：webssh_login_total{result}、webssh_step_up_total{result}、
 *         webssh_ws_total、webssh_session_total{kind}、webssh_command_total{kind}
 * 仪表盘：webssh_up、webssh_sessions{kind}、webssh_ws_connections、
 *         webssh_audit_forward_pending、webssh_audit_seq、
 *         webssh_process_resident_memory_bytes、webssh_uptime_seconds
 *
 * 通过 GET /metrics 暴露，可用 METRICS_TOKEN 收紧访问。
 */

const counters = new Map(); // name -> { help, values: Map<key, { labels, value }> }
const gauges = []; // { name, help, fn }

function labelsKey(labels) {
  return Object.keys(labels)
    .sort()
    .map((k) => `${k}=${labels[k]}`)
    .join(',');
}

function inc(name, labels = {}, value = 1) {
  let entry = counters.get(name);
  if (!entry) {
    entry = { help: `Counter ${name}`, values: new Map() };
    counters.set(name, entry);
  }
  const key = labelsKey(labels);
  const current = entry.values.get(key);
  if (current) current.value += value;
  else entry.values.set(key, { labels, value });
}

function registerGauge(name, help, fn) {
  gauges.push({ name, help, fn });
}

function escapeLabel(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function formatSeries(name, labels, value) {
  const keys = Object.keys(labels).sort();
  const suffix = keys.length ? `{${keys.map((k) => `${k}="${escapeLabel(labels[k])}"`).join(',')}}` : '';
  return `${name}${suffix} ${Number.isFinite(value) ? value : 0}`;
}

function render() {
  const lines = [];

  lines.push('# HELP webssh_up 服务存活状态');
  lines.push('# TYPE webssh_up gauge');
  lines.push('webssh_up 1');

  for (const [name, entry] of counters) {
    lines.push(`# HELP ${name} ${entry.help}`);
    lines.push(`# TYPE ${name} counter`);
    for (const { labels, value } of entry.values.values()) lines.push(formatSeries(name, labels, value));
  }

  for (const gauge of gauges) {
    let value;
    try {
      value = gauge.fn();
    } catch {
      value = 0;
    }
    lines.push(`# HELP ${gauge.name} ${gauge.help}`);
    lines.push(`# TYPE ${gauge.name} gauge`);
    if (Array.isArray(value)) {
      for (const item of value) lines.push(formatSeries(gauge.name, item.labels || {}, item.value));
    } else {
      lines.push(formatSeries(gauge.name, {}, value));
    }
  }

  return `${lines.join('\n')}\n`;
}

module.exports = { inc, registerGauge, render };
