'use strict';

/**
 * WebSSH 前端：终端渲染 + WebSocket 会话管理 + 断线重连
 *
 * 设计要点：
 * - 每个会话拥有独立的 xterm 实例与 WebSocket，互不影响；
 * - WebSocket 断开后优先用 sessionId + token "续接"后端已有的 SSH 会话，
 *   终端内容由服务端回放，用户不会因为刷新页面或网络抖动而丢失工作现场；
 * - 续接失败（会话已被回收）才提示用户重新建立连接。
 */

(function () {
  const TerminalCtor = window.Terminal;
  const FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;

  const $ = (id) => document.getElementById(id);

  const ui = {
    form: $('conn-form'),
    host: $('host'),
    port: $('port'),
    username: $('username'),
    password: $('password'),
    privateKey: $('privateKey'),
    passphrase: $('passphrase'),
    passwordField: $('password-field'),
    keyFields: $('key-fields'),
    authSeg: $('auth-seg'),
    connectBtn: $('connect-btn'),
    formError: $('form-error'),
    noPermission: $('no-permission'),
    hostNote: $('host-note'),
    modeTitle: $('mode-title'),
    sideTips: document.querySelector('.side-tips'),
    currentRole: $('current-role'),
    modeSeg: $('mode-seg'),
    sshFields: $('ssh-fields'),
    localPanel: $('local-panel'),
    localHost: $('local-host'),
    localShell: $('local-shell'),
    localCwd: $('local-cwd'),
    localUser: $('local-user'),
    localNote: $('local-note'),
    localError: $('local-error'),
    connectLocalBtn: $('connect-local-btn'),
    tabs: $('tabs'),
    tabbarEmpty: $('tabbar-empty'),
    terminals: $('terminals'),
    emptyState: $('empty-state'),
    statusLeft: $('status-left'),
    statusLatency: $('status-latency'),
    statusSize: $('status-size'),
    statusHistory: $('history-btn'),
    history: $('history'),
    historyClose: $('history-close'),
    historyList: $('history-list'),
    historyMeta: $('history-meta'),
    main: document.querySelector('.main'),
    stepupModal: $('stepup-modal'),
    stepupForm: $('stepup-form'),
    stepupPassword: $('stepup-password'),
    stepupError: $('stepup-error'),
    stepupCancel: $('stepup-cancel'),
    stepupSubmit: $('stepup-submit'),
    recordingsBtn: $('recordings-btn'),
    recordingsModal: $('recordings-modal'),
    recordingsClose: $('recordings-close'),
    recList: $('rec-list'),
    recPlayer: $('rec-player'),
    recEmpty: $('rec-empty'),
    recPlay: $('rec-play'),
    recProgress: $('rec-progress'),
    recTime: $('rec-time'),
    recSpeed: $('rec-speed'),
    touchBar: $('touch-bar'),
    currentUser: $('current-user'),
    logoutBtn: $('logout-btn'),
    sidebar: $('sidebar'),
    menuBtn: $('menu-btn'),
    sidebarClose: $('sidebar-close'),
  };

  const STORAGE_KEY = 'webssh.resumable.v1';
  const MAX_RECONNECT_ATTEMPTS = 5;

  const state = {
    sessions: new Map(),
    order: [],
    activeKey: null,
    config: {
      scrollback: 5000,
      maxSessionsPerUser: 10,
      resumeGraceSeconds: 120,
    },
    authType: 'password',
    mode: 'local',
    permissions: [],
    hostRestricted: false,
    role: 'developer',
    roleLabel: '',
    stepUp: { required: false, ttlSeconds: 300, remainingSeconds: 0 },
    recording: { enabled: false, loaded: false },
    player: {
      term: null,
      events: [],
      duration: 0,
      index: 0,
      elapsed: 0,
      timer: null,
      playing: false,
      speed: 1,
      id: null,
    },
    local: { enabled: false, available: false, reason: '', maxSessions: 2 },
    historyTimer: null,
    seq: 0,
  };

  const THEME = {
    background: '#0a0e13',
    foreground: '#d8e3f0',
    cursor: '#4c9df3',
    cursorAccent: '#0a0e13',
    selectionBackground: 'rgba(76, 157, 243, 0.28)',
    black: '#1c2530',
    red: '#f0716b',
    green: '#5ed6a0',
    yellow: '#e3bd4f',
    blue: '#5aa9f0',
    magenta: '#c793ea',
    cyan: '#5ac8d8',
    white: '#cfdae7',
    brightBlack: '#5b6d80',
    brightRed: '#ff8b85',
    brightGreen: '#7ce8b6',
    brightYellow: '#f4d06f',
    brightBlue: '#7cbcff',
    brightMagenta: '#d9aef7',
    brightCyan: '#7fdce9',
    brightWhite: '#f2f7fd',
  };

  const STATUS_TEXT = {
    idle: '未连接',
    connecting: '连接中',
    connected: '已连接',
    reconnecting: '重连中',
    closed: '已断开',
    error: '连接失败',
  };

  function sessionLabel(session) {
    if (session.meta && session.meta.label) return session.meta.label;
    if (session.kind === 'local') return '部署机终端';
    return connectionLabel(session.params);
  }

  function connectionLabel(params) {
    const port = Number(params.port) || 22;
    return `${params.username}@${params.host}${port === 22 ? '' : `:${port}`}`;
  }

  function makeEl(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /** 写剪贴板：优先异步 API，HTTP 等非安全上下文回退到 execCommand */
  async function writeClipboard(text) {
    if (!text) return false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      /* 继续尝试回退方案 */
    }
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }

  /** 读剪贴板：非安全上下文返回 null，由调用方提示使用浏览器原生粘贴 */
  async function readClipboard() {
    try {
      if (navigator.clipboard && window.isSecureContext) return await navigator.clipboard.readText();
    } catch {
      /* 用户拒绝授权等 */
    }
    return null;
  }

  function wsEndpoint() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws`;
  }

  /* ------------------------------ 会话 ------------------------------ */

  class Session {
    constructor({ params, sessionId = null, token = null }) {
      this.key = `s${++state.seq}`;
      this.params = { ...params };
      this.kind = params.kind === 'local' ? 'local' : 'ssh';
      this.meta = null;
      this.sessionId = sessionId;
      this.token = token;

      this.status = 'idle';
      this.ws = null;
      this.term = null;
      this.fitAddon = null;
      this.pane = null;
      this.termHost = null;
      this.overlay = null;

      this.reconnectTimer = null;
      this.countdownTimer = null;
      this.pingTimer = null;
      this.lastPong = Date.now();
      this.latency = null;

      this.attempts = 0;
      this.everReady = false;
      this.disposed = false;
      this.intentionalClose = false;
      this.resizeObserver = null;
      this.fitFrame = null;
    }

    /* ---------- UI 构建 ---------- */
    mount() {
      const pane = makeEl('div', 'term-pane');
      pane.dataset.key = this.key;

      const host = makeEl('div', 'term-host');
      pane.appendChild(host);

      const overlay = makeEl('div', 'pane-overlay');
      overlay.hidden = true;
      overlay.innerHTML = `
        <div class="overlay-card">
          <div class="spinner"></div>
          <div class="overlay-icon" hidden></div>
          <h3></h3>
          <p></p>
          <div class="overlay-actions" hidden>
            <button class="btn primary" data-act="retry" type="button">重新连接</button>
            <button class="btn ghost" data-act="dismiss" type="button">关闭会话</button>
          </div>
        </div>`;
      pane.appendChild(overlay);

      ui.terminals.appendChild(pane);

      this.pane = pane;
      this.termHost = host;
      this.overlay = overlay;

      overlay.addEventListener('click', (event) => {
        const act = event.target.dataset && event.target.dataset.act;
        if (act === 'retry') this.retry();
        if (act === 'dismiss') closeSession(this.key);
      });

      this.term = new TerminalCtor({
        fontFamily:
          'ui-monospace, "JetBrains Mono", "Cascadia Code", "SFMono-Regular", Consolas, "Microsoft YaHei Mono", monospace',
        fontSize: 13,
        lineHeight: 1.2,
        letterSpacing: 0,
        cursorBlink: true,
        cursorStyle: 'bar',
        cursorWidth: 2,
        scrollback: state.config.scrollback || 5000,
        allowTransparency: true,
        macOptionIsMeta: true,
        theme: THEME,
      });

      this.fitAddon = new FitAddonCtor();
      this.term.loadAddon(this.fitAddon);
      this.term.open(host);

      this.bindTerminal();
      this.observeResize();
    }

    bindTerminal() {
      this.term.onData((data) => {
        if (this.status === 'connected') this.send({ type: 'input', data });
        // 本机终端提交命令后，若历史面板打开则自动刷新
        if (this.kind === 'local' && data.includes('\r') && !ui.history.hidden) {
          clearTimeout(state.historyTimer);
          state.historyTimer = setTimeout(loadHistory, 350);
        }
      });

      this.term.onResize(({ cols, rows }) => {
        this.send({ type: 'resize', cols, rows });
        if (isActive(this)) updateStatusBar();
      });

      this.term.attachCustomKeyEventHandler((event) => {
        if (event.type !== 'keydown') return true;
        const mod = event.ctrlKey || event.metaKey;
        if (mod && event.shiftKey && event.code === 'KeyC') {
          writeClipboard(this.term.getSelection());
          return false;
        }
        if (mod && event.shiftKey && event.code === 'KeyV') {
          readClipboard().then((text) => {
            if (text) {
              this.send({ type: 'input', data: text });
              return;
            }
            if (!this.pasteHinted) {
              this.pasteHinted = true;
              this.term.write(
                '\r\n\x1b[38;5;245m[当前环境无法读取剪贴板，请使用 Ctrl+V 或浏览器菜单粘贴]\x1b[0m\r\n'
              );
            }
          });
          return false;
        }
        return true;
      });
    }

    observeResize() {
      if (typeof ResizeObserver === 'undefined') return;
      this.resizeObserver = new ResizeObserver(() => {
        if (!isActive(this) || this.fitFrame) return;
        this.fitFrame = requestAnimationFrame(() => {
          this.fitFrame = null;
          this.fit();
        });
      });
      this.resizeObserver.observe(this.pane);
    }

    fit() {
      if (!this.pane || !this.pane.classList.contains('active')) return;
      try {
        this.fitAddon.fit();
      } catch {
        /* 容器尺寸为 0 时忽略 */
      }
    }

    focus() {
      if (this.term) this.term.focus();
    }

    /* ---------- 生命周期 ---------- */
    start() {
      // 已有 sessionId 说明是页面刷新后的续接
      this.connect({ fresh: !this.sessionId });
    }

    connect({ fresh }) {
      this.clearTimers();
      this.intentionalClose = false;
      this.setStatus(fresh ? 'connecting' : 'reconnecting');
      this.showOverlay({
        kind: 'loading',
        title: fresh ? '正在建立 SSH 连接…' : '正在恢复会话…',
        message: fresh
          ? `目标 ${connectionLabel(this.params)}`
          : '尝试接续服务端保留的 SSH 会话，终端输出将自动回放。',
      });

      this.openSocket(() => {
        const cols = this.term ? this.term.cols : 80;
        const rows = this.term ? this.term.rows : 24;
        if (fresh && this.kind === 'local') {
          this.send({ type: 'connect', kind: 'local', cols, rows, term: 'xterm-256color' });
        } else if (fresh) {
          const p = this.params;
          this.send({
            type: 'connect',
            kind: 'ssh',
            host: p.host,
            port: Number(p.port) || 22,
            username: p.username,
            authType: p.authType || 'password',
            password: p.password || '',
            privateKey: p.privateKey || '',
            passphrase: p.passphrase || '',
            cols,
            rows,
            term: 'xterm-256color',
          });
        } else {
          this.send({ type: 'resume', sessionId: this.sessionId, token: this.token, cols, rows });
        }
      });
    }

    openSocket(onOpen) {
      if (this.ws) {
        try {
          this.ws.onclose = null;
          this.ws.close();
        } catch {
          /* ignore */
        }
      }

      let ws;
      try {
        ws = new WebSocket(wsEndpoint());
      } catch {
        this.fail('无法建立 WebSocket 连接', '请确认服务端已启动且反向代理已支持 WebSocket 升级。');
        return;
      }

      this.ws = ws;
      this.lastPong = Date.now();

      ws.onopen = () => {
        this.startHeartbeat();
        onOpen();
      };
      ws.onmessage = (event) => this.onMessage(event.data);
      ws.onclose = () => this.onSocketClose();
      ws.onerror = () => {
        /* 具体原因由 onclose 统一处理 */
      };
    }

    send(payload) {
      const ws = this.ws;
      if (!ws || ws.readyState !== WebSocket.OPEN) return false;
      try {
        ws.send(JSON.stringify(payload));
        return true;
      } catch {
        return false;
      }
    }

    onMessage(raw) {
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }

      switch (msg.type) {
        case 'ready':
          this.sessionId = msg.sessionId;
          this.token = msg.token;
          this.meta = msg.meta || this.meta;
          this.attempts = 0;
          this.everReady = true;
          this.setStatus('connected');
          this.hideOverlay();
          if (msg.resumed) this.term.reset();
          if (msg.replay) this.term.write(msg.replay);
          if (msg.truncated) {
            this.term.write('\r\n\x1b[38;5;244m[历史输出较多，已省略早期部分]\x1b[0m\r\n');
          }
          persistSessions();
          if (this.kind === 'local' && !ui.history.hidden) loadHistory();
          if (isActive(this)) {
            this.fit();
            this.focus();
            updateStatusBar();
          }
          break;

        case 'data':
          this.term.write(msg.data);
          break;

        case 'status':
          if (msg.message && !this.everReady) this.setOverlayMessage(msg.message);
          break;

        case 'pong':
          this.lastPong = Date.now();
          this.latency = Math.max(0, Date.now() - (Number(msg.t) || Date.now()));
          if (isActive(this)) updateStatusBar();
          break;

        case 'exit':
          this.setStatus('closed');
          this.term.write(
            `\r\n\x1b[38;5;245m[远端 Shell 已退出${msg.code !== undefined && msg.code !== null ? ` · code ${msg.code}` : ''}${
              msg.signal ? ` · ${msg.signal}` : ''
            }]\x1b[0m\r\n`
          );
          this.clearSessionTicket();
          this.showOverlay({
            kind: 'closed',
            title: '会话已结束',
            message: '远端 Shell 进程已退出。可以重新连接，或关闭该标签页。',
            actions: true,
          });
          break;

        case 'closed':
          this.handleServerClosed(msg.reason);
          break;

        case 'error':
          this.onServerError(msg);
          break;

        default:
          break;
      }
    }

    onServerError(msg) {
      const message = msg.message || '服务端返回错误';

      if (msg.code === 'FORBIDDEN') {
        this.fail('权限不足', message);
        return;
      }

      if (msg.code === 'STEP_UP_REQUIRED') {
        // 凭证已过期：弹出二次认证，成功后自动重试
        this.setStatus('connecting');
        this.showOverlay({
          kind: 'loading',
          title: '需要二次身份验证',
          message: '请在弹窗中确认账号口令，验证成功后将自动打开终端。',
        });
        promptStepUp().then((ok) => {
          if (ok) this.connect({ fresh: true });
          else this.fail('已取消验证', '打开部署机终端需要二次身份验证。');
        });
        return;
      }

      // 运行期错误：终端里提示即可，不断开会话
      if (this.status === 'connected' && (msg.code === 'SSH_ERROR' || msg.code === 'INTERNAL')) {
        this.term.write(`\r\n\x1b[31m[错误] ${message}\x1b[0m\r\n`);
        return;
      }

      if (msg.code === 'RESUME_FAILED') {
        this.clearSessionTicket();
      }

      this.fail(msg.code === 'RESUME_FAILED' ? '会话已断开' : '连接失败', message);
    }

    handleServerClosed(reason) {
      const reasonText = {
        shell_exit: '远端 Shell 已退出',
        ssh_closed: 'SSH 连接已关闭',
        ssh_error: 'SSH 连接异常',
        resume_timeout: '断线时间过长，会话已被服务端回收',
        idle_timeout: '长时间无操作，会话已自动断开',
        closed_by_user: '会话已被关闭',
        connect_failed: 'SSH 连接建立失败',
      }[reason] || '会话已结束';

      this.clearSessionTicket();
      this.setStatus('closed');
      this.showOverlay({
        kind: 'closed',
        title: reasonText,
        message: '可以重新连接，或关闭该标签页。',
        actions: true,
      });
    }

    fail(title, message) {
      this.setStatus('error');
      this.clearTimers();
      if (this.ws) {
        try {
          this.ws.onclose = null;
          this.ws.close();
        } catch {
          /* ignore */
        }
        this.ws = null;
      }
      this.showOverlay({ kind: 'error', title, message, actions: true });
    }

    onSocketClose() {
      this.stopHeartbeat();
      if (this.disposed || this.intentionalClose) return;

      // 已达终态（Shell 退出 / 服务端关闭 / 连接失败）无需重连
      if (this.status === 'closed' || this.status === 'error') return;

      if (this.status === 'connected') {
        // 网络中断或服务端重启，进入自动重连
        this.scheduleReconnect();
      } else if (this.status === 'connecting') {
        this.fail('连接中断', '与服务端的连接在建立过程中断开，请检查网络或服务端日志。');
      } else if (this.status === 'reconnecting') {
        this.scheduleReconnect();
      }
    }

    scheduleReconnect() {
      if (this.reconnectTimer) return;

      if (this.attempts >= MAX_RECONNECT_ATTEMPTS) {
        this.clearSessionTicket();
        this.fail(
          '无法恢复连接',
          `已重试 ${MAX_RECONNECT_ATTEMPTS} 次仍未成功，会话可能已被服务端回收（宽限期 ${state.config.resumeGraceSeconds} 秒）。`
        );
        return;
      }

      this.attempts += 1;
      const delay = Math.min(1000 * 2 ** (this.attempts - 1), 8000);
      this.setStatus('reconnecting');

      let remaining = Math.ceil(delay / 1000);
      this.showOverlay({
        kind: 'loading',
        title: '连接已断开',
        message: `第 ${this.attempts}/${MAX_RECONNECT_ATTEMPTS} 次自动重连将于 ${remaining} 秒后开始…`,
      });

      this.countdownTimer = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          clearInterval(this.countdownTimer);
          this.countdownTimer = null;
          return;
        }
        this.setOverlayMessage(
          `第 ${this.attempts}/${MAX_RECONNECT_ATTEMPTS} 次自动重连将于 ${remaining} 秒后开始…`
        );
      }, 1000);

      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.connect({ fresh: !this.sessionId });
      }, delay);
    }

    retry() {
      this.clearTimers();
      this.attempts = 0;

      if (this.kind !== 'local' && !this.sessionId && !this.params.password && !this.params.privateKey) {
        this.fail('需要重新认证', '会话已过期，请在左侧连接面板重新输入密码建立连接。');
        ui.password.focus();
        return;
      }

      this.connect({ fresh: !this.sessionId });
    }

    /* ---------- 心跳 ---------- */
    startHeartbeat() {
      this.stopHeartbeat();
      this.lastPong = Date.now();
      this.pingTimer = setInterval(() => {
        if (Date.now() - this.lastPong > 45000) {
          // 连续三个周期无响应，判定链路已死，主动关闭以触发重连
          try {
            this.ws.close();
          } catch {
            /* ignore */
          }
          return;
        }
        this.send({ type: 'ping', t: Date.now() });
      }, 15000);
    }

    stopHeartbeat() {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }

    clearTimers() {
      clearTimeout(this.reconnectTimer);
      clearInterval(this.countdownTimer);
      clearInterval(this.pingTimer);
      this.reconnectTimer = null;
      this.countdownTimer = null;
    }

    /* ---------- 状态与浮层 ---------- */
    setStatus(status) {
      if (this.status === status) return;
      this.status = status;
      renderTabs();
      if (isActive(this)) updateStatusBar();
    }

    showOverlay({ kind, title, message, actions = false }) {
      const card = this.overlay.querySelector('.overlay-card');
      const spinner = card.querySelector('.spinner');
      const icon = card.querySelector('.overlay-icon');
      const actionBox = card.querySelector('.overlay-actions');

      spinner.hidden = kind !== 'loading';
      icon.hidden = kind === 'loading';
      icon.className = `overlay-icon ${kind === 'error' ? 'err' : 'ok'}`;
      icon.textContent = kind === 'error' ? '!' : '✓';

      card.querySelector('h3').textContent = title || '';
      card.querySelector('p').textContent = message || '';
      actionBox.hidden = !actions;
      this.overlay.hidden = false;
    }

    setOverlayMessage(message) {
      const p = this.overlay.querySelector('p');
      if (p) p.textContent = message;
    }

    hideOverlay() {
      this.overlay.hidden = true;
    }

    clearSessionTicket() {
      this.sessionId = null;
      this.token = null;
      persistSessions();
    }

    /* ---------- 销毁 ---------- */
    dispose() {
      this.intentionalClose = true;
      this.disposed = true;
      this.clearTimers();

      // 优先通过 WebSocket 通知服务端回收；socket 已断时退化为 HTTP 删除，
      // 避免「先关会话再删会话」造成的重复请求与 404。
      const socketOpen = this.ws && this.ws.readyState === WebSocket.OPEN;
      if (socketOpen) {
        try {
          this.send({ type: 'close' });
          this.ws.onclose = null;
          this.ws.close(1000, 'client close');
        } catch {
          /* ignore */
        }
      } else if (this.sessionId) {
        fetch(`/api/sessions/${encodeURIComponent(this.sessionId)}`, {
          method: 'DELETE',
          credentials: 'same-origin',
          keepalive: true,
        }).catch(() => {});
      }
      this.ws = null;

      if (this.resizeObserver) this.resizeObserver.disconnect();
      if (this.fitFrame) cancelAnimationFrame(this.fitFrame);

      try {
        this.term.dispose();
      } catch {
        /* ignore */
      }

      if (this.pane) this.pane.remove();
      this.term = null;
      this.pane = null;
    }
  }

  /* ------------------------------ 会话集合操作 ------------------------------ */

  function isActive(session) {
    return state.activeKey === session.key;
  }

  function activeSession() {
    return state.sessions.get(state.activeKey) || null;
  }

  function register(session) {
    state.sessions.set(session.key, session);
    state.order.push(session.key);
    session.mount();
    renderTabs();
    activate(session.key);
  }

  function activate(key) {
    const session = state.sessions.get(key);
    if (!session) return;

    state.activeKey = key;
    for (const [k, s] of state.sessions) {
      if (s.pane) s.pane.classList.toggle('active', k === key);
    }
    renderTabs();
    ui.emptyState.hidden = state.order.length > 0;

    requestAnimationFrame(() => {
      session.fit();
      session.focus();
      updateStatusBar();
    });
  }

  function closeSession(key) {
    const session = state.sessions.get(key);
    if (!session) return;

    const idx = state.order.indexOf(key);
    session.dispose();
    state.sessions.delete(key);
    state.order.splice(idx, 1);

    if (state.activeKey === key) {
      state.activeKey = null;
      const nextKey = state.order[Math.min(idx, state.order.length - 1)];
      if (nextKey) activate(nextKey);
      else {
        ui.emptyState.hidden = false;
        renderTabs();
        updateStatusBar();
      }
    } else {
      renderTabs();
    }
    persistSessions();
  }

  function renderTabs() {
    ui.tabs.textContent = '';
    ui.tabbarEmpty.hidden = state.order.length > 0;

    for (const key of state.order) {
      const session = state.sessions.get(key);
      if (!session) continue;

      const tab = makeEl('div', `tab${state.activeKey === key ? ' active' : ''}`);
      tab.title = `${sessionLabel(session)} · ${STATUS_TEXT[session.status] || ''}`;
      tab.tabIndex = 0;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-selected', String(state.activeKey === key));
      tab.addEventListener('click', () => activate(key));
      tab.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          activate(key);
        } else if (event.key === 'Delete' || event.key === 'Backspace') {
          event.preventDefault();
          closeSession(key);
        }
      });

      tab.appendChild(makeEl('i', `tab-dot ${session.status}`));
      tab.appendChild(makeEl('span', 'tab-label', sessionLabel(session)));

      const closeBtn = makeEl('button', 'tab-close', '×');
      closeBtn.type = 'button';
      closeBtn.title = '关闭会话';
      closeBtn.setAttribute('aria-label', `关闭 ${sessionLabel(session)}`);
      closeBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        closeSession(key);
      });
      tab.appendChild(closeBtn);

      ui.tabs.appendChild(tab);
    }
  }

  function updateStatusBar() {
    const session = activeSession();
    ui.statusLeft.textContent = '';
    ui.statusLatency.textContent = '';
    ui.statusSize.textContent = '';

    // 有本机会话时展示历史；仅审计角色（无终端权限）始终展示
    const noTerminal = !can('terminal:ssh') && !can('terminal:local');
    const showHistory = can('audit:read') && (session ? session.kind === 'local' : noTerminal);
    ui.statusHistory.hidden = !showHistory;
    if (!showHistory) closeHistory();

    if (!session) return;

    const label = makeEl('span', 'status-item mono', sessionLabel(session));
    const badgeClass =
      session.status === 'connected' ? 'ok' : session.status === 'error' || session.status === 'closed' ? 'err' : 'warn';
    const badge = makeEl('span', `badge ${badgeClass}`, STATUS_TEXT[session.status] || session.status);

    ui.statusLeft.appendChild(label);
    ui.statusLeft.appendChild(badge);

    if (session.status === 'connected' && session.latency !== null) {
      ui.statusLatency.textContent = `RTT ${session.latency}ms`;
    }
    if (session.term) {
      ui.statusSize.textContent = `${session.term.cols}×${session.term.rows}`;
    }
  }

  /* ------------------------------ 刷新后恢复会话 ------------------------------ */

  function persistSessions() {
    try {
      const items = [];
      for (const key of state.order) {
        const s = state.sessions.get(key);
        if (!s || s.disposed || !s.sessionId || !s.token) continue;
        items.push({
          sessionId: s.sessionId,
          token: s.token,
          params:
            s.kind === 'local'
              ? { kind: 'local' }
              : {
                  host: s.params.host,
                  port: s.params.port,
                  username: s.params.username,
                  authType: s.params.authType,
                },
        });
      }
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(items));
    } catch {
      /* 存储不可用时静默降级 */
    }
  }

  function restoreSessions() {
    let items = [];
    try {
      items = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '[]');
    } catch {
      items = [];
    }
    if (!Array.isArray(items) || !items.length) return;

    for (const item of items) {
      if (!item || !item.sessionId || !item.token || !item.params) continue;
      if (state.sessions.size >= state.config.maxSessionsPerUser) break;
      const session = new Session({ params: item.params, sessionId: item.sessionId, token: item.token });
      register(session);
      session.start();
    }
  }

  /* ------------------------------ 会话录像 ------------------------------ */

  function formatDuration(ms) {
    const total = Math.max(0, Math.round(ms / 1000));
    const m = Math.floor(total / 60);
    const s = total % 60;
    return `${m}:${String(s).padStart(2, '0')}`;
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  function ensurePlayer() {
    if (state.player.term) return;
    state.player.term = new TerminalCtor({
      fontSize: 10,
      lineHeight: 1.15,
      disableStdin: true,
      cursorBlink: false,
      scrollback: 4000,
      theme: THEME,
    });
    state.player.term.open(ui.recPlayer);
    ui.recEmpty.hidden = true;
  }

  function stopPlaybackTimer() {
    clearTimeout(state.player.timer);
    state.player.timer = null;
  }

  function updatePlayerTime() {
    ui.recTime.textContent = `${formatDuration(state.player.elapsed * 1000)} / ${formatDuration(
      state.player.duration * 1000
    )}`;
    if (ui.recProgress.max !== String(state.player.duration)) {
      ui.recProgress.max = String(state.player.duration || 0.1);
    }
    ui.recProgress.value = String(state.player.elapsed);
  }

  function applyCastEvent(event) {
    const [time, type, data] = event;
    if (type === 'o') state.player.term.write(data);
    state.player.elapsed = time;
  }

  function scheduleNextEvent() {
    const player = state.player;
    if (!player.playing) return;
    const event = player.events[player.index];
    if (!event) {
      player.playing = false;
      ui.recPlay.textContent = '重播';
      updatePlayerTime();
      return;
    }

    // 空闲间隔最长等待 2 秒，避免长时间无输出时回放“卡住”
    const raw = ((event[0] - player.elapsed) * 1000) / player.speed;
    const delay = Math.min(Math.max(raw, 0), 2000);

    player.timer = setTimeout(() => {
      applyCastEvent(event);
      player.index += 1;
      updatePlayerTime();
      scheduleNextEvent();
    }, delay);
  }

  function pausePlayback() {
    state.player.playing = false;
    stopPlaybackTimer();
    ui.recPlay.textContent = '播放';
  }

  function playPlayback() {
    const player = state.player;
    if (!player.events.length) return;
    if (player.index >= player.events.length) seekPlayback(0);
    player.playing = true;
    ui.recPlay.textContent = '暂停';
    scheduleNextEvent();
  }

  function seekPlayback(seconds) {
    const player = state.player;
    stopPlaybackTimer();
    player.playing = false;
    ui.recPlay.textContent = '播放';
    if (!player.term) return;

    player.term.reset();
    player.index = 0;
    player.elapsed = 0;

    while (player.index < player.events.length && player.events[player.index][0] <= seconds) {
      applyCastEvent(player.events[player.index]);
      player.index += 1;
    }
    updatePlayerTime();
  }

  function renderRecordings(items, info) {
    ui.recList.textContent = '';

    if (!items.length) {
      const empty = makeEl(
        'li',
        'rec-empty-item',
        info && info.enabled
          ? '暂无录像。打开一个终端并产生输出后，会自动生成录像。'
          : '录像功能已关闭（RECORDING_ENABLED=false）。'
      );
      ui.recList.appendChild(empty);
      return;
    }

    for (const item of items) {
      const li = makeEl('li', `rec-item${state.selectedRecording === item.id ? ' active' : ''}`);
      li.tabIndex = 0;
      li.setAttribute('role', 'button');

      const line1 = makeEl('div', 'line1');
      line1.appendChild(
        makeEl('span', '', `${item.kind === 'local' ? '部署机' : 'SSH'} · ${item.user}`)
      );
      line1.appendChild(makeEl('span', '', formatDuration(item.durationMs)));
      li.appendChild(line1);

      const line2 = makeEl(
        'div',
        'line2',
        `${formatTime(item.startedAt)} · ${formatBytes(item.sizeBytes)}${item.status === 'truncated' ? ' · 已截断' : ''}`
      );
      li.appendChild(line2);
      if (item.target) li.title = item.target;

      const choose = () => selectRecording(item);
      li.addEventListener('click', choose);
      li.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          choose();
        }
      });

      ui.recList.appendChild(li);
    }
  }

  async function loadRecordings() {
    try {
      const res = await fetch('/api/recordings?limit=200', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('加载失败');
      const data = await res.json();
      state.recordingItems = data.items || [];
      renderRecordings(state.recordingItems, data.info);
      if (state.recordingItems.length) {
        const target = state.recordingItems.find((x) => x.id === state.selectedRecording) || state.recordingItems[0];
        selectRecording(target);
      }
    } catch {
      renderRecordings([], null);
    }
  }

  async function selectRecording(item) {
    state.selectedRecording = item.id;
    for (const node of ui.recList.querySelectorAll('.rec-item')) node.classList.remove('active');
    renderRecordings(state.recordingItems, { enabled: true });

    try {
      const res = await fetch(`/api/recordings/${encodeURIComponent(item.id)}`, { credentials: 'same-origin' });
      if (!res.ok) throw new Error('录像不可用');
      const text = await res.text();
      const lines = text.split('\n').filter(Boolean);
      const header = JSON.parse(lines[0]);
      const events = [];
      for (let i = 1; i < lines.length; i += 1) {
        try {
          events.push(JSON.parse(lines[i]));
        } catch {
          /* 截断的尾行 */
        }
      }

      ensurePlayer();
      const player = state.player;
      stopPlaybackTimer();
      player.events = events;
      player.index = 0;
      player.elapsed = 0;
      player.duration = events.length ? events[events.length - 1][0] : 0;
      player.id = item.id;
      ui.recPlay.textContent = '播放';
      ui.recProgress.value = '0';
      ui.recProgress.max = String(player.duration || 0.1);
      player.term.reset();
      player.term.resize(header.width || 80, header.height || 24);
      updatePlayerTime();
      playPlayback();
    } catch {
      ui.recEmpty.hidden = false;
      ui.recEmpty.textContent = '录像加载失败，请稍后重试';
    }
  }

  function openRecordings() {
    ui.recordingsModal.hidden = false;
    loadRecordings();
    setTimeout(() => {
      const first = ui.recList.querySelector('.rec-item');
      if (first) first.focus();
    }, 300);
  }

  function closeRecordings() {
    pausePlayback();
    ui.recordingsModal.hidden = true;
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !ui.recordingsModal.hidden) closeRecordings();
  });

  ui.recordingsBtn.addEventListener('click', openRecordings);
  ui.recordingsClose.addEventListener('click', closeRecordings);
  ui.recPlay.addEventListener('click', () => {
    if (state.player.playing) pausePlayback();
    else playPlayback();
  });
  ui.recSpeed.addEventListener('change', () => {
    state.player.speed = Number(ui.recSpeed.value) || 1;
    if (state.player.playing) {
      stopPlaybackTimer();
      scheduleNextEvent();
    }
  });
  ui.recProgress.addEventListener('input', () => {
    seekPlayback(Number(ui.recProgress.value) || 0);
  });

  /* ------------------------------ 表单交互 ------------------------------ */

  function setAuthType(type) {
    state.authType = type;
    for (const btn of ui.authSeg.querySelectorAll('.seg-btn')) {
      btn.classList.toggle('active', btn.dataset.auth === type);
    }
    const isPassword = type === 'password';
    ui.passwordField.hidden = !isPassword;
    ui.keyFields.hidden = isPassword;
    ui.password.required = isPassword;
    ui.privateKey.required = !isPassword;
  }

  function showFormError(message) {
    ui.formError.textContent = message || '';
  }

  /* ------------------------------ 连接方式切换 ------------------------------ */

  function can(permission) {
    return state.permissions.includes(permission);
  }

  /* ------------------------------ 二次身份验证 ------------------------------ */

  let stepUpResolver = null;

  function promptStepUp() {
    if (!ui.stepupModal.hidden) return Promise.resolve(false);
    return new Promise((resolve) => {
      stepUpResolver = resolve;
      ui.stepupError.textContent = '';
      ui.stepupPassword.value = '';
      ui.stepupModal.hidden = false;
      setTimeout(() => ui.stepupPassword.focus(), 30);
    });
  }

  function closeStepUp(ok) {
    ui.stepupModal.hidden = true;
    const resolve = stepUpResolver;
    stepUpResolver = null;
    if (resolve) resolve(ok);
  }

  ui.stepupCancel.addEventListener('click', () => closeStepUp(false));

  ui.stepupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const plain = ui.stepupPassword.value;
    if (!plain) {
      ui.stepupError.textContent = '请输入当前账号口令';
      return;
    }

    ui.stepupSubmit.disabled = true;
    ui.stepupError.textContent = '';
    try {
      const res = await fetch('/api/step-up', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: plain }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        ui.stepupError.textContent = data.message || '验证失败';
        ui.stepupPassword.select();
        return;
      }
      state.stepUp.remainingSeconds = data.expiresIn || state.stepUp.ttlSeconds;
      closeStepUp(true);
    } catch {
      ui.stepupError.textContent = '网络异常，请稍后重试';
    } finally {
      ui.stepupSubmit.disabled = false;
    }
  });

  /** 打开本机终端前确保已完成二次认证 */
  async function ensureStepUp() {
    if (!state.stepUp.required) return true;
    if (state.stepUp.remainingSeconds > 0) return true;
    return promptStepUp();
  }

  /* ------------------------------ 角色能力 ---------- */

  function applyCapabilities() {
    const canSsh = can('terminal:ssh');
    const canLocal = can('terminal:local');
    const canAudit = can('audit:read');

    ui.modeSeg.hidden = !(canSsh && canLocal);
    ui.form.hidden = !canSsh;
    if (!canLocal) ui.localPanel.hidden = true;

    const noTerminal = !canSsh && !canLocal;
    ui.noPermission.hidden = !noTerminal;

    // 空状态文案按角色裁剪
    const points = [...ui.emptyState.querySelectorAll('.empty-points li')];
    if (points[0]) points[0].hidden = !canLocal;
    if (points[1]) points[1].hidden = !canSsh;

    if (noTerminal) {
      ui.emptyState.hidden = false;
      const title = ui.emptyState.querySelector('h2');
      const desc = ui.emptyState.querySelector('p');
      if (title) title.textContent = '当前角色仅可查看审计';
      if (desc) desc.textContent = '该账号没有终端权限，可在右下角打开命令历史查看审计记录。';
      const list = ui.emptyState.querySelector('.empty-points');
      if (list) list.hidden = true;
      ui.modeTitle.hidden = true;
      ui.sideTips.hidden = true;
      if (canAudit) openHistory();
    } else if (!canLocal) {
      const desc = ui.emptyState.querySelector('p');
      if (desc) desc.textContent = '通过 SSH 连接其他主机，可同时打开多个会话。';
    }
  }

  function setMode(mode) {
    state.mode = mode === 'ssh' ? 'ssh' : 'local';
    for (const btn of ui.modeSeg.querySelectorAll('.seg-btn')) {
      btn.classList.toggle('active', btn.dataset.mode === state.mode);
    }
    ui.sshFields.hidden = state.mode !== 'ssh';
    ui.localPanel.hidden = state.mode !== 'local';
  }

  function applyLocalInfo() {
    const local = state.local || {};
    ui.localHost.textContent = local.hostname || '—';
    ui.localShell.textContent = local.shell || '—';
    ui.localShell.title = local.shell || '';
    ui.localCwd.textContent = local.cwd || '—';
    ui.localCwd.title = local.cwd || '';
    ui.localUser.textContent = local.user || '—';

    const roleAllows = can('terminal:local');
    const usable = Boolean(local.available) && roleAllows;
    ui.connectLocalBtn.disabled = !usable;
    ui.connectLocalBtn.textContent = usable ? '打开部署机终端' : '部署机终端不可用';

    const auditInfo = state.config.audit || {};
    const forward = auditInfo.forward || {};
    if (!usable) {
      ui.localNote.textContent = roleAllows
        ? local.reason || '部署机终端当前不可用，请检查服务端配置。'
        : '当前角色无权打开部署机终端。';
      ui.localNote.classList.add('warn');
    } else if (forward.enabled && !forward.healthy) {
      ui.localNote.textContent = '审计远端投递异常，命令可能无法及时送达审计系统。';
      ui.localNote.classList.add('warn');
    } else if (local.auditEnabled) {
      ui.localNote.textContent = `以 ${local.user} 身份运行在部署机器上，提交的命令会写入审计日志。`;
      ui.localNote.classList.remove('warn');
    } else {
      ui.localNote.textContent = `以 ${local.user} 身份运行在部署机器上，命令审计当前未开启。`;
      ui.localNote.classList.add('warn');
    }

    // 首次加载时给一个默认模式；用户已手动切换过则不覆盖
    if (!state.modeInitialized) {
      setMode(usable ? 'local' : 'ssh');
      state.modeInitialized = true;
    }
  }

  function createLocalSession() {
    if (state.sessions.size >= state.config.maxSessionsPerUser) {
      ui.localError.textContent = `同时打开的会话不能超过 ${state.config.maxSessionsPerUser} 个`;
      return;
    }
    const localCount = [...state.sessions.values()].filter((s) => s.kind === 'local').length;
    if (localCount >= (state.local.maxSessions || 2)) {
      ui.localError.textContent = `部署机终端最多同时打开 ${state.local.maxSessions} 个会话`;
      return;
    }

    const session = new Session({ params: { kind: 'local' } });
    register(session);
    session.start();

    if (window.innerWidth <= 900) ui.sidebar.classList.remove('open');
  }

  async function connectLocal() {
    ui.localError.textContent = '';
    if (!can('terminal:local')) {
      ui.localError.textContent = '当前角色无权打开部署机终端';
      return;
    }
    if (!state.local.available) {
      ui.localError.textContent = state.local.reason || '部署机终端当前不可用';
      return;
    }

    const ok = await ensureStepUp();
    if (!ok) {
      ui.localError.textContent = '已取消二次身份验证';
      return;
    }
    createLocalSession();
  }

  /* ------------------------------ 命令历史 ------------------------------ */

  function formatTime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    const pad = (n) => String(n).padStart(2, '0');
    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function insertCommand(cmd, run = false) {
    const session = activeSession();
    if (!session || session.status !== 'connected') {
      ui.historyMeta.textContent = '请先打开并连接一个终端，再回填命令';
      return;
    }
    // 先用 Ctrl+C 取消当前输入行（bash 与常见交互式 shell 行为一致），再写入历史命令；
    // 不使用 Ctrl+U：部分 Windows 终端宿主对该组合键支持不一致
    session.send({ type: 'input', data: `\u0003${cmd}${run ? '\r' : ''}` });
    session.focus();
  }

  function renderHistory(entries, info) {
    ui.historyList.textContent = '';

    if (!entries.length) {
      ui.historyList.appendChild(
        makeEl('li', 'history-empty', '暂无命令记录。\n在部署机终端中执行命令后，会出现在这里。')
      );
    } else {
      for (const entry of [...entries].reverse()) {
        const redacted = Boolean(entry.redacted) || /^\[REDACTED/.test(entry.cmd || '');
        const item = makeEl('li', `history-item${redacted ? ' redacted' : ''}`);
        item.appendChild(
          makeEl('div', 'cmd', redacted ? '••••••（疑似密码输入，已屏蔽）' : entry.cmd)
        );
        item.appendChild(
          makeEl('div', 'meta', `${formatTime(entry.ts)} · ${entry.kind === 'local' ? '部署机' : 'SSH'}`)
        );
        item.title = redacted ? '敏感输入不记录明文' : entry.cmd;

        if (!redacted) {
          let timer = null;
          item.addEventListener('click', () => {
            clearTimeout(timer);
            timer = setTimeout(() => insertCommand(entry.cmd), 220);
          });
          item.addEventListener('dblclick', () => {
            clearTimeout(timer);
            insertCommand(entry.cmd, true);
          });
        }

        ui.historyList.appendChild(item);
      }
    }

    if (!info || !info.enabled) {
      ui.historyMeta.textContent = `最近 ${entries.length} 条 · 审计日志未开启（仅内存）`;
      return;
    }
    const forward = info.forward || {};
    const chain = info.hashChain ? '哈希链校验' : '无哈希链';
    const delivery = forward.enabled
      ? `远端投递${forward.healthy ? '正常' : '异常'}（待发 ${forward.pending || 0}）`
      : '仅本地落盘';
    ui.historyMeta.textContent = `最近 ${entries.length} 条 · ${chain} · ${delivery}`;
  }

  async function loadHistory() {
    try {
      const res = await fetch('/api/audit?type=command&limit=200', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('unauthorized');
      const data = await res.json();
      renderHistory(data.entries || [], data.info || null);
    } catch {
      ui.historyMeta.textContent = '命令历史加载失败';
    }
  }

  function openHistory() {
    ui.history.hidden = false;
    ui.main.classList.add('history-open');
    loadHistory();
    const session = activeSession();
    if (session) setTimeout(() => session.fit(), 200);
  }

  function closeHistory() {
    if (ui.history.hidden) return;
    ui.history.hidden = true;
    ui.main.classList.remove('history-open');
    const session = activeSession();
    if (session) setTimeout(() => session.fit(), 200);
  }

  ui.modeSeg.addEventListener('click', (event) => {
    const btn = event.target.closest('.seg-btn');
    if (!btn) return;
    state.modeInitialized = true;
    setMode(btn.dataset.mode);
  });

  ui.connectLocalBtn.addEventListener('click', connectLocal);

  ui.statusHistory.addEventListener('click', () => {
    if (ui.history.hidden) openHistory();
    else closeHistory();
  });

  ui.historyClose.addEventListener('click', closeHistory);

  ui.authSeg.addEventListener('click', (event) => {
    const btn = event.target.closest('.seg-btn');
    if (!btn) return;
    setAuthType(btn.dataset.auth);
    showFormError('');
  });

  ui.form.addEventListener('submit', (event) => {
    event.preventDefault();
    showFormError('');

    if (state.sessions.size >= state.config.maxSessionsPerUser) {
      showFormError(`同时打开的会话不能超过 ${state.config.maxSessionsPerUser} 个`);
      return;
    }

    const host = ui.host.value.trim();
    const port = Number(ui.port.value) || 22;
    const username = ui.username.value.trim();
    const authType = state.authType;

    if (!host) return showFormError('请填写目标主机');
    if (!username) return showFormError('请填写登录用户名');
    if (!Number.isInteger(port) || port < 1 || port > 65535) return showFormError('端口需为 1-65535 的整数');

    const params = { host, port, username, authType };

    if (authType === 'password') {
      if (!ui.password.value) return showFormError('请填写登录密码');
      params.password = ui.password.value;
    } else {
      const key = ui.privateKey.value.trim();
      if (!key) return showFormError('请粘贴私钥内容');
      if (!/BEGIN [A-Z ]*PRIVATE KEY/.test(key)) return showFormError('私钥格式不正确');
      params.privateKey = key;
      params.passphrase = ui.passphrase.value;
    }

    const session = new Session({ params });
    register(session);
    session.start();

    // 凭据不留在表单里，降低被旁观或误粘贴的风险
    ui.password.value = '';
    ui.privateKey.value = '';
    ui.passphrase.value = '';

    if (window.innerWidth <= 900) ui.sidebar.classList.remove('open');
  });

  ui.logoutBtn.addEventListener('click', async () => {
    if (!window.confirm('退出登录将断开所有会话，确定继续？')) return;
    closeHistory();
    try {
      await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    } catch {
      /* ignore */
    }
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
    location.replace('/login');
  });

  ui.menuBtn.addEventListener('click', () => ui.sidebar.classList.toggle('open'));
  ui.sidebarClose.addEventListener('click', () => ui.sidebar.classList.remove('open'));

  /* ------------------------------ 移动端操作栏 ------------------------------ */

  const TOUCH_KEYS = {
    esc: '\u001b',
    tab: '\t',
    'ctrl-c': '\u0003',
    'ctrl-d': '\u0004',
    up: '\u001b[A',
    down: '\u001b[B',
    left: '\u001b[D',
    right: '\u001b[C',
  };

  function updateTouchBar() {
    const coarse = typeof window.matchMedia === 'function' && window.matchMedia('(pointer: coarse)').matches;
    const show = coarse || window.innerWidth <= 900;
    ui.touchBar.hidden = !show;
    document.body.classList.toggle('has-touch-bar', show);
  }

  ui.touchBar.addEventListener('pointerdown', (event) => event.preventDefault());
  ui.touchBar.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-key]');
    if (!button) return;
    const session = activeSession();
    const sequence = TOUCH_KEYS[button.dataset.key];
    if (!session || !sequence) return;
    session.send({ type: 'input', data: sequence });
    session.focus();
  });

  updateTouchBar();

  window.addEventListener('resize', () => {
    updateTouchBar();
    const session = activeSession();
    if (session) session.fit();
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      const session = activeSession();
      if (session) session.fit();
    }
  });

  /* ------------------------------ 启动 ------------------------------ */

  async function bootstrap() {
    if (!TerminalCtor || !FitAddonCtor) {
      document.body.innerHTML =
        '<p style="padding:40px;font-family:sans-serif;color:#f0655f">终端组件加载失败，请检查静态资源是否完整。</p>';
      return;
    }

    try {
      const res = await fetch('/api/config', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('unauthorized');
      const cfg = await res.json();
      if (!cfg.ok || !cfg.user) {
        location.replace('/login');
        return;
      }
      state.config = {
        scrollback: cfg.scrollback || 5000,
        maxSessionsPerUser: cfg.maxSessionsPerUser || 10,
        resumeGraceSeconds: cfg.resumeGraceSeconds || 120,
        tls: Boolean(cfg.tls),
      };
      state.config.audit = cfg.audit || {};
      state.recording = cfg.recording || { enabled: false };
      ui.recordingsBtn.hidden = !state.recording.enabled;
      state.permissions = Array.isArray(cfg.permissions) ? cfg.permissions : [];
      state.hostRestricted = Boolean(cfg.hostRestricted);
      ui.hostNote.hidden = !state.hostRestricted;
      state.role = cfg.role || 'developer';
      state.roleLabel = cfg.roleLabel || '';
      state.stepUp = cfg.stepUp || { required: false, ttlSeconds: 300, remainingSeconds: 0 };
      state.local = cfg.localTerminal || {
        enabled: false,
        available: false,
        reason: '服务端未返回本机终端信息',
        maxSessions: 2,
      };
      ui.currentUser.textContent = cfg.user;
      ui.currentRole.textContent = state.roleLabel;
      applyLocalInfo();
      applyCapabilities();
    } catch {
      location.replace('/login');
      return;
    }

    ui.port.value = ui.port.value || '22';
    setAuthType('password');
    restoreSessions();
    updateStatusBar();

    if (state.mode === 'ssh') ui.host.focus();
  }

  bootstrap();
})();
