# WebSSH

浏览器里的远程终端：既能通过 SSH 连接其他主机，也能直接操作 WebSSH 所在的部署机器。
技术栈：Node.js + WebSocket + ssh2 + node-pty + xterm.js。

前端只负责渲染与输入，真正的 SSH 连接由服务端建立，因此无需在浏览器里安装任何插件，
也避免了把私钥、密码交给浏览器直连目标主机。

---

## 1. 功能

| 能力 | 说明 |
| --- | --- |
| 实时双向通信 | WebSocket 全双工，输入延迟接近本地终端；服务端 8ms 合并输出分片 |
| SSH 协议连接 | 基于 `ssh2` 建立标准 SSH 会话，申请 PTY，支持 `xterm-256color` |
| 完整终端交互 | xterm.js 渲染，支持输入、输出、光标、颜色、滚动回看、窗口尺寸同步（`SIGWINCH`） |
| 用户登录认证 | 账号口令登录，scrypt 哈希校验，HttpOnly + SameSite=Strict Cookie |
| 多用户与角色 | admin / operator / developer / auditor 四类角色，按能力授权终端与审计范围 |
| 二次身份认证 | 打开部署机终端前需重新确认口令（step-up，默认 5 分钟有效） |
| 可观测性 | `GET /metrics` 暴露 Prometheus 指标；`LOG_FORMAT=json` 输出结构化日志 |
| 启动自检 | 配置冲突、目录不可写、无可用管理员等问题在启动阶段直接拒绝启动 |
| 就绪探针 | `/healthz` 存活、`/readyz` 检查用户表与各数据目录可写、审计投递健康 |
| 密钥轮换 | `SESSION_SECRETS` 密钥环，签发用新密钥、验证兼容旧密钥，登录态不中断 |
| 登录审计 | 登录 / 登出 / 二次认证 / 越权拒绝均写入审计链 |
| 会话录像 | 以 asciinema v2 cast 记录终端输出，页面内支持播放 / 暂停 / 拖动进度 / 变速 |
| 主机白名单 | 按账号限制可连接的 SSH 主机（`10.0.0.*`、`*.internal`），超范围直接拒绝 |
| 移动端操作栏 | 触屏设备提供 Esc / Tab / Ctrl-C / 方向键，标签页与列表支持键盘操作 |
| 容器化部署 | 多阶段构建、非 root 运行、只读根文件系统、健康检查与 Docker 冒烟测试 |
| 多会话管理 | 单标签页内多个独立会话并行，标签切换、独立关闭；服务端按账号限额 |
| 断线重连 | 前端指数退避重连；后端保留 SSH 会话与输出缓冲，凭 token 续接，历史输出自动回放 |
| 传输安全 | 支持 HTTPS/WSS；CSP、HSTS、点击劫持防护；SSH 主机密钥校验（TOFU） |
| 认证方式 | 目标主机支持密码认证与私钥（OpenSSH / PEM，可带口令）认证 |
| 部署机终端 | 无需 SSH 配置，直接在服务所在机器拉起本机 PTY（Linux devpts / Windows ConPTY），一键进入 Shell |
| 命令审计 | 记录本机会话生命周期与每条提交的命令；密码提示处的输入自动脱敏 |
| 审计防篡改 | 每条记录带 `seq/prev/hash` 哈希链，`GET /api/audit/verify` 可校验是否被删改 |
| 审计远端投递 | 支持批量推送 JSON 到 SIEM / 日志网关，可开启 fail-closed（投递异常时拒绝新建本机终端） |
| 资源保护 | 本机会话支持进程数 / 内存看门狗（Linux），超限自动终止，避免 fork bomb 拖垮主机 |
| 审计查询 | `GET /api/audit` 提供最近 500 条记录，支持按事件类型过滤 |

---

## 2. 工作原理

```
┌──────────────┐   HTTPS (静态资源 / 登录 / 审计 API)  ┌──────────────────────┐
│   浏览器      │ ───────────────────────────────────▶ │  Express             │
│              │                                     │  ├─ /api/login       │
│  xterm.js    │   WSS (JSON 控制帧 + 数据帧)         │  ├─ /api/sessions    │
│  ├─ 终端渲染  │ ◀─────────────────────────────────▶ │  ├─ /api/audit       │
│  ├─ 会话标签  │                                     │  └─ /ws  (ws)        │
│  └─ 命令历史  │                                     │         │            │
└──────────────┘                                     │         ▼            │
                                                     │  SessionRegistry     │
                                                     │  ├─ SshSession ──────┼──▶ 目标主机 (SSH)
                                                     │  └─ LocalSession ────┼──▶ 部署机 PTY (node-pty)
                                                     │         │            │
                                                     │    data/audit.log    │
                                                     └──────────────────────┘
```

关键设计：**会话的生命周期独立于 WebSocket**。
WebSocket 断开时不会立即销毁底层连接（SSH 通道或本机 PTY），而是在宽限期（默认 120 秒）内保留，
前端凭 `sessionId + token` 重新挂载后继续使用同一个终端，滚动缓冲一并回放。

---

## 3. 目录结构

```
webssh/
├── server.js                 # 入口：HTTP/HTTPS 服务、启动自检、优雅退出
├── package.json
├── .env.example              # 配置模板
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── config.js             # 环境变量解析与默认值
│   ├── logger.js             # 结构化日志（敏感字段自动脱敏）
│   ├── auth.js               # 会话票据、二次认证、限流、同源校验
│   ├── password.js           # scrypt 口令哈希（参数可升级）
│   ├── users.js              # 多用户文件与角色权限
│   ├── metrics.js            # Prometheus 指标收集与渲染
│   ├── preflight.js          # 启动自检（配置、目录、用户）
│   ├── health.js             # 就绪探针（依赖可写性与投递健康）
│   ├── ratelimit.js          # /api 通用限流
│   ├── app.js                # Express 装配：安全响应头、路由、静态资源
│   ├── ws.js                 # WebSocket 握手鉴权与消息协议
│   ├── audit.js              # 操作审计：哈希链、远端投递、轮转与校验
│   ├── recordings.js         # 会话录像（asciinema v2）与元信息
│   ├── hostKeyStore.js       # 主机密钥指纹记录（known_hosts）
│   ├── sessions/
│   │   ├── index.js          # 统一出口：注册表、参数校验、可用性探测
│   │   ├── base.js           # 会话基类：回放缓冲、合帧、背压、挂载/回收
│   │   ├── sshSession.js     # SSH 远程会话（ssh2 + PTY）
│   │   ├── localSession.js   # 部署机本机会话（node-pty + 口令脱敏 + 资源看门狗）
│   │   ├── inputParser.js    # 终端输入还原为命令行、口令提示识别
│   │   ├── resourceGuard.js  # /proc 进程树统计（Linux 资源限制）
│   │   └── registry.js       # 会话注册表：限额、索引、生命周期审计
│   └── routes/
│       └── api.js            # 登录、会话、配置、审计
├── public/
│   ├── index.html            # 终端主界面（双模式 + 命令历史抽屉）
│   ├── login.html            # 登录页
│   ├── 404.html
│   ├── favicon.svg
│   ├── css/app.css
│   ├── js/login.js
│   ├── js/app.js             # 终端实例、会话标签、重连、历史面板
│   └── vendor/xterm/         # xterm.js 5.5 + fit addon（已内置，离线可用）
├── test/
│   ├── auth.test.js          # 口令哈希、票据签发/吊销
│   ├── audit.test.js         # 哈希链、篡改检测、远端投递
│   ├── inputParser.test.js   # 命令还原与口令提示识别
│   ├── params.test.js        # 连接参数校验
│   ├── rbac.test.js          # 多用户、角色权限、二次认证、主机白名单
│   ├── recording.test.js     # 录像写入、权限隔离、空会话清理
│   └── integration.test.js   # 服务进程 + 模拟 SSH 的端到端测试
├── docker/
│   └── entrypoint.sh         # 容器入口：数据卷属主修正 + 降权到 node
├── deploy/                   # Nginx / systemd / 备份脚本
│   ├── nginx.conf
│   ├── proxy_params_webssh.conf
│   ├── webssh.service
│   └── backup.sh
├── .github/workflows/ci.yml  # CI：Node 20/22 覆盖率门禁 + 依赖审计 + 镜像构建
├── scripts/
│   ├── docker-smoke.sh       # 镜像构建 + 启动 + 健康/登录冒烟测试
│   ├── hash-password.js      # 生成 WEBSSH_PASS_HASH
│   ├── user.js               # 用户与角色管理 CLI
│   └── mock-ssh.js           # 本地演示用 SSH 服务（可选）
└── data/
    ├── known_hosts.json      # 运行时生成，记录已信任的主机密钥指纹
    └── audit.log             # 运行时生成，操作审计日志（JSONL）
```

---

## 4. 快速开始

要求 Node.js ≥ 22（推荐 22 LTS / 24 LTS；Node 18/20 已停止维护）。

```bash
# 1. 安装依赖
npm install

# 2. 准备配置
cp .env.example .env        # Windows: copy .env.example .env

# 3. 修改 .env 中的登录口令与 SESSION_SECRET，然后启动
npm start
```

打开 <http://localhost:3000>，用 `WEBSSH_USER` / `WEBSSH_PASS` 登录。
登录后默认停在「部署机终端」，点击「打开部署机终端」并完成一次口令二次验证，
即可直接操作本机（详见第 8 节）。

需要多人分权使用时，先创建用户再重启服务：

```bash
npm run user -- add alice --role operator
npm run user -- list
```


> 若未创建 `.env`，服务同样可以启动：它会随机生成一个登录口令并打印在控制台，
> 但 `SESSION_SECRET` 也会是临时的，重启后需要重新登录。生产环境请务必显式配置。

生成口令哈希（推荐，避免明文口令出现在环境变量里）：

```bash
npm run hash
# 将输出的 WEBSSH_PASS_HASH 写入 .env，并删除 WEBSSH_PASS
```

### 没有可连的主机？用内置模拟服务验证

```bash
npm run mock      # 监听 127.0.0.1:2222，账号 demo / 密码 demo
```

然后在页面中连接 `127.0.0.1:2222`，即可完整体验终端交互、页面刷新续接与断线重连。
该脚本仅用于本地演示，固定弱口令且只监听回环地址，请勿在生产环境运行。

---

## 5. 配置项

所有配置通过环境变量（`.env`）注入，完整列表见 `.env.example`，常用项如下：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址，仅本机可设为 `127.0.0.1` |
| `TRUST_PROXY` | `false` | 位于反向代理之后时设为 `true`，否则限流会把代理 IP 当成客户端 |
| `HTTP_RATE_LIMIT_PER_MIN` | `300` | `/api` 每 IP 每分钟请求上限，0 表示关闭 |
| `WEBSSH_USER` / `WEBSSH_PASS` | `admin` / 随机 | 登录账号与明文口令 |
| `WEBSSH_PASS_HASH` | 空 | scrypt 哈希，配置后优先于明文口令 |
| `WEBSSH_USERS_FILE` | `data/users.json` | 多用户文件；存在时优先于单账号配置 |
| `SCRYPT_N` | `65536`（2^16） | 新口令哈希的 scrypt 成本（内存约 64MB/次） |
| `STEP_UP_FOR_LOCAL` / `STEP_UP_TTL_MINUTES` | `true` / `5` | 本机终端二次认证开关与有效期 |
| `METRICS_ENABLED` / `METRICS_TOKEN` | `true` / 空 | 指标端点开关与 Bearer Token |
| `RECORDING_ENABLED` | `true` | 是否录制终端输出 |
| `RECORDING_MAX_MB` / `RECORDING_KEEP_DAYS` | `50` / `30` | 单会话录像上限与保留天数 |
| `RECORDING_DIR` | `data/recordings` | 录像存放目录 |
| `LOG_FORMAT` | `text` | 设为 `json` 输出结构化日志 |
| `SESSION_SECRET` | 随机 | 登录票据签名密钥，**必须固定**，否则重启后登录态失效 |
| `SESSION_SECRETS` | 空 | 密钥环（逗号分隔），首个签发、其余验证，用于无感轮换 |
| `SESSION_TTL_MINUTES` | `480` | 登录有效期 |
| `TLS_KEY` / `TLS_CERT` | 空 | 配置后直接以 HTTPS + WSS 运行 |
| `COOKIE_SECURE` | 随 TLS 自动 | Cookie 是否仅 HTTPS 传输 |
| `ALLOWED_ORIGINS` | 空 | 跨域白名单；留空则按 Host 做同源校验 |
| `MAX_SESSIONS` / `MAX_SESSIONS_PER_USER` | `100` / `10` | 并发会话上限 |
| `RESUME_GRACE_SECONDS` | `120` | 断线后保留 SSH 会话的时长 |
| `IDLE_TIMEOUT_MINUTES` | `0` | 无操作自动断开，0 表示不限制 |
| `REPLAY_BUFFER_KB` | `256` | 重连回放的输出缓冲上限 |
| `SSH_BLOCK_PRIVATE_HOSTS` | `false` | 禁止连接内网 / 保留地址（对公网开放时建议开启） |
| `SSH_STRICT_HOST_KEY` | `false` | 仅允许连接已知指纹的主机 |
| `LOGIN_MAX_ATTEMPTS` | `10` | 单 IP 在窗口期内的最大失败次数 |
| `LOCAL_TERMINAL_ENABLED` | `true` | 是否允许打开部署机终端 |
| `LOCAL_TERMINAL_SHELL` | 自动探测 | 指定 Shell 可执行文件路径 |
| `LOCAL_TERMINAL_ARGS` | 空 | Shell 启动参数（空格分隔），如 `-l` |
| `LOCAL_TERMINAL_CWD` | 进程工作目录 | 本机终端的初始工作目录 |
| `LOCAL_TERMINAL_MAX_SESSIONS` | `2` | 本机终端并发上限 |
| `LOCAL_TERMINAL_MAX_PROCS` | `200` | 单个本机会话的进程树上限（Linux） |
| `LOCAL_TERMINAL_MAX_MEMORY_MB` | `1024` | 单个本机会话的常驻内存上限（Linux） |
| `LOCAL_TERMINAL_ENV_ALLOW` | 空 | 额外放行给本机 Shell 的环境变量（白名单之外） |
| `AUDIT_LOG_ENABLED` | `true` | 是否把审计事件写入文件 |
| `AUDIT_RECORD_COMMANDS` | `true` | 是否记录本机会话提交的命令行 |
| `AUDIT_REDACT_SECRET_PROMPTS` | `true` | 密码 / 口令提示处的输入是否脱敏 |
| `AUDIT_HASH_CHAIN` | `true` | 是否为每条记录生成哈希链 |
| `AUDIT_CHAIN_KEY` | 从 `SESSION_SECRET` 派生 | 哈希链 HMAC 密钥 |
| `AUDIT_LOG_FILE` | `data/audit.log` | 审计日志路径 |
| `AUDIT_MAX_FILE_MB` / `AUDIT_KEEP_FILES` | `10` / `5` | 单文件大小上限与保留份数 |
| `AUDIT_FORWARD_URL` | 空 | 远端投递地址（HTTP POST，JSON 批量） |
| `AUDIT_FORWARD_TOKEN` | 空 | 投递鉴权（`Authorization: Bearer`） |
| `AUDIT_REQUIRE_DELIVERY` | `false` | fail-closed：投递连续失败时拒绝新建本机会话 |
| `AUDIT_SYSLOG_HOST` / `PORT` | 空 / `514` | 可选 UDP syslog 旁路 |

---

## 6. 使用说明

- **连接方式**：左侧面板顶部可切换「部署机终端」与「远程 SSH」，两者可同时打开、并行使用。
- **远程 SSH**：填写主机、端口、用户名，选择密码或密钥认证后点击「建立连接」。
- **多会话**：每个连接生成一个标签页，终端实例与 SSH 通道相互独立，可并行操作。
- **快捷键**：`Ctrl+Shift+C` 复制选中、`Ctrl+Shift+V` 粘贴、`Ctrl+L` 清屏（由远端 Shell 处理）。
- **断线重连**：网络抖动或页面刷新后，前端会自动带 `sessionId + token` 续接原会话，
  终端历史输出由服务端回放；只有超出宽限期才会提示重新认证。
- **关闭会话**：点击标签上的 `×`，前端会通知服务端立即回收底层连接（SSH 通道或本机 PTY）。

### 部署机终端

1. 左侧「连接方式」选择 **部署机终端**，面板会显示主机名、Shell 路径、工作目录与运行身份。
2. 点击「打开部署机终端」，获得与本地终端一致的交互体验：颜色、全屏程序（`vim`、`top`）、
   窗口尺寸同步、`Ctrl+C` 等控制字符均正常工作。
3. 连续输入多条命令，输出实时回显；`↑` / `↓` 可调出 Shell 自带历史。
4. 底部「命令历史」按钮打开审计记录（最近 200 条）：单击回填到当前输入行，双击直接执行。
5. 网络中断或刷新页面后自动续接同一个 Shell 会话，历史输出自动回放。

### 用户与角色

推荐用用户文件管理多账号：

```bash
npm run user -- list
npm run user -- add alice --role operator      # 交互式设置口令
npm run user -- passwd alice
npm run user -- role alice developer
npm run user -- disable alice
npm run user -- hosts alice "10.0.0.*,*.internal"   # 限制可连接的主机
npm run user -- hosts alice                          # 查看当前限制
```

| 角色 | SSH 终端 | 部署机终端 | 审计范围 | 说明 |
| --- | --- | --- | --- | --- |
| `admin` | 是 | 是 | 全部用户 | 管理员 |
| `operator` | 是 | 是 | 仅自己 | 运维 |
| `developer` | 是 | 否 | 仅自己 | 开发 |
| `auditor` | 否 | 否 | 全部用户 | 审计员，仅只读审计 |

- 用户文件写入后需**重启服务**生效；删除最后一个 admin 会被拒绝。
- 文件存在时，`.env` 中的 `WEBSSH_USER` / `WEBSSH_PASS` 不再参与登录。
- 打开部署机终端时前端会弹出二次认证窗口，验证结果在 `STEP_UP_TTL_MINUTES` 内复用；
  该验证与登录共用失败限流。
- `hosts` 为空表示不限制；支持 `*`（不跨 `.`）与 `?` 通配，如 `10.0.0.*`、`*.internal`、
  `db-??.example.com`。超出范围时 WebSocket 直接返回 `FORBIDDEN`。

### 会话录像与回放

- 每个会话自动生成 `data/recordings/<sessionId>.cast`（asciinema v2）与同名 `.json` 元信息；
  只记录**终端输出**与窗口尺寸变化，不记录键盘输入。
- 右下角「会话录像」打开列表：按时间倒序展示操作人、类型、时长、大小；
  选中后自动播放，支持暂停 / 重播、拖动进度、0.5×–4× 变速。
- 权限：普通角色只能查看自己的录像；`audit:readAll`（admin / auditor）可查看全部。
- 容量：单会话达到 `RECORDING_MAX_MB` 后停止录制并标记 `truncated`；
  启动时清理超过 `RECORDING_KEEP_DAYS` 天的文件，未正常结束的录像标记为 `interrupted`。

### 移动端与键盘操作

- 触屏或窄屏设备会在终端底部显示操作栏：Esc、Tab、Ctrl-C、Ctrl-D、方向键。
- 会话标签支持 `Tab` 聚焦、`Enter` 切换、`Delete` 关闭；录像与历史列表同样可键盘操作。
- 弹出层支持 `Esc` 关闭（二次认证需显式取消）。

### WebSocket 消息协议

连接地址：`/ws`（握手需携带登录 Cookie，且 `Origin` 必须同源）。

客户端 → 服务端：

| type | 字段 | 说明 |
| --- | --- | --- |
| `connect` | `kind, host, port, username, authType, password, privateKey, passphrase, cols, rows, term` | 新建会话；`kind=local` 时忽略主机与凭据字段 |
| `resume` | `sessionId, token, cols, rows` | 续接已有会话 |
| `input` | `data` | 键盘输入（原样写入 PTY） |
| `resize` | `cols, rows` | 终端尺寸变更 |
| `ping` | `t` | 心跳，服务端回 `pong` |
| `close` | — | 主动结束会话 |

服务端 → 客户端：

| type | 字段 | 说明 |
| --- | --- | --- |
| `ready` | `sessionId, token, replay, truncated, meta, resumed` | 会话就绪（含历史输出回放） |
| `data` | `data` | 终端输出 |
| `status` | `state, message` | 过程状态（如正在连接） |
| `error` | `code, message` | 错误（`BAD_PARAMS` / `CONNECT_FAILED` / `RESUME_FAILED` / `LIMIT` 等） |
| `exit` | `code, signal` | 远端 Shell 退出 |
| `closed` | `reason, exit` | 会话结束 |
| `pong` | `t` | 心跳响应 |

### HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/login` | 登录，成功返回 HttpOnly Cookie |
| `POST` | `/api/logout` | 退出，回收该账号所有会话并吊销票据 |
| `POST` | `/api/step-up` | 二次身份验证（打开部署机终端前） |
| `GET` | `/api/me` | 当前登录用户 |
| `GET` | `/api/sessions` | 当前账号的会话列表（仅元信息，不含凭据） |
| `DELETE` | `/api/sessions/:id` | 主动结束会话 |
| `GET` | `/api/config` | 登录用户可见的配置：并发上限、本机终端信息、审计开关 |
| `GET` | `/api/audit` | 操作审计查询：`?type=command\|session.start\|session.end\|session.limit&limit=200` |
| `GET` | `/api/audit/verify` | 校验审计文件哈希链完整性 |
| `GET` | `/api/recordings` | 录像列表（普通角色仅自己，`audit:readAll` 可看全部） |
| `GET` | `/api/recordings/:id` | 下载 asciinema v2 cast 录像 |
| `GET` | `/metrics` | Prometheus 指标（可用 `METRICS_TOKEN` 保护） |
| `GET` | `/healthz` | 健康检查（无需登录，供探针使用） |

---

## 7. 安全设计

1. **认证**：口令使用 scrypt（默认 N=65536, r=8, p=1）异步哈希比对（线程池，不阻塞终端 I/O），
   恒时比较；哈希串自带参数，登录时自动把旧参数哈希升级到当前成本；
   登录票据为 HMAC-SHA256 签名的 Token，写入 `HttpOnly` + `SameSite=Strict` Cookie，
   前端 JS 无法读取，降低 XSS 窃取风险。票据绑定进程实例标识与用户版本号：
   **登出立即吊销同账号所有旧票据，服务重启后所有登录态失效**（需重新登录）。
2. **CSRF**：所有写操作（登录、登出、删除会话、WebSocket 握手）校验 `Origin`，
   默认要求与请求 `Host` 同源，可用 `ALLOWED_ORIGINS` 收紧。
3. **暴力破解**：按 IP 统计失败次数，超限后窗口期内直接拒绝（`429` + `Retry-After`）。
4. **SSH 主机密钥**：首次连接记录指纹（TOFU），之后指纹不一致立即拒绝并记录告警日志，
   可防中间人攻击；`SSH_STRICT_HOST_KEY=true` 时只信任已记录的主机。
5. **凭据处理**：SSH 密码/私钥仅驻留服务端内存，随会话关闭立即清空；
   日志与 `/api/sessions` 响应中均不包含凭据；私钥内容长度与格式在入口处校验。
6. **SSRF 防护**：`SSH_BLOCK_PRIVATE_HOSTS=true` 时解析目标域名并拒绝内网/保留地址；
   主机名、端口、用户名均做白名单式字符校验。
7. **资源保护**：单 IP 连接数、单账号会话数、全局会话数、WebSocket 报文大小、
   消息速率、输出缓冲、回放缓冲均有上限；当前端消费不及时时暂停 SSH 读取（背压）。
8. **传输安全**：内置 HTTPS/WSS 支持；未启用时启动横幅会明确告警。
   响应头包含 CSP、`X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`，
   TLS 下追加 HSTS。
9. **最小权限**：容器以 `node` 非 root 用户运行，开启 `no-new-privileges`。
10. **本机终端隔离**：部署机终端仅对已认证用户开放，可用 `LOCAL_TERMINAL_ENABLED=false` 关闭；
    Shell 子进程的环境变量使用**白名单**（仅 PATH/HOME/LANG 等运行必需项，外加
    `LOCAL_TERMINAL_ENV_ALLOW` 显式放行的变量），`AWS_SECRET_ACCESS_KEY`、`DATABASE_URL`
    等第三方凭据不会传入终端。
11. **审计可信度**：审计记录以追加写方式落盘（进程崩溃不丢缓冲）并按 `AUDIT_FSYNC_MS` 批量 fsync；
    记录带哈希链，删行、改行、序号断档都可通过 `/api/audit/verify` 检出；
    支持实时投递到远端 SIEM，并可开启 fail-closed——投递连续失败时拒绝新建本机终端。
    密码提示处的输入只记录脱敏标记，不落明文。
12. **资源保护**：本机会话在 Linux 下带进程树看门狗，超过进程数或内存上限即终止；
    配合并发限制与输出背压，降低 fork bomb / 内存耗尽的影响。
13. **权限模型**：角色到能力的映射集中在 `src/users.js`，HTTP 路由与 WebSocket 建连
    双重校验；审计查询按 `audit:readAll` 决定范围。越权请求返回 403 / `FORBIDDEN`。
14. **二次认证**：step-up 与登录票据绑定（jti），TTL 到期自动失效；登出立即清除。
15. **SSRF 加固**：开启 `SSH_BLOCK_PRIVATE_HOSTS` 后，解析结果校验通过即**固定该 IP 建连**，
    避免校验与连接之间发生 DNS 重绑定。
16. **指标访问控制**：`/metrics` 可用 `METRICS_TOKEN` 要求 Bearer Token，避免指标泄露公网。
17. **主机白名单**：账号级 `hosts` 在 WebSocket 建连前校验，支持通配但不跨域名层级，
    避免用通配符意外放行整段域名。
18. **录像访问控制**：录像按会话所有者隔离，`audit:readAll` 才可跨用户查看；
    文件权限 0600，目录 0700，且录像不记录键盘输入。
19. **认证事件审计**：登录成功/失败/限流、登出、二次认证、RBAC 越权拒绝均写入审计链，
    并计入 `/metrics`，可与终端操作记录关联分析。
20. **请求可追踪**：所有 HTTP 响应返回 `X-Request-Id`，错误日志带同一个 ID，便于与网关日志对齐。
21. **故障快速失败**：未捕获异常会记录后触发优雅退出（退出码 1），由 systemd / 容器重启，
    避免进程在不确定状态下继续服务。

### 风险边界（请务必了解）

- 本程序本质上是**受控的 SSH 代理**：任何能登录本服务的人，都可以用服务端的网络位置去连接目标主机。
  请把它部署在可信网络中，或配合 VPN / 零信任网关使用。
- 登录账号是单账号模型。若需要多用户、按用户授权不同目标主机，需要扩展 `auth.js`
  与 `SessionRegistry`（按用户维护主机白名单）。
- 命令审计覆盖**本机会话的命令行**与会话生命周期，不记录终端输出，也不覆盖交互式程序内部操作；
  SSH 远端命令需由目标主机的 auditd / shell hook 完成。
- 哈希链只能**发现**篡改，不能阻止拥有文件写权限的账号删除整个审计文件；
  合规场景请同时启用 `AUDIT_FORWARD_URL`（实时送出本机）与 `AUDIT_REQUIRE_DELIVERY=true`。
- `data/known_hosts.json` 中保存的是**公钥指纹**，属于可公开信息，但仍建议限制文件权限。

---

## 8. 部署机终端：前置配置、权限与安全边界

### 8.1 前置配置

1. **安装 PTY 组件**：`node-pty` 已声明为 `optionalDependencies`，执行 `npm install` 即可；
   即使安装失败也不会影响 SSH 功能，但页面中的部署机终端会显示「不可用」并给出原因。
2. **编译依赖**（无预编译产物时需要）：

   | 平台 | 依赖 |
   | --- | --- |
   | Debian / Ubuntu | `sudo apt install -y build-essential python3` |
   | RHEL / CentOS | `sudo yum groupinstall "Development Tools"`，并安装 `python3` |
   | Alpine（容器） | `apk add --no-cache python3 make g++` |
   | macOS | `xcode-select --install` |
   | Windows | Visual Studio Build Tools（C++ 生成工具）；ConPTY 需 Win10 1809+ |

3. **确认 Shell 可用**：Linux 默认使用 `$SHELL` 或 `/bin/bash`（登录模式 `-l`）；
   Windows 依次探测 `pwsh.exe` → `powershell.exe` → `%COMSPEC%`。
   可用 `LOCAL_TERMINAL_SHELL` 指定 Shell，`LOCAL_TERMINAL_ARGS` 传参，`LOCAL_TERMINAL_CWD` 指定初始目录。
4. **启用开关**：默认开启；设置 `LOCAL_TERMINAL_ENABLED=false` 可完全关闭该入口
   （服务端拒绝 `connect kind=local`，前端按钮置灰）。

### 8.2 权限要求

- Shell 以 **WebSSH 服务进程的身份**运行，拥有该账号的全部权限：能读写的文件、能执行的命令、
  能访问的网络，与手工登录该账号一致。
- **不要用 root 运行本服务**：systemd 配置 `User=webssh`，容器使用 `USER node`。
  需要提权的运维动作应通过受控的 `sudoers` 规则显式授权，并保留审计。
- 服务账号遵循最小权限：只授予运维必需的目录与命令；`data/` 建议 `chmod 700`，
  避免审计日志与主机指纹被其他账号读取。
- 审计文件需要可写权限；建议单独挂载到独立磁盘，并纳入日志轮转与备份策略。
- 本机会话在 Linux 下受进程数与内存看门狗约束（`LOCAL_TERMINAL_MAX_PROCS` /
  `LOCAL_TERMINAL_MAX_MEMORY_MB`）；Windows / macOS 暂不支持，需自行通过容器或系统层限制资源。

### 8.3 安全边界

| 边界 | 现状与建议 |
| --- | --- |
| 访问控制 | 仅登录成功的账号可打开本机终端；多用户场景需在 `auth.js` 增加角色判断，并在 `ws.js`、`routes/api.js` 入口校验 |
| 权限边界 | 终端权限 = 服务进程权限；不做提权，也不做命令内容限制（如需限制请接入 `sudo` 策略或命令白名单） |
| 命令审计 | 记录本机会话的命令行与会话生命周期，JSONL 写入 `data/audit.log`（10MB 轮转、保留 5 份），`GET /api/audit` 可查；不记录输出 |
| 审计防篡改 | 哈希链 + 校验接口；可实时投递远端 SIEM，`AUDIT_REQUIRE_DELIVERY=true` 时投递异常即拒绝新建会话 |
| 审计盲区 | 交互式程序内部操作（`vim` 保存、数据库客户端内的 SQL）不会记录；SSH 会话仅记录连接生命周期 |
| 敏感信息 | 密码提示处输入自动脱敏；`export TOKEN=xxx` 之类仍会落盘，避免在命令行书写明文密钥 |
| 网络暴露 | 本机终端等于把服务器 Shell 暴露到浏览器，必须置于 HTTPS 与可信网络 / VPN 之后 |
| 资源限制 | Linux 下按进程树限制进程数与常驻内存；`LOCAL_TERMINAL_MAX_SESSIONS` 限制并发；`IDLE_TIMEOUT_MINUTES` 可设空闲断开 |
| 关闭方式 | `LOCAL_TERMINAL_ENABLED=false`；或在反向代理层限制 `/ws` 的来源与访问者 |

---

## 9. 部署

### 9.1 Nginx 反向代理（推荐）

```nginx
server {
    listen 443 ssl http2;
    server_name ssh.example.com;

    ssl_certificate     /etc/ssl/certs/ssh.example.com.crt;
    ssl_certificate_key /etc/ssl/private/ssh.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;

        # WebSocket 升级
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 终端会话是长连接，避免被代理空闲超时切断
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

对应 `.env`：

```ini
TRUST_PROXY=true
COOKIE_SECURE=true
ALLOWED_ORIGINS=https://ssh.example.com
```

### 9.2 直接启用 TLS

```ini
TLS_KEY=/etc/ssl/private/webssh.key
TLS_CERT=/etc/ssl/certs/webssh.crt
```

### 9.3 Docker / Docker Compose

#### 快速开始

```bash
cp .env.example .env          # 至少修改 WEBSSH_PASS 与 SESSION_SECRET
vim .env
docker compose up -d --build
docker compose logs -f
```

默认只监听 `127.0.0.1:3000`，由反向代理对外提供服务。需要局域网直连时：

```bash
WEBSSH_BIND=0.0.0.0 WEBSSH_PORT=3000 docker compose up -d
```

访问 `http://<host>:3000`，用 `.env` 中的账号登录。

#### 纯 docker run（不使用 Compose）

```bash
docker build -t webssh:1.0.0 .
docker volume create webssh-data
docker run -d --name webssh \
  -p 127.0.0.1:3000:3000 \
  -e WEBSSH_USER=admin -e WEBSSH_PASS='替换为强口令' \
  -e SESSION_SECRET="$(openssl rand -hex 32)" \
  -v webssh-data:/app/data \
  --read-only \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --tmpfs /tmp --tmpfs /home/node:size=64m,uid=1000,gid=1000,mode=0700 \
  webssh:1.0.0
```

`CHOWN/SETUID/SETGID` 仅用于入口脚本修正数据卷属主并降权到 `node`；
若使用外部编排已保证卷属主为 UID 1000，可移除这三个能力并以 `--user 1000:1000` 运行。

#### 镜像设计

- **多阶段构建**：构建阶段安装 `python3 make g++` 编译 `node-pty`，运行阶段不包含任何编译工具；基础镜像为 `node:22-bookworm-slim`（Node 22 LTS，glibc，`node-pty` 编译与终端兼容性更稳定）。
- **非 root 运行**：入口脚本先修正数据卷属主，再用 `su-exec` 降权到 `node`（UID 1000）；应用进程不以 root 身份服务。
- **信号与回收**：`tini` 作为 PID 1，正确转发 `SIGTERM` 并回收 `node-pty` 派生的 Shell 子进程；`STOPSIGNAL SIGTERM` 配合应用 8 秒优雅退出。
- **只读根文件系统**：Compose 开启 `read_only`，仅 `/app/data`（命名卷）、`/tmp`、`/home/node`（tmpfs）可写。
- **能力最小化**：`cap_drop: ALL`，仅保留入口脚本所需的 `CHOWN`、`SETUID`、`SETGID`；`no-new-privileges`。
- **资源与日志**：`pids_limit`、`mem_limit`、`nofile` 上限；`json-file` 日志滚动（10MB × 3）。
- **健康检查**：镜像内置 `HEALTHCHECK` 调用 `/healthz`，`docker ps` 可直接看到 `healthy`；编排系统可另外使用 `/readyz`。

#### 数据与备份

```bash
docker volume ls | grep webssh
docker run --rm -v webssh_webssh-data:/data -v "$PWD:/backup" alpine   tar -czf /backup/webssh-data.tgz -C /data .
```

卷内包含审计日志、录像、用户文件、`known_hosts.json` 与审计链密钥 `audit.key`。
恢复时把归档解回卷内并重启容器；**`audit.key` 缺失将无法校验历史哈希链**。

> `docker compose down -v` 会删除命名卷，等同于清空审计与用户数据，执行前务必备份。

#### 升级

```bash
docker compose pull            # 若使用镜像仓库
docker compose up -d --build   # 本地构建
```

升级前建议先备份卷；服务重启后所有登录态失效（票据绑定进程实例），终端会话会在 8 秒内优雅关闭。

#### 验证与冒烟测试

```bash
bash scripts/docker-smoke.sh
```

该脚本会构建镜像、以生产参数启动（只读根文件系统 + 最小能力 + 命名卷），验证
`/healthz`、`/readyz`、登录、`/metrics` 以及**容器内本机终端可用**（即 `node-pty` 在镜像构建阶段编译成功），
并检查应用进程以 `node` 用户运行。CI 的 `docker` 任务会执行同一脚本。

#### 多架构构建

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t registry.example.com/webssh:1.0.0 --push .
```

#### 注意事项

- 容器内的「部署机终端」操作的是**容器内部**，不是宿主机。若需要操作宿主机，请把 WebSSH 直接以 systemd 方式运行在宿主机上；不建议通过 `--privileged`、挂载宿主根目录或 `/var/run/docker.sock` 来把容器变成宿主机 Shell，那会失去隔离边界。
- 镜像基于 Debian slim，自带 `/bin/bash`；如需其他 Shell 可通过 `LOCAL_TERMINAL_SHELL` 指定。
- 时区默认 UTC；如需本地时区，可在 `.env` 中设置 `TZ=Asia/Shanghai` 并在镜像中安装 `tzdata`。
- 若使用外部数据库/Redis（当前版本未内置），请通过自定义网络连接，不要把管理端口暴露到公网。

### 9.4 systemd

```ini
[Unit]
Description=WebSSH
After=network.target

[Service]
Type=simple
User=webssh
WorkingDirectory=/opt/webssh
EnvironmentFile=/opt/webssh/.env
ExecStart=/usr/bin/node /opt/webssh/server.js
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 9.5 测试与 CI

```bash
npm test          # 单元 + 集成测试（node:test，无需额外测试框架）
npm run coverage  # 覆盖率门禁：行 ≥45%、分支 ≥55%、函数 ≥28%
npm audit --omit=dev --audit-level=high
```

测试覆盖：口令哈希与票据吊销、异步哈希与密钥轮换、RBAC 权限矩阵与二次认证、主机白名单、
输入解析与口令提示识别、审计哈希链与篡改检测、审计落盘持久性、远端投递、会话录像与权限隔离、
启动自检、通用限流、指标与就绪探针、SSH 与本机会话端到端流程（51 个用例）。

仓库内置 GitHub Actions（`.github/workflows/ci.yml`）：Ubuntu（Node 22/24）跑覆盖率门禁与依赖审计，
Windows / macOS（Node 22）跑完整测试，另设 Docker 构建与冒烟任务。

#### 依赖与供应链

运行时依赖只有 4 个（外加 1 个可选原生模块），前端库以 vendored 方式内置于 `public/vendor/`：

| 包 | 许可证 | 用途 |
| --- | --- | --- |
| `express` | MIT | HTTP 服务、路由、静态资源与安全中间件 |
| `ws` | MIT | WebSocket 终端通道 |
| `ssh2` | MIT* | SSH 客户端协议实现（远程会话） |
| `dotenv` | BSD-2-Clause | 读取 `.env` 配置 |
| `node-pty`（可选） | MIT | 本机终端伪终端；缺失时仅本机终端不可用 |

\* `ssh2` 的 package.json 未声明 license 字段，官方仓库声明为 MIT。

- 前端 `xterm.js` 与 fit 插件已内置到 `public/vendor/xterm/`，运行时不依赖 npm 包；对应 npm 包仅用于升级内置文件，已归入 devDependencies。
- `playwright-core` 仅用于浏览器 E2E 测试（devDependencies）。
- 传递依赖共 82 个（生产安装约 79 个），许可证全部为 MIT / BSD / ISC / Apache-2.0 / Unlicense 等宽松许可；`ssh2` 的 `cpu-features`/`buildcheck` 是安装期可选组件，不进入运行时。

供应链策略：

1. 依赖一律锁定在 `package-lock.json`，安装使用 `npm ci`；
2. CI 执行 `npm audit --audit-level=high` 与覆盖率门禁，失败即拦截合并；
3. 每次构建生成 CycloneDX SBOM（`npm run sbom` → `sbom.cdx.json`）并作为 CI 产物归档；
4. `node-pty` 为唯一需要编译的原生模块，镜像构建阶段提供工具链，运行阶段不包含；
5. 升级依赖需通过测试与覆盖率门禁后合入。

### 9.6 运行与维护

**运行环境支持矩阵**：

| 环境 | 支持情况 |
| --- | --- |
| Linux（glibc，systemd） | 完整支持：PTY、资源看门狗、systemd、Docker |
| Linux（musl/Alpine） | 需自行编译 `node-pty`；官方镜像使用 Debian slim |
| macOS | SSH 与本机终端可用；无 `/proc` 资源看门狗；服务化需 launchd |
| Windows 10 1809+ / Server 2019+ | SSH 与本机终端（ConPTY）可用；无进程/内存限制；文件权限语义不同；建议用 WinSW 封装服务 |
| ARM64 | 理论支持（需编译 `node-pty`），未在 CI 真机覆盖 |
| 容器 / Kubernetes | 单副本 + 持久卷 + WebSocket 入口；不支持 Serverless/边缘运行时 |
| 多副本 | 会话与限流在内存，需粘性路由；当前不内置共享会话存储 |

**启动自检**：进程启动时校验 `SCRYPT_N`、会话上限、用户文件、数据/审计/录像目录可写性、
TLS 文件可读性等；存在致命问题时直接退出并打印原因（`配置错误: ...`），避免“带病上线”。

**健康检查**：

| 端点 | 用途 | 说明 |
| --- | --- | --- |
| `/healthz` | 存活探针 | 只返回进程存活，不触碰磁盘 |
| `/readyz` | 就绪探针 | 检查用户表、数据目录、审计目录（含投递健康）、录像目录；失败返回 503 |
| `/metrics` | 指标 | Prometheus 文本格式，可用 `METRICS_TOKEN` 保护 |

Kubernetes 示例：`livenessProbe` 用 `/healthz`，`readinessProbe` 用 `/readyz`，
`terminationGracePeriodSeconds: 20`。

**密钥轮换**（不中断登录态）：

```ini
# 1. 生成新密钥并放在最前，旧密钥保留在密钥环中
SESSION_SECRETS=new-64-hex,old-64-hex
# 2. 重启服务（新票据用新密钥签发，旧票据仍可验证）
# 3. 等待超过 SESSION_TTL_MINUTES 后移除旧密钥，再次重启
```

审计哈希链密钥独立存放于 `data/audit.key`（或 `AUDIT_CHAIN_KEY`），不会随会话密钥轮换而失效。

**备份与恢复**：

```bash
DATA_DIR=/opt/webssh/data BACKUP_DIR=/var/backups/webssh KEEP_DAYS=14   ./deploy/backup.sh
```

备份包含审计日志、录像、用户文件、`known_hosts.json`、`audit.key`（**缺失将无法校验历史哈希链**）。
恢复时停止服务 → 解包到数据目录 → 修正属主与权限（`chown -R webssh:webssh`、`chmod 700`）→ 启动。

**升级**：备份 → 拉取新版本 → `npm ci --omit=dev` → 重启（`systemctl restart webssh`）。
服务会在 8 秒内优雅退出并关闭所有终端会话；客户端会提示会话结束，重新登录即可。

**部署规模与高可用**：
本版本是**单实例、会话在内存**的架构（会话、限流计数、二次认证状态均不共享）。
生产建议采用「单活 + 进程守护」：systemd `Restart=always` 或容器 `restart: unless-stopped`，
前面挂反向代理与健康检查；需要多副本时，必须先引入共享会话存储与粘性路由，
否则跨副本的断线重连会失败。当前不内置 Redis，避免把外部依赖强加给中小规模部署。

**资源与限制**：systemd 单元已给出 `MemoryMax=1G`、`TasksMax=4096`、`LimitNOFILE=65535`；
容器编排示例限制了 `pids_limit`、`mem_limit`、`cap_drop: ALL` 与只读根文件系统。
录像与审计占用随使用增长，请按第 5 节配置上限并纳入备份。

**故障排查入口**：`/readyz` 的 `checks` 字段、`journalctl -u webssh`、`LOG_FORMAT=json` 的结构化日志，
以及审计链校验 `GET /api/audit/verify`。

---

## 10. 常见问题

**连接失败：主机密钥校验失败**
目标主机重装或更换了 SSH 主机密钥。确认变更可信后，删除 `data/known_hosts.json` 中对应条目再重连。

**页面能打开，但终端一直显示「正在连接」**
检查反向代理是否转发了 WebSocket 升级头（`Upgrade` / `Connection`），以及是否设置了过短的读超时。

**输入中文出现乱码**
服务端已用 `StringDecoder` 处理跨 TCP 分片的多字节字符；若仍异常，请确认目标主机 `LANG` 为 UTF-8
（如 `export LANG=zh_CN.UTF-8`）。

**刷新页面后会话没了**
`sessionStorage` 被清理、或超过 `RESUME_GRACE_SECONDS` 宽限期、或服务端已重启，都会导致无法续接。

**打开部署机终端时提示「需要二次身份验证」？**
这是 step-up 保护：输入当前账号口令即可，默认 5 分钟内复用。连续输错会触发登录限流。

**录像占磁盘怎么办？**
调小 `RECORDING_MAX_MB`、缩短 `RECORDING_KEEP_DAYS`，或设置 `RECORDING_ENABLED=false`
关闭录像；`data/recordings` 可单独挂载并纳入备份策略。

**如何新增运维同事的账号？**
`npm run user -- add <name> --role operator`，写入 `data/users.json` 后重启服务；
随后可在首页用该账号登录。删除最后一个 admin 会被 CLI 拒绝。

**服务重启后需要重新登录？**
票据绑定了进程实例标识，这是刻意设计：会话与进程生命周期一致，重启后旧 Cookie 一律失效。
若使用固定 `SESSION_SECRET`，票据签名仍有效，但实例标识不匹配，同样会被拒绝。

**审计校验返回 `hash-mismatch` / `sequence-gap`？**
说明审计文件被修改或删行。请保全现场（备份 `data/audit.log`），排查有文件写权限的账号；
若已启用远端投递，请以远端 SIEM 中的副本为准。恢复文件后校验会重新通过。

**部署机终端显示「不可用」**
说明 `node-pty` 未安装成功。页面会给出具体原因：按第 8.1 节补齐编译工具链后重新
`npm install`，或在 `.env` 中设置 `LOCAL_TERMINAL_ENABLED=false` 明确关闭该入口。

**Windows 下关闭本机会话时日志出现 `Error: AttachConsole failed`**
这是 `node-pty` 在无控制台环境（服务、部分终端宿主）中清理 ConPTY 进程列表时的已知行为，
不影响终端功能，可忽略；Linux 部署不会出现。

**为什么不能直接连内网主机？**
默认允许；若开启 `SSH_BLOCK_PRIVATE_HOSTS=true`，则出于 SSRF 防护会拒绝内网地址。

---

## 11. 已知限制

- 角色为内置的四类固定组合，暂不支持自定义权限集与按主机维度的细粒度授权。
- 用户文件不热加载，增删改用户需重启服务。
- 本机终端依赖 `node-pty`，缺少编译工具链或平台不支持时不可用（SSH 功能不受影响）。
- 不支持 SFTP 文件传输、端口转发；录像为终端输出回放，不含键盘输入与操作审计的逐键轨迹。
- 录像/审计均为本地文件存储，未内置对象存储或远端归档，多副本部署需自行共享存储。
- 单实例架构：会话、限流与二次认证状态在内存中，不支持多副本水平扩展（见 9.6 的说明）。
- 测试覆盖以服务端为主（前端通过 Playwright 做端到端验证，未纳入 CI 覆盖率门禁）。
- 资源看门狗仅 Linux 生效；Windows/macOS 需依赖容器或系统层限制。
- ARM64 与 musl 未纳入 CI 真机矩阵，属于「理论支持、需自测」。
- 审计防篡改依赖哈希链与远端投递，未提供独立的远端存储服务；进程级资源限制仅 Linux 生效。
- 前端未做移动端软键盘特殊适配，小屏体验以连接与查看为主。
- 主机密钥信任为 TOFU 模式，首次连接仍存在被劫持的理论风险；高安全场景请预置 `known_hosts` 并开启严格模式。

## 12. 许可证

MIT — 详见 [LICENSE](LICENSE)。
