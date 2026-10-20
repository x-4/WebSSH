# Changelog

所有显著变更都会记录在本文件中。格式参考 Keep a Changelog。

## [1.0.0] - 2026-10-20

### Added
- 双模式终端：远程 SSH（ssh2）与部署机本机终端（node-pty / ConPTY）
- 多用户与角色：admin / operator / developer / auditor，用户文件 + CLI（`npm run user`）
- 敏感操作二次认证（step-up），本机终端默认开启
- 按主机白名单授权（通配符匹配，WebSocket 建连前校验）
- 多会话标签页、断线指数退避重连、凭 token 续接（页面刷新可用）
- 审计：哈希链 + 校验接口、密码提示脱敏、CycloneDX SBOM、远端投递与 fail-closed
- 会话录像（asciinema v2）与内置回放器（变速 / 进度 / 重播）
- 资源看门狗（Linux 进程树 / 内存上限）、审计批量 fsync、通用 API 限流
- 可观测性：/metrics（Prometheus）、/readyz（就绪探针）、JSON 结构化日志、请求 ID
- 启动自检：配置 / 目录 / 用户表校验，致命问题拒绝启动
- 密钥轮换（SESSION_SECRETS 密钥环）、票据吊销（登出即失效）
- 测试：51 个单元 / 集成 / 浏览器 E2E 用例；CI 覆盖 Windows / macOS / Linux 与覆盖率门禁
- 部署：Dockerfile 多阶段构建（非 root + 只读根文件系统）、Compose 加固、Nginx / systemd / 备份脚本

### Security
- scrypt（默认 N=2^16）异步哈希，恒时比较；登出吊销票据
- CSP / HSTS / Origin 校验 / CSRF 缓解 / SSH 主机密钥 TOFU
- 环境变量白名单传入本机 Shell；凭据仅驻留内存

[1.0.0]: https://github.com/your-org/webssh/releases/tag/v1.0.0
