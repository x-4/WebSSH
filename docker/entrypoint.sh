#!/bin/sh
# 容器入口：修正数据卷权限后以 node 用户运行，避免长期以 root 身份服务。
# 仅当以 root 启动时执行 chown（需要 CHOWN/SETUID/SETGID 能力）。
set -eu

# 新创建的文件默认仅属主可读写
umask 077

DATA_DIR="${DATA_DIR:-/app/data}"

if [ "$(id -u)" = "0" ]; then
  if [ -d "$DATA_DIR" ]; then
    # 已有卷可能是 root 所有，交给运行用户
    chown -R node:node "$DATA_DIR" 2>/dev/null || true
  fi
  exec gosu node "$@"
fi

exec "$@"
