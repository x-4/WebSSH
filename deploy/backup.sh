#!/usr/bin/env bash
# 备份 WebSSH 数据目录：审计日志、录像、用户文件、known_hosts、审计链密钥
# 用法：DATA_DIR=/opt/webssh/data BACKUP_DIR=/var/backups/webssh KEEP_DAYS=14 ./backup.sh
set -euo pipefail

DATA_DIR="${DATA_DIR:-/opt/webssh/data}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/webssh}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="${BACKUP_DIR}/webssh-${STAMP}.tar.gz"

umask 077
mkdir -p "${BACKUP_DIR}"

if [[ ! -d "${DATA_DIR}" ]]; then
  echo "数据目录不存在: ${DATA_DIR}" >&2
  exit 1
fi

tar -C "${DATA_DIR}" -czf "${ARCHIVE}" .
chmod 600 "${ARCHIVE}"

# 只保留最近 KEEP_DAYS 天
find "${BACKUP_DIR}" -maxdepth 1 -name 'webssh-*.tar.gz' -mtime +"${KEEP_DAYS}" -delete

echo "备份完成: ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
